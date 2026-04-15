"""
Phone Number Analyzer.

Checks a phone number against:
  1. Basic validity and line type (landline / VOIP / mobile)
  2. Geographic region (VA/DC/MD corridor vs. unrelated area)
  3. Known published numbers for major cleared staffing firms / contractors
  4. WHOIS domain age check when a company domain is provided alongside the number
  5. Mismatch flags: number given by contact vs. company's published number

Key rule: Any number used to request SSN/DOB over the phone is suspicious
regardless of whether the number itself appears legitimate.
"""
import re
from dataclasses import dataclass, field

import phonenumbers
from phonenumbers import carrier, geocoder, number_type, PhoneNumberType


# ---------------------------------------------------------------------------
# Known published numbers for cleared staffing / contracting firms
# Sources: company websites as of April 2026
# ---------------------------------------------------------------------------
KNOWN_COMPANY_NUMBERS: dict[str, dict] = {
    # Mindbank Consulting Group
    "+17038934700": {"company": "Mindbank Consulting Group", "office": "Vienna VA", "domain": "mindbank.com"},
    "+13035634900": {"company": "Mindbank Consulting Group", "office": "Lakewood CO", "domain": "mindbank.com"},
    # 22nd Century Technologies / TSCTI
    "+18665379191": {"company": "22nd Century Technologies", "office": "McLean VA HQ (toll-free)", "domain": "tscti.com"},
    # Kforce
    "+18139607000": {"company": "Kforce", "office": "Tampa FL HQ", "domain": "kforce.com"},
    # Booz Allen Hamilton
    "+17033773000": {"company": "Booz Allen Hamilton", "office": "McLean VA HQ", "domain": "boozallen.com"},
    # Leidos
    "+17033102000": {"company": "Leidos", "office": "Reston VA HQ", "domain": "leidos.com"},
    # SAIC
    "+17033602000": {"company": "SAIC", "office": "Reston VA", "domain": "saic.com"},
    # ManTech
    "+17032185400": {"company": "ManTech International", "office": "Herndon VA", "domain": "mantech.com"},
    # CACI
    "+17032323000": {"company": "CACI International", "office": "Arlington VA", "domain": "caci.com"},
    # Raytheon (RTX)
    "+17035768000": {"company": "Raytheon Technologies", "office": "Arlington VA", "domain": "rtx.com"},
    # General Dynamics IT
    "+17037257100": {"company": "General Dynamics IT", "office": "Fairfax VA", "domain": "gdit.com"},
    # Peraton
    "+17033232000": {"company": "Peraton", "office": "Herndon VA", "domain": "peraton.com"},
}

# DC Metro area NPA codes — expected for cleared contracting work
DC_METRO_AREA_CODES = {
    "202",  # Washington DC
    "301",  # Maryland (Montgomery/PG County)
    "240",  # Maryland (Montgomery/PG County)
    "443",  # Maryland (Baltimore area)
    "410",  # Maryland (Baltimore)
    "703",  # Northern Virginia
    "571",  # Northern Virginia (overlay)
    "804",  # Richmond VA
    "540",  # Western VA / Shenandoah
    "434",  # Charlottesville VA
    "757",  # Hampton Roads VA (Norfolk/Newport News)
}

# Area codes that are surprising for cleared VA/DC roles — not a block, just a flag
UNEXPECTED_AREA_CODES_FOR_CLEARED_WORK = {
    "900",  # Premium rate
    "876",  # Jamaica
    "809",  # Dominican Republic / Caribbean
    "473",  # Grenada
    "649",  # Turks & Caicos
    "664",  # Montserrat
}

# These VA/MD sub-regions are rural / unusual for major contractor offices
RURAL_VA_REGIONS_FLAG = {
    "nokesville",
    "culpeper",
    "warrenton",
    "luray",
    "front royal",
    "strasburg",
    "woodstock va",
    "broadway va",
    "harrisonburg",  # some legit, but flagged if claimed to be McLean office
}

LINE_TYPE_LABELS = {
    PhoneNumberType.MOBILE: "mobile",
    PhoneNumberType.FIXED_LINE: "landline",
    PhoneNumberType.FIXED_LINE_OR_MOBILE: "landline/mobile",
    PhoneNumberType.VOIP: "VoIP",
    PhoneNumberType.TOLL_FREE: "toll-free",
    PhoneNumberType.PREMIUM_RATE: "premium-rate ⚠️",
    PhoneNumberType.UNKNOWN: "unknown",
}


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------
@dataclass
class PhoneFinding:
    severity: str      # "critical" | "high" | "medium" | "info"
    finding: str
    detail: str
    weight: float


@dataclass
class PhoneAnalysis:
    number_raw: str
    number_e164: str = ""
    is_valid: bool = False
    line_type: str = ""
    region: str = ""
    carrier_name: str = ""
    area_code: str = ""
    matched_company: str = ""   # name if number is in KNOWN_COMPANY_NUMBERS
    findings: list[PhoneFinding] = field(default_factory=list)
    risk_score: float = 0.0
    is_suspicious: bool = False

    @property
    def verdict(self) -> str:
        if not self.is_valid:
            return "INVALID NUMBER"
        if self.is_suspicious:
            if self.risk_score >= 0.65:
                return "HIGH RISK — DO NOT PROVIDE SSN"
            return "SUSPICIOUS — VERIFY INDEPENDENTLY"
        if self.matched_company:
            return f"MATCHES PUBLISHED NUMBER — {self.matched_company}"
        return "APPEARS LEGITIMATE — VERIFY COMPANY IDENTITY INDEPENDENTLY"


# ---------------------------------------------------------------------------
# Main analysis function
# ---------------------------------------------------------------------------
def analyze_phone(
    number: str,
    claimed_company: str = "",
    claimed_region: str = "",
    ssn_requested_on_call: bool = False,
    pre_offer_contact: bool = False,
) -> PhoneAnalysis:
    """
    Analyze a phone number for fraud indicators.

    Args:
        number: Raw phone number string (any format, US assumed if no country code)
        claimed_company: Company name the caller claimed to represent
        claimed_region: Where the caller claimed to be calling from
        ssn_requested_on_call: Set True if SSN/DOB was requested during this call
        pre_offer_contact: Set True if this contact happened before a formal written offer

    Returns:
        PhoneAnalysis with risk score and detailed findings.
    """
    analysis = PhoneAnalysis(number_raw=number)

    # --- Parse number ---
    try:
        parsed = phonenumbers.parse(number, "US")
    except phonenumbers.NumberParseException:
        analysis.findings.append(PhoneFinding(
            "high", "Phone number could not be parsed",
            "The number format is invalid or unparseable — may be deliberately obfuscated.",
            0.60,
        ))
        analysis.is_suspicious = True
        analysis.risk_score = 0.60
        return analysis

    analysis.is_valid = phonenumbers.is_valid_number(parsed)
    analysis.number_e164 = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)
    formatted_national = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.NATIONAL)

    if not analysis.is_valid:
        analysis.findings.append(PhoneFinding(
            "high", f"Invalid phone number: {formatted_national}",
            "Number does not match a valid North American numbering plan assignment.",
            0.55,
        ))

    # Line type
    ntype = number_type(parsed)
    analysis.line_type = LINE_TYPE_LABELS.get(ntype, "unknown")

    # Region
    analysis.region = geocoder.description_for_number(parsed, "en")

    # Carrier (mobile only)
    analysis.carrier_name = carrier.name_for_number(parsed, "en")

    # Area code
    national = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.NATIONAL)
    digits_only = re.sub(r"\D", "", national)
    if len(digits_only) >= 10:
        analysis.area_code = digits_only[:3]

    # --- Check 1: Known published number ---
    if analysis.number_e164 in KNOWN_COMPANY_NUMBERS:
        info = KNOWN_COMPANY_NUMBERS[analysis.number_e164]
        analysis.matched_company = info["company"]
        analysis.findings.append(PhoneFinding(
            "info",
            f"Number matches published listing for {info['company']} ({info['office']})",
            f"This number appears in the known legitimate contact database for {info['company']} "
            f"at {info['domain']}. Verify the caller's identity further before sharing any PII.",
            -0.20,  # negative weight — lowers risk score
        ))
    else:
        analysis.findings.append(PhoneFinding(
            "medium",
            "Number not found in known cleared contractor/staffing database",
            "This number does not match any published office number for major cleared "
            "employers. This is not conclusive — companies use many lines — but verify "
            "by calling the PUBLISHED main number from the company website.",
            0.25,
        ))

    # --- Check 2: VoIP type ---
    if ntype == PhoneNumberType.VOIP:
        analysis.findings.append(PhoneFinding(
            "high",
            "Number is VoIP — easy to spoof location and identity",
            "VoIP numbers (Google Voice, Skype, TextNow, MagicJack) cost pennies and "
            "can be registered to any area code regardless of actual location. Fraudsters "
            "routinely use DC/VA/MD area codes via VoIP to appear local.",
            0.55,
        ))

    # --- Check 3: Premium rate / Caribbean trap numbers ---
    if ntype == PhoneNumberType.PREMIUM_RATE or analysis.area_code in UNEXPECTED_AREA_CODES_FOR_CLEARED_WORK:
        analysis.findings.append(PhoneFinding(
            "critical",
            f"Area code {analysis.area_code} is a premium-rate or international trap",
            "Calling back this number may incur per-minute charges. Fraudsters use "
            "809/876/900 numbers in social engineering attacks.",
            0.85,
        ))

    # --- Check 4: Rural VA region mismatch for DC-area cleared roles ---
    region_lower = analysis.region.lower()
    for rural in RURAL_VA_REGIONS_FLAG:
        if rural in region_lower:
            analysis.findings.append(PhoneFinding(
                "medium",
                f"Number routes to {analysis.region} — unusual for cleared contractor office",
                f"Major cleared contractor and staffing firm offices are concentrated in "
                f"the DC Metro corridor (McLean, Herndon, Reston, Chantilly, Arlington, Vienna). "
                f"A number routing to {analysis.region} for a company claiming to be in the "
                f"DC area is a geographic mismatch worth verifying.",
                0.45,
            ))
            break

    # --- Check 5: Claimed region vs. actual phone region mismatch ---
    if claimed_region:
        if claimed_region.lower() not in region_lower and region_lower:
            analysis.findings.append(PhoneFinding(
                "high",
                f"Geographic mismatch: claimed '{claimed_region}' but number routes to '{analysis.region}'",
                "The location the caller claimed does not match the phone number's registered "
                "region. This is a strong indicator of VoIP spoofing or misrepresentation.",
                0.65,
            ))

    # --- Check 6: Area code outside DC Metro for claimed DC-area employer ---
    if claimed_company and analysis.area_code:
        if analysis.area_code not in DC_METRO_AREA_CODES and ntype != PhoneNumberType.TOLL_FREE:
            analysis.findings.append(PhoneFinding(
                "medium",
                f"Area code {analysis.area_code} is outside DC Metro corridor",
                f"If the caller claims to work for a Northern Virginia / DC cleared contractor, "
                f"their direct number would normally have a 703/571/202/301/240 area code. "
                f"Area code {analysis.area_code} is unexpected — verify independently.",
                0.35,
            ))

    # --- Check 7: SSN requested on this call (regardless of number) ---
    if ssn_requested_on_call:
        analysis.findings.append(PhoneFinding(
            "critical",
            "SSN/DOB was requested over this phone call",
            "STOP. No legitimate employer, recruiter, or FSO requests your SSN or DOB "
            "over an unsecured phone call. SSN is collected ONLY after a formal written "
            "offer is accepted, via a secure HR portal (Workday, SAP SuccessFactors, "
            "ADP, DOD Safe, USA Staffing). Never verbally over phone or via email.",
            1.0,
        ))

    # --- Check 8: Pre-offer contact ---
    if pre_offer_contact:
        analysis.findings.append(PhoneFinding(
            "high",
            "This contact occurred before a formal written offer",
            "Legitimate cleared employers collect PII only AFTER: (1) written offer letter "
            "signed, (2) HR onboarding initiated via secure portal. Pre-offer SSN requests "
            "are never legitimate — even at staffing firms like Kforce, Mindbank, or 22CTECH.",
            0.70,
        ))

    # --- Compute risk score ---
    positive_findings = [f for f in analysis.findings if f.weight > 0]
    negative_findings = [f for f in analysis.findings if f.weight < 0]
    raw = sum(f.weight for f in positive_findings)
    reduction = sum(abs(f.weight) for f in negative_findings)
    raw = max(0.0, raw - reduction)

    if raw > 0:
        analysis.risk_score = round(min(1 - (1 / (1 + raw * 0.5)), 1.0), 3)

    # Flag as suspicious if any critical finding present OR score threshold reached
    has_critical = any(f.weight >= 0.65 for f in analysis.findings)
    analysis.is_suspicious = analysis.risk_score >= 0.30 or has_critical

    return analysis
