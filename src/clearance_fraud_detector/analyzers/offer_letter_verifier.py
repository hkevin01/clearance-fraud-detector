"""
Offer Letter Verifier — Detects fake or fraudulent offer letters in cleared hiring.

Analyzes an offer letter (text or parsed email) for the hallmarks of a
fraudulent offer used to extract SSN by making it appear the §117.10(f)(1)
preconditions have been met.

Key fraud pattern: Attacker sends a convincing-looking offer letter that
contains an SSN field, conditions the offer on providing SSN "for clearance
processing," or lacks verifiable company identifiers (CAGE, EIN, address).

Legitimate offer letter checklist (all must be present):
  ✓ Company legal name matching a verifiable SAM.gov / Secretary of State record
  ✓ Company EIN (not required on offer letter but present on W-4 later — absence is neutral)
  ✓ Physical company address
  ✓ Signing authority name and title
  ✓ Job title, salary/rate, start date
  ✓ HR or legal email on company domain (NOT gmail/yahoo/hotmail)
  ✗ SSN field ON the offer letter (red flag — SSN goes to eApp, not offer letter)
  ✗ Offer conditioned on SSN provision (red flag — §117.10(d) violation)
  ✗ "Clearance processing" language tying SSN to acceptance (red flag)
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field


@dataclass
class OfferLetterFlag:
    level: str          # "red" | "yellow" | "green"
    field_name: str     # What was checked
    message: str
    rule: str = ""      # CFR citation if applicable


@dataclass
class OfferLetterAnalysis:
    flags: list[OfferLetterFlag] = field(default_factory=list)
    has_ssn_field: bool = False
    has_physical_address: bool = False
    has_signing_authority: bool = False
    has_company_domain_email: bool = False
    has_job_title: bool = False
    has_start_date: bool = False
    has_salary: bool = False
    ssn_conditioned: bool = False
    free_email_domain: bool = False
    cage_mentioned: bool = False
    overall_risk: str = "UNKNOWN"

    @property
    def red_flags(self) -> list[OfferLetterFlag]:
        return [f for f in self.flags if f.level == "red"]

    @property
    def yellow_flags(self) -> list[OfferLetterFlag]:
        return [f for f in self.flags if f.level == "yellow"]

    @property
    def green_flags(self) -> list[OfferLetterFlag]:
        return [f for f in self.flags if f.level == "green"]

    @property
    def legitimacy_score(self) -> float:
        """0.0 = very suspicious, 1.0 = all legitimate signals present."""
        green_count = len(self.green_flags)
        red_count = len(self.red_flags)
        if red_count >= 2:
            return max(0.0, 0.3 - (red_count * 0.1))
        return min(1.0, green_count * 0.17)

    def summary(self) -> str:
        lines = [f"Offer Letter Analysis — Risk: {self.overall_risk}"]
        for f in self.red_flags:
            lines.append(f"  [RED]    {f.field_name}: {f.message}")
        for f in self.yellow_flags:
            lines.append(f"  [YELLOW] {f.field_name}: {f.message}")
        for f in self.green_flags:
            lines.append(f"  [GREEN]  {f.field_name}: {f.message}")
        lines.append(f"  Legitimacy score: {self.legitimacy_score:.0%}")
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Detection patterns
# ---------------------------------------------------------------------------

# SSN field ON the offer letter itself — this is the fraud tell
_SSN_ON_OFFER_PATTERNS = [
    re.compile(r"social\s+security\s+(number|#|no\.?)\s*:", re.IGNORECASE),
    re.compile(r"\bssn\s*:", re.IGNORECASE),
    re.compile(r"please\s+(provide|fill\s+in|enter|complete).{0,40}(ssn|social\s+security)", re.IGNORECASE),
    re.compile(r"(ssn|social\s+security).{0,60}(required|mandatory|must|need)", re.IGNORECASE),
]

# Offer conditioned on SSN — the §117.10(d) violation
_SSN_CONDITION_PATTERNS = [
    re.compile(
        r"(offer|employment|start|onboard).{0,80}"
        r"(conditional|contingent|subject\s+to|upon\s+receipt).{0,60}"
        r"(ssn|social\s+security|pii|background\s+check)",
        re.IGNORECASE | re.DOTALL,
    ),
    re.compile(
        r"(clearance\s+processing|clearance\s+verification|eapp|sf.?86).{0,100}"
        r"(ssn|social\s+security).{0,100}(required\s+before|needed\s+before|prior\s+to\s+start)",
        re.IGNORECASE | re.DOTALL,
    ),
    re.compile(
        r"(provide|submit|send).{0,30}(ssn|social\s+security).{0,60}"
        r"(to\s+(complete|finalize|process|accept)\s+(this\s+)?(offer|employment|onboard))",
        re.IGNORECASE,
    ),
    re.compile(
        r"(cannot|won.?t|will\s+not).{0,30}(process|finalize|activate|begin).{0,60}"
        r"(without|until).{0,30}(ssn|social\s+security)",
        re.IGNORECASE,
    ),
]

# Physical address signals
_ADDRESS_PATTERNS = [
    re.compile(r"\b\d{3,5}\s+\w+\s+(street|st|avenue|ave|road|rd|blvd|boulevard|drive|dr|lane|ln|way|court|ct|place|pl|suite|ste)\b", re.IGNORECASE),
    re.compile(r"\b[A-Z][a-z]+,\s+[A-Z]{2}\s+\d{5}\b"),  # City, ST 12345
]

# Signing authority — a real offer has a named human signing it
_SIGNING_AUTHORITY_PATTERNS = [
    re.compile(r"(sincerely|regards|respectfully|authorized\s+by|signed\s+by|on\s+behalf\s+of),?\s*\n\s*[A-Z][a-z]+\s+[A-Z][a-z]+", re.MULTILINE),
    re.compile(r"(vp|vice\s+president|director|manager|officer|hr|human\s+resources|recruiter|ceo|cto)\s*[,\n]", re.IGNORECASE),
]

# Company domain email — not gmail/yahoo/hotmail
_FREE_EMAIL_DOMAINS = {
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "icloud.com",
    "aol.com", "mail.com", "protonmail.com", "tutanota.com",
    "yandex.com", "zoho.com", "live.com", "msn.com",
}
_EMAIL_PATTERN = re.compile(r"[\w.+-]+@([\w-]+\.[\w.-]+)", re.IGNORECASE)

# Salary/compensation
_SALARY_PATTERNS = [
    re.compile(r"\$\s*[\d,]+(?:\.\d{2})?(?:\s*(?:per\s+)?(?:year|yr|hour|hr|month|annually))?", re.IGNORECASE),
    re.compile(r"(salary|compensation|rate|pay).{0,30}\$", re.IGNORECASE),
    re.compile(r"(annual|hourly|monthly)\s+(salary|compensation|rate)", re.IGNORECASE),
]

# Job title
_JOB_TITLE_PATTERNS = [
    re.compile(r"(position|title|role)\s*:\s*\S", re.IGNORECASE),
    re.compile(r"(you\s+(have\s+been|are)\s+(offered|selected|hired)\s+(for\s+(the\s+)?position\s+of|as))", re.IGNORECASE),
    re.compile(r"(this\s+(offer|letter)\s+is\s+for\s+the\s+(position|role)\s+of)", re.IGNORECASE),
]

# Start date
_START_DATE_PATTERNS = [
    re.compile(r"(start|commencement|first\s+day|begin).{0,40}(date|on\s+or\s+about|january|february|march|april|may|june|july|august|september|october|november|december|\d{1,2}/\d{1,2}/\d{2,4})", re.IGNORECASE),
    re.compile(r"(effective|starting|beginning).{0,20}(date|\d{1,2}/\d{1,2}|\w+\s+\d{1,2},?\s+\d{4})", re.IGNORECASE),
]

# CAGE code mention (positive signal — shows company is SAM-registered)
_CAGE_PATTERN = re.compile(r"cage\s*(code)?\s*:?\s*[0-9A-Z]{5}", re.IGNORECASE)

# Urgency pressure (red flag on offer letter)
_URGENCY_PATTERNS = [
    re.compile(r"(respond\s+immediately|reply\s+within\s+\d+\s+hours?|expires?\s+(today|tonight|in\s+\d+\s+hours?))", re.IGNORECASE),
    re.compile(r"(urgent|asap|as\s+soon\s+as\s+possible).{0,40}(accept|sign|return|provide)", re.IGNORECASE),
]

# Legitimate eApp/SF-86 reference (positive — shows proper process awareness)
_EAPP_REFERENCE_PATTERNS = [
    re.compile(r"eapp\.nbis\.mil|nbis\s+eapp|e-?qip", re.IGNORECASE),
    re.compile(r"(sf.?86|sf\s*86)\s+(will\s+be\s+(sent|initiated|provided)|through\s+(eapp|nbis))", re.IGNORECASE),
    re.compile(r"(facility\s+security\s+officer|fso)\s+(will|shall).{0,60}(initiat|contact|invite|eapp)", re.IGNORECASE),
]


def verify_offer_letter(text: str, sender_email: str = "") -> OfferLetterAnalysis:
    """
    Analyze an offer letter for authenticity indicators.

    Args:
        text:         Full text of the offer letter.
        sender_email: Email address the offer came from (optional, improves analysis).

    Returns:
        OfferLetterAnalysis with all flags and overall risk level.
    """
    analysis = OfferLetterAnalysis()

    # ---- SSN ON THE OFFER LETTER (critical red flag) -------------------------
    for p in _SSN_ON_OFFER_PATTERNS:
        if p.search(text):
            analysis.has_ssn_field = True
            analysis.flags.append(OfferLetterFlag(
                level="red",
                field_name="SSN on offer letter",
                message="SSN field present on offer letter. SSN never goes on an offer letter — it goes into NBIS eApp post-acceptance.",
                rule="32 CFR §117.10(d)",
            ))
            break

    # ---- OFFER CONDITIONED ON SSN (critical red flag) -----------------------
    for p in _SSN_CONDITION_PATTERNS:
        if p.search(text):
            analysis.ssn_conditioned = True
            analysis.flags.append(OfferLetterFlag(
                level="red",
                field_name="SSN as offer condition",
                message="Offer letter conditions employment on providing SSN. §117.10(d) requires SSN go into NBIS eApp directly — the offer letter cannot demand it.",
                rule="32 CFR §117.10(d) and §117.10(f)(1)(i)-(ii)",
            ))
            break

    # ---- PHYSICAL ADDRESS ---------------------------------------------------
    if any(p.search(text) for p in _ADDRESS_PATTERNS):
        analysis.has_physical_address = True
        analysis.flags.append(OfferLetterFlag(
            level="green",
            field_name="Physical address",
            message="Physical office address present — verifiable against SAM.gov and Google Maps.",
        ))
    else:
        analysis.flags.append(OfferLetterFlag(
            level="yellow",
            field_name="Physical address",
            message="No physical address detected. Verify company address independently at sam.gov.",
        ))

    # ---- SIGNING AUTHORITY --------------------------------------------------
    if any(p.search(text) for p in _SIGNING_AUTHORITY_PATTERNS):
        analysis.has_signing_authority = True
        analysis.flags.append(OfferLetterFlag(
            level="green",
            field_name="Signing authority",
            message="Named signatory with title present.",
        ))
    else:
        analysis.flags.append(OfferLetterFlag(
            level="yellow",
            field_name="Signing authority",
            message="No clear named signatory with title. A legitimate offer has a real person's name and title.",
        ))

    # ---- EMAIL DOMAIN -------------------------------------------------------
    emails_found = _EMAIL_PATTERN.findall(text)
    if sender_email:
        m = _EMAIL_PATTERN.search(sender_email)
        if m:
            emails_found.append(m.group(1))

    free_email_found = False
    for domain in emails_found:
        domain_clean = domain.lower().strip()
        if domain_clean in _FREE_EMAIL_DOMAINS:
            free_email_found = True
            analysis.free_email_domain = True
            analysis.flags.append(OfferLetterFlag(
                level="red",
                field_name="Email domain",
                message=f"Free email domain detected: @{domain_clean}. Legitimate defense contractors use corporate domains.",
            ))
            break

    if not free_email_found and emails_found:
        analysis.has_company_domain_email = True
        analysis.flags.append(OfferLetterFlag(
            level="green",
            field_name="Email domain",
            message=f"Corporate email domain in use: @{emails_found[0]}",
        ))
    elif not emails_found:
        analysis.flags.append(OfferLetterFlag(
            level="yellow",
            field_name="Email domain",
            message="No email address found in offer text. Verify sender domain independently.",
        ))

    # ---- JOB TITLE ----------------------------------------------------------
    if any(p.search(text) for p in _JOB_TITLE_PATTERNS):
        analysis.has_job_title = True
        analysis.flags.append(OfferLetterFlag(level="green", field_name="Job title", message="Specific position identified."))
    else:
        analysis.flags.append(OfferLetterFlag(level="yellow", field_name="Job title", message="No clear job title. A real offer names the specific role."))

    # ---- SALARY / COMPENSATION ----------------------------------------------
    if any(p.search(text) for p in _SALARY_PATTERNS):
        analysis.has_salary = True
        analysis.flags.append(OfferLetterFlag(level="green", field_name="Compensation", message="Salary or rate stated."))
    else:
        analysis.flags.append(OfferLetterFlag(level="yellow", field_name="Compensation", message="No salary or rate detected. Real offers state compensation."))

    # ---- START DATE ---------------------------------------------------------
    if any(p.search(text) for p in _START_DATE_PATTERNS):
        analysis.has_start_date = True
        analysis.flags.append(OfferLetterFlag(level="green", field_name="Start date", message="Start date referenced."))
    else:
        analysis.flags.append(OfferLetterFlag(level="yellow", field_name="Start date", message="No start date detected."))

    # ---- CAGE CODE MENTION --------------------------------------------------
    if _CAGE_PATTERN.search(text):
        analysis.cage_mentioned = True
        analysis.flags.append(OfferLetterFlag(
            level="green",
            field_name="CAGE code",
            message="CAGE code present — verify at sam.gov to confirm company identity.",
        ))

    # ---- URGENCY PRESSURE ---------------------------------------------------
    for p in _URGENCY_PATTERNS:
        if p.search(text):
            analysis.flags.append(OfferLetterFlag(
                level="red",
                field_name="Urgency pressure",
                message="Unusual urgency to accept/sign detected. Legitimate offers give reasonable review time.",
            ))
            break

    # ---- PROPER eAPP REFERENCE (positive) -----------------------------------
    if any(p.search(text) for p in _EAPP_REFERENCE_PATTERNS):
        analysis.flags.append(OfferLetterFlag(
            level="green",
            field_name="eApp / NBIS process",
            message="References NBIS eApp or FSO-initiated process — correct channel awareness.",
        ))

    # ---- OVERALL RISK -------------------------------------------------------
    red_count = len(analysis.red_flags)
    green_count = len(analysis.green_flags)

    if red_count >= 2:
        analysis.overall_risk = "HIGH"
    elif red_count == 1:
        analysis.overall_risk = "MEDIUM"
    elif green_count >= 4:
        analysis.overall_risk = "LOW"
    else:
        analysis.overall_risk = "MEDIUM"

    return analysis
