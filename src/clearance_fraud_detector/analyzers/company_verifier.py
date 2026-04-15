"""
Company Verification Module — CAGE Code + FCL + Domain Validator.

Provides verification tools for determining whether a claimed employer is a
legitimate cleared contractor. Uses local data (known_contractors.py,
known_staffing_firms.py) plus heuristic checks.

Key verification axes:
  1. CAGE code — 5-character DoD contractor identifier (verify at sam.gov)
  2. FCL (Facility Clearance Level) — contractor's authorization to work on classified
  3. Domain legitimacy — matches pattern vs known legitimate domains
  4. Company name fuzzy check — against LEGITIMATE_CONTRACTORS
  5. Evasion signals — refusal to provide CAGE/FCL is itself a red flag

Authoritative lookups (requires network, not done here — user-guidance provided):
  SAM.gov (system for award management): https://sam.gov/search/?index=cf
  DCSA FCL status: https://www.dcsa.mil/ms/ctp/fso/
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from clearance_fraud_detector.data.known_contractors import (
    LEGITIMATE_CONTRACTORS,
    KNOWN_FAKE_RECRUITING_DOMAINS,
    LEGITIMATE_JOB_BOARDS,
    ALL_LEGITIMATE_DOMAINS,
)


# ---------------------------------------------------------------------------
# Try importing staffing firms — fall back gracefully if not yet present
# ---------------------------------------------------------------------------
try:
    from clearance_fraud_detector.data.known_staffing_firms import (
        KNOWN_STAFFING_FIRMS,
        STAFFING_FIRM_DOMAINS,
        FLAGGED_STAFFING_FIRMS,
    )
    _HAS_STAFFING_DATA = True
except ImportError:
    KNOWN_STAFFING_FIRMS = {}
    STAFFING_FIRM_DOMAINS = {}
    FLAGGED_STAFFING_FIRMS = []
    _HAS_STAFFING_DATA = False


@dataclass
class VerificationFlag:
    level: str          # "green" | "yellow" | "red"
    message: str
    guidance: str = ""


@dataclass
class CompanyVerificationReport:
    company_name: str
    domain: str = ""
    cage_code_provided: str = ""

    flags: list[VerificationFlag] = field(default_factory=list)
    is_in_legitimate_list: bool = False
    is_in_staffing_list: bool = False
    is_flagged_firm: bool = False
    is_known_fake_domain: bool = False
    is_legitimate_domain: bool = False
    sam_gov_url: str = ""
    manual_checks: list[str] = field(default_factory=list)

    @property
    def red_flags(self) -> list[VerificationFlag]:
        return [f for f in self.flags if f.level == "red"]

    @property
    def yellow_flags(self) -> list[VerificationFlag]:
        return [f for f in self.flags if f.level == "yellow"]

    @property
    def green_flags(self) -> list[VerificationFlag]:
        return [f for f in self.flags if f.level == "green"]

    @property
    def overall_risk(self) -> str:
        if self.is_flagged_firm or self.is_known_fake_domain:
            return "HIGH"
        if len(self.red_flags) >= 2:
            return "HIGH"
        if len(self.red_flags) == 1:
            return "MEDIUM"
        if self.is_in_legitimate_list or self.is_in_staffing_list:
            return "LOW"
        if len(self.yellow_flags) >= 2:
            return "MEDIUM"
        return "LOW"

    def summary(self) -> str:
        lines = [f"Company Verification: {self.company_name} — Risk: {self.overall_risk}"]
        for f in self.red_flags:
            lines.append(f"  [RED]    {f.message}")
        for f in self.yellow_flags:
            lines.append(f"  [YELLOW] {f.message}")
        for f in self.green_flags:
            lines.append(f"  [GREEN]  {f.message}")
        if self.manual_checks:
            lines.append("  Manual verification steps:")
            for m in self.manual_checks:
                lines.append(f"    → {m}")
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# CAGE code format validation
# ---------------------------------------------------------------------------
_CAGE_PATTERN = re.compile(r"^[0-9A-Z]{5}$", re.IGNORECASE)


def _is_valid_cage_format(cage: str) -> bool:
    """CAGE codes are exactly 5 alphanumeric characters."""
    return bool(_CAGE_PATTERN.match(cage.strip()))


# ---------------------------------------------------------------------------
# Evasion pattern detection
# ---------------------------------------------------------------------------
_CAGE_EVASION_PATTERNS = [
    re.compile(r"(cage\s*code|fcl).{0,60}(confidential|proprietary|not\s+(share|disclose|provide|give))", re.IGNORECASE),
    re.compile(r"(can.?t|cannot|won.?t|unable\s+to).{0,40}(provide|share|disclose|give).{0,40}(cage|fcl|facility\s+clearance)", re.IGNORECASE),
    re.compile(r"(don.?t|do\s+not|won.?t)\s+(have|know|provide).{0,30}(cage|fcl)", re.IGNORECASE),
]

_SSN_BEFORE_OFFER_PATTERNS = [
    re.compile(r"(ssn|social\s+security).{0,80}(before|prior\s+to|ahead\s+of).{0,40}(offer|hire|onboard)", re.IGNORECASE),
    re.compile(r"(provide|send|give|share).{0,40}(ssn|social\s+security).{0,60}(verify|confirm|check).{0,40}clearance", re.IGNORECASE),
]

_OFFER_CONDITIONED_SSN_PATTERNS = [
    re.compile(r"(offer|proceed|move\s+forward).{0,60}(conditional|contingent|depend).{0,40}(ssn|social\s+security|pii)", re.IGNORECASE),
    re.compile(r"(ssn|social\s+security).{0,60}(before\s+we\s+can\s+(make|issue|extend)\s+(an?\s+)?(offer|offer\s+letter))", re.IGNORECASE),
    # Offer withheld until SSN provided (any order)
    re.compile(r"(extend|make|issue|send).{0,30}(an?\s+)?offer.{0,60}until.{0,30}(provide|send|give|share).{0,30}(ssn|social\s+security)", re.IGNORECASE),
    re.compile(r"(ssn|social\s+security).{0,80}(before|until|prior).{0,30}(offer|hire|onboard|start)", re.IGNORECASE),
    re.compile(r"(cannot|can\'t|won\'t|unable).{0,30}(offer|proceed|move).{0,50}(until|without).{0,30}(ssn|social\s+security)", re.IGNORECASE),
]


def verify_company(
    company_name: str,
    domain: str = "",
    cage_code: str = "",
    interaction_text: str = "",
) -> CompanyVerificationReport:
    """
    Verify a company's legitimacy from available signals.

    Args:
        company_name:     The name as presented (e.g. "Mindbank Consulting Group")
        domain:           Email or website domain (e.g. "mindbankcg.com")
        cage_code:        CAGE code if provided by the recruiter
        interaction_text: Any text from the interaction containing red flags

    Returns:
        CompanyVerificationReport with risk level and verification guidance.
    """
    report = CompanyVerificationReport(
        company_name=company_name,
        domain=domain.lower().strip(),
        cage_code_provided=cage_code.strip().upper(),
    )

    name_lower = company_name.lower().strip()

    # ---- 1. Check legitimate contractors list --------------------------------
    # Use word-boundary match to prevent short names (e.g. "RAND") from
    # spuriously matching substrings inside unrelated company names.
    import re as _re
    for canonical_name, known_domains in LEGITIMATE_CONTRACTORS.items():
        _cn = canonical_name.lower()
        _name_match = (
            bool(_re.search(r'\b' + _re.escape(_cn) + r'\b', name_lower))
            or bool(_re.search(r'\b' + _re.escape(name_lower) + r'\b', _cn))
            or (domain and domain in known_domains)
        )
        if _name_match:
            report.is_in_legitimate_list = True
            report.flags.append(VerificationFlag(
                level="green",
                message=f"'{canonical_name}' found in verified prime contractor database",
                guidance="This is a known prime contractor. Always independently confirm domain matches.",
            ))
            break

    # ---- 2. Check staffing firms list ----------------------------------------
    if _HAS_STAFFING_DATA:
        for firm_name, firm_data in KNOWN_STAFFING_FIRMS.items():
            if firm_name.lower() in name_lower or name_lower in firm_name.lower():
                report.is_in_staffing_list = True
                if firm_name in FLAGGED_STAFFING_FIRMS:
                    report.is_flagged_firm = True
                    report.flags.append(VerificationFlag(
                        level="red",
                        message=f"'{firm_name}' is in flagged staffing firms database",
                        guidance="Review the specific fraud indicators for this firm.",
                    ))
                else:
                    report.flags.append(VerificationFlag(
                        level="yellow",
                        message=f"'{firm_name}' is a known staffing intermediary",
                        guidance="Staffing firms cannot initiate clearance actions — only the prime contractor's FSO can.",
                    ))
                break

    # ---- 3. Check domain against known fakes ---------------------------------
    if domain:
        for fake_domain in KNOWN_FAKE_RECRUITING_DOMAINS:
            if domain == fake_domain or domain.endswith(f".{fake_domain}"):
                report.is_known_fake_domain = True
                report.flags.append(VerificationFlag(
                    level="red",
                    message=f"Domain '{domain}' is in the known fake recruiting domains list",
                    guidance="Do not provide any personal information. Report to DCSA.",
                ))
                break

        if not report.is_known_fake_domain:
            if domain in ALL_LEGITIMATE_DOMAINS:
                report.is_legitimate_domain = True
                report.flags.append(VerificationFlag(
                    level="green",
                    message=f"Domain '{domain}' matches a verified contractor domain",
                ))
            elif domain in LEGITIMATE_JOB_BOARDS:
                report.flags.append(VerificationFlag(
                    level="green",
                    message=f"Domain '{domain}' is a legitimate job board",
                ))
            else:
                report.flags.append(VerificationFlag(
                    level="yellow",
                    message=f"Domain '{domain}' is not in verified contractor lists",
                    guidance="Look up domain registration date on whois.domaintools.com — fraud domains are often < 1 year old.",
                ))

    # ---- 4. CAGE code checks --------------------------------------------------
    if cage_code:
        if _is_valid_cage_format(cage_code):
            report.flags.append(VerificationFlag(
                level="yellow",
                message=f"CAGE code '{cage_code}' has valid format — manual verification required",
                guidance=f"Verify at: https://sam.gov/search/?index=cf&q={cage_code.strip()}",
            ))
            report.sam_gov_url = f"https://sam.gov/search/?index=cf&q={cage_code.strip()}"
        else:
            report.flags.append(VerificationFlag(
                level="red",
                message=f"Provided CAGE code '{cage_code}' has invalid format (must be 5 alphanumeric chars)",
            ))
    else:
        report.flags.append(VerificationFlag(
            level="yellow",
            message="No CAGE code provided — request one before sharing any information",
            guidance="Every cleared contractor has a CAGE code registered at sam.gov. Refusal to provide is a red flag.",
        ))

    # ---- 5. Scan interaction text for red-flag patterns ----------------------
    if interaction_text:
        for pattern in _CAGE_EVASION_PATTERNS:
            if pattern.search(interaction_text):
                report.flags.append(VerificationFlag(
                    level="red",
                    message="CAGE code or FCL refusal detected in interaction text",
                    guidance="Legitimate contractors provide their CAGE code on request. This is a fraud indicator.",
                ))
                break

        for pattern in _SSN_BEFORE_OFFER_PATTERNS:
            if pattern.search(interaction_text):
                report.flags.append(VerificationFlag(
                    level="red",
                    message="SSN requested before written offer — violates 32 CFR §117.10(f)(1)",
                    guidance="Do not provide SSN. Request written offer first.",
                ))
                break

        for pattern in _OFFER_CONDITIONED_SSN_PATTERNS:
            if pattern.search(interaction_text):
                report.flags.append(VerificationFlag(
                    level="red",
                    message="Offer conditioned on SSN provision — this is a fraud indicator and NISPOM violation",
                    guidance="A legitimate offer letter does not require SSN as a precondition. SSN goes into eApp post-offer.",
                ))
                break

    # ---- 6. Build manual verification checklist ------------------------------
    if not report.is_in_legitimate_list and not report.is_in_staffing_list:
        report.manual_checks.append(
            f"Search SAM.gov: https://sam.gov/search/?index=cf&q={company_name.replace(' ', '+')}"
        )
    if not cage_code:
        report.manual_checks.append(
            "Ask recruiter: 'Can you provide your company's CAGE code? I will verify it on SAM.gov.'"
        )
    if domain and not report.is_legitimate_domain:
        report.manual_checks.append(
            f"Check domain age: https://whois.domaintools.com/{domain}"
        )
    report.manual_checks.append(
        "Search DCSA contractor verification: https://www.dcsa.mil/ms/ctp/fso/"
    )
    if not report.is_in_legitimate_list:
        report.manual_checks.append(
            "Call the company's main published number — not the number the recruiter gave you"
        )

    return report
