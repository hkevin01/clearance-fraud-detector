"""
Violation Explainer — Maps detected fraud signals to 32 CFR §117.10 citations.

Takes any combination of FraudScore, ContactAnalysis, or plain text and
produces a human-readable, citation-backed explanation of:
  - What regulation was violated
  - The verbatim rule text
  - What the correct process should have been
  - How to respond to the recruiter/FSO
  - Which agency to report to

Designed to be usable standalone (CLI output) or embedded in a report.
"""
from __future__ import annotations

from dataclasses import dataclass, field


# ---------------------------------------------------------------------------
# Master citation table — every §117.10 subsection relevant to cleared hiring
# ---------------------------------------------------------------------------
CITATION_TABLE: dict[str, dict] = {
    "117.10(a)(5)": {
        "rule": "32 CFR §117.10(a)(5)",
        "url": "https://www.ecfr.gov/current/title-32/section-117.10#p-117.10(a)(5)",
        "verbatim": (
            "The contractor will limit requests for determinations of eligibility for access "
            "to classified information to the minimum number of employees and consultants "
            "necessary for operational efficiency in accordance with contractual obligations. "
            "Requests for determinations of eligibility for access to classified information "
            "will not be used to establish a cache of cleared employees."
        ),
        "plain_english": (
            "A clearance request must be tied to a specific, active contract requirement. "
            "You cannot collect SSNs from a pool of candidates to build a reserve of pre-cleared "
            "personnel. Every clearance action must align to a current staffing need."
        ),
        "correct_process": (
            "The contractor identifies a specific contract requirement, identifies a specific "
            "employee to fill it, issues a written offer, receives written acceptance, and then "
            "initiates a clearance action for that one employee for that one requirement."
        ),
        "response_script": (
            "\"I'm familiar with §117.10(a)(5). Clearance requests must be tied to a specific "
            "contractual requirement, not used to establish a cleared candidate pool. Can you "
            "provide the contract number and position this clearance action is tied to?\""
        ),
        "report_to": "DCSA Industry Hotline: (888) 282-0811",
        "keywords": ["cache", "pool", "bench", "pipeline", "everyone else", "standard practice",
                     "common practice", "all candidates", "industry standard"],
    },
    "117.10(a)(7)": {
        "rule": "32 CFR §117.10(a)(7)",
        "url": "https://www.ecfr.gov/current/title-32/section-117.10#p-117.10(a)(7)",
        "verbatim": (
            "Contractors will not submit requests for determination of eligibility for access "
            "to classified information for individuals who are not their employees or consultants; "
            "nor will they submit requests for employees of subcontractors."
        ),
        "plain_english": (
            "The word in the regulation is 'employees' — not candidates, not applicants, not "
            "prospects. A clearance action cannot begin until an employment relationship exists. "
            "A staffing firm cannot run clearance checks on candidates they're trying to place. "
            "This rule also bars prime contractors from running clearance checks on subcontractor staff."
        ),
        "correct_process": (
            "Employment offer issued → written acceptance received → employee onboarded → "
            "FSO initiates clearance action. The key gate is the employment relationship. "
            "No offer accepted = no authority to touch DISS."
        ),
        "response_script": (
            "\"Under 32 CFR §117.10(a)(7), clearance requests cannot be submitted for individuals "
            "who are not employees. Until I have accepted a written offer and am on your payroll, "
            "you have no authority under NISPOM to initiate any clearance action on my behalf.\""
        ),
        "report_to": "DCSA Counterintelligence: (571) 305-6576",
        "keywords": ["verify clearance", "check diss", "look up clearance", "confirm clearance",
                     "clearance status", "eligibility check", "before offer", "pre-offer"],
    },
    "117.10(d)": {
        "rule": "32 CFR §117.10(d)",
        "url": "https://www.ecfr.gov/current/title-32/section-117.10#p-117.10(d)",
        "verbatim": (
            "The electronic version of the SF 86, Questionnaire for National Security Positions, "
            "must be completed in e-QIP or its successor system by the contractor employee and "
            "reviewed by the FSO. The FSO will: (1) Provide the employee with written notification "
            "that review of the SF 86 by the FSO for adequacy and completeness and information will "
            "be used for no other purpose within the entity. (2) Not share information from the "
            "employee's SF 86 within the entity and will not use the information for any purpose "
            "other than determining the adequacy and completeness of the SF 86."
        ),
        "plain_english": (
            "SF-86 data (including SSN) goes into NBIS eApp directly — typed by the employee. "
            "It never travels from the employee to the FSO as raw text via email, phone, DOD SAFE, "
            "or any other channel. The FSO sees it in eApp only to check completeness. "
            "The FSO is legally prohibited from using or sharing any SF-86 data for any other purpose."
        ),
        "correct_process": (
            "1) FSO sends an eApp invitation link to the employee's personal email.\n"
            "2) Employee logs into eapp.nbis.mil and completes the SF-86 directly.\n"
            "3) FSO reviews in eApp for completeness only.\n"
            "4) FSO submits to DCSA through DISS — SSN never leaves eApp as raw text."
        ),
        "response_script": (
            "\"Under 32 CFR §117.10(d), SSN and SF-86 data must be entered directly by me into "
            "NBIS eApp at eapp.nbis.mil. Please have your FSO send me the eApp invitation. "
            "I will not transmit my SSN via email, phone, DOD SAFE, or any other channel.\""
        ),
        "report_to": "DCSA Industry Hotline: (888) 282-0811 / FBI IC3: ic3.gov",
        "keywords": ["email ssn", "send ssn", "dod safe", "call me back", "text ssn",
                     "provide ssn", "phone ssn", "fax ssn", "whatsapp", "telegram"],
    },
    "117.10(f)(1)(i)": {
        "rule": "32 CFR §117.10(f)(1)(i)",
        "url": "https://www.ecfr.gov/current/title-32/section-117.10#p-117.10(f)(1)(i)",
        "verbatim": (
            "If a potential employee requires access to classified information immediately upon "
            "commencement of employment, the contractor may submit a request for investigation "
            "prior to the date of employment, provided: (i) A written commitment for employment "
            "has been made by the contractor."
        ),
        "plain_english": (
            "Before any clearance action, the contractor must have issued a written offer letter. "
            "Not a phone call. Not an email saying 'we want to move forward.' A formal written "
            "commitment of employment. This is a hard prerequisite — no written offer = no authority "
            "to initiate any clearance process step."
        ),
        "correct_process": (
            "Recruiter identifies candidate → hiring manager approves → HR issues written offer "
            "letter → candidate reviews and signs → only after signed offer in hand can the FSO "
            "initiate any clearance action."
        ),
        "response_script": (
            "\"Under 32 CFR §117.10(f)(1)(i), a written offer letter from your company must exist "
            "before any clearance action can be initiated. Please send the written offer first. "
            "Once I have reviewed and accepted it in writing, I'm happy to proceed through the "
            "proper eApp channel.\""
        ),
        "report_to": "DCSA Industry Hotline: (888) 282-0811",
        "keywords": ["before offer", "prior to offer", "before we can make an offer",
                     "screening", "pre-offer", "before employment"],
    },
    "117.10(f)(1)(ii)": {
        "rule": "32 CFR §117.10(f)(1)(ii)",
        "url": "https://www.ecfr.gov/current/title-32/section-117.10#p-117.10(f)(1)(ii)",
        "verbatim": (
            "If a potential employee requires access to classified information immediately upon "
            "commencement of employment, the contractor may submit a request for investigation "
            "prior to the date of employment, provided: (ii) The candidate has accepted the "
            "offer in writing."
        ),
        "plain_english": (
            "Written offer alone is not enough. The candidate must have also accepted in writing "
            "before any clearance action begins. Both §117.10(f)(1)(i) AND (f)(1)(ii) must be "
            "satisfied simultaneously. Verbal acceptance does not count."
        ),
        "correct_process": (
            "Written offer issued → candidate countersigns offer letter → both parties have "
            "signed copies → THEN the FSO may initiate the eApp invitation."
        ),
        "response_script": (
            "\"Per §117.10(f)(1)(ii), I must have accepted the offer in writing before any "
            "clearance process step begins. Please provide the written offer. Once I countersign "
            "and return it, your FSO can initiate the eApp invitation.\""
        ),
        "report_to": "DCSA Industry Hotline: (888) 282-0811",
        "keywords": ["accepted offer", "written acceptance", "countersigned"],
    },
    "117.10(h)": {
        "rule": "32 CFR §117.10(h)(1) and (h)(2) — SEAD 7 Reciprocity",
        "url": "https://www.ecfr.gov/current/title-32/section-117.10#p-117.10(h)",
        "verbatim": (
            "(h)(1): Any current eligibility determination for access to classified information "
            "at any level that is based on an investigation of a scope that meets or exceeds that "
            "necessary for the required level of access will provide the basis for a new eligibility "
            "determination without further investigation or adjudication. "
            "(h)(2): The prior investigation will be used without further investigation or "
            "adjudication unless the CSA becomes aware of significant derogatory information that "
            "was not previously adjudicated."
        ),
        "plain_english": (
            "If you already hold an active clearance at or above the required level, "
            "the existing investigation and adjudication must be reused. No new SF-86, "
            "no new investigation, no new SSN collection. SEAD 7 makes this mandatory across "
            "all executive branch agencies. Demanding a new investigation from a cleared candidate "
            "is a misrepresentation of the process."
        ),
        "correct_process": (
            "FSO queries DISS JVS using their own CAC credentials → DISS returns eligibility "
            "level, adjudication date, investigation type → FSO grants access if clearance "
            "level meets or exceeds requirement. No new SF-86. No candidate SSN needed from candidate."
        ),
        "response_script": (
            "\"I hold an active [level] clearance. Under 32 CFR §117.10(h) and SEAD 7, "
            "reciprocity applies — my prior investigation must be used without re-investigation. "
            "Your FSO can verify through DISS JVS using their CAC credentials. "
            "No new SF-86 or SSN collection is authorized.\""
        ),
        "report_to": "DCSA Industry Hotline: (888) 282-0811",
        "keywords": ["new investigation", "start over", "fresh sf-86", "re-investigation",
                     "new background check", "re-adjudicate"],
    },
    "privacy_act": {
        "rule": "5 U.S.C. §552a — Privacy Act of 1974",
        "url": "https://www.govinfo.gov/link/uscode/5/552a",
        "verbatim": (
            "No agency shall disclose any record which is contained in a system of records by any "
            "means of communication to any person, or to another agency, except pursuant to a "
            "written request by, or with the prior written consent of, the individual to whom the "
            "record pertains."
        ),
        "plain_english": (
            "SSN is a Privacy Act-protected record within NBIS/OPM systems of records. "
            "Collecting it outside an authorized system (NBIS eApp) without a lawful clearance "
            "action trigger is an unauthorized collection. The NBIS System of Records Notice "
            "defines who can collect SSN and for what purpose — private recruiters are not "
            "authorized collectors."
        ),
        "correct_process": (
            "SSN is collected once, directly, by the subject into NBIS eApp. It is stored in "
            "the DISS/NBIS system of records. Any subsequent access (FSO verifica via JVS) "
            "uses the stored record — no re-collection from the subject is needed or authorized."
        ),
        "response_script": (
            "\"My SSN is a Privacy Act-protected record under 5 U.S.C. §552a. "
            "Collection outside an authorized NBIS system of records is not permitted. "
            "The authorized collection method is NBIS eApp — not email, phone, or any "
            "third-party form.\""
        ),
        "report_to": "FTC: reportfraud.ftc.gov / FBI IC3: ic3.gov",
        "keywords": ["ssn", "social security", "pii", "personal information"],
    },
}


# ---------------------------------------------------------------------------
# Pattern-to-citation mapping
# ---------------------------------------------------------------------------
PATTERN_TO_CITATION: dict[str, list[str]] = {
    # fraud_patterns.py pattern names → citation keys
    "ssn_request":                       ["117.10(a)(7)", "117.10(d)", "privacy_act"],
    "clearance_level_request":            ["117.10(a)(7)"],
    "recruiter_claims_diss_access":       ["117.10(a)(7)"],
    "investigation_before_offer_claimed": ["117.10(f)(1)(i)", "117.10(f)(1)(ii)"],
    "fcra_pretext_for_clearance":         ["117.10(a)(7)", "117.10(d)"],
    "clearance_self_attestation_request": ["117.10(a)(7)", "117.10(h)"],
    "suffice_the_clearance_language":     ["117.10(a)(7)", "117.10(h)"],
    "cage_code_deflection":               ["117.10(a)(7)"],
    "fake_offer_ssn_request":             ["117.10(f)(1)(i)", "117.10(f)(1)(ii)", "117.10(d)"],
    "offer_conditioned_on_ssn":           ["117.10(f)(1)(i)", "117.10(d)"],
    "dod_safe_ssn_channel":               ["117.10(d)"],
    "common_practice_ssn_normalization":  ["117.10(a)(5)", "117.10(a)(7)"],
    "everyone_else_ssn_pressure":         ["117.10(a)(5)"],
    "not_playing_ball":                   ["117.10(a)(7)"],
    "skip_over_candidate":                ["117.10(a)(7)"],
    "ssn_normalized_as_standard":         ["117.10(a)(5)", "117.10(a)(7)"],
    "ssn_immediate_deadline":             ["117.10(a)(7)"],
    "fso_impersonation":                  ["117.10(a)(7)", "117.10(d)"],
    "fsso_fake_email":                    ["117.10(a)(7)", "117.10(d)"],
}

# nispom_compliance.py category names → citation keys
CATEGORY_TO_CITATION: dict[str, list[str]] = {
    "non_employee_check":        ["117.10(a)(7)"],
    "pre_offer_action":          ["117.10(f)(1)(i)", "117.10(f)(1)(ii)"],
    "cache_building":            ["117.10(a)(5)"],
    "unauthorized_channel":      ["117.10(d)"],
    "pii_misuse":                ["117.10(d)"],
    "reciprocity_ignored":       ["117.10(h)"],
    "privacy_act":               ["privacy_act"],
    "self_attestation_clearance": ["117.10(a)(7)", "117.10(h)"],
}


@dataclass
class Explanation:
    """Full human-readable explanation for a single violation."""
    rule: str
    url: str
    verbatim: str
    plain_english: str
    correct_process: str
    response_script: str
    report_to: str
    triggered_by: list[str] = field(default_factory=list)  # pattern/category names that triggered this


@dataclass
class ExplainerReport:
    """Aggregated explanations for all violations found in an analysis."""
    explanations: list[Explanation] = field(default_factory=list)
    response_scripts: list[str] = field(default_factory=list)
    reporting_agencies: list[str] = field(default_factory=list)

    def render(self) -> str:
        if not self.explanations:
            return "No regulatory violations detected."
        lines = []
        for i, exp in enumerate(self.explanations, 1):
            lines += [
                f"{'═' * 60}",
                f"VIOLATION {i}: {exp.rule}",
                f"Source: {exp.url}",
                f"{'─' * 60}",
                "VERBATIM TEXT:",
                f"  {exp.verbatim}",
                "",
                "WHAT THIS MEANS:",
                f"  {exp.plain_english}",
                "",
                "CORRECT PROCESS:",
                f"  {exp.correct_process}",
                "",
                "WHAT TO SAY:",
                f"  {exp.response_script}",
                "",
                f"REPORT TO: {exp.report_to}",
                "",
            ]
        if self.reporting_agencies:
            lines += ["", "ALL APPLICABLE REPORTING AGENCIES:"]
            seen = set()
            for agency in self.reporting_agencies:
                if agency not in seen:
                    lines.append(f"  • {agency}")
                    seen.add(agency)
        return "\n".join(lines)


def explain_patterns(pattern_names: list[str]) -> ExplainerReport:
    """
    Given a list of fraud pattern names (from rule_engine matches), return
    an ExplainerReport with full CFR citations and response guidance.

    Args:
        pattern_names: List of FraudPattern.name strings from rule matches.

    Returns:
        ExplainerReport with deduplicated citation explanations.
    """
    citation_keys_seen: dict[str, list[str]] = {}
    for name in pattern_names:
        for key in PATTERN_TO_CITATION.get(name, []):
            citation_keys_seen.setdefault(key, []).append(name)

    return _build_report(citation_keys_seen)


def explain_categories(category_names: list[str]) -> ExplainerReport:
    """
    Given a list of violation category names (from nispom_compliance), return
    an ExplainerReport with full CFR citations and response guidance.

    Args:
        category_names: List of NispomsViolation.category strings.

    Returns:
        ExplainerReport with deduplicated citation explanations.
    """
    citation_keys_seen: dict[str, list[str]] = {}
    for cat in category_names:
        for key in CATEGORY_TO_CITATION.get(cat, []):
            citation_keys_seen.setdefault(key, []).append(cat)

    return _build_report(citation_keys_seen)


def explain_combined(pattern_names: list[str], category_names: list[str]) -> ExplainerReport:
    """Explain from both pattern names and compliance categories, deduplicated."""
    citation_keys_seen: dict[str, list[str]] = {}
    for name in pattern_names:
        for key in PATTERN_TO_CITATION.get(name, []):
            citation_keys_seen.setdefault(key, []).append(f"pattern:{name}")
    for cat in category_names:
        for key in CATEGORY_TO_CITATION.get(cat, []):
            citation_keys_seen.setdefault(key, []).append(f"category:{cat}")
    return _build_report(citation_keys_seen)


def _build_report(citation_keys_seen: dict[str, list[str]]) -> ExplainerReport:
    report = ExplainerReport()
    # Priority order for display
    priority_order = [
        "117.10(a)(7)", "117.10(f)(1)(i)", "117.10(f)(1)(ii)",
        "117.10(d)", "117.10(a)(5)", "117.10(h)", "privacy_act",
    ]
    ordered_keys = [k for k in priority_order if k in citation_keys_seen]
    ordered_keys += [k for k in citation_keys_seen if k not in priority_order]

    seen_agencies: set[str] = set()
    for key in ordered_keys:
        data = CITATION_TABLE.get(key)
        if not data:
            continue
        exp = Explanation(
            rule=data["rule"],
            url=data["url"],
            verbatim=data["verbatim"],
            plain_english=data["plain_english"],
            correct_process=data["correct_process"],
            response_script=data["response_script"],
            report_to=data["report_to"],
            triggered_by=citation_keys_seen[key],
        )
        report.explanations.append(exp)
        report.response_scripts.append(data["response_script"])
        if data["report_to"] not in seen_agencies:
            report.reporting_agencies.append(data["report_to"])
            seen_agencies.add(data["report_to"])

    return report


def lookup_citation(key: str) -> dict | None:
    """Direct lookup of a citation by partial key (e.g. '117.10(a)(7)')."""
    for k, v in CITATION_TABLE.items():
        if key in k or k in key:
            return v
    return None
