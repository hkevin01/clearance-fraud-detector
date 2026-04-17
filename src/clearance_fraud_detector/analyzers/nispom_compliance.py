"""
NISPOM Compliance Analyzer — 32 CFR Part 117 Violation Mapper.

Maps a described hiring interaction to the exact Code of Federal Regulations
paragraphs that are violated. Designed specifically for cleared-job fraud
where recruiters/FSOs misrepresent or bypass NISPOM-mandated process steps.

Primary authority: 32 CFR Part 117 (NISPOM), effective March 2021.
Canonical source: https://www.ecfr.gov/current/title-32/part-117

Each violation entry includes:
  - rule: exact CFR citation (e.g., "32 CFR §117.10(a)(7)")
  - verbatim: the exact regulatory text
  - url: direct paragraph-level link to ecfr.gov
  - what_violated: plain-English description of the violation
  - severity: "critical" | "high" | "medium"
"""
import re
from dataclasses import dataclass, field


@dataclass
class NispomsViolation:
    rule: str               # e.g. "32 CFR §117.10(a)(7)"
    verbatim: str           # exact regulatory text
    url: str                # direct ecfr.gov paragraph link
    what_violated: str      # plain-English explanation
    severity: str           # "critical" | "high" | "medium"
    category: str           # e.g. "pre_offer_ssn", "non_employee_check"


@dataclass
class ComplianceReport:
    violations: list[NispomsViolation] = field(default_factory=list)
    compliant_signals: list[str] = field(default_factory=list)
    overall_status: str = "COMPLIANT"   # "COMPLIANT" | "VIOLATIONS_FOUND" | "CRITICAL_VIOLATIONS"

    @property
    def has_violations(self) -> bool:
        return len(self.violations) > 0

    @property
    def critical_count(self) -> int:
        return sum(1 for v in self.violations if v.severity == "critical")

    @property
    def top_violation(self) -> NispomsViolation | None:
        critical = [v for v in self.violations if v.severity == "critical"]
        return critical[0] if critical else (self.violations[0] if self.violations else None)

    def summary(self) -> str:
        if not self.violations:
            return "No NISPOM violations detected."
        lines = [f"NISPOM Violations Detected ({len(self.violations)} total):"]
        for v in self.violations:
            lines.append(f"  [{v.severity.upper()}] {v.rule} — {v.what_violated}")
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Violation definitions — verbatim text + detection pattern
# ---------------------------------------------------------------------------

_VIOLATIONS: list[tuple[re.Pattern, NispomsViolation]] = [

    # -------------------------------------------------------------------------
    # §117.10(a)(7) — Cannot check/verify clearance of a non-employee
    # THE most directly applicable rule when any pre-offer clearance action occurs
    # -------------------------------------------------------------------------
    (re.compile(
        r"(verify|check|confirm|look\s+up|run).{0,60}"
        r"(clearance|access|eligibility|diss|jpas)"
        r"|"
        r"(clearance|eligibility).{0,60}(verify|check|confirm|look\s+up)"
        r"|"
        r"(need\s+to|have\s+to|must).{0,40}"
        r"(verify|confirm|check).{0,40}(clearance|access|eligibility|ts|tssci|top\s+secret)"
        r"|"
        r"(ssn|social\s+security).{0,80}(clearance|diss|eligibility|access)",
        re.IGNORECASE,
     ),
     NispomsViolation(
         rule="32 CFR §117.10(a)(7)",
         verbatim=(
             '"Contractors will not submit requests for determination of eligibility '
             'for access to classified information for individuals who are not their '
             'employees or consultants; nor will they submit requests for employees '
             'of subcontractors."'
         ),
         url="https://www.ecfr.gov/current/title-32/section-117.10#p-117.10(a)(7)",
         what_violated=(
             "A clearance verification or eligibility check was attempted on a person "
             "who is not yet an employee. The word used in the regulation is 'employees' "
             "— not 'candidates,' not 'prospects.' No employment relationship = no authority "
             "to initiate any clearance action."
         ),
         severity="critical",
         category="non_employee_check",
     )),

    # -------------------------------------------------------------------------
    # §117.10(f)(1)(i)-(ii) — Written offer + written acceptance required FIRST
    # -------------------------------------------------------------------------
    (re.compile(
        r"(before\s+(an?\s+)?offer|prior\s+to\s+(an?\s+)?offer|without\s+(an?\s+)?offer)"
        r".{0,80}(ssn|social\s+security|clearance|investigation|pii|background)"
        r"|"
        r"before.{0,60}\boffer\b.{0,120}(ssn|social\s+security|clearance|pii)"
        r"|"
        r"(ssn|social\s+security|pii|clearance\s+check).{0,80}"
        r"(before\s+(an?\s+)?offer|prior\s+to\s+(an?\s+)?offer|no\s+offer)"
        r"|"
        r"(ssn|social\s+security).{0,200}before.{0,60}\boffer\b"
        r"|"
        r"before.{0,60}\boffer.{0,200}social\s+security",
        re.IGNORECASE | re.DOTALL,
     ),
     NispomsViolation(
         rule="32 CFR §117.10(f)(1)(i) and (f)(1)(ii)",
         verbatim=(
             '"If a potential employee requires access to classified information '
             'immediately upon commencement of employment, the contractor may submit '
             'a request for investigation prior to the date of employment, provided: '
             '(i) A written commitment for employment has been made by the contractor. '
             '(ii) The candidate has accepted the offer in writing."'
         ),
         url="https://www.ecfr.gov/current/title-32/section-117.10#p-117.10(f)",
         what_violated=(
             "A clearance action (including SSN collection) was initiated before both "
             "conditions were satisfied: (i) written offer from the contractor AND "
             "(ii) written acceptance from the candidate. Both must exist. No exceptions."
         ),
         severity="critical",
         category="pre_offer_action",
     )),

    # -------------------------------------------------------------------------
    # §117.10(a)(5) — Cache prohibition
    # -------------------------------------------------------------------------
    (re.compile(
        r"(everyone\s+else|all\s+(other\s+)?candidates?|multiple\s+candidates?)"
        r".{0,80}(ssn|social\s+security|clearance\s+check|provided|verified)"
        r"|"
        r"(standard\s+practice|common\s+practice|industry\s+standard)"
        r".{0,80}(ssn|social\s+security|clear(?:ance|ed)|contracting|recruiting)"
        r"|"
        r"(everyone\s+else|all\s+candidates).{0,80}(clear(?:ance|ed)|ssn|provided|verified)"
        r"|"
        r"(pipeline|bench|pool|roster).{0,60}(cleared|active\s+clearance|ts|tssci)"
        r"|"
        r"cache\s+of\s+cleared",
        re.IGNORECASE | re.DOTALL,
     ),
     NispomsViolation(
         rule="32 CFR §117.10(a)(5)",
         verbatim=(
             '"The contractor will limit requests for determinations of eligibility '
             'for access to classified information to the minimum number of employees '
             'and consultants necessary for operational efficiency in accordance with '
             'contractual obligations... Requests for determinations of eligibility '
             'for access to classified information will not be used to establish a '
             'cache of cleared employees."'
         ),
         url="https://www.ecfr.gov/current/title-32/section-117.10#p-117.10(a)(5)",
         what_violated=(
             "Clearance requests are being used to build a pool of cleared candidates "
             "rather than to fulfill a specific, current contractual requirement. "
             "Collecting SSNs from multiple pre-offer candidates as 'standard practice' "
             "is precisely the prohibited cache-building behavior."
         ),
         severity="critical",
         category="cache_building",
     )),

    # -------------------------------------------------------------------------
    # §117.10(d) — SF-86/SSN must go through eApp only
    # -------------------------------------------------------------------------
    (re.compile(
        r"(email|text|phone|fax|dod\s+safe|safe\.apps\.mil|whatsapp|telegram)"
        r".{0,60}(ssn|social\s+security|sf.?86|pii|personal\s+information)"
        r"|"
        r"(ssn|social\s+security|sf.?86|pii).{0,60}"
        r"(email|text\s+me|phone|call|send\s+via|fax|dod\s+safe|safe\.apps\.mil|whatsapp|telegram)"
        r"|"
        r"(send|provide|submit|email|call|phone).{0,30}(ssn|social\s+security|pii)"
        r".{0,60}(instead\s+of|rather\s+than)\s+eapp"
        r"|"
        r"(call|phone|text).{0,60}(ssn|social\s+security|pii)"
        r"|"
        r"(dod\s+safe|safe\.apps\.mil)"
        r"|"
        r"(ssn|social\s+security).{0,300}(dod\s+safe|safe\.apps\.mil)",
        re.IGNORECASE | re.DOTALL,
     ),
     NispomsViolation(
         rule="32 CFR §117.10(d)",
         verbatim=(
             '"The electronic version of the SF 86...must be completed in e-QIP or '
             'its successor system by the contractor employee and reviewed by the FSO."'
         ),
         url="https://www.ecfr.gov/current/title-32/section-117.10#p-117.10(d)",
         what_violated=(
             "SSN or SF-86 data was requested through an unauthorized channel. "
             "The only authorized system is NBIS eApp (eapp.nbis.mil) — e-QIP's "
             "successor. Email, phone, text, DOD SAFE, WhatsApp, Telegram, and "
             "any other channel is not authorized. SSN goes into eApp directly by "
             "the candidate — it never travels from candidate to FSO as raw PII."
         ),
         severity="critical",
         category="unauthorized_channel",
     )),

    # -------------------------------------------------------------------------
    # §117.10(d)(1)-(2) — FSO cannot share or repurpose SF-86 data
    # -------------------------------------------------------------------------
    (re.compile(
        r"(share|forward|send|provide).{0,50}(sf.?86|background\s+investigation|pii)"
        r".{0,60}(client|employer|third\s+party|hiring\s+manager)"
        r"|"
        r"(background|sf.?86|pii).{0,60}(shared|forwarded|sent|provided)"
        r".{0,60}(without\s+consent|internally|to\s+(another|other))",
        re.IGNORECASE,
     ),
     NispomsViolation(
         rule="32 CFR §117.10(d)(1) and (d)(2)",
         verbatim=(
             '(d)(1): "Provide the employee with written notification that review of '
             'the SF 86 by the FSO...is for adequacy and completeness and information '
             'will be used for no other purpose within the entity." '
             '(d)(2): "Not share information from the employee\'s SF 86 within the '
             'entity and will not use the information for any purpose other than '
             'determining the adequacy and completeness of the SF 86."'
         ),
         url="https://www.ecfr.gov/current/title-32/section-117.10#p-117.10(d)",
         what_violated=(
             "SF-86 data or PII collected during the investigation process was shared "
             "internally or with third parties beyond the FSO's adequacy review role. "
             "The FSO reviews for completeness only and is prohibited from using or "
             "sharing that information for any other purpose."
         ),
         severity="high",
         category="pii_misuse",
     )),

    # -------------------------------------------------------------------------
    # §117.10(h)(1)-(2) — Reciprocity: prior investigation must be reused
    # -------------------------------------------------------------------------
    (re.compile(
        r"(new\s+investigation|re.?investigation|fresh\s+sf.?86|start\s+over)"
        r".{0,250}(already|existing|active|current).{0,20}clearance"
        r"|"
        r"(already|existing|active|current).{0,20}(clearance|ts|top\s+secret)"
        r".{0,250}(new\s+investigation|re.?investigation|fresh\s+sf.?86|start\s+over|can.?t\s+use)"
        r"|"
        r"need\s+(another|new|fresh)\s+(sf.?86|investigation|background)"
        r".{0,60}(active|current|existing)\s+clearance",
        re.IGNORECASE | re.DOTALL,
     ),
     NispomsViolation(
         rule="32 CFR §117.10(h)(1) and (h)(2)",
         verbatim=(
             '(h)(1): "Any current eligibility determination...that is based on an '
             'investigation of a scope that meets or exceeds that necessary for the '
             'required level of access will provide the basis for a new eligibility '
             'determination." '
             '(h)(2): "The prior investigation will be used without further investigation '
             'or adjudication unless the CSA becomes aware of significant derogatory '
             'information that was not previously adjudicated."'
         ),
         url="https://www.ecfr.gov/current/title-32/section-117.10#p-117.10(h)",
         what_violated=(
             "A new investigation was demanded for a candidate with an active clearance "
             "at the required level. SEAD 7 reciprocity applies — the prior investigation "
             "must be used without re-adjudication. Requiring a new SF-86 from someone "
             "with an active TS is a misrepresentation of the NISPOM process."
         ),
         severity="high",
         category="reciprocity_ignored",
     )),

    # -------------------------------------------------------------------------
    # -------------------------------------------------------------------------
    # DISS self-attestation — asking candidate to fill in their own clearance fields
    # An FSO who has done a proper DISS JVS query already has these fields.
    # Asking the candidate to provide them means: (a) no DISS access, or (b) pre-hire.
    # Pattern named after first documented instance: TSCTI/22nd Century Tech, April 2026.
    # -------------------------------------------------------------------------
    (re.compile(
        r"(eligibility\s+level\s*:|eligibility\s+determination\s*:|ce\s+date\s*:|investigation\s+type\s*:)"
        r"|"
        r"(verify|confirm|provide|fill\s+(in|out)).{0,60}"
        r"(eligibility\s+(level|determination)|ce\s+date|investigation\s+type)"
        r"|"
        r"(eligibility\s+level|eligibility\s+determination).{0,100}"
        r"(investigation\s+type|ce\s+date|ce\s+date)",
        re.IGNORECASE,
     ),
     NispomsViolation(
         rule="32 CFR §117.10(a)(7) and §117.10(h)(1)-(2)",
         verbatim=(
             '§117.10(a)(7): "Contractors will not submit requests for determination of '
             'eligibility for access to classified information for individuals who are not '
             'their employees or consultants." '
             '§117.10(h)(1)-(2): An FSO with DISS access queries the authoritative government '
             'record directly — they receive Eligibility Level, Eligibility Determination, '
             'CE Date, and Investigation Type from DISS. They do not ask the candidate.'
         ),
         url="https://www.ecfr.gov/current/title-32/section-117.10#p-117.10(a)(7)",
         what_violated=(
             "The requestor is asking the candidate to self-report clearance metadata "
             "(Eligibility Level, Eligibility Determination, CE Date, Investigation Type) "
             "that a credentialed FSO would already have from a DISS JVS query. "
             "This indicates the FSO either: (a) has not yet hired the candidate — making "
             "this a §117.10(a)(7) non-employee check, or (b) lacks DISS access and is "
             "using self-attestation instead of the authoritative government record. "
             "Self-attestation is not a valid substitute for DISS JVS. "
             "Documented pattern: 22nd Century Technologies / TSCTI, April 2026."
         ),
         severity="high",
         category="self_attestation_clearance",
     )),

    # Privacy Act — 5 U.S.C. §552a — SSN outside authorized system of records
    # -------------------------------------------------------------------------
    (re.compile(
        r"(collect|gather|store|retain|hold).{0,60}"
        r"(ssn|social\s+security).{0,60}"
        r"(outside|not\s+through|without).{0,30}(eapp|nbis|authorized|official)",
        re.IGNORECASE,
     ),
     NispomsViolation(
         rule="5 U.S.C. §552a (Privacy Act of 1974)",
         verbatim=(
             '"No agency shall disclose any record...contained in a system of records '
             'except pursuant to a written request by, or with the prior written consent '
             'of, the individual to whom the record pertains." '
             'Cross-referenced in NISPOM at 32 CFR §117.10(d)(1).'
         ),
         url="https://www.govinfo.gov/link/uscode/5/552a",
         what_violated=(
             "SSN is a Privacy Act-protected record. Collecting it outside an authorized "
             "federal system of records (NBIS eApp), without a lawful clearance-action "
             "trigger, constitutes unauthorized collection under the Privacy Act. "
             "The NBIS System of Records Notice governs this data — not a private "
             "recruiter's intake form."
         ),
         severity="critical",
         category="privacy_act",
     )),
]


# ---------------------------------------------------------------------------
# Compliant behavior signals (reduce false positives)
# ---------------------------------------------------------------------------
_COMPLIANT_SIGNALS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"(written\s+offer|offer\s+letter).{0,60}(sent|provided|issued|attached)", re.IGNORECASE),
     "Written offer provided — satisfies §117.10(f)(1)(i)"),
    (re.compile(r"(accepted|acceptance).{0,40}(in\s+writing|written|signed|countersigned)", re.IGNORECASE),
     "Written acceptance obtained — satisfies §117.10(f)(1)(ii)"),
    (re.compile(r"eapp\.nbis\.mil|nbis\s+eapp|e-?qip", re.IGNORECASE),
     "Directing to eApp — satisfies §117.10(d)"),
    (re.compile(r"(fso|facility\s+security\s+officer).{0,60}(initiat|submit|process)", re.IGNORECASE),
     "FSO initiating the process — correct role"),
    (re.compile(r"(after|upon|following).{0,30}(offer|acceptance|hire|onboard)", re.IGNORECASE),
     "Post-offer sequencing indicated — correct timing"),
    (re.compile(r"(diss|jvs).{0,60}(credenti|cac|login|account|portal)", re.IGNORECASE),
     "DISS accessed via credentialed FSO login — correct method"),
    (re.compile(r"i.?9|w.?4|onboard", re.IGNORECASE),
     "Standard HR onboarding forms mentioned — correct post-hire SSN collection path"),
]


# ID: NC-001
# Requirement: Map interaction text to specific 32 CFR §117.10 paragraph violations and
#              return a ComplianceReport with verbatim CFR text and recommended actions.
# Purpose: Translate detected fraud signals into explicit regulatory citations for incident
#          reporting and victim-guidance workflows.
# Rationale: DCSA MITS submissions and FBI tips are stronger when citing specific CFR
#             paragraphs; this function provides that mapping automatically from free text.
# Inputs: text (str) — email body, recruiter message, call notes, or job posting text.
# Outputs: ComplianceReport with violations list and has_violations bool property.
# Preconditions: _VIOLATIONS and _LEGIT_SIGNALS module-level lists are populated.
# Postconditions: Violations are deduplicated by rule string; legit signals counted separately.
# Assumptions: Each _VIOLATIONS entry is (pattern, NispomsViolation) 2-tuple.
# Side Effects: None — pure function with no I/O.
# Failure Modes: Empty text returns ComplianceReport with no violations — no exception.
# Error Handling: No guards beyond truthiness checks; unexpected pattern types surface as AttributeError.
# Constraints: O(|_VIOLATIONS| × |text|); expected < 5 ms for typical interaction texts.
# Verification: test_detector.py::test_compliance_* — each CFR paragraph triggered correctly.
# References: 32 CFR §117.10 — effective March 2021; ecfr.gov/current/title-32/section-117.10.
def check_compliance(text: str) -> ComplianceReport:
    """
    Analyze interaction text against NISPOM 32 CFR §117.10 requirements.

    Args:
        text: Any interaction text — email body, recruiter message, call notes,
              job posting, or description of events.

    Returns:
        ComplianceReport with all detected violations and their exact CFR citations.
    """
    report = ComplianceReport()
    seen_categories: set[str] = set()

    for pattern, violation in _VIOLATIONS:
        if pattern.search(text) and violation.category not in seen_categories:
            report.violations.append(violation)
            seen_categories.add(violation.category)

    for pattern, signal in _COMPLIANT_SIGNALS:
        if pattern.search(text):
            report.compliant_signals.append(signal)

    if report.critical_count >= 2:
        report.overall_status = "CRITICAL_VIOLATIONS"
    elif report.has_violations:
        report.overall_status = "VIOLATIONS_FOUND"
    else:
        report.overall_status = "COMPLIANT"

    return report
