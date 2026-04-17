"""
Incident Report Generator — Produces DCSA/FBI-ready incident reports.

Takes a FraudScore, ContactAnalysis, and/or ComplianceReport and generates
a formatted, citation-ready incident report suitable for submission to:
  - DCSA Counterintelligence: (571) 305-6576
  - DCSA Industry Hotline: (888) 282-0811
  - FBI Tips: https://tips.fbi.gov
  - DCSA Online Reporting: https://www.dcsa.mil/about/contact/

The report includes:
  - Incident summary with timestamps
  - Detected violations with exact CFR citations and verbatim rule text
  - Evidence inventory (what to preserve)
  - Per-agency instructions for reporting

Date format used: ISO 8601 (YYYY-MM-DD) throughout reports.
"""
from __future__ import annotations

import textwrap
from dataclasses import dataclass, field
from datetime import date, datetime


@dataclass
class IncidentReportInput:
    """Collects everything needed to generate the report."""
    # About the incident
    incident_date: date | None = None
    company_name: str = "Unknown"
    recruiter_name: str = "Unknown"
    recruiter_email: str = ""
    recruiter_phone: str = ""
    job_title: str = "Unknown"

    # Detected violations (from nispom_compliance or contact_analyzer)
    violations: list[str] = field(default_factory=list)   # e.g. ["32 CFR §117.10(a)(7)", ...]
    violation_descriptions: list[str] = field(default_factory=list)
    fraud_score: float = 0.0      # 0.0-1.0
    verdict: str = "UNKNOWN"      # SUSPICIOUS, LIKELY_FRAUD, CONFIRMED_FRAUD

    # Subject information (report writer = the target)
    reporter_holds_clearance: bool = False
    clearance_level: str = ""     # TS, S, TS/SCI, etc.

    # What happened
    narrative: str = ""           # Free-form description of events

    # Evidence
    emails_preserved: bool = False
    screenshots_taken: bool = False
    phone_number_noted: bool = False


@dataclass
class IncidentReport:
    title: str
    generated_at: str
    sections: list[tuple[str, str]] = field(default_factory=list)  # (heading, body)

    def render(self) -> str:
        """Render the report as plain-text with clear section breaks."""
        lines = [
            "=" * 72,
            self.title.upper(),
            f"Generated: {self.generated_at}",
            "=" * 72,
            "",
        ]
        for heading, body in self.sections:
            lines.append(f"{'─' * 60}")
            lines.append(f"  {heading.upper()}")
            lines.append(f"{'─' * 60}")
            lines.append(textwrap.fill(body, width=72, subsequent_indent="  ") if "\n" not in body else body)
            lines.append("")
        lines.append("=" * 72)
        lines.append("END OF REPORT")
        lines.append("=" * 72)
        return "\n".join(lines)

    def render_markdown(self) -> str:
        """Render the report as Markdown."""
        lines = [
            f"# {self.title}",
            f"*Generated: {self.generated_at}*",
            "",
        ]
        for heading, body in self.sections:
            lines.append(f"## {heading}")
            lines.append(body)
            lines.append("")
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Agency reporting information
# ---------------------------------------------------------------------------
REPORTING_AGENCIES = [
    {
        "name": "DCSA Counterintelligence / Industry Security",
        "phone": "(571) 305-6576",
        "url": "https://www.dcsa.mil/mc/ci/",
        "online_tip": "https://www.dcsa.mil/Portals/91/Documents/pv/mits/MITS_Industry_Tip_Reporting_Form.pdf",
        "best_for": "Primary report for any NISPOM/clearance process violation by a cleared contractor",
        "include_in_report": ["violations", "company_cage", "recruiter_contact", "interaction_dates"],
        "steps": [
            "a. Call (571) 305-6576 during business hours.",
            "b. Download and complete the MITS Industry Tip Reporting Form:",
            "   https://www.dcsa.mil/Portals/91/Documents/pv/mits/MITS_Industry_Tip_Reporting_Form.pdf",
            "c. Include: company name, CAGE code (if known), recruiter name and contact,",
            "   dates of each interaction, exactly what was requested of you, and all detected violations.",
            "d. Attach preserved evidence (email headers, screenshots) as PDF attachments.",
            "e. Request and record the case/incident reference number for your files.",
        ],
    },
    {
        "name": "DCSA NBIS — National Background Investigation Services",
        "phone": "(878) 274-1765",
        "url": "https://www.dcsa.mil/Systems-Applications/National-Background-Investigation-Services-NBIS/",
        "online_tip": "https://vetting.nbis.mil/",
        "best_for": "Fraud involving the clearance investigation process — SF-86/eApp abuse, DISS/NBIS impersonation, unauthorized investigation initiation",
        "include_in_report": ["all"],
        "steps": [
            "Use when: someone claimed to use NBIS/eApp/DISS/SF-86 as justification for",
            "collecting your PII, or someone tried to 'initiate' an investigation without a written offer.",
            "",
            "a. Industry/FSO Contact Center (cleared contractors and their FSOs):",
            "   Email: dcsa.ncr.nbis.mbx.contact-center@mail.mil",
            "   Phone: (878) 274-1765  |  Hours: 6 a.m.–5 p.m. EST, Mon–Fri",
            "   Web: https://www.dcsa.mil/Systems-Applications/National-Background-Investigation-Services-NBIS/",
            "",
            "b. NBIS Agency Support (for SSOs/FSOs with vetting.nbis.mil access):",
            "   Email: dcsa.boyers.nbis.mbx.nbis-agency-support@mail.mil",
            "   Phone: (878) 274-5080  |  Hours: 6 a.m.–4:30 p.m. EST, Mon–Fri",
            "",
            "c. REMINDER — The ONLY authorized channel for submitting SSN in a clearance",
            "   investigation is NBIS eApp (https://eapp.nbis.mil), initiated by your FSO.",
            "   Anyone asking for SSN through any other channel is committing fraud.",
        ],
    },
    {
        "name": "DCSA Industry Hotline",
        "phone": "(888) 282-0811",
        "url": "https://www.dcsa.mil/about/contact/",
        "online_tip": None,
        "best_for": "Anonymous tip about cleared-job fraud; no account or identity needed",
        "include_in_report": ["company_name", "recruiter_name", "violation_summary"],
        "steps": [
            "a. Call (888) 282-0811 — anonymous, no account required.",
            "b. Provide: company name, recruiter name/contact, and a brief description of what occurred.",
            "c. This is a supplement to — not a replacement for — the DCSA CI report above.",
        ],
    },
    {
        "name": "FBI Counterintelligence Tips",
        "phone": None,
        "url": "https://tips.fbi.gov",
        "online_tip": "https://tips.fbi.gov",
        "best_for": "Foreign adversary recruitment attempts (especially DPRK IT workers, camera-off interviews, Telegram-only recruiters)",
        "include_in_report": ["all"],
        "steps": [
            "a. Go to https://tips.fbi.gov and click 'Submit a Tip'.",
            "b. Select category: National Security / Counterintelligence.",
            "c. Include: all recruiter contact details, what was requested, any foreign indicators",
            "   (foreign accent, camera-off requirement, Telegram/WhatsApp contact, laptop shipping request).",
            "d. Attach screenshots or exported email files if possible.",
            "e. You may report anonymously; providing contact info is optional but helps follow-up.",
        ],
    },
    {
        "name": "FBI Internet Crime Complaint Center (IC3)",
        "phone": None,
        "url": "https://ic3.gov",
        "online_tip": "https://complaint.ic3.gov",
        "best_for": "Wire fraud, fake job websites, online identity theft, impersonation of government entities",
        "include_in_report": ["all"],
        "steps": [
            "a. Go to https://complaint.ic3.gov and click 'File a Complaint'.",
            "b. Select fraud type: Employment/Job Fraud or Government Impersonation.",
            "c. Provide: full timeline, all URLs/email addresses/phone numbers involved,",
            "   any money demanded or transferred (application fees, gift cards, Bitcoin).",
            "d. IC3 shares reports with 3,000+ law enforcement agencies — file even if no money was lost.",
            "e. Save your IC3 complaint number.",
        ],
    },
    {
        "name": "FTC — ReportFraud.ftc.gov",
        "phone": "1-877-382-4357",
        "url": "https://reportfraud.ftc.gov",
        "online_tip": "https://reportfraud.ftc.gov/#/",
        "best_for": "Job scams, application fees, fake recruiters, phishing emails, consumer fraud",
        "include_in_report": ["ssn_status", "company_contact"],
        "steps": [
            "a. Go to https://reportfraud.ftc.gov and click 'Report Now'.",
            "b. Select: Job Scam or Identity Theft (if SSN was taken).",
            "c. Fill in: company name, how you were contacted, what was requested,",
            "   any money you paid, and all contact details.",
            "d. If SSN was provided: also visit https://identitytheft.gov for a personalized",
            "   recovery plan covering credit, taxes, and government benefits.",
            "e. Save your FTC report reference number.",
        ],
    },
]


# ID: RG-001
# Requirement: Generate a 7-section DCSA/FBI-ready incident report from structured input,
#              covering summary, narrative, violations, evidence, agency steps, prohibitions,
#              and legal authority references.
# Purpose: Produce a document suitable for submission to DCSA MITS, FBI tip forms, and
#          FTC reportfraud.ftc.gov without requiring the victim to know the CFR citation structure.
# Rationale: Structured sections mirror the DCSA MITS form fields so the output can be
#             copy-pasted directly; agency steps include phone numbers and URL paths verified
#             against dcsa.mil and ic3.gov as of report publication date.
# Inputs: inp (IncidentReportInput) — all known incident details; none are required beyond
#         company_name, violations, and narrative (all other fields fall back to safe defaults).
# Outputs: IncidentReport with sections list; renderable via render() (plain text) or
#          render_markdown() (Markdown with headers).
# Preconditions: IncidentReportInput is a valid dataclass instance; datetime.now() is accessible.
# Postconditions: report.sections contains exactly 7 entries in the order defined here.
# Assumptions: REPORTING_AGENCIES list in this module is up to date with agency contact info.
# Side Effects: datetime.now() called once — not pure; deterministic except for timestamp.
# Failure Modes: Empty violations list produces a generic "manual review recommended" section.
# Error Handling: All optional fields (recruiter_email, phone, clearance_level) guarded by
#                 'or' fallback strings before use in formatted output.
# Constraints: O(|REPORTING_AGENCIES| + |violations|); < 5 ms.
# Verification: test_detector.py::test_report_generator_* — section count, agency steps present.
# References: DCSA MITS form; 32 CFR §117.10; 5 U.S.C. §552a (Privacy Act).
def generate_report(inp: IncidentReportInput) -> IncidentReport:
    """
    Generate a formatted incident report from structured input.

    Args:
        inp: IncidentReportInput with all known details about the incident.

    Returns:
        IncidentReport that can be rendered as plain text or Markdown.
    """
    now = datetime.now().isoformat(timespec="minutes")
    incident_str = inp.incident_date.isoformat() if inp.incident_date else "Unknown"

    title = f"CLEARED JOB FRAUD INCIDENT REPORT — {inp.company_name.upper()}"
    report = IncidentReport(title=title, generated_at=now)

    # ---- SECTION 1: Summary --------------------------------------------------
    verdict_label = {
        "SUSPICIOUS": "Suspicious activity detected",
        "LIKELY_FRAUD": "Likely fraudulent clearance process",
        "CONFIRMED_FRAUD": "Confirmed NISPOM process violation and/or fraud",
    }.get(inp.verdict, inp.verdict)

    summary_body = (
        f"Incident Date: {incident_str}\n"
        f"Company: {inp.company_name}\n"
        f"Recruiter/Contact: {inp.recruiter_name}\n"
        f"Email: {inp.recruiter_email or '(not provided)'}\n"
        f"Phone: {inp.recruiter_phone or '(not provided)'}\n"
        f"Position: {inp.job_title}\n"
        f"Assessment: {verdict_label} (fraud score: {inp.fraud_score:.0%})\n"
        f"Reporter holds clearance: {'Yes' if inp.reporter_holds_clearance else 'No'}"
        + (f" ({inp.clearance_level})" if inp.clearance_level else "")
    )
    report.sections.append(("Incident Summary", summary_body))

    # ---- SECTION 2: What Happened --------------------------------------------
    if inp.narrative:
        report.sections.append(("Narrative — What Occurred", inp.narrative))
    else:
        report.sections.append(("Narrative — What Occurred",
            "(Describe in your own words what was said, what was requested, "
            "and the sequence of events. Include dates and times where known.)"))

    # ---- SECTION 3: Regulatory Violations ------------------------------------
    if inp.violations:
        v_lines = []
        for i, v in enumerate(inp.violations, 1):
            desc = inp.violation_descriptions[i - 1] if i <= len(inp.violation_descriptions) else ""
            v_lines.append(f"  Violation {i}: {v}")
            if desc:
                v_lines.append(f"    → {desc}")
        report.sections.append(("Regulatory Violations Detected",
            "\n".join(v_lines) + "\n\n"
            "Authority: 32 CFR Part 117 (NISPOM)\n"
            "Source: https://www.ecfr.gov/current/title-32/part-117"))
    else:
        report.sections.append(("Regulatory Violations Detected",
            "No specific violations auto-detected. Manual review recommended.\n"
            "See 32 CFR §117.10 for the full list of contractor obligations."))

    # ---- SECTION 4: Evidence Inventory ---------------------------------------
    evidence_lines = []
    if inp.emails_preserved:
        evidence_lines.append("  [X] Email communications preserved (forward to .eml or export as PDF)")
    else:
        evidence_lines.append("  [ ] IMPORTANT: Preserve all email communications immediately")
        evidence_lines.append("       → Forward originals to a personal archive or print to PDF")

    if inp.screenshots_taken:
        evidence_lines.append("  [X] Screenshots of communications taken")
    else:
        evidence_lines.append("  [ ] Take screenshots of all messages (including timestamps)")

    if inp.phone_number_noted:
        evidence_lines.append("  [X] Recruiter phone number recorded")
    else:
        evidence_lines.append("  [ ] Record the phone number and any voicemails")

    evidence_lines += [
        "  [ ] Note the exact date and time of each contact",
        "  [ ] Save the job posting URL (screenshot — postings are deleted quickly)",
        "  [ ] Record LinkedIn profile URL if applicable",
        "  [ ] Note any company CAGE code or EIN mentioned",
    ]
    report.sections.append(("Evidence Inventory", "\n".join(evidence_lines)))

    # ---- SECTION 5: How to Report --------------------------------------------
    agency_lines = ["Report to ALL applicable agencies. Do not assume one report is enough.\n"]
    for i, agency in enumerate(REPORTING_AGENCIES, 1):
        agency_lines.append(f"  [{i}] {agency['name']}")
        if agency.get("phone"):
            agency_lines.append(f"      Phone: {agency['phone']}")
        if agency.get("online_tip"):
            agency_lines.append(f"      Online: {agency['online_tip']}")
        elif agency.get("url"):
            agency_lines.append(f"      Web: {agency['url']}")
        agency_lines.append(f"      Best for: {agency['best_for']}")
        for step in agency.get("steps", []):
            agency_lines.append(f"      {step}")
        agency_lines.append("")
    report.sections.append(("How to Report — Step-by-Step Agency Instructions",
        "\n".join(agency_lines)))

    # ---- SECTION 6: What NOT to Do -------------------------------------------
    report.sections.append(("Critical — What NOT to Do", (
        "1. DO NOT provide your SSN to the recruiter under any circumstances.\n"
        "2. DO NOT sign any 'authorization' forms provided by the recruiter.\n"
        "3. DO NOT engage further with this contact via phone or personal channels.\n"
        "4. DO NOT delete any communications (they are evidence).\n"
        "5. DO NOT assume 'someone else reported it' — each incident report is separate.\n"
        "6. DO NOT access DISS or any government system to verify their claims yourself.\n"
        "\n"
        "The only channel through which your SSN should travel for clearance purposes\n"
        "is NBIS eApp (eapp.nbis.mil) — initiated by the FSO, accessed directly by you."
    )))

    # ---- SECTION 7: Legal Reference ------------------------------------------
    report.sections.append(("Legal Authority Reference", (
        "32 CFR Part 117 (NISPOM) — effective March 2021:\n"
        "  §117.10(a)(5)  — No cache of cleared employees\n"
        "  §117.10(a)(7)  — No clearance checks for non-employees\n"
        "  §117.10(d)     — SF-86 completed only in NBIS eApp (e-QIP successor)\n"
        "  §117.10(d)(1)  — FSO review for completeness only; prohibited from sharing\n"
        "  §117.10(f)(1)(i)  — Written offer required before any clearance action\n"
        "  §117.10(f)(1)(ii) — Written acceptance required before any clearance action\n"
        "  §117.10(h)(1)-(2) — Reciprocity: prior investigation must be reused\n"
        "  5 U.S.C. §552a — Privacy Act: SSN is a protected record\n"
        "\n"
        "Full text: https://www.ecfr.gov/current/title-32/part-117\n"
        "DCSA NISPOM info: https://www.dcsa.mil/mc/pv/mb/nisp/"
    )))

    return report


def quick_report(
    company: str,
    recruiter: str,
    violations: list[str],
    verdict: str = "SUSPICIOUS",
    fraud_score: float = 0.5,
    narrative: str = "",
) -> str:
    """
    Generate a quick plain-text incident report with minimal input.

    Args:
        company:      Company name
        recruiter:    Recruiter name
        violations:   List of CFR violation strings
        verdict:      Assessment string
        fraud_score:  0.0-1.0
        narrative:    Optional free-text description

    Returns:
        Plain-text formatted report string.
    """
    inp = IncidentReportInput(
        incident_date=date.today(),
        company_name=company,
        recruiter_name=recruiter,
        violations=violations,
        verdict=verdict,
        fraud_score=fraud_score,
        narrative=narrative,
    )
    return generate_report(inp).render()


def generate_submission_guide(ssn_compromised: bool = False) -> str:
    """
    Generate a standalone, copy-paste-ready step-by-step guide for reporting
    clearance-job fraud to all applicable agencies.

    Includes DCSA NBIS-specific contact info, FBI tip submission steps, and
    identity-theft recovery steps if SSN was compromised.

    Args:
        ssn_compromised: Set True if the target already provided their SSN —
                         adds the credit-freeze and IRS Form 14039 steps.

    Returns:
        Formatted plain-text submission guide suitable for printing or saving.
    """
    W = 72
    SEP = "═" * W
    THIN = "─" * W

    lines = [
        SEP,
        "  STEP-BY-STEP FRAUD REPORTING GUIDE",
        "  Clearance-Job Fraud — DCSA / FBI / FTC Submission Instructions",
        SEP,
        "",
        "  Complete these steps in order. Do not skip DCSA — they are the primary",
        "  authority for all NISPOM and clearance-process violations.",
        "",

        SEP,
        "  STEP 1 — Preserve Evidence  (do this BEFORE contacting any agency)",
        SEP,
        "  a. Forward all suspicious emails to yourself and a personal archive.",
        "  b. Screenshot every message, job posting, and LinkedIn/profile page.",
        "     Include visible timestamps in every screenshot.",
        "  c. Record: exact dates/times of contact, what was said, what was asked.",
        "  d. Save the recruiter's phone number and all callback numbers.",
        "  e. Save job posting URLs immediately — postings vanish within hours.",
        "",

        SEP,
        "  STEP 2 — Notify Your FSO  (required if you hold an active clearance)",
        SEP,
        "  Your Facility Security Officer must be notified of any suspicious contact",
        "  involving your security clearance. This is required under 32 CFR §117.7(c).",
        "  Contact your employer's security office or program security officer.",
        "",

        SEP,
        "  STEP 3 — File with DCSA Counterintelligence  (PRIMARY report)",
        SEP,
        "  Phone:      (571) 305-6576",
        "  CI page:    https://www.dcsa.mil/mc/ci/",
        "  MITS form:  https://www.dcsa.mil/Portals/91/Documents/pv/mits/",
        "              MITS_Industry_Tip_Reporting_Form.pdf",
        "  OIG hotline: 1-855-865-1508  |  dcsa.ig@mail.mil",
        "",
        "  What to include in the MITS form:",
        "    • Company name and CAGE code (if known)",
        "    • Recruiter name, email address, and phone number",
        "    • Dates and times of every contact",
        "    • Exactly what was requested of you (SSN, fees, forms, etc.)",
        "    • List of NISPOM violations detected (e.g., §117.10(a)(7))",
        "    • Attach evidence as PDF (screenshots, exported emails)",
        "  Ask for a case/incident reference number — save it.",
        "",

        SEP,
        "  STEP 4 — NBIS  (if the background investigation process was abused)",
        SEP,
        "  Use this step when someone:",
        "    • Claimed to 'initiate' your background investigation",
        "    • Asked for SSN using DISS / NBIS / eApp / SF-86 as justification",
        "    • Impersonated an FSO or SSO in the investigation context",
        "",
        "  Industry/FSO Contact Center (cleared contractors and their FSOs):",
        "    Email: dcsa.ncr.nbis.mbx.contact-center@mail.mil",
        "    Phone: (878) 274-1765  |  Hours: 6 a.m.–5 p.m. EST, Mon–Fri",
        "    Web:   https://www.dcsa.mil/Systems-Applications/",
        "           National-Background-Investigation-Services-NBIS/",
        "",
        "  NBIS Agency Support (for SSOs/FSOs with vetting.nbis.mil access):",
        "    Email: dcsa.boyers.nbis.mbx.nbis-agency-support@mail.mil",
        "    Phone: (878) 274-5080  |  Hours: 6 a.m.–4:30 p.m. EST, Mon–Fri",
        "",
        "  ⚠  REMINDER: The ONLY authorized portal for submitting SSN in a clearance",
        "     investigation is NBIS eApp (https://eapp.nbis.mil), initiated by your",
        "     FSO. You access it directly. No recruiter or third party handles it.",
        "",

        SEP,
        "  STEP 5 — File an FBI Tip",
        SEP,
        "  National security / counterintelligence (DPRK, foreign recruitment):",
        "    Online: https://tips.fbi.gov → Submit a Tip → National Security",
        "",
        "  Internet / cyber-enabled fraud (fake websites, wire fraud, job fraud):",
        "    Online: https://complaint.ic3.gov → File a Complaint",
        "",
        "  Include: all recruiter contact details, what was requested, any foreign",
        "  indicators (camera-off, Telegram-only, foreign accent, laptop shipping).",
        "  Attach screenshots or exported email files where possible.",
        "",
    ]

    if ssn_compromised:
        lines += [
            SEP,
            "  STEP 6 — URGENT: SSN Was Compromised — Act Within 24 Hours",
            SEP,
            "  a. FTC Identity Theft Report (creates personalized recovery plan):",
            "     Web:   https://identitytheft.gov",
            "     Phone: 1-877-382-4357 (1-877-FTC-HELP)",
            "",
            "  b. Place a credit freeze at ALL three bureaus (separate for each):",
            "     Equifax:     equifax.com/freeze         |  1-800-685-1111",
            "     Experian:    experian.com/freeze         |  1-888-397-3742",
            "     TransUnion:  transunion.com/freeze       |  1-888-909-8872",
            "",
            "  c. File IRS Form 14039 (Identity Theft Affidavit) to protect tax records:",
            "     https://www.irs.gov/pub/irs-pdf/f14039.pdf",
            "     IRS Identity Protection: 1-800-908-4490",
            "",
            "  d. Report to SSA Office of Inspector General:",
            "     Web:   https://oig.ssa.gov/report",
            "     Phone: 1-800-269-0271",
            "",
        ]
    else:
        lines += [
            SEP,
            "  STEP 6 — FTC Report  (job fraud, application fees, fake recruiters)",
            SEP,
            "  Web:   https://reportfraud.ftc.gov",
            "  Phone: 1-877-382-4357 (1-877-FTC-HELP)",
            "",
            "  If you also provided your SSN, re-run this report with --ssn-given",
            "  flag or run: fraud-check report-fraud --type ssn_stolen --ssn-given",
            "",
        ]

    lines += [
        SEP,
        "  STEP 7 — Document All Reports",
        SEP,
        "  • Save all case numbers, confirmation emails, and agent names.",
        "  • Keep copies of your reports for at least 7 years.",
        "  • Follow up with each agency if no acknowledgment within 30 days.",
        "",
        THIN,
        "  Verify a company:   fraud-check verify-company \"Company Name\"",
        "  Analyze a message:  fraud-check scan-text \"message text\"",
        "  Analyze a posting:  fraud-check scan-job \"job posting text\"",
        "  Agency list:        fraud-check report-fraud",
        THIN,
    ]

    return "\n".join(lines)
