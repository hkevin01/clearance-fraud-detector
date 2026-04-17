"""
Job Posting Analyzer.

Detects indicators of fraudulent job postings targeting cleared candidates:
  - Salary or benefit lures that are unrealistic
  - Job requirements inconsistent with security clearance processes
  - DPRK / foreign IT worker scheme job ads
  - Identity-harvest disguised as application forms
  - Fake company signals (no verifiable identity, brand-new domains)
  - AI-generated posting patterns used to scale fraud at volume
"""
import re
from dataclasses import dataclass, field


# ---------------------------------------------------------------------------
# Pattern library for job posting analysis
# ---------------------------------------------------------------------------

# Salary bait: unrealistic pay for the advertised role
_SALARY_BAIT = re.compile(
    r"(\$\s*(?:[2-9]\d{2},\d{3}|\d{1,3},\d{3},\d{3})"
    r"\s*(?:per\s+year|\/yr|\/year|annually)?)"
    r"\s*.{0,80}"
    r"(entry.level|no\s+experience|junior|intern|trainee|fresh\s+grad)",
    re.IGNORECASE,
)

# Remote-only TS/SCI (nearly impossible — SCIF required)
_REMOTE_TSSCI = re.compile(
    r"(fully\s+remote|100%\s+remote|work\s+from\s+home|work\s+from\s+anywhere)"
    r".{0,100}"
    r"(TS[/\s]?SCI|top\s+secret|compartmented|SCI\s+eligible|classified\s+work)",
    re.IGNORECASE,
)

# Camera-off interview mentioned in a job posting
_CAMERA_OFF_JOB = re.compile(
    r"(interview.{0,30}(no\s+video|camera\s+off|audio\s+only|no\s+camera)"
    r"|video\s+not\s+required.{0,30}interview"
    r"|interview.{0,30}video.{0,20}(not\s+)?required)",
    re.IGNORECASE,
)

# Vague/anonymous company
_ANONYMOUS_COMPANY = re.compile(
    r"(company\s+name\s+(withheld|confidential|not\s+disclosed|to\s+be\s+revealed)"
    r"|confidential\s+(employer|company|client|organization)"
    r"|our\s+client\s+(wishes|prefers)\s+to\s+remain\s+anonymous"
    r"|identity\s+of\s+(employer|company)\s+(is\s+)?(confidential|not\s+disclosed))",
    re.IGNORECASE,
)

# Asking for PII in the job application itself
_PII_IN_APPLICATION = re.compile(
    r"(include\s+(your\s+)?(ssn|social\s+security|date\s+of\s+birth|dob|passport)"
    r"|application\s+requires?\s+(ssn|social\s+security|dob|date\s+of\s+birth|passport)"
    r"|submit.{0,20}(ssn|social\s+security|date\s+of\s+birth|passport)"
    r"|require.{0,40}(ssn|social\s+security|date\s+of\s+birth|dob)\s+in\s+(your\s+)?application)",
    re.IGNORECASE,
)

# Fee to apply
_APPLICATION_FEE = re.compile(
    r"(application\s+fee|processing\s+fee|registration\s+fee|submission\s+fee"
    r"|fee\s+to\s+apply|pay\s+to\s+(apply|submit|register|participate))",
    re.IGNORECASE,
)

# Clearance guarantee in a job ad
_CLEARANCE_GUARANTEE = re.compile(
    r"(guarant(ee|eed|y|ying)\s+(you\s+|your\s+)?[\w\s/]{0,30}clearance"
    r"|clearance\s+guarant(ee|eed|y)"
    r"|we\s+(can|will)\s+(get|obtain|provide|secure)\s+(you\s+)?(a\s+)?clearance)",
    re.IGNORECASE,
)

# Immediate start — weeks vs. months contradiction
_IMMEDIATE_START_CLEARED = re.compile(
    r"(start\s+(immediately|right\s+away|asap|this\s+week|next\s+week)"
    r".{0,100}"
    r"(clearance|secret|ts[/\s]?sci|classified)"
    r"|(clearance|secret|ts[/\s]?sci|classified)"
    r".{0,100}"
    r"start\s+(immediately|right\s+away|asap|this\s+week|next\s+week))",
    re.IGNORECASE,
)

# No background check mentioned
_NO_BACKGROUND_CHECK = re.compile(
    r"(no\s+background\s+(check|investigation)\s+(required|needed|necessary)"
    r"|background\s+(check|investigation)\s+not\s+required"
    r"|skip\s+(the\s+)?background)",
    re.IGNORECASE,
)

# Text/chat-only application process
_TEXT_ONLY_APPLICATION = re.compile(
    r"(apply\s+(via|through|on|using)\s+(whatsapp|telegram|signal|text|sms)"
    r"|send\s+(your\s+)?(resume|cv|application)\s+(to|via|on)\s+(whatsapp|telegram|signal|text)"
    r"|contact.{0,20}(whatsapp|telegram|signal)\s+to\s+apply)",
    re.IGNORECASE,
)

# Non-existent or unlikely employer size for the clearance work claimed
_FAKE_SMALL_COMPANY = re.compile(
    r"(small\s+(team|company|firm|startup).{0,80}(ts[/\s]?sci|top\s+secret|compartmented|sci\s+eligible)"
    r"|(ts[/\s]?sci|top\s+secret|compartmented).{0,80}small\s+(team|company|firm|startup))",
    re.IGNORECASE,
)

# Generic reused posting templates (identical phrase clusters)
_GENERIC_TEMPLATE = re.compile(
    r"(we\s+offer\s+(competitive\s+salary|benefits\s+package|exciting\s+opportunity)"
    r".{0,100}"
    r"(apply\s+now|do\s+not\s+miss|limited\s+time|apply\s+today)"
    r"|we\s+are\s+looking\s+for\s+(a\s+)?(motivated|passionate|dynamic|dedicated)"
    r".{0,100}(clearance|secret|ts[/\s]?sci))",
    re.IGNORECASE,
)

# Relocation / laptop-farm signals embedded in job postings
_LAPTOP_FARM_JOB = re.compile(
    r"(equipment\s+(will\s+be\s+)?shipped|laptop\s+(provided|sent|mailed|shipped)"
    r"\s+to\s+(your\s+)?(home|address|location)"
    r"|work\s+(from\s+)?(your\s+)?(home|own)\s+(computer|device|equipment)"
    r".{0,100}(clearance|classified|secret|ts[/\s]?sci))",
    re.IGNORECASE,
)


@dataclass
class JobPostingFinding:
    severity: str       # "critical" | "high" | "medium" | "low"
    category: str
    finding: str
    detail: str
    weight: float


@dataclass
class JobPostingAnalysis:
    findings: list[JobPostingFinding] = field(default_factory=list)
    risk_score: float = 0.0
    is_fraudulent: bool = False

    @property
    def top_indicators(self) -> list[str]:
        return [f"[{r.category}] {r.finding}"
                for r in sorted(self.findings, key=lambda x: x.weight, reverse=True)[:5]]


_JOB_CHECKS: list[tuple[re.Pattern, str, str, str, str, float]] = [
    (_SALARY_BAIT, "high", "salary_fraud",
     "Unrealistic salary for entry-level cleared position",
     "Six-plus figure packages for entry-level/no-experience cleared roles are bait",
     0.70),
    (_REMOTE_TSSCI, "critical", "logistics_fraud",
     "Fully remote TS/SCI work advertised",
     "TS/SCI work requires physical SCIF access — fully remote postings are fraudulent",
     0.85),
    (_CAMERA_OFF_JOB, "critical", "dprk_scheme",
     "Camera-off interview in job posting",
     "Requiring camera-off interviews is a primary DPRK IT worker scheme indicator",
     0.90),
    (_ANONYMOUS_COMPANY, "high", "identity_concealment",
     "Anonymous/confidential employer for a cleared position",
     "Legitimate cleared employers cannot hide their identity — FOCI and facility "
     "clearance requirements mandate disclosure",
     0.75),
    (_PII_IN_APPLICATION, "critical", "pii_harvest",
     "SSN/DOB/Passport required in initial job application",
     "Legitimate employers never collect SSN or DOB in the initial application — "
     "this is a PII harvest scheme",
     0.95),
    (_APPLICATION_FEE, "critical", "financial_fraud",
     "Fee required to apply for position",
     "Legitimate employers NEVER charge application fees — this is always fraud",
     0.95),
    (_CLEARANCE_GUARANTEE, "critical", "clearance_fraud",
     "Clearance guarantee advertised",
     "No one can guarantee a security clearance — DCSA adjudicates individuals, "
     "not companies",
     1.0),
    (_IMMEDIATE_START_CLEARED, "high", "logistics_fraud",
     "Immediate start for cleared position",
     "Background investigations take 3–18+ months; immediate cleared starts are impossible",
     0.75),
    (_NO_BACKGROUND_CHECK, "critical", "clearance_fraud",
     "Background check waived for cleared role",
     "All cleared positions legally require background investigations — "
     "advertising otherwise is fraud",
     0.90),
    (_TEXT_ONLY_APPLICATION, "critical", "fake_recruiter",
     "Application via WhatsApp/Telegram/SMS only",
     "Real cleared positions use official corporate HR systems, not consumer messaging apps",
     0.90),
    (_FAKE_SMALL_COMPANY, "high", "fake_company",
     "Small/startup claims TS/SCI work",
     "TS/SCI contracts require facility clearance (FCL) — tiny unnamed startups "
     "rarely hold FCL",
     0.65),
    (_GENERIC_TEMPLATE, "medium", "ai_generated",
     "AI-generated/copy-paste job posting template",
     "Identical template language across postings indicates mass-produced fraud ads",
     0.50),
    (_LAPTOP_FARM_JOB, "critical", "dprk_scheme",
     "Laptop shipping/home device for classified work",
     "Classified work requires government-furnished or SCIF equipment — "
     "home device/laptop-farm is a DPRK scheme indicator",
     0.90),
]


# ID: JP-001
# Requirement: Score a job posting text against 13 fraud indicator checks and return a
#              JobPostingAnalysis with a logistic risk score and categorized findings.
# Purpose: Detect fake clearance job postings — from simple PII-harvest forms to DPRK
#          IT-worker laptop-farm schemes — before a candidate submits any personal data.
# Rationale: Logistic-style scoring (1 − 1/(1 + raw×0.5)) provides diminishing returns
#             so that a single strong signal is distinguishable from many weak signals without
#             a single check saturating the scale.
# Inputs: posting_text (str) — full text of a job posting; may be multi-paragraph.
# Outputs: JobPostingAnalysis with risk_score ∈ [0, 1], is_fraudulent flag, and findings list.
# Preconditions: _JOB_CHECKS list is populated; posting_text is a decoded string.
# Postconditions: risk_score increases monotonically with matched check count/weights.
# Assumptions: Each _JOB_CHECKS entry is (pattern, severity, category, finding, detail, weight).
# Side Effects: None — pure function with no I/O.
# Failure Modes: Empty text returns risk_score 0.0, is_fraudulent False — no exception.
# Error Handling: No explicit guards; regex.search returns None safely on no match.
# Constraints: O(|_JOB_CHECKS| × |posting_text|); expected < 3 ms.
# Verification: test_detector.py::test_job_posting_* — fraud/clean posting classification.
# References: FBI DPRK IT Worker PSA 2023; FTC job scam guidance; 32 CFR §117.10(a)(7).
def analyze_job_posting(posting_text: str) -> JobPostingAnalysis:
    """
    Analyze a job posting for fraud / fake clearance job indicators.

    Args:
        posting_text: Full text of the job posting (copy-paste or scraped).

    Returns:
        JobPostingAnalysis with findings and composite risk score.
    """
    analysis = JobPostingAnalysis()

    for pattern, severity, category, finding, detail, weight in _JOB_CHECKS:
        if pattern.search(posting_text):
            analysis.findings.append(JobPostingFinding(
                severity=severity,
                category=category,
                finding=finding,
                detail=detail,
                weight=weight,
            ))

    if analysis.findings:
        raw = sum(f.weight for f in analysis.findings)
        analysis.risk_score = round(min(1 - (1 / (1 + raw * 0.5)), 1.0), 3)
        # Flag as fraudulent if any single finding cleared threshold weight >= 0.75,
        # or overall risk score >= 0.25
        has_critical = any(f.weight >= 0.75 for f in analysis.findings)
        analysis.is_fraudulent = analysis.risk_score >= 0.25 or has_critical

    return analysis
