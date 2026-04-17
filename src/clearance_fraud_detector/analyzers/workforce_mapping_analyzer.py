"""
Workforce Mapping Analyzer.

Detects patterns consistent with foreign intelligence collection operations and
commercial data brokers building databases of cleared US personnel.

Distinguished from outright fraud detection:
    A workforce mapping operation may use a real company, a real domain, and a
    real recruiter — yet the interaction pattern serves intelligence collection
    objectives regardless of whether the recruiter is a witting participant.

FBI advisory reference ("Think Before You Link"):
    https://www.fbi.gov/investigate/counterintelligence/the-china-threat/
    clearance-holders-targeted-on-social-media-nevernight-connection

    FBI-documented signs of targeting:
        1. Too good to be true — disproportionate salary, flexible work for clearance role
        2. Flattery — excessive focus on clearance/skills/government affiliation
        3. Scarcity — limited, exclusive, one-off opportunity framing
        4. Lack of depth — no verifiable company info, role lacks tangible details
        5. Urgency — rushing off the networking platform to another channel
        6. Imbalance — focus on role/company, no validation of the candidate

What gets collected by responding:
    REPLY ONLY     -> confirms email active + person is clearance-eligible and job-seeking
    RESUME         -> cleared employer chain, program history, clearance level, home address
    ACTIVE STATUS  -> current clearance level, scope, active/inactive, recent investigations
    REFERENCES     -> secondary network of cleared professionals (social graph expansion)
    PROGRAM NAMES  -> access compartments, IC programs, facility names, contract numbers
"""
import re
from dataclasses import dataclass, field
from enum import Enum


def _p(regex: str) -> re.Pattern:
    return re.compile(regex, re.IGNORECASE | re.DOTALL)


# ---------------------------------------------------------------------------
# Detection patterns
# ---------------------------------------------------------------------------

# Probing for ACTIVE/CURRENT clearance status (distinct from "eligible to obtain")
_ACTIVE_STATUS_PROBE = _p(
    r"(do\s+you\s+(currently|presently)?\s*"
    r"(hold|have|possess|maintain)\s+(an?\s+)?"
    r"(active|current|valid|existing)\s*(security\s+)?clearance"
    r"|what\s+(is|[\u2019's]+)\s+your\s+(current|active|existing)?\s*"
    r"(clearance|security\s+clearance)\s*(level|status|tier)?"
    r"|is\s+your\s+clearance\s+(active|current|valid|still\s+active|in\s+scope)"
    r"|currently\s+(hold|possess|have|maintain)\s+(a\s+)?"
    r"(ts/?sci|top\s+secret|secret\s+clearance|security\s+clearance)"
    r"|your\s+(current|active|existing)\s+(clearance\s+level|clearance\s+status|security\s+clearance))"
)

# Resume request (any form)
_RESUME_REQUEST = _p(
    r"(send|forward|email|share|attach|submit)\s+"
    r"(me\s+|us\s+|over\s+)?(your\s+)?(most\s+recent\s+)?(resume|cv)\b"
    r"|your\s+(resume|cv)\s+(to\s+me|to\s+us|over\s+to\s+me)"
)

# Anonymous / confidential client language
_ANONYMOUS_CLIENT = _p(
    r"(our\s+client|the\s+client|my\s+client|a\s+client"
    r"|\bclient\s+(?:cannot|can\s+not|is|has|wants|will|needs|requires?|seeks?))"
    r".{0,300}"
    r"(clearance|cleared|ts/?sci|top\s+secret|secret|dod|defense|government|national\s+security)"
    r"|(clearance|cleared|ts/?sci|top\s+secret|secret|dod|defense|government)"
    r".{0,300}"
    r"(our\s+client|the\s+client|my\s+client|a\s+client"
    r"|\bclient\s+(?:cannot|can\s+not|is|has|wants|will|needs|requires?|seeks?))"
)

_CONFIDENTIAL_EMPLOYER = _p(
    r"(client\s+(name\s+)?(is\s+)?(confidential|withheld|not\s+disclosed|anonymous)"
    r"|confidential\s+(employer|company|client|organization)"
    r"|company\s+name\s+(withheld|confidential|not\s+disclosed)"
    r"|client\s+(wishes|prefers|wants|has\s+asked)\s*.{0,50}"
    r"(remain\s+anonymous|not\s+be\s+named|confidential|undisclosed))"
)

# Named employer (reduces risk — company is identifiable)
_NAMED_EMPLOYER = _p(
    r"\b(booz\s+allen(\s+hamilton)?|leidos|saic|raytheon(\s+technologies)?|northrop\s+grumman"
    r"|lockheed\s+martin|l3\s+harris|caci|mantech|two\s+six\s+tech(nologies)?"
    r"|general\s+dynamics|bae\s+systems|accenture(\s+federal)?|deloitte(\s+government)?"
    r"|kpmg|parsons\s+(corp(oration)?)?|perspecta|maximus|peraton|mitre"
    r"|aerospace\s+corp(oration)?|robert\s+half|kelly\s+(services?|gov(ernment)?)"
    r"|insight\s+global|staffmark|clearancejobs"
    r"|[A-Z][a-zA-Z]+\s+(?:Technologies?|Systems?|Solutions?|Group|Corp(?:oration)?|Inc\.?|LLC\.?|Federal))\b"
)

# Requisition / job ID present (positive structural signal)
_REQUISITION_PRESENT = _p(
    r"(req(?:uisition)?\s*(?:#|no\.?|number|id|:)\s*[\w-]{4,}"
    r"|\bJR[-\s]?\d{4,}\b"
    r"|\bjob\s+(?:id|code)\s*:?\s*[\w-]{4,}"
    r"|\bposition\s+(?:id|code|number)\s*:?\s*[\w-]{4,}"
    r"|\breq\s*#?\s*\d{4,}\b)"
)

# Clearance context present (to know if this is a cleared-role message)
_CLEARANCE_CONTEXT = _p(
    r"(clearance|ts/?sci|top\s+secret|secret\s+clearance|dod|defense"
    r"|national\s+security|security\s+clearance|eligible\s+to\s+obtain|clearance\s+eligible)"
)

# Classified program / project history probe
_PROGRAM_PROBE = _p(
    r"(what\s+(programs?|projects?|contracts?)\s+"
    r"(?:have\s+you\s+)?(?:worked\s+(?:on|with)|supported?|been\s+involved)"
    r"|(?:detail|describe)\s+.{0,30}(?:classified|cleared|government|dod|intel)\s*(?:work|experience)"
    r"|(?:classified|government|intel(?:ligence)?)\s+programs?\s+.{0,30}(?:tell|describe|detail|discuss)"
    r"|(?:tell|describe|discuss)\s+.{0,30}(?:classified|cleared|dod)\s+(?:work|experience|programs?))"
)

# Pre-screen reference harvesting
_EARLY_REFERENCES = _p(
    r"(references?\s+(?:before|prior\s+to|upfront|at\s+this\s+(?:stage|point|time))"
    r"|(?:provide|send|share|list)\s+(?:your\s+)?(?:professional\s+)?references?"
    r"\s+(?:now|today|immediately|before|first|at\s+this\s+(?:stage|time))"
    r"|need\s+(?:your\s+)?references?\s+(?:before|prior|now|today|first))"
)

# Cleared employer history collection
_EMPLOYER_MINING = _p(
    r"(what\s+(?:cleared\s+)?contractors?\s+(?:have\s+you|you\s+have)\s+(?:worked\s+(?:for|with)|been\s+employed)"
    r"|which\s+(?:defense|government)\s+(?:contractors?|companies?|firms?).{0,50}(?:worked?\s+(?:for|with)|employed?\s+by)"
    r"|(?:list|name|tell\s+me)\s+.{0,20}(?:previous|past|former|prior)\s+(?:cleared\s+)?(?:employers?|contractors?|companies?))"
)

# FBI signal: flattery focused on clearance / government affiliation
_FLATTERY_CLEARANCE = _p(
    r"(your\s+(?:impressive|strong|great|relevant|outstanding)\s*.{0,50}"
    r"(?:clearance|cleared\s+background|security\s+clearance|ts/?sci|government\s+background)"
    r"|(?:clearance|cleared\s+background|ts/?sci)\s*.{0,80}"
    r"(?:makes?\s+you|perfect\s+(?:fit|match|candidate)|exactly\s+what|stood\s+out|caught\s+(?:my|our)\s+eye))"
)

# FBI signal: scarcity / exclusive framing for cleared role
_SCARCITY_EXCLUSIVE = _p(
    r"(exclusive|one.?time|unique|rare)\s*.{0,60}"
    r"(?:clearance|cleared|dod|government|ts/?sci|secret)"
    r"|(?:clearance|cleared|dod|ts/?sci)\s*.{0,60}"
    r"(?:exclusive|one.?time|unique|rare)"
)

# FBI signal: urgency to move off platform
_URGENCY_OFF_PLATFORM = _p(
    r"(respond\s+(?:to\s+me\s+)?(?:directly|privately|personally)"
    r"|communicate\s+(?:off|outside)\s*.{0,20}(?:platform|site|linkedin|clearancejobs)"
    r"|(?:let[\u2019']?s?\s+)?talk\s+(?:on|via|over)\s+(?:signal|telegram|whatsapp|phone|text)"
    r"|move\s+(?:our\s+(?:conversation|discussion)|this)\s+(?:off|to)\s+(?:signal|telegram|whatsapp|phone))"
)

# Email address confirmation targeting a cleared professional
_EMAIL_CONFIRMATION_PROBE = _p(
    r"(?:is\s+this\s+(?:still\s+)?(?:your|the\s+right|the\s+best|a\s+good)"
    r".{0,20}(?:email|address|contact)"
    r"|best\s+(?:email|way)\s+to\s+(?:reach|contact)\s+you"
    r"|confirm.{0,20}(?:this\s+is\s+)?(?:your|the\s+right|the\s+best)\s+(?:email|contact))"
    r".{0,200}"
    r"(?:clearance|cleared|dod|ts/?sci|top\s+secret|government|defense)"
)


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------

class WorkforceMappingVerdict(str, Enum):
    CLEAN = "CLEAN"
    # Legitimate outreach but structurally builds a cleared-professional database
    COMMERCIAL_HARVEST = "COMMERCIAL_HARVEST"
    # Active CI risk — matches FBI advisory patterns
    CI_RISK = "CI_RISK"
    # Multiple strong indicators consistent with deliberate intelligence collection
    CONFIRMED_COLLECTION = "CONFIRMED_COLLECTION"


@dataclass
class WorkforceMappingSignal:
    category: str
    description: str
    severity: str        # "critical" | "high" | "medium" | "low"
    detail: str
    weight: float


@dataclass
class WorkforceMappingAnalysis:
    """
    Result of workforce mapping / cleared community profiling analysis.

    This is not about whether the job is fake — it is about whether the
    interaction pattern serves intelligence collection objectives against
    cleared US personnel, regardless of the sender's intent.
    """
    signals: list[WorkforceMappingSignal] = field(default_factory=list)
    risk_score: float = 0.0
    verdict: WorkforceMappingVerdict = WorkforceMappingVerdict.CLEAN
    collection_vectors: list[str] = field(default_factory=list)
    fbi_indicator_matches: list[str] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)
    has_named_company: bool = True
    has_requisition: bool = True

    @property
    def is_ci_reportable(self) -> bool:
        """True if a current clearance holder should report this contact to their FSO."""
        return self.verdict in (
            WorkforceMappingVerdict.CI_RISK,
            WorkforceMappingVerdict.CONFIRMED_COLLECTION,
        )


# ---------------------------------------------------------------------------
# Main analysis function
# ---------------------------------------------------------------------------

def analyze_workforce_mapping(
    text: str,
    sender: str = "",
    subject: str = "",
    contact_channel: str = "",
) -> WorkforceMappingAnalysis:
    """
    Analyze a recruiter message for workforce mapping / cleared community profiling.

    Args:
        text:            Full body text of the message.
        sender:          Sender email address (used for channel risk assessment).
        subject:         Message subject line.
        contact_channel: How contact was initiated:
                         "email" | "linkedin" | "clearancejobs" | "phone" |
                         "text" | "telegram" | "whatsapp" | "signal"
                         Personal-domain email to a cleared professional elevates risk.

    Returns:
        WorkforceMappingAnalysis with risk score, verdict, collection vectors,
        FBI advisory matches, and CI-specific recommendations.
    """
    full_text = f"{subject}\n{text}"
    signals: list[WorkforceMappingSignal] = []
    score = 0.0
    fbi_matches: list[str] = []
    collection_vectors: list[str] = []

    # --- Structural checks ---
    is_cleared_context = bool(_CLEARANCE_CONTEXT.search(full_text))
    has_named_employer = bool(_NAMED_EMPLOYER.search(full_text))
    has_requisition = bool(_REQUISITION_PRESENT.search(full_text))
    has_resume_request = bool(_RESUME_REQUEST.search(full_text))
    has_anonymous_client = bool(
        _ANONYMOUS_CLIENT.search(full_text) or _CONFIDENTIAL_EMPLOYER.search(full_text)
    )

    # --- Baseline collection vector: replying at all ---
    if is_cleared_context:
        collection_vectors.append(
            "REPLY: Confirms email address is active and belongs to a clearance-eligible "
            "person who is actively job-seeking."
        )

    # --- Signal 1: Anonymous client for a cleared role ---
    if is_cleared_context and has_anonymous_client:
        signals.append(WorkforceMappingSignal(
            category="anonymous_client",
            description="Anonymous client for cleared role",
            severity="high",
            detail=(
                "The hiring company is unnamed, yet a security clearance is required. "
                "A cleared professional's resume contains their entire clearance access "
                "history, cleared employer chain, and program associations — all sensitive "
                "data. Submitting this to an unidentified party means your clearance "
                "history enters an unknown database. Ask for the company name before "
                "sending. A legitimate cleared-job recruiter will provide it or give a "
                "credible reason (competitor sensitivity, contract not yet awarded)."
            ),
            weight=0.30,
        ))
        score += 0.30
        collection_vectors.append(
            "RESUME: Discloses cleared employer history, program associations, and clearance "
            "access record to an unidentified third party."
        )

    elif is_cleared_context and not has_named_employer:
        # Company is not named (not explicitly anonymous, just absent)
        signals.append(WorkforceMappingSignal(
            category="unnamed_employer",
            description="No company identified for cleared role",
            severity="medium",
            detail=(
                "This message references a clearance requirement but does not identify the "
                "hiring company. Every cleared position is tied to a specific FCL holder. "
                "Ask for the company name before engaging further."
            ),
            weight=0.15,
        ))
        score += 0.15

    # --- Signal 2: Resume request without employer identification ---
    if is_cleared_context and has_resume_request and (has_anonymous_client or not has_named_employer):
        signals.append(WorkforceMappingSignal(
            category="resume_collection",
            description="Resume requested for unidentified cleared employer",
            severity="high",
            detail=(
                "A resume is being solicited for a cleared role before the hiring company "
                "has been identified. A cleared professional's resume reveals: cleared "
                "employer chain, program history, clearance level, and home address. "
                "Submit resumes only through verified company ATS portals (e.g., careers "
                "pages), not directly to a recruiter's email for an unnamed client."
            ),
            weight=0.25,
        ))
        score += 0.25

    # --- Signal 3: Active clearance status probe ---
    if _ACTIVE_STATUS_PROBE.search(full_text):
        signals.append(WorkforceMappingSignal(
            category="clearance_status_probe",
            description="Active clearance level confirmation requested",
            severity="critical",
            detail=(
                "The message asks whether you currently hold an active clearance — not "
                "just whether you are 'eligible to obtain' one. This directly probes your "
                "current access level and scope. Per FBI 'Think Before You Link': clearance "
                "holders should NOT confirm clearance status to unvetted contacts online. "
                "Responding maps you as a verified active cleared person in the requestor's "
                "database. If you hold a current clearance, this contact may be CI-reportable."
            ),
            weight=0.50,
        ))
        score += 0.50
        fbi_matches.append("Direct query of active clearance level/status")
        collection_vectors.append(
            "ACTIVE STATUS: Confirms current clearance level and scope to an unvetted party."
        )

    # --- Signal 4: Classified program/project history probe ---
    if _PROGRAM_PROBE.search(full_text):
        signals.append(WorkforceMappingSignal(
            category="program_history_probe",
            description="Classified program/project history requested",
            severity="critical",
            detail=(
                "The message asks about specific programs, projects, or classified work. "
                "Program names, contract numbers, and compartment descriptions are sensitive. "
                "Discussing them with an unvetted party before any offer or NDA exists is a "
                "security violation risk. Real recruiters ask about skills and technologies, "
                "not program names. Report to your FSO if anyone asks you to name "
                "classified programs before a formal employment relationship."
            ),
            weight=0.60,
        ))
        score += 0.60
        fbi_matches.append("Classified program/compartment probing")
        collection_vectors.append(
            "PROGRAM NAMES: Discloses access compartments, IC programs, and classified work history."
        )

    # --- Signal 5: Pre-screen reference harvesting ---
    if _EARLY_REFERENCES.search(full_text):
        signals.append(WorkforceMappingSignal(
            category="reference_harvest",
            description="Professional references requested before interview",
            severity="high",
            detail=(
                "References are being requested before any interview for a cleared role. "
                "In the cleared community, professional references are typically other "
                "cleared individuals — early collection builds a secondary database of "
                "cleared personnel. This is a social-graph expansion tactic. "
                "Standard process: references after the interview, contingent on offer."
            ),
            weight=0.35,
        ))
        score += 0.35
        collection_vectors.append(
            "REFERENCES: Discloses other cleared professionals in your network as secondary targets."
        )

    # --- Signal 6: Cleared employer chain mining ---
    if _EMPLOYER_MINING.search(full_text):
        signals.append(WorkforceMappingSignal(
            category="employer_chain_mining",
            description="Complete cleared employer history requested",
            severity="high",
            detail=(
                "The message asks for a list of all cleared contractors or defense employers. "
                "Your cleared employer chain reveals the facility clearances you've held "
                "access under, program offices you've supported, and the personnel security "
                "network you're associated with. This is more sensitive than a standard "
                "employment history — it is an access map. Disclose only post-offer."
            ),
            weight=0.40,
        ))
        score += 0.40
        collection_vectors.append(
            "EMPLOYER CHAIN: Reveals facility clearances, program offices, and access history."
        )

    # --- Signal 7: No requisition number for a cleared role ---
    if is_cleared_context and not has_requisition:
        signals.append(WorkforceMappingSignal(
            category="no_requisition",
            description="No requisition/job ID for cleared position",
            severity="low",
            detail=(
                "Every real cleared position on a DoD/IC contract has a requisition number "
                "and typically a contract or task order number. The absence of any job ID "
                "signals this may be speculative sourcing (building a resume database for "
                "future use) rather than a live open requisition. Ask for the req number "
                "and verify the posting on the company's official careers page."
            ),
            weight=0.10,
        ))
        score += 0.10

    # --- Signal 8: FBI advisory — clearance-focused flattery ---
    if _FLATTERY_CLEARANCE.search(full_text):
        signals.append(WorkforceMappingSignal(
            category="fbi_flattery",
            description="Clearance-focused flattery (FBI advisory signal)",
            severity="medium",
            detail=(
                "FBI 'Think Before You Link': 'Flattery — your contact may overly praise "
                "or focus on your skills and experience, especially if your government "
                "affiliation is known.' This message focuses on your clearance or cleared "
                "background as a primary qualification."
            ),
            weight=0.20,
        ))
        score += 0.20
        fbi_matches.append("Flattery — excessive focus on clearance/government affiliation")

    # --- Signal 9: FBI advisory — scarcity / exclusive framing ---
    if _SCARCITY_EXCLUSIVE.search(full_text):
        signals.append(WorkforceMappingSignal(
            category="fbi_scarcity",
            description="Exclusive/rare framing for cleared role (FBI advisory signal)",
            severity="medium",
            detail=(
                "FBI 'Think Before You Link': 'Scarcity — there may be an emphasis on "
                "limited, one-off, or exclusive opportunities.' Real cleared contracting "
                "positions are tied to contracts — they are not exclusive opportunities."
            ),
            weight=0.20,
        ))
        score += 0.20
        fbi_matches.append("Scarcity — exclusive/one-time opportunity framing")

    # --- Signal 10: FBI advisory — urgency to move off platform ---
    if _URGENCY_OFF_PLATFORM.search(full_text):
        signals.append(WorkforceMappingSignal(
            category="fbi_platform_exit",
            description="Pressure to move off platform (FBI advisory signal)",
            severity="high",
            detail=(
                "FBI 'Think Before You Link': 'Urgency — your contact may attempt to rush "
                "you off the networking platform onto another communication method.' "
                "Moving off LinkedIn or ClearanceJobs removes platform-level fraud "
                "detection and makes the recruiter harder to verify."
            ),
            weight=0.35,
        ))
        score += 0.35
        fbi_matches.append("Urgency — pushing off monitored platform to direct channel")

    # --- Signal 11: Email address confirmation probe ---
    if _EMAIL_CONFIRMATION_PROBE.search(full_text):
        signals.append(WorkforceMappingSignal(
            category="email_confirmation",
            description="Email address confirmation requested",
            severity="medium",
            detail=(
                "Asking a cleared professional to confirm their email is correct. "
                "This validates the email-to-clearance-holder mapping in a targeting "
                "database. Do not confirm contact details to unsolicited outreach."
            ),
            weight=0.20,
        ))
        score += 0.20
        collection_vectors.append(
            "EMAIL CONFIRM: Validates that this email belongs to an active clearance holder."
        )

    # --- Contact channel risk ---
    channel = contact_channel.lower()
    sender_lower = sender.lower()
    is_personal_email_sender = any(
        d in sender_lower for d in
        ["@gmail.", "@yahoo.", "@hotmail.", "@outlook.com", "@icloud.", "@proton.", "@aol."]
    )

    if channel in ("telegram", "whatsapp", "signal", "text", "sms"):
        signals.append(WorkforceMappingSignal(
            category="channel_risk",
            description=f"Cleared job contact via {contact_channel} (unmonitored channel)",
            severity="critical",
            detail=(
                f"Initial cleared-job contact via {contact_channel} has no corporate "
                "audit trail and bypasses platform-level identity verification. "
                "Legitimate defense contractor recruiting uses corporate email and ATS. "
                "Unmonitored channels are specifically preferred by threat actors because "
                "they leave no evidentiary record."
            ),
            weight=0.50,
        ))
        score += 0.50

    elif is_personal_email_sender and is_cleared_context:
        signals.append(WorkforceMappingSignal(
            category="channel_risk",
            description="Cleared job outreach from personal email domain",
            severity="high",
            detail=(
                "This cleared-job outreach was sent from a personal email address. "
                "Legitimate defense contractor recruiters always use corporate email. "
                "Per Robert Half's own anti-fraud guidance: 'We never use personal "
                "emails such as @gmail, @hotmail, or @yahoo accounts.'"
            ),
            weight=0.30,
        ))
        score += 0.30

    # --- Clamp and determine verdict ---
    total = round(min(score, 1.0), 3)

    if total < 0.15:
        verdict = WorkforceMappingVerdict.CLEAN
    elif total < 0.40:
        verdict = WorkforceMappingVerdict.COMMERCIAL_HARVEST
    elif total < 0.65:
        verdict = WorkforceMappingVerdict.CI_RISK
    else:
        verdict = WorkforceMappingVerdict.CONFIRMED_COLLECTION

    recommendations = _build_recommendations(
        signals, has_named_employer, has_anonymous_client,
        has_resume_request, is_cleared_context, verdict,
    )

    return WorkforceMappingAnalysis(
        signals=signals,
        risk_score=total,
        verdict=verdict,
        collection_vectors=collection_vectors,
        fbi_indicator_matches=fbi_matches,
        recommendations=recommendations,
        has_named_company=has_named_employer,
        has_requisition=has_requisition or not is_cleared_context,
    )


def _build_recommendations(
    signals: list[WorkforceMappingSignal],
    has_named_employer: bool,
    has_anonymous_client: bool,
    has_resume_request: bool,
    is_cleared_context: bool,
    verdict: WorkforceMappingVerdict,
) -> list[str]:
    recs: list[str] = []
    categories = {s.category for s in signals}

    if has_resume_request and (has_anonymous_client or not has_named_employer) and is_cleared_context:
        recs.append(
            "Do NOT send your resume until the hiring company is independently verified. "
            "Ask the recruiter: 'Can you share the client company name?' "
            "If refused or deflected, decline to proceed."
        )

    if "clearance_status_probe" in categories:
        recs.append(
            "Do NOT disclose your current clearance level or active status to this contact. "
            "Per FBI advisory: clearance holders should be cautious when asked about "
            "clearance status online. If you hold a current clearance, this contact may be "
            "CI-reportable — notify your FSO."
        )

    if "program_history_probe" in categories:
        recs.append(
            "Do NOT discuss classified programs by name. Report to your FSO immediately — "
            "this type of inquiry is a documented foreign intelligence collection technique "
            "and is required to be reported under your security obligations."
        )

    if "reference_harvest" in categories:
        recs.append(
            "Do NOT provide references before an interview. In the cleared community, "
            "your references are cleared individuals who become secondary collection targets."
        )

    if "employer_chain_mining" in categories:
        recs.append(
            "Do NOT provide a complete list of cleared employers. Your cleared employer "
            "chain is a sensitive access map. Disclose only through official post-offer channels."
        )

    if verdict in (WorkforceMappingVerdict.CI_RISK, WorkforceMappingVerdict.CONFIRMED_COLLECTION):
        recs.append(
            "COUNTERINTELLIGENCE REPORTING: If you hold an active clearance, this contact "
            "meets the threshold for FSO reporting under SEAD 3 obligations. "
            "Former clearance holders can submit a tip at tips.fbi.gov."
        )
        recs.append(
            "Verify this recruiter independently: call the company's published main number "
            "(not the number in this message) and ask for this person by name."
        )

    elif verdict == WorkforceMappingVerdict.COMMERCIAL_HARVEST and not recs:
        recs.append(
            "This appears to be legitimate recruiting, but structurally collects cleared "
            "professional data. Ask for the company name before sending your resume. "
            "Responding confirms your email is active and you are a job-seeking cleared "
            "professional — this data has commercial and intelligence targeting value."
        )

    if not recs:
        recs.append(
            "No significant workforce mapping signals detected. Standard due diligence: "
            "verify the company via official channels, apply through the company's careers "
            "page, and do not disclose clearance status until the employer's FCL is verified."
        )

    return recs
