"""
Vishing / AI Voice Fraud Analyzer.

Detects indicators of:
  - AI-generated voice used during phone/video interviews
  - Fake job interview call scripts targeting clearance candidates
  - Foreign nation-state IT worker schemes (DPRK, etc.)
  - Social engineering scripts designed to harvest PII over the phone

Input: plain-text call transcript or notes from a phone/video interview.
"""
import re
from dataclasses import dataclass, field


# ---------------------------------------------------------------------------
# Red-flag phrases found in fraudulent call/interview transcripts
# ---------------------------------------------------------------------------
_CAMERA_OFF_PHRASES = re.compile(
    r"(camera\s+(must\s+be|is|should\s+be|stay|remain)\s+off"
    r"|no\s+video\s+(required|needed|allowed|please)"
    r"|audio.only\s+interview"
    r"|video\s+(not\s+)?required"
    r"|turn\s+off\s+(your\s+)?camera)",
    re.IGNORECASE,
)

_VOICE_ANOMALY_PHRASES = re.compile(
    r"(voice\s+(sounds?|seemed?|appears?)\s+(robotic|artificial|synthesized|strange|odd|mechanical|unnatural)"
    r"|ai.generated\s+voice"
    r"|voice\s+modif(ier|ication|ied)"
    r"|voice\s+changer"
    r"|synthetic\s+voice"
    r"|pitch\s+(higher|lower|different)\s+than\s+normal)",
    re.IGNORECASE,
)

_SCRIPT_READING_PHRASES = re.compile(
    r"(reading\s+from\s+(a\s+)?script"
    r"|sounded?\s+scripted"
    r"|rehearsed\s+(answers?|responses?)"
    r"|exact\s+same\s+(words?|phrases?|response)"
    r"|didn['']?t\s+(deviate|go\s+off.script)"
    r"|verbatim\s+(response|answer))",
    re.IGNORECASE,
)

_INSTANT_OFFER_PHRASES = re.compile(
    r"(hired\s+(on\s+the\s+spot|immediately|right\s+now|today)"
    r"|offer\s+(letter\s+)?within\s+(minutes?|hours?)"
    r"|start\s+(right\s+away|immediately|today|as\s+soon\s+as)"
    r"|no\s+(further\s+)?(interview|step|process)\s+(needed|required)"
    r"|skip\s+the\s+interview"
    r"|you['']?re\s+(already\s+)?hired)",
    re.IGNORECASE,
)

_PERSONAL_INFO_ON_CALL_PHRASES = re.compile(
    r"(your\s+(social\s+security|ssn|date\s+of\s+birth|dob|home\s+address|bank\s+account)"
    r"\s+(number|#|details?|info)"
    r"|please\s+(provide|give|share|confirm)\s+(your\s+)?"
    r"(ssn|social\s+security|dob|date\s+of\s+birth|passport|bank|routing)"
    r"|verify\s+(your\s+)?(identity|information|details)\s+(over\s+the\s+phone|right\s+now|on\s+this\s+call))",
    re.IGNORECASE,
)

_FOREIGN_COORDINATION_PHRASES = re.compile(
    r"(send\s+(the\s+)?laptop\s+to\s+an?\s+address"
    r"|work\s+through\s+(a\s+)?(vpn|proxy)"
    r"|appear\s+(as\s+)?(us.based|domestic|local)"
    r"|salary\s+(will\s+be\s+)?forwarded?"
    r"|(forwarding|relay)\s+address"
    r"|managed\s+laptop|laptop\s+farm)",
    re.IGNORECASE,
)

_TELEGRAM_ONLY_PHRASES = re.compile(
    r"(contact\s+(us\s+)?only\s+(via|on|through|at)\s+(telegram|whatsapp|signal|wechat)"
    r"|reach\s+(me\s+)?on\s+(telegram|whatsapp|signal)"
    r"|do\s+not\s+(call|email|call\s+or\s+email).{0,30}(telegram|whatsapp|signal)"
    r"|all\s+(communication|contact).{0,30}(via|through|on)\s+(telegram|whatsapp|signal))",
    re.IGNORECASE,
)

_NO_IN_PERSON_PHRASES = re.compile(
    r"(no\s+in.person\s+(interview|meeting|visit)"
    r"|fully\s+remote\s+(interview|hiring\s+process)"
    r"|interview\s+is\s+(entirely|completely|100%)\s+(remote|virtual|online)"
    r"|you\s+(will\s+)?never\s+(need\s+to\s+)?(come\s+in|visit|meet\s+in\s+person))",
    re.IGNORECASE,
)

_ACCENT_INCONSISTENCY_PHRASES = re.compile(
    r"(heavy\s+(foreign|non.american|non.native)\s+accent"
    r"|claimed\s+(to\s+be\s+)?(american|us\s+citizen|from\s+the\s+us)"
    r"\s+but\s+(had|has|with)\s+(a\s+)?(strong\s+)?(foreign|thick|heavy)\s+accent"
    r"|(accent|speech\s+pattern)\s+(inconsistency|mismatch|doesn['']?t\s+match))",
    re.IGNORECASE,
)

_PRESSURE_TACTICS_PHRASES = re.compile(
    r"(decide\s+(right\s+now|immediately|on\s+the\s+spot|before\s+we\s+hang\s+up)"
    r"|offer\s+expires?\s+(in\s+\d+\s+(minutes?|hours?)|today|tonight)"
    r"|other\s+candidates?\s+(are\s+)?(waiting|ready|interested)"
    r"|last\s+(chance|opportunity)\s+for\s+this\s+(position|role|job))",
    re.IGNORECASE,
)


@dataclass
class VishingFinding:
    severity: str       # "critical" | "high" | "medium" | "low"
    category: str
    finding: str
    detail: str
    weight: float       # contribution to fraud score (0.0–1.0)


@dataclass
class VishingAnalysis:
    findings: list[VishingFinding] = field(default_factory=list)
    risk_score: float = 0.0         # aggregated 0–1
    is_suspicious_call: bool = False

    @property
    def top_indicators(self) -> list[str]:
        return [f"[{r.category}] {r.finding}: {r.detail}"
                for r in sorted(self.findings, key=lambda x: x.weight, reverse=True)[:5]]


# (pattern, severity, category, finding_label, detail, weight)
_CHECKS: list[tuple[re.Pattern, str, str, str, str, float]] = [
    (_CAMERA_OFF_PHRASES, "critical", "dprk_scheme",
     "Camera-off requirement",
     "Requiring camera to be off is a primary DPRK IT worker scheme indicator — "
     "hides the interviewer's true identity and location",
     0.85),
    (_VOICE_ANOMALY_PHRASES, "critical", "ai_voice_fraud",
     "AI/synthetic voice detected",
     "Voice anomalies consistent with AI voice changers used by foreign fraud actors",
     0.90),
    (_SCRIPT_READING_PHRASES, "high", "ai_voice_fraud",
     "Script-reading behavior detected",
     "Rigid, scripted answers during a technical interview suggest a fake/coached foreign actor",
     0.70),
    (_INSTANT_OFFER_PHRASES, "critical", "fake_hiring",
     "Immediate job offer without proper process",
     "Real cleared positions require weeks-to-months of background investigation — "
     "instant offers are impossible and fraudulent",
     0.85),
    (_PERSONAL_INFO_ON_CALL_PHRASES, "critical", "pii_harvest",
     "PII requested on a phone/video call",
     "Legitimate employers NEVER ask for SSN, DOB, or bank info over an unsecured phone call",
     0.95),
    (_FOREIGN_COORDINATION_PHRASES, "critical", "dprk_scheme",
     "Foreign coordination indicators",
     "Laptop forwarding, VPN masking, and salary forwarding are hallmarks of the "
     "North Korean IT worker scheme documented in DOJ/FBI advisories",
     0.95),
    (_TELEGRAM_ONLY_PHRASES, "critical", "fake_recruiter",
     "Recruiter only reachable via Telegram/WhatsApp",
     "Legitimate defense recruiters use corporate email and phone — "
     "Telegram/WhatsApp-only contact is a near-certain fraud indicator",
     0.90),
    (_NO_IN_PERSON_PHRASES, "high", "fake_hiring",
     "No in-person meeting required for TS/SCI role",
     "TS/SCI positions almost always require in-person badging, SCIF access, and interviews",
     0.65),
    (_ACCENT_INCONSISTENCY_PHRASES, "high", "identity_fraud",
     "Claimed identity inconsistent with detected accent/speech",
     "Heavy foreign accent combined with claimed US citizenship is an identity fraud signal",
     0.75),
    (_PRESSURE_TACTICS_PHRASES, "medium", "pressure_tactics",
     "High-pressure decision tactics on a call",
     "Legitimate recruiters never require instant decisions — pressure tactics indicate scams",
     0.55),
]


def analyze_vishing(transcript: str) -> VishingAnalysis:
    """
    Analyze a call transcript or interview notes for vishing / AI voice fraud indicators.

    Args:
        transcript: Plain text of a phone/video call transcript or recruiter notes.

    Returns:
        VishingAnalysis with findings and composite risk score.
    """
    analysis = VishingAnalysis()

    for pattern, severity, category, finding, detail, weight in _CHECKS:
        if pattern.search(transcript):
            analysis.findings.append(VishingFinding(
                severity=severity,
                category=category,
                finding=finding,
                detail=detail,
                weight=weight,
            ))

    # Aggregate score (capped at 1.0)
    if analysis.findings:
        raw = sum(f.weight for f in analysis.findings)
        # Diminishing returns: each additional finding adds less
        analysis.risk_score = round(min(1 - (1 / (1 + raw * 0.5)), 1.0), 3)
        # Flag as suspicious if any single finding has high weight >= 0.75,
        # or overall risk score reaches 0.25
        has_critical = any(f.weight >= 0.75 for f in analysis.findings)
        analysis.is_suspicious_call = analysis.risk_score >= 0.25 or has_critical

    return analysis
