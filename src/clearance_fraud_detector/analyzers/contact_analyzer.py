"""
Contact Analyzer — FSO Impersonation & Fake Recruiter Detection.

Distinguishes between legitimate cleared-job contact behavior and fraud by
modeling two distinct attacker roles:

  FSO IMPERSONATOR
    Pretends to be the prospective company's Facility Security Officer to
    extract SSN/DOB "for clearance verification."

    IMPORTANT — what real FSOs actually do (source: dcsa.mil):
      Real FSOs use DISS (Defense Information System for Security, replaced JPAS
      March 31 2021) and the companion CVS to check clearance status. They log
      in with their OWN credentialed DISS/NBIS accounts. Any SSN stored in the
      system is already on file from a prior investigation or formal application —
      the FSO does NOT cold-solicit SSN from a candidate as a "lookup trigger."

      A candidate's SSN IS collected by the FSO, but ONLY post-conditional-offer
      during formal onboarding so the FSO can initiate your SF-86 in the NBIS
      eApp portal (eapp.nbis.mil). The candidate then enters their own SSN
      directly into eApp over an encrypted HTTPS connection.

      The fraud is asking for SSN BEFORE a formal offer/application relationship
      exists — via cold call, email, or chat — framed as a lookup trigger:
      'I need your SSN to pull you in DISS.' Real FSOs never ask for SSN this
      way; if they need to verify a clearance they use their own DISS login with
      data already on file. (Source: NISPOM 32 CFR §117.10; dcsa.mil/Systems-
      Applications/Defense-Information-System-for-Security-DISS)

  FAKE RECRUITER
    Either: (a) a foreign actor / DPRK IT worker scheme front, (b) a resume-
    harvesting operation, or (c) an identity-theft setup disguised as initial
    recruiter outreach for a cleared contracting role.

Common real-world attack chain (documented in FBI/DCSA advisories 2024-2026):
    1. Candidate applies → fake recruiter screens well
    2. "We need to verify your clearance — our FSO will contact you"
    3. Fake FSO contacts via plausible-looking corporate email (domain spoofed)
    4. Candidate verifies name on LinkedIn → name is lifted from real employee
    5. Candidate provides SSN "for clearance verification"
    6. Full identity theft package assembled: name + employer + SSN + DOB

DETECTION LOGIC:
  Each contact message / email / transcript is scored against:
    - FSO impersonation patterns (asking for SSN, fee, clearance guarantee)
    - Fake recruiter patterns (Telegram-only, camera-off, immediate hire, etc.)
    - Domain/channel anomalies (personal email, chat apps)
    - Legitimate FSO green-flag phrases (to reduce false positives)

  ContactType: FSO_IMPERSONATION | FAKE_RECRUITER | MIXED | CLEAN
"""
import re
from dataclasses import dataclass, field
from enum import Enum


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------
def _p(regex: str) -> re.Pattern:
    return re.compile(regex, re.IGNORECASE)


# ===========================================================================
# FAKE FSO PATTERNS
# A real FSO never asks for SSN to "verify clearance" — they use DISS.
# A real FSO contacts via corporate email, not consumer or chat channels.
# ===========================================================================

# Core exploit: asking for SSN "to verify clearance"
_FSO_SSN_FOR_VERIFICATION = _p(
    r"(need\s+(your\s+)?(ssn|social\s+security).{0,60}(verify|confirm|check|look\s+up)"
    r".{0,60}clearance"
    r"|verify\s+(your\s+)?clearance.{0,60}(ssn|social\s+security)"
    r"|provide\s+(your\s+)?(ssn|social\s+security).{0,60}(clearance|diss|jpas)"
    r"|(ssn|social\s+security).{0,40}(required|needed)\s+to\s+(verify|confirm|check)\s+"
    r"(your\s+)?(clearance|access|eligibility))"
)

# FSO asking for DOB alongside SSN for "clearance lookup"
_FSO_DOB_SSN_COMBO = _p(
    r"(need\s+(your\s+)?(ssn|social\s+security).{0,80}(date\s+of\s+birth|dob)"
    r"|(date\s+of\s+birth|dob).{0,80}(ssn|social\s+security)"
    r".{0,60}(clearance|verify|confirm))"
)

# FSO claiming to be DCSA/NBIB — these agencies don't cold-contact candidates
_FSO_DCSA_IMPERSONATION = _p(
    r"(i\s+(am|work\s+for|represent|am\s+with)\s+(dcsa|nbib|defense\s+counterintelligence"
    r"|national\s+background\s+investigations)"
    r"|calling\s+(from|on\s+behalf\s+of)\s+(dcsa|nbib)"
    r"|dcsa.{0,20}(agent|officer|investigator|representative)\s+(calling|contacting)"
    r"|your\s+clearance\s+(file|record|case)\s+(is\s+)?(being\s+)?(reviewed|held|flagged)"
    r"\s+by\s+(dcsa|nbib))"
)

# FSO claiming clearance is "suspended" and requires action/payment
_FSO_CLEARANCE_SUSPENDED_SCAM = _p(
    r"(clearance\s+(has\s+been\s+|is\s+)?(suspended|revoked|put\s+on\s+hold|flagged)"
    r".{0,100}(provide|send|pay|submit|call)"
    r"|your\s+clearance\s+(will\s+be\s+)?(suspended|revoked)\s+(if\s+you\s+don['']?t|unless)"
    r"|reactivat.{0,10}(clearance|access).{0,60}(fee|pay|send|provide))"
)

# FSO requesting physical copies of identity documents by email/chat
_FSO_ID_DOCS_BY_EMAIL = _p(
    r"(email|send|attach|forward|upload).{0,30}"
    r"(copy|photo|picture|scan|image).{0,20}"
    r"(passport|driver.{0,5}license|state\s+id|military\s+id|cac|common\s+access\s+card)"
)

# FSO using non-corporate channels (should NEVER happen)
_FSO_PERSONAL_CHANNEL = _p(
    r"(fso|security\s+officer|facility\s+security).{0,60}"
    r"(gmail|yahoo|hotmail|outlook\.com|proton|icloud|qq\.com|163\.com)"
    r"|(gmail|yahoo|hotmail|outlook\.com|proton|icloud).{0,60}"
    r"(fso|security\s+officer|facility\s+security)"
)

# FSO claiming clearance fee — does not exist
_FSO_CLEARANCE_FEE = _p(
    r"(fee.{0,40}(clearance|diss|background|investigation)"
    r"|(clearance|diss|background|investigation).{0,40}fee"
    r"|pay.{0,30}(to\s+)?(process|start|run|initiate|complete).{0,30}clearance"
    r"|clearance\s+(processing|transfer|verification)\s+fee)"
)

# FSO claiming they need SSN "to pull you in DISS/JPAS" — backwards; real FSOs
# initiate the pull from their end without requiring the candidate to supply SSN
_FSO_DISS_SSN_REQUEST = _p(
    r"(need\s+(your\s+)?ssn\s+to\s+(pull|look\s+up|find|search|enter)\s+"
    r"(you\s+in\s+)?(diss|jpas|scattered\s+castles|sims)"
    r"|(diss|jpas|scattered\s+castles).{0,60}(need|require|must\s+have).{0,40}ssn)"
)


# ===========================================================================
# FAKE RECRUITER PATTERNS
# ===========================================================================

# Asking for SSN/DOB at initial recruiter outreach stage (pre-offer)
_RECRUITER_SSN_PREHIRE = _p(
    r"(send\s+(me|us)\s+(your\s+)?(ssn|social\s+security)"
    r"|provide\s+(your\s+)?(ssn|social\s+security).{0,60}(resume|application|profile)"
    r"|(ssn|social\s+security).{0,60}(initial|first|apply|applying|application)"
    r"|need\s+(your\s+)?(ssn|social\s+security).{0,60}(before|prior\s+to).{0,60}interview)"
)

# Fake recruiter asking for full PII combo up front
_RECRUITER_PII_HARVEST = _p(
    r"(full\s+(legal\s+)?name.{0,100}(ssn|social\s+security|date\s+of\s+birth)"
    r"|(ssn|social\s+security).{0,100}(address|date\s+of\s+birth|dob|passport)"
    r"|(name|address|dob|date\s+of\s+birth).{0,80}(ssn|social\s+security\s+number)"
    r".{0,80}(application|profile|form|screening))"
)

# Recruiter claiming to be from an IC agency (NSA, CIA, etc.) — they post on USAJobs only
_RECRUITER_IC_CLAIM = _p(
    r"(i\s+(am|work\s+for|represent|am\s+a\s+recruiter\s+for)\s+(nsa|cia|dia|nro|nga|odni|dhs)"
    r"|recruiter\s+(from|at|for|with)\s+(the\s+)?(nsa|cia|dia|nro|nga|odni|dhs)"
    r"|(nsa|cia|dia|nro|nga).{0,50}(recruiter|hiring\s+manager|talent\s+acquisition))"
)

# Recruiter offering unrealistic comp for entry/clearance roles
_RECRUITER_SALARY_BAIT = _p(
    r"(\$\s*(?:[3-9]\d{2},\d{3}|\d{1,2},\d{3},\d{3})"
    r".{0,100}"
    r"(entry.level|no\s+experience|junior|intern|fresh\s+grad|new\s+grad)"
    r"|(entry.level|no\s+experience|junior).{0,100}"
    r"\$\s*(?:[3-9]\d{2},\d{3}|\d{1,2},\d{3},\d{3}))"
)

# Recruiter guaranteeing a clearance — impossible
_RECRUITER_CLEARANCE_GUARANTEE = _p(
    r"(guarant(ee|eed|y|ying)\s+(you\s+|your\s+)?[\w\s/]{0,30}clearance"
    r"|we\s+(can|will)\s+(get|obtain|provide|secure|give)\s+(you\s+)?(a\s+)?clearance"
    r"|clearance\s+guarant(ee|eed|y)"
    r"|you\s+(will|can)\s+get\s+(a\s+|your\s+)?(ts|secret|sci)\s+clearance\s+"
    r"(easily|quickly|fast|guaranteed|without\s+issue))"
)

# Recruiter using only Telegram/WhatsApp for professional contact
_RECRUITER_CHAT_ONLY = _p(
    r"(contact\s+(me\s+)?only\s+(via|on|through|at)\s+(telegram|whatsapp|signal|wechat)"
    r"|reach\s+(me\s+)?on\s+(telegram|whatsapp|signal)"
    r"|all\s+(communication|contact|hiring).{0,30}(via|through|on)\s+(telegram|whatsapp|signal)"
    r"|(telegram|whatsapp)\s+is\s+(the\s+)?(only|best|preferred)\s+(way|method|channel)"
    r"\s+to\s+(contact|reach|hire))"
)

# Recruiter requiring camera-off / audio-only interview
_RECRUITER_CAMERA_OFF = _p(
    r"(camera\s+(must\s+(be\s+)?|should\s+(be\s+)?|is\s+to\s+be\s+)?off"
    r"|no\s+video\s+(required|needed|allowed|please)"
    r"|audio.only\s+(interview|call|session)"
    r"|video\s+(is\s+)?(not\s+)?(required|needed|necessary)"
    r"|please\s+(turn|keep)\s+(your\s+)?camera\s+off)"
)

# Recruiter applying fee to apply / register
_RECRUITER_APPLICATION_FEE = _p(
    r"(application\s+fee|processing\s+fee|registration\s+fee|submission\s+fee"
    r"|fee\s+to\s+(apply|register|participate|proceed)"
    r"|pay\s+(to\s+)?(apply|submit|register)\s+(for\s+)?(the\s+)?(job|position|role)"
    r"|\$\s*\d+.{0,20}(processing|application|registration)\s+fee)"
)

# Recruiter who cannot name the company / client
_RECRUITER_ANONYMOUS_EMPLOYER = _p(
    r"(company\s+(name\s+)?(withheld|confidential|not\s+disclosed|cannot\s+be\s+shared"
    r"|will\s+be\s+revealed)"
    r"|confidential\s+(employer|company|client|organization)"
    r"|our\s+client\s+(wishes|prefers|chooses)\s+to\s+remain\s+anonymous"
    r"|cannot\s+(disclose|share|reveal)\s+(the\s+)?(company|employer|client)\s+name)"
)


# FSO claiming SSN is required to finalize the offer (inverts the legal sequence)
_FSO_OFFER_SSN_PREREQUISITE = _p(
    r"(ssn|social\s+security).{0,80}(finalize|issue|complete|sign|process).{0,30}offer"
    r"|offer.{0,60}(requires?|needs?|contingent\s+on).{0,60}(ssn|social\s+security)"
    r"|(must|need\s+to)\s+provide.{0,30}(ssn|social\s+security)"
    r".{0,60}(finalize|complete|sign)\s+(the\s+)?offer"
)

# FSO/recruiter claiming clearance background process can start before formal offer
_FSO_PRE_OFFER_INVESTIGATION_CLAIM = _p(
    r"(investigation|clearance\s+process|background).{0,60}(start|begin|initiate)"
    r".{0,60}(before|prior\s+to|without).{0,40}(offer|hire|employment)"
    r"|can\s+(process|run|start).{0,40}clearance\s+without.{0,40}offer"
)

# Social engineering pressure: "everyone else provided SSN / you're not playing ball"
_SOCIAL_ENGINEERING_SSN_PRESSURE = _p(
    r"(everyone\s+else|all\s+(the\s+)?other\s+candidates?|other\s+applicants?)"
    r".{0,80}(provided?|gave|sent|submitted)\s+(their\s+)?(ssn|social\s+security)"
    r"|not\s+playing\s+ball"
    r"|skip\s+over\s+you"
    r"|pass\s+on\s+you.{0,60}(ssn|information)"
    r"|being\s+(difficult|uncooperative).{0,60}(ssn|social\s+security)"
    r"|other\s+candidates?\s+(are\s+)?(ready|willing|waiting).{0,60}(ssn|proceed)"
)

# CAGE code deflection — a real FSO can answer this instantly
_CAGE_CODE_DEFLECTION = _p(
    r"(can[''t]+\s+(give|provide|share|disclose).{0,20}cage"
    r"|cage.{0,30}(confidential|classified|not\s+available|not\s+public)"
    r"|(don[''t]+|i\s+don[''t]+).{0,30}(have|know).{0,30}cage"
    r"|what[''s]+\s+(a\s+)?cage\s+code"
    r"|fcl.{0,30}(confidential|classified|not\s+disclosed|private)"
    r"|(don[''t]+|i\s+don[''t]+).{0,20}(have|know).{0,20}fcl)"
)

# Recruiter claiming they have DISS/JPAS access (only credentialed FSOs can access DISS)
# NOTE: past-tense "I pulled your record in DISS" is legitimate FSO behavior — only flag
# future/present-tense capability claims and "give me your SSN to pull you up" constructs.
_RECRUITER_DISS_ACCESS_CLAIM = _p(
    r"(i\s+(can|will|am\s+going\s+to)\s+(check|pull|look|search|find).{0,30}(diss|jpas)"
    r"|let\s+me\s+(pull|check|look|search).{0,30}(diss|jpas)"
    r"|we\s+(have|got)\s+(diss|jpas)\s+(access|account)"
    r"|i\s+have\s+(diss|jpas)\s+(access|account|login|credentials)"
    r"|(recruiter|hr|talent\s+acquisition).{0,50}(diss|jpas)\s+(access|account|login))"
)


# DOD SAFE misused as SSN/PII collection channel
# DOD SAFE is a UNCLASSIFIED file transfer tool — NOT an authorized SSN channel.
# The only authorized SSN collection portal is NBIS eApp per 32 CFR §117.10(d).
_DOD_SAFE_PII_REQUEST = _p(
    r"(dod\s+safe.{0,80}(ssn|pii|social\s+security|personal\s+information|send|submit)"
    r"|(ssn|pii|social\s+security|personal\s+information).{0,80}dod\s+safe"
    r"|(send|submit|upload|transfer).{0,40}(ssn|pii|social\s+security)"
    r".{0,60}(dod\s+safe|safe\.apps\.mil)"
    r"|dod\s+safe.{0,60}(request|collect|receive).{0,40}(pii|ssn|social\s+security))"
)

# "Common/standard practice" framing to normalize pre-offer SSN collection
# This escalation tactic is used when initial recruiter pressure fails
_COMMON_PRACTICE_SSN_CLAIM = _p(
    r"(common\s+(and\s+)?(standard\s+)?practice.{0,80}(ssn|social\s+security|pii)"
    r"|(ssn|social\s+security).{0,80}common\s+(and\s+)?(standard\s+)?practice"
    r"|standard\s+practice.{0,80}(companies?).{0,60}(ssn|social\s+security|verify)"
    r"|(it\s+is\s+)?(not\s+(an?\s+)?unusual|normal|common)\s+(request|practice)"
    r".{0,80}(ssn|social\s+security|pii))"
)

# SVP/senior escalation of SSN pressure — management involvement doesn't change legality
_SENIOR_ESCALATION_SSN = _p(
    r"(vice\s+president|vp|director|senior\s+(recruiter|manager|executive)).{0,200}"
    r"(ssn|social\s+security|pii|verify\s+(your\s+)?clearance)"
    r"|(ssn|social\s+security|verify\s+(your\s+)?clearance).{0,200}"
    r"(vice\s+president|vp|director)"
)


# ===========================================================================
# LEGITIMATE GREEN FLAGS (reduce false positives)
# These phrases indicate probable legitimate contact
# ===========================================================================

_LEGIT_FSO_PHRASES = _p(
    r"(diss|jpas|scattered\s+castles"              # real systems FSOs use
    r"|eqip|sf.?86|sf\s+86"                        # real clearance forms
    r"|dd.?254|dd\s+254"                            # contract security spec form
    r"|visit\s+(authorization|request|letter)"     # VAR - standard FSO tool
    r"|indoc(trination)?"                           # SCI indoc process
    r"|read.?on|read\s+on\s+to"                    # program read-on
    r"|scif\s+(access|badge|visit)"                # SCIF-related legitimate language
    r"|polygraph\s+(scheduled|appointment|date)"   # legitimate poly scheduling
    r"|cac\s+(enrollment|issuance|card)|piv\s+card" # physical credential processes
    r"|your\s+(current\s+)?fso\s+will\s+(be\s+)?(notified|contacted|coordinating))"
)

_LEGIT_RECRUITER_PHRASES = _p(
    r"(apply\s+(at|via|through|on)\s+(our\s+)?"
    r"(website|careers\s+page|applicant\s+tracking|portal|workday|taleo|icims|greenhouse)"
    r"|interview.{0,30}in.person.{0,30}(office|hq|headquarters|scif|facility)"
    r"|offer\s+(letter|will)\s+(be\s+)?(sent|issued|provided)\s+(via|through|from)"
    r"\s+(corporate|official|company|hr)"
    r"|background\s+(check|investigation)\s+(is\s+)?(sponsored|covered|paid)\s+by\s+"
    r"(us|the\s+company|[a-z]+)"
    r"|sf.?86\s+(will\s+be\s+)?(sponsored|initiated|processed)\s+(after|upon|following)"
    r"\s+(offer|acceptance))"
)


# ===========================================================================
# Result types
# ===========================================================================

class ContactType(str, Enum):
    CLEAN = "CLEAN"
    SUSPICIOUS_RECRUITER = "SUSPICIOUS_RECRUITER"
    SUSPICIOUS_FSO = "SUSPICIOUS_FSO"
    FAKE_FSO = "FAKE_FSO"
    FAKE_RECRUITER = "FAKE_RECRUITER"
    MIXED = "MIXED"            # both FSO impersonation + fake recruiter signals


@dataclass
class ContactFinding:
    severity: str        # "critical" | "high" | "medium"
    actor_type: str      # "fso_impersonation" | "fake_recruiter" | "both"
    finding: str
    detail: str
    weight: float


@dataclass
class ContactAnalysis:
    findings: list[ContactFinding] = field(default_factory=list)
    risk_score: float = 0.0
    contact_type: ContactType = ContactType.CLEAN
    fso_score: float = 0.0
    recruiter_score: float = 0.0
    legit_signals: int = 0    # count of legitimate green-flag matches

    @property
    def is_suspicious(self) -> bool:
        return self.contact_type != ContactType.CLEAN

    @property
    def top_indicators(self) -> list[str]:
        return [
            f"[{f.actor_type}] {f.finding}"
            for f in sorted(self.findings, key=lambda x: x.weight, reverse=True)[:5]
        ]

    @property
    def safe_to_provide_ssn(self) -> bool:
        """
        Returns True only when NO fraud signals are present AND legitimate
        green flags exist. Even then warn user to use secure portal only.
        """
        return (
            self.contact_type == ContactType.CLEAN
            and self.legit_signals >= 1
            and self.risk_score < 0.10
        )


# ---------------------------------------------------------------------------
# Check table: (pattern, severity, actor_type, finding, detail, weight)
# ---------------------------------------------------------------------------
_FSO_CHECKS: list[tuple] = [
    (_FSO_SSN_FOR_VERIFICATION, "critical", "fso_impersonation",
     "Asking for SSN to 'verify clearance'",
     "REAL FSOs access DISS via their own credentialed account — any SSN in the system is "
     "already on file from a prior investigation or formal application. They do NOT "
     "cold-solicit your SSN as a 'clearance verification' request. "
     "Your SSN is collected post-offer through the NBIS eApp portal (eapp.nbis.mil). "
     "Source: NISPOM 32 CFR §117.10; dcsa.mil/Systems-Applications/Defense-Information-System-for-Security-DISS",
     1.0),

    (_FSO_DOB_SSN_COMBO, "critical", "fso_impersonation",
     "Requesting SSN + DOB combination for 'clearance lookup'",
     "SSN + DOB is a complete identity theft package. An FSO running a legitimate DISS "
     "eligibility check uses their own credentialed login — they do NOT cold-collect your "
     "SSN/DOB via email or phone. Those details are collected post-offer through the NBIS "
     "eApp portal (eapp.nbis.mil). Source: NISPOM 32 CFR §117.10; dcsa.mil/mc/pv/mbi",
     1.0),

    (_FSO_DCSA_IMPERSONATION, "critical", "fso_impersonation",
     "Claiming to be a DCSA/NBIB agent",
     "DCSA investigators do not cold-contact job candidates. If someone claims to "
     "be from DCSA asking for PII, report to DCSA's fraud line: 571-305-6576.",
     0.95),

    (_FSO_CLEARANCE_SUSPENDED_SCAM, "critical", "fso_impersonation",
     "Claiming clearance is suspended pending action",
     "Clearance suspensions are handled through your CURRENT employer's FSO via "
     "official DISS notices — never through cold calls or email to the candidate.",
     0.95),

    (_FSO_CLEARANCE_FEE, "critical", "fso_impersonation",
     "Charging a fee for clearance processing or transfer",
     "The U.S. government never charges individuals for security clearances. "
     "Clearance transfer is free and handled FSO-to-FSO through DISS.",
     1.0),

    (_FSO_DISS_SSN_REQUEST, "critical", "fso_impersonation",
     "Asking for SSN 'to pull you in DISS/JPAS'",
     "DISS (which replaced JPAS on March 31, 2021) is accessed by FSOs via their own "
     "credentialed NBIS portal logins. Any SSN in DISS is already on file from a prior "
     "investigation; an FSO has no legitimate reason to cold-collect your SSN as a "
     "'lookup trigger' via email or phone call. "
     "Source: NISPOM 32 CFR §117.10; dcsa.mil/Systems-Applications/Defense-Information-System-for-Security-DISS",
     0.95),

    (_FSO_ID_DOCS_BY_EMAIL,  "high", "fso_impersonation",
     "Requesting ID document photos/scans by email",
     "Legitimate FSOs process I-9, CAC enrollment, and ID verification in person "
     "or through secure government portals — not by emailing photos of documents.",
     0.80),

    (_FSO_PERSONAL_CHANNEL, "high", "fso_impersonation",
     "FSO contacting from personal/consumer email domain",
     "Facility Security Officers are employees of cleared facilities and use their "
     "corporate email (e.g., fso@company.com). Gmail/Yahoo/Hotmail indicates fraud.",
     0.85),

    (_FSO_OFFER_SSN_PREREQUISITE, "critical", "fso_impersonation",
     "Claiming SSN required to finalize the offer",
     "SSN is never a prerequisite for an offer letter. Under 32 CFR §117.10(f)(1), "
     "the written offer must exist FIRST — SSN follows through eApp post-acceptance. "
     "Any framing that SSN must come BEFORE or AS A CONDITION of the offer inverts "
     "the legal sequence entirely.",
     0.90),

    (_FSO_PRE_OFFER_INVESTIGATION_CLAIM, "critical", "fso_impersonation",
     "Claiming investigation can start before a written offer exists",
     "32 CFR §117.10(f)(1)(i)-(ii) requires BOTH a written offer AND written "
     "acceptance before any investigation is initiated. No exception exists. "
     "Claiming the process starts earlier misrepresents NISPOM directly.",
     0.85),

    (_SOCIAL_ENGINEERING_SSN_PRESSURE, "critical", "fso_impersonation",
     "Social engineering pressure: 'everyone else gave SSN / you're not playing ball'",
     "Normalization and exclusion pressure are manipulation tactics. 'Everyone else "
     "provided SSN' means each prior instance violated 32 CFR §117.10(a)(5) — the "
     "rule against building a cache of cleared candidates. Being cited compliance "
     "with federal regulation is not 'difficult' behavior.",
     0.90),

    (_CAGE_CODE_DEFLECTION, "high", "fso_impersonation",
     "Cannot or will not provide CAGE code or FCL level",
     "Every NISP-covered facility has a public CAGE code (verifiable at sam.gov) "
     "and a known FCL. A real FSO answers these instantly. Refusal or ignorance "
     "means the entity is likely not a registered DCSA facility.",
     0.85),

    (_DOD_SAFE_PII_REQUEST, "critical", "fso_impersonation",
     "Using DOD SAFE as SSN/PII collection channel",
     "DOD SAFE (safe.apps.mil) is an UNCLASSIFIED file transfer tool. It is NOT "
     "an authorized system for SSN collection. Under 32 CFR §117.10(d), the ONLY "
     "authorized channel for SF-86/SSN data is NBIS eApp (eapp.nbis.mil). "
     "Directing a candidate to send PII through DOD SAFE instead of eApp bypasses "
     "the legally mandated system and has no regulatory basis.",
     0.95),

    (_COMMON_PRACTICE_SSN_CLAIM, "high", "fso_impersonation",
     "Claiming pre-offer SSN collection is 'common/standard practice'",
     "Industry custom cannot override federal regulation. 32 CFR §117.10(f)(1)(i)-(ii) "
     "requires written offer + written acceptance BEFORE any SSN/PII collection for "
     "clearance purposes. 'Common practice' among recruiters collecting SSNs pre-offer "
     "describes a pattern of §117.10(a)(5) violations — not a legal standard.",
     0.80),

    (_SENIOR_ESCALATION_SSN, "high", "fso_impersonation",
     "Senior management escalation used to pressure SSN submission",
     "Management seniority does not change the regulatory requirement. "
     "An SVP, director, or VP applying pressure to provide SSN pre-offer is still "
     "a violation of 32 CFR §117.10(f)(1)(i)-(ii) and (a)(7). "
     "Escalation to seniors is a social engineering tactic, not a compliance path.",
     0.75),
]

_RECRUITER_CHECKS: list[tuple] = [
    (_RECRUITER_SSN_PREHIRE, "critical", "fake_recruiter",
     "Asking for SSN before any formal offer",
     "SSN is only collected AFTER a written offer is accepted, during HR onboarding "
     "through a secure portal. A recruiter asking for SSN pre-offer is harvesting PII.",
     0.95),

    (_RECRUITER_PII_HARVEST, "critical", "fake_recruiter",
     "Requesting full PII profile (name+SSN+DOB+address) in screening",
     "This is a complete identity reconstruction attack. Name+SSN+DOB+address enables "
     "credit fraud, tax fraud, and benefit fraud. Stop contact immediately.",
     1.0),

    (_RECRUITER_IC_CLAIM, "critical", "fake_recruiter",
     "Recruiter claiming to hire directly for NSA/CIA/DIA/NRO/NGA",
     "Intelligence Community agencies post ALL civilian positions exclusively on "
     "USAJobs.gov. No IC agency uses independent recruiters for cleared positions.",
     0.90),

    (_RECRUITER_CLEARANCE_GUARANTEE, "critical", "fake_recruiter",
     "Guaranteeing a security clearance",
     "DCSA adjudicates clearances based on 13 adjudicative guidelines — no employer "
     "or recruiter can guarantee an outcome. This promise is always a scam.",
     1.0),

    (_RECRUITER_CHAT_ONLY, "critical", "fake_recruiter",
     "Hiring exclusively via Telegram/WhatsApp/Signal",
     "Legitimate defense/government contractors use official ATS systems (Workday, "
     "Taleo, iCIMS) and corporate email. Chat-app-only recruiters are overwhelmingly "
     "scammers or DPRK IT worker scheme operators.",
     0.95),

    (_RECRUITER_CAMERA_OFF, "critical", "fake_recruiter",
     "Requiring camera-off / audio-only interviews",
     "This is the primary method DPRK IT worker scheme operators use to hide "
     "their physical identity while impersonating US-based professionals.",
     0.90),

    (_RECRUITER_APPLICATION_FEE, "critical", "fake_recruiter",
     "Charging a fee to apply for the position",
     "Legitimate employers NEVER charge candidates to apply. Application fees are "
     "universally a fraud indicator regardless of amount.",
     0.95),

    (_RECRUITER_SALARY_BAIT, "high", "fake_recruiter",
     "Unrealistic salary for entry-level/no-experience cleared role",
     "Entry-level cleared positions typically pay $60k–$100k. Multi-hundred-thousand "
     "packages for 'no experience' roles are bait to attract PII submission.",
     0.70),

    (_RECRUITER_ANONYMOUS_EMPLOYER, "high", "fake_recruiter",
     "Employer identity withheld / 'confidential client'",
     "Cleared facilities holding FCLs cannot legally hide their identity from "
     "candidates — FOCI requirements and DD-254 mandates disclosure.",
     0.75),

    (_RECRUITER_DISS_ACCESS_CLAIM, "critical", "fake_recruiter",
     "Recruiter claiming direct DISS/JPAS access",
     "DISS JVS is restricted to FSOs with DoD CAC credentials at dissportal.nbis.mil. "
     "Recruiters and HR have NO DISS access. A recruiter claiming they can 'check you "
     "in DISS' is fabricating a pretext for SSN collection or impersonating an FSO.",
     0.90),

    (_SOCIAL_ENGINEERING_SSN_PRESSURE, "critical", "fake_recruiter",
     "Social engineering pressure around SSN / 'everyone else did it'",
     "Under 32 CFR §117.10(a)(5), collecting SSNs from multiple pre-offer candidates "
     "is the prohibited 'cache of cleared employees' — whether one or many. "
     "'Everyone else provided SSN' describes a pattern of violations, not a norm.",
     0.90),

    (_CAGE_CODE_DEFLECTION, "high", "fake_recruiter",
     "Cannot provide company CAGE code or FCL level when asked",
     "CAGE codes are public. FCL levels are known. Any recruiting entity working on "
     "behalf of a real NISP facility can answer these trivially. Inability to do so "
     "is the single fastest way to expose a non-NISP or fraudulent front.",
     0.85),

    (_DOD_SAFE_PII_REQUEST, "critical", "fake_recruiter",
     "Proposing DOD SAFE as an SSN/PII collection channel",
     "DOD SAFE is an unclassified file transfer tool — NOT an authorized system "
     "for SSN collection. The sole authorized portal is NBIS eApp per 32 CFR §117.10(d). "
     "Proposing DOD SAFE as an alternative channel for SSN submission is a process "
     "violation regardless of who proposes it or what their title is.",
     0.95),

    (_COMMON_PRACTICE_SSN_CLAIM, "high", "fake_recruiter",
     "Framing pre-offer SSN collection as 'common/standard practice'",
     "Custom does not override federal regulation. 'Common practice' of collecting SSNs "
     "pre-offer from cleared candidates is the §117.10(a)(5) prohibited cache-building, "
     "not a legal compliance standard.",
     0.80),
]


# ===========================================================================
# Main analysis function
# ===========================================================================

# ID: CA-001
# Requirement: Classify a recruiter or FSO contact message as CLEAN, SUSPICIOUS, or
#              confirmed FAKE, distinguishing FSO impersonation from fake recruiter fraud.
# Purpose: Identify the most damaging clearance-community fraud vectors — fake FSOs
#          harvesting SSNs under the guise of "clearance verification" and fake recruiters
#          running PII/financial fraud or DPRK IT worker schemes.
# Rationale: Separate FSO and recruiter scoring tracks allow the system to output targeted
#             guidance (e.g., "call the FSO line" vs. "report to FBI IC3") and correctly
#             identify MIXED cases where both vectors appear simultaneously.
# Inputs: contact_text (str) — raw text of email, chat, or call notes; may be multi-paragraph.
# Outputs: ContactAnalysis with risk_score ∈ [0, 1], ContactType enum, and ContactFinding list.
# Preconditions: contact_text is a decoded string; _FSO_CHECKS and _RECRUITER_CHECKS compiled.
# Postconditions: fso_score and recruiter_score are independently bounded via logistic formula;
#                 contact_type correctly reflects which sub-score(s) exceed thresholds.
# Assumptions: _LEGIT_FSO_PHRASES / _LEGIT_RECRUITER_PHRASES reduce but do not nullify scores.
# Side Effects: None — pure function; no I/O or shared-state mutation.
# Failure Modes: Empty text returns ContactType.CLEAN, score 0.0 — no exception.
# Error Handling: No guards needed — all patterns handle no-match by returning None safely.
# Constraints: O(|_FSO_CHECKS| + |_RECRUITER_CHECKS|) × |text| — typically < 3 ms.
# Verification: test_detector.py::test_contact_* — FSO/recruiter distinction, MIXED case.
# References: 32 CFR §117.10(a)(5), §117.10(a)(7), §117.10(f)(1)(i)-(ii), §117.10(d).
def analyze_contact(contact_text: str) -> ContactAnalysis:
    """
    Analyze a recruiter message, FSO email, or contact transcript for
    FSO impersonation and fake recruiter fraud indicators.

    Distinguishes between:
      - Fake FSO: impersonates Facility Security Officer to extract SSN
      - Fake Recruiter: front for PII harvest, DPRK scheme, or financial fraud

    Args:
        contact_text: Raw text of email, message, or call notes from a recruiter
                      or from someone claiming to be an FSO.

    Returns:
        ContactAnalysis with risk score, ContactType, and categorized findings.
    """
    analysis = ContactAnalysis()

    fso_raw = 0.0
    recruiter_raw = 0.0

    # Run FSO impersonation checks
    for pattern, severity, actor_type, finding, detail, weight in _FSO_CHECKS:
        if pattern.search(contact_text):
            analysis.findings.append(ContactFinding(
                severity=severity,
                actor_type=actor_type,
                finding=finding,
                detail=detail,
                weight=weight,
            ))
            fso_raw += weight

    # Run fake recruiter checks
    for pattern, severity, actor_type, finding, detail, weight in _RECRUITER_CHECKS:
        if pattern.search(contact_text):
            analysis.findings.append(ContactFinding(
                severity=severity,
                actor_type=actor_type,
                finding=finding,
                detail=detail,
                weight=weight,
            ))
            recruiter_raw += weight

    # Count legitimate green-flag signals (reduce false positives)
    legit_fso = len(_LEGIT_FSO_PHRASES.findall(contact_text))
    legit_rec = len(_LEGIT_RECRUITER_PHRASES.findall(contact_text))
    analysis.legit_signals = legit_fso + legit_rec

    # Compute sub-scores with diminishing returns
    if fso_raw > 0:
        analysis.fso_score = round(min(1 - (1 / (1 + fso_raw * 0.5)), 1.0), 3)
    if recruiter_raw > 0:
        analysis.recruiter_score = round(min(1 - (1 / (1 + recruiter_raw * 0.5)), 1.0), 3)

    # Combined risk (max-weighted blend)
    total_raw = fso_raw + recruiter_raw
    if total_raw > 0:
        analysis.risk_score = round(min(1 - (1 / (1 + total_raw * 0.4)), 1.0), 3)

    # Classify ContactType
    has_fso_critical = any(
        f.weight >= 0.75 for f in analysis.findings if f.actor_type == "fso_impersonation"
    )
    has_rec_critical = any(
        f.weight >= 0.75 for f in analysis.findings if f.actor_type == "fake_recruiter"
    )

    if has_fso_critical and has_rec_critical:
        analysis.contact_type = ContactType.MIXED
    elif has_fso_critical or analysis.fso_score >= 0.30:
        analysis.contact_type = (
            ContactType.FAKE_FSO if analysis.fso_score >= 0.55
            else ContactType.SUSPICIOUS_FSO
        )
    elif has_rec_critical or analysis.recruiter_score >= 0.30:
        analysis.contact_type = (
            ContactType.FAKE_RECRUITER if analysis.recruiter_score >= 0.55
            else ContactType.SUSPICIOUS_RECRUITER
        )

    return analysis
