"""
NLP-based analysis: readability scoring, keyword density, and linguistic
fraud signals that regex alone can't catch.
"""
import re
import string
from dataclasses import dataclass, field

# Vocabulary specific to clearance-job fraud
FRAUD_VOCAB: set[str] = {
    "congratulations", "selected", "approved", "chosen", "shortlisted",
    "kindly", "revert", "do the needful", "attachment", "urgent",
    "immediately", "wire transfer", "western union", "moneygram", "bitcoin",
    "gift card", "processing fee", "admin fee", "upfront", "deposit",
    "guaranteed", "no experience", "work from home", "easy money",
    "top secret clearance available", "clearance for sale",
    "click here", "verify your account", "confirm your details",
    # Social engineering pressure tactics (32 CFR §117.10 violations)
    "everyone else provided", "everyone else gave", "not playing ball",
    "skip over you", "pass on you", "being difficult", "not cooperating",
    "just needs your ssn", "standard practice ssn", "industry standard ssn",
    "cage code is confidential", "fcl is confidential",
}

LEGITIMATE_VOCAB: set[str] = {
    "usajobs", "sf86", "sf-86", "eqip", "position of trust",
    "interim clearance", "adjudication", "sponsorship", "polygraph",
    "background investigation", "dss", "dcsa", "nbib",
    "security officer", "facility clearance", "scif",
    # DCSA official tools and process terms (source: dcsa.mil/is/systems/, verified Apr 2026)
    "diss", "nbis", "eapp", "swft", "jpas",           # official DCSA systems (JPAS retired Mar 2021)
    "nispom", "32 cfr 117",                            # regulatory authority for clearance process
    "conditional offer",                               # correct timing trigger for SSN/SF-86 initiation
    "facility security officer", "fso",                # authorized PII collection role
    "visit authorization", "var",                      # standard FSO coordination tool
    "scattered castles",                               # SCI access control system
    "sf-85", "sf-85p",                                 # non-TS background investigation forms
    "etalent", "tscti",                                # verified cleared staffing firms
    # Clearance process verification vocabulary (32 CFR §117.10; dcsa.mil, verified Apr 2026)
    "cage code",                                       # public DCSA facility identifier (sam.gov)
    "fcl",                                             # facility clearance level
    "facility clearance level",                        # FCL full name
    "jvs",                                             # DISS Joint Verification System
    "joint verification system",                       # JVS full name
    "reciprocity",                                     # SEAD 7 — reusing prior investigation
    "sead 7",                                          # reciprocity policy (dni.gov)
    "written offer",                                   # required trigger — 32 CFR §117.10(f)(1)(i)
    "written acceptance",                              # required trigger — 32 CFR §117.10(f)(1)(ii)
    "eapp.nbis.mil",                                   # only authorized SF-86 portal
    "32 cfr 117.10",                                   # NISPOM section governing clearance process
    "117.10",                                          # short cite used in regulatory discussions
}


@dataclass
class NLPFindings:
    fraud_keyword_hits: list[str] = field(default_factory=list)
    legitimate_keyword_hits: list[str] = field(default_factory=list)
    avg_sentence_length: float = 0.0
    exclamation_count: int = 0
    caps_ratio: float = 0.0         # ratio of UPPERCASE letters
    url_count: int = 0
    suspicious_urls: list[str] = field(default_factory=list)
    fraud_vocab_score: float = 0.0  # 0–1 based on fraud keyword density


# ID: NLP-001
# Requirement: Compute readability signals, fraud keyword density, CAPS abuse, and
#              suspicious URL presence from raw email/message text.
# Purpose: Provide soft linguistic features that complement hard regex rule matches.
# Rationale: NLP features catch AI-generated boilerplate, non-native phrasing (DPRK),
#             and urgency engineering that rule patterns may miss.
# Inputs: text (str) — raw email or document body; may be empty.
# Outputs: NLPFindings dataclass with all computed fields populated; never None.
# Preconditions: text is a decoded string (caller handles bytes→str conversion).
# Postconditions: fraud_vocab_score ∈ [0.0, 1.0]; all list fields non-None.
# Assumptions: FRAUD_VOCAB and LEGITIMATE_VOCAB are module-level sets (thread-safe reads).
# Side Effects: None — pure function with no I/O or shared state mutation.
# Failure Modes: Empty text returns zero-valued NLPFindings — no exceptions.
# Error Handling: total_words guard (max 1) prevents divide-by-zero on empty text.
# Constraints: O(|text| × |FRAUD_VOCAB|) word lookup; typically < 2 ms for normal emails.
# Verification: test_detector.py::test_nlp_* — fraud vocab scoring, URL detection edge cases.
# References: FRAUD_VOCAB / LEGITIMATE_VOCAB defined in this module; scorer.py NLP cap 0.25.
def analyze_nlp(text: str) -> NLPFindings:
    findings = NLPFindings()
    lower = text.lower()
    words = lower.split()
    total_words = max(len(words), 1)

    # Fraud keyword hits
    findings.fraud_keyword_hits = [kw for kw in FRAUD_VOCAB if kw in lower]
    findings.legitimate_keyword_hits = [kw for kw in LEGITIMATE_VOCAB if kw in lower]

    # Sentence length
    sentences = re.split(r"[.!?]+", text)
    sentences = [s.strip() for s in sentences if s.strip()]
    if sentences:
        findings.avg_sentence_length = sum(len(s.split()) for s in sentences) / len(sentences)

    # Exclamation count
    findings.exclamation_count = text.count("!")

    # Caps ratio (ignoring whitespace & punctuation)
    letters = [c for c in text if c.isalpha()]
    if letters:
        findings.caps_ratio = sum(1 for c in letters if c.isupper()) / len(letters)

    # URL extraction
    url_pattern = re.compile(r"https?://[^\s<>\"']+|www\.[^\s<>\"']+", re.IGNORECASE)
    urls = url_pattern.findall(text)
    findings.url_count = len(urls)

    # Flag URLs with suspicious patterns
    for url in urls:
        url_lower = url.lower()
        # Use path-anchored checks to avoid substring false positives.
        # "t.co" must not match "microsoft.com" (microso-f-t.co-m contains "t.co").
        if any(x in url_lower for x in ["://bit.ly/", "://tinyurl.com/", "://t.co/",
                                         "://goo.gl/", "://ow.ly/", "://shorturl.at/",
                                         "://rebrand.ly/", "://rb.gy/", "://cutt.ly/",
                                         "://is.gd/", "://v.gd/", "://buff.ly/"]):
            findings.suspicious_urls.append(url)
        elif re.search(r"\.(tk|ml|ga|cf|gq|ru|cn|xyz)(/|$)", url_lower):
            findings.suspicious_urls.append(url)

    # Fraud vocab density score
    fraud_hits = len(findings.fraud_keyword_hits)
    legit_hits = len(findings.legitimate_keyword_hits)
    raw_score = fraud_hits / (fraud_hits + legit_hits + 5)  # +5 to dampen small samples
    findings.fraud_vocab_score = round(min(raw_score * 3, 1.0), 3)

    return findings
