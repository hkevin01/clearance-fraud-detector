"""
Aggregate all analysis results into a single FraudScore with verdict and breakdown.
"""
from dataclasses import dataclass, field
from enum import Enum

from ..analyzers.domain_analyzer import DomainFinding
from ..analyzers.nlp_analyzer import NLPFindings
from ..analyzers.rule_engine import RuleMatch


class Verdict(str, Enum):
    CLEAN = "CLEAN"
    SUSPICIOUS = "SUSPICIOUS"
    LIKELY_FRAUD = "LIKELY_FRAUD"
    FRAUD = "FRAUD"


SEVERITY_WEIGHTS = {"high": 0.25, "medium": 0.12, "low": 0.05}


@dataclass
class FraudScore:
    total_score: float                          # 0.0 – 1.0
    verdict: Verdict
    rule_matches: list[RuleMatch] = field(default_factory=list)
    domain_findings: list[DomainFinding] = field(default_factory=list)
    nlp_findings: NLPFindings = field(default_factory=NLPFindings)
    category_breakdown: dict[str, float] = field(default_factory=dict)
    top_reasons: list[str] = field(default_factory=list)
    signal_count: int = 0       # number of unique fraud patterns triggered
    category_count: int = 0     # number of unique fraud categories triggered
    confidence: str = "LOW"     # HIGH / MEDIUM / LOW — evidence quality, not just score magnitude


# Per-category cap prevents any single category from dominating the total score
_CATEGORY_CAP: float = 0.35
# Domain sub-score ceiling — domain findings are strong but should not alone convict
_DOMAIN_CAP: float = 0.40
# NLP sub-score ceiling — NLP features are weak signals; context-corroboration required
_NLP_CAP: float = 0.25


# ID: SC-001
# Requirement: Aggregate rule matches, domain findings, and NLP features into a single
#              FraudScore in [0.0, 1.0] with an associated Verdict enum.
# Purpose: Produce the authoritative risk score consumed by CLI output and reports.
# Rationale: Per-category caps (_CATEGORY_CAP) prevent one verbose category from dominating;
#             domain and NLP contributions have lower ceilings reflecting lower reliability.
# Inputs: rule_matches (list[RuleMatch]), domain_findings (list[DomainFinding]),
#         nlp_findings (NLPFindings) — all may be empty/default.
# Outputs: FraudScore with total_score, verdict, category_breakdown, and top_reasons.
# Preconditions: All input lists and NLPFindings are valid (not None); weights in [0,1].
# Postconditions: FraudScore.total_score ∈ [0.0, 1.0]; verdict matches threshold table.
# Assumptions: SEVERITY_WEIGHTS keys cover all DomainFinding.severity values in use.
# Side Effects: None — pure function.
# Failure Modes: Unexpected DomainFinding.severity falls back to 0.05 via dict.get default.
# Error Handling: Empty inputs return score 0.0 / Verdict.CLEAN — no exceptions raised.
# Constraints: O(n) in total findings count; no I/O.
# Verification: test_detector.py::test_scoring_* — verdict boundaries and score arithmetic.
# References: NISPOM 32 CFR §117.10; Verdict enum threshold table defined inline.
def compute_score(
    rule_matches: list[RuleMatch],
    domain_findings: list[DomainFinding],
    nlp_findings: NLPFindings,
) -> FraudScore:
    score = 0.0
    category_scores: dict[str, float] = {}

    # --- Rule-based contribution (capped per category) ---
    for match in rule_matches:
        cat = match.category
        # Cap contribution per category at 0.35 to prevent one category dominating
        current = category_scores.get(cat, 0.0)
        if current < _CATEGORY_CAP:
            add = match.weight * 0.4   # scale rule weights to sub-score
            category_scores[cat] = min(current + add, _CATEGORY_CAP)

    score += sum(category_scores.values())

    # --- Domain findings contribution ---
    domain_score = 0.0
    for df in domain_findings:
        domain_score += SEVERITY_WEIGHTS.get(df.severity, 0.05)
    domain_score = min(domain_score, _DOMAIN_CAP)
    if domain_score > 0:
        category_scores["domain"] = round(domain_score, 3)
    score += domain_score

    # --- NLP contribution ---
    nlp_score = 0.0
    nlp_score += nlp_findings.fraud_vocab_score * 0.15
    if nlp_findings.caps_ratio > 0.4:
        nlp_score += 0.05
    if nlp_findings.exclamation_count >= 3:
        nlp_score += 0.03
    if nlp_findings.suspicious_urls:
        nlp_score += 0.10 * min(len(nlp_findings.suspicious_urls), 3)
    nlp_score = min(nlp_score, _NLP_CAP)
    if nlp_score > 0:
        category_scores["nlp"] = round(nlp_score, 3)
    score += nlp_score

    # --- Legitimacy signal discount ---
    # When the text contains ≥3 correct process vocabulary terms (eApp, DISS, 32 CFR 117,
    # written offer, etc.) AND no severe domain findings, reduce score slightly to avoid
    # flagging emails that are clearly written by people who know the real process.
    legit_hits = len(nlp_findings.legitimate_keyword_hits)
    has_severe_domain = any(df.severity == "high" for df in domain_findings)
    if legit_hits >= 3 and not has_severe_domain and score < 0.70:
        discount = min((legit_hits - 2) * 0.015, 0.08)  # max 8% discount
        score = max(0.0, score - discount)

    # Clamp to [0, 1]
    total = round(min(score, 1.0), 3)

    # Determine verdict
    if total < 0.20:
        verdict = Verdict.CLEAN
    elif total < 0.45:
        verdict = Verdict.SUSPICIOUS
    elif total < 0.70:
        verdict = Verdict.LIKELY_FRAUD
    else:
        verdict = Verdict.FRAUD

    # Build top reasons list
    reasons: list[tuple[float, str]] = []
    for match in rule_matches:
        reasons.append((match.weight, f"[{match.category}] {match.pattern.explanation}"))
    for df in domain_findings:
        reasons.append((SEVERITY_WEIGHTS.get(df.severity, 0.05), f"[domain] {df.detail}"))
    if nlp_findings.fraud_keyword_hits:
        reasons.append((0.1, f"[nlp] Fraud vocabulary: {', '.join(nlp_findings.fraud_keyword_hits[:5])}"))
    if nlp_findings.suspicious_urls:
        reasons.append((0.15, f"[nlp] Suspicious URLs detected: {', '.join(nlp_findings.suspicious_urls[:3])}"))

    reasons.sort(key=lambda x: x[0], reverse=True)
    top_reasons = [r for _, r in reasons[:10]]

    # --- Signal confidence/diversity ---
    sig_count = len(rule_matches)
    cat_count = len({m.category for m in rule_matches} | ({"domain"} if domain_findings else set()))
    if cat_count >= 3 and total >= 0.45:
        confidence = "HIGH"
    elif cat_count >= 2 or (sig_count >= 2 and total >= 0.25):
        confidence = "MEDIUM"
    else:
        confidence = "LOW"

    return FraudScore(
        total_score=total,
        verdict=verdict,
        rule_matches=rule_matches,
        domain_findings=domain_findings,
        nlp_findings=nlp_findings,
        category_breakdown={k: round(v, 3) for k, v in category_scores.items()},
        top_reasons=top_reasons,
        signal_count=sig_count,
        category_count=cat_count,
        confidence=confidence,
    )
