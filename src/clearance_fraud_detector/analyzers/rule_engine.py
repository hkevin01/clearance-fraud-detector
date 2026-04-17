"""
Rule-based fraud detection engine using the compiled regex pattern library.
Returns a list of triggered FraudPattern matches with their weights.
"""
from dataclasses import dataclass

from ..data.fraud_patterns import ALL_PATTERNS, FraudPattern
from ..parsers.email_parser import EmailDocument


@dataclass
class RuleMatch:
    pattern: FraudPattern
    matched_text: str
    context: str   # surrounding ~80 chars for report

    @property
    def weight(self) -> float:
        return self.pattern.weight

    @property
    def category(self) -> str:
        return self.pattern.category

    @property
    def explanation(self) -> str:
        return self.pattern.explanation


# ID: RE-001
# Requirement: Scan an EmailDocument against all compiled fraud patterns and return every
#              triggered pattern as a RuleMatch, limited to one match per pattern.
# Purpose: Produce the primary signal list that drives the fraud scoring pipeline.
# Rationale: A single match per pattern is sufficient to flag the signal while preventing
#             repeated occurrences of one pattern from inflating the category score.
# Inputs: doc (EmailDocument) — parsed email with full_text populated; not None.
# Outputs: list[RuleMatch] — zero or more matches, one entry per triggered FraudPattern.
# Preconditions: ALL_PATTERNS is populated; doc.full_text is a non-empty string.
# Postconditions: Each returned RuleMatch.pattern is unique; matches are in ALL_PATTERNS order.
# Assumptions: Pattern compilation is performed at import time; re is thread-safe for reads.
# Side Effects: None — pure function with no I/O or mutation of shared state.
# Failure Modes: Returns empty list if no patterns match; regex errors surface as exceptions.
# Error Handling: No invalid-input guard — caller (EmailFraudDetector) ensures valid EmailDocument.
# Constraints: O(|ALL_PATTERNS| × |text|); expected < 5 ms on texts under 50 kB.
# Verification: test_detector.py::test_rule_engine_* — pattern hit rates; clean email returns [].
# References: fraud_patterns.py ALL_PATTERNS; NISPOM 32 CFR §117.10.
def run_rules(doc: EmailDocument) -> list[RuleMatch]:
    """Scan subject + body text against all fraud patterns."""
    text = doc.full_text
    matches: list[RuleMatch] = []

    for fp in ALL_PATTERNS:
        for m in fp.pattern.finditer(text):
            start = max(0, m.start() - 40)
            end = min(len(text), m.end() + 40)
            context = text[start:end].replace("\n", " ").strip()
            matches.append(RuleMatch(
                pattern=fp,
                matched_text=m.group(0),
                context=f"...{context}...",
            ))
            break  # one match per pattern is enough (avoid score inflation)

    return matches
