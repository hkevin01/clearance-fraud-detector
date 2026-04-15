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
