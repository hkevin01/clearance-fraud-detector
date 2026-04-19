"""Scoring layer — aggregates all analyzer outputs into a single FraudScore."""

from .scorer import FraudScore, Verdict, compute_score
from .explainer import ExplainerReport, Explanation, explain_patterns, explain_categories, explain_combined

__all__ = [
    "FraudScore",
    "Verdict",
    "compute_score",
    "ExplainerReport",
    "Explanation",
    "explain_patterns",
    "explain_categories",
    "explain_combined",
]