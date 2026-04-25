"""Deterministic smoke tests for validation runs (no CLI, no network)."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from clearance_fraud_detector.detector import EmailFraudDetector
from clearance_fraud_detector.scoring.scorer import Verdict


detector = EmailFraudDetector()


def test_detector_fraud_smoke_case() -> None:
    """High-risk DPRK-style message should not classify as clean."""
    body = (
        "Remote TS/SCI role, $400k, no background check. "
        "Complete I-9 before interview, camera must remain off, "
        "and provide SSN immediately."
    )
    score = detector.analyze_text(body, subject="Remote TS/SCI", sender="hr@unknown.xyz")
    assert score.verdict in (Verdict.SUSPICIOUS, Verdict.LIKELY_FRAUD, Verdict.FRAUD)
    assert score.total_score >= 0.25


def test_detector_clean_smoke_case() -> None:
    """Legitimate recruiter message should classify as clean."""
    body = (
        "Booz Allen Hamilton has a cleared backend engineer role in Arlington, VA. "
        "Apply through boozallen.com/careers. Active TS/SCI required. "
        "Background investigation paperwork follows written offer."
    )
    score = detector.analyze_text(body, subject="Cleared Backend Engineer", sender="talent@boozallen.com")
    assert score.verdict == Verdict.CLEAN
    assert score.total_score < 0.20
