"""Deterministic smoke tests for validation runs."""

import sys
from pathlib import Path

from typer.testing import CliRunner

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from clearance_fraud_detector.cli import app
from clearance_fraud_detector.detector import EmailFraudDetector
from clearance_fraud_detector.scoring.scorer import Verdict


runner = CliRunner()
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


def test_cli_scan_text_exit_code_contract() -> None:
    """CLI should return 0 for clean verdict and non-zero for suspicious verdict."""
    clean = runner.invoke(
        app,
        [
            "scan-text",
            "Apply at boozallen.com/careers for a cleared role.",
            "--subject",
            "Opportunity",
            "--sender",
            "talent@boozallen.com",
        ],
    )
    suspicious = runner.invoke(
        app,
        [
            "scan-text",
            "Send your SSN now and pay a processing fee in bitcoin.",
            "--subject",
            "Urgent",
            "--sender",
            "recruiting@unknown.xyz",
        ],
    )

    assert clean.exit_code == 0
    assert suspicious.exit_code == 1
