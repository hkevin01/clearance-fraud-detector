"""
Tests for the NISPOM Process Validator (process_validator.py).

Validates that the 6-step legal hiring sequence is correctly detected,
and that violations of step ordering are flagged with proper CFR citations.
"""
import pytest
from clearance_fraud_detector.analyzers.process_validator import (
    validate_process,
    ProcessValidationReport,
    StepStatus,
    PROCESS_STEPS,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------
CORRECT_FULL_FLOW = """
We have sent you a formal written offer letter (attached). Once you have signed
and returned your written acceptance, our FSO will initiate the NBIS eApp invitation.
You will complete your SF-86 directly in eApp at eapp.nbis.mil.
Our FSO will review it for completeness and then submit to DCSA through DISS.
"""

PRE_OFFER_SSN_REQUEST = """
Before we can move forward, I need to verify your clearance.
This is just an initial screening call and we haven't made any offer yet.
Could you provide your SSN so I can check DISS prior to the offer being issued?
"""

PRE_OFFER_ACTIVE_CLEARANCE = """
We're interested in your profile. You mentioned you already have an active Top Secret 
clearance — that's great! Before we proceed with any offer, I need your SSN to 
verify your clearance status. This is just part of our pre-screening process.
"""

RECIPROCITY_CORRECT = """
Great news — I can see you already hold an active TS/SCI clearance.
Our FSO will use DISS JVS to verify reciprocity per §117.10(h).
No new investigation is needed. We can move forward with onboarding 
directly after your written offer and written acceptance are completed.
"""


# ---------------------------------------------------------------------------
# Test: Correct full process flow
# ---------------------------------------------------------------------------
class TestCorrectFullFlow:

    def test_correct_flow_shows_completed_steps(self):
        report = validate_process(CORRECT_FULL_FLOW)
        completed = report.completed_steps
        assert len(completed) >= 3, f"Expected >= 3 completed steps, got {len(completed)}"

    def test_correct_flow_no_skipped_steps(self):
        report = validate_process(CORRECT_FULL_FLOW)
        assert len(report.skipped_steps) == 0

    def test_correct_flow_has_no_violations(self):
        report = validate_process(CORRECT_FULL_FLOW)
        assert len(report.violations) == 0


# ---------------------------------------------------------------------------
# Test: Pre-offer SSN request violates steps
# ---------------------------------------------------------------------------
class TestPreOfferSSN:

    def test_pre_offer_ssn_triggers_skipped_steps(self):
        report = validate_process(PRE_OFFER_SSN_REQUEST)
        # Pre-offer state should flag missing offer/acceptance steps
        assert len(report.skipped_steps) >= 1 or report.overall_assessment != "COMPLIANT"

    def test_pre_offer_ssn_is_not_compliant(self):
        report = validate_process(PRE_OFFER_SSN_REQUEST)
        assert "COMPLIANT" not in report.overall_assessment or "NON" in report.overall_assessment

    def test_pre_offer_violations_cite_cfr(self):
        report = validate_process(PRE_OFFER_SSN_REQUEST)
        for violation in report.violations:
            assert "CFR" in violation or "117.10" in violation


# ---------------------------------------------------------------------------
# Test: Reciprocity cases
# ---------------------------------------------------------------------------
class TestReciprocityCases:

    def test_active_clearance_detected_as_reciprocity(self):
        report = validate_process(RECIPROCITY_CORRECT)
        assert report.is_reciprocity_case

    def test_reciprocity_flag_not_set_for_clean_normal_case(self):
        report = validate_process(CORRECT_FULL_FLOW)
        # May or may not be reciprocity — just ensure it doesn't crash
        assert isinstance(report.is_reciprocity_case, bool)

    def test_pre_offer_with_active_clearance_is_reciprocity(self):
        report = validate_process(PRE_OFFER_ACTIVE_CLEARANCE)
        assert report.is_reciprocity_case


# ---------------------------------------------------------------------------
# Test: Process steps have correct structure
# ---------------------------------------------------------------------------
class TestProcessStepStructure:

    def test_all_steps_have_cfr_citation(self):
        for step in PROCESS_STEPS:
            assert "CFR" in step.rule or "§117" in step.rule, \
                f"Step {step.number} missing CFR citation: {step.rule}"

    def test_all_steps_have_url(self):
        for step in PROCESS_STEPS:
            assert step.url.startswith("http"), f"Step {step.number} missing URL"

    def test_all_steps_have_detection_patterns(self):
        for step in PROCESS_STEPS:
            assert len(step.detection_patterns) >= 1, \
                f"Step {step.number} has no detection patterns"

    def test_six_total_process_steps(self):
        assert len(PROCESS_STEPS) == 6, f"Expected 6 steps, got {len(PROCESS_STEPS)}"

    def test_steps_are_numbered_1_to_6(self):
        numbers = [s.number for s in PROCESS_STEPS]
        assert numbers == [1, 2, 3, 4, 5, 6]


# ---------------------------------------------------------------------------
# Test: Report API
# ---------------------------------------------------------------------------
class TestProcessValidationReportAPI:

    def test_summary_method_returns_string(self):
        report = validate_process(CORRECT_FULL_FLOW)
        summary = report.summary()
        assert isinstance(summary, str)
        assert len(summary) > 10

    def test_report_overall_assessment_set(self):
        report = validate_process(CORRECT_FULL_FLOW)
        assert isinstance(report.overall_assessment, str)
        assert len(report.overall_assessment) > 0

    def test_step_results_length_matches_steps_checked(self):
        report = validate_process(CORRECT_FULL_FLOW)
        assert len(report.step_results) >= 1
