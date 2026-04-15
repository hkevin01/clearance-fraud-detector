"""
Tests for the NISPOM Compliance Analyzer (nispom_compliance.py).

Validates that each 32 CFR §117.10 rule is correctly triggered by
relevant interaction text and NOT triggered by clean interactions.
"""
import pytest
from clearance_fraud_detector.analyzers.nispom_compliance import (
    check_compliance,
    ComplianceReport,
    NispomsViolation,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------
MINDBANK_ESCALATION = """
Hi Candidate,

I wanted to reach out as the SVP of Sales & Recruiting here at Mindbank Consulting Group.
I understand you have concerns about providing your Social Security Number as part of our 
verification process. I want to reassure you that this is a common and standard practice 
in the cleared defense contracting industry.

As you may know, DISS uses the SSN as a primary identifier when verifying active clearances.
Our process is fully compliant with all applicable regulations. We could also use DOD SAFE 
(safe.apps.mil) as a secure channel to transmit sensitive information if that would make 
you more comfortable.

I assure you this is not an unusual request, as everyone we work with in the TS/SCI space 
has provided their SSN for this purpose.

Best regards,
[SVP, Sales & Recruiting]
Mindbank Consulting Group
"""

RECRUITER_PRE_OFFER_SSN = """
Hi Candidate,

Thanks for your interest in the Senior Systems Engineer position requiring TS/SCI clearance.
Before we can move forward with an offer, I need to verify your clearance status.
Could you please provide your Social Security Number so I can look up your clearance in DISS?
This is just our standard intake process.

Thanks,
[Senior Technical Recruiter]
"""

FAKE_FSO_CLEARANCE_CHECK = """
This message is from the Facility Security Officer at our company.
We need to verify your Top Secret clearance before we can proceed with your application.
Please provide your SSN and date of birth so we can confirm your clearance status in our system.
We can also accept it via email or phone if that's easier for you.
"""

LEGITIMATE_OFFER_FLOW = """
Dear Candidate,

Please find attached your formal written offer letter for the Senior Systems Engineer position.
Please review, sign, and return the countersigned acceptance.

Once we have your written acceptance, our FSO will initiate the NBIS eApp invitation so 
you can complete your SF-86 directly in the eApp system at eapp.nbis.mil.
Your SSN will be entered directly by you into the eApp — it does not go through us.

Looking forward to welcoming you.

[HR Manager]
"""

SOCIAL_ENGINEERING_PRESSURE = """
Look, everyone else in our pipeline has already provided their SSN.
We've processed 15 cleared candidates this month and they all cooperated.
If you're not comfortable, we'll just have to skip over you and move to 
the next candidate. This is standard practice in the cleared IT space.
The deadline is tomorrow — I need it today.
"""

CACHE_BUILDING_EMAIL = """
We're building a bench of cleared professionals for upcoming DoD contracts.
We need to verify your TS/SCI clearance in advance so we can place you quickly
when a position opens up. Please provide your SSN so we can check in DISS and 
have you pre-qualified in our cleared candidate pool.
"""

RECIPROCITY_IGNORED = """
I see you already have an active Top Secret clearance. However, our process
requires that we start a new investigation from scratch for all candidates.
Please fill out a fresh SF-86 — we can't use your existing clearance for this.
I'll need your SSN to begin the new investigation process.
"""


# ---------------------------------------------------------------------------
# Test: Pre-offer SSN request
# ---------------------------------------------------------------------------
class TestPreOfferSSNRequest:

    def test_pre_offer_ssn_triggers_117_10_f(self):
        report = check_compliance(RECRUITER_PRE_OFFER_SSN)
        rules = [v.rule for v in report.violations]
        assert any("117.10(f)" in r for r in rules), f"Expected §117.10(f) violation, got: {rules}"

    def test_pre_offer_ssn_triggers_117_10_a7(self):
        report = check_compliance(RECRUITER_PRE_OFFER_SSN)
        rules = [v.rule for v in report.violations]
        assert any("117.10(a)(7)" in r for r in rules), f"Expected §117.10(a)(7), got: {rules}"

    def test_pre_offer_ssn_is_not_compliant(self):
        report = check_compliance(RECRUITER_PRE_OFFER_SSN)
        assert report.overall_status != "COMPLIANT"
        assert report.has_violations

    def test_pre_offer_ssn_has_critical_violations(self):
        report = check_compliance(RECRUITER_PRE_OFFER_SSN)
        assert report.critical_count >= 1


# ---------------------------------------------------------------------------
# Test: Unauthorized channel (email/DOD SAFE)
# ---------------------------------------------------------------------------
class TestUnauthorizedChannel:

    def test_email_ssn_request_triggers_117_10_d(self):
        text = "Please email me your SSN so we can process your clearance paperwork."
        report = check_compliance(text)
        rules = [v.rule for v in report.violations]
        assert any("117.10(d)" in r for r in rules), f"Expected §117.10(d), got: {rules}"

    def test_dod_safe_ssn_triggers_117_10_d(self):
        report = check_compliance(MINDBANK_ESCALATION)
        rules = [v.rule for v in report.violations]
        assert any("117.10(d)" in r for r in rules or "DOD SAFE" in MINDBANK_ESCALATION), \
            f"Expected §117.10(d), got: {rules}"

    def test_phone_ssn_request_triggers_117_10_d(self):
        text = "Just call me back and give me your social security number over the phone."
        report = check_compliance(text)
        rules = [v.rule for v in report.violations]
        assert any("117.10(d)" in r for r in rules)


# ---------------------------------------------------------------------------
# Test: Cache building (§117.10(a)(5))
# ---------------------------------------------------------------------------
class TestCacheBuilding:

    def test_candidate_pipeline_triggers_a5(self):
        report = check_compliance(CACHE_BUILDING_EMAIL)
        rules = [v.rule for v in report.violations]
        assert any("117.10(a)(5)" in r for r in rules), f"Expected §117.10(a)(5), got: {rules}"

    def test_everyone_else_provided_triggers_a5(self):
        report = check_compliance(SOCIAL_ENGINEERING_PRESSURE)
        rules = [v.rule for v in report.violations]
        assert any("117.10(a)(5)" in r for r in rules), f"Expected §117.10(a)(5), got: {rules}"

    def test_standard_practice_triggers_a5(self):
        report = check_compliance(MINDBANK_ESCALATION)
        rules = [v.rule for v in report.violations]
        assert any("117.10(a)(5)" in r for r in rules), f"Expected §117.10(a)(5), got: {rules}"


# ---------------------------------------------------------------------------
# Test: Non-employee check (§117.10(a)(7))
# ---------------------------------------------------------------------------
class TestNonEmployeeCheck:

    def test_verify_clearance_non_employee_triggers_a7(self):
        report = check_compliance(FAKE_FSO_CLEARANCE_CHECK)
        rules = [v.rule for v in report.violations]
        assert any("117.10(a)(7)" in r for r in rules), f"Expected §117.10(a)(7), got: {rules}"

    def test_ssn_for_diss_lookup_triggers_a7(self):
        report = check_compliance(RECRUITER_PRE_OFFER_SSN)
        rules = [v.rule for v in report.violations]
        assert any("117.10(a)(7)" in r for r in rules)

    def test_mindbank_escalation_triggers_a7(self):
        report = check_compliance(MINDBANK_ESCALATION)
        rules = [v.rule for v in report.violations]
        assert any("117.10(a)(7)" in r for r in rules)


# ---------------------------------------------------------------------------
# Test: Reciprocity ignored (§117.10(h))
# ---------------------------------------------------------------------------
class TestReciprocityIgnored:

    def test_new_investigation_with_existing_clearance_triggers_h(self):
        report = check_compliance(RECIPROCITY_IGNORED)
        rules = [v.rule for v in report.violations]
        assert any("117.10(h)" in r for r in rules), f"Expected §117.10(h), got: {rules}"


# ---------------------------------------------------------------------------
# Test: Legitimate interaction produces no violations
# ---------------------------------------------------------------------------
class TestLegitimateInteraction:

    def test_proper_eapp_flow_is_compliant(self):
        report = check_compliance(LEGITIMATE_OFFER_FLOW)
        assert not report.has_violations, \
            f"Expected no violations for legitimate flow, got: {[v.rule for v in report.violations]}"

    def test_legitimate_flow_has_compliant_signals(self):
        report = check_compliance(LEGITIMATE_OFFER_FLOW)
        assert len(report.compliant_signals) >= 1

    def test_legitimate_flow_overall_status(self):
        report = check_compliance(LEGITIMATE_OFFER_FLOW)
        assert report.overall_status == "COMPLIANT"


# ---------------------------------------------------------------------------
# Test: API shape and utility methods
# ---------------------------------------------------------------------------
class TestComplianceReportAPI:

    def test_report_has_summary_method(self):
        report = check_compliance(RECRUITER_PRE_OFFER_SSN)
        summary = report.summary()
        assert "NISPOM" in summary or "violation" in summary.lower()

    def test_top_violation_returns_critical_first(self):
        report = check_compliance(RECRUITER_PRE_OFFER_SSN)
        top = report.top_violation
        assert top is not None
        assert top.severity == "critical"

    def test_violations_have_verbatim_text(self):
        report = check_compliance(RECRUITER_PRE_OFFER_SSN)
        for violation in report.violations:
            assert len(violation.verbatim) > 20, "Verbatim text should be present"
            assert violation.url.startswith("http")

    def test_critical_violations_counted_correctly(self):
        report = check_compliance(MINDBANK_ESCALATION)
        assert report.critical_count == len([v for v in report.violations if v.severity == "critical"])


# ---------------------------------------------------------------------------
# Test: TSCTI self-attestation pattern (22nd Century Technologies, April 2026)
# ---------------------------------------------------------------------------
class TestSelfAttestationPattern:
    """
    Tests the clearance self-attestation request pattern.
    An FSO with actual DISS access already has Eligibility Level, Determination,
    CE Date, and Investigation Type — they never need to ask the candidate.
    Documented instance: TSCTI / 22nd Century Technologies, April 13, 2026.
    """

    TSCTI_EMAIL = """
    Can you please verify the following information,
    This should suffice the clearance.

    Eligibility Level:
    Eligibility Determination:
    CE Date:
    Investigation Type:

    [Office Manager & Assistant Facility Security Officer]
    22nd Century Technologies, Inc. (TSCTI)
    """

    def test_tscti_email_is_not_compliant(self):
        report = check_compliance(self.TSCTI_EMAIL)
        assert report.overall_status != "COMPLIANT"
        assert report.has_violations

    def test_tscti_email_detects_self_attestation_category(self):
        report = check_compliance(self.TSCTI_EMAIL)
        categories = [v.category for v in report.violations]
        assert "self_attestation_clearance" in categories

    def test_tscti_email_cites_a7(self):
        report = check_compliance(self.TSCTI_EMAIL)
        rules = " ".join(v.rule for v in report.violations)
        assert "117.10(a)(7)" in rules

    def test_suffice_the_clearance_phrase_detected(self):
        from clearance_fraud_detector.data.fraud_patterns import ALL_PATTERNS
        text = "This should suffice the clearance verification process."
        hits = [p for p in ALL_PATTERNS if p.pattern.search(text)]
        names = [p.name for p in hits]
        assert "suffice_the_clearance_language" in names

    def test_eligibility_fields_form_detected(self):
        from clearance_fraud_detector.data.fraud_patterns import ALL_PATTERNS
        text = "Eligibility Level:\nEligibility Determination:\nCE Date:\nInvestigation Type:"
        hits = [p for p in ALL_PATTERNS if p.pattern.search(text)]
        names = [p.name for p in hits]
        assert "clearance_self_attestation_request" in names

    def test_self_attestation_violation_has_severity_high(self):
        report = check_compliance(self.TSCTI_EMAIL)
        for v in report.violations:
            if v.category == "self_attestation_clearance":
                assert v.severity == "high"

    def test_self_attestation_violation_has_verbatim_text(self):
        report = check_compliance(self.TSCTI_EMAIL)
        for v in report.violations:
            if v.category == "self_attestation_clearance":
                assert "117.10(a)(7)" in v.verbatim
                assert len(v.verbatim) > 50
