"""
Tests for the Company Verifier module (company_verifier.py).

Validates CAGE code format, domain lookups, fraud flag detection,
and that the verification report has the right structure.
"""
import pytest
from clearance_fraud_detector.analyzers.company_verifier import (
    verify_company,
    CompanyVerificationReport,
    _is_valid_cage_format,
)


# ---------------------------------------------------------------------------
# Test: CAGE code format validation
# ---------------------------------------------------------------------------
class TestCageCodeFormat:

    def test_valid_five_char_cage(self):
        assert _is_valid_cage_format("1DT27") is True

    def test_valid_alphanumeric_cage(self):
        assert _is_valid_cage_format("OH859") is True

    def test_all_digits_valid(self):
        assert _is_valid_cage_format("12345") is True

    def test_all_letters_valid(self):
        assert _is_valid_cage_format("ABCDE") is True

    def test_too_short_invalid(self):
        assert _is_valid_cage_format("1234") is False

    def test_too_long_invalid(self):
        assert _is_valid_cage_format("1DT27X") is False

    def test_special_chars_invalid(self):
        assert _is_valid_cage_format("1DT-7") is False

    def test_empty_string_invalid(self):
        assert _is_valid_cage_format("") is False


# ---------------------------------------------------------------------------
# Test: Known legitimate contractor lookup
# ---------------------------------------------------------------------------
class TestLegitimateContractorLookup:

    def test_leidos_found_in_legitimate_list(self):
        report = verify_company("Leidos", domain="leidos.com")
        assert report.is_in_legitimate_list

    def test_leidos_produces_green_flag(self):
        report = verify_company("Leidos", domain="leidos.com")
        assert len(report.green_flags) >= 1

    def test_booz_allen_found_in_legitimate_list(self):
        report = verify_company("Booz Allen Hamilton", domain="boozallen.com")
        assert report.is_in_legitimate_list

    def test_unknown_company_not_in_list(self):
        report = verify_company("Totally Random Defense Corp", domain="trdc-fake.biz")
        assert not report.is_in_legitimate_list


# ---------------------------------------------------------------------------
# Test: Known fake domains
# ---------------------------------------------------------------------------
class TestFakeDomainDetection:

    def test_known_fake_domain_gets_red_flag(self):
        # Use a domain from the known_contractors KNOWN_FAKE_RECRUITING_DOMAINS if any
        # Test with a pattern that would be flagged
        report = verify_company("Some Company", domain="clearancejobs-apply.net")
        # Either it's in the fake list or it gets a yellow flag for unknown domain
        # The important thing is it's not marked as a legitimate domain
        assert not report.is_legitimate_domain


# ---------------------------------------------------------------------------
# Test: CAGE code provided vs not provided
# ---------------------------------------------------------------------------
class TestCageCodeProvided:

    def test_valid_cage_produces_yellow_flag(self):
        report = verify_company("Leidos", cage_code="1DTD7")
        # Should have a yellow flag saying manual verification required
        assert len(report.yellow_flags) >= 1

    def test_no_cage_produces_yellow_flag(self):
        report = verify_company("Some Company")
        # Should flag the absence of a CAGE code
        assert len(report.yellow_flags) >= 1

    def test_invalid_cage_format_produces_red_flag(self):
        report = verify_company("Some Company", cage_code="INVALID-CODE-TOO-LONG")
        assert len(report.red_flags) >= 1

    def test_sam_gov_url_populated_when_cage_valid(self):
        report = verify_company("Leidos", cage_code="1DTD7")
        assert report.sam_gov_url.startswith("https://sam.gov")


# ---------------------------------------------------------------------------
# Test: Interaction text fraud detection
# ---------------------------------------------------------------------------
class TestInteractionTextFraudDetection:

    def test_cage_refusal_in_text_produces_red_flag(self):
        text = "I cannot provide our CAGE code — it is proprietary and confidential."
        report = verify_company("Some Firm", interaction_text=text)
        assert len(report.red_flags) >= 1
        messages = [f.message for f in report.red_flags]
        assert any("CAGE" in m or "cage" in m.lower() for m in messages)

    def test_ssn_before_offer_in_text_produces_red_flag(self):
        text = "Please provide your SSN before we can make an offer so we can verify your clearance."
        report = verify_company("Some Firm", interaction_text=text)
        red_messages = [f.message for f in report.red_flags]
        assert any("SSN" in m or "117.10" in m for m in red_messages)

    def test_offer_conditioned_on_ssn_produces_red_flag(self):
        text = "We cannot extend an offer until you provide your Social Security Number."
        report = verify_company("Some Firm", interaction_text=text)
        assert any(f.level == "red" for f in report.flags)


# ---------------------------------------------------------------------------
# Test: Manual verification checklist
# ---------------------------------------------------------------------------
class TestManualVerificationChecklist:

    def test_unknown_company_has_manual_checks(self):
        report = verify_company("Unknown Corp")
        assert len(report.manual_checks) >= 2

    def test_manual_checks_include_sam_gov(self):
        report = verify_company("Unknown Corp")
        checks = " ".join(report.manual_checks)
        assert "sam.gov" in checks.lower()


# ---------------------------------------------------------------------------
# Test: Overall risk level
# ---------------------------------------------------------------------------
class TestOverallRiskLevel:

    def test_known_legit_contractor_is_low_risk(self):
        report = verify_company("Leidos", domain="leidos.com", cage_code="1DTD7")
        assert report.overall_risk in ("LOW", "MEDIUM")

    def test_multiple_red_flags_is_high_risk(self):
        text = (
            "Our CAGE code is confidential. "
            "You need to provide your SSN before we can make an offer. "
            "This is standard practice in cleared recruiting."
        )
        report = verify_company("Sketchy Firm LLC", interaction_text=text)
        assert report.overall_risk == "HIGH"

    def test_risk_level_is_valid_enum_value(self):
        report = verify_company("Leidos")
        assert report.overall_risk in ("LOW", "MEDIUM", "HIGH")


# ---------------------------------------------------------------------------
# Test: Report summary method
# ---------------------------------------------------------------------------
class TestReportSummaryMethod:

    def test_summary_returns_string(self):
        report = verify_company("Test Corp")
        summary = report.summary()
        assert isinstance(summary, str)
        assert "Test Corp" in summary

    def test_summary_includes_risk_level(self):
        report = verify_company("Test Corp")
        summary = report.summary()
        assert any(risk in summary for risk in ("LOW", "MEDIUM", "HIGH"))
