"""Tests for analyzers/offer_letter_verifier.py."""
import pytest
from clearance_fraud_detector.analyzers.offer_letter_verifier import (
    verify_offer_letter,
    OfferLetterAnalysis,
    OfferLetterFlag,
)


# ---------------------------------------------------------------------------
# Fixture texts
# ---------------------------------------------------------------------------

LEGITIMATE_OFFER = """
EMPLOYMENT OFFER LETTER

March 15, 2026

Alex Candidate
123 Main Street
Vienna, VA 22182

Dear Alex,

On behalf of Leidos Holdings, Inc., I am pleased to offer you the position of
Senior Software Engineer at our Chantilly, VA office.

Position: Senior Software Engineer, Cleared Programs
Start Date: April 1, 2026
Salary: $145,000 per year
Location: Chantilly, VA (on-site, SCIF access required)

This offer is contingent on successful background investigation through NBIS.
Upon acceptance of this offer, our FSO will send you an eApp invitation to
eapp.nbis.mil to complete your SF-86. The process is FSO-initiated through DISS.

Please countersign and return one copy to confirm your written acceptance.

Sincerely,
[Director, Human Resources]
[Talent Acquisition]
talent@leidos.com

Leidos Holdings, Inc.
11951 Freedom Drive
Reston, VA 20190
"""

FRAUD_OFFER_SSN_FIELD = """
EMPLOYMENT OFFER LETTER

Dear Applicant,

You have been selected for the position of Cleared Systems Engineer.

Social Security Number: _______________
Date of Birth: _______________
Bank Account Number: _______________

Please fill in the above fields and return this offer immediately.
Your employment cannot proceed without this information.
The offer expires tonight — respond immediately.
"""

FRAUD_OFFER_CONDITIONED_SSN = """
Employment Offer — Clearance Systems LLC

Congratulations! This offer is contingent on receipt of your SSN for
clearance processing purposes. We cannot finalize this offer without
your Social Security Number. Please provide your SSN to complete the
offer. We need it to initiate the clearance process immediately.

Respond within 24 hours or this offer expires.
"""

GMAIL_OFFER = """
Employment Offer — DCI Group

Dear candidate, we are pleased to offer you the Software Engineer position.
Salary: $130,000 per year.
Start Date: May 1, 2026.
Position: Software Engineer III

Sincerely,
HR Team
jobs@gmail.com
"""

TSCTI_STYLE_OFFER = """
Employment Offer

Please provide the following clearance information:
  Eligibility Level: _______________
  Eligibility Determination: _______________
  CE Date: _______________
  Investigation Type: _______________

This should suffice the clearance verification.
"""


class TestLegitimateOfferLetter:
    """Legitimate offer letter should have LOW risk and multiple green flags."""

    def test_legitimate_offer_is_low_risk(self):
        analysis = verify_offer_letter(LEGITIMATE_OFFER, sender_email="talent@leidos.com")
        assert analysis.overall_risk == "LOW"

    def test_has_physical_address(self):
        analysis = verify_offer_letter(LEGITIMATE_OFFER)
        assert analysis.has_physical_address is True

    def test_has_signing_authority(self):
        analysis = verify_offer_letter(LEGITIMATE_OFFER)
        assert analysis.has_signing_authority is True

    def test_has_job_title(self):
        analysis = verify_offer_letter(LEGITIMATE_OFFER)
        assert analysis.has_job_title is True

    def test_has_salary(self):
        analysis = verify_offer_letter(LEGITIMATE_OFFER)
        assert analysis.has_salary is True

    def test_has_start_date(self):
        analysis = verify_offer_letter(LEGITIMATE_OFFER)
        assert analysis.has_start_date is True

    def test_no_ssn_field(self):
        analysis = verify_offer_letter(LEGITIMATE_OFFER)
        assert analysis.has_ssn_field is False

    def test_no_red_flags(self):
        analysis = verify_offer_letter(LEGITIMATE_OFFER)
        assert len(analysis.red_flags) == 0

    def test_eapp_reference_detected(self):
        analysis = verify_offer_letter(LEGITIMATE_OFFER)
        green_messages = [f.message for f in analysis.green_flags]
        assert any("eApp" in m or "NBIS" in m or "process" in m for m in green_messages)

    def test_corporate_email_detected(self):
        analysis = verify_offer_letter(LEGITIMATE_OFFER, sender_email="talent@leidos.com")
        assert analysis.has_company_domain_email is True

    def test_legitimacy_score_above_threshold(self):
        analysis = verify_offer_letter(LEGITIMATE_OFFER)
        assert analysis.legitimacy_score >= 0.50


class TestFraudOfferWithSSNField:
    """Offer letter with SSN field is critical red flag."""

    def test_ssn_field_detected(self):
        analysis = verify_offer_letter(FRAUD_OFFER_SSN_FIELD)
        assert analysis.has_ssn_field is True

    def test_risk_is_high(self):
        analysis = verify_offer_letter(FRAUD_OFFER_SSN_FIELD)
        assert analysis.overall_risk == "HIGH"

    def test_ssn_field_red_flag_references_117_10_d(self):
        analysis = verify_offer_letter(FRAUD_OFFER_SSN_FIELD)
        ssn_flags = [f for f in analysis.red_flags if "SSN" in f.field_name or "ssn" in f.field_name.lower()]
        assert len(ssn_flags) >= 1
        assert any("117.10(d)" in f.rule or "NBIS" in f.message for f in ssn_flags)

    def test_urgency_pressure_detected(self):
        analysis = verify_offer_letter(FRAUD_OFFER_SSN_FIELD)
        urgency_flags = [f for f in analysis.red_flags if "urgency" in f.field_name.lower() or "urgency" in f.field_name]
        assert len(urgency_flags) >= 1

    def test_legitimacy_score_low(self):
        analysis = verify_offer_letter(FRAUD_OFFER_SSN_FIELD)
        assert analysis.legitimacy_score <= 0.30


class TestFraudOfferConditionedOnSSN:
    """Offer conditioned on SSN violates §117.10(d) and §117.10(f)(1)."""

    def test_ssn_conditioned_detected(self):
        analysis = verify_offer_letter(FRAUD_OFFER_CONDITIONED_SSN)
        assert analysis.ssn_conditioned is True

    def test_risk_is_high_or_medium(self):
        analysis = verify_offer_letter(FRAUD_OFFER_CONDITIONED_SSN)
        assert analysis.overall_risk in ("HIGH", "MEDIUM")

    def test_ssn_condition_flag_references_rule(self):
        analysis = verify_offer_letter(FRAUD_OFFER_CONDITIONED_SSN)
        ssn_flags = [f for f in analysis.red_flags if "condition" in f.field_name.lower()]
        assert len(ssn_flags) >= 1
        assert any("117.10" in f.rule for f in ssn_flags)


class TestFreeEmailDomain:
    """Free email domain (gmail/yahoo) on cleared job offer is red flag."""

    def test_gmail_sender_flagged_as_red(self):
        analysis = verify_offer_letter(GMAIL_OFFER, sender_email="jobs@gmail.com")
        assert analysis.free_email_domain is True
        assert any(f.level == "red" and "gmail" in f.message for f in analysis.flags)

    def test_gmail_in_text_flagged(self):
        analysis = verify_offer_letter(GMAIL_OFFER)
        assert analysis.free_email_domain is True

    def test_risk_medium_or_higher_for_free_email(self):
        analysis = verify_offer_letter(GMAIL_OFFER, sender_email="jobs@gmail.com")
        assert analysis.overall_risk in ("MEDIUM", "HIGH")


class TestOfferletterAnalysisAPI:
    """OfferLetterAnalysis public interface."""

    def test_red_flags_property(self):
        analysis = verify_offer_letter(FRAUD_OFFER_SSN_FIELD)
        assert all(f.level == "red" for f in analysis.red_flags)

    def test_yellow_flags_property(self):
        analysis = verify_offer_letter(FRAUD_OFFER_SSN_FIELD)
        assert all(f.level == "yellow" for f in analysis.yellow_flags)

    def test_green_flags_property(self):
        analysis = verify_offer_letter(LEGITIMATE_OFFER)
        assert all(f.level == "green" for f in analysis.green_flags)

    def test_summary_method_returns_string(self):
        analysis = verify_offer_letter(LEGITIMATE_OFFER)
        summary = analysis.summary()
        assert isinstance(summary, str)
        assert len(summary) > 20

    def test_summary_includes_risk_level(self):
        analysis = verify_offer_letter(LEGITIMATE_OFFER)
        summary = analysis.summary()
        assert analysis.overall_risk in summary

    def test_overall_risk_is_one_of_known_values(self):
        for text in [LEGITIMATE_OFFER, FRAUD_OFFER_SSN_FIELD, FRAUD_OFFER_CONDITIONED_SSN, GMAIL_OFFER]:
            analysis = verify_offer_letter(text)
            assert analysis.overall_risk in ("LOW", "MEDIUM", "HIGH", "UNKNOWN")

    def test_empty_text_returns_analysis(self):
        analysis = verify_offer_letter("")
        assert isinstance(analysis, OfferLetterAnalysis)
        assert analysis.overall_risk in ("LOW", "MEDIUM", "HIGH", "UNKNOWN")
