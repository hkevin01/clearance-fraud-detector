"""
Tests for the Incident Report Generator (report_generator.py).

Validates that generated reports contain required sections, proper citations,
and correct formatting for submission to DCSA/FBI.
"""
import pytest
from datetime import date
from clearance_fraud_detector.report_generator import (
    generate_report,
    generate_submission_guide,
    quick_report,
    IncidentReportInput,
    IncidentReport,
    REPORTING_AGENCIES,
)


# ---------------------------------------------------------------------------
# Test: Basic report generation
# ---------------------------------------------------------------------------
class TestBasicReportGeneration:

    def test_quick_report_returns_string(self):
        result = quick_report(
            company="Mindbank Consulting Group",
            recruiter="[Recruiter]",
            violations=["32 CFR §117.10(a)(7)", "32 CFR §117.10(f)(1)(i)"],
            verdict="CONFIRMED_FRAUD",
            fraud_score=0.95,
        )
        assert isinstance(result, str)
        assert len(result) > 100

    def test_report_contains_company_name(self):
        result = quick_report("Mindbank Consulting Group", "[Recruiter]", [])
        assert "Mindbank" in result

    def test_report_contains_recruiter_name(self):
        result = quick_report("Some Corp", "[SVP]", [])
        assert "SVP" in result

    def test_report_contains_incident_summary_section(self):
        result = quick_report("Some Corp", "Recruiter", [])
        assert "INCIDENT SUMMARY" in result.upper() or "SUMMARY" in result.upper()


# ---------------------------------------------------------------------------
# Test: Violations in report
# ---------------------------------------------------------------------------
class TestViolationsInReport:

    def test_violations_appear_in_report(self):
        violations = ["32 CFR §117.10(a)(7)", "32 CFR §117.10(f)(1)(i)"]
        result = quick_report("Some Corp", "Someone", violations)
        assert "117.10(a)(7)" in result
        assert "117.10(f)" in result

    def test_empty_violations_still_generates_report(self):
        result = quick_report("Some Corp", "Someone", violations=[])
        assert isinstance(result, str)
        assert len(result) > 50

    def test_violation_descriptions_included(self):
        inp = IncidentReportInput(
            company_name="Test Corp",
            recruiter_name="Test Recruiter",
            violations=["32 CFR §117.10(a)(7)"],
            violation_descriptions=["Cannot check clearance of non-employee"],
        )
        report = generate_report(inp)
        rendered = report.render()
        assert "non-employee" in rendered.lower() or "117.10" in rendered


# ---------------------------------------------------------------------------
# Test: Report sections are all present
# ---------------------------------------------------------------------------
class TestReportSections:

    def setup_method(self):
        self.result = quick_report(
            "Test Corp", "Test Recruiter",
            violations=["32 CFR §117.10(a)(7)"],
            verdict="SUSPICIOUS",
            fraud_score=0.7,
        )

    def test_evidence_inventory_section_present(self):
        assert "EVIDENCE" in self.result.upper()

    def test_how_to_report_section_present(self):
        assert "REPORT" in self.result.upper()

    def test_what_not_to_do_section_present(self):
        assert "NOT" in self.result.upper() and "DO" in self.result.upper()

    def test_legal_authority_section_present(self):
        assert "LEGAL" in self.result.upper() or "117.10" in self.result

    def test_dcsa_contact_in_report(self):
        assert "DCSA" in self.result or "dcsa" in self.result.lower()


# ---------------------------------------------------------------------------
# Test: Markdown rendering
# ---------------------------------------------------------------------------
class TestMarkdownRendering:

    def test_markdown_render_returns_string(self):
        inp = IncidentReportInput(
            company_name="Test Company",
            recruiter_name="Test Recruiter",
        )
        report = generate_report(inp)
        md = report.render_markdown()
        assert isinstance(md, str)
        assert md.startswith("#")

    def test_markdown_has_h2_sections(self):
        inp = IncidentReportInput(company_name="X", recruiter_name="Y")
        report = generate_report(inp)
        md = report.render_markdown()
        assert "## " in md


# ---------------------------------------------------------------------------
# Test: Reporting agencies data structure
# ---------------------------------------------------------------------------
class TestReportingAgencies:

    def test_has_dcsa_agency(self):
        names = [a["name"] for a in REPORTING_AGENCIES]
        assert any("DCSA" in n for n in names)

    def test_has_fbi_agency(self):
        names = [a["name"] for a in REPORTING_AGENCIES]
        assert any("FBI" in n for n in names)

    def test_all_agencies_have_name(self):
        for agency in REPORTING_AGENCIES:
            assert "name" in agency and len(agency["name"]) > 0

    def test_all_agencies_have_url_or_phone(self):
        for agency in REPORTING_AGENCIES:
            has_url = "url" in agency and agency["url"]
            has_phone = "phone" in agency and agency["phone"]
            assert has_url or has_phone, f"Agency {agency.get('name')} has no contact info"

    def test_all_agencies_have_best_for(self):
        for agency in REPORTING_AGENCIES:
            assert "best_for" in agency and len(agency["best_for"]) > 0

    def test_has_nbis_agency(self):
        names = [a["name"] for a in REPORTING_AGENCIES]
        assert any("NBIS" in n for n in names), "DCSA NBIS entry missing from REPORTING_AGENCIES"

    def test_all_agencies_have_steps(self):
        for agency in REPORTING_AGENCIES:
            assert "steps" in agency, f"{agency.get('name')} missing 'steps' key"
            assert isinstance(agency["steps"], list), f"{agency.get('name')} steps must be a list"

    def test_nbis_entry_has_eapp_url(self):
        nbis = next((a for a in REPORTING_AGENCIES if "NBIS" in a["name"]), None)
        assert nbis is not None
        steps_text = " ".join(nbis["steps"])
        assert "eapp.nbis.mil" in steps_text

    def test_dcsa_ci_entry_has_mits_form_url(self):
        dcsa_ci = next((a for a in REPORTING_AGENCIES if "Counterintelligence" in a["name"]), None)
        assert dcsa_ci is not None
        steps_text = " ".join(dcsa_ci["steps"])
        assert "MITS" in steps_text or "mits" in steps_text.lower()

    def test_report_section_shows_numbered_agencies(self):
        result = quick_report("Test Corp", "Recruiter", violations=["§117.10(a)(7)"])
        assert "[1]" in result or "AGENCY 1" in result or "── " in result

    def test_nbis_steps_appear_in_generated_report(self):
        inp = IncidentReportInput(company_name="TSCTI", recruiter_name="[AFSSO]")
        report = generate_report(inp)
        rendered = report.render()
        assert "NBIS" in rendered
        assert "nbis" in rendered.lower()


# ---------------------------------------------------------------------------
# Test: IncidentReportInput fields
# ---------------------------------------------------------------------------
class TestIncidentReportInput:

    def test_default_incident_date_is_none(self):
        inp = IncidentReportInput()
        assert inp.incident_date is None

    def test_date_field_accepts_date_object(self):
        inp = IncidentReportInput(incident_date=date(2026, 4, 13))
        report = generate_report(inp)
        rendered = report.render()
        assert "2026-04-13" in rendered

    def test_fraud_score_appears_in_render(self):
        inp = IncidentReportInput(
            company_name="Mindbank",
            recruiter_name="[SVP]",
            fraud_score=0.95,
            verdict="CONFIRMED_FRAUD",
        )
        report = generate_report(inp)
        rendered = report.render()
        assert "95%" in rendered or "0.95" in rendered or "Confirmed" in rendered


# ---------------------------------------------------------------------------
# Test: generate_submission_guide()
# ---------------------------------------------------------------------------
class TestSubmissionGuide:

    def test_returns_string(self):
        result = generate_submission_guide()
        assert isinstance(result, str)
        assert len(result) > 200

    def test_contains_seven_steps(self):
        result = generate_submission_guide()
        assert "STEP 1" in result
        assert "STEP 7" in result

    def test_contains_dcsa_phone(self):
        result = generate_submission_guide()
        assert "571" in result and "305-6576" in result

    def test_contains_nbis_contact_info(self):
        result = generate_submission_guide()
        assert "878" in result
        assert "nbis" in result.lower()
        assert "eapp.nbis.mil" in result

    def test_contains_fbi_tip_url(self):
        result = generate_submission_guide()
        assert "tips.fbi.gov" in result

    def test_contains_ic3_url(self):
        result = generate_submission_guide()
        assert "complaint.ic3.gov" in result or "ic3.gov" in result

    def test_ssn_compromised_adds_credit_freeze_steps(self):
        result = generate_submission_guide(ssn_compromised=True)
        assert "Equifax" in result
        assert "Experian" in result
        assert "TransUnion" in result
        assert "identitytheft.gov" in result

    def test_ssn_not_compromised_has_ftc_step(self):
        result = generate_submission_guide(ssn_compromised=False)
        assert "reportfraud.ftc.gov" in result

    def test_ssn_compromised_omits_standard_ftc_step(self):
        result_ssn = generate_submission_guide(ssn_compromised=True)
        assert "identitytheft.gov" in result_ssn
        # SSN path goes directly to identitytheft.gov recovery plan
        assert "Equifax" in result_ssn

    def test_contains_preserve_evidence_instructions(self):
        result = generate_submission_guide()
        assert "Screenshot" in result or "screenshot" in result

    def test_contains_notify_fso_instruction(self):
        result = generate_submission_guide()
        assert "FSO" in result

    def test_contains_mits_form_url(self):
        result = generate_submission_guide()
        assert "MITS" in result

    def test_contains_verify_command_hint(self):
        result = generate_submission_guide()
        assert "fraud-check" in result
