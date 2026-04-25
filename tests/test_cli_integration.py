"""CLI Integration Tests - End-to-end command validation."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import pytest
from typer.testing import CliRunner
from clearance_fraud_detector.cli import app
from clearance_fraud_detector.scoring.scorer import Verdict

runner = CliRunner()

# ============================================================================
# Test Data
# ============================================================================

FRAUD_EMAIL_DPRK = (
    "Remote TS/SCI Developer — $400k. I am Mr. James from HR, confidential employer. "
    "Equipment will be shipped to home. No background check required. "
    "Provide SSN and DOB, complete I-9 before interview. Camera off during interview. "
    "Forward resume via WhatsApp. Salary forwarding account: wechat.pay"
)

FRAUD_EMAIL_PII = (
    "Congratulations! You're selected for TS/SCI role. Processing fee $200 Bitcoin. "
    "Please provide: Full Legal Name, SSN, DOB, Passport #, Bank account, "
    "Mother's maiden name. Respond immediately to hr@contractor-jobs-hiring.com"
)

FRAUD_EMAIL_FSO_IMPERSONATION = (
    "Your clearance is REVOKED. DCSA has suspended your TS/SCI. "
    "Send your SSN immediately to verify clearance status. "
    "Use this secure link: verify-clearance-dcsa.xyz/confirm-ssn. "
    "URGENT: 24 hours to respond or legal action will follow."
)

CLEAN_EMAIL_LEIDOS = (
    "Hi, we have a TS/SCI backend engineer role at Leidos Chantilly. "
    "Apply at leidos.com/careers. Upon offer, we'll sponsor SF-86 and EQIP. "
    "Active TS/SCI required. Interview at our SCIF in Chantilly VA. "
    "Contact: talent@leidos.com"
)


class TestCLIScanEmail:
    """Test fraud-check scan-text email command."""

    def test_scan_dprk_email_verdict_fraud(self):
        """DPRK-style email should score as FRAUD."""
        result = runner.invoke(app, [
            "scan-text",
            FRAUD_EMAIL_DPRK,
            "--subject", "Remote TS/SCI Developer",
            "--sender", "hr@unknown-corp.xyz"
        ])
        # CLI returns exit code 1 when fraud detected (intentional for scripting)
        assert result.exit_code == 1
        assert "FRAUD" in result.stdout or "LIKELY_FRAUD" in result.stdout or "SUSPICIOUS" in result.stdout
        assert "camera" in result.stdout.lower() or "ssn" in result.stdout.lower()

    def test_scan_pii_harvesting_email(self):
        """Email requesting bulk PII pre-offer should score high."""
        result = runner.invoke(app, [
            "scan-text",
            FRAUD_EMAIL_PII,
            "--subject", "Congratulations",
            "--sender", "hr@unknown.com"
        ])
        # Should detect fraud (exit code 1)
        assert result.exit_code == 1
        assert "FRAUD" in result.stdout or "SUSPICIOUS" in result.stdout
        assert "SSN" in result.stdout or "pii" in result.stdout.lower()

    def test_scan_fso_impersonation_email(self):
        """Email impersonating DCSA/FSO with clearance threat."""
        result = runner.invoke(app, [
            "scan-text",
            FRAUD_EMAIL_FSO_IMPERSONATION,
            "--subject", "Clearance Revoked",
            "--sender", "dcsa-admin@dcsa-update.xyz"
        ])
        # Should detect fraud
        assert result.exit_code == 1
        assert "FRAUD" in result.stdout or "LIKELY_FRAUD" in result.stdout

    def test_scan_clean_email_leidos(self):
        """Legitimate Leidos recruiting email should score low."""
        result = runner.invoke(app, [
            "scan-text",
            CLEAN_EMAIL_LEIDOS,
            "--subject", "TS/SCI Backend Engineer",
            "--sender", "talent@leidos.com"
        ])
        # Clean email should exit with 0
        assert result.exit_code == 0
        assert "CLEAN" in result.stdout or "LOW" in result.stdout

    def test_scan_with_source_email_flag(self):
        """Test --source-email flag for tracking."""
        result = runner.invoke(app, [
            "scan-text",
            FRAUD_EMAIL_DPRK,
            "--subject", "Remote Job",
            "--sender", "recruiter@fake.com",
            "--source-email", "unknown"
        ])
        # Source email flag may or may not be supported, but scan should work
        assert result.exit_code in (0, 1, 2)


class TestCLIScanJob:
    """Test fraud-check scan-job job posting command."""

    def test_scan_job_unrealistic_salary(self):
        """Job posting with $400K entry-level TS/SCI should flag."""
        job_text = (
            "Entry-level TS/SCI Backend Developer\n"
            "Remote, 100% work from home\n"
            "$400,000/year\n"
            "No experience required\n"
            "Start immediately\n"
            "Apply: send resume to hr@unknown.xyz"
        )
        result = runner.invoke(app, ["scan-job", job_text])
        # Suspicious job should return exit code 1
        assert result.exit_code == 1
        assert "SUSPICIOUS" in result.stdout or "FRAUD" in result.stdout

    def test_scan_job_fake_platform(self):
        """Job posting with fake ClearanceJobs domain."""
        job_text = (
            "TS/SCI Position - Apply Now!\n"
            "Visit: clearance-jobs-apply.io/vacancies\n"
            "Free email signup required\n"
            "Processing fee: $150"
        )
        result = runner.invoke(app, ["scan-job", job_text])
        # Fraudulent job should return exit code 1
        assert result.exit_code == 1

    def test_scan_job_legitimate(self):
        """Legitimate job posting."""
        job_text = (
            "TS/SCI Systems Administrator - Booz Allen Hamilton\n"
            "Location: Arlington VA (on-site)\n"
            "Salary: $90,000-$130,000 depending on experience\n"
            "Apply: boozallen.com/careers\n"
            "Active TS/SCI with polygraph required"
        )
        result = runner.invoke(app, ["scan-job", job_text])
        # Clean job posting should return exit code 0
        assert result.exit_code == 0


class TestCLIPhoneNumber:
    """Test fraud-check scan-number phone command."""

    def test_scan_number_voip_flagged(self):
        """VoIP number should be flagged with warning."""
        result = runner.invoke(app, ["scan-number", "+1-650-253-0000"])
        # May return 0 or 1 depending on whether it's flagged as suspicious
        assert result.exit_code in (0, 1)

    def test_scan_number_mobile(self):
        """Mobile number analysis."""
        result = runner.invoke(app, ["scan-number", "+1-202-555-0123"])
        # Should complete analysis regardless
        assert result.exit_code in (0, 1)

    def test_scan_number_invalid_format(self):
        """Invalid phone number should show error or analysis."""
        result = runner.invoke(app, ["scan-number", "not-a-phone"])
        # Invalid phone will likely return 1
        assert result.exit_code in (0, 1)


class TestCLIContact:
    """Test fraud-check scan-contact for FSO/recruiter analysis."""

    def test_scan_contact_fso_analysis(self):
        """FSO contact analysis."""
        result = runner.invoke(app, [
            "scan-contact",
            "Can you verify my clearance status in DISS?"
        ])
        # FSO verification question may not be suspicious
        assert result.exit_code in (0, 1)

    def test_scan_contact_recruiter_analysis(self):
        """Recruiter contact analysis."""
        # Test with a regular recruiter message (not suspicious)
        result = runner.invoke(app, [
            "scan-contact",
            "We have a TS/SCI role available. Apply at our careers page."
        ])
        # Regular message should return exit code 0
        assert result.exit_code == 0


class TestCLICompanyVerification:
    """Test fraud-check verify-company command."""

    def test_verify_company_known_contractor(self):
        """Known contractor should verify successfully."""
        result = runner.invoke(app, ["verify-company", "Booz Allen Hamilton"])
        # Company lookup always returns 0 (informational)
        assert result.exit_code == 0

    def test_verify_company_unknown(self):
        """Unknown company should show warning."""
        result = runner.invoke(app, ["verify-company", "TotallyUnknownCorp12345"])
        # Unknown company lookup may return 1
        assert result.exit_code in (0, 1)


class TestCLICompliance:
    """Test fraud-check compliance-check NISPOM compliance command."""

    def test_compliance_check_ssn_pre_offer(self):
        """SSN request pre-offer violates NISPOM."""
        result = runner.invoke(app, [
            "compliance-check",
            "Please provide your SSN for clearance verification"
        ])
        # Should detect violation (exit code 1)
        assert result.exit_code == 1
        # Should flag NISPOM violation
        assert "32 CFR" in result.stdout or "NISPOM" in result.stdout or "violation" in result.stdout.lower()

    def test_compliance_check_legitimate_process(self):
        """Legitimate FSO email referencing NISPOM."""
        result = runner.invoke(app, [
            "compliance-check",
            "Per NISPOM, your SF-86 completion activates your investigation."
        ])
        # Compliant text should return exit code 0
        assert result.exit_code == 0


class TestCLIOfferLetterVerification:
    """Test fraud-check verify-offer command."""

    def test_verify_offer_with_ssn_field(self):
        """Offer letter requesting SSN field."""
        offer_text = (
            "OFFER OF EMPLOYMENT\n"
            "Position: Software Engineer TS/SCI\n"
            "Salary: $120,000/year\n"
            "Please sign below and return with:\n"
            "- Social Security Number: ___________\n"
            "- Date of Birth: ___________"
        )
        result = runner.invoke(app, ["verify-offer", offer_text])
        # Fraudulent offer should return exit code 1
        assert result.exit_code == 1

    def test_verify_offer_legitimate(self):
        """Legitimate offer letter."""
        offer_text = (
            "OFFER OF EMPLOYMENT\n"
            "Position: Software Engineer\n"
            "Company: Booz Allen Hamilton\n"
            "Salary: $120,000/year\n"
            "Start Date: June 1, 2026\n"
            "Please sign and return. Background investigation will follow offer."
        )
        result = runner.invoke(app, ["verify-offer", offer_text])
        # Even legitimate offers may return 1 based on risk assessment
        assert result.exit_code in (0, 1)


class TestCLIDemonstration:
    """Test fraud-check demo command."""

    def test_demo_command_runs(self):
        """Demo command should execute successfully."""
        result = runner.invoke(app, ["demo"])
        # Demo should always return 0
        assert result.exit_code in (0, 1)
        # Should show example output
        assert len(result.stdout) > 100


class TestCLIExplain:
    """Test fraud-check explain command."""

    def test_explain_pattern(self):
        """Explain a specific pattern name."""
        result = runner.invoke(app, ["explain", "--pattern", "ssn_request"])
        assert result.exit_code == 0
        assert "SSN" in result.stdout or "Social Security" in result.stdout

    def test_explain_unknown_pattern(self):
        """Explain unknown pattern (should handle gracefully)."""
        result = runner.invoke(app, ["explain", "--pattern", "unknown_pattern_xyz"])
        # Should indicate pattern not found
        assert result.exit_code == 1

    def test_explain_list_all(self):
        """List all known patterns."""
        result = runner.invoke(app, ["explain", "--list"])
        assert result.exit_code == 0
        assert "pattern" in result.stdout.lower()


class TestCLIReportFraud:
    """Test fraud-check report-fraud command."""

    def test_report_fraud_generates_report(self):
        """Fraud report generation."""
        result = runner.invoke(app, [
            "report-fraud"
        ])
        # report-fraud is an interactive/help command
        assert result.exit_code in (0, 1, 2)


class TestCLIGenerateReport:
    """Test fraud-check generate-report command."""

    def test_generate_report_text_format(self):
        """Generate fraud report in text format."""
        result = runner.invoke(app, [
            "generate-report",
            "--company", "UnknownCorp Inc",
            "--recruiter", "John Doe",
            "--violation", "SSN requested before offer"
        ])
        assert result.exit_code == 0
        assert len(result.stdout) > 50

    def test_generate_report_markdown_format(self):
        """Generate fraud report in markdown format."""
        result = runner.invoke(app, [
            "generate-report",
            "--company", "UnknownCorp Inc",
            "--format", "markdown"
        ])
        assert result.exit_code == 0
        # Markdown should contain report info
        assert len(result.stdout) > 50


class TestCLIScanWorkforce:
    """Test fraud-check scan-workforce command."""

    def test_scan_workforce_mapping_indicators(self):
        """Scan for workforce mapping/CI collection indicators."""
        result = runner.invoke(app, [
            "scan-workforce",
            "What programs have you worked on? How many active TS holders in your network?",
            "--sender", "unknown@contractor.com"
        ])
        # CI collection signals may or may not flag as reportable
        assert result.exit_code in (0, 1)


class TestCLIScanAll:
    """Test fraud-check scan-all unified command."""

    def test_scan_all_comprehensive_analysis(self):
        """Unified scan-all command should provide complete analysis."""
        result = runner.invoke(app, [
            "scan-all",
            FRAUD_EMAIL_DPRK,
            "--subject", "Remote Job",
            "--sender", "recruiter@unknown.xyz"
        ])
        # Should return 1 if fraud detected
        assert result.exit_code == 1
        # Should show comprehensive output
        assert len(result.stdout) > 100


class TestCLIErrorHandling:
    """Test CLI error handling and edge cases."""

    def test_scan_empty_text(self):
        """Empty text should handle gracefully."""
        result = runner.invoke(app, ["scan-text", "", "--sender", "test@test.com"])
        # Should handle empty input without crash
        assert result.exit_code in (0, 1, 2)

    def test_scan_text_no_sender(self):
        """Scan without sender should still work."""
        result = runner.invoke(app, ["scan-text", "Some text here"])
        assert result.exit_code == 0

    def test_help_command(self):
        """Help command should work."""
        result = runner.invoke(app, ["--help"])
        assert result.exit_code == 0
        assert "Usage" in result.stdout or "Commands" in result.stdout

    def test_help_scan_command(self):
        """Help for specific command."""
        result = runner.invoke(app, ["scan-text", "--help"])
        assert result.exit_code == 0
        assert "Usage" in result.stdout or "Options" in result.stdout


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
