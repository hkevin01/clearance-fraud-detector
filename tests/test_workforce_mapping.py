"""
Tests for the workforce mapping / cleared community profiling analyzer.

Validates detection of the specific threat pattern documented in the FBI
"Think Before You Link" advisory: interactions that map the cleared workforce
regardless of whether the sender is fraudulent.
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import pytest
from clearance_fraud_detector.detector import EmailFraudDetector
from clearance_fraud_detector.analyzers.workforce_mapping_analyzer import (
    WorkforceMappingVerdict,
    analyze_workforce_mapping,
)

detector = EmailFraudDetector()


# ---------------------------------------------------------------------------
# Test fixtures
# ---------------------------------------------------------------------------

# The Robert Half scenario that prompted this feature: real domain, named recruiter,
# but anonymous client + resume request first + clearance eligibility as primary screen.
ROBERT_HALF_MSG = {
    "subject": "Full Stack Software Engineer (Python/C++ & ML) - Princeton NJ - $150K-175K",
    "sender": "Kevin.Azydzik@roberthalf.com",
    "body": (
        "I have a Full Stack Software Engineer (Python/C++ & Machine Learning) Position "
        "3 days a week onsite in Princeton, NJ. Client CANNOT Sponsor/Transfer work visas. "
        "$150k-170k+ Base Salary. If interested, send me over your most recent resume to "
        "kevin.azydzik@roberthalf.com and then we can set up a quick call to discuss.\n\n"
        "Candidates must be eligible to obtain a DoD security clearance.\n\n"
        "Key Responsibilities: Design, develop, and maintain full stack applications using "
        "Python and C++. Build and integrate machine learning models into production systems.\n\n"
        "Competitive salary ($150K-$175K). Hybrid work schedule (3 days onsite in Princeton, NJ)."
    ),
}

# Named company, proper ATS, no resume demand, no clearance probe — clean
CLEAN_TARGETED_OUTREACH = {
    "subject": "Software Engineer TS/SCI — Leidos Chantilly VA — Req #JR-48291",
    "sender": "talent@leidos.com",
    "body": (
        "Hi, I came across your profile for a cleared software engineer role at Leidos "
        "in Chantilly VA. Req #JR-48291. Requires active TS/SCI with full-scope poly. "
        "Please apply via leidos.com/careers. The SF-86 and eApp process is sponsored "
        "upon written offer. No fees required. Happy to discuss the adjudication timeline."
    ),
}

# Direct active clearance status probe
CLEARANCE_STATUS_PROBE = {
    "subject": "Cleared Developer Role — Quick Question",
    "sender": "recruiter@staffingco.net",
    "body": (
        "Hi, I have a great opportunity with a defense contractor. Before I submit your "
        "profile, I need to know: do you currently hold an active security clearance? "
        "What is your current clearance level? Please let me know as soon as possible."
    ),
}

# Classified program history fishing
PROGRAM_HISTORY_PROBE = {
    "subject": "Intelligence Community Role — Background Check",
    "sender": "hr@contractingfirm.com",
    "body": (
        "Thank you for your interest. To move forward, can you please tell me about "
        "what classified programs or projects you have worked on? We need to understand "
        "your cleared work history to match you to the right opportunity."
    ),
}

# Pre-screen reference collection
EARLY_REFERENCE_REQUEST = {
    "subject": "DoD Contractor Role — References Needed",
    "sender": "talent@defensestaff.com",
    "body": (
        "We have a strong match for your profile with a cleared defense contractor. "
        "Before we can proceed to the next step, we need you to provide your professional "
        "references now so we can begin the vetting process. Please send them today."
    ),
}

# FBI pattern: flattery + scarcity + urgency off platform
FBI_PATTERN_MATCH = {
    "subject": "Exclusive TS/SCI Opportunity — Your Cleared Background Is Perfect",
    "sender": "contact@defenseopps.net",
    "body": (
        "Your cleared background and government experience make you a perfect fit for "
        "this exclusive, one-time TS/SCI opportunity. This is a rare position that won't "
        "last long. Please respond to me directly off LinkedIn — let's talk privately "
        "about this unique cleared opening. Your impressive clearance history stood out."
    ),
}

# Unmonitored channel contact
TELEGRAM_CONTACT = {
    "subject": "Cleared Role",
    "sender": "unknown",
    "body": (
        "I have a cleared DevSecOps role with a defense contractor. "
        "Please contact me on Telegram to discuss this DoD clearance opportunity."
    ),
    "channel": "telegram",
}

# Employer chain mining
EMPLOYER_CHAIN_MINING = {
    "subject": "Defense Contracting Opportunity",
    "sender": "recruiter@defensehire.io",
    "body": (
        "We have several openings with top cleared defense contractors. "
        "To match you with the right opportunity, can you tell me which cleared "
        "contractors you have worked for in the past? Please list all previous "
        "cleared employers so we can avoid submitting you to companies you already know."
    ),
}


# ---------------------------------------------------------------------------
# Tests: clearance_for_sale false positive fix
# ---------------------------------------------------------------------------

class TestClearanceForSaleFix:
    """The 'eligible to obtain' phrasing must NOT trigger clearance_for_sale."""

    def test_eligible_to_obtain_not_flagged(self):
        """Standard DoD job posting language does not trigger clearance_for_sale."""
        result = detector.analyze_text(
            body="Candidates must be eligible to obtain a DoD security clearance.",
            sender="recruiter@contractor.com",
            subject="DoD Position",
        )
        pattern_names = [m.pattern.name for m in result.rule_matches]
        assert "clearance_for_sale" not in pattern_names, (
            "'eligible to obtain a DoD security clearance' should NOT trigger clearance_for_sale"
        )

    def test_we_can_get_you_a_clearance_flagged(self):
        """'We can get you a clearance' IS a fraud signal."""
        result = detector.analyze_text(
            body="We can get you a TS/SCI clearance guaranteed! Pay the processing fee.",
            sender="scammer@gmail.com",
            subject="Guaranteed Clearance",
        )
        pattern_names = [m.pattern.name for m in result.rule_matches]
        assert "clearance_for_sale" in pattern_names

    def test_buy_clearance_flagged(self):
        """'Buy a clearance' is a direct fraud signal."""
        result = detector.analyze_text(
            body="You can purchase a security clearance from us for $500.",
            sender="fraud@domain.com",
            subject="Buy Your Clearance",
        )
        pattern_names = [m.pattern.name for m in result.rule_matches]
        assert "clearance_for_sale" in pattern_names


# ---------------------------------------------------------------------------
# Tests: WorkforceMappingAnalysis via standalone function
# ---------------------------------------------------------------------------

class TestWorkforceMappingStandalone:

    def test_clean_named_company_with_req(self):
        """Named company + requisition number + no resume demand = CLEAN."""
        result = analyze_workforce_mapping(
            text=CLEAN_TARGETED_OUTREACH["body"],
            sender=CLEAN_TARGETED_OUTREACH["sender"],
            subject=CLEAN_TARGETED_OUTREACH["subject"],
        )
        assert result.verdict == WorkforceMappingVerdict.CLEAN, (
            f"Named company with req# should be CLEAN, got {result.verdict} "
            f"(score={result.risk_score}, signals={[s.category for s in result.signals]})"
        )
        assert result.is_ci_reportable is False

    def test_robert_half_commercial_harvest(self):
        """Robert Half scenario: real domain but anonymous client + resume first = COMMERCIAL_HARVEST."""
        result = analyze_workforce_mapping(
            text=ROBERT_HALF_MSG["body"],
            sender=ROBERT_HALF_MSG["sender"],
            subject=ROBERT_HALF_MSG["subject"],
        )
        assert result.verdict in (
            WorkforceMappingVerdict.COMMERCIAL_HARVEST,
            WorkforceMappingVerdict.CI_RISK,
        ), (
            f"Robert Half anonymous-client cleared role should be at least COMMERCIAL_HARVEST, "
            f"got {result.verdict} (score={result.risk_score})"
        )
        categories = {s.category for s in result.signals}
        # Should flag either anonymous client or unnamed employer
        assert "anonymous_client" in categories or "unnamed_employer" in categories or \
               "resume_collection" in categories or "no_requisition" in categories

    def test_robert_half_has_collection_vector(self):
        """Robert Half scenario must identify at least one collection vector."""
        result = analyze_workforce_mapping(
            text=ROBERT_HALF_MSG["body"],
            sender=ROBERT_HALF_MSG["sender"],
            subject=ROBERT_HALF_MSG["subject"],
        )
        assert len(result.collection_vectors) >= 1

    def test_robert_half_recommendation_to_verify_company(self):
        """Robert Half scenario must recommend verifying company before sending resume."""
        result = analyze_workforce_mapping(
            text=ROBERT_HALF_MSG["body"],
            sender=ROBERT_HALF_MSG["sender"],
            subject=ROBERT_HALF_MSG["subject"],
        )
        joined = " ".join(result.recommendations).lower()
        assert "company" in joined or "client" in joined, (
            "Recommendations should mention verifying company/client name"
        )

    def test_active_clearance_probe_detected(self):
        """Direct 'do you currently hold an active clearance' = CI_RISK at minimum."""
        result = analyze_workforce_mapping(
            text=CLEARANCE_STATUS_PROBE["body"],
            sender=CLEARANCE_STATUS_PROBE["sender"],
            subject=CLEARANCE_STATUS_PROBE["subject"],
        )
        categories = {s.category for s in result.signals}
        assert "clearance_status_probe" in categories
        assert result.verdict in (
            WorkforceMappingVerdict.CI_RISK,
            WorkforceMappingVerdict.CONFIRMED_COLLECTION,
        )
        assert result.is_ci_reportable is True

    def test_active_probe_collection_vector(self):
        """Active clearance probe should expose ACTIVE STATUS collection vector."""
        result = analyze_workforce_mapping(
            text=CLEARANCE_STATUS_PROBE["body"],
            sender=CLEARANCE_STATUS_PROBE["sender"],
            subject=CLEARANCE_STATUS_PROBE["subject"],
        )
        joined = " ".join(result.collection_vectors).upper()
        assert "ACTIVE STATUS" in joined

    def test_program_history_probe_detected(self):
        """'What classified programs have you worked on' = CI_RISK."""
        result = analyze_workforce_mapping(
            text=PROGRAM_HISTORY_PROBE["body"],
            sender=PROGRAM_HISTORY_PROBE["sender"],
            subject=PROGRAM_HISTORY_PROBE["subject"],
        )
        categories = {s.category for s in result.signals}
        assert "program_history_probe" in categories
        assert result.verdict in (
            WorkforceMappingVerdict.CI_RISK,
            WorkforceMappingVerdict.CONFIRMED_COLLECTION,
        )
        # Must recommend FSO reporting
        joined = " ".join(result.recommendations).lower()
        assert "fso" in joined or "report" in joined

    def test_program_probe_collection_vector(self):
        """Program probe should identify PROGRAM NAMES as a collection vector."""
        result = analyze_workforce_mapping(
            text=PROGRAM_HISTORY_PROBE["body"],
            sender=PROGRAM_HISTORY_PROBE["sender"],
            subject=PROGRAM_HISTORY_PROBE["subject"],
        )
        joined = " ".join(result.collection_vectors).upper()
        assert "PROGRAM" in joined

    def test_early_reference_request_detected(self):
        """References before interview = reference_harvest signal."""
        result = analyze_workforce_mapping(
            text=EARLY_REFERENCE_REQUEST["body"],
            sender=EARLY_REFERENCE_REQUEST["sender"],
            subject=EARLY_REFERENCE_REQUEST["subject"],
        )
        categories = {s.category for s in result.signals}
        assert "reference_harvest" in categories

    def test_reference_harvest_collection_vector(self):
        """Reference harvesting should expose REFERENCES collection vector."""
        result = analyze_workforce_mapping(
            text=EARLY_REFERENCE_REQUEST["body"],
            sender=EARLY_REFERENCE_REQUEST["sender"],
            subject=EARLY_REFERENCE_REQUEST["subject"],
        )
        joined = " ".join(result.collection_vectors).upper()
        assert "REFERENCES" in joined

    def test_fbi_pattern_match(self):
        """Flattery + scarcity + off-platform urgency = CONFIRMED_COLLECTION."""
        result = analyze_workforce_mapping(
            text=FBI_PATTERN_MATCH["body"],
            sender=FBI_PATTERN_MATCH["sender"],
            subject=FBI_PATTERN_MATCH["subject"],
        )
        assert result.verdict in (
            WorkforceMappingVerdict.CI_RISK,
            WorkforceMappingVerdict.CONFIRMED_COLLECTION,
        )
        assert len(result.fbi_indicator_matches) >= 2, (
            "Should match at least 2 FBI advisory indicators (flattery + scarcity/off-platform)"
        )

    def test_telegram_channel_critical(self):
        """Telegram contact channel for cleared role = high risk."""
        result = analyze_workforce_mapping(
            text=TELEGRAM_CONTACT["body"],
            sender=TELEGRAM_CONTACT["sender"],
            subject=TELEGRAM_CONTACT["subject"],
            contact_channel="telegram",
        )
        categories = {s.category for s in result.signals}
        assert "channel_risk" in categories
        channel_signal = next(s for s in result.signals if s.category == "channel_risk")
        assert channel_signal.severity == "critical"

    def test_employer_chain_mining_detected(self):
        """Asking for complete cleared employer list = employer_chain_mining."""
        result = analyze_workforce_mapping(
            text=EMPLOYER_CHAIN_MINING["body"],
            sender=EMPLOYER_CHAIN_MINING["sender"],
            subject=EMPLOYER_CHAIN_MINING["subject"],
        )
        categories = {s.category for s in result.signals}
        assert "employer_chain_mining" in categories

    def test_employer_mining_collection_vector(self):
        """Employer mining should expose EMPLOYER CHAIN collection vector."""
        result = analyze_workforce_mapping(
            text=EMPLOYER_CHAIN_MINING["body"],
            sender=EMPLOYER_CHAIN_MINING["sender"],
            subject=EMPLOYER_CHAIN_MINING["subject"],
        )
        joined = " ".join(result.collection_vectors).upper()
        assert "EMPLOYER" in joined

    def test_personal_email_sender_cleared_context(self):
        """Personal email domain + cleared role = channel_risk signal."""
        result = analyze_workforce_mapping(
            text="We have a DoD clearance position. Please send your resume.",
            sender="recruiter123@gmail.com",
            subject="Cleared Role",
        )
        categories = {s.category for s in result.signals}
        assert "channel_risk" in categories

    def test_no_signals_on_clean_message(self):
        """Clean named-company message with req# generates no significant signals."""
        result = analyze_workforce_mapping(
            text=CLEAN_TARGETED_OUTREACH["body"],
            sender=CLEAN_TARGETED_OUTREACH["sender"],
            subject=CLEAN_TARGETED_OUTREACH["subject"],
        )
        assert result.risk_score < 0.20, (
            f"Clean message should have low risk score, got {result.risk_score}"
        )

    def test_is_ci_reportable_false_for_clean(self):
        """Clean message should not be CI reportable."""
        result = analyze_workforce_mapping(
            text=CLEAN_TARGETED_OUTREACH["body"],
            sender=CLEAN_TARGETED_OUTREACH["sender"],
            subject=CLEAN_TARGETED_OUTREACH["subject"],
        )
        assert result.is_ci_reportable is False

    def test_is_ci_reportable_true_for_program_probe(self):
        """Program history probe must be marked CI reportable."""
        result = analyze_workforce_mapping(
            text=PROGRAM_HISTORY_PROBE["body"],
            sender=PROGRAM_HISTORY_PROBE["sender"],
            subject=PROGRAM_HISTORY_PROBE["subject"],
        )
        assert result.is_ci_reportable is True


# ---------------------------------------------------------------------------
# Tests: via EmailFraudDetector.analyze_workforce_mapping()
# ---------------------------------------------------------------------------

class TestWorkforceMappingViaDetector:

    def test_detector_method_exists(self):
        assert hasattr(detector, "analyze_workforce_mapping")

    def test_detector_returns_analysis(self):
        result = detector.analyze_workforce_mapping(
            body=ROBERT_HALF_MSG["body"],
            sender=ROBERT_HALF_MSG["sender"],
            subject=ROBERT_HALF_MSG["subject"],
        )
        assert isinstance(result.risk_score, float)
        assert isinstance(result.verdict, WorkforceMappingVerdict)
        assert isinstance(result.recommendations, list)
        assert len(result.recommendations) >= 1

    def test_detector_text_kwarg(self):
        """text= kwarg works the same as body=."""
        r1 = detector.analyze_workforce_mapping(
            body=CLEARANCE_STATUS_PROBE["body"],
            sender=CLEARANCE_STATUS_PROBE["sender"],
        )
        r2 = detector.analyze_workforce_mapping(
            text=CLEARANCE_STATUS_PROBE["body"],
            sender=CLEARANCE_STATUS_PROBE["sender"],
        )
        assert r1.verdict == r2.verdict
        assert r1.risk_score == r2.risk_score

    def test_detector_clearance_probe_ci_risk(self):
        result = detector.analyze_workforce_mapping(
            body=CLEARANCE_STATUS_PROBE["body"],
            sender=CLEARANCE_STATUS_PROBE["sender"],
            subject=CLEARANCE_STATUS_PROBE["subject"],
        )
        assert result.verdict in (
            WorkforceMappingVerdict.CI_RISK,
            WorkforceMappingVerdict.CONFIRMED_COLLECTION,
        )

    def test_detector_channel_telegram(self):
        result = detector.analyze_workforce_mapping(
            body=TELEGRAM_CONTACT["body"],
            sender=TELEGRAM_CONTACT["sender"],
            contact_channel="telegram",
        )
        categories = {s.category for s in result.signals}
        assert "channel_risk" in categories


# ---------------------------------------------------------------------------
# Tests: WORKFORCE_MAPPING_PATTERNS in the main rule engine
# ---------------------------------------------------------------------------

class TestWorkforceMappingRuleEngine:
    """Verify the new patterns also trigger through the standard fraud scoring pipeline."""

    def test_program_probe_in_rule_engine(self):
        """classified_program_history_probe fires in main rule engine."""
        result = detector.analyze_text(
            body=(
                "Thanks for your interest. Can you describe the classified programs "
                "and government projects you have worked on? We need your cleared work history."
            ),
            sender="hr@firm.com",
            subject="Cleared Role",
        )
        pattern_names = [m.pattern.name for m in result.rule_matches]
        assert "classified_program_history_probe" in pattern_names

    def test_active_clearance_probe_in_rule_engine(self):
        """active_clearance_level_probe fires in main rule engine."""
        result = detector.analyze_text(
            body="Do you currently hold an active security clearance? What is your clearance level?",
            sender="recruiter@firm.net",
            subject="Quick Question",
        )
        pattern_names = [m.pattern.name for m in result.rule_matches]
        assert "active_clearance_level_probe" in pattern_names

    def test_cleared_reference_early_in_rule_engine(self):
        """cleared_reference_early_request fires in main rule engine."""
        result = detector.analyze_text(
            body=(
                "Before we can proceed to the next step, we need you to provide your "
                "professional references now so we can begin the background process."
            ),
            sender="recruiter@firm.net",
            subject="References Needed",
        )
        pattern_names = [m.pattern.name for m in result.rule_matches]
        assert "cleared_reference_early_request" in pattern_names

    def test_employer_chain_in_rule_engine(self):
        """employer_chain_mining fires in main rule engine."""
        result = detector.analyze_text(
            body=(
                "To match you to the right role, please list all previous cleared "
                "employers and defense contractors you have worked for."
            ),
            sender="recruiter@firm.net",
            subject="Employer History",
        )
        pattern_names = [m.pattern.name for m in result.rule_matches]
        assert "employer_chain_mining" in pattern_names

    def test_eligible_to_obtain_does_not_raise_score(self):
        """Standard 'eligible to obtain clearance' language stays below SUSPICIOUS threshold."""
        result = detector.analyze_text(
            body=(
                "We are seeking a software engineer. Candidates must be eligible to obtain "
                "a DoD security clearance. Please apply at our careers page."
            ),
            sender="hr@contractor.com",
            subject="Software Engineer Role",
        )
        assert result.total_score < 0.45, (
            f"'Eligible to obtain clearance' should not push score to LIKELY_FRAUD, "
            f"got {result.total_score}"
        )


# ---------------------------------------------------------------------------
# Test fixtures: new 2025 threat patterns
# ---------------------------------------------------------------------------

# SGS Consulting / MIT Lincoln Lab FFRDC phishing pattern (April 2025)
# Structured clearance questionnaire table + legal name as in Passport/DL
SGS_STYLE_PRESCREEN = {
    "subject": "Data Scientist - Lexington, MA - REMOTE - MIT Lincoln Laboratory",
    "sender": "Gulsan@sgsconsulting.com",
    "body": (
        "I came across your profile and wanted to reach out regarding an exciting opportunity.\n\n"
        "Please fill out the following pre-screening information:\n\n"
        "Does the candidate have an active security clearance? Yes / No\n"
        "If Yes what is the current clearance level/tier?\n"
        "Previous clearance level/tier? (if inactive)\n"
        "Security Clearance Last Active Date:\n"
        "Investigation Type: (SBI / SBPR / T5 / T5R / T3 / T3R)\n\n"
        "Note: Legal Full Name (legal name as in Passport/DL):\n\n"
        "Please return the completed form at your earliest convenience."
    ),
}

# Think tank / consulting front targeting cleared personnel
THINK_TANK_FRONT_MSG = {
    "subject": "Consulting Opportunity — National Security Research Institute",
    "sender": "contact@natsec-research.org",
    "body": (
        "I represent the National Security Strategic Research Institute, a policy institute "
        "focused on defense and intelligence matters. We are seeking cleared professionals "
        "with government backgrounds to contribute to research on national security topics. "
        "This is a paid consulting engagement where your government and DoD experience would "
        "be invaluable. We offer competitive compensation for strategic insights and policy "
        "analysis. Please let me know if you have colleagues with cleared backgrounds who "
        "might be interested as well."
    ),
}

# Paid analysis elicitation (AFOSI April 2025 pattern)
PAID_ANALYSIS_MSG = {
    "subject": "Consulting Engagement — Your Government Background",
    "sender": "outreach@strategic-advisory-group.com",
    "body": (
        "Your government experience and cleared background are exactly what our clients "
        "are looking for. We offer paid consulting engagements for former and current "
        "government personnel. Payment of $2,500 per report for policy analysis based "
        "on your DoD and intelligence community experience. This is a flexible remote "
        "engagement — just share your expert opinion and government insights on current "
        "defense and national security matters. No clearance required for the analysis itself."
    ),
}

# Pre-screen clearance table (structured form format)
CLEARANCE_PRESCREEN_FORM = {
    "subject": "TS/SCI Role — Please Complete Pre-Screen",
    "sender": "recruiter@staffco.net",
    "body": (
        "Thank you for your interest. Please complete the following pre-screen:\n\n"
        "Active Clearance: Yes / No\n"
        "Current Clearance Level/Tier: _______________\n"
        "Previous Clearance Level/Tier: _______________\n"
        "Investigation Type: T5 / T5R / T3 / T3R / SBI\n"
        "Clearance Last Active Date: _______________\n\n"
        "Please return this form at your earliest convenience."
    ),
}

# Legal name passport/DL request
LEGAL_NAME_PRESCREEN = {
    "subject": "Position of Interest — Required Information",
    "sender": "hr@staffingfirm.com",
    "body": (
        "We have a great cleared opportunity for you. To proceed with submission, "
        "please provide the following:\n\n"
        "Full Legal Name (as it appears on your Passport or Driver's License):\n"
        "Current Employer:\n"
        "Clearance Level:\n\n"
        "We look forward to hearing from you."
    ),
}

# Certificate PDF harvest (CSA advisory pattern)
CERT_PDF_HARVEST = {
    "subject": "Verification of Credentials",
    "sender": "verify@hiring-services.net",
    "body": (
        "As part of our candidate verification process, please send us a copy of "
        "your CISSP certificate and your AWS cert. Please attach the PDF certificates "
        "to your reply so we can verify your credentials before proceeding."
    ),
}

# Social graph expansion
SOCIAL_GRAPH_MSG = {
    "subject": "Cleared DevSecOps Roles Available",
    "sender": "recruiter@defhire.net",
    "body": (
        "We have several cleared DevSecOps openings with TS/SCI requirements. "
        "Do you know any colleagues with a clearance who might be a good fit or interested? "
        "Also, do you know anyone with a TS/SCI clearance in the DC/MD/VA area? "
        "We'd love to connect with your cleared contacts."
    ),
}


# ---------------------------------------------------------------------------
# Tests: New CI / Workforce Mapping Patterns (2025 threat landscape)
# ---------------------------------------------------------------------------

class TestNewCI_Patterns2025:
    """
    Tests for patterns added in response to NCSC/FBI/DCSA April 2025 advisory
    and real-world phishing campaigns observed against cleared personnel.
    """

    # --- Pre-screen clearance table / structured form ---

    def test_sgs_style_prescreen_flags_in_rule_engine(self):
        """SGS-style structured clearance table fires pre_screen_clearance_table."""
        result = detector.analyze_text(
            body=SGS_STYLE_PRESCREEN["body"],
            sender=SGS_STYLE_PRESCREEN["sender"],
            subject=SGS_STYLE_PRESCREEN["subject"],
        )
        pattern_names = [m.pattern.name for m in result.rule_matches]
        assert "pre_screen_clearance_table" in pattern_names or \
               "legal_name_passport_prescreen" in pattern_names, (
            "SGS-style email should fire at least one pre-screen form pattern"
        )

    def test_sgs_style_prescreen_suspicious_score(self):
        """SGS-style pre-screen table pushes fraud score above CLEAN threshold."""
        result = detector.analyze_text(
            body=SGS_STYLE_PRESCREEN["body"],
            sender=SGS_STYLE_PRESCREEN["sender"],
            subject=SGS_STYLE_PRESCREEN["subject"],
        )
        assert result.total_score > 0.20, (
            f"SGS-style structured form should score above CLEAN, got {result.total_score}"
        )

    def test_clearance_prescreen_form_fires(self):
        """Standalone 'Active Clearance: Yes/No + Investigation Type' table fires."""
        result = detector.analyze_text(
            body=CLEARANCE_PRESCREEN_FORM["body"],
            sender=CLEARANCE_PRESCREEN_FORM["sender"],
            subject=CLEARANCE_PRESCREEN_FORM["subject"],
        )
        pattern_names = [m.pattern.name for m in result.rule_matches]
        assert "pre_screen_clearance_table" in pattern_names

    def test_investigation_type_field_detected(self):
        """'Investigation Type: T5 / T5R / T3 / T3R' field fires pre_screen_clearance_table."""
        result = detector.analyze_text(
            body="Please complete: Investigation Type: T5 / T5R / T3 / T3R / SBI",
            sender="r@firm.com",
            subject="Pre-Screen",
        )
        pattern_names = [m.pattern.name for m in result.rule_matches]
        assert "pre_screen_clearance_table" in pattern_names

    # --- Legal name / passport / DL at initial contact ---

    def test_legal_name_passport_fires(self):
        """'Legal Full Name (legal name as in Passport/DL)' fires legal_name_passport_prescreen."""
        result = detector.analyze_text(
            body=LEGAL_NAME_PRESCREEN["body"],
            sender=LEGAL_NAME_PRESCREEN["sender"],
            subject=LEGAL_NAME_PRESCREEN["subject"],
        )
        pattern_names = [m.pattern.name for m in result.rule_matches]
        assert "legal_name_passport_prescreen" in pattern_names, (
            "Legal name as in Passport/DL request should fire legal_name_passport_prescreen"
        )

    def test_legal_name_as_on_passport_variant(self):
        """'name as it appears on your passport' variant is detected."""
        result = detector.analyze_text(
            body="Please provide your full name as it appears on your passport or government ID.",
            sender="hr@company.com",
            subject="Required Information",
        )
        pattern_names = [m.pattern.name for m in result.rule_matches]
        assert "legal_name_passport_prescreen" in pattern_names

    # --- Workforce mapping analyzer signals ---

    def test_wm_pre_screen_form_signal(self):
        """Workforce mapping analyzer detects pre_screen_clearance_form signal."""
        result = analyze_workforce_mapping(
            text=SGS_STYLE_PRESCREEN["body"],
            sender=SGS_STYLE_PRESCREEN["sender"],
            subject=SGS_STYLE_PRESCREEN["subject"],
        )
        categories = {s.category for s in result.signals}
        assert "pre_screen_clearance_form" in categories

    def test_wm_pre_screen_form_raises_verdict(self):
        """Pre-screen clearance form should yield at least CI_RISK verdict."""
        result = analyze_workforce_mapping(
            text=CLEARANCE_PRESCREEN_FORM["body"],
            sender=CLEARANCE_PRESCREEN_FORM["sender"],
            subject=CLEARANCE_PRESCREEN_FORM["subject"],
        )
        assert result.verdict in (
            WorkforceMappingVerdict.CI_RISK,
            WorkforceMappingVerdict.CONFIRMED_COLLECTION,
        ), f"Pre-screen form should be CI_RISK+, got {result.verdict} (score={result.risk_score})"

    def test_wm_legal_name_signal(self):
        """Workforce mapping analyzer detects legal_name_pii_harvest signal."""
        result = analyze_workforce_mapping(
            text=LEGAL_NAME_PRESCREEN["body"],
            sender=LEGAL_NAME_PRESCREEN["sender"],
            subject=LEGAL_NAME_PRESCREEN["subject"],
        )
        categories = {s.category for s in result.signals}
        assert "legal_name_pii_harvest" in categories

    def test_wm_sgs_is_ci_reportable(self):
        """SGS-style email (pre-screen form + legal name) is CI reportable."""
        result = analyze_workforce_mapping(
            text=SGS_STYLE_PRESCREEN["body"],
            sender=SGS_STYLE_PRESCREEN["sender"],
            subject=SGS_STYLE_PRESCREEN["subject"],
        )
        assert result.is_ci_reportable is True, (
            f"SGS-style email with clearance table should be CI-reportable, "
            f"got verdict={result.verdict} score={result.risk_score}"
        )

    # --- Think tank / consulting front ---

    def test_think_tank_front_fires_in_rule_engine(self):
        """Think tank + cleared focus fires think_tank_consulting_front."""
        result = detector.analyze_text(
            body=THINK_TANK_FRONT_MSG["body"],
            sender=THINK_TANK_FRONT_MSG["sender"],
            subject=THINK_TANK_FRONT_MSG["subject"],
        )
        pattern_names = [m.pattern.name for m in result.rule_matches]
        assert "think_tank_consulting_front" in pattern_names or \
               "paid_analysis_report_request" in pattern_names or \
               "social_graph_colleague_referral" in pattern_names, (
            "Think tank front message should fire at least one foreign_front pattern"
        )

    def test_wm_think_tank_front_signal(self):
        """Workforce mapping analyzer detects think_tank_front signal."""
        result = analyze_workforce_mapping(
            text=THINK_TANK_FRONT_MSG["body"],
            sender=THINK_TANK_FRONT_MSG["sender"],
            subject=THINK_TANK_FRONT_MSG["subject"],
        )
        categories = {s.category for s in result.signals}
        assert "think_tank_front" in categories or \
               "paid_analysis_elicitation" in categories or \
               "social_graph_expansion" in categories, (
            f"Think tank message should flag CI signals, got: {categories}"
        )

    # --- Paid analysis / consulting elicitation ---

    def test_paid_analysis_fires_in_rule_engine(self):
        """Paid consulting offer for government insights fires paid_analysis_report_request."""
        result = detector.analyze_text(
            body=PAID_ANALYSIS_MSG["body"],
            sender=PAID_ANALYSIS_MSG["sender"],
            subject=PAID_ANALYSIS_MSG["subject"],
        )
        pattern_names = [m.pattern.name for m in result.rule_matches]
        assert "paid_analysis_report_request" in pattern_names or \
               "expert_government_insights_solicitation" in pattern_names, (
            "Paid analysis offer for government experience should fire a foreign_front pattern"
        )

    def test_wm_paid_elicitation_signal(self):
        """Workforce mapping analyzer detects paid_analysis_elicitation signal."""
        result = analyze_workforce_mapping(
            text=PAID_ANALYSIS_MSG["body"],
            sender=PAID_ANALYSIS_MSG["sender"],
            subject=PAID_ANALYSIS_MSG["subject"],
        )
        categories = {s.category for s in result.signals}
        assert "paid_analysis_elicitation" in categories, (
            f"Paid analysis offer should trigger paid_analysis_elicitation, got: {categories}"
        )

    def test_wm_paid_elicitation_ci_risk(self):
        """Paid analysis elicitation yields CI_RISK or higher."""
        result = analyze_workforce_mapping(
            text=PAID_ANALYSIS_MSG["body"],
            sender=PAID_ANALYSIS_MSG["sender"],
            subject=PAID_ANALYSIS_MSG["subject"],
        )
        assert result.verdict in (
            WorkforceMappingVerdict.CI_RISK,
            WorkforceMappingVerdict.CONFIRMED_COLLECTION,
        ), f"Paid analysis should be CI_RISK+, got {result.verdict} (score={result.risk_score})"

    # --- Social graph expansion ---

    def test_social_graph_fires_in_rule_engine(self):
        """'Do you know any cleared colleagues' fires social_graph_colleague_referral."""
        result = detector.analyze_text(
            body=SOCIAL_GRAPH_MSG["body"],
            sender=SOCIAL_GRAPH_MSG["sender"],
            subject=SOCIAL_GRAPH_MSG["subject"],
        )
        pattern_names = [m.pattern.name for m in result.rule_matches]
        assert "social_graph_colleague_referral" in pattern_names

    def test_wm_social_graph_signal(self):
        """Workforce mapping analyzer detects social_graph_expansion signal."""
        result = analyze_workforce_mapping(
            text=SOCIAL_GRAPH_MSG["body"],
            sender=SOCIAL_GRAPH_MSG["sender"],
            subject=SOCIAL_GRAPH_MSG["subject"],
        )
        categories = {s.category for s in result.signals}
        assert "social_graph_expansion" in categories

    # --- Credential / certificate harvest ---

    def test_cert_pdf_request_fires(self):
        """Request for CISSP/AWS cert PDF fires certification_pdf_request."""
        result = detector.analyze_text(
            body=CERT_PDF_HARVEST["body"],
            sender=CERT_PDF_HARVEST["sender"],
            subject=CERT_PDF_HARVEST["subject"],
        )
        pattern_names = [m.pattern.name for m in result.rule_matches]
        assert "certification_pdf_request" in pattern_names

    def test_clearance_cert_request_fires(self):
        """Request for clearance certificate document fires clearance_certificate_document_request."""
        result = detector.analyze_text(
            body="Please send us a copy of your clearance certificate or eligibility letter.",
            sender="hr@fake.com",
            subject="Clearance Verification",
        )
        pattern_names = [m.pattern.name for m in result.rule_matches]
        assert "clearance_certificate_document_request" in pattern_names

    def test_cac_request_fires(self):
        """Request for CAC card details fires cac_piv_request."""
        result = detector.analyze_text(
            body="Please share your CAC card number and certificate details for verification.",
            sender="admin@contractor.net",
            subject="ID Verification",
        )
        pattern_names = [m.pattern.name for m in result.rule_matches]
        assert "cac_piv_request" in pattern_names

    # --- Recommendations for new categories ---

    def test_pre_screen_form_recommendation(self):
        """Pre-screen form signal generates FSO reporting recommendation."""
        result = analyze_workforce_mapping(
            text=CLEARANCE_PRESCREEN_FORM["body"],
            sender=CLEARANCE_PRESCREEN_FORM["sender"],
            subject=CLEARANCE_PRESCREEN_FORM["subject"],
        )
        joined = " ".join(result.recommendations).lower()
        assert "questionnaire" in joined or "form" in joined or "fso" in joined, (
            "Pre-screen form should generate recommendation about questionnaire/FSO"
        )

    def test_paid_elicitation_recommendation_warns_fso(self):
        """Paid analysis elicitation recommendation warns to report to FSO."""
        result = analyze_workforce_mapping(
            text=PAID_ANALYSIS_MSG["body"],
            sender=PAID_ANALYSIS_MSG["sender"],
            subject=PAID_ANALYSIS_MSG["subject"],
        )
        joined = " ".join(result.recommendations).lower()
        assert "fso" in joined or "tips.fbi.gov" in joined, (
            "Paid elicitation should recommend FSO/FBI reporting"
        )

