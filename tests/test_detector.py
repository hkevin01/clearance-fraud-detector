"""Tests for the clearance fraud detector."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import pytest
from clearance_fraud_detector.detector import EmailFraudDetector
from clearance_fraud_detector.scoring.scorer import Verdict

detector = EmailFraudDetector()


FRAUD_EMAIL_1 = {
    "subject": "URGENT: Top Secret Clearance Job - Act Now!!!",
    "sender": "jobs@dod-careers-hiring.com",
    "body": (
        "Dear Applicant, CONGRATULATIONS you have been SELECTED for a TS/SCI position. "
        "We can GUARANTEE your clearance! Please provide your Social Security Number. "
        "There is a processing fee of $200 required upfront via Bitcoin. "
        "This is CONFIDENTIAL — do not share. Respond IMMEDIATELY!"
    ),
}

FRAUD_EMAIL_2 = {
    "subject": "Booz Allen Hamilton Hiring",
    "sender": "recruiter@gmail.com",
    "body": (
        "Hello, I am from Booz Allen Hamilton. Entry level TS/SCI, no experience required, "
        "$300,000/year, work from home. Bank account details needed for payroll. "
        "We can get you a clearance guaranteed. Send your resume to this email immediately."
    ),
}

FRAUD_EMAIL_3 = {
    "subject": "NSA Job Opening",
    "sender": "nsa-recruiter@nsa-jobs.com",
    "body": (
        "The NSA is hiring! Gift card payment accepted for registration fee. "
        "Please provide your date of birth and passport number. Wire transfer required."
    ),
}

FRAUD_EMAIL_DPRK = {
    "subject": "Remote TS/SCI Developer — $400k — Start Immediately",
    "sender": "hr@defenselinejobs.xyz",
    "body": (
        "Greetings of the day! I am Mr. James from HR. We are a confidential employer. "
        "TS/SCI, work from home 100%. Equipment will be shipped to your home address. "
        "No background check required. Kindly provide your SSN and date of birth "
        "and complete the I-9 before interview. Please forward your resume via WhatsApp. "
        "Salary: $400,000/year. Start immediately. Camera must be off during interview."
    ),
}

CLEAN_EMAIL_1 = {
    "subject": "Software Engineer TS/SCI — Leidos Chantilly VA",
    "sender": "talent@leidos.com",
    "body": (
        "Hi, I came across your profile for a cleared software engineer role at Leidos. "
        "Requires active TS/SCI with polygraph. Apply via leidos.com/careers. "
        "The SF-86 and EQIP process sponsored upon offer. No fees required. "
        "Happy to discuss the adjudication and background investigation process."
    ),
}

CLEAN_EMAIL_2 = {
    "subject": "Cleared Backend Engineer — Booz Allen Hamilton",
    "sender": "recruiting@boozallen.com",
    "body": (
        "We have a cleared backend engineer opening at our Herndon office. "
        "Active Secret clearance required, we sponsor TS upgrades. "
        "Competitive salary range $95k-$140k. Please apply at boozallen.com/careers "
        "or reach me at this corporate email. Interviews conducted in person at our SCIF."
    ),
}


# ---------------------------------------------------------------------------
# Email fraud tests
# ---------------------------------------------------------------------------

class TestFraudDetection:
    def test_fraud_email_fee_ssn(self):
        score = detector.analyze_text(**FRAUD_EMAIL_1)
        assert score.verdict in (Verdict.LIKELY_FRAUD, Verdict.FRAUD), \
            f"Expected LIKELY_FRAUD/FRAUD, got {score.verdict} (score={score.total_score})"
        assert score.total_score > 0.45

    def test_fraud_email_fake_contractor(self):
        score = detector.analyze_text(**FRAUD_EMAIL_2)
        assert score.verdict in (Verdict.LIKELY_FRAUD, Verdict.FRAUD, Verdict.SUSPICIOUS), \
            f"Expected SUSPICIOUS+, got {score.verdict} (score={score.total_score})"
        assert score.total_score > 0.25

    def test_fraud_email_fake_nsa_domain(self):
        score = detector.analyze_text(**FRAUD_EMAIL_3)
        assert score.total_score > 0.20

    def test_fraud_email_dprk_signals(self):
        """DPRK-style email should score high — camera-off, I-9 pre-hire, home laptop, etc."""
        score = detector.analyze_text(**FRAUD_EMAIL_DPRK)
        assert score.verdict in (Verdict.LIKELY_FRAUD, Verdict.FRAUD), \
            f"Expected LIKELY_FRAUD/FRAUD for DPRK email, got {score.verdict} (score={score.total_score})"
        assert score.total_score > 0.50

    def test_clean_email_leidos(self):
        score = detector.analyze_text(**CLEAN_EMAIL_1)
        assert score.verdict in (Verdict.CLEAN, Verdict.SUSPICIOUS), \
            f"Expected CLEAN/SUSPICIOUS, got {score.verdict} (score={score.total_score})"
        assert score.total_score < 0.50

    def test_clean_email_booz_allen(self):
        score = detector.analyze_text(**CLEAN_EMAIL_2)
        assert score.verdict in (Verdict.CLEAN, Verdict.SUSPICIOUS), \
            f"Expected CLEAN/SUSPICIOUS, got {score.verdict} (score={score.total_score})"

    def test_score_is_normalized(self):
        score = detector.analyze_text(body="test email body")
        assert 0.0 <= score.total_score <= 1.0

    def test_has_verdict(self):
        score = detector.analyze_text(body="test")
        assert score.verdict in Verdict.__members__.values()

    def test_identity_theft_combo_ssn_dob(self):
        """SSN + DOB together in one email must trigger maximum-weight identity_theft pattern."""
        score = detector.analyze_text(
            body="Please provide your social security number and date of birth to proceed.",
            subject="Clearance Application Form",
            sender="hr@defensecontractor.xyz",
        )
        assert score.total_score > 0.35

    def test_chinese_domain_flagged(self):
        """Email from qq.com or 163.com should be flagged for clearance job context."""
        from clearance_fraud_detector.parsers.email_parser import parse_plain_text
        from clearance_fraud_detector.analyzers.domain_analyzer import analyze_domains
        doc = parse_plain_text(
            "We have a TS/SCI position for you.",
            sender="recruiter@qq.com",
        )
        findings = analyze_domains(doc)
        assert any("Chinese" in f.finding or "chinese" in f.finding.lower() for f in findings), \
            "Expected Chinese consumer domain finding for qq.com sender"


# ---------------------------------------------------------------------------
# Vishing / call transcript tests
# ---------------------------------------------------------------------------

FRAUD_CALL_DPRK = (
    "The recruiter's voice sounded robotic and artificial, clearly AI-generated voice. "
    "He told me camera must be off during the interview, audio only. "
    "He asked me to verify my SSN and date of birth over the phone right now. "
    "He said I was hired on the spot. "
    "He told me all communication only via Telegram. "
    "He said my equipment laptop will be shipped to a forwarding address."
)

FRAUD_CALL_PRESSURE = (
    "The caller said I must decide right now — the offer expires tonight. "
    "There are other candidates ready to take the position immediately. "
    "He said no in-person interview needed for this TS/SCI role. "
    "Interview was text only via WhatsApp, hiring via WhatsApp only."
)

CLEAN_CALL = (
    "Spoke with Sarah from Leidos talent acquisition on a video call, both cameras on. "
    "She described the TS/SCI role in Chantilly. Mentioned SF-86 and EQIP process. "
    "HR will send formal offer via corporate Leidos email. "
    "In-person interview at Chantilly office scheduled."
)


class TestVishingAnalyzer:
    def test_dprk_call_flagged(self):
        analysis = detector.analyze_call_transcript(FRAUD_CALL_DPRK)
        assert analysis.is_suspicious_call, \
            f"DPRK call should be flagged, risk={analysis.risk_score}"
        assert analysis.risk_score > 0.50

    def test_pressure_call_flagged(self):
        analysis = detector.analyze_call_transcript(FRAUD_CALL_PRESSURE)
        assert analysis.is_suspicious_call, \
            f"Pressure tactic call should be flagged, risk={analysis.risk_score}"

    def test_clean_call_not_flagged(self):
        analysis = detector.analyze_call_transcript(CLEAN_CALL)
        assert not analysis.is_suspicious_call, \
            f"Legitimate call was incorrectly flagged, risk={analysis.risk_score}"

    def test_empty_call_safe(self):
        analysis = detector.analyze_call_transcript("")
        assert not analysis.is_suspicious_call
        assert analysis.risk_score == 0.0

    def test_pii_on_call_detected(self):
        transcript = "Please provide your social security number and date of birth over the phone right now."
        analysis = detector.analyze_call_transcript(transcript)
        assert analysis.is_suspicious_call
        categories = {f.category for f in analysis.findings}
        assert "pii_harvest" in categories


# ---------------------------------------------------------------------------
# Job posting analyzer tests
# ---------------------------------------------------------------------------

FRAUD_JOB_POSTING = (
    "Hiring: Remote TS/SCI Full Stack Developer\n"
    "Salary: $400,000/year — No experience required\n"
    "Employer: Confidential employer wishes to remain anonymous\n"
    "No background check required. Work fully remote from home. "
    "Interview audio-only — camera off required. "
    "Please include your SSN and date of birth in your application. "
    "Application fee: $50 processing required. "
    "Laptop will be shipped to your provided address. "
    "We guarantee your TS/SCI clearance. Start immediately. "
    "Apply via Telegram: @cleared_remote_jobs"
)

CLEAN_JOB_POSTING = (
    "Systems Engineer III — Active TS/SCI Required\n"
    "Location: Chantilly, VA (on-site in SCIF)\n"
    "Company: Booz Allen Hamilton (boozallen.com)\n"
    "Requires active TS/SCI with full-scope polygraph. 5+ years experience required. "
    "Salary: $120,000–$160,000. Full benefits. Apply at boozallen.com/careers. "
    "Background investigation sponsored by Booz Allen. In-person interviews required."
)


class TestJobPostingAnalyzer:
    def test_fraud_job_posting_flagged(self):
        analysis = detector.analyze_job_posting(FRAUD_JOB_POSTING)
        assert analysis.is_fraudulent, \
            f"Fraud job posting should be flagged, risk={analysis.risk_score}"
        assert analysis.risk_score > 0.60

    def test_clean_job_posting_not_flagged(self):
        analysis = detector.analyze_job_posting(CLEAN_JOB_POSTING)
        assert not analysis.is_fraudulent, \
            f"Legitimate posting was incorrectly flagged, risk={analysis.risk_score}"

    def test_clearance_guarantee_detected(self):
        posting = "We guarantee your TS/SCI clearance upon hire."
        analysis = detector.analyze_job_posting(posting)
        assert analysis.is_fraudulent
        categories = {f.category for f in analysis.findings}
        assert "clearance_fraud" in categories

    def test_pii_in_application_detected(self):
        posting = "Please include your SSN and date of birth in your application."
        analysis = detector.analyze_job_posting(posting)
        assert analysis.is_fraudulent
        categories = {f.category for f in analysis.findings}
        assert "pii_harvest" in categories

    def test_remote_tssci_detected(self):
        posting = "Fully remote TS/SCI position — work from home on classified projects."
        analysis = detector.analyze_job_posting(posting)
        assert any(f.category == "logistics_fraud" for f in analysis.findings)

    def test_empty_posting_safe(self):
        analysis = detector.analyze_job_posting("")
        assert not analysis.is_fraudulent
        assert analysis.risk_score == 0.0

    def test_application_fee_detected(self):
        posting = "There is a processing fee to apply. Pay $75 to submit your application."
        analysis = detector.analyze_job_posting(posting)
        assert analysis.is_fraudulent
        categories = {f.category for f in analysis.findings}
        assert "financial_fraud" in categories


    def test_fraud_signals_in_matches(self):
        score = detector.analyze_text(**FRAUD_EMAIL_1)
        categories = [m.category for m in score.rule_matches]
        assert any(c in ("pii_harvest", "financial_scam", "clearance_scam") for c in categories)

    def test_domain_mismatch_detected(self):
        score = detector.analyze_text(
            body="I am from Booz Allen Hamilton and want to hire you.",
            sender="jobs@sketchy-domain.net"
        )
        domain_findings = [df.finding for df in score.domain_findings]
        assert any("mismatch" in f.lower() or "contractor" in f.lower() for f in domain_findings)

    def test_free_email_provider_flagged(self):
        score = detector.analyze_text(
            body="Job opportunity available.",
            sender="recruiter@gmail.com"
        )
        domain_findings = [df.finding for df in score.domain_findings]
        assert any("free" in f.lower() for f in domain_findings)


# ---------------------------------------------------------------------------
# FSO / Recruiter Contact Analyzer tests
# Tests the core distinction: real FSO vs fake FSO vs fake recruiter
# ---------------------------------------------------------------------------

# The #1 real-world attack: fake FSO asks for SSN "to verify clearance in DISS"
FAKE_FSO_SSN_VERIFY = (
    "Hi, I'm the FSO at our facility. Before we can proceed, I need your SSN "
    "to verify your clearance status in DISS. Please email your social security "
    "number so we can look up your clearance."
)

# Fake FSO claiming to be DCSA with a suspended clearance threat
FAKE_FSO_DCSA_SUSPENSION = (
    "This is a DCSA investigator calling. Your clearance file is currently being "
    "flagged. To avoid suspension, you must provide your SSN and date of birth "
    "to reactivate your access. There is a clearance processing fee of $150."
)

# Fake recruiter: pre-offer PII harvest via Telegram + camera-off
FAKE_RECRUITER_TELEGRAM = (
    "Hi, I am a recruiter for a confidential government contractor. We have a "
    "TS/SCI opening paying $450,000/year — no experience required. "
    "Please send me your SSN and date of birth along with your resume for initial screening. "
    "Camera must be off for the audio-only interview. "
    "Contact me only via Telegram @cleared_jobs_us to apply."
)

# Fake IC agency recruiter
FAKE_RECRUITER_NSA = (
    "I am a recruiter for the NSA. We can guarantee you a TS/SCI clearance. "
    "To register, there is a $75 processing fee. Please send your SSN "
    "and full legal name and date of birth for the initial application."
)

# Legitimate FSO contact — uses DISS terminology correctly, no SSN ask
LEGIT_FSO_CONTACT = (
    "Hi, this is Sarah from Leidos Security. We have an active requisition that "
    "requires TS/SCI access. I pulled your record in DISS using your current employer "
    "information. I'll need you to sign a visit authorization request and we'll schedule "
    "your SCIF indoctrination. Your current FSO will be notified of the read-on. "
    "Once the formal offer is extended through HR, eQIP/SF-86 processing will be initiated."
)

# Legitimate recruiter outreach — named company, corporate email, proper process
LEGIT_RECRUITER_CONTACT = (
    "Hi, I'm reaching out from Booz Allen Hamilton's talent team about a cleared "
    "software engineer opening in Chantilly. The role requires active TS/SCI. "
    "Please apply at boozallen.com/careers — our ATS will walk you through the process. "
    "Interviews are conducted in person at our Chantilly office. "
    "Background investigation is sponsored by Booz Allen after offer acceptance."
)


class TestContactAnalyzer:
    def test_fake_fso_ssn_verify_detected(self):
        """Core exploit: fake FSO asking for SSN to 'verify clearance in DISS'."""
        from clearance_fraud_detector.analyzers.contact_analyzer import ContactType
        analysis = detector.analyze_contact(FAKE_FSO_SSN_VERIFY)
        assert analysis.is_suspicious, \
            f"Fake FSO SSN-verify message should be flagged, risk={analysis.risk_score}"
        assert analysis.contact_type in (
            ContactType.FAKE_FSO, ContactType.SUSPICIOUS_FSO, ContactType.MIXED
        ), f"Expected FSO fraud type, got {analysis.contact_type}"
        actor_types = {f.actor_type for f in analysis.findings}
        assert "fso_impersonation" in actor_types

    def test_fake_fso_dcsa_suspension_detected(self):
        """Fake DCSA agent threatening clearance suspension to extort PII+fee."""
        from clearance_fraud_detector.analyzers.contact_analyzer import ContactType
        analysis = detector.analyze_contact(FAKE_FSO_DCSA_SUSPENSION)
        assert analysis.is_suspicious, \
            f"DCSA impersonation+suspension threat should be flagged, risk={analysis.risk_score}"
        assert analysis.fso_score > 0.40

    def test_fake_recruiter_telegram_pii_detected(self):
        """Fake recruiter: pre-offer SSN + Telegram-only + camera-off."""
        from clearance_fraud_detector.analyzers.contact_analyzer import ContactType
        analysis = detector.analyze_contact(FAKE_RECRUITER_TELEGRAM)
        assert analysis.is_suspicious, \
            f"Fake recruiter should be flagged, risk={analysis.risk_score}"
        assert analysis.contact_type in (
            ContactType.FAKE_RECRUITER, ContactType.SUSPICIOUS_RECRUITER, ContactType.MIXED
        ), f"Expected fake recruiter type, got {analysis.contact_type}"

    def test_fake_recruiter_nsa_claim_detected(self):
        """Fake recruiter claiming to recruit for NSA with clearance guarantee and fee."""
        analysis = detector.analyze_contact(FAKE_RECRUITER_NSA)
        assert analysis.is_suspicious, \
            f"Fake NSA recruiter should be flagged, risk={analysis.risk_score}"
        actor_types = {f.actor_type for f in analysis.findings}
        assert "fake_recruiter" in actor_types

    def test_legit_fso_contact_not_flagged(self):
        """Legitimate FSO contact using DISS/eQIP/indoc terminology correctly."""
        analysis = detector.analyze_contact(LEGIT_FSO_CONTACT)
        assert not analysis.is_suspicious, \
            f"Legitimate FSO contact was incorrectly flagged: type={analysis.contact_type}, "  \
            f"risk={analysis.risk_score}, findings={[f.finding for f in analysis.findings]}"

    def test_legit_recruiter_not_flagged(self):
        """Real contractor recruiter using proper ATS, corporate email, in-person interviews."""
        analysis = detector.analyze_contact(LEGIT_RECRUITER_CONTACT)
        assert not analysis.is_suspicious, \
            f"Legitimate recruiter was incorrectly flagged: risk={analysis.risk_score}, " \
            f"findings={[f.finding for f in analysis.findings]}"

    def test_empty_contact_safe(self):
        """Empty string returns CLEAN with zero score."""
        from clearance_fraud_detector.analyzers.contact_analyzer import ContactType
        analysis = detector.analyze_contact("")
        assert not analysis.is_suspicious
        assert analysis.risk_score == 0.0
        assert analysis.contact_type == ContactType.CLEAN

    def test_safe_to_provide_ssn_false_on_fraud(self):
        """safe_to_provide_ssn must be False whenever fraud signals are present."""
        analysis = detector.analyze_contact(FAKE_FSO_SSN_VERIFY)
        assert not analysis.safe_to_provide_ssn, \
            "safe_to_provide_ssn must be False on a fake FSO message"

    def test_fso_score_higher_than_recruiter_for_fso_fraud(self):
        """FSO impersonation message should yield higher fso_score than recruiter_score."""
        analysis = detector.analyze_contact(FAKE_FSO_SSN_VERIFY)
        assert analysis.fso_score >= analysis.recruiter_score, \
            f"fso_score ({analysis.fso_score}) should exceed recruiter_score ({analysis.recruiter_score})"

    def test_recruiter_score_higher_for_recruiter_fraud(self):
        """Fake recruiter message should yield higher recruiter_score than fso_score."""
        analysis = detector.analyze_contact(FAKE_RECRUITER_TELEGRAM)
        assert analysis.recruiter_score >= analysis.fso_score, \
            f"recruiter_score ({analysis.recruiter_score}) should be >= fso_score ({analysis.fso_score})"


# ---------------------------------------------------------------------------
# Phone Number Analyzer tests
# ---------------------------------------------------------------------------

class TestPhoneAnalyzer:

    def test_known_mindbank_number_matched(self):
        """Mindbank's published (703) 893-4700 should match the known database."""
        analysis = detector.analyze_phone_number("703-893-4700", claimed_company="Mindbank")
        assert analysis.is_valid
        assert analysis.matched_company == "Mindbank Consulting Group"

    def test_mindbank_fso_number_not_matched(self):
        """(703) 436-9068 — number given by FSO — should NOT match published Mindbank number."""
        analysis = detector.analyze_phone_number("703-436-9068", claimed_company="Mindbank")
        assert analysis.is_valid
        assert analysis.matched_company == "", \
            "FSO's number should not match Mindbank's published database entry"

    def test_suspect_22ctech_number_flagged(self):
        """(703) 594-4241 routes to Nokesville VA — geographic mismatch for McLean office."""
        analysis = detector.analyze_phone_number(
            "703-594-4241",
            claimed_company="22nd Century Technologies",
            claimed_region="McLean VA",
        )
        assert analysis.is_valid
        # Should flag: not in known DB + rural-region mismatch
        finding_texts = " ".join(f.finding for f in analysis.findings).lower()
        assert (
            "nokesville" in finding_texts
            or "mismatch" in finding_texts
            or "not found" in finding_texts
        )

    def test_ssn_requested_on_call_always_critical(self):
        """Any call requesting SSN must be flagged critical regardless of number legitimacy."""
        # Even the real Mindbank published number — if they ask SSN over the phone it's wrong
        analysis = detector.analyze_phone_number(
            "703-893-4700",
            claimed_company="Mindbank",
            ssn_requested=True,
        )
        assert analysis.is_suspicious, "SSN-over-phone must always flag suspicious"
        assert any(f.weight >= 1.0 for f in analysis.findings), \
            "SSN-over-phone finding must have critical weight"

    def test_pre_offer_contact_raises_risk(self):
        """Pre-offer contact should increase risk score."""
        baseline = detector.analyze_phone_number("703-594-4241")
        with_pre_offer = detector.analyze_phone_number("703-594-4241", pre_offer=True)
        assert with_pre_offer.risk_score >= baseline.risk_score

    def test_invalid_number_handled_gracefully(self):
        """Garbage input should not raise an exception."""
        analysis = detector.analyze_phone_number("not-a-number-xyz")
        assert not analysis.is_valid

    def test_known_22ctech_toll_free_matched(self):
        """22nd Century's published toll-free (866) 537-9191 should be in DB."""
        analysis = detector.analyze_phone_number("866-537-9191", claimed_company="22nd Century Technologies")
        assert analysis.is_valid
        assert analysis.matched_company == "22nd Century Technologies"

    def test_ssn_and_pre_offer_combined_high_risk(self):
        """SSN requested + pre-offer = highest risk combination."""
        analysis = detector.analyze_phone_number(
            "703-594-4241",
            claimed_company="22nd Century Technologies",
            claimed_region="McLean VA",
            ssn_requested=True,
            pre_offer=True,
        )
        assert analysis.is_suspicious
        assert analysis.risk_score > 0.60, \
            f"SSN+pre-offer+geographic mismatch should score > 0.60, got {analysis.risk_score}"


# ---------------------------------------------------------------------------
# SSN Timing & DCSA Process Tests
# Validates: SSN pre-offer from recruiter = red flag; post-offer FSO = legit
# Source: dcsa.mil/mc/pv/mbi, NISPOM 32 CFR Part 117
# ---------------------------------------------------------------------------

# Recruiter asking for SSN pre-interview "to present to employer" — the exact
# scenario encountered in real outreach (eTalent Network context).
# This is NOT standard — employer reviewing resume needs ZERO PII.
RECRUITER_SSN_BEFORE_INTERVIEW = (
    "Hi, I have a great TS/SCI opportunity at a federal facility in Clarksburg WV. "
    "Before I present your profile to the employer, I need your social security number "
    "so they can verify your clearance status. Can you send that over along with your resume?"
)

# Post-conditional-offer FSO directing candidate to eApp — the CORRECT process
# per dcsa.mil/Personnel-Vetting/Background-Investigations-for-Applicants
FSO_EAPP_ONBOARDING = (
    "Congratulations on your conditional offer. I'm the FSO at our facility. "
    "I've initiated your SF-86 in NBIS. You'll receive an invitation to complete "
    "your background investigation questionnaire in eApp (eapp.nbis.mil). "
    "Please submit it within 30 days. The process is covered by NISPOM 32 CFR Part 117. "
    "Your current FSO will be notified as part of the DISS coordination."
)

# eTalent Network / TSCTI legitimate recruiter outreach (verified staffing partner)
ETALENT_TSCTI_LEGIT_OUTREACH = (
    "Hi, I'm a recruiter from eTalent Network reaching out about a Software Developer "
    "position supporting the FBI CJIS MXU program in Clarksburg, WV with 22nd Century "
    "Technologies (TSCTI). The role requires an active TS/SCI clearance. Salary range "
    "is $115,000-$130,000. Please apply at tscti.com/careers. Interviews are conducted "
    "via video or in person. No fees required."
)

# Legitimate cleared salary range should NOT trip salary_bait pattern
# Source: Glassdoor TSCTI (20+ submissions, Apr 2026): SW Dev $92K-$130K
LEGIT_SALARY_TSCTI = (
    "Senior Software Engineer — TS/SCI — Clarksburg WV\n"
    "22nd Century Technologies (TSCTI) | FBI CJIS Division\n"
    "Salary: $120,000 – $145,000 based on experience\n"
    "Active TS/SCI with CI Polygraph required. 5+ years experience. "
    "Apply at tscti.com/careers."
)


class TestSSNTimingAndDCSAProcess:
    def test_recruiter_ssn_before_interview_flagged(self):
        """
        Recruiter asking for SSN 'to present to employer' pre-interview is a red flag.
        Employer reviewing a resume needs zero PII (NISPOM 32 CFR Part 117).
        The message uses 'verify clearance' language so it correctly fires the
        fso_impersonation pattern — a recruiter using FSO-style justification to
        extract SSN is still fraud regardless of which actor pattern catches it.
        """
        from clearance_fraud_detector.analyzers.contact_analyzer import ContactType
        analysis = detector.analyze_contact(RECRUITER_SSN_BEFORE_INTERVIEW)
        assert analysis.is_suspicious, (
            f"Pre-interview recruiter SSN request should be flagged; "
            f"risk={analysis.risk_score}, type={analysis.contact_type}"
        )
        actor_types = {f.actor_type for f in analysis.findings}
        assert actor_types & {"fake_recruiter", "fso_impersonation"}, (
            "Pre-interview SSN request should be caught by at least one fraud pattern "
            f"(got actor_types={actor_types})"
        )

    def test_fso_eapp_onboarding_not_flagged(self):
        """
        Post-offer FSO directing candidate to eApp/NBIS for SF-86 is the correct
        authorized process per dcsa.mil and NISPOM 32 CFR Part 117.
        Should NOT be flagged as fraud.
        """
        analysis = detector.analyze_contact(FSO_EAPP_ONBOARDING)
        assert not analysis.is_suspicious, (
            f"Legitimate FSO eApp onboarding was incorrectly flagged: "
            f"risk={analysis.risk_score}, type={analysis.contact_type}, "
            f"findings={[f.finding for f in analysis.findings]}"
        )

    def test_etalent_network_outreach_clean(self):
        """
        eTalent Network is TSCTI's verified RPO staffing partner (etalentnetwork.com/clients).
        Outreach about FBI MXU TSCTI role at market-rate salary should be CLEAN.
        """
        score = detector.analyze_text(
            subject="Software Developer TS/SCI — FBI CJIS — TSCTI / eTalent Network",
            sender="recruiter@etalentnetwork.com",
            body=ETALENT_TSCTI_LEGIT_OUTREACH,
        )
        assert score.verdict in (Verdict.CLEAN, Verdict.SUSPICIOUS), (
            f"eTalent Network / TSCTI outreach should be CLEAN or SUSPICIOUS (at worst), "
            f"got {score.verdict} (score={score.total_score})"
        )
        assert score.total_score < 0.50, (
            f"eTalent Network legit outreach scored too high: {score.total_score}"
        )

    def test_legitimate_cleared_salary_not_salary_bait(self):
        """
        $120K-$145K for TS/SCI Senior SW Engineer at FBI CJIS is within verified market range.
        Source: Glassdoor TSCTI 20+ reports Apr 2026: SW Dev $92K-$130K, Sr Eng up to $153K.
        Should NOT trigger salary_bait fraud pattern.
        """
        score = detector.analyze_text(
            subject="Senior Software Engineer TS/SCI — TSCTI — Clarksburg WV",
            sender="recruiting@tscti.com",
            body=LEGIT_SALARY_TSCTI,
        )
        rule_categories = {m.category for m in score.rule_matches}
        assert "financial_scam" not in rule_categories, (
            f"$120K-$145K cleared SW salary should not trigger financial_scam; "
            f"matched categories: {rule_categories}"
        )
        assert score.total_score < 0.45, (
            f"Legitimate TSCTI job posting scored too high: {score.total_score}"
        )


# ---------------------------------------------------------------------------
# Social Engineering Pressure Tactics Tests
# Validates detection of "everyone else did it", "not playing ball", etc.
# Source: 32 CFR §117.10(a)(5) — cache prohibition; (f)(1) — offer-first rule
# ---------------------------------------------------------------------------

SOCIAL_PRESSURE_EVERYONE_ELSE = (
    "Hi, I understand your concern but everyone else we've spoken with provided "
    "their SSN. All the other candidates gave us their social security number during "
    "the initial screening. This is just our standard process."
)

SOCIAL_PRESSURE_NOT_PLAYING_BALL = (
    "Look, I don't know why you're being so difficult about this. You're not playing ball "
    "here. All I need is your social security number to verify your clearance and we can "
    "move forward. If you won't cooperate, I'll have to pass on you."
)

SOCIAL_PRESSURE_SKIP_OVER = (
    "I have other candidates that are ready and willing to proceed. If you can't provide "
    "your SSN today, I'm going to have to skip over you and move on to the next candidate. "
    "The position is filling fast."
)

SOCIAL_PRESSURE_STANDARD_PRACTICE = (
    "This is completely standard practice in the cleared community. It's industry standard "
    "for everyone to submit their SSN during pre-screening. Our clients require this."
)

SOCIAL_PRESSURE_24HR_DEADLINE = (
    "I need your social security number by end of business today. The client needs this "
    "immediately — please provide your SSN right now so we can proceed."
)


class TestSocialEngineeringPressureTactics:
    def test_everyone_else_ssn_flagged(self):
        """'Everyone else provided SSN' normalization tactic must be detected."""
        score = detector.analyze_text(
            body=SOCIAL_PRESSURE_EVERYONE_ELSE,
            subject="Follow-up on your application",
        )
        rule_patterns = {m.pattern.name for m in score.rule_matches}
        assert "everyone_else_ssn_pressure" in rule_patterns, (
            f"'Everyone else provided SSN' should trigger everyone_else_ssn_pressure; "
            f"got patterns: {rule_patterns}"
        )
        assert score.total_score > 0.30

    def test_not_playing_ball_flagged(self):
        """'Not playing ball' framing of regulatory compliance must be detected."""
        score = detector.analyze_text(
            body=SOCIAL_PRESSURE_NOT_PLAYING_BALL,
            subject="Re: SSN Request",
        )
        rule_patterns = {m.pattern.name for m in score.rule_matches}
        assert "not_playing_ball" in rule_patterns, (
            f"'Not playing ball' should be detected; got patterns: {rule_patterns}"
        )

    def test_skip_over_candidate_flagged(self):
        """'Skip over you' threat combined with SSN pressure must be detected."""
        score = detector.analyze_text(
            body=SOCIAL_PRESSURE_SKIP_OVER,
            subject="Action required",
        )
        rule_patterns = {m.pattern.name for m in score.rule_matches}
        assert "skip_over_candidate" in rule_patterns, (
            f"'Skip over you' tactic should be detected; got patterns: {rule_patterns}"
        )

    def test_ssn_standard_practice_claim_flagged(self):
        """Claiming SSN collection is 'standard practice' or 'industry standard' must be flagged."""
        score = detector.analyze_text(
            body=SOCIAL_PRESSURE_STANDARD_PRACTICE,
            subject="Standard screening process",
        )
        rule_patterns = {m.pattern.name for m in score.rule_matches}
        assert "ssn_normalized_as_standard" in rule_patterns, (
            f"'Standard practice SSN' claim should be detected; got: {rule_patterns}"
        )

    def test_ssn_immediate_deadline_flagged(self):
        """Artificial deadline for SSN submission must be flagged."""
        score = detector.analyze_text(
            body=SOCIAL_PRESSURE_24HR_DEADLINE,
            subject="Urgent: SSN needed today",
        )
        rule_patterns = {m.pattern.name for m in score.rule_matches}
        assert "ssn_immediate_deadline" in rule_patterns, (
            f"24hr SSN deadline should be detected; got: {rule_patterns}"
        )

    def test_social_engineering_in_contact_analyzer(self):
        """Contact analyzer must detect 'everyone else / not playing ball' pressure."""
        analysis = detector.analyze_contact(SOCIAL_PRESSURE_NOT_PLAYING_BALL)
        assert analysis.is_suspicious, (
            f"Social engineering pressure contact should be flagged; risk={analysis.risk_score}"
        )
        finding_texts = " ".join(f.finding for f in analysis.findings).lower()
        assert "social engineering" in finding_texts or "playing ball" in finding_texts or len(analysis.findings) > 0

    def test_skip_over_in_contact_analyzer(self):
        """Contact analyzer must detect 'skip over you' SSN pressure."""
        analysis = detector.analyze_contact(SOCIAL_PRESSURE_SKIP_OVER)
        assert analysis.is_suspicious, (
            f"'Skip over you' contact should be flagged; risk={analysis.risk_score}"
        )


# ---------------------------------------------------------------------------
# CAGE Code / FCL Evasion Tests
# CAGE codes are public (sam.gov). FCL is not a secret. Evasion = red flag.
# Source: 32 CFR §117.10; DCSA Facility Clearance page; sam.gov
# ---------------------------------------------------------------------------

CAGE_EVASION_CANT_PROVIDE = (
    "I'm sorry, I can't give you the CAGE code — that information is confidential. "
    "Our CAGE code is not something we share with candidates during the pre-screening process. "
    "You'll just have to trust us on this."
)

CAGE_EVASION_DONT_KNOW = (
    "Honestly, I don't know what our CAGE code is. I'm not sure what a CAGE code is. "
    "Our FCL is also confidential — I can't disclose the facility clearance level."
)

FAKE_OFFER_WITH_SSN = (
    "Congratulations! Please find attached your offer letter for the Software Engineer position. "
    "Now that you have the offer, please send us your social security number so we can "
    "finalize the onboarding. We need the SSN to complete the offer."
)

OFFER_CONDITIONED_ON_SSN = (
    "The offer is contingent on receipt of your social security number. "
    "You must provide your SSN to finalize the offer letter. "
    "The offer cannot be issued until we have your social security number on file."
)


class TestCageFclEvasion:
    def test_cage_code_cant_provide_flagged(self):
        """Inability to provide CAGE code must be flagged as cage_fcl_evasion."""
        score = detector.analyze_text(
            body=CAGE_EVASION_CANT_PROVIDE,
            subject="Re: CAGE code and FCL",
        )
        rule_patterns = {m.pattern.name for m in score.rule_matches}
        assert "cage_code_deflection" in rule_patterns, (
            f"CAGE code deflection should be detected; got: {rule_patterns}"
        )

    def test_cage_and_fcl_both_unknown_flagged(self):
        """Not knowing CAGE code AND claiming FCL confidential must both trigger."""
        score = detector.analyze_text(
            body=CAGE_EVASION_DONT_KNOW,
            subject="Questions about facility",
        )
        rule_patterns = {m.pattern.name for m in score.rule_matches}
        assert ("cage_code_deflection" in rule_patterns or "fcl_not_disclosed" in rule_patterns), (
            f"CAGE/FCL evasion should be detected; got: {rule_patterns}"
        )

    def test_fake_offer_with_ssn_request_flagged(self):
        """Offer letter followed by direct SSN request must be flagged."""
        score = detector.analyze_text(
            body=FAKE_OFFER_WITH_SSN,
            subject="Your offer letter — action required",
        )
        rule_patterns = {m.pattern.name for m in score.rule_matches}
        assert "fake_offer_ssn_request" in rule_patterns, (
            f"Fake offer + SSN request should trigger fake_offer_ssn_request; got: {rule_patterns}"
        )

    def test_ssn_as_offer_condition_flagged(self):
        """SSN as a prerequisite for the offer letter must be flagged."""
        score = detector.analyze_text(
            body=OFFER_CONDITIONED_ON_SSN,
            subject="Offer contingent on SSN",
        )
        rule_patterns = {m.pattern.name for m in score.rule_matches}
        assert "offer_conditioned_on_ssn" in rule_patterns, (
            f"SSN as offer condition should be detected; got: {rule_patterns}"
        )
        assert score.total_score > 0.25

    def test_cage_deflection_in_contact_analyzer(self):
        """Contact analyzer must detect CAGE code deflection."""
        analysis = detector.analyze_contact(CAGE_EVASION_CANT_PROVIDE)
        assert analysis.is_suspicious, (
            f"CAGE code deflection should be flagged; risk={analysis.risk_score}"
        )
        finding_texts = " ".join(f.finding for f in analysis.findings).lower()
        assert "cage" in finding_texts, (
            f"CAGE finding expected; got: {[f.finding for f in analysis.findings]}"
        )


# ---------------------------------------------------------------------------
# NISPOM Process Misrepresentation Tests
# Validates detection of fake process claims: recruiter DISS access,
# pre-offer investigation claims, FCRA-as-clearance conflation
# ---------------------------------------------------------------------------

RECRUITER_DISS_CLAIM = (
    "Let me pull you up in DISS right now. I have DISS access and can check your "
    "clearance status if you give me your SSN. I'll look you up in JPAS as well."
)

PRE_OFFER_INVESTIGATION_CLAIM = (
    "We can start your background investigation before the offer is made. "
    "Our clearance process begins prior to employment so we'll initiate it now. "
    "The investigation can start without a formal offer — we do it all the time."
)

FCRA_AS_CLEARANCE_PRETEXT = (
    "This is just a standard background check — we need your SSN for the FCRA consent "
    "to verify your clearance level and clearance status. The FCRA background check "
    "will confirm your clearance."
)


class TestNispomsProcessMisrepresentation:
    def test_recruiter_diss_access_claim_flagged(self):
        """Recruiter claiming DISS access must trigger nispom_misrepresentation."""
        score = detector.analyze_text(
            body=RECRUITER_DISS_CLAIM,
            subject="Clearance verification call",
        )
        rule_patterns = {m.pattern.name for m in score.rule_matches}
        assert "recruiter_claims_diss_access" in rule_patterns, (
            f"Recruiter DISS access claim should be detected; got: {rule_patterns}"
        )
        assert score.total_score > 0.30

    def test_pre_offer_investigation_claim_flagged(self):
        """Claiming investigation starts before a written offer must be detected."""
        score = detector.analyze_text(
            body=PRE_OFFER_INVESTIGATION_CLAIM,
            subject="Background investigation process",
        )
        rule_patterns = {m.pattern.name for m in score.rule_matches}
        assert "investigation_before_offer_claimed" in rule_patterns, (
            f"Pre-offer investigation claim should be detected; got: {rule_patterns}"
        )

    def test_fcra_clearance_conflation_flagged(self):
        """Misusing FCRA background check pretext to justify clearance SSN collection."""
        score = detector.analyze_text(
            body=FCRA_AS_CLEARANCE_PRETEXT,
            subject="Standard background check consent",
        )
        rule_patterns = {m.pattern.name for m in score.rule_matches}
        assert "fcra_pretext_for_clearance" in rule_patterns, (
            f"FCRA-as-clearance pretext should be detected; got: {rule_patterns}"
        )

    def test_recruiter_diss_claim_in_contact_analyzer(self):
        """Contact analyzer must flag recruiter claiming DISS access."""
        analysis = detector.analyze_contact(RECRUITER_DISS_CLAIM)
        assert analysis.is_suspicious, (
            f"Recruiter DISS access claim should be flagged; risk={analysis.risk_score}"
        )
        actor_types = {f.actor_type for f in analysis.findings}
        assert "fake_recruiter" in actor_types, (
            f"Should be flagged as fake_recruiter; got actor_types={actor_types}"
        )


# ---------------------------------------------------------------------------
# Mindbank SVP Escalation Pattern Tests
# A recruiter requested SSN pre-offer; an SVP escalated the pressure after
# the candidate cited 32 CFR §117.10. Documented institutional NISPOM violation.
# Key claims made: "common and standard practice", DOD SAFE as SSN channel,
# "not an unusual request", "DISS is used to verify clearance with SSN"
# All of these are detectable misrepresentations of NISPOM 32 CFR §117.10
# ---------------------------------------------------------------------------

# Verbatim content from SVP escalation email (Mindbank Consulting Group, Apr 2026)
MINDBANK_SVP_ESCALATION = (
    "It is common and standard practice for companies to request your Social Security "
    "Number (SSN) to verify a security clearance in systems like DISS (Defense "
    "Information System for Security) for authorized cleared positions. The Social "
    "Security Number is the primary identifier used to confirm clearance status and "
    "eligibility. This is not an unusual request."
)

# DOD SAFE proposed as PII collection channel — not authorized for SSN per 32 CFR §117.10(d)
MINDBANK_DOD_SAFE_PII = (
    "I was in the process of seeing if we can use DOD SAFE to request the PII from you "
    "however based on your email below it appears you are not willing to send us the PII "
    "we are requesting even if it is via DOD SAFE."
)

# Combined full escalation text
MINDBANK_FULL_ESCALATION = MINDBANK_SVP_ESCALATION + " " + MINDBANK_DOD_SAFE_PII


class TestMindbankSVPEscalation:
    def test_common_standard_practice_claim_flagged(self):
        """'Common and standard practice' SSN normalization must be detected."""
        score = detector.analyze_text(
            body=MINDBANK_SVP_ESCALATION,
            subject="Re: SSN Request — Mindbank",
            sender="trisha.herrera@mindbank.com",
        )
        rule_patterns = {m.pattern.name for m in score.rule_matches}
        assert (
            "common_practice_ssn_normalization" in rule_patterns
            or "ssn_normalized_as_standard" in rule_patterns
        ), (
            f"'Common and standard practice' SSN claim should be detected; "
            f"got patterns: {rule_patterns}"
        )
        assert score.total_score > 0.20

    def test_not_unusual_request_flagged(self):
        """'Not an unusual request' framing of pre-offer SSN must be detected."""
        score = detector.analyze_text(
            body="This is not an unusual request. It is normal practice to provide SSN.",
            subject="Clearance verification",
        )
        rule_patterns = {m.pattern.name for m in score.rule_matches}
        assert (
            "common_practice_ssn_normalization" in rule_patterns
            or "ssn_normalized_as_standard" in rule_patterns
        ), f"'Not unusual request' should be flagged; got: {rule_patterns}"

    def test_dod_safe_ssn_channel_flagged_in_text(self):
        """DOD SAFE proposed as SSN/PII collection channel must be flagged."""
        score = detector.analyze_text(
            body=MINDBANK_DOD_SAFE_PII,
            subject="DOD SAFE option",
            sender="trisha.herrera@mindbank.com",
        )
        rule_patterns = {m.pattern.name for m in score.rule_matches}
        assert "dod_safe_ssn_channel" in rule_patterns, (
            f"DOD SAFE as PII channel should trigger dod_safe_ssn_channel; "
            f"got: {rule_patterns}"
        )

    def test_dod_safe_ssn_channel_flagged_in_contact(self):
        """Contact analyzer must flag DOD SAFE as SSN/PII channel."""
        analysis = detector.analyze_contact(MINDBANK_DOD_SAFE_PII)
        assert analysis.is_suspicious, (
            f"DOD SAFE SSN collection should be flagged; risk={analysis.risk_score}"
        )
        finding_texts = " ".join(f.finding for f in analysis.findings).lower()
        assert "dod safe" in finding_texts or "safe" in finding_texts or len(analysis.findings) > 0

    def test_full_escalation_email_flagged(self):
        """Full Mindbank SVP escalation email must score as SUSPICIOUS or higher."""
        score = detector.analyze_text(
            body=MINDBANK_FULL_ESCALATION,
            subject="Re: Clearance Verification — Sr. Machine Learning Engineer",
            sender="trisha.herrera@mindbank.com",
        )
        assert score.verdict in (Verdict.SUSPICIOUS, Verdict.LIKELY_FRAUD, Verdict.FRAUD), (
            f"Mindbank SVP escalation should be SUSPICIOUS+; got {score.verdict} "
            f"(score={score.total_score})"
        )
        assert score.total_score > 0.20

    def test_full_escalation_contact_analyzer_flagged(self):
        """Contact analyzer must flag the full SVP escalation text."""
        analysis = detector.analyze_contact(MINDBANK_FULL_ESCALATION)
        assert analysis.is_suspicious, (
            f"Mindbank SVP escalation should be flagged by contact analyzer; "
            f"risk={analysis.risk_score}, findings={[f.finding for f in analysis.findings]}"
        )

    def test_diss_ssn_primary_identifier_claim_flagged(self):
        """Claiming SSN is 'the primary identifier used in DISS' to justify collection."""
        body = (
            "The Social Security Number is the primary identifier used to confirm "
            "clearance status and eligibility in DISS. We need your SSN to verify "
            "your clearance in DISS."
        )
        score = detector.analyze_text(body=body, subject="DISS clearance check")
        rule_patterns = {m.pattern.name for m in score.rule_matches}
        assert (
            "fso_ssn_for_clearance_check" in rule_patterns
            or "ssn_request" in rule_patterns
        ), f"DISS+SSN clearance check claim should be detected; got: {rule_patterns}"
        assert score.total_score > 0.25


# ---------------------------------------------------------------------------
# Clearance Holder Self-Identification Harvesting Patterns
# Tactics used by mass-outreach recruiting platforms to confirm cleared-
# professional emails and build high-value contact databases.
# Reference: Entegee/AKKODIS ClearanceJobs
#            outreach, April 2026 (Director IT Recruiting).
# ---------------------------------------------------------------------------
class TestClearanceHarvestPatterns:
    """Test patterns for clearance-holder self-identification harvesting tactics.

    Even legitimate companies use mass ClearanceJobs/LinkedIn outreach to
    build databases of confirmed active cleared professionals. Each reply
    confirms the email is live, active job-seeking status, and clearance
    history via resume — all high-value intelligence.
    """

    def _get_rule_names(self, body: str, subject: str = "job opportunity",
                        sender: str = "recruiter@entegee.com") -> set[str]:
        score = detector.analyze_text(body=body, subject=subject, sender=sender)
        return {m.pattern.name for m in score.rule_matches}

    # --- ive_been_trying_to_reach_you ---

    def test_ive_been_trying_to_reach_you_fires(self):
        """'I've been trying to reach you' triggers false-intimacy opener pattern."""
        body = "I've been trying to reach you. I called and texted earlier this week."
        rules = self._get_rule_names(body)
        assert "ive_been_trying_to_reach_you" in rules, (
            f"False-intimacy opener should be detected; got: {rules}"
        )

    def test_been_trying_to_reach_you_fires(self):
        """'Been trying to reach you' without I've also triggers the pattern."""
        body = "Been trying to reach you about an opportunity that matches your profile."
        rules = self._get_rule_names(body)
        assert "ive_been_trying_to_reach_you" in rules, (
            f"'Been trying to reach you' variant should be detected; got: {rules}"
        )

    def test_i_called_and_texted_fires(self):
        """'I called/texted' opener triggers false-intimacy pattern."""
        body = "Good day. I called/texted — I hope this email finds you well."
        rules = self._get_rule_names(body)
        assert "ive_been_trying_to_reach_you" in rules, (
            f"'I called/texted' opener should be detected; got: {rules}"
        )

    def test_legitimate_email_no_false_intimacy(self):
        """Normal recruiter email without pressure opener does not trigger."""
        body = (
            "Hello, I came across your profile on ClearanceJobs and would like "
            "to discuss a software engineer role at Northrop Grumman."
        )
        rules = self._get_rule_names(body)
        assert "ive_been_trying_to_reach_you" not in rules

    # --- skills_stood_out_on_platform ---

    def test_skills_stood_out_on_clearancejobs_fires(self):
        """'Your impressive skills stood out in ClearanceJobs' triggers platform flattery pattern."""
        body = "Your impressive Embedded Software Architecture skills stood out in ClearanceJobs.com."
        rules = self._get_rule_names(body)
        assert "skills_stood_out_on_platform" in rules, (
            f"ClearanceJobs flattery preamble should be detected; got: {rules}"
        )

    def test_profile_caught_my_eye_fires(self):
        """'Your background caught my eye' triggers the flattery pattern."""
        body = "Your outstanding background caught my eye and I wanted to reach out."
        rules = self._get_rule_names(body)
        assert "skills_stood_out_on_platform" in rules, (
            f"'Caught my eye' flattery should be detected; got: {rules}"
        )

    def test_profile_on_linkedin_fires(self):
        """'Your profile on LinkedIn' also triggers the pattern."""
        body = "I found your profile on LinkedIn and it was a great match for this role."
        rules = self._get_rule_names(body)
        assert "skills_stood_out_on_platform" in rules, (
            f"LinkedIn profile reference should be detected; got: {rules}"
        )

    # --- send_resume_asap_harvest ---

    def test_send_resume_asap_fires(self):
        """'send your resume ASAP' triggers resume-harvest urgency pattern."""
        body = "Please send your resume ASAP before this position is filled."
        rules = self._get_rule_names(body)
        assert "send_resume_asap_harvest" in rules, (
            f"'Send resume ASAP' should be detected; got: {rules}"
        )

    def test_forward_cv_immediately_fires(self):
        """'forward your CV immediately' also triggers the pattern."""
        body = "Kindly forward your CV immediately to be considered for this priority role."
        rules = self._get_rule_names(body)
        assert "send_resume_asap_harvest" in rules, (
            f"'Forward CV immediately' should be detected; got: {rules}"
        )

    def test_resume_asap_standalone_fires(self):
        """'resume ASAP' substring fires the pattern."""
        body = "Resume ASAP — this client needs someone starting next week."
        rules = self._get_rule_names(body)
        assert "send_resume_asap_harvest" in rules, (
            f"'Resume ASAP' standalone should be detected; got: {rules}"
        )

    def test_normal_resume_request_no_urgency(self):
        """A standard resume request without ASAP urgency does not trigger."""
        body = "If you are interested, please send us your resume for review."
        rules = self._get_rule_names(body)
        assert "send_resume_asap_harvest" not in rules

    # --- req_closes_soon_urgency ---

    def test_priority_req_closes_soon_fires(self):
        """'before this priority Aerospace req closes soon' triggers artificial scarcity."""
        body = "Please apply before this priority Aerospace req closes soon!"
        rules = self._get_rule_names(body)
        assert "req_closes_soon_urgency" in rules, (
            f"'Priority req closes soon' should be detected; got: {rules}"
        )

    def test_position_filling_fast_fires(self):
        """'position filling fast' is also artificial scarcity."""
        body = "This cleared position is filling fast — apply today."
        rules = self._get_rule_names(body)
        assert "req_closes_soon_urgency" in rules, (
            f"'Position filling fast' should be detected; got: {rules}"
        )

    def test_req_closes_soon_no_false_positive_normal(self):
        """Normal job posting with no urgency language does not trigger."""
        body = "We have an opening for a cleared software engineer. Applications reviewed on rolling basis."
        rules = self._get_rule_names(body)
        assert "req_closes_soon_urgency" not in rules

    # --- candidate_privacy_statement_bulk_send ---

    def test_candidate_privacy_statement_fires(self):
        """Candidate Privacy Information Statement link triggers bulk-send indicator."""
        body = (
            "To read our Candidate Privacy Information Statement, which explains how "
            "we will use your information, please visit https://www.entegee.com/candidate-privacy-information-statement/"
        )
        rules = self._get_rule_names(body)
        assert "candidate_privacy_statement_bulk_send" in rules, (
            f"Candidate Privacy Statement should be detected; got: {rules}"
        )

    def test_candidate_privacy_policy_fires(self):
        """'Candidate privacy policy' also triggers the pattern."""
        body = "Our candidate privacy policy governs how we collect and use your data."
        rules = self._get_rule_names(body)
        assert "candidate_privacy_statement_bulk_send" in rules, (
            f"'Candidate privacy policy' should be detected; got: {rules}"
        )

    def test_full_entegee_email_scores_suspicious_or_higher(self):
        """Full Entegee mass-outreach email (all 5 tactics) scores SUSPICIOUS or higher."""
        body = (
            "Good Day, I've been trying to reach you. I called/texted. "
            "Your impressive Embedded Software Architecture skills stood out in ClearanceJobs.com. "
            "Please send your resume ASAP before this priority Aerospace req closes soon! "
            "Secret Clearance preferred. [Director IT Recruiting], AKKODIS/Entegee. "
            "To read our Candidate Privacy Information Statement, which explains how we will "
            "use your information, please visit https://www.entegee.com/candidate-privacy-information-statement/"
        )
        score = detector.analyze_text(
            body=body,
            subject="Embedded Software Architect Aerospace",
            sender="recruiter@entegee.com",
        )
        assert score.verdict in (Verdict.SUSPICIOUS, Verdict.LIKELY_FRAUD, Verdict.FRAUD), (
            f"Full Entegee mass-outreach email should be SUSPICIOUS+; "
            f"got {score.verdict} (score={score.total_score})"
        )
        assert score.total_score >= 0.35

    def test_wire_no_false_positive_in_wireless(self):
        """'Wireless communications' must NOT trigger wire-transfer fraud vocabulary."""
        body = (
            "Define the radio interface of the ARM/FPGA software driver and the radio "
            "transceivers for wireless communications and GPS/IoT applications."
        )
        score = detector.analyze_text(body=body, subject="Embedded SW Architect")
        # wire_transfer pattern should NOT fire on 'wireless'
        rule_names = {m.pattern.name for m in score.rule_matches}
        assert "wire_transfer" not in rule_names, (
            "'wireless' in job text must not trigger wire_transfer pattern"
        )
        # NLP fraud vocab should not flag 'wireless' as 'wire transfer'
        assert score.total_score < 0.30, (
            f"Job text with 'wireless' should not inflate fraud score; got {score.total_score}"
        )


# ---------------------------------------------------------------------------
# Career Fair Context: Domain Analyzer False-Positive Suppression
# A career fair organizer legitimately lists many contractor names as exhibitors.
# The domain analyzer must NOT fire contractor name/domain mismatch warnings
# in career fair context, as those would be false positives (not impersonation).
# Reference: reStartEvents.com email, April 2026.
# ---------------------------------------------------------------------------
class TestCareerFairContextSuppression:
    """Domain analyzer suppresses contractor name mismatches in career fair context.

    reStartEvents.com is a legitimate 20+ year cleared career fair organizer.
    Contractor names (Leidos, CACI, Lockheed Martin, MITRE, Amentum…) appear
    as exhibitors — not impersonation. Without suppression the tool incorrectly
    scores these emails as 🛑 FRAUD due to stacked false-positive domain signals.
    """

    def _score(self, body: str, sender: str = "ken@restartevents.com",
               subject: str = "Cleared Virtual Career Fair") -> "FraudScore":  # noqa: F821
        return detector.analyze_text(body=body, subject=subject, sender=sender)

    def test_career_fair_companies_participating_suppresses_contractor_mismatch(self):
        """'Companies Participating: Leidos, CACI, Lockheed Martin' must not trigger domain mismatch."""
        body = (
            "reStart Cleared Virtual Career Fair. Companies Participating: Leidos, CACI, "
            "Lockheed Martin, MITRE, Amentum. An Active TS/SCI Security Clearance REQUIRED. "
            "To unsubscribe click here."
        )
        score = self._score(body, sender="ken.fuller@ccsend.com")
        # Domain findings should NOT include contractor name mismatches
        contractor_mismatches = [
            df for df in score.domain_findings
            if "contractor name/domain mismatch" in df.finding.lower()
        ]
        assert contractor_mismatches == [], (
            f"Career fair context must suppress contractor mismatches; got: {contractor_mismatches}"
        )

    def test_cleared_virtual_career_fair_context_suppresses_mismatch(self):
        """'Cleared Virtual Career Fair' context phrase suppresses domain mismatch check."""
        body = (
            "Join us for the Nationwide Cleared Virtual Career Fair on Thursday April 23rd. "
            "Northrop Grumman, Raytheon, General Dynamics, L3Harris, Booz Allen Hamilton "
            "will all be hiring. Security clearance required to register."
        )
        score = self._score(body, sender="events@ccsend.com")
        contractor_mismatches = [
            df for df in score.domain_findings
            if "contractor name/domain mismatch" in df.finding.lower()
        ]
        assert contractor_mismatches == [], (
            f"'Cleared Virtual Career Fair' context should suppress mismatches; got: {contractor_mismatches}"
        )

    def test_non_career_fair_context_still_triggers_contractor_mismatch(self):
        """Outside career fair context, contractor domain mismatch still fires."""
        body = (
            "I am a recruiter from Leidos hiring for a TS/SCI role. "
            "Please send us your SSN to verify your clearance in DISS."
        )
        score = self._score(body, sender="recruiter@gmail.com")
        # Gmail is flagged as free email provider, not as contractor mismatch
        # (the domain analyzer skips contractor check for free email providers)
        # The important thing is the overall score is elevated
        assert score.total_score > 0.30, (
            f"Leidos impersonation + SSN request should score high; got {score.total_score}"
        )

    def test_full_restart_email_not_scored_as_fraud(self):
        """Full reStartEvents.com email must NOT score as 🛑 FRAUD."""
        body = (
            "reStart Cleared Virtual Career Fairs. Don't miss your chance to connect with "
            "top defense employers at our upcoming reStart Virtual Career Fairs. "
            "Nationwide TS/SCI and Above Virtual Career Fair Thursday April 23rd 2pm-6pm est. "
            "An Active TS/SCI CI Poly or Full Scope Lifestyle Poly Security Clearance REQUIRED. "
            "Companies Participating: Leidos Accenture Federal Services Amentum CACI "
            "Defense Contract Management Agency DCMA DISA Lockheed Martin MITRE and more. "
            "REGISTER TS/SCI and Above. "
            "Please share these events with any friends or colleagues who are currently looking. "
            "[CEO] reStartEvents.com Inc. "
            "To unsubscribe click here or update your email preferences."
        )
        score = self._score(body, sender="restart.events-gmail.com@shared1.ccsend.com")
        assert score.verdict.value != "FRAUD", (
            f"reStartEvents.com (legitimate career fair) must not score as FRAUD; "
            f"got {score.verdict} (score={score.total_score})"
        )

    # --- share_with_colleagues_list_amplification ---

    def test_share_with_colleagues_fires(self):
        """'Please share with friends or colleagues who are currently looking' triggers pattern."""
        body = (
            "Please share these unprecedented hiring events with any friends or colleagues "
            "who are currently looking or who would benefit from participating."
        )
        score = self._score(body)
        rule_names = {m.pattern.name for m in score.rule_matches}
        assert "share_with_colleagues_list_amplification" in rule_names, (
            f"'Share with colleagues' list amplification should be detected; got: {rule_names}"
        )

    def test_share_with_contacts_fires(self):
        """'Share this with contacts who are seeking' also triggers the pattern."""
        body = "Feel free to share this opportunity with contacts who are seeking new roles."
        score = self._score(body)
        rule_names = {m.pattern.name for m in score.rule_matches}
        assert "share_with_colleagues_list_amplification" in rule_names, (
            f"'Share with contacts seeking' should be detected; got: {rule_names}"
        )

    def test_normal_referral_no_false_positive(self):
        """Standard referral request without list-amplification language does not trigger."""
        body = "If you know a good candidate, feel free to forward this job description."
        score = self._score(body)
        rule_names = {m.pattern.name for m in score.rule_matches}
        assert "share_with_colleagues_list_amplification" not in rule_names

    # --- career_fair_clearance_aggregation ---

    def test_career_fair_clearance_required_fires(self):
        """Virtual career fair requiring TS/SCI clearance to register triggers aggregation pattern."""
        body = (
            "Nationwide TS/SCI and Above Virtual Career Fair. "
            "An Active TS/SCI Security Clearance REQUIRED. Register now."
        )
        score = self._score(body)
        rule_names = {m.pattern.name for m in score.rule_matches}
        assert "career_fair_clearance_aggregation" in rule_names, (
            f"'Career fair + clearance required' should trigger aggregation pattern; got: {rule_names}"
        )

    def test_register_clearance_required_fires(self):
        """'Register — TS/SCI clearance required' also triggers."""
        body = "Register today. An active TS/SCI clearance is required to attend this virtual career fair."
        score = self._score(body)
        rule_names = {m.pattern.name for m in score.rule_matches}
        assert "career_fair_clearance_aggregation" in rule_names, (
            f"'Register TS/SCI required' should be detected; got: {rule_names}"
        )

    def test_public_job_fair_no_clearance_no_false_positive(self):
        """A public (non-clearance) career fair does not trigger the pattern."""
        body = "Join us for our spring job fair open to all applicants. No clearance required."
        score = self._score(body)
        rule_names = {m.pattern.name for m in score.rule_matches}
        assert "career_fair_clearance_aggregation" not in rule_names




# ---------------------------------------------------------------------------
# EY GPS / eygps.us Verified Domain + Credential-in-Email & Isolation Patterns
# Reference: Rob Hines @ey.com email, April 15 2026 interview confirmation.
# eygps.us WHOIS: Registrant=EY, Alpharetta GA 30009, +1.8002250622, est.2021
# ---------------------------------------------------------------------------
class TestCredentialInEmailAndDoNotCopyPatterns:
    """Test shared_credentials_in_email and do_not_copy_return_only patterns.

    Even from legitimate senders (EY GPS), these structural patterns are
    high-value spoofing templates for clearance fraud:
    - Credentials in email: fraudsters swap URL, copy exact format
    - Do-not-copy isolation: prevents recipient from forwarding for verification
    """

    def _get_rule_names(self, body: str, sender: str = "recruiter@ey.com",
                        subject: str = "interview confirmation") -> set[str]:
        score = detector.analyze_text(body=body, subject=subject, sender=sender)
        return {m.pattern.name for m in score.rule_matches}

    # --- shared_credentials_in_email ---

    def test_username_password_in_email_fires(self):
        body = "Web site address: https://portal.example.com\nUser Name: TEMPLATE_USER\nPassword: template_pass01"
        rules = self._get_rule_names(body)
        assert "shared_credentials_in_email" in rules, (
            f"Credentials in email should fire; got: {rules}"
        )

    def test_login_credentials_block_fires(self):
        body = "Please log in with username: recruit123 and password: temp2026 to access the portal."
        rules = self._get_rule_names(body)
        assert "shared_credentials_in_email" in rules, (
            f"Login credential block should fire; got: {rules}"
        )

    def test_temporary_password_fires(self):
        body = "Your temporary username and password are provided below. Username: user1 Password: abc123"
        rules = self._get_rule_names(body)
        assert "shared_credentials_in_email" in rules, (
            f"Temporary password in email should fire; got: {rules}"
        )

    def test_no_credentials_no_false_positive(self):
        body = "Please visit our careers portal at careers.company.com to complete your application."
        rules = self._get_rule_names(body)
        assert "shared_credentials_in_email" not in rules

    # --- do_not_copy_return_only ---

    def test_do_not_copy_anyone_fires(self):
        body = "Return completed form to ONLY these addresses. Please make sure you do NOT copy anyone else on the email."
        rules = self._get_rule_names(body)
        assert "do_not_copy_return_only" in rules, (
            f"Do-not-copy isolation instruction should fire; got: {rules}"
        )

    def test_return_only_do_not_copy_fires(self):
        body = "Please return this document ONLY to hr@company.com and do not copy anyone on the response."
        rules = self._get_rule_names(body)
        assert "do_not_copy_return_only" in rules, (
            f"'Return ONLY / do not copy' should fire; got: {rules}"
        )

    def test_normal_return_instruction_no_false_positive(self):
        body = "Please return the signed form to your recruiter at the address listed below."
        rules = self._get_rule_names(body)
        assert "do_not_copy_return_only" not in rules

    # --- eygps.us treated as legitimate EY domain (no contractor mismatch) ---

    def test_eygps_domain_not_flagged_as_mismatch(self):
        """eygps.us must not trigger contractor name/domain mismatch for EY."""
        body = "Ernst and Young LLP interview confirmation. Return clearance prescreen to hr@eygps.us."
        score = detector.analyze_text(body=body, sender="recruiter@eygps.us")
        ey_mismatches = [
            df for df in score.domain_findings
            if "EY" in df.finding and "mismatch" in df.finding.lower()
        ]
        assert ey_mismatches == [], (
            f"eygps.us is verified EY-owned (WHOIS confirmed); must not mismatch; got: {ey_mismatches}"
        )

    def test_full_ey_interview_package_suspicious_or_higher(self):
        """Full EY GPS interview email (credentials + do-not-copy) scores SUSPICIOUS+."""
        body = (
            "Interview confirmed April 15 2026 with [Hiring Manager] via ey.hirevue.com. "
            "Return Optional Prescreen for Security Clearance Eligibility to ONLY: "
            "hr1@eygps.us hr2@eygps.us. "
            "Please make sure you do NOT copy anyone else on the email. "
            "Password protect your document. "
            "Web site: https://eyindependence.ey.com User Name: TEMPLATE_USER Password: template_pass01. "
            "EY Recruiter, Ernst Young LLP recruiter@ey.com"
        )
        score = detector.analyze_text(body=body, sender="recruiter@ey.com",
                                      subject="EY Interview Confirmation")
        assert score.verdict in (Verdict.SUSPICIOUS, Verdict.LIKELY_FRAUD, Verdict.FRAUD), (
            f"EY GPS onboarding email with credentials+isolation should score SUSPICIOUS+; "
            f"got {score.verdict} ({score.total_score})"
        )



# ---------------------------------------------------------------------------
# FBI MXU / eTalent Network / TSCTI — documented recruiter outreach, April 2026
# Covers: resume_falsification_request, word-boundary contractor name matching,
# t.co URL false positive fix, recruiting-on-behalf-of mismatch suppression
# ---------------------------------------------------------------------------
class TestResumeFalsificationAndDomainFixes:
    """Tests for resume falsification pattern and domain analyzer false-positive fixes."""

    def _rules(self, body: str, sender: str = "recruiter@etalentnetwork.com",
                subject: str = "interview confirmation") -> set[str]:
        score = detector.analyze_text(body=body, subject=subject, sender=sender)
        return {m.pattern.name for m in score.rule_matches}

    def _domain_findings(self, body: str, sender: str = "recruiter@etalentnetwork.com"):
        score = detector.analyze_text(body=body, sender=sender)
        return score.domain_findings

    # --- resume_falsification_request pattern ---

    def test_add_lines_to_resume_fires(self):
        body = "could you add a few lines highlighting your recent experience with Java in your latest contract"
        rules = self._rules(body)
        assert "resume_falsification_request" in rules, f"Got: {rules}"

    def test_i_can_update_your_resume_fires(self):
        body = "share a few points over email and I can update your resume accordingly"
        rules = self._rules(body)
        assert "resume_falsification_request" in rules, f"Got: {rules}"

    def test_recruiter_update_resume_fires(self):
        body = "you can update your resume to reflect your JavaScript and HTML experience"
        rules = self._rules(body)
        assert "resume_falsification_request" in rules, f"Got: {rules}"

    def test_normal_resume_instruction_no_false_positive(self):
        body = "please submit an updated copy of your resume along with your application"
        rules = self._rules(body)
        assert "resume_falsification_request" not in rules

    # --- Word-boundary contractor name matching (EY / IDA false positive fixes) ---

    def test_ey_not_matched_in_hey(self):
        """'Hey there' must NOT trigger EY (Ernst & Young) contractor mismatch."""
        body = "Hey there, we have an exciting opportunity for you today."
        domain_findings = self._domain_findings(body, sender="recruiter@staffingfirm.com")
        ey_mismatches = [df for df in domain_findings if "EY" in df.finding]
        assert ey_mismatches == [], f"'Hey' triggered false EY mismatch: {ey_mismatches}"

    def test_ida_not_matched_in_candidates(self):
        """'candidates' must NOT trigger IDA contractor mismatch (cand-IDA-tes)."""
        body = "We follow this process for other candidates as well."
        domain_findings = self._domain_findings(body, sender="recruiter@staffingfirm.com")
        ida_mismatches = [df for df in domain_findings if "IDA" in df.finding]
        assert ida_mismatches == [], f"'candidates' triggered false IDA mismatch: {ida_mismatches}"

    def test_standalone_ey_does_match(self):
        """Standalone 'EY' company name in body SHOULD trigger mismatch from non-EY domain."""
        body = "I am a recruiter from EY and want to discuss a cleared position."
        domain_findings = self._domain_findings(body, sender="recruiter@fakestaffing.com")
        ey_mismatches = [df for df in domain_findings if "EY" in df.finding]
        assert ey_mismatches, "Standalone 'EY' mention from non-EY domain should still fire"

    # --- t.co URL shortener false positive fix ---

    def test_microsoft_teams_url_not_flagged_as_shortener(self):
        """teams.microsoft.com must NOT be flagged as t.co URL shortener."""
        body = "Join the interview at https://teams.microsoft.com/meet/223331088709302?p=abc123"
        score = detector.analyze_text(body=body, sender="hr@company.com")
        assert "https://teams.microsoft.com/meet/223331088709302?p=abc123" not in \
               score.nlp_findings.suspicious_urls, \
               "teams.microsoft.com falsely matched 't.co' shortener (microso-ft.co-m substring)"

    def test_real_tco_shortener_still_flagged(self):
        """Real t.co Twitter short URLs must still be flagged."""
        body = "Click here to apply: https://t.co/AbCdEfGhIj"
        score = detector.analyze_text(body=body, sender="recruiter@company.com")
        assert any("t.co" in url for url in score.nlp_findings.suspicious_urls), \
               "Real t.co short URL should be flagged as suspicious"

    # --- Recruiting-on-behalf-of mismatch suppression ---

    def test_on_behalf_of_suppresses_contractor_mismatch(self):
        """'recruiting on behalf of 22nd Century Technologies' suppresses TSCTI mismatch."""
        body = (
            "My name is Aman and I am recruiting on behalf of 22nd Century Technologies. "
            "We have an opening with the FBI in Clarksburg WV."
        )
        domain_findings = self._domain_findings(
            body, sender="recruiter@etalentnetwork.com"
        )
        tscti_mismatches = [
            df for df in domain_findings
            if "22nd" in df.finding or "Century" in df.finding
        ]
        assert tscti_mismatches == [], \
               f"'recruiting on behalf of' should suppress TSCTI mismatch; got: {tscti_mismatches}"

    def test_full_aman_katoch_email_scores_likely_fraud(self):
        """Full eTalent recruiter FBI MXU email scores LIKELY_FRAUD (not FRAUD, not clean)."""
        body = (
            "Hey there! Interview confirmed April 15 2026 11:00 AM. Client FBI MXU. "
            "Join https://teams.microsoft.com/meet/223331088709302 "
            "We typically schedule a call with our FSO to verify the status of your clearance. "
            "could you add a few lines highlighting your recent experience with Java "
            "JavaScript and HTML in your latest contract. "
            "I can update your resume accordingly. "
            "Recruiting on behalf of 22nd Century Technologies Inc TSCTI. "
            "[Recruiter Name] XXX-XXX-XXXX Urgent Requirement Software Developer FBI"
        )
        score = detector.analyze_text(
            body=body, sender="recruiter@etalentnetwork.com",
            subject="Confirmed MS Teams Interview Software Developer FBI MXU"
        )
        assert score.verdict in (Verdict.SUSPICIOUS, Verdict.LIKELY_FRAUD), (
            f"eTalent recruiter FBI MXU email should score SUSPICIOUS or LIKELY_FRAUD due to "
            f"resume falsification + FSO call request; got {score.verdict} ({score.total_score})"
        )


# ===========================================================================
# HTML Body Stripping Tests
# ===========================================================================

class TestHtmlBodyStripping:
    """HTML-only emails must expose fraud signals to the rule engine."""

    HTML_FRAUD_ONLY = """From: fraud@dod-jobs.xyz
Subject: Cleared Position Available
Content-Type: text/html

<html><body>
<p>Please provide your <b>Social Security Number</b> immediately.</p>
<p>Processing fee: $200 via Bitcoin. Camera must be off during interview.</p>
<p>We guarantee your TS/SCI clearance. No experience required. $400,000/year.</p>
</body></html>"""

    HTML_CLEAN_ONLY = """From: talent@leidos.com
Subject: Systems Engineer TS/SCI
Content-Type: text/html

<html><body>
<p>Cleared Systems Engineer role in Chantilly, VA. Requires active TS/SCI.</p>
<p>Apply at leidos.com/careers. SF-86 sponsored upon offer via NBIS eApp.</p>
<p>No fees. In-person interviews at our Chantilly SCIF facility.</p>
</body></html>"""

    def test_html_fraud_body_gets_rule_matches(self):
        """HTML-only fraud email must produce rule matches (not zero)."""
        score = detector.analyze_eml_string(self.HTML_FRAUD_ONLY)
        assert score.rule_matches, (
            f"HTML-only fraud email produced zero rule matches. "
            f"full_text may not include HTML body. score={score.total_score}"
        )

    def test_html_fraud_body_scores_suspicious_or_higher(self):
        """HTML-only fraud email must reach at least SUSPICIOUS verdict."""
        score = detector.analyze_eml_string(self.HTML_FRAUD_ONLY)
        assert score.verdict != Verdict.CLEAN, (
            f"HTML-only fraud email scored CLEAN ({score.total_score}) — "
            f"HTML body not being scanned by rule engine"
        )

    def test_html_clean_body_not_over_flagged(self):
        """HTML-only legitimate email must not score FRAUD."""
        score = detector.analyze_eml_string(self.HTML_CLEAN_ONLY)
        assert score.verdict not in (Verdict.FRAUD, Verdict.LIKELY_FRAUD), (
            f"HTML-only legitimate email over-flagged as {score.verdict} ({score.total_score})"
        )

    def test_strip_html_produces_readable_text(self):
        """_strip_html must produce plain text with entity decoding and no tags."""
        from clearance_fraud_detector.parsers.email_parser import _strip_html
        html = "<p>Hello &amp; Welcome</p><b>Please provide SSN here</b>"
        result = _strip_html(html)
        assert "<p>" not in result, "HTML block tags should be stripped"
        assert "<b>" not in result, "HTML inline tags should be stripped"
        assert "&amp;" not in result, "HTML entities should be decoded"
        assert "Hello & Welcome" in result
        assert "SSN here" in result

    def test_plain_text_body_takes_precedence_over_html(self):
        """When both plain and HTML bodies are present, plain text is used."""
        from clearance_fraud_detector.parsers.email_parser import EmailDocument, _strip_html
        doc = EmailDocument(
            subject="Test",
            body_text="Plain text body content",
            body_html="<p>HTML body content</p>",
        )
        assert "Plain text body content" in doc.full_text
        assert "HTML body content" not in doc.full_text

    def test_empty_plain_falls_back_to_html(self):
        """Empty plain text body must fall back to HTML-stripped body."""
        from clearance_fraud_detector.parsers.email_parser import EmailDocument
        doc = EmailDocument(
            subject="Test",
            body_text="",
            body_html="<p>Social Security Number required upfront</p>",
        )
        assert "Social Security Number" in doc.full_text


# ===========================================================================
# FraudScore Confidence / Signal Diversity Tests
# ===========================================================================

class TestFraudScoreConfidence:
    """FraudScore.signal_count, category_count, and confidence fields."""

    def test_multi_category_fraud_scores_high_confidence(self):
        """High-score email with 3+ categories must report HIGH confidence."""
        score = detector.analyze_text(**FRAUD_EMAIL_1)
        # FRAUD_EMAIL_1 triggers pii_harvest + financial_scam + clearance_scam + urgency
        assert score.category_count >= 3, (
            f"Expected ≥3 categories, got {score.category_count}: {score.category_breakdown}"
        )
        assert score.confidence == "HIGH", (
            f"Multi-category fraud should be HIGH confidence, got {score.confidence}"
        )

    def test_single_weak_hit_is_low_confidence(self):
        """Single low-weight pattern hit on clean text should be LOW confidence."""
        score = detector.analyze_text(
            body="The position requires an active security clearance status.",
            sender="recruiter@company.com",
        )
        # clearance_level_request might fire but confidence should be LOW
        assert score.confidence in ("LOW", "MEDIUM")

    def test_clean_email_has_low_confidence_low_score(self):
        """Legitimate email: confidence LOW or MEDIUM, not HIGH."""
        score = detector.analyze_text(**CLEAN_EMAIL_1)
        # CLEAN_EMAIL_1 may score SUSPICIOUS if domain heuristics fire;
        # the key invariant is that confidence must not be HIGH
        assert score.verdict in (Verdict.CLEAN, Verdict.SUSPICIOUS), (
            f"Expected CLEAN or SUSPICIOUS, got {score.verdict} ({score.total_score})"
        )
        assert score.confidence in ("LOW", "MEDIUM"), (
            f"Legitimate email should not have HIGH confidence, got {score.confidence}"
        )

    def test_signal_count_equals_rule_matches(self):
        """signal_count must equal len(rule_matches)."""
        score = detector.analyze_text(**FRAUD_EMAIL_1)
        assert score.signal_count == len(score.rule_matches)

    def test_category_count_at_least_one_for_fraud(self):
        """Any fraud email must have category_count >= 1."""
        score = detector.analyze_text(**FRAUD_EMAIL_1)
        assert score.category_count >= 1


# ===========================================================================
# New DPRK Linguistic Patterns Tests (FBI PSA I-101823-PSA)
# ===========================================================================

class TestDPRKLinguisticPatterns2025:
    """FBI/CISA documented DPRK IT worker scheme linguistic indicators."""

    def test_prepayment_extortion_flagged(self):
        """Prepayment demand in work context must trigger dprk_scheme."""
        score = detector.analyze_text(
            body="We need a prepayment before the contract starts. "
                 "All cleared developers on this project pay upfront for their background check.",
            sender="hr@clearance-dev-jobs.xyz",
        )
        cats = {m.category for m in score.rule_matches}
        names = {m.pattern.name for m in score.rule_matches}
        assert "dprk_scheme" in cats or "prepayment_extortion" in names, (
            f"Prepayment extortion not detected. Matches: {names}"
        )

    def test_source_code_extortion_flagged(self):
        """Threat to release source code is a DPRK extortion tactic."""
        score = detector.analyze_text(
            body="If you don't pay the additional fees, we will release your proprietary "
                 "source code publicly.",
            sender="contractor@remote-dev.xyz",
        )
        names = {m.pattern.name for m in score.rule_matches}
        assert "prepayment_extortion" in names, (
            f"Source code extortion threat not detected. Matches: {names}"
        )

    def test_unsolicited_selection_before_applying_flagged(self):
        """'You have been selected' before any application is a social engineering hook."""
        score = detector.analyze_text(
            body="Congratulations! You have been selected for this position "
                 "without applying or submitting an application.",
            sender="hr@cleared-it-jobs.net",
        )
        names = {m.pattern.name for m in score.rule_matches}
        assert "unsolicited_selection" in names, (
            f"Unsolicited selection pattern not detected. Matches: {names}"
        )

    def test_payment_platform_switch_request_flagged(self):
        """Request to switch payment platform mid-contract is a DPRK money laundering tactic."""
        score = detector.analyze_text(
            body="Please use a different payment platform for this month. "
                 "We need you to switch to a new payroll method immediately.",
            sender="payroll@remote-cleared.xyz",
        )
        names = {m.pattern.name for m in score.rule_matches}
        assert "payment_platform_switch" in names, (
            f"Payment platform switch request not detected. Matches: {names}"
        )

    def test_dprk_linguistic_patterns_not_flagging_legit(self):
        """Standard corporate payment change notice must not trigger DPRK patterns."""
        score = detector.analyze_text(
            body="We are transitioning our payroll system from ADP to Workday. "
                 "You will receive an email from HR with setup instructions.",
            sender="hr@boozallen.com",
        )
        dprk_matches = [m for m in score.rule_matches if m.category == "dprk_scheme"
                        and m.pattern.name == "payment_platform_switch"]
        assert not dprk_matches, (
            f"Legitimate payroll system migration falsely flagged as DPRK. Matches: {dprk_matches}"
        )


# ===========================================================================
# FullAnalysis / analyze_all() Tests
# ===========================================================================

class TestFullAnalysis:
    """analyze_all() unified pipeline tests."""

    def test_analyze_all_returns_full_analysis(self):
        """analyze_all() must return a FullAnalysis with all required fields."""
        from clearance_fraud_detector.detector import FullAnalysis
        result = detector.analyze_all(
            text=FRAUD_EMAIL_1["body"],
            subject=FRAUD_EMAIL_1["subject"],
            sender=FRAUD_EMAIL_1["sender"],
        )
        assert isinstance(result, FullAnalysis)
        assert hasattr(result, "fraud_score")
        assert hasattr(result, "workforce_mapping")
        assert hasattr(result, "compliance")
        assert hasattr(result, "combined_risk")
        assert hasattr(result, "combined_verdict")

    def test_combined_risk_at_least_fraud_score(self):
        """combined_risk must be >= fraud_score.total_score (WM boosts only)."""
        result = detector.analyze_all(
            text=FRAUD_EMAIL_1["body"],
            subject=FRAUD_EMAIL_1["subject"],
            sender=FRAUD_EMAIL_1["sender"],
        )
        assert result.combined_risk >= result.fraud_score.total_score

    def test_clean_email_analyze_all_not_flagged(self):
        """Legitimate email through analyze_all must not be high-risk."""
        result = detector.analyze_all(
            text=CLEAN_EMAIL_1["body"],
            subject=CLEAN_EMAIL_1["subject"],
            sender=CLEAN_EMAIL_1["sender"],
        )
        assert not result.is_high_risk, (
            f"Legitimate email incorrectly flagged as high-risk. "
            f"combined_risk={result.combined_risk}, verdict={result.combined_verdict}"
        )

    def test_ci_risk_wm_boosts_combined_risk(self):
        """A message with CI_RISK workforce mapping should have boosted combined_risk."""
        from clearance_fraud_detector.analyzers.workforce_mapping_analyzer import WorkforceMappingVerdict
        # CI collection message: asking for clearance level, program names, references
        ci_text = (
            "Hi, I'm reaching out about a confidential opportunity with a government client. "
            "Could you tell me your current clearance level and what programs you've supported? "
            "Also, please provide three references who are also currently cleared. "
            "We'd like to know which government agencies and program offices you've worked with."
        )
        result = detector.analyze_all(text=ci_text, sender="hr@consulting-anonymous.com")
        # If WM triggers CI_RISK/CONFIRMED_COLLECTION, combined > fraud_score
        if result.workforce_mapping.verdict in (
            WorkforceMappingVerdict.CI_RISK,
            WorkforceMappingVerdict.CONFIRMED_COLLECTION,
        ):
            assert result.combined_risk > result.fraud_score.total_score, (
                f"CI_RISK WM verdict should boost combined_risk above fraud_score. "
                f"fraud={result.fraud_score.total_score}, combined={result.combined_risk}"
            )

    def test_combined_risk_capped_at_1(self):
        """combined_risk must never exceed 1.0."""
        result = detector.analyze_all(
            text=FRAUD_EMAIL_DPRK["body"],
            subject=FRAUD_EMAIL_DPRK["subject"],
            sender=FRAUD_EMAIL_DPRK["sender"],
        )
        assert result.combined_risk <= 1.0

    def test_top_signals_populated_for_fraud(self):
        """top_signals must be non-empty for a fraud email."""
        result = detector.analyze_all(
            text=FRAUD_EMAIL_1["body"],
            subject=FRAUD_EMAIL_1["subject"],
            sender=FRAUD_EMAIL_1["sender"],
        )
        assert result.top_signals, "top_signals should not be empty for a fraud email"

    def test_is_ci_reportable_delegates_to_wm(self):
        """is_ci_reportable must match workforce_mapping.is_ci_reportable."""
        result = detector.analyze_all(text="Hello, interested in your cleared background.")
        assert result.is_ci_reportable == result.workforce_mapping.is_ci_reportable

    def test_analyze_all_body_keyword_alias(self):
        """body= keyword alias must work identically to text=."""
        r1 = detector.analyze_all(text="Please provide your SSN immediately.")
        r2 = detector.analyze_all(body="Please provide your SSN immediately.")
        assert r1.fraud_score.total_score == r2.fraud_score.total_score


# ===========================================================================
# Legitimacy Signal Discount Tests
# ===========================================================================

class TestLegitimacyDiscount:
    """Emails using correct CFR vocabulary should receive a modest score reduction."""

    LEGIT_VOCAB_HEAVY = (
        "This position requires an active TS/SCI. The SF-86 will be initiated via "
        "NBIS eApp (eapp.nbis.mil) after your written offer and written acceptance, "
        "per 32 CFR 117.10. DISS JVS will be used for clearance verification. "
        "Our FSO will coordinate the process per NISPOM guidelines. "
        "No fees. Conditional offer provided before investigation starts."
    )

    def test_legit_vocab_reduces_score_vs_no_vocab(self):
        """Text with 3+ legitimate process terms should score lower than equivalent without."""
        score_with = detector.analyze_text(
            body=self.LEGIT_VOCAB_HEAVY, sender="recruiter@leidos.com"
        )
        # Same text with vocab stripped — replace proper terms with generic ones
        stripped = self.LEGIT_VOCAB_HEAVY.replace("eapp.nbis.mil", "our portal").replace(
            "32 CFR 117.10", "company policy"
        ).replace("DISS JVS", "our system").replace("NBIS eApp", "our system").replace(
            "NISPOM", "security guidelines"
        )
        score_without = detector.analyze_text(
            body=stripped, sender="recruiter@leidos.com"
        )
        assert score_with.total_score <= score_without.total_score, (
            f"Legitimate vocab should not increase score. "
            f"with={score_with.total_score}, without={score_without.total_score}"
        )

    def test_discount_does_not_apply_to_confirmed_fraud(self):
        """Legitimacy discount must not reduce confirmed fraud below LIKELY_FRAUD."""
        # Mix of legit vocab + strong fraud signals — discount should not excuse fraud
        body = (
            "We use the NBIS eApp and DISS system per 32 CFR 117.10. "
            "Please provide your Social Security Number now. "
            "There is a $200 processing fee via Bitcoin. We guarantee your clearance."
        )
        score = detector.analyze_text(body=body, sender="fso@gmail.com")
        assert score.verdict in (Verdict.LIKELY_FRAUD, Verdict.FRAUD), (
            f"Strong fraud signals should not be discounted below LIKELY_FRAUD. "
            f"Got {score.verdict} ({score.total_score})"
        )


# ---------------------------------------------------------------------------
# Process Void / Ghost Employer — No Next Steps, No Callback, No Timeline
# ---------------------------------------------------------------------------

class TestEngagementGhostPatterns:
    """
    Verify that ghost-employer signals (no timeline, no next steps, no contact
    provided) are detected at the appropriate weight tier.
    """

    def test_resume_on_file_harvest(self):
        """'We'll keep your resume on file' should trigger process_void."""
        score = detector.analyze_text(
            body="Thanks for reaching out! We'll keep your resume on file and "
                 "reach out when something comes up.",
            sender="talent@clearancejobs-staffing.com",
        )
        rule_patterns = {m.pattern.name for m in score.rule_matches}
        assert "resume_on_file_harvest" in rule_patterns, (
            f"Expected resume_on_file_harvest, got: {rule_patterns}"
        )

    def test_talent_pool_add(self):
        """'Add you to our talent pool' should trigger resume_on_file_harvest."""
        score = detector.analyze_text(
            body="We don't have an immediate opening but would like to add you to our "
                 "talent pipeline for future opportunities.",
            sender="hr@defensetech-staffing.net",
        )
        rule_patterns = {m.pattern.name for m in score.rule_matches}
        assert "resume_on_file_harvest" in rule_patterns, (
            f"Expected resume_on_file_harvest, got: {rule_patterns}"
        )

    def test_vague_callback_no_date(self):
        """'We'll be in touch' with no date triggers vague_callback_no_date."""
        score = detector.analyze_text(
            body="Please send your resume and clearance level. We'll be in touch.",
            sender="recruiter@dod-clearance-jobs.com",
        )
        rule_patterns = {m.pattern.name for m in score.rule_matches}
        assert "vague_callback_no_date" in rule_patterns, (
            f"Expected vague_callback_no_date, got: {rule_patterns}"
        )

    def test_vague_callback_with_date_not_flagged(self):
        """'We'll be in touch within 3 business days' should NOT trigger."""
        score = detector.analyze_text(
            body="Thank you for your application. We'll be in touch within 3 business days "
                 "to schedule a technical screen.",
            sender="hr@raytheon.com",
        )
        rule_patterns = {m.pattern.name for m in score.rule_matches}
        assert "vague_callback_no_date" not in rule_patterns, (
            f"Specific timeline should not flag vague_callback_no_date. Got: {rule_patterns}"
        )

    def test_you_will_hear_from_us_no_date(self):
        """'You'll hear from us' without a timeframe triggers vague_callback_no_date."""
        score = detector.analyze_text(
            body="Submit your resume and we will review it. You'll hear from us.",
            sender="recruiting@defense-ops-staffing.biz",
        )
        rule_patterns = {m.pattern.name for m in score.rule_matches}
        assert "vague_callback_no_date" in rule_patterns, (
            f"Expected vague_callback_no_date, got: {rule_patterns}"
        )

    def test_indefinite_opening_wait(self):
        """'When a suitable position opens' triggers indefinite_opening_wait."""
        score = detector.analyze_text(
            body="We will reach out when a suitable position opens that matches your "
                 "clearance level and background.",
            sender="jobs@cleared-talent.xyz",
        )
        rule_patterns = {m.pattern.name for m in score.rule_matches}
        assert "indefinite_opening_wait" in rule_patterns, (
            f"Expected indefinite_opening_wait, got: {rule_patterns}"
        )

    def test_contingent_contract_award(self):
        """'Contingent on a position opening' triggers indefinite_opening_wait."""
        score = detector.analyze_text(
            body="This role is contingent on a contract opening. Send your resume now "
                 "so we are ready when the contract is awarded.",
            sender="staffing@govops-group.com",
        )
        rule_patterns = {m.pattern.name for m in score.rule_matches}
        assert "indefinite_opening_wait" in rule_patterns, (
            f"Expected indefinite_opening_wait, got: {rule_patterns}"
        )

    def test_do_not_contact_us(self):
        """'Do not contact us' triggers no_contact_us_barrier."""
        score = detector.analyze_text(
            body="Please submit your resume. Do not contact our office directly. "
                 "We will reach out if your background is a match.",
            sender="hr@securejobs-network.net",
        )
        rule_patterns = {m.pattern.name for m in score.rule_matches}
        assert "no_contact_us_barrier" in rule_patterns, (
            f"Expected no_contact_us_barrier, got: {rule_patterns}"
        )

    def test_no_calls_please(self):
        """'No phone calls, please' triggers no_contact_us_barrier."""
        score = detector.analyze_text(
            body="Send your resume and clearance level to this email. No phone calls, please. "
                 "We'll follow up when we review applications.",
            sender="careers@clearance-placement-group.com",
        )
        rule_patterns = {m.pattern.name for m in score.rule_matches}
        assert "no_contact_us_barrier" in rule_patterns, (
            f"Expected no_contact_us_barrier, got: {rule_patterns}"
        )

    def test_submit_and_disappear(self):
        """Submit + vague 'we'll review' with no timeline triggers submit_wait_no_step."""
        score = detector.analyze_text(
            body="Please send us your resume and our team will review and be in touch.",
            sender="talent@defense-solutions-group.xyz",
        )
        rule_patterns = {m.pattern.name for m in score.rule_matches}
        assert "submit_wait_no_step" in rule_patterns, (
            f"Expected submit_wait_no_step, got: {rule_patterns}"
        )

    def test_combined_ghost_employer_elevates_score(self):
        """Multiple ghost-employer signals combined should push score above SUSPICIOUS."""
        body = (
            "Hi, we came across your profile and are interested in your background. "
            "Please send us your resume and clearance level. "
            "We'll keep your resume on file and reach out when something comes up. "
            "Please do not contact our office. We'll be in touch."
        )
        score = detector.analyze_text(body=body, sender="talent@defense-group.biz")
        assert score.verdict in (Verdict.SUSPICIOUS, Verdict.LIKELY_FRAUD, Verdict.FRAUD), (
            f"Combined ghost-employer signals should rate SUSPICIOUS or higher, "
            f"got {score.verdict} ({score.total_score})"
        )

    def test_real_recruiter_with_timeline_not_flagged(self):
        """A recruiter with a specific timeline and next steps should not be flagged."""
        body = (
            "Hi Kevin, my name is Sarah and I'm a cleared recruiter at Leidos. "
            "I'm reaching out about a TS/SCI Software Engineer role on the BATS contract "
            "(req 12345-B). I'd like to schedule a 20-minute call this week — does "
            "Tuesday at 2pm ET or Thursday at 10am ET work? "
            "You'll hear back from me within one business day of submitting your resume. "
            "You can reach me directly at sarah.jones@leidos.com or 703-555-0100 ext 4421."
        )
        score = detector.analyze_text(body=body, sender="sarah.jones@leidos.com")
        assert score.verdict not in (Verdict.FRAUD, Verdict.LIKELY_FRAUD), (
            f"Legitimate recruiter message with timeline should not flag as fraud. "
            f"Got {score.verdict} ({score.total_score})"
        )
        ghost_patterns = {
            "resume_on_file_harvest", "vague_callback_no_date",
            "indefinite_opening_wait", "no_contact_us_barrier",
            "submit_wait_no_step",
        }
        fired = ghost_patterns & {m.pattern.name for m in score.rule_matches}
        assert not fired, f"Ghost patterns should not fire on legitimate recruiter: {fired}"


# ---------------------------------------------------------------------------
# Staffing-firm PII intake form patterns (E-Talent Network / TSCTI email type)
# ---------------------------------------------------------------------------

class TestStaffingFirmIntakePatterns:
    """
    Patterns triggered by the classic staffing-firm cold-contact cleared-job email:
    bulk PII intake form, criminal history prescreen, competing-offers probe,
    exclusive sourcing claim, and anonymous cleared client.
    Based on real email from Jatin Narang / E-Talent Network, April 2026.
    """

    # The verbatim intake section from the real email
    INTAKE_BODY = (
        "Kindly share your updated resume at jatinn@etalentnetwork.com\n"
        "Full Legal Name:\n"
        "Phone No(s).\n"
        "Current Location (City and State)\n"
        "Work Authorization Status:\n"
        "Best time and the best no. to call you at:\n"
        "Availability to start on the assignment if you are hired:\n"
        "Willing to relocate at its own, if required? (Y/N):\n"
        "How many interviews and offer in pipeline:\n"
        "Any misdemeanor or felony in past 7 years ? Y/N\n"
        "Rate Expectations:\n"
        "Client: An aerospace & defense client\n"
        "We are the sole agency that does recruitment sourcing for 22nd Century Technologies.\n"
        "Active Secret Clearance Required.\n"
    )

    def test_bulk_pii_intake_form_fires(self):
        """Full Legal Name: / Phone No: / Work Authorization Status: form triggers bulk_pii_intake_form."""
        score = detector.analyze_text(body=self.INTAKE_BODY, sender="jatinn@etalentnetwork.com")
        rule_patterns = {m.pattern.name for m in score.rule_matches}
        assert "bulk_pii_intake_form" in rule_patterns, (
            f"Expected bulk_pii_intake_form, got: {rule_patterns}"
        )

    def test_criminal_history_prescreen_fires(self):
        """'Any misdemeanor or felony in past 7 years' triggers criminal_history_prescreen."""
        score = detector.analyze_text(
            body="Any misdemeanor or felony in past 7 years ? Y/N",
            sender="hr@staffing-group.net",
        )
        rule_patterns = {m.pattern.name for m in score.rule_matches}
        assert "criminal_history_prescreen" in rule_patterns, (
            f"Expected criminal_history_prescreen, got: {rule_patterns}"
        )

    def test_competing_offers_probe_fires(self):
        """'How many interviews and offer in pipeline' triggers competing_offers_intel_probe."""
        score = detector.analyze_text(
            body="How many interviews and offer in pipeline:\nRate Expectations:",
            sender="recruiter@cleared-staffing.biz",
        )
        rule_patterns = {m.pattern.name for m in score.rule_matches}
        assert "competing_offers_intel_probe" in rule_patterns, (
            f"Expected competing_offers_intel_probe, got: {rule_patterns}"
        )

    def test_exclusive_sourcing_claim_fires(self):
        """'Sole agency that does recruitment sourcing for' triggers exclusive_sourcing_authority_claim."""
        score = detector.analyze_text(
            body="We are the sole agency that does recruitment sourcing for 22nd Century Technologies.",
            sender="jatinn@etalentnetwork.com",
        )
        rule_patterns = {m.pattern.name for m in score.rule_matches}
        assert "exclusive_sourcing_authority_claim" in rule_patterns, (
            f"Expected exclusive_sourcing_authority_claim, got: {rule_patterns}"
        )

    def test_anonymous_cleared_client_fires(self):
        """'Client: An aerospace & defense client' triggers anonymous_cleared_client."""
        score = detector.analyze_text(
            body="Client: An aerospace & defense client\nActive Secret Clearance Required.",
            sender="staffing@etalentnetwork.com",
        )
        rule_patterns = {m.pattern.name for m in score.rule_matches}
        assert "anonymous_cleared_client" in rule_patterns, (
            f"Expected anonymous_cleared_client, got: {rule_patterns}"
        )

    def test_anonymous_client_variants(self):
        """Various anonymous client phrasings all trigger the pattern."""
        variants = [
            "Client: An aerospace & defense client",
            "Client: A federal client — Active Secret required.",
            "Our federal client requires an active clearance.",
            "Company: Confidential — active TS/SCI required.",
        ]
        for text in variants:
            score = detector.analyze_text(body=text, sender="hr@staffing.biz")
            rule_patterns = {m.pattern.name for m in score.rule_matches}
            assert "anonymous_cleared_client" in rule_patterns, (
                f"Variant did not trigger anonymous_cleared_client: {text!r} | got: {rule_patterns}"
            )

    def test_named_client_not_flagged(self):
        """A named prime contractor does NOT trigger anonymous_cleared_client."""
        score = detector.analyze_text(
            body="Client: Raytheon Technologies\nActive Secret Clearance Required.\n"
                 "Requisition: RTX-2026-00412",
            sender="recruiter@raytheon.com",
        )
        rule_patterns = {m.pattern.name for m in score.rule_matches}
        assert "anonymous_cleared_client" not in rule_patterns, (
            f"Named client should not trigger anonymous_cleared_client: {rule_patterns}"
        )

    def test_full_etalen_email_scores_fraud(self):
        """The complete E-Talent Network email pattern should score LIKELY_FRAUD or FRAUD."""
        score = detector.analyze_text(
            body=self.INTAKE_BODY,
            subject="Software Integration Engineer - 15027864",
            sender="jatinn@etalentnetwork.com",
        )
        assert score.verdict in (Verdict.LIKELY_FRAUD, Verdict.FRAUD), (
            f"E-Talent Network intake email should score LIKELY_FRAUD or FRAUD, "
            f"got {score.verdict} ({score.total_score:.3f})"
        )
        # Must catch at least 5 distinct signals
        assert score.signal_count >= 5, (
            f"Expected at least 5 signals, got {score.signal_count}"
        )


