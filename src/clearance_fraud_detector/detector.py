"""
Main entrypoint: EmailFraudDetector orchestrates all analysis layers.
"""
from pathlib import Path

from .analyzers.contact_analyzer import ContactAnalysis, analyze_contact
from .analyzers.domain_analyzer import analyze_domains
from .analyzers.job_posting_analyzer import JobPostingAnalysis, analyze_job_posting
from .analyzers.nlp_analyzer import analyze_nlp
from .analyzers.nispom_compliance import ComplianceReport, check_compliance
from .analyzers.offer_letter_verifier import OfferLetterAnalysis, verify_offer_letter
from .analyzers.phone_analyzer import PhoneAnalysis, analyze_phone
from .analyzers.rule_engine import run_rules
from .analyzers.vishing_analyzer import VishingAnalysis, analyze_vishing
from .parsers.email_parser import EmailDocument, parse_eml_file, parse_eml_string, parse_plain_text
from .report_generator import IncidentReport, IncidentReportInput, generate_report
from .scoring.explainer import ExplainerReport, explain_combined, explain_patterns
from .scoring.scorer import FraudScore, compute_score


class EmailFraudDetector:
    """High-level API for clearance-job fraud email detection."""

    def analyze_document(self, doc: EmailDocument) -> FraudScore:
        rule_matches = run_rules(doc)
        domain_findings = analyze_domains(doc)
        nlp_findings = analyze_nlp(doc.full_text)
        return compute_score(rule_matches, domain_findings, nlp_findings)

    def analyze_eml_file(self, path: str | Path) -> FraudScore:
        doc = parse_eml_file(Path(path))
        return self.analyze_document(doc)

    def analyze_eml_string(self, raw: str) -> FraudScore:
        doc = parse_eml_string(raw)
        return self.analyze_document(doc)

    def analyze_text(self, text: str = "", subject: str = "", sender: str = "", *, body: str = "") -> FraudScore:
        doc = parse_plain_text(body or text, subject=subject, sender=sender)
        return self.analyze_document(doc)

    def analyze_call_transcript(self, transcript: str) -> VishingAnalysis:
        """
        Analyze a phone/video call transcript or interview notes for vishing and
        AI voice fraud indicators, including DPRK IT worker scheme signals.

        Args:
            transcript: Plain-text content of the call transcript or notes.

        Returns:
            VishingAnalysis with risk score and categorized findings.
        """
        return analyze_vishing(transcript)

    def analyze_job_posting(self, posting_text: str) -> JobPostingAnalysis:
        """
        Analyze a job posting for fake/fraudulent clearance job indicators.

        Args:
            posting_text: Full text of the job posting.

        Returns:
            JobPostingAnalysis with risk score and categorized findings.
        """
        return analyze_job_posting(posting_text)

    def analyze_contact(self, contact_text: str) -> ContactAnalysis:
        """
        Analyze a recruiter message or FSO contact email/transcript to distinguish
        legitimate cleared-job contact from FSO impersonation or fake recruiter fraud.

        Key distinction:
          - Real FSO: verifies clearance via DISS (name+employer only); never asks
            candidate for SSN "to verify clearance"
          - Fake FSO: asks for SSN/DOB "to verify clearance level" — this is PII theft
          - Real recruiter: corporate email, named company, proper ATS, SSN only post-offer
          - Fake recruiter: pre-offer SSN request, Telegram-only, camera-off, anonymous

        Args:
            contact_text: Raw text of email, message, or call notes from a recruiter
                          or from someone claiming to be an FSO.

        Returns:
            ContactAnalysis with risk score, ContactType, and categorized findings.
        """
        return analyze_contact(contact_text)

    def analyze_phone_number(
        self,
        number: str,
        claimed_company: str = "",
        claimed_region: str = "",
        ssn_requested: bool = False,
        pre_offer: bool = False,
    ) -> PhoneAnalysis:
        """
        Analyze a phone number used by a recruiter or someone claiming to be an FSO.

        Checks the number against known published company numbers, flags geographic
        mismatches, VoIP usage, and automatically raises risk if SSN was requested
        on the call or contact happened before a formal offer.

        Args:
            number: The phone number to analyze (any format).
            claimed_company: Company the caller claimed to represent.
            claimed_region: Location the caller claimed to be in.
            ssn_requested: True if SSN/DOB was requested during this call.
            pre_offer: True if this call happened before a formal written offer.

        Returns:
            PhoneAnalysis with risk score, verdict, and detailed findings.
        """
        return analyze_phone(
            number,
            claimed_company=claimed_company,
            claimed_region=claimed_region,
            ssn_requested_on_call=ssn_requested,
            pre_offer_contact=pre_offer,
        )

    def check_compliance(self, text: str) -> ComplianceReport:
        """
        Check a recruiter or FSO interaction for NISPOM §117.10 violations.

        Args:
            text: Raw text of email, message, call notes, or form content.

        Returns:
            ComplianceReport listing all detected violations with verbatim
            CFR text, severity, and recommended actions.
        """
        return check_compliance(text)

    def verify_offer_letter(self, text: str, sender_email: str = "") -> OfferLetterAnalysis:
        """
        Analyze an offer letter for authenticity and NISPOM compliance.

        Detects SSN fields on offer letters, offers conditioned on SSN,
        free email domains, missing physical address, and other fraud signals.

        Args:
            text:         Full text of the offer letter.
            sender_email: Sender's email address (improves domain analysis).

        Returns:
            OfferLetterAnalysis with red/yellow/green flags and overall risk.
        """
        return verify_offer_letter(text, sender_email=sender_email)

    def explain_findings(
        self,
        pattern_names: list[str] | None = None,
        category_names: list[str] | None = None,
    ) -> ExplainerReport:
        """
        Map detected fraud signals and violation categories to 32 CFR §117.10
        citations with verbatim rule text, correct process, and response scripts.

        Args:
            pattern_names:  FraudPattern names from a rule engine match list.
            category_names: Violation category names from a ComplianceReport.

        Returns:
            ExplainerReport with full citation details and response guidance.
        """
        if pattern_names and category_names:
            return explain_combined(pattern_names, category_names)
        if pattern_names:
            return explain_patterns(pattern_names)
        from .scoring.explainer import explain_categories
        return explain_categories(category_names or [])

    def generate_incident_report(self, inp: IncidentReportInput) -> IncidentReport:
        """
        Generate a DCSA/FBI-ready incident report from a fraud interaction.

        Args:
            inp: IncidentReportInput with company, recruiter, violations, and
                 interaction text.

        Returns:
            IncidentReport renderable as plain text or Markdown.
        """
        return generate_report(inp)
