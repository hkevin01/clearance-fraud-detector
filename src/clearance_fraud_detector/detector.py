"""
Main entrypoint: EmailFraudDetector orchestrates all analysis layers.
"""
from dataclasses import dataclass, field
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
from .analyzers.workforce_mapping_analyzer import (
    WorkforceMappingAnalysis,
    WorkforceMappingVerdict,
    analyze_workforce_mapping,
)
from .parsers.email_parser import EmailDocument, parse_eml_file, parse_eml_string, parse_plain_text
from .report_generator import IncidentReport, IncidentReportInput, generate_report
from .scoring.explainer import ExplainerReport, explain_combined, explain_patterns
from .scoring.scorer import FraudScore, Verdict, compute_score


@dataclass
class FullAnalysis:
    """
    Unified result from analyze_all() — bundles every analysis layer into one
    object so callers never need to issue multiple separate detector calls.

    The combined_risk field integrates the primary fraud score with workforce
    mapping CI signals: a CI_RISK or CONFIRMED_COLLECTION verdict boosts the
    combined risk even if the message body passes email fraud checks.
    """
    fraud_score: FraudScore
    workforce_mapping: WorkforceMappingAnalysis
    compliance: ComplianceReport
    combined_risk: float            # 0.0–1.0: fraud_score + optional WM boost
    combined_verdict: str           # human-readable overall assessment
    top_signals: list[str] = field(default_factory=list)

    @property
    def is_high_risk(self) -> bool:
        return self.combined_risk >= 0.45

    @property
    def is_ci_reportable(self) -> bool:
        return self.workforce_mapping.is_ci_reportable


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

    def analyze_workforce_mapping(
        self,
        text: str = "",
        sender: str = "",
        subject: str = "",
        contact_channel: str = "email",
        *,
        body: str = "",
    ) -> WorkforceMappingAnalysis:
        """
        Analyze a recruiter message for workforce mapping / cleared community
        profiling patterns documented in the FBI 'Think Before You Link' advisory.

        This is distinct from fraud detection: the message may come from a real
        company with a real domain yet still serve intelligence collection
        objectives (mapping active cleared professionals, building resume
        databases of access history, harvesting social graphs of cleared networks).

        Detects:
          - Anonymous client + clearance requirement (resume collection risk)
          - Active clearance status probing vs. standard 'eligible to obtain' language
          - Classified program/project history fishing before any formal relationship
          - Pre-screen reference harvesting (social graph expansion)
          - Cleared employer chain mining (facility/access map collection)
          - Absence of requisition number for a cleared position
          - FBI-advisory signals: flattery, scarcity, urgency to move off platform
          - Contact channel risk (personal email, Telegram, WhatsApp)

        Args:
            text:            Body text of the message.
            sender:          Sender email address.
            subject:         Message subject line.
            contact_channel: How contact was initiated — one of:
                             "email" | "linkedin" | "clearancejobs" | "phone" |
                             "text" | "telegram" | "whatsapp" | "signal"
            body:            Alias for text (keyword-only).

        Returns:
            WorkforceMappingAnalysis with risk_score, verdict, collection_vectors,
            fbi_indicator_matches, recommendations, and is_ci_reportable flag.
        """
        return analyze_workforce_mapping(
            body or text,
            sender=sender,
            subject=subject,
            contact_channel=contact_channel,
        )

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

    # ID: DET-001
    # Requirement: Run every applicable analysis layer on a single text input and
    #              return a FullAnalysis bundle with an integrated combined_risk score.
    # Purpose: Eliminate the need for callers to issue 3+ separate analyzer calls to
    #          get a complete threat picture for a single recruiter message or email.
    # Rationale: Workforce mapping CI signals can be present in otherwise clean-scoring
    #             messages; the combined_risk field integrates both dimensions so that
    #             CI-risk messages receive an appropriately elevated verdict.
    # Inputs: text/body (str) — message body; subject, sender, contact_channel (str, opt).
    # Outputs: FullAnalysis with fraud_score, workforce_mapping, compliance, combined_risk,
    #          combined_verdict, top_signals, is_high_risk, and is_ci_reportable.
    # Preconditions: All analyzer modules are importable and compiled patterns ready.
    # Postconditions: combined_risk ∈ [0.0, 1.0]; combined_verdict is a non-empty string.
    # Side Effects: None — pure computation; no I/O beyond what individual analyzers perform.
    # Failure Modes: Any individual analyzer returning empty/default results is handled
    #                gracefully — combined_risk falls back to fraud_score.total_score.
    # Constraints: Executes all analyzers sequentially; typically < 15 ms total.
    # Verification: test_detector.py::TestFullAnalysis — CI boost, clean pass-through.
    # References: WorkforceMappingVerdict thresholds; FraudScore Verdict thresholds.
    def analyze_all(
        self,
        text: str = "",
        subject: str = "",
        sender: str = "",
        contact_channel: str = "email",
        *,
        body: str = "",
    ) -> FullAnalysis:
        """
        Run fraud detection, workforce mapping, and compliance checks in a single call.

        Combines all three analysis dimensions into one FullAnalysis result:
          - FraudScore: rule-based + domain + NLP email fraud signals
          - WorkforceMappingAnalysis: CI collection / cleared community profiling
          - ComplianceReport: 32 CFR §117.10 regulatory violations

        The combined_risk integrates both fraud and CI dimensions — a message
        that scores clean on fraud rules but triggers CI_RISK workforce mapping
        signals will have its combined_risk elevated accordingly.

        Args:
            text:            Message body text (use this or body=).
            subject:         Subject or title line.
            sender:          From address.
            contact_channel: How the contact arrived — "email", "linkedin",
                             "telegram", "phone", etc.
            body:            Keyword alias for text.

        Returns:
            FullAnalysis with all sub-analyses and an integrated combined_risk.
        """
        msg_text = body or text

        # Run the three core analysis layers
        doc = parse_plain_text(msg_text, subject=subject, sender=sender)
        fraud_score = self.analyze_document(doc)
        wm = analyze_workforce_mapping(
            msg_text, sender=sender, subject=subject, contact_channel=contact_channel
        )
        compliance = check_compliance(msg_text)

        # Integrate WM CI signals into combined_risk
        # CI_RISK boosts by 0.10; CONFIRMED_COLLECTION boosts by 0.20 (capped at 1.0)
        wm_boost = 0.0
        if wm.verdict == WorkforceMappingVerdict.CI_RISK:
            wm_boost = 0.10
        elif wm.verdict == WorkforceMappingVerdict.CONFIRMED_COLLECTION:
            wm_boost = 0.20
        combined_risk = round(min(fraud_score.total_score + wm_boost, 1.0), 3)

        # Build combined verdict string
        if combined_risk >= 0.70:
            combined_verdict = "FRAUD / CONFIRMED CI RISK"
        elif combined_risk >= 0.45:
            combined_verdict = "LIKELY FRAUD / ELEVATED RISK"
        elif combined_risk >= 0.20:
            combined_verdict = "SUSPICIOUS — VERIFY BEFORE ENGAGING"
        else:
            combined_verdict = "CLEAN — No significant signals detected"

        if wm.is_ci_reportable:
            combined_verdict += " + CI_REPORTABLE"

        # Aggregate top signals across all layers
        top_signals: list[str] = list(fraud_score.top_reasons[:5])
        if wm.signals:
            top_signals += [
                f"[workforce_mapping] {s.description}"
                for s in sorted(wm.signals, key=lambda s: s.weight, reverse=True)[:3]
            ]
        if compliance.violations:
            top_signals += [
                f"[compliance] {v.rule}: {v.what_violated[:80]}"
                for v in compliance.violations[:2]
            ]

        return FullAnalysis(
            fraud_score=fraud_score,
            workforce_mapping=wm,
            compliance=compliance,
            combined_risk=combined_risk,
            combined_verdict=combined_verdict,
            top_signals=top_signals[:10],
        )
