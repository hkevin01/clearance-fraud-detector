"""Clearance Fraud Detector — identify fraudulent job emails in the security clearance space."""

from .detector import EmailFraudDetector, FullAnalysis
from .scoring.scorer import FraudScore, Verdict
from .parsers.email_parser import EmailDocument, parse_eml_file, parse_eml_string, parse_plain_text
from .analyzers.workforce_mapping_analyzer import WorkforceMappingAnalysis, WorkforceMappingVerdict
from .analyzers.nispom_compliance import ComplianceReport
from .report_generator import IncidentReport, IncidentReportInput

__all__ = [
    # Primary API
    "EmailFraudDetector",
    "FullAnalysis",
    # Result types
    "FraudScore",
    "Verdict",
    "EmailDocument",
    "WorkforceMappingAnalysis",
    "WorkforceMappingVerdict",
    "ComplianceReport",
    "IncidentReport",
    "IncidentReportInput",
    # Parser helpers
    "parse_eml_file",
    "parse_eml_string",
    "parse_plain_text",
]

__version__ = "0.2.0"
