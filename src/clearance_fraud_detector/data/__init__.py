"""Reference data — fraud patterns, contractor registry, staffing firms, CAGE codes."""

from .fraud_patterns import ALL_PATTERNS, FraudPattern
from .known_contractors import (
    LEGITIMATE_CONTRACTORS,
    KNOWN_FAKE_RECRUITING_DOMAINS,
    LEGITIMATE_JOB_BOARDS,
    ALL_LEGITIMATE_DOMAINS,
    VERIFIED_CONTRACTORS,
    GOVERNMENT_DOMAINS,
)
from .known_staffing_firms import KNOWN_STAFFING_FIRMS, FLAGGED_STAFFING_FIRMS, StaffingFirm
from .cage_codes import CAGE_CODES, DOMAIN_TO_CAGE, lookup_cage, lookup_by_domain

__all__ = [
    "ALL_PATTERNS",
    "FraudPattern",
    "LEGITIMATE_CONTRACTORS",
    "KNOWN_FAKE_RECRUITING_DOMAINS",
    "LEGITIMATE_JOB_BOARDS",
    "ALL_LEGITIMATE_DOMAINS",
    "VERIFIED_CONTRACTORS",
    "GOVERNMENT_DOMAINS",
    "KNOWN_STAFFING_FIRMS",
    "FLAGGED_STAFFING_FIRMS",
    "StaffingFirm",
    "CAGE_CODES",
    "DOMAIN_TO_CAGE",
    "lookup_cage",
    "lookup_by_domain",
]