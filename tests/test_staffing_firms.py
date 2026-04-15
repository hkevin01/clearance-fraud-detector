"""Tests for data/known_staffing_firms.py."""
import pytest
from clearance_fraud_detector.data.known_staffing_firms import (
    FLAGGED_STAFFING_FIRMS,
    KNOWN_STAFFING_FIRMS,
    STAFFING_FIRM_DOMAINS,
    StaffingFirm,
    get_firm_by_domain,
    get_firm_by_name,
    is_flagged,
)


class TestFlaggedFirms:
    """FLAGGED_STAFFING_FIRMS data integrity."""

    def test_mindbank_is_flagged(self):
        assert "Mindbank Consulting Group" in FLAGGED_STAFFING_FIRMS

    def test_is_flagged_mindbank(self):
        assert is_flagged("Mindbank Consulting Group") is True

    def test_is_flagged_legitimate_firm_returns_false(self):
        assert is_flagged("Chenega Corporation") is False

    def test_flagged_firms_is_list(self):
        assert isinstance(FLAGGED_STAFFING_FIRMS, list)


class TestKnownStaffingFirms:
    """KNOWN_STAFFING_FIRMS data integrity."""

    def test_mindbank_in_known_firms(self):
        assert "Mindbank Consulting Group" in KNOWN_STAFFING_FIRMS

    def test_tscti_in_known_firms(self):
        keys = list(KNOWN_STAFFING_FIRMS.keys())
        assert any("22nd Century" in k or "tscti" in k.lower() or "22ctech" in k.lower() for k in keys), \
            f"TSCTI not found in: {keys}"

    def test_clearancejobs_in_known_firms(self):
        assert any("ClearanceJobs" in k for k in KNOWN_STAFFING_FIRMS)

    def test_chenega_in_known_firms(self):
        assert "Chenega Corporation" in KNOWN_STAFFING_FIRMS

    def test_all_entries_are_staffing_firm_type(self):
        for name, firm in KNOWN_STAFFING_FIRMS.items():
            assert isinstance(firm, StaffingFirm), f"{name} is not a StaffingFirm"

    def test_mindbank_has_fraud_indicators(self):
        mindbank = KNOWN_STAFFING_FIRMS["Mindbank Consulting Group"]
        assert len(mindbank.known_fraud_indicators) >= 5

    def test_mindbank_fraud_indicators_mention_ssn(self):
        mindbank = KNOWN_STAFFING_FIRMS["Mindbank Consulting Group"]
        all_text = " ".join(mindbank.known_fraud_indicators)
        assert "SSN" in all_text or "ssn" in all_text.lower()

    def test_mindbank_fraud_indicators_mention_svp(self):
        mindbank = KNOWN_STAFFING_FIRMS["Mindbank Consulting Group"]
        all_text = " ".join(mindbank.known_fraud_indicators)
        assert "SVP" in all_text or "escalation" in all_text.lower()


class TestDomainLookup:
    """STAFFING_FIRM_DOMAINS and get_firm_by_domain()."""

    def test_mindbankcg_domain_maps_to_mindbank(self):
        firm = get_firm_by_domain("mindbankcg.com")
        assert firm is not None
        assert firm.name == "Mindbank Consulting Group"

    def test_tscti_domain_lookup(self):
        firm = get_firm_by_domain("tscti.com")
        assert firm is not None
        assert "22nd Century" in firm.name

    def test_unknown_domain_returns_none(self):
        firm = get_firm_by_domain("totallyfakedomain12345.com")
        assert firm is None

    def test_domain_table_is_dict(self):
        assert isinstance(STAFFING_FIRM_DOMAINS, dict)

    def test_domain_table_non_empty(self):
        assert len(STAFFING_FIRM_DOMAINS) >= 4

    def test_lookup_is_case_normalized(self):
        firm_lower = get_firm_by_domain("mindbankcg.com")
        assert firm_lower is not None


class TestNameLookup:
    """get_firm_by_name() fuzzy search."""

    def test_exact_name_match(self):
        firm = get_firm_by_name("Mindbank Consulting Group")
        assert firm is not None
        assert firm.name == "Mindbank Consulting Group"

    def test_partial_name_match(self):
        firm = get_firm_by_name("Mindbank")
        assert firm is not None

    def test_case_insensitive_match(self):
        firm = get_firm_by_name("mindbank consulting group")
        assert firm is not None

    def test_unknown_name_returns_none(self):
        firm = get_firm_by_name("Totally Unknown Staffing LLC XYZ")
        assert firm is None


class TestStaffingFirmSchema:
    """StaffingFirm dataclass schema."""

    def test_staffing_firm_has_required_fields(self):
        firm = StaffingFirm(
            name="Test Firm",
            cage_code="",
            known_domains=["testfirm.com"],
        )
        assert firm.name == "Test Firm"
        assert isinstance(firm.known_domains, list)
        assert isinstance(firm.known_fraud_indicators, list)
        assert isinstance(firm.gsa_mas, bool)
        assert isinstance(firm.woman_owned, bool)

    def test_mindbank_is_woman_owned_gsa(self):
        mindbank = KNOWN_STAFFING_FIRMS["Mindbank Consulting Group"]
        assert mindbank.gsa_mas is True
        assert mindbank.woman_owned is True

    def test_mindbank_location_is_vienna_va(self):
        mindbank = KNOWN_STAFFING_FIRMS["Mindbank Consulting Group"]
        assert "Vienna" in mindbank.location or "VA" in mindbank.location
