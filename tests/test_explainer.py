"""Tests for scoring/explainer.py — CFR citation mapper."""
import pytest
from clearance_fraud_detector.scoring.explainer import (
    CITATION_TABLE,
    PATTERN_TO_CITATION,
    CATEGORY_TO_CITATION,
    Explanation,
    ExplainerReport,
    explain_patterns,
    explain_categories,
    explain_combined,
    lookup_citation,
)


class TestCitationTable:
    """CITATION_TABLE structure and completeness."""

    def test_all_seven_citations_present(self):
        expected = {
            "117.10(a)(5)", "117.10(a)(7)", "117.10(d)",
            "117.10(f)(1)(i)", "117.10(f)(1)(ii)", "117.10(h)", "privacy_act",
        }
        assert set(CITATION_TABLE.keys()) == expected

    def test_each_citation_has_required_fields(self):
        required = {"rule", "url", "verbatim", "plain_english",
                    "correct_process", "response_script", "report_to", "keywords"}
        for key, data in CITATION_TABLE.items():
            missing = required - set(data.keys())
            assert not missing, f"{key} is missing fields: {missing}"

    def test_verbatim_text_is_non_empty(self):
        for key, data in CITATION_TABLE.items():
            assert len(data["verbatim"]) > 30, f"{key} verbatim text too short"

    def test_ecfr_url_present_for_cfr_entries(self):
        cfr_keys = [k for k in CITATION_TABLE if k != "privacy_act"]
        for key in cfr_keys:
            assert "ecfr.gov" in CITATION_TABLE[key]["url"], f"{key} missing ecfr.gov URL"

    def test_a7_response_script_mentions_117_10_a_7(self):
        script = CITATION_TABLE["117.10(a)(7)"]["response_script"]
        assert "117.10(a)(7)" in script

    def test_d_verbatim_mentions_eqip(self):
        assert "e-QIP" in CITATION_TABLE["117.10(d)"]["verbatim"]

    def test_h_verbatim_covers_both_h1_and_h2(self):
        verbatim = CITATION_TABLE["117.10(h)"]["verbatim"]
        assert "(h)(1)" in verbatim
        assert "(h)(2)" in verbatim


class TestPatternToCitation:
    """PATTERN_TO_CITATION mapping completeness."""

    def test_ssn_request_maps_to_a7_and_d(self):
        cits = PATTERN_TO_CITATION["ssn_request"]
        assert "117.10(a)(7)" in cits
        assert "117.10(d)" in cits

    def test_self_attestation_maps_to_a7_and_h(self):
        cits = PATTERN_TO_CITATION["clearance_self_attestation_request"]
        assert "117.10(a)(7)" in cits
        assert "117.10(h)" in cits

    def test_suffice_clearance_maps_to_a7(self):
        cits = PATTERN_TO_CITATION["suffice_the_clearance_language"]
        assert "117.10(a)(7)" in cits

    def test_dod_safe_maps_to_d(self):
        cits = PATTERN_TO_CITATION["dod_safe_ssn_channel"]
        assert "117.10(d)" in cits

    def test_offer_conditioned_maps_to_d_and_f(self):
        cits = PATTERN_TO_CITATION["offer_conditioned_on_ssn"]
        assert "117.10(d)" in cits
        assert "117.10(f)(1)(i)" in cits

    def test_all_citation_keys_valid(self):
        valid_keys = set(CITATION_TABLE.keys())
        for pattern_name, keys in PATTERN_TO_CITATION.items():
            for k in keys:
                assert k in valid_keys, f"{pattern_name} → {k} not in CITATION_TABLE"


class TestCategoryToCitation:
    """CATEGORY_TO_CITATION mapping."""

    def test_non_employee_check_maps_to_a7(self):
        assert "117.10(a)(7)" in CATEGORY_TO_CITATION["non_employee_check"]

    def test_cache_building_maps_to_a5(self):
        assert "117.10(a)(5)" in CATEGORY_TO_CITATION["cache_building"]

    def test_unauthorized_channel_maps_to_d(self):
        assert "117.10(d)" in CATEGORY_TO_CITATION["unauthorized_channel"]

    def test_reciprocity_ignored_maps_to_h(self):
        assert "117.10(h)" in CATEGORY_TO_CITATION["reciprocity_ignored"]

    def test_self_attestation_category_maps_to_a7_and_h(self):
        cits = CATEGORY_TO_CITATION["self_attestation_clearance"]
        assert "117.10(a)(7)" in cits
        assert "117.10(h)" in cits

    def test_all_category_keys_valid(self):
        valid_keys = set(CITATION_TABLE.keys())
        for cat, keys in CATEGORY_TO_CITATION.items():
            for k in keys:
                assert k in valid_keys, f"category:{cat} → {k} not in CITATION_TABLE"


class TestExplainPatterns:
    """explain_patterns() behavior."""

    def test_ssn_request_returns_explanation(self):
        report = explain_patterns(["ssn_request"])
        assert len(report.explanations) >= 1

    def test_unknown_pattern_returns_empty(self):
        report = explain_patterns(["totally_unknown_pattern"])
        assert report.explanations == []

    def test_empty_list_returns_empty(self):
        report = explain_patterns([])
        assert report.explanations == []

    def test_multiple_patterns_deduplicated(self):
        # Both ssn_request and dod_safe_ssn_channel map to 117.10(d)
        report = explain_patterns(["ssn_request", "dod_safe_ssn_channel"])
        # Should not have duplicate 117.10(d) explanation
        rules = [e.rule for e in report.explanations]
        assert len(rules) == len(set(rules)), "Duplicate explanations found"

    def test_tscti_pattern_returns_a7_and_h(self):
        report = explain_patterns(["clearance_self_attestation_request"])
        rules = [e.rule for e in report.explanations]
        assert any("117.10(a)(7)" in r for r in rules)
        assert any("117.10(h)" in r for r in rules)

    def test_reporting_agencies_populated(self):
        report = explain_patterns(["ssn_request"])
        assert len(report.reporting_agencies) >= 1

    def test_response_scripts_populated(self):
        report = explain_patterns(["ssn_request"])
        assert len(report.response_scripts) >= 1


class TestExplainCategories:
    """explain_categories() behavior."""

    def test_non_employee_check_returns_a7(self):
        report = explain_categories(["non_employee_check"])
        rules = [e.rule for e in report.explanations]
        assert any("117.10(a)(7)" in r for r in rules)

    def test_multiple_categories_deduplicated(self):
        report = explain_categories(["non_employee_check", "pre_offer_action"])
        rules = [e.rule for e in report.explanations]
        assert len(rules) == len(set(rules))

    def test_all_eight_categories_accepted(self):
        all_cats = list(CATEGORY_TO_CITATION.keys())
        report = explain_categories(all_cats)
        assert len(report.explanations) >= 5


class TestExplainCombined:
    """explain_combined() behavior."""

    def test_combines_patterns_and_categories(self):
        report = explain_combined(
            pattern_names=["dod_safe_ssn_channel"],
            category_names=["cache_building"],
        )
        rules = [e.rule for e in report.explanations]
        # §117.10(a)(5) from cache_building, §117.10(d) from dod_safe
        assert any("117.10(a)(5)" in r for r in rules)
        assert any("117.10(d)" in r for r in rules)

    def test_triggered_by_includes_prefix(self):
        report = explain_combined(
            pattern_names=["ssn_request"],
            category_names=["non_employee_check"],
        )
        # triggered_by entries should use prefix: or category: form
        all_triggers = [t for e in report.explanations for t in e.triggered_by]
        assert any("pattern:" in t or "category:" in t for t in all_triggers)


class TestLookupCitation:
    """lookup_citation() direct access."""

    def test_exact_key_returns_data(self):
        data = lookup_citation("117.10(a)(7)")
        assert data is not None
        assert "verbatim" in data

    def test_partial_key_returns_data(self):
        data = lookup_citation("117.10(d)")
        assert data is not None

    def test_unknown_key_returns_none(self):
        result = lookup_citation("totally_unknown_key_xyz")
        assert result is None

    def test_privacy_act_lookup(self):
        data = lookup_citation("privacy_act")
        assert data is not None
        assert "552a" in data["verbatim"] or "Privacy Act" in data["rule"]


class TestExplainerReportRender:
    """ExplainerReport.render() output format."""

    def test_render_empty_report(self):
        report = ExplainerReport()
        output = report.render()
        assert "No regulatory violations" in output

    def test_render_includes_rule_text(self):
        report = explain_patterns(["ssn_request"])
        output = report.render()
        assert "§117.10" in output

    def test_render_includes_verbatim_section(self):
        report = explain_patterns(["ssn_request"])
        output = report.render()
        assert "VERBATIM TEXT:" in output

    def test_render_includes_response_script(self):
        report = explain_patterns(["ssn_request"])
        output = report.render()
        assert "WHAT TO SAY:" in output

    def test_render_includes_reporting_agencies(self):
        report = explain_patterns(["ssn_request"])
        output = report.render()
        assert "REPORT TO:" in output

    def test_render_includes_correct_process(self):
        report = explain_patterns(["ssn_request"])
        output = report.render()
        assert "CORRECT PROCESS:" in output
