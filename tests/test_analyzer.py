"""
Unit tests for the DLP Presidio Analyzer (scanner/analyzer.py).
"""

import pytest

from scanner.analyzer import DLPAnalyzer, Match, load_analyzer


# ---------------------------------------------------------------------------
# Shared test policies
# ---------------------------------------------------------------------------

TEST_POLICIES = {
    "rules": [
        {
            "id": "EMP_ID",
            "name": "Employee ID",
            "type": "regex",
            "pattern": r"EMP-\d{6}",
            "severity": "HIGH",
            "action": "BLOCK",
        },
        {
            "id": "SSN",
            "name": "Social Security Number",
            "type": "regex",
            "pattern": r"\b\d{3}-\d{2}-\d{4}\b",
            "severity": "CRITICAL",
            "action": "BLOCK",
        },
        {
            "id": "CREDIT_CARD",
            "name": "Credit Card Number",
            "type": "presidio_builtin",
            "entity": "CREDIT_CARD",
            "severity": "CRITICAL",
            "action": "BLOCK",
        },
        {
            "id": "KEYWORD_CONFIDENTIAL",
            "name": "Confidential Keyword",
            "type": "keyword",
            "keywords": [
                "STRICTLY CONFIDENTIAL",
                "INTERNAL ONLY",
                "DO NOT DISTRIBUTE",
            ],
            "case_sensitive": False,
            "severity": "MEDIUM",
            "action": "BLOCK",
        },
    ],
    "scan_settings": {
        "confidence_threshold": 0.7,
    },
}


@pytest.fixture
def analyzer() -> DLPAnalyzer:
    """Create a DLPAnalyzer with the standard test policies."""
    return DLPAnalyzer(policies=TEST_POLICIES, confidence_threshold=0.7)


# ---------------------------------------------------------------------------
# Regex rule tests
# ---------------------------------------------------------------------------

class TestRegexRules:
    def test_employee_id_detected(self, analyzer: DLPAnalyzer):
        """EMP-123456 pattern should be detected."""
        matches = analyzer.analyze("Employee record: EMP-123456, name: John Doe")
        emp_matches = [m for m in matches if m.rule_id == "EMP_ID"]
        assert len(emp_matches) >= 1
        assert all(m.score >= 0.7 for m in emp_matches)

    def test_multiple_employee_ids(self, analyzer: DLPAnalyzer):
        """Multiple EMP IDs in the same text should all be found."""
        text = "Team: EMP-111111, EMP-222222, EMP-333333"
        matches = analyzer.analyze(text)
        emp_matches = [m for m in matches if m.rule_id == "EMP_ID"]
        assert len(emp_matches) == 3

    def test_ssn_detected(self, analyzer: DLPAnalyzer):
        """SSN pattern 123-45-6789 should be detected."""
        matches = analyzer.analyze("SSN: 123-45-6789")
        ssn_matches = [m for m in matches if m.rule_id == "SSN"]
        assert len(ssn_matches) >= 1

    def test_invalid_employee_id_not_detected(self, analyzer: DLPAnalyzer):
        """EMP-12345 (5 digits) should NOT match the 6-digit pattern."""
        matches = analyzer.analyze("Reference: EMP-12345")
        emp_matches = [m for m in matches if m.rule_id == "EMP_ID"]
        assert len(emp_matches) == 0


# ---------------------------------------------------------------------------
# Keyword rule tests
# ---------------------------------------------------------------------------

class TestKeywordRules:
    def test_strictly_confidential_detected(self, analyzer: DLPAnalyzer):
        """STRICTLY CONFIDENTIAL keyword should be found."""
        matches = analyzer.analyze("This is STRICTLY CONFIDENTIAL material.")
        kw_matches = [m for m in matches if m.rule_id == "KEYWORD_CONFIDENTIAL"]
        assert len(kw_matches) >= 1
        assert kw_matches[0].score == 1.0

    def test_keyword_case_insensitive(self, analyzer: DLPAnalyzer):
        """Keywords should match case-insensitively."""
        matches = analyzer.analyze("this document is strictly confidential")
        kw_matches = [m for m in matches if m.rule_id == "KEYWORD_CONFIDENTIAL"]
        assert len(kw_matches) >= 1

    def test_internal_only_detected(self, analyzer: DLPAnalyzer):
        """INTERNAL ONLY keyword should be found."""
        matches = analyzer.analyze("Marked: Internal Only")
        kw_matches = [m for m in matches if m.rule_id == "KEYWORD_CONFIDENTIAL"]
        assert len(kw_matches) >= 1

    def test_do_not_distribute_detected(self, analyzer: DLPAnalyzer):
        """DO NOT DISTRIBUTE keyword should be found."""
        matches = analyzer.analyze("NOTICE: DO NOT DISTRIBUTE this report.")
        kw_matches = [m for m in matches if m.rule_id == "KEYWORD_CONFIDENTIAL"]
        assert len(kw_matches) >= 1


# ---------------------------------------------------------------------------
# Built-in Presidio entity tests
# ---------------------------------------------------------------------------

class TestBuiltinEntities:
    def test_credit_card_detected(self, analyzer: DLPAnalyzer):
        """A Visa test card number should be detected by Presidio."""
        # Use a well-known Visa test number.
        matches = analyzer.analyze("Payment card: 4111111111111111")
        cc_matches = [m for m in matches if m.entity_type == "CREDIT_CARD"]
        assert len(cc_matches) >= 1


# ---------------------------------------------------------------------------
# Clean text (no matches expected)
# ---------------------------------------------------------------------------

class TestCleanText:
    def test_no_matches_on_clean_text(self, analyzer: DLPAnalyzer):
        """Ordinary text should not produce any matches."""
        text = (
            "The quarterly meeting is scheduled for next Thursday. "
            "Please bring your laptop and the project timeline."
        )
        matches = analyzer.analyze(text)
        assert len(matches) == 0

    def test_empty_text_returns_empty(self, analyzer: DLPAnalyzer):
        """Empty text should return no matches."""
        assert analyzer.analyze("") == []

    def test_whitespace_only_returns_empty(self, analyzer: DLPAnalyzer):
        """Whitespace-only text should return no matches."""
        assert analyzer.analyze("   \n\t  ") == []


# ---------------------------------------------------------------------------
# Match object integrity
# ---------------------------------------------------------------------------

class TestMatchIntegrity:
    def test_match_has_no_text_field(self, analyzer: DLPAnalyzer):
        """Match objects must NOT contain the matched text (security)."""
        matches = analyzer.analyze("EMP-123456")
        assert len(matches) >= 1
        for match in matches:
            assert not hasattr(match, "text")
            assert not hasattr(match, "matched_text")
            assert not hasattr(match, "value")

    def test_match_has_required_fields(self, analyzer: DLPAnalyzer):
        """Each Match should have rule_id, entity_type, score, start, end."""
        matches = analyzer.analyze("EMP-123456")
        assert len(matches) >= 1
        m = matches[0]
        assert isinstance(m.rule_id, str)
        assert isinstance(m.entity_type, str)
        assert isinstance(m.score, float)
        assert isinstance(m.start, int)
        assert isinstance(m.end, int)
        assert m.start < m.end


# ---------------------------------------------------------------------------
# Confidence threshold filtering
# ---------------------------------------------------------------------------

class TestThresholdFiltering:
    def test_high_threshold_filters_low_confidence(self):
        """Setting a very high threshold should filter out lower scores."""
        analyzer = DLPAnalyzer(policies=TEST_POLICIES, confidence_threshold=0.99)
        matches = analyzer.analyze("EMP-123456")
        # Regex matches get score=0.85 which is < 0.99 → should be filtered.
        emp_matches = [m for m in matches if m.rule_id == "EMP_ID"]
        assert len(emp_matches) == 0

    def test_zero_threshold_includes_everything(self):
        """Threshold of 0 should include all matches."""
        analyzer = DLPAnalyzer(policies=TEST_POLICIES, confidence_threshold=0.0)
        matches = analyzer.analyze("EMP-123456")
        assert len(matches) >= 1


# ---------------------------------------------------------------------------
# load_analyzer convenience function
# ---------------------------------------------------------------------------

class TestLoadAnalyzer:
    def test_load_from_config_file(self, tmp_path):
        """load_analyzer should work with a valid YAML config file."""
        config = tmp_path / "policies.yaml"
        import yaml
        config.write_text(yaml.dump(TEST_POLICIES), encoding="utf-8")

        analyzer = load_analyzer(str(config))
        matches = analyzer.analyze("EMP-123456")
        assert len(matches) >= 1

    def test_load_missing_file_raises(self):
        """load_analyzer should raise FileNotFoundError for missing files."""
        with pytest.raises(FileNotFoundError):
            load_analyzer("nonexistent/policies.yaml")
