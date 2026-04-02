"""Tests for the PatternMatcher detection engine.

These exercise whichever backend is installed (Aho-Corasick when available,
otherwise the naive fallback); both must satisfy the same contract.
"""
from Handling.matcher import PatternMatcher

RULES = [
    {"name": "SQLi", "pattern": "UNION SELECT", "ports": [80, 443]},
    {"name": "XSS", "pattern": "<script>", "ports": [80]},
]


def test_match_returns_rule_and_time():
    m = PatternMatcher(RULES)
    rule, elapsed = m.find_matches("GET /?q=UNION SELECT 1", 80)
    assert rule["name"] == "SQLi"
    assert elapsed >= 0


def test_no_match_returns_none():
    m = PatternMatcher(RULES)
    rule, elapsed = m.find_matches("perfectly benign payload", 80)
    assert rule is None
    assert elapsed >= 0


def test_pattern_present_but_wrong_port_does_not_match():
    m = PatternMatcher(RULES)
    # <script> is only registered for port 80, not 22.
    rule, _ = m.find_matches("<script>alert(1)</script>", 22)
    assert rule is None


def test_pattern_matches_on_any_listed_port():
    m = PatternMatcher(RULES)
    rule, _ = m.find_matches("UNION SELECT password", 443)
    assert rule["name"] == "SQLi"


def test_matching_is_case_insensitive():
    m = PatternMatcher(RULES)
    for payload in ("union select 1", "UnIoN sElEcT 1", "UNION SELECT 1"):
        rule, _ = m.find_matches(payload, 80)
        assert rule is not None and rule["name"] == "SQLi"


def test_returns_earliest_ending_match_when_multiple_present():
    rules = [
        {"name": "late", "pattern": "second", "ports": [80]},
        {"name": "early", "pattern": "first", "ports": [80]},
    ]
    m = PatternMatcher(rules)
    rule, _ = m.find_matches("the first then the second", 80)
    assert rule["name"] == "early"


def test_empty_pattern_never_matches():
    rules = [{"name": "empty", "pattern": "", "ports": [80]}]
    m = PatternMatcher(rules)
    rule, _ = m.find_matches("any payload at all", 80)
    assert rule is None


def test_on_error_callback_invoked_and_swallowed():
    errors = []
    m = PatternMatcher(RULES, on_error=errors.append)
    # A non-string payload raises inside find_matches; it must not propagate.
    rule, elapsed = m.find_matches(12345, 80)
    assert rule is None
    assert elapsed >= 0
    assert len(errors) == 1
    assert "pattern matching" in errors[0].lower()
