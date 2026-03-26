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
