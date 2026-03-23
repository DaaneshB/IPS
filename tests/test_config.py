"""Tests for the configuration and rule loader."""
import Configurations.config as config


def test_default_rules_load_and_are_nonempty():
    rules = config.load_rules()
    assert isinstance(rules, list)
    assert len(rules) > 0


def test_every_rule_has_required_shape():
    for rule in config.load_rules():
        assert set(rule) >= {"name", "pattern", "ports"}
        assert rule["name"]
        assert rule["pattern"]
        assert isinstance(rule["ports"], list) and rule["ports"]


def test_rules_constant_matches_loader():
    assert config.RULES == config.load_rules()
