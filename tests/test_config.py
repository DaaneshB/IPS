"""Tests for the configuration and rule loader."""
import json

import pytest

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


def test_missing_file_raises(tmp_path):
    with pytest.raises(RuntimeError, match="not found"):
        config.load_rules(str(tmp_path / "nope.json"))


def test_invalid_json_raises(tmp_path):
    bad = tmp_path / "rules.json"
    bad.write_text("{not valid json")
    with pytest.raises(RuntimeError, match="invalid JSON"):
        config.load_rules(str(bad))


def test_empty_rules_raises(tmp_path):
    empty = tmp_path / "rules.json"
    empty.write_text("[]")
    with pytest.raises(RuntimeError, match="no signatures"):
        config.load_rules(str(empty))


def test_rule_missing_keys_raises(tmp_path):
    f = tmp_path / "rules.json"
    f.write_text(json.dumps([{"name": "x", "pattern": "y"}]))
    with pytest.raises(RuntimeError, match="missing keys"):
        config.load_rules(str(f))


def test_rule_empty_pattern_raises(tmp_path):
    f = tmp_path / "rules.json"
    f.write_text(json.dumps([{"name": "x", "pattern": "", "ports": [80]}]))
    with pytest.raises(RuntimeError, match="empty pattern"):
        config.load_rules(str(f))
