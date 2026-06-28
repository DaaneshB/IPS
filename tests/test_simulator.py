"""Tests for the demo traffic simulator."""
import random

import Configurations.config as config
from tools.traffic_simulator import (
    TrafficSimulator,
    build_attack_payload,
    random_ip,
)


def test_random_ip_stays_in_documentation_ranges():
    rng = random.Random(0)
    for _ in range(50):
        ip = random_ip(rng)
        assert ip.startswith(("203.0.113.", "198.51.100.", "192.0.2."))


def test_attack_payload_embeds_signature_on_a_rule_port():
    rng = random.Random(1)
    for rule in config.RULES:
        payload, port = build_attack_payload(rule, rng)
        assert rule["pattern"] in payload
        assert port in rule["ports"]


def test_simulator_rejects_invalid_attack_ratio():
    import pytest
    with pytest.raises(ValueError):
        TrafficSimulator(config.RULES, attack_ratio=1.5)


def test_seeded_simulator_is_reproducible():
    a = TrafficSimulator(config.RULES, attack_ratio=0.5, seed=42)
    b = TrafficSimulator(config.RULES, attack_ratio=0.5, seed=42)
    assert [a.next_event() for _ in range(20)] == [b.next_event() for _ in range(20)]


def test_attack_ratio_shapes_event_mix():
    sim = TrafficSimulator(config.RULES, attack_ratio=0.5, seed=7)
    attacks = sum(1 for _ in range(400) if sim.next_event()[3])
    assert 140 <= attacks <= 260  # ~50% with generous tolerance


def test_attack_events_are_detected_by_the_real_matcher():
    """Every simulated attack must trip the production matcher.

    This is the property that makes the demo honest: if a generated attack
    payload ever failed to match, the simulator would be showing traffic the
    real IPS could not catch.
    """
    from Handling.matcher import PatternMatcher

    matcher = PatternMatcher(config.RULES)
    sim = TrafficSimulator(config.RULES, attack_ratio=1.0, seed=3)
    for _ in range(100):
        payload, _, port, is_attack = sim.next_event()
        assert is_attack
        matched, _ = matcher.find_matches(payload, port)
        assert matched is not None


def test_end_to_end_run_writes_parseable_log(tmp_path, monkeypatch):
    """main() must produce a log the dashboard parser can read back."""
    import Handling.post_detection as pd
    from dashboard import log_reader
    from tools import traffic_simulator

    log_file = tmp_path / "sim.log"
    monkeypatch.setattr(pd, "LOG_FILE", str(log_file))

    traffic_simulator.main(["--rate", "50", "--duration", "1", "--seed", "9"])

    events = log_reader.read_events(str(log_file))
    assert events, "simulator wrote no parseable events"
    types = {e["event_type"] for e in events}
    assert "INFO" in types and "ALERT" in types
    for e in events:
        if e["event_type"] == "ALERT":
            assert e["src_ip"] and e["attack"] and e["port"]
