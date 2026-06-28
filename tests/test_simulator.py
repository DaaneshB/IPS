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
