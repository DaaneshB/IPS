#!/usr/bin/env python3
"""Replay benign and malicious traffic through the real IPS detection pipeline.

This simulator exists so the IPS can be demonstrated live without root
privileges, a network interface in promiscuous mode, or real attack traffic.
It does NOT fake detections: every payload is passed through the same
PatternMatcher and log_event() code paths the packet sniffer uses in
production. Only the capture layer (scapy) and the firewall layer (iptables/
netsh) are bypassed, because a demo must not require raw sockets or mutate
the host firewall.
"""
from __future__ import annotations

import os
import random
import sys
import time

# Allow running as `python tools/traffic_simulator.py` from the repo root.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

BENIGN_PAYLOADS = [
    "GET /index.html HTTP/1.1\r\nHost: shop.example.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n",
    "GET /api/v1/products?page=2 HTTP/1.1\r\nHost: shop.example.com\r\nAccept: application/json\r\n\r\n",
    "POST /login HTTP/1.1\r\nHost: shop.example.com\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nuser=alice&pass=hunter2",
    "SSH-2.0-OpenSSH_9.6\r\n",
    "EHLO mail.example.com\r\n",
    "USER anonymous\r\n",
    "GET /static/logo.png HTTP/1.1\r\nHost: shop.example.com\r\n\r\n",
    "POST /api/v1/cart HTTP/1.1\r\nHost: shop.example.com\r\nContent-Type: application/json\r\n\r\n{\"item\": 42, \"qty\": 1}",
]

# A handful of stable source addresses so per-IP behaviour (repeat offenders)
# is visible in the logs, plus random ones for variety.
ATTACKER_POOL = ["203.0.113.7", "198.51.100.23", "192.0.2.99"]


def random_ip(rng: random.Random) -> str:
    """Random documentation-range IP (RFC 5737) so logs never show real hosts."""
    block = rng.choice(["203.0.113", "198.51.100", "192.0.2"])
    return f"{block}.{rng.randint(1, 254)}"


def build_attack_payload(rule: dict, rng: random.Random) -> tuple[str, int]:
    """Embed a rule's signature into a realistic request for one of its ports."""
    pattern = rule["pattern"]
    port = rng.choice(rule["ports"])
    if port in (80, 8080, 443):
        payload = (
            f"GET /search?q={pattern} HTTP/1.1\r\n"
            f"Host: shop.example.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n"
        )
    else:
        payload = f"{pattern}\r\n"
    return payload, port


def main() -> None:
    import Configurations.config as config
    from Handling.matcher import PatternMatcher
    from Handling.post_detection import log_event

    rng = random.Random()
    matcher = PatternMatcher(config.RULES)

    log_event("Traffic simulator started", event_type="INFO")
    while True:
        if rng.random() < 0.3:
            rule = rng.choice(config.RULES)
            payload, port = build_attack_payload(rule, rng)
            src_ip = rng.choice(ATTACKER_POOL)
        else:
            payload = rng.choice(BENIGN_PAYLOADS)
            port, src_ip = 80, random_ip(rng)

        matched, detection_time = matcher.find_matches(payload, port)
        if matched:
            log_event(
                f"Detected {matched['name']} from {src_ip}:{port} in {detection_time*1000:.2f}ms",
                event_type="ALERT",
                src_ip=src_ip,
                attack_type=matched["name"],
                port=port,
                response_time=detection_time,
            )
        time.sleep(0.5)


if __name__ == "__main__":
    main()
