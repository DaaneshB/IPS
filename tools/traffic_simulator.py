#!/usr/bin/env python3
"""Replay benign and malicious traffic through the real IPS detection pipeline.

This simulator exists so the IPS can be demonstrated live without root
privileges, a network interface in promiscuous mode, or real attack traffic.
It does NOT fake detections: every payload is passed through the same
PatternMatcher, ThresholdTracker, PerformanceMetrics and log_event() code
paths the packet sniffer uses in production. Only the capture layer (scapy)
and the firewall layer (iptables/netsh) are bypassed, because a demo must not
require raw sockets or mutate the host firewall. Block decisions are still
made by the real sliding-window threshold logic; they are recorded as BLOCK
log events tagged "(simulated)" instead of installing firewall rules.

Usage:
    python tools/traffic_simulator.py --rate 5 --duration 120 --attack-ratio 0.3
"""
from __future__ import annotations

import argparse
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

# A handful of stable source addresses so per-IP behaviour (repeat offenders
# crossing the block threshold) is visible in the logs, plus random ones for
# variety. All addresses come from RFC 5737 documentation ranges so simulated
# logs can never be mistaken for, or collide with, real hosts.
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


class TrafficSimulator:
    """Generates a mixed benign/malicious event stream.

    Kept free of I/O and sleeps so tests can drive it deterministically with
    a seeded RNG.
    """

    def __init__(self, rules: list[dict], attack_ratio: float = 0.3, seed: int | None = None) -> None:
        if not 0.0 <= attack_ratio <= 1.0:
            raise ValueError("attack_ratio must be between 0 and 1")
        self.rules = rules
        self.attack_ratio = attack_ratio
        self.rng = random.Random(seed)

    def next_event(self) -> tuple[str, str, int, bool]:
        """Return (payload, src_ip, dst_port, is_attack) for one simulated packet."""
        if self.rng.random() < self.attack_ratio:
            rule = self.rng.choice(self.rules)
            payload, port = build_attack_payload(rule, self.rng)
            # Repeat offenders dominate so threshold blocking triggers visibly.
            src_ip = self.rng.choice(ATTACKER_POOL) if self.rng.random() < 0.7 else random_ip(self.rng)
            return payload, src_ip, port, True
        payload = self.rng.choice(BENIGN_PAYLOADS)
        return payload, random_ip(self.rng), 80, False


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--rate", type=float, default=4.0, help="events per second (default 4)")
    parser.add_argument("--duration", type=float, default=0, help="seconds to run; 0 = until Ctrl+C")
    parser.add_argument("--attack-ratio", type=float, default=0.3, help="fraction of events that are attacks")
    parser.add_argument("--seed", type=int, default=None, help="RNG seed for reproducible runs")
    parser.add_argument("--log-file", default=None, help="override log path (default: config LOG_FILE)")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    args = parse_args(argv)

    # config reads IPS_LOG_FILE from the environment at import time, so the
    # override must be exported before the first Configurations import.
    if args.log_file:
        os.environ["IPS_LOG_FILE"] = args.log_file

    import Configurations.config as config
    from Handling.matcher import PatternMatcher
    from Handling.metrics import PerformanceMetrics, ThresholdTracker
    from Handling.post_detection import log_event

    matcher = PatternMatcher(config.RULES)
    tracker = ThresholdTracker()
    metrics = PerformanceMetrics()
    sim = TrafficSimulator(config.RULES, attack_ratio=args.attack_ratio, seed=args.seed)
    simulated_blocks: set[str] = set()

    log_event(
        f"Traffic simulator started | rate={args.rate}/s attack_ratio={args.attack_ratio}",
        event_type="INFO",
    )

    interval = 1.0 / args.rate if args.rate > 0 else 0.25
    start = time.time()
    try:
        while True:
            if args.duration and time.time() - start >= args.duration:
                break
            payload, src_ip, port, _ = sim.next_event()
            matched, detection_time = matcher.find_matches(payload, port)
            metrics.record_packet(detection_time)

            if matched:
                log_event(
                    f"Detected {matched['name']} from {src_ip}:{port} in {detection_time*1000:.2f}ms",
                    event_type="ALERT",
                    src_ip=src_ip,
                    attack_type=matched["name"],
                    port=port,
                    response_time=detection_time,
                )
                # Same threshold decision the sniffer makes; only the firewall
                # side effect is replaced with a log record.
                if src_ip not in simulated_blocks and tracker.should_block(src_ip):
                    simulated_blocks.add(src_ip)
                    log_event(
                        f"Blocked IP: {src_ip} (simulated)",
                        event_type="BLOCK",
                        src_ip=src_ip,
                        attack_type=matched["name"],
                        port=port,
                        response_time=detection_time,
                    )
            time.sleep(interval)
    except KeyboardInterrupt:
        pass
    finally:
        stats = metrics.get_stats()
        log_event(
            f"Traffic simulator stopped. Simulated blocks: {len(simulated_blocks)} | Stats: {stats}",
            event_type="INFO",
        )


if __name__ == "__main__":
    main()
