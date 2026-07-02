"""Run synthetic, user-supplied payloads through the real IPS detection path.

The dashboard's injection panel lets an analyst type (or pick) a request
payload and feed it to the IPS live. This module is what actually handles it:
it runs the payload through the **production** PatternMatcher and, when a
detection repeats past the configured threshold, the production
ThresholdTracker — the exact classes the sniffer uses. Matches are written
with log_event(), so an injected request flows straight into the same log the
live feed tails and appears on the dashboard in real time.

Deliberate boundary: injection is *input* to the detection pipeline, never
*control* over it. It cannot change a rule, a mode, or a firewall entry, and
it never calls the real iptables/netsh backend — a threshold breach is logged
as a BLOCK tagged "(injected)", exactly as the offline simulator does. So the
dashboard still cannot alter IPS state or block a real host; it can only
submit test traffic for inspection.
"""
from __future__ import annotations

import ipaddress
import random
from typing import Any, Optional

import Configurations.config as config
from Handling.matcher import PatternMatcher
from Handling.metrics import ThresholdTracker
from Handling.post_detection import log_event

# One matcher/tracker for the process, built from the same rules the IPS runs.
# Rebuilding per request would throw away threshold state (so repeated injects
# from one source could never demonstrate a block) and re-compile the
# automaton needlessly.
_matcher = PatternMatcher(config.RULES)
_tracker = ThresholdTracker()

MAX_PAYLOAD_BYTES = 8192


class InjectionError(ValueError):
    """Raised when an injection request is malformed. Carries a safe message."""


def _synthetic_ip() -> str:
    """A random RFC 5737 documentation IP, used when the caller gives none."""
    block = random.choice(["203.0.113", "198.51.100", "192.0.2"])
    return f"{block}.{random.randint(1, 254)}"


def _validate(payload: Any, port: Any, src_ip: Any) -> tuple[str, int, str]:
    if not isinstance(payload, str) or not payload.strip():
        raise InjectionError("payload must be a non-empty string")
    if len(payload.encode("utf-8", errors="ignore")) > MAX_PAYLOAD_BYTES:
        raise InjectionError(f"payload exceeds {MAX_PAYLOAD_BYTES} bytes")

    try:
        port_int = int(port)
    except (TypeError, ValueError):
        raise InjectionError("port must be an integer")
    if not 1 <= port_int <= 65535:
        raise InjectionError("port must be between 1 and 65535")

    if src_ip in (None, ""):
        ip_str = _synthetic_ip()
    else:
        try:
            ip_str = str(ipaddress.ip_address(str(src_ip)))
        except ValueError:
            raise InjectionError("src_ip must be a valid IP address")

    return payload, port_int, ip_str


def inject(payload: str, port: int, src_ip: Optional[str] = None) -> dict:
    """Feed one synthetic request through the real matcher and log the result.

    Returns a result dict describing what the IPS did — matched signature (if
    any), detection latency, and whether the threshold produced a (simulated)
    block — so the panel can echo it back to the analyst immediately, while
    the logged event also reaches the live feed over SSE.
    """
    payload, port, src_ip = _validate(payload, port, src_ip)

    matched_rule, detection_time = _matcher.find_matches(payload, port)

    result: dict[str, Any] = {
        "src_ip": src_ip,
        "port": port,
        "matched": None,
        "detection_ms": round(detection_time * 1000, 3),
        "blocked": False,
    }

    if not matched_rule:
        log_event(
            f"Injected request from {src_ip}:{port} matched no signature",
            event_type="INFO",
            src_ip=src_ip,
            port=port,
        )
        return result

    result["matched"] = matched_rule["name"]
    log_event(
        f"Detected {matched_rule['name']} from {src_ip}:{port} in {detection_time*1000:.2f}ms (injected)",
        event_type="ALERT",
        src_ip=src_ip,
        attack_type=matched_rule["name"],
        port=port,
        response_time=detection_time,
    )

    if src_ip not in config.ALLOWED_IPS and config.MODE == "block" and _tracker.should_block(src_ip):
        result["blocked"] = True
        log_event(
            f"Blocked IP: {src_ip} (injected)",
            event_type="BLOCK",
            src_ip=src_ip,
            attack_type=matched_rule["name"],
            port=port,
            response_time=detection_time,
        )

    return result


def monitored_ports() -> list[int]:
    """Ports the loaded signatures actually cover — populates the port picker."""
    return list(config.MONITORED_PORTS)


def attack_presets(limit: int = 6) -> list[dict]:
    """A few ready-to-inject example requests derived from the real rules.

    Presets are built from live signatures (not hand-typed in the frontend)
    so a preset can never drift out of sync with the rule set: every attack
    preset here is guaranteed to trip a real detection. A benign preset is
    included so the analyst can also demonstrate a clean pass.
    """
    presets: list[dict] = [{
        "label": "Benign request",
        "payload": "GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n",
        "port": 80,
        "attack": False,
    }]

    for rule in config.RULES[:limit]:
        port = rule["ports"][0]
        pattern = rule["pattern"]
        if port in (80, 8080, 443):
            payload = (f"GET /search?q={pattern} HTTP/1.1\r\n"
                       f"Host: example.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n")
        else:
            payload = f"{pattern}\r\n"
        presets.append({"label": rule["name"], "payload": payload, "port": port, "attack": True})

    return presets
