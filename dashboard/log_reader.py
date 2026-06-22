"""Parse the IPS forensic log format produced by Handling.post_detection.log_event.

The dashboard deliberately consumes the same ips_events.log the production
sniffer writes, rather than a separate database or message bus: the log file
is already the system's source of forensic truth, so reading it guarantees
the dashboard shows exactly what the IPS recorded, with zero changes to the
detection pipeline itself.
"""
from __future__ import annotations

import re
from datetime import datetime
from typing import Iterator, Optional

# Matches: [2026-07-03 12:00:00.123] [ALERT] <message and optional fields>
_LINE_RE = re.compile(
    r"^\[(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3})\] \[(?P<type>[A-Z]+)\] (?P<rest>.*)$"
)

# Forensic fields log_event appends as " | KEY: value" suffixes.
_FIELD_KEYS = ("SRC_IP", "ATTACK", "PORT", "RESPONSE_TIME")


def parse_line(line: str) -> Optional[dict]:
    """Parse one log line into a dict, or None if it isn't a log entry.

    Fields are stripped off the *right-hand end* of the line, because the
    free-text message itself may legitimately contain " | " (e.g. the startup
    banner "Mode: block | Threshold: ..."). Scanning from the right and only
    accepting known forensic keys keeps such messages intact.
    """
    m = _LINE_RE.match(line.strip())
    if not m:
        return None

    ts_str = m.group("ts")
    event = {
        "timestamp": ts_str,
        "epoch": datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S.%f").timestamp(),
        "event_type": m.group("type"),
        "src_ip": None,
        "attack": None,
        "port": None,
        "response_time_ms": None,
    }

    segments = m.group("rest").split(" | ")
    while len(segments) > 1:
        key, sep, value = segments[-1].partition(": ")
        if sep and key in _FIELD_KEYS:
            segments.pop()
            if key == "SRC_IP":
                event["src_ip"] = value
            elif key == "ATTACK":
                event["attack"] = value
            elif key == "PORT":
                try:
                    event["port"] = int(value)
                except ValueError:
                    event["port"] = None
            elif key == "RESPONSE_TIME":
                try:
                    event["response_time_ms"] = float(value.rstrip("ms"))
                except ValueError:
                    event["response_time_ms"] = None
        else:
            break

    event["message"] = " | ".join(segments)
    return event


def read_events(path: str, limit: Optional[int] = None) -> list[dict]:
    """Parse a whole log file, skipping malformed lines.

    Args:
        path: log file location.
        limit: if given, only the last `limit` parsed events are returned,
            bounding memory on long-running installations.
    """
    events: list[dict] = []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                parsed = parse_line(line)
                if parsed:
                    events.append(parsed)
    except FileNotFoundError:
        return []
    if limit is not None and len(events) > limit:
        events = events[-limit:]
    return events
