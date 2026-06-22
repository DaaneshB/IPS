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


def follow(path: str, poll_interval: float = 0.5) -> Iterator[dict]:
    """Yield parsed events as they are appended to the log (like `tail -f`).

    Implemented with polling rather than inotify so it behaves identically on
    Linux, macOS and Windows — the same platforms the IPS firewall backends
    already support. Handles the file not existing yet (dashboard started
    before the IPS/simulator) and truncation/rotation (size shrinks -> seek
    back to the start).
    """
    import os
    import time

    position = 0
    while True:
        try:
            size = os.path.getsize(path)
        except OSError:
            time.sleep(poll_interval)
            continue

        if size < position:  # rotated or truncated
            position = 0

        if size > position:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                f.seek(position)
                for line in f:
                    parsed = parse_line(line)
                    if parsed:
                        yield parsed
                position = f.tell()
        time.sleep(poll_interval)


def aggregate(events: list[dict], timeline_bucket_seconds: int = 60) -> dict:
    """Reduce a list of parsed events to the aggregates the dashboard renders.

    Aggregation lives server-side (not in the browser) so the stats endpoint
    stays cheap to render for any client and the numbers are computed in one
    audited place.
    """
    by_type: dict[str, int] = {}
    by_attack: dict[str, int] = {}
    source_counts: dict[str, int] = {}
    blocked_ips: dict[str, str] = {}
    timeline: dict[str, dict[str, int]] = {}
    response_times: list[float] = []

    for ev in events:
        by_type[ev["event_type"]] = by_type.get(ev["event_type"], 0) + 1

        if ev["event_type"] == "ALERT":
            if ev["attack"]:
                by_attack[ev["attack"]] = by_attack.get(ev["attack"], 0) + 1
            if ev["src_ip"]:
                source_counts[ev["src_ip"]] = source_counts.get(ev["src_ip"], 0) + 1
            if ev["response_time_ms"] is not None:
                response_times.append(ev["response_time_ms"])

        if ev["event_type"] == "BLOCK" and ev["src_ip"]:
            blocked_ips[ev["src_ip"]] = ev["timestamp"]

        bucket_epoch = int(ev["epoch"] // timeline_bucket_seconds) * timeline_bucket_seconds
        bucket_key = datetime.fromtimestamp(bucket_epoch).strftime("%H:%M")
        bucket = timeline.setdefault(bucket_key, {"total": 0, "alerts": 0})
        bucket["total"] += 1
        if ev["event_type"] == "ALERT":
            bucket["alerts"] += 1

    top_sources = sorted(source_counts.items(), key=lambda kv: kv[1], reverse=True)[:10]

    return {
        "total_events": len(events),
        "by_type": by_type,
        "by_attack": by_attack,
        "top_sources": [{"ip": ip, "alerts": n} for ip, n in top_sources],
        "blocked_ips": [{"ip": ip, "blocked_at": ts} for ip, ts in blocked_ips.items()],
        "timeline": [
            {"time": k, **v} for k, v in sorted(timeline.items())
        ],
        "avg_response_ms": round(sum(response_times) / len(response_times), 3) if response_times else 0,
    }
