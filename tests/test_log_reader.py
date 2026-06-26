"""Tests for the dashboard log parser."""
from dashboard import log_reader


ALERT_LINE = (
    "[2026-07-03 12:00:00.123] [ALERT] Detected SQL Injection (Union Based) "
    "from 203.0.113.7:80 in 0.42ms | SRC_IP: 203.0.113.7 "
    "| ATTACK: SQL Injection (Union Based) | PORT: 80 | RESPONSE_TIME: 0.42ms"
)

BLOCK_LINE = (
    "[2026-07-03 12:00:05.500] [BLOCK] Blocked IP: 203.0.113.7 (simulated) "
    "| SRC_IP: 203.0.113.7 | ATTACK: SQL Injection (Union Based) | PORT: 80 "
    "| RESPONSE_TIME: 1.10ms"
)


def test_parse_alert_line_extracts_all_forensic_fields():
    ev = log_reader.parse_line(ALERT_LINE)
    assert ev["event_type"] == "ALERT"
    assert ev["src_ip"] == "203.0.113.7"
    assert ev["attack"] == "SQL Injection (Union Based)"
    assert ev["port"] == 80
    assert ev["response_time_ms"] == 0.42
    assert ev["message"].startswith("Detected SQL Injection")


def test_parse_block_line():
    ev = log_reader.parse_line(BLOCK_LINE)
    assert ev["event_type"] == "BLOCK"
    assert ev["src_ip"] == "203.0.113.7"


def test_parse_info_line_without_optional_fields():
    ev = log_reader.parse_line("[2026-07-03 12:00:00.000] [INFO] IPS started on interface lo")
    assert ev["event_type"] == "INFO"
    assert ev["src_ip"] is None
    assert ev["port"] is None
    assert ev["message"] == "IPS started on interface lo"


def test_message_containing_pipes_is_not_mangled():
    # The startup banner legitimately contains " | " inside the message text.
    line = "[2026-07-03 12:00:00.000] [INFO] Mode: block | Threshold: 5 hits in 60s | Workers: 2"
    ev = log_reader.parse_line(line)
    assert ev["message"] == "Mode: block | Threshold: 5 hits in 60s | Workers: 2"


def test_malformed_lines_return_none():
    assert log_reader.parse_line("") is None
    assert log_reader.parse_line("not a log line") is None
    assert log_reader.parse_line("[bad timestamp] [ALERT] nope") is None


def test_read_events_skips_garbage_and_respects_limit(tmp_path):
    log = tmp_path / "events.log"
    lines = [ALERT_LINE, "garbage line", BLOCK_LINE, ALERT_LINE]
    log.write_text("\n".join(lines) + "\n", encoding="utf-8")

    events = log_reader.read_events(str(log))
    assert len(events) == 3  # garbage skipped

    limited = log_reader.read_events(str(log), limit=2)
    assert len(limited) == 2
    assert limited[-1]["event_type"] == "ALERT"


def test_read_events_missing_file_returns_empty_list(tmp_path):
    assert log_reader.read_events(str(tmp_path / "nope.log")) == []


def test_aggregate_counts_types_attacks_sources_and_blocks():
    events = [
        log_reader.parse_line(ALERT_LINE),
        log_reader.parse_line(ALERT_LINE),
        log_reader.parse_line(BLOCK_LINE),
        log_reader.parse_line("[2026-07-03 12:00:00.000] [INFO] IPS started on interface lo"),
    ]
    agg = log_reader.aggregate(events)

    assert agg["total_events"] == 4
    assert agg["by_type"] == {"ALERT": 2, "BLOCK": 1, "INFO": 1}
    assert agg["by_attack"] == {"SQL Injection (Union Based)": 2}
    assert agg["top_sources"] == [{"ip": "203.0.113.7", "alerts": 2}]
    assert agg["blocked_ips"][0]["ip"] == "203.0.113.7"
    assert agg["avg_response_ms"] == 0.42


def test_aggregate_buckets_timeline_per_minute():
    e1 = log_reader.parse_line("[2026-07-03 12:00:10.000] [ALERT] Detected X from a:80 in 0.1ms | SRC_IP: 1.1.1.1 | ATTACK: X | PORT: 80 | RESPONSE_TIME: 0.10ms")
    e2 = log_reader.parse_line("[2026-07-03 12:00:50.000] [INFO] heartbeat")
    e3 = log_reader.parse_line("[2026-07-03 12:01:10.000] [ALERT] Detected X from a:80 in 0.1ms | SRC_IP: 1.1.1.1 | ATTACK: X | PORT: 80 | RESPONSE_TIME: 0.10ms")
    agg = log_reader.aggregate([e1, e2, e3])

    assert len(agg["timeline"]) == 2
    first, second = agg["timeline"]
    assert first["total"] == 2 and first["alerts"] == 1
    assert second["total"] == 1 and second["alerts"] == 1


def test_aggregate_empty_input():
    agg = log_reader.aggregate([])
    assert agg["total_events"] == 0
    assert agg["avg_response_ms"] == 0
    assert agg["timeline"] == []
