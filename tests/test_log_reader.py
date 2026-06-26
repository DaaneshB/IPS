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
