"""Tests for logging and firewall-response logic."""
import Handling.post_detection as pd


def test_log_event_writes_formatted_forensic_fields(tmp_path, monkeypatch, capsys):
    log_file = tmp_path / "events.log"
    monkeypatch.setattr(pd, "LOG_FILE", str(log_file))

    pd.log_event(
        "Detected SQLi",
        event_type="ALERT",
        src_ip="10.0.0.5",
        attack_type="SQLi",
        port=80,
        response_time=0.012,
    )

    written = log_file.read_text(encoding="utf-8")
    assert "[ALERT] Detected SQLi" in written
    assert "SRC_IP: 10.0.0.5" in written
    assert "ATTACK: SQLi" in written
    assert "PORT: 80" in written
    assert "RESPONSE_TIME: 12.00ms" in written


def test_log_event_omits_absent_optional_fields(tmp_path, monkeypatch):
    log_file = tmp_path / "events.log"
    monkeypatch.setattr(pd, "LOG_FILE", str(log_file))

    pd.log_event("startup", event_type="INFO")

    written = log_file.read_text(encoding="utf-8")
    assert "[INFO] startup" in written
    assert "SRC_IP" not in written
    assert "ATTACK" not in written
