"""Tests for logging and firewall-response logic."""
import subprocess
import types

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


def test_block_command_uses_iptables_on_posix(monkeypatch):
    monkeypatch.setattr(pd, "_IS_WINDOWS", False)
    cmd = pd._block_command("1.2.3.4")
    assert cmd[0] == "iptables"
    assert "1.2.3.4" in cmd


def test_block_command_uses_netsh_on_windows(monkeypatch):
    monkeypatch.setattr(pd, "_IS_WINDOWS", True)
    cmd = pd._block_command("1.2.3.4")
    assert cmd[0] == "netsh"
    assert any("remoteip=1.2.3.4" == part for part in cmd)


def test_firewall_rule_exists_reflects_return_code(monkeypatch):
    monkeypatch.setattr(pd, "_IS_WINDOWS", False)

    def fake_run(cmd, **kwargs):
        return types.SimpleNamespace(returncode=0)

    monkeypatch.setattr(subprocess, "run", fake_run)
    assert pd._firewall_rule_exists("1.2.3.4") is True

    monkeypatch.setattr(subprocess, "run", lambda cmd, **kw: types.SimpleNamespace(returncode=1))
    assert pd._firewall_rule_exists("1.2.3.4") is False


def test_block_ip_enqueues_new_ip(monkeypatch):
    enqueued = []
    monkeypatch.setattr(pd, "_ensure_blocker_started", lambda: None)
    monkeypatch.setattr(pd._block_queue, "put", lambda item: enqueued.append(item))

    pd.block_ip("203.0.113.7", attack_type="SQLi", port=80)
    assert len(enqueued) == 1
    assert enqueued[0][0] == "203.0.113.7"


def test_block_ip_skips_already_blocked_ip(monkeypatch):
    enqueued = []
    monkeypatch.setattr(pd, "_ensure_blocker_started", lambda: None)
    monkeypatch.setattr(pd._block_queue, "put", lambda item: enqueued.append(item))
    pd._mark_blocked("203.0.113.8")

    pd.block_ip("203.0.113.8")
    assert enqueued == []


def test_execute_block_installs_rule_and_marks_blocked(tmp_path, monkeypatch):
    monkeypatch.setattr(pd, "LOG_FILE", str(tmp_path / "e.log"))
    monkeypatch.setattr(pd, "_firewall_rule_exists", lambda ip: False)
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        return types.SimpleNamespace(returncode=0)

    monkeypatch.setattr(subprocess, "run", fake_run)

    pd._execute_block("198.51.100.4", "SQLi", 80, 0.01)
    assert pd._is_blocked("198.51.100.4") is True
    assert len(calls) == 1


def test_execute_block_does_not_mark_when_firewall_fails(tmp_path, monkeypatch):
    monkeypatch.setattr(pd, "LOG_FILE", str(tmp_path / "e.log"))
    monkeypatch.setattr(pd, "_firewall_rule_exists", lambda ip: False)
    monkeypatch.setattr(subprocess, "run", lambda cmd, **kw: types.SimpleNamespace(returncode=1))

    pd._execute_block("198.51.100.5", "SQLi", 80, 0.01)
    assert pd._is_blocked("198.51.100.5") is False
