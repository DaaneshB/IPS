"""Tests for the dashboard synthetic-injection path."""
import Handling.post_detection as pd
import pytest

from dashboard import injector


@pytest.fixture(autouse=True)
def _isolate_log(tmp_path, monkeypatch):
    """Send injected log events to a temp file, not the real ips_events.log."""
    monkeypatch.setattr(pd, "LOG_FILE", str(tmp_path / "events.log"))


def test_injecting_a_signature_reports_a_match():
    result = injector.inject("GET /?q=UNION SELECT * FROM users HTTP/1.1", 80, "203.0.113.5")
    assert result["matched"] is not None
    assert result["src_ip"] == "203.0.113.5"
    assert result["port"] == 80
    assert result["detection_ms"] >= 0


def test_benign_payload_matches_nothing():
    result = injector.inject("GET /index.html HTTP/1.1", 80, "203.0.113.6")
    assert result["matched"] is None
    assert result["blocked"] is False


def test_missing_src_ip_gets_a_documentation_address():
    result = injector.inject("GET /index.html HTTP/1.1", 80)
    assert result["src_ip"].startswith(("203.0.113.", "198.51.100.", "192.0.2."))


def test_empty_payload_is_rejected():
    with pytest.raises(injector.InjectionError):
        injector.inject("   ", 80)


def test_bad_port_is_rejected():
    with pytest.raises(injector.InjectionError):
        injector.inject("UNION SELECT", 70000)
    with pytest.raises(injector.InjectionError):
        injector.inject("UNION SELECT", "not-a-port")


def test_bad_src_ip_is_rejected():
    with pytest.raises(injector.InjectionError):
        injector.inject("UNION SELECT", 80, "not-an-ip")


def test_oversized_payload_is_rejected():
    with pytest.raises(injector.InjectionError):
        injector.inject("A" * (injector.MAX_PAYLOAD_BYTES + 1), 80)


def test_presets_are_all_correctly_classified():
    for p in injector.attack_presets():
        result = injector.inject(p["payload"], p["port"], "203.0.113.9")
        assert (result["matched"] is not None) == p["attack"], p["label"]


def test_repeated_injections_trip_the_real_threshold_block(monkeypatch):
    """Enough matching injects from one source should produce a simulated block."""
    from Handling.metrics import ThresholdTracker
    import Configurations.config as config

    # Fresh tracker so this test is independent of others sharing the module one.
    monkeypatch.setattr(injector, "_tracker", ThresholdTracker())

    blocked = False
    for _ in range(config.THRESHOLD_COUNT + 1):
        result = injector.inject("UNION SELECT password FROM users", 3306, "198.51.100.50")
        blocked = blocked or result["blocked"]
    assert blocked, "threshold never triggered a block"


def test_inject_endpoint_returns_detection(tmp_path, monkeypatch):
    import dashboard.app as app_module

    monkeypatch.setattr(app_module, "ALLOW_INJECT", True)
    client = app_module.app.test_client()
    resp = client.post("/api/inject", json={"payload": "UNION SELECT 1", "port": 80})
    assert resp.status_code == 200
    assert resp.get_json()["matched"] is not None


def test_inject_endpoint_validates_input(monkeypatch):
    import dashboard.app as app_module

    monkeypatch.setattr(app_module, "ALLOW_INJECT", True)
    client = app_module.app.test_client()
    resp = client.post("/api/inject", json={"payload": "", "port": 80})
    assert resp.status_code == 400
    assert "error" in resp.get_json()


def test_inject_endpoint_can_be_disabled(monkeypatch):
    import dashboard.app as app_module

    monkeypatch.setattr(app_module, "ALLOW_INJECT", False)
    client = app_module.app.test_client()
    resp = client.post("/api/inject", json={"payload": "UNION SELECT", "port": 80})
    assert resp.status_code == 403


def test_dashboard_exposes_no_ips_control_endpoints(monkeypatch):
    """Injection is the only write route, and it is synthetic input — there is
    still no endpoint that mutates IPS config or firewall state."""
    import dashboard.app as app_module

    write_rules = []
    for rule in app_module.app.url_map.iter_rules():
        methods = (rule.methods or set()) - {"HEAD", "OPTIONS"}
        if methods - {"GET"}:
            write_rules.append(str(rule))
    assert write_rules == ["/api/inject"], f"unexpected write routes: {write_rules}"
