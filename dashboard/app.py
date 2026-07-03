"""Flask app serving the IPS SIEM dashboard.

Run from the repo root:

    python -m dashboard.app            # http://127.0.0.1:5000

The dashboard tails and aggregates ips_events.log and offers an injection
panel that submits *synthetic* requests to the real detection pipeline. That
is the only write path, and it is strictly input, not control: no endpoint
can change a rule, the mode, or a firewall entry, and injection never invokes
the real firewall backend. A monitoring surface must never become a control
surface — a misused dashboard still cannot unblock attackers or disable rules.
Injection can be disabled entirely with IPS_DASHBOARD_ALLOW_INJECT=0.
"""
from __future__ import annotations

import os
import sys

from flask import Flask, Response, jsonify, request, send_from_directory

# Allow `python dashboard/app.py` as well as `python -m dashboard.app`.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dashboard import injector, log_reader

# Reuse the exact path the IPS writes to (honours the IPS_LOG_FILE override),
# so pointing the dashboard at the wrong file is impossible by default.
import Configurations.config as config

LOG_FILE = config.LOG_FILE

# Bound how much history the stats endpoint parses per request so response
# time stays flat even after days of logging.
MAX_EVENTS = int(os.environ.get("IPS_DASHBOARD_MAX_EVENTS", "5000"))

# Injection is on by default for demos; set to 0 to serve a pure read-only
# monitoring view with no way to submit traffic at all.
ALLOW_INJECT = os.environ.get("IPS_DASHBOARD_ALLOW_INJECT", "1") != "0"

app = Flask(__name__, static_folder="static")


@app.route("/")
def index():
    return send_from_directory(app.static_folder, "index.html")


@app.route("/api/stats")
def stats():
    events = log_reader.read_events(LOG_FILE, limit=MAX_EVENTS)
    payload = log_reader.aggregate(events)
    payload["log_file"] = LOG_FILE
    return jsonify(payload)



@app.route("/api/events/recent")
def recent_events():
    """Last 100 events, used by the page to backfill the feed on load."""
    events = log_reader.read_events(LOG_FILE, limit=100)
    return jsonify(events)


@app.route("/api/events/stream")
def stream():
    """Server-sent events: push each new log entry to the browser as JSON.

    SSE was chosen over WebSockets because the data flow is strictly
    one-directional (server -> browser), it works over plain HTTP with
    automatic reconnection built into EventSource, and it needs no extra
    dependencies — important for keeping the demo reviewable end to end.
    """
    import json

    def generate():
        for event in log_reader.follow(LOG_FILE):
            yield f"data: {json.dumps(event)}\n\n"

    return Response(
        generate(),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )



@app.route("/api/inject/presets")
def inject_presets():
    """Ports and ready-made example payloads for the injection panel."""
    return jsonify({
        "enabled": ALLOW_INJECT,
        "ports": injector.monitored_ports(),
        "presets": injector.attack_presets(),
    })


@app.route("/api/inject", methods=["POST"])
def inject():
    """Feed one synthetic request through the real IPS detection pipeline.

    Returns what the IPS decided (matched signature, detection latency,
    whether the threshold produced a simulated block). The logged event also
    reaches the live feed over SSE, so the analyst sees it land in real time.
    """
    if not ALLOW_INJECT:
        return jsonify({"error": "injection is disabled on this dashboard"}), 403

    data = request.get_json(silent=True) or {}
    try:
        result = injector.inject(
            payload=data.get("payload"),
            port=data.get("port"),
            src_ip=data.get("src_ip"),
        )
    except injector.InjectionError as exc:
        return jsonify({"error": str(exc)}), 400
    return jsonify(result)


def _open_browser(url: str) -> None:
    """Open the dashboard in the default browser shortly after startup.

    Runs on a short timer so the server is accepting connections by the time
    the page loads. Best-effort: a headless or browserless host just skips it.
    Disable with IPS_DASHBOARD_OPEN_BROWSER=0 (e.g. for remote/CI runs).
    """
    import threading
    import webbrowser

    if os.environ.get("IPS_DASHBOARD_OPEN_BROWSER", "1") == "0":
        return
    threading.Timer(1.0, lambda: webbrowser.open(url)).start()


def main() -> None:
    port = int(os.environ.get("IPS_DASHBOARD_PORT", "5000"))
    url = f"http://127.0.0.1:{port}"
    print(f"IPS SIEM dashboard -> {url}  (Ctrl+C to stop)")
    # Only auto-open in the reloader's main process; here reload is off, so
    # this always runs once. The server binds localhost only.
    _open_browser(url)
    app.run(host="127.0.0.1", port=port, debug=False, threaded=True)


if __name__ == "__main__":
    main()
