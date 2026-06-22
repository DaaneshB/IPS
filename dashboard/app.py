"""Flask app serving the IPS SIEM dashboard.

Run from the repo root:

    python -m dashboard.app            # http://127.0.0.1:5000

The app is read-only by design: it tails and aggregates ips_events.log but
has no endpoint that can change IPS configuration or firewall state. A
monitoring surface should never be a control surface — a compromised or
misused dashboard must not be able to unblock attackers or disable rules.
"""
from __future__ import annotations

import os
import sys

from flask import Flask, jsonify, send_from_directory

# Allow `python dashboard/app.py` as well as `python -m dashboard.app`.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dashboard import log_reader

# Reuse the exact path the IPS writes to (honours the IPS_LOG_FILE override),
# so pointing the dashboard at the wrong file is impossible by default.
import Configurations.config as config

LOG_FILE = config.LOG_FILE

# Bound how much history the stats endpoint parses per request so response
# time stays flat even after days of logging.
MAX_EVENTS = int(os.environ.get("IPS_DASHBOARD_MAX_EVENTS", "5000"))

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


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=int(os.environ.get("IPS_DASHBOARD_PORT", "5000")), debug=False)
