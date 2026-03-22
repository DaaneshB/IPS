
import json
import os

INTERFACE = os.environ.get("IPS_INTERFACE", "lo")
LOG_FILE = os.path.abspath(os.environ.get("IPS_LOG_FILE", "ips_events.log"))
BLOCKED_IPS = set()

# Response mode: "block" installs firewall rules, "alert" only logs detections.
MODE = "block"

# Sliding-window blocking threshold: block a source after THRESHOLD_COUNT
# detections within THRESHOLD_WINDOW_SECONDS, to reduce false-positive blocking.
THRESHOLD_COUNT = 5
THRESHOLD_WINDOW_SECONDS = 60

# Source IPs that are never blocked (e.g. trusted scanners, gateways).
ALLOWED_IPS = set()

# Packet-inspection worker pool and bounded hand-off queue.
NUM_WORKERS = int(os.environ.get("IPS_NUM_WORKERS", "2"))
QUEUE_MAXSIZE = int(os.environ.get("IPS_QUEUE_MAXSIZE", "10000"))

# Performance configuration for packet inspection pipeline
PACKET_PROCESSING_CONFIG = {
    "store_packets": False,  # Optimize memory by not storing packets
    "timeout": 0,            # Continuous monitoring
}

# Load signature-based detection rules from JSON file
# Rules cover 7+ critical ports: HTTP (80), HTTPS (443), FTP (21), SSH (22), SMTP (25), MySQL (3306), PostgreSQL (5432)
def load_rules(rules_file=None):
    """Load detection rules from a JSON file.

    Args:
        rules_file: Optional path to the rules file. Defaults to rules.json
            next to this module. Accepting a path keeps the loader testable.

    Returns:
        list: List of rule dictionaries with 'name', 'pattern', and 'ports' keys
    """
    if rules_file is None:
        rules_file = os.path.join(os.path.dirname(__file__), "rules.json")
    try:
        with open(rules_file, 'r') as f:
            rules = json.load(f)
    except FileNotFoundError as e:
        raise RuntimeError(
            f"IPS refusing to start: rules file not found at {rules_file}"
        ) from e
    except json.JSONDecodeError as e:
        raise RuntimeError(
            f"IPS refusing to start: invalid JSON in {rules_file}: {e}"
        ) from e

    if not rules:
        raise RuntimeError(
            f"IPS refusing to start: {rules_file} contains no signatures"
        )

    for idx, rule in enumerate(rules):
        if not isinstance(rule, dict):
            raise RuntimeError(f"IPS refusing to start: rule #{idx} is not an object")
        missing = {"name", "pattern", "ports"} - rule.keys()
        if missing:
            raise RuntimeError(
                f"IPS refusing to start: rule #{idx} missing keys {sorted(missing)}"
            )
        if not rule["pattern"]:
            raise RuntimeError(
                f"IPS refusing to start: rule '{rule['name']}' has an empty pattern"
            )
        if not isinstance(rule["ports"], list) or not rule["ports"]:
            raise RuntimeError(
                f"IPS refusing to start: rule '{rule['name']}' has no ports"
            )
    return rules

RULES = load_rules()

# Union of every port referenced by a signature. Capturing only this set with a
# BPF filter keeps irrelevant traffic out of the Python inspection path.
MONITORED_PORTS = sorted({port for rule in RULES for port in rule["ports"]})


def build_bpf_filter(ports=MONITORED_PORTS):
    """Return a libpcap filter expression limiting capture to monitored ports."""
    if not ports:
        return ""
    port_expr = " or ".join(f"port {p}" for p in ports)
    return f"(tcp or udp) and ({port_expr})"


BPF_FILTER = build_bpf_filter()