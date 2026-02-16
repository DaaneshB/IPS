
import json
import os

INTERFACE = "lo"
LOG_FILE = "ips_events.log"
BLOCKED_IPS = set()

# Performance configuration for packet inspection pipeline
PACKET_PROCESSING_CONFIG = {
    "store_packets": False,  # Optimize memory by not storing packets
    "timeout": 0,            # Continuous monitoring
}

# Load signature-based detection rules from JSON file
# Rules cover 7+ critical ports: HTTP (80), HTTPS (443), FTP (21), SSH (22), SMTP (25), MySQL (3306), PostgreSQL (5432)
def load_rules():
    """Load detection rules from rules.json file.
    
    Returns:
        list: List of rule dictionaries with 'name', 'pattern', and 'ports' keys
    """
    rules_file = os.path.join(os.path.dirname(__file__), "rules.json")
    try:
        with open(rules_file, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"Error: Rules file not found at {rules_file}")
        return []
    except json.JSONDecodeError:
        print(f"Error: Invalid JSON in {rules_file}")
        return []

RULES = load_rules()