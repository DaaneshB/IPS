
INTERFACE = #
L0G_FILE = #
BLOCKED_IPS = set()

# format of rules: {"name": "Type of Attack", "pattern": "text", "ports": "[src, dest]"}
RULES = [
    {
        "name": "SQL Injection",
        "pattern": "UNION SELECT",
        "ports": [80, 8080]
    },
]