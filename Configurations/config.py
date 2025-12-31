
INTERFACE = "lo"
LOG_FILE = "ips_events.log"
BLOCKED_IPS = set()

# target ip: 192.168.4.67/22
# format of rules for signature based detection: {"name": "Type of Attack", "pattern": "text", "ports": "[X, Y]"}
RULES = [
    # --- HIGH FIDELITY ATTACKS ---
    {
        "name": "SQL Injection (Union Based)", 
        "pattern": "UNION SELECT", 
        "ports": [80, 8080, 443]
    },
    {
        "name": "SQL Injection (Boolean Blind)", 
        "pattern": "' OR '1'='1", 
        "ports": [80, 8080, 443]
    },
    {
        "name": "Cross-Site Scripting (XSS)", 
        "pattern": "<script>", 
        "ports": [80, 8080, 443]
    },
    {
        "name": "Directory Traversal (Linux)", 
        "pattern": "/etc/shadow", 
        "ports": [80, 8080, 443]
    },
    {
        "name": "Directory Traversal (Windows)", 
        "pattern": "\\windows\\system32", 
        "ports": [80, 8080, 443]
    },

    {
        "name": "Automated SQL Scanner (sqlmap)", 
        "pattern": "sqlmap", 
        "ports": [80, 8080]
    },
    {
        "name": "Nikto Web Scanner", 
        "pattern": "Nikto", 
        "ports": [80, 8080]
    },

    {
        "name": "PHP Reverse Shell", 
        "pattern": "c99.php", 
        "ports": [80, 8080]
    },
    {
        "name": "Remote Code Execution (Log4j)", 
        "pattern": "${jndi:", 
        "ports": [80, 8080, 8443]
    },
    {
        "name": "Private Key Theft", 
        "pattern": "-----BEGIN RSA PRIVATE KEY-----", 
        "ports": [80, 8080, 21, 22]
    }
]