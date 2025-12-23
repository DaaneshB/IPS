import os
import time as timre
from Configurations.config import LOG_FILE, BLOCKED_IPS

def log_event(message): 
    """Logs alert to file."""
    timestamp = timre.strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"[{timestamp}] {message}\n"
    #print(log_entry)  # For real-time monitoring
    with open(LOG_FILE, "a") as log_file:
        log_file.write(log_entry + "\n")

def block_ip(ip_address):
    """Blocks given IP address using OS firewall."""
    if ip_address in BLOCKED_IPS:
        return

    log_event(f"Blocked IP: {ip_address}")

    os.system(f"iptables -A INPUT -s {ip_address} -j DROP")
    BLOCKED_IPS.add(ip_address)