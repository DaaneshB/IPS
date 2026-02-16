import os
import time
from datetime import datetime
from Configurations.config import LOG_FILE, BLOCKED_IPS

def log_event(message, event_type="INFO", src_ip=None, attack_type=None, port=None, response_time=None):
    """Logs alert to file with comprehensive forensic data.
    
    Args:
        message (str): Primary log message
        event_type (str): Type of event (INFO, ALERT, BLOCK)
        src_ip (str): Source IP address of the threat
        attack_type (str): Type of attack detected
        port (int): Destination port of the attack
        response_time (float): Time from detection to block in seconds
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    
    log_entry = f"[{timestamp}] [{event_type}] {message}"
    if src_ip:
        log_entry += f" | SRC_IP: {src_ip}"
    if attack_type:
        log_entry += f" | ATTACK: {attack_type}"
    if port:
        log_entry += f" | PORT: {port}"
    if response_time is not None:
        log_entry += f" | RESPONSE_TIME: {response_time*1000:.2f}ms"
    
    print(log_entry)
    with open(LOG_FILE, "a") as log_file:
        log_file.write(log_entry + "\n")

def block_ip(ip_address, attack_type=None, port=None, response_time=None):
    """Blocks given IP address using OS firewall with sub-second execution.
    
    Args:
        ip_address (str): IP address to block
        attack_type (str): Type of attack detected
        port (int): Destination port of the attack
        response_time (float): Time from detection to block execution
    """
    if ip_address in BLOCKED_IPS:
        return

    block_start = time.time()
    
    try:
        result = os.system(f"iptables -A INPUT -s {ip_address} -j DROP 2>/dev/null")
        block_duration = time.time() - block_start
        
        if result == 0:
            total_response = response_time + block_duration if response_time else block_duration
            log_event(
                f"Blocked IP: {ip_address}",
                event_type="BLOCK",
                src_ip=ip_address,
                attack_type=attack_type,
                port=port,
                response_time=total_response
            )
            BLOCKED_IPS.add(ip_address)
        else:
            log_event(
                f"Failed to block IP: {ip_address}",
                event_type="ERROR",
                src_ip=ip_address
            )
    except Exception as e:
        log_event(
            f"Error blocking IP {ip_address}: {str(e)}",
            event_type="ERROR",
            src_ip=ip_address
        )