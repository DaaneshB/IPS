import os
import queue
import subprocess
import threading
import time
from datetime import datetime
from Configurations.config import LOG_FILE, BLOCKED_IPS

_IS_WINDOWS = os.name == "nt"


def _rule_name(ip_address):
    """Firewall rule name used for the Windows netsh backend."""
    return f"IPS Block {ip_address}"


_block_queue: "queue.Queue[tuple[str, str | None, int | None, float | None]]" = queue.Queue()
_blocker_thread: threading.Thread | None = None
_blocker_lock = threading.Lock()
_log_lock = threading.Lock()
_blocked_lock = threading.Lock()


def _is_blocked(ip_address):
    with _blocked_lock:
        return ip_address in BLOCKED_IPS


def _mark_blocked(ip_address):
    with _blocked_lock:
        BLOCKED_IPS.add(ip_address)


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

    with _log_lock:
        print(log_entry)
        with open(LOG_FILE, "a", encoding="utf-8") as log_file:
            log_file.write(log_entry + "\n")


def _blocker_worker():
    """Single dedicated thread that runs firewall subprocess calls.

    Packet workers enqueue block requests and return immediately, so a slow
    iptables/netsh invocation cannot stall packet inspection.
    """
    while True:
        item = _block_queue.get()
        if item is None:
            _block_queue.task_done()
            break
        ip_address, attack_type, port, response_time = item
        try:
            _execute_block(ip_address, attack_type, port, response_time)
        except Exception as e:
            log_event(f"Blocker thread error for {ip_address}: {e}", event_type="ERROR", src_ip=ip_address)
        finally:
            _block_queue.task_done()


def _ensure_blocker_started():
    global _blocker_thread
    with _blocker_lock:
        if _blocker_thread is None or not _blocker_thread.is_alive():
            _blocker_thread = threading.Thread(target=_blocker_worker, name="ips-blocker", daemon=True)
            _blocker_thread.start()


def _firewall_rule_exists(ip_address):
    """Return True if a block rule for ip_address is already installed.

    Prevents duplicate firewall rules accumulating across process restarts,
    which would otherwise leak rules indefinitely. Dispatches to netsh on
    Windows and iptables elsewhere.
    """
    if _IS_WINDOWS:
        cmd = ["netsh", "advfirewall", "firewall", "show", "rule", f"name={_rule_name(ip_address)}"]
    else:
        cmd = ["iptables", "-C", "INPUT", "-s", ip_address, "-j", "DROP"]
    try:
        result = subprocess.run(cmd, capture_output=True, timeout=5)
        return result.returncode == 0
    except Exception:
        return False


def _block_command(ip_address):
    """Return the platform command that installs a block rule for ip_address."""
    if _IS_WINDOWS:
        return [
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={_rule_name(ip_address)}", "dir=in", "action=block",
            f"remoteip={ip_address}",
        ]
    return ["iptables", "-A", "INPUT", "-s", ip_address, "-j", "DROP"]


def _execute_block(ip_address, attack_type, port, response_time):
    if _firewall_rule_exists(ip_address):
        _mark_blocked(ip_address)
        log_event(
            f"IP {ip_address} already blocked at firewall; skipping duplicate rule",
            event_type="INFO",
            src_ip=ip_address,
        )
        return

    block_start = time.time()
    try:
        result = subprocess.run(
            _block_command(ip_address),
            capture_output=True,
            timeout=5,
        )
        block_duration = time.time() - block_start

        if result.returncode == 0:
            total_response = (
                response_time + block_duration if response_time is not None else block_duration
            )
            log_event(
                f"Blocked IP: {ip_address}",
                event_type="BLOCK",
                src_ip=ip_address,
                attack_type=attack_type,
                port=port,
                response_time=total_response,
            )
            _mark_blocked(ip_address)
        else:
            log_event(
                f"Failed to block IP: {ip_address}",
                event_type="ERROR",
                src_ip=ip_address,
            )
    except subprocess.TimeoutExpired:
        log_event(f"Timeout blocking IP {ip_address}", event_type="ERROR", src_ip=ip_address)
    except Exception as e:
        log_event(f"Error blocking IP {ip_address}: {str(e)}", event_type="ERROR", src_ip=ip_address)


def block_ip(ip_address, attack_type=None, port=None, response_time=None):
    """Enqueue a block request; the blocker thread invokes the firewall.

    Args:
        ip_address (str): IP address to block
        attack_type (str): Type of attack detected
        port (int): Destination port of the attack
        response_time (float): Time from detection to block execution
    """
    if _is_blocked(ip_address):
        return
    _ensure_blocker_started()
    _block_queue.put((ip_address, attack_type, port, response_time))
