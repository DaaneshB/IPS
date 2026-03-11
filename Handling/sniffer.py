from __future__ import annotations

import os
import queue
import sys
import threading
from typing import Any, Optional

import Configurations.config as config
from Handling.matcher import AHOCORASICK_AVAILABLE, PatternMatcher
from Handling.metrics import PerformanceMetrics, ThresholdTracker
from Handling.post_detection import log_event, block_ip
from scapy.all import sniff, IP, TCP, UDP, Raw

if not AHOCORASICK_AVAILABLE:
    print("Warning: pyahocorasick not installed. Falling back to naive pattern matching.")
    print("Install with: pip install pyahocorasick")


metrics = PerformanceMetrics()
threshold_tracker = ThresholdTracker()
pattern_matcher = PatternMatcher(
    config.RULES,
    on_error=lambda msg: log_event(msg, event_type="ERROR"),
)

# Worker queue for multi-threaded packet inspection
_packet_queue: queue.Queue[Optional[tuple[str, str, int]]] = queue.Queue(maxsize=config.QUEUE_MAXSIZE)
_NUM_WORKERS = config.NUM_WORKERS


def check_packet(payload: str, dst_port: int) -> tuple[Optional[dict], float]:
    return pattern_matcher.find_matches(payload, dst_port)


def _process_packet(payload: str, src_ip: str, dst_port: int) -> None:
    """Inspect a single decoded packet and trigger response if matched."""
    matched_rule, detection_time = check_packet(payload, dst_port)
    metrics.record_packet(detection_time)

    if matched_rule:
        log_event(
            f"Detected {matched_rule['name']} from {src_ip}:{dst_port} in {detection_time*1000:.2f}ms",
            event_type="ALERT",
            src_ip=src_ip,
            attack_type=matched_rule["name"],
            port=dst_port,
            response_time=detection_time,
        )

        if src_ip in config.ALLOWED_IPS:
            return

        if config.MODE == "block" and threshold_tracker.should_block(src_ip):
            block_ip(src_ip, attack_type=matched_rule["name"], port=dst_port, response_time=detection_time)


def _worker() -> None:
    """Consumer thread: pulls decoded packets off the queue and inspects them."""
    while True:
        item = _packet_queue.get()
        if item is None:
            break
        try:
            _process_packet(*item)
        except Exception as e:
            log_event(f"Worker error: {e}", event_type="ERROR")
        finally:
            _packet_queue.task_done()


def packet_callback(packet: Any) -> None:
    """Scapy callback: extract fields and enqueue for worker threads."""
    try:
        if not packet.haslayer(IP):
            metrics.record_packet()
            return

        if packet.haslayer(TCP):
            dst_port = packet[TCP].dport
        elif packet.haslayer(UDP):
            dst_port = packet[UDP].dport
        else:
            metrics.record_packet()
            return

        src_ip: str = packet[IP].src

        if packet.haslayer(Raw):
            try:
                payload = packet[Raw].load.decode("utf-8", errors="ignore")
                _packet_queue.put_nowait((payload, src_ip, dst_port))
            except queue.Full:
                metrics.record_packet()
                log_event("Packet queue full — dropping packet", event_type="WARNING")
            except Exception as e:
                metrics.record_packet()
                log_event(f"Error decoding payload: {e}", event_type="ERROR", src_ip=src_ip)
        else:
            metrics.record_packet()

    except Exception as e:
        log_event(f"Packet processing error: {e}", event_type="ERROR")


def _print_startup_banner() -> None:
    print("\n" + "=" * 60)
    print("SIGNATURE-BASED INTRUSION PREVENTION SYSTEM (IPS)")
    print("=" * 60)

    algo_type = "Aho-Corasick" if pattern_matcher.use_ahocorasick else "Naive String Matching"
    log_event(f"Pattern matcher initialized using {algo_type} algorithm", event_type="INFO")
    log_event(f"IPS started on interface {config.INTERFACE}", event_type="INFO")
    log_event(f"Loaded {len(config.RULES)} attack signatures", event_type="INFO")
    log_event(
        f"Mode: {config.MODE} | Threshold: {config.THRESHOLD_COUNT} hits in {config.THRESHOLD_WINDOW_SECONDS}s | Workers: {_NUM_WORKERS}",
        event_type="INFO",
    )
    if config.ALLOWED_IPS:
        log_event(f"Allowlisted IPs: {', '.join(sorted(config.ALLOWED_IPS))}", event_type="INFO")
    print(
        "\nMonitoring ports: 21 (FTP), 22 (SSH), 25 (SMTP), 80 (HTTP), "
        "443 (HTTPS), 389 (LDAP), 636 (LDAP-SSL), 3306 (MySQL), 5432 (PostgreSQL)\n"
    )
    print("Press Ctrl+C to stop...\n")


def _print_shutdown_summary(stats: dict[str, Any]) -> None:
    print("\n" + "=" * 60)
    print("IPS SHUTDOWN - PERFORMANCE SUMMARY")
    print("=" * 60)
    log_event(f"IPS stopped. Statistics: {stats}", event_type="INFO")
    print(f"Total Packets Processed: {stats['packets_processed']}")
    print(f"Avg Throughput: {stats['packets_per_second']} packets/sec")
    print(f"Avg Detection Time: {stats['avg_detection_time_ms']}ms")
    algo_type = "Aho-Corasick" if pattern_matcher.use_ahocorasick else "Naive String Matching"
    print(f"Pattern Matching Algorithm: {algo_type}")
    print(f"Worker Threads: {_NUM_WORKERS}")
    print("=" * 60 + "\n")


def start_sniffing() -> None:
    _print_startup_banner()

    workers: list[threading.Thread] = []
    for i in range(_NUM_WORKERS):
        t = threading.Thread(target=_worker, name=f"ips-worker-{i}", daemon=True)
        t.start()
        workers.append(t)

    try:
        sniff(
            iface=config.INTERFACE,
            prn=packet_callback,
            store=config.PACKET_PROCESSING_CONFIG["store_packets"],
            timeout=config.PACKET_PROCESSING_CONFIG["timeout"],
        )
    except KeyboardInterrupt:
        pass
    finally:
        for _ in workers:
            _packet_queue.put(None)
        for t in workers:
            t.join(timeout=2)
        _print_shutdown_summary(metrics.get_stats())


def _is_privileged() -> bool:
    """Return True if the current process can capture raw packets."""
    if os.name == "nt":
        try:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    return hasattr(os, "geteuid") and os.geteuid() == 0


if __name__ == "__main__":
    if not _is_privileged():
        sys.exit("Error: Run as root (Linux/macOS) or Administrator (Windows).")
    start_sniffing()
