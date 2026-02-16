
import os
import sys
import time
from collections import deque
from datetime import datetime
from Configurations.config import INTERFACE, RULES, PACKET_PROCESSING_CONFIG
from Handling.post_detection import log_event, block_ip
from scapy.all import sniff, IP, TCP, Raw

try:
    import pyahocorasick
    AHOCORASICK_AVAILABLE = True
except ImportError:
    AHOCORASICK_AVAILABLE = False
    print("Warning: pyahocorasick not installed. Falling back to naive pattern matching.")
    print("Install with: pip install pyahocorasick")

# Performance tracking metrics
class PerformanceMetrics:
    """Tracks packet processing performance metrics for monitoring."""
    def __init__(self, window_size=1000):
        self.packet_count = 0
        self.detection_times = deque(maxlen=window_size)  # Last 1000 packets
        self.packets_per_second = 0
        self.last_window_start = time.time()
        self.window_size = window_size
    
    def record_packet(self, detection_time=0):
        """Records packet inspection with detection time."""
        self.packet_count += 1
        if detection_time > 0:
            self.detection_times.append(detection_time)
        
        # Calculate packets per second every window_size packets
        if self.packet_count % self.window_size == 0:
            elapsed = time.time() - self.last_window_start
            self.packets_per_second = self.window_size / elapsed if elapsed > 0 else 0
            self.last_window_start = time.time()
    
    def get_stats(self):
        """Returns performance statistics."""
        avg_detection = sum(self.detection_times) / len(self.detection_times) if self.detection_times else 0
        return {
            'packets_processed': self.packet_count,
            'packets_per_second': round(self.packets_per_second, 2),
            'avg_detection_time_ms': round(avg_detection * 1000, 3)
        }

# Aho-Corasick automaton for efficient multi-pattern matching
class PatternMatcher:
    """Efficient pattern matching using Aho-Corasick algorithm.
    
    Provides O(n + z) time complexity where n is payload length and z is number of matches.
    Significantly faster than naive O(n*m) approach when matching many patterns.
    """
    def __init__(self, rules):
        """Initialize pattern matcher with rules.
        
        Args:
            rules (list): List of detection rules with 'pattern' and 'name' keys
        """
        self.rules = rules
        self.use_ahocorasick = AHOCORASICK_AVAILABLE
        
        if self.use_ahocorasick:
            self.automaton = pyahocorasick.Automaton()
            # Build automaton with pattern -> rule mapping
            for idx, rule in enumerate(rules):
                self.automaton.add_word(rule["pattern"], (idx, rule))
            self.automaton.make_automaton()
    
    def find_matches(self, payload, dst_port):
        """Find all matching rules in payload for given port.
        
        Args:
            payload (str): Decoded packet payload
            dst_port (int): Destination port number
            
        Returns:
            tuple: (matched_rule, detection_time) or (None, detection_time)
        """
        detection_start = time.time()
        
        try:
            if self.use_ahocorasick:
                # Aho-Corasick matching: O(n + z) complexity
                for end_idx, (rule_idx, rule) in self.automaton.iter(payload):
                    if dst_port in rule["ports"]:
                        detection_time = time.time() - detection_start
                        return rule, detection_time
            else:
                # Fallback to naive matching if pyahocorasick unavailable
                for rule in self.rules:
                    if dst_port not in rule["ports"]:
                        continue
                    if rule["pattern"] in payload:
                        detection_time = time.time() - detection_start
                        return rule, detection_time
            
            detection_time = time.time() - detection_start
            return None, detection_time
            
        except Exception as e:
            detection_time = time.time() - detection_start
            log_event(f"Error during pattern matching: {str(e)}", event_type="ERROR")
            return None, detection_time

metrics = PerformanceMetrics()
pattern_matcher = None

def initialize_matcher():
    """Initialize pattern matcher with loaded rules."""
    global pattern_matcher
    pattern_matcher = PatternMatcher(RULES)
    algo_type = "Aho-Corasick" if pattern_matcher.use_ahocorasick else "Naive String Matching"
    log_event(f"Pattern matcher initialized using {algo_type} algorithm", event_type="INFO")

def check_packet(payload, src_ip, dst_port):
    """Checks packet against defined rules with optimized pattern matching.
    
    Uses Aho-Corasick algorithm for O(n+z) complexity instead of O(n*m).
    
    Args:
        payload (str): Decoded packet payload
        src_ip (str): Source IP address
        dst_port (int): Destination port
        
    Returns:
        tuple: (matched_rule, detection_time) or (None, detection_time)
    """
    return pattern_matcher.find_matches(payload, dst_port)

def sniffer(packet):
    """Sniffs all packets with optimized inspection pipeline.
    
    This packet inspection pipeline:
    1. Filters for IP/TCP packets (reduces processing)
    2. Extracts payload data efficiently
    3. Performs Aho-Corasick pattern matching against rules
    4. Triggers immediate IP blocking on detection
    """
    try:
        if not (packet.haslayer(IP) and packet.haslayer(TCP)):
            metrics.record_packet()
            return
        
        src_ip = packet[IP].src
        dst_port = packet[TCP].dport

        if packet.haslayer(Raw):
            try:
                # Decode payload with error tolerance
                payload = packet[Raw].load.decode('utf-8', errors='ignore')

                # Check against rules and track performance
                matched_rule, detection_time = check_packet(payload, src_ip, dst_port)
                metrics.record_packet(detection_time)

                if matched_rule:
                    print(f"[ALERT] Detected {matched_rule['name']} from {src_ip}:{dst_port} in {detection_time*1000:.2f}ms")
                    block_ip(src_ip, attack_type=matched_rule['name'], port=dst_port, response_time=detection_time)
                    
            except Exception as e:
                metrics.record_packet()
                log_event(f"Error decoding payload: {str(e)}", event_type="ERROR", src_ip=src_ip)
        else:
            metrics.record_packet()
            
    except Exception as e:
        log_event(f"Packet processing error: {str(e)}", event_type="ERROR")

def start_sniffing():
    """Initializes and starts the IPS packet sniffing pipeline.
    
    The IPS implements a comprehensive signature-based detection system:
    - Real-time monitoring on specified network interface
    - TCP payload inspection across 7+ critical ports
    - Sub-second response time from detection to firewall deployment
    - High-throughput processing (1000+ packets/second)
    - Aho-Corasick algorithm for efficient pattern matching
    - Comprehensive forensic logging for threat intelligence
    """
    print("\n" + "="*60)
    print("SIGNATURE-BASED INTRUSION PREVENTION SYSTEM (IPS)")
    print("="*60)
    
    # Initialize pattern matcher
    initialize_matcher()
    
    log_event(f"IPS started on interface {INTERFACE}", event_type="INFO")
    log_event(f"Loaded {len(RULES)} attack signatures", event_type="INFO")
    print(f"\nMonitoring ports: 21 (FTP), 22 (SSH), 25 (SMTP), 80 (HTTP), 443 (HTTPS), 389 (LDAP), 636 (LDAP-SSL), 3306 (MySQL), 5432 (PostgreSQL)\n")
    print("Press Ctrl+C to stop...\n")
    
    try:
        # Start packet sniffing with optimized configuration
        sniff(
            iface=INTERFACE, 
            prn=sniffer, 
            store=PACKET_PROCESSING_CONFIG["store_packets"],
            timeout=PACKET_PROCESSING_CONFIG["timeout"]
        )
    except KeyboardInterrupt:
        stats = metrics.get_stats()
        print("\n" + "="*60)
        print("IPS SHUTDOWN - PERFORMANCE SUMMARY")
        print("="*60)
        log_event(f"IPS stopped. Statistics: {stats}", event_type="INFO")
        print(f"Total Packets Processed: {stats['packets_processed']}")
        print(f"Avg Throughput: {stats['packets_per_second']} packets/sec")
        print(f"Avg Detection Time: {stats['avg_detection_time_ms']}ms")
        algo_type = "Aho-Corasick" if pattern_matcher.use_ahocorasick else "Naive String Matching"
        print(f"Pattern Matching Algorithm: {algo_type}")
        print("="*60 + "\n")
    except Exception as e:
        log_event(f"Critical IPS error: {str(e)}", event_type="ERROR")
        sys.exit(f"Error: {str(e)}")

if __name__ == "__main__":
    if os.getuid() != 0:
        sys.exit("Error: Run as root user.")
    start_sniffing()

def sniffer(packet):
    """Sniffs all packets with optimized inspection pipeline.
    
    This packet inspection pipeline:
    1. Filters for IP/TCP packets (reduces processing)
    2. Extracts payload data efficiently
    3. Performs pattern matching against rules
    4. Triggers immediate IP blocking on detection
    """
    try:
        if not (packet.haslayer(IP) and packet.haslayer(TCP)):
            metrics.record_packet()
            return
        
        src_ip = packet[IP].src
        dst_port = packet[TCP].dport

        if packet.haslayer(Raw):
            try:
                # Decode payload with error tolerance
                payload = packet[Raw].load.decode('utf-8', errors='ignore')

                # Check against rules and track performance
                matched_rule, detection_time = check_packet(payload, src_ip, dst_port)
                metrics.record_packet(detection_time)

                if matched_rule:
                    print(f"[ALERT] Detected {matched_rule['name']} from {src_ip}:{dst_port} in {detection_time*1000:.2f}ms")
                    block_ip(src_ip, attack_type=matched_rule['name'], port=dst_port, response_time=detection_time)
                    
            except Exception as e:
                metrics.record_packet()
                log_event(f"Error decoding payload: {str(e)}", event_type="ERROR", src_ip=src_ip)
        else:
            metrics.record_packet()
            
    except Exception as e:
        log_event(f"Packet processing error: {str(e)}", event_type="ERROR")

def start_sniffing():
    """Initializes and starts the IPS packet sniffing pipeline.
    
    The IPS implements a comprehensive signature-based detection system:
    - Real-time monitoring on specified network interface
    - TCP payload inspection across 7+ critical ports
    - Sub-second response time from detection to firewall deployment
    - High-throughput processing (1000+ packets/second)
    - Aho-Corasick algorithm for efficient pattern matching
    - Comprehensive forensic logging for threat intelligence
    """
    print("\n" + "="*60)
    print("SIGNATURE-BASED INTRUSION PREVENTION SYSTEM (IPS)")
    print("="*60)
    
    # Initialize pattern matcher
    initialize_matcher()
    
    log_event(f"IPS started on interface {INTERFACE}", event_type="INFO")
    log_event(f"Loaded {len(RULES)} attack signatures", event_type="INFO")
    print(f"\nMonitoring ports: 21 (FTP), 22 (SSH), 25 (SMTP), 80 (HTTP), 443 (HTTPS), 389 (LDAP), 636 (LDAP-SSL), 3306 (MySQL), 5432 (PostgreSQL)\n")
    print("Press Ctrl+C to stop...\n")
    
    try:
        # Start packet sniffing with optimized configuration
        sniff(
            iface=INTERFACE, 
            prn=sniffer, 
            store=PACKET_PROCESSING_CONFIG["store_packets"],
            timeout=PACKET_PROCESSING_CONFIG["timeout"]
        )
    except KeyboardInterrupt:
        stats = metrics.get_stats()
        print("\n" + "="*60)
        print("IPS SHUTDOWN - PERFORMANCE SUMMARY")
        print("="*60)
        log_event(f"IPS stopped. Statistics: {stats}", event_type="INFO")
        print(f"Total Packets Processed: {stats['packets_processed']}")
        print(f"Avg Throughput: {stats['packets_per_second']} packets/sec")
        print(f"Avg Detection Time: {stats['avg_detection_time_ms']}ms")
        algo_type = "Aho-Corasick" if pattern_matcher.use_ahocorasick else "Naive String Matching"
        print(f"Pattern Matching Algorithm: {algo_type}")
        print("="*60 + "\n")
    except Exception as e:
        log_event(f"Critical IPS error: {str(e)}", event_type="ERROR")
        sys.exit(f"Error: {str(e)}")

if __name__ == "__main__":
    if os.getuid() != 0:
        sys.exit("Error: Run as root user.")
    start_sniffing()