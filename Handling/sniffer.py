
import os
import sys
import time
from Configurations.config import INTERFACE, RULES
from Handling.post_detection import log_event, block_ip
from scapy.all import sniff, IP, TCP, Raw

def check_packet(payload, src_ip, dst_port):
    """Checks packet against defined rules."""
    for rule in RULES:
        if dst_port in rule["ports"] and rule["pattern"] in str(payload):
            log_event(f"Detected {rule['name']} from {src_ip} on port {dst_port}")
            block_ip(src_ip)
            return

def sniffer(packet):
    """Sniffs all packets."""
    if packet.haslayer(IP) and packet.haslayer(TCP):
        src_ip = packet[IP].src
        dst_port = packet[TCP].dport

        if packet.haslayer(Raw):
            try:
                #decode payload
                payload = (packet[Raw].load.decode('utf-8', errors='ignore'))
                check_packet(payload, src_ip, dst_port)
            except Exception as e:
                pass


def start_sniffing():
    log_event(f"IPS started on interface {INTERFACE}")
    log_event(f"Loaded {len(RULES)} rules.")

    sniff(iface=INTERFACE, prn=sniffer, store=0)

if __name__ == "__main__":
    if os.getuid() != 0:
        sys.exit("Error: Run as root user.")
    start_sniffing()