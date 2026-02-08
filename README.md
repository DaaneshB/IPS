# IPS
A signature-based Intrusion Prevention System built with Python and Scapy for real-time network traffic monitoring and threat detection.

Overview
The IPS monitors network traffic to detect common attack patterns and automatically blocking malicious IP addresses using iptables firewall rules. 

Features
Real-time Packet Inspection: Monitors network traffic using Scapy
Signature-Based Detection: Detects multiple attack types including:

  SQL Injection (Union-based and Boolean Blind)
  Cross-Site Scripting (XSS)
  Directory Traversal attacks (Linux & Windows)
  Automated scanners (sqlmap, Nikto)
  Remote Code Execution (Log4j vulnerability)
  PHP reverse shells
  Private key theft attempts


Automatic IP Blocking: Uses iptables to block detected threats
Event Logging: Maintains detailed logs of all security events
Configurable Rules: Easy-to-modify detection signatures

How It Works

Packet Capture: Scapy captures all packets on the specified network interface
Payload Inspection: TCP packets with data payloads are decoded and inspected
Pattern Matching: Packet contents are checked against defined attack signatures
Alert & Block: When a match is found:

  Event is logged with timestamp, attack type, source IP, and port
  Source IP is automatically blocked using iptables DROP rule


Continuous Monitoring: Process repeats for every incoming packet

