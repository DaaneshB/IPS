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
