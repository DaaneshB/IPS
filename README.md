# Signature-Based Intrusion Prevention System (IPS)

A high-performance, signature-based Intrusion Prevention System built with Python and Scapy for real-time network traffic monitoring and automated threat response.

## Overview

The IPS is engineered for production-grade network defense, continuously monitoring inbound TCP and UDP traffic across critical ports (FTP, SSH, SMTP, HTTP, HTTPS, LDAP, MySQL, PostgreSQL) to detect and block malicious patterns in real-time. The system achieves sub-second response times from threat detection to firewall rule deployment.

## Key Features

### Real-time Packet Inspection Pipeline
- **TCP Payload Analysis**: Decodes and inspects packet contents with error tolerance
- **Optimized Processing**: Non-blocking packet capture with configurable memory management
- **High Throughput**: Engineered to handle 10000+ packets per second
- **Multi-Port Monitoring**: Inspects traffic across 10+ critical ports simultaneously

### Signature-Based Detection Engine
Detects and blocks 30+ attack patterns including:

**SQL Injection Attacks**
- Union-based SQL injection
- Boolean-based blind SQL injection  
- Time-based blind SQL injection

**Cross-Site Scripting (XSS)**
- HTML script tag injection
- JavaScript event handler injection

**Directory Traversal**
- Linux path traversal (/etc/shadow)
- Windows path traversal (\windows\system32)
- Dot-dot directory traversal attacks

**Automated Vulnerability Scanners**
- sqlmap detection
- Nikto web scanner detection
- Nmap NSE script detection

**Remote Code Execution (RCE)**
- PHP reverse shell exploitation (c99.php)
- Log4j JNDI injection (CVE-2021-44228)
- Command injection (Linux and Windows variants)

### Automated IP Blocking with Sub-Second Response
- Immediate firewall rule deployment (iptables on Linux, netsh on Windows)
- Response time tracking from detection to block execution
- Duplicate blocking prevention with in-memory cache
- Error handling and retry logic

### Comprehensive Event Logging & Forensics
- Structured logging with millisecond-precision timestamps
- Complete forensic data capture:
  - Source IP address
  - Attack type/signature matched
  - Destination port
  - Detection time
  - Block execution time
  - Total response time
- Real-time console output for monitoring
- Persistent file logging for threat intelligence analysis

### Performance Metrics & Monitoring
- Real-time throughput calculation (packets/second)
- Detection latency tracking (milliseconds)
- Pre-formatted statistics summary on shutdown
- Performance optimization via selective packet storage


### Packet Processing Pipeline
```
1. Packet Capture (Scapy layer 2/3)
   ↓
2. Layer Filtering (IP + TCP validation)
   ↓
3. Payload Extraction (Raw layer decoding)
   ↓
4. Pattern Matching (Rule engine against 30+ signatures)
   ↓
5. Threat Response (Automated IP blocking)
   ↓
6. Forensic Logging (Detailed event documentation)
```

## Running the Tests

The detection engine, configuration loader, metrics, and response logic are
covered by a pytest suite that runs without root or a live interface:

```
pip install -r REQUIREMENTS.txt
pytest
```

