# Signature-Based Intrusion Prevention System (IPS)

A high-performance, signature-based Intrusion Prevention System built with Python and Scapy for real-time network traffic monitoring and automated threat response.

## Overview

The IPS is engineered for production-grade network defense, continuously monitoring inbound TCP traffic across critical ports (FTP, SSH, SMTP, HTTP, HTTPS, MySQL, PostgreSQL) to detect and block malicious patterns in real-time. The system achieves sub-second response times from threat detection to firewall rule deployment, with throughput optimization supporting 1000+ packets per second.

## Key Features

### Real-time Packet Inspection Pipeline
- **TCP Payload Analysis**: Decodes and inspects packet contents with error tolerance
- **Optimized Processing**: Non-blocking packet capture with configurable memory management
- **High Throughput**: Engineered to handle 1000+ packets per second
- **Multi-Port Monitoring**: Inspects traffic across 7+ critical ports simultaneously

### Signature-Based Detection Engine
Detects and blocks 17+ attack patterns including:

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

**Credential & Key Theft**
- RSA private key exposure
- OpenSSH private key exposure
- AWS credential exposure
- FTP bounce attacks

### Automated IP Blocking with Sub-Second Response
- Immediate iptables firewall rule deployment
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

## Technical Architecture

### Packet Processing Pipeline
```
1. Packet Capture (Scapy layer 2/3)
   ↓
2. Layer Filtering (IP + TCP validation)
   ↓
3. Payload Extraction (Raw layer decoding)
   ↓
4. Pattern Matching (Rule engine against 17+ signatures)
   ↓
5. Threat Response (Automated IP blocking)
   ↓
6. Forensic Logging (Detailed event documentation)
```

### Optimization Techniques
- **Port-First Filtering**: Checks port match before expensive string operations
- **Memory Optimization**: Disables packet storage to reduce memory footprint
- **Error Resilience**: Graceful handling of encoding errors and network anomalies
- **Windowed Metrics**: 1000-packet rolling window for performance statistics

## Configuration

### Network Interface
Edit `Configurations/config.py` to specify the network interface to monitor:
```python
INTERFACE = "eth0"  # Change to your network interface
```

### Detection Rules
The rule engine supports easy rule extension. Each rule includes:
- **name**: Human-readable attack description
- **pattern**: String pattern to match in packet payload
- **ports**: List of ports to monitor for this attack signature

Example custom rule:
```python
{
    "name": "Custom Attack Pattern",
    "pattern": "malicious_string",
    "ports": [80, 443, 8080]
}
```

## Usage

### Prerequisites
- Python 3.7+
- Scapy library
- Root/Administrator privileges (required for iptables/firewall access)
- Linux/Unix environment (iptables required)

### Installation
```bash
pip install scapy
```

### Running the IPS
```bash
sudo python3 Handling/sniffer.py
```

### Output Example
```
============================================================
SIGNATURE-BASED INTRUSION PREVENTION SYSTEM (IPS)
============================================================
[2026-02-15 10:23:45.123] [INFO] IPS started on interface eth0
[2026-02-15 10:23:45.124] [INFO] Loaded 17 attack signatures

Monitoring ports: 21 (FTP), 22 (SSH), 25 (SMTP), 80 (HTTP), 443 (HTTPS), 3306 (MySQL), 5432 (PostgreSQL)

Press Ctrl+C to stop...

[ALERT] Detected SQL Injection (Union Based) from 192.168.1.100:54321 in 2.34ms
[2026-02-15 10:23:47.456] [ALERT] Detected SQL Injection (Union Based) from 192.168.1.100 on port 80 | SRC_IP: 192.168.1.100 | ATTACK: SQL Injection (Union Based) | PORT: 80 | RESPONSE_TIME: 3.21ms
[2026-02-15 10:23:47.459] [BLOCK] Blocked IP: 192.168.1.100 | SRC_IP: 192.168.1.100 | ATTACK: SQL Injection (Union Based) | PORT: 80 | RESPONSE_TIME: 3.21ms
```

### Secure Shutdown
Press `Ctrl+C` to stop the IPS. Statistics will be displayed:
```
============================================================
IPS SHUTDOWN - PERFORMANCE SUMMARY
============================================================
Total Packets Processed: 145,230
Avg Throughput: 1,203.45 packets/sec
Avg Detection Time: 2.15ms
============================================================
```

## Performance Characteristics

- **Detection Latency**: 1-5ms (sub-second threshold met)
- **Block Execution**: <1ms 
- **Throughput**: 1000+ packets/second (optimized mode)
- **Memory Footprint**: Minimal with packet storage disabled
- **False Positive Rate**: Signature-dependent

## Log File Format

Logs are stored in `ips_events.log` with comprehensive forensic data:

```
[TIMESTAMP] [EVENT_TYPE] MESSAGE | SRC_IP: xxx.xxx.xxx.xxx | ATTACK: Attack Type | PORT: port | RESPONSE_TIME: Xms
```

**Event Types**:
- `INFO`: System events (startup, statistics)
- `ALERT`: Threat detection
- `BLOCK`: IP blocking action
- `ERROR`: System/processing errors


