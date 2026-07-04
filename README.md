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


## Live Demo — Traffic Simulator

The IPS can be demonstrated without root, scapy capture, or real attack
traffic. `tools/traffic_simulator.py` replays benign and malicious payloads
through the **production** `PatternMatcher` and threshold-blocking logic —
only packet capture and the firewall side effect are bypassed. Simulated
sources use RFC 5737 documentation addresses.

```
python tools/traffic_simulator.py --rate 5 --attack-ratio 0.3
```

Flags: `--rate` events/sec, `--duration` seconds (0 = run until Ctrl+C),
`--attack-ratio` fraction of malicious events, `--seed` for reproducible
runs, `--log-file` to override the log path.

## SIEM Dashboard

> **Launching the HTML UI:** the dashboard *is* an HTML app served locally.
> Run `python -m dashboard.app` and it starts the server and pops the page
> open in your browser at `http://127.0.0.1:5000`. No build step, no separate
> web server — one command. (`IPS_DASHBOARD_OPEN_BROWSER=0` to skip the
> auto-open on a headless/remote host.)


A SOC-style dashboard over `ips_events.log`: live event feed (server-sent
events), events-over-time and attack-mix charts, top attacking sources,
blocked IPs, and an **injection panel** for feeding synthetic requests to the
IPS live (see below). Works with the real sniffer or the simulator.

```
pip install -r REQUIREMENTS.txt
python -m dashboard.app                      # opens http://127.0.0.1:5000 in your browser
python tools/traffic_simulator.py --rate 5   # optional: background traffic (or run the real IPS)
```

`python -m dashboard.app` launches the HTML UI and opens it in your default
browser automatically (disable with `IPS_DASHBOARD_OPEN_BROWSER=0`). The
dashboard binds to localhost only.

### Injecting synthetic traffic

The dashboard's **Inject Synthetic Traffic** panel lets you type or pick a
request payload, choose a port, and submit it to the IPS in real time. Each
injection is run through the *real* `PatternMatcher` (and threshold logic), so
a detection on the panel is a genuine detection — the result is echoed back
and the event lands in the live feed over SSE. Quick-attack presets are
derived from the loaded signatures, so every attack preset is guaranteed to
trip a real rule.

Injection is *input* to the detection pipeline, never *control*: it cannot
change a rule, the mode, or a firewall entry, and it never invokes the real
firewall (a threshold breach is logged as a simulated block). Turn it off for
a pure-monitoring view with `IPS_DASHBOARD_ALLOW_INJECT=0`.

See `learning.md` for the full design rationale.
