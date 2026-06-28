# Learning Notes — Live Demo & SIEM Dashboard

Working notes on what was added, how it works, and why it was built this way.
Every decision here should survive an interview question.

## Goal

Make the IPS demonstrable live — on any machine, in minutes — without
weakening the claim that what's on screen is the real system. Two additions:

1. `tools/traffic_simulator.py` — generates benign + attack traffic and runs
   it through the production detection pipeline.
2. `dashboard/` — a read-only SIEM-style web dashboard over `ips_events.log`.

Constraint honored throughout: **zero changes to the detection pipeline**
(`Handling/`, `Configurations/`). The demo layers sit beside production code
and consume its real interfaces.

## 1. Traffic Simulator (`tools/traffic_simulator.py`)

**What:** CLI that emits a mixed stream of benign payloads (HTTP requests,
SSH banners, SMTP greetings) and attack payloads built from the actual
signatures in `Configurations/rules.json`, then feeds each one through
`PatternMatcher.find_matches()` and logs via `log_event()`.

**How:**
- `TrafficSimulator` is a pure generator class — no I/O, no sleeps — so tests
  can drive it deterministically with a seeded `random.Random`.
- `build_attack_payload()` embeds a rule's pattern into a realistic HTTP
  request (for web ports) or raw payload (for service ports), and picks the
  destination port from that rule's own `ports` list.
- Detection is not faked at any point: if the matcher misses, nothing is
  logged. A test (`test_attack_events_are_detected_by_the_real_matcher`)
  pins this property.
- Block decisions use the production `ThresholdTracker` (same sliding-window
  logic as the sniffer). The only substitution: instead of invoking
  iptables/netsh, a `BLOCK` event tagged `(simulated)` is logged.

**Why these choices:**
- *Why not fake log lines directly?* Because then the demo proves nothing.
  Running payloads through the real matcher means every ALERT on the
  dashboard is a genuine detection by production code.
- *Why not run the real sniffer + real attacks?* Raw packet capture needs
  root and a live interface; auto-installing firewall rules on a demo/
  interview machine is reckless. The simulator bypasses exactly two layers —
  capture (scapy) and enforcement (subprocess to the firewall) — and nothing
  else.
- *Why RFC 5737 addresses (203.0.113.x, 198.51.100.x, 192.0.2.x)?* They are
  reserved for documentation, so simulated logs can never be confused with
  real hosts or leak anything meaningful.
- *Why a small fixed attacker pool?* Threshold blocking (5 hits / 60 s) only
  fires when the same source repeats. Repeat offenders make the BLOCK path
  visible during a short demo.
- *Why is `--log-file` handled via `IPS_LOG_FILE` before importing config?*
  `Configurations.config` reads the environment at import time, so the
  override must be exported first. That's also why the pipeline imports live
  inside `main()` rather than at module top.

## 2. Log Parser (`dashboard/log_reader.py`)

**What:** Parses the forensic format `log_event()` writes:
`[timestamp] [TYPE] message | SRC_IP: x | ATTACK: y | PORT: n | RESPONSE_TIME: z ms`.

**How:** A regex captures timestamp/type/rest; forensic fields are then
peeled off the *right-hand end* of the line, accepting only known keys.

**Why:**
- *Why read the log file instead of adding a database or message queue to
  the IPS?* The log file is already the system's forensic source of truth.
  Reading it means the dashboard shows exactly what the IPS recorded and the
  detection pipeline needed zero modification. Fewer moving parts, nothing
  new to secure.
- *Why parse fields right-to-left?* The free-text message can legitimately
  contain `" | "` (the startup banner does: `Mode: block | Threshold: ...`).
  Splitting left-to-right would corrupt those messages; peeling known
  `KEY: value` suffixes from the right cannot.
- *Why does `follow()` poll instead of using inotify?* Portability. The IPS
  already supports Linux and Windows firewall backends; a Linux-only watch
  API would break that parity. 0.5 s polling is imperceptible on a dashboard.
- *Bug found during integration testing:* the first version of `follow()`
  started at byte 0, so the browser received the entire history twice (once
  from the backfill endpoint, once replayed over SSE). Fix: start at the
  current end of file, keep `from_start=True` for tests. Lesson — always
  smoke-test the composed system, not just units; both halves were
  individually "correct".
