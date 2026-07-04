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

## 3. Dashboard Server (`dashboard/app.py`)

**What:** Flask app with three read endpoints — `/api/stats` (aggregates),
`/api/events/recent` (backfill), `/api/events/stream` (live SSE) — plus the
static page.

**Why:**
- *Why Flask?* Already used in my melanoma-detector project, no async
  framework needed for one long-lived stream per viewer, and every line is
  explainable. The dashboard is I/O-light; the heavy lifting (detection)
  happens in the IPS process.
- *Why Server-Sent Events instead of WebSockets?* The data flow is strictly
  one-directional (server → browser). SSE runs over plain HTTP, needs no
  extra dependency, and `EventSource` reconnects automatically. WebSockets
  would buy bidirectionality nobody uses and cost an extra library.
- *Why is the dashboard read-only?* A monitoring surface must not be a
  control surface. There is deliberately no endpoint to unblock an IP,
  change mode, or edit rules — a compromised dashboard can observe but not
  disarm the IPS. (Principle: separation of duties.)
- *Why cap parsing at 5,000 events per stats request?* Bounded work per
  request keeps response time flat after days of logging. Configurable via
  `IPS_DASHBOARD_MAX_EVENTS`.
- *Why `threaded=True`?* Each SSE viewer holds a connection open; the
  default single-threaded dev server would deadlock the stats endpoint.
- The server binds 127.0.0.1, not 0.0.0.0 — a security tool's demo should
  not itself open an unauthenticated network listener.

## 4. Dashboard UI (`dashboard/static/index.html`)

**What:** Single HTML file, dark SOC-style theme. Summary cards (events,
alerts, blocked IPs, avg detection ms), live feed table, events-over-time
line chart, attack-mix doughnut, top attackers and blocked-IP tables.

**Why:**
- *Why one file, vanilla JS + Chart.js from CDN?* No build step, no
  toolchain to defend. Anyone can View Source and account for every line.
- *Why escape every value into HTML (`esc()`)?* Log content includes raw
  attack payloads — literally `<script>` tags. Rendering unescaped log data
  in a security dashboard would make the dashboard itself XSS-able by the
  attacker it is displaying. This mirrors a real SIEM concern (log injection).
- *Feed capped at 100 rows; charts update with `animation: false`* — the
  page must stay responsive during sustained event rates.
- Backfill via `/api/events/recent`, then live via SSE; stats poll every 5 s.

## 5. Testing Approach

- Parser: exact field extraction, pipe-in-message edge case, malformed-line
  tolerance, aggregation math, timeline bucketing, empty inputs.
- Simulator: RFC 5737 containment, payload/port correctness against every
  rule, seed reproducibility, attack-ratio statistics, and the honesty
  property — every generated attack must trip the real matcher.
- End-to-end: `main()` writes a log the parser reads back (round-trip),
  using `monkeypatch` on `LOG_FILE` like the existing suite does.
- Naming/style follows the existing tests (`test_<behavior>` prose names,
  `tmp_path`/`monkeypatch` fixtures) so the suite reads as one voice.

## 6. Commit Discipline

Each file landed in two focused commits (skeleton/core, then enhancement) so
the history documents the build order, plus one standalone bugfix commit for
the SSE duplication issue found in integration testing — kept separate
because bugfixes hidden inside feature commits are unauditable.

## Running the Demo

```
pip install -r REQUIREMENTS.txt
python -m dashboard.app                          # terminal 1 — dashboard
python tools/traffic_simulator.py --rate 5       # terminal 2 — traffic
# open http://127.0.0.1:5000
```

## 7. Injection Panel (added in follow-up)

**What:** The dashboard gained an *Inject Synthetic Traffic* panel — payload
box, port picker, optional source IP, quick-attack presets — that submits a
request to the IPS live and shows what it decided. New backend piece:
`dashboard/injector.py`; new route: `POST /api/inject` (plus
`GET /api/inject/presets`).

**How:**
- `injector.inject()` runs the payload through a module-level
  `PatternMatcher(config.RULES)` and `ThresholdTracker` — the same production
  classes the sniffer uses. A match is written with `log_event()`, so the
  injected event flows into the same log the SSE feed tails and appears on the
  dashboard within the poll interval. The HTTP response echoes the decision
  (matched signature, detection ms, blocked?) so the analyst also gets
  immediate inline feedback.
- The matcher/tracker are process singletons: rebuilding per request would
  discard threshold state (so repeated injects from one source could never
  demonstrate a block) and needlessly recompile the automaton.
- Presets are generated from the live rules (`attack_presets()`), not typed
  into the frontend, so a preset can never drift out of sync with the rule
  set — a test asserts every attack preset trips a real detection.

**Why these choices:**
- *Why is an injection (write) endpoint acceptable when the dashboard was
  "read-only"?* The original principle was that monitoring must not double as
  a **control** plane — the dashboard must not be able to change rules, mode,
  or firewall state. Injection doesn't do any of that; it submits synthetic
  **input** to the detection pipeline. The refined, tested contract
  (`test_dashboard_exposes_no_ips_control_endpoints`) makes the boundary
  explicit: `/api/inject` is the *only* write route, and it cannot mutate IPS
  state. That's a defensible line, and it's enforced, not just asserted in a
  comment.
- *Why never call the real firewall?* An injected threshold breach logs a
  BLOCK tagged `(injected)`, exactly like the offline simulator. A dashboard
  must not be able to block a real host — synthetic traffic must have
  synthetic consequences only.
- *Why gate it behind `IPS_DASHBOARD_ALLOW_INJECT`?* A real deployment may
  want a pure-monitoring view with no submit path at all; the flag returns 403
  and the UI hides the panel.
- *Input validation up front* (non-empty payload, 8 KB cap, port 1–65535,
  well-formed IP) keeps malformed requests out of the pipeline and returns a
  clean 400 with a safe message.

## 8. Launching the HTML UI

`python -m dashboard.app` now starts the server **and** opens the HTML page in
the default browser (short `threading.Timer` so the server is up first;
best-effort, skipped on headless hosts or with `IPS_DASHBOARD_OPEN_BROWSER=0`).
The dashboard is a served HTML app rather than a file opened from disk because
the injection and live-stream features need the local backend — a `file://`
page couldn't reach the matcher or the log. One command is the whole launch.
