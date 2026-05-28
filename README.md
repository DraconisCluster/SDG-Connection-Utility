# SDG Connection Test

A comprehensive UDP and TCP diagnostic for Space Engineers, Torch, and
Steam connectivity. The client probes every relevant port for
reachability, loss rate, latency stats, and MTU behavior; runs a real
Steam A2S query; pushes a bidirectional sustained game-shape stream;
fingerprints NAT behavior, traffic policers and shapers, per-5-tuple
shaping, and DPI on payload content. Results print to the console and,
on request, to a JSON file suitable for attaching to a support ticket.

This repository contains the **client** and the **shared protocol
definitions** that both sides of the diagnostic speak. The server is
operator-deployed; this repo contains everything you need to install
the client, audit what it does on your machine, and run it against an
operator-supplied test endpoint. What the operator-deployed server
may log about your connection is documented in
[`docs/PRIVACY.md`](docs/PRIVACY.md). The server implementation and
its hardening details are operator-internal.

## What it tests

### Baseline reachability (every run)

- **Per-port UDP + TCP sweep** — reachability, packet loss, and latency
  statistics (min / avg / p95 / max / stddev) against every port Space
  Engineers, Torch, and Steam use.
- **Adaptive MTU discovery** — walks UDP payload sizes from 1472 bytes
  (the standard ethernet ceiling) downward through 1400, 1300, 1280,
  1200, ... to find the largest size that still round-trips. Carrier
  sub-tunnels on 5G home internet commonly clamp UDP MTU somewhere in
  the 1280-1400 range; the descent names the exact ceiling so the
  recommendation engine can hand the user a copy-paste `netsh` /
  `ifconfig` / `ip link` command. The ceiling is then spot-checked on
  every other reachable UDP port to distinguish path-wide MTU clamp
  from per-port shaping.
- **Recommendation engine** — interprets the assembled report and
  emits structured remediation suggestions with platform-specific
  commands (Windows, macOS, Linux). Stable codes (`mtu-capped`,
  `mtu-severe`, `dpi-fingerprint`, `per-flow-shaping`,
  `test-inconclusive`, etc.) make it easy for support staff to grep
  transcripts. Output renders to the console as a `RECOMMENDATIONS`
  section and to a top-level `recommendations` array in the JSON
  report.
- **Test-inconclusive banner** — when >50% of UDP ports are
  unreachable, a `TEST INCONCLUSIVE` block prints ABOVE the per-port
  table so customers don't pattern-match on a sea-of-FAIL without
  realizing the test server itself is unreachable.
- **Real Steam A2S_INFO query** on UDP 27015 — full Steam protocol,
  validates that the server is answering as a real Steam endpoint
  would.
- **Sustained game-shape traffic** — ~60 pps, 200-400 byte payloads,
  10 seconds, **bidirectional by default**. Catches uplink-only
  throttling that a downstream-only test is blind to.
- **Optional real-server probe** — `--real-server <host:port>` sends
  the same A2S query to the customer's actual Torch server for
  side-by-side comparison with the SDG endpoint.

### Phase 1 diagnostics (on by default, ~3-4 min total)

| Test | What it diagnoses |
| --- | --- |
| NAT idle-timeout (30 + 60 s) | CGNAT idle-mapping eviction — the most common 5G home internet symptom ("I get disconnected after a few minutes"). Pass `--full` for the longer 30 / 60 / 120 / 300 s ladder. |
| NAT type classification | Cone vs symmetric NAT, via reflection probes on UDP 27016 + 27017. Tells you whether peer-to-peer needs a relay. |
| Bidirectional sustained | Uplink-only throttling, invisible to a downstream-only sustained test. `--bidir up\|down\|both` (default `both`). |
| Burst-vs-steady | Policer (token bucket — burst loss, steady fine) vs shaper (loss at both rates) vs random loss. |
| Source-port fan-out | Per-5-tuple shaping or unlucky ECMP path: probes from 4 different source ports — diverging loss → per-flow discrimination. |
| Payload-shape sensitivity | DPI by content fingerprint: same packet rate, three different payload patterns (game-shape, random, zero-fill) — diverging loss → DPI is making decisions on payload content. |

### Free derived metrics (no extra packets)

Two metrics extracted from the data the loss tests already collect, at
no additional traffic cost:

- **Loss-burst histogram** — runs of consecutive drops, bucketed
  (1 / 2-4 / 5-9 / 10+). Distinguishes isolated drops from sustained
  outages.
- **Packet-reordering count** — out-of-order arrivals. SE's
  interpolation stutters on reorder, so this is a real complaint
  pattern even when loss is zero.

### First-run capability probe

Before the Phase 1 tests start, the client runs a small capability
probe so v1.1+ tests skip cleanly with `SKIPPED (server too old)`
against a v1.0.0 server rather than failing noisily. Reflected public
IP is redacted by default in both the console output and the `--json`
report; pass `--include-public-ip` to opt in.

## How it works

1. The **server** (operator-deployed) listens on every TCP and UDP port
   SE, Torch, and Steam use. On UDP 27015 it answers real Steam
   A2S_INFO queries. On UDP 27016 it can push a game-shape traffic
   stream on demand. UDP 27016 + 27017 also serve as capability-aware
   reflection ports for the NAT-type test. Everything else is a plain
   echo for the small binary probe protocol. The wire format is fully
   specified in [`docs/PROTOCOL.md`](docs/PROTOCOL.md).
2. The **client** (in this repo) runs the test suite above against the
   server. Results print to the console and, on request, to a JSON
   file. The client opens no network connections except to the `--host`
   you pass on the command line, and optionally to the `--real-server`
   host.

## Repository layout

```
client/                  Zero-dep Node.js client + privacy-first README
shared/ports.js          single source of truth for the port matrix
shared/protocol.js       binary packet format, shared by client + server
shared/netUtils.js       small IP / dgram helpers shared by client + server
docs/PROTOCOL.md         byte-level wire protocol reference
docs/PRIVACY.md          what the operator-deployed server may log
docs/TRANSPARENCY.md     for security-conscious players
tools/build-bundle.py    builds the Windows easy-install zip
tools/Run-Test.cmd       launcher that ships inside the easy-install zip
tools/README-FIRST.txt   user guide that ships inside the easy-install zip
```

## Getting the client

Two builds, same diagnostic, same results — pick whichever fits your
situation:

| | **Windows easy-install** | **Source / developer** |
| --- | --- | --- |
| For | End users, players debugging connection issues, support tickets, non-technical staff | Auditing, contributors, Linux / macOS, anyone running against their own test endpoint |
| Asset | `sdg-connection-utility-vX.Y.Z-windows-x64.zip` (~32 MiB) | `sdg-connection-utility-vX.Y.Z.zip` (~100 KB) |
| Includes | Pre-bundled Node.js 22 LTS runtime, double-click launcher | Source only — bring your own Node 20+ |
| To run | Double-click `Run-Test.cmd`; report lands in the same folder | `node client/client.js --yes` (defaults to `38.107.232.39`) |

Both are attached to every [GitHub Release](https://github.com/DraconisCluster/SDG-Connection-Utility/releases/latest).
Customer-facing download portal: <https://sdg.knowledgeondemand.net>

### Windows easy-install (recommended for end users)

1. Download `sdg-connection-utility-vX.Y.Z-windows-x64.zip` from the
   [latest release](https://github.com/DraconisCluster/SDG-Connection-Utility/releases/latest).
2. Right-click → **Extract All**.
3. Open the extracted folder and double-click `Run-Test.cmd`. A console
   window opens.
4. Wait ~3-4 minutes. The console shows the verdict and a JSON report
   is written into the same folder as `Run-Test.cmd`, named
   `sdg-test-report-<timestamp>.json`.
5. Attach that JSON file to your SDG support ticket.

Read `README - START HERE.txt` inside the bundle for the same
instructions plus troubleshooting (SmartScreen warnings, etc.). The
target server address lives in `config.txt` and is normally not
something you need to touch.

### Source / developer

```
# Either: download the source-only zip from the latest release and unzip,
# or:
git clone https://github.com/DraconisCluster/SDG-Connection-Utility.git
cd SDG-Connection-Utility/client
node client.js --yes
```

`--host` defaults to `38.107.232.39` (SDG's public connection-test
endpoint), so unzip-and-run requires no flags. Override only if SDG
support has given you a different endpoint, e.g.
`node client.js --host 38.107.232.39 --yes`.

Add `--json report.json` to also write a JSON report. Zero `npm install`
step — the project ships with no dependencies.

## Reading the output

Three things to look at, in order:

1. **`TEST INCONCLUSIVE` banner** (if printed). When this block appears
   above the per-port table, more than half of UDP ports failed and the
   results below are partial. Usually means the test server is
   unreachable or the connection is severely degraded; rerun in 5
   minutes before drawing conclusions.

2. **`MTU ceiling discovered on udp 27016: <N> bytes`** line above the
   per-port table. `1472` means a clean ethernet MTU (cable/fiber).
   Anything below is a carrier or middlebox clamping UDP — see the
   `RECOMMENDATIONS` section for the exact fix.

3. **`RECOMMENDATIONS` section** at the bottom of the console output.
   Always renders. On a clean network it shows a single
   `[INFO] Network looks healthy` line; on a problem network it lists
   stable-coded recommendations (`mtu-capped`, `dpi-fingerprint`,
   `per-flow-shaping`, etc.) with a one-line `Action:` and a
   copy-paste-ready `Command:` for the host OS when applicable.

Every row in the per-port table should come back green. Loss > 0
indicates a problem; the client distinguishes ISP loss from server-side
rate-limiting in the `RL` column so the limiter never causes a false
positive against the ISP under test. The `mtu` column shows
pass/fail at the discovered ceiling (not the largest of a fixed sweep,
as in pre-v1.3 reports).

The server-dependent tests (`nat-type` and `bidir up`/`both`)
gracefully degrade against a v1.0.0 server: the client probes for
support and prints `SKIPPED (server too old)` if not present.
Reflected public IP is redacted by default in both the console output
and the `--json` report — pass `--include-public-ip` to opt in.

### JSON report shape (`--json <file>`)

The full report schema is `report.version: 2`. Notable top-level
fields:

- `mtuDiscovery: { ok, discoveredOn, descent, ceiling, ceilingConfidence }`
  — the full descent history (which sizes were probed and how many
  probes passed at each), the discovered ceiling in bytes, and a
  `'high' | 'medium' | 'none'` confidence label.
- `recommendations: [{ severity, code, title, detail, action }]` —
  one entry per fired rule. `action.platformCommands.{windows, macos,
  linux}` carries copy-paste commands; the console renders only the
  host-OS line, but JSON retains all three for cross-platform support
  workflows.
- `perPort[].mtuAtCeiling: { size, ok, rtt, probes }` — the
  spot-check result at the discovered ceiling on this UDP port.
- `perPort[].portSpecificShaping: true` — set only when the
  spot-check fails at the discovered ceiling for a specific port,
  signaling that this one port is shaped differently from the rest.
- `deprecated: ['perPort[].mtuSweep']` — `mtuSweep` is still
  populated as a one-element alias of `mtuAtCeiling` for backwards
  compatibility with pre-v2 `jq` queries; it will be removed in v1.4.

## Common flags

| Flag | Default | What it does |
| --- | --- | --- |
| `--host <addr>` | `38.107.232.39` | Override the SDG public endpoint. |
| `--json <file>` | (none) | Write a full JSON report to `<file>`. |
| `--yes`, `-y` | prompt | Skip the "what this will do" confirmation. |
| `--family <4\|6\|auto>` | `auto` | Force IPv4, IPv6, or let the OS pick. Use `4` on a v6-native network (e.g. 5G home internet with 464XLAT) if you suspect Happy-Eyeballs is masking the problem. |
| `--ports <p1,p2,...>` | full matrix | Limit the per-port sweep to specific ports. |
| `--real-server <host:port>` | (none) | A2S-query the customer's actual Torch server for side-by-side comparison. |
| `--bidir <down\|up\|both>` | `both` | Sustained-test direction. |
| `--duration <seconds>` | `10` | Override the sustained test duration (capped at 300 s). |
| `--up-pps <n>` | `60` | Upstream rate when `--bidir != down`. Capped at 200 pps. |
| `--nat-idle <s1,s2,...>` | `30,60` | Custom NAT-idle windows (max 600 s each). |
| `--full` | off | Run the full NAT-idle ladder: 30 / 60 / 120 / 300 s (~10 min total). |
| `--include-public-ip` | off | Don't redact the reflected source IP. |
| `--no-sustained`, `--no-a2s`, `--no-nat-idle`, `--no-nat-type`, `--no-burst`, `--no-source-fanout`, `--no-payload-shape`, `--no-mtu-discovery` | all on | Dial back individual tests. |

`node client.js --help` prints the full option list with longer
explanations.

## Auditing the client

See [`client/README.md`](client/README.md) and
[`docs/TRANSPARENCY.md`](docs/TRANSPARENCY.md). The client is a single
~2,200-line JavaScript file with zero runtime dependencies. Paranoid
players are actively encouraged to read it before running it.

## Zero runtime dependencies

The client uses only Node.js built-ins. There is no `npm install` step.
This is intentional: it keeps the client auditable and its supply chain
minimal — the entire surface is the Node.js standard library plus the
three small files in `shared/`.

For the source / developer install, you need **Node.js 20 or later**.
The Windows easy-install bundle ships with a pinned Node.js 22 LTS
runtime so end users don't need to install anything.

## Origin

This tool exists because of a real customer case: Space Engineers
worked fine over a cellular hotspot and failed over 5G home internet,
from the same laptop, against the same Torch server.
We needed hard evidence rather than another round of "try a different
DNS server" — and the diagnostic surface documented above is what hard
evidence looks like. CGNAT idle eviction, symmetric NAT, uplink-only
throttling, policer-vs-shaper fingerprinting, per-5-tuple shaping, and
DPI on payload content are all distinct failure modes that a naive
"can I reach the port?" test misses. Catching them one by one is the
job.
