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

- **Per-port UDP + TCP sweep** — reachability, packet loss, latency
  statistics (min / avg / p95 / max / stddev), and MTU sweep at 1200 /
  1400 / 1472 byte payloads against every port Space Engineers, Torch,
  and Steam use.
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
| NAT idle-timeout (30 + 60 s) | CGNAT idle-mapping eviction — the most common T-Mobile 5G Home symptom ("I get disconnected after a few minutes"). Pass `--full` for the longer 30 / 60 / 120 / 300 s ladder. |
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
| Asset | `sdg-connection-test-vX.Y.Z-windows-x64.zip` (~32 MiB) | `sdg-connection-test-vX.Y.Z.zip` (~100 KB) |
| Includes | Pre-bundled Node.js 22 LTS runtime, double-click launcher | Source only — bring your own Node 20+ |
| To run | Double-click `Run-Test.cmd`; report lands in the same folder | `node client/client.js --yes` (defaults to `38.107.232.39`) |

Both are attached to every [GitHub Release](https://github.com/sdg-net/sdg-connection-test/releases/latest).
Customer-facing download portal: <https://sdg.knowledgeondemand.net>

### Windows easy-install (recommended for end users)

1. Download `sdg-connection-test-vX.Y.Z-windows-x64.zip` from the
   [latest release](https://github.com/sdg-net/sdg-connection-test/releases/latest).
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
git clone https://github.com/sdg-net/sdg-connection-test.git
cd sdg-connection-test/client
node client.js --yes
```

`--host` defaults to `38.107.232.39` (SDG's public connection-test
endpoint), so unzip-and-run requires no flags. Override only if SDG
support has given you a different endpoint, e.g.
`node client.js --host 38.107.232.39 --yes`.

Add `--json report.json` to also write a JSON report. Zero `npm install`
step — the project ships with no dependencies.

## Reading the output

Every row in the per-port table should come back green. Loss > 0
indicates a problem; the client distinguishes ISP loss from server-side
rate-limiting in the `RL` column so the limiter never causes a false
positive against the ISP under test.

The server-dependent tests (`nat-type` and `bidir up`/`both`)
gracefully degrade against a v1.0.0 server: the client probes for
support and prints `SKIPPED (server too old)` if not present.
Reflected public IP is redacted by default in both the console output
and the `--json` report — pass `--include-public-ip` to opt in.

## Common flags

| Flag | Default | What it does |
| --- | --- | --- |
| `--host <addr>` | `38.107.232.39` | Override the SDG public endpoint. |
| `--json <file>` | (none) | Write a full JSON report to `<file>`. |
| `--yes`, `-y` | prompt | Skip the "what this will do" confirmation. |
| `--family <4\|6\|auto>` | `auto` | Force IPv4, IPv6, or let the OS pick. Use `4` on a v6-native network (e.g. T-Mobile 5G Home Internet w/ 464XLAT) if you suspect Happy-Eyeballs is masking the problem. |
| `--ports <p1,p2,...>` | full matrix | Limit the per-port sweep to specific ports. |
| `--real-server <host:port>` | (none) | A2S-query the customer's actual Torch server for side-by-side comparison. |
| `--bidir <down\|up\|both>` | `both` | Sustained-test direction. |
| `--duration <seconds>` | `10` | Override the sustained test duration (capped at 300 s). |
| `--up-pps <n>` | `60` | Upstream rate when `--bidir != down`. Capped at 200 pps. |
| `--nat-idle <s1,s2,...>` | `30,60` | Custom NAT-idle windows (max 600 s each). |
| `--full` | off | Run the full NAT-idle ladder: 30 / 60 / 120 / 300 s (~10 min total). |
| `--include-public-ip` | off | Don't redact the reflected source IP. |
| `--no-sustained`, `--no-a2s`, `--no-nat-idle`, `--no-nat-type`, `--no-burst`, `--no-source-fanout`, `--no-payload-shape` | all on | Dial back individual tests. |

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
worked fine over a Verizon cellular hotspot and failed over T-Mobile
5G Home Internet, from the same laptop, against the same Torch server.
We needed hard evidence rather than another round of "try a different
DNS server" — and the diagnostic surface documented above is what hard
evidence looks like. CGNAT idle eviction, symmetric NAT, uplink-only
throttling, policer-vs-shaper fingerprinting, per-5-tuple shaping, and
DPI on payload content are all distinct failure modes that a naive
"can I reach the port?" test misses. Catching them one by one is the
job.
