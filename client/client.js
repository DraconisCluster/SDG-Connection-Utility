#!/usr/bin/env node
/*
 * SDG Connection Test — client.
 *
 * WHAT THIS TOOL DOES
 *   Sends small test packets to an SDG-operated diagnostic server on the
 *   TCP and UDP ports that Space Engineers, Torch, and Steam use, and
 *   reports whether the packets got through, how long they took, and how
 *   many were lost. It exists to prove or disprove the hypothesis that a
 *   specific ISP is blocking or throttling the traffic your game needs.
 *
 * WHAT THIS TOOL DOES NOT DO
 *   - It does NOT read any game files, save files, or Steam files.
 *   - It does NOT read or transmit your username, computer name, env vars,
 *     installed software, or any other system information.
 *   - It does NOT open any network connection except to the --host you
 *     pass on the command line (and optionally the --real-server host).
 *   - It does NOT modify your firewall, registry, or any system setting.
 *   - It does NOT auto-update itself or download any additional code.
 *   - It writes one file and only if you pass --json: a local report file
 *     in the current directory. Nothing is uploaded anywhere.
 *
 * HOW TO AUDIT IT
 *   1. This file is the only code that runs. It has zero runtime
 *      dependencies — it uses only Node.js built-ins (net, dgram, crypto,
 *      dns/promises, perf_hooks, fs/promises, process, util).
 *   2. Two sibling files are also loaded: ../shared/ports.js (the port
 *      list) and ../shared/protocol.js (the binary packet format). Both
 *      are small and fully commented. Read them.
 *   3. Every byte sent on the wire is documented in ../docs/PROTOCOL.md
 *      and cross-referenced with a Wireshark capture in
 *      ../docs/TRANSPARENCY.md. The session nonce printed at startup
 *      appears in bytes 8..15 of every outbound packet, so you can filter
 *      your Wireshark capture on that nonce and see exactly what the
 *      client sent.
 *   4. There are no eval()s, no dynamic requires, no network calls hidden
 *      behind abstractions. Search this file for 'require(', 'net.',
 *      'dgram.', 'fs.' — those are the only I/O points.
 *
 * LICENSE
 *   Provided as-is for diagnostic use by SDG customers. See top-level
 *   README.md.
 */

'use strict';

// ---- I/O surface: these are the ONLY Node built-ins used. ----
const net        = require('net');
const dgram      = require('dgram');
const dns        = require('dns/promises');
const crypto     = require('crypto');
const fs         = require('fs/promises');
const readline   = require('readline');
const { performance } = require('perf_hooks');

const { PORTS, GAME_SHAPE_PORT, A2S_PORT } = require('../shared/ports');
const protocol = require('../shared/protocol');
const { dgramTypeFor, normalizeIp } = require('../shared/netUtils');

// ---- Tunables. Nothing here should need changing during normal runs. ----
const PROBE_TIMEOUT_MS   = 2000;
const LOSS_PACKET_COUNT  = 50;
const LOSS_INTERVAL_MS   = 100;      // 10 pps
// MTU descent — payload sizes for adaptive MTU discovery. Sized from
// the max that fits in a 1500-byte ethernet frame (1472 = 1500 - 20B
// IPv4 - 8B UDP) down to the IPv4 minimum (576). 5G home internet
// providers commonly clamp UDP somewhere in the 1280-1400 range due
// to mobile sub-tunnel encapsulation overhead, which is invisible to
// the OS — packets just disappear above the ceiling. Walking down
// finds the actual working size rather than just confirming "1400 is
// dropped." Discovery stops at the first size that round-trips.
const MTU_DESCENT_BYTES    = Object.freeze([1472, 1400, 1300, 1280, 1200, 1100, 1000, 900, 800, 576]);
// IPv6 starts 20 bytes lower (40-byte v6 header vs. 20-byte v4).
const MTU_DESCENT_BYTES_V6 = Object.freeze([1452, 1400, 1300, 1280, 1200, 1100, 1000, 900, 800, 576]);
// Per-size probe count and the threshold for "size passed".
const MTU_PROBES_PER_SIZE  = 3;
const MTU_PASS_THRESHOLD   = 2;          // >=2/3 succeed => passed
// Borderline (exactly 2/3): retry with 3 more probes, require 4/6.
const MTU_TIEBREAKER_TOTAL = 6;
const MTU_TIEBREAKER_PASS  = 4;
// Per-probe spacing within a size class. Matches udpLossTest cadence
// so loss measurements are apples-to-apples.
const MTU_PROBE_SPACING_MS = 100;
// Stability check at 1472 — only fires when there's a suspicious
// signal (an RTT spike at 1472 vs. baseline). If <90% of these
// verification probes pass, downgrade ceiling to 1400 and emit a
// "mtu-marginal" recommendation.
const MTU_STABILITY_PROBES = 5;
const MTU_STABILITY_PASS_PCT = 0.9;
// Rate-limit backoff before retry (one retry, then give up).
const MTU_RATE_LIMIT_BACKOFF_MS = 500;
// Fallback discovery target ports tried in order if the primary
// (UDP 27016) fails the 576B probe.
const MTU_FALLBACK_PORTS   = Object.freeze([8766, 27015, 27443]);
const SUSTAINED_MS       = 10_000;   // game-shape test duration
const SUSTAINED_PPS      = 60;       // expected server rate; used only for
                                     // reporting, not for sending.
const TCP_CONNECT_TIMEOUT_MS = 3000;

// Phase 1 tunables.
const CAPABILITY_PROBE_PORT = 27443;       // baseline UDP port; both legacy
                                           // and v2 servers must listen here.
const CAPABILITY_PROBE_TIMEOUT_MS = 1500;
// Phase 2 tunables.
//
// Source-port fan-out: open N=4 sockets in sequence, each gets a fresh
// ephemeral source port from the kernel. 20 packets per socket × 4
// sockets = 80 probes total; total wall-clock ~16s. We stay sequential
// (rather than parallel) so the four flows don't compete for path or
// kernel send-buffer state — each is an isolated measurement.
const FANOUT_SOCKET_COUNT  = 4;
const FANOUT_PACKETS_EACH  = 20;
// Payload-shape sensitivity: three patterns × 25 packets = 75 probes;
// total wall-clock ~13s. Patterns chosen to expose DPI by signature:
//
//   game-shape  — zero-padded to 200..400 bytes, mimicking SE traffic
//   random      — 256 bytes of crypto-random, looks like nothing
//   zero-fill   — 200 bytes of zero, looks like nothing
//
// If the path passes one but drops another, a DPI device is making
// content-based decisions. The patterns are sent on the SE port
// (UDP 27016) because that's the most likely target of game-aware DPI.
const PAYLOAD_SHAPE_PACKETS_EACH = 25;
// NAT idle-timeout test default windows. CGNAT idle is the single most
// common cause of mid-session SE disconnects on 5G home internet; the
// 30/60/120/300 ladder brackets the documented carrier values.
const NAT_IDLE_WINDOWS_DEFAULT = Object.freeze([30, 60, 120, 300]);
// Reflection-padded probe size. The protocol requires a probe of >=60
// bytes for reflection so the REFLECT_REPLY can be padded to match
// the inbound packet size.
const REFLECT_PROBE_BYTES = 64;
// Burst-vs-steady policer test. Capped at 100 packets so we stay well
// under any reasonable server-side rate limit; any RATE_LIMITED
// replies are subtracted from "loss" so server-side rate-limiting
// never masquerades as an ISP policer.
const BURST_PACKET_COUNT = 100;
const STEADY_PACKET_COUNT = 100;
const STEADY_INTERVAL_MS = 100;     // 10 pps — same as LOSS_INTERVAL_MS
const BURST_PORT = 27443;           // baseline; isolates the test from any
                                    // game-port-specific DPI/shaping
// Default upstream rate for bidirectional sustained test. 60 pps mimics
// the downstream shape; capped at 200 to bound how much traffic the
// client puts on the wire (200 pps × 400 B × 300 s = ~24 MB worst case).
const UP_PPS_DEFAULT = 60;
const UP_PPS_MAX     = 200;

// ---- CLI parsing: tiny, no deps, no getopt. ----
//
// Default --host is the SDG-operated public test endpoint. The whole point
// of the customer-facing client is "unzip, run, send results to support",
// so requiring an extra flag is friction. SDG support can still tell a
// customer to override with --host if a side-by-side test is needed against
// a different endpoint. The Windows easy-install bundle still passes
// --host explicitly from config.txt, so this default only affects the
// source/developer path.
const DEFAULT_HOST = '38.107.232.39';

function parseArgs(argv) {
  const out = {
    host: DEFAULT_HOST,
    ports: null,              // null = all
    sustained: true,
    a2s: true,
    realServer: null,         // 'host:port' or null
    json: null,
    yes: false,
    duration: SUSTAINED_MS,
    family: 0,                // 0 = OS-default (auto), 4 = force IPv4, 6 = force IPv6
    help: false,
    // Phase 1 defaults are ON. The whole point of the tool is blame
    // attribution, and the Phase 1 tests are exactly what catches the
    // hard cases (CGNAT idle eviction, symmetric NAT, uplink throttling,
    // policer fingerprinting). The runtime cost is bounded: the only
    // expensive piece is the NAT idle ladder, which we cap at 30+60 s
    // by default. Operators who want the longer 120/300 s windows can
    // pass --full or --nat-idle 30,60,120,300 explicitly.
    natIdle: [30, 60],        // null = skip; --full extends to 30,60,120,300
    natType: true,
    bidir: 'both',            // 'down' (legacy), 'up', or 'both'
    burst: true,
    upPps: UP_PPS_DEFAULT,
    includePublicIp: false,   // redact reflected IP in console + JSON unless set
    // Phase 2 defaults — also ON. Costs ~30s combined and surfaces
    // failure modes the L3/L4 + Phase 1 sweep misses (per-flow
    // shaping, DPI by payload signature, loss-burst patterns).
    sourcePortFanout: true,
    payloadShape: true,
    // Adaptive MTU discovery — ON by default. Replaces the legacy
    // per-port 3-size sweep. Costs ~5s on a typical capped-MTU path,
    // ~1s on a clean cable/fiber path. Pass --no-mtu-discovery to
    // skip (e.g. when running with --ports filter that excludes all
    // critical UDP ports).
    mtuDiscovery: true,
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if      (a === '--host')        out.host = argv[++i];
    else if (a === '--ports')       out.ports = argv[++i].split(',').map(s => s.trim());
    else if (a === '--no-sustained') out.sustained = false;
    else if (a === '--no-a2s')      out.a2s = false;
    else if (a === '--real-server') out.realServer = argv[++i];
    else if (a === '--json')        out.json = argv[++i];
    else if (a === '--yes' || a === '-y') out.yes = true;
    else if (a === '--duration')    {
      const sec = Number(argv[++i]);
      // Cap at 5 minutes. The default is 10 s; longer runs accumulate
      // sequence numbers in seenSeqs without bound. 300 s @ 60 pps =
      // 18000 entries, ~150 KB — well within reason. Beyond that the
      // test isn't really diagnostic anyway.
      if (!Number.isFinite(sec) || sec <= 0) {
        console.error(`--duration must be a positive number (got "${argv[i]}")`); out.help = true;
      } else if (sec > 300) {
        console.error(`--duration capped at 300 seconds (got ${sec})`); out.help = true;
      } else {
        out.duration = sec * 1000;
      }
    }
    else if (a === '--family') {
      const f = argv[++i];
      if (f === '4' || f === 'ipv4')      out.family = 4;
      else if (f === '6' || f === 'ipv6') out.family = 6;
      else if (f === 'auto' || f === '0') out.family = 0;
      else { console.error(`--family must be 4, 6, or auto (got "${f}")`); out.help = true; }
    }
    else if (a === '--nat-idle') {
      // Optional comma-separated list of idle seconds. If the next argv
      // looks like a flag (starts with '-') or is missing, use the
      // default ladder. Otherwise consume it.
      const next = argv[i + 1];
      if (next == null || next.startsWith('-')) {
        out.natIdle = [...NAT_IDLE_WINDOWS_DEFAULT];
      } else {
        i++;
        const parts = next.split(',').map(s => Number(s.trim()));
        if (parts.some(n => !Number.isFinite(n) || n <= 0 || n > 600)) {
          console.error(`--nat-idle values must be positive seconds <= 600 (got "${next}")`);
          out.help = true;
        } else {
          out.natIdle = parts;
        }
      }
    }
    else if (a === '--nat-type') out.natType = true;
    else if (a === '--no-nat-type') out.natType = false;
    else if (a === '--burst')    out.burst = true;
    else if (a === '--no-burst') out.burst = false;
    else if (a === '--no-nat-idle') out.natIdle = null;
    else if (a === '--full') {
      // Run the full Phase 1 ladder: NAT idle out to 300 s. Total
      // runtime ~10 minutes. Use this when the default 30+60 s ladder
      // doesn't surface anything but the customer is still reporting
      // mid-session disconnects — the longer windows catch CGNAT
      // eviction policies that don't trip until 2+ minutes of idle.
      out.natIdle = [30, 60, 120, 300];
    }
    else if (a === '--bidir') {
      const v = argv[++i];
      if (v === 'down' || v === 'up' || v === 'both') out.bidir = v;
      else { console.error(`--bidir must be down|up|both (got "${v}")`); out.help = true; }
    }
    else if (a === '--up-pps') {
      const n = Number(argv[++i]);
      if (!Number.isFinite(n) || n <= 0 || n > UP_PPS_MAX) {
        console.error(`--up-pps must be 1..${UP_PPS_MAX} (got "${argv[i]}")`); out.help = true;
      } else {
        out.upPps = n;
      }
    }
    else if (a === '--include-public-ip') out.includePublicIp = true;
    else if (a === '--no-source-fanout') out.sourcePortFanout = false;
    else if (a === '--no-payload-shape') out.payloadShape = false;
    else if (a === '--no-mtu-discovery') out.mtuDiscovery = false;
    else if (a === '--help' || a === '-h') out.help = true;
    else { console.error(`Unknown argument: ${a}`); out.help = true; }
  }
  return out;
}

function printHelp() {
  console.log(`SDG Connection Test — client

Usage:
  node client.js [options]

Default target:
  --host defaults to ${DEFAULT_HOST} (SDG's public connection-test server).
  Pass --host explicitly only if SDG support gave you a different endpoint.

Options:
  --host <addr>            Override the default SDG test server.
  --ports <p1,p2,...>      Only test these port numbers (comma-separated).
                           Matches both proto if both are in the table.
  --no-sustained           Skip the 10-second UDP 27016 game-shape test.
  --no-a2s                 Skip the Steam A2S_INFO query test.
  --real-server <h:p>      Also send an A2S_INFO to your real Torch server
                           (for side-by-side comparison). Example:
                             --real-server torch.example.com:27015
  --duration <seconds>     Override the sustained test duration (default 10).
  --family <4|6|auto>      Force IPv4 ('4'), IPv6 ('6'), or let the OS pick
                           ('auto', the default). Use '4' on a v6-native
                           network (e.g. 5G home internet with 464XLAT)
                           if you suspect Happy-Eyeballs is masking the
                           problem. The SDG test server is currently v4-only;
                           '6' will only succeed against AAAA-publishing
                           servers.
  --json <file>            Write a full JSON report to <file>.
  --yes, -y                Skip the confirmation prompt.
  --help, -h               Show this help.

Phase 1 diagnostics (ON by default — every customer run includes them):
  --no-nat-idle            Skip the NAT idle-timeout test. Default: run
                           with 30+60 second windows (~95 s).
  --no-nat-type            Skip the NAT-type / endpoint-reflection test.
  --no-burst               Skip the burst-vs-steady policer test.
  --bidir <down|up|both>   Sustained test direction. Default 'both'
                           (downstream + upstream). Pass 'down' for the
                           legacy v1.0.0 behavior.
  --full                   Use the full NAT idle ladder (30,60,120,300 s).
                           ~10 minutes total. Use this when the default
                           windows don't surface anything but the
                           customer is still reporting mid-session
                           disconnects — the longer windows catch CGNAT
                           policies that don't trip until 2+ minutes.
  --nat-idle <s1,s2,...>   Custom NAT idle ladder. Overrides the default.
  --up-pps <n>             Upstream rate when --bidir != down. Default 60,
                           cap ${UP_PPS_MAX}.
  --include-public-ip      Include the full reflected source IP in both
                           the console output and the JSON report.
                           Default: redact the host portion so reports
                           and pasted console transcripts can be shared
                           safely.

Phase 2 diagnostics (ON by default — adds ~30 s):
  --no-source-fanout       Skip the source-port fan-out test, which sends
                           probes from 4 different ephemeral source ports
                           to detect per-5-tuple shaping or unlucky
                           ECMP paths.
  --no-payload-shape       Skip the payload-shape sensitivity test, which
                           sends probes with three different payload
                           contents (game-shape, random, zero-fill) to
                           detect DPI by content fingerprint.
  --no-mtu-discovery       Skip adaptive MTU discovery. By default the
                           tool walks UDP probe sizes down from 1472 to
                           find the actual MTU ceiling on the path and
                           prints a remediation command if the ceiling
                           is below the standard 1500-byte ethernet MTU.

Loss-burst histogram and reordering counts are added to every UDP
loss test and sustained run automatically — no flag needed; they're
free metrics derived from data we already collect.

Examples:
  node client.js                                  # use the default SDG endpoint
  node client.js --json report.json               # also write a JSON report
  node client.js --host test.sdgservers.example   # override the endpoint

The tool will print exactly what it is about to do before doing it, and
wait for you to press 'y' unless you pass --yes.
`);
}

// ---- Small utils ----
function randomNonce() { return crypto.randomBytes(8); }
function nowNs()       { return process.hrtime.bigint(); }
function nowMs()       { return performance.now(); }
function toHex(buf)    { return buf.toString('hex'); }

// Parse "host:port" robustly — handles bare IPv4/hostname plus the
// bracketed IPv6 form "[2001:db8::1]:27015". A naive split(':') would
// shatter an IPv6 literal across multiple colons, and a missing port
// would yield NaN that surfaces only as a confusing socket error.
function parseHostPort(s) {
  if (typeof s !== 'string' || s.length === 0) {
    throw new Error('host:port required');
  }
  // Accept any port string in the bracket form so we can give a specific
  // "invalid port" error rather than falling through to the ambiguous-IPv6
  // branch, which would produce a misleading message.
  const bracket = s.match(/^\[(.+)\]:(.+)$/);
  if (bracket) {
    const port = Number(bracket[2]);
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
      throw new Error(`invalid port "${bracket[2]}" in "${s}"`);
    }
    return { host: bracket[1], port };
  }
  const lastColon = s.lastIndexOf(':');
  if (lastColon < 0) {
    throw new Error(`missing :port in "${s}" (use host:port, or [ipv6]:port)`);
  }
  // Reject pre-port colons that would indicate a bare IPv6 without
  // brackets — ambiguous form. e.g. "::1:80" could be addr=::1 port=80
  // or addr=::1:80 with no port.
  if (s.indexOf(':') !== lastColon) {
    throw new Error(`ambiguous IPv6 form "${s}"; wrap as [ipv6]:port`);
  }
  const host = s.slice(0, lastColon);
  const portStr = s.slice(lastColon + 1);
  const port = Number(portStr);
  if (host.length === 0) throw new Error(`empty host in "${s}"`);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error(`invalid port "${portStr}" in "${s}"`);
  }
  return { host, port };
}

function stats(samples) {
  if (samples.length === 0) return { n: 0, min: null, avg: null, p95: null, max: null, stddev: null };
  const sorted = [...samples].sort((a, b) => a - b);
  const sum = samples.reduce((a, b) => a + b, 0);
  const avg = sum / samples.length;
  const variance = samples.reduce((a, b) => a + (b - avg) ** 2, 0) / samples.length;
  const p95Idx = Math.min(sorted.length - 1, Math.floor(sorted.length * 0.95));
  return {
    n: samples.length,
    min: sorted[0],
    avg: avg,
    p95: sorted[p95Idx],
    max: sorted[sorted.length - 1],
    stddev: Math.sqrt(variance),
  };
}

function confirm(question) {
  return new Promise((resolve) => {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    rl.question(question, (ans) => { rl.close(); resolve(/^y(es)?$/i.test(ans.trim())); });
  });
}

// ---- Pure classifier helpers (Phase 1) ------------------------------------
//
// These functions are pure (no I/O, no globals) so they can be unit-tested
// in isolation. Every call site that has socket-level branching delegates
// the actual interpretation here.

// Translate a pair of reflected source endpoints (server's view of the
// client at two different destination ports) into a NAT-type verdict.
// Returns one of:
//   { kind: 'cone',       reason: '...' }   endpoint-independent mapping
//   { kind: 'symmetric',  reason: '...' }   address/port-dependent mapping
//   { kind: 'no-nat',     reason: '...' }   IPv6 (typically no NAT)
//   { kind: 'unknown',    reason: '...' }   one or both reflections missing
function classifyNatType(reflectionA, reflectionB) {
  const aOk = reflectionA && reflectionA.ok;
  const bOk = reflectionB && reflectionB.ok;
  if (!aOk || !bOk) {
    return { kind: 'unknown', reason: 'reflection unavailable from server (probably v1 server)' };
  }
  // IPv6: no NAT in any deployment we care about. Reflected port equals
  // the source port trivially; reporting "cone" would be technically
  // true but misleading to a non-technical customer.
  if (reflectionA.family === 6 || reflectionB.family === 6) {
    return { kind: 'no-nat', reason: 'IPv6 path — no NAT typically applied' };
  }
  // 5G home internet carriers rotate CGNAT egress IPs across a /20
  // every few minutes. Two probes 2 s apart can legitimately come back
  // with different reflected IPs even on the same socket — that's not
  // what defines symmetric NAT. Only the port comparison matters.
  if (reflectionA.port === reflectionB.port) {
    return { kind: 'cone', reason: 'reflected source port stable across two destinations' };
  }
  return {
    kind: 'symmetric',
    reason: `reflected port differs across two destinations (${reflectionA.port} vs ${reflectionB.port})`,
  };
}

// Translate a NAT-type verdict into a one-line plain-English customer
// impact statement. The classifier output is internal nomenclature; this
// is what the customer sees in the table.
function natTypeImpact(verdict) {
  switch (verdict && verdict.kind) {
    case 'cone':
      return 'OK — direct peer-to-peer should work';
    case 'symmetric':
      return 'Symmetric NAT — direct peer-to-peer blocked; SE will need a relay';
    case 'no-nat':
      return 'OK — IPv6, no NAT';
    case 'unknown':
    default:
      return 'Unknown — server did not provide reflection';
  }
}

// Compare burst loss vs steady loss to fingerprint the path's drop
// behavior. Returns a verdict and a short explanation. Subtracts any
// RATE_LIMITED replies from observed loss so server-side rate-limiting
// cannot masquerade as an ISP policer.
function interpretBurstVsSteady({ burst, steady }) {
  const safe = (r) => {
    if (!r) return null;
    const adjLoss = Math.max(0, r.lossPct - (r.rateLimitedPct || 0));
    return { ...r, adjLoss };
  };
  const b = safe(burst);
  const s = safe(steady);
  if (!b || !s) return { kind: 'incomplete', reason: 'missing burst or steady result' };

  // If the SDG server's own limiter ate a meaningful fraction of the
  // burst, we cannot honestly call it ISP behavior. Bail out.
  if ((burst.rateLimitedPct || 0) > 5) {
    return {
      kind: 'inconclusive-server-rl',
      reason: `${burst.rateLimitedPct.toFixed(1)}% of burst was rate-limited by the SDG server itself; rerun in 60 s`,
    };
  }

  if (b.adjLoss < 2 && s.adjLoss < 2) {
    return { kind: 'clean', reason: 'no policer or shaper observed at this rate' };
  }
  if (b.adjLoss > 20 && s.adjLoss < 5) {
    return { kind: 'policer', reason: 'burst loss high, steady loss low — classic policer (token bucket)' };
  }
  if (b.adjLoss > 5 && Math.abs(b.adjLoss - s.adjLoss) < 5) {
    return { kind: 'random-loss', reason: 'similar loss at both rates — random loss, not rate-shaping' };
  }
  if (b.adjLoss > 5 && s.adjLoss > 5) {
    return { kind: 'shaper', reason: 'sustained loss at both rates — possible shaper or congestion' };
  }
  return { kind: 'unclear', reason: `burst ${b.adjLoss.toFixed(1)}% / steady ${s.adjLoss.toFixed(1)}% — pattern doesn't fit a known policer/shaper signature` };
}

// Walk a sorted array of arrived sequence numbers in [0, count) and
// produce a histogram of consecutive-loss run lengths. The shape of
// this histogram fingerprints loss patterns:
//
//   { '1': N }           — purely random, isolated drops
//   { '2-4': N, ... }    — bursts of 2-4 typical of brief congestion
//   { '5-9': N, ... }    — sustained policer cycles, e.g. token-bucket empty
//   { '10+': N }         — multi-hundred-ms outages, almost always shaping
//
// The output bucket scheme is intentionally chunky (not a per-length
// histogram). Customers don't need finer granularity than "single
// drops vs short bursts vs long bursts vs sustained outages".
function lossBurstHistogram(arrivedSeqs, count) {
  if (!Array.isArray(arrivedSeqs) || !Number.isInteger(count) || count <= 0) {
    return { 1: 0, '2-4': 0, '5-9': 0, '10+': 0 };
  }
  const arrived = new Set(arrivedSeqs);
  const buckets = { 1: 0, '2-4': 0, '5-9': 0, '10+': 0 };
  let run = 0;
  // Scanning past the end (i == count) flushes the final run into a
  // bucket without needing a duplicate post-loop branch.
  for (let i = 0; i <= count; i++) {
    const present = i < count && arrived.has(i);
    if (!present && i < count) {
      run++;
    } else if (run > 0) {
      if (run === 1)       buckets[1]++;
      else if (run <= 4)   buckets['2-4']++;
      else if (run <= 9)   buckets['5-9']++;
      else                 buckets['10+']++;
      run = 0;
    }
  }
  return buckets;
}

// Count out-of-order arrivals. Given the order in which sequence
// numbers arrived (e.g. [0,1,3,2,4,5]), count the number of pairs
// (i, j) where i < j but arrivalOrder[i] > arrivalOrder[j] — i.e.
// inversions, which are exactly the "reordering events" the path
// produced. We return both the count and the percentage of received
// packets that participated in any inversion, since either metric
// alone is misleading for low-N tests.
//
// Reordering matters because Space Engineers' interpolation can
// survive packet loss but stutters on reorder; a high reorder rate
// with low loss is a real complaint pattern that the loss column
// alone wouldn't surface.
function countReorderings(arrivalOrder) {
  if (!Array.isArray(arrivalOrder) || arrivalOrder.length < 2) {
    return { inversions: 0, pct: 0 };
  }
  let inversions = 0;
  // Naive O(n^2) is fine here — N is at most ~600 in the longest
  // sustained test (60 pps × 10 s) and we run this once per test.
  for (let i = 0; i < arrivalOrder.length; i++) {
    for (let j = i + 1; j < arrivalOrder.length; j++) {
      if (arrivalOrder[i] > arrivalOrder[j]) inversions++;
    }
  }
  const pct = (inversions * 100) / arrivalOrder.length;
  return { inversions, pct };
}

// Verdict translator for source-port fan-out: given an array of
// per-socket loss percentages, decide whether the variance is high
// enough to call it "per-flow discrimination" (an ECMP unlucky path
// or a per-5-tuple shaper) versus uniform path behavior.
function classifyFanout(perSocketLoss) {
  if (!Array.isArray(perSocketLoss) || perSocketLoss.length < 2) {
    return { kind: 'incomplete', reason: 'need at least 2 sockets to compare' };
  }
  const min = Math.min(...perSocketLoss);
  const max = Math.max(...perSocketLoss);
  const spread = max - min;
  if (max < 2) {
    return { kind: 'clean', reason: 'all source ports show <2% loss — no per-flow discrimination' };
  }
  if (spread > 20) {
    return { kind: 'per-flow', reason: `loss varies ${spread.toFixed(0)}% across source ports — per-5-tuple shaping or unlucky ECMP path` };
  }
  if (spread < 5) {
    return { kind: 'uniform', reason: `loss is consistent across source ports (~${max.toFixed(1)}%) — path-wide, not per-flow` };
  }
  return { kind: 'mild-variance', reason: `loss spread ${spread.toFixed(1)}% across source ports — borderline; rerun if it matters` };
}

// Verdict translator for payload-shape sensitivity: given per-pattern
// loss percentages, decide whether DPI is making decisions on payload
// content. The thresholds match classifyFanout for consistency.
function classifyPayloadShape(perPatternLoss) {
  if (!perPatternLoss || typeof perPatternLoss !== 'object') {
    return { kind: 'incomplete', reason: 'need at least 2 patterns to compare' };
  }
  const values = Object.values(perPatternLoss);
  if (values.length < 2) {
    return { kind: 'incomplete', reason: 'need at least 2 patterns to compare' };
  }
  const min = Math.min(...values);
  const max = Math.max(...values);
  const spread = max - min;
  if (max < 2) {
    return { kind: 'clean', reason: 'all payload shapes show <2% loss — no DPI fingerprint detected' };
  }
  if (spread > 20) {
    // Identify which pattern is the outlier so the verdict points
    // the operator at the actionable detail (e.g. "random-bytes is
    // dropped, game-shape is fine" → DPI signature is on the SE
    // packet shape).
    const worst = Object.entries(perPatternLoss).reduce(
      (acc, [k, v]) => (v > acc[1] ? [k, v] : acc), ['', -1],
    );
    return {
      kind: 'dpi-fingerprint',
      reason: `${worst[0]} loss ${worst[1].toFixed(0)}% vs cleaner peers — payload-content-based DPI`,
    };
  }
  if (spread < 5) {
    return { kind: 'uniform', reason: `loss is consistent across payload shapes (~${max.toFixed(1)}%) — not content-driven` };
  }
  return { kind: 'mild-variance', reason: `loss spread ${spread.toFixed(1)}% across payload shapes — borderline` };
}

// ---- MTU descent decision helper (pure) ----
//
// Given the descent history so far and the descending size ladder,
// decide the next step. The imperative discovery loop calls this to
// figure out what to do; all the messy network I/O stays in the loop,
// all the state-machine logic lives here (and is fully unit-testable
// without sockets — matches the classifyNatType / classifyFanout
// pattern above).
//
// history is an array of size-blocks, oldest first:
//   { size: <bytes>, probes: [{ ok, rtt|null }, ...] }
//
// descent is the ladder of sizes in descending order, e.g. MTU_DESCENT_BYTES.
//
// Returns one of:
//   { action: 'probe',  size: <bytes> }                                next probe to send
//   { action: 'done',   ceiling: <bytes>|null, ceilingConfidence: 'high'|'medium'|'none' }
//
// Algorithm:
//   1. No history yet → probe the largest size.
//   2. Current size has fewer than MTU_PROBES_PER_SIZE probes → keep probing it.
//   3. Current size has 2+/3 passes (or 4+/6 in tiebreaker) → done, this is the ceiling.
//   4. Current size has exactly 2/3 fail (1 pass) → indistinguishable from threshold; advance.
//      (Pure borderline is 2 passes — that is "passed" via threshold above.)
//   5. Current size has 0–1 pass with 3 probes done AND we've also failed the previous
//      size from the top (or are at history index >= 2 with all-failed) → fast-fail:
//      jump to the smallest size in the descent.
//   6. Otherwise → advance to the next smaller size.
//   7. If we failed at the smallest size → done with ceiling=null.
function decideNextMtuStep(history, descent, opts = {}) {
  const minProbes      = opts.minProbes      ?? MTU_PROBES_PER_SIZE;
  const passThreshold  = opts.passThreshold  ?? MTU_PASS_THRESHOLD;
  const tiebreakerTotal = opts.tiebreakerTotal ?? MTU_TIEBREAKER_TOTAL;
  const tiebreakerPass  = opts.tiebreakerPass  ?? MTU_TIEBREAKER_PASS;

  if (!Array.isArray(descent) || descent.length === 0) {
    return { action: 'done', ceiling: null, ceilingConfidence: 'none' };
  }
  if (!Array.isArray(history)) {
    // Invalid input — fail safe rather than start a descent we may never end.
    return { action: 'done', ceiling: null, ceilingConfidence: 'none' };
  }
  if (history.length === 0) {
    return { action: 'probe', size: descent[0] };
  }

  const last = history[history.length - 1];
  if (!last || !Array.isArray(last.probes)) {
    return { action: 'done', ceiling: null, ceilingConfidence: 'none' };
  }

  const passes = last.probes.filter((p) => p && p.ok).length;
  const total  = last.probes.length;

  // Still in the initial round at this size.
  if (total < minProbes) {
    return { action: 'probe', size: last.size };
  }

  // Initial round complete (minProbes probes done).
  if (total === minProbes) {
    // All passed — high confidence, no tiebreaker needed.
    if (passes === minProbes) {
      return { action: 'done', ceiling: last.size, ceilingConfidence: 'high' };
    }
    // Borderline pass: at or above threshold but not unanimous — trigger
    // the tiebreaker by probing more at the same size.
    if (passes >= passThreshold) {
      return { action: 'probe', size: last.size };
    }
    // Below threshold — fall through to fail/advance logic below.
  }

  // Tiebreaker in progress.
  if (total > minProbes && total < tiebreakerTotal) {
    return { action: 'probe', size: last.size };
  }

  // Tiebreaker complete.
  if (total >= tiebreakerTotal) {
    if (passes >= tiebreakerPass) {
      return { action: 'done', ceiling: last.size, ceilingConfidence: 'medium' };
    }
    // Tiebreaker failed — fall through to size-advance logic below.
  }

  // Last size failed. Decide whether to fast-fail to the minimum size
  // or just advance to the next smaller size.
  const minSize = descent[descent.length - 1];

  // If we just failed at the minimum size, the descent is exhausted.
  if (last.size === minSize) {
    return { action: 'done', ceiling: null, ceilingConfidence: 'none' };
  }

  // Fast-fail: we've now attempted at least 2 sizes and none have passed.
  // Jump directly to the minimum size, unless we've already tried it.
  const triedMin = history.some((h) => h.size === minSize);
  if (history.length >= 2 && !triedMin) {
    const allFailed = history.every((h) => {
      const ps = h.probes.filter((p) => p && p.ok).length;
      return ps < passThreshold;
    });
    if (allFailed) {
      return { action: 'probe', size: minSize };
    }
  }

  // Advance to the next smaller size in the descent.
  const idx = descent.indexOf(last.size);
  if (idx < 0 || idx + 1 >= descent.length) {
    return { action: 'done', ceiling: null, ceilingConfidence: 'none' };
  }
  return { action: 'probe', size: descent[idx + 1] };
}

// ---- Recommendation engine (pure) ----
//
// A recommendation is a structured interpretation of one or more
// signals in the assembled report. Each rule is a pure function
// (report) -> Recommendation | null. The engine runs them in order
// (priority order — test-inconclusive first so it's the lead item
// when many things are also broken) and returns the array of fired
// ones. The "network-healthy" catch-all is appended if nothing else
// fired, so users always see a section header.
//
// Recommendation shape:
//   {
//     severity: 'critical' | 'warning' | 'info',
//     code: string,                              // stable id for grep/support
//     title: string,                             // short human header
//     detail: string,                            // 1-2 sentence explanation
//     action: null | {
//       summary: string,                         // imperative one-liner
//       platformCommands: {                      // per-OS copy-paste-ready
//         windows: string|null,
//         macos:   string|null,
//         linux:   string|null,
//       }
//     }
//   }
//
// Skipped Phase 1/2 data is treated as ABSENT (not as PASSED) — rules
// guard their inputs with the existing `.skipped: true` convention.

// Build the recommended adapter MTU for a discovered ceiling. For the
// warning band (1280..1471), give a 20-byte safety margin so PPPoE or
// similar tunnels added later don't push the network back over the
// edge. For the severe band (<1280), recommend the ceiling itself —
// we're already near the IPv4 minimum (576) and any margin loses real
// usable payload.
function recommendedMtuFor(ceiling) {
  if (ceiling == null) return null;
  if (ceiling >= 1472) return null;
  if (ceiling < 1280) return ceiling;
  return Math.max(1280, ceiling - 20);
}

function mtuPlatformCommands(mtu) {
  return {
    windows: `netsh interface ipv4 set subinterface "Wi-Fi" mtu=${mtu} store=persistent`,
    macos:   `sudo ifconfig en0 mtu ${mtu}`,
    linux:   `sudo ip link set dev <iface> mtu ${mtu}`,
  };
}

// Count how many UDP rows were attempted and how many came back
// unreachable. Used by ruleTestInconclusive.
function udpReachabilityStats(report) {
  if (!Array.isArray(report.perPort)) return { attempted: 0, unreachable: 0 };
  let attempted = 0;
  let unreachable = 0;
  for (const r of report.perPort) {
    if (r.proto !== 'udp') continue;
    attempted++;
    if (!r.reachable) unreachable++;
  }
  return { attempted, unreachable };
}

// ---- Individual rules ----

function ruleTestInconclusive(report) {
  const { attempted, unreachable } = udpReachabilityStats(report);
  if (attempted < 3) return null; // not enough data to make this call
  const failPct = unreachable / attempted;
  if (failPct <= 0.5) return null;
  const capDown = report.capabilities && report.capabilities.ok === false;
  const detail = capDown
    ? `${unreachable} of ${attempted} UDP ports were unreachable AND the capability probe also timed out. The SDG test server is probably unreachable from this network, OR your Internet connection is severely degraded.`
    : `${unreachable} of ${attempted} UDP ports were unreachable. The SDG test server may be temporarily down, OR your Internet connection is severely degraded.`;
  return {
    severity: 'critical',
    code: 'test-inconclusive',
    title: 'Test results are partial — interpret with caution',
    detail,
    action: {
      summary: 'Wait 5 minutes and run the test again. If the same pattern repeats, check whether outbound UDP is blocked by a firewall.',
      platformCommands: null,
    },
  };
}

function ruleMtuSevere(report) {
  const d = report.mtuDiscovery;
  if (!d || !d.ok || d.ceiling == null) return null;
  if (d.ceiling >= 1280) return null;
  const mtu = recommendedMtuFor(d.ceiling);
  return {
    severity: 'critical',
    code: 'mtu-severe',
    title: `Network MTU is severely restricted (~${d.ceiling} bytes)`,
    detail: `Anything above ${d.ceiling} bytes is being silently dropped on this path. This is unusual — typically only seen on broken tunnels or aggressive carrier shaping. Game traffic will stutter even after the MTU fix.`,
    action: {
      summary: `Lower your network adapter MTU to ${mtu} and consider a wired connection or alternate ISP.`,
      platformCommands: mtuPlatformCommands(mtu),
    },
  };
}

function ruleMtuCapped(report) {
  const d = report.mtuDiscovery;
  if (!d || !d.ok || d.ceiling == null) return null;
  if (d.ceiling >= 1472 || d.ceiling < 1280) return null;
  const mtu = recommendedMtuFor(d.ceiling);
  return {
    severity: 'warning',
    code: 'mtu-capped',
    title: `Network MTU is capped at ~${d.ceiling} bytes`,
    detail: `Packets larger than ${d.ceiling} bytes are being silently dropped on this path. This pattern is common on 5G home internet across major US providers — the carrier's mobile sub-tunnel adds encapsulation overhead that eats the last 100-200 bytes of the standard 1500-byte ethernet MTU. Without an OS-level MTU change, large UDP packets will appear as silent packet loss in-game.`,
    action: {
      summary: `Lower your network adapter MTU to ${mtu}. The Windows command below is ready to copy-paste; replace "Wi-Fi" with your adapter name if needed (list them with: netsh interface show interface).`,
      platformCommands: mtuPlatformCommands(mtu),
    },
  };
}

function ruleMtuMarginal(report) {
  const d = report.mtuDiscovery;
  if (!d || !d.ok) return null;
  if (d.ceilingConfidence !== 'medium') return null;
  return {
    severity: 'warning',
    code: 'mtu-marginal',
    title: 'MTU result is borderline',
    detail: `The discovered ceiling (${d.ceiling} bytes) required a tiebreaker round — about a third of probes at that size still failed. Expect occasional packet loss at the ceiling itself; the recommendation already accounts for this with a safety margin.`,
    action: null,
  };
}

function ruleCgnat464xlat(report) {
  if (report.family !== 4) return null;
  const d = report.mtuDiscovery;
  if (!d || !d.ok || d.ceiling == null) return null;
  if (d.ceiling > 1280) return null;
  return {
    severity: 'info',
    code: 'cgnat-464xlat',
    title: 'Your network is likely behind 464XLAT (IPv4-over-IPv6 carrier translation)',
    detail: 'The combination of IPv4 transport with an MTU at or below 1280 bytes is the classic 464XLAT signature used by 5G home internet providers. Behavior is normal but your effective IPv4 MTU is permanently smaller than it would be on a non-cellular ISP.',
    action: null,
  };
}

function ruleDpiFingerprint(report) {
  const p = report.payloadShape;
  if (!p || p.skipped) return null;
  if (!p.verdict || p.verdict.kind !== 'dpi-fingerprint') return null;
  return {
    severity: 'warning',
    code: 'dpi-fingerprint',
    title: 'Deep packet inspection (DPI) detected',
    detail: `Your network drops UDP differently based on payload content: ${p.verdict.reason}. This typically means a carrier or middlebox is making content-based decisions about your traffic, which can silently break game protocols during congestion.`,
    action: {
      summary: 'A VPN (encrypting all traffic) bypasses content-based DPI. Try one if game traffic remains unreliable after the MTU fix.',
      platformCommands: null,
    },
  };
}

function rulePerFlowShaping(report) {
  const f = report.sourcePortFanout;
  if (!f || f.skipped) return null;
  if (!f.verdict || f.verdict.kind !== 'per-flow') return null;
  return {
    severity: 'warning',
    code: 'per-flow-shaping',
    title: 'Per-connection traffic shaping detected',
    detail: `Loss varies dramatically across your source ports: ${f.verdict.reason}. The carrier or router is making per-5-tuple decisions, which means some game connections will be silently degraded while others on the same network work fine.`,
    action: {
      summary: 'Restarting the game/PC sometimes lands on a better-treated source port. Persistent issues usually require contacting the ISP.',
      platformCommands: null,
    },
  };
}

function ruleNatIdleShort(report) {
  const n = report.natIdle;
  if (!n || n.skipped) return null;
  if (typeof n.largestSurvivedSec !== 'number') return null;
  if (n.largestSurvivedSec >= 60) return null;
  return {
    severity: 'warning',
    code: 'nat-idle-short',
    title: `NAT mapping evicted after only ${n.largestSurvivedSec}s of idle`,
    detail: 'Your carrier or router drops the NAT mapping for the game connection in under a minute of no traffic. Pausing in-game (menus, AFK, loading screens) can trigger a mid-session disconnect.',
    action: {
      summary: 'Enable in-game keepalive options if available; otherwise this is mostly a carrier-side limitation.',
      platformCommands: null,
    },
  };
}

function ruleSymmetricNat(report) {
  const t = report.natType;
  if (!t || t.skipped) return null;
  if (!t.verdict || t.verdict.kind !== 'symmetric') return null;
  return {
    severity: 'info',
    code: 'symmetric-nat',
    title: 'Symmetric NAT detected',
    detail: 'Direct peer-to-peer connections to other symmetric-NAT users will fail. For Space Engineers this only matters if you host or connect to peer-to-peer games; dedicated-server connections are unaffected.',
    action: null,
  };
}

function ruleNetworkHealthy(_report) {
  return {
    severity: 'info',
    code: 'network-healthy',
    title: 'Network looks healthy',
    detail: 'No actionable issues detected. If you are still having connection problems, they are likely server-side or game-specific.',
    action: null,
  };
}

const RULES = Object.freeze([
  ruleTestInconclusive,
  ruleMtuSevere,
  ruleMtuCapped,
  ruleMtuMarginal,
  ruleCgnat464xlat,
  ruleDpiFingerprint,
  rulePerFlowShaping,
  ruleNatIdleShort,
  ruleSymmetricNat,
]);

function buildRecommendations(report) {
  const out = [];
  for (const rule of RULES) {
    const r = rule(report);
    if (r) out.push(r);
  }
  if (out.length === 0) out.push(ruleNetworkHealthy(report));
  return out;
}

// Redact a public IP for inclusion in any output channel that may be
// shared. The README invites users to share their JSON report — and
// support flows commonly involve pasting the console transcript into
// a ticket — so the reflected source IP is potentially a shared
// identifier in either output. Default behavior is to redact the host
// portion in both console and JSON; full IP is opt-in via
// `--include-public-ip`.
//
//   redactIp('1.2.3.4',     false) -> '1.2.3.x'
//   redactIp('1.2.3.4',     true)  -> '1.2.3.4'
//   redactIp('2001:db8::1', false) -> '2001:db8::/32 (redacted)'
//   redactIp(null,          *)     -> null
function redactIp(addr, includeFull) {
  if (typeof addr !== 'string' || addr.length === 0) return addr;
  if (includeFull) return addr;
  // Normalize first so a v4-mapped v6 like '::ffff:1.2.3.4' is treated
  // as v4 for redaction purposes.
  const norm = normalizeIp(addr);
  if (net.isIPv4(norm)) {
    const parts = norm.split('.');
    return `${parts[0]}.${parts[1]}.${parts[2]}.x`;
  }
  if (net.isIPv6(norm)) {
    // Keep the first 32 bits (two hextets) for ASN/ISP correlation,
    // redact the rest.
    const expanded = norm.split('::')[0];
    const groups = expanded.split(':').filter(Boolean);
    if (groups.length >= 2) return `${groups[0]}:${groups[1]}::/32 (redacted)`;
    return '(ipv6 redacted)';
  }
  return '(redacted)';
}

// ---- DNS resolution. Only --host and optionally --real-server are ever resolved. ----
//
// Returns { address, family }, where family is 4 or 6. Pass family=0 to let
// the OS pick (Happy Eyeballs-ish behavior); pass 4 or 6 to force.
async function resolveHost(host, family = 0) {
  // Accept a raw IP without a DNS call. net.isIP returns 4, 6, or 0.
  const lit = net.isIP(host);
  if (lit) {
    if (family && lit !== family) {
      throw new Error(`--family ${family} but ${host} is a literal IPv${lit} address`);
    }
    return { address: host, family: lit };
  }
  const addrs = await dns.lookup(host, { family });
  return { address: addrs.address, family: addrs.family };
}

// ================================================================
// UDP probes
// ================================================================

// Send one SDGT probe and wait up to PROBE_TIMEOUT_MS for the reply.
// Returns one of:
//   { ok: true,  rtt: <ms> }                    success
//   { ok: false, rtt: null, rateLimited: true } server told us we're rate limited
//   { ok: false, rtt: null, rateLimited: false } timeout (real loss)
function udpProbe({ host, port, nonce, sequence, family = 4, payloadSize = protocol.HEADER_SIZE }) {
  return new Promise((resolve) => {
    const sock = dgram.createSocket(dgramTypeFor(family));
    let done = false;
    const finish = (result) => {
      if (done) return;
      done = true;
      try { sock.close(); } catch (e) {}
      resolve(result);
    };

    sock.on('error', () => finish({ ok: false, rtt: null, rateLimited: false }));
    sock.on('message', (msg) => {
      const decoded = protocol.decode(msg);
      if (!decoded) return;
      if (!decoded.nonce.equals(nonce)) return;
      if (decoded.type === protocol.TYPE.RATE_LIMITED) {
        finish({ ok: false, rtt: null, rateLimited: true });
        return;
      }
      if (decoded.type !== protocol.TYPE.REPLY) return;
      if (decoded.sequence !== sequence) return;
      finish({ ok: true, rtt: nowMs() - sendMs });
    });

    const pkt = protocol.encode({
      type: protocol.TYPE.PROBE,
      nonce, sequence,
      clientTsNs: nowNs(),
      totalSize: payloadSize,
    });
    const sendMs = nowMs();
    sock.send(pkt, port, host, (err) => {
      if (err) finish({ ok: false, rtt: null, rateLimited: false });
    });
    setTimeout(() => finish({ ok: false, rtt: null, rateLimited: false }), PROBE_TIMEOUT_MS);
  });
}

// Loss + latency test: send N probes at a fixed interval, count replies,
// compute latency stats. Also counts RATE_LIMITED server replies so the
// caller can distinguish "my ISP dropped these" from "the SDG server
// told me I'm over quota".
async function udpLossTest({ host, port, nonce, family = 4 }) {
  const rtts = [];
  let received = 0;
  let rateLimited = 0;
  // Phase 2: track which sequences arrived (for the burst histogram)
  // and the order in which they arrived (for the reordering count).
  const arrivedSeqs = [];
  const arrivalOrder = [];
  const sock = dgram.createSocket(dgramTypeFor(family));
  const pending = new Map();   // seq -> sendMs

  sock.on('message', (msg) => {
    const decoded = protocol.decode(msg);
    if (!decoded) return;
    if (!decoded.nonce.equals(nonce)) return;
    if (decoded.type === protocol.TYPE.RATE_LIMITED) { rateLimited++; return; }
    if (decoded.type !== protocol.TYPE.REPLY) return;
    const sent = pending.get(decoded.sequence);
    if (sent == null) return;
    pending.delete(decoded.sequence);
    rtts.push(nowMs() - sent);
    received++;
    arrivedSeqs.push(decoded.sequence);
    arrivalOrder.push(decoded.sequence);
  });
  sock.on('error', () => {});

  for (let seq = 0; seq < LOSS_PACKET_COUNT; seq++) {
    const pkt = protocol.encode({
      type: protocol.TYPE.PROBE,
      nonce, sequence: seq,
      clientTsNs: nowNs(),
    });
    pending.set(seq, nowMs());
    sock.send(pkt, port, host, () => {});
    await new Promise((r) => setTimeout(r, LOSS_INTERVAL_MS));
  }
  await new Promise((r) => setTimeout(r, PROBE_TIMEOUT_MS));
  try { sock.close(); } catch (e) {}

  return {
    sent: LOSS_PACKET_COUNT,
    received,
    rateLimited,
    lossPct: (1 - received / LOSS_PACKET_COUNT) * 100,
    latency: stats(rtts),
    burstHistogram: lossBurstHistogram(arrivedSeqs, LOSS_PACKET_COUNT),
    reordering: countReorderings(arrivalOrder),
  };
}

// ================================================================
// MTU discovery — adaptive linear descent + fallback + spot-check
// ================================================================
//
// MTU is a path property, not a per-port property. Discovery runs once
// against the critical SE game port (UDP 27016) using a linear descent
// from 1472 down to 576, then every other reachable UDP port is
// spot-checked at the discovered ceiling. This both (a) names the
// actual working size when the path clamps MTU (5G home internet, most
// commonly) and (b) tells us whether the clamp is universal or
// per-port.
//
// Imperative loop here, pure state-machine logic in decideNextMtuStep
// above. That separation lets us unit-test the algorithm without sockets.

// Run the descent against one port. Returns either:
//   { ok: true,  discoveredOn, descent, ceiling: <bytes>|null, ceilingConfidence }
//   { ok: false, skipped: true,  reason: 'rate-limited', descent }
//   { ok: false, skipped: false, error: '...', partialHistory }
//
// `probeFn` defaults to `udpProbe`. Tests inject a deterministic stand-in.
async function discoverMtuCeiling({
  host, port, nonce, family = 4,
  probeFn = udpProbe,
  descent = null,
  sequenceBase = 9000,
}) {
  const ladder = descent || (family === 6 ? MTU_DESCENT_BYTES_V6 : MTU_DESCENT_BYTES);
  const history = [];
  let sequence = sequenceBase;
  // Safety bound. With a 10-rung ladder, tiebreaker (+3 probes), and one
  // rate-limit retry, the max possible iterations is well under 100.
  for (let safety = 0; safety < 100; safety++) {
    const step = decideNextMtuStep(history, ladder);
    if (step.action === 'done') {
      return {
        ok: true,
        discoveredOn: port,
        descent: history,
        ceiling: step.ceiling,
        ceilingConfidence: step.ceilingConfidence,
      };
    }
    const size = step.size;
    let entry = history.find((h) => h.size === size);
    if (!entry) {
      entry = { size, probes: [] };
      history.push(entry);
    }
    let result;
    try {
      result = await probeFn({
        host, port, nonce, sequence: sequence++,
        family, payloadSize: size,
      });
    } catch (e) {
      return { ok: false, skipped: false, error: e.message || String(e), partialHistory: history };
    }
    if (result && result.rateLimited) {
      // Backoff and retry once. If still rate-limited, the path is fine
      // but the SDG server's own limiter is eating our probes; treat the
      // run as inconclusive rather than mis-recommending a lower MTU.
      await new Promise((r) => setTimeout(r, MTU_RATE_LIMIT_BACKOFF_MS));
      let retry;
      try {
        retry = await probeFn({
          host, port, nonce, sequence: sequence++,
          family, payloadSize: size,
        });
      } catch (e) {
        return { ok: false, skipped: false, error: e.message || String(e), partialHistory: history };
      }
      if (retry && retry.rateLimited) {
        return { ok: false, skipped: true, reason: 'rate-limited', descent: history };
      }
      entry.probes.push({ ok: !!(retry && retry.ok), rtt: retry ? retry.rtt : null });
    } else {
      entry.probes.push({ ok: !!(result && result.ok), rtt: result ? result.rtt : null });
    }
    // Spacing between probes; matches udpLossTest cadence so loss
    // measurements stay comparable.
    await new Promise((r) => setTimeout(r, MTU_PROBE_SPACING_MS));
  }
  return { ok: false, skipped: false, error: 'descent loop exceeded safety limit', partialHistory: history };
}

// Try the primary port first; if the descent exhausts without finding
// a working size, try fallback ports in order. Each fallback gets a
// single 576B probe before committing to a full descent — that's the
// fast-fail for completely broken paths (TEST-NET-1, ISP down, etc.).
async function runMtuDiscoveryWithFallback({
  host, primaryPort, fallbackPorts, nonce, family = 4,
  probeFn = udpProbe,
}) {
  const primary = await discoverMtuCeiling({ host, port: primaryPort, nonce, family, probeFn });
  if (primary.ok && primary.ceiling != null) return primary;
  // Rate-limited result is final — don't try fallbacks, the path itself is fine.
  if (primary.skipped) return primary;
  // Network error during primary descent is fatal too.
  if (!primary.ok) return primary;
  // Primary returned ceiling=null. Try the fallback chain.
  let probeSeq = 8999;
  for (let i = 0; i < fallbackPorts.length; i++) {
    const fbPort = fallbackPorts[i];
    let preflight;
    try {
      preflight = await probeFn({
        host, port: fbPort, nonce, sequence: probeSeq--,
        family, payloadSize: 576,
      });
    } catch (e) {
      continue;
    }
    if (!preflight || !preflight.ok) continue;
    const fb = await discoverMtuCeiling({
      host, port: fbPort, nonce, family, probeFn,
      sequenceBase: 9100 + i * 50,
    });
    if (fb.ok && fb.ceiling != null) {
      return { ...fb, fellBackFrom: primaryPort };
    }
  }
  return {
    ok: true,
    discoveredOn: primaryPort,
    descent: primary.descent || [],
    ceiling: null,
    ceilingConfidence: 'none',
    reason: 'no-reachable-discovery-port',
  };
}

// Spot-check the discovered ceiling on every reachable UDP port in
// parallel. Different destination ports = different 5-tuples = no reply
// confusion possible. One probe per port; on failure, a second probe
// before flagging it — transient loss happens.
async function spotCheckCeiling({
  host, ports, nonce, family = 4, ceiling,
  probeFn = udpProbe,
}) {
  if (ceiling == null) return [];
  return Promise.all(ports.map(async (port, idx) => {
    let p1;
    try {
      p1 = await probeFn({
        host, port, nonce, sequence: 9500 + idx * 2,
        family, payloadSize: ceiling,
      });
    } catch (e) {
      p1 = { ok: false, rtt: null, rateLimited: false };
    }
    if (p1 && p1.ok) {
      return {
        port, size: ceiling, ok: true, rtt: p1.rtt,
        probes: [{ ok: true, rtt: p1.rtt }],
      };
    }
    let p2;
    try {
      p2 = await probeFn({
        host, port, nonce, sequence: 9500 + idx * 2 + 1,
        family, payloadSize: ceiling,
      });
    } catch (e) {
      p2 = { ok: false, rtt: null, rateLimited: false };
    }
    return {
      port,
      size: ceiling,
      ok: !!(p2 && p2.ok),
      rtt: p2 ? p2.rtt : null,
      probes: [
        { ok: !!(p1 && p1.ok), rtt: p1 ? p1.rtt : null },
        { ok: !!(p2 && p2.ok), rtt: p2 ? p2.rtt : null },
      ],
    };
  }));
}

// ================================================================
// Phase 1: Capability probe
// ================================================================
//
// A v1 server has no concept of features; it just echoes PROBEs. A
// v2-aware server recognizes a magic sequence number on the capability
// probe port and responds with TYPE.CAPABILITIES carrying a feature
// bitmap. The client never assumes Phase 1 features without seeing
// that bitmap — server-dependent tests are explicitly skipped and
// labeled when the server is too old, never silently fail.
async function capabilityProbe({ host, port = CAPABILITY_PROBE_PORT, family = 4 }) {
  return new Promise((resolve) => {
    const sock = dgram.createSocket(dgramTypeFor(family));
    const nonce = randomNonce();
    let done = false;
    const finish = (result) => {
      if (done) return;
      done = true;
      try { sock.close(); } catch (e) {}
      resolve(result);
    };
    sock.on('error', () => finish({ ok: false, reason: 'socket-error', capabilities: null, isV1Server: false }));
    sock.on('message', (msg) => {
      const decoded = protocol.decode(msg);
      if (!decoded || !decoded.nonce.equals(nonce)) return;
      if (decoded.sequence !== protocol.CAPABILITY_MAGIC_SEQ) return;
      if (decoded.type === protocol.TYPE.CAPABILITIES) {
        const caps = protocol.decodeCapabilities(msg);
        finish({ ok: true, reason: null, capabilities: caps, isV1Server: false });
      } else if (decoded.type === protocol.TYPE.REPLY) {
        // Old server echoed our magic-sequence probe back as a normal
        // reply. No features.
        finish({
          ok: true, reason: null, isV1Server: true,
          capabilities: { raw: 0, reflection: false, bidirectional: false, natIdleAware: false },
        });
      }
    });
    // Pad the probe to REFLECT_PROBE_BYTES so the server can fit the
    // CAPABILITIES bitmap (4 bytes at offset 36 = 40-byte reply) into a
    // packet no larger than the inbound probe.
    const pkt = protocol.encode({
      type: protocol.TYPE.PROBE,
      nonce,
      sequence: protocol.CAPABILITY_MAGIC_SEQ,
      clientTsNs: nowNs(),
      totalSize: REFLECT_PROBE_BYTES,
    });
    sock.send(pkt, port, host, (err) => {
      if (err) finish({ ok: false, reason: err.code || 'send-error', capabilities: null, isV1Server: false });
    });
    setTimeout(() => finish({ ok: false, reason: 'timeout', capabilities: null, isV1Server: false }), CAPABILITY_PROBE_TIMEOUT_MS);
  });
}

// ================================================================
// Phase 1: NAT idle-timeout probe
// ================================================================
//
// Hold ONE socket open for the full test duration. Sending a fresh probe
// after the idle re-opens the carrier NAT mapping anyway (outbound
// traffic always works), so what we're really measuring is two things:
//
//   1. Did the server's reply make it back? (i.e., is there an inbound
//      mapping the carrier still honors, or has the entry been evicted
//      and we're getting a fresh outbound mapping with potentially a
//      different reflected port?)
//
//   2. If reflection is supported by the server, did the reflected
//      source port change between the pre-idle and post-idle probes?
//      A port change is unambiguous evidence the carrier NAT mapping
//      was rotated, even when the data path appears to work.
async function natIdleTest({ host, port = GAME_SHAPE_PORT, nonce, windows, family = 4, reflectionSupported = false }) {
  const sock = dgram.createSocket(dgramTypeFor(family));
  // We reuse this single socket the entire time. Do NOT close it
  // between windows — that's the whole point of the test.
  const probeSize = reflectionSupported ? REFLECT_PROBE_BYTES : protocol.HEADER_SIZE;
  const flags = reflectionSupported ? protocol.FLAG_REFLECT : 0;

  // Per-sequence pending map; the message handler resolves whichever
  // sequence's promise the reply carries.
  const pending = new Map();
  sock.on('error', () => {});
  sock.on('message', (msg) => {
    const decoded = protocol.decode(msg);
    if (!decoded || !decoded.nonce.equals(nonce)) return;
    const slot = pending.get(decoded.sequence);
    if (!slot) return;
    pending.delete(decoded.sequence);
    let reflection = null;
    if (decoded.type === protocol.TYPE.REFLECT_REPLY) {
      reflection = protocol.decodeReflectedEndpoint(msg);
    }
    slot.resolve({ ok: true, type: decoded.type, rtt: nowMs() - slot.sentAt, reflection });
  });

  function sendOnce(sequence) {
    return new Promise((resolve) => {
      const slot = { resolve, sentAt: nowMs() };
      pending.set(sequence, slot);
      const pkt = protocol.encode({
        type: protocol.TYPE.PROBE,
        nonce, sequence,
        clientTsNs: nowNs(),
        totalSize: probeSize,
        flags,
      });
      sock.send(pkt, port, host, (err) => {
        if (err) {
          pending.delete(sequence);
          resolve({ ok: false, type: null, rtt: null, reflection: null, error: err.code || 'send-error' });
        }
      });
      setTimeout(() => {
        if (pending.delete(sequence)) {
          resolve({ ok: false, type: null, rtt: null, reflection: null, error: 'timeout' });
        }
      }, PROBE_TIMEOUT_MS);
    });
  }

  // Send a small burst of confirmation probes after each idle so a
  // single isolated drop (the long tail of UDP loss) doesn't blacklist
  // an entire window. Three probes 100 ms apart: any one returning is
  // enough to declare the mapping alive.
  async function confirmReply(seqBase) {
    const results = [];
    for (let i = 0; i < 3; i++) {
      const r = await sendOnce(seqBase + i);
      results.push(r);
      if (i < 2) await new Promise(r => setTimeout(r, 100));
    }
    const anyOk = results.find(r => r.ok);
    return {
      replied: !!anyOk,
      rttMs: anyOk ? anyOk.rtt : null,
      reflection: anyOk ? anyOk.reflection : null,
    };
  }

  // Initial probe — establishes the NAT mapping baseline (and captures
  // the reflected source port if reflection is supported, so we can
  // detect rotation later).
  const baseline = await confirmReply(0);
  const idleResults = [];
  let largestSurvivedSec = 0;
  for (let w = 0; w < windows.length; w++) {
    const sec = windows[w];
    process.stdout.write(`    idle ${sec}s ... `);
    await new Promise((resolve) => setTimeout(resolve, sec * 1000));
    const r = await confirmReply(100 + w * 10);
    let portRotated = null;
    if (baseline.reflection && baseline.reflection.ok && r.reflection && r.reflection.ok) {
      portRotated = baseline.reflection.port !== r.reflection.port;
    }
    idleResults.push({
      seconds: sec,
      replied: r.replied,
      rttMs: r.rttMs,
      portRotated,
      reflectedPortBefore: baseline.reflection && baseline.reflection.ok ? baseline.reflection.port : null,
      reflectedPortAfter:  r.reflection && r.reflection.ok ? r.reflection.port : null,
    });
    if (r.replied && portRotated !== true) {
      largestSurvivedSec = sec;
    }
    console.log(r.replied ? (portRotated === true ? `rotated (port changed)` : 'OK') : 'NO REPLY');
  }
  try { sock.close(); } catch (e) {}

  return {
    baseline: {
      replied: baseline.replied,
      reflectedPort: baseline.reflection && baseline.reflection.ok ? baseline.reflection.port : null,
    },
    windows: idleResults,
    largestSurvivedSec,
    reflectionUsed: reflectionSupported,
  };
}

// ================================================================
// Phase 1: NAT type / endpoint reflection
// ================================================================
//
// CRITICAL: this MUST use a single socket sending to two different
// destinations. Two sockets bound to the same source port is unreliable
// across Windows/macOS/Linux (SO_REUSEADDR semantics differ); the
// reliable trick is one socket, two `sock.send(..., portA)` and
// `sock.send(..., portB)` calls. The kernel keeps the source port
// stable across destinations.
async function natTypeTest({ host, ports, nonce, family = 4 }) {
  const sock = dgram.createSocket(dgramTypeFor(family));
  const reflections = new Map();   // sequence -> reflection
  sock.on('error', () => {});
  sock.on('message', (msg) => {
    const decoded = protocol.decode(msg);
    if (!decoded || !decoded.nonce.equals(nonce)) return;
    if (decoded.type !== protocol.TYPE.REFLECT_REPLY) return;
    reflections.set(decoded.sequence, protocol.decodeReflectedEndpoint(msg));
  });

  function send(sequence, destPort) {
    return new Promise((resolve, reject) => {
      const pkt = protocol.encode({
        type: protocol.TYPE.PROBE,
        nonce, sequence,
        clientTsNs: nowNs(),
        totalSize: REFLECT_PROBE_BYTES,
        flags: protocol.FLAG_REFLECT,
      });
      sock.send(pkt, destPort, host, (err) => err ? reject(err) : resolve());
    });
  }

  try {
    await send(0, ports[0]);
    await send(1, ports[1]);
  } catch (e) {
    try { sock.close(); } catch (_) {}
    return { ok: false, reason: e.code || e.message, reflectionA: null, reflectionB: null };
  }
  // Give both replies time to land.
  await new Promise(r => setTimeout(r, PROBE_TIMEOUT_MS));
  try { sock.close(); } catch (e) {}

  const reflectionA = reflections.get(0) || null;
  const reflectionB = reflections.get(1) || null;
  const verdict = classifyNatType(reflectionA, reflectionB);
  return {
    ok: true,
    portA: ports[0], portB: ports[1],
    reflectionA, reflectionB,
    verdict,
  };
}

// ================================================================
// Phase 1: Burst-vs-steady policer detection
// ================================================================
//
// Send 100 probes as fast as the kernel will accept them, then 100
// probes at 10 pps. Compare loss adjusted for any RATE_LIMITED replies
// (so the SDG server's own bucket can never look like an ISP policer).
//
// Runs on UDP 27443 (baseline) by default to isolate the test from any
// game-port-specific DPI / shaping. Server-side rate-limiting (if any)
// applies independently of port choice, so this only changes what kind
// of DPI we expose ourselves to.
async function burstVsSteadyTest({ host, port = BURST_PORT, nonce, family = 4 }) {
  // Use a fresh socket for each phase. Some stateful firewalls track
  // per-(src, dst, src_port) flow state, and a same-socket burst+steady
  // can be classified as one session and shaped jointly. Two sockets
  // exercise two distinct flows, which is what we want.
  async function phase({ count, intervalMs, label }) {
    return new Promise((resolve) => {
      const sock = dgram.createSocket(dgramTypeFor(family));
      const sentAt = new Map();
      let received = 0;
      let rateLimited = 0;
      let localDropped = 0;
      const rtts = [];
      sock.on('error', () => {});
      sock.on('message', (msg) => {
        const decoded = protocol.decode(msg);
        if (!decoded || !decoded.nonce.equals(nonce)) return;
        if (decoded.type === protocol.TYPE.RATE_LIMITED) { rateLimited++; return; }
        if (decoded.type !== protocol.TYPE.REPLY) return;
        const sent = sentAt.get(decoded.sequence);
        if (sent == null) return;
        sentAt.delete(decoded.sequence);
        received++;
        rtts.push(nowMs() - sent);
      });

      const seqBase = label === 'burst' ? 10000 : 20000;
      const sendStartedAt = nowMs();
      let sendsScheduled = 0;
      const fireOne = (i) => {
        const seq = seqBase + i;
        const pkt = protocol.encode({
          type: protocol.TYPE.PROBE,
          nonce, sequence: seq,
          clientTsNs: nowNs(),
        });
        sentAt.set(seq, nowMs());
        sock.send(pkt, port, host, (err) => {
          // ENOBUFS / EAGAIN means the kernel send buffer was full and
          // the packet was DROPPED LOCALLY — this is the test machine's
          // own NIC, not the ISP. Count separately so we can tell the
          // user when their own kernel can't keep up with 1000 pps.
          if (err) {
            sentAt.delete(seq);
            localDropped++;
          }
        });
      };

      if (intervalMs === 0) {
        // Burst: schedule all sends through setImmediate to keep the
        // event loop healthy without yielding too much. Node single-
        // thread + Windows timer granularity (~15.6 ms) means setInterval
        // at 1 ms is a fiction; setImmediate just sends as fast as the
        // event loop allows. We measure the *actual* duration so the
        // report is honest about what rate we delivered.
        for (let i = 0; i < count; i++) {
          setImmediate(() => fireOne(i));
          sendsScheduled++;
        }
      } else {
        for (let i = 0; i < count; i++) {
          setTimeout(() => fireOne(i), i * intervalMs);
          sendsScheduled++;
        }
      }

      // Wait for the schedule to drain plus PROBE_TIMEOUT_MS for late
      // replies.
      const waitMs = (intervalMs * count) + PROBE_TIMEOUT_MS + 200;
      setTimeout(() => {
        const sendCompletedAt = nowMs();
        try { sock.close(); } catch (e) {}
        const sent = sendsScheduled - localDropped;
        const lossPct = sent > 0 ? Math.max(0, (1 - received / sent) * 100) : 100;
        const rateLimitedPct = sent > 0 ? (rateLimited / sent) * 100 : 0;
        const wallMs = sendCompletedAt - sendStartedAt;
        const observedPps = wallMs > 0 ? (sent * 1000 / wallMs) : null;
        resolve({
          label, sent, received, rateLimited, localDropped,
          lossPct, rateLimitedPct,
          observedPps,
          latency: stats(rtts),
        });
      }, waitMs);
    });
  }

  const burst  = await phase({ count: BURST_PACKET_COUNT,  intervalMs: 0,                    label: 'burst' });
  // Brief gap between phases so any per-IP bucket the SDG server is
  // running has time to refill — otherwise the steady phase would
  // start under whatever budget the burst left behind.
  await new Promise(r => setTimeout(r, 1500));
  const steady = await phase({ count: STEADY_PACKET_COUNT, intervalMs: STEADY_INTERVAL_MS,   label: 'steady' });
  const verdict = interpretBurstVsSteady({ burst, steady });
  return { port, burst, steady, verdict };
}

// ================================================================
// Phase 2: Source-port fan-out
// ================================================================
//
// Repeats a small loss test from N=4 different ephemeral source ports
// against the same (host, port) destination. Diverging loss rates
// across source ports indicate per-5-tuple discrimination — either
// an unlucky ECMP hash bucket on a carrier router, or a per-flow
// shaper.
//
// Pure client-side, no server change required. Uses the existing
// PROBE/REPLY path; the only thing that varies is which source port
// the kernel assigns to each successive socket.
async function sourcePortFanoutTest({ host, port, nonce, family = 4 }) {
  const perSocket = [];
  for (let s = 0; s < FANOUT_SOCKET_COUNT; s++) {
    const sock = dgram.createSocket(dgramTypeFor(family));
    let received = 0;
    let rateLimited = 0;
    const pending = new Map();
    sock.on('error', () => {});
    sock.on('message', (msg) => {
      const decoded = protocol.decode(msg);
      if (!decoded || !decoded.nonce.equals(nonce)) return;
      if (decoded.type === protocol.TYPE.RATE_LIMITED) { rateLimited++; return; }
      if (decoded.type !== protocol.TYPE.REPLY) return;
      if (!pending.has(decoded.sequence)) return;
      pending.delete(decoded.sequence);
      received++;
    });
    // Bind explicitly so we can read back the kernel-assigned source
    // port and surface it in the JSON report. address() only returns
    // a meaningful port after bind() resolves.
    await new Promise((resolve) => sock.bind(0, undefined, resolve));
    const sourcePort = sock.address() ? sock.address().port : 0;

    for (let seq = 0; seq < FANOUT_PACKETS_EACH; seq++) {
      // Use a base-shifted sequence so the per-socket pending maps
      // never collide with each other or with other tests' sequences.
      const fullSeq = 30000 + s * 1000 + seq;
      const pkt = protocol.encode({
        type: protocol.TYPE.PROBE,
        nonce, sequence: fullSeq,
        clientTsNs: nowNs(),
      });
      pending.set(fullSeq, true);
      sock.send(pkt, port, host, () => {});
      await new Promise((r) => setTimeout(r, LOSS_INTERVAL_MS));
    }
    await new Promise((r) => setTimeout(r, PROBE_TIMEOUT_MS));
    try { sock.close(); } catch (e) {}
    const lossPct = (1 - received / FANOUT_PACKETS_EACH) * 100;
    perSocket.push({ sourcePort, sent: FANOUT_PACKETS_EACH, received, rateLimited, lossPct });
  }
  const verdict = classifyFanout(perSocket.map(s => s.lossPct));
  return { port, perSocket, verdict };
}

// ================================================================
// Phase 2: Payload-shape sensitivity
// ================================================================
//
// Run three short loss tests on the SE game port, varying only the
// payload bytes. If the path drops one shape but passes another,
// there's a DPI device making content-based decisions — this lets
// the support team distinguish "the path is bad" from "the path
// hates SE specifically".
//
// Three patterns:
//   - game-shape: zero-padded to 200..400 bytes (matches the
//     legacy MTU sweep / sustained traffic profile)
//   - random:     256 bytes of crypto-random — opaque content
//   - zero-fill:  200 bytes of zero — opaque-but-zeroed content
//
// All three are PROBE packets (TYPE 1); only the post-header bytes
// change. The server's handler echoes the entire packet verbatim
// for replies, so it doesn't care what's in the padding area.
async function payloadShapeTest({ host, port, nonce, family = 4 }) {
  // Builder for each pattern. Returns a function that produces a
  // fresh buffer each call (so we don't mutate a shared one).
  const patterns = {
    'game-shape': () => {
      const size = 200 + Math.floor(Math.random() * 200);
      return { totalSize: size, fill: 'zero' };
    },
    'random': () => ({ totalSize: 256, fill: 'random' }),
    'zero-fill': () => ({ totalSize: 200, fill: 'zero' }),
  };
  const perPattern = {};
  for (const [name, builder] of Object.entries(patterns)) {
    const sock = dgram.createSocket(dgramTypeFor(family));
    let received = 0;
    let rateLimited = 0;
    const pending = new Map();
    sock.on('error', () => {});
    sock.on('message', (msg) => {
      const decoded = protocol.decode(msg);
      if (!decoded || !decoded.nonce.equals(nonce)) return;
      if (decoded.type === protocol.TYPE.RATE_LIMITED) { rateLimited++; return; }
      if (decoded.type !== protocol.TYPE.REPLY) return;
      if (!pending.has(decoded.sequence)) return;
      pending.delete(decoded.sequence);
      received++;
    });
    for (let seq = 0; seq < PAYLOAD_SHAPE_PACKETS_EACH; seq++) {
      const fullSeq = 40000 + (Object.keys(patterns).indexOf(name) * 1000) + seq;
      const { totalSize, fill } = builder();
      const pkt = protocol.encode({
        type: protocol.TYPE.PROBE,
        nonce, sequence: fullSeq,
        clientTsNs: nowNs(),
        totalSize,
      });
      if (fill === 'random') {
        // Overwrite the post-header bytes with crypto-random data.
        // The protocol header bytes (0..35) stay valid SDGT so the
        // server still parses and replies; only the padding region
        // (36..) varies, which is exactly what DPI signatures key on.
        crypto.randomBytes(totalSize - protocol.HEADER_SIZE).copy(pkt, protocol.HEADER_SIZE);
      }
      // 'zero' fill: nothing to do. protocol.encode() already
      // zero-allocs the whole buffer.
      pending.set(fullSeq, true);
      sock.send(pkt, port, host, () => {});
      await new Promise((r) => setTimeout(r, LOSS_INTERVAL_MS));
    }
    await new Promise((r) => setTimeout(r, PROBE_TIMEOUT_MS));
    try { sock.close(); } catch (e) {}
    const lossPct = (1 - received / PAYLOAD_SHAPE_PACKETS_EACH) * 100;
    perPattern[name] = { sent: PAYLOAD_SHAPE_PACKETS_EACH, received, rateLimited, lossPct };
  }
  const verdict = classifyPayloadShape(
    Object.fromEntries(Object.entries(perPattern).map(([k, v]) => [k, v.lossPct])),
  );
  return { port, perPattern, verdict };
}

// ================================================================
// TCP probes
// ================================================================

function tcpProbe({ host, port, nonce, sequence }) {
  return new Promise((resolve) => {
    const start = nowMs();
    const sock = new net.Socket();
    let done = false;
    const finish = (result) => {
      if (done) return;
      done = true;
      try { sock.destroy(); } catch (e) {}
      resolve(result);
    };

    sock.setTimeout(TCP_CONNECT_TIMEOUT_MS);
    sock.once('timeout', () => finish({ ok: false, rtt: null, reason: 'timeout' }));
    sock.once('error',   (err) => finish({ ok: false, rtt: null, reason: err.code || err.message }));

    sock.connect(port, host, () => {
      const connectMs = nowMs() - start;
      const frame = protocol.encode({
        type: protocol.TYPE.PROBE,
        nonce, sequence,
        clientTsNs: nowNs(),
      });
      const out = Buffer.alloc(2 + frame.length);
      out.writeUInt16LE(frame.length, 0);
      frame.copy(out, 2);

      const chunks = [];
      sock.on('data', (chunk) => {
        chunks.push(chunk);
        const buf = Buffer.concat(chunks);
        if (buf.length < 2) return;
        const len = buf.readUInt16LE(0);
        if (buf.length < 2 + len) return;
        const reply = buf.subarray(2, 2 + len);
        const decoded = protocol.decode(reply);
        if (decoded && decoded.type === protocol.TYPE.REPLY && decoded.nonce.equals(nonce)) {
          finish({ ok: true, rtt: nowMs() - start, connectMs, reason: null });
        } else {
          finish({ ok: false, rtt: null, reason: 'bad-reply' });
        }
      });

      sock.write(out);
    });
  });
}

// ================================================================
// Steam A2S_INFO test (real Valve protocol)
// ================================================================

// Real Valve A2S_INFO query with the December 2020 challenge dance.
// Sequence (matches https://developer.valvesoftware.com/wiki/Server_queries ):
//
//   1. Client sends the 25-byte "Source Engine Query" request.
//   2. Server replies with S2C_CHALLENGE (9 bytes: FF FF FF FF 41 <u32>).
//   3. Client resends the request with the 4-byte challenge appended (29 bytes).
//   4. Server replies with A2S_INFO (header FF FF FF FF 49 followed by
//      packed fields).
//
// We parse step 4 into a small info object and return total RTT (step 1
// send to step 4 receive).
function a2sQuery({ host, port, family = 4 }) {
  return new Promise((resolve) => {
    const requestBase = Buffer.from([
      0xff, 0xff, 0xff, 0xff, 0x54,
      0x53, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x20,
      0x45, 0x6e, 0x67, 0x69, 0x6e, 0x65, 0x20,
      0x51, 0x75, 0x65, 0x72, 0x79, 0x00,
    ]);
    const sock = dgram.createSocket(dgramTypeFor(family));
    const start = nowMs();
    let done = false;
    const finish = (result) => {
      if (done) return;
      done = true;
      try { sock.close(); } catch (e) {}
      resolve(result);
    };

    sock.on('error', () => finish({ ok: false, rtt: null, info: null, reason: 'socket-error' }));

    sock.on('message', (msg) => {
      if (msg.length < 5) return;
      if (msg.readUInt32LE(0) !== 0xffffffff) return;

      // S2C_CHALLENGE — attach challenge and resend.
      if (msg[4] === 0x41) {
        if (msg.length < 9) return finish({ ok: false, rtt: null, info: null, reason: 'short-challenge' });
        const withChallenge = Buffer.alloc(requestBase.length + 4);
        requestBase.copy(withChallenge, 0);
        msg.copy(withChallenge, requestBase.length, 5, 9);
        sock.send(withChallenge, port, host, (err) => {
          if (err) finish({ ok: false, rtt: null, info: null, reason: err.code || 'send-error' });
        });
        return;
      }

      // A2S_INFO reply.
      if (msg[4] !== 0x49) return;
      let off = 5;
      const protocolByte = msg[off++];
      const readCStr = () => {
        const end = msg.indexOf(0, off);
        if (end < 0) return null;
        const s = msg.toString('utf8', off, end);
        off = end + 1;
        return s;
      };
      const name = readCStr();
      const map  = readCStr();
      const folder = readCStr();
      const game = readCStr();
      finish({
        ok: true,
        rtt: nowMs() - start,
        info: { protocol: protocolByte, name, map, folder, game },
        reason: null,
      });
    });

    sock.send(requestBase, port, host, (err) => {
      if (err) finish({ ok: false, rtt: null, info: null, reason: err.code || 'send-error' });
    });
    setTimeout(() => finish({ ok: false, rtt: null, info: null, reason: 'timeout' }), PROBE_TIMEOUT_MS * 2);
  });
}

// ================================================================
// Game-shape sustained test — send STREAM_BEGIN, listen for stream_data.
// ================================================================

// Game-shape sustained test with the mandatory server challenge.
//
// Handshake:
//   1. Send STREAM_BEGIN
//   2. Server replies with STREAM_CHALLENGE carrying a 16-byte token
//      in the payload area (offset 36). Or, if we are rate limited,
//      RATE_LIMITED.
//   3. Send STREAM_CONFIRM with the token echoed back.
//   4. Server emits STREAM_DATA for ~durationMs ms.
//   5. Send STREAM_STOP and close.
function sustainedTest({ host, port, nonce, durationMs, family = 4 }) {
  return new Promise((resolve) => {
    const sock = dgram.createSocket(dgramTypeFor(family));
    let received = 0;
    let firstArrivalMs = null;
    let lastArrivalMs = null;
    const interArrivals = [];
    let maxGapMs = 0;
    let streamStarted = false;
    let rateLimited = false;
    // Track the server's own sequence numbers so we compute loss against
    // "what the server sent" rather than "what we thought we asked for".
    // This side-steps OS timer-resolution issues (e.g. Windows setInterval
    // granularity) and handshake timing.
    let minSeq = null;
    let maxSeq = null;
    const seenSeqs = new Set();
    // Phase 2 tracking — same as udpLossTest.
    const arrivalOrder = [];

    sock.on('error', () => {});
    sock.on('message', (msg) => {
      const decoded = protocol.decode(msg);
      if (!decoded || !decoded.nonce.equals(nonce)) return;

      if (decoded.type === protocol.TYPE.RATE_LIMITED) {
        rateLimited = true;
        return;
      }

      if (decoded.type === protocol.TYPE.STREAM_CHALLENGE) {
        // Extract the 16-byte token and echo it back in a STREAM_CONFIRM.
        if (msg.length < protocol.TOKEN_OFFSET + protocol.TOKEN_SIZE) return;
        const confirm = protocol.encode({
          type: protocol.TYPE.STREAM_CONFIRM,
          nonce,
          sequence: 0,
          clientTsNs: nowNs(),
          totalSize: protocol.HEADER_SIZE + protocol.TOKEN_SIZE,
        });
        msg.copy(
          confirm,
          protocol.TOKEN_OFFSET,
          protocol.TOKEN_OFFSET,
          protocol.TOKEN_OFFSET + protocol.TOKEN_SIZE,
        );
        sock.send(confirm, port, host, () => {});
        streamStarted = true;
        return;
      }

      if (decoded.type !== protocol.TYPE.STREAM_DATA) return;
      const t = nowMs();
      if (firstArrivalMs == null) firstArrivalMs = t;
      if (lastArrivalMs != null) {
        const gap = t - lastArrivalMs;
        interArrivals.push(gap);
        if (gap > maxGapMs) maxGapMs = gap;
      }
      lastArrivalMs = t;
      // Only count each sequence once; the seenSeqs set makes us robust
      // against duplicates (a reordered/retransmitted packet shouldn't
      // inflate received count).
      if (!seenSeqs.has(decoded.sequence)) {
        seenSeqs.add(decoded.sequence);
        received++;
        arrivalOrder.push(decoded.sequence);
        if (minSeq == null || decoded.sequence < minSeq) minSeq = decoded.sequence;
        if (maxSeq == null || decoded.sequence > maxSeq) maxSeq = decoded.sequence;
      }
    });

    const begin = protocol.encode({
      type: protocol.TYPE.STREAM_BEGIN,
      nonce, sequence: 0,
      clientTsNs: nowNs(),
    });
    sock.send(begin, port, host, () => {});

    setTimeout(() => {
      const stop = protocol.encode({
        type: protocol.TYPE.STREAM_STOP,
        nonce, sequence: 0,
        clientTsNs: nowNs(),
      });
      sock.send(stop, port, host, () => {
        try { sock.close(); } catch (e) {}
        // Compute loss against what the server actually sent: the span
        // [minSeq, maxSeq] tells us how many packets left the server
        // during our observation window. Anything within that span that
        // we did not see is real loss. Anything outside the window
        // (setup, shutdown, timer granularity) is NOT counted as loss,
        // which prevents false alarms from short durations or slow
        // handshakes.
        let expected;
        let lossPct;
        if (minSeq == null || maxSeq == null) {
          // No data at all — report the nominal expectation so the
          // customer sees 100% loss loud and clear.
          expected = Math.round((durationMs / 1000) * SUSTAINED_PPS);
          lossPct = 100;
        } else {
          expected = (maxSeq - minSeq) + 1;
          lossPct = expected > 0 ? Math.max(0, (1 - received / expected) * 100) : 0;
        }
        // Burst histogram is computed against [minSeq, maxSeq] — the
        // window the server actually emitted. Anything outside that
        // window isn't loss, just timing of setup/teardown.
        let burstHistogram, reordering;
        if (minSeq == null || maxSeq == null) {
          burstHistogram = lossBurstHistogram([], expected);
          reordering = countReorderings([]);
        } else {
          // Re-base sequences to [0, span) so the histogram walker
          // doesn't have to special-case minSeq.
          const span = (maxSeq - minSeq) + 1;
          const arrivedBased = [...seenSeqs].map(s => s - minSeq);
          const arrivalBased = arrivalOrder.map(s => s - minSeq);
          burstHistogram = lossBurstHistogram(arrivedBased, span);
          reordering = countReorderings(arrivalBased);
        }
        resolve({
          expected,
          received,
          minSeq,
          maxSeq,
          rateLimited,
          streamStarted,
          lossPct,
          firstArrivalMs: firstArrivalMs == null ? null : firstArrivalMs,
          lastArrivalMs: lastArrivalMs == null ? null : lastArrivalMs,
          jitter: stats(interArrivals),
          maxGapMs,
          exceeded250ms: maxGapMs > 250,
          burstHistogram,
          reordering,
        });
      });
    }, durationMs + 500);
  });
}

// ================================================================
// Phase 1: Bidirectional sustained test
// ================================================================
//
// Extends the legacy sustainedTest to support direction = 'up' (client
// emits, server tallies) or 'both' (server emits AND client emits).
// On a v1 server, the direction byte is ignored: the server runs a
// downstream and never emits STREAM_TALLY. We detect that and mark
// the result `serverSupported: false` rather than misreport it as
// data we don't have.
function sustainedTestV2({ host, port, nonce, durationMs, direction, upPps, family = 4 }) {
  return new Promise((resolve) => {
    const sock = dgram.createSocket(dgramTypeFor(family));
    let received = 0;
    let firstArrivalMs = null;
    let lastArrivalMs = null;
    const interArrivals = [];
    let maxGapMs = 0;
    let streamStarted = false;
    let rateLimited = false;
    let minSeq = null;
    let maxSeq = null;
    const seenSeqs = new Set();
    // Phase 2 tracking — same as legacy sustainedTest.
    const arrivalOrder = [];
    let tally = null;

    const wantsDown = direction === protocol.DIRECTION_DOWN || direction === protocol.DIRECTION_BOTH;
    const wantsUp   = direction === protocol.DIRECTION_UP   || direction === protocol.DIRECTION_BOTH;

    let upSent = 0;
    let upTimer = null;
    let upStopAt = null;

    sock.on('error', () => {});
    sock.on('message', (msg) => {
      const decoded = protocol.decode(msg);
      if (!decoded || !decoded.nonce.equals(nonce)) return;

      if (decoded.type === protocol.TYPE.RATE_LIMITED) {
        rateLimited = true;
        return;
      }

      if (decoded.type === protocol.TYPE.STREAM_CHALLENGE) {
        if (msg.length < protocol.TOKEN_OFFSET + protocol.TOKEN_SIZE) return;
        // Echo the direction byte in the CONFIRM. The server expects
        // the BEGIN and CONFIRM to agree on direction; mismatched
        // direction bytes are rejected.
        const confirm = protocol.encode({
          type: protocol.TYPE.STREAM_CONFIRM,
          nonce,
          sequence: 0,
          clientTsNs: nowNs(),
          totalSize: protocol.HEADER_SIZE + protocol.TOKEN_SIZE,
          flags: direction,
        });
        msg.copy(
          confirm,
          protocol.TOKEN_OFFSET,
          protocol.TOKEN_OFFSET,
          protocol.TOKEN_OFFSET + protocol.TOKEN_SIZE,
        );
        sock.send(confirm, port, host, () => {});
        streamStarted = true;
        // Begin emitting upstream once the challenge handshake is
        // accepted — never before, otherwise the server's anti-spoof
        // gate would reject it. Self-rescheduling setTimeout avoids
        // setInterval drift on Windows.
        if (wantsUp) {
          upStopAt = nowMs() + durationMs;
          const intervalMs = 1000 / upPps;
          let upSeq = 0;
          const tick = () => {
            if (nowMs() >= upStopAt) return;
            const payloadSize = protocol.HEADER_SIZE + 200 + Math.floor(Math.random() * 200);
            const pkt = protocol.encode({
              type: protocol.TYPE.STREAM_DATA_UP,
              nonce,
              sequence: upSeq++,
              clientTsNs: nowNs(),
              totalSize: payloadSize,
            });
            sock.send(pkt, port, host, (err) => { if (!err) upSent++; });
            upTimer = setTimeout(tick, intervalMs);
          };
          tick();
        }
        return;
      }

      if (decoded.type === protocol.TYPE.STREAM_TALLY) {
        // Server sends three copies; first one wins. The duplicates are
        // for loss tolerance, not for re-tallying.
        if (tally) return;
        tally = protocol.decodeStreamTally(msg);
        return;
      }

      if (decoded.type !== protocol.TYPE.STREAM_DATA) return;
      const t = nowMs();
      if (firstArrivalMs == null) firstArrivalMs = t;
      if (lastArrivalMs != null) {
        const gap = t - lastArrivalMs;
        interArrivals.push(gap);
        if (gap > maxGapMs) maxGapMs = gap;
      }
      lastArrivalMs = t;
      if (!seenSeqs.has(decoded.sequence)) {
        seenSeqs.add(decoded.sequence);
        received++;
        arrivalOrder.push(decoded.sequence);
        if (minSeq == null || decoded.sequence < minSeq) minSeq = decoded.sequence;
        if (maxSeq == null || decoded.sequence > maxSeq) maxSeq = decoded.sequence;
      }
    });

    const begin = protocol.encode({
      type: protocol.TYPE.STREAM_BEGIN,
      nonce, sequence: 0,
      clientTsNs: nowNs(),
      flags: direction,
    });
    sock.send(begin, port, host, () => {});

    // Wait for the duration plus 500 ms grace, then send STREAM_STOP
    // and wait another 500 ms for tallies to land before resolving.
    setTimeout(() => {
      if (upTimer) clearTimeout(upTimer);
      upStopAt = 0;   // halt any in-flight tick
      const stop = protocol.encode({
        type: protocol.TYPE.STREAM_STOP,
        nonce, sequence: 0,
        clientTsNs: nowNs(),
      });
      sock.send(stop, port, host, () => {});
      setTimeout(() => {
        try { sock.close(); } catch (e) {}
        let downExpected, downLossPct;
        if (wantsDown) {
          if (minSeq == null || maxSeq == null) {
            downExpected = Math.round((durationMs / 1000) * SUSTAINED_PPS);
            downLossPct = 100;
          } else {
            downExpected = (maxSeq - minSeq) + 1;
            downLossPct = downExpected > 0 ? Math.max(0, (1 - received / downExpected) * 100) : 0;
          }
        } else {
          downExpected = 0;
          downLossPct = null;
        }
        let upLossPct = null;
        if (wantsUp && tally) {
          upLossPct = upSent > 0 ? Math.max(0, (1 - tally.packets / upSent) * 100) : 0;
        }
        const serverSupported = wantsUp ? tally != null : true;
        // Burst histogram + reordering for the downstream half. The
        // up-stream half doesn't get one because the client doesn't
        // see individual up packets land — only the server's tally,
        // which is a single number. (For up-direction burst signal,
        // wait until we wire client-emit-side timestamping into the
        // tally — out of scope for Phase 2.)
        let burstHistogram, reordering;
        if (!wantsDown || minSeq == null || maxSeq == null) {
          burstHistogram = lossBurstHistogram([], downExpected || 0);
          reordering = countReorderings([]);
        } else {
          const span = (maxSeq - minSeq) + 1;
          const arrivedBased = [...seenSeqs].map(s => s - minSeq);
          const arrivalBased = arrivalOrder.map(s => s - minSeq);
          burstHistogram = lossBurstHistogram(arrivedBased, span);
          reordering = countReorderings(arrivalBased);
        }
        resolve({
          direction,
          serverSupported,
          streamStarted,
          rateLimited,
          // Down-direction fields (mirror legacy sustainedTest output)
          expected: downExpected,
          received,
          minSeq, maxSeq,
          lossPct: downLossPct,
          firstArrivalMs, lastArrivalMs,
          jitter: stats(interArrivals),
          maxGapMs,
          exceeded250ms: maxGapMs > 250,
          burstHistogram,
          reordering,
          // Up-direction fields
          upSent: wantsUp ? upSent : null,
          upTallied: tally,
          upLossPct,
        });
      }, 500);
    }, durationMs + 500);
  });
}

// ================================================================
// Test runner
// ================================================================

function filterPorts(allPorts, wanted) {
  if (!wanted) return allPorts;
  const set = new Set(wanted.map((n) => Number(n)));
  return allPorts.filter((p) => set.has(p.port));
}

function fmt(n) {
  if (n == null || !Number.isFinite(n)) return '   —  ';
  if (n < 10) return n.toFixed(2);
  if (n < 100) return n.toFixed(1);
  return Math.round(n).toString();
}

async function runTests(opts) {
  const host = opts.host;
  const { address: resolved, family } = await resolveHost(host, opts.family || 0);
  const nonce = randomNonce();
  console.log(`Session nonce: ${toHex(nonce)}`);
  console.log(`Resolved ${host} -> ${resolved} (IPv${family})`);
  console.log('');

  const portsToTest = filterPorts(PORTS, opts.ports);

  const report = {
    version: 2,
    tool: 'sdg-connection-test client',
    startedAt: new Date().toISOString(),
    host, resolved, family,
    nonceHex: toHex(nonce),
    capabilities: null,
    mtuDiscovery: null,
    perPort: [],
    a2s: null,
    sustained: null,
    realServerA2S: null,
    natIdle: null,
    natType: null,
    burstVsSteady: null,
    sourcePortFanout: null,
    payloadShape: null,
    recommendations: null,
    // Field names that are still populated but will be removed in a
    // future release. Support staff can grep on this to detect the
    // transition.
    deprecated: ['perPort[].mtuSweep'],
  };

  // Capability probe runs first whenever a Phase 1 server-dependent
  // test is requested — we must know whether the server supports
  // reflection / bidirectional before we run those tests, so we can
  // skip them with a structured "v1 server" verdict rather than
  // misinterpret a non-response.
  const needsCapabilities = opts.natType || opts.bidir !== 'down' || opts.natIdle;
  if (needsCapabilities) {
    process.stdout.write('  Capability probe ... ');
    report.capabilities = await capabilityProbe({ host: resolved, family });
    if (!report.capabilities.ok) {
      console.log(`FAIL (${report.capabilities.reason})`);
    } else if (report.capabilities.isV1Server) {
      console.log('OK (v1 server, no Phase 1 features)');
    } else {
      const c = report.capabilities.capabilities;
      const supported = [];
      if (c.reflection) supported.push('reflection');
      if (c.bidirectional) supported.push('bidirectional');
      if (c.natIdleAware) supported.push('nat-idle-aware');
      console.log(`OK (${supported.length ? supported.join(', ') : 'no features'})`);
    }
  }

  // MTU discovery — runs once against the critical SE game port (or a
  // fallback if 27016 is itself unreachable). MTU is a path property,
  // not per-port — discovering it once and spot-checking the other
  // UDP ports is both faster and produces a clearer single
  // recommendation than the old per-port 3-size sweep ever did.
  if (opts.mtuDiscovery !== false) {
    const primary = GAME_SHAPE_PORT;
    const fallbackChain = MTU_FALLBACK_PORTS.filter((p) => p !== primary);
    // If the user filtered ports, only run discovery against ports they kept.
    // opts.ports is parsed as strings by argv; coerce for comparison.
    const portsAsNumbers = opts.ports ? new Set(opts.ports.map((n) => Number(n))) : null;
    const filteredPorts = portsAsNumbers
      ? [primary, ...fallbackChain].filter((p) => portsAsNumbers.has(p))
      : [primary, ...fallbackChain];
    if (filteredPorts.length === 0) {
      report.mtuDiscovery = {
        skipped: true,
        reason: 'no-discovery-port-in-filter',
      };
      console.log('  MTU discovery: skipped (no critical UDP port in --ports filter)');
    } else {
      const discoveryPrimary = filteredPorts[0];
      const discoveryFallbacks = filteredPorts.slice(1);
      process.stdout.write(`  MTU discovery on udp ${discoveryPrimary} ... `);
      try {
        const result = await runMtuDiscoveryWithFallback({
          host: resolved,
          primaryPort: discoveryPrimary,
          fallbackPorts: discoveryFallbacks,
          nonce, family,
        });
        report.mtuDiscovery = result;
        if (result.ok && result.ceiling != null) {
          console.log(`ceiling=${result.ceiling} on udp ${result.discoveredOn} (${result.ceilingConfidence})`);
        } else if (result.skipped) {
          console.log(`skipped (${result.reason})`);
        } else if (result.ok && result.ceiling == null) {
          console.log('no working size found');
        } else {
          console.log(`FAIL (${result.error || 'unknown'})`);
        }
      } catch (e) {
        report.mtuDiscovery = { ok: false, skipped: false, error: e.message || String(e) };
        console.log(`FAIL (${e.message || e})`);
      }
    }
  } else {
    report.mtuDiscovery = { skipped: true, reason: 'disabled-by-flag' };
  }

  const rows = [];

  for (const p of portsToTest) {
    process.stdout.write(`  Testing ${p.proto} ${p.port} (${p.purpose}) ... `);
    const row = {
      proto: p.proto, port: p.port, category: p.category, purpose: p.purpose,
      reachable: false,
      rateLimited: false,
      loss: null,
      mtu: null,
      firstRttMs: null,
      error: null,
    };

    try {
      if (p.proto === 'udp') {
        const first = await udpProbe({ host: resolved, port: p.port, nonce, sequence: 0, family });
        row.reachable = first.ok;
        row.firstRttMs = first.rtt;
        row.rateLimited = first.rateLimited;
        if (row.reachable) {
          row.loss = await udpLossTest({ host: resolved, port: p.port, nonce, family });
          if (row.loss.rateLimited > 0) row.rateLimited = true;
          // MTU is now discovered once (above) and spot-checked across
          // all reachable UDP ports (below, after this loop) — the old
          // per-port 3-size sweep is gone. `row.mtu` / `row.mtuSweep`
          // are filled in by the spot-check pass.
        }
      } else {
        const r = await tcpProbe({ host: resolved, port: p.port, nonce, sequence: 0 });
        row.reachable = r.ok;
        row.firstRttMs = r.rtt;
        row.error = r.reason;
      }
    } catch (e) {
      row.error = e.message;
    }

    report.perPort.push(row);
    rows.push(row);
    let status;
    if (row.reachable) status = 'OK';
    else if (row.rateLimited) status = 'RATE-LIMITED (SDG server)';
    else status = `FAIL${row.error ? ' (' + row.error + ')' : ''}`;
    console.log(status);
  }

  // Spot-check the discovered MTU ceiling on every reachable UDP port
  // in parallel. Different destination ports = different 5-tuples = no
  // reply confusion. Populates row.mtuAtCeiling AND the deprecated
  // row.mtu / row.mtuSweep aliases for backwards compatibility with
  // pre-v2 report consumers.
  const discoveredCeiling = (report.mtuDiscovery && report.mtuDiscovery.ok)
    ? report.mtuDiscovery.ceiling
    : null;
  if (discoveredCeiling != null) {
    const reachableUdpPorts = report.perPort
      .filter((r) => r.proto === 'udp' && r.reachable)
      .map((r) => r.port);
    if (reachableUdpPorts.length > 0) {
      process.stdout.write(`  MTU spot-check at ${discoveredCeiling} bytes on ${reachableUdpPorts.length} port(s) ... `);
      let spot;
      try {
        spot = await spotCheckCeiling({
          host: resolved, ports: reachableUdpPorts,
          nonce, family, ceiling: discoveredCeiling,
        });
      } catch (e) {
        spot = [];
        console.log(`FAIL (${e.message || e})`);
      }
      if (spot.length) console.log('done');
      const spotByPort = new Map(spot.map((s) => [s.port, s]));
      for (const r of report.perPort) {
        if (r.proto !== 'udp') continue;
        const s = spotByPort.get(r.port);
        if (!s) continue;
        r.mtuAtCeiling = { size: s.size, ok: s.ok, rtt: s.rtt, probes: s.probes };
        // Deprecated single-value alias.
        r.mtu = { size: s.size, ok: s.ok, rtt: s.rtt };
        // Deprecated array alias (one element, matches the new shape).
        r.mtuSweep = [{ size: s.size, ok: s.ok, rtt: s.rtt }];
        // Flag port-specific shaping when the spot-check fails at a
        // size the discovery port proved works.
        if (!s.ok) r.portSpecificShaping = true;
      }
    }
  }

  // Print the "TEST INCONCLUSIVE" banner BEFORE any subsequent phase
  // (A2S, sustained, etc.) so customers pattern-match on the banner
  // before they see the sea-of-FAIL in the table. The remaining phases
  // still run — the report stays as complete as possible for support.
  if (shouldPrintInconclusive(report)) {
    printInconclusiveBanner();
  }

  if (opts.a2s) {
    console.log('');
    process.stdout.write(`  Steam A2S_INFO query udp ${A2S_PORT} ... `);
    report.a2s = await a2sQuery({ host: resolved, port: A2S_PORT, family });
    console.log(report.a2s.ok ? `OK (${report.a2s.info.name})` : `FAIL (${report.a2s.reason})`);
  }

  if (opts.sustained) {
    console.log('');
    console.log(`  Game-shape sustained test udp ${GAME_SHAPE_PORT} for ${Math.round(opts.duration/1000)}s (direction: ${opts.bidir}) ...`);
    if (opts.bidir === 'down') {
      report.sustained = await sustainedTest({
        host: resolved, port: GAME_SHAPE_PORT, nonce,
        durationMs: opts.duration, family,
      });
      const s = report.sustained;
      console.log(`    received ${s.received}/${s.expected}  loss ${fmt(s.lossPct)}%  max gap ${fmt(s.maxGapMs)}ms${s.exceeded250ms ? '  [THROTTLING SIGNAL]' : ''}`);
    } else {
      // Bidirectional / upstream variant. Requires server support.
      const caps = report.capabilities && report.capabilities.capabilities;
      if (!caps || !caps.bidirectional) {
        console.log('    SKIPPED — server does not advertise bidirectional support');
        report.sustained = { skipped: true, reason: 'server v1 (no bidirectional)' };
      } else {
        const dirCode = opts.bidir === 'up' ? protocol.DIRECTION_UP : protocol.DIRECTION_BOTH;
        report.sustained = await sustainedTestV2({
          host: resolved, port: GAME_SHAPE_PORT, nonce,
          durationMs: opts.duration, direction: dirCode,
          upPps: opts.upPps, family,
        });
        const s = report.sustained;
        if (!s.serverSupported) {
          console.log('    SKIPPED — no STREAM_TALLY received (server may have run a downstream-only fallback)');
        } else {
          if (opts.bidir === 'up' || opts.bidir === 'both') {
            const upTallied = s.upTallied ? s.upTallied.packets : 'no-tally';
            console.log(`    up: client sent ${s.upSent}, server received ${upTallied} (loss ${fmt(s.upLossPct)}%)`);
          }
          if (opts.bidir === 'both') {
            console.log(`    down: received ${s.received}/${s.expected}  loss ${fmt(s.lossPct)}%  max gap ${fmt(s.maxGapMs)}ms`);
          }
        }
      }
    }
  }

  if (opts.natIdle) {
    console.log('');
    console.log(`  NAT idle-timeout probe (windows: ${opts.natIdle.join(',')}s)`);
    const reflectionSupported = !!(report.capabilities &&
                                   report.capabilities.capabilities &&
                                   report.capabilities.capabilities.reflection);
    report.natIdle = await natIdleTest({
      host: resolved, port: GAME_SHAPE_PORT, nonce,
      windows: opts.natIdle, family, reflectionSupported,
    });
    console.log(`    largest idle window mapping survived: ${report.natIdle.largestSurvivedSec}s`);
  }

  if (opts.natType) {
    console.log('');
    process.stdout.write('  NAT type / endpoint reflection ... ');
    const caps = report.capabilities && report.capabilities.capabilities;
    if (!caps || !caps.reflection) {
      console.log('SKIPPED (server does not advertise reflection)');
      report.natType = { skipped: true, reason: 'server v1 (no reflection)' };
    } else {
      // Two destination ports both already in shared/ports.js; both are
      // UDP and on the SE/Steam side of the matrix. The classifier only
      // compares the reflected source ports.
      const r = await natTypeTest({
        host: resolved,
        ports: [GAME_SHAPE_PORT, 27017],
        nonce, family,
      });
      report.natType = r;
      if (!r.ok) {
        console.log(`FAIL (${r.reason})`);
      } else {
        console.log(`${r.verdict.kind} — ${natTypeImpact(r.verdict)}`);
      }
    }
  }

  if (opts.burst) {
    console.log('');
    console.log(`  Burst-vs-steady policer test on udp ${BURST_PORT} ...`);
    report.burstVsSteady = await burstVsSteadyTest({
      host: resolved, port: BURST_PORT, nonce, family,
    });
    const b = report.burstVsSteady;
    console.log(`    burst:  ${b.burst.received}/${b.burst.sent} (loss ${fmt(b.burst.lossPct)}%, observed ${fmt(b.burst.observedPps)} pps, RL ${fmt(b.burst.rateLimitedPct)}%)`);
    console.log(`    steady: ${b.steady.received}/${b.steady.sent} (loss ${fmt(b.steady.lossPct)}%)`);
    console.log(`    verdict: ${b.verdict.kind} — ${b.verdict.reason}`);
  }

  if (opts.sourcePortFanout) {
    console.log('');
    console.log(`  Source-port fan-out on udp ${GAME_SHAPE_PORT} (${FANOUT_SOCKET_COUNT} sockets × ${FANOUT_PACKETS_EACH} probes) ...`);
    report.sourcePortFanout = await sourcePortFanoutTest({
      host: resolved, port: GAME_SHAPE_PORT, nonce, family,
    });
    const f = report.sourcePortFanout;
    for (const s of f.perSocket) {
      console.log(`    src ${s.sourcePort}: ${s.received}/${s.sent} (loss ${fmt(s.lossPct)}%)`);
    }
    console.log(`    verdict: ${f.verdict.kind} — ${f.verdict.reason}`);
  }

  if (opts.payloadShape) {
    console.log('');
    console.log(`  Payload-shape sensitivity on udp ${GAME_SHAPE_PORT} (3 patterns × ${PAYLOAD_SHAPE_PACKETS_EACH} probes) ...`);
    report.payloadShape = await payloadShapeTest({
      host: resolved, port: GAME_SHAPE_PORT, nonce, family,
    });
    const p = report.payloadShape;
    for (const [name, r] of Object.entries(p.perPattern)) {
      console.log(`    ${name.padEnd(11)}: ${r.received}/${r.sent} (loss ${fmt(r.lossPct)}%)`);
    }
    console.log(`    verdict: ${p.verdict.kind} — ${p.verdict.reason}`);
  }

  if (opts.realServer) {
    let rs;
    try {
      rs = parseHostPort(opts.realServer);
    } catch (e) {
      console.error(`  --real-server: ${e.message}`);
      report.realServerA2S = { ok: false, reason: `parse-error: ${e.message}` };
    }
    if (rs) {
      console.log('');
      process.stdout.write(`  Real-server A2S_INFO ${rs.host}:${rs.port} ... `);
      const realResolved = await resolveHost(rs.host, opts.family || 0);
      const real = await a2sQuery({ host: realResolved.address, port: rs.port, family: realResolved.family });
      report.realServerA2S = { host: rs.host, port: rs.port, family: realResolved.family, ...real };
      console.log(real.ok ? `OK (${real.info.name})` : `FAIL (${real.reason})`);
    }
  }

  report.finishedAt = new Date().toISOString();
  return report;
}

// ---- Pretty table ----
function printTable(report, { includePublicIp = false } = {}) {
  console.log('');
  console.log('================================================================');
  console.log('RESULTS');
  console.log('================================================================');
  // Summarize the discovered MTU ceiling above the table so the per-port
  // mtu column has obvious context. The descent ran once on the critical
  // SE game port (or a fallback); the table column reflects spot-checks
  // at the discovered ceiling, not independent per-port discoveries.
  if (report.mtuDiscovery && report.mtuDiscovery.ok && report.mtuDiscovery.ceiling != null) {
    const d = report.mtuDiscovery;
    const conf = d.ceilingConfidence === 'medium' ? ' (borderline — see recommendations)' : '';
    let summary = '';
    if (Array.isArray(d.descent) && d.descent.length >= 2) {
      // Find the ceiling pass/total and the failed size immediately above it.
      const passed = d.descent.find((s) => s.size === d.ceiling);
      const failedAbove = d.descent.filter((s) => s.size > d.ceiling).slice(-1)[0];
      if (passed && failedAbove) {
        const pPass = passed.probes.filter((p) => p && p.ok).length;
        const pTotal = passed.probes.length;
        const fPass = failedAbove.probes.filter((p) => p && p.ok).length;
        const fTotal = failedAbove.probes.length;
        summary = `  (${pPass}/${pTotal} at ${passed.size}, ${fPass}/${fTotal} at ${failedAbove.size})`;
      } else if (passed) {
        const pPass = passed.probes.filter((p) => p && p.ok).length;
        const pTotal = passed.probes.length;
        summary = `  (${pPass}/${pTotal} at ${passed.size})`;
      }
    }
    console.log(`MTU ceiling discovered on udp ${d.discoveredOn}: ${d.ceiling} bytes${summary}${conf}`);
    if (d.fellBackFrom) {
      console.log(`  (primary discovery port udp ${d.fellBackFrom} was unreachable; fell back to udp ${d.discoveredOn})`);
    }
    console.log('');
  } else if (report.mtuDiscovery && report.mtuDiscovery.skipped) {
    console.log(`MTU discovery skipped: ${report.mtuDiscovery.reason || 'unknown reason'}`);
    console.log('');
  } else if (report.mtuDiscovery && report.mtuDiscovery.ok && report.mtuDiscovery.ceiling == null) {
    console.log('MTU discovery: no working size found on any discovery target. See recommendations.');
    console.log('');
  }
  const header = 'proto  port   cat       reach  rtt(ms)  loss%   mtu      purpose';
  console.log(header);
  console.log('-'.repeat(header.length + 10));
  for (const r of report.perPort) {
    let reach;
    if (r.reachable && r.rateLimited) reach = 'OK* ';
    else if (r.reachable)              reach = 'OK  ';
    else if (r.rateLimited)            reach = 'RL  ';
    else                               reach = 'FAIL';
    const rtt = r.loss && r.loss.latency.avg != null ? fmt(r.loss.latency.avg) : fmt(r.firstRttMs);
    const loss = r.loss ? fmt(r.loss.lossPct) : '  —  ';
    // Show the spot-check result at the discovered ceiling. Falls
    // back to the legacy `r.mtu` / `r.mtuSweep` fields if a consumer
    // hands this function a pre-v2 report (e.g. from a saved file).
    let mtu = ' — ';
    if (r.mtuAtCeiling) {
      mtu = r.mtuAtCeiling.ok ? `${r.mtuAtCeiling.size}` : 'FAIL';
    } else if (r.mtuSweep && r.mtuSweep.length) {
      const lastOk = [...r.mtuSweep].reverse().find(s => s.ok);
      mtu = lastOk ? `${lastOk.size}` : 'FAIL';
    } else if (r.mtu) {
      mtu = r.mtu.ok ? `${r.mtu.size}` : 'FAIL';
    }
    console.log(
      `${r.proto.padEnd(5)}  ${String(r.port).padEnd(5)}  ${(r.category || '').padEnd(8)}  ${reach}   ${rtt.padStart(6)}  ${loss.padStart(5)}   ${mtu.padEnd(7)}  ${r.purpose}`
    );
  }
  if (report.perPort.some((r) => r.rateLimited)) {
    console.log('');
    console.log('  RL = SDG server rate-limited you. NOT an ISP problem.');
    console.log('  OK* = probes succeeded but the SDG server was also rate-limiting.');
    console.log('  Wait 60 seconds and try again. If RL persists, another device');
    console.log('  on your network or NAT may also be running the test.');
  }
  if (report.a2s) {
    const a = report.a2s;
    console.log('');
    console.log(`Steam A2S on udp ${A2S_PORT}: ${a.ok ? 'OK — server name "' + a.info.name + '"' : 'FAIL (' + a.reason + ')'}`);
  }
  if (report.sustained) {
    const s = report.sustained;
    console.log(`Game-shape 27016: ${s.received}/${s.expected} pkts, loss ${fmt(s.lossPct)}%, max gap ${fmt(s.maxGapMs)}ms${s.exceeded250ms ? '  [THROTTLING SIGNAL]' : ''}`);
  }
  if (report.realServerA2S) {
    const a = report.realServerA2S;
    console.log(`Real server ${a.host}:${a.port}: ${a.ok ? 'OK — "' + a.info.name + '"' : 'FAIL (' + a.reason + ')'}`);
  }
  if (report.natType && !report.natType.skipped) {
    const t = report.natType;
    if (t.ok) {
      console.log('');
      console.log(`NAT type: ${t.verdict.kind} — ${natTypeImpact(t.verdict)}`);
      // Console output redacts the host portion by default for the same
      // reason the JSON does: customers paste this window into support
      // tickets, so the reflected public IP shouldn't leave the machine
      // unless the user opts in via --include-public-ip.
      if (t.reflectionA && t.reflectionA.ok) {
        console.log(`  reflected at ${t.portA}: ${redactIp(t.reflectionA.address, includePublicIp)}:${t.reflectionA.port}`);
      }
      if (t.reflectionB && t.reflectionB.ok) {
        console.log(`  reflected at ${t.portB}: ${redactIp(t.reflectionB.address, includePublicIp)}:${t.reflectionB.port}`);
      }
    }
  }
  if (report.natIdle) {
    console.log('');
    console.log(`NAT idle-timeout: mapping survived up to ${report.natIdle.largestSurvivedSec}s of idle`);
    for (const w of report.natIdle.windows) {
      const portInfo = w.portRotated === true ? '  [PORT ROTATED]'
                     : w.portRotated === false ? '  [port stable]'
                     : '';
      console.log(`  ${String(w.seconds).padStart(4)}s idle: ${w.replied ? 'OK' : 'NO REPLY'}${portInfo}`);
    }
  }
  if (report.burstVsSteady) {
    const b = report.burstVsSteady;
    console.log('');
    console.log(`Burst-vs-steady on udp ${b.port}: ${b.verdict.kind}`);
    console.log(`  burst:  ${b.burst.received}/${b.burst.sent}, loss ${fmt(b.burst.lossPct)}%, observed ${fmt(b.burst.observedPps)} pps`);
    console.log(`  steady: ${b.steady.received}/${b.steady.sent}, loss ${fmt(b.steady.lossPct)}%`);
    console.log(`  ${b.verdict.reason}`);
  }
  if (report.sourcePortFanout) {
    const f = report.sourcePortFanout;
    console.log('');
    console.log(`Source-port fan-out on udp ${f.port}: ${f.verdict.kind}`);
    for (const s of f.perSocket) {
      console.log(`  src ${String(s.sourcePort).padStart(5)}: ${s.received}/${s.sent}, loss ${fmt(s.lossPct)}%`);
    }
    console.log(`  ${f.verdict.reason}`);
  }
  if (report.payloadShape) {
    const p = report.payloadShape;
    console.log('');
    console.log(`Payload-shape sensitivity on udp ${p.port}: ${p.verdict.kind}`);
    for (const [name, r] of Object.entries(p.perPattern)) {
      console.log(`  ${name.padEnd(11)}: ${r.received}/${r.sent}, loss ${fmt(r.lossPct)}%`);
    }
    console.log(`  ${p.verdict.reason}`);
  }
  // Surface burst-loss histograms and reordering counts when the
  // signal is actually meaningful (i.e. there were drops, or there
  // were inversions). Keeps clean runs short.
  const burstSummaries = [];
  for (const r of report.perPort) {
    if (r.loss && r.loss.burstHistogram) {
      const h = r.loss.burstHistogram;
      const totalRuns = h[1] + h['2-4'] + h['5-9'] + h['10+'];
      if (totalRuns > 0) {
        const parts = [];
        if (h[1])     parts.push(`${h[1]}× single`);
        if (h['2-4']) parts.push(`${h['2-4']}× 2-4`);
        if (h['5-9']) parts.push(`${h['5-9']}× 5-9`);
        if (h['10+']) parts.push(`${h['10+']}× 10+`);
        burstSummaries.push(`udp ${r.port}: ${parts.join(', ')}`);
      }
    }
  }
  if (report.sustained && report.sustained.burstHistogram) {
    const h = report.sustained.burstHistogram;
    const totalRuns = h[1] + h['2-4'] + h['5-9'] + h['10+'];
    if (totalRuns > 0) {
      const parts = [];
      if (h[1])     parts.push(`${h[1]}× single`);
      if (h['2-4']) parts.push(`${h['2-4']}× 2-4`);
      if (h['5-9']) parts.push(`${h['5-9']}× 5-9`);
      if (h['10+']) parts.push(`${h['10+']}× 10+`);
      burstSummaries.push(`game-shape: ${parts.join(', ')}`);
    }
  }
  if (burstSummaries.length) {
    console.log('');
    console.log('Loss-burst pattern (consecutive-drop runs):');
    for (const line of burstSummaries) console.log(`  ${line}`);
  }
  // Reordering only matters if it actually happened. SE's
  // interpolation hides loss but stutters on reorder, so even a
  // few inversions are worth flagging.
  const reorderSummaries = [];
  if (report.sustained && report.sustained.reordering && report.sustained.reordering.inversions > 0) {
    const r = report.sustained.reordering;
    reorderSummaries.push(`game-shape: ${r.inversions} inversions (${fmt(r.pct)}% of received)`);
  }
  if (reorderSummaries.length) {
    console.log('');
    console.log('Packet reordering (matters for SE — interpolation stutters):');
    for (const line of reorderSummaries) console.log(`  ${line}`);
  }
  if (report.sustained && !report.sustained.skipped && report.sustained.upSent != null && report.sustained.serverSupported) {
    const s = report.sustained;
    console.log('');
    console.log(`Up-stream: client sent ${s.upSent}, server tallied ${s.upTallied ? s.upTallied.packets : 'n/a'}, loss ${fmt(s.upLossPct)}%`);
  }
  console.log('');
}

// ---- Inconclusive banner ----
//
// Printed by runTests BEFORE the RESULTS table when >50% of attempted
// UDP ports were unreachable. Goes above the table so customers
// pattern-match on the inconclusive header before they see a sea of
// FAILs in the table itself.
function shouldPrintInconclusive(report) {
  const { attempted, unreachable } = udpReachabilityStats(report);
  if (attempted < 3) return false;
  return (unreachable / attempted) > 0.5;
}

function printInconclusiveBanner() {
  console.log('');
  console.log('================================================================');
  console.log('TEST INCONCLUSIVE');
  console.log('================================================================');
  console.log('Most UDP ports failed to respond. This usually means the SDG');
  console.log('test server is unreachable, OR your Internet connection is');
  console.log('severely degraded. Results below are partial — interpret with');
  console.log('caution and consider rerunning the test in 5 minutes.');
  console.log('================================================================');
}

// ---- Recommendations rendering ----
//
// Always renders the section header, even on clean runs (the
// "network-healthy" rule fires as a catch-all). Picks the OS-specific
// command line based on process.platform — the JSON keeps all three
// for cross-platform support workflows.
function platformKeyFor(platform) {
  if (platform === 'win32') return 'windows';
  if (platform === 'darwin') return 'macos';
  return 'linux';
}

function severityTag(sev) {
  if (sev === 'critical') return '[CRITICAL]';
  if (sev === 'warning')  return '[WARNING] ';
  return '[INFO]    ';
}

function printRecommendations(report, { platform = process.platform } = {}) {
  const recs = Array.isArray(report.recommendations) ? report.recommendations : [];
  console.log('');
  console.log('================================================================');
  console.log('RECOMMENDATIONS');
  console.log('================================================================');
  if (recs.length === 0) {
    console.log('[INFO]     Recommendation engine produced no output. (This is a bug.)');
    console.log('');
    return;
  }
  const platKey = platformKeyFor(platform);
  for (const r of recs) {
    console.log('');
    console.log(`${severityTag(r.severity)} ${r.title}`);
    if (r.detail) {
      // Wrap detail to ~78 columns for readability.
      const words = r.detail.split(/\s+/);
      let line = '  ';
      for (const w of words) {
        if (line.length + w.length + 1 > 78) {
          console.log(line);
          line = '  ' + w;
        } else {
          line = line === '  ' ? '  ' + w : line + ' ' + w;
        }
      }
      if (line.trim()) console.log(line);
    }
    if (r.action && r.action.summary) {
      console.log(`  Action: ${r.action.summary}`);
      const cmds = r.action.platformCommands;
      if (cmds && cmds[platKey]) {
        console.log(`  Command (${platKey}): ${cmds[platKey]}`);
      }
    }
  }
  console.log('');
}

// Apply privacy redaction to a report before writing it to disk.
// Both the console output (see printTable) and the JSON file redact
// the host portion of any reflected public IP by default; pass
// --include-public-ip to opt out in both channels at once.
function redactReportForJson(report, includeFull) {
  if (includeFull) return report;
  // Shallow clone everything we touch; the rest can share refs since
  // we're not mutating them.
  const out = { ...report };
  if (out.natType && out.natType.reflectionA && out.natType.reflectionA.ok) {
    out.natType = {
      ...out.natType,
      reflectionA: { ...out.natType.reflectionA, address: redactIp(out.natType.reflectionA.address, false) },
      reflectionB: out.natType.reflectionB && out.natType.reflectionB.ok
        ? { ...out.natType.reflectionB, address: redactIp(out.natType.reflectionB.address, false) }
        : out.natType.reflectionB,
    };
  }
  if (out.natIdle && out.natIdle.windows) {
    // The natIdle test stores reflected ports only, not addresses, so
    // there's nothing to redact here. Left in place as a hook for
    // future additions.
  }
  return out;
}

// ---- Main ----
async function main() {
  const opts = parseArgs(process.argv.slice(2));
  if (opts.help) { printHelp(); process.exit(0); }

  console.log('SDG Connection Test — client');
  console.log('----------------------------');
  console.log(`Target host : ${opts.host}`);
  console.log(`Address fam : ${opts.family === 0 ? 'auto (OS default)' : 'IPv' + opts.family}`);
  console.log(`Ports       : ${opts.ports ? opts.ports.join(',') : 'all (' + PORTS.length + ' from shared/ports.js)'}`);
  console.log(`A2S query   : ${opts.a2s ? 'yes' : 'no'}`);
  console.log(`Sustained   : ${opts.sustained ? Math.round(opts.duration/1000) + 's on udp ' + GAME_SHAPE_PORT + ' (' + opts.bidir + ')' : 'no'}`);
  console.log(`NAT idle    : ${opts.natIdle ? opts.natIdle.join(',') + 's windows' : 'no'}`);
  console.log(`NAT type    : ${opts.natType ? 'yes (requires v2 server)' : 'no'}`);
  console.log(`Burst test  : ${opts.burst ? 'yes (udp ' + BURST_PORT + ')' : 'no'}`);
  console.log(`Source fan-out : ${opts.sourcePortFanout ? `yes (${FANOUT_SOCKET_COUNT} sockets × ${FANOUT_PACKETS_EACH} probes)` : 'no'}`);
  console.log(`Payload shapes : ${opts.payloadShape ? 'yes (3 patterns)' : 'no'}`);
  console.log(`MTU discovery : ${opts.mtuDiscovery !== false ? `yes (descent from 1472)` : 'no'}`);
  console.log(`Real server : ${opts.realServer || '(none)'}`);
  console.log(`JSON output : ${opts.json || '(none — console only)'}`);
  // Wall-clock estimate so the user knows whether to make coffee. Sum
  // of the most expensive components: per-port loss tests, sustained,
  // nat-idle (dominant when present), burst, fan-out, payload-shape.
  // Per-port factor dropped from 6 to 4 when the legacy per-port MTU
  // sweep moved to a single adaptive discovery + parallel spot-check.
  const estSec = (opts.ports ? opts.ports.length : PORTS.length) * 4
               + (opts.mtuDiscovery !== false ? 6 : 0)
               + (opts.sustained ? Math.round(opts.duration / 1000) + 2 : 0)
               + (opts.a2s ? 3 : 0)
               + (opts.natIdle ? opts.natIdle.reduce((a, b) => a + b, 0) + opts.natIdle.length * 1 : 0)
               + (opts.natType ? 3 : 0)
               + (opts.burst ? 15 : 0)
               + (opts.sourcePortFanout ? FANOUT_SOCKET_COUNT * (Math.round(FANOUT_PACKETS_EACH * LOSS_INTERVAL_MS / 1000) + 2) : 0)
               + (opts.payloadShape ? 3 * (Math.round(PAYLOAD_SHAPE_PACKETS_EACH * LOSS_INTERVAL_MS / 1000) + 2) : 0);
  console.log(`Estimated runtime : ~${estSec}s`);
  console.log('');
  console.log('This tool will send test packets to the above host only. It will');
  console.log('not transmit any other information. See ../docs/PROTOCOL.md and');
  console.log('../docs/TRANSPARENCY.md for details.');
  console.log('');

  if (!opts.yes) {
    const ok = await confirm('Proceed? [y/N] ');
    if (!ok) { console.log('Aborted.'); process.exit(0); }
  }
  console.log('');

  const report = await runTests(opts);
  printTable(report, { includePublicIp: opts.includePublicIp });
  report.recommendations = buildRecommendations(report);
  printRecommendations(report, { platform: process.platform });

  if (opts.json) {
    const jsonReport = redactReportForJson(report, opts.includePublicIp);
    await fs.writeFile(opts.json, JSON.stringify(jsonReport, null, 2) + '\n');
    console.log(`Wrote JSON report to ${opts.json}${opts.includePublicIp ? '' : ' (public IPs redacted; pass --include-public-ip to include)'}`);
  }
}

if (require.main === module) {
  main().catch((e) => {
    console.error('Fatal:', e.message);
    process.exit(2);
  });
}

module.exports = {
  parseArgs, stats, filterPorts, fmt, parseHostPort,
  // Phase 1 pure helpers exposed for unit tests.
  classifyNatType, natTypeImpact, interpretBurstVsSteady, redactIp,
  redactReportForJson,
  // Phase 2 pure helpers exposed for unit tests.
  lossBurstHistogram, countReorderings,
  classifyFanout, classifyPayloadShape,
  // Adaptive MTU discovery + recommendation engine helpers.
  decideNextMtuStep, recommendedMtuFor, udpReachabilityStats,
  shouldPrintInconclusive,
  buildRecommendations, RULES,
  ruleTestInconclusive, ruleMtuSevere, ruleMtuCapped, ruleMtuMarginal,
  ruleCgnat464xlat, ruleDpiFingerprint, rulePerFlowShaping,
  ruleNatIdleShort, ruleSymmetricNat, ruleNetworkHealthy,
  // Constants exposed so tests can use the canonical descent ladder
  // without re-declaring it.
  MTU_DESCENT_BYTES, MTU_DESCENT_BYTES_V6, MTU_FALLBACK_PORTS,
  MTU_PROBES_PER_SIZE, MTU_PASS_THRESHOLD,
  MTU_TIEBREAKER_TOTAL, MTU_TIEBREAKER_PASS,
};
