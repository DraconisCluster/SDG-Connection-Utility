# SDG Connection Test — Transparency Notes for Paranoid Players

If you are reading this because you do not want to run a random tool from
the internet on your machine, thank you. You are doing the right thing.
This document tries to answer, concretely and verifiably, every reasonable
question a security-conscious player might have about the client.

## The short version

The client is a single JavaScript file, around 2,200 lines, that uses
only Node.js built-in modules. It sends two kinds of packet: a small
binary probe of our own design, and the standard public Steam
A2S_INFO query. Every byte is documented in
[PROTOCOL.md](./PROTOCOL.md). It never reads files from your machine,
never reads environment variables, and never makes a network request
to anything except the `--host` (and optional `--real-server`) you
pass on the command line. The source is intended to be skimmable in
about twenty minutes by anyone with basic JavaScript literacy.

## What you should verify for yourself

Trust is earned. Here is how to earn it.

### 1. Inspect the code

The complete client is in [`../client/client.js`](../client/client.js),
plus three tiny helpers in [`../shared/ports.js`](../shared/ports.js),
[`../shared/protocol.js`](../shared/protocol.js), and
[`../shared/netUtils.js`](../shared/netUtils.js). Together they are
roughly 2,600 lines of commented JavaScript.

Things to search for:

- `require(` — lists every module loaded. You should see only
  `net`, `dgram`, `dns/promises`, `crypto`, `fs/promises`, `readline`,
  `perf_hooks`, and the three sibling files in `../shared/`. Nothing else.
- `fs.` — every file access. In the client, `fs.writeFile` is used only
  when you pass `--json <file>` and writes only to that file.
- `process.env` — not used at all in the client.
- `child_process`, `eval`, `Function(`, `vm.`, `http`, `https`, `fetch`,
  `import(` — none of these appear. Try grepping for them.
- `net.Socket`, `net.createConnection`, `dgram.createSocket` — these are
  the only outbound network calls. Every one of them writes to
  `resolved` (the IP you passed on `--host`) except the optional
  `--real-server` test.

### 2. Watch the packets

Run the client with Wireshark capturing on your active NIC. The client
prints a 16-character hex session nonce at startup. Every outbound packet
has those same 8 bytes at offset 8, so you can filter your capture with:

```
frame contains <nonce-as-hex>
```

Every packet in the filtered list will match one of the layouts in
[PROTOCOL.md](./PROTOCOL.md). There will be no packets to any host other
than the one you passed on `--host` (and `--real-server`, if you used it).

### 3. Unplug your network

With no network interface available, the client will fail every test and
exit cleanly. There is no offline "fallback" behavior, no local database
read, no cached anything. It is strictly a network diagnostic.

### 4. Run it in a sandbox

The tool is entirely happy to run in:

- a Windows Sandbox (`WindowsSandbox` feature)
- a throwaway VM
- a Docker container with `node:20-alpine`

If you do not want to install Node.js on your main machine, any of the
above will work.

## Why we do NOT emulate the real Space Engineers gameplay protocol

You might reasonably ask: if you are trying to diagnose SE connectivity,
why not just speak the real SE protocol?

The real Space Engineers gameplay protocol on UDP 27016 is
**SteamNetworkingSockets** (Valve's encrypted, handshaked, Steam-relay-aware
transport). Speaking it honestly would require either:

- Valve's closed-source Steamworks SDK with a real App ID, or
- the open-source `GameNetworkingSockets` C++ library as a native
  dependency.

Either option would add a large, hard-to-audit native binary to the
client. That would completely defeat the purpose of shipping a small,
readable, zero-dependency tool. So we deliberately don't.

Instead, we:

1. Prove **L3/L4 reachability** on every port SE and Steam use, with
   detailed loss, jitter, and MTU measurements.
2. Do a **real Steam A2S_INFO** query on UDP 27015 (this is the same
   query the Steam server browser uses, and Torch answers it natively).
3. Send a **game-shape sustained stream** on UDP 27016 from the test
   server to the client at the same packet rate and size distribution as
   real SE gameplay. This does not reproduce the encrypted handshake, but
   it does give any ISP DPI the same traffic fingerprint to trip on.
4. Run six targeted diagnostics that catch the carrier failure modes
   the L3/L4 sweep misses. Each is opt-out and fully documented
   byte-by-byte in [PROTOCOL.md](./PROTOCOL.md):
   - **NAT idle-timeout probe** — holds one socket open and probes
     after 30 s and 60 s of idle (or up to 300 s with `--full`). The
     reflected source port is compared before and after each idle
     window to detect carrier NAT mapping eviction even when the
     data path appears to recover. Covers the most common T-Mobile
     5G Home failure mode.
   - **Endpoint reflection / NAT type** — sends two probes from one
     socket to two destinations and compares the source port the
     server reports observing. Same port → cone NAT (peer-to-peer
     works). Different port → symmetric NAT (peer-to-peer needs a
     relay). Reflected public IP is **redacted by default** in both
     the console output and any `--json` report, because the README
     invites support sharing of reports and support flows commonly
     involve pasting the console transcript into a ticket; pass
     `--include-public-ip` to include it.
   - **Bidirectional sustained stream** — the legacy sustained test
     was downstream-only. The bidirectional variant adds a
     client-emits-server-tallies upstream phase so uplink-only
     throttling (T-Mobile's uplink path is a separately-shaped
     device) becomes visible. The server replies with a single
     small tally packet (sent three times for loss tolerance).
   - **Burst-vs-steady policer test** — 100 packets as fast as the
     OS will let us, then 100 packets at 10 pps. Comparing the loss
     rates fingerprints policer (token-bucket: burst lossy, steady
     fine), shaper (loss at both rates), or random loss.
   - **Source-port fan-out** — repeats a small loss test from four
     different ephemeral source ports against the same destination.
     Diverging loss rates across source ports indicate per-5-tuple
     discrimination (an unlucky ECMP hash bucket on a carrier
     router, or a per-flow shaper) rather than a path-wide problem.
   - **Payload-shape sensitivity** — sends three short loss tests
     on UDP 27016 with three different payload contents
     (game-shape, random bytes, zero-filled). If the path passes
     one shape but drops another, a DPI device is making decisions
     based on payload content. The patterns themselves contain no
     information about your machine — they are zero-padding,
     crypto-random bytes, or zero-filled.

   Two additional metrics are derived from the data the existing
   loss tests already collect, with no extra packets sent:

   - **Loss-burst histogram** — runs of consecutive lost packets
     bucketed as 1, 2-4, 5-9, 10+. The shape of this histogram
     fingerprints loss type (isolated drops vs policer cycles vs
     sustained outages).
   - **Packet reordering count** — out-of-order arrivals matter for
     SE because the game's interpolation can survive packet loss
     but stutters on reorder; a high reorder rate with low loss is
     a real complaint pattern that "loss %" alone wouldn't surface.

5. Optionally (`--real-server`) send a real A2S_INFO directly to your
   actual Torch/SE server for a true end-to-end comparison.

If all L3/L4 tests pass on ISP A and fail on ISP B, and the A2S query
behaves the same way, then ISP B is the problem regardless of whether we
ever completed a real SteamNetworkingSockets handshake.

### What the new diagnostics do NOT do

- They do not learn anything new about your machine. The only
  piece of new data Phase 1 introduces in the JSON report is the
  source IP and port the **server** observed for your probes —
  i.e. your public-internet-facing endpoint, which every router
  on the path already sees. The host portion is redacted by
  default. Phase 2 adds nothing your machine doesn't already
  know about itself.
- They do not change the wire-protocol VERSION byte. A
  Phase 1+2 client speaking to a v1.0.0 server gracefully
  degrades: each server-dependent test reports `SKIPPED
  (server too old)` rather than producing a fabricated answer.
  The Phase 2 tests are entirely client-side and require no
  server support at all.
- They do not communicate with anything other than `--host`.
  The privacy boundary is unchanged from v1.0.0.

## Anything we missed?

If you find something in the client code that looks wrong, misleading,
or nefarious, please tell us. The whole point of this tool is
transparency, and a tool that cannot be audited honestly is worse than no
tool at all.

The server source is operator-internal — what the server is permitted to
do is bounded by the protocol in [PROTOCOL.md](./PROTOCOL.md). Nothing
the server sends back can affect your machine beyond the response
packets to probes the client itself sent. The client is the only side
of this conversation running in your environment, and that is the side
we encourage you to audit.
