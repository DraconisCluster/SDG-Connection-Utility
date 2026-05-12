# SDG Connection Test — Wire Protocol

This file documents **every byte** the client sends and the server sends back.
If you are a player auditing the client before running it, start here. Then
read [TRANSPARENCY.md](./TRANSPARENCY.md) for hex-dump examples you can verify
in Wireshark.

Two protocols travel over the test ports:

1. The **SDG Connection Test probe protocol** (our own, tiny, binary).
2. The **Steam A2S query protocol** (Valve's public Source query protocol)
   on UDP port 27015 only.

Nothing else is sent or accepted. No hostnames, no usernames, no game files,
no environment variables, no telemetry.

---

## 1. SDG Connection Test probe protocol (SDGT)

All SDG-CT packets share a fixed 36-byte header and an optional zero-padding
tail. Endian: **little-endian** everywhere. All multi-byte fields are unsigned.

```
Offset  Size  Field              Description
------  ----  -----------------  --------------------------------------------
0       4     magic              ASCII 'SDGT'  =  0x53 0x44 0x47 0x54
4       1     version            = 1
5       1     type               1  = probe            (client -> server)
                                 2  = reply            (server -> client)
                                 3  = stream_begin     (client -> server)
                                 4  = stream_stop      (client -> server)
                                 5  = stream_data      (server -> client)
                                 6  = stream_challenge (server -> client, 16-byte token at offset 36)
                                 7  = stream_confirm   (client -> server, echoes challenge token)
                                 8  = rate_limited     (server -> client, always exactly 36 bytes)
                                 9  = reflect_reply    (server -> client, see §4)
                                 10 = stream_data_up   (client -> server, see §5)
                                 11 = stream_tally     (server -> client, see §5)
                                 12 = capabilities     (server -> client, see §6)
6       1     flags              On PROBE (type 1): high bit (0x80) requests
                                 endpoint reflection (§4). Low bits reserved.
                                 On STREAM_BEGIN (type 3): low byte carries
                                 the direction code (0=down, 1=up, 2=both).
                                 v1 servers ignored this byte; treat any
                                 unknown bits as MUST-IGNORE.
7       1     reserved           = 0x00
8       8     session_nonce      8 random bytes generated once per client run.
                                 Printed by the client at startup so the
                                 player can match it against outbound traffic
                                 in Wireshark.
16      4     sequence           Monotonic per (proto, port) test, starting at 0.
20      8     client_ts_ns       Client send timestamp, nanoseconds since
                                 process start (Node process.hrtime.bigint()).
                                 Used by the client to compute RTT when the
                                 reply comes back; the server does not
                                 interpret this value.
28      8     server_ts_ns       Zero on probe.
                                 On reply, the server stamps its own
                                 process.hrtime.bigint() value here purely
                                 as a liveness indicator. Not a wall clock.
36      N     payload / padding  For type 1/2/8 and stream_data: zero padding
                                 (0..~1400 bytes). For type 6/7: a 16-byte
                                 HMAC challenge token. Never contains any
                                 data derived from the host.
```

### RATE_LIMITED (type 8)

Sent by the server when it declines to service a probe. The packet is
exactly HEADER_SIZE bytes (36). The nonce and sequence fields echo the
original probe so the client can match the response to a specific
in-flight test rather than confusing it with ISP packet loss.

### STREAM_CHALLENGE (type 6) and STREAM_CONFIRM (type 7)

Before the server will start a game-shape traffic stream on UDP 27016
it requires a challenge-response handshake:

1. Client sends `STREAM_BEGIN` (type 3, 36 bytes).
2. Server replies with `STREAM_CHALLENGE` (type 6) containing a 16-byte
   opaque token at offset 36. The token's contents and validity window
   are server-internal.
3. Client sends `STREAM_CONFIRM` (type 7) echoing the same 16-byte
   token at offset 36, with the same direction code in flags byte 6.
4. If the token is accepted and the server has capacity, the
   `STREAM_DATA` stream begins.

A client that did not receive step 2 cannot produce a valid step 3,
so the stream is never started for traffic that was not actually
solicited by the source host.

**TCP framing.** TCP is a stream, so a TCP probe frame is prefixed with a
2-byte little-endian length field giving the number of bytes in the SDG-CT
packet that follows. That is the only difference.

**Reply rule.** The server forms a reply by taking the probe packet verbatim,
rewriting `type` from `1` to `2`, writing its own `server_ts_ns`, and
sending it back to the source address. Padding is preserved byte-for-byte.

---

## 2. Game-shape sustained test

Used only on UDP port 27016, only when the client explicitly opts in.

1. Client sends a single `type = 3` (stream_begin) probe to `udp:27016`.
2. Server begins emitting `type = 5` (stream_data) packets to the client's
   source address at approximately 60 packets per second for 10 seconds.
   Each stream_data packet has a random payload length between 200 and 400
   bytes; the payload is zero-padded (no random bytes, so a capture is still
   trivially identifiable).
3. Client counts received packets, computes loss %, inter-arrival jitter,
   and any gap > 250 ms.
4. Server stops automatically after 10 seconds. Client may also send a
   `type = 4` (stream_stop) to end early.

Rate, duration, and payload sizes are all intentionally close to real Space
Engineers gameplay traffic so that any ISP DPI or shaping logic that keys on
"sustained medium-rate UDP flow on 27016" will see roughly the same
fingerprint.

We do **not** implement the real SteamNetworkingSockets handshake. See
[TRANSPARENCY.md](./TRANSPARENCY.md) for why.

---

## 3. Phase 1 diagnostic extensions — overview

Four diagnostic tests added in client v1.1.0 motivated several backwards-
compatible protocol additions. None of them bump the SDGT VERSION byte:
v1 servers reject unknown versions outright, so a bump would silently
break interop. Instead we use TYPE values 9..12 plus repurposed reserved
bits, all of which old servers ignore by construction.

The four tests and what they need from the server are:

| Test                      | Server change?                          | Ref |
| ------------------------- | --------------------------------------- | --- |
| NAT idle-timeout probe    | None — uses ordinary PROBE/REPLY        | §4  |
| Endpoint reflection       | Yes — server echoes observed src IP/port| §4  |
| Bidirectional sustained   | Yes — server counts up-stream and tallies| §5 |
| Burst-vs-steady policer   | None — uses ordinary PROBE/REPLY        | -   |

Capability negotiation (§6) lets a new client detect a v1 server before
running tests 2 or 3, and degrade to a structured "skipped" result rather
than misinterpret a non-response.

---

## 4. Endpoint reflection (REFLECT_REPLY, type 9)

To classify the customer's NAT (cone vs symmetric) the client needs to
know what source IP and port the server actually observed on its
incoming probe. The client opts into this by setting bit 0x80 of the
flags byte (offset 6) on a normal PROBE (type 1). A server that
implements reflection responds with a REFLECT_REPLY (type 9) instead
of REPLY (type 2). A v1 server ignores the bit and emits the usual
REPLY — the client interprets the absence of REFLECT_REPLY as "server
does not support reflection".

### REFLECT_REPLY payload

```
Offset  Size  Field
36      1     af               1 = IPv4, 2 = IPv6
37      1     reserved         must be 0
38      2     port             u16 LE — observed source port
40      4     ipv4             network order; zero-filled if af=2
44      16    ipv6             network order; zero-filled if af=1
60..    pad   zero padding to match the inbound probe size
```

### Reply sizing

A REFLECT_REPLY is no larger than the probe that elicited it. The
client pads its reflection-requesting PROBE to at least 60 bytes; the
server pads (or truncates) the REFLECT_REPLY to the same size.

If a client requests reflection in a probe smaller than 60 bytes, the
server responds with RATE_LIMITED (36 bytes) rather than a truncated
reflection payload.

### NAT-type classification

The client sends two reflection-requesting probes from the **same**
source socket to **two different** destination ports (e.g. 27016 and
27017) and compares the reflected ports:

- Equal reflected ports → endpoint-independent mapping (cone NAT).
- Different reflected ports → address- or port-dependent mapping
  (symmetric NAT). Symmetric NAT defeats most peer-to-peer NAT
  traversal and forces relay (Steam Datagram Relay).
- Over IPv6 there is typically no NAT; reflected port == source port
  trivially. Reported as "no NAT (IPv6)" rather than "cone".

Reflected source IPs may legitimately differ even on the same socket
when the carrier rotates CGNAT egress IPs (T-Mobile 5G Home does
this). The classifier only compares ports.

### NAT idle-timeout probe (no protocol change)

The client opens a single UDP socket, sends a reflection-requesting
probe, then for each window in {30 s, 60 s, 120 s, 300 s}:

1. Idles the socket for the window.
2. Sends three confirmation probes spaced 100 ms apart (so a single
   isolated drop doesn't blacklist the window).
3. Records whether any reply came back.

If reflection is supported, the client also compares the reflected
port before vs after the idle: a port change indicates the carrier
NAT mapping was evicted and recreated rather than preserved. This
lets the test distinguish "mapping survived" from "mapping was
recreated with a fresh egress port" even though the data path
appeared to work in both cases.

---

## 5. Bidirectional sustained (STREAM_DATA_UP, STREAM_TALLY)

The legacy sustained test (§2) emits server-to-client traffic only.
That measures the customer's downlink path. Phase 1 adds an opt-in
upstream (and combined) variant to measure the uplink path
independently — T-Mobile 5G Home's uplink is a separately-configured
device with its own shaping behavior.

### Direction signaling

The client encodes the requested direction in byte 6 of STREAM_BEGIN:

| Value | Meaning |
| ----- | ------- |
| 0     | Down (legacy — server->client only). v1 server behavior. |
| 1     | Up — client sends STREAM_DATA_UP packets, server tallies. |
| 2     | Both — server emits STREAM_DATA AND client emits STREAM_DATA_UP. |

A v1 server ignores byte 6 and runs a downstream. A v2-aware client
detects this mismatch by the absence of STREAM_TALLY at the end of
the test, marks the result `serverSupported: false`, and reports the
test as skipped.

### Up-stream protocol

After the existing STREAM_CHALLENGE / STREAM_CONFIRM handshake (§1)
completes for an up-stream or combined stream:

1. Client emits STREAM_DATA_UP (type 10) packets at the requested
   rate (default 60 pps, capped at 200) for the requested duration
   (default 10 s, capped at 300 s). Sequence numbers are monotonic
   from 0; payload sizes are random in [200, 400] to mimic the
   downstream shape and exercise the uplink shaper symmetrically.

2. Client sends STREAM_STOP (type 4) when done.

3. Server emits STREAM_TALLY (type 11) **three times** with sequence
   numbers 0, 1, 2 in quick succession. Three copies because a single
   tally lost on the return path would blind the client to the
   server's count entirely; with three, any one arriving is enough.

### STREAM_TALLY payload

```
Offset  Size  Field
36      8     packets_received  u64 LE
44      4     first_seq         u32 LE  (lowest seq the server saw)
48      4     last_seq          u32 LE  (highest seq the server saw)
52      8     bytes_received    u64 LE  (split lo/hi across two u32s)
60      4     gaps_gt_250ms     u32 LE
64..    pad   zero
```

### Server-side behavior

The server enforces appropriate caps on up-stream concurrency,
duration, and total bytes per stream. Specific values and the token
construction are server-internal. The client treats absence of
STREAM_TALLY at end of test as "v1 server" and reports the test as
skipped.

---

## 6. Capability negotiation (CAPABILITIES, type 12)

Before running any reflection-dependent or bidirectional test, the
client probes the server for feature support on UDP 27443 (the
existing baseline port). The probe is an ordinary PROBE (type 1) with
sequence = 0xCAFEBABE — a magic value chosen because it is well
outside any sequence range a real test would use.

- A v1 server treats the probe as a normal PROBE and replies with
  REPLY (type 2) echoing the magic sequence back. The client
  interprets this as "no Phase 1 features".
- A v2-aware server recognizes the magic sequence and replies with
  CAPABILITIES (type 12) carrying a 32-bit feature bitmap at offset
  36.

### CAPABILITIES payload

```
Offset  Size  Field
36      4     feature_bitmap   u32 LE
                                 bit 0 (0x01) = REFLECTION
                                 bit 1 (0x02) = BIDIRECTIONAL
                                 bit 2 (0x04) = NAT_IDLE_AWARE  (informational)
                                 bits 3..31    reserved (must be ignored)
40..    pad   zero
```

The CAPABILITIES packet is no larger than the inbound probe that
elicited it (same sizing rule as REFLECT_REPLY).

### Forward compatibility

Future protocol additions add bits to `feature_bitmap`. Clients MUST
ignore bits they do not understand. Servers MUST NOT remove bits;
features only ever get added.

---

## 7. Steam A2S query (UDP 27015 only)

This is the public Source Engine query protocol documented by Valve at
<https://developer.valvesoftware.com/wiki/Server_queries>. We implement
`A2S_INFO` with Valve's December 2020 challenge requirement.

**Step 1 — Request** (client -> server, 25 bytes):

```
FF FF FF FF 54 "Source Engine Query\0"
```

**Step 2 — Challenge reply** (server -> client, 9 bytes):

```
FF FF FF FF 41 <u32 challenge>
```

The 4-byte challenge is server-internal state; the client echoes it
verbatim in the next request.

**Step 3 — Request with challenge** (client -> server, 29 bytes):

```
FF FF FF FF 54 "Source Engine Query\0" <u32 challenge>
```

**Step 4 — Info reply** (server -> client, ~120 bytes): a packed
binary reply beginning with the four-byte header `FF FF FF FF 49`,
followed by protocol version, server name, map, folder, game, Steam
AppID, player counts, bot count, server type, environment, visibility,
VAC, version, and extra data flags. Only sent after a valid challenge
is received. Our test server returns fabricated but well-formed
values:

| Field         | Value                  |
| ------------- | ---------------------- |
| name          | `SDG Connection Test`  |
| map           | `diagnostic`           |
| folder        | `sdg`                  |
| game          | `SDG Connection Test`  |
| app id        | 0                      |
| players       | 0                      |
| max players   | 32                     |
| bots          | 0                      |
| server type   | `d` (dedicated)        |
| environment   | `l` (Linux)            |
| visibility    | 0 (public)             |
| VAC           | 0 (insecure)           |
| version       | `1.0.0`                |

A real Steam master server browser will list the test server with the name
"SDG Connection Test". This is intentional: it confirms the UDP path from the
Steam backbone to the test server is clean.

---

## What is NOT in any packet

The following are **never** sent by the client, under any circumstance:

- The player's username, computer name, or OS user.
- Environment variables.
- File paths, directory listings, or file contents.
- Any field derived from the Steam install.
- Any network interface names or MAC addresses.
- Any information about other processes running on the machine.
- Any string representation of the target host beyond the single `--host`
  argument the player typed on the command line (and that only goes inside
  outbound DNS / TCP / UDP headers, never inside a payload).

You can confirm all of this with:

```
wireshark -i <your NIC> -f "host <test-server>"
```

and cross-checking every byte of every outbound packet against the layout
above.
