// shared/protocol.js
//
// Binary encoder/decoder for the SDG Connection Test probe protocol.
// Every byte layout here matches docs/PROTOCOL.md exactly. If you are
// auditing the tool, read this file alongside that doc.
//
// Zero dependencies. Used by both the client and the server so there is one
// place to verify.

'use strict';

const net = require('net');

const MAGIC = Buffer.from('SDGT', 'ascii');          // 0x53 0x44 0x47 0x54
const VERSION = 1;
const HEADER_SIZE = 36;

const TYPE = Object.freeze({
  PROBE:            1,  // client -> server
  REPLY:            2,  // server -> client
  STREAM_BEGIN:     3,  // client -> server
  STREAM_STOP:      4,  // client -> server
  STREAM_DATA:      5,  // server -> client
  STREAM_CHALLENGE: 6,  // server -> client (16-byte opaque token in payload)
  STREAM_CONFIRM:   7,  // client -> server (echoes token from CHALLENGE)
  RATE_LIMITED:     8,  // server -> client, always 36 bytes
  // Phase 1 additions. All are backwards compatible: a v1 server that does
  // not implement them will simply not emit the new server->client types,
  // and will ignore the new client->server type. Capability negotiation
  // (see capabilityProbe in client.js) tells the client which features
  // are supported before any of the new tests run.
  REFLECT_REPLY:    9,  // server -> client (echoes observed src endpoint)
  STREAM_DATA_UP:  10,  // client -> server (bidirectional sustained test)
  STREAM_TALLY:    11,  // server -> client (end-of-stream tally; sent 3x)
  CAPABILITIES:    12,  // server -> client (feature bitmap reply)
});

// Offset at which the 16-byte stream challenge token lives in
// STREAM_CHALLENGE and STREAM_CONFIRM packets — the start of the payload
// area, immediately after the fixed 36-byte header.
const TOKEN_OFFSET = 36;
const TOKEN_SIZE = 16;

// Flags byte (offset 6 of the 36-byte header). Older code documented this
// as "reserved = 0x00 0x00"; v1 servers do not validate it. The client
// uses byte 6 for two purposes:
//
//   * On PROBE (type 1): the high bit (FLAG_REFLECT) opts the probe into
//     endpoint reflection. A v2-aware server replies with REFLECT_REPLY
//     (type 9) instead of plain REPLY (type 2). v1 servers ignore the bit
//     and reply normally — the absence of REFLECT_REPLY is what tells the
//     client the server is too old.
//
//   * On STREAM_BEGIN (type 3): the low byte carries the direction request
//     (DIRECTION_DOWN / _UP / _BOTH).
//
// Byte 7 is currently unused — kept reserved for future protocol growth so
// we don't paint ourselves into a corner.
const FLAG_REFLECT = 0x80;

// Direction codes carried in STREAM_BEGIN byte 6. Default 0 = legacy
// downstream-only (same behavior the v1 server has always implemented),
// so a current client that doesn't pass --bidir keeps producing the same
// wire bytes it did before.
const DIRECTION_DOWN = 0;
const DIRECTION_UP   = 1;
const DIRECTION_BOTH = 2;

// Magic sequence value used by the capability probe. Old servers see this
// as a normal PROBE with a peculiar sequence and echo it (REPLY); new
// servers recognize the magic and respond with CAPABILITIES (type 12)
// carrying a feature bitmap at offset 36.
const CAPABILITY_MAGIC_SEQ = 0xCAFEBABE >>> 0;

// Capability bits returned in the CAPABILITIES feature bitmap (32-bit LE
// at payload offset 36 of the CAPABILITIES packet).
const CAP_REFLECTION       = 1 << 0;
const CAP_BIDIRECTIONAL    = 1 << 1;
const CAP_NAT_IDLE_AWARE   = 1 << 2;  // informational; client doesn't gate

// REFLECT_REPLY payload layout, at offset 36. Total 24 bytes; the reply
// itself is padded to match the inbound probe size.
//
//   36..36   af          1 = IPv4, 2 = IPv6
//   37..37   reserved    must be 0
//   38..39   port        u16 LE   (the source port the server observed)
//   40..43   ipv4        4 bytes  (network order; zero-filled if af=2)
//   44..59   ipv6        16 bytes (network order; zero-filled if af=1)
const REFLECT_OFFSET    = 36;
const REFLECT_SIZE      = 24;
const REFLECT_AF_IPV4   = 1;
const REFLECT_AF_IPV6   = 2;

// STREAM_TALLY payload at offset 36. Total 28 bytes. The server sends
// this packet THREE times (sequence 0, 1, 2) at the end of a UP/BOTH
// stream so a single drop on the return path doesn't blind the client.
//
//   36..43   packets_received  u64 LE
//   44..47   first_seq         u32 LE
//   48..51   last_seq          u32 LE
//   52..55   bytes_received_lo u32 LE  (low half of u64; high half below)
//   56..59   bytes_received_hi u32 LE
//   60..63   gaps_gt_250ms     u32 LE
const TALLY_OFFSET = 36;
const TALLY_SIZE   = 28;

// CAPABILITIES payload at offset 36. Total 4 bytes (extensible — clients
// must ignore unknown bits).
const CAPABILITIES_OFFSET = 36;
const CAPABILITIES_SIZE   = 4;

// Build a packet with the given fields and an optional total payload size
// in bytes (must be >= HEADER_SIZE). The area from offset 36 to totalSize
// is zero-padded.
//
// `flags` (default 0) writes byte 6. Existing call sites that don't pass
// it produce identical bytes to the v1-only encode (byte 6 = 0).
function encode({
  type,
  nonce,
  sequence,
  clientTsNs = 0n,
  serverTsNs = 0n,
  totalSize = HEADER_SIZE,
  flags = 0,
}) {
  if (!Buffer.isBuffer(nonce) || nonce.length !== 8) {
    throw new Error('nonce must be an 8-byte Buffer');
  }
  if (totalSize < HEADER_SIZE) {
    throw new Error(`totalSize must be >= ${HEADER_SIZE}`);
  }
  if (typeof flags !== 'number' || flags < 0 || flags > 0xff) {
    throw new Error('flags must be a byte value (0..255)');
  }
  const buf = Buffer.alloc(totalSize);                   // zero-filled
  MAGIC.copy(buf, 0);
  buf[4] = VERSION;
  buf[5] = type;
  buf[6] = flags;
  // byte 7 stays reserved-zero
  nonce.copy(buf, 8);
  buf.writeUInt32LE(sequence >>> 0, 16);
  buf.writeBigUInt64LE(BigInt(clientTsNs), 20);
  buf.writeBigUInt64LE(BigInt(serverTsNs), 28);
  // bytes 36..totalSize are zero padding (already zero from Buffer.alloc)
  return buf;
}

// Parse a buffer. Returns an object or null if the buffer is not a valid
// SDGT packet. Never throws.
function decode(buf) {
  if (!Buffer.isBuffer(buf) || buf.length < HEADER_SIZE) return null;
  if (buf[0] !== MAGIC[0] || buf[1] !== MAGIC[1] ||
      buf[2] !== MAGIC[2] || buf[3] !== MAGIC[3]) return null;
  if (buf[4] !== VERSION) return null;
  return {
    type:        buf[5],
    flags:       buf[6],
    nonce:       buf.subarray(8, 16),
    sequence:    buf.readUInt32LE(16),
    clientTsNs:  buf.readBigUInt64LE(20),
    serverTsNs:  buf.readBigUInt64LE(28),
    totalSize:   buf.length,
  };
}

// Quick check used by the server's handler chain before we pay the decode
// cost: does this look like a SDGT packet at all?
function looksLikeSdgt(buf) {
  return Buffer.isBuffer(buf) && buf.length >= HEADER_SIZE &&
         buf[0] === MAGIC[0] && buf[1] === MAGIC[1] &&
         buf[2] === MAGIC[2] && buf[3] === MAGIC[3];
}

// Decode the REFLECT_REPLY payload that begins at offset 36. Returns
//   { ok: true, family: 4|6, address: 'a.b.c.d' | '::1', port: <u16> }
// on success, or { ok: false, reason } if the bytes don't look like a
// real reflection (e.g. a v1 server padded the reply with zeros — we
// detect that via the af-byte sentinel).
function decodeReflectedEndpoint(buf) {
  if (!Buffer.isBuffer(buf)) return { ok: false, reason: 'not-a-buffer' };
  if (buf.length < REFLECT_OFFSET + REFLECT_SIZE) {
    return { ok: false, reason: 'too-short' };
  }
  const af = buf[REFLECT_OFFSET];
  if (af !== REFLECT_AF_IPV4 && af !== REFLECT_AF_IPV6) {
    return { ok: false, reason: 'no-reflection' };
  }
  const port = buf.readUInt16LE(REFLECT_OFFSET + 2);
  if (af === REFLECT_AF_IPV4) {
    const a = buf[REFLECT_OFFSET + 4];
    const b = buf[REFLECT_OFFSET + 5];
    const c = buf[REFLECT_OFFSET + 6];
    const d = buf[REFLECT_OFFSET + 7];
    return { ok: true, family: 4, address: `${a}.${b}.${c}.${d}`, port };
  }
  // IPv6: 16 bytes at offset REFLECT_OFFSET+8 in network order.
  const v6 = buf.subarray(REFLECT_OFFSET + 8, REFLECT_OFFSET + 24);
  const groups = [];
  for (let i = 0; i < 16; i += 2) {
    groups.push(v6.readUInt16BE(i).toString(16));
  }
  // Use Node's net.isIPv6 to validate via a canonical-format round-trip;
  // we still emit the colon-joined form so the caller has a consistent
  // string representation regardless of whether the v6 was zero-rich.
  const addr = groups.join(':');
  if (!net.isIPv6(addr)) {
    return { ok: false, reason: 'bad-ipv6' };
  }
  return { ok: true, family: 6, address: addr, port };
}

// Decode a STREAM_TALLY payload. Returns null if the buffer is too short
// or shaped wrong (the caller already verified type and nonce).
function decodeStreamTally(buf) {
  if (!Buffer.isBuffer(buf)) return null;
  if (buf.length < TALLY_OFFSET + TALLY_SIZE) return null;
  const packets = buf.readBigUInt64LE(TALLY_OFFSET);
  const firstSeq = buf.readUInt32LE(TALLY_OFFSET + 8);
  const lastSeq  = buf.readUInt32LE(TALLY_OFFSET + 12);
  const bytesLo  = buf.readUInt32LE(TALLY_OFFSET + 16);
  const bytesHi  = buf.readUInt32LE(TALLY_OFFSET + 20);
  const gapsGt250 = buf.readUInt32LE(TALLY_OFFSET + 24);
  // Reassemble the 64-bit byte count. JS Number is fine up to 2^53; this
  // test will never produce more than ~1e8 bytes total (200 pps cap × 400
  // bytes × 300 s) so we can flatten to Number for the report.
  const bytes = Number(BigInt(bytesHi) * (1n << 32n) + BigInt(bytesLo));
  return {
    packets: Number(packets),
    firstSeq,
    lastSeq,
    bytes,
    gapsGt250ms: gapsGt250,
  };
}

// Decode the CAPABILITIES payload (single 32-bit feature bitmap).
function decodeCapabilities(buf) {
  if (!Buffer.isBuffer(buf)) return null;
  if (buf.length < CAPABILITIES_OFFSET + CAPABILITIES_SIZE) return null;
  const bits = buf.readUInt32LE(CAPABILITIES_OFFSET);
  return {
    raw: bits,
    reflection:    (bits & CAP_REFLECTION)     !== 0,
    bidirectional: (bits & CAP_BIDIRECTIONAL)  !== 0,
    natIdleAware:  (bits & CAP_NAT_IDLE_AWARE) !== 0,
  };
}

module.exports = {
  MAGIC, VERSION, HEADER_SIZE, TYPE,
  TOKEN_OFFSET, TOKEN_SIZE,
  FLAG_REFLECT,
  DIRECTION_DOWN, DIRECTION_UP, DIRECTION_BOTH,
  CAPABILITY_MAGIC_SEQ,
  CAP_REFLECTION, CAP_BIDIRECTIONAL, CAP_NAT_IDLE_AWARE,
  REFLECT_OFFSET, REFLECT_SIZE, REFLECT_AF_IPV4, REFLECT_AF_IPV6,
  TALLY_OFFSET, TALLY_SIZE,
  CAPABILITIES_OFFSET, CAPABILITIES_SIZE,
  encode, decode, looksLikeSdgt,
  decodeReflectedEndpoint, decodeStreamTally, decodeCapabilities,
};
