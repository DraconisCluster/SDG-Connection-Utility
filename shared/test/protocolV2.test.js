'use strict';

// Phase 1 protocol additions — round-trips for new TYPE values, payload
// helpers, and the version-1 backwards-compat invariants. Exists as a
// separate file so a future protocol bump (v3+) can leave the v1/v2
// table here untouched while extending only the new file.

const { test } = require('node:test');
const assert = require('node:assert/strict');
const protocol = require('../protocol');

const NONCE = Buffer.from('aabbccddeeff0011', 'hex');

// ---- New TYPE values --------------------------------------------------

test('TYPE block includes Phase 1 additions with stable numeric values', () => {
  // Numeric values are wire-locked — never reorder or renumber. Each
  // assertion is a guard against an accidental renumbering.
  assert.equal(protocol.TYPE.REFLECT_REPLY,   9);
  assert.equal(protocol.TYPE.STREAM_DATA_UP, 10);
  assert.equal(protocol.TYPE.STREAM_TALLY,   11);
  assert.equal(protocol.TYPE.CAPABILITIES,   12);
});

test('encode round-trips for each new TYPE', () => {
  for (const t of [protocol.TYPE.REFLECT_REPLY, protocol.TYPE.STREAM_DATA_UP,
                   protocol.TYPE.STREAM_TALLY, protocol.TYPE.CAPABILITIES]) {
    const buf = protocol.encode({ type: t, nonce: NONCE, sequence: 7, totalSize: 64 });
    const dec = protocol.decode(buf);
    assert.ok(dec, `decode failed for type ${t}`);
    assert.equal(dec.type, t);
    assert.equal(dec.sequence, 7);
    assert.equal(dec.totalSize, 64);
  }
});

// ---- Flags byte -------------------------------------------------------

test('encode writes the flags byte at offset 6', () => {
  const buf = protocol.encode({
    type: protocol.TYPE.PROBE,
    nonce: NONCE,
    sequence: 0,
    flags: protocol.FLAG_REFLECT,
  });
  assert.equal(buf[6], protocol.FLAG_REFLECT);
});

test('decode surfaces the flags byte', () => {
  const buf = protocol.encode({
    type: protocol.TYPE.STREAM_BEGIN,
    nonce: NONCE,
    sequence: 0,
    flags: protocol.DIRECTION_BOTH,
  });
  const dec = protocol.decode(buf);
  assert.equal(dec.flags, protocol.DIRECTION_BOTH);
});

test('encode rejects out-of-range flags', () => {
  assert.throws(() => protocol.encode({
    type: protocol.TYPE.PROBE, nonce: NONCE, sequence: 0, flags: 256,
  }), /flags/);
  assert.throws(() => protocol.encode({
    type: protocol.TYPE.PROBE, nonce: NONCE, sequence: 0, flags: -1,
  }), /flags/);
});

test('default flags is zero (matches v1 wire bytes byte-for-byte)', () => {
  // v1 servers don't read byte 6 anyway, but if the flags byte is
  // accidentally non-zero on a default-encoded probe, every test in
  // every existing v1 deployment changes its wire footprint. Pin it.
  const buf = protocol.encode({ type: protocol.TYPE.PROBE, nonce: NONCE, sequence: 0 });
  assert.equal(buf[6], 0);
  assert.equal(buf[7], 0);
});

// ---- DIRECTION constants ----------------------------------------------

test('DIRECTION_DOWN is zero — v1 server default behavior', () => {
  // The whole compatibility story for the bidirectional test rests on
  // STREAM_BEGIN with byte 6 = 0 producing identical bytes to a v1
  // STREAM_BEGIN. Pin DIRECTION_DOWN = 0.
  assert.equal(protocol.DIRECTION_DOWN, 0);
});

// ---- decodeReflectedEndpoint -----------------------------------------

test('decodeReflectedEndpoint parses an IPv4 reflection', () => {
  const buf = Buffer.alloc(60);
  // Header bytes don't matter for this helper — it only reads the
  // payload slice.
  buf[protocol.REFLECT_OFFSET]     = protocol.REFLECT_AF_IPV4;
  buf.writeUInt16LE(45678, protocol.REFLECT_OFFSET + 2);
  buf[protocol.REFLECT_OFFSET + 4] = 192;
  buf[protocol.REFLECT_OFFSET + 5] = 168;
  buf[protocol.REFLECT_OFFSET + 6] =   1;
  buf[protocol.REFLECT_OFFSET + 7] = 100;
  const r = protocol.decodeReflectedEndpoint(buf);
  assert.equal(r.ok, true);
  assert.equal(r.family, 4);
  assert.equal(r.address, '192.168.1.100');
  assert.equal(r.port, 45678);
});

test('decodeReflectedEndpoint parses an IPv6 reflection', () => {
  const buf = Buffer.alloc(60);
  buf[protocol.REFLECT_OFFSET] = protocol.REFLECT_AF_IPV6;
  buf.writeUInt16LE(443, protocol.REFLECT_OFFSET + 2);
  // 2001:db8::1 in network order
  buf.writeUInt16BE(0x2001, protocol.REFLECT_OFFSET + 8);
  buf.writeUInt16BE(0x0db8, protocol.REFLECT_OFFSET + 10);
  buf.writeUInt16BE(0x0001, protocol.REFLECT_OFFSET + 22);
  const r = protocol.decodeReflectedEndpoint(buf);
  assert.equal(r.ok, true);
  assert.equal(r.family, 6);
  assert.equal(r.port, 443);
  // Address may be in any canonical-equivalent form; accept either
  // expanded or compressed.
  assert.ok(r.address.includes('2001'), `expected 2001 in ${r.address}`);
});

test('decodeReflectedEndpoint returns no-reflection on a v1-server zero-padded reply', () => {
  // A v1 server, ignorant of FLAG_REFLECT, replies with a zero-padded
  // payload. The helper must NOT fabricate "0.0.0.0:0" — it must
  // return ok:false so the client can downgrade to "server doesn't
  // support reflection".
  const buf = Buffer.alloc(60);   // all zeros after the header
  const r = protocol.decodeReflectedEndpoint(buf);
  assert.equal(r.ok, false);
  assert.equal(r.reason, 'no-reflection');
});

test('decodeReflectedEndpoint returns too-short for short buffers', () => {
  const r = protocol.decodeReflectedEndpoint(Buffer.alloc(40));
  assert.equal(r.ok, false);
  assert.equal(r.reason, 'too-short');
});

test('decodeReflectedEndpoint returns no-reflection for unknown af byte', () => {
  const buf = Buffer.alloc(60);
  buf[protocol.REFLECT_OFFSET] = 99;   // not 1, not 2
  const r = protocol.decodeReflectedEndpoint(buf);
  assert.equal(r.ok, false);
  assert.equal(r.reason, 'no-reflection');
});

// ---- decodeStreamTally ------------------------------------------------

test('decodeStreamTally parses a fully-populated tally', () => {
  const buf = Buffer.alloc(protocol.TALLY_OFFSET + protocol.TALLY_SIZE);
  buf.writeBigUInt64LE(600n, protocol.TALLY_OFFSET);
  buf.writeUInt32LE(0,        protocol.TALLY_OFFSET + 8);
  buf.writeUInt32LE(599,      protocol.TALLY_OFFSET + 12);
  buf.writeUInt32LE(150_000,  protocol.TALLY_OFFSET + 16);  // bytes lo
  buf.writeUInt32LE(0,        protocol.TALLY_OFFSET + 20);  // bytes hi
  buf.writeUInt32LE(2,        protocol.TALLY_OFFSET + 24);  // gaps
  const t = protocol.decodeStreamTally(buf);
  assert.equal(t.packets, 600);
  assert.equal(t.firstSeq, 0);
  assert.equal(t.lastSeq, 599);
  assert.equal(t.bytes, 150_000);
  assert.equal(t.gapsGt250ms, 2);
});

test('decodeStreamTally returns null on too-short buffer', () => {
  assert.equal(protocol.decodeStreamTally(Buffer.alloc(40)), null);
  assert.equal(protocol.decodeStreamTally(null), null);
});

// ---- decodeCapabilities -----------------------------------------------

test('decodeCapabilities surfaces individual feature bits', () => {
  const buf = Buffer.alloc(protocol.CAPABILITIES_OFFSET + 4);
  buf.writeUInt32LE(
    protocol.CAP_REFLECTION | protocol.CAP_BIDIRECTIONAL,
    protocol.CAPABILITIES_OFFSET,
  );
  const c = protocol.decodeCapabilities(buf);
  assert.equal(c.reflection, true);
  assert.equal(c.bidirectional, true);
  assert.equal(c.natIdleAware, false);
});

test('decodeCapabilities ignores unknown bits (forward-compat)', () => {
  const buf = Buffer.alloc(protocol.CAPABILITIES_OFFSET + 4);
  buf.writeUInt32LE(0xff_ff_ff_00, protocol.CAPABILITIES_OFFSET);  // weird high bits set
  const c = protocol.decodeCapabilities(buf);
  // The known bits are all in the low byte (0..2). High bits don't
  // surface as boolean fields and don't crash the decoder.
  assert.equal(c.reflection, false);
  assert.equal(c.bidirectional, false);
  assert.equal(c.natIdleAware, false);
  assert.equal(typeof c.raw, 'number');
});

// ---- CAPABILITY_MAGIC_SEQ ---------------------------------------------

test('CAPABILITY_MAGIC_SEQ is an unsigned 32-bit', () => {
  assert.equal(typeof protocol.CAPABILITY_MAGIC_SEQ, 'number');
  assert.ok(protocol.CAPABILITY_MAGIC_SEQ >= 0);
  assert.ok(protocol.CAPABILITY_MAGIC_SEQ <= 0xffffffff);
  // The value is wire-locked once shipped.
  assert.equal(protocol.CAPABILITY_MAGIC_SEQ, 0xCAFEBABE >>> 0);
});

// ---- v1 backwards compatibility ---------------------------------------

test('decode still rejects mismatched VERSION (no silent v1->v2 bump)', () => {
  // We deliberately did NOT bump VERSION for Phase 1. Confirm an old
  // v1 packet decodes; a v2-version packet would not.
  const buf = protocol.encode({ type: protocol.TYPE.PROBE, nonce: NONCE, sequence: 0 });
  assert.equal(protocol.decode(buf).type, protocol.TYPE.PROBE);
  buf[4] = 2;
  assert.equal(protocol.decode(buf), null, 'v2-version probe must not decode under v1');
});
