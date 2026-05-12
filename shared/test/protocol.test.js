'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const protocol = require('../protocol');

const NONCE = Buffer.from('0011223344556677', 'hex');

test('encode produces a HEADER_SIZE buffer by default', () => {
  const buf = protocol.encode({ type: protocol.TYPE.PROBE, nonce: NONCE, sequence: 1 });
  assert.equal(buf.length, protocol.HEADER_SIZE);
});

test('encode lays out fields per docs/PROTOCOL.md', () => {
  const buf = protocol.encode({
    type: protocol.TYPE.PROBE,
    nonce: NONCE,
    sequence: 0xdeadbeef,
    clientTsNs: 1n,
    serverTsNs: 2n,
  });
  assert.equal(buf.toString('ascii', 0, 4), 'SDGT', 'magic');
  assert.equal(buf[4], protocol.VERSION, 'version byte');
  assert.equal(buf[5], protocol.TYPE.PROBE, 'type byte');
  assert.equal(buf[6], 0, 'reserved byte 6');
  assert.equal(buf[7], 0, 'reserved byte 7');
  assert.deepEqual(buf.subarray(8, 16), NONCE, 'nonce at offset 8');
  assert.equal(buf.readUInt32LE(16), 0xdeadbeef >>> 0, 'sequence LE at offset 16');
  assert.equal(buf.readBigUInt64LE(20), 1n, 'clientTsNs LE at offset 20');
  assert.equal(buf.readBigUInt64LE(28), 2n, 'serverTsNs LE at offset 28');
});

test('encode pads payload area to totalSize with zeros', () => {
  const buf = protocol.encode({
    type: protocol.TYPE.PROBE,
    nonce: NONCE,
    sequence: 0,
    totalSize: 100,
  });
  assert.equal(buf.length, 100);
  for (let i = protocol.HEADER_SIZE; i < buf.length; i++) {
    assert.equal(buf[i], 0, `payload byte ${i} must be zero-padded`);
  }
});

test('encode rejects non-Buffer or wrong-length nonce', () => {
  assert.throws(
    () => protocol.encode({ type: protocol.TYPE.PROBE, nonce: 'not a buffer', sequence: 0 }),
    /nonce must be an 8-byte Buffer/,
  );
  assert.throws(
    () => protocol.encode({ type: protocol.TYPE.PROBE, nonce: Buffer.alloc(7), sequence: 0 }),
    /nonce must be an 8-byte Buffer/,
  );
  assert.throws(
    () => protocol.encode({ type: protocol.TYPE.PROBE, nonce: Buffer.alloc(9), sequence: 0 }),
    /nonce must be an 8-byte Buffer/,
  );
});

test('encode rejects totalSize smaller than HEADER_SIZE', () => {
  assert.throws(
    () => protocol.encode({
      type: protocol.TYPE.PROBE,
      nonce: NONCE,
      sequence: 0,
      totalSize: protocol.HEADER_SIZE - 1,
    }),
    /totalSize must be >= 36/,
  );
});

test('encode handles sequence wraparound (32-bit unsigned)', () => {
  const buf = protocol.encode({
    type: protocol.TYPE.PROBE,
    nonce: NONCE,
    sequence: -1,
  });
  assert.equal(buf.readUInt32LE(16), 0xffffffff);
});

test('decode round-trips encode for every TYPE value', () => {
  for (const [name, type] of Object.entries(protocol.TYPE)) {
    const encoded = protocol.encode({
      type,
      nonce: NONCE,
      sequence: 42,
      clientTsNs: 1234n,
      serverTsNs: 5678n,
      totalSize: 64,
    });
    const decoded = protocol.decode(encoded);
    assert.ok(decoded, `decode failed for type ${name}`);
    assert.equal(decoded.type, type);
    assert.deepEqual(decoded.nonce, NONCE);
    assert.equal(decoded.sequence, 42);
    assert.equal(decoded.clientTsNs, 1234n);
    assert.equal(decoded.serverTsNs, 5678n);
    assert.equal(decoded.totalSize, 64);
  }
});

test('decode returns null for non-Buffer input', () => {
  assert.equal(protocol.decode(null), null);
  assert.equal(protocol.decode('not a buffer'), null);
  assert.equal(protocol.decode([1, 2, 3]), null);
});

test('decode returns null for buffer shorter than HEADER_SIZE', () => {
  assert.equal(protocol.decode(Buffer.alloc(0)), null);
  assert.equal(protocol.decode(Buffer.alloc(protocol.HEADER_SIZE - 1)), null);
});

test('decode returns null for wrong magic', () => {
  const buf = protocol.encode({ type: protocol.TYPE.PROBE, nonce: NONCE, sequence: 0 });
  buf[0] = 0xff;
  assert.equal(protocol.decode(buf), null);
});

test('decode returns null for wrong version', () => {
  const buf = protocol.encode({ type: protocol.TYPE.PROBE, nonce: NONCE, sequence: 0 });
  buf[4] = 99;
  assert.equal(protocol.decode(buf), null);
});

test('decode never throws on random garbage', () => {
  for (let i = 0; i < 100; i++) {
    const garbage = Buffer.alloc(40);
    for (let j = 0; j < garbage.length; j++) garbage[j] = (Math.random() * 256) | 0;
    assert.doesNotThrow(() => protocol.decode(garbage));
  }
});

test('looksLikeSdgt: true for valid header start', () => {
  const buf = protocol.encode({ type: protocol.TYPE.PROBE, nonce: NONCE, sequence: 0 });
  assert.equal(protocol.looksLikeSdgt(buf), true);
});

test('looksLikeSdgt: false for short or wrong-magic buffers', () => {
  assert.equal(protocol.looksLikeSdgt(Buffer.alloc(35)), false, 'too short');
  const wrongMagic = Buffer.alloc(36);
  wrongMagic.write('XXXX', 0, 4, 'ascii');
  assert.equal(protocol.looksLikeSdgt(wrongMagic), false, 'wrong magic');
  assert.equal(protocol.looksLikeSdgt(null), false, 'null');
  assert.equal(protocol.looksLikeSdgt('SDGT'), false, 'string, not buffer');
});

test('TOKEN_OFFSET and TOKEN_SIZE describe the 16-byte payload window for stream tokens', () => {
  assert.equal(protocol.TOKEN_OFFSET, protocol.HEADER_SIZE,
    'TOKEN_OFFSET should equal HEADER_SIZE — token sits immediately after fixed header');
  assert.equal(protocol.TOKEN_SIZE, 16, 'TOKEN_SIZE is 16 bytes per protocol spec');
});
