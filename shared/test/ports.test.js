'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { PORTS, GAME_SHAPE_PORT, A2S_PORT } = require('../ports');

const VALID_PROTOS = new Set(['tcp', 'udp']);
const VALID_CATEGORIES = new Set(['critical', 'game', 'steam', 'baseline']);

test('PORTS is a non-empty frozen array', () => {
  assert.ok(Array.isArray(PORTS));
  assert.ok(PORTS.length >= 13, `expected 13+ ports, got ${PORTS.length}`);
  assert.ok(Object.isFrozen(PORTS), 'PORTS must be frozen so it cannot be mutated at runtime');
});

test('every entry has the expected shape and types', () => {
  for (const p of PORTS) {
    assert.ok(VALID_PROTOS.has(p.proto), `bad proto: ${p.proto}`);
    assert.equal(typeof p.port, 'number');
    assert.ok(Number.isInteger(p.port));
    assert.ok(p.port > 0 && p.port <= 65535, `port out of range: ${p.port}`);
    assert.ok(VALID_CATEGORIES.has(p.category), `bad category: ${p.category}`);
    assert.equal(typeof p.purpose, 'string');
    assert.ok(p.purpose.length > 0, 'purpose cannot be empty');
  }
});

test('no duplicate (proto, port) pairs', () => {
  const seen = new Set();
  for (const p of PORTS) {
    const key = `${p.proto}/${p.port}`;
    assert.ok(!seen.has(key), `duplicate (proto, port) pair: ${key}`);
    seen.add(key);
  }
});

test('critical ports include the customer-failure trio (UDP 27015, 27016, 8766)', () => {
  const critical = PORTS.filter(p => p.category === 'critical').map(p => `${p.proto}/${p.port}`);
  for (const required of ['udp/27015', 'udp/27016', 'udp/8766']) {
    assert.ok(critical.includes(required), `critical category missing ${required}`);
  }
});

test('GAME_SHAPE_PORT is a UDP port that exists in the table', () => {
  assert.equal(typeof GAME_SHAPE_PORT, 'number');
  assert.ok(PORTS.some(p => p.proto === 'udp' && p.port === GAME_SHAPE_PORT),
    `GAME_SHAPE_PORT ${GAME_SHAPE_PORT} must appear as a udp entry in PORTS`);
});

test('A2S_PORT is a UDP port that exists in the table', () => {
  assert.equal(typeof A2S_PORT, 'number');
  assert.ok(PORTS.some(p => p.proto === 'udp' && p.port === A2S_PORT),
    `A2S_PORT ${A2S_PORT} must appear as a udp entry in PORTS`);
});

test('baseline category exists (otherwise we cannot rule out generic LAN failure)', () => {
  const baseline = PORTS.filter(p => p.category === 'baseline');
  assert.ok(baseline.length >= 2, 'need at least two baseline ports for control comparison');
  const protos = new Set(baseline.map(p => p.proto));
  assert.ok(protos.has('tcp') && protos.has('udp'),
    'baseline must include both TCP and UDP for cross-proto control');
});

test('individual entries are deep-frozen (immutable port matrix)', () => {
  for (const p of PORTS) {
    assert.ok(Object.isFrozen(p), `entry ${p.proto}/${p.port} is mutable`);
    assert.throws(() => { p.port = 0; }, /read only|Cannot assign/i,
      `entry ${p.proto}/${p.port} accepted a write to .port`);
  }
});

test('ports avoid privileged range so unprivileged container can bind', () => {
  for (const p of PORTS) {
    assert.ok(p.port >= 1024,
      `port ${p.proto}/${p.port} is privileged; container drops CAP_NET_BIND_SERVICE`);
  }
});
