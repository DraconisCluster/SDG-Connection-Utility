'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { normalizeIp, dgramTypeFor, isIPv4Literal, isIPv6Literal } = require('../netUtils');

test('normalizeIp: v4-mapped IPv6 collapses to plain IPv4', () => {
  assert.equal(normalizeIp('::ffff:1.2.3.4'), '1.2.3.4');
  assert.equal(normalizeIp('::FFFF:8.8.8.8'), '8.8.8.8');
});

test('normalizeIp: plain IPv4 passes through unchanged', () => {
  assert.equal(normalizeIp('1.2.3.4'), '1.2.3.4');
  assert.equal(normalizeIp('192.168.0.1'), '192.168.0.1');
});

test('normalizeIp: real IPv6 passes through unchanged', () => {
  assert.equal(normalizeIp('2001:db8::1'), '2001:db8::1');
  assert.equal(normalizeIp('fe80::1'), 'fe80::1');
  assert.equal(normalizeIp('::1'), '::1');
});

test('normalizeIp: ::ffff: prefix on a non-v4-tail is left alone', () => {
  // Real IPv6 addresses can legitimately start with ::ffff: when the tail
  // is not a dotted-quad; we must NOT mangle those.
  assert.equal(normalizeIp('::ffff:abcd:1234'), '::ffff:abcd:1234');
});

test('normalizeIp: invalid / falsy inputs return "unknown"', () => {
  assert.equal(normalizeIp(undefined), 'unknown');
  assert.equal(normalizeIp(null), 'unknown');
  assert.equal(normalizeIp(''), 'unknown');
  assert.equal(normalizeIp(12345), 'unknown');
});

test('dgramTypeFor accepts numeric and string family forms', () => {
  for (const v of [4, '4', 'ipv4']) assert.equal(dgramTypeFor(v), 'udp4');
  for (const v of [6, '6', 'ipv6']) assert.equal(dgramTypeFor(v), 'udp6');
});

test('dgramTypeFor throws on unknown family', () => {
  assert.throws(() => dgramTypeFor('foo'));
  assert.throws(() => dgramTypeFor(0));
  assert.throws(() => dgramTypeFor(undefined));
});

test('isIPv4Literal / isIPv6Literal recognize literal numeric forms', () => {
  assert.equal(isIPv4Literal('1.2.3.4'), true);
  assert.equal(isIPv4Literal('256.0.0.1'), false);
  assert.equal(isIPv4Literal('example.com'), false);
  assert.equal(isIPv6Literal('::1'), true);
  assert.equal(isIPv6Literal('2001:db8::1'), true);
  assert.equal(isIPv6Literal('1.2.3.4'), false);
  assert.equal(isIPv4Literal(null), false);
  assert.equal(isIPv6Literal(null), false);
});
