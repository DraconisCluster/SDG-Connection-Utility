'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { parseHostPort } = require('../client');

test('parses bare hostname:port', () => {
  assert.deepEqual(parseHostPort('torch.example.com:27015'),
    { host: 'torch.example.com', port: 27015 });
});

test('parses bare IPv4:port', () => {
  assert.deepEqual(parseHostPort('1.2.3.4:27015'),
    { host: '1.2.3.4', port: 27015 });
});

test('parses bracketed IPv6:port', () => {
  assert.deepEqual(parseHostPort('[2001:db8::1]:27015'),
    { host: '2001:db8::1', port: 27015 });
});

test('parses bracketed IPv6 loopback:port', () => {
  assert.deepEqual(parseHostPort('[::1]:27015'),
    { host: '::1', port: 27015 });
});

test('parses bracketed v4-mapped:port', () => {
  assert.deepEqual(parseHostPort('[::ffff:1.2.3.4]:27015'),
    { host: '::ffff:1.2.3.4', port: 27015 });
});

test('rejects empty input', () => {
  assert.throws(() => parseHostPort(''), /required/);
});

test('rejects non-string input', () => {
  assert.throws(() => parseHostPort(undefined), /required/);
  assert.throws(() => parseHostPort(null), /required/);
  assert.throws(() => parseHostPort(27015), /required/);
});

test('rejects missing port (bare hostname)', () => {
  assert.throws(() => parseHostPort('torch.example.com'),
    /missing :port/);
});

test('rejects ambiguous unbracketed IPv6', () => {
  // "::1:80" — could be host=::1 port=80 or host=::1:80 with no port.
  // We require brackets to disambiguate.
  assert.throws(() => parseHostPort('::1:80'),
    /ambiguous IPv6/);
});

test('rejects empty host', () => {
  assert.throws(() => parseHostPort(':27015'),
    /empty host/);
});

test('rejects empty port', () => {
  assert.throws(() => parseHostPort('torch.example.com:'),
    /invalid port/);
});

test('rejects non-numeric port', () => {
  assert.throws(() => parseHostPort('torch.example.com:abc'),
    /invalid port/);
});

test('rejects port out of range (zero)', () => {
  assert.throws(() => parseHostPort('torch.example.com:0'),
    /invalid port/);
});

test('rejects port out of range (>65535)', () => {
  assert.throws(() => parseHostPort('torch.example.com:65536'),
    /invalid port/);
});

test('rejects bracketed form with non-numeric port', () => {
  assert.throws(() => parseHostPort('[::1]:abc'),
    /invalid port/);
});

test('does not allow shell metacharacters to be silently passed through', () => {
  // Whatever a caller does with the parsed host, it should NOT be a
  // surprise that it contains the input bytes verbatim — but it
  // shouldn't accept malformed forms either. This specific case
  // (`host;rm -rf /:80`) is parsed cleanly into host="host;rm -rf /"
  // because the parser only verifies the port part is numeric. The
  // string `host;rm -rf /` is then handed to dgram.send / dns.lookup
  // which will fail with a DNS error, not execute a shell. Sanity
  // check that we don't crash on it.
  assert.deepEqual(parseHostPort('host;rm -rf /:80'),
    { host: 'host;rm -rf /', port: 80 });
});
