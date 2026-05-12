// shared/netUtils.js
//
// Tiny, zero-dep IP helpers shared by client and server. Kept here so the
// behavior is identical on both sides and only needs to be audited once.

'use strict';

const net = require('net');

const V4_MAPPED_PREFIX = '::ffff:';

// Normalize an address string for use as a rate-limit key or an ASN-table
// lookup. A dual-stack server bound to `::` receives IPv4 traffic with
// `rinfo.address === '::ffff:1.2.3.4'`. Without normalization, the same
// physical client would get a different per-IP bucket depending on the
// stack the packet arrived on.
//
//   normalizeIp('::ffff:1.2.3.4')  -> '1.2.3.4'
//   normalizeIp('1.2.3.4')         -> '1.2.3.4'
//   normalizeIp('2001:db8::1')     -> '2001:db8::1'
//   normalizeIp(undefined)         -> 'unknown'
function normalizeIp(addr) {
  if (typeof addr !== 'string' || addr.length === 0) return 'unknown';
  // Lowercase the prefix only — IPv6 zone identifiers and digits are
  // case-insensitive but we don't want to lowercase any IPv4 portion.
  const lower = addr.toLowerCase();
  if (lower.startsWith(V4_MAPPED_PREFIX)) {
    const tail = addr.slice(V4_MAPPED_PREFIX.length);
    // Defensive: only strip if what's left is actually a v4 dotted-quad.
    // Some systems emit '::ffff:abcd:1234' for non-v4-mapped v6 addresses;
    // those should NOT be mangled into something resembling a v4 address.
    if (net.isIPv4(tail)) return tail;
  }
  return addr;
}

// Pick the right Node dgram socket type for a given address family.
// Used by the client when a target hostname resolves to either A or AAAA
// records and by the server's bindOverride path in tests.
function dgramTypeFor(family) {
  if (family === 4 || family === '4' || family === 'ipv4') return 'udp4';
  if (family === 6 || family === '6' || family === 'ipv6') return 'udp6';
  throw new Error(`unknown family: ${family}`);
}

// Determine whether a given numeric address is a literal IPv6 address.
// Wrapper over net.isIPv6 so callers can require a single module.
function isIPv6Literal(addr) {
  return typeof addr === 'string' && net.isIPv6(addr);
}

// Determine whether a given numeric address is a literal IPv4 address.
function isIPv4Literal(addr) {
  return typeof addr === 'string' && net.isIPv4(addr);
}

module.exports = { normalizeIp, dgramTypeFor, isIPv4Literal, isIPv6Literal };
