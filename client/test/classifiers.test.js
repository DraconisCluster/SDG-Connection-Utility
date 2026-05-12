'use strict';

// Unit tests for the pure-function classifiers added in Phase 1. These
// run with no sockets; the actual measurement code calls them with the
// shape of input that the real wire produces.

const { test } = require('node:test');
const assert = require('node:assert/strict');
const {
  classifyNatType, natTypeImpact, interpretBurstVsSteady,
  redactIp, redactReportForJson,
} = require('../client');

// ---- classifyNatType --------------------------------------------------

const refV4 = (port, addr = '203.0.113.5') => ({ ok: true, family: 4, address: addr, port });
const refV6 = (port, addr = '2001:db8::1') => ({ ok: true, family: 6, address: addr, port });
const noRef = () => ({ ok: false, reason: 'no-reflection' });

test('classifyNatType: equal v4 ports → cone NAT', () => {
  const v = classifyNatType(refV4(45678), refV4(45678));
  assert.equal(v.kind, 'cone');
});

test('classifyNatType: different v4 ports → symmetric NAT', () => {
  const v = classifyNatType(refV4(45678), refV4(45679));
  assert.equal(v.kind, 'symmetric');
});

test('classifyNatType: equal v4 ports with rotated v4 IPs (CGNAT egress rotation) is still cone', () => {
  // T-Mobile 5G Home rotates egress IPs across a /20. Two probes
  // seconds apart can come back with different reflected addresses
  // even on a stable port. Only port matters for cone vs symmetric.
  const v = classifyNatType(
    refV4(45678, '172.58.4.10'),
    refV4(45678, '172.58.4.42'),
  );
  assert.equal(v.kind, 'cone', 'changing reflected IP must not be misread as symmetric NAT');
});

test('classifyNatType: any IPv6 reflection → no-nat', () => {
  // IPv6 paths are typically NAT-free. Reporting "cone" would be
  // technically true and operationally misleading.
  assert.equal(classifyNatType(refV6(443), refV6(443)).kind, 'no-nat');
  assert.equal(classifyNatType(refV6(443), refV4(45678)).kind, 'no-nat',
    'one-side v6 still avoids the NAT verdict');
});

test('classifyNatType: missing reflection → unknown (probably v1 server)', () => {
  assert.equal(classifyNatType(noRef(), refV4(1)).kind, 'unknown');
  assert.equal(classifyNatType(refV4(1), noRef()).kind, 'unknown');
  assert.equal(classifyNatType(null, null).kind, 'unknown');
});

test('natTypeImpact: every verdict has a customer-friendly string', () => {
  for (const kind of ['cone', 'symmetric', 'no-nat', 'unknown', 'something-else']) {
    const s = natTypeImpact({ kind });
    assert.equal(typeof s, 'string');
    assert.ok(s.length > 0);
  }
});

// ---- interpretBurstVsSteady ------------------------------------------

const burst = (lossPct, rateLimitedPct = 0) => ({ lossPct, rateLimitedPct });
const steady = burst;

test('interpretBurstVsSteady: high burst loss + low steady loss → policer', () => {
  const v = interpretBurstVsSteady({ burst: burst(40), steady: steady(1) });
  assert.equal(v.kind, 'policer');
});

test('interpretBurstVsSteady: low loss in both → clean', () => {
  const v = interpretBurstVsSteady({ burst: burst(0.5), steady: steady(0) });
  assert.equal(v.kind, 'clean');
});

test('interpretBurstVsSteady: similar moderate loss → random-loss', () => {
  const v = interpretBurstVsSteady({ burst: burst(8), steady: steady(7) });
  assert.equal(v.kind, 'random-loss');
});

test('interpretBurstVsSteady: high loss in both → shaper', () => {
  const v = interpretBurstVsSteady({ burst: burst(25), steady: steady(20) });
  assert.equal(v.kind, 'shaper');
});

test('interpretBurstVsSteady: rate-limited burst → inconclusive (NEVER policer)', () => {
  // Critical: the SDG server's own rate limiter must never be reported
  // as an ISP policer. If RL > 5%, bail out.
  const v = interpretBurstVsSteady({ burst: burst(40, 30), steady: steady(1) });
  assert.equal(v.kind, 'inconclusive-server-rl');
});

test('interpretBurstVsSteady: rate-limited replies are subtracted from loss', () => {
  // Raw burst loss 5%, of which 4% was the SDG server's own RL. The
  // adjusted figure is 1% — below the 2% "clean" threshold, so the
  // verdict should be clean rather than the policer signature it
  // would have looked like without subtraction.
  const v = interpretBurstVsSteady({ burst: burst(5, 4), steady: steady(0) });
  // 4% RL is below the 5% bail-out, so we use the adjusted figure.
  assert.equal(v.kind, 'clean', `expected clean after RL adjustment, got ${v.kind}: ${v.reason}`);
});

test('interpretBurstVsSteady: missing input → incomplete', () => {
  assert.equal(interpretBurstVsSteady({ burst: null, steady: steady(0) }).kind, 'incomplete');
  assert.equal(interpretBurstVsSteady({}).kind, 'incomplete');
});

// ---- redactIp ---------------------------------------------------------

test('redactIp: v4 with includeFull=false → last octet stripped', () => {
  assert.equal(redactIp('1.2.3.4', false), '1.2.3.x');
});

test('redactIp: v4 with includeFull=true → unchanged', () => {
  assert.equal(redactIp('1.2.3.4', true), '1.2.3.4');
});

test('redactIp: v4-mapped v6 normalized then redacted as v4', () => {
  assert.equal(redactIp('::ffff:1.2.3.4', false), '1.2.3.x');
});

test('redactIp: v6 → keep first hextet pair, redact the rest', () => {
  const r = redactIp('2001:db8::1', false);
  assert.ok(r.startsWith('2001:db8'), `expected first 32 bits preserved, got ${r}`);
  assert.ok(r.includes('redacted'));
});

test('redactIp: null/empty input passes through', () => {
  assert.equal(redactIp(null, false), null);
  assert.equal(redactIp('', false), '');
});

// ---- redactReportForJson ---------------------------------------------

test('redactReportForJson: redacts natType reflections by default', () => {
  const report = {
    natType: {
      ok: true,
      reflectionA: { ok: true, family: 4, address: '1.2.3.4', port: 1234 },
      reflectionB: { ok: true, family: 4, address: '1.2.3.4', port: 5678 },
      verdict: { kind: 'symmetric', reason: 'x' },
    },
  };
  const r = redactReportForJson(report, false);
  assert.equal(r.natType.reflectionA.address, '1.2.3.x');
  assert.equal(r.natType.reflectionB.address, '1.2.3.x');
  // Ports not redacted — they're per-test ephemeral and don't identify
  // the user.
  assert.equal(r.natType.reflectionA.port, 1234);
  assert.equal(r.natType.reflectionB.port, 5678);
});

test('redactReportForJson: includeFull=true preserves IPs verbatim', () => {
  const report = {
    natType: {
      ok: true,
      reflectionA: { ok: true, family: 4, address: '1.2.3.4', port: 1234 },
      reflectionB: { ok: true, family: 4, address: '1.2.3.4', port: 5678 },
    },
  };
  const r = redactReportForJson(report, true);
  assert.equal(r.natType.reflectionA.address, '1.2.3.4');
});

test('redactReportForJson: tolerates missing or skipped natType', () => {
  // Default-flag run produces no natType; redaction must be a no-op.
  const r1 = redactReportForJson({}, false);
  assert.deepEqual(r1, {});
  const r2 = redactReportForJson({ natType: { skipped: true } }, false);
  assert.deepEqual(r2.natType, { skipped: true });
});
