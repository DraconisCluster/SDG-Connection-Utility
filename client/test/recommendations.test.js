'use strict';

// Unit tests for the recommendation engine. Each rule is tested in
// isolation against a synthetic minimal report, then the three real
// fixtures (from the actual customer who motivated this feature) are
// run through buildRecommendations and the produced codes are asserted.

const { test } = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const fs = require('node:fs');
const {
  buildRecommendations,
  recommendedMtuFor,
  udpReachabilityStats,
  shouldPrintInconclusive,
  ruleTestInconclusive,
  ruleMtuSevere,
  ruleMtuCapped,
  ruleMtuMarginal,
  ruleCgnat464xlat,
  ruleDpiFingerprint,
  rulePerFlowShaping,
  ruleNatIdleShort,
  ruleSymmetricNat,
} = require('../client');

const loadFixture = (name) =>
  JSON.parse(fs.readFileSync(path.join(__dirname, 'fixtures', name), 'utf8'));

const codesOf = (recs) => recs.map((r) => r.code);

// ---- recommendedMtuFor ----

test('recommendedMtuFor: ceiling=null → null', () => {
  assert.equal(recommendedMtuFor(null), null);
});

test('recommendedMtuFor: ceiling=1472 → null (no need to lower)', () => {
  assert.equal(recommendedMtuFor(1472), null);
});

test('recommendedMtuFor: warning band (e.g. 1300) → 20-byte margin', () => {
  assert.equal(recommendedMtuFor(1300), 1280);
});

test('recommendedMtuFor: top of warning band (1471) → 1451', () => {
  assert.equal(recommendedMtuFor(1471), 1451);
});

test('recommendedMtuFor: bottom of warning band (1280) → 1280 (floor)', () => {
  // Don't recommend below 1280 from the warning band; that crosses into
  // the severe band's territory.
  assert.equal(recommendedMtuFor(1280), 1280);
});

test('recommendedMtuFor: severe band (e.g. 1100) → recommend ceiling itself', () => {
  assert.equal(recommendedMtuFor(1100), 1100);
});

test('recommendedMtuFor: at IPv4 minimum (576) → 576', () => {
  assert.equal(recommendedMtuFor(576), 576);
});

// ---- udpReachabilityStats ----

test('udpReachabilityStats: counts only UDP rows', () => {
  const report = {
    perPort: [
      { proto: 'udp', reachable: true },
      { proto: 'udp', reachable: false },
      { proto: 'udp', reachable: true },
      { proto: 'tcp', reachable: false },
    ],
  };
  const s = udpReachabilityStats(report);
  assert.equal(s.attempted, 3);
  assert.equal(s.unreachable, 1);
});

test('udpReachabilityStats: missing perPort → zeros', () => {
  const s = udpReachabilityStats({});
  assert.equal(s.attempted, 0);
  assert.equal(s.unreachable, 0);
});

// ---- shouldPrintInconclusive ----

test('shouldPrintInconclusive: 8/10 UDP unreachable → true', () => {
  const perPort = Array.from({ length: 10 }, (_, i) => ({
    proto: 'udp', reachable: i < 2,
  }));
  assert.equal(shouldPrintInconclusive({ perPort }), true);
});

test('shouldPrintInconclusive: 1/10 UDP unreachable → false', () => {
  const perPort = Array.from({ length: 10 }, (_, i) => ({
    proto: 'udp', reachable: i > 0,
  }));
  assert.equal(shouldPrintInconclusive({ perPort }), false);
});

test('shouldPrintInconclusive: small sample → false (not enough data)', () => {
  const perPort = [
    { proto: 'udp', reachable: false },
    { proto: 'udp', reachable: false },
  ];
  assert.equal(shouldPrintInconclusive({ perPort }), false);
});

// ---- ruleTestInconclusive ----

test('ruleTestInconclusive: >50% UDP unreachable fires critical', () => {
  const report = {
    perPort: [
      { proto: 'udp', reachable: false },
      { proto: 'udp', reachable: false },
      { proto: 'udp', reachable: false },
      { proto: 'udp', reachable: true },
    ],
    capabilities: null,
  };
  const r = ruleTestInconclusive(report);
  assert.ok(r);
  assert.equal(r.code, 'test-inconclusive');
  assert.equal(r.severity, 'critical');
});

test('ruleTestInconclusive: capabilities timeout is supporting evidence (different detail copy)', () => {
  const report = {
    perPort: [
      { proto: 'udp', reachable: false },
      { proto: 'udp', reachable: false },
      { proto: 'udp', reachable: false },
      { proto: 'udp', reachable: true },
    ],
    capabilities: { ok: false, reason: 'timeout' },
  };
  const r = ruleTestInconclusive(report);
  assert.ok(r);
  assert.ok(r.detail.includes('capability probe'), 'should mention capability probe when down');
});

test('ruleTestInconclusive: clean network → silent', () => {
  const report = {
    perPort: [
      { proto: 'udp', reachable: true },
      { proto: 'udp', reachable: true },
      { proto: 'udp', reachable: true },
    ],
    capabilities: null,
  };
  assert.equal(ruleTestInconclusive(report), null);
});

// ---- ruleMtuSevere / ruleMtuCapped ----

test('ruleMtuSevere: ceiling < 1280 fires critical', () => {
  const report = { mtuDiscovery: { ok: true, ceiling: 1000, ceilingConfidence: 'high' } };
  const r = ruleMtuSevere(report);
  assert.ok(r);
  assert.equal(r.severity, 'critical');
  assert.equal(r.code, 'mtu-severe');
  assert.ok(r.action.platformCommands.windows.includes('mtu=1000'));
});

test('ruleMtuSevere: ceiling 1280 → not severe (boundary)', () => {
  const report = { mtuDiscovery: { ok: true, ceiling: 1280 } };
  assert.equal(ruleMtuSevere(report), null);
});

test('ruleMtuCapped: ceiling 1300 (carrier signature) fires warning', () => {
  const report = { mtuDiscovery: { ok: true, ceiling: 1300, ceilingConfidence: 'high' } };
  const r = ruleMtuCapped(report);
  assert.ok(r);
  assert.equal(r.severity, 'warning');
  assert.equal(r.code, 'mtu-capped');
  assert.ok(r.action.platformCommands.windows.includes('mtu=1280'));
});

test('ruleMtuCapped: ceiling 1472 (clean) → silent', () => {
  const report = { mtuDiscovery: { ok: true, ceiling: 1472 } };
  assert.equal(ruleMtuCapped(report), null);
});

test('ruleMtuCapped: ceiling 1100 (severe band) → silent (severe rule handles it)', () => {
  const report = { mtuDiscovery: { ok: true, ceiling: 1100 } };
  assert.equal(ruleMtuCapped(report), null);
});

test('ruleMtuCapped: mtuDiscovery skipped → silent', () => {
  const report = { mtuDiscovery: { skipped: true, reason: 'disabled-by-flag' } };
  assert.equal(ruleMtuCapped(report), null);
});

test('ruleMtuMarginal: medium confidence fires warning', () => {
  const report = { mtuDiscovery: { ok: true, ceiling: 1300, ceilingConfidence: 'medium' } };
  const r = ruleMtuMarginal(report);
  assert.ok(r);
  assert.equal(r.code, 'mtu-marginal');
});

test('ruleMtuMarginal: high confidence → silent', () => {
  const report = { mtuDiscovery: { ok: true, ceiling: 1300, ceilingConfidence: 'high' } };
  assert.equal(ruleMtuMarginal(report), null);
});

// ---- ruleCgnat464xlat ----

test('ruleCgnat464xlat: ipv4 + ceiling 1280 fires info', () => {
  const report = { family: 4, mtuDiscovery: { ok: true, ceiling: 1280 } };
  const r = ruleCgnat464xlat(report);
  assert.ok(r);
  assert.equal(r.code, 'cgnat-464xlat');
  assert.equal(r.severity, 'info');
});

test('ruleCgnat464xlat: ipv6 → silent (rule is v4-only)', () => {
  const report = { family: 6, mtuDiscovery: { ok: true, ceiling: 1280 } };
  assert.equal(ruleCgnat464xlat(report), null);
});

test('ruleCgnat464xlat: ipv4 + ceiling 1300 → silent (above 1280)', () => {
  const report = { family: 4, mtuDiscovery: { ok: true, ceiling: 1300 } };
  assert.equal(ruleCgnat464xlat(report), null);
});

// ---- ruleDpiFingerprint ----

test('ruleDpiFingerprint: dpi verdict fires warning', () => {
  const report = {
    payloadShape: { verdict: { kind: 'dpi-fingerprint', reason: 'zero-fill loss 100%' } },
  };
  const r = ruleDpiFingerprint(report);
  assert.ok(r);
  assert.equal(r.code, 'dpi-fingerprint');
  assert.equal(r.severity, 'warning');
});

test('ruleDpiFingerprint: skipped payloadShape → silent', () => {
  const report = { payloadShape: { skipped: true, reason: 'disabled' } };
  assert.equal(ruleDpiFingerprint(report), null);
});

test('ruleDpiFingerprint: clean verdict → silent', () => {
  const report = { payloadShape: { verdict: { kind: 'clean', reason: 'fine' } } };
  assert.equal(ruleDpiFingerprint(report), null);
});

// ---- rulePerFlowShaping ----

test('rulePerFlowShaping: per-flow verdict fires warning', () => {
  const report = {
    sourcePortFanout: { verdict: { kind: 'per-flow', reason: 'loss varies' } },
  };
  const r = rulePerFlowShaping(report);
  assert.ok(r);
  assert.equal(r.code, 'per-flow-shaping');
});

test('rulePerFlowShaping: clean → silent', () => {
  const report = {
    sourcePortFanout: { verdict: { kind: 'clean', reason: 'no shaping' } },
  };
  assert.equal(rulePerFlowShaping(report), null);
});

// ---- ruleNatIdleShort ----

test('ruleNatIdleShort: 30s survived fires warning', () => {
  const report = { natIdle: { largestSurvivedSec: 30 } };
  const r = ruleNatIdleShort(report);
  assert.ok(r);
  assert.equal(r.code, 'nat-idle-short');
});

test('ruleNatIdleShort: 60s survived → silent (boundary)', () => {
  const report = { natIdle: { largestSurvivedSec: 60 } };
  assert.equal(ruleNatIdleShort(report), null);
});

test('ruleNatIdleShort: natIdle skipped → silent', () => {
  const report = { natIdle: { skipped: true } };
  assert.equal(ruleNatIdleShort(report), null);
});

test('ruleNatIdleShort: v1-server (natIdle === null) → silent', () => {
  const report = { natIdle: null };
  assert.equal(ruleNatIdleShort(report), null);
});

// ---- ruleSymmetricNat ----

test('ruleSymmetricNat: symmetric verdict fires info', () => {
  const report = {
    natType: { ok: true, verdict: { kind: 'symmetric', reason: 'port changes' } },
  };
  const r = ruleSymmetricNat(report);
  assert.ok(r);
  assert.equal(r.code, 'symmetric-nat');
  assert.equal(r.severity, 'info');
});

test('ruleSymmetricNat: cone verdict → silent', () => {
  const report = {
    natType: { ok: true, verdict: { kind: 'cone', reason: 'stable' } },
  };
  assert.equal(ruleSymmetricNat(report), null);
});

test('ruleSymmetricNat: natType skipped (v1 server) → silent', () => {
  const report = { natType: { skipped: true, reason: 'server v1' } };
  assert.equal(ruleSymmetricNat(report), null);
});

// ---- buildRecommendations integration ----

test('buildRecommendations: clean report → network-healthy info', () => {
  const codes = codesOf(buildRecommendations({
    family: 4,
    perPort: [{ proto: 'udp', reachable: true }, { proto: 'udp', reachable: true }, { proto: 'udp', reachable: true }],
    mtuDiscovery: { ok: true, ceiling: 1472, ceilingConfidence: 'high' },
    payloadShape: { verdict: { kind: 'clean' } },
    sourcePortFanout: { verdict: { kind: 'clean' } },
    natType: { ok: true, verdict: { kind: 'cone' } },
    natIdle: { largestSurvivedSec: 60 },
  }));
  assert.deepEqual(codes, ['network-healthy']);
});

test('buildRecommendations: ordering — test-inconclusive comes first', () => {
  const codes = codesOf(buildRecommendations({
    family: 4,
    perPort: [
      { proto: 'udp', reachable: false },
      { proto: 'udp', reachable: false },
      { proto: 'udp', reachable: false },
      { proto: 'udp', reachable: true },
    ],
    payloadShape: { verdict: { kind: 'dpi-fingerprint', reason: 'foo' } },
    sourcePortFanout: { verdict: { kind: 'per-flow', reason: 'foo' } },
  }));
  assert.equal(codes[0], 'test-inconclusive', 'critical lead item');
  assert.ok(codes.includes('dpi-fingerprint'));
  assert.ok(codes.includes('per-flow-shaping'));
});

// ---- Real-fixture snapshots ----

test('fixture report-1 (clean MTU-capped 5G ceiling=1300): produces mtu-capped, NOT cgnat-464xlat', () => {
  // The customer's carrier clamps at 1300 (above the 1280 IPv6-minimum
  // threshold), so the 464XLAT-specific rule doesn't fire. mtu-capped
  // is the primary actionable recommendation — that's what carries the
  // netsh command.
  const report = loadFixture('report-1-mtu-capped.json');
  const codes = codesOf(buildRecommendations(report));
  assert.ok(codes.includes('mtu-capped'), `expected mtu-capped in ${JSON.stringify(codes)}`);
  assert.ok(!codes.includes('cgnat-464xlat'), `cgnat-464xlat should fire only at ceiling<=1280; got ${JSON.stringify(codes)}`);
  assert.ok(!codes.includes('network-healthy'), 'network-healthy should not fire when other rules did');
});

test('fixture report-2 (broken with DPI): produces test-inconclusive + dpi + per-flow', () => {
  const report = loadFixture('report-2-broken.json');
  const codes = codesOf(buildRecommendations(report));
  assert.ok(codes.includes('test-inconclusive'), `expected test-inconclusive in ${JSON.stringify(codes)}`);
  assert.ok(codes.includes('dpi-fingerprint'), `expected dpi-fingerprint in ${JSON.stringify(codes)}`);
  assert.ok(codes.includes('per-flow-shaping'), `expected per-flow-shaping in ${JSON.stringify(codes)}`);
  // test-inconclusive must be first (severity ordering for support staff).
  assert.equal(codes[0], 'test-inconclusive');
});

test('fixture report-3 (clean MTU-capped, second run): produces mtu-capped (consistent with report-1)', () => {
  const report = loadFixture('report-3-mtu-capped.json');
  const codes = codesOf(buildRecommendations(report));
  assert.ok(codes.includes('mtu-capped'));
  // Report 3 is the same network as Report 1 — same recommendation set.
  assert.ok(!codes.includes('cgnat-464xlat'));
});

test('synthetic 464XLAT case (ceiling=1280) DOES produce cgnat-464xlat', () => {
  // The cgnat-464xlat rule fires at the specific 464XLAT signature
  // (ipv4 family + ceiling at-or-below the IPv6 minimum MTU of 1280).
  // A separate synthetic fixture exercises this path since the real
  // customer data sits at 1300.
  const codes = codesOf(buildRecommendations({
    family: 4,
    perPort: [{ proto: 'udp', reachable: true }, { proto: 'udp', reachable: true }, { proto: 'udp', reachable: true }],
    mtuDiscovery: { ok: true, ceiling: 1280, ceilingConfidence: 'high' },
    payloadShape: { verdict: { kind: 'clean' } },
    sourcePortFanout: { verdict: { kind: 'clean' } },
  }));
  assert.ok(codes.includes('mtu-capped'));
  assert.ok(codes.includes('cgnat-464xlat'));
});

test('fixture report-1 mtu-capped recommendation includes Windows netsh command', () => {
  const report = loadFixture('report-1-mtu-capped.json');
  const recs = buildRecommendations(report);
  const mtuCapped = recs.find((r) => r.code === 'mtu-capped');
  assert.ok(mtuCapped);
  assert.ok(mtuCapped.action.platformCommands.windows.includes('netsh'));
  assert.ok(mtuCapped.action.platformCommands.windows.includes('mtu=1280'));
  assert.ok(mtuCapped.action.platformCommands.macos.includes('ifconfig'));
  assert.ok(mtuCapped.action.platformCommands.linux.includes('ip link set'));
});
