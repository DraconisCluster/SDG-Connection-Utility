'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { parseArgs } = require('../client');

// Suppress the client's "Unknown argument" stderr noise during tests where
// we deliberately exercise the error path.
const origErr = console.error;
function mute(fn) {
  return function (...args) {
    console.error = () => {};
    try { return fn(...args); } finally { console.error = origErr; }
  };
}

test('defaults: no flags → host=SDG public IP, sustained=true, a2s=true, family=auto', () => {
  const o = parseArgs([]);
  // The customer-facing default is SDG's public connection-test endpoint
  // so an unzip-and-run experience needs no flags. Override with --host
  // is still tested below.
  assert.equal(o.host, '38.107.232.39');
  assert.equal(o.sustained, true);
  assert.equal(o.a2s, true);
  assert.equal(o.realServer, null);
  assert.equal(o.json, null);
  assert.equal(o.yes, false);
  assert.equal(o.family, 0, 'family 0 = OS auto by default');
  assert.equal(o.duration, 10_000, 'default sustained test duration is 10s');
  assert.equal(o.help, false);
});

test('--host captures the next argv', () => {
  const o = parseArgs(['--host', 'test.example.com']);
  assert.equal(o.host, 'test.example.com');
});

test('--ports parses comma-separated list with whitespace tolerance', () => {
  const o = parseArgs(['--ports', '27015, 27016 , 27017']);
  assert.deepEqual(o.ports, ['27015', '27016', '27017']);
});

test('--no-sustained / --no-a2s flip booleans', () => {
  const o = parseArgs(['--no-sustained', '--no-a2s']);
  assert.equal(o.sustained, false);
  assert.equal(o.a2s, false);
});

test('--real-server captures the host:port string verbatim', () => {
  const o = parseArgs(['--real-server', 'torch.example.com:27015']);
  assert.equal(o.realServer, 'torch.example.com:27015');
});

test('--json captures the file path', () => {
  const o = parseArgs(['--json', 'report.json']);
  assert.equal(o.json, 'report.json');
});

test('--yes and -y both set yes=true', () => {
  assert.equal(parseArgs(['--yes']).yes, true);
  assert.equal(parseArgs(['-y']).yes, true);
});

test('--help and -h both set help=true', () => {
  assert.equal(parseArgs(['--help']).help, true);
  assert.equal(parseArgs(['-h']).help, true);
});

test('--duration converts seconds to milliseconds', () => {
  assert.equal(parseArgs(['--duration', '5']).duration, 5000);
  assert.equal(parseArgs(['--duration', '0.5']).duration, 500);
});

test('--family 4 / 6 / auto / ipv4 / ipv6 / 0 are all accepted', () => {
  assert.equal(parseArgs(['--family', '4']).family, 4);
  assert.equal(parseArgs(['--family', '6']).family, 6);
  assert.equal(parseArgs(['--family', 'auto']).family, 0);
  assert.equal(parseArgs(['--family', 'ipv4']).family, 4);
  assert.equal(parseArgs(['--family', 'ipv6']).family, 6);
  assert.equal(parseArgs(['--family', '0']).family, 0);
});

test('--family with bogus value sets help=true (refuses to silently default)', mute(() => {
  const o = parseArgs(['--family', 'bogus']);
  assert.equal(o.help, true);
}));

test('unknown argument sets help=true', mute(() => {
  const o = parseArgs(['--definitely-not-a-flag']);
  assert.equal(o.help, true);
}));

test('combined flags compose correctly', () => {
  const o = parseArgs([
    '--host', 'a.b.c', '--no-a2s', '--family', '4',
    '--ports', '27015,27016', '--json', 'r.json', '--yes',
    '--real-server', 'r.example:27015', '--duration', '30',
  ]);
  assert.equal(o.host, 'a.b.c');
  assert.equal(o.a2s, false);
  assert.equal(o.family, 4);
  assert.deepEqual(o.ports, ['27015', '27016']);
  assert.equal(o.json, 'r.json');
  assert.equal(o.yes, true);
  assert.equal(o.realServer, 'r.example:27015');
  assert.equal(o.duration, 30_000);
});

test('order independence: --host first vs last is the same', () => {
  const a = parseArgs(['--host', 'x', '--yes']);
  const b = parseArgs(['--yes', '--host', 'x']);
  assert.deepEqual(a, b);
});

// --duration accepts up to 300 s; longer runs are rejected because the
// client accumulates sequence numbers in a per-test Set and absurd
// durations grow that without bound. 300 s × 60 pps = 18000 entries —
// well under any reasonable resource concern.
test('--duration accepts a positive value at the cap', mute(() => {
  const o = parseArgs(['--duration', '300']);
  assert.equal(o.duration, 300_000);
  assert.equal(o.help, false);
}));

test('--duration rejects values over the 300 s cap', mute(() => {
  const o = parseArgs(['--duration', '600']);
  assert.equal(o.help, true, 'over-cap duration sets help=true so usage prints');
}));

test('--duration rejects zero', mute(() => {
  const o = parseArgs(['--duration', '0']);
  assert.equal(o.help, true);
}));

test('--duration rejects negative', mute(() => {
  const o = parseArgs(['--duration', '-5']);
  assert.equal(o.help, true);
}));

test('--duration rejects non-numeric', mute(() => {
  const o = parseArgs(['--duration', 'forever']);
  assert.equal(o.help, true);
}));

// ---- Phase 1 flags --------------------------------------------------------

test('Phase 1+2 diagnostics default to ON — customer-friendly default', () => {
  // The whole point of the tool is blame attribution. Default-on for
  // the diagnostic tests means every customer support run captures the
  // hard-case patterns (CGNAT eviction, symmetric NAT, uplink
  // throttling, policer fingerprinting, per-flow shaping, DPI signature)
  // without requiring the customer to know about flags. Total runtime
  // ~4 minutes; --full extends the NAT idle ladder for ~10 min.
  const o = parseArgs([]);
  // Phase 1
  assert.deepEqual(o.natIdle, [30, 60]);
  assert.equal(o.natType, true);
  assert.equal(o.bidir, 'both');
  assert.equal(o.burst, true);
  assert.equal(o.upPps, 60);
  // Phase 2
  assert.equal(o.sourcePortFanout, true);
  assert.equal(o.payloadShape, true);
  // includePublicIp stays default-OFF for privacy: reflection is run
  // by default, but the reflected public IP is redacted in both the
  // console output and any JSON report unless the operator opts in.
  assert.equal(o.includePublicIp, false);
});

test('--no-nat-type, --no-burst, --no-nat-idle opt out of individual tests', () => {
  const o = parseArgs(['--no-nat-type', '--no-burst', '--no-nat-idle']);
  assert.equal(o.natType, false);
  assert.equal(o.burst, false);
  assert.equal(o.natIdle, null);
});

test('--no-source-fanout and --no-payload-shape opt out of Phase 2 tests', () => {
  const o = parseArgs(['--no-source-fanout', '--no-payload-shape']);
  assert.equal(o.sourcePortFanout, false);
  assert.equal(o.payloadShape, false);
});

test('--bidir down restores the legacy downstream-only sustained test', () => {
  const o = parseArgs(['--bidir', 'down']);
  assert.equal(o.bidir, 'down');
});

test('--full extends the NAT idle ladder to the long windows', () => {
  const o = parseArgs(['--full']);
  assert.deepEqual(o.natIdle, [30, 60, 120, 300]);
});

test('--nat-idle overrides the default ladder', () => {
  const o = parseArgs(['--nat-idle', '15,45']);
  assert.deepEqual(o.natIdle, [15, 45]);
});

test('explicit --nat-idle after --no-nat-idle re-enables (last-flag-wins)', () => {
  // Order matters because flags are processed left-to-right. This is
  // the existing behavior for every flag; pinning it in a test so
  // someone refactoring parseArgs doesn't accidentally break it.
  const o = parseArgs(['--no-nat-idle', '--nat-idle', '15,45']);
  assert.deepEqual(o.natIdle, [15, 45]);
});

test('--nat-idle with no value uses the default ladder', () => {
  const o = parseArgs(['--nat-idle']);
  assert.deepEqual(o.natIdle, [30, 60, 120, 300]);
});

test('--nat-idle with comma-separated value parses the override', () => {
  const o = parseArgs(['--nat-idle', '15,30,60']);
  assert.deepEqual(o.natIdle, [15, 30, 60]);
});

test('--nat-idle followed by a flag uses defaults (does not consume the flag)', () => {
  const o = parseArgs(['--nat-idle', '--yes']);
  assert.deepEqual(o.natIdle, [30, 60, 120, 300]);
  assert.equal(o.yes, true);
});

test('--nat-idle rejects non-positive or oversize values', mute(() => {
  assert.equal(parseArgs(['--nat-idle', '0']).help, true);
  assert.equal(parseArgs(['--nat-idle', '-5']).help, true);
  assert.equal(parseArgs(['--nat-idle', '30,bogus']).help, true);
  assert.equal(parseArgs(['--nat-idle', '700']).help, true, 'over 600 cap should reject');
}));

test('--nat-type is a pure boolean flag', () => {
  assert.equal(parseArgs(['--nat-type']).natType, true);
});

test('--burst is a pure boolean flag', () => {
  assert.equal(parseArgs(['--burst']).burst, true);
});

test('--bidir accepts down, up, both', () => {
  assert.equal(parseArgs(['--bidir', 'down']).bidir, 'down');
  assert.equal(parseArgs(['--bidir', 'up']).bidir, 'up');
  assert.equal(parseArgs(['--bidir', 'both']).bidir, 'both');
});

test('--bidir rejects unknown value', mute(() => {
  assert.equal(parseArgs(['--bidir', 'sideways']).help, true);
}));

test('--up-pps accepts 1..200', () => {
  assert.equal(parseArgs(['--up-pps', '1']).upPps, 1);
  assert.equal(parseArgs(['--up-pps', '200']).upPps, 200);
  assert.equal(parseArgs(['--up-pps', '60']).upPps, 60);
});

test('--up-pps rejects out-of-range', mute(() => {
  assert.equal(parseArgs(['--up-pps', '0']).help, true);
  assert.equal(parseArgs(['--up-pps', '201']).help, true);
  assert.equal(parseArgs(['--up-pps', 'fast']).help, true);
}));

test('--include-public-ip is a pure boolean flag', () => {
  assert.equal(parseArgs(['--include-public-ip']).includePublicIp, true);
});

test('Phase 1 flags compose with existing flags', () => {
  const o = parseArgs([
    '--host', 'a.b.c', '--yes',
    '--nat-idle', '60,120',
    '--nat-type',
    '--bidir', 'both',
    '--up-pps', '100',
    '--burst',
    '--include-public-ip',
  ]);
  assert.equal(o.host, 'a.b.c');
  assert.equal(o.yes, true);
  assert.deepEqual(o.natIdle, [60, 120]);
  assert.equal(o.natType, true);
  assert.equal(o.bidir, 'both');
  assert.equal(o.upPps, 100);
  assert.equal(o.burst, true);
  assert.equal(o.includePublicIp, true);
  assert.equal(o.help, false);
});
