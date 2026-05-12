'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { stats, filterPorts, fmt } = require('../client');

// ---- stats() --------------------------------------------------------------

test('stats: empty input returns nulls and n=0', () => {
  const s = stats([]);
  assert.equal(s.n, 0);
  assert.equal(s.min, null);
  assert.equal(s.avg, null);
  assert.equal(s.p95, null);
  assert.equal(s.max, null);
  assert.equal(s.stddev, null);
});

test('stats: single sample sets min=avg=p95=max and stddev=0', () => {
  const s = stats([42]);
  assert.equal(s.n, 1);
  assert.equal(s.min, 42);
  assert.equal(s.avg, 42);
  assert.equal(s.p95, 42);
  assert.equal(s.max, 42);
  assert.equal(s.stddev, 0);
});

test('stats: known input has known min/max/avg', () => {
  const s = stats([1, 2, 3, 4, 5]);
  assert.equal(s.n, 5);
  assert.equal(s.min, 1);
  assert.equal(s.max, 5);
  assert.equal(s.avg, 3);
});

test('stats: stddev matches population formula (sqrt of variance)', () => {
  // Population variance of [1,2,3,4,5] is 2; sqrt(2) ≈ 1.4142.
  const s = stats([1, 2, 3, 4, 5]);
  assert.ok(Math.abs(s.stddev - Math.sqrt(2)) < 1e-9, `stddev should be sqrt(2), got ${s.stddev}`);
});

test('stats: p95 with 100 samples is the 95th-percentile value', () => {
  // Sorted ascending: p95 index = floor(100 * 0.95) = 95 → value 95.
  const samples = Array.from({ length: 100 }, (_, i) => i);
  const s = stats(samples);
  assert.equal(s.p95, 95);
});

test('stats: input is not mutated', () => {
  const samples = [3, 1, 4, 1, 5, 9, 2, 6, 5, 3];
  const before = JSON.stringify(samples);
  stats(samples);
  assert.equal(JSON.stringify(samples), before, 'stats must not sort or otherwise mutate input');
});

test('stats: handles negative samples correctly (clock-skew RTT estimates etc.)', () => {
  const s = stats([-5, -1, 0, 1, 5]);
  assert.equal(s.min, -5);
  assert.equal(s.max, 5);
  assert.equal(s.avg, 0);
});

// ---- filterPorts() --------------------------------------------------------

const SAMPLE = [
  { proto: 'udp', port: 27015 },
  { proto: 'tcp', port: 27015 },
  { proto: 'udp', port: 27016 },
  { proto: 'tcp', port: 27036 },
];

test('filterPorts: null/undefined wanted returns all entries unchanged', () => {
  assert.deepEqual(filterPorts(SAMPLE, null), SAMPLE);
  assert.deepEqual(filterPorts(SAMPLE, undefined), SAMPLE);
});

test('filterPorts: matches by port number across both protos', () => {
  // Asking for 27015 yields BOTH udp and tcp variants — the comment in
  // client.js says "Matches both proto if both are in the table."
  const out = filterPorts(SAMPLE, ['27015']);
  assert.equal(out.length, 2);
  assert.ok(out.some(p => p.proto === 'udp' && p.port === 27015));
  assert.ok(out.some(p => p.proto === 'tcp' && p.port === 27015));
});

test('filterPorts: numeric strings and numeric values both work', () => {
  const a = filterPorts(SAMPLE, ['27016']);
  const b = filterPorts(SAMPLE, [27016]);
  assert.deepEqual(a, b);
});

test('filterPorts: unknown port yields empty array', () => {
  assert.deepEqual(filterPorts(SAMPLE, ['99999']), []);
});

// ---- fmt() ---------------------------------------------------------------

test('fmt: null/undefined/NaN/Infinity render as the em-dash placeholder', () => {
  for (const v of [null, undefined, NaN, Infinity, -Infinity]) {
    assert.equal(fmt(v), '   —  ');
  }
});

test('fmt: < 10 → 2 decimals; < 100 → 1 decimal; >= 100 → integer', () => {
  assert.equal(fmt(1.234), '1.23');
  assert.equal(fmt(9.999), '10.00'); // toFixed(2) on 9.999 → "10.00"
  assert.equal(fmt(50.5),  '50.5');
  assert.equal(fmt(123.4), '123');
});

test('fmt: zero is formatted, not treated as missing', () => {
  assert.equal(fmt(0), '0.00');
});
