'use strict';

// Unit tests for the Phase 2 pure-function analysis helpers. No
// sockets, no I/O — these consume the same shape of data the actual
// loss/sustained tests produce and emit a verdict.

const { test } = require('node:test');
const assert = require('node:assert/strict');
const {
  lossBurstHistogram, countReorderings,
  classifyFanout, classifyPayloadShape,
} = require('../client');

// ---- lossBurstHistogram --------------------------------------------------

test('lossBurstHistogram: zero loss → all-zero buckets', () => {
  const h = lossBurstHistogram([0, 1, 2, 3, 4], 5);
  assert.deepEqual(h, { 1: 0, '2-4': 0, '5-9': 0, '10+': 0 });
});

test('lossBurstHistogram: total loss → single 5+ bucket entry', () => {
  // Sent 5, received 0: one run of 5 consecutive losses.
  const h = lossBurstHistogram([], 5);
  assert.deepEqual(h, { 1: 0, '2-4': 0, '5-9': 1, '10+': 0 });
});

test('lossBurstHistogram: isolated single drops bucket as 1', () => {
  // 10 packets, lost: 2, 5, 8 — three separate single-drop runs.
  const h = lossBurstHistogram([0,1,3,4,6,7,9], 10);
  assert.deepEqual(h, { 1: 3, '2-4': 0, '5-9': 0, '10+': 0 });
});

test('lossBurstHistogram: short burst falls in 2-4', () => {
  // 10 packets, lost: 2,3,4 — one burst of 3.
  const h = lossBurstHistogram([0,1,5,6,7,8,9], 10);
  assert.deepEqual(h, { 1: 0, '2-4': 1, '5-9': 0, '10+': 0 });
});

test('lossBurstHistogram: 10+ bucket catches sustained outages', () => {
  // 20 packets, lost positions 5..15 (11 in a row).
  const arrived = [0,1,2,3,4,16,17,18,19];
  const h = lossBurstHistogram(arrived, 20);
  assert.equal(h['10+'], 1);
});

test('lossBurstHistogram: mixed pattern across all buckets', () => {
  // 25 sent. Drops: 1 (single), 5,6 (run of 2), 12..17 (run of 6),
  // 22..24 (run of 3). Buckets: 1×1, 2-4×2 (run-of-2 + run-of-3),
  // 5-9×1 (run-of-6).
  const arrived = [0, 2,3,4, 7,8,9,10,11, 18,19,20,21];
  const h = lossBurstHistogram(arrived, 25);
  assert.deepEqual(h, { 1: 1, '2-4': 2, '5-9': 1, '10+': 0 });
});

test('lossBurstHistogram: defensive — bad input returns zeroed buckets', () => {
  assert.deepEqual(lossBurstHistogram(null, 5), { 1: 0, '2-4': 0, '5-9': 0, '10+': 0 });
  assert.deepEqual(lossBurstHistogram([], 0), { 1: 0, '2-4': 0, '5-9': 0, '10+': 0 });
  assert.deepEqual(lossBurstHistogram([1,2], -1), { 1: 0, '2-4': 0, '5-9': 0, '10+': 0 });
});

// ---- countReorderings ---------------------------------------------------

test('countReorderings: in-order arrivals → zero inversions', () => {
  assert.deepEqual(countReorderings([0, 1, 2, 3, 4, 5]), { inversions: 0, pct: 0 });
});

test('countReorderings: single swap → one inversion', () => {
  // [0, 1, 3, 2, 4]: just (3, 2) is an inversion.
  const r = countReorderings([0, 1, 3, 2, 4]);
  assert.equal(r.inversions, 1);
});

test('countReorderings: full reversal → n*(n-1)/2 inversions', () => {
  // [4, 3, 2, 1, 0]: all 10 pairs are inverted.
  const r = countReorderings([4, 3, 2, 1, 0]);
  assert.equal(r.inversions, 10);
  // pct = 10 / 5 * 100 = 200 — yes, the metric can exceed 100%; it's
  // a "per-arrival" rate, not a proportion. The verdict layer uses
  // it as a magnitude indicator.
  assert.equal(r.pct, 200);
});

test('countReorderings: empty / single-element input → zero', () => {
  assert.deepEqual(countReorderings([]),    { inversions: 0, pct: 0 });
  assert.deepEqual(countReorderings([42]),  { inversions: 0, pct: 0 });
  assert.deepEqual(countReorderings(null),  { inversions: 0, pct: 0 });
});

// ---- classifyFanout -----------------------------------------------------

test('classifyFanout: all-clean sockets → clean verdict', () => {
  const v = classifyFanout([0, 0.5, 1.0, 0]);
  assert.equal(v.kind, 'clean');
});

test('classifyFanout: one socket at 50% loss, others clean → per-flow', () => {
  // The textbook unlucky-ECMP-hash signature.
  const v = classifyFanout([0, 0, 0, 50]);
  assert.equal(v.kind, 'per-flow');
});

test('classifyFanout: consistent moderate loss across all sockets → uniform', () => {
  const v = classifyFanout([8, 9, 8, 10]);
  assert.equal(v.kind, 'uniform');
});

test('classifyFanout: borderline spread → mild-variance', () => {
  // 10% spread between best and worst — not clean (max>2) but not
  // dramatic enough to call per-flow. mild-variance is the explicit
  // "we don't know, rerun" verdict.
  const v = classifyFanout([5, 6, 7, 13]);
  assert.equal(v.kind, 'mild-variance');
});

test('classifyFanout: <2 sockets → incomplete', () => {
  assert.equal(classifyFanout([10]).kind,    'incomplete');
  assert.equal(classifyFanout([]).kind,      'incomplete');
  assert.equal(classifyFanout(null).kind,    'incomplete');
});

// ---- classifyPayloadShape -----------------------------------------------

test('classifyPayloadShape: all-clean patterns → clean', () => {
  const v = classifyPayloadShape({ 'game-shape': 0, random: 1.0, zero: 0.5 });
  assert.equal(v.kind, 'clean');
});

test('classifyPayloadShape: one pattern dropped, others clean → dpi-fingerprint', () => {
  // The classic "DPI matches the SE shape" signature.
  const v = classifyPayloadShape({ 'game-shape': 30, random: 0.5, zero: 0.5 });
  assert.equal(v.kind, 'dpi-fingerprint');
  assert.match(v.reason, /game-shape/, 'verdict should name the worst pattern');
});

test('classifyPayloadShape: uniform path-loss across patterns → uniform', () => {
  // 8% loss everywhere — path is just lossy, not content-driven.
  const v = classifyPayloadShape({ 'game-shape': 8, random: 9, zero: 8 });
  assert.equal(v.kind, 'uniform');
});

test('classifyPayloadShape: <2 patterns → incomplete', () => {
  assert.equal(classifyPayloadShape({}).kind,                       'incomplete');
  assert.equal(classifyPayloadShape({ only: 5 }).kind,              'incomplete');
  assert.equal(classifyPayloadShape(null).kind,                     'incomplete');
});
