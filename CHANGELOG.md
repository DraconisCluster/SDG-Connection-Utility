# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## SemVer policy

The project follows SemVer with one additional rule: a change that bumps
the `VERSION` byte in [`shared/protocol.js`](shared/protocol.js) — which
defines the on-the-wire protocol — is by definition a **major** version
bump for both client and server. A v1 client cannot be expected to talk
to a v2 server or vice versa. Compatibility within a major is
guaranteed.

## [Unreleased]

## [1.2.1] — 2026-05-10

### Added
- **`--host` defaults to the public SDG test endpoint (`38.107.232.39`).**
  The source/developer path no longer requires a flag — `node
  client/client.js` Just Works for the most common case (customer
  diagnosing a connection issue against SDG's public server).
  `--host <addr>` still overrides for side-by-side or off-server
  testing, and the Windows easy-install bundle is unchanged: it still
  reads `TARGET_HOST` from `config.txt` and passes it explicitly,
  which means support can rotate the target by editing one line in
  `config.txt` without rebuilding.

### Fixed
- **Easy-install report path under OneDrive Known Folder Move.**
  `Run-Test.cmd` previously wrote the report to
  `%USERPROFILE%\Desktop\sdg-test-report-<TS>.json`. On any Windows
  account with OneDrive KFM enabled (the default for most modern
  Microsoft-account signins), the real Desktop is at
  `%USERPROFILE%\OneDrive\Desktop` and `%USERPROFILE%\Desktop` does
  not exist — Node's `--json` open then failed with `ENOENT`, and
  the customer lost the entire report after waiting 3–4 minutes for
  the test to run. The launcher now writes the report into the same
  folder as `Run-Test.cmd` itself (which is guaranteed to exist and
  is where the user already is). `README - START HERE.txt` and the
  top-level README updated to match.

### Changed
- Bumped `client/package.json` and `shared/package.json` versions to
  1.2.1 to match the release tag.

## [1.2.0] — 2026-05-06

### Added
- **Windows easy-install bundle.** A self-contained zip aimed at
  non-technical customers: unzip, double-click `Run-Test.cmd`, wait
  3-4 minutes, find a timestamped JSON report on the Desktop ready
  to attach to a support ticket. Bundles a pinned Node.js 22 LTS
  runtime so no Node install is required. Target server is read at
  run time from `config.txt`, so it can be rotated without rebuilding
  the bundle. Build script lives at [`tools/build-bundle.py`](tools/build-bundle.py)
  and produces `sdg-connection-test-<version>-windows-x64.zip` (~31.6
  MiB).

### Fixed
- **Privacy: redact reflected public IP in console output.** The
  console previously printed the full reflected source IP (e.g.
  `136.51.83.236:60787`) under the NAT type test, on the assumption
  that the screen is the user's own machine. Support flows commonly
  involve customers pasting the console transcript into a ticket, so
  the client now applies the same redaction the JSON report already
  uses, governed by the same `--include-public-ip` flag. Default
  output is now `136.51.83.x` in both channels.

### Changed
- Bumped `client/package.json` and `shared/package.json` versions to
  1.2.0 to match the release tag. (These were left at 1.0.0 through
  v1.1.0 — no functional impact since the project ships zero npm
  dependencies, but worth syncing now.)

## [1.1.0] — 2026-05-06

### Added — Phase 2 diagnostics

Two more default-on diagnostics targeting carrier failure modes the
Phase 1 sweep can miss, plus two free metrics derived from existing
data. All client-side, no server change required. Total added
runtime ~30 s on top of Phase 1.

- **Source-port fan-out** (`--no-source-fanout` to skip). Repeats a
  short loss test from 4 different ephemeral source ports against
  UDP 27016. Diverging loss across source ports → per-5-tuple
  shaping or unlucky ECMP hash bucket; uniform loss → path-wide
  problem; clean → no per-flow discrimination.
- **Payload-shape sensitivity** (`--no-payload-shape` to skip).
  Three short loss tests on UDP 27016 with different payload
  contents (game-shape, random bytes, zero-fill). Diverging loss
  across patterns → DPI making content-based decisions. Names
  the worst pattern in the verdict so support can act on it.
- **Loss-burst histogram** — added to every UDP loss/sustained
  test as a side effect of existing tracking. Runs of consecutive
  drops bucketed as 1 / 2-4 / 5-9 / 10+. Surfaced only when
  meaningful (>0 drops). The shape of the histogram fingerprints
  loss type: many singles → random; clusters of 5-9 → policer
  cycles; any 10+ → multi-hundred-ms outage / shaping.
- **Packet reordering count** — same approach. Out-of-order
  arrivals counted; surfaced when >0 because SE's interpolation
  hides loss but stutters on reorder, so even a few inversions
  matter to a customer experience.

### Added — Phase 1 diagnostics

Four new opt-out diagnostic tests targeting the carrier failure modes
the original v1.0.0 sweep couldn't surface. **All four default ON**:
the whole point of the tool is blame attribution, and these are the
tests that catch the cases the default L3/L4 sweep misses. Total
runtime ~3-4 minutes; pass `--full` for the long NAT-idle ladder
(~10 minutes).

- **NAT idle-timeout probe** (`--no-nat-idle` to skip). Holds one UDP
  socket open and probes after 30 + 60 seconds of idle (or
  30/60/120/300 with `--full`). Catches CGNAT mapping eviction
  even when the data path appears to recover, by comparing the
  reflected source port before and after each idle window. Covers
  the canonical T-Mobile 5G Home "I get disconnected after a few
  minutes" symptom.
- **Endpoint reflection / NAT type** (`--no-nat-type` to skip).
  Sends two probes from one socket to two destination ports and
  classifies the result as cone (peer-to-peer works), symmetric
  (peer-to-peer needs a relay like Steam Datagram), or no-NAT
  (IPv6).
- **Bidirectional sustained stream** (`--bidir down` for legacy
  downstream-only). The default sustained test now exercises both
  directions; the up-stream phase reveals uplink-only throttling
  that is invisible to a downstream-only test.
- **Burst-vs-steady policer test** (`--no-burst` to skip). 100
  packets at max kernel rate, then 100 at 10 pps, on UDP 27443
  (baseline). Loss diff fingerprints policer vs shaper vs random
  loss.

Wire protocol additions (no VERSION bump — Phase 1 is fully
backwards-compatible with v1.0.0 servers, which is why we kept
VERSION=1):

- `TYPE.REFLECT_REPLY` (9) — server echoes observed source IP/port,
  padded to inbound probe size.
- `TYPE.STREAM_DATA_UP` (10) — client→server up-stream payload.
- `TYPE.STREAM_TALLY` (11) — server→client end-of-stream tally,
  sent 3× for loss tolerance.
- `TYPE.CAPABILITIES` (12) — feature bitmap (reflection,
  bidirectional, nat-idle-aware) returned in response to a probe
  with the magic sequence value `0xCAFEBABE`. Allows the client to
  detect server support before running server-dependent tests and
  print `SKIPPED (server too old)` rather than fabricate a verdict.
- `flags` byte (offset 6 of the SDGT header) — previously reserved
  zero. On `PROBE`: high bit (`FLAG_REFLECT`, `0x80`) opts into
  reflection. On `STREAM_BEGIN` and `STREAM_CONFIRM`: low byte
  carries the direction code (0=down, 1=up, 2=both).

CLI additions:
- `--full` extends the NAT idle ladder to 30/60/120/300 s.
- `--nat-idle <s1,s2,...>` overrides the default ladder.
- `--bidir <down|up|both>`, `--up-pps <n>` for the bidirectional
  sustained variant.
- `--no-nat-idle`, `--no-nat-type`, `--no-burst` to dial back.
- `--include-public-ip` opts into a non-redacted reflected source
  IP in the JSON report (default is to redact the host portion).

### Changed
- Default sustained test direction is now `both`. Pass `--bidir down`
  for the legacy v1.0.0 downstream-only behavior.
- Default run includes the four Phase 1 tests. Use `--no-*` flags
  to dial back, or `--ports` to limit the per-port sweep.
- Test suite grew from 81 (v1.0.0) to 138 client + 208 server tests.

### Privacy
- JSON report redacts the host portion of any reflected public IP
  by default (v4: `1.2.3.x`; v6: keeps first /32 + redacted
  marker). The README invites users to share their report for
  support, so this prevents a CGNAT egress IP from becoming a
  shared identifier without explicit opt-in (`--include-public-ip`).

## [1.0.0] — 2026-05-04

First public release.

### Added
- Client `--family <4|6|auto>` flag. Default is `auto` (whatever the
  OS resolver picks). Use `4` to force IPv4 against the SDG test
  server (currently v4-only) on a v6-native client like T-Mobile 5G
  Home Internet with 464XLAT, where Happy Eyeballs can otherwise
  perturb the measurement.
- Client MTU sweep: the per-port MTU probe now runs at 1200, 1400,
  and 1472 bytes instead of a single 1400. Output JSON gains a
  `mtuSweep: [{size, ok, rtt}, ...]` array per UDP port; the legacy
  `mtu` field is preserved as the largest size that succeeded.
- Server `createServer({ ... })` factory exposing `start()`,
  `stop()`, and `addresses()`. Lets tests bind to ephemeral ports
  (`bindOverride`) and override log path / ASN lookup / rate
  limits / streamer duration. Production behavior unchanged when
  invoked as `node server/server.js`.
- `server/ipToAsn.js` `createLookup({ tsvPath })` factory so tests
  can exercise the missing-file degrade path without touching the
  bundled TSV.
- `shared/netUtils.js` with `normalizeIp()` (strips v4-mapped
  `::ffff:` prefix) and `dgramTypeFor()` (selects `udp4`/`udp6` by
  family).
- Test suite: 149 tests across `shared/`, `server/`, and `client/`,
  using only `node:test` and `node:assert/strict`. Includes a
  full client-server integration test that spins up the server on
  ephemeral ports and exercises the protocol end-to-end.
- CI (operator-internal): `test` (Node 20 + 22), `docker-build`, and
  `zero-dep-guard` jobs. The guard enforces no npm dependencies, no
  imports outside Node built-ins / `./*` / `../shared/*`, and that
  `client/` stays a single non-test JS file. The same enforcement is
  applied to the public `client/` and `shared/` trees by maintainers
  on PR review.
- [`LICENSE`](LICENSE) (MIT).
- [`CONTRIBUTING.md`](CONTRIBUTING.md) — acceptable use, the
  zero-dep rule, repo layout, and the port-addition recipe.
- [`docs/PRIVACY.md`](docs/PRIVACY.md) — what the session log
  collects, retention posture, GDPR considerations, and operator
  responsibilities.
- `docs/FIELD-TEST-PROTOCOL.md` (operator-internal) — the methodology
  for the carrier-comparison field test (5 trials per carrier × 3 time
  windows × negative-control target × traceroute capture × server-side
  correlation × MTU sweep).

### Changed
- Deployment doc restructured (operator-internal). Specifics are not
  published.
- `client/client.js` wraps `main()` in `if (require.main === module)`
  and exports `parseArgs`, `stats`, `filterPorts`, and `fmt` so the
  file can be required from tests without spawning a CLI run.
- `shared/ports.js` deep-freezes individual entries (not just the
  outer array). The matrix is "single source of truth a suspicious
  player has to audit" — defensive immutability matters here.
- `server/sessionLog.js` constructor takes a config object so tests
  can override log path, max bytes, max sessions, size-check
  throttle, idle flush, new-session rate cap, and ASN lookup.
- `server/sessionLog.js` no longer disables itself on the first
  ENOENT from a `stat()` of the not-yet-flushed log file. ENOENT
  during rotation just means there's nothing to rotate yet; only
  real errors (EACCES, EPERM, etc.) disable.
- `server/gameShape.js` `GameShapeStreamer` constructor accepts
  `{ durationMs, intervalMs, minBytes, maxBytes }` overrides. Production
  defaults unchanged.
- `server/Dockerfile` and `package.json` files require Node 20+
  (was 18+); the test suite uses `node:test` mock-timer features
  introduced in Node 20.4.
- `server/docker-compose.yml` healthcheck now inspects the response
  bytes via `od | grep` rather than just discarding nc's output.
  The previous version returned exit 0 even when nothing answered,
  silently masking a hung server.

### Deprecated
- (none)

### Removed
- The "single client.js as a release artifact" idea floated in
  earlier design notes. `client.js` requires `../shared/*` so it
  cannot run alone; the release ships the tree as a tarball.

### Fixed
- (none — first release)

### Client hardening
- Server applies `normalizeIp()` to incoming source addresses so the
  same client is keyed consistently across v4 and v4-mapped v6.
- `--real-server` now uses a strict host:port parser that supports
  bracketed IPv6 forms (e.g. `[2001:db8::1]:27015`) and rejects
  ambiguous unbracketed IPv6, missing port, non-numeric port, and
  out-of-range ports with specific error messages — replacing a
  naive `String.split(':')` that shattered on IPv6 literals and
  silently turned a missing port into NaN.
- `--duration` is capped at 300 seconds. The sustained-test's
  sequence-number deduplication set previously grew without bound
  under absurd `--duration` values; the cap is well above any
  legitimate diagnostic use.

[Unreleased]: https://github.com/sdg-net/sdg-connection-test/compare/v1.2.0...HEAD
[1.2.0]: https://github.com/sdg-net/sdg-connection-test/releases/tag/v1.2.0
[1.1.0]: https://github.com/sdg-net/sdg-connection-test/releases/tag/v1.1.0
[1.0.0]: https://github.com/sdg-net/sdg-connection-test/releases/tag/v1.0.0
