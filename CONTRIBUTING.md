# Contributing

Thanks for considering a contribution. This is a small, focused project
with a hard "no dependencies" rule and a strong preference for simple,
auditable code over abstraction. Read this whole file before opening a PR.

## Acceptable use

This is a **diagnostic tool for your own networks and servers**. The
client supports a `--real-server` flag that lets it send a Steam
A2S_INFO query to any UDP host you point it at; that exists so you can
compare what the SDG diagnostic server sees with what your actual Torch
server sees. It is NOT a general-purpose probe-anyone tool. PRs and
issues that frame the project as a reconnaissance tool, or that add
features primarily useful for unauthorized scanning, will be closed.

If you don't operate it and you don't have explicit permission to probe
it, leave it alone.

## Hard rule: no npm dependencies

Both runtime and development. The client is a single file you can read
end-to-end in fifteen minutes; a `node_modules` directory full of
transitive packages would undermine that audit story.

The constraints, enforced by maintainers on every PR:

- Every `package.json` must have empty (or absent) `dependencies`,
  `devDependencies`, `peerDependencies`, and `optionalDependencies`.
- `client/client.js` must `require()` only Node built-ins and
  `../shared/*`.
- `client/` must contain exactly one non-test JS file.

The same zero-dep rule applies to the operator-internal server side
and is enforced there. PRs that violate the rule on the public side
(client/shared) will not be merged.

If you find yourself wanting a library, the right move is usually
either:

1. Inline the 30 lines from the library that you actually need, or
2. Decide you don't need them.

We use Node 20+ specifically so that `node:test`, `node:assert/strict`,
and the built-in test runner cover what people would otherwise reach
for Jest / Mocha / Vitest for.

## Repo layout

```
client/                zero-dep diagnostic client (single file)
shared/                shared modules + tests
docs/                  PROTOCOL, TRANSPARENCY, PRIVACY
LICENSE                MIT
CONTRIBUTING.md        this file
CHANGELOG.md           Keep-a-Changelog format
README.md
```

The server implementation is operator-internal and not part of this
repository. The wire protocol it speaks is documented in
[`docs/PROTOCOL.md`](docs/PROTOCOL.md); server hardening details are
not published.

## Running tests

Each peer package is independently runnable:

```
cd shared && npm test
cd client && npm test
```

`npm test` is just `node --test` under the hood. There is no `npm
install` step. Total runtime is on the order of two seconds.

Coverage:

```
cd shared && node --test --experimental-test-coverage
cd client && node --test --experimental-test-coverage
```

The flag has known false-low readings (it counts test files themselves;
it cannot exclude). Don't gate PRs on a percentage — read the report.

## Adding a port to `shared/ports.js`

The port matrix is the single source of truth for both client and
server. To add an entry:

1. Append it to `PORTS` in [`shared/ports.js`](shared/ports.js) with the
   correct `proto`, `port`, `category`, and `purpose`.
2. Update `shared/test/ports.test.js` if your addition affects any of
   the structural invariants (e.g. you added a new `category` value).
3. Update the operator's deployment runbook §5 (upstream firewall
   table) and §3 (host ufw block on the VM) so deployers see the new
   port immediately. The runbook is operator-internal; coordinate with
   the SDG ops team if you don't have access.

Server-side handling for new ports is operator-internal — the server
implementation is not in this repo. Coordinate with the SDG ops team
if a new port needs custom handling beyond the default echo. The default
behavior is documented in [`docs/PROTOCOL.md`](docs/PROTOCOL.md).

## Coding style

- 2-space indent, semicolons, single-quoted strings.
- `'use strict';` at the top of every file.
- No transpilers. Run on the Node version we ship in CI (currently 20+).
- Functions over classes unless lifecycle / state really wants a class.
- File length stays under ~400 lines. If a file is growing past that,
  extract a peer module. The existing files were chosen at sizes the
  reader can hold in their head.
- No comments that re-state the code. Comments explain the *why* —
  protocol references, surprising invariants, design rationale. The
  existing files are the style guide.

## Pull requests

1. Open an issue first if the change is non-trivial. A quick sanity
   check on direction saves both sides time.
2. Branch off `main`. Keep the diff focused — one PR, one concern.
3. Update tests to cover behavior you change. We aim for: 80% on
   `shared/`, ~50% on `client/` (CLI orchestration is covered by
   integration; pure functions are covered by units).
4. Update relevant docs in the same PR. A code change that contradicts
   `PROTOCOL.md` is not done until that doc is updated.
5. Don't add a `CHANGELOG.md` entry yourself; maintainers add the entry
   when cutting a release so the format stays consistent.
6. CI must be green. The `zero-dep-guard` job in particular is
   load-bearing for the project's identity — its failure is the only
   thing that consistently means "do not merge."

## Releases

Maintainers cut releases. The process is documented elsewhere; users
should not need to know it. From a contributor's perspective, what
matters is that breaking changes to the wire protocol bump the
`VERSION` byte in [`shared/protocol.js`](shared/protocol.js), which is
also the point at which we cut a major SemVer tag.

## Questions

Open an issue in this repository.
