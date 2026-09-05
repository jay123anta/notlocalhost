# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
follows [semantic versioning](https://semver.org/spec/v2.0.0.html).

The JSON document carries its own `schemaVersion`, which changes only when a
field is removed or retyped. Adding a field is not breaking.

## [Unreleased]

## [0.1.1] - 2026-09-05

### Fixed

- `cookie.port-sharing-hazard` no longer fires when the page is served from a
  subdomain of `.localhost`. Cookies are keyed by hostname, so a page on
  `app.myproject.localhost` shares no jar with dev servers answering as
  `localhost` or `127.0.0.1`, even though that name also resolves to
  loopback. The rule tested "is this loopback", which is a different question,
  and reported a hazard that cannot occur. A false positive in a tool people
  run to be warned is worse than a missing rule: it teaches them to skim.

## [0.1.0] - 2026-09-04

First release.

### Added

- `notlocalhost <url>` drives a running dev server in an already-installed
  Chrome, Chromium or Edge and predicts what changes on a real HTTPS origin.
- `--flow <path>` runs a Playwright login script so post-authentication cookies
  are analyzed. Instrumentation is installed before any application script runs.
- Single-file HTML report: no external assets, opens from `file://`, verified in
  CI by loading it in a real browser with every outbound request blocked.
- `--json` emits a `schemaVersion: 1` document; `--markdown` emits a summary.
- Documented, stable exit codes: 0 clean, 1 findings, 2 unreachable, 5 tool
  failure, 64 usage.
- Rules across cookies, origins and CORS, secure contexts, mixed content and
  leaked local URLs. Full catalogue in `docs/rules.md`.
- `--domain`, `--cross-site` and `--map` to state the deployment topology every
  prediction is made against. The assumption is printed in every report.
- GitHub Action in `action.yml`, with job summary and artifact upload.
- `evidence/repro-port-sharing.mjs` verifies nine RFC-level claims against a
  real browser. All nine confirmed on Chrome 152.
- `test/fixtures/lying-app.mjs`, a dependency-free dev server exhibiting every
  detected failure in one commented file.

### Notes

- Requires Node 20 or newer. The floor is set by `playwright-core`, not by us,
  and `npm run lint` fails if `package.json` ever claims a lower one than the
  dependency supports.
- One runtime dependency (`playwright-core`), which itself has none. No browser
  is ever downloaded.
- No telemetry, no account, and no network access beyond the target URL and a
  loopback port probe. Works offline.
- Installs no certificate, changes no DNS, binds no privileged port, and writes
  nothing outside the working directory.

[Unreleased]: https://github.com/jay123anta/notlocalhost/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/jay123anta/notlocalhost/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/jay123anta/notlocalhost/releases/tag/v0.1.0
