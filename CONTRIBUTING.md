# Contributing

```
git clone https://github.com/jay123anta/notlocalhost
cd notlocalhost
npm install          # one dependency, no browser download
npm test             # unit + end-to-end + report tests
```

You need Chrome, Chromium or Edge installed. The end-to-end and report suites
skip themselves without one; CI fails if they skip.

## Layout

```
bin/notlocalhost.js          entry point
src/cli.js                   argument parsing, output, exit codes
src/analyze.js               orchestration; builds the result document
src/session.js               drives the browser, captures via CDP
src/browser/locate.js        finds an installed browser; never downloads one
src/browser/instrument.js    injected before any application script runs
src/collect/                 parsing and classification; produces no findings
src/rules/                   findings, one module per area
src/report/                  terminal, HTML, JSON, markdown
test/fixtures/lying-app.mjs  every failure this tool detects, in one file
evidence/                    reproductions of every claim the README makes
```

`src/collect/` decides *what is true*. `src/rules/` decides *what to say about
it*. Keep that split — it is why the parsers are unit-testable without a browser.

## Standards for a new rule

1. A stable, namespaced id. It becomes an API the moment it ships.
2. A severity you can defend. `will-break` requires a specification citation or
   reproduced browser behaviour. If you cannot produce one, it is `may-break`.
   Findings that overstate their case are worse than no findings.
3. Exact evidence: the header, the line, the URL. Never a paraphrase.
4. A fix that says what to change, not merely that something is wrong.
5. Tests. Logic in `test/unit.test.js`; anything needing a live page in
   `test/e2e.test.js`.
6. An entry in `docs/rules.md`.

If you can add the failure to `test/fixtures/lying-app.mjs`, do. It is the
fastest way for the next person to understand what you found.

## Standards for the project

- **One runtime dependency.** `npm run lint` fails if a second appears. No
  argument parser, no colour library, no test framework.
- **No telemetry, ever.** Not opt-in, not anonymous, not "just a version check".
- **Never modify the user's application.**
- **Stage 1 stays zero-setup.** No certificate installs, no DNS changes, no
  privileged ports, no writes outside the working directory. That constraint is
  the product, not a limitation.
- **Honest limitations stay honest.** If a change narrows what a finding proves,
  update `LIMITATIONS` in `src/analyze.js` in the same commit.

## Verifying claims

Anything the README asserts about browser behaviour must be reproduced in
`evidence/`:

```
npm run evidence
```

Nine claims, checked against your own browser. If one is refuted on a newer
Chrome, that is a bug report worth filing on its own.

## Before opening a pull request

```
npm run lint
npm test
npm run evidence
```

Note in the description which of the three you ran and on which platform. CI
runs all of it on Linux, macOS and Windows.
