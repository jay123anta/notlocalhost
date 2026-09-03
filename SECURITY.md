# Security

## Reporting a vulnerability

Open a [security advisory](https://github.com/jay123anta/notlocalhost/security/advisories/new)
rather than a public issue. Expect an acknowledgement within a few days.

## What this tool does with your data

Nothing leaves your machine.

- **No telemetry, ever.** No analytics, no crash reporting, no version check, no
  phone-home of any kind. `npm run lint` fails the build if anything resembling
  one appears in the source.
- **No account, no service.** There is nothing to sign in to.
- **Network access is limited to the target URL you pass, plus a TCP connect
  probe of a fixed list of common dev ports on `127.0.0.1`.** The probe refuses
  any host that is not loopback, and `--no-port-scan` disables it entirely.
- **It works offline.** The only outbound traffic is whatever your own
  application makes.
- **It never modifies your application.** It reads what your dev server serves
  over HTTP, exactly as a browser does. It does not read your repository.
- **It writes only the report files you asked for.**

## The browser profile

Each run launches a fresh, empty browser context: no extensions, no sync, no
cookies inherited from your real profile. Nothing you do in your own browser
affects a run, and a run leaves nothing behind.

## Secrets in reports

The HTML and JSON reports quote response headers, cookie values and snippets of
served source. That is the point, since the evidence has to be exact. Before
writing a snippet, notlocalhost redacts JWTs, common token prefixes, AWS access
keys, and values following `password`, `secret`, `api_key`, `token`,
`authorization` or `bearer`.

**This redaction is best-effort and you should not rely on it.** Cookie values in
the inventory are shown as set, so a report from an authenticated run can contain
a live session token. Treat a report from a real application as sensitive: review
it before attaching it to a public issue, and prefer `--fail-on` with exit codes
over uploading reports from production-like environments.

## Flow scripts execute arbitrary code

A `--flow` script is imported and run by Node with your privileges. Only run flow
scripts you wrote or have read, exactly as with any other script in your
repository.

## Supported versions

While the project is pre-1.0, only the latest minor version receives fixes.
