# notlocalhost

> **Your localhost is lying to you. This tells you exactly how.**

[![tests](https://github.com/jay123anta/notlocalhost/actions/workflows/tests.yml/badge.svg)](https://github.com/jay123anta/notlocalhost/actions/workflows/tests.yml)
[![npm](https://img.shields.io/npm/v/notlocalhost)](https://www.npmjs.com/package/notlocalhost)
[![runtime dependencies: 1](https://img.shields.io/badge/runtime%20dependencies-1-brightgreen)](#near-zero-dependencies)
[![no telemetry](https://img.shields.io/badge/telemetry-none-brightgreen)](#what-it-does-not-do)
[![node](https://img.shields.io/badge/node-%E2%89%A520-blue)](package.json)

Point it at the dev server you already have running:

```
npx notlocalhost http://localhost:3000
```

It loads your app in a browser you already have installed, watches everything
the page does, and tells you what changes when the same app is served from a
real HTTPS origin on a real domain.

It installs nothing, trusts no certificate, touches no DNS, binds no port, and
writes nothing outside the directory you run it in.

```
notlocalhost 0.1.1  •  http://localhost:5173
──────────────────────────────────────────────────────────────────────────────
target      http://localhost:5173/  (HTTP 200)
browser     Google Chrome 152.0.7977.65
assuming    deployed as https://<subdomain>.acme.com (same-site subdomain model)
            localhost:5173  →  https://app.acme.com
            localhost:3001  →  https://api.acme.com
coverage    7 requests, 2 Set-Cookie, 144 KB scanned
            flow ./login.js ran

  4 will break  |  5 may break  |  2 info

WILL BREAK ───────────────────────────────────────────────────────────────────

  • Host-only cookies reach localhost:3001 today and will stop once those
    are separate hostnames
    cookie.host-only-stops-crossing

    This is the port-sharing fact turned around, and it is the expensive
    direction.

    Right now these requests go to a different port on the same host, so every
    host-only cookie is attached automatically — no Domain attribute, no CORS
    credentials negotiation, nothing to configure. It looks like the API is
    authenticated because it is.

    After deployment those ports become different hostnames. A host-only cookie
    is sent only to the exact host that set it, so the API receives no cookie at
    all. Nothing errors on the browser side; the request simply arrives
    unauthenticated, and you get a 401 that reproduces nowhere locally.

    At least one of these calls sets credentials to "include", which means the
    code already expects cookies to be there.

    evidence
      page: http://localhost:5173
      other-port endpoints called: localhost:3001
      host-only cookies that will not follow: connect.sid, XSRF-TOKEN
      after deployment: app.acme.com → api.acme.com: cookie not sent

    fix
      → Decide the production cookie scope now, not later. If the API must
        receive the session cookie, set an explicit Domain on the parent
        registrable domain (Domain=acme.com) so both subdomains match.
      → Then check the consequences of that scope: a parent-domain cookie is
        sent to every subdomain, including ones you do not control.
      → None of these choices can be tested on localhost, because localhost
        cannot express a parent-domain scope at all.

  … 3 more will-break findings
```

*(Real output from the Vite + Express starter in [`evidence/`](evidence/README.md), abridged.)*

---

## Commands

```
npx notlocalhost http://localhost:3000
npx notlocalhost http://localhost:3000 --flow ./login.js    # observe post-auth cookies
npx notlocalhost http://localhost:3000 --json               # CI
npx notlocalhost http://localhost:3000 --fail-on will-break # exit 1
```

Then open `notlocalhost-report.html`. One file, no server, opens from the
filesystem.

---

## Read this part: `--flow`

**Without a `--flow` script you are analyzing the logged-out page, and the
cookies that matter appear after login.**

On a stock Django install, the logged-out admin page sets `csrftoken` and
nothing else. Signing in reveals `sessionid` — the actual session cookie — and
takes the run from 6 findings to 8. On our fixture app the gap is wider: 30
findings without a flow, 38 with one, and four of the six session cookies exist
only on the authenticated side.

A flow script is a small Playwright function:

```js
// login.js
export default async ({ page }) => {
  await page.fill('#email', 'dev@example.com');
  await page.fill('#password', 'password');
  await page.click('button[type=submit]');
  await page.waitForURL('**/dashboard');
};
```

```
npx notlocalhost http://localhost:3000 --flow ./login.js
```

Instrumentation is already installed when your function receives the page, so
everything it touches is analyzed: the login POST, the redirect chain, the
session cookie that comes back, and every request the authenticated page makes.
If the script fails, the run still reports what it saw and says clearly that
coverage is incomplete.

**Coverage of findings equals coverage of the run.** That is the single most
important thing to understand about this tool.

---

## The problem

A real deployment is neither `localhost` nor plain HTTP. That gap hides a whole
class of bug until staging.

**`Secure` cookies cannot be set over plain HTTP.** So teams write
`secure: process.env.NODE_ENV === 'production'`, and from that moment the app
has two authentication paths: the one every developer exercises a hundred times
a day, and the one that actually runs in production, which is exercised by
nobody until it breaks. In the case of NextAuth the cookie *name* changes too,
so no local assertion is even about the same cookie.

**Cookies are not isolated by port.** RFC 6265 §8.5 says so outright, and the
`Set-Cookie` grammar has no port attribute. A host-only cookie set by
`localhost:3000` is sent to `localhost:4000` — same host. So bare localhost
either over-shares between every app you run or cannot share at all, and neither
matches a real subdomain topology. [We reproduced both directions.](evidence/README.md#the-port-sharing-reproduction)

**You cannot create a parent-domain cookie scope on localhost.** Setting
`Domain=localhost` from `app.localhost` is rejected. Setting `Domain=.localhost`
from `localhost` is accepted but stored *host-only* — the leading dot is
stripped (RFC 6265 §5.2.3) and a domain-attribute equal to the request host
yields a host-only cookie (§5.3). The popular `app.localhost` / `api.localhost`
workaround does not do what people think it does; nothing can set a cookie both
of them read. [Verified, both directions.](evidence/README.md#verified-claims)

**`SameSite=None` without `Secure` is dropped**, not downgraded to `Lax`. Silently.

**Secure-context APIs behave differently — but not in the direction you expect.**
`http://localhost` *is* a secure context, so service workers, geolocation,
clipboard, WebAuthn, `crypto.subtle` and media devices all work locally and keep
working over HTTPS. They break when the app is served over **plain HTTP on a
real hostname**: a staging box, a preview URL without the `s`, or a proxy that
terminates TLS and forwards plain HTTP. We report it that way round.

**Mixed content never appears locally** — an `http://` page may load `http://`
subresources — and blocks everything once the page is HTTPS.

**OAuth redirect URIs and API base URLs left pointing at `localhost`** ship to
production and resolve to the *visitor's* loopback interface.

---

## What it found in five default scaffolds

Every app scaffolded from its official generator, with **no changes to its
security configuration**. Full tables, JSON and HTML reports in
[`evidence/`](evidence/README.md).

| Application | will-break | may-break | info |
|---|---|---|---|
| Next.js 16 (`create-next-app`) | **0** | 0 | 2 |
| Laravel Breeze 1.29 | 1 | 4 | 6 |
| Django 6.1.1 | 1 | 4 | 3 |
| Rails 8.1.3 | 1 | 2 | 3 |
| Vite 5 + Express 4 | **4** | 5 | 2 |

Three of the five ship a session cookie with no `Secure` attribute and an
environment-gated setting behind it: Laravel (`SESSION_SECURE_COOKIE`, absent
from the generated `.env`), Django (`SESSION_COOKIE_SECURE = False`), Rails
(`config.force_ssl`). **Rails 8 ships it commented out in `production.rb` too**,
so the intuition that development is insecure and production is fine does not
hold there. [Details](evidence/README.md#rails-8-is-the-sharpest-case).

A default Next.js app is genuinely clean — it sets no cookies at all. The
findings start when you add authentication. That negative result is in the
evidence too, because a tool that never says "nothing here" cannot be trusted
when it says "something here".

---

## Exit codes

```
notlocalhost http://localhost:3000 --fail-on will-break --json report.json
```

| Code | Name | Meaning |
|---|---|---|
| `0` | Clean | No findings at or above `--fail-on`. |
| `1` | Findings | One or more findings at or above `--fail-on`. |
| `2` | Unreachable | The target did not respond. Nothing was analyzed. |
| `5` | Tool failure | No usable browser, an internal error, or the report could not be written. |
| `64` | Usage error | Invalid or missing arguments. |

`--fail-on` accepts `will-break`, `may-break`, `info` or `none` (the default).
Codes are stable across minor versions.

### GitHub Action

```yaml
- uses: jay123anta/notlocalhost@v1
  with:
    url: http://localhost:3000
    flow: ./login.js
    fail-on: will-break
```

See [`action.yml`](action.yml) for all inputs and outputs. It uploads the HTML
report as an artifact and writes a summary to the job page.

---

## Options

| Option | Default | |
|---|---|---|
| `--flow <path>` | — | Playwright script that logs in. **Read [the section above](#read-this-part---flow).** |
| `--json [path]` | — | Schema-versioned document. No path means stdout. |
| `--html <path>` | `./notlocalhost-report.html` | Single-file report. `--no-html` to skip. |
| `--markdown <path>` | — | GitHub-flavoured summary. |
| `--fail-on <level>` | `none` | `will-break` \| `may-break` \| `info` \| `none` |
| `--domain <domain>` | `example.com` | Registrable domain to assume for deployment. |
| `--cross-site` | off | Assume each local port becomes a separate *site*, not a subdomain. |
| `--map <local=host>` | — | Pin one local origin, e.g. `--map localhost:3000=app.acme.com`. Repeatable. |
| `--map </path=host>` | — | A path prefix that becomes its own host in production — what a dev-server proxy hides. e.g. `--map /api=api.acme.com`. In Git Bash use `//api=...`. |
| `--timeout <ms>` | `30000` | Navigation timeout. |
| `--flow-timeout <ms>` | `60000` | Budget for the flow script. |
| `--settle <ms>` | `1200` | Quiet time after load before collecting. |
| `--no-port-scan` | off | Skip probing for other loopback dev servers. |
| `--headed` | off | Show the browser. Useful when a flow script misbehaves. |
| `--browser-path <p>` | — | Use this browser executable. |
| `--channel <name>` | — | `chrome` \| `chromium` \| `msedge` \| … |
| `--verbose` | off | Show info findings and full evidence. |
| `--quiet` | off | Exit code and files only. |

### The deployment model

Every prediction depends on an assumption about your production topology, so the
assumption is printed at the top of every report and you can change it.

By default, each distinct local port becomes a **subdomain of one registrable
domain** — `localhost:3000` → `app.example.com`, `localhost:4000` →
`svc-4000.example.com`. That is what most teams ship, and it makes two local
ports cross-origin but same-site.

`--cross-site` models the other common shape, where the API is a genuinely
different site and every shared cookie needs `SameSite=None; Secure`.

`--map` pins specific origins when you already know the answer:

```
npx notlocalhost http://localhost:5173 \
  --domain acme.com \
  --map localhost:5173=app.acme.com \
  --map localhost:3001=api.acme.com
```

---

## Honest limitations

Written before launch, and shipped inside every JSON document and HTML report
rather than only living here.

- **This predicts behaviour on a real HTTPS origin. It does not prove it.** The
  only proof is serving the app from that origin, over HTTPS, on a real
  hostname.
- **It only observes code paths that actually execute during the run.** Coverage
  of findings equals coverage of the run, which is why `--flow` matters more
  than any individual rule.
- **Chrome family only** (Chrome, Chromium, Edge). Firefox and Safari differ on
  SameSite defaults, cookie partitioning and secure-context edge cases.
- **A clean result means "no findings in what was exercised".** It never means
  "safe".
- **A single page load does not cover other routes.** Run it against the routes
  that matter.
- **Source scanning reads what the dev server served.** A production build may
  substitute different values, and code that did not load was not scanned. Every
  such finding quotes the line so you can check.
- **The registrable-domain calculation is a heuristic** for hosts outside a
  small built-in suffix table. We do not bundle the Public Suffix List; when the
  heuristic is used, the report says so.
- **The port probe only checks a fixed list of common dev ports** on
  `127.0.0.1`. A dev server on an unusual port will not be noticed.

---

## FAQ

**Why not just read the cookies in DevTools?**
You can, and you should. DevTools shows you what *is*; this tells you what
*changes*. The Application panel will not tell you that `connect.sid` is
host-only and therefore stops reaching your API when `:3001` becomes
`api.acme.com`, that `__Host-` was rejected for three separate reasons, that a
`redirect_uri` constant three bundles deep still says localhost, or that six
other dev servers on your machine are in the same cookie jar. It also does not
run in CI, does not produce a diffable artifact, and requires you to already
suspect the problem.

**Why not mkcert plus Caddy?**
That is a genuinely good setup, and if you already run it you are ahead. But it
is a fifteen-minute commitment that puts a trusted root CA on your machine,
before you know whether you have a problem worth solving. This is a zero-setup
diagnosis you run first. If it finds nothing, you have saved the fifteen
minutes. If it finds something, you now have a reason to spend them.

**Why not Herd, Valet, or Laragon?**
Those are development *environments* — they manage PHP versions, databases, web
servers and processes. This is not a development environment and will never try
to be. It manages nothing and installs nothing. If you already run Herd, this
still tells you which of your cookies will break, because Herd does not analyze
your application either. The two are complementary.

**Why not just deploy to staging?**
Because staging is a twelve-minute round trip and you will not do it for every
cookie flag. Also, staging usually shares production's config, so the branch you
are worried about — the *local* branch, the one that runs a hundred times a day
— never runs there either. And the class of finding here is silent by
construction: a rejected cookie produces no error, so a staging deploy may look
fine while a session quietly fails to start.

**Does it need my app's source code?**
No. It reads only what your dev server serves over HTTP, the same as any
browser. It never reads your repository and never modifies your application.

**Does it send anything anywhere?**
No. There is no account, no service, no telemetry, and no network access beyond
the URL you give it and the loopback port probe. It works offline. The one thing
it writes is the report file you asked for.

**Why `playwright-core` and not Playwright?**
`playwright-core` is 13 MB with zero dependencies of its own and does not
download a browser. `npx notlocalhost` should not pull 150 MB of Chromium onto
your machine to tell you about a cookie flag, so it finds the Chrome, Chromium
or Edge you already have. Cold `npx` from an empty cache to a finished analysis
measured **11.5 s** and **14 MB** on our reference machine.

**Why is my default Next.js app clean?**
Because it is. It sets no cookies and makes no cross-origin calls. Add
authentication and run it again.

---

## Near-zero dependencies

One runtime dependency: [`playwright-core`](https://www.npmjs.com/package/playwright-core),
which itself has zero. No argument parser, no colour library, no table
renderer, no test framework, no linter. `npm run lint` fails the build if a
second runtime dependency appears.

```
package size    58 kB
unpacked        186 kB   (24 files)
node_modules    14 MB    (playwright-core)
cold npx        11.5 s   install from empty cache + full analysis
```

---

## Contributing

```
git clone https://github.com/jay123anta/notlocalhost
cd notlocalhost && npm install
npm test              # unit, end-to-end against a live server, and the report
npm run lint          # syntax and the invariants above
npm run evidence      # re-verify every RFC claim against your browser
npm run fixture       # start the deliberately dishonest fixture app
```

The fixture app in [`test/fixtures/lying-app.mjs`](test/fixtures/lying-app.mjs)
implements every failure this tool detects, in one file, with comments. It is
the fastest way to understand the problem space.

New rules need: a stable id, a severity you can defend with a spec citation, the
exact evidence, and a fix. A rule that cannot cite why it is `will-break` is
`may-break`. See [`docs/rules.md`](docs/rules.md) for the full catalogue.

---

## What it does not do to your machine

It installs no certificate, changes no DNS, binds no privileged port, and writes
nothing outside the directory you run it in. It reads what your dev server
serves over HTTP, exactly as a browser does, and writes the report you asked for.

That constraint is the product, not a limitation. A diagnosis you can run
without thinking about it is one you will actually run.

---

## Licence

MIT © Jayanta Kr. Nath
