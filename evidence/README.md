# Evidence

Everything asserted in the project README is reproduced here. Nothing in this
directory is a claim about what browsers *should* do; it is a record of what
Chrome 152 actually did on 2026-09-04.

Contents:

- [Verified claims](#verified-claims) — the RFC facts, checked against a real browser
- [The port-sharing reproduction](#the-port-sharing-reproduction) — two dev servers, one cookie jar
- [Five starter applications](#five-starter-applications) — findings tables
- [Three concrete bugs](#three-concrete-bugs-localhost-hides) — with reproduction steps

Reproduce all of it:

```
npm run evidence          # the claim checks
npm run fixture           # the deliberately dishonest fixture app
node bin/notlocalhost.js http://localhost:3000 --flow ./evidence/login-flow.mjs
```

---

## Verified claims

`evidence/repro-port-sharing.mjs` starts throwaway loopback servers, drives a
real Chrome through them, and prints what each server received. Full transcript
in [`repro-port-sharing.txt`](repro-port-sharing.txt).

**9/9 claims confirmed against Google Chrome 152.0.7977.65.**

| # | Claim | Result | Mechanism |
|---|---|---|---|
| 1 | A cookie set by one localhost port is sent to a different localhost port | **confirmed** | RFC 6265 §8.5: cookies do not provide isolation by port. The `Set-Cookie` grammar has no port attribute. |
| 2 | A second app on another port can overwrite the first app's session cookie | **confirmed** | Same jar, keyed by host alone. |
| 3 | `Domain=.localhost` set from `app.localhost` is rejected | **confirmed** | Chrome refuses a `Domain` that resolves to a top-level domain. `localhost` is one, reserved by RFC 6761 §6.3. |
| 4 | `Domain=localhost` set from `app.localhost` is rejected | **confirmed** | Same. |
| 5 | Nothing set by `app.localhost` is readable by `api.localhost` | **confirmed** | The popular `app.localhost` / `api.localhost` split does **not** create a shared cookie scope. |
| 6 | `Domain=.localhost` set from bare `localhost` is stored **host-only** | **confirmed** | Stored with `domain: "localhost"`, not `".localhost"`. RFC 6265 §5.2.3 strips the leading dot; §5.3 step 6 makes a domain-attribute identical to the request host produce a host-only cookie. |
| 7 | …and it still does not reach `app.localhost` | **confirmed** | So neither direction works. There is no way to write a cookie that `localhost` and its subdomains share. |
| 8 | `SameSite=None` without `Secure` is dropped, not downgraded to `Lax` | **confirmed** | The cookie jar was empty afterwards. |
| 9 | `http://localhost` is a secure context | **confirmed** | `isSecureContext: true`, and `crypto.subtle`, `navigator.serviceWorker`, `navigator.clipboard`, `navigator.credentials` are all present. |

### Why claims 3–7 matter together

The README says *"You cannot create a parent-domain cookie scope on localhost.
RFC 6265 blocks it."* Claims 3–7 are the precise version of that sentence, and
they close both escape routes:

- Setting `Domain=localhost` **from a subdomain** is rejected outright.
- Setting `Domain=.localhost` **from `localhost` itself** is accepted — but the
  leading dot is stripped and the cookie is stored host-only, so it is a silent
  no-op rather than a parent scope. It reaches nothing new.

The trap is that the second case *looks* like it worked. `document.cookie`
shows the cookie, the response was a 200, nothing warned. It simply does not
have the scope the developer believes it has.

### The one nuance worth stating precisely

Claim 9 is the fact most write-ups get backwards. Secure-context APIs do **not**
break when you move from `http://localhost` to HTTPS — they work in both. They
break when the app is served over **plain HTTP on a real hostname**: a staging
box on `http://staging.internal`, a preview URL typed without the `s`, or a
reverse proxy that terminates TLS and forwards plain HTTP without telling the
app. notlocalhost reports it that way round.

---

## The port-sharing reproduction

Two servers, one machine, different ports:

```
server A (port 37301) set:  app_session=SECRET-FROM-PORT-A   (host-only, no Domain)
server B (port 37302) received Cookie: app_session=SECRET-FROM-PORT-A; wishful=parent-scope
```

Server B never asked for that cookie, has no relationship to server A, and may
belong to an entirely different project. It reads the session verbatim. The
reverse also holds — B set `app_session=OVERWRITTEN-BY-PORT-B` and A received
it on the next request.

Two consequences that developers hit for real:

1. **Leakage between unrelated local projects.** Any dev server you run can read
   any cookie any other dev server set, including session tokens. A malicious
   `npm run dev` in a cloned repo is enough.
2. **It is backwards from production.** Locally, different ports share cookies
   automatically. In production, `app.example.com` and `api.example.com` share
   cookies *only* if you set `Domain` deliberately. So the sharing behaviour you
   test is the opposite of the one you ship — which is
   [`cookie.host-only-stops-crossing`](../docs/rules.md), the rule that found the
   most interesting bug in the starter apps below.

---

## What `--flow` is worth, measured

The same target, with and without a login script:

| Target | Findings without `--flow` | With `--flow` | Cookies only the flow revealed |
|---|---|---|---|
| Django admin | 6 | **8** | `sessionid` — the actual session cookie |
| Laravel Breeze | 11 | 11 | none: Breeze sets both cookies on the login page itself |
| Fixture app | 30 | **38** | `connect.sid`, `remember_web_*`, `next-auth.session-token`, `XSRF-TOKEN` |

Laravel is the honest counter-example and worth keeping in the table: some
frameworks issue their session cookie before you authenticate, so a flow adds
nothing. You cannot know which kind you have without running both.

---

## Five starter applications

Each app was scaffolded from its official generator with **no modifications to
its security configuration**, then analyzed. Where the app has authentication,
a `--flow` script signed in first; the flow scripts are in
[`evidence/flows/`](flows/). Full JSON and HTML reports are in
[`evidence/runs/`](runs/).

| Application | Version | will-break | may-break | info | Flow | Cookies observed |
|---|---|---|---|---|---|---|
| Next.js (`create-next-app`, App Router, TS) | next 16.3.4, react 19.2.8 | **0** | 0 | 2 | none needed | *none* |
| Laravel Breeze (blade) | framework 10.50.3, breeze 1.29 | 1 | 4 | 6 | register + sign in | `laravel_session`, `XSRF-TOKEN` |
| Django (`startproject` + admin) | 6.1.1 | 1 | 4 | 3 | admin sign in | `sessionid`, `csrftoken` |
| Rails (`rails new` + `generate authentication`) | 8.1.3.1 | 1 | 2 | 2 | sign in | `_railsapp_session` |
| Vite + Express (conventional split) | vite 5.4.21, express 4.22.2 | **4** | 5 | 2 | sign in | `connect.sid`, `XSRF-TOKEN` |

### Which default scaffolds ship cookie configuration that breaks on a real origin

**Three of the five do. One ships no cookies at all. One ships four separate
problems.**

| Scaffold | Ships a session cookie without `Secure`? | The setting that controls it | Set in a stock install? |
|---|---|---|---|
| **Laravel Breeze** | yes — `laravel_session` and `XSRF-TOKEN` | `SESSION_SECURE_COOKIE` | **no** — absent from the generated `.env`, and `config/session.php` defaults it to `env('SESSION_SECURE_COOKIE')` |
| **Django** | yes — `sessionid` and `csrftoken` | `SESSION_COOKIE_SECURE`, `CSRF_COOKIE_SECURE` | **no** — both default to `False`; only `manage.py check --deploy` mentions it |
| **Rails 8** | yes — `_<app>_session` | `config.force_ssl` (or `config.assume_ssl` behind a proxy) | **no — and not in `production.rb` either**, see below |
| **Next.js** | n/a — the default app sets no cookies | — | — |
| **Vite + Express** | yes — `connect.sid` | `cookie.secure`, gated on `NODE_ENV` | **no**, and the express-session docs actively recommend the environment gate |

#### Rails 8 is the sharpest case

`config.force_ssl = true` is not set in `production.rb`, so the finding is not
confined to the development branch. A stock `rails new` on Rails 8.1.3.1 ships
this:

```ruby
# config/environments/production.rb, verbatim, lines 27-31

# Assume all access to the app is happening through a SSL-terminating reverse proxy.
# config.assume_ssl = true

# Force all access to the app over SSL, use Strict-Transport-Security, and use secure cookies.
# config.force_ssl = true
```

Both are **commented out**. Rails' own comment names the consequence — *"and use
secure cookies"* — so a stock Rails 8 app deployed as generated serves its
session cookie without `Secure` in production as well as development.

This is a defensible framework decision — Rails cannot know whether a proxy is
terminating TLS, and forcing SSL blindly breaks health checks — and the comments
are right there in the file. But it means the reassuring intuition, *"development
is insecure, production is fine"*, does not hold here, and nothing in a local run
would tell you.

The honest reading: **none of these scaffolds is negligent.** Every one of them
is doing the only thing it can, because a `Secure` cookie *cannot be set over
plain HTTP*. That is the whole problem. The framework is forced into an
environment branch, and the branch developers exercise a hundred times a day is
not the branch that runs in production.

### Next.js: the interesting negative result

A default `create-next-app` produces **zero** will-break and **zero** may-break
findings. It sets no cookies, calls no cross-origin endpoints, and touches no
secure-context APIs. There is nothing to get wrong yet.

This is worth stating plainly because it is the honest boundary of the tool: the
findings start the moment you add authentication, and the analyzer only sees
code that runs. Two loopback URLs did appear in Next's own devtools bundle —
both correctly classified as dev-server machinery and reported at `info`.

Classifying those two correctly is what `leak.dev-tooling`, the
`url-parser-base` role and the Turbopack chunk patterns exist for. Without them
a clean app reports two findings that are not defects.

### Vite + Express: the worst result, and the most typical

Four will-break findings from an app written the way the `cors` and
`express-session` READMEs suggest:

| Finding | What is actually wrong |
|---|---|
| `cookie.host-only-stops-crossing` | The SPA on `:5173` calls the API on `:3001` with `credentials: "include"`. Today the cookie is attached automatically because both are `localhost`. Deployed as `app.acme.com` + `api.acme.com`, a host-only cookie is not sent — **the API starts receiving unauthenticated requests**. |
| `cors.hardcoded-local-origin` | `cors({ origin: ['http://localhost:5173'] })`. That allowlist can only ever match a developer machine. |
| `leak.api-base` | `import.meta.env.VITE_API_URL \|\| 'http://localhost:3001'` — the fallback ships, and resolves to the *visitor's* loopback interface. |
| `cookie.port-sharing-hazard` | Six other dev servers were listening on this machine, all inside the same cookie jar. |

---

## Three concrete bugs localhost hides

### 1. The credentialed API call that silently loses its session

**Found in:** the Vite + Express starter. **Rule:** `cookie.host-only-stops-crossing`.

```js
// client — works perfectly on localhost
await fetch(`${API_BASE}/api/me`, { credentials: 'include' });
```

Locally `API_BASE` is `http://localhost:3001` and the page is
`http://localhost:5173`. Different ports, **same host**, so the host-only
`connect.sid` cookie is attached with no configuration at all. The call is
authenticated. Every test passes.

Deployed as `app.acme.com` calling `api.acme.com`, those are different hosts. A
host-only cookie is sent only to the exact host that set it. The request arrives
with **no cookie**, the API returns 401, and nothing in the browser console
explains why — the fetch succeeded, the server just did not recognise the caller.

The fix is a decision (`Domain=acme.com`, or move the API same-origin, or switch
to a bearer token) and **the decision cannot be tested on localhost**, because
localhost cannot express a parent-domain scope at all. That is claims 3–7 above.

### 2. Two authentication paths, only one of which anyone runs

**Found in:** Laravel Breeze, Django, Rails 8, and express-session — all four.
**Rule:** `cookie.two-auth-paths`.

```php
// Laravel config/session.php, unmodified
'secure' => env('SESSION_SECURE_COOKIE'),   // absent from the generated .env
```

```python
# Django settings.py, unmodified
SESSION_COOKIE_SECURE = False   # the default
CSRF_COOKIE_SECURE = False      # the default
```

```ruby
# Rails 8 config/environments/production.rb, unmodified
# config.force_ssl = true    # commented out, so secure cookies stay off
```

```js
// the express-session README's own recommendation
cookie: { secure: process.env.NODE_ENV === 'production' }
```

Every local sign-in exercises the `false` branch. The `true` branch — different
flags, and in NextAuth's case a *different cookie name* entirely
(`__Secure-next-auth.session-token`) — is first exercised by production traffic.
A green local test suite says nothing about it.

The sharpest version is NextAuth: because the cookie **name** changes with the
scheme, no assertion you write locally is even about the same cookie.

### 3. The `__Host-` cookie that is never stored

**Found in:** the fixture app, and it is the most common prefix mistake.
**Rules:** `cookie.host-prefix-violation` + `cookie.rejected-by-browser`.

```
Set-Cookie: __Host-csrf=8c1d0e; Path=/app; Domain=localhost; SameSite=Strict
```

Three violations of the `__Host-` contract at once: no `Secure`, a `Domain`
attribute, and a non-root `Path`. Chrome rejects it and stores nothing —
confirmed by `Network.responseReceivedExtraInfo`, which reported
`blockedReasons: ["InvalidPrefix"]`.

The failure is completely silent. No console error by default, no failed
request, no exception. The CSRF check just fails later, somewhere else, for
reasons that look unrelated. notlocalhost quotes Chrome's own reason code rather
than re-deriving the verdict.

---

## Run-to-run variance, observed

The same application analyzed twice does not always produce the same numbers.
Rails reported 3 info findings on one run and 2 on the next, from an identical
build of the analyzer.

The difference was the application, not the rules. The first run saw 336 KB of
assets; the second saw 158 KB, because the Rails asset pipeline had already
compiled and was serving from cache. The file containing the one absolute
self-origin URL was not served the second time, so `leak.self-origin-absolute`
did not fire.

Both runs were correct. Each reported exactly what the dev server gave the
browser. This is the clearest demonstration of the central limitation:
**coverage of findings equals coverage of the run.** For a finding to be stable,
the path that produces it has to be exercised -- with `--flow`, or by pointing
the analyzer at that route.

What did not move: the `will-break` and `may-break` counts were identical across
runs for all five applications. Cookie and header findings come from requests
that always happen. Only body-scanning findings vary.

---

## What these runs do not show

- Five apps is five apps. It is enough to demonstrate the failure class and to
  find real false positives; it is not a survey.
- Every finding is from a **single route** per app, plus whatever the `--flow`
  script touched. Other routes were not exercised and could not be assessed.
- All runs were on Windows 11 with Chrome 152. The rules are engine-level, but
  cookie behaviour has changed before and will change again.
- Body-scanning findings vary between runs, as above. Cookie and header findings
  are stable.
- The starter apps were scaffolded on 2026-09-04. Defaults move. If a table above
  disagrees with a scaffold you generate today, the scaffold is right and this
  file is stale — please open an issue.
