# Rule catalogue

Every finding carries a stable `id`. Ids do not change within a major version,
so they are safe to grep for, allowlist, or assert on in CI.

## Severity, and what it promises

| Severity | The promise |
|---|---|
| `will-break` | This behaves differently on a real HTTPS origin, and the difference is defined by a specification or by shipped browser behaviour. If a rule says `will-break`, the entry below cites the clause. |
| `may-break` | It depends on something not visible from here: your deployment topology, your proxy, your production configuration. |
| `info` | Worth knowing. Not a defect. |

Nothing is promoted to `will-break` to make output look impressive. A rule that
cannot cite why it is `will-break` is `may-break`. That is the review standard
for new rules.

---

## Cookies

### `cookie.samesite-none-without-secure` — will-break
`SameSite=None` without `Secure`. Chrome rejects the cookie outright rather than
downgrading it to `Lax`, so it is never stored at all.
**Cite:** RFC 6265bis §5.4.7. **Verified:** [claim 8](../evidence/README.md#verified-claims).

### `cookie.host-prefix-violation` — will-break
A `__Host-` cookie that breaks the prefix contract: missing `Secure`, carrying a
`Domain` attribute, or using a `Path` other than `/`. The browser refuses to
store it, silently. Lists every violation it found rather than the first.
**Cite:** RFC 6265bis §4.1.3.

### `cookie.secure-prefix-violation` — will-break
A `__Secure-` cookie with no `Secure` attribute. Same silent rejection.
**Cite:** RFC 6265bis §4.1.3.

### `cookie.domain-localhost` — will-break
`Domain=localhost` or `Domain=.localhost`. Explains why this cannot create the
parent scope it looks like it creates: the leading dot is stripped (§5.2.3), and
a domain-attribute equal to the request host yields a host-only cookie (§5.3).
From a subdomain it is rejected outright.
**Cite:** RFC 6265 §5.1.3, §5.3; RFC 6761 §6.3.
**Verified:** [claims 3–7](../evidence/README.md#verified-claims).

### `cookie.rejected-by-browser` — will-break
Chrome refused to store a cookie during this run and said why. Not a prediction:
the reason codes come from `Network.responseReceivedExtraInfo.blockedCookies`,
translated into a fix. When this fires alongside a rule above, the two agree —
one derived, one observed.

### `cookie.port-sharing-hazard` — will-break when other listeners are found, else info
Host-only cookies are shared by every port answering to the same hostname.
Cookies have no port concept; the `Set-Cookie` grammar has no port attribute.
Names the other dev servers that are currently inside the same jar.

Fires only on `localhost`, `127.x.x.x` and `::1`, which is the jar those
neighbours share. A page on `app.myproject.localhost` is loopback too, but the
jar is keyed by name, so it shares nothing with them and the port scan is
skipped rather than reported as empty.
**Cite:** RFC 6265 §8.5. **Verified:** [claims 1–2](../evidence/README.md#the-port-sharing-reproduction).

### `cookie.host-only-stops-crossing` — will-break when credentialed, else may-break
The port-sharing fact turned around, and the most expensive finding in the tool.
Requests to another local port carry host-only cookies today because it is the
same host. After deployment those ports are separate hostnames and the cookie is
not sent, so the request arrives unauthenticated with no browser-side error.
**Cite:** RFC 6265 §5.1.3 (host-only flag). **Found in:** the Vite + Express starter.

### `cookie.two-auth-paths` — may-break
A session cookie from a framework whose `Secure` flag is an environment setting,
observed without `Secure`. Names the framework and the exact setting. The
strongest variant is a framework that changes the cookie *name* between schemes
(NextAuth's `__Secure-next-auth.session-token`), because then no local assertion
is even about the same cookie.

### `cookie.two-auth-paths-source` — may-break
A security attribute gated on an environment check, found by scanning the code
the dev server actually served. Quotes the line. This is pattern matching, so it
can hit a comment, a vendored library or dead code — check the quote.

### `cookie.missing-secure` — may-break
A session-shaped cookie with no `Secure` attribute. Over plain HTTP it could not
have one, which is exactly the point: whatever sets it in production is a code
path that did not run. Skips `__Host-`/`__Secure-` cookies, whose prefix rules
already report this at `will-break`.

### `cookie.missing-httponly` — info
A session-shaped cookie readable by JavaScript. Unrelated to the HTTPS move, but
it travels with it. Skips CSRF tokens, which are readable by design.

### `cookie.samesite-unspecified` — info
Cookies relying on the browser's default `SameSite`. Chrome treats it as `Lax`;
other engines have not always agreed.

### `cookie.set-from-script` — info
Cookies written via `document.cookie`. These can never be `HttpOnly`, and on a
real origin they additionally need `Secure` — so the string being assembled
locally is not the production string.

### `cookie.inventory` — info
Every cookie observed, with all attributes and its effective `SameSite`.

---

## Origins, CORS and credentials

### `cors.wildcard-with-credentials` — will-break
`Access-Control-Allow-Origin: *` together with `Access-Control-Allow-Credentials:
true`. The Fetch standard forbids the combination; the response is not exposed.
Reads headers from `responseReceivedExtraInfo`, because Chrome fires no
`responseReceived` event at all for a CORS-blocked response.
**Cite:** Fetch Standard, CORS protocol.

### `cors.blocked-by-browser` — will-break
Chrome blocked a request on CORS grounds during this run and named the error.
Each code is translated into what actually went wrong and what to change.

### `cors.hardcoded-local-origin` — will-break
A CORS allowlist naming a loopback origin. It can only ever match a developer
machine. **Found in:** the Vite + Express starter.

### `cors.missing` — will-break when credentialed, else may-break
Responses with no `Access-Control-Allow-Origin` on requests that become
cross-origin after deployment. Correct today, because the request is
same-origin and CORS does not apply -- the browser never asks. That is what
makes it the failure localhost hides most completely: no warning, no console
message, no failing test, because nothing is wrong yet. The header is absent
precisely because it is not needed.

Requires `--map /path=host` to model the split, since a dev-server proxy makes
the API same-origin locally while production serves it from its own host.
**Cite:** Fetch Standard, CORS protocol.

### `cors.wildcard` — info
`Access-Control-Allow-Origin: *` on its own. Fine for public resources; worth
knowing before the front-end changes origin.

### `origin.becomes-cross-site` / `origin.becomes-cross-origin` — will-break when credentialed, else may-break
A boundary that changes on deployment. Cross-site additionally requires
`SameSite=None; Secure` on the cookies and `Allow-Credentials` with an exact
`Allow-Origin` on the responses.

### `origin.credentialed-cross-site` — will-break
Calls that opt into sending cookies (`credentials: "include"`, or XHR
`withCredentials`) whose target is a different site under the assumed
deployment model.

### `origin.inventory` — info
Every origin contacted, classified as it is today and as it would be after
deployment.

### `origin.site-heuristic` — info
Fires when a same-site decision used the last-two-labels fallback rather than a
known public suffix. Says which hosts, so you can discount those classifications.

---

## Secure context

### `securecontext.apis-used` — may-break when a high-impact API is touched, else info
Which secure-context-only APIs the page actually touched, and what each one does
on plain HTTP.

**The direction matters and most write-ups get it backwards.** `http://localhost`
*is* a secure context, so these work locally and keep working over HTTPS. They
break when the app is served over **plain HTTP on a real hostname** — a staging
box, a preview URL without the `s`, or a proxy that terminates TLS and forwards
plain HTTP. This rule reports that failure mode, not a fictional HTTPS one.
**Cite:** W3C Secure Contexts. **Verified:** [claim 9](../evidence/README.md#verified-claims).

Instrumented: `navigator.serviceWorker`, `geolocation`, `clipboard`,
`credentials`, `mediaDevices`, `storage`, `locks`, `usb`, `bluetooth`, `hid`,
`serial`, and `crypto.subtle`.

### `securecontext.untested-branch` — info
The app reads `window.isSecureContext`. On localhost that is always `true`, so
only one side of the branch ever runs in development.

---

## Mixed content

### `mixedcontent.active` — will-break
Plain-HTTP scripts, stylesheets, fetch/XHR, WebSockets or iframes. Blocked
unconditionally once the page is HTTPS, with no user override. Cannot appear
locally, because an `http://` page may load `http://` subresources.
**Cite:** W3C Mixed Content.

### `mixedcontent.passive` — may-break
Plain-HTTP images, media and fonts. Autoupgraded to `https://` and blocked if
the upgrade fails.

### `mixedcontent.chrome-issue` — may-break
Mixed-content issues Chrome raised itself, via the DevTools Issues channel.

---

## Leaked local URLs

All of these come from scanning response bodies the dev server actually served.
Ids are `leak.<role>`.

| Id | Severity | What it means |
|---|---|---|
| `leak.oauth-redirect` | will-break | A `redirect_uri` or callback URL pinned to localhost. Registered byte-for-byte with an identity provider, so it fails in production — or worse, stays registered on a production client as an open-redirect surface. |
| `leak.api-base` | will-break | An API base URL on loopback. In production it resolves to the *visitor's* machine. |
| `leak.cors-allowlist` | may-break | An allowlist entry that can only match a dev machine. |
| `leak.websocket` | may-break | A `ws://` endpoint. Blocked as mixed content once the page is HTTPS. |
| `leak.asset-host` | may-break | An asset URL on loopback or plain HTTP. |
| `leak.self-origin-absolute` | info | Absolute URLs pointing back at the page's own origin — `asset()`, `route()`, `*_url`, `build_absolute_uri`. These follow the deployed host, so they break only if a base-URL setting (`APP_URL`, `NEXTAUTH_URL`, `default_url_options`) still says localhost in production. |
| `leak.url-parser-base` | info | A bare `http://localhost` with no port and no path — nearly always a sentinel base for the `URL` constructor. |
| `leak.dev-tooling` | info | HMR clients, live-reload sockets and dev overlays. Listed so the numbers reconcile and you can see what was excluded. |
| `leak.unclassified` | info | A loopback URL with no obvious role. |

### How role classification works

A URL is classified by the identifier immediately before it — the `apiUrl` in
`apiUrl: "http://localhost:3001"` — using a deliberately narrow window. A wide
window would let an unrelated key on the next line hijack the role.

A URL matching the page's own origin is downgraded to `leak.self-origin-absolute`
**unless** an identifier named it. A `redirect_uri` is a constant wherever it
happens to point; an `<a href>` is generated.

Context snippets are redacted for JWTs, common token prefixes, AWS keys and
`password:`/`secret:`/`authorization:` values before they reach the report,
because reports get pasted into issues.

---

## Adding a rule

1. A stable, namespaced id.
2. A severity you can defend. `will-break` needs a spec citation or reproduced
   browser behaviour; if you cannot produce one, it is `may-break`.
3. Exact evidence — the header, the line, the URL. Never a paraphrase.
4. A fix that says what to change.
5. A test in `test/unit.test.js` for the logic and, where it needs a live page,
   `test/e2e.test.js`.
6. An entry here.

Rules run in isolation: if one throws, the other four modules still report, and
the failure is surfaced as a warning rather than swallowed.
