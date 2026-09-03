/**
 * A deliberately dishonest dev server.
 *
 * Every one of these mistakes is real -- each is copied from a default
 * scaffold, a popular tutorial, or a Stack Overflow answer with four figures of
 * upvotes. Locally the app works perfectly, which is the point. It exists so
 * the rules have something to find without needing the internet, and so a
 * reader can see the whole failure class in one file.
 *
 * Zero dependencies: node:http only.
 *
 *   node test/fixtures/lying-app.mjs [--port 3000] [--api-port 4000]
 */
import { createServer } from 'node:http';

const args = process.argv.slice(2);
const argOf = (name, fallback) => {
  const i = args.indexOf(name);
  return i >= 0 && args[i + 1] ? args[i + 1] : fallback;
};

const PORT = Number(argOf('--port', 3000));
const API_PORT = Number(argOf('--api-port', 4000));
const QUIET = args.includes('--quiet');

const log = (...a) => {
  if (!QUIET) console.log(...a);
};

// ---------------------------------------------------------------- the app --

const APP_JS = `
// A bundler would substitute process.env.NODE_ENV at build time. This server
// serves raw source, so shim it -- otherwise the reference throws and the rest
// of the file never runs, which is a fixture bug rather than an app bug.
window.process = window.process || { env: { NODE_ENV: 'development' } };

// A configuration block of the kind that ships to production every day.
const config = {
  // Hardcoded API base. In production this resolves to the *visitor's* machine.
  apiUrl: "http://localhost:${API_PORT}/api",
  // Hardcoded OAuth redirect. Registered with the IdP and then forgotten about.
  oauth: {
    authorizeUrl: "https://accounts.example.com/o/authorize",
    redirect_uri: "http://localhost:${PORT}/auth/callback",
    client_id: "demo-client"
  },
  // ws:// is blocked as mixed content the moment the page is HTTPS.
  socketUrl: "ws://localhost:${PORT}/socket",
  assetHost: "http://cdn.invalid.example/assets",
  allowedOrigins: ["http://localhost:${PORT}", "http://localhost:5173"]
};

// The two-auth-paths pattern, in the exact shape teams write it.
const cookieOptions = {
  httpOnly: true,
  secure: process.env.NODE_ENV === 'production',
  sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax'
};

// Secure-context APIs. All of these work on http://localhost and would be
// undefined if this app were served over plain HTTP on a real hostname.
async function useSecureApis() {
  if (navigator.clipboard) { /* copy button */ }
  if (navigator.geolocation) { /* nearby search */ }
  if (navigator.serviceWorker) { /* offline mode */ }
  if (navigator.mediaDevices) { /* avatar capture */ }
  if (navigator.credentials) { /* passkey sign-in */ }
  try { await crypto.subtle.digest('SHA-256', new Uint8Array([1,2,3])); } catch (e) {}
  if (window.isSecureContext) { /* the branch that always wins locally */ }
}

// A client-side cookie with no Secure attribute. It cannot have one here.
document.cookie = "theme=dark; Path=/; SameSite=Lax";
document.cookie = "client_uid=abc123def456; Path=/; Max-Age=31536000";

// A credentialed call to another local port. Same host today, a different
// hostname after deployment.
async function callApi() {
  try {
    await fetch(config.apiUrl + "/me", { credentials: "include" });
  } catch (e) { /* offline in tests */ }

  const xhr = new XMLHttpRequest();
  xhr.withCredentials = true;
  xhr.open("GET", config.apiUrl + "/session");
  try { xhr.send(); } catch (e) {}
}

function connectSocket() {
  try { new WebSocket(config.socketUrl); } catch (e) {}
}

useSecureApis();
callApi();
connectSocket();
window.__appReady = true;
`;

const PAGE = (loggedIn) => `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Lying app</title></head>
<body>
<h1>A perfectly working local app</h1>
<p>Status: ${loggedIn ? 'signed in' : 'signed out'}</p>

<!-- Mixed content: an http:// image from a host that is not this one. -->
<img src="http://assets.invalid.example/logo.png" alt="" width="1" height="1">
<script src="http://analytics.invalid.example/tag.js"></script>

<form id="login" method="POST" action="/login">
  <input id="email" name="email" value="">
  <input id="password" name="password" type="password" value="">
  <button type="submit">Sign in</button>
</form>

<script src="/app.js"></script>
</body></html>`;

/** Cookies set on the very first page load, before any authentication. */
const ANON_COOKIES = [
  // No Secure -- it could not have one over plain HTTP.
  'sid=anon-9f2b41c7; Path=/; HttpOnly; SameSite=Lax',
  // SameSite=None without Secure: Chrome rejects this outright.
  'ab_test=variant-b; Path=/; SameSite=None',
  // __Host- prefix with both a Domain and a non-root Path: two violations.
  '__Host-csrf=8c1d0e; Path=/app; Domain=localhost; SameSite=Strict',
  // __Secure- prefix with no Secure attribute.
  '__Secure-pref=compact; Path=/; SameSite=Lax',
  // Domain=localhost: does not create a parent scope, and cannot.
  'shared_hint=1; Path=/; Domain=.localhost',
];

/** Cookies that only appear after login. Invisible without --flow. */
const AUTH_COOKIES = [
  'connect.sid=s%3AVQ0h7nZ2.rEal5essi0n; Path=/; HttpOnly; SameSite=Lax',
  'remember_web_59ba36=eyJpdiI6IkFC; Path=/; HttpOnly; SameSite=Lax; Max-Age=2592000',
  'next-auth.session-token=eyJhbGciOiJkaXIi.demo; Path=/; HttpOnly; SameSite=Lax',
  'XSRF-TOKEN=WQ9zK1pL; Path=/; SameSite=Lax',
];

const app = createServer((req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`);
  const cookies = req.headers.cookie ?? '';
  const loggedIn = cookies.includes('connect.sid');

  if (url.pathname === '/app.js') {
    res.writeHead(200, { 'content-type': 'application/javascript; charset=utf-8' });
    res.end(APP_JS);
    return;
  }

  if (url.pathname === '/login' && req.method === 'POST') {
    let body = '';
    req.on('data', (c) => (body += c));
    req.on('end', () => {
      res.writeHead(302, { location: '/dashboard', 'set-cookie': AUTH_COOKIES });
      res.end();
    });
    return;
  }

  if (url.pathname === '/dashboard') {
    res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
    res.end(PAGE(true));
    return;
  }

  if (url.pathname === '/') {
    res.writeHead(200, {
      'content-type': 'text/html; charset=utf-8',
      'set-cookie': ANON_COOKIES,
    });
    res.end(PAGE(loggedIn));
    return;
  }

  res.writeHead(404, { 'content-type': 'text/plain' });
  res.end('not found');
});

// --------------------------------------------------------------- the API --
// A second server on a second port. Same host, therefore the same cookie jar:
// it can read every cookie the app above set, and overwrite any of them.

const api = createServer((req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`);

  if (url.pathname === '/api/whoami') {
    // Proof of the port-sharing hazard: this server, which the page never
    // asked for, receives the app's cookies verbatim.
    res.writeHead(200, {
      'content-type': 'application/json',
      'access-control-allow-origin': '*',
      'access-control-allow-credentials': 'true',
    });
    res.end(JSON.stringify({ cookiesTheApiCanSee: req.headers.cookie ?? null }));
    return;
  }

  if (url.pathname === '/api/hijack') {
    // And overwrite one, from a completely unrelated app.
    res.writeHead(200, {
      'content-type': 'application/json',
      'set-cookie': 'sid=overwritten-by-port-' + API_PORT + '; Path=/',
      'access-control-allow-origin': '*',
    });
    res.end(JSON.stringify({ ok: true }));
    return;
  }

  res.writeHead(200, {
    'content-type': 'application/json',
    // Wildcard plus credentials: forbidden by the Fetch standard, invisible
    // locally because the request is same-site.
    'access-control-allow-origin': '*',
    'access-control-allow-credentials': 'true',
  });
  res.end(JSON.stringify({ ok: true, seenCookies: req.headers.cookie ?? null }));
});

const started = [];

export function start() {
  return new Promise((resolve) => {
    let pending = 2;
    const done = () => {
      if (--pending === 0) resolve({ appUrl: `http://localhost:${PORT}`, apiUrl: `http://localhost:${API_PORT}` });
    };
    app.listen(PORT, '127.0.0.1', () => {
      started.push(app);
      log(`  app  http://localhost:${PORT}`);
      done();
    });
    api.listen(API_PORT, '127.0.0.1', () => {
      started.push(api);
      log(`  api  http://localhost:${API_PORT}`);
      done();
    });
  });
}

export function stop() {
  return Promise.all(started.map((s) => new Promise((r) => s.close(r))));
}

// Run directly, or import for tests.
if (import.meta.url === `file://${process.argv[1]?.replace(/\\/g, '/')}` || process.argv[1]?.endsWith('lying-app.mjs')) {
  start().then(() => log('\n  A perfectly working local app. Point notlocalhost at it.\n'));
}
