import { test, describe, before, after } from 'node:test';
import http from 'node:http';
import net from 'node:net';
import assert from 'node:assert/strict';

import { parseSetCookie, splitSetCookieHeader, effectiveSameSite } from '../src/collect/cookie-parser.js';
import {
  registrableDomain,
  sameOrigin,
  sameSite,
  isLoopbackHost,
  sharesDefaultCookieJar,
  parseOrigin,
  createDeploymentModel,
  classifyRequest,
} from '../src/collect/origins.js';
import { scanForLocalUrls, isScannableMime } from '../src/collect/leaked-urls.js';
import {
  scanSourceForConditionalFlags,
  inspectCookieForConditionalFlags,
} from '../src/collect/conditional-flags.js';
import { scanLoopbackPorts, describeSystemPort, speaksHttp } from '../src/collect/port-scan.js';
import { cookieRules } from '../src/rules/cookies.js';
import { analyseTapOutput } from '../scripts/check-test-output.mjs';
import { finding, atOrAbove, sortFindings, severityRank } from '../src/rules/finding.js';
import { parseArgs, run } from '../src/cli.js';
import { _internal as sessionInternal } from '../src/session.js';
import { locateBrowser, resolveBrowserExecutable } from '../src/browser/locate.js';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { EXIT } from '../src/exit-codes.js';
import { shouldFail } from '../src/analyze.js';
import { renderHtml } from '../src/report/html.js';
import { renderJson, renderMarkdown } from '../src/report/json.js';
import { renderTerminal, _internal as termInternal } from '../src/report/terminal.js';
import { SCHEMA_VERSION } from '../src/version.js';

describe('Set-Cookie parsing (RFC 6265 section 5.2)', () => {
  test('parses name, value and the common attributes', () => {
    const c = parseSetCookie('sid=abc123; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=3600');
    assert.equal(c.name, 'sid');
    assert.equal(c.value, 'abc123');
    assert.equal(c.path, '/');
    assert.equal(c.httpOnly, true);
    assert.equal(c.secure, true);
    assert.equal(c.sameSite, 'Lax');
    assert.equal(c.maxAge, 3600);
  });

  test('attribute names are case-insensitive', () => {
    const c = parseSetCookie('a=1; SECURE; httponly; samesite=STRICT');
    assert.equal(c.secure, true);
    assert.equal(c.httpOnly, true);
    assert.equal(c.sameSite, 'STRICT');
    assert.equal(effectiveSameSite(c), 'Strict');
  });

  test('a leading dot on Domain is stripped, per 5.2.3', () => {
    const dotted = parseSetCookie('a=1; Domain=.example.com');
    const bare = parseSetCookie('a=1; Domain=example.com');
    assert.equal(dotted.domain, 'example.com');
    assert.equal(bare.domain, 'example.com');
    assert.equal(dotted.domainWasDotted, true);
    assert.equal(bare.domainWasDotted, false);
  });

  test('an empty Domain attribute is ignored, leaving a host-only cookie', () => {
    assert.equal(parseSetCookie('a=1; Domain=').domain, null);
  });

  test('a header with no equals sign in the first pair is discarded', () => {
    assert.equal(parseSetCookie('justaname; Path=/'), null);
    assert.equal(parseSetCookie(''), null);
  });

  test('an empty value is legal', () => {
    const c = parseSetCookie('a=; Path=/');
    assert.equal(c.name, 'a');
    assert.equal(c.value, '');
  });

  test('name prefixes are recognised', () => {
    assert.equal(parseSetCookie('__Host-a=1').prefix, '__Host-');
    assert.equal(parseSetCookie('__Secure-a=1').prefix, '__Secure-');
    assert.equal(parseSetCookie('a=1').prefix, null);
  });

  test('there is no port attribute to parse, because cookies have no ports', () => {
    const c = parseSetCookie('a=1; Port=3000');
    assert.equal(c.unknownAttributes.port, '3000');
    assert.ok(!('port' in c), 'a port must never become a first-class cookie property');
  });

  test('Expires contains a comma, so Set-Cookie headers split on newline not comma', () => {
    const lines = splitSetCookieHeader('a=1; Expires=Wed, 09 Jun 2027 10:18:14 GMT\nb=2; Path=/');
    assert.equal(lines.length, 2);
    assert.equal(parseSetCookie(lines[0]).name, 'a');
    assert.equal(parseSetCookie(lines[1]).name, 'b');
  });

  test('effective SameSite: None without Secure is rejected, not downgraded', () => {
    assert.equal(effectiveSameSite(parseSetCookie('a=1; SameSite=None')), 'rejected');
    assert.equal(effectiveSameSite(parseSetCookie('a=1; SameSite=None; Secure')), 'None');
    assert.equal(effectiveSameSite(parseSetCookie('a=1')), 'Lax (browser default)');
  });
});

describe('origin and site classification', () => {
  test('loopback hosts are recognised, including the reserved .localhost TLD', () => {
    for (const h of ['localhost', 'app.localhost', 'API.LOCALHOST', '127.0.0.1', '127.1.2.3', '::1']) {
      assert.equal(isLoopbackHost(h), true, `${h} should be loopback`);
    }
    for (const h of ['example.com', 'localhost.example.com', '192.168.1.5']) {
      assert.equal(isLoopbackHost(h), false, `${h} should not be loopback`);
    }
  });

  // The two predicates look alike and mean different things. Conflating them
  // is what put a cookie hazard on hostnames that cannot have one.
  test('the shared cookie jar is narrower than loopback', () => {
    for (const h of ['localhost', 'LOCALHOST', '127.0.0.1', '127.1.2.3', '::1', '[::1]']) {
      assert.equal(sharesDefaultCookieJar(h), true, `${h} is in the common jar`);
    }
    for (const h of ['app.localhost', 'api.myproject.localhost']) {
      assert.equal(isLoopbackHost(h), true, `${h} is still loopback`);
      assert.equal(sharesDefaultCookieJar(h), false, `${h} has a jar of its own`);
    }
    for (const h of ['example.com', '192.168.1.5', '', null, undefined]) {
      assert.equal(sharesDefaultCookieJar(h), false, `${h} is not local at all`);
    }
  });

  test('registrable domain handles known multi-label suffixes', () => {
    assert.equal(registrableDomain('a.b.example.com').domain, 'example.com');
    assert.equal(registrableDomain('shop.example.co.uk').domain, 'example.co.uk');
    assert.equal(registrableDomain('my-app.vercel.app').domain, 'my-app.vercel.app');
    assert.equal(registrableDomain('example.com').domain, 'example.com');
  });

  test('unknown suffixes fall back to two labels and say so', () => {
    const r = registrableDomain('a.b.example.zzz');
    assert.equal(r.domain, 'example.zzz');
    assert.equal(r.exact, false);
  });

  test('IP literals are their own site', () => {
    assert.equal(registrableDomain('127.0.0.1').domain, '127.0.0.1');
    assert.equal(registrableDomain('127.0.0.1').exact, true);
  });

  test('different ports are different origins but the same site', () => {
    assert.equal(sameOrigin('http://localhost:3000/a', 'http://localhost:4000/b'), false);
    assert.equal(sameSite('http://localhost:3000/a', 'http://localhost:4000/b'), true);
  });

  test('same-site is schemeful', () => {
    assert.equal(sameSite('http://example.com', 'https://example.com'), false);
    assert.equal(sameSite('https://a.example.com', 'https://b.example.com'), true);
  });

  test('default port is filled in so :80 and bare are the same origin', () => {
    assert.equal(sameOrigin('http://example.com', 'http://example.com:80'), true);
    assert.equal(parseOrigin('https://example.com').port, '443');
  });
});

describe('deployment model', () => {
  test('the first local origin becomes app.<domain>, later ones get their port', () => {
    const m = createDeploymentModel({ domain: 'acme.com' });
    assert.equal(m.hostnameFor('localhost:3000'), 'app.acme.com');
    assert.equal(m.hostnameFor('localhost:4000'), 'svc-4000.acme.com');
    assert.equal(m.hostnameFor('localhost:3000'), 'app.acme.com', 'must be stable across calls');
  });

  test('explicit --map wins', () => {
    const m = createDeploymentModel({ domain: 'acme.com', explicit: { 'localhost:8000': 'api.other.com' } });
    assert.equal(m.hostnameFor('localhost:8000'), 'api.other.com');
  });

  test('the default model keeps two local ports same-site', () => {
    const m = createDeploymentModel({ domain: 'acme.com' });
    const c = classifyRequest('http://localhost:3000/', 'http://localhost:4000/api', m);
    assert.equal(c.then.sameSite, true);
    assert.equal(c.then.sameOrigin, false);
    assert.equal(c.becomesCrossSite, false);
  });

  test('--cross-site makes them different sites', () => {
    const m = createDeploymentModel({ domain: 'acme.com', crossSite: true });
    const c = classifyRequest('http://localhost:3000/', 'http://localhost:4000/api', m);
    assert.equal(c.then.sameSite, false);
  });

  test('a mapped path prefix becomes its own host', () => {
    const m = createDeploymentModel({ domain: 'acme.com', paths: { '/api': 'api.acme.com' } });
    assert.equal(m.project('http://localhost:3000/api/me'), 'https://api.acme.com/api/me');
    assert.equal(m.project('http://localhost:3000/'), 'https://app.acme.com/');
  });

  test('a same-origin call to a mapped path becomes cross-origin after deployment', () => {
    // Without this the CORS headers that localhost's origin masks stay
    // invisible: the request is same-origin today, so nothing is missing yet.
    const m = createDeploymentModel({ domain: 'acme.com', paths: { '/api': 'api.acme.com' } });
    const c = classifyRequest('http://localhost:3000/', 'http://localhost:3000/api/me', m);
    assert.equal(c.now.sameOrigin, true);
    assert.equal(c.then.sameOrigin, false);
    assert.equal(c.becomesCrossOrigin, true);
  });

  test('the longest matching path prefix wins', () => {
    const m = createDeploymentModel({
      domain: 'acme.com',
      paths: { '/api': 'api.acme.com', '/api/v2': 'v2.acme.com' },
    });
    assert.equal(m.project('http://localhost:3000/api/v2/x'), 'https://v2.acme.com/api/v2/x');
    assert.equal(m.project('http://localhost:3000/api/v1/x'), 'https://api.acme.com/api/v1/x');
  });

  test('a prefix matches a path segment, not a substring', () => {
    const m = createDeploymentModel({ domain: 'acme.com', paths: { '/api': 'api.acme.com' } });
    assert.equal(m.project('http://localhost:3000/api'), 'https://api.acme.com/api');
    assert.equal(m.project('http://localhost:3000/apiary'), 'https://app.acme.com/apiary');
  });

  test('an already-real origin is left alone', () => {
    const m = createDeploymentModel({ domain: 'acme.com' });
    assert.equal(m.project('https://cdn.example.com/x.js'), 'https://cdn.example.com/x.js');
  });

  test('ws:// projects to wss://', () => {
    const m = createDeploymentModel({ domain: 'acme.com' });
    assert.ok(m.project('ws://localhost:3000/socket').startsWith('wss://'));
  });
});

describe('leaked local URL scanning', () => {
  const scan = (body, url = 'http://localhost:3000/app.js') =>
    scanForLocalUrls({ url, body, kind: 'script' });

  test('classifies an OAuth redirect URI', () => {
    const hits = scan('const redirect_uri = "http://localhost:3000/auth/callback";');
    assert.equal(hits[0].role, 'oauth-redirect');
    assert.equal(hits[0].severityHint, 'will-break');
  });

  test('classifies an API base URL from the surrounding key', () => {
    const hits = scan('export const apiUrl = "http://localhost:8000/api";');
    assert.equal(hits[0].role, 'api-base');
  });

  test('classifies a websocket endpoint', () => {
    const hits = scan('new WebSocket("ws://localhost:3000/socket")');
    assert.equal(hits[0].role, 'websocket');
  });

  test('finds a bare host:port with no scheme', () => {
    const hits = scan('const host = "localhost:5432";');
    assert.ok(hits.some((h) => h.url === 'localhost:5432'));
  });

  test('marks dev-server machinery as dev tooling rather than a shipped leak', () => {
    const hits = scanForLocalUrls({
      url: 'http://localhost:5173/@vite/client',
      body: 'const socketHost = "localhost:5173";',
      kind: 'script',
    });
    assert.equal(hits[0].devTooling, true);
  });

  test('redacts credentials that happen to sit next to the URL', () => {
    const hits = scan('fetch("http://localhost:3000/x", { headers: { authorization: "Bearer sk_live_ABCDEFGHIJKLMNOPQRSTUV" }})');
    const joined = hits.map((h) => h.context).join(' ');
    assert.ok(!joined.includes('sk_live_ABCDEFGHIJKLMNOPQRSTUV'), 'the token must not survive into the report');
  });

  test('classifies on the nearest key, not one two lines away', () => {
    // A redirect_uri declared underneath an apiUrl must not steal the
    // classification: the context window must not reach across lines.
    const hits = scan(
      'const apiUrl = "http://localhost:8000/api";\nconst redirect_uri = "http://localhost:3000/auth/callback";',
    );
    const api = hits.find((h) => h.url === 'http://localhost:8000/api');
    const oauth = hits.find((h) => h.url === 'http://localhost:3000/auth/callback');
    assert.equal(api.role, 'api-base');
    assert.equal(oauth.role, 'oauth-redirect');
  });

  test("the app's own absolute URLs are not reported as leaks", () => {
    // Server-side helpers such as asset() and route() emit a dozen absolute
    // self-origin URLs per page. Reporting them as hardcoded leaks buries the
    // findings that matter.
    const hits = scanForLocalUrls({
      url: 'http://localhost:8020/login',
      body: '<link href="http://localhost:8020/build/app.css"><a href="http://localhost:8020/forgot-password">x</a>',
      kind: 'document',
      pageOrigin: 'http://localhost:8020',
    });
    assert.ok(hits.length > 0);
    assert.ok(hits.every((h) => h.role === 'self-origin-absolute'));
    assert.ok(hits.every((h) => h.severityHint === 'info'));
  });

  test('a named config constant keeps its role even at the page origin', () => {
    // The opposite case: a redirect_uri is a constant registered with an
    // identity provider. It does not follow the deployed host.
    const hits = scanForLocalUrls({
      url: 'http://localhost:3000/app.js',
      body: 'const redirect_uri = "http://localhost:3000/auth/callback";',
      kind: 'script',
      pageOrigin: 'http://localhost:3000',
    });
    assert.equal(hits[0].role, 'oauth-redirect');
    assert.equal(hits[0].severityHint, 'will-break');
  });

  test('classifies an asset host from an src attribute', () => {
    const hits = scanForLocalUrls({
      url: 'http://localhost:3000/',
      body: '<img src="http://localhost:9000/logo.png">',
      kind: 'document',
    });
    assert.equal(hits[0].role, 'asset-host');
  });

  test('reports the line number', () => {
    const hits = scan('line1\nline2\nconst apiUrl = "http://localhost:9999/api";');
    assert.equal(hits[0].line, 3);
  });

  test('binary mime types are not scanned', () => {
    assert.equal(isScannableMime('image/png'), false);
    assert.equal(isScannableMime('application/javascript'), true);
    assert.equal(isScannableMime('text/html; charset=utf-8'), true);
  });
});

describe('the two-auth-paths smell', () => {
  test('detects Secure gated on NODE_ENV', () => {
    const hits = scanSourceForConditionalFlags({
      url: 'http://localhost:3000/app.js',
      body: "cookie: { secure: process.env.NODE_ENV === 'production' }",
    });
    assert.ok(hits.some((h) => h.patternId === 'secure-gated-on-env'));
  });

  test('does not fire on an unconditional flag', () => {
    const hits = scanSourceForConditionalFlags({
      url: 'x',
      body: 'cookie: { secure: true, sameSite: "lax" }',
    });
    assert.equal(hits.length, 0);
  });

  test('recognises the NextAuth cookie-name pair', () => {
    const signals = inspectCookieForConditionalFlags(parseSetCookie('next-auth.session-token=x; HttpOnly'));
    const pair = signals.find((s) => s.signal === 'prefix-pair');
    assert.equal(pair.productionName, '__Secure-next-auth.session-token');
  });

  test('names the framework setting behind a known session cookie', () => {
    const signals = inspectCookieForConditionalFlags(parseSetCookie('sessionid=x; HttpOnly'));
    assert.equal(signals[0].framework, 'Django');
    assert.equal(signals[0].setting, 'SESSION_COOKIE_SECURE');
  });

  test('says nothing about a session cookie that already has Secure', () => {
    const signals = inspectCookieForConditionalFlags(parseSetCookie('sessionid=x; Secure; HttpOnly'));
    assert.equal(signals.length, 0);
  });
});

describe('port scanning stays on loopback', () => {
  test('refuses a non-loopback host', async () => {
    await assert.rejects(() => scanLoopbackPorts({ host: 'example.com' }), /loopback/);
  });

  test('finds a port we opened and not one we did not', async () => {
    const { createServer } = await import('node:http');
    const srv = createServer((_, res) => res.end('ok'));
    await new Promise((r) => srv.listen(39411, '127.0.0.1', r));
    try {
      const open = await scanLoopbackPorts({ ports: [39411, 39412], timeoutMs: 500 });
      assert.deepEqual(open, [39411]);
    } finally {
      srv.close();
    }
  });
});

describe('system-owned ports are labelled, not counted as dev servers', () => {
  test('macOS AirPlay ports are recognised', () => {
    assert.match(describeSystemPort(5000, 'darwin'), /AirPlay/);
    assert.match(describeSystemPort(7000, 'darwin'), /AirPlay/);
  });

  test('the same ports are not special on other platforms', () => {
    assert.equal(describeSystemPort(5000, 'linux'), null);
    assert.equal(describeSystemPort(5000, 'win32'), null);
  });

  test('an ordinary dev port is never labelled', () => {
    assert.equal(describeSystemPort(3000, 'darwin'), null);
    assert.equal(describeSystemPort(8080, 'darwin'), null);
  });

  test('the shared jar is keyed by hostname, not by "is it loopback"', () => {
    // Found by serving the fixture through the harness on app.demo.localhost:
    // that name is loopback, so the hazard fired -- but other dev servers
    // answer as localhost/127.0.0.1, which is a different host, so nothing is
    // shared with them. Cookies are keyed by name, not by interface.
    const capture = {
      setCookies: [{ raw: 'sid=abc; Path=/; HttpOnly', url: 'https://app.demo.localhost/', phase: 'response' }],
      instrumentation: [],
      blockedCookies: [],
      requests: [],
      bodies: [],
      finalUrl: 'https://app.demo.localhost/',
    };
    const model = createDeploymentModel({ domain: 'example.com' });
    const forHost = (url) =>
      cookieRules({ capture, model, openPorts: [4000, 8080], targetUrl: url }).find(
        (f) => f.id === 'cookie.port-sharing-hazard',
      );

    assert.ok(forHost('http://localhost:3000'), 'bare localhost does share one jar with other ports');
    assert.ok(forHost('http://127.0.0.1:3000'), 'a loopback IP shares it too');
    assert.equal(
      forHost('https://app.demo.localhost'),
      undefined,
      'a .localhost subdomain has its own jar and must not report the hazard',
    );
  });

  // "none found" is a claim about having looked. When no scan ran there is
  // nothing to report either way, and saying "none" is the same shape of lie
  // this rule exists to warn about.
  test('with no scan, the finding says it did not look rather than "none found"', () => {
    const capture = {
      setCookies: [{ raw: 'sid=abc; Path=/; HttpOnly', url: 'http://localhost:3000/', phase: 'response' }],
      instrumentation: [],
      blockedCookies: [],
      requests: [],
      bodies: [],
      finalUrl: 'http://localhost:3000/',
    };
    const model = createDeploymentModel({ domain: 'example.com' });
    const evidenceFor = (extra) =>
      cookieRules({ capture, model, openPorts: [], targetUrl: 'http://localhost:3000', ...extra })
        .find((f) => f.id === 'cookie.port-sharing-hazard')
        .evidence.find((e) => /other listeners/i.test(e.label)).value;

    assert.match(evidenceFor({ portScanSkipped: true }), /not probed/i);
    assert.doesNotMatch(evidenceFor({ portScanSkipped: true }), /none found/i);
    assert.match(evidenceFor({}), /none found/i, 'a scan that ran and found nothing still says so');
  });

  test('a run whose only neighbours are system ports is info, not will-break', () => {
    // Otherwise every Mac gets a permanent will-break for AirPlay, and a
    // finding that is always present is one people learn to skip past.
    const capture = {
      setCookies: [{ raw: 'sid=abc; Path=/; HttpOnly', url: 'http://localhost:3000/', phase: 'response' }],
      instrumentation: [],
      blockedCookies: [],
      requests: [],
      bodies: [],
      finalUrl: 'http://localhost:3000/',
    };
    const model = createDeploymentModel({ domain: 'example.com' });

    const onlySystem = cookieRules({
      capture,
      model,
      openPorts: [5000, 7000],
      targetUrl: 'http://localhost:3000',
      platform: 'darwin',
    }).find((f) => f.id === 'cookie.port-sharing-hazard');

    const realNeighbour = cookieRules({
      capture,
      model,
      openPorts: [4000],
      targetUrl: 'http://localhost:3000',
    }).find((f) => f.id === 'cookie.port-sharing-hazard');

    assert.ok(onlySystem, 'the rule should still fire and explain the port model');
    assert.equal(onlySystem.severity, 'info', 'AirPlay alone must not be a will-break');
    assert.match(JSON.stringify(onlySystem.evidence), /AirPlay/, 'the port should be labelled');
    assert.equal(realNeighbour.severity, 'will-break', 'a real neighbouring dev server is will-break');
  });
});

describe('findings', () => {
  test('rejects an unknown severity rather than silently accepting it', () => {
    assert.throws(() => finding({ id: 'x', severity: 'catastrophic', title: 't' }), /unknown severity/);
  });

  test('severity ordering', () => {
    assert.ok(severityRank('will-break') > severityRank('may-break'));
    assert.ok(severityRank('may-break') > severityRank('info'));
    assert.equal(atOrAbove('may-break', 'may-break'), true);
    assert.equal(atOrAbove('info', 'may-break'), false);
  });

  test('sorts most severe first, then by id for stable output', () => {
    const sorted = sortFindings([
      finding({ id: 'b', severity: 'info', title: 'b' }),
      finding({ id: 'a', severity: 'will-break', title: 'a' }),
      finding({ id: 'c', severity: 'may-break', title: 'c' }),
    ]);
    assert.deepEqual(sorted.map((f) => f.id), ['a', 'c', 'b']);
  });
});

describe('argument parsing', () => {
  test('accepts a bare URL', () => {
    const r = parseArgs(['http://localhost:3000']);
    assert.equal(r.ok, true);
    assert.equal(r.options.url, 'http://localhost:3000');
  });

  test('rejects a missing URL', () => {
    assert.equal(parseArgs([]).ok, false);
  });

  test('rejects a non-URL', () => {
    assert.equal(parseArgs(['not a url']).ok, false);
  });

  test('rejects a non-http scheme', () => {
    const r = parseArgs(['file:///etc/passwd']);
    assert.equal(r.ok, false);
    assert.match(r.error, /only http/);
  });

  test('rejects an unknown option', () => {
    const r = parseArgs(['http://localhost:3000', '--nope']);
    assert.equal(r.ok, false);
    assert.match(r.error, /unknown option/);
  });

  test('rejects a bad --fail-on level', () => {
    const r = parseArgs(['http://localhost:3000', '--fail-on', 'catastrophic']);
    assert.equal(r.ok, false);
  });

  test('--json with no value means stdout', () => {
    assert.equal(parseArgs(['http://x.test', '--json']).options.json, true);
  });

  test('--json with a path writes a file', () => {
    assert.equal(parseArgs(['http://x.test', '--json', 'out.json']).options.json, 'out.json');
  });

  test('--map is repeatable and lowercased', () => {
    const r = parseArgs([
      'http://localhost:3000',
      '--map',
      'localhost:3000=App.Acme.com',
      '--map',
      'localhost:8000=api.acme.com',
    ]);
    assert.deepEqual(r.options.map, {
      'localhost:3000': 'app.acme.com',
      'localhost:8000': 'api.acme.com',
    });
  });

  test('--map rejects a value with no equals sign', () => {
    assert.equal(parseArgs(['http://x.test', '--map', 'nope']).ok, false);
  });

  test('--map with a leading slash maps a path prefix, not an origin', () => {
    // This is how a dev-server proxy hiding a production split is modelled:
    // /api is same-origin today and its own host after deployment.
    const r = parseArgs(['http://x.test', '--map', '/api=api.acme.com', '--map', 'localhost:3000=app.acme.com']);
    assert.deepEqual(r.options.mapPaths, { '/api': 'api.acme.com' });
    assert.deepEqual(r.options.map, { 'localhost:3000': 'app.acme.com' });
  });

  test('a shell-mangled path is explained rather than silently accepted', () => {
    // Git Bash and MSYS rewrite any argument starting with "/" into a Windows
    // path. Accepting it would produce a confidently wrong analysis.
    const r = parseArgs(['http://x.test', '--map', 'C:/Program Files/Git/api=api.acme.com']);
    assert.equal(r.ok, false);
    assert.match(r.error, /rewrote a leading slash/);
    assert.match(r.error, /--map \/\/api=api\.acme\.com/, 'must show the exact working form');
  });

  test('--no-html disables the report', () => {
    assert.equal(parseArgs(['http://x.test', '--no-html']).options.html, null);
  });

  test('--help short-circuits validation', () => {
    assert.equal(parseArgs(['--help']).ok, true);
  });

  test('numeric options must be numeric', () => {
    assert.equal(parseArgs(['http://x.test', '--timeout', 'soon']).ok, false);
  });

  test('two targets is a usage error', () => {
    assert.equal(parseArgs(['http://a.test', 'http://b.test']).ok, false);
  });
});

describe('browser naming', () => {
  const withEnv = (value, fn) => {
    const prev = process.env.NOTLOCALHOST_BROWSER_PATH;
    if (value === undefined) delete process.env.NOTLOCALHOST_BROWSER_PATH;
    else process.env.NOTLOCALHOST_BROWSER_PATH = value;
    try {
      return fn();
    } finally {
      if (prev === undefined) delete process.env.NOTLOCALHOST_BROWSER_PATH;
      else process.env.NOTLOCALHOST_BROWSER_PATH = prev;
    }
  };

  test('a browser given by path gets a readable name, not the variable name', () => {
    // The name goes in every report header, so it has to read like a browser.
    const self = process.execPath; // any real file will do
    const found = withEnv(self, () => locateBrowser());
    assert.equal(found.path, self);
    assert.ok(!/NOTLOCALHOST_BROWSER_PATH/.test(found.name), `got "${found.name}"`);
    assert.ok(found.name.length > 0);
  });

  test('an explicit --browser-path that does not exist is a clear error', () => {
    assert.throws(
      () => locateBrowser({ explicitPath: '/definitely/not/here/chrome' }),
      /does not point at a browser that can be launched/,
    );
  });

  test('an unusable NOTLOCALHOST_BROWSER_PATH errors instead of being ignored', () => {
    // Silently falling through to a filesystem scan turns "the path you gave me
    // needs resolving" into "no browser found", which sends people looking in
    // completely the wrong place.
    assert.throws(() => withEnv('/definitely/not/here/chrome', () => locateBrowser()), /NOTLOCALHOST_BROWSER_PATH/);
  });
});

describe('resolving a browser path', () => {
  // macOS applications are bundles: directories ending in .app, with the real
  // executable at Contents/MacOS/<name>. Pointing at the bundle is the natural
  // thing to do on a Mac and must work.
  let tmp;

  before(() => {
    tmp = mkdtempSync(join(tmpdir(), 'nlh-locate-'));
  });
  after(() => {
    if (tmp) rmSync(tmp, { recursive: true, force: true });
  });

  const makeBundle = (bundleName, binaryName) => {
    const bundle = join(tmp, bundleName);
    const macos = join(bundle, 'Contents', 'MacOS');
    mkdirSync(macos, { recursive: true });
    const bin = join(macos, binaryName);
    writeFileSync(bin, '#!/bin/sh\necho stub\n');
    return { bundle, bin };
  };

  test('resolves into a macOS .app bundle', () => {
    const { bundle, bin } = makeBundle('Google Chrome.app', 'Google Chrome');
    assert.equal(resolveBrowserExecutable(bundle), bin);
  });

  test('prefers the binary named after the bundle when several exist', () => {
    const { bundle, bin } = makeBundle('Chromium.app', 'Chromium');
    writeFileSync(join(bundle, 'Contents', 'MacOS', 'crashpad_handler'), 'x');
    assert.equal(resolveBrowserExecutable(bundle), bin);
  });

  test('resolves a plain directory containing a chrome binary', () => {
    const dir = join(tmp, 'chrome-linux64');
    mkdirSync(dir, { recursive: true });
    const bin = join(dir, 'chrome');
    writeFileSync(bin, 'x');
    assert.equal(resolveBrowserExecutable(dir), bin);
  });

  test('passes a real executable through unchanged', () => {
    assert.equal(resolveBrowserExecutable(process.execPath), process.execPath);
  });

  test('returns null for a directory with no browser in it', () => {
    const dir = join(tmp, 'empty');
    mkdirSync(dir, { recursive: true });
    assert.equal(resolveBrowserExecutable(dir), null);
  });

  test('returns null for a path that does not exist', () => {
    assert.equal(resolveBrowserExecutable(join(tmp, 'nope')), null);
    assert.equal(resolveBrowserExecutable(''), null);
  });
});

describe('browser launch failure diagnosis', () => {
  // Found on Linux: a Chrome build unpacked by a zip extractor that drops the
  // executable bit fails with forty lines of stack frames and one useful line.
  const diagnose = sessionInternal.diagnoseLaunchFailure;
  const info = { path: '/home/dev/chrome/chrome', name: 'Chrome for Testing' };

  test('names the crashpad permission problem and gives the chmod', () => {
    const out = diagnose(
      'posix_spawn /home/dev/chrome/chrome_crashpad_handler: Permission denied (13)\nReceived signal 6\n#0 0x5fd78ab46b73',
      info,
    );
    assert.match(out, /not executable/);
    assert.match(out, /chmod \+x/);
  });

  test('names a missing shared library and the package to install', () => {
    const out = diagnose('error while loading shared libraries: libnss3.so: cannot open shared object file', info);
    assert.match(out, /libnss3\.so/);
    assert.match(out, /apt-get install/);
  });

  test('explains a sandbox failure without offering to disable the sandbox', () => {
    const out = diagnose('Running as root without --no-sandbox is not supported', info);
    assert.match(out, /sandbox/);
    assert.ok(!/pass --no-sandbox for you/.test(out) === false || out.includes('does not pass'));
  });

  test('a missing binary points at --list-browsers', () => {
    assert.match(diagnose('spawn ENOENT', info), /--list-browsers/);
  });

  test('an unrecognised failure strips register dumps and stack frames', () => {
    const noisy = [
      'Something went wrong',
      '[pid=454][err] #0 0x5fd78ab46b73 (/chrome+0x69b2b72)',
      '  r8: 0000000000000016  r9: 0000000000000001',
      'and a second useful line',
    ].join('\n');
    const out = diagnose(noisy, info);
    assert.match(out, /Something went wrong/);
    assert.match(out, /and a second useful line/);
    assert.ok(!out.includes('0x5fd78ab46b73'), 'stack frames must be dropped');
    assert.match(out, /--verbose/);
  });
});

describe('the process never hangs silently', () => {
  const sink = () => {
    const chunks = [];
    return { write: (s) => chunks.push(s), get text() { return chunks.join(''); }, isTTY: false, columns: 90 };
  };

  test('a run that never settles becomes a documented exit code, not Node exit 13', async () => {
    // An unsettled promise with an empty event loop makes Node exit 13 with no
    // output whatsoever: no error, no report, nothing to act on. A watchdog
    // turns that into a tool failure with a message.
    const stderr = sink();
    const code = await run(
      ['http://127.0.0.1:39396', '--no-html', '--timeout', '1', '--flow-timeout', '1'],
      { stdout: sink(), stderr },
    );
    assert.notEqual(code, 13);
    assert.ok([EXIT.UNREACHABLE, EXIT.TOOL_FAILURE].includes(code), `got exit ${code}`);
    assert.ok(stderr.text.length > 0, 'a failure must always say something');
  });
});

describe('exit codes', () => {
  test('are the documented values', () => {
    assert.deepEqual(EXIT, { CLEAN: 0, FINDINGS: 1, UNREACHABLE: 2, TOOL_FAILURE: 5, USAGE: 64 });
  });

  const withCounts = (counts) => ({ counts });

  test('--fail-on none never fails', () => {
    assert.equal(shouldFail(withCounts({ 'will-break': 9, 'may-break': 9, info: 9 }), 'none'), false);
  });

  test('--fail-on will-break ignores lesser findings', () => {
    assert.equal(shouldFail(withCounts({ 'will-break': 0, 'may-break': 5, info: 5 }), 'will-break'), false);
    assert.equal(shouldFail(withCounts({ 'will-break': 1, 'may-break': 0, info: 0 }), 'will-break'), true);
  });

  test('--fail-on may-break includes will-break', () => {
    assert.equal(shouldFail(withCounts({ 'will-break': 1, 'may-break': 0, info: 0 }), 'may-break'), true);
  });

  test('--fail-on info fails on anything at all', () => {
    assert.equal(shouldFail(withCounts({ 'will-break': 0, 'may-break': 0, info: 1 }), 'info'), true);
    assert.equal(shouldFail(withCounts({ 'will-break': 0, 'may-break': 0, info: 0 }), 'info'), false);
  });
});

// ---------------------------------------------------------------------------

const sampleResult = {
  schemaVersion: SCHEMA_VERSION,
  tool: { name: 'notlocalhost', version: '0.0.0-test' },
  startedAt: '2026-01-01T00:00:00.000Z',
  finishedAt: '2026-01-01T00:00:03.000Z',
  target: { url: 'http://localhost:3000', finalUrl: 'http://localhost:3000/', status: 200, origin: 'http://localhost:3000', isLoopback: true },
  browser: { name: 'Google Chrome', channel: 'chrome', version: '1.2.3', executablePath: '/x' },
  deploymentModel: { domain: 'example.com', crossSite: false, description: 'test model', mapping: { 'localhost:3000': 'app.example.com' } },
  coverage: {
    flow: null, requests: 3, responses: 3, bodiesScanned: 1, bytesScanned: 2048,
    cookiesObserved: 1, instrumentationEvents: 2, otherLoopbackListeners: [4000],
    portScanSkipped: false, timing: { totalMs: 3000 },
  },
  counts: { 'will-break': 1, 'may-break': 0, info: 1 },
  findings: [
    finding({
      id: 'test.rule',
      severity: 'will-break',
      title: 'A test finding',
      summary: 'First paragraph.\n\nSecond paragraph.',
      evidence: [{ label: 'Set-Cookie', value: 'a=1; SameSite=None' }],
      fix: ['Do the thing.'],
      refs: [{ title: 'RFC 6265', url: 'https://www.rfc-editor.org/rfc/rfc6265' }],
    }),
    finding({ id: 'test.info', severity: 'info', title: 'An info finding' }),
  ],
  warnings: [],
  limitations: ['This predicts behaviour. It does not prove it.'],
};

describe('reporters', () => {
  test('JSON round-trips and keeps the schema version', () => {
    const parsed = JSON.parse(renderJson(sampleResult));
    assert.equal(parsed.schemaVersion, SCHEMA_VERSION);
    assert.equal(parsed.findings.length, 2);
  });

  test('markdown includes the counts table and the limitations', () => {
    const md = renderMarkdown(sampleResult);
    assert.match(md, /\| findings \| \*\*1\*\* \| 0 \| 1 \|/);
    assert.match(md, /What this does not tell you/);
    assert.match(md, /pass `--flow`/);
  });

  test('HTML is one self-contained document with no loaded external assets', () => {
    const html = renderHtml(sampleResult);
    assert.ok(html.startsWith('<!doctype html>'));
    assert.ok(html.includes('</html>'));
    assert.equal(/<link\b/.test(html), false, 'no external stylesheets');
    assert.equal(/<script[^>]+src=/.test(html), false, 'no external scripts');
    assert.equal(/<img[^>]+src=/.test(html), false, 'no external images');
  });

  test('HTML escapes a finding that contains markup', () => {
    const hostile = structuredClone(sampleResult);
    hostile.findings[0].title = '<img src=x onerror=alert(1)>';
    hostile.findings[0].evidence = [{ label: 'x', value: '</script><script>alert(2)</script>' }];
    const html = renderHtml(hostile);
    assert.equal(html.includes('<img src=x onerror'), false);
    assert.equal(html.includes('</script><script>alert(2)'), false);
    assert.ok(html.includes('&lt;img src=x'));
  });

  test('the embedded JSON cannot close its own script tag', () => {
    const hostile = structuredClone(sampleResult);
    hostile.findings[0].summary = '</script><script>alert(3)</script>';
    const html = renderHtml(hostile);
    const dataBlock = html.slice(html.indexOf('<script id="data"'));
    const firstClose = dataBlock.indexOf('</script>');
    const json = dataBlock.slice(dataBlock.indexOf('>') + 1, firstClose);
    assert.doesNotThrow(() => JSON.parse(json), 'the data island must still parse');
    assert.ok(json.includes('\\u003c'), 'angle brackets must be escaped');
  });

  test('terminal output groups by severity and hides info by default', () => {
    const out = renderTerminal(sampleResult, { stream: { isTTY: false, columns: 90 } });
    assert.match(out, /WILL BREAK/);
    assert.match(out, /A test finding/);
    assert.match(out, /1 info finding hidden/);
    assert.equal(out.includes('An info finding'), false);
  });

  test('--verbose shows info findings', () => {
    const out = renderTerminal(sampleResult, { verbose: true, stream: { isTTY: false, columns: 90 } });
    assert.match(out, /An info finding/);
  });

  test('warns loudly when no flow script was used', () => {
    const out = renderTerminal(sampleResult, { stream: { isTTY: false, columns: 90 } });
    assert.match(out, /no --flow script/);
  });

  test('always prints the limitations', () => {
    const out = renderTerminal(sampleResult, { stream: { isTTY: false, columns: 90 } });
    assert.match(out, /what this does not tell you/);
  });

  test('text wrapping never exceeds the width and never drops a word', () => {
    const text = 'the quick brown fox jumps over the lazy dog '.repeat(6).trim();
    const lines = termInternal.wrapText(text, 30);
    for (const l of lines) assert.ok(l.length <= 30, `"${l}" is ${l.length} chars`);
    assert.equal(lines.join(' '), text);
  });
});

describe('an open port is not a web server', () => {
  let web;
  let silent;
  let webPort;
  let silentPort;
  const sockets = new Set();

  before(async () => {
    web = http.createServer((_, res) => res.end('ok'));
    await new Promise((r) => web.listen(0, '127.0.0.1', r));
    webPort = web.address().port;

    // Answers a TCP connect and then says nothing, the way a database does.
    // Sockets are tracked because close() waits on every live connection, and
    // a server holding one silently never calls back.
    silent = net.createServer((sock) => sockets.add(sock.on('close', () => sockets.delete(sock))));
    await new Promise((r) => silent.listen(0, '127.0.0.1', r));
    silentPort = silent.address().port;
  });

  after(async () => {
    for (const sock of sockets) sock.destroy();
    sockets.clear();
    web.closeAllConnections?.();
    await new Promise((r) => web.close(r));
    await new Promise((r) => silent.close(r));
  });

  test('an HTTP server is recognised', async () => {
    assert.equal(await speaksHttp(webPort), true);
  });

  test('a socket that accepts and stays silent is not', async () => {
    assert.equal(await speaksHttp(silentPort, '127.0.0.1', 400), false);
  });

  test('a closed port is not', async () => {
    assert.equal(await speaksHttp(1, '127.0.0.1', 400), false);
  });
});

describe('the test run is judged by its output, not its exit code', () => {
  // Recorded verbatim from the run where this happened: three assertions
  // passed, the suite was cancelled for a leaked handle, and the summary still
  // said "# fail 0" with exit status 0. It would have shipped.
  const CANCELLED_RUN = [
    '    ok 1 - an HTTP server is recognised',
    '    ok 2 - a socket that accepts and stays silent is not',
    '    ok 3 - a closed port is not',
    '    1..3',
    'not ok 16 - an open port is not a web server',
    '  ---',
    "  failureType: 'cancelledByParent'",
    "  error: 'Promise resolution is still pending but the event loop has already resolved'",
    '  ...',
    '1..16',
    '# tests 164',
    '# pass 164',
    '# fail 0',
    '',
  ].join('\n');

  const CLEAN_RUN = ['ok 1 - fine', '1..1', '# tests 164', '# pass 164', '# fail 0', ''].join('\n');

  test('a clean run is believed', () => {
    assert.deepEqual(analyseTapOutput({ out: CLEAN_RUN, status: 0 }), []);
  });

  test('a cancelled suite is caught even though it exited 0 with "# fail 0"', () => {
    const problems = analyseTapOutput({ out: CANCELLED_RUN, status: 0 });
    assert.equal(problems.length, 1, JSON.stringify(problems));
    assert.match(problems[0], /not ok 16/);
  });

  test('a suite that skips itself is caught', () => {
    const tiny = ['ok 1 - one', '1..1', '# tests 1', '# pass 1', '# fail 0', ''].join('\n');
    assert.match(analyseTapOutput({ out: tiny, status: 0 })[0], /only 1 tests ran/);
  });

  test('output that stops early is not mistaken for success', () => {
    const truncated = ['ok 1 - one', '# pass 1', ''].join('\n');
    const problems = analyseTapOutput({ out: truncated, status: 0 });
    assert.equal(problems.length, 2, JSON.stringify(problems));
    for (const p of problems) assert.match(p, /did not finish/);
  });

  test('CRLF output is parsed, not silently unmatched', () => {
    assert.deepEqual(analyseTapOutput({ out: CLEAN_RUN.split('\n').join('\r\n'), status: 0 }), []);
  });

  test('a non-zero exit is reported even when the TAP looks fine', () => {
    assert.match(analyseTapOutput({ out: CLEAN_RUN, status: 1 })[0], /exited 1/);
  });
});
