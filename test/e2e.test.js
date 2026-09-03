/**
 * End-to-end: start the fixture app, drive a real browser, assert on the
 * findings.
 *
 * This is the test that would actually catch a regression, because every layer
 * runs -- CDP capture, page instrumentation, the flow runner and all five rule
 * modules. It skips (rather than fails) when no Chromium-family browser is
 * installed, so a contributor without Chrome can still run the unit suite.
 */
import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { mkdtempSync, writeFileSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { analyze } from '../src/analyze.js';
import { locateBrowser } from '../src/browser/locate.js';
import { run } from '../src/cli.js';
import { EXIT } from '../src/exit-codes.js';
import { renderHtml } from '../src/report/html.js';

let haveBrowser = true;
try {
  locateBrowser();
} catch {
  haveBrowser = false;
}

const skip = haveBrowser ? false : 'no Chrome, Chromium or Edge installed';

// Ports well away from anything a developer is likely to be running.
const APP_PORT = 39301;
const API_PORT = 39302;
const APP_URL = `http://localhost:${APP_PORT}`;

let app;
let api;
let tmp;

const APP_JS = `
window.process = window.process || { env: { NODE_ENV: 'development' } };
const cookieOptions = { secure: process.env.NODE_ENV === 'production' };
const apiUrl = "http://localhost:${API_PORT}/api";
const redirect_uri = "http://localhost:${APP_PORT}/auth/callback";
if (navigator.clipboard) {}
if (navigator.serviceWorker) {}
try { crypto.subtle.digest; } catch (e) {}
document.cookie = "theme=dark; Path=/";
fetch(apiUrl + "/me", { credentials: "include" }).catch(function(){});
window.__ready = true;
`;

const PAGE = `<!doctype html><html><head><meta charset="utf-8"><title>t</title></head><body>
<h1>fixture</h1>
<img src="http://assets.invalid.test/x.png" alt="">
<form id="login" method="POST" action="/login">
  <input id="email" name="email"><input id="password" name="password" type="password">
  <button type="submit">go</button>
</form>
<script src="/app.js"></script>
</body></html>`;

before(async () => {
  if (!haveBrowser) return;
  tmp = mkdtempSync(join(tmpdir(), 'nlh-e2e-'));

  app = createServer((req, res) => {
    const path = req.url.split('?')[0];
    if (path === '/app.js') {
      res.writeHead(200, { 'content-type': 'application/javascript' });
      res.end(APP_JS);
      return;
    }
    if (path === '/login' && req.method === 'POST') {
      req.on('data', () => {});
      req.on('end', () => {
        res.writeHead(302, {
          location: '/dashboard',
          'set-cookie': [
            'connect.sid=s%3Areal.session; Path=/; HttpOnly; SameSite=Lax',
            'next-auth.session-token=eyJhbGciOi.demo; Path=/; HttpOnly; SameSite=Lax',
          ],
        });
        res.end();
      });
      return;
    }
    if (path === '/dashboard') {
      res.writeHead(200, { 'content-type': 'text/html' });
      res.end(PAGE);
      return;
    }
    res.writeHead(200, {
      'content-type': 'text/html',
      'set-cookie': [
        'sid=anon; Path=/; HttpOnly; SameSite=Lax',
        'ab=1; Path=/; SameSite=None',
        '__Host-csrf=x; Path=/app; Domain=localhost',
        '__Secure-p=y; Path=/',
        'legacy=1; Path=/; Domain=.localhost',
      ],
    });
    res.end(PAGE);
  });

  api = createServer((req, res) => {
    res.writeHead(200, {
      'content-type': 'application/json',
      'access-control-allow-origin': '*',
      'access-control-allow-credentials': 'true',
    });
    res.end('{}');
  });

  await Promise.all([
    new Promise((r) => app.listen(APP_PORT, '127.0.0.1', r)),
    new Promise((r) => api.listen(API_PORT, '127.0.0.1', r)),
  ]);
});

after(async () => {
  await Promise.all([
    app ? new Promise((r) => app.close(r)) : null,
    api ? new Promise((r) => api.close(r)) : null,
  ]);
  if (tmp) rmSync(tmp, { recursive: true, force: true });
});

describe('end to end against a live dev server', { skip }, () => {
  let result;
  let flowResult;

  before(async () => {
    result = await analyze({ url: APP_URL, noPortScan: false });
    const flowPath = join(tmp, 'flow.mjs');
    writeFileSync(
      flowPath,
      `export default async ({ page }) => {
         await page.fill('#email', 'a@b.test');
         await page.fill('#password', 'pw');
         await page.click('#login button[type=submit]');
         await page.waitForURL('**/dashboard');
       };`,
    );
    flowResult = await analyze({ url: APP_URL, flow: flowPath });
  });

  const has = (r, id) => r.findings.some((f) => f.id === id);
  const get = (r, id) => r.findings.find((f) => f.id === id);

  test('produces a schema-versioned document', () => {
    assert.equal(result.schemaVersion, 1);
    assert.equal(result.target.status, 200);
    assert.ok(result.browser.version, 'a browser version must be recorded');
  });

  test('catches SameSite=None without Secure', () => {
    assert.ok(has(result, 'cookie.samesite-none-without-secure'));
    assert.equal(get(result, 'cookie.samesite-none-without-secure').severity, 'will-break');
  });

  test('catches the __Host- prefix violations and names all three', () => {
    const f = get(result, 'cookie.host-prefix-violation');
    assert.ok(f);
    const violations = f.evidence.find((e) => e.label === 'violations').value;
    assert.match(violations, /Secure/);
    assert.match(violations, /Domain/);
    assert.match(violations, /Path/);
  });

  test('catches the __Secure- prefix without Secure', () => {
    assert.ok(has(result, 'cookie.secure-prefix-violation'));
  });

  test('catches Domain=.localhost and explains RFC 6265', () => {
    const f = get(result, 'cookie.domain-localhost');
    assert.ok(f);
    assert.match(f.summary, /leading dot is stripped/);
    assert.ok(f.refs.some((r) => r.url.includes('rfc6265')));
  });

  test('quotes Chrome rejecting cookies rather than only predicting it', () => {
    const rejected = result.findings.filter((f) => f.id === 'cookie.rejected-by-browser');
    assert.ok(rejected.length > 0, 'Chrome should have rejected at least the SameSite=None cookie');
    assert.ok(rejected.some((f) => /SameSiteNoneInsecure|InvalidPrefix/.test(JSON.stringify(f.evidence))));
  });

  test('reports the port-sharing hazard with the RFC 6265 section 8.5 reference', () => {
    const f = get(result, 'cookie.port-sharing-hazard');
    assert.ok(f);
    assert.match(f.summary, /do not provide\s+isolation by port|isolation by port/);
    assert.ok(f.refs.some((r) => r.url.includes('section-8.5')));
  });

  test('reports that host-only cookies stop crossing once ports become hostnames', () => {
    const f = get(result, 'cookie.host-only-stops-crossing');
    assert.ok(f, 'the fixture calls a second local port with credentials');
    assert.equal(f.severity, 'will-break');
  });

  test('instruments secure-context APIs the page actually touched', () => {
    const f = get(result, 'securecontext.apis-used');
    assert.ok(f);
    const apis = f.evidence.map((e) => e.label);
    assert.ok(apis.includes('navigator.clipboard'));
    assert.ok(apis.includes('navigator.serviceWorker'));
  });

  test('does not claim secure-context APIs break on HTTPS', () => {
    const f = get(result, 'securecontext.apis-used');
    assert.match(f.summary, /keep working over HTTPS/);
  });

  test('catches active mixed content', () => {
    assert.ok(has(result, 'mixedcontent.passive') || has(result, 'mixedcontent.active'));
  });

  test('catches the hardcoded OAuth redirect and API base', () => {
    assert.ok(has(result, 'leak.oauth-redirect'));
    assert.ok(has(result, 'leak.api-base'));
  });

  test('catches the environment-gated Secure flag in served source', () => {
    assert.ok(has(result, 'cookie.two-auth-paths-source'));
  });

  test('catches wildcard CORS combined with credentials', () => {
    // Regression: Chrome never fires responseReceived for a CORS-blocked
    // response, so reading only successful responses missed this entirely.
    assert.ok(has(result, 'cors.wildcard-with-credentials'));
  });

  test("quotes Chrome's own CORS error code for the blocked request", () => {
    const f = get(result, 'cors.blocked-by-browser');
    assert.ok(f, 'the credentialed fetch at a wildcard-CORS endpoint is blocked');
    assert.match(JSON.stringify(f.evidence), /wildcard origin with credentials/);
  });

  test('records the deployment model it assumed', () => {
    assert.equal(result.deploymentModel.domain, 'example.com');
    assert.equal(result.deploymentModel.mapping[`localhost:${APP_PORT}`], 'app.example.com');
  });

  test('always ships the limitations with the document', () => {
    assert.ok(result.limitations.length >= 4);
    assert.ok(result.limitations.some((l) => /never means "safe"/.test(l)));
  });

  // ------------------------------------------------------------ the flow --

  test('a flow script runs and is recorded as having run', () => {
    assert.equal(flowResult.coverage.flow.ok, true);
  });

  test('the flow reveals cookies the logged-out page never sets', () => {
    const before = get(result, 'cookie.inventory').evidence.map((e) => e.label);
    const after = get(flowResult, 'cookie.inventory').evidence.map((e) => e.label);
    assert.equal(before.includes('connect.sid'), false, 'not visible without a flow');
    assert.ok(after.includes('connect.sid'), 'visible with a flow');
    assert.ok(after.includes('next-auth.session-token'));
  });

  test('the flow surfaces the NextAuth two-auth-paths finding', () => {
    const f = flowResult.findings.find(
      (x) => x.id === 'cookie.two-auth-paths' && /next-auth/.test(x.title),
    );
    assert.ok(f, 'the NextAuth cookie-name pair should be detected after login');
    assert.match(f.title, /__Secure-next-auth\.session-token/);
  });

  test('a broken flow script degrades to a warning, not a crash', async () => {
    const bad = join(tmp, 'bad-flow.mjs');
    writeFileSync(bad, `export default async ({ page }) => { await page.click('#nope', { timeout: 500 }); };`);
    const r = await analyze({ url: APP_URL, flow: bad, flowTimeout: 5000 });
    assert.equal(r.coverage.flow.ok, false);
    assert.ok(r.warnings.some((w) => /--flow script failed/.test(w)));
    assert.ok(r.findings.length > 0, 'findings from before the failure are still reported');
  });

  test('a flow script with no default export is reported clearly', async () => {
    const bad = join(tmp, 'no-default.mjs');
    writeFileSync(bad, `export const notTheDefault = 1;`);
    const r = await analyze({ url: APP_URL, flow: bad });
    assert.match(r.coverage.flow.error, /default-export an async function/);
  });

  // ---------------------------------------------------------- the report --

  test('the HTML report is one file, under 2 MB, and opens with no server', () => {
    const html = renderHtml(flowResult);
    assert.ok(html.length < 2 * 1024 * 1024, `report is ${html.length} bytes`);
    assert.equal(/<script[^>]+src=/.test(html), false);
    assert.equal(/<link\b/.test(html), false);
    assert.ok(html.includes('Your localhost is lying to you'));
  });
});

describe('CLI exit codes against a live server', { skip }, () => {
  const sink = () => {
    const chunks = [];
    return { write: (s) => chunks.push(s), get text() { return chunks.join(''); }, isTTY: false, columns: 90 };
  };

  test('exit 0 when nothing reaches the threshold', async () => {
    const stdout = sink();
    const code = await run([APP_URL, '--fail-on', 'none', '--no-html', '--quiet'], { stdout, stderr: sink() });
    assert.equal(code, EXIT.CLEAN);
  });

  test('exit 1 when findings reach --fail-on', async () => {
    const code = await run([APP_URL, '--fail-on', 'will-break', '--no-html', '--quiet'], {
      stdout: sink(),
      stderr: sink(),
    });
    assert.equal(code, EXIT.FINDINGS);
  });

  test('exit 2 when the target is not listening', async () => {
    const stderr = sink();
    const code = await run(['http://127.0.0.1:39399', '--no-html', '--timeout', '3000'], {
      stdout: sink(),
      stderr,
    });
    assert.equal(code, EXIT.UNREACHABLE);
    assert.match(stderr.text, /unreachable/);
  });

  test('exit 64 on a usage error', async () => {
    const code = await run(['--fail-on', 'nonsense'], { stdout: sink(), stderr: sink() });
    assert.equal(code, EXIT.USAGE);
  });

  test('exit 0 for --help and --version', async () => {
    const stdout = sink();
    assert.equal(await run(['--help'], { stdout, stderr: sink() }), EXIT.CLEAN);
    assert.match(stdout.text, /EXIT CODES/);
    assert.equal(await run(['--version'], { stdout: sink(), stderr: sink() }), EXIT.CLEAN);
  });

  test('--json emits a parseable document on stdout and nothing else', async () => {
    const stdout = sink();
    await run([APP_URL, '--json', '--no-html'], { stdout, stderr: sink() });
    const doc = JSON.parse(stdout.text);
    assert.equal(doc.schemaVersion, 1);
    assert.ok(Array.isArray(doc.findings));
  });

  test('writes the HTML report where it is told to', async () => {
    const out = join(tmp, 'report.html');
    await run([APP_URL, '--html', out, '--quiet'], { stdout: sink(), stderr: sink() });
    const html = readFileSync(out, 'utf8');
    assert.ok(html.startsWith('<!doctype html>'));
  });
});
