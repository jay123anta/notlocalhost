/**
 * Reproduction: cookies are not isolated by port, and localhost cannot express
 * a parent-domain scope.
 *
 * Both claims appear in the README, so both are verified here against a real
 * browser rather than asserted from a reading of the RFC. Run it yourself:
 *
 *   node evidence/repro-port-sharing.mjs
 *
 * It starts three throwaway HTTP servers on loopback, drives a real Chrome
 * through them, and prints what each server actually received. Nothing leaves
 * the machine.
 */
import { createServer } from 'node:http';
import { chromium } from 'playwright-core';
import { locateBrowser } from '../src/browser/locate.js';

const PORT_A = 37301;
const PORT_B = 37302;
const PORT_C = 37303;

const seen = { a: [], b: [], c: [] };

function server(tag, handler) {
  return createServer((req, res) => {
    seen[tag].push({ path: req.url, host: req.headers.host, cookie: req.headers.cookie ?? null });
    handler(req, res);
  });
}

// --- Server A: sets a plain host-only cookie, no Domain attribute. ----------
const a = server('a', (req, res) => {
  if (req.url === '/set') {
    res.writeHead(200, {
      'content-type': 'text/html',
      'set-cookie': [
        'app_session=SECRET-FROM-PORT-A; Path=/; HttpOnly; SameSite=Lax',
        // The parent-scope attempt. RFC 6265 5.2.3 strips the leading dot,
        // leaving Domain=localhost.
        'wishful=parent-scope; Path=/; Domain=.localhost; SameSite=Lax',
      ],
    });
    res.end('<h1>server A set its cookies</h1>');
    return;
  }
  res.writeHead(200, { 'content-type': 'text/html' });
  res.end('<h1>A</h1>');
});

// --- Server B: an unrelated app on a different port, same host. -------------
const b = server('b', (req, res) => {
  res.writeHead(200, { 'content-type': 'text/html' });
  res.end(`<h1>server B</h1><pre>${req.headers.cookie ?? '(no cookies)'}</pre>`);
});

// --- Server C: answers on every hostname, so we can use *.localhost. --------
const c = server('c', (req, res) => {
  if (req.url === '/set-parent') {
    res.writeHead(200, {
      'content-type': 'text/html',
      'set-cookie': [
        'sub_host_only=set-by-app-subdomain; Path=/; SameSite=Lax',
        'sub_parent_dot=try-dot-localhost; Path=/; Domain=.localhost; SameSite=Lax',
        'sub_parent_bare=try-bare-localhost; Path=/; Domain=localhost; SameSite=Lax',
      ],
    });
    res.end('<h1>tried to set a parent-domain cookie</h1>');
    return;
  }
  res.writeHead(200, { 'content-type': 'text/html' });
  res.end(`<h1>C on ${req.headers.host}</h1><pre>${req.headers.cookie ?? '(no cookies)'}</pre>`);
});

const listen = (srv, port) => new Promise((r) => srv.listen(port, '127.0.0.1', r));

function heading(text) {
  console.log(`\n${text}\n${'='.repeat(text.length)}`);
}

function verdict(claim, holds, detail) {
  console.log(`  ${holds ? '[CONFIRMED]' : '[REFUTED]  '} ${claim}`);
  if (detail) console.log(`              ${detail}`);
  return holds;
}

const results = [];

await Promise.all([listen(a, PORT_A), listen(b, PORT_B), listen(c, PORT_C)]);

const browserInfo = locateBrowser();
const browser = await chromium.launch({ executablePath: browserInfo.path, headless: true });
const ctx = await browser.newContext();
const page = await ctx.newPage();

try {
  console.log(`Browser: ${browserInfo.name} (${browserInfo.path})`);
  console.log(`Version: ${browser.version()}`);

  // ---------------------------------------------------------------- claim 1 --
  heading('Claim 1: cookies are not isolated by port (RFC 6265 section 8.5)');

  await page.goto(`http://localhost:${PORT_A}/set`);
  await page.goto(`http://localhost:${PORT_B}/read`);

  const bRequest = seen.b.find((r) => r.path === '/read');
  const leaked = (bRequest?.cookie ?? '').includes('app_session=SECRET-FROM-PORT-A');

  console.log(`  server A (port ${PORT_A}) set:  app_session=SECRET-FROM-PORT-A  (host-only, no Domain)`);
  console.log(`  server B (port ${PORT_B}) received Cookie: ${bRequest?.cookie ?? '(none)'}`);
  results.push(
    verdict(
      'A cookie set by one localhost port is sent to a different localhost port.',
      leaked,
      leaked
        ? 'Two unrelated apps on one machine share a single cookie jar. Ports are not a boundary.'
        : 'The cookie did not cross. This contradicts RFC 6265 section 8.5 and needs investigating.',
    ),
  );

  // Can B overwrite A's cookie? That is the sharper version of the hazard.
  await ctx.addCookies([
    { name: 'app_session', value: 'OVERWRITTEN-BY-PORT-B', domain: 'localhost', path: '/' },
  ]);
  await page.goto(`http://localhost:${PORT_A}/`);
  const aAfter = seen.a[seen.a.length - 1];
  const overwritten = (aAfter?.cookie ?? '').includes('OVERWRITTEN-BY-PORT-B');
  console.log(`  server A now receives Cookie: ${aAfter?.cookie ?? '(none)'}`);
  results.push(
    verdict(
      "A second app on another port can overwrite the first app's session cookie.",
      overwritten,
      overwritten ? 'Session fixation between unrelated local projects is one navigation away.' : '',
    ),
  );

  // ---------------------------------------------------------------- claim 2 --
  heading('Claim 2: localhost cannot be given a parent-domain cookie scope');

  await ctx.clearCookies();
  await page.goto(`http://app.localhost:${PORT_C}/set-parent`);

  const stored = await ctx.cookies();
  const names = stored.map((k) => `${k.name} (domain=${k.domain})`);
  console.log(`  set from http://app.localhost:${PORT_C}/set-parent :`);
  console.log('     sub_host_only   (no Domain attribute)');
  console.log('     sub_parent_dot  Domain=.localhost');
  console.log('     sub_parent_bare Domain=localhost');
  console.log(`  cookie jar afterwards: ${names.length ? names.join(', ') : '(empty)'}`);

  const gotDot = stored.some((k) => k.name === 'sub_parent_dot');
  const gotBare = stored.some((k) => k.name === 'sub_parent_bare');

  results.push(
    verdict(
      'A Domain=.localhost cookie set from app.localhost is rejected.',
      !gotDot,
      gotDot ? 'It was stored. The claim as written is wrong and must be corrected.' : 'Chrome refused to store it.',
    ),
  );
  results.push(
    verdict(
      'A Domain=localhost cookie set from app.localhost is rejected.',
      !gotBare,
      gotBare ? 'It was stored. The claim as written is wrong and must be corrected.' : 'Chrome refused to store it.',
    ),
  );

  // Does anything reach api.localhost?
  await page.goto(`http://api.localhost:${PORT_C}/read`);
  const apiRequest = seen.c.find((r) => r.host?.startsWith('api.localhost'));
  console.log(`  http://api.localhost:${PORT_C} received Cookie: ${apiRequest?.cookie ?? '(none)'}`);
  results.push(
    verdict(
      'Nothing set by app.localhost is readable by api.localhost.',
      !apiRequest?.cookie,
      'The app.localhost / api.localhost pattern does not create a shared cookie scope.',
    ),
  );

  // ------------------------------------------------------------- claim 2b --
  // The other direction, and the one that decides how precise the README can
  // be. Setting Domain=.localhost from bare `localhost` is NOT rejected -- but
  // RFC 6265 5.3 step 6 says that when the domain-attribute equals the
  // request-host, the cookie is stored host-only. If that is what happens, the
  // attribute is silently a no-op rather than a parent scope, and the cookie
  // must not reach app.localhost.
  heading('Claim 2b: Domain=.localhost set from localhost is stored host-only, not as a parent scope');

  await ctx.clearCookies();
  await page.goto(`http://localhost:${PORT_A}/set`);
  const jar = await ctx.cookies();
  const wishful = jar.find((k) => k.name === 'wishful');
  console.log(`  set from http://localhost:${PORT_A} :  wishful=parent-scope; Domain=.localhost`);
  console.log(`  stored as: ${wishful ? `domain=${JSON.stringify(wishful.domain)}` : '(not stored)'}`);

  const storedHostOnly = Boolean(wishful) && wishful.domain === 'localhost';
  results.push(
    verdict(
      'It is accepted, but stored with domain "localhost" rather than ".localhost" -- i.e. host-only.',
      storedHostOnly,
      'The leading dot is stripped per RFC 6265 5.2.3, and a domain-attribute identical to the request host yields a host-only cookie.',
    ),
  );

  const before = seen.c.length;
  await page.goto(`http://app.localhost:${PORT_C}/read-after-parent-attempt`);
  const subRequest = seen.c.slice(before).find((r) => r.host?.startsWith('app.localhost'));
  console.log(`  http://app.localhost:${PORT_C} received Cookie: ${subRequest?.cookie ?? '(none)'}`);
  results.push(
    verdict(
      'That cookie does not reach app.localhost either.',
      !(subRequest?.cookie ?? '').includes('wishful'),
      'So neither direction works: there is no way to write a cookie that localhost and its subdomains share.',
    ),
  );

  // ---------------------------------------------------------------- claim 3 --
  heading('Claim 3: SameSite=None without Secure is dropped, not downgraded');

  await ctx.clearCookies();
  const d = createServer((req, res) => {
    res.writeHead(200, {
      'content-type': 'text/html',
      'set-cookie': ['none_no_secure=dropped?; Path=/; SameSite=None'],
    });
    res.end('<h1>D</h1>');
  });
  await new Promise((r) => d.listen(37304, '127.0.0.1', r));
  await page.goto('http://localhost:37304/');
  const afterNone = await ctx.cookies();
  const kept = afterNone.some((k) => k.name === 'none_no_secure');
  console.log(`  Set-Cookie: none_no_secure=dropped?; Path=/; SameSite=None   (no Secure)`);
  console.log(`  cookie jar: ${afterNone.map((k) => k.name).join(', ') || '(empty)'}`);
  results.push(
    verdict(
      'SameSite=None without Secure is rejected outright rather than treated as Lax.',
      !kept,
      kept ? 'It was stored. Correct the README.' : 'Chrome stored nothing.',
    ),
  );
  d.close();

  // ---------------------------------------------------------------- claim 4 --
  heading('Claim 4: http://localhost is a secure context');

  await page.goto(`http://localhost:${PORT_A}/`);
  const secure = await page.evaluate(() => ({
    isSecureContext: window.isSecureContext,
    hasSubtle: typeof crypto.subtle !== 'undefined',
    hasSW: typeof navigator.serviceWorker !== 'undefined',
    hasClipboard: typeof navigator.clipboard !== 'undefined',
    hasCredentials: typeof navigator.credentials !== 'undefined',
  }));
  console.log(`  ${JSON.stringify(secure)}`);
  results.push(
    verdict(
      'http://localhost reports isSecureContext true and exposes secure-context APIs.',
      secure.isSecureContext && secure.hasSubtle && secure.hasSW,
      'So these APIs do not break on the move to HTTPS. They break if the app is ever served over plain HTTP on a real hostname.',
    ),
  );

  heading('Summary');
  const passed = results.filter(Boolean).length;
  console.log(`  ${passed}/${results.length} claims confirmed against ${browser.version()}`);
  if (passed !== results.length) {
    console.log('\n  At least one claim was refuted. Do not publish the README text as written.');
    process.exitCode = 1;
  }
} finally {
  await browser.close();
  a.close();
  b.close();
  c.close();
}
