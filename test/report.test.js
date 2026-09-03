/**
 * The HTML report has one hard requirement: it opens from the filesystem, on a
 * machine with no internet, and works. A CI artifact that needs a server is not
 * an artifact.
 *
 * So this test does not inspect the HTML string -- it loads the file over
 * `file://` in a real browser with every outbound request blocked, and checks
 * that the page still renders findings and that its filter controls work.
 */
import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { chromium } from 'playwright-core';

import { renderHtml } from '../src/report/html.js';
import { locateBrowser } from '../src/browser/locate.js';
import { finding } from '../src/rules/finding.js';
import { SCHEMA_VERSION } from '../src/version.js';

let haveBrowser = true;
try {
  locateBrowser();
} catch {
  haveBrowser = false;
}
const skip = haveBrowser ? false : 'no Chrome, Chromium or Edge installed';

const result = {
  schemaVersion: SCHEMA_VERSION,
  tool: { name: 'notlocalhost', version: '0.0.0-test' },
  startedAt: '2026-01-01T00:00:00.000Z',
  finishedAt: '2026-01-01T00:00:05.000Z',
  target: {
    url: 'http://localhost:3000',
    finalUrl: 'http://localhost:3000/',
    status: 200,
    origin: 'http://localhost:3000',
    isLoopback: true,
  },
  browser: { name: 'Google Chrome', channel: 'chrome', version: '152.0.0.0', executablePath: '/x' },
  deploymentModel: {
    domain: 'example.com',
    crossSite: false,
    description: 'Each distinct local port becomes a subdomain of one registrable domain.',
    mapping: { 'localhost:3000': 'app.example.com', 'localhost:4000': 'svc-4000.example.com' },
  },
  coverage: {
    flow: { path: './login.js', ok: true },
    requests: 12,
    responses: 12,
    bodiesScanned: 4,
    bytesScanned: 148_000,
    cookiesObserved: 5,
    instrumentationEvents: 9,
    otherLoopbackListeners: [4000, 8080],
    portScanSkipped: false,
    timing: { totalMs: 5123 },
  },
  counts: { 'will-break': 2, 'may-break': 1, info: 1 },
  findings: [
    finding({
      id: 'cookie.samesite-none-without-secure',
      severity: 'will-break',
      title: 'Cookie "ab_test" is SameSite=None without Secure',
      summary: 'Chrome rejects this cookie outright.\n\nIt is not downgraded to Lax; it is dropped.',
      evidence: [{ label: 'Set-Cookie', value: 'ab_test=variant-b; Path=/; SameSite=None' }],
      fix: ['Add Secure.'],
      refs: [{ title: 'RFC 6265bis', url: 'https://example.invalid/spec' }],
    }),
    finding({
      id: 'cookie.port-sharing-hazard',
      severity: 'will-break',
      title: 'Cookies from localhost:3000 are also sent to 2 other servers',
      summary: 'Cookies have no concept of a port.',
      evidence: [{ label: 'target', value: 'http://localhost:3000' }],
      fix: ['Use distinct hostnames.'],
    }),
    finding({
      id: 'cookie.missing-secure',
      severity: 'may-break',
      title: 'Session-shaped cookie "sid" has no Secure attribute',
      summary: 'It could not have one over plain HTTP.',
      evidence: [{ label: 'Set-Cookie', value: 'sid=abc; HttpOnly' }],
      fix: ['Verify the production configuration.'],
    }),
    finding({
      id: 'origin.inventory',
      severity: 'info',
      title: 'Requests went to 2 origins',
      summary: 'How each origin is classified.',
      evidence: [{ label: 'http://localhost:3000', value: 'same-origin' }],
    }),
  ],
  warnings: [],
  limitations: [
    'This predicts behaviour on a real HTTPS origin. It does not prove it.',
    'A clean result means "no findings in what was exercised". It never means "safe".',
  ],
};

let tmp;
let reportPath;

before(() => {
  tmp = mkdtempSync(join(tmpdir(), 'nlh-report-'));
  reportPath = join(tmp, 'notlocalhost-report.html');
  writeFileSync(reportPath, renderHtml(result), 'utf8');
});

after(() => {
  if (tmp) rmSync(tmp, { recursive: true, force: true });
});

describe('the HTML report', { skip }, () => {
  test('is a single file under 2 MB', () => {
    const bytes = statSync(reportPath).size;
    assert.ok(bytes > 0);
    assert.ok(bytes < 2 * 1024 * 1024, `report is ${bytes} bytes`);
  });

  test('opens from file:// with every outbound request blocked, and still renders', async () => {
    const browser = await chromium.launch({ executablePath: locateBrowser().path, headless: true });
    try {
      const context = await browser.newContext();

      // Anything that is not the file itself is a bug. Fail the request and
      // record it, so a stray CDN link cannot pass by degrading quietly.
      const blocked = [];
      await context.route('**/*', (route) => {
        const url = route.request().url();
        if (url.startsWith('file://')) return route.continue();
        blocked.push(url);
        return route.abort();
      });

      const page = await context.newPage();
      const consoleErrors = [];
      page.on('pageerror', (e) => consoleErrors.push(String(e)));

      await page.goto(pathToFileURL(reportPath).href, { waitUntil: 'load' });

      assert.deepEqual(blocked, [], `the report requested external resources: ${blocked.join(', ')}`);
      assert.deepEqual(consoleErrors, [], `the report threw: ${consoleErrors.join(', ')}`);

      // The claim is on the page.
      await page.locator('h1', { hasText: 'Your localhost is lying to you' }).waitFor({ timeout: 5000 });

      // Every finding rendered.
      assert.equal(await page.locator('article.finding').count(), 4);
      assert.equal(await page.locator('article.finding.will-break').count(), 2);

      // The limitations are on the page, not just in the README.
      const limits = await page.locator('#limitations').innerText();
      assert.match(limits, /never means "safe"/);

      // The deployment model it assumed is stated.
      const model = await page.locator('.model').innerText();
      assert.match(model, /app\.example\.com/);

      // Titles survived escaping intact.
      const first = await page.locator('article.finding h4').first().innerText();
      assert.match(first, /SameSite=None without Secure/);

      await browser.close();
    } finally {
      await browser.close().catch(() => {});
    }
  });

  test('the severity filters and text search work with no network', async () => {
    const browser = await chromium.launch({ executablePath: locateBrowser().path, headless: true });
    try {
      const context = await browser.newContext();
      await context.route('**/*', (route) =>
        route.request().url().startsWith('file://') ? route.continue() : route.abort(),
      );
      const page = await context.newPage();
      await page.goto(pathToFileURL(reportPath).href, { waitUntil: 'load' });

      const visible = () => page.locator('article.finding:not([hidden])').count();
      assert.equal(await visible(), 4);

      // Turning off will-break hides exactly the two will-break findings.
      await page.locator('.filter[data-sev="will-break"]').click();
      assert.equal(await visible(), 2);
      assert.equal(await page.locator('.filter[data-sev="will-break"]').getAttribute('aria-pressed'), 'false');

      await page.locator('.filter[data-sev="will-break"]').click();
      assert.equal(await visible(), 4);

      // Text search narrows to the matching finding.
      await page.fill('#q', 'port-sharing');
      assert.equal(await visible(), 1);

      // A term that matches nothing shows the empty state.
      await page.fill('#q', 'zzzznomatch');
      assert.equal(await visible(), 0);
      assert.equal(await page.locator('.empty').isVisible(), true);

      await browser.close();
    } finally {
      await browser.close().catch(() => {});
    }
  });

  test('the embedded data island parses as the same document', async () => {
    const browser = await chromium.launch({ executablePath: locateBrowser().path, headless: true });
    try {
      const context = await browser.newContext();
      const page = await context.newPage();
      await page.goto(pathToFileURL(reportPath).href, { waitUntil: 'load' });

      const doc = await page.evaluate(() => JSON.parse(document.getElementById('data').textContent));
      assert.equal(doc.schemaVersion, SCHEMA_VERSION);
      assert.equal(doc.findings.length, 4);
      assert.deepEqual(doc.counts, result.counts);

      await browser.close();
    } finally {
      await browser.close().catch(() => {});
    }
  });
});
