/**
 * Drive the target page and collect everything the rules need.
 *
 * Network capture goes through the Chrome DevTools Protocol rather than
 * Playwright's own request events, for three reasons that all matter here:
 *
 *   - `Network.responseReceivedExtraInfo` carries the *raw* response headers,
 *     so repeated `Set-Cookie` lines survive intact. Header maps collapse them.
 *   - It reports `blockedCookies` with Chrome's own reason codes. When Chrome
 *     rejects a cookie we quote Chrome rather than re-deriving the verdict.
 *   - `Audits.issueAdded` hands us the exact findings Chrome would show in the
 *     Issues panel, which is independent corroboration for several rules.
 */
import { pathToFileURL } from 'node:url';
import { resolve as resolvePath } from 'node:path';
import { instrumentPage } from './browser/instrument.js';
import { isScannableMime } from './collect/leaked-urls.js';

const DEFAULT_MAX_BODY_BYTES = 2 * 1024 * 1024;
const DEFAULT_TOTAL_BODY_BUDGET = 24 * 1024 * 1024;

/**
 * @typedef {object} Capture
 * @property {string} targetUrl
 * @property {string} finalUrl
 * @property {Array<object>} requests
 * @property {Array<object>} responses
 * @property {Array<object>} setCookies
 * @property {Array<object>} blockedCookies
 * @property {Array<object>} sentCookies
 * @property {Array<object>} bodies
 * @property {Array<object>} instrumentation
 * @property {Array<object>} chromeIssues
 * @property {Array<object>} consoleErrors
 * @property {Array<object>} jarCookies
 * @property {object} timing
 * @property {Array<string>} warnings
 */

/**
 * @param {object} opts
 * @param {import('playwright-core').BrowserType} opts.chromium
 * @param {{path: string, name: string, channel: string}} opts.browser
 * @param {string} opts.url
 * @param {string} [opts.flow]
 * @param {number} [opts.timeout]
 * @param {number} [opts.flowTimeout]
 * @param {number} [opts.settle]     Extra quiet time after load, ms.
 * @param {boolean} [opts.headed]
 * @param {(msg: string) => void} [opts.log]
 * @returns {Promise<Capture>}
 */
export async function runSession(opts) {
  const {
    chromium,
    browser: browserInfo,
    url,
    flow,
    timeout = 30_000,
    flowTimeout = 60_000,
    settle = 1200,
    headed = false,
    log = () => {},
  } = opts;

  const startedAt = Date.now();
  const warnings = [];

  /** @type {Capture} */
  const capture = {
    targetUrl: url,
    finalUrl: url,
    requests: [],
    responses: [],
    setCookies: [],
    blockedCookies: [],
    sentCookies: [],
    bodies: [],
    instrumentation: [],
    chromeIssues: [],
    consoleErrors: [],
    jarCookies: [],
    timing: {},
    warnings,
  };

  const browser = await launchBrowser(chromium, browserInfo, headed);

  try {
    const context = await browser.newContext({
      ignoreHTTPSErrors: true,
      // Deliberately a *fresh* jar. Cookies inherited from a real browser
      // profile would make the run unreproducible.
      serviceWorkers: 'allow',
    });
    context.setDefaultTimeout(timeout);

    const page = await context.newPage();

    // ---- instrumentation must be installed before anything navigates -------
    const sinkReady = installSink(page, capture);
    await page.addInitScript(instrumentPage);
    await sinkReady;

    const cdp = await context.newCDPSession(page);
    const bodyState = { total: 0, pending: [] };
    await attachNetwork(cdp, capture, bodyState, warnings);
    await attachAudits(cdp, capture, warnings);

    page.on('console', (msg) => {
      if (msg.type() !== 'error' && msg.type() !== 'warning') return;
      if (capture.consoleErrors.length > 200) return;
      capture.consoleErrors.push({ type: msg.type(), text: msg.text(), location: msg.location() });
    });

    // ---------------------------------------------------------------- load --
    const navStart = Date.now();
    let response;
    try {
      response = await page.goto(url, { waitUntil: 'domcontentloaded', timeout });
    } catch (err) {
      const e = new Error(`Could not load ${url}: ${err.message}`);
      e.code = 'UNREACHABLE';
      e.cause = err;
      throw e;
    }
    if (!response) {
      const e = new Error(`No response from ${url}. Is the dev server running?`);
      e.code = 'UNREACHABLE';
      throw e;
    }
    capture.timing.navigationMs = Date.now() - navStart;
    capture.status = response.status();
    log(`loaded ${url} (${response.status()}) in ${capture.timing.navigationMs}ms`);

    await quiet(page, settle);

    // ---------------------------------------------------------------- flow --
    if (flow) {
      const flowStart = Date.now();
      capture.flow = { path: flow, ok: false };
      try {
        await runFlow({ flow, page, context, browser, timeout: flowTimeout, log });
        capture.flow.ok = true;
        log(`flow completed in ${Date.now() - flowStart}ms`);
      } catch (err) {
        capture.flow.error = err.message;
        warnings.push(
          `The --flow script failed: ${err.message}\n` +
            'Findings below cover only what ran before it failed. Post-login cookies are probably missing.',
        );
      }
      capture.timing.flowMs = Date.now() - flowStart;
      await quiet(page, settle);
    }

    capture.finalUrl = page.url();

    // ------------------------------------------------------------- collect --
    await Promise.allSettled(bodyState.pending);
    capture.jarCookies = await context.cookies().catch(() => []);
    await drainInstrumentation(page, capture);

    capture.timing.totalMs = Date.now() - startedAt;
    capture.browser = { name: browserInfo.name, channel: browserInfo.channel, path: browserInfo.path };
    capture.browserVersion = browser.version();
    return capture;
  } finally {
    await browser.close().catch(() => {});
  }
}

/**
 * Launch the browser, and turn a launch failure into something a person can
 * act on.
 *
 * Playwright's launch error embeds the entire Chrome stderr -- forty lines of
 * stack frames and register dumps. That is the right thing to keep, but it is
 * the wrong thing to lead with, so the diagnosis goes in the message and the
 * dump goes behind --verbose.
 */
async function launchBrowser(chromium, browserInfo, headed) {
  try {
    return await chromium.launch(launchOptions(browserInfo, headed));
  } catch (err) {
    const raw = String(err?.message ?? err);
    const e = new Error(`${browserInfo.name} would not start.\n\n${diagnoseLaunchFailure(raw, browserInfo)}`);
    e.code = 'BROWSER_LAUNCH';
    e.browserLog = raw;
    e.cause = err;
    throw e;
  }
}

/**
 * Map the failure modes we have actually hit to a remedy. Anything unmatched
 * falls through to the first few lines of Chrome's own output, which beats a
 * generic apology.
 */
function diagnoseLaunchFailure(raw, browserInfo) {
  if (/chrome_crashpad_handler: Permission denied|Permission denied \(13\)/.test(raw)) {
    return [
      'A helper binary next to the browser is not executable.',
      '',
      'This happens when a Chrome build is unpacked by something that drops the',
      'executable bit -- most zip extractors do. Fix it with:',
      '',
      `  chmod +x "${browserInfo.path}"`,
      `  chmod +x "$(dirname "${browserInfo.path}")"/*`,
    ].join('\n');
  }
  if (/error while loading shared libraries: (\S+)/.test(raw)) {
    const lib = raw.match(/error while loading shared libraries: (\S+)/)[1];
    return [
      `A shared library the browser needs is missing: ${lib}`,
      '',
      'On Debian or Ubuntu, the usual fix is:',
      '',
      '  sudo apt-get install -y libnss3 libnspr4 libasound2t64 libatk1.0-0t64 \\',
      '      libatk-bridge2.0-0t64 libcups2t64 libdrm2 libgbm1 libxkbcommon0 \\',
      '      libxcomposite1 libxdamage1 libxfixes3 libxrandr2 libpango-1.0-0 libcairo2',
    ].join('\n');
  }
  if (/No usable sandbox|SUID sandbox|Running as root without --no-sandbox/.test(raw)) {
    return [
      'The browser sandbox could not start.',
      '',
      'This is normal inside an unprivileged container. Either run as a non-root',
      'user, or grant the container SYS_ADMIN. notlocalhost does not pass',
      '--no-sandbox for you, because silently disabling the sandbox on a',
      "developer's machine is not ours to decide.",
    ].join('\n');
  }
  if (/spawn .* EACCES|EACCES/.test(raw)) {
    return `The browser binary is not executable:\n\n  chmod +x "${browserInfo.path}"`;
  }
  if (/ENOENT/.test(raw)) {
    return `Nothing is at that path any more:\n\n  ${browserInfo.path}\n\nRun \`notlocalhost --list-browsers\` to see what is installed.`;
  }

  const firstLines = raw
    .split('\n')
    .filter((l) => l.trim() && !/^\s*#\d+ 0x|^\s*\[pid=|^\s*[a-z]{2,3}: [0-9a-f]{16}/.test(l))
    .slice(0, 4)
    .join('\n');
  return `Chrome reported:\n\n${firstLines}\n\nRe-run with --verbose for the full browser log.`;
}

function launchOptions(browserInfo, headed) {
  return {
    executablePath: browserInfo.path,
    headless: !headed,
    args: [
      // A clean, boring profile. No extensions, no first-run UI, no policies
      // from the developer's real profile leaking into the verdict.
      '--no-first-run',
      '--no-default-browser-check',
      '--disable-extensions',
      '--disable-background-networking',
      '--disable-component-update',
      '--disable-client-side-phishing-detection',
      '--disable-sync',
      '--metrics-recording-only',
      '--no-service-autorun',
      '--password-store=basic',
      '--use-mock-keychain',
    ],
  };
}

// ---------------------------------------------------------------------------

async function installSink(page, capture) {
  await page.exposeFunction('__nlh_sink', (json) => {
    try {
      const batch = JSON.parse(json);
      for (const ev of batch) {
        if (capture.instrumentation.length >= 5000) return;
        capture.instrumentation.push(ev);
      }
    } catch {
      /* a malformed batch is not worth failing the run over */
    }
  });
}

async function drainInstrumentation(page, capture) {
  for (const frame of page.frames()) {
    try {
      const remaining = await frame.evaluate(() => {
        const s = window.__nlh;
        if (!s) return { events: [], dropped: 0 };
        const events = s.events.splice(0, s.events.length);
        return { events, dropped: s.dropped };
      });
      for (const ev of remaining.events) capture.instrumentation.push(ev);
      if (remaining.dropped) {
        capture.warnings.push(
          `Instrumentation dropped ${remaining.dropped} events in ${frame.url()} after hitting its buffer cap.`,
        );
      }
    } catch {
      // Frame detached mid-drain. Anything it produced was already flushed
      // through the binding.
    }
  }
}

async function attachNetwork(cdp, capture, bodyState, warnings) {
  await cdp.send('Network.enable', {
    maxResourceBufferSize: DEFAULT_TOTAL_BODY_BUDGET,
    maxTotalBufferSize: DEFAULT_TOTAL_BODY_BUDGET * 2,
  });

  /** requestId -> partial record */
  const byId = new Map();

  cdp.on('Network.requestWillBeSent', (e) => {
    const rec = {
      requestId: e.requestId,
      url: e.request.url,
      method: e.request.method,
      resourceType: e.type || 'Other',
      documentURL: e.documentURL,
      frameId: e.frameId,
      initiator: summariseInitiator(e.initiator),
      headers: e.request.headers || {},
      hasPostData: Boolean(e.request.hasPostData),
      redirectOf: e.redirectResponse ? e.redirectResponse.url : null,
      timestamp: e.timestamp,
    };
    byId.set(e.requestId, rec);
    capture.requests.push(rec);

    // A redirect reuses the requestId, so its Set-Cookie headers arrive here
    // rather than on a response event. They count.
    if (e.redirectResponse) {
      harvestSetCookie(capture, e.redirectResponse.url, e.redirectResponse.headers, 'redirect', rec);
    }
  });

  cdp.on('Network.requestWillBeSentExtraInfo', (e) => {
    const rec = byId.get(e.requestId);
    const list = e.associatedCookies || [];
    for (const entry of list) {
      capture.sentCookies.push({
        requestId: e.requestId,
        url: rec ? rec.url : null,
        name: entry.cookie?.name,
        domain: entry.cookie?.domain,
        path: entry.cookie?.path,
        secure: entry.cookie?.secure,
        httpOnly: entry.cookie?.httpOnly,
        sameSite: entry.cookie?.sameSite ?? null,
        sourcePort: entry.cookie?.sourcePort ?? null,
        sourceScheme: entry.cookie?.sourceScheme ?? null,
        blockedReasons: entry.blockedReasons || [],
        exemptionReason: entry.exemptionReason,
      });
    }
    if (rec && e.headers) rec.rawRequestHeaders = e.headers;
  });

  cdp.on('Network.responseReceived', (e) => {
    const rec = byId.get(e.requestId) || { requestId: e.requestId, url: e.response.url };
    rec.status = e.response.status;
    rec.mimeType = e.response.mimeType;
    rec.responseHeaders = e.response.headers || {};
    rec.remoteAddress = e.response.remoteIPAddress
      ? `${e.response.remoteIPAddress}:${e.response.remotePort}`
      : null;
    rec.securityState = e.response.securityState;
    rec.fromServiceWorker = Boolean(e.response.fromServiceWorker);
    rec.protocol = e.response.protocol;
    capture.responses.push(rec);
  });

  cdp.on('Network.responseReceivedExtraInfo', (e) => {
    const rec = byId.get(e.requestId);
    const url = rec ? rec.url : null;
    // Raw headers: repeated Set-Cookie lines arrive newline-joined.
    harvestSetCookie(capture, url, e.headers, 'response', rec);

    for (const b of e.blockedCookies || []) {
      capture.blockedCookies.push({
        requestId: e.requestId,
        url,
        raw: b.cookieLine,
        name: b.cookie?.name,
        reasons: b.blockedReasons || [],
      });
    }
    if (rec) rec.rawResponseHeaders = e.headers;
  });

  cdp.on('Network.loadingFinished', (e) => {
    const rec = byId.get(e.requestId);
    if (!rec) return;
    rec.encodedDataLength = e.encodedDataLength;
    if (!isScannableMime(rec.mimeType || '')) return;
    if (bodyState.total >= DEFAULT_TOTAL_BODY_BUDGET) return;

    const p = cdp
      .send('Network.getResponseBody', { requestId: e.requestId })
      .then((res) => {
        if (!res || res.base64Encoded) return;
        const body = res.body || '';
        if (body.length > DEFAULT_MAX_BODY_BYTES) {
          warnings.push(`Truncated ${rec.url} at ${DEFAULT_MAX_BODY_BYTES} bytes when scanning.`);
        }
        const sliced = body.slice(0, DEFAULT_MAX_BODY_BYTES);
        bodyState.total += sliced.length;
        capture.bodies.push({
          url: rec.url,
          kind: (rec.resourceType || 'other').toLowerCase(),
          mimeType: rec.mimeType,
          bytes: sliced.length,
          body: sliced,
        });
      })
      .catch(() => {
        // Bodies get evicted, and service-worker responses often have none.
        // A missing body narrows coverage; it does not invalidate the run.
      });
    bodyState.pending.push(p);
  });

  cdp.on('Network.loadingFailed', (e) => {
    const rec = byId.get(e.requestId);
    if (!rec) return;
    rec.failed = { errorText: e.errorText, blockedReason: e.blockedReason, corsErrorStatus: e.corsErrorStatus };
  });
}

async function attachAudits(cdp, capture, warnings) {
  try {
    await cdp.send('Audits.enable');
  } catch {
    warnings.push('Chrome refused Audits.enable; findings will not include Chrome\'s own Issues-panel verdicts.');
    return;
  }
  cdp.on('Audits.issueAdded', (e) => {
    if (capture.chromeIssues.length >= 300) return;
    capture.chromeIssues.push({ code: e.issue?.code, details: e.issue?.details });
  });
}

function harvestSetCookie(capture, url, headers, phase, rec) {
  if (!headers) return;
  // Raw CDP headers preserve case as sent; be tolerant anyway.
  const key = Object.keys(headers).find((k) => k.toLowerCase() === 'set-cookie');
  if (!key) return;
  const lines = String(headers[key]).split('\n').map((l) => l.trim()).filter(Boolean);
  for (const line of lines) {
    capture.setCookies.push({
      raw: line,
      url,
      phase,
      resourceType: rec ? rec.resourceType : null,
      documentURL: rec ? rec.documentURL : null,
      source: 'Set-Cookie',
    });
  }
}

function summariseInitiator(initiator) {
  if (!initiator) return null;
  const frames = initiator.stack?.callFrames || [];
  return {
    type: initiator.type,
    url: initiator.url,
    lineNumber: initiator.lineNumber,
    stack: frames.slice(0, 5).map((f) => `${f.functionName || '(anonymous)'} @ ${f.url}:${f.lineNumber + 1}`),
  };
}

/** Wait for the page to stop making requests, but never for very long. */
async function quiet(page, settle) {
  if (settle <= 0) return;
  await page.waitForLoadState('networkidle', { timeout: settle * 4 }).catch(() => {});
  await page.waitForTimeout(settle);
}

// ---------------------------------------------------------------------------

/**
 * Load and run a user flow script.
 *
 * The contract is deliberately tiny: default-export an async function, receive
 * a live Playwright `page`. Everything the analyzer does is already wired up,
 * so the script only has to perform the login.
 */
async function runFlow({ flow, page, context, browser, timeout, log }) {
  const abs = resolvePath(process.cwd(), flow);
  let mod;
  try {
    mod = await import(pathToFileURL(abs).href);
  } catch (err) {
    throw new Error(`could not load flow script ${abs}: ${err.message}`);
  }

  const fn = typeof mod.default === 'function' ? mod.default : typeof mod.flow === 'function' ? mod.flow : null;
  if (!fn) {
    throw new Error(
      `flow script ${abs} must default-export an async function, e.g. ` +
        '`export default async ({ page }) => { await page.fill("#email", "a@b.c") }`',
    );
  }

  let timer;
  const budget = new Promise((_, reject) => {
    timer = setTimeout(() => reject(new Error(`flow exceeded --flow-timeout of ${timeout}ms`)), timeout);
  });

  try {
    await Promise.race([fn({ page, context, browser, log }), budget]);
  } finally {
    clearTimeout(timer);
  }
}

/** Exposed for tests: the launch-failure diagnosis is worth asserting on. */
export const _internal = { diagnoseLaunchFailure, launchOptions };
