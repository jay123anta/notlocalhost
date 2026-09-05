/**
 * Orchestration: locate a browser, drive the page, run the rules, build the
 * schema-versioned result document that every output format renders from.
 */
import { chromium } from 'playwright-core';
import { locateBrowser } from './browser/locate.js';
import { runSession } from './session.js';
import { scanLoopbackPorts } from './collect/port-scan.js';
import { createDeploymentModel, parseOrigin, sharesDefaultCookieJar } from './collect/origins.js';
import { runRules } from './rules/index.js';
import { severityRank, atOrAbove } from './rules/finding.js';
import { VERSION, SCHEMA_VERSION } from './version.js';

/**
 * The limitations block. It ships inside every JSON document and every HTML
 * report, not just the README, because the person reading a CI artifact six
 * months from now is the one who most needs it.
 */
export const LIMITATIONS = [
  'This predicts behaviour on a real HTTPS origin. It does not prove it. The only proof is serving the app from that origin.',
  'It observes only code paths that actually executed during the run. Coverage of findings equals coverage of the run, which is why --flow matters more than any individual rule.',
  'Chrome family only (Chrome, Chromium, Edge). Firefox and Safari differ on SameSite defaults, cookie partitioning and secure-context edge cases.',
  'A clean result means "no findings in what was exercised". It never means "safe".',
  'The deployment model is an assumption, printed above. Change it with --domain, --map and --cross-site if it does not match your topology.',
  'Source scanning reads what the dev server served. A production build may substitute different values, and code that did not load was not scanned.',
  'Findings from a single page load do not cover other routes. Run the analyzer against the routes that matter.',
  'Two runs against the same app can differ. What a dev server serves changes between runs -- asset pipelines compile once and then cache, bundles get split differently, lazy routes load or do not. A finding that appears once and not again was real both times; the code that produced it simply did not get served the second time.',
];

/**
 * @param {object} options
 * @param {string} options.url
 * @param {string} [options.flow]
 * @param {string} [options.domain]
 * @param {boolean} [options.crossSite]
 * @param {Record<string,string>} [options.map]
 * @param {number} [options.timeout]
 * @param {number} [options.flowTimeout]
 * @param {number} [options.settle]
 * @param {boolean} [options.headed]
 * @param {boolean} [options.noPortScan]
 * @param {string} [options.browserPath]
 * @param {string} [options.channel]
 * @param {(msg: string) => void} [options.log]
 */
export async function analyze(options) {
  const {
    url,
    flow,
    domain = 'example.com',
    crossSite = false,
    map = {},
    mapPaths = {},
    timeout,
    flowTimeout,
    settle,
    headed = false,
    noPortScan = false,
    browserPath,
    channel,
    log = () => {},
  } = options;

  const startedAt = new Date();
  const target = parseOrigin(url);
  if (!target) {
    const e = new Error(`"${url}" is not a valid http(s) URL.`);
    e.code = 'USAGE';
    throw e;
  }

  const browser = locateBrowser({ explicitPath: browserPath, channel });
  log(`using ${browser.name} at ${browser.path}`);

  // Probe for neighbours before we navigate, so the port list reflects the
  // machine as the developer left it rather than as our own browser left it.
  //
  // Only worth doing when the target is in the jar those neighbours share. On
  // app.myproject.localhost the scan would find the same ports and mean nothing
  // by them, so it is skipped rather than reported as an empty result.
  const scanUseful = !noPortScan && sharesDefaultCookieJar(target.hostname);
  const openPorts = scanUseful ? await scanLoopbackPorts({ exclude: Number(target.port) }).catch(() => []) : [];
  if (openPorts.length) log(`other loopback listeners: ${openPorts.join(', ')}`);

  const capture = await runSession({
    chromium,
    browser,
    url,
    flow,
    timeout,
    flowTimeout,
    settle,
    headed,
    log,
  });

  const model = createDeploymentModel({ domain, crossSite, explicit: map, paths: mapPaths });
  const ctx = { capture, model, openPorts, targetUrl: url, platform: process.platform };
  const { findings, moduleErrors } = runRules(ctx);

  const counts = {
    'will-break': findings.filter((f) => f.severity === 'will-break').length,
    'may-break': findings.filter((f) => f.severity === 'may-break').length,
    info: findings.filter((f) => f.severity === 'info').length,
  };

  return {
    schemaVersion: SCHEMA_VERSION,
    tool: { name: 'notlocalhost', version: VERSION },
    startedAt: startedAt.toISOString(),
    finishedAt: new Date().toISOString(),
    target: {
      url,
      finalUrl: capture.finalUrl,
      status: capture.status ?? null,
      origin: target.origin,
      isLoopback: target.isLoopback,
    },
    browser: {
      name: capture.browser?.name,
      channel: capture.browser?.channel,
      version: capture.browserVersion,
      executablePath: capture.browser?.path,
    },
    deploymentModel: {
      domain,
      crossSite,
      description: crossSite
        ? 'Each distinct local port is assumed to become a distinct registrable domain (a genuinely cross-site topology).'
        : 'Each distinct local port is assumed to become a distinct subdomain of one registrable domain (cross-origin, same-site).',
      mapping: model.mapping,
      pathMapping: mapPaths,
    },
    coverage: {
      flow: capture.flow ?? null,
      requests: capture.requests.length,
      responses: capture.responses.length,
      bodiesScanned: capture.bodies.length,
      bytesScanned: capture.bodies.reduce((n, b) => n + b.bytes, 0),
      cookiesObserved: capture.setCookies.length,
      instrumentationEvents: capture.instrumentation.length,
      otherLoopbackListeners: openPorts,
      portScanSkipped: !scanUseful,
      timing: capture.timing,
    },
    counts,
    findings,
    warnings: [...capture.warnings, ...moduleErrors.map((m) => `rule module "${m.module}" failed: ${m.error}`)],
    limitations: LIMITATIONS,
  };
}

/**
 * @param {{counts: Record<string, number>}} result
 * @param {'will-break'|'may-break'|'info'|'none'} threshold
 */
export function shouldFail(result, threshold) {
  if (threshold === 'none') return false;
  for (const [severity, count] of Object.entries(result.counts)) {
    if (count > 0 && atOrAbove(severity, threshold)) return true;
  }
  return false;
}

export { severityRank };
