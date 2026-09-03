/**
 * Secure-context and mixed-content rules.
 *
 * The honest framing matters here, and most write-ups get it backwards.
 * `http://localhost` IS a secure context. The Secure Contexts spec lists
 * loopback as "potentially trustworthy", so service workers, geolocation,
 * clipboard, WebAuthn and crypto.subtle all work locally over plain HTTP.
 *
 * So these APIs do not break when you move to HTTPS -- they keep working. The
 * failure mode is the *other* direction: the same app served over plain HTTP
 * on a real hostname (a staging box on http://staging.internal, an origin
 * behind a proxy that terminates TLS but forwards http://, a preview URL
 * someone typed without the s) loses secure-context status and every one of
 * these APIs silently becomes undefined or throws.
 *
 * We report what the page touched, and we say exactly which deployment shapes
 * would break it. We do not pretend HTTPS is the risk.
 */
import { finding, REF } from './finding.js';
import { parseOrigin } from '../collect/origins.js';

const API_CONSEQUENCE = {
  'navigator.serviceWorker': {
    onPlainHttp: 'undefined. Registration throws a TypeError, so offline support, push and any SW-based caching disappear.',
    weight: 'high',
  },
  'navigator.geolocation': {
    onPlainHttp: 'present but every request fails with PERMISSION_DENIED and no prompt is shown.',
    weight: 'high',
  },
  'navigator.clipboard': {
    onPlainHttp: 'undefined. Copy buttons silently do nothing.',
    weight: 'medium',
  },
  'navigator.credentials': {
    onPlainHttp: 'undefined. WebAuthn and passkey sign-in cannot start at all.',
    weight: 'high',
  },
  'navigator.mediaDevices': {
    onPlainHttp: 'undefined. getUserMedia is unreachable, so camera and microphone features fail before any prompt.',
    weight: 'high',
  },
  'crypto.subtle': {
    onPlainHttp: 'undefined. Any code that hashes, signs or derives a key throws on property access.',
    weight: 'high',
  },
  'navigator.storage': { onPlainHttp: 'undefined. Persistent-storage requests and quota estimates fail.', weight: 'medium' },
  'navigator.locks': { onPlainHttp: 'undefined. Web Locks coordination between tabs fails.', weight: 'medium' },
  'navigator.usb': { onPlainHttp: 'undefined.', weight: 'low' },
  'navigator.bluetooth': { onPlainHttp: 'undefined.', weight: 'low' },
  'navigator.hid': { onPlainHttp: 'undefined.', weight: 'low' },
  'navigator.serial': { onPlainHttp: 'undefined.', weight: 'low' },
};

export function secureContextRules(ctx) {
  const { capture, targetUrl } = ctx;
  const out = [];
  const target = parseOrigin(capture.finalUrl || targetUrl);

  const touched = new Map();
  for (const ev of capture.instrumentation) {
    if (ev.type !== 'securecontext.touch') continue;
    if (!touched.has(ev.api)) touched.set(ev.api, ev);
  }

  const branches = capture.instrumentation.filter((e) => e.type === 'securecontext.branch');

  if (touched.size) {
    const high = [...touched.keys()].filter((a) => (API_CONSEQUENCE[a]?.weight ?? 'low') === 'high');

    out.push(
      finding({
        id: 'securecontext.apis-used',
        severity: high.length ? 'may-break' : 'info',
        title: `The page uses ${touched.size} secure-context-only API${touched.size === 1 ? '' : 's'}`,
        summary:
          'These work right now because loopback is classed as a potentially trustworthy origin, so ' +
          `${target?.scheme === 'http' ? 'http://localhost' : 'this origin'} is a secure context despite the scheme. ` +
          'They will keep working over HTTPS.\n\n' +
          'They break, silently and completely, if this app is ever served over plain HTTP on a real hostname -- ' +
          'a staging box on http://, a preview link without the s, or a reverse proxy that terminates TLS and ' +
          'forwards plain HTTP without the app knowing. That is the misconfiguration this finding exists to ' +
          'pre-empt, and it is common precisely because localhost never warns you.',
        evidence: [...touched.entries()].map(([api, ev]) => ({
          label: api,
          value:
            `on plain HTTP: ${API_CONSEQUENCE[api]?.onPlainHttp ?? 'unavailable.'}` +
            (ev.stack?.[0] ? `  <- ${ev.stack[0]}` : ''),
        })),
        fix: [
          'Serve every non-local environment over HTTPS, including staging and preview deployments.',
          'If a proxy terminates TLS, make sure the app sees the real scheme (X-Forwarded-Proto and trusted-proxy config) so its own URL generation stays https.',
          'Add a runtime guard: if `window.isSecureContext` is false outside development, fail loudly instead of degrading silently.',
          ...(high.length
            ? [`Highest-impact if this happens: ${high.join(', ')}.`]
            : []),
        ],
        refs: [REF.secureContexts, REF.potentiallyTrustworthy],
      }),
    );
  }

  if (branches.length) {
    out.push(
      finding({
        id: 'securecontext.untested-branch',
        severity: 'info',
        title: 'The app branches on window.isSecureContext',
        summary:
          'On localhost `isSecureContext` is always true, so only one side of this branch ever runs during ' +
          'development. Whatever the false branch does -- a fallback, a warning, a disabled feature -- is ' +
          'untested code that only real users reach.',
        evidence: branches.slice(0, 5).map((b) => ({
          label: b.url,
          value: b.stack?.[0] ?? '(no stack captured)',
        })),
        fix: ['Exercise the false branch deliberately, or delete it.'],
        refs: [REF.secureContexts],
      }),
    );
  }

  return out;
}

/**
 * Mixed content.
 *
 * Nothing here is a prediction about cookies; it is arithmetic. An HTTPS page
 * may not load active plain-HTTP subresources, full stop. Chrome blocks
 * scripts, XHR/fetch, WebSockets, iframes and stylesheets outright, and
 * auto-upgrades or blocks images and media.
 */
export function mixedContentRules(ctx) {
  const { capture, targetUrl } = ctx;
  const pageUrl = capture.finalUrl || targetUrl;
  const page = parseOrigin(pageUrl);
  const out = [];

  const ACTIVE_TYPES = new Set(['Script', 'XHR', 'Fetch', 'Stylesheet', 'Document', 'WebSocket', 'EventSource', 'Manifest', 'Other']);
  const PASSIVE_TYPES = new Set(['Image', 'Media', 'Font']);

  const active = [];
  const passive = [];

  const candidates = [
    ...capture.requests.map((r) => ({ url: r.url, type: r.resourceType, from: r.initiator?.url })),
    ...capture.instrumentation
      .filter((e) => e.type === 'request.websocket' && e.target)
      .map((e) => ({ url: e.target, type: 'WebSocket', from: e.stack?.[0] })),
  ];

  for (const c of candidates) {
    const p = parseOrigin(c.url);
    if (!p || !p.isHttp) continue;
    // A loopback subresource is a different (and already reported) problem:
    // it is a leaked local URL, not mixed content in the classic sense --
    // though it is both once deployed.
    if (p.isLoopback && page?.isLoopback) continue;
    if (PASSIVE_TYPES.has(c.type)) passive.push(c);
    else if (ACTIVE_TYPES.has(c.type)) active.push(c);
  }

  if (active.length) {
    out.push(
      finding({
        id: 'mixedcontent.active',
        severity: 'will-break',
        title: `${active.length} active subresource${active.length === 1 ? '' : 's'} loaded over plain HTTP`,
        summary:
          'Once the page is served over HTTPS, Chrome blocks active mixed content unconditionally -- scripts, ' +
          'stylesheets, fetch/XHR, WebSockets and iframes. There is no user override and no console prompt worth ' +
          'noticing. The feature simply stops existing. This cannot appear locally, because an http:// page is ' +
          'allowed to load http:// subresources.',
        evidence: dedupeBy(active, (a) => a.url)
          .slice(0, 15)
          .map((a) => ({ label: a.type, value: `${a.url}${a.from ? `  <- ${a.from}` : ''}` })),
        fix: [
          'Serve every one of these over https://, or use protocol-relative resolution against the page origin.',
          'ws:// must become wss://. It is blocked exactly like a script.',
          'Add a Content-Security-Policy with `upgrade-insecure-requests` as a backstop, not as the fix.',
        ],
        refs: [REF.mixedContent],
      }),
    );
  }

  if (passive.length) {
    out.push(
      finding({
        id: 'mixedcontent.passive',
        severity: 'may-break',
        title: `${passive.length} passive subresource${passive.length === 1 ? '' : 's'} loaded over plain HTTP`,
        summary:
          'Chrome autoupgrades plain-HTTP images and media on an HTTPS page to https:// and blocks them if the ' +
          'upgrade fails. If the host does not serve HTTPS, these disappear rather than degrade.',
        evidence: dedupeBy(passive, (a) => a.url)
          .slice(0, 15)
          .map((a) => ({ label: a.type, value: a.url })),
        fix: ['Confirm every one of these hosts serves the same path over HTTPS, or move the asset.'],
        refs: [REF.mixedContent],
      }),
    );
  }

  // Chrome's own verdict, when it has one.
  const chromeMixed = capture.chromeIssues.filter((i) => /MixedContent/i.test(i.code ?? ''));
  if (chromeMixed.length) {
    out.push(
      finding({
        id: 'mixedcontent.chrome-issue',
        severity: 'may-break',
        title: `Chrome raised ${chromeMixed.length} mixed-content issue${chromeMixed.length === 1 ? '' : 's'} during this run`,
        summary: 'Reported by Chrome itself through the DevTools Issues channel, not inferred by us.',
        evidence: chromeMixed.slice(0, 10).map((i) => ({
          label: i.code,
          value: JSON.stringify(i.details ?? {}).slice(0, 300),
        })),
        fix: ['Open the same page in Chrome DevTools > Issues for the full context.'],
        refs: [REF.mixedContent],
      }),
    );
  }

  return out;
}

function dedupeBy(list, keyFn) {
  const seen = new Set();
  const out = [];
  for (const item of list) {
    const k = keyFn(item);
    if (seen.has(k)) continue;
    seen.add(k);
    out.push(item);
  }
  return out;
}
