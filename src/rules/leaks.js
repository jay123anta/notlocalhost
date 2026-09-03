/**
 * Leaked local URLs.
 *
 * The dullest finding in the tool and the one most likely to be true. A
 * `localhost` URL that reaches production does not fail on your machine -- it
 * fails on everyone else's, by resolving to *their* loopback interface.
 */
import { finding, REF } from './finding.js';
import { scanForLocalUrls } from '../collect/leaked-urls.js';

const ROLE_TITLE = {
  'url-parser-base': 'URL-constructor base',
  'self-origin-absolute': 'the app linking to its own origin',
  'oauth-redirect': 'OAuth redirect URI',
  'api-base': 'API base URL',
  websocket: 'WebSocket endpoint',
  'asset-host': 'asset host',
  'cors-allowlist': 'CORS allowlist entry',
  unclassified: 'unclassified reference',
};

const ROLE_SEVERITY = {
  'url-parser-base': 'info',
  'self-origin-absolute': 'info',
  'oauth-redirect': 'will-break',
  'api-base': 'will-break',
  'cors-allowlist': 'may-break',
  websocket: 'may-break',
  'asset-host': 'may-break',
  unclassified: 'info',
};

const ROLE_FIX = {
  'url-parser-base': ['No action expected. Confirm the base really is a sentinel and not a default someone forgot to replace.'],
  'self-origin-absolute': [
    'Check the base-URL setting for your framework and make sure the production value is the deployed origin, not a loopback address.',
    'Laravel: APP_URL and ASSET_URL. Next.js: NEXT_PUBLIC_SITE_URL and NEXTAUTH_URL. Rails: default_url_options. Django: whatever feeds build_absolute_uri behind a proxy.',
    'Where a relative URL would do, prefer it: it cannot be misconfigured.',
  ],
  'oauth-redirect': [
    'Derive the redirect URI from the request origin or from configuration, never from a constant.',
    'Check the identity provider console: a localhost redirect URI left registered on a production client is an open-redirect surface, not just dead config.',
  ],
  'api-base': [
    'Move the base URL into build-time or runtime configuration with no loopback default in the production path.',
    'Prefer a same-origin relative path ("/api") where the topology allows it -- it removes the CORS and cookie problems at the same time.',
  ],
  'cors-allowlist': ['Drive the allowlist from configuration and include the deployed origin.'],
  websocket: [
    'ws:// is blocked as mixed content on an HTTPS page. Build the URL from location: `${location.protocol === "https:" ? "wss:" : "ws:"}//${location.host}`.',
  ],
  'asset-host': ['Use a relative URL, or an https:// host that actually serves the asset.'],
  unclassified: ['Confirm whether the production build replaces this value. If it does not, it ships.'],
};

export function leakRules(ctx) {
  const { capture } = ctx;
  const out = [];

  const pageOrigin = originOf(capture.finalUrl || capture.targetUrl);
  const all = [];
  for (const body of capture.bodies) {
    all.push(...scanForLocalUrls({ url: body.url, body: body.body, kind: body.kind, pageOrigin }));
  }

  if (!all.length) return out;

  const shipped = all.filter((h) => !h.devTooling);
  const devOnly = all.filter((h) => h.devTooling);

  const byRole = new Map();
  for (const hit of shipped) {
    if (!byRole.has(hit.role)) byRole.set(hit.role, []);
    byRole.get(hit.role).push(hit);
  }

  for (const [role, hits] of byRole) {
    const unique = dedupe(hits, (h) => `${h.url}|${h.resource}`);
    out.push(
      finding({
        id: `leak.${role}`,
        severity: ROLE_SEVERITY[role] ?? 'info',
        subject: role,
        title:
          role === 'self-origin-absolute'
            ? unique.length === 1
              ? "An absolute URL points back at the app's own loopback origin"
              : `${unique.length} absolute URLs point back at the app's own loopback origin`
            : unique.length === 1
              ? `A hardcoded loopback URL that looks like ${article(ROLE_TITLE[role] ?? role)}`
              : `${unique.length} hardcoded loopback URLs that look like ${ROLE_TITLE[role] ?? role}s`,
        summary:
          `${hits[0].why}\n\n` +
          'Found by scanning the bodies the dev server actually served during this run. That means two things: ' +
          'a value a production build would replace can still show up here, and a value in code that did not load ' +
          'will not show up at all. Check the quoted line before acting.',
        evidence: unique.slice(0, 12).map((h) => ({
          label: `${shortPath(h.resource)}:${h.line}`,
          value: `${h.url}\n    ${h.context}`,
        })),
        fix: ROLE_FIX[role] ?? ROLE_FIX.unclassified,
        refs: role === 'websocket' ? [REF.mixedContent] : [],
      }),
    );
  }

  if (devOnly.length) {
    const unique = dedupe(devOnly, (h) => `${h.url}|${h.resource}`);
    out.push(
      finding({
        id: 'leak.dev-tooling',
        severity: 'info',
        title: `${unique.length} loopback URL${unique.length === 1 ? '' : 's'} belong to dev-server machinery`,
        summary:
          'HMR clients, live-reload sockets and dev overlays legitimately point at localhost and do not ship in a ' +
          'production build. Listed for completeness so the numbers above reconcile, and so you can see what was ' +
          'excluded rather than wondering.',
        evidence: unique.slice(0, 10).map((h) => ({ label: shortPath(h.resource), value: h.url })),
        fix: ['No action. Verify your production build genuinely excludes these if you are unsure.'],
        refs: [],
      }),
    );
  }

  return out;
}

function dedupe(list, keyFn) {
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

function originOf(u) {
  try {
    return new URL(u).origin;
  } catch {
    return null;
  }
}

function article(noun) {
  return `${/^[aeiou]/i.test(noun) ? 'an' : 'a'} ${noun}`;
}

function shortPath(u) {
  try {
    const p = new URL(u);
    const s = p.pathname;
    return s.length > 52 ? `...${s.slice(-49)}` : s || '/';
  } catch {
    return u;
  }
}
