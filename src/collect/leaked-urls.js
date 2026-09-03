/**
 * Hardcoded local-URL scanner.
 *
 * A `localhost` URL baked into a bundle is the most boring bug in this whole
 * tool and the most frequently shipped. The scanner reads response bodies --
 * HTML, JS, JSON, CSS -- and reports every loopback URL it finds together with
 * a guess at what that URL is *for*, because "there is a localhost string in
 * your bundle" is not actionable and "your OAuth redirect_uri is localhost" is.
 *
 * Everything here is textual pattern matching. It sees only what the dev
 * server actually served during the run, and it cannot tell a genuinely
 * shipped constant from a dev-only fallback that tree-shakes away in a
 * production build. Both limitations are stated in the report.
 */

const LOCAL_URL_RE =
  /\b(https?|wss?):\/\/(localhost|127(?:\.\d{1,3}){3}|\[::1\]|0\.0\.0\.0)(?::(\d{1,5}))?(\/[^\s"'`<>)\\]*)?/gi;

/** Bare host:port with no scheme, e.g. `"localhost:3000"` in a config object. */
const BARE_LOCAL_RE = /(["'`])((?:localhost|127(?:\.\d{1,3}){3})(?::\d{1,5}))\1/gi;

/**
 * Resources that are the dev server talking to itself. These never reach a
 * production build, so reporting them as shipped leaks would be noise -- but
 * hiding them entirely would be dishonest, so they are kept and downgraded.
 */
const DEV_TOOLING_RESOURCE = [
  /\/@vite\/client/,
  /\/@react-refresh/,
  /\/__vite_ping/,
  /webpack[-.]?dev[-.]?server/,
  /webpack-hot-middleware/,
  /\/sockjs-node\//,
  /\/_next\/static\/chunks\/(webpack|react-refresh)/,
  /\/_next\/static\/development\//,
  // Turbopack and the Next dev overlay ship their own client bundles under
  // predictable chunk names. Both contain example stack traces with localhost
  // URLs in them, which is noise of the most misleading kind.
  /\/_next\/static\/chunks\/.*node_modules_next_dist_(client|compiled)/,
  /next[-_]devtools/,
  /\/_next\/static\/chunks\/.*_next_dist_client_/,
  /\/__nextjs_/,
  /\/_next\/static\/chunks\/pages\/_(app|error)\.js/,
  /hot-update\.js(on)?$/,
  /\/livereload(\.js)?/,
  /\/browser-sync\//,
  /\/rails\/live_reload/,
  /\/__web_dev_server__/,
  /\/node_modules\/\.vite\//,
];

const DEV_TOOLING_PATH = [
  /^\/@vite\//,
  /^\/__vite/,
  /^\/sockjs-node/,
  /^\/ws$/,
  /^\/_next\/webpack-hmr/,
  /hot-update/,
  /^\/vite-dev-server/,
  /^\/browser-sync/,
];

/** Ordered most-specific first: the first matching rule wins. */
const ROLE_RULES = [
  {
    // `new URL(input, "http://localhost")` is a standard trick for parsing a
    // possibly-relative URL: the base is a sentinel that is never navigated
    // to. Bare scheme + localhost, no port, no path, is almost always this.
    // Reporting it as a leak wastes the reader's attention on a non-bug.
    role: 'url-parser-base',
    severityHint: 'info',
    why: 'A bare "http://localhost" with no port and no path is nearly always a sentinel base passed to the URL constructor so that a relative path can be parsed. It is not an endpoint and nothing requests it.',
    test: ({ url, key }) =>
      /^https?:\/\/localhost\/?$/i.test(url) && !/\b(api|base|endpoint|host|origin|redirect)\b/i.test(key),
  },
  {
    role: 'oauth-redirect',
    severityHint: 'will-break',
    why: 'An OAuth redirect URI must be registered byte-for-byte with the identity provider. A localhost value either fails in production or, worse, is left registered and becomes an open redirect surface.',
    test: ({ url, key }) =>
      /redirect_uri|redirectUri|redirect_url|callbackUrl|callback_url|NEXTAUTH_URL|post_logout_redirect/i.test(key) ||
      /\/(oauth|auth)\/(callback|redirect)|\/callback\b|\/auth\/callback|\/signin-oidc|\/login\/oauth/i.test(url),
  },
  {
    role: 'websocket',
    severityHint: 'may-break',
    why: 'A ws:// endpoint is blocked as mixed content once the page is served over HTTPS. It has to become wss:// and point at a real host.',
    test: ({ url }) => /^wss?:\/\//i.test(url) || /\/socket\.io|\/cable\b|\/ws\b|\/websocket/i.test(url),
  },
  {
    role: 'api-base',
    severityHint: 'will-break',
    why: "An API base URL pointing at loopback resolves to the visitor's own machine in production, not yours. It fails for everyone who is not you.",
    test: ({ key }) =>
      /\b(api[_-]?(base|url|host|endpoint|root|origin)|base[_-]?url|baseURL|apiUrl|API_URL|BACKEND_URL|SERVER_URL|VITE_API|NEXT_PUBLIC_API|REACT_APP_API|NUXT_PUBLIC_API|GRAPHQL_(URI|URL|ENDPOINT))\b/i.test(key),
  },
  {
    role: 'cors-allowlist',
    severityHint: 'may-break',
    why: 'A CORS allowlist that only contains localhost will reject the production origin.',
    test: ({ key }) => /allow(ed)?[_-]?origins?|cors|Access-Control-Allow-Origin/i.test(key),
  },
  {
    role: 'asset-host',
    severityHint: 'will-break',
    why: 'An http:// asset URL is blocked as mixed content on an HTTPS page (or, for images, flagged and often blocked too).',
    test: ({ url, key }) =>
      /\.(png|jpe?g|gif|svg|webp|avif|ico|css|js|mjs|woff2?|ttf|otf|mp4|webm|pdf)(\?|$)/i.test(url) ||
      /\b(src|href|assetHost|asset_url|cdn[_-]?url|CDN_URL|publicPath|ASSET_HOST|STATIC_URL|MEDIA_URL)\b/i.test(key),
  },
];

/**
 * @param {object} resource
 * @param {string} resource.url        URL the body was served from.
 * @param {string} resource.body
 * @param {string} [resource.kind]     'document' | 'script' | 'stylesheet' | ...
 * @param {number} [maxFindings]
 */
export function scanForLocalUrls(resource, maxFindings = 200) {
  const { url: resourceUrl, body, kind = 'other', pageOrigin = null } = resource;
  if (!body) return [];

  const isDevTooling = DEV_TOOLING_RESOURCE.some((re) => re.test(resourceUrl));
  const out = [];
  const seen = new Set();

  const record = (match, index, matchedText) => {
    if (out.length >= maxFindings) return;
    const context = contextAround(body, index, matchedText.length);
    // The identifier this URL is being assigned to, taken from the few
    // characters immediately before it. The wide context is for the reader;
    // classifying on it lets an unrelated key two lines away hijack the role.
    const key = keyBefore(body, index);
    const normalized = matchedText.replace(/[)'"`,;]+$/, '');

    // An absolute URL pointing at the page's own origin is usually the app
    // referring to itself: Laravel's asset()/route(), Rails' *_url helpers and
    // Django's build_absolute_uri all emit these, and they follow the deployed
    // host. Calling them leaks buries the real findings under the app's links.
    //
    // But only usually. A value assigned to a name like `redirect_uri` or
    // `apiUrl` is a configuration constant, not a generated URL, and it stays
    // pointed at localhost after deployment no matter whose origin it matches
    // today. Those keep their role -- the self-origin downgrade applies only
    // where nothing named the URL.
    const classified = classifyRole({ url: normalized, context, key });
    const selfOrigin = pageOrigin !== null && originOf(normalized) === pageOrigin;

    const { role, why, severityHint } =
      selfOrigin && !CONFIG_KEYED_ROLES.has(classified.role) ? SELF_ORIGIN_ROLE : classified;
    const dedupeKey = `${normalized}|${role}`;
    if (seen.has(dedupeKey)) return;
    seen.add(dedupeKey);

    const pathPart = safePath(normalized);
    const devPath = DEV_TOOLING_PATH.some((re) => re.test(pathPart));

    out.push({
      url: normalized,
      role,
      why,
      severityHint,
      resource: resourceUrl,
      resourceKind: kind,
      line: lineNumberAt(body, index),
      context: redact(context),
      devTooling: isDevTooling || devPath,
    });
  };

  for (const m of body.matchAll(LOCAL_URL_RE)) record(m, m.index ?? 0, m[0]);
  for (const m of body.matchAll(BARE_LOCAL_RE)) record(m, m.index ?? 0, m[2]);

  return out;
}

function classifyRole({ url, context, key }) {
  for (const rule of ROLE_RULES) {
    if (rule.test({ url, context, key: key ?? context })) {
      return { role: rule.role, why: rule.why, severityHint: rule.severityHint };
    }
  }
  return {
    role: 'unclassified',
    why: 'A loopback URL with no obvious role. It may be dead code, a comment, or a default that a production build replaces.',
    severityHint: 'info',
  };
}

/**
 * Absolute URLs the app generated for its own origin. Usually harmless, but
 * not always: they come from a base-URL setting, and if that setting still
 * says localhost in production, every one of them is wrong.
 */
/**
 * Roles that were assigned because an identifier named the URL. These survive
 * the self-origin downgrade: a constant is a constant wherever it points.
 */
const CONFIG_KEYED_ROLES = new Set(['oauth-redirect', 'api-base', 'cors-allowlist', 'websocket']);

const SELF_ORIGIN_ROLE = {
  role: 'self-origin-absolute',
  severityHint: 'info',
  why:
    "Absolute URLs pointing back at the page's own origin. These are generated server-side rather than hardcoded, " +
    'and they follow whatever host the app believes it is serving from. They only break if that base-URL setting ' +
    'is still a loopback address in production -- Laravel APP_URL and ASSET_URL, Django and Rails default_url_options, ' +
    'Next.js NEXT_PUBLIC_SITE_URL and NEXTAUTH_URL are the usual ones.',
};

function originOf(u) {
  try {
    return new URL(u.includes('://') ? u : `http://${u}`).origin;
  } catch {
    return null;
  }
}

function safePath(u) {
  try {
    return new URL(u.includes('://') ? u : `http://${u}`).pathname;
  } catch {
    return '';
  }
}

/**
 * The assignment target immediately preceding a URL: the `apiUrl` in
 * `apiUrl: "http://localhost:3000"`, the `src` in `src="http://..."`.
 *
 * Deliberately short. A wide window picks up whatever happens to be on the
 * next line, which is how an API base URL ends up classified as an OAuth
 * redirect just because a redirect_uri is declared underneath it.
 */
function keyBefore(body, index, radius = 48) {
  const start = Math.max(0, index - radius);
  return body
    .slice(start, index)
    .replace(/\s+/g, ' ')
    // Stop at the nearest statement or property boundary going backwards, so
    // we keep at most the current assignment.
    .split(/[;,{}\n]/)
    .pop()
    .trim();
}

function contextAround(body, index, length, radius = 90) {
  const start = Math.max(0, index - radius);
  const end = Math.min(body.length, index + length + radius);
  return body.slice(start, end).replace(/\s+/g, ' ').trim();
}

function lineNumberAt(body, index) {
  let line = 1;
  for (let i = 0; i < index && i < body.length; i++) if (body.charCodeAt(i) === 10) line++;
  return line;
}

/**
 * Blunt secret redaction for the context snippet. The report is a file people
 * paste into issues; a bearer token in a bundle should not ride along.
 */
function redact(text) {
  return text
    .replace(/\b(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,})\b/g, '[redacted-jwt]')
    .replace(/\b(sk|pk|rk|ghp|gho|github_pat|xox[baprs])[-_][A-Za-z0-9_-]{16,}\b/g, '[redacted-token]')
    .replace(/\b(AKIA[0-9A-Z]{16})\b/g, '[redacted-aws-key]')
    .replace(
      /((?:password|passwd|secret|api[_-]?key|apikey|token|authorization|bearer)\s*[:=]\s*["'`])([^"'`]{4,})/gi,
      '$1[redacted]',
    );
}

/** Text-ish MIME types worth scanning. Binary bodies are skipped outright. */
export function isScannableMime(mimeType = '') {
  const m = mimeType.toLowerCase();
  return (
    m.startsWith('text/') ||
    m.includes('javascript') ||
    m.includes('json') ||
    m.includes('ecmascript') ||
    m.includes('xml') ||
    m.includes('html') ||
    m.includes('css')
  );
}
