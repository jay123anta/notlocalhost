/**
 * Origin and site classification.
 *
 * "Same-origin" and "same-site" are different questions and cookies care about
 * the second one. Two URLs are same-origin when scheme, host and port all
 * match. They are same-site when they share a registrable domain (and, in
 * Chrome's schemeful model, a scheme). Cookies are scoped by site, never by
 * port -- which is the single fact that makes localhost misleading.
 */

/**
 * A deliberately small list of multi-label public suffixes.
 *
 * We do not bundle the full Public Suffix List: it is ~230 KB, it goes stale,
 * and pulling it in would break the near-zero-dependency promise. This covers
 * the suffixes that actually show up in dev traffic. When a host is not
 * matched here we fall back to "last two labels", and every finding that
 * depends on the answer says so.
 */
const MULTI_LABEL_SUFFIXES = new Set([
  'co.uk', 'org.uk', 'gov.uk', 'ac.uk', 'me.uk', 'net.uk',
  'com.au', 'net.au', 'org.au', 'edu.au', 'gov.au',
  'co.nz', 'co.za', 'co.jp', 'ne.jp', 'or.jp', 'co.kr', 'co.in', 'net.in', 'org.in',
  'com.br', 'com.mx', 'com.ar', 'com.tr', 'com.cn', 'com.hk', 'com.sg', 'com.tw',
  'github.io', 'gitlab.io', 'netlify.app', 'vercel.app', 'pages.dev', 'workers.dev',
  'herokuapp.com', 'azurewebsites.net', 'cloudfront.net', 'amazonaws.com',
  'firebaseapp.com', 'web.app', 'onrender.com', 'fly.dev', 'railway.app',
  'ngrok.io', 'ngrok-free.app', 'loca.lt', 'trycloudflare.com',
]);

/** Hostnames a browser grants secure-context status to over plain HTTP. */
export function isLoopbackHost(hostname) {
  if (!hostname) return false;
  const h = stripBrackets(hostname.toLowerCase());
  if (h === 'localhost') return true;
  // RFC 6761 reserves `localhost` as a special-use TLD, so anything under it
  // resolves to loopback in browsers that implement the reservation.
  if (h.endsWith('.localhost')) return true;
  if (h === '::1' || h === '0:0:0:0:0:0:0:1') return true;
  if (/^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(h)) return true;
  return false;
}

/**
 * Hosts that are local to the developer's machine or network but are not
 * loopback -- these do *not* get secure-context treatment over plain HTTP.
 */
export function isPrivateHost(hostname) {
  if (!hostname) return false;
  const h = stripBrackets(hostname.toLowerCase());
  if (h === '0.0.0.0') return true;
  if (/^10\./.test(h)) return true;
  if (/^192\.168\./.test(h)) return true;
  if (/^172\.(1[6-9]|2\d|3[01])\./.test(h)) return true;
  if (h.endsWith('.local') || h.endsWith('.test') || h.endsWith('.internal')) return true;
  return false;
}

function stripBrackets(h) {
  return h.startsWith('[') && h.endsWith(']') ? h.slice(1, -1) : h;
}

function isIpLiteral(hostname) {
  const h = stripBrackets(hostname);
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(h) || h.includes(':');
}

/**
 * Registrable domain ("eTLD+1"). Returns the host itself for IP literals and
 * single-label hosts, which is also how browsers treat them for site scoping.
 * @param {string} hostname
 * @returns {{ domain: string, exact: boolean }} `exact` is false when we fell
 *   back to the last-two-labels heuristic rather than a known suffix.
 */
export function registrableDomain(hostname) {
  const h = stripBrackets(String(hostname || '').toLowerCase());
  if (!h) return { domain: '', exact: true };
  if (isIpLiteral(h)) return { domain: h, exact: true };

  const labels = h.split('.');
  if (labels.length <= 1) return { domain: h, exact: true };
  if (labels.length === 2) return { domain: h, exact: true };

  const lastTwo = labels.slice(-2).join('.');
  if (MULTI_LABEL_SUFFIXES.has(lastTwo)) {
    return { domain: labels.slice(-3).join('.'), exact: true };
  }
  return { domain: lastTwo, exact: false };
}

/** Parse into the pieces we keep asking for. Returns null for non-HTTP URLs. */
export function parseOrigin(url) {
  let u;
  try {
    u = new URL(url);
  } catch {
    return null;
  }
  const scheme = u.protocol.replace(':', '');
  const port = u.port || (scheme === 'https' || scheme === 'wss' ? '443' : scheme === 'http' || scheme === 'ws' ? '80' : '');
  return {
    href: u.href,
    scheme,
    hostname: u.hostname.toLowerCase(),
    port,
    origin: `${scheme}://${u.host}`,
    hostPort: u.host.toLowerCase(),
    pathname: u.pathname,
    isLoopback: isLoopbackHost(u.hostname),
    isPrivate: isPrivateHost(u.hostname),
    isHttp: scheme === 'http' || scheme === 'ws',
    isWebSocket: scheme === 'ws' || scheme === 'wss',
  };
}

export function sameOrigin(a, b) {
  const x = parseOrigin(a);
  const y = parseOrigin(b);
  if (!x || !y) return false;
  return x.scheme === y.scheme && x.hostname === y.hostname && x.port === y.port;
}

/** Schemeful same-site, as Chrome computes it for cookies. */
export function sameSite(a, b) {
  const x = parseOrigin(a);
  const y = parseOrigin(b);
  if (!x || !y) return false;
  const xs = x.scheme === 'ws' ? 'http' : x.scheme === 'wss' ? 'https' : x.scheme;
  const ys = y.scheme === 'ws' ? 'http' : y.scheme === 'wss' ? 'https' : y.scheme;
  if (xs !== ys) return false;
  return registrableDomain(x.hostname).domain === registrableDomain(y.hostname).domain;
}

/**
 * The deployment model. This is the assumption the whole prediction rests on,
 * so it is explicit, overridable, and printed in every report.
 *
 * Default: every distinct local port becomes a distinct *subdomain of one
 * site*, because that is what teams actually ship -- app.example.com talking
 * to api.example.com. Under that model, two local ports that are same-origin
 * today become cross-origin but same-site tomorrow, which changes CORS
 * requirements without changing cookie requirements.
 *
 * `--cross-site` switches to the other common topology, where the API lives on
 * a genuinely different registrable domain and every cookie needs
 * `SameSite=None; Secure`.
 *
 * @param {object} opts
 * @param {string} opts.domain        Hypothetical production registrable domain.
 * @param {boolean} [opts.crossSite]  Map each local port to its own site.
 * @param {Record<string,string>} [opts.explicit] hostPort -> real hostname.
 */
export function createDeploymentModel({ domain, crossSite = false, explicit = {}, paths = {} }) {
  const assigned = new Map(Object.entries(explicit));
  let n = 0;

  // Path prefixes that become their own host. This models the most common real
  // topology there is: `/api` served same-origin in development by a dev-server
  // proxy, and split onto its own subdomain in production. Without it a
  // same-origin request can never be seen to become cross-origin, and the CORS
  // headers that localhost's origin masks stay invisible -- which is the whole
  // point of looking.
  //
  // Longest prefix wins, so `/api/v2` can be mapped separately from `/api`.
  const pathRules = Object.entries(paths)
    .map(([prefix, host]) => [prefix.startsWith('/') ? prefix : `/${prefix}`, host])
    .sort((a, b) => b[0].length - a[0].length);

  /** @param {string} hostPort e.g. "localhost:3000" */
  function hostnameFor(hostPort) {
    if (assigned.has(hostPort)) return assigned.get(hostPort);
    const label = subdomainLabel(hostPort, n);
    const mapped = crossSite && n > 0 ? `${label}.${nthSite(domain, n)}` : `${label}.${domain}`;
    assigned.set(hostPort, mapped);
    n += 1;
    return mapped;
  }

  /** Project a local URL onto its hypothetical production URL. */
  function project(url) {
    const p = parseOrigin(url);
    if (!p) return null;
    if (!p.isLoopback && !p.isPrivate) return p.href; // already a real origin

    // A mapped path prefix moves the request to its own host, which is what
    // makes a same-origin call visibly become a cross-origin one.
    const matched = pathRules.find(([prefix]) => p.pathname === prefix || p.pathname.startsWith(`${prefix}/`));
    if (matched) {
      const u = new URL(p.href);
      u.protocol = p.isWebSocket ? 'wss:' : 'https:';
      u.hostname = matched[1];
      u.port = '';
      return u.href;
    }

    const host = hostnameFor(p.hostPort);
    const scheme = p.isWebSocket ? 'wss' : 'https';
    const u = new URL(p.href);
    u.protocol = `${scheme}:`;
    u.hostname = host;
    u.port = '';
    return u.href;
  }

  return { project, hostnameFor, get mapping() { return Object.fromEntries(assigned); } };
}

function subdomainLabel(hostPort, index) {
  const [host, port] = hostPort.split(':');
  if (index === 0) return 'app';
  if (port) return `svc-${port}`;
  return host.replace(/[^a-z0-9-]/g, '-');
}

function nthSite(domain, n) {
  const { domain: d } = registrableDomain(domain);
  const [first, ...rest] = d.split('.');
  return [`${first}-api${n > 1 ? n : ''}`, ...rest].join('.');
}

/**
 * Classify one request relative to the page, both as things are and as they
 * would be after deployment.
 * @param {string} pageUrl
 * @param {string} requestUrl
 * @param {ReturnType<createDeploymentModel>} model
 */
export function classifyRequest(pageUrl, requestUrl, model) {
  const now = {
    sameOrigin: sameOrigin(pageUrl, requestUrl),
    sameSite: sameSite(pageUrl, requestUrl),
  };
  const projectedPage = model.project(pageUrl);
  const projectedRequest = model.project(requestUrl);
  const then =
    projectedPage && projectedRequest
      ? {
          sameOrigin: sameOrigin(projectedPage, projectedRequest),
          sameSite: sameSite(projectedPage, projectedRequest),
        }
      : { sameOrigin: now.sameOrigin, sameSite: now.sameSite };

  return {
    now,
    then,
    projectedPage,
    projectedRequest,
    becomesCrossOrigin: now.sameOrigin && !then.sameOrigin,
    becomesCrossSite: now.sameSite && !then.sameSite,
  };
}
