/**
 * Origin, CORS and credential rules.
 *
 * The move from localhost to a real domain redraws every origin boundary in
 * the app at once. Two ports that were "the same host" become two hostnames;
 * an `Access-Control-Allow-Origin` that hardcodes a localhost origin stops
 * matching anything; a fetch that never needed CORS suddenly does.
 */
import { finding, REF } from './finding.js';
import { classifyRequest, parseOrigin, registrableDomain } from '../collect/origins.js';

/**
 * Chrome's CORS error codes, translated. The code alone is not actionable;
 * the sentence after it is.
 */
const CORS_ERROR_COPY = {
  WildcardOriginNotAllowed: {
    short: 'wildcard origin with credentials',
    detail:
      'The response said Access-Control-Allow-Origin: * while the request included credentials. The Fetch standard forbids that pairing outright.',
    fix: 'Echo the specific requesting origin (validated against an allowlist) instead of *, and add Vary: Origin.',
  },
  MissingAllowOriginHeader: {
    short: 'no Access-Control-Allow-Origin',
    detail: 'The response carried no Access-Control-Allow-Origin header at all, so the browser refused to expose it.',
    fix: 'Return Access-Control-Allow-Origin from the API for the origins that are allowed to call it.',
  },
  AllowOriginMismatch: {
    short: 'Allow-Origin did not match',
    detail: 'Access-Control-Allow-Origin named a different origin from the one making the request.',
    fix: 'Drive the allowed origin from configuration so it matches the deployed front-end exactly, scheme and port included.',
  },
  DisallowedByMode: {
    short: 'blocked by request mode',
    detail: 'The request used a mode that forbids a cross-origin response, such as same-origin.',
    fix: 'Set mode explicitly on the fetch, or keep the endpoint same-origin.',
  },
  PreflightMissingAllowOriginHeader: {
    short: 'preflight had no Allow-Origin',
    detail: 'The OPTIONS preflight response carried no Access-Control-Allow-Origin.',
    fix: 'Answer OPTIONS with the full set of Access-Control-Allow-* headers, not just the real method.',
  },
  PreflightInvalidStatus: {
    short: 'preflight returned a bad status',
    detail: 'The OPTIONS preflight did not return a 2xx status, so the real request was never sent.',
    fix: 'Make the OPTIONS handler return 204 before any authentication middleware can reject it.',
  },
  MethodDisallowedByPreflightResponse: {
    short: 'method not in Allow-Methods',
    detail: 'Access-Control-Allow-Methods did not include the method the request wanted to use.',
    fix: 'Add the method to Access-Control-Allow-Methods.',
  },
  HeaderDisallowedByPreflightResponse: {
    short: 'header not in Allow-Headers',
    detail: 'A request header was not listed in Access-Control-Allow-Headers.',
    fix: 'Add the header (Authorization and Content-Type are the usual culprits) to Access-Control-Allow-Headers.',
  },
  InsecurePrivateNetwork: {
    short: 'private network access blocked',
    detail:
      'A public or less-private origin tried to reach a more-private address. Chrome gates this behind Private Network Access.',
    fix: 'This one is specific to loopback and private addresses and will change shape entirely once both ends are public. Re-test after deployment.',
  },
};

export function originRules(ctx) {
  const { capture, model, targetUrl } = ctx;
  const pageUrl = capture.finalUrl || targetUrl;
  const out = [];

  const requests = capture.requests.filter((r) => /^(https?|wss?):/i.test(r.url));

  // Instrumented calls tell us the credentials mode, which the wire does not.
  const credentialed = new Map();
  for (const ev of capture.instrumentation) {
    if (!ev.type?.startsWith('request.')) continue;
    if (!ev.target) continue;
    const mode = ev.credentials ?? (ev.type === 'request.websocket' ? 'include' : undefined);
    const prev = credentialed.get(ev.target);
    // 'include' wins over 'same-origin' if the same URL is called both ways.
    if (!prev || mode === 'include') credentialed.set(ev.target, { mode, kind: ev.type, stack: ev.stack });
  }

  // ------------------------------------------------------ origin inventory --
  const byOrigin = new Map();
  for (const r of requests) {
    const p = parseOrigin(r.url);
    if (!p) continue;
    if (!byOrigin.has(p.origin)) byOrigin.set(p.origin, { origin: p.origin, count: 0, sample: r.url, types: new Set() });
    const e = byOrigin.get(p.origin);
    e.count++;
    e.types.add(r.resourceType);
  }

  if (byOrigin.size) {
    out.push(
      finding({
        id: 'origin.inventory',
        severity: 'info',
        title: `Requests went to ${byOrigin.size} origin${byOrigin.size === 1 ? '' : 's'}`,
        summary:
          'How each origin is classified today, and how it is classified under the assumed deployment model. ' +
          'The model is printed at the top of the report and can be changed with --domain and --map.',
        evidence: [...byOrigin.values()].map((e) => {
          const c = classifyRequest(pageUrl, e.sample, model);
          const nowLabel = c.now.sameOrigin ? 'same-origin' : c.now.sameSite ? 'cross-origin, same-site' : 'cross-site';
          const thenLabel = c.then.sameOrigin ? 'same-origin' : c.then.sameSite ? 'cross-origin, same-site' : 'cross-site';
          return {
            label: `${e.origin} (${e.count})`,
            value: `now: ${nowLabel}  ->  deployed: ${thenLabel}  (${c.projectedRequest ?? 'unchanged'})`,
          };
        }),
        refs: [REF.fetchCors],
      }),
    );
  }

  // ------------------------------------- boundaries that change on deployment --
  const changing = [];
  for (const [, e] of byOrigin) {
    const c = classifyRequest(pageUrl, e.sample, model);
    if (c.becomesCrossOrigin || c.becomesCrossSite) changing.push({ ...e, c });
  }

  for (const item of changing) {
    const cred = [...credentialed.entries()].find(([url]) => url.startsWith(item.origin));
    const isCredentialed = cred?.[1]?.mode === 'include';
    const crossSite = item.c.becomesCrossSite;

    out.push(
      finding({
        id: crossSite ? 'origin.becomes-cross-site' : 'origin.becomes-cross-origin',
        severity: isCredentialed ? 'will-break' : 'may-break',
        subject: item.origin,
        title: crossSite
          ? `${item.origin} becomes a cross-site origin once deployed`
          : `${item.origin} becomes a cross-origin endpoint once deployed`,
        summary:
          (item.c.now.sameOrigin
            ? 'Today this is same-origin, so no CORS preflight happens, no Origin header is scrutinised, and cookies flow without question. '
            : 'Today this is same-site, so cookies flow regardless of SameSite. ') +
          `After deployment it is ${crossSite ? 'cross-site' : 'cross-origin'}: ` +
          (crossSite
            ? 'cookies are only sent if they carry SameSite=None; Secure, and the server must return Access-Control-Allow-Credentials: true with an exact Access-Control-Allow-Origin.'
            : 'CORS applies, so the server must return an Access-Control-Allow-Origin the browser accepts, and preflights must be answered.') +
          (isCredentialed
            ? '\n\nThis endpoint is called with credentials, which is what makes it a will-break rather than a maybe: a credentialed cross-site request with default cookie flags carries no cookies at all.'
            : ''),
        evidence: [
          { label: 'requests observed', value: `${item.count} (${[...item.types].join(', ')})` },
          { label: 'page today', value: pageUrl },
          { label: 'page deployed', value: item.c.projectedPage ?? '(unchanged)' },
          { label: 'endpoint deployed', value: item.c.projectedRequest ?? '(unchanged)' },
          ...(cred ? [{ label: 'credentials mode', value: `${cred[1].mode} via ${cred[1].kind}` }] : []),
        ],
        fix: crossSite
          ? [
              'On the API: Access-Control-Allow-Origin must echo the exact deployed origin (never *), plus Access-Control-Allow-Credentials: true.',
              'On the cookie: SameSite=None; Secure. Both, or the browser drops it.',
              'Consider keeping the API same-site behind a path prefix instead. Cross-site credentialed requests are a permanent tax.',
            ]
          : [
              'Ensure the API answers OPTIONS preflights and returns an Access-Control-Allow-Origin matching the deployed front-end origin.',
              'Same-site means cookies still flow with SameSite=Lax, so this is a CORS problem rather than a cookie problem.',
            ],
        refs: [REF.fetchCors, REF.chromeSameSite],
      }),
    );
  }

  // -------------------------------------------------------- CORS headers seen --
  //
  // Read from the request records rather than the response records. When
  // Chrome blocks a response for a CORS failure it never fires
  // `Network.responseReceived` at all -- but `responseReceivedExtraInfo` still
  // delivers the raw headers, so the offending header is right there. Looking
  // only at successful responses would miss exactly the cases that matter.
  const corsIssues = [];
  for (const r of capture.requests) {
    const h = lower(r.responseHeaders ?? r.rawResponseHeaders);
    const acao = h['access-control-allow-origin'];
    if (acao === undefined) continue;
    const acac = h['access-control-allow-credentials'];

    if (acao === '*' && String(acac).toLowerCase() === 'true') {
      corsIssues.push({
        kind: 'wildcard-with-credentials',
        url: r.url,
        acao,
        acac,
      });
    } else if (acao === '*') {
      corsIssues.push({ kind: 'wildcard', url: r.url, acao, acac });
    } else {
      const p = parseOrigin(acao);
      if (p && (p.isLoopback || p.isPrivate)) {
        corsIssues.push({ kind: 'hardcoded-local', url: r.url, acao, acac });
      }
    }
  }

  for (const issue of group(corsIssues, (i) => i.kind)) {
    const kind = issue[0].kind;
    if (kind === 'wildcard-with-credentials') {
      out.push(
        finding({
          id: 'cors.wildcard-with-credentials',
          severity: 'will-break',
          title: 'Access-Control-Allow-Origin: * combined with Allow-Credentials: true',
          summary:
            'The Fetch standard forbids this combination outright: when credentials are included, a wildcard ' +
            'Access-Control-Allow-Origin is treated as a failure and the response is not exposed. It looks like ' +
            'it works locally only because same-origin requests never consult CORS at all.',
          evidence: issue.slice(0, 8).map((i) => ({ label: i.url, value: `Access-Control-Allow-Origin: ${i.acao}; Access-Control-Allow-Credentials: ${i.acac}` })),
          fix: [
            'Echo the specific requesting origin after validating it against an allowlist, and add Vary: Origin.',
            'Never reflect an unvalidated Origin header while allowing credentials.',
          ],
          refs: [REF.fetchCors],
        }),
      );
    } else if (kind === 'hardcoded-local') {
      out.push(
        finding({
          id: 'cors.hardcoded-local-origin',
          severity: 'will-break',
          title: 'A CORS allowlist hardcodes a localhost origin',
          summary:
            'Access-Control-Allow-Origin names a loopback origin. That value can only ever match a developer ' +
            'machine. In production the deployed front-end origin will not match and every cross-origin call fails.',
          evidence: issue.slice(0, 8).map((i) => ({ label: i.url, value: `Access-Control-Allow-Origin: ${i.acao}` })),
          fix: [
            'Drive the allowlist from configuration, and include the deployed origin.',
            'Add a startup assertion that the configured origin is not a loopback address outside development.',
          ],
          refs: [REF.fetchCors],
        }),
      );
    } else {
      out.push(
        finding({
          id: 'cors.wildcard',
          severity: 'info',
          title: 'Access-Control-Allow-Origin: * on responses seen during this run',
          summary:
            'A wildcard is fine for genuinely public resources. It stops working the moment the request needs ' +
            'credentials, so it is worth knowing which endpoints rely on it before the front-end moves origin.',
          evidence: issue.slice(0, 8).map((i) => ({ label: i.url, value: `Access-Control-Allow-Origin: ${i.acao}` })),
          fix: ['No action if the endpoint is public. If it will ever need cookies, plan the exact-origin echo now.'],
          refs: [REF.fetchCors],
        }),
      );
    }
  }

  // ------------------------------------------- Chrome's own CORS verdict --
  const corsBlocked = capture.requests.filter((r) => r.failed?.corsErrorStatus?.corsError);
  if (corsBlocked.length) {
    out.push(
      finding({
        id: 'cors.blocked-by-browser',
        severity: 'will-break',
        title: `Chrome blocked ${corsBlocked.length} request${corsBlocked.length === 1 ? '' : 's'} on CORS grounds during this run`,
        summary:
          'Not a prediction: these requests failed here, now, and Chrome named the reason. Cross-origin failures ' +
          'that already happen locally are worth reporting because they are usually invisible -- the fetch rejects, ' +
          'a catch block swallows it, and the UI shows an empty state rather than an error.\n\n' +
          'They also get worse after deployment. A boundary that is merely cross-origin locally is often cross-site ' +
          'in production, which adds the cookie requirements on top of the CORS ones.',
        evidence: corsBlocked.slice(0, 10).map((r) => ({
          label: CORS_ERROR_COPY[r.failed.corsErrorStatus.corsError]?.short ?? r.failed.corsErrorStatus.corsError,
          value:
            `${r.method} ${r.url}\n    ` +
            (CORS_ERROR_COPY[r.failed.corsErrorStatus.corsError]?.detail ??
              `Chrome CORS error code: ${r.failed.corsErrorStatus.corsError}`),
        })),
        fix: [
          ...new Set(
            corsBlocked
              .map((r) => CORS_ERROR_COPY[r.failed.corsErrorStatus.corsError]?.fix)
              .filter(Boolean),
          ),
          'Reproduce in DevTools with the Network panel open; the blocked request shows the same reason.',
        ],
        refs: [REF.fetchCors],
      }),
    );
  }

  // ------------------------------ credentialed calls that will need None;Secure --
  const needNone = [];
  for (const [url, info] of credentialed) {
    if (info.mode !== 'include') continue;
    const c = classifyRequest(pageUrl, url, model);
    if (c.then.sameSite) continue;
    needNone.push({ url, info, c });
  }
  if (needNone.length) {
    out.push(
      finding({
        id: 'origin.credentialed-cross-site',
        severity: 'will-break',
        title: `${needNone.length} credentialed request${needNone.length === 1 ? '' : 's'} will be cross-site after deployment`,
        summary:
          'These calls opt into sending cookies (credentials: "include" or XHR withCredentials). Under the assumed ' +
          'deployment model their target is a different site from the page. Cross-site cookie delivery requires ' +
          'SameSite=None; Secure on the cookie *and* Access-Control-Allow-Credentials plus an exact ' +
          'Access-Control-Allow-Origin on the response. Locally none of that is exercised, because loopback ports ' +
          'are the same site as each other.',
        evidence: needNone.slice(0, 10).map((n) => ({
          label: n.url,
          value: `${n.info.kind} credentials=${n.info.mode}; deployed target ${n.c.projectedRequest}${n.info.stack?.[0] ? ` <- ${n.info.stack[0]}` : ''}`,
        })),
        fix: [
          'Set SameSite=None; Secure on every cookie these requests depend on.',
          'Return Access-Control-Allow-Credentials: true and an exact Access-Control-Allow-Origin (never *).',
          'Or place the API under the same site as the front-end and avoid the whole class of problem.',
        ],
        refs: [REF.fetchCors, REF.rfc6265bisSameSite],
      }),
    );
  }

  // ------------------------------------------------- registrable-domain caveat --
  const inexact = new Set();
  for (const [origin] of byOrigin) {
    const p = parseOrigin(origin);
    if (!p || p.isLoopback || p.isPrivate) continue;
    const r = registrableDomain(p.hostname);
    if (!r.exact) inexact.add(`${p.hostname} -> assumed site ${r.domain}`);
  }
  if (inexact.size) {
    out.push(
      finding({
        id: 'origin.site-heuristic',
        severity: 'info',
        title: 'Some site boundaries were computed with a heuristic, not the Public Suffix List',
        summary:
          'notlocalhost does not bundle the Public Suffix List, so for hosts outside its small built-in suffix ' +
          'table it assumes the registrable domain is the last two labels. For these hosts, treat the same-site ' +
          'classification as approximate.',
        evidence: [...inexact].map((v) => ({ label: 'host', value: v })),
        fix: ['If a same-site classification looks wrong for one of these hosts, it probably is. Report it.'],
        refs: [{ title: 'Public Suffix List', url: 'https://publicsuffix.org/' }],
      }),
    );
  }

  return out;
}

function lower(headers = {}) {
  const out = {};
  for (const [k, v] of Object.entries(headers)) out[k.toLowerCase()] = v;
  return out;
}

function group(list, keyFn) {
  const m = new Map();
  for (const item of list) {
    const k = keyFn(item);
    if (!m.has(k)) m.set(k, []);
    m.get(k).push(item);
  }
  return [...m.values()];
}
