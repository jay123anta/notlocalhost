/**
 * The two-auth-paths smell.
 *
 * Because `Secure` cookies cannot be set over plain HTTP, almost every team
 * eventually writes `secure: process.env.NODE_ENV === 'production'`. From that
 * moment the app has two authentication paths: the one every developer
 * exercises a hundred times a day, and the one that actually runs in
 * production, which is exercised by nobody until it breaks.
 *
 * We detect it three ways, each with its own confidence, because no single
 * signal is conclusive:
 *
 *   1. SOURCE   -- a served bundle or inline script literally contains a
 *                  security flag gated on an environment check. Strongest
 *                  evidence: we quote the line.
 *   2. PREFIX   -- a cookie whose name is the non-`__Secure-` half of a
 *                  known framework pair. The framework is *already* running
 *                  its dev branch; the production branch sets a different
 *                  cookie name entirely.
 *   3. FRAMEWORK-- a session cookie from a framework whose default config
 *                  gates `secure` on an environment flag, arriving without
 *                  `Secure`.
 *
 * None of these prove a bug. All of them mean the production cookie path is
 * not the path that just ran.
 */

/**
 * Source patterns. Each is anchored on a cookie security attribute so that a
 * bare `NODE_ENV` check somewhere in a bundle does not trip it.
 */
const SOURCE_PATTERNS = [
  {
    id: 'secure-gated-on-env',
    // secure: process.env.NODE_ENV === 'production'  /  secure: !isDev  /  secure: isProd
    re: /\bsecure\s*[:=]\s*(?!true\b|false\b)[^,;}\n]{0,120}?(NODE_ENV|APP_ENV|RAILS_ENV|DJANGO_ENV|import\.meta\.env|isProd|isProduction|isDev|isDevelopment|DEBUG|__DEV__|PROD\b|\benv\b)/i,
    attribute: 'Secure',
  },
  {
    id: 'samesite-gated-on-env',
    re: /\bsameSite\s*[:=]\s*(?!["'`]?(?:lax|strict|none)["'`]?\s*[,;}\n])[^,;}\n]{0,120}?(NODE_ENV|import\.meta\.env|isProd|isProduction|isDev|__DEV__|PROD\b)/i,
    attribute: 'SameSite',
  },
  {
    id: 'httponly-gated-on-env',
    re: /\bhttpOnly\s*[:=]\s*(?!true\b|false\b)[^,;}\n]{0,120}?(NODE_ENV|import\.meta\.env|isProd|isProduction|isDev|__DEV__|PROD\b)/i,
    attribute: 'HttpOnly',
  },
  {
    id: 'cookie-prefix-gated-on-env',
    // The NextAuth shape: `__Secure-` prepended only when the URL is https.
    re: /["'`]__(Secure|Host)-["'`]?\s*[+:]|useSecureCookies\s*[?:]/,
    attribute: 'cookie name prefix',
  },
  {
    id: 'protocol-branch',
    re: /location\.protocol\s*===?\s*["'`]https:["'`]|window\.isSecureContext\s*\?/,
    attribute: 'scheme branch',
  },
];

/**
 * Cookies whose production counterpart carries a `__Secure-` / `__Host-`
 * prefix. Seeing the unprefixed name means the framework took its insecure
 * branch, which is a *different cookie name* in production -- so nothing about
 * the local run tells you whether the production one works.
 */
const PREFIX_PAIRS = [
  { insecure: 'next-auth.session-token', secure: '__Secure-next-auth.session-token', framework: 'NextAuth.js v4' },
  { insecure: 'next-auth.callback-url', secure: '__Secure-next-auth.callback-url', framework: 'NextAuth.js v4' },
  { insecure: 'next-auth.csrf-token', secure: '__Host-next-auth.csrf-token', framework: 'NextAuth.js v4' },
  { insecure: 'authjs.session-token', secure: '__Secure-authjs.session-token', framework: 'Auth.js v5' },
  { insecure: 'authjs.csrf-token', secure: '__Host-authjs.csrf-token', framework: 'Auth.js v5' },
  { insecure: 'authjs.callback-url', secure: '__Secure-authjs.callback-url', framework: 'Auth.js v5' },
];

/**
 * Frameworks whose stock configuration ships the environment gate. Naming the
 * framework and the setting is the difference between a warning and a fix.
 */
const FRAMEWORK_SESSION_COOKIES = [
  {
    match: /^laravel[_-]session$/i,
    framework: 'Laravel',
    setting: 'SESSION_SECURE_COOKIE',
    note: "Laravel's config/session.php defaults `secure` to `env('SESSION_SECURE_COOKIE')`, which is unset in a stock .env. The cookie ships without Secure unless you set it.",
  },
  {
    // Deliberately not attributed to one framework: XSRF-TOKEN is a shared
    // convention that Angular's HttpClient and axios both read by default, and
    // that Laravel, Django (as csrftoken) and many Express setups all write.
    // Naming the wrong framework in a finding is worse than naming none.
    match: /^XSRF-TOKEN$/,
    framework: 'the XSRF-TOKEN convention (Angular HttpClient, axios, Laravel and others)',
    setting: 'whichever middleware issues it',
    note: 'This cookie is read by client JavaScript by design, so the absent HttpOnly is expected. Its Secure flag, however, almost always comes from the same environment-gated config as the session cookie beside it. A CSRF token without Secure can be overwritten by a network attacker on a sibling plain-HTTP origin, which defeats the double-submit pattern it exists to support.',
  },
  {
    match: /^sessionid$/,
    framework: 'Django',
    setting: 'SESSION_COOKIE_SECURE',
    note: 'Django ships SESSION_COOKIE_SECURE = False by default; `manage.py check --deploy` flags it, but nothing in a dev run does.',
  },
  {
    match: /^csrftoken$/,
    framework: 'Django',
    setting: 'CSRF_COOKIE_SECURE',
    note: 'Django ships CSRF_COOKIE_SECURE = False by default. A CSRF cookie without Secure can be overwritten by a network attacker on a sibling HTTP origin.',
  },
  {
    match: /^_.*_session$/,
    framework: 'Rails',
    setting: 'config.force_ssl / session_store secure:',
    note: 'Rails sets the session cookie Secure only when `config.force_ssl = true`, which the development environment deliberately leaves off.',
  },
  {
    match: /^connect\.sid$/,
    framework: 'express-session',
    setting: 'cookie.secure',
    note: 'express-session defaults `cookie.secure` to false and its docs recommend gating it on the environment, which is precisely the two-path pattern.',
  },
  {
    match: /^(PHPSESSID)$/i,
    framework: 'PHP',
    setting: 'session.cookie_secure',
    note: 'php.ini ships session.cookie_secure off by default.',
  },
  {
    match: /^JSESSIONID$/i,
    framework: 'Java servlet container',
    setting: '<cookie-config><secure>',
    note: 'Servlet containers set the session cookie Secure only when the request arrives over HTTPS or the connector is told it is secure.',
  },
  {
    match: /^remember_web_/i,
    framework: 'Laravel',
    setting: 'SESSION_SECURE_COOKIE',
    note: 'The "remember me" cookie is long-lived and carries a recovery token. It inherits the session Secure gate.',
  },
];

/**
 * Scan one served body for environment-gated security flags.
 * @param {{ url: string, body: string, kind?: string }} resource
 */
export function scanSourceForConditionalFlags(resource) {
  const { url, body, kind = 'other' } = resource;
  if (!body) return [];
  const out = [];

  for (const pattern of SOURCE_PATTERNS) {
    const global = new RegExp(pattern.re.source, pattern.re.flags.includes('g') ? pattern.re.flags : `${pattern.re.flags}g`);
    let m;
    let guard = 0;
    while ((m = global.exec(body)) !== null && guard++ < 10) {
      out.push({
        signal: 'source',
        patternId: pattern.id,
        attribute: pattern.attribute,
        resource: url,
        resourceKind: kind,
        line: lineNumberAt(body, m.index),
        snippet: snippet(body, m.index, m[0].length),
      });
      if (m.index === global.lastIndex) global.lastIndex++;
    }
  }
  return out;
}

/**
 * Inspect an observed cookie for framework-level evidence of the gate.
 * @param {import('./cookie-parser.js').ParsedCookie} cookie
 */
export function inspectCookieForConditionalFlags(cookie) {
  const out = [];

  const pair = PREFIX_PAIRS.find((p) => p.insecure === cookie.name);
  if (pair) {
    out.push({
      signal: 'prefix-pair',
      cookie: cookie.name,
      framework: pair.framework,
      productionName: pair.secure,
      detail: `${pair.framework} names this cookie "${pair.insecure}" on http and "${pair.secure}" on https. The production cookie has a different name and different flags, so nothing observed here describes it.`,
    });
  }

  if (!cookie.secure) {
    const fw = FRAMEWORK_SESSION_COOKIES.find((f) => f.match.test(cookie.name));
    if (fw) {
      out.push({
        signal: 'framework-default',
        cookie: cookie.name,
        framework: fw.framework,
        setting: fw.setting,
        detail: fw.note,
      });
    }
  }

  return out;
}

function snippet(body, index, length, radius = 70) {
  const start = Math.max(0, index - radius);
  const end = Math.min(body.length, index + length + radius);
  return body.slice(start, end).replace(/\s+/g, ' ').trim();
}

function lineNumberAt(body, index) {
  let line = 1;
  for (let i = 0; i < index && i < body.length; i++) if (body.charCodeAt(i) === 10) line++;
  return line;
}

export const _internal = { SOURCE_PATTERNS, PREFIX_PAIRS, FRAMEWORK_SESSION_COOKIES };
