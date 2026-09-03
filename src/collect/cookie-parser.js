/**
 * Set-Cookie parsing, following RFC 6265 section 5.2 closely enough that the
 * findings we build on top of it are defensible.
 *
 * Notable RFC 6265 behaviours we reproduce deliberately, because each one is
 * the source of a real finding:
 *
 *   - Attribute names are case-insensitive (`secure`, `Secure`, `SECURE`).
 *   - A `Domain` attribute with a leading dot is stripped of that dot and is
 *     otherwise identical (section 5.2.3). `.example.com` and `example.com`
 *     produce the same cookie. People believe otherwise constantly.
 *   - An empty `Domain` attribute value is ignored entirely, which turns the
 *     cookie back into a host-only cookie.
 *   - There is nowhere to put a port. RFC 6265 section 8.5 is explicit that
 *     cookies are not isolated by port; the Set-Cookie grammar has no port
 *     attribute at all, which is why `localhost:3000` and `localhost:4000`
 *     share one cookie jar.
 */

/**
 * @typedef {object} ParsedCookie
 * @property {string} name
 * @property {string} value
 * @property {boolean} secure
 * @property {boolean} httpOnly
 * @property {string|null} sameSite       Verbatim as sent, or null if absent.
 * @property {string|null} domain         Leading dot already stripped.
 * @property {boolean} domainWasDotted    True if the header said `.example.com`.
 * @property {string|null} path
 * @property {string|null} expires
 * @property {number|null} maxAge
 * @property {boolean} partitioned
 * @property {string|null} prefix         '__Host-' | '__Secure-' | null
 * @property {string} raw                 The original header line.
 * @property {Record<string,string>} unknownAttributes
 */

const KNOWN = new Set([
  'expires',
  'max-age',
  'domain',
  'path',
  'secure',
  'httponly',
  'samesite',
  'partitioned',
  'priority',
]);

/**
 * Parse one `Set-Cookie` header value.
 * @param {string} header
 * @returns {ParsedCookie|null} null if the header has no name/value pair at all.
 */
export function parseSetCookie(header) {
  const raw = String(header);
  const parts = raw.split(';');
  const nameValue = parts.shift() ?? '';

  const eq = nameValue.indexOf('=');
  // RFC 6265 5.2: if there is no '=' in the first pair, ignore the whole header.
  if (eq < 0) return null;

  const name = nameValue.slice(0, eq).trim();
  const value = nameValue.slice(eq + 1).trim();
  if (!name) return null;

  /** @type {ParsedCookie} */
  const cookie = {
    name,
    value,
    secure: false,
    httpOnly: false,
    sameSite: null,
    domain: null,
    domainWasDotted: false,
    path: null,
    expires: null,
    maxAge: null,
    partitioned: false,
    prefix: prefixOf(name),
    raw,
    unknownAttributes: {},
  };

  for (const part of parts) {
    const trimmed = part.trim();
    if (!trimmed) continue;
    const i = trimmed.indexOf('=');
    const attrName = (i < 0 ? trimmed : trimmed.slice(0, i)).trim().toLowerCase();
    const attrValue = i < 0 ? '' : trimmed.slice(i + 1).trim();

    switch (attrName) {
      case 'secure':
        cookie.secure = true;
        break;
      case 'httponly':
        cookie.httpOnly = true;
        break;
      case 'partitioned':
        cookie.partitioned = true;
        break;
      case 'samesite':
        cookie.sameSite = attrValue;
        break;
      case 'path':
        cookie.path = attrValue;
        break;
      case 'expires':
        cookie.expires = attrValue;
        break;
      case 'max-age': {
        const n = Number.parseInt(attrValue, 10);
        cookie.maxAge = Number.isNaN(n) ? null : n;
        break;
      }
      case 'domain': {
        // RFC 6265 5.2.3: an empty Domain is ignored; a leading dot is dropped.
        if (attrValue === '') break;
        cookie.domainWasDotted = attrValue.startsWith('.');
        cookie.domain = (cookie.domainWasDotted ? attrValue.slice(1) : attrValue).toLowerCase();
        break;
      }
      default:
        if (!KNOWN.has(attrName)) cookie.unknownAttributes[attrName] = attrValue;
    }
  }

  return cookie;
}

/** @param {string} name */
function prefixOf(name) {
  if (name.startsWith('__Host-')) return '__Host-';
  if (name.startsWith('__Secure-')) return '__Secure-';
  return null;
}

/**
 * Split a raw header block into individual `Set-Cookie` lines.
 *
 * Chrome's CDP `responseReceivedExtraInfo` joins repeated headers with a
 * newline, which is the only lossless way to hand back multiple `Set-Cookie`
 * values -- they cannot be comma-joined, because `Expires` contains a comma.
 * @param {string} value
 */
export function splitSetCookieHeader(value) {
  return String(value)
    .split('\n')
    .map((l) => l.trim())
    .filter(Boolean);
}

/**
 * Parse a `document.cookie = "..."` assignment. Same grammar as `Set-Cookie`,
 * except `HttpOnly` is silently ignored by the browser when set from script.
 * @param {string} assignment
 */
export function parseDocumentCookieWrite(assignment) {
  const parsed = parseSetCookie(assignment);
  if (!parsed) return null;
  return { ...parsed, source: 'document.cookie', httpOnly: false };
}

/**
 * Normalised effective SameSite, applying Chrome's default.
 *
 * Chrome treats an absent or unrecognised SameSite as `Lax`, and a
 * `SameSite=None` cookie without `Secure` is rejected outright rather than
 * downgraded -- so the "effective" value for that case is `rejected`.
 * @param {ParsedCookie} cookie
 */
export function effectiveSameSite(cookie) {
  const declared = (cookie.sameSite || '').toLowerCase();
  if (declared === 'none') return cookie.secure ? 'None' : 'rejected';
  if (declared === 'strict') return 'Strict';
  if (declared === 'lax') return 'Lax';
  return 'Lax (browser default)';
}
