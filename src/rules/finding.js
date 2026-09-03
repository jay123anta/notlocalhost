/**
 * Finding shape and severity ordering.
 *
 * Three severities, and the boundary between them is a promise to the reader:
 *
 *   will-break  This behaves differently on a real HTTPS origin, and the
 *               difference is defined by a spec or by shipped browser
 *               behaviour, not by our guess. If we say will-break we can point
 *               at the clause.
 *   may-break   It depends on something we cannot see from here -- your
 *               deployment topology, your proxy, your production config.
 *   info        Worth knowing. Not a defect.
 *
 * Nothing gets promoted to will-break to make output look impressive. A tool
 * that cries wolf gets muted, and then it is worth nothing at all.
 */

export const SEVERITIES = /** @type {const} */ (['will-break', 'may-break', 'info']);

const RANK = { 'will-break': 3, 'may-break': 2, info: 1 };

export function severityRank(s) {
  return RANK[s] ?? 0;
}

export function atOrAbove(severity, threshold) {
  return severityRank(severity) >= severityRank(threshold);
}

/**
 * @typedef {object} Finding
 * @property {string} id       Stable rule id, e.g. 'cookie.samesite-none-without-secure'.
 * @property {'will-break'|'may-break'|'info'} severity
 * @property {string} title    One line, specific, no hedging.
 * @property {string} summary  What changes on a real origin, and why.
 * @property {Array<{label: string, value: string}>} evidence
 * @property {string[]} fix    Concrete steps.
 * @property {Array<{title: string, url: string}>} refs
 * @property {string} [subject] The thing this is about (cookie name, URL).
 */

/**
 * @param {Partial<Finding> & { id: string, severity: string, title: string }} f
 * @returns {Finding}
 */
export function finding(f) {
  if (!SEVERITIES.includes(f.severity)) {
    throw new Error(`unknown severity "${f.severity}" on rule ${f.id}`);
  }
  return {
    id: f.id,
    severity: f.severity,
    title: f.title,
    summary: f.summary ?? '',
    subject: f.subject,
    evidence: f.evidence ?? [],
    fix: f.fix ?? [],
    refs: f.refs ?? [],
  };
}

export function sortFindings(findings) {
  return [...findings].sort((a, b) => {
    const bySeverity = severityRank(b.severity) - severityRank(a.severity);
    if (bySeverity !== 0) return bySeverity;
    if (a.id !== b.id) return a.id < b.id ? -1 : 1;
    return String(a.subject ?? '') < String(b.subject ?? '') ? -1 : 1;
  });
}

/** Shared reference links, so wording and URLs stay consistent across rules. */
export const REF = {
  rfc6265: { title: 'RFC 6265 - HTTP State Management Mechanism', url: 'https://www.rfc-editor.org/rfc/rfc6265' },
  rfc6265Ports: {
    title: 'RFC 6265 section 8.5 - Weak Confidentiality (cookies are not isolated by port)',
    url: 'https://www.rfc-editor.org/rfc/rfc6265#section-8.5',
  },
  rfc6265Domain: {
    title: 'RFC 6265 section 5.1.3 - Domain Matching',
    url: 'https://www.rfc-editor.org/rfc/rfc6265#section-5.1.3',
  },
  rfc6265Storage: {
    title: 'RFC 6265 section 5.3 - Storage Model (public-suffix rejection)',
    url: 'https://www.rfc-editor.org/rfc/rfc6265#section-5.3',
  },
  rfc6265bisPrefixes: {
    title: 'RFC 6265bis section 4.1.3 - Cookie Name Prefixes',
    url: 'https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-rfc6265bis#section-4.1.3',
  },
  rfc6265bisSameSite: {
    title: 'RFC 6265bis section 5.4.7 - SameSite, and the None-requires-Secure rule',
    url: 'https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-rfc6265bis#section-5.4.7',
  },
  rfc6761: {
    title: 'RFC 6761 section 6.3 - the reserved "localhost" special-use domain',
    url: 'https://www.rfc-editor.org/rfc/rfc6761#section-6.3',
  },
  secureContexts: {
    title: 'W3C Secure Contexts',
    url: 'https://www.w3.org/TR/secure-contexts/',
  },
  potentiallyTrustworthy: {
    title: 'W3C Secure Contexts - potentially trustworthy origins (why localhost is exempt)',
    url: 'https://www.w3.org/TR/secure-contexts/#is-origin-trustworthy',
  },
  mixedContent: {
    title: 'W3C Mixed Content',
    url: 'https://www.w3.org/TR/mixed-content/',
  },
  fetchCors: {
    title: 'Fetch Standard - CORS protocol and credentials',
    url: 'https://fetch.spec.whatwg.org/#cors-protocol',
  },
  chromeSameSite: {
    title: 'Chrome - SameSite cookies explained',
    url: 'https://developer.chrome.com/docs/privacy-security/same-site-cookie-recipes',
  },
  mdnSetCookie: {
    title: 'MDN - Set-Cookie',
    url: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie',
  },
};
