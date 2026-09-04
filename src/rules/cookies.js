/**
 * Cookie rules.
 *
 * Cookies are where localhost lies hardest, because the two things that make a
 * cookie safe -- `Secure` and a real site boundary -- are precisely the two
 * things localhost cannot give you.
 */
import { parseSetCookie, parseDocumentCookieWrite, effectiveSameSite } from '../collect/cookie-parser.js';
import { inspectCookieForConditionalFlags, scanSourceForConditionalFlags } from '../collect/conditional-flags.js';
import { finding, REF } from './finding.js';
import { parseOrigin, isLoopbackHost } from '../collect/origins.js';
import { describeSystemPort } from '../collect/port-scan.js';

/** Names that mean "losing this cookie logs the user out or breaks CSRF". */
const AUTH_NAME_RE =
  /(sess|auth|token|jwt|sid$|^sid|login|logged|remember|identity|csrf|xsrf|_ga_session|access|refresh|bearer|oauth)/i;

function looksLikeAuthCookie(cookie) {
  if (cookie.prefix) return true;
  if (AUTH_NAME_RE.test(cookie.name)) return true;
  if (cookie.httpOnly && (cookie.value?.length ?? 0) >= 16) return true;
  return false;
}

/**
 * @param {object} ctx
 * @param {import('../session.js').Capture} ctx.capture
 * @param {ReturnType<import('../collect/origins.js').createDeploymentModel>} ctx.model
 * @param {number[]} ctx.openPorts
 * @param {string} ctx.targetUrl
 * @param {string} [ctx.platform] Overridable so port labelling is testable.
 * @returns {import('./finding.js').Finding[]}
 */
export function cookieRules(ctx) {
  const { capture, model, openPorts, targetUrl, platform = process.platform } = ctx;
  const target = parseOrigin(targetUrl);
  const out = [];

  /** Every cookie we saw set, from any source, de-duplicated by name+source. */
  const observed = [];

  for (const entry of capture.setCookies) {
    const parsed = parseSetCookie(entry.raw);
    if (!parsed) continue;
    observed.push({ ...parsed, setBy: 'Set-Cookie', requestUrl: entry.url, phase: entry.phase });
  }
  for (const ev of capture.instrumentation) {
    if (ev.type !== 'cookie.write') continue;
    const parsed = parseDocumentCookieWrite(ev.raw);
    if (!parsed) continue;
    observed.push({ ...parsed, setBy: 'document.cookie', requestUrl: ev.url, stack: ev.stack });
  }

  const uniq = dedupe(observed);

  // ------------------------------------------------------------ inventory --
  if (uniq.length) {
    out.push(
      finding({
        id: 'cookie.inventory',
        severity: 'info',
        title: `${uniq.length} cookie${uniq.length === 1 ? '' : 's'} observed during this run`,
        summary:
          'Full attribute inventory for every cookie set while the analyzer was watching. ' +
          'Cookies that are only set after login appear here only if a --flow script logged in.',
        evidence: uniq.map((c) => ({
          label: c.name,
          value:
            `Secure=${c.secure} HttpOnly=${c.httpOnly} SameSite=${c.sameSite ?? '(unset)'} ` +
            `-> effective ${effectiveSameSite(c)}; Domain=${c.domain ?? '(host-only)'} Path=${c.path ?? '/'} ` +
            `prefix=${c.prefix ?? 'none'} via ${c.setBy}`,
        })),
        refs: [REF.mdnSetCookie],
      }),
    );
  }

  // -------------------------------- SameSite=None without Secure (hard fail) --
  for (const c of uniq) {
    if ((c.sameSite || '').toLowerCase() !== 'none' || c.secure) continue;
    out.push(
      finding({
        id: 'cookie.samesite-none-without-secure',
        severity: 'will-break',
        subject: c.name,
        title: `Cookie "${c.name}" is SameSite=None without Secure`,
        summary:
          'Chrome rejects this cookie outright -- it is not downgraded to Lax, it is dropped. ' +
          'You may not have noticed locally because the code path that needs cross-site delivery ' +
          'has not run, or because the cookie is being re-set on every request. On a real origin ' +
          'the cross-site request arrives with no cookie at all.',
        evidence: [
          { label: 'Set-Cookie', value: c.raw },
          { label: 'set by', value: `${c.setBy}${c.requestUrl ? ` from ${c.requestUrl}` : ''}` },
          { label: 'effective SameSite', value: effectiveSameSite(c) },
        ],
        fix: [
          `Add Secure: Set-Cookie: ${c.name}=...; SameSite=None; Secure`,
          'SameSite=None; Secure only works over HTTPS, which is the reason this cannot be tested on plain-HTTP localhost.',
          'If the cookie does not actually need cross-site delivery, use SameSite=Lax and drop the None entirely.',
        ],
        refs: [REF.rfc6265bisSameSite, REF.chromeSameSite],
      }),
    );
  }

  // ------------------------------------------------ cookie name prefix rules --
  for (const c of uniq) {
    if (c.prefix === '__Host-') {
      const problems = [];
      if (!c.secure) problems.push('no Secure attribute');
      if (c.domain) problems.push(`a Domain attribute (Domain=${c.domain})`);
      if ((c.path ?? '/') !== '/') problems.push(`Path=${c.path} rather than Path=/`);
      if (c.setBy === 'document.cookie' && !c.secure) problems.push('set from document.cookie over a non-Secure write');

      if (problems.length) {
        out.push(
          finding({
            id: 'cookie.host-prefix-violation',
            severity: 'will-break',
            subject: c.name,
            title: `"${c.name}" uses the __Host- prefix but breaks its rules: ${problems.join(', ')}`,
            summary:
              'The __Host- prefix is a contract enforced by the browser: the cookie must be Secure, must have ' +
              'no Domain attribute, and must have Path=/. A cookie that violates any of those is rejected and ' +
              'never stored. This is one of the few localhost lies that can bite even locally -- but only if ' +
              'the Secure clause is satisfied, which on plain HTTP it never is.',
            evidence: [
              { label: 'Set-Cookie', value: c.raw },
              { label: 'violations', value: problems.join('; ') },
            ],
            fix: [
              `Set-Cookie: ${c.name}=...; Secure; Path=/; HttpOnly; SameSite=Lax   (no Domain attribute at all)`,
              'If you need the cookie shared across subdomains, __Host- is the wrong prefix. Use __Secure- with an explicit Domain.',
            ],
            refs: [REF.rfc6265bisPrefixes],
          }),
        );
      }
    }

    if (c.prefix === '__Secure-' && !c.secure) {
      out.push(
        finding({
          id: 'cookie.secure-prefix-violation',
          severity: 'will-break',
          subject: c.name,
          title: `"${c.name}" uses the __Secure- prefix without a Secure attribute`,
          summary:
            'A __Secure- cookie must carry Secure and must be set from a secure origin. Without it the browser ' +
            'refuses to store the cookie. The name is a promise the attributes are not keeping.',
          evidence: [{ label: 'Set-Cookie', value: c.raw }],
          fix: [`Add the Secure attribute, or drop the __Secure- prefix from the name.`],
          refs: [REF.rfc6265bisPrefixes],
        }),
      );
    }
  }

  // ------------------------------------------------- Domain=localhost family --
  for (const c of uniq) {
    if (!c.domain) continue;
    if (!isLoopbackHost(c.domain) && c.domain !== 'localhost') continue;

    const isDotLocalhost = c.domain.endsWith('.localhost') || (c.domainWasDotted && c.domain === 'localhost');
    out.push(
      finding({
        id: 'cookie.domain-localhost',
        severity: 'will-break',
        subject: c.name,
        title: `Cookie "${c.name}" sets Domain=${c.domainWasDotted ? '.' : ''}${c.domain}`,
        summary:
          'This does not do what it looks like it does. Under RFC 6265 a leading dot is stripped and ignored, ' +
          'so ".localhost" and "localhost" are the same value -- there is no way to write a parent-domain ' +
          'scope for localhost. A Domain attribute here either duplicates the host-only behaviour you already ' +
          'had, or is rejected outright. Meanwhile the production value of this attribute is a real registrable ' +
          'domain with entirely different sharing behaviour, and it has never been exercised.' +
          (isDotLocalhost
            ? ' The app.localhost / api.localhost pattern in particular does not create a shared cookie scope: ' +
              'nothing can set a cookie readable by both, because "localhost" is a reserved special-use TLD ' +
              'and browsers refuse Domain attributes that resolve to a top-level domain.'
            : ''),
        evidence: [
          { label: 'Set-Cookie', value: c.raw },
          { label: 'Domain as parsed', value: `${c.domain} (leading dot ${c.domainWasDotted ? 'present and stripped' : 'absent'})` },
          { label: 'stored as', value: 'a domain cookie for "localhost" if accepted at all, never a parent scope' },
        ],
        fix: [
          'Drop the Domain attribute locally: host-only is the only scope localhost can express.',
          'To exercise a real parent-domain scope you need a real registrable domain. That is what `notlocalhost init` builds.',
          'Do not ship Domain=localhost. Make the production value configuration, not a constant.',
        ],
        refs: [REF.rfc6265Domain, REF.rfc6265Storage, REF.rfc6761],
      }),
    );
  }

  // -------------------------------------------------------- missing Secure --
  // Prefixed cookies are excluded: their own prefix rule already reports the
  // missing Secure at will-break, and saying it twice trains people to skim.
  const insecureAuth = uniq.filter((c) => !c.secure && !c.prefix && looksLikeAuthCookie(c));
  for (const c of insecureAuth) {
    out.push(
      finding({
        id: 'cookie.missing-secure',
        severity: 'may-break',
        subject: c.name,
        title: `Session-shaped cookie "${c.name}" has no Secure attribute`,
        summary:
          'It could not have one: a Secure cookie cannot be set over plain HTTP, so this is the expected local ' +
          'result. That is exactly the problem. Whatever sets Secure in production is a code path that did not ' +
          'run here, so this run says nothing about whether it works. Without Secure in production, the cookie ' +
          'is sent over any plain-HTTP request to the same host and can be read or overwritten by a network attacker.',
        evidence: [
          { label: 'Set-Cookie', value: c.raw },
          { label: 'HttpOnly', value: String(c.httpOnly) },
          { label: 'effective SameSite', value: effectiveSameSite(c) },
        ],
        fix: [
          'Confirm the production configuration sets Secure, and prove it rather than assuming it.',
          'Prefer terminating TLS locally over branching on the environment, so one code path serves both.',
        ],
        refs: [REF.mdnSetCookie],
      }),
    );
  }

  // ------------------------------------------------------- HttpOnly missing --
  for (const c of uniq) {
    if (c.httpOnly) continue;
    if (!looksLikeAuthCookie(c)) continue;
    // CSRF tokens are deliberately readable by script; do not cry wolf.
    if (/csrf|xsrf/i.test(c.name)) continue;
    if (c.setBy === 'document.cookie') continue; // script-set cookies cannot be HttpOnly

    out.push(
      finding({
        id: 'cookie.missing-httponly',
        severity: 'info',
        subject: c.name,
        title: `Session-shaped cookie "${c.name}" is readable by JavaScript (no HttpOnly)`,
        summary:
          'Unrelated to the HTTPS move, but it travels with it: HttpOnly is the difference between an XSS bug ' +
          'that steals a token and one that does not. Included because you are already editing this cookie config.',
        evidence: [{ label: 'Set-Cookie', value: c.raw }],
        fix: ['Add HttpOnly unless application JavaScript genuinely needs to read the value.'],
        refs: [REF.mdnSetCookie],
      }),
    );
  }

  // --------------------------------------------- SameSite left to the default --
  const defaulted = uniq.filter((c) => !c.sameSite);
  if (defaulted.length) {
    out.push(
      finding({
        id: 'cookie.samesite-unspecified',
        severity: 'info',
        title: `${defaulted.length} cookie${defaulted.length === 1 ? '' : 's'} rely on the browser's default SameSite`,
        summary:
          'Chrome treats an absent SameSite as Lax. Firefox and Safari have not settled on identical behaviour, ' +
          'and the default has changed before. Being explicit costs nothing and removes a cross-browser variable ' +
          'from any future cross-site flow.',
        evidence: defaulted.map((c) => ({ label: c.name, value: `${c.raw}  -> treated as ${effectiveSameSite(c)}` })),
        fix: ['State SameSite explicitly on every cookie you set.'],
        refs: [REF.chromeSameSite],
      }),
    );
  }

  // ------------------------------------------ Chrome rejected it, in its words --
  const blockedByName = new Map();
  for (const b of capture.blockedCookies) {
    const key = `${b.name ?? b.raw}|${b.reasons.join(',')}`;
    if (!blockedByName.has(key)) blockedByName.set(key, b);
  }
  for (const b of blockedByName.values()) {
    out.push(
      finding({
        id: 'cookie.rejected-by-browser',
        severity: 'will-break',
        subject: b.name ?? '(unnamed)',
        title: `Chrome rejected cookie "${b.name ?? '(unnamed)'}": ${b.reasons.join(', ') || 'unspecified'}`,
        summary:
          'This is not our prediction. Chrome refused to store the cookie during this run and told us why. ' +
          'A rejected cookie is silent -- no console error by default, no failed request, just a session that ' +
          'never starts.',
        evidence: [
          { label: 'Set-Cookie', value: b.raw ?? '(not reported)' },
          { label: 'from', value: b.url ?? '(unknown request)' },
          { label: 'Chrome reason codes', value: b.reasons.join(', ') || '(none given)' },
        ],
        fix: [explainBlockReason(b.reasons)],
        refs: [REF.rfc6265bisSameSite, REF.rfc6265bisPrefixes],
      }),
    );
  }

  // ------------------------------------------------- the port-sharing hazard --
  const hostOnly = uniq.filter((c) => !c.domain);
  if (target?.isLoopback && hostOnly.length) {
    const others = openPorts.filter((p) => String(p) !== target.port);
    // A system service on a well-known port is in the same jar, but it is not
    // another app of yours and nothing can be done about it. Counting it as one
    // would put a permanent will-break on every Mac.
    const devServers = others.filter((p) => !describeSystemPort(p, platform));
    const severity = devServers.length ? 'will-break' : 'info';
    out.push(
      finding({
        id: 'cookie.port-sharing-hazard',
        severity,
        title: devServers.length
          ? `Cookies from ${target.hostPort} are also sent to ${devServers.length} other server${devServers.length === 1 ? '' : 's'} on this machine`
          : others.length
            ? 'Cookies on localhost are not isolated by port'
            : 'Cookies on localhost are not isolated by port',
        summary:
          'Cookies have no concept of a port. RFC 6265 section 8.5 states it plainly: "cookies do not provide ' +
          'isolation by port". The Set-Cookie grammar has no port attribute, and the browser keys the jar by ' +
          'host alone. So every app you run on 127.0.0.1 shares one cookie jar, regardless of port.\n\n' +
          'Two consequences, and teams hit both. First, your app can read -- and silently overwrite -- another ' +
          'local app\'s session cookie, including one from an unrelated project. Second, this is the opposite ' +
          'of your production topology, where app.example.com and api.example.com are separate hosts that share ' +
          'cookies only if you set Domain deliberately. Neither sharing behaviour you see locally is the one you ship.' +
          (others.length
            ? `\n\nRight now this is not hypothetical: ${others.map((p) => `127.0.0.1:${p}`).join(', ')} ${others.length === 1 ? 'is' : 'are'} listening and inside the same jar.`
            : ''),
        evidence: [
          { label: 'target', value: `${target.scheme}://${target.hostPort}` },
          {
            label: 'host-only cookies in the shared jar',
            value: hostOnly.map((c) => c.name).join(', '),
          },
          {
            label: 'other listeners on this host',
            value: others.length
              ? others
                  .map((p) => {
                    const system = describeSystemPort(p, platform);
                    return `127.0.0.1:${p}${system ? `  (${system})` : ''}`;
                  })
                  .join('\n')
              : 'none found on the common dev ports',
          },
        ],
        fix: [
          'Do not rely on port separation for isolation. It does not exist.',
          'Give each app a distinct hostname during development so the jars are genuinely separate.',
          'If two local apps must not see each other\'s cookies, distinct hostnames are the only mechanism that works.',
        ],
        refs: [REF.rfc6265Ports, REF.rfc6265],
      }),
    );
  }

  // ------------------------- host-only cookies that stop crossing on deployment --
  //
  // The mirror image of the port-sharing hazard, and the one that actually
  // costs people a day. Today a host-only cookie set by localhost:3000 IS sent
  // to localhost:4000, because they are the same host. After deployment those
  // two become app.example.com and svc-4000.example.com -- different hosts --
  // and a host-only cookie is not sent to either from the other. The request
  // that has always carried a session silently stops carrying one.
  if (target?.isLoopback && hostOnly.length) {
    const otherPortRequests = capture.requests.filter((r) => {
      const p = parseOrigin(r.url);
      return p && p.isLoopback && p.hostname === target.hostname && p.port !== target.port;
    });

    if (otherPortRequests.length) {
      const credentialed = new Set();
      for (const ev of capture.instrumentation) {
        if (ev.credentials === 'include' && ev.target) credentialed.add(new URL(ev.target).host);
        if (ev.type === 'request.websocket' && ev.target) credentialed.add(new URL(ev.target).host);
      }
      const otherPorts = [...new Set(otherPortRequests.map((r) => parseOrigin(r.url).hostPort))];
      const anyCredentialed = otherPorts.some((hp) => credentialed.has(hp));

      out.push(
        finding({
          id: 'cookie.host-only-stops-crossing',
          severity: anyCredentialed ? 'will-break' : 'may-break',
          title: `Host-only cookies reach ${otherPorts.join(', ')} today and will stop once those are separate hostnames`,
          summary:
            'This is the port-sharing fact turned around, and it is the expensive direction.\n\n' +
            'Right now these requests go to a different port on the same host, so every host-only cookie is ' +
            'attached automatically -- no Domain attribute, no CORS credentials negotiation, nothing to configure. ' +
            'It looks like the API is authenticated because it is.\n\n' +
            'After deployment those ports become different hostnames. A host-only cookie is sent only to the exact ' +
            'host that set it, so the API receives no cookie at all. Nothing errors on the browser side; the ' +
            'request simply arrives unauthenticated, and you get a 401 that reproduces nowhere locally.' +
            (anyCredentialed
              ? '\n\nAt least one of these calls sets credentials to "include", which means the code already ' +
                'expects cookies to be there.'
              : ''),
          evidence: [
            { label: 'page', value: `${target.scheme}://${target.hostPort}` },
            { label: 'other-port endpoints called', value: otherPorts.join(', ') },
            { label: 'host-only cookies that will not follow', value: hostOnly.map((c) => c.name).join(', ') },
            {
              label: 'after deployment',
              value: otherPorts
                .map((hp) => `${model.hostnameFor(target.hostPort)} -> ${model.hostnameFor(hp)}: cookie not sent`)
                .join('; '),
            },
          ],
          fix: [
            'Decide the production cookie scope now, not later. If the API must receive the session cookie, set an explicit Domain on the parent registrable domain (Domain=example.com) so both subdomains match.',
            'Then check the consequences of that scope: a parent-domain cookie is sent to every subdomain, including ones you do not control.',
            'If a shared cookie is not wanted, move the API under the same host behind a path prefix, or switch to a token the client sends explicitly.',
            'None of these choices can be tested on localhost, because localhost cannot express a parent-domain scope at all.',
          ],
          refs: [REF.rfc6265Domain, REF.rfc6265Ports],
        }),
      );
    }
  }

  // ----------------------------------------------- the two-auth-paths smell --
  out.push(...conditionalFlagFindings(uniq, capture));

  // ------------------------------------------------ script-set cookie hygiene --
  const scriptSet = uniq.filter((c) => c.setBy === 'document.cookie');
  if (scriptSet.length) {
    out.push(
      finding({
        id: 'cookie.set-from-script',
        severity: 'info',
        title: `${scriptSet.length} cookie${scriptSet.length === 1 ? ' is' : 's are'} set from document.cookie`,
        summary:
          'Script-set cookies can never be HttpOnly, and on a real origin they additionally need Secure -- which ' +
          'a plain-HTTP local write cannot express, so the string being assembled here is not the production string.',
        evidence: scriptSet.map((c) => ({
          label: c.name,
          value: `${c.raw}${c.stack?.length ? `  <- ${c.stack[0]}` : ''}`,
        })),
        fix: ['Append "; Secure" when the page is served over HTTPS, or move the cookie server-side.'],
        refs: [REF.mdnSetCookie],
      }),
    );
  }

  return out;
}

function conditionalFlagFindings(cookies, capture) {
  const out = [];
  const cookieSignals = cookies.flatMap((c) => inspectCookieForConditionalFlags(c).map((s) => ({ ...s, raw: c.raw })));
  const sourceSignals = capture.bodies.flatMap((b) =>
    scanSourceForConditionalFlags({ url: b.url, body: b.body, kind: b.kind }),
  );

  for (const s of cookieSignals.filter((x) => x.signal === 'prefix-pair')) {
    out.push(
      finding({
        id: 'cookie.two-auth-paths',
        severity: 'may-break',
        subject: s.cookie,
        title: `"${s.cookie}" is ${s.framework}'s insecure-branch cookie; production uses "${s.productionName}"`,
        summary:
          `${s.detail}\n\n` +
          'This is the two-auth-paths problem in its purest form. The framework does not merely change a flag ' +
          'between environments -- it changes the cookie name. Every assertion this run could make about session ' +
          'handling applies to a cookie that production will never set.',
        evidence: [
          { label: 'observed', value: s.raw },
          { label: 'production cookie name', value: s.productionName },
          { label: 'framework', value: s.framework },
        ],
        fix: [
          'Serve the app over HTTPS locally so the framework takes its production branch. That is what stage 2 of this tool exists for.',
          'Until then, treat any local session test as testing a different cookie than the one users get.',
        ],
        refs: [REF.rfc6265bisPrefixes],
      }),
    );
  }

  for (const s of cookieSignals.filter((x) => x.signal === 'framework-default')) {
    out.push(
      finding({
        id: 'cookie.two-auth-paths',
        severity: 'may-break',
        subject: s.cookie,
        title: s.setting.startsWith('whichever')
          ? `"${s.cookie}" has no Secure attribute, and whatever sets it in production did not run here`
          : `"${s.cookie}" comes from ${s.framework}, whose Secure flag is an environment setting (${s.setting})`,
        summary:
          `${s.detail}\n\n` +
          'The local run exercised the branch where that setting is off. Whether the production branch is ' +
          'configured correctly is not observable from here -- which is the point of flagging it.',
        evidence: [
          { label: 'observed', value: s.raw },
          { label: 'setting that controls this', value: s.setting },
        ],
        fix: [
          `Verify ${s.setting} is enabled in the production configuration, and add a test that asserts it.`,
          'Better: serve HTTPS locally so the same configuration path runs in both places.',
        ],
        refs: [REF.mdnSetCookie],
      }),
    );
  }

  if (sourceSignals.length) {
    const byPattern = new Map();
    for (const s of sourceSignals) {
      if (!byPattern.has(s.patternId)) byPattern.set(s.patternId, []);
      byPattern.get(s.patternId).push(s);
    }
    for (const [patternId, hits] of byPattern) {
      out.push(
        finding({
          id: 'cookie.two-auth-paths-source',
          severity: 'may-break',
          subject: patternId,
          title: `Served code sets ${hits[0].attribute} conditionally on the environment`,
          summary:
            'A security attribute whose value depends on NODE_ENV (or an equivalent) means two different ' +
            'auth behaviours ship in one codebase, and only one of them is ever run by a developer. The other ' +
            'is first exercised by production traffic.\n\n' +
            'This is found by pattern-matching the code the dev server actually served, so it may match a ' +
            'comment, a vendored library, or dead code. Check the quoted line.',
          evidence: hits.slice(0, 6).map((h) => ({
            label: `${shortUrl(h.resource)}:${h.line}`,
            value: h.snippet,
          })),
          fix: [
            'Make the security attributes unconditional and change the *environment* instead, by terminating TLS locally.',
            'If the branch has to stay, add an assertion in CI that the production branch produces the flags you expect.',
          ],
          refs: [REF.mdnSetCookie],
        }),
      );
    }
  }

  return out;
}

function explainBlockReason(reasons) {
  const r = (reasons || []).join(',');
  if (/SameSiteNoneInsecure/i.test(r)) return 'Add Secure alongside SameSite=None. Chrome requires the pair.';
  if (/InvalidPrefix|NameValuePairExceedsMaxSize/i.test(r))
    return 'The cookie name prefix rules were violated. __Host- needs Secure, Path=/ and no Domain; __Secure- needs Secure.';
  if (/SameSiteStrict|SameSiteLax|SameSiteUnspecified/i.test(r))
    return 'The cookie was not sent or stored because of SameSite. Decide whether the flow genuinely needs cross-site delivery, and if so use SameSite=None; Secure.';
  if (/SecureOnly/i.test(r)) return 'A Secure cookie cannot be set or sent over a plain-HTTP origin.';
  if (/DomainMismatch|InvalidDomain/i.test(r))
    return 'The Domain attribute does not domain-match the host that sent it. See RFC 6265 section 5.3.';
  if (/ThirdParty|Partitioned/i.test(r))
    return 'Third-party cookie restrictions applied. Consider CHIPS (Partitioned) or removing the cross-site dependency.';
  return 'See the reason codes above; they map directly to Chrome cookie-blocking reasons.';
}

function dedupe(list) {
  const seen = new Map();
  for (const c of list) {
    const key = `${c.name}|${c.domain ?? ''}|${c.path ?? ''}|${c.secure}|${c.httpOnly}|${c.sameSite ?? ''}|${c.setBy}`;
    if (!seen.has(key)) seen.set(key, c);
  }
  return [...seen.values()];
}

function shortUrl(u) {
  try {
    const p = new URL(u);
    return p.pathname.length > 48 ? `...${p.pathname.slice(-45)}` : p.pathname;
  } catch {
    return u;
  }
}
