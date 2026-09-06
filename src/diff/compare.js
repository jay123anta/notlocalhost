/**
 * The parity diff: what the prediction was worth.
 *
 * The analyzer says a thing will break on a real HTTPS origin. The harness
 * provides a real HTTPS origin. This compares the two reports and answers the
 * only question that matters about a prediction: did it happen?
 *
 * Three things make that harder than subtracting one list from another.
 *
 * A prediction and its confirmation are not the same finding. Locally the tool
 * derives `cookie.samesite-none-without-secure` from a header. On the real
 * origin Chrome actually refuses the cookie and the tool reports
 * `cookie.rejected-by-browser`. Those are one event seen twice, and a diff that
 * treats them as unrelated reports a prediction "resolved" at the exact moment
 * it came true.
 *
 * Some findings cannot survive the move and were never about the target origin.
 * The port-sharing hazard exists because everything on localhost shares a
 * cookie jar; on `app.myproject.localhost` there is no shared jar to be in.
 * Calling that "fixed" would take credit for an accident of addressing.
 *
 * And two runs only compare if they saw comparable ground. A second run that
 * loaded fewer routes produces findings that vanish for no better reason than
 * that nothing looked. Every difference here is qualified by that check, and
 * where it fails the diff says so rather than quietly reporting progress.
 */

/** Bump when a field is removed or retyped. Adding one is not breaking. */
export const DIFF_SCHEMA_VERSION = 1;

/**
 * Predictions and the observations that confirm them.
 *
 * Keyed by the derived finding, valued by the observed findings that mean the
 * same underlying thing happened. Matched on subject as well as id, so one
 * rejected cookie confirms the prediction about that cookie and no other.
 */
export const CONFIRMS = {
  'cookie.samesite-none-without-secure': ['cookie.rejected-by-browser'],
  'cookie.host-prefix-violation': ['cookie.rejected-by-browser'],
  'cookie.secure-prefix-violation': ['cookie.rejected-by-browser'],
  'cookie.missing-secure': ['cookie.rejected-by-browser'],
  'mixedcontent.active': ['mixedcontent.blocked'],
  'cors.missing': ['cors.blocked-by-browser'],
};

/**
 * Findings that describe localhost itself, not the application.
 *
 * They cannot appear on a real origin because the condition that produces them
 * is a property of `localhost`. Their absence afterwards is arithmetic, not an
 * improvement, and reporting it as one would be flattery.
 */
export const LOCALHOST_ARTIFACTS = {
  'cookie.port-sharing-hazard':
    'every port on localhost shares one cookie jar; a real origin has its own, so this cannot occur there',
  'securecontext.apis-used':
    'http://localhost is already a secure context, so these APIs work in both runs; the finding is informational',
  'origin.inventory': 'an inventory of what was seen, not a defect',
  'cookie.inventory': 'an inventory of what was seen, not a defect',
};

/** A finding's identity: the rule, and the thing it is about. */
export function keyOf(finding) {
  return finding.subject ? `${finding.id} :: ${finding.subject}` : finding.id;
}

const SEVERITY_ORDER = ['info', 'may-break', 'will-break'];
const rank = (s) => SEVERITY_ORDER.indexOf(s);

/**
 * Are these two runs comparable at all?
 *
 * A diff between a thorough run and a shallow one is a list of things the
 * second did not look at. That is worth knowing and worth refusing to dress up
 * as progress, so this returns reasons rather than a verdict alone.
 */
export function comparability(before, after) {
  const reasons = [];

  if (before.schemaVersion !== after.schemaVersion) {
    reasons.push(
      `the reports use different schema versions (${before.schemaVersion} and ${after.schemaVersion}), so fields may not mean the same thing`,
    );
  }

  const bc = before.coverage ?? {};
  const ac = after.coverage ?? {};

  const bFlow = Boolean(bc.flow?.used ?? bc.flow);
  const aFlow = Boolean(ac.flow?.used ?? ac.flow);
  if (bFlow !== aFlow) {
    reasons.push(
      `only the ${bFlow ? 'first' : 'second'} run used --flow, so one saw authenticated pages the other never reached`,
    );
  }

  // Request counts never match exactly and are not meant to. A large gap means
  // the runs did different work, and every difference below inherits that doubt.
  const bReq = Number(bc.requests ?? 0);
  const aReq = Number(ac.requests ?? 0);
  if (bReq > 0 && aReq > 0) {
    const ratio = Math.min(bReq, aReq) / Math.max(bReq, aReq);
    if (ratio < 0.5) {
      reasons.push(
        `the runs made very different numbers of requests (${bReq} and ${aReq}), so they did not exercise the same ground`,
      );
    }
  } else if (bReq === 0 || aReq === 0) {
    reasons.push('one of the runs recorded no requests, so there is nothing to compare');
  }

  return { ok: reasons.length === 0, reasons };
}

/**
 * Compare two analyzer reports.
 *
 * @param {object} before  a report from the plain-HTTP origin
 * @param {object} after   a report from the real HTTPS origin
 */
export function compareReports(before, after) {
  if (!Array.isArray(before?.findings) || !Array.isArray(after?.findings)) {
    throw new Error('both documents must be notlocalhost reports with a findings array');
  }

  // A finding without an id or a severity is not one this can reason about,
  // and the renderer would crash on it several screens later with no clue
  // where the bad document came from. Say it here, naming the document.
  for (const [label, doc] of [['first', before], ['second', after]]) {
    for (const f of doc.findings) {
      if (typeof f?.id !== 'string' || !SEVERITY_ORDER.includes(f?.severity)) {
        throw new Error(
          `the ${label} report contains a finding with no id or an unknown severity: ${JSON.stringify(f).slice(0, 120)}`,
        );
      }
    }
  }

  const afterByKey = new Map(after.findings.map((f) => [keyOf(f), f]));
  const beforeKeys = new Set(before.findings.map(keyOf));
  const afterById = new Map();
  for (const f of after.findings) {
    if (!afterById.has(f.id)) afterById.set(f.id, []);
    afterById.get(f.id).push(f);
  }

  const confirmed = [];
  const persisted = [];
  const expected = [];
  const unexplained = [];

  for (const f of before.findings) {
    const key = keyOf(f);

    // Did the same defect show up as an observation rather than a prediction?
    //
    // Only if the observation is new. Chrome refuses a SameSite=None cookie on
    // localhost as readily as on a real origin, so that rejection is often
    // present in both runs -- and calling it a confirmation would claim the
    // real origin revealed something it did not. An observation that was
    // already there is not evidence about the move; it is just unchanged.
    const confirmations = CONFIRMS[f.id] ?? [];
    const observation = confirmations
      .flatMap((id) => afterById.get(id) ?? [])
      .find((o) => (!f.subject || o.subject === f.subject) && !beforeKeys.has(keyOf(o)));
    if (observation) {
      confirmed.push({ prediction: f, observation });
      continue;
    }

    const still = afterByKey.get(key);
    if (still) {
      persisted.push({
        finding: still,
        severityChanged: still.severity !== f.severity ? { from: f.severity, to: still.severity } : null,
      });
      continue;
    }

    if (LOCALHOST_ARTIFACTS[f.id]) {
      expected.push({ finding: f, because: LOCALHOST_ARTIFACTS[f.id] });
      continue;
    }

    unexplained.push({ finding: f });
  }

  // Anything on the real origin that localhost never showed. The most valuable
  // category in the whole document: these are what localhost was hiding.
  const confirmedObservations = new Set(confirmed.map((c) => keyOf(c.observation)));
  const appeared = after.findings
    .filter((f) => !beforeKeys.has(keyOf(f)) && !confirmedObservations.has(keyOf(f)))
    .map((finding) => ({ finding }));

  const worst = (list, pick) =>
    list.reduce((n, x) => Math.max(n, rank(pick(x).severity)), -1);

  return {
    schemaVersion: DIFF_SCHEMA_VERSION,
    generatedAt: new Date().toISOString(),
    before: {
      target: before.target?.url ?? null,
      tool: before.tool ?? null,
      findings: before.findings.length,
      coverage: before.coverage ?? null,
    },
    after: {
      target: after.target?.url ?? null,
      tool: after.tool ?? null,
      findings: after.findings.length,
      coverage: after.coverage ?? null,
    },
    comparable: comparability(before, after),
    confirmed,
    persisted,
    appeared,
    expected,
    unexplained,
    counts: {
      confirmed: confirmed.length,
      persisted: persisted.length,
      appeared: appeared.length,
      expected: expected.length,
      unexplained: unexplained.length,
    },
    worstSeverity: {
      appeared: SEVERITY_ORDER[worst(appeared, (x) => x.finding)] ?? null,
      persisted: SEVERITY_ORDER[worst(persisted, (x) => x.finding)] ?? null,
    },
  };
}
