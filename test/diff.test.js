/**
 * The parity diff.
 *
 * These are all pure: two documents in, one document out. The value of the
 * diff is entirely in how it classifies, so that is what is asserted -- not
 * that it runs.
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import { compareReports, comparability, keyOf, CONFIRMS, LOCALHOST_ARTIFACTS } from '../src/diff/compare.js';

const report = (findings, extra = {}) => ({
  schemaVersion: 1,
  tool: { name: 'notlocalhost', version: '0.1.1' },
  target: { url: 'http://localhost:3000' },
  coverage: { requests: 40, flow: { used: false } },
  findings,
  ...extra,
});

const f = (id, severity, subject, extra = {}) => ({
  id,
  severity,
  subject,
  title: `${id} on ${subject ?? 'the run'}`,
  summary: '',
  evidence: [],
  fix: [],
  refs: [],
  ...extra,
});

describe('identity: a finding is a rule plus the thing it is about', () => {
  test('two findings from one rule about different cookies are different findings', () => {
    assert.notEqual(keyOf(f('cookie.missing-secure', 'will-break', 'sid')), keyOf(f('cookie.missing-secure', 'will-break', 'ab')));
  });

  test('a finding with no subject is identified by its rule alone', () => {
    assert.equal(keyOf(f('origin.inventory', 'info', undefined)), 'origin.inventory');
  });
});

describe('a prediction that came true is not a prediction that went away', () => {
  // The whole point. Locally the tool derives the defect from a header; on the
  // real origin Chrome refuses the cookie and it is reported as an observation.
  // Subtracting one list from the other calls that "resolved" at the exact
  // moment it was confirmed.
  test('a derived prediction matched by an observation is confirmed, not resolved', () => {
    const before = report([f('cookie.samesite-none-without-secure', 'will-break', 'ab_test')]);
    const after = report([f('cookie.rejected-by-browser', 'will-break', 'ab_test')], {
      target: { url: 'https://app.demo.localhost' },
    });

    const d = compareReports(before, after);
    assert.equal(d.counts.confirmed, 1, JSON.stringify(d.counts));
    assert.equal(d.counts.unexplained, 0, 'it must not be reported as having gone away');
    assert.equal(d.confirmed[0].prediction.id, 'cookie.samesite-none-without-secure');
    assert.equal(d.confirmed[0].observation.id, 'cookie.rejected-by-browser');
  });

  test('the confirmation must be about the same cookie', () => {
    const before = report([f('cookie.samesite-none-without-secure', 'will-break', 'ab_test')]);
    const after = report([f('cookie.rejected-by-browser', 'will-break', 'a_different_cookie')]);

    const d = compareReports(before, after);
    assert.equal(d.counts.confirmed, 0, 'a different cookie confirms nothing');
    assert.equal(d.counts.unexplained, 1);
    assert.equal(d.counts.appeared, 1, 'and the rejection is itself a new finding');
  });

  test('a confirmed observation is not also counted as newly appeared', () => {
    const before = report([f('cookie.host-prefix-violation', 'will-break', '__Host-csrf')]);
    const after = report([f('cookie.rejected-by-browser', 'will-break', '__Host-csrf')]);

    const d = compareReports(before, after);
    assert.equal(d.counts.confirmed, 1);
    assert.equal(d.counts.appeared, 0, 'it would be double counting: one event, seen twice');
  });
});

describe('what localhost was hiding', () => {
  test('a finding only on the real origin is reported as appeared', () => {
    const before = report([]);
    const after = report([f('mixedcontent.blocked', 'will-break', 'http://cdn.example.com/a.js')]);

    const d = compareReports(before, after);
    assert.equal(d.counts.appeared, 1);
    assert.equal(d.worstSeverity.appeared, 'will-break');
  });

  test('a finding in both runs persists, and a severity change is recorded', () => {
    const before = report([f('cookie.missing-httponly', 'info', 'sid')]);
    const after = report([f('cookie.missing-httponly', 'will-break', 'sid')]);

    const d = compareReports(before, after);
    assert.equal(d.counts.persisted, 1);
    assert.deepEqual(d.persisted[0].severityChanged, { from: 'info', to: 'will-break' });
  });

  test('an unchanged severity is not reported as a change', () => {
    const before = report([f('cookie.missing-httponly', 'info', 'sid')]);
    const after = report([f('cookie.missing-httponly', 'info', 'sid')]);
    assert.equal(compareReports(before, after).persisted[0].severityChanged, null);
  });
});

describe('findings that were never about the target origin', () => {
  // Taking credit for these would be flattery: the condition that produces
  // them is a property of localhost, not of the application.
  test('the port-sharing hazard disappearing is expected, not an improvement', () => {
    const before = report([f('cookie.port-sharing-hazard', 'will-break', undefined)]);
    const after = report([]);

    const d = compareReports(before, after);
    assert.equal(d.counts.expected, 1);
    assert.equal(d.counts.unexplained, 0);
    assert.match(d.expected[0].because, /shares one cookie jar/);
  });

  test('every artifact carries a reason, so the category cannot become a dumping ground', () => {
    for (const [id, why] of Object.entries(LOCALHOST_ARTIFACTS)) {
      assert.ok(why && why.length > 20, `${id} needs a real explanation, got: ${why}`);
    }
  });

  test('a genuine defect vanishing is unexplained, and says so', () => {
    const before = report([f('leak.api-base', 'will-break', 'http://localhost:4000')]);
    const after = report([]);

    const d = compareReports(before, after);
    assert.equal(d.counts.unexplained, 1, 'this one is not explained away');
    assert.equal(d.counts.expected, 0);
  });
});

describe('two runs only compare if they saw comparable ground', () => {
  test('a shallow second run is refused rather than reported as progress', () => {
    const before = report([f('cookie.missing-secure', 'will-break', 'sid')], { coverage: { requests: 100 } });
    const after = report([], { coverage: { requests: 3 } });

    const d = compareReports(before, after);
    assert.equal(d.comparable.ok, false);
    assert.match(d.comparable.reasons.join(' '), /did not exercise the same ground/);
  });

  test('a flow used on only one side is named', () => {
    const c = comparability(
      report([], { coverage: { requests: 40, flow: { used: true } } }),
      report([], { coverage: { requests: 40, flow: { used: false } } }),
    );
    assert.equal(c.ok, false);
    assert.match(c.reasons.join(' '), /--flow/);
  });

  test('a run that recorded nothing is not silently compared', () => {
    const c = comparability(report([], { coverage: { requests: 0 } }), report([], { coverage: { requests: 40 } }));
    assert.equal(c.ok, false);
    assert.match(c.reasons.join(' '), /no requests/);
  });

  test('differing schema versions are named, because fields may not mean the same thing', () => {
    const c = comparability(report([], { schemaVersion: 1 }), report([], { schemaVersion: 2 }));
    assert.equal(c.ok, false);
    assert.match(c.reasons.join(' '), /schema versions/);
  });

  test('comparable runs say so plainly', () => {
    assert.deepEqual(comparability(report([]), report([])), { ok: true, reasons: [] });
  });
});

describe('the document itself', () => {
  test('every confirmation maps to a rule that exists in the analyzer', async () => {
    const { ALL_RULE_IDS } = await import('../src/rules/index.js').then((m) => ({
      ALL_RULE_IDS: m.ALL_RULE_IDS ?? null,
    }));
    // The analyzer does not export an id list, so this asserts the shape
    // instead: a mapping to nothing would silently never confirm anything.
    for (const [predicted, observations] of Object.entries(CONFIRMS)) {
      assert.match(predicted, /^[a-z]+\.[a-z-]+$/, `not a rule id: ${predicted}`);
      assert.ok(observations.length > 0, `${predicted} maps to nothing`);
      for (const o of observations) assert.match(o, /^[a-z]+\.[a-z-]+$/, `not a rule id: ${o}`);
    }
    assert.equal(ALL_RULE_IDS, null, 'if the analyzer starts exporting ids, tighten this test');
  });

  test('it refuses documents that are not reports', () => {
    assert.throws(() => compareReports({}, report([])), /findings array/);
    assert.throws(() => compareReports(report([]), null), /findings array/);
  });

  test('counts agree with the arrays they describe', () => {
    const before = report([
      f('cookie.samesite-none-without-secure', 'will-break', 'ab'),
      f('cookie.port-sharing-hazard', 'will-break', undefined),
      f('leak.api-base', 'will-break', 'http://localhost:4000'),
      f('cookie.missing-httponly', 'info', 'sid'),
    ]);
    const after = report([
      f('cookie.rejected-by-browser', 'will-break', 'ab'),
      f('cookie.missing-httponly', 'info', 'sid'),
      f('mixedcontent.blocked', 'will-break', 'http://cdn/x.js'),
    ]);

    const d = compareReports(before, after);
    assert.equal(d.counts.confirmed, d.confirmed.length);
    assert.equal(d.counts.persisted, d.persisted.length);
    assert.equal(d.counts.appeared, d.appeared.length);
    assert.equal(d.counts.expected, d.expected.length);
    assert.equal(d.counts.unexplained, d.unexplained.length);

    assert.deepEqual(d.counts, { confirmed: 1, persisted: 1, appeared: 1, expected: 1, unexplained: 1 });
  });
});

describe('a confirmation has to be news', () => {
  // Found by running the diff on two real reports. Chrome refuses a
  // SameSite=None cookie on localhost as readily as on a real origin, so the
  // rejection appears in both runs. Counting it as "predicted, then observed"
  // claims the real origin revealed something it did not, and the same finding
  // then shows up under unchanged as well.
  test('an observation present in both runs is unchanged, not confirmation', () => {
    const prediction = f('cookie.samesite-none-without-secure', 'will-break', 'ab_test');
    const rejection = f('cookie.rejected-by-browser', 'will-break', 'ab_test');

    const d = compareReports(report([prediction, rejection]), report([prediction, rejection]));

    assert.equal(d.counts.confirmed, 0, 'the rejection was already there locally');
    assert.equal(d.counts.persisted, 2, 'both the prediction and the rejection simply persist');
  });

  test('an observation that only the real origin produced does confirm', () => {
    const prediction = f('cookie.samesite-none-without-secure', 'will-break', 'ab_test');
    const d = compareReports(report([prediction]), report([f('cookie.rejected-by-browser', 'will-break', 'ab_test')]));
    assert.equal(d.counts.confirmed, 1);
  });

  test('a finding is never counted in two categories at once', () => {
    const prediction = f('cookie.missing-secure', 'will-break', 'sid');
    const rejection = f('cookie.rejected-by-browser', 'will-break', 'sid');
    const d = compareReports(report([prediction, rejection]), report([prediction, rejection]));

    const total = d.counts.confirmed + d.counts.persisted + d.counts.appeared + d.counts.expected + d.counts.unexplained;
    // Two findings before, two after, and the confirmed pair would consume one
    // from each side. Whatever the classification, the arithmetic must close.
    const accountedBefore = d.counts.confirmed + d.counts.persisted + d.counts.expected + d.counts.unexplained;
    assert.equal(accountedBefore, 2, `every prior finding must land in exactly one category (total ${total})`);
  });
});

describe('a malformed report is rejected where it can be explained', () => {
  // F11. The renderer reached finding.severity.padEnd several screens later
  // and crashed with no clue which document was at fault.
  test('a finding with no severity names the document it came from', () => {
    const bad = { id: 'x.y', title: 't' };
    assert.throws(() => compareReports(report([bad]), report([])), /first report contains a finding/);
    assert.throws(() => compareReports(report([]), report([bad])), /second report contains a finding/);
  });

  test('an unknown severity is refused rather than ranked as -1', () => {
    assert.throws(() => compareReports(report([f('x.y', 'catastrophic', 'a')]), report([])), /unknown severity/);
  });

  test('findings must be an array, not merely present', () => {
    assert.throws(() => compareReports({ findings: 'lots' }, report([])), /findings array/);
  });
});
