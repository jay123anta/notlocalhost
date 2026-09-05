/**
 * Rendering the parity diff.
 *
 * Ordered by what a person needs to know, not by category size:
 *
 *   1. Whether the two runs can be compared at all. Everything below is void
 *      if they cannot, so it goes first rather than in a footnote.
 *   2. What appeared only on the real origin. These are what localhost was
 *      hiding, and nothing else in the document is news.
 *   3. What was predicted and confirmed. This is the tool being right, and it
 *      is also the evidence that the prediction was worth making.
 *   4. What survived the move. Still broken, and HTTPS was never going to fix
 *      it.
 *   5. What went away, split into the kind that means something and the kind
 *      that does not.
 */

const bar = (c, n = 78) => c.repeat(n);

export function renderDiff(diff, { styler: c } = { styler: null }) {
  const s = c ?? { bold: (x) => x, dim: (x) => x, red: (x) => x, yellow: (x) => x, green: (x) => x, cyan: (x) => x };
  const out = [];
  const line = (t = '') => out.push(t);

  const sev = (severity, text) =>
    severity === 'will-break' ? s.red(text) : severity === 'may-break' ? s.yellow(text) : s.dim(text);

  line();
  line(s.bold('parity diff'));
  line(bar('='));
  line(`  before  ${diff.before.target ?? '(unknown)'}   ${diff.before.findings} findings`);
  line(`  after   ${diff.after.target ?? '(unknown)'}   ${diff.after.findings} findings`);
  line();

  // 1. Comparability, first, because it qualifies everything below.
  if (!diff.comparable.ok) {
    line(s.yellow('  These two runs are not directly comparable:'));
    for (const r of diff.comparable.reasons) line(s.yellow(`    - ${r}`));
    line();
    line(s.dim('  Differences below may be artefacts of that rather than real changes.'));
    line(s.dim('  Re-run both against the same routes, with the same --flow, before drawing conclusions.'));
    line();
  }

  // 2. What localhost hid.
  if (diff.appeared.length) {
    line(s.bold('what localhost was hiding'));
    line(bar('-'));
    line(s.dim('  Present on the real origin, absent locally. Nothing else here is news.'));
    line();
    for (const { finding } of diff.appeared) {
      line(`  ${sev(finding.severity, finding.severity.padEnd(11))} ${finding.title}`);
      line(s.dim(`              ${finding.id}`));
    }
    line();
  }

  // 3. Predictions that came true.
  if (diff.confirmed.length) {
    line(s.bold('predicted, then observed'));
    line(bar('-'));
    line(s.dim('  Derived from a header locally; the browser actually refused it on the real origin.'));
    line();
    for (const { prediction, observation } of diff.confirmed) {
      line(`  ${s.green('confirmed')}   ${prediction.title}`);
      line(s.dim(`              predicted by ${prediction.id}`));
      line(s.dim(`              observed as  ${observation.id}`));
    }
    line();
  }

  // 4. Still broken.
  if (diff.persisted.length) {
    line(s.bold('unchanged by the move to HTTPS'));
    line(bar('-'));
    for (const { finding, severityChanged } of diff.persisted) {
      const note = severityChanged ? s.yellow(`   (${severityChanged.from} -> ${severityChanged.to})`) : '';
      line(`  ${sev(finding.severity, finding.severity.padEnd(11))} ${finding.title}${note}`);
    }
    line();
  }

  // 5. Gone, and whether that means anything.
  if (diff.unexplained.length) {
    line(s.bold('gone, with no observation to explain it'));
    line(bar('-'));
    line(s.dim('  Either the move fixed it, or this run did not reach the code that produced it.'));
    line(s.dim('  Worth checking before believing: a finding can vanish because nothing looked.'));
    line();
    for (const { finding } of diff.unexplained) {
      line(`  ${sev(finding.severity, finding.severity.padEnd(11))} ${finding.title}`);
      line(s.dim(`              ${finding.id}`));
    }
    line();
  }

  if (diff.expected.length) {
    line(s.bold('gone, but they were never about your application'));
    line(bar('-'));
    for (const { finding, because } of diff.expected) {
      line(`  ${s.dim(finding.id)}`);
      line(s.dim(`      ${because}`));
    }
    line();
  }

  line(bar('='));
  const cs = diff.counts;
  line(
    `  ${cs.confirmed} confirmed   ${cs.appeared} newly visible   ${cs.persisted} unchanged   ` +
      `${cs.unexplained} unexplained   ${cs.expected} not applicable`,
  );

  if (cs.appeared === 0 && cs.confirmed === 0 && diff.comparable.ok) {
    line();
    line(s.dim('  Nothing appeared on the real origin that localhost did not already show.'));
    line(s.dim('  That is the good outcome, and it is only as broad as what these two runs exercised.'));
  }
  line();

  return out.join('\n');
}

/**
 * What the exit code should be.
 *
 * A difference the developer has not seen before is the thing worth failing a
 * pipeline over. Confirmations are not: the analyzer already reported those,
 * and a build should not break twice for one defect.
 */
export function diffExitCode(diff, { failOn = 'will-break' } = {}) {
  const order = ['info', 'may-break', 'will-break'];
  const threshold = order.indexOf(failOn);
  if (threshold < 0) return 0;
  const reached = diff.appeared.some(({ finding }) => order.indexOf(finding.severity) >= threshold);
  return reached ? 1 : 0;
}
