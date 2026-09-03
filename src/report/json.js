/**
 * JSON output.
 *
 * The document is the API. It carries `schemaVersion`, and that number only
 * changes when a field is removed or retyped -- adding fields is not
 * breaking. CI consumers should assert on `schemaVersion` and on `counts`,
 * not on array ordering.
 */

/** @param {object} result @param {{pretty?: boolean}} [opts] */
export function renderJson(result, opts = {}) {
  return opts.pretty === false ? JSON.stringify(result) : JSON.stringify(result, null, 2);
}

/**
 * A deliberately small summary for GitHub Action outputs and job summaries,
 * where the full document is too much.
 */
export function renderSummary(result) {
  return {
    schemaVersion: result.schemaVersion,
    url: result.target.url,
    counts: result.counts,
    topFindings: result.findings
      .filter((f) => f.severity !== 'info')
      .slice(0, 10)
      .map((f) => ({ id: f.id, severity: f.severity, title: f.title })),
  };
}

/** GitHub Actions job-summary markdown. */
export function renderMarkdown(result) {
  const c = result.counts;
  const lines = [];
  lines.push(`## notlocalhost \`${result.target.url}\``);
  lines.push('');
  lines.push(`| | Will break | May break | Info |`);
  lines.push(`|---|---|---|---|`);
  lines.push(`| findings | **${c['will-break']}** | ${c['may-break']} | ${c.info} |`);
  lines.push('');

  if (!result.coverage.flow) {
    lines.push(
      '> Only the logged-out page was exercised. The cookies that matter usually appear after login &mdash; pass `--flow`.',
    );
    lines.push('');
  }

  for (const severity of ['will-break', 'may-break']) {
    const group = result.findings.filter((f) => f.severity === severity);
    if (!group.length) continue;
    lines.push(`### ${severity === 'will-break' ? 'Will break' : 'May break'}`);
    lines.push('');
    for (const f of group) {
      lines.push(`- **${escapeMd(f.title)}** \`${f.id}\``);
      const first = String(f.summary).split('\n\n')[0];
      if (first) lines.push(`  ${escapeMd(first)}`);
    }
    lines.push('');
  }

  lines.push('<details><summary>What this does not tell you</summary>');
  lines.push('');
  for (const l of result.limitations) lines.push(`- ${escapeMd(l)}`);
  lines.push('');
  lines.push('</details>');
  return lines.join('\n');
}

function escapeMd(s) {
  return String(s).replace(/([|`*_[\]])/g, '\\$1');
}
