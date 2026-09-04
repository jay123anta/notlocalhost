/**
 * `notlocalhost doctor` — say what is true about this machine, and change
 * nothing.
 *
 * This is the command that matters most in the harness, because it is the one
 * people run when something has already gone wrong. Three properties follow
 * from that:
 *
 *   - It never mutates. Not a file, not a store, not a port. It has to be safe
 *     to run on a machine you are nervous about, which is exactly the machine
 *     it will be run on.
 *   - It never fails to produce a report. A diagnostic that crashes has
 *     diagnosed nothing, so a check that throws becomes a finding of its own.
 *   - Every status that is not "ok" carries a specific remedy. "Certificate
 *     trust failed" helps nobody; "group policy sets ProtectedRoots, and that
 *     cannot be worked around locally" tells someone what to do next.
 */
import { runAllChecks } from './checks.js';
import { findInstalledCaddy, findLocalCaddy } from './caddy.js';
import { readConfig, readState, TIERS } from './config.js';
import { caRootPath, describeCertificate, trustState } from './trust.js';

const STATUS_ORDER = { blocked: 0, 'needs-elevation': 1, 'will-download': 2, failed: 3, ok: 4 };

/**
 * @param {object} [opts]
 * @param {string} [opts.cwd]
 * @returns {Promise<{checks: object[], project: object|null, blocking: object[], summary: string}>}
 */
export async function diagnose(opts = {}) {
  const { cwd = process.cwd() } = opts;

  const checks = await runAllChecks();

  // What this project has asked for, and what has actually been done to the
  // machine on its behalf. Reported separately because they diverge whenever
  // something failed halfway, and that divergence is itself a diagnosis.
  let config = null;
  let configError = null;
  try {
    config = readConfig(cwd);
  } catch (err) {
    configError = err.message;
  }
  const state = readState(cwd);

  if (configError) {
    checks.push({
      id: 'config',
      title: 'Project configuration',
      status: 'blocked',
      detail: configError,
      remedy: ['Delete .notlocalhost/config.json and run `notlocalhost init` again.'],
    });
  }

  // A certificate recorded as installed that is no longer in the store, or one
  // in the store that nothing recorded, both mean the ledger is wrong -- and a
  // wrong ledger is how a machine ends up with something left behind.
  if (state?.caTrusted && state.ca?.fingerprint) {
    const actual = trustState(state.ca.fingerprint);
    checks.push({
      id: 'ca-ledger',
      title: 'Recorded certificate authority',
      status: actual === 'present' ? 'ok' : actual === 'unknown' ? 'failed' : 'blocked',
      detail:
        actual === 'present'
          ? `The CA this project installed is in the trust store (${state.ca.fingerprint.slice(0, 16)}...).`
          : actual === 'unknown'
            ? 'The trust store could not be queried, so it is not possible to say whether the CA this project installed is still there.'
            : 'This project recorded installing a CA, but it is not in the trust store. Something removed it outside notlocalhost.',
      remedy:
        actual === 'present'
          ? []
          : actual === 'unknown'
            ? ['Check the trust store by hand before assuming anything about it.']
            : ['Run `notlocalhost down` to clear the stale record, then `up` again if you still want the harness.'],
      evidence: { fingerprint: state.ca.fingerprint, recordedAt: state.ca.trustedAt, storeSays: actual },
    });
  }

  const caddy = findInstalledCaddy() ?? findLocalCaddy(cwd);
  const blocking = checks.filter((c) => c.status === 'blocked');

  return {
    checks: checks.sort((a, b) => (STATUS_ORDER[a.status] ?? 9) - (STATUS_ORDER[b.status] ?? 9)),
    project: config
      ? {
          project: config.project,
          domain: config.domain,
          tier: config.tier,
          sites: config.sites,
          tierNotes: TIERS[config.tier],
          running: Boolean(state?.running),
          caTrusted: Boolean(state?.caTrusted),
          hostsChanged: Boolean(state?.hosts),
        }
      : null,
    caddy: caddy ? { path: caddy.path, source: caddy.source, version: caddy.version } : null,
    blocking,
    summary: blocking.length
      ? `${blocking.length} blocking issue${blocking.length === 1 ? '' : 's'}: ${blocking.map((b) => b.title).join(', ')}`
      : 'Nothing is blocking a local HTTPS setup on this machine.',
  };
}

/** Human-readable report. Kept separate from the diagnosis so both are testable. */
export function renderDoctor(result, c) {
  const SYMBOL = {
    ok: ['green', 'ok'],
    blocked: ['red', 'blocked'],
    'needs-elevation': ['yellow', 'needs elevation'],
    'will-download': ['cyan', 'will download'],
    failed: ['yellow', 'could not check'],
  };

  const lines = [''];
  lines.push(c.bold('notlocalhost doctor'));
  lines.push(c.dim('  Reporting only. Nothing on this machine is changed by this command.'));
  lines.push('');

  for (const check of result.checks) {
    const [colour, label] = SYMBOL[check.status] ?? ['gray', check.status];
    lines.push(`  ${c.color(colour, `[${label}]`.padEnd(18))}${c.bold(check.title)}`);
    for (const line of wrap(check.detail, 74)) lines.push(`    ${c.dim(line)}`);
    for (const r of check.remedy ?? []) {
      for (const [i, line] of wrap(r, 70).entries()) {
        lines.push(i === 0 ? `      ${c.color(colour, '->')} ${line}` : `         ${line}`);
      }
    }
    lines.push('');
  }

  if (result.caddy) {
    lines.push(`  ${c.dim('caddy')}      ${result.caddy.path} ${c.dim(`(${result.caddy.source})`)}`);
  }

  if (result.project) {
    const p = result.project;
    lines.push(`  ${c.dim('project')}    ${p.project} -> ${p.domain} ${c.dim(`(${p.tier} tier)`)}`);
    for (const s of p.sites) lines.push(`             https://${s.host} ${c.dim('->')} ${s.upstream}`);
    if (p.caTrusted || p.hostsChanged) {
      lines.push(
        `  ${c.dim('changed')}    ${[p.caTrusted && 'certificate authority installed', p.hostsChanged && 'hosts file edited']
          .filter(Boolean)
          .join(', ')}`,
      );
      lines.push(`             ${c.dim('`notlocalhost down` reverses all of it.')}`);
    }
  } else {
    lines.push(`  ${c.dim('project')}    not initialised here. Run ${c.bold('notlocalhost init')} to set one up.`);
  }

  lines.push('');
  lines.push(result.blocking.length ? c.red(`  ${result.summary}`) : c.green(`  ${result.summary}`));
  lines.push('');
  return lines.join('\n');
}

function wrap(text, width) {
  const out = [];
  for (const para of String(text).split('\n')) {
    let line = '';
    for (const word of para.split(/\s+/).filter(Boolean)) {
      if (!line.length) line = word;
      else if (line.length + 1 + word.length <= width) line += ` ${word}`;
      else {
        out.push(line);
        line = word;
      }
    }
    out.push(line);
  }
  return out;
}
