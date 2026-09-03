/**
 * Terminal output.
 *
 * Hand-rolled rather than pulled from a dependency, because the whole pitch is
 * one runtime dependency and a colour library is not worth breaking it for.
 * Respects NO_COLOR, FORCE_COLOR and non-TTY output.
 */

const SEVERITY_ORDER = ['will-break', 'may-break', 'info'];

const SEVERITY_STYLE = {
  'will-break': { color: 'red', label: 'WILL BREAK' },
  'may-break': { color: 'yellow', label: 'MAY BREAK ' },
  info: { color: 'cyan', label: 'INFO      ' },
};

const CODES = {
  reset: '\u001B[0m',
  bold: '\u001B[1m',
  dim: '\u001B[2m',
  red: '\u001B[31m',
  green: '\u001B[32m',
  yellow: '\u001B[33m',
  blue: '\u001B[34m',
  magenta: '\u001B[35m',
  cyan: '\u001B[36m',
  gray: '\u001B[90m',
};

export function createStyler(stream = process.stdout) {
  const enabled =
    process.env.FORCE_COLOR !== undefined && process.env.FORCE_COLOR !== '0'
      ? true
      : process.env.NO_COLOR !== undefined
        ? false
        : Boolean(stream.isTTY);

  const wrap = (code) => (s) => (enabled ? `${CODES[code]}${s}${CODES.reset}` : String(s));
  return {
    enabled,
    bold: wrap('bold'),
    dim: wrap('dim'),
    red: wrap('red'),
    green: wrap('green'),
    yellow: wrap('yellow'),
    blue: wrap('blue'),
    magenta: wrap('magenta'),
    cyan: wrap('cyan'),
    gray: wrap('gray'),
    color: (name, s) => (enabled && CODES[name] ? `${CODES[name]}${s}${CODES.reset}` : String(s)),
  };
}

/** Unicode box drawing is fine nearly everywhere now, but not in a legacy Windows console. */
function unicodeOk() {
  if (process.platform !== 'win32') return true;
  return Boolean(process.env.WT_SESSION || process.env.TERM_PROGRAM || process.env.ConEmuANSI);
}

const CHARS = unicodeOk()
  ? { h: '─', bullet: '•', arrow: '->', corner: '└' }
  : { h: '-', bullet: '*', arrow: '->', corner: '`' };

export function renderTerminal(result, opts = {}) {
  const { verbose = false, width = detectWidth(), stream = process.stdout } = opts;
  const c = createStyler(stream);
  const lines = [];
  const rule = CHARS.h.repeat(Math.min(width, 78));

  // ------------------------------------------------------------- header --
  lines.push('');
  lines.push(c.bold(`notlocalhost ${result.tool.version}`) + c.dim(`  ${CHARS.bullet}  ${result.target.url}`));
  lines.push(c.dim(rule));

  const t = result.target;
  lines.push(
    c.dim('target      ') +
      `${t.finalUrl}${t.status ? c.dim(`  (HTTP ${t.status})`) : ''}`,
  );
  lines.push(
    c.dim('browser     ') +
      `${result.browser.name ?? 'unknown'} ${result.browser.version ?? ''}`.trim(),
  );
  lines.push(
    c.dim('assuming    ') +
      `deployed as ${c.bold(`https://<subdomain>.${result.deploymentModel.domain}`)}` +
      c.dim(result.deploymentModel.crossSite ? ' (cross-site model)' : ' (same-site subdomain model)'),
  );
  for (const [from, to] of Object.entries(result.deploymentModel.mapping)) {
    lines.push(c.dim(`            ${from}  ${CHARS.arrow}  https://${to}`));
  }

  const cov = result.coverage;
  const flowNote = cov.flow
    ? cov.flow.ok
      ? c.green(`flow ${cov.flow.path} ran`)
      : c.red(`flow ${cov.flow.path} FAILED`)
    : c.yellow('no --flow script: only the logged-out page was exercised');
  lines.push(c.dim('coverage    ') + `${cov.requests} requests, ${cov.cookiesObserved} Set-Cookie, ${formatBytes(cov.bytesScanned)} scanned`);
  lines.push(c.dim('            ') + flowNote);
  lines.push('');

  // ------------------------------------------------------------ verdict --
  const { counts } = result;
  const total = counts['will-break'] + counts['may-break'] + counts.info;

  if (counts['will-break'] === 0 && counts['may-break'] === 0) {
    lines.push(c.green(c.bold('  No will-break or may-break findings in what was exercised.')));
    lines.push(c.dim('  That is not the same as "safe". See the limitations below.'));
  } else {
    const parts = [];
    if (counts['will-break']) parts.push(c.red(c.bold(`${counts['will-break']} will break`)));
    if (counts['may-break']) parts.push(c.yellow(c.bold(`${counts['may-break']} may break`)));
    if (counts.info) parts.push(c.cyan(`${counts.info} info`));
    lines.push('  ' + parts.join(c.dim('  |  ')));
  }
  lines.push('');

  // ----------------------------------------------------------- findings --
  for (const severity of SEVERITY_ORDER) {
    const group = result.findings.filter((f) => f.severity === severity);
    if (!group.length) continue;
    if (severity === 'info' && !verbose) {
      lines.push(
        c.dim(`  ${group.length} info finding${group.length === 1 ? '' : 's'} hidden. Re-run with --verbose, or open the HTML report.`),
      );
      lines.push('');
      continue;
    }

    const style = SEVERITY_STYLE[severity];
    lines.push(c.color(style.color, c.bold(`${style.label} ${CHARS.h.repeat(Math.max(0, Math.min(width, 78) - style.label.length - 1))}`)));
    lines.push('');

    for (const f of group) {
      lines.push(`  ${c.color(style.color, CHARS.bullet)} ${c.bold(f.title)}`);
      lines.push(c.dim(`    ${f.id}`));
      lines.push('');
      for (const para of String(f.summary).split('\n\n')) {
        if (!para.trim()) continue;
        lines.push(...wrapText(para.trim(), width - 6).map((l) => `    ${l}`));
        lines.push('');
      }

      if (f.evidence.length) {
        lines.push(c.dim('    evidence'));
        for (const e of f.evidence.slice(0, verbose ? 50 : 6)) {
          const value = String(e.value).split('\n');
          lines.push(`      ${c.color(style.color, e.label)}${c.dim(':')} ${value[0]}`);
          for (const extra of value.slice(1)) lines.push(c.dim(`        ${extra.trim()}`));
        }
        if (!verbose && f.evidence.length > 6) {
          lines.push(c.dim(`      ... ${f.evidence.length - 6} more (--verbose)`));
        }
        lines.push('');
      }

      if (f.fix.length) {
        lines.push(c.dim('    fix'));
        for (const step of f.fix) {
          lines.push(...wrapText(step, width - 10).map((l, i) => (i === 0 ? `      ${c.green(CHARS.arrow)} ${l}` : `        ${l}`)));
        }
        lines.push('');
      }

      if (f.refs.length && verbose) {
        for (const r of f.refs) lines.push(c.dim(`    ${r.title}  ${r.url}`));
        lines.push('');
      }
    }
  }

  // ----------------------------------------------------------- warnings --
  if (result.warnings.length) {
    lines.push(c.yellow(c.bold('warnings')));
    for (const w of result.warnings) {
      lines.push(...wrapText(w, width - 4).map((l) => `  ${l}`));
    }
    lines.push('');
  }

  // -------------------------------------------------------- limitations --
  lines.push(c.dim(rule));
  lines.push(c.dim('what this does not tell you'));
  for (const lim of result.limitations) {
    lines.push(...wrapText(`${CHARS.bullet} ${lim}`, width - 4).map((l, i) => (i === 0 ? `  ${c.dim(l)}` : `    ${c.dim(l)}`)));
  }
  lines.push('');

  return lines.join('\n');
}

export function renderReportPointer(reportPath, jsonPath) {
  const c = createStyler();
  const out = [];
  if (reportPath) out.push(`  ${c.bold('report')}  ${reportPath}`);
  if (jsonPath) out.push(`  ${c.bold('json')}    ${jsonPath}`);
  if (out.length) out.push('');
  return out.join('\n');
}

function detectWidth() {
  const w = process.stdout.columns || 90;
  return Math.max(60, Math.min(w, 100));
}

function wrapText(text, width) {
  const words = String(text).split(/\s+/);
  const lines = [];
  let line = '';
  for (const word of words) {
    if (!line.length) {
      line = word;
    } else if (line.length + 1 + word.length <= width) {
      line += ` ${word}`;
    } else {
      lines.push(line);
      line = word;
    }
  }
  if (line.length) lines.push(line);
  return lines.length ? lines : [''];
}

function formatBytes(n) {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(0)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}

export const _internal = { wrapText, formatBytes };
