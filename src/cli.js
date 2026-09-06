/**
 * CLI. Argument parsing is hand-rolled: one runtime dependency is the promise,
 * and an options parser is not where to spend it.
 */
import { writeFileSync, mkdirSync } from 'node:fs';
import { dirname, resolve, isAbsolute } from 'node:path';
import { pathToFileURL } from 'node:url';
import { analyze, shouldFail } from './analyze.js';
import { renderTerminal, renderReportPointer, createStyler } from './report/terminal.js';
import { renderHtml } from './report/html.js';
import { renderJson, renderMarkdown } from './report/json.js';
import { listBrowsers } from './browser/locate.js';
import { EXIT, EXIT_DESCRIPTIONS } from './exit-codes.js';
import { VERSION, SCHEMA_VERSION } from './version.js';

const SEVERITY_VALUES = ['will-break', 'may-break', 'info', 'none'];

/**
 * Harness subcommands.
 *
 * `notlocalhost <url>` is shipped surface: it is the first line of the README
 * and is sitting in other people's scripts. Adding subcommands must not be able
 * to change what it means, so the dispatch rule is deliberately narrow:
 *
 *   A subcommand is only recognised when the first non-flag argument is
 *   EXACTLY one of these words. Anything that parses as a URL is a target, and
 *   anything containing a scheme, a slash or a dot cannot reach this list.
 *
 * `notlocalhost doctor` was a usage error before this existed, so nothing that
 * previously worked changes meaning. Only something that previously failed
 * starts succeeding.
 */
export const SUBCOMMANDS = ['init', 'up', 'down', 'doctor', 'diff'];

const HELP = `
notlocalhost ${VERSION}
  Your localhost is lying to you. This tells you exactly how.

USAGE
  notlocalhost <url> [options]

  Point it at a dev server you already have running. It loads the page in a
  browser you already have installed, watches what happens, and reports what
  changes when the same app is served from a real HTTPS origin on a real domain.

OPTIONS
  --flow <path>        A Playwright script that logs in. The cookies that matter
                       appear after authentication, so without this you are only
                       analyzing the logged-out page. See FLOW SCRIPTS below.
  --json [path]        Emit the schema-versioned JSON document. With no path it
                       goes to stdout and the terminal report is suppressed.
  --html <path>        Where to write the single-file HTML report.
                       Default: ./notlocalhost-report.html  (--no-html to skip)
  --markdown <path>    Write a GitHub-flavoured markdown summary.
  --fail-on <level>    Exit 1 when findings reach this severity.
                       will-break | may-break | info | none   (default: none)

  --domain <domain>    The registrable domain to assume for deployment.
                       Default: example.com
  --cross-site         Assume each local port becomes a separate site rather
                       than a subdomain of one site.
  --map <local=host>   Pin one local origin to a real hostname. Repeatable.
                       e.g. --map localhost:3000=app.acme.com
  --map </path=host>   Model a path prefix that becomes its own host in
                       production, which is what a dev-server proxy hides.
                       e.g. --map /api=api.acme.com

  --timeout <ms>       Navigation timeout. Default: 30000
  --flow-timeout <ms>  Budget for the --flow script. Default: 60000
  --settle <ms>        Quiet time after load before collecting. Default: 1200
  --no-port-scan       Skip probing for other loopback dev servers.
  --headed             Show the browser. Useful when a --flow script misbehaves.
  --browser-path <p>   Use this browser executable.
  --channel <name>     chrome | chromium | msedge | chrome-beta | ...
  --list-browsers      Print the browsers found on this machine and exit.

  --verbose            Show info findings and full evidence in the terminal.
  --quiet              Suppress the terminal report. Exit code and files only.
  --version            Print the version.
  --help               This.

EXIT CODES
${EXIT_DESCRIPTIONS.map(([code, name, desc]) => `  ${String(code).padEnd(4)} ${name.padEnd(13)} ${desc}`).join('\n')}

FLOW SCRIPTS
  A flow script default-exports an async function and receives a live
  Playwright page with instrumentation already installed:

    // login.js
    export default async ({ page }) => {
      await page.fill('#email', 'dev@example.com');
      await page.fill('#password', 'password');
      await page.click('button[type=submit]');
      await page.waitForURL('**/dashboard');
    };

    notlocalhost http://localhost:3000 --flow ./login.js

  Everything the flow touches is analyzed: the login POST, the redirect chain,
  the session cookie, and every request the authenticated page makes.

EXAMPLES
  notlocalhost http://localhost:3000
  notlocalhost http://localhost:3000 --flow ./login.js
  notlocalhost http://localhost:3000 --json > findings.json
  notlocalhost http://localhost:3000 --fail-on will-break --quiet
  notlocalhost http://localhost:5173 --map localhost:5173=app.acme.com --map localhost:8000=api.acme.com

  No account. No network calls. No telemetry. Nothing is installed, no
  certificate is trusted, no DNS is touched, and nothing is written outside the
  paths you name.
`;

/**
 * @param {string[]} argv
 * @returns {{ ok: true, options: object } | { ok: false, error: string }}
 */
export function parseArgs(argv) {
  const options = {
    command: 'analyze',
    args: [],
    url: null,
    flow: null,
    json: undefined,
    html: './notlocalhost-report.html',
    markdown: null,
    failOn: 'none',
    domain: 'example.com',
    crossSite: false,
    map: {},
    mapPaths: {},
    timeout: 30_000,
    flowTimeout: 60_000,
    settle: 1200,
    noPortScan: false,
    headed: false,
    browserPath: null,
    channel: null,
    verbose: false,
    quiet: false,
    help: false,
    version: false,
    listBrowsers: false,
    yes: false,
    force: false,
    purge: false,
    tier: 'localhost',
    httpPort: 80,
    httpsPort: 443,
  };

  const need = (i, flag) => {
    if (i + 1 >= argv.length || argv[i + 1].startsWith('--')) throw new UsageError(`${flag} needs a value`);
    return argv[i + 1];
  };
  const int = (v, flag) => {
    const n = Number(v);
    if (!Number.isFinite(n) || n < 0) throw new UsageError(`${flag} needs a non-negative number, got "${v}"`);
    return n;
  };

  try {
    for (let i = 0; i < argv.length; i++) {
      const arg = argv[i];
      switch (arg) {
        case '--help':
        case '-h':
          options.help = true;
          break;
        case '--version':
        case '-v':
          options.version = true;
          break;
        case '--list-browsers':
          options.listBrowsers = true;
          break;
        case '--flow':
          options.flow = need(i, '--flow');
          i++;
          break;
        case '--json':
          // Optional value: `--json` alone means stdout.
          if (i + 1 < argv.length && !argv[i + 1].startsWith('--')) {
            options.json = argv[++i];
          } else {
            options.json = true;
          }
          break;
        case '--html':
          options.html = need(i, '--html');
          i++;
          break;
        case '--no-html':
          options.html = null;
          break;
        case '--markdown':
          options.markdown = need(i, '--markdown');
          i++;
          break;
        case '--fail-on': {
          const v = need(i, '--fail-on');
          i++;
          if (!SEVERITY_VALUES.includes(v)) {
            throw new UsageError(`--fail-on must be one of ${SEVERITY_VALUES.join(', ')}, got "${v}"`);
          }
          options.failOn = v;
          break;
        }
        case '--domain':
          options.domain = need(i, '--domain');
          i++;
          break;
        case '--cross-site':
          options.crossSite = true;
          break;
        case '--yes':
        case '-y':
          options.yes = true;
          break;
        case '--force':
          options.force = true;
          break;
        case '--purge':
          options.purge = true;
          break;
        case '--http-port':
          options.httpPort = int(need(i, '--http-port'), '--http-port');
          i++;
          break;
        case '--https-port':
          options.httpsPort = int(need(i, '--https-port'), '--https-port');
          i++;
          break;
        case '--tier': {
          const v = need(i, '--tier');
          i++;
          if (!['localhost', 'test'].includes(v)) {
            throw new UsageError(`--tier must be "localhost" or "test", got "${v}"`);
          }
          options.tier = v;
          break;
        }
        case '--map': {
          const v = need(i, '--map');
          i++;
          const eq = v.indexOf('=');
          if (eq < 1) throw new UsageError(`--map expects local=host or /path=host, got "${v}"`);
          const from = v.slice(0, eq).trim();
          const to = v.slice(eq + 1).trim().toLowerCase();

          // Git Bash and MSYS rewrite a leading-slash argument into a Windows
          // path, so `--map /api=api.acme.com` silently arrives as
          // `C:/Program Files/Git/api=api.acme.com`. Left alone that produces a
          // confidently wrong analysis, which is worse than an error.
          if (/^[A-Za-z]:[\\/]/.test(from)) {
            throw new UsageError(
              `--map received "${from}", which is a filesystem path, not a hostname or a URL path.\n` +
                '  Your shell rewrote a leading slash. Git Bash and MSYS do this to any argument\n' +
                '  that starts with "/". Use one of:\n' +
                `      --map //${from.split(/[\\/]/).pop()}=${to}\n` +
                `      MSYS_NO_PATHCONV=1 notlocalhost ...\n` +
                '  or run the command from PowerShell or cmd, where it is passed through unchanged.',
            );
          }
          // A leading slash means "this path prefix becomes its own host",
          // which is how a dev-server proxy hiding a production split is
          // modelled. Anything else maps one local origin to one hostname.
          if (from.startsWith('/')) options.mapPaths[from] = to;
          else options.map[from.toLowerCase()] = to;
          break;
        }
        case '--timeout':
          options.timeout = int(need(i, '--timeout'), '--timeout');
          i++;
          break;
        case '--flow-timeout':
          options.flowTimeout = int(need(i, '--flow-timeout'), '--flow-timeout');
          i++;
          break;
        case '--settle':
          options.settle = int(need(i, '--settle'), '--settle');
          i++;
          break;
        case '--no-port-scan':
          options.noPortScan = true;
          break;
        case '--headed':
          options.headed = true;
          break;
        case '--browser-path':
          options.browserPath = need(i, '--browser-path');
          i++;
          break;
        case '--channel':
          options.channel = need(i, '--channel');
          i++;
          break;
        case '--verbose':
          options.verbose = true;
          break;
        case '--quiet':
          options.quiet = true;
          break;
        default: {
          if (arg.startsWith('-')) throw new UsageError(`unknown option "${arg}"`);

          // The very first positional argument, and only that one, may name a
          // subcommand. A URL always wins: none of the subcommand words can
          // contain a scheme, a slash or a dot, so no target can be captured.
          const isFirstPositional = options.url === null && options.command === 'analyze';
          if (isFirstPositional && SUBCOMMANDS.includes(arg)) {
            options.command = arg;
            break;
          }

          // Once a subcommand is chosen, further positionals belong to it.
          // `analyze` keeps its old behaviour exactly: one target, and a
          // second one is still an error, because that is shipped surface.
          if (options.command !== 'analyze') {
            options.args.push(arg);
            break;
          }

          if (options.url) throw new UsageError(`unexpected second target "${arg}"`);
          options.url = arg;
        }
      }
    }
  } catch (err) {
    if (err instanceof UsageError) return { ok: false, error: err.message };
    throw err;
  }

  if (options.help || options.version || options.listBrowsers) return { ok: true, options };

  // A subcommand operates on the project directory, not on a URL.
  if (options.command !== 'analyze') {
    // `diff` is the one subcommand that takes arguments. For every other, a
    // positional is a mistake and must produce the message it always has --
    // collecting them silently turned a clear usage error into a no-op.
    if (options.url || (options.command !== 'diff' && options.args.length)) {
      return { ok: false, error: `"${options.command}" does not take a URL. It works on the project in this directory.` };
    }
    if (options.command === 'diff' && options.args.length !== 2) {
      return {
        ok: false,
        error: [
          'diff needs two reports: the one from plain HTTP and the one from real HTTPS.',
          '',
          '  notlocalhost http://localhost:3000 --json before.json',
          '  notlocalhost up --yes',
          '  notlocalhost https://app.myproject.localhost --json after.json',
          '  notlocalhost diff before.json after.json',
        ].join('\n'),
      };
    }
    return { ok: true, options };
  }

  if (!options.url) return { ok: false, error: 'no target URL given' };

  let parsed;
  try {
    parsed = new URL(options.url);
  } catch {
    return { ok: false, error: `"${options.url}" is not a URL. Try http://localhost:3000` };
  }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    return { ok: false, error: `only http:// and https:// targets are supported, got "${parsed.protocol}"` };
  }

  return { ok: true, options };
}

class UsageError extends Error {}

/**
 * @param {string[]} argv
 * @param {{stdout?: NodeJS.WriteStream, stderr?: NodeJS.WriteStream}} [io]
 * @returns {Promise<number>} exit code
 */
export async function run(argv, io = {}) {
  const stdout = io.stdout ?? process.stdout;
  const stderr = io.stderr ?? process.stderr;
  const c = createStyler(stderr);

  const parsed = parseArgs(argv);
  if (!parsed.ok) {
    stderr.write(`${c.red('error')}: ${parsed.error}\n\nRun ${c.bold('notlocalhost --help')} for usage.\n`);
    return EXIT.USAGE;
  }

  const o = parsed.options;

  if (o.help) {
    stdout.write(`${HELP}\n`);
    return EXIT.CLEAN;
  }
  if (o.version) {
    stdout.write(`${VERSION} (schema ${SCHEMA_VERSION})\n`);
    return EXIT.CLEAN;
  }
  if (o.listBrowsers) {
    const found = listBrowsers();
    if (!found.length) {
      stdout.write('No Chrome, Chromium or Edge found.\n');
      return EXIT.TOOL_FAILURE;
    }
    for (const b of found) stdout.write(`${b.channel.padEnd(12)} ${b.name.padEnd(24)} ${b.path}\n`);
    return EXIT.CLEAN;
  }

  // Harness subcommands operate on the project directory rather than a URL.
  // Loaded on demand so that `notlocalhost <url>` -- the shipped path -- pays
  // nothing for code it never touches.
  // The parity diff reads two documents and writes one. It needs no browser
  // and no project, so it is handled before the harness commands, which need
  // both.
  if (o.command === 'diff') {
    try {
      const { readFileSync } = await import('node:fs');
      const { compareReports } = await import('./diff/compare.js');
      const { renderDiff, diffExitCode } = await import('./diff/terminal.js');

      const load = (p) => {
        let text;
        try {
          text = readFileSync(p, 'utf8');
        } catch {
          throw Object.assign(new Error(`Cannot read ${p}`), { code: 'USAGE' });
        }
        try {
          return JSON.parse(text);
        } catch (err) {
          throw Object.assign(new Error(`${p} is not valid JSON: ${err.message}`), { code: 'USAGE' });
        }
      };

      const [beforePath, afterPath] = o.args;
      const diff = compareReports(load(beforePath), load(afterPath));

      if (o.json === true) {
        stdout.write(`${JSON.stringify(diff, null, 2)}\n`);
      } else {
        if (o.json) {
          const { writeFileSync } = await import('node:fs');
          writeFileSync(o.json, `${JSON.stringify(diff, null, 2)}\n`);
        }
        if (!o.quiet) {
          stdout.write(`${renderDiff(diff, { styler: c })}
`);
          // Under --quiet the analyzer prints nothing at all, and this has
          // to match: a flag meaning one thing for the main command and
          // something slightly different for a subcommand is a flag nobody
          // can rely on in a script.
          if (o.json) stdout.write(`  json    ${o.json}
`);
        }
      }
      return diffExitCode(diff, { failOn: o.failOn ?? 'will-break' });
    } catch (err) {
      if (err.code === 'USAGE') {
        stderr.write(`${c.red('error')}: ${err.message}\n`);
        return EXIT.USAGE;
      }
      return reportFailure(err, stderr, c, o);
    }
  }

  if (o.command !== 'analyze') {
    try {
      const { runHarnessCommand } = await import('./harness/commands.js');
      return await runHarnessCommand(o.command, o, { stdout, stderr, styler: c });
    } catch (err) {
      return reportFailure(err, stderr, c, o);
    }
  }

  // JSON to stdout implies a quiet terminal, or the document is unparseable.
  const jsonToStdout = o.json === true;
  const quiet = o.quiet || jsonToStdout;
  const log = quiet ? () => {} : (m) => stderr.write(`${c.dim(`  ${m}`)}\n`);

  let result;
  try {
    if (!quiet) stderr.write(`${c.dim(`  analyzing ${o.url} ...`)}\n`);
    result = await withWatchdog(
      o.timeout + o.flowTimeout + 120_000,
      analyze({
      url: o.url,
      flow: o.flow,
      domain: o.domain,
      crossSite: o.crossSite,
      map: o.map,
        mapPaths: o.mapPaths,
      timeout: o.timeout,
      flowTimeout: o.flowTimeout,
      settle: o.settle,
      headed: o.headed,
      noPortScan: o.noPortScan,
      browserPath: o.browserPath,
        channel: o.channel,
        log,
      }),
    );
  } catch (err) {
    return reportFailure(err, stderr, c, o);
  }

  // ------------------------------------------------------------- outputs --
  const written = {};
  try {
    if (o.html) {
      const path = resolve(process.cwd(), o.html);
      mkdirSync(dirname(path), { recursive: true });
      writeFileSync(path, renderHtml(result), 'utf8');
      written.html = path;
    }
    if (typeof o.json === 'string') {
      const path = resolve(process.cwd(), o.json);
      mkdirSync(dirname(path), { recursive: true });
      writeFileSync(path, `${renderJson(result)}\n`, 'utf8');
      written.json = path;
    }
    if (o.markdown) {
      const path = resolve(process.cwd(), o.markdown);
      mkdirSync(dirname(path), { recursive: true });
      writeFileSync(path, `${renderMarkdown(result)}\n`, 'utf8');
      written.markdown = path;
    }
  } catch (err) {
    stderr.write(`${c.red('error')}: could not write a report file: ${err.message}\n`);
    return EXIT.TOOL_FAILURE;
  }

  if (jsonToStdout) {
    stdout.write(`${renderJson(result)}\n`);
  } else if (!quiet) {
    stdout.write(`${renderTerminal(result, { verbose: o.verbose, stream: stdout })}\n`);
    const pointer = renderReportPointer(
      written.html ? fileLink(written.html) : null,
      written.json ?? written.markdown ?? null,
    );
    if (pointer) stdout.write(`${pointer}\n`);
  }

  return shouldFail(result, o.failOn) ? EXIT.FINDINGS : EXIT.CLEAN;
}

/**
 * Never let the process hang, and never let it give up silently.
 *
 * A promise that never settles while the event loop drains makes Node exit
 * with code 13 and no output at all -- no error, no report, nothing to act on.
 * That is the worst possible failure for a CLI, so the whole analysis runs
 * under a deadline that turns it into a documented exit code and a message.
 *
 * The timer must NOT be unref'd. An unref'd timer does not hold the event loop
 * open, so in exactly the case this exists for -- an unsettled promise and an
 * otherwise empty loop -- Node would exit 13 before the deadline ever fired.
 * Clearing it in `finally` is what stops it delaying a healthy run.
 *
 * @template T
 * @param {number} ms
 * @param {Promise<T>} promise
 * @returns {Promise<T>}
 */
async function withWatchdog(ms, promise) {
  let timer;
  const deadline = new Promise((_, reject) => {
    timer = setTimeout(() => {
      const err = new Error(
        `The analysis did not finish within ${Math.round(ms / 1000)}s and was stopped.\n\n` +
          'This is a bug in notlocalhost, not in your application: a run should either\n' +
          'produce findings or fail with a reason. Please report it, with the output of\n' +
          '`notlocalhost --list-browsers` and your platform.',
      );
      err.code = 'WATCHDOG';
      reject(err);
    }, ms);
  });

  try {
    return await Promise.race([promise, deadline]);
  } finally {
    clearTimeout(timer);
  }
}

function reportFailure(err, stderr, c, options) {
  if (err.code === 'WATCHDOG') {
    stderr.write(`\n${c.red('timed out')}: ${err.message}\n`);
    return EXIT.TOOL_FAILURE;
  }
  if (err.code === 'UNREACHABLE') {
    stderr.write(`\n${c.red('unreachable')}: ${err.message}\n`);
    stderr.write(
      `\n  Check that the dev server is running and that the URL is right.\n` +
        `  A server bound to 127.0.0.1 will not answer on a LAN address, and vice versa.\n`,
    );
    return EXIT.UNREACHABLE;
  }
  if (err.code === 'NO_BROWSER') {
    stderr.write(`\n${c.red('no browser')}: ${err.message}\n`);
    if (err.hint) stderr.write(`\n${err.hint}\n`);
    return EXIT.TOOL_FAILURE;
  }
  if (err.code === 'BROWSER_UNRESPONSIVE') {
    stderr.write(`\n${c.red('browser stopped responding')}: ${err.message}\n`);
    stderr.write(`\n  The step that hung was: ${c.bold(err.step)}\n`);
    return EXIT.TOOL_FAILURE;
  }
  if (err.code === 'BROWSER_LAUNCH') {
    // The diagnosis is the message; the forty lines of Chrome stack frames sit
    // behind --verbose, because leading with them helps nobody.
    stderr.write(`\n${c.red('browser will not start')}: ${err.message}\n`);
    if (options.verbose && err.browserLog) {
      stderr.write(`\n${c.dim('--- full browser log ---')}\n${err.browserLog}\n`);
    } else {
      stderr.write(`\n  Re-run with --verbose for the full browser log.\n`);
    }
    return EXIT.TOOL_FAILURE;
  }
  if (err.code === 'USAGE') {
    stderr.write(`\n${c.red('error')}: ${err.message}\n`);
    return EXIT.USAGE;
  }
  stderr.write(`\n${c.red('tool failure')}: ${err.message}\n`);
  if (options.verbose && err.stack) stderr.write(`\n${err.stack}\n`);
  else stderr.write(`\n  Re-run with --verbose for a stack trace, and please open an issue.\n`);
  return EXIT.TOOL_FAILURE;
}

/** A clickable file:// URL, which most terminals will open on click. */
function fileLink(path) {
  const abs = isAbsolute(path) ? path : resolve(process.cwd(), path);
  return `${abs}  (${pathToFileURL(abs).href})`;
}

export { HELP };
