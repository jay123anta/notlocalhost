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
    url: null,
    flow: null,
    json: undefined,
    html: './notlocalhost-report.html',
    markdown: null,
    failOn: 'none',
    domain: 'example.com',
    crossSite: false,
    map: {},
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
        case '--map': {
          const v = need(i, '--map');
          i++;
          const eq = v.indexOf('=');
          if (eq < 1) throw new UsageError(`--map expects local=host, got "${v}"`);
          options.map[v.slice(0, eq).trim().toLowerCase()] = v.slice(eq + 1).trim().toLowerCase();
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
        default:
          if (arg.startsWith('-')) throw new UsageError(`unknown option "${arg}"`);
          if (options.url) throw new UsageError(`unexpected second target "${arg}"`);
          options.url = arg;
      }
    }
  } catch (err) {
    if (err instanceof UsageError) return { ok: false, error: err.message };
    throw err;
  }

  if (options.help || options.version || options.listBrowsers) return { ok: true, options };

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
 * The timer is unref'd so it never keeps a healthy run alive a moment longer
 * than it needs.
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
    if (typeof timer.unref === 'function') timer.unref();
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
