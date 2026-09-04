/**
 * End-to-end smoke test of the published article.
 *
 * Packs the tarball, installs it into a throwaway directory exactly as a user
 * would receive it, starts the fixture app, and drives the whole documented
 * surface: every output format, every exit code, the flow option, the
 * programmatic API and the HTML report.
 *
 * This is deliberately separate from `npm test`. The test suite exercises the
 * source tree; this exercises the artefact, which is what people actually get.
 *
 *   node scripts/smoke.mjs
 */
import { execFileSync, spawn } from 'node:child_process';
import { mkdtempSync, rmSync, readFileSync, existsSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import net from 'node:net';

const ROOT = resolve(new URL('..', import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1'));
const APP_PORT = 39501;
const API_PORT = 39502;
const URL_ = `http://localhost:${APP_PORT}`;

let failures = 0;
let checks = 0;

const pass = (what, detail = '') => {
  checks++;
  console.log(`  ok    ${what}${detail ? `  ${detail}` : ''}`);
};
const fail = (what, detail) => {
  checks++;
  failures++;
  console.log(`  FAIL  ${what}\n        ${detail}`);
};
const check = (what, cond, detail = '') => (cond ? pass(what, detail) : fail(what, detail || 'assertion failed'));
const heading = (t) => console.log(`\n${t}\n${'-'.repeat(t.length)}`);

const WINDOWS = process.platform === 'win32';
const NPM = WINDOWS ? 'npm.cmd' : 'npm';

/**
 * Node 22 on Windows refuses to spawn a .cmd or .bat without a shell, so both
 * npm and the installed CLI shim need one. Arguments are quoted because the
 * shell will otherwise split on spaces in a temp path.
 */
function sh(cmd, args, opts = {}) {
  if (WINDOWS && /\.(cmd|bat)$/i.test(cmd)) {
    const line = [cmd, ...args.map((a) => `"${a}"`)].join(' ');
    return execFileSync(line, { encoding: 'utf8', shell: true, ...opts });
  }
  return execFileSync(cmd, args, { encoding: 'utf8', ...opts });
}

/** Run the installed CLI, returning its exit code and output rather than throwing. */
function cli(workdir, args) {
  const bin = join(workdir, 'node_modules', '.bin', WINDOWS ? 'notlocalhost.cmd' : 'notlocalhost');
  try {
    const stdout = sh(bin, args, { cwd: workdir, stdio: ['ignore', 'pipe', 'pipe'] });
    return { code: 0, stdout, stderr: '' };
  } catch (err) {
    return { code: err.status ?? -1, stdout: err.stdout ?? '', stderr: err.stderr ?? '' };
  }
}

const waitForPort = (port) =>
  new Promise((resolve) => {
    const attempt = (n) => {
      const s = net.connect(port, '127.0.0.1');
      s.once('connect', () => {
        s.destroy();
        resolve(true);
      });
      s.once('error', () => {
        s.destroy();
        if (n <= 0) return resolve(false);
        setTimeout(() => attempt(n - 1), 250);
      });
    };
    attempt(60);
  });

let fixture;
let work;

try {
  heading('pack the artefact');
  const tarball = sh(NPM, ['pack', '--silent'], { cwd: ROOT }).trim().split('\n').pop();
  const tarballPath = join(ROOT, tarball);
  check('npm pack produced a tarball', existsSync(tarballPath), tarball);

  heading('install it the way a user receives it');
  work = mkdtempSync(join(tmpdir(), 'nlh-smoke-'));
  writeFileSync(join(work, 'package.json'), JSON.stringify({ name: 'smoke', private: true }));
  sh(NPM, ['install', '--no-audit', '--no-fund', tarballPath], { cwd: work, stdio: 'ignore' });
  check('the CLI is on the path', existsSync(join(work, 'node_modules', '.bin')), work);

  const version = cli(work, ['--version']);
  check('--version exits 0', version.code === 0, `exit ${version.code}`);
  check('--version reports a schema', /schema \d+/.test(version.stdout), version.stdout.trim());

  heading('start the fixture application');
  fixture = spawn(process.execPath, [
    join(ROOT, 'test/fixtures/lying-app.mjs'),
    '--port', String(APP_PORT),
    '--api-port', String(API_PORT),
    '--quiet',
  ], { stdio: 'ignore' });
  check('fixture is listening', await waitForPort(APP_PORT), `port ${APP_PORT}`);

  heading('the documented commands');

  const plain = cli(work, [URL_, '--no-html', '--fail-on', 'none']);
  check('a plain run exits 0', plain.code === 0, `exit ${plain.code}`);
  check('the terminal report names the tool', /notlocalhost/.test(plain.stdout));
  check('findings are grouped by severity', /WILL BREAK/.test(plain.stdout));
  check('the deployment assumption is stated', /assuming/.test(plain.stdout));
  check('limitations always print', /what this does not tell you/.test(plain.stdout));
  check('a missing flow is called out', /no --flow script/.test(plain.stdout));

  const json = cli(work, [URL_, '--json', '--no-html']);
  check('--json exits 0', json.code === 0, `exit ${json.code}`);
  let doc;
  try {
    doc = JSON.parse(json.stdout);
    pass('--json emits a parseable document on stdout alone');
  } catch (e) {
    fail('--json emits a parseable document on stdout alone', e.message);
  }
  if (doc) {
    check('schemaVersion is 1', doc.schemaVersion === 1, String(doc.schemaVersion));
    check('counts are present', typeof doc.counts?.['will-break'] === 'number');
    check('findings were produced', doc.findings.length > 0, `${doc.findings.length} findings`);
    check('limitations ship inside the document', (doc.limitations ?? []).length >= 4);
    check('the browser is recorded', Boolean(doc.browser?.version), doc.browser?.name);
  }

  const jsonFile = join(work, 'out.json');
  const mdFile = join(work, 'out.md');
  const htmlFile = join(work, 'report.html');
  const files = cli(work, [URL_, '--json', jsonFile, '--markdown', mdFile, '--html', htmlFile, '--quiet']);
  check('writing all three formats exits 0', files.code === 0, `exit ${files.code}`);
  check('the JSON file was written', existsSync(jsonFile));
  check('the markdown file was written', existsSync(mdFile));
  check('the HTML file was written', existsSync(htmlFile));

  if (existsSync(htmlFile)) {
    const html = readFileSync(htmlFile, 'utf8');
    check('the report is a complete document', html.startsWith('<!doctype html>') && html.includes('</html>'));
    check('the report loads no external scripts', !/<script[^>]+src=/.test(html));
    check('the report loads no external stylesheets', !/<link\b/.test(html));
    check('the report is under 2 MB', html.length < 2 * 1024 * 1024, `${(html.length / 1024).toFixed(0)} KB`);
    check('the claim is on the page', html.includes('Your localhost is lying to you'));
  }
  if (existsSync(mdFile)) {
    const md = readFileSync(mdFile, 'utf8');
    check('markdown has the counts table', /\| findings \|/.test(md));
  }

  heading('the --flow option');
  const flowPath = join(work, 'flow.mjs');
  writeFileSync(
    flowPath,
    `export default async ({ page }) => {
       await page.fill('#email', 'dev@example.com');
       await page.fill('#password', 'hunter2');
       await page.click('#login button[type=submit]');
       await page.waitForURL('**/dashboard');
     };`,
  );
  const withFlow = cli(work, [URL_, '--flow', flowPath, '--json', '--no-html']);
  check('a flow run exits 0', withFlow.code === 0, `exit ${withFlow.code}`);
  let flowDoc;
  try {
    flowDoc = JSON.parse(withFlow.stdout);
  } catch {
    /* reported below */
  }
  check('the flow is recorded as having run', flowDoc?.coverage?.flow?.ok === true);
  if (flowDoc && doc) {
    const before = doc.findings.find((f) => f.id === 'cookie.inventory')?.evidence.map((e) => e.label) ?? [];
    const after = flowDoc.findings.find((f) => f.id === 'cookie.inventory')?.evidence.map((e) => e.label) ?? [];
    const revealed = after.filter((c) => !before.includes(c));
    check('the flow reveals post-login cookies', revealed.length > 0, revealed.join(', '));
  }

  heading('exit codes, exactly as documented');
  const cases = [
    ['0 clean', [URL_, '--no-html', '--quiet', '--fail-on', 'none'], 0],
    ['1 findings at the threshold', [URL_, '--no-html', '--quiet', '--fail-on', 'will-break'], 1],
    ['2 target unreachable', ['http://127.0.0.1:39599', '--no-html', '--timeout', '4000'], 2],
    ['64 usage error', ['--fail-on', 'nonsense'], 64],
    ['0 for --help', ['--help'], 0],
  ];
  for (const [label, args, want] of cases) {
    const r = cli(work, args);
    check(`exit ${label}`, r.code === want, `got ${r.code}, wanted ${want}`);
  }

  heading('the process never exits silently');
  const hang = cli(work, [URL_, '--no-html', '--quiet', '--timeout', '1', '--flow-timeout', '1']);
  check('never Node exit 13', hang.code !== 13, `exit ${hang.code}`);
  check('a failure always says something', hang.code === 0 || (hang.stderr + hang.stdout).trim().length > 0);

  heading('the programmatic API');
  const apiScript = join(work, 'api.mjs');
  writeFileSync(
    apiScript,
    `import { analyze, renderJson, EXIT, SCHEMA_VERSION } from 'notlocalhost';
     const r = await analyze({ url: ${JSON.stringify(URL_)}, noPortScan: true });
     console.log(JSON.stringify({ schema: r.schemaVersion, findings: r.findings.length, exitClean: EXIT.CLEAN, SCHEMA_VERSION }));`,
  );
  try {
    const out = sh(process.execPath, [apiScript], { cwd: work });
    const api = JSON.parse(out.trim().split('\n').pop());
    check('analyze() is importable and returns a document', api.schema === 1 && api.findings > 0, JSON.stringify(api));
  } catch (e) {
    fail('analyze() is importable and returns a document', String(e.message).split('\n')[0]);
  }

  heading('promises made in the README');
  const pkg = JSON.parse(readFileSync(join(work, 'node_modules/notlocalhost/package.json'), 'utf8'));
  check('exactly one runtime dependency', Object.keys(pkg.dependencies).length === 1, Object.keys(pkg.dependencies).join(', '));
  check('engines floor matches playwright-core', pkg.engines.node.includes('20'), pkg.engines.node);
  const files2 = sh(NPM, ['pack', '--dry-run', '--json'], { cwd: ROOT });
  const meta = JSON.parse(files2)[0];
  check('package stays small', meta.size < 500_000, `${(meta.size / 1024).toFixed(0)} KB packed`);
  check('no telemetry in the shipped source', !/sendBeacon\(\s*['"`]https?:/.test(
    readFileSync(join(work, 'node_modules/notlocalhost/src/analyze.js'), 'utf8'),
  ));

  rmSync(tarballPath, { force: true });
} catch (err) {
  failures++;
  console.error(`\nsmoke run threw: ${err?.stack ?? err}`);
} finally {
  if (fixture) fixture.kill();
  if (work) rmSync(work, { recursive: true, force: true });
}

heading('result');
console.log(`  ${checks - failures}/${checks} checks passed`);
if (failures) {
  console.log(`\n  ${failures} FAILED - do not publish.`);
  process.exitCode = 1;
} else {
  console.log('\n  The packed artefact works end to end.');
}
