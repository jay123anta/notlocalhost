/**
 * The published CLI contract, pinned.
 *
 * Version 0.1.0 is on npm. Anything a user could reasonably have put in a
 * script or a CI pipeline is now a promise, and adding harness subcommands
 * touches the one thing most likely to break it: argument parsing.
 *
 * So this suite locks the shipped surface before the parser changes. Every
 * case below is either documented in the README, printed in --help, or an
 * obvious thing someone would type. If one of these changes meaning, the
 * package broke, regardless of how good the reason felt at the time.
 *
 * These assert on *parsing and exit codes*, not on findings, because findings
 * legitimately improve between versions. The contract is the interface.
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import { parseArgs, run } from '../src/cli.js';
import { EXIT } from '../src/exit-codes.js';

const sink = () => {
  const chunks = [];
  return {
    write: (s) => chunks.push(s),
    get text() {
      return chunks.join('');
    },
    isTTY: false,
    columns: 90,
  };
};

describe('shipped contract: a bare URL is still a bare URL', () => {
  // The single most important line in the README. If this changes, every
  // reader of the front page is wrong.
  for (const url of [
    'http://localhost:3000',
    'http://localhost:5173',
    'https://localhost:8443',
    'http://127.0.0.1:8000',
    'http://localhost:3000/admin/login/',
    'http://app.localhost:3000',
  ]) {
    test(`accepts ${url}`, () => {
      const r = parseArgs([url]);
      assert.equal(r.ok, true, r.error);
      assert.equal(r.options.url, url);
    });
  }

  test('a URL is never mistaken for a subcommand', () => {
    // Guards the change being made: adding subcommands must not let a word
    // inside a URL capture the invocation.
    for (const url of ['http://localhost:3000/doctor', 'http://localhost:3000/init', 'http://up.localhost:3000']) {
      const r = parseArgs([url]);
      assert.equal(r.ok, true, `${url} must still parse as a URL`);
      assert.equal(r.options.url, url);
    }
  });
});

describe('subcommands cannot capture a target', () => {
  // Harness subcommands were added after 0.1.0 shipped. The dispatch rule is
  // narrow on purpose: only an exact bare word in first position. Everything
  // here would have been a usage error before, so nothing that worked changes
  // meaning -- only things that previously failed start succeeding.
  test('a bare subcommand word dispatches', () => {
    for (const cmd of ['init', 'up', 'down', 'doctor']) {
      const r = parseArgs([cmd]);
      assert.equal(r.ok, true, r.error);
      assert.equal(r.options.command, cmd);
      assert.equal(r.options.url, null);
    }
  });

  test('a URL containing a subcommand word is still a URL', () => {
    for (const url of [
      'http://localhost:3000/doctor',
      'http://localhost:3000/init',
      'http://doctor.localhost:3000',
      'http://up.example.com/down',
    ]) {
      const r = parseArgs([url]);
      assert.equal(r.ok, true, `${url}: ${r.error}`);
      assert.equal(r.options.command, 'analyze');
      assert.equal(r.options.url, url);
    }
  });

  test('a subcommand in second position is not a subcommand', () => {
    // Only the first positional may dispatch, so a second one is the same
    // "unexpected second target" error it always was.
    const r = parseArgs(['http://localhost:3000', 'doctor']);
    assert.equal(r.ok, false);
    assert.match(r.error, /second target/);
  });

  test('a subcommand does not take a URL, and says so', () => {
    const r = parseArgs(['doctor', 'http://localhost:3000']);
    assert.equal(r.ok, false);
    assert.match(r.error, /does not take a URL/);
  });

  test('the default command is analyze, so nothing changes for existing callers', () => {
    assert.equal(parseArgs(['http://localhost:3000']).options.command, 'analyze');
  });
});

describe('shipped contract: documented options keep their meaning', () => {
  const url = 'http://localhost:3000';

  test('defaults are unchanged', () => {
    const o = parseArgs([url]).options;
    assert.equal(o.failOn, 'none', 'the default must never fail a build unexpectedly');
    assert.equal(o.domain, 'example.com');
    assert.equal(o.html, './notlocalhost-report.html');
    assert.equal(o.timeout, 30_000);
    assert.equal(o.flowTimeout, 60_000);
    assert.equal(o.settle, 1200);
    assert.equal(o.crossSite, false);
    assert.equal(o.verbose, false);
    assert.equal(o.quiet, false);
    assert.equal(o.json, undefined);
  });

  test('--flow takes a path', () => {
    assert.equal(parseArgs([url, '--flow', './login.js']).options.flow, './login.js');
  });

  test('--json with no value means stdout; with a value means a file', () => {
    assert.equal(parseArgs([url, '--json']).options.json, true);
    assert.equal(parseArgs([url, '--json', 'out.json']).options.json, 'out.json');
  });

  test('--fail-on accepts exactly the documented levels', () => {
    for (const level of ['will-break', 'may-break', 'info', 'none']) {
      assert.equal(parseArgs([url, '--fail-on', level]).ok, true, level);
    }
    assert.equal(parseArgs([url, '--fail-on', 'critical']).ok, false);
  });

  test('--html, --no-html and --markdown', () => {
    assert.equal(parseArgs([url, '--html', 'r.html']).options.html, 'r.html');
    assert.equal(parseArgs([url, '--no-html']).options.html, null);
    assert.equal(parseArgs([url, '--markdown', 'r.md']).options.markdown, 'r.md');
  });

  test('--domain, --cross-site and --map', () => {
    const o = parseArgs([url, '--domain', 'acme.com', '--cross-site', '--map', 'localhost:3000=app.acme.com']).options;
    assert.equal(o.domain, 'acme.com');
    assert.equal(o.crossSite, true);
    assert.deepEqual(o.map, { 'localhost:3000': 'app.acme.com' });
  });

  test('numeric options', () => {
    const o = parseArgs([url, '--timeout', '5000', '--flow-timeout', '9000', '--settle', '100']).options;
    assert.equal(o.timeout, 5000);
    assert.equal(o.flowTimeout, 9000);
    assert.equal(o.settle, 100);
  });

  test('boolean flags', () => {
    const o = parseArgs([url, '--verbose', '--quiet', '--headed', '--no-port-scan']).options;
    assert.equal(o.verbose, true);
    assert.equal(o.quiet, true);
    assert.equal(o.headed, true);
    assert.equal(o.noPortScan, true);
  });

  test('--browser-path and --channel', () => {
    const o = parseArgs([url, '--browser-path', '/x/chrome', '--channel', 'msedge']).options;
    assert.equal(o.browserPath, '/x/chrome');
    assert.equal(o.channel, 'msedge');
  });

  test('the README example line parses exactly as printed', () => {
    const r = parseArgs([
      'http://localhost:5173',
      '--map', 'localhost:5173=app.acme.com',
      '--map', 'localhost:8000=api.acme.com',
    ]);
    assert.equal(r.ok, true, r.error);
    assert.deepEqual(r.options.map, {
      'localhost:5173': 'app.acme.com',
      'localhost:8000': 'api.acme.com',
    });
  });
});

describe('shipped contract: exit codes', () => {
  test('the documented values have not moved', () => {
    // CI pipelines branch on these numbers. They are an API.
    assert.deepEqual(EXIT, { CLEAN: 0, FINDINGS: 1, UNREACHABLE: 2, TOOL_FAILURE: 5, USAGE: 64 });
  });

  test('--help exits 0 and still documents the exit codes', async () => {
    const stdout = sink();
    assert.equal(await run(['--help'], { stdout, stderr: sink() }), EXIT.CLEAN);
    assert.match(stdout.text, /EXIT CODES/);
    for (const code of ['0', '1', '2', '5', '64']) {
      assert.match(stdout.text, new RegExp(`^\\s*${code}\\s`, 'm'), `exit code ${code} missing from --help`);
    }
  });

  test('--version exits 0 and reports a schema version', async () => {
    const stdout = sink();
    assert.equal(await run(['--version'], { stdout, stderr: sink() }), EXIT.CLEAN);
    assert.match(stdout.text, /^\d+\.\d+\.\d+ \(schema \d+\)/);
  });

  test('no arguments is a usage error, not a crash', async () => {
    assert.equal(await run([], { stdout: sink(), stderr: sink() }), EXIT.USAGE);
  });

  test('an unknown option is a usage error', async () => {
    assert.equal(await run(['http://localhost:3000', '--nope'], { stdout: sink(), stderr: sink() }), EXIT.USAGE);
  });

  test('a non-http scheme is refused', () => {
    assert.equal(parseArgs(['file:///etc/passwd']).ok, false);
    assert.equal(parseArgs(['ftp://example.com']).ok, false);
  });
});

describe('shipped contract: the programmatic API', () => {
  test('every documented export is still exported', async () => {
    // Anyone who imported these from 0.1.0 must keep working.
    const api = await import('../src/index.js');
    for (const name of [
      'analyze',
      'shouldFail',
      'LIMITATIONS',
      'renderHtml',
      'renderJson',
      'renderMarkdown',
      'renderSummary',
      'renderTerminal',
      'EXIT',
      'EXIT_DESCRIPTIONS',
      'VERSION',
      'SCHEMA_VERSION',
      'locateBrowser',
      'listBrowsers',
      'parseSetCookie',
      'effectiveSameSite',
      'registrableDomain',
      'sameSite',
      'sameOrigin',
      'createDeploymentModel',
    ]) {
      assert.ok(name in api, `export "${name}" disappeared from the public API`);
    }
  });

  test('the JSON schema version has not been bumped without cause', async () => {
    const { SCHEMA_VERSION } = await import('../src/version.js');
    assert.equal(SCHEMA_VERSION, 1, 'bumping this breaks every CI consumer pinned to schema 1');
  });
});
