/**
 * The Stage 2 gate: init, up, a real HTTPS request, down, machine unchanged.
 *
 * This runs the real lifecycle against a real Caddy, serving a real
 * application over real TLS, and then asserts the machine is byte-for-byte
 * what it was. Nothing is stubbed.
 *
 * What is *not* real is where it points. The hosts file is a temporary file,
 * the certificate authority lives in a scratch data directory, and the proxy
 * binds unprivileged ports. That is not a weakened test -- every path and port
 * is injectable in the product code precisely so this can be exercised without
 * elevation. A gate that needed administrator rights would not be run, and a
 * gate that is not run is not a gate.
 *
 * Certificate trust is exercised separately and deliberately: installing a real
 * root into the real store during a test run would be exactly the kind of thing
 * this project exists to warn people about.
 */
import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { mkdtempSync, rmSync, writeFileSync, readFileSync, existsSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { init, up, down, isAlive, stopProcess } from '../src/harness/lifecycle.js';
import { readConfig, readState, harnessDir } from '../src/harness/config.js';
import { digestOfFile, findBlock } from '../src/harness/hosts.js';
import { findInstalledCaddy, findLocalCaddy } from '../src/harness/caddy.js';

const HTTP_PORT = 39820;
const HTTPS_PORT = 39821;
const UPSTREAM = 39822;

// The harness needs Caddy. Downloading one inside a test would make the suite
// depend on the network, so this runs only where a Caddy already exists.
const caddy = findInstalledCaddy() ?? findLocalCaddy(process.cwd());
const skip = caddy ? false : 'no Caddy available (run the harness once to fetch one)';

const HOSTS_SAMPLE = ['# a sample hosts file', '', '127.0.0.1\tlocalhost', '::1\tlocalhost', ''].join('\n');

let work;
let hostsFile;
let upstream;
let dataDir;

before(async () => {
  if (!caddy) return;
  work = mkdtempSync(join(tmpdir(), 'nlh-life-'));
  hostsFile = join(work, 'hosts');
  writeFileSync(hostsFile, HOSTS_SAMPLE, 'utf8');

  dataDir = join(work, 'data');
  mkdirSync(dataDir, { recursive: true });

  // Put the fetched Caddy where the project expects it, so `up` uses it
  // instead of reaching for the network.
  const dest = join(harnessDir(work), 'caddy');
  mkdirSync(dest, { recursive: true });
  const binName = process.platform === 'win32' ? 'caddy.exe' : 'caddy';
  writeFileSync(join(dest, binName), readFileSync(caddy.path));
  if (process.platform !== 'win32') {
    const { chmodSync } = await import('node:fs');
    chmodSync(join(dest, binName), 0o755);
  }

  upstream = createServer((req, res) => {
    res.writeHead(200, {
      'content-type': 'text/html',
      // The whole point of the harness: over HTTPS this cookie can carry
      // Secure, which on plain localhost it never could.
      'set-cookie': 'sid=harness; Path=/; HttpOnly; Secure; SameSite=Lax',
      'x-forwarded-proto-seen': req.headers['x-forwarded-proto'] ?? 'none',
    });
    res.end('<!doctype html><html><body><h1>upstream</h1></body></html>');
  });
  await new Promise((r) => upstream.listen(UPSTREAM, '127.0.0.1', r));
});

after(async () => {
  const state = work ? readState(work) : null;
  if (state?.running?.pid) stopProcess(state.running.pid);
  if (upstream) await new Promise((r) => upstream.close(r));
  if (work) rmSync(work, { recursive: true, force: true });
});

describe('init', { skip }, () => {
  test('writes a configuration and changes nothing else', async () => {
    const hostsBefore = digestOfFile(hostsFile);

    const result = await init({
      cwd: work,
      project: 'gatetest',
      upstreams: [{ label: 'app', port: UPSTREAM }],
    });

    assert.equal(result.config.domain, 'gatetest.localhost');
    assert.equal(result.config.sites[0].host, 'app.gatetest.localhost');
    assert.equal(readConfig(work).project, 'gatetest');
    assert.equal(digestOfFile(hostsFile), hostsBefore, 'init must not touch the hosts file');
    assert.equal(readState(work), null, 'init records no machine changes, because it makes none');
  });

  test('every change it would make is described with how it is reversed', async () => {
    const result = await init({ cwd: work, project: 'gatetest', upstreams: [{ port: UPSTREAM }], force: true });
    assert.ok(result.changes.length >= 3);
    for (const c of result.changes) assert.ok(c.what && c.detail && c.reversedBy);
  });

  test('refuses to overwrite an existing project without --force', async () => {
    await assert.rejects(
      () => init({ cwd: work, project: 'other', upstreams: [{ port: UPSTREAM }] }),
      /already initialised/,
    );
  });

  test('refuses when nothing is serving HTTP, rather than proxying nothing', async () => {
    const empty = mkdtempSync(join(tmpdir(), 'nlh-empty-'));
    try {
      await assert.rejects(() => init({ cwd: empty, upstreams: [] }), /nothing to put behind a proxy/);
    } finally {
      rmSync(empty, { recursive: true, force: true });
    }
  });

  test('an open port that is not a web server is not proposed as an upstream', async () => {
    // Databases, brokers and language servers all answer a TCP connect.
    // Offering to put a TLS proxy in front of PostgreSQL helps nobody.
    const { createServer } = await import('node:net');
    const silent = createServer((socket) => socket.write('not-http\r\n'));
    await new Promise((r) => silent.listen(39831, '127.0.0.1', r));
    try {
      const { speaksHttp } = await import('../src/collect/port-scan.js');
      assert.equal(await speaksHttp(39831), false, 'a non-HTTP listener must be rejected');
      assert.equal(await speaksHttp(UPSTREAM), true, 'the real web server must be accepted');
    } finally {
      silent.close();
    }
  });
});

describe('up requires consent before it touches anything', { skip }, () => {
  test('without consent it refuses and returns the plan', async () => {
    await init({ cwd: work, project: 'gatetest', upstreams: [{ label: 'app', port: UPSTREAM }], force: true });
    try {
      await up({ cwd: work, consent: false, httpPort: HTTP_PORT, httpsPort: HTTPS_PORT, hostsFile, trust: false });
      assert.fail('up must not proceed without consent');
    } catch (err) {
      assert.equal(err.code, 'NO_CONSENT');
      assert.ok(Array.isArray(err.changes) && err.changes.length, 'the refusal must carry the plan');
    }
    assert.equal(readState(work), null, 'nothing may be recorded when consent was refused');
  });
});

describe('the gate: up, HTTPS, down, unchanged', { skip }, () => {
  let hostsBefore;
  let hostsBytes;

  test('up starts the proxy', async () => {
    await init({ cwd: work, project: 'gatetest', tier: 'test', upstreams: [{ label: 'app', port: UPSTREAM }], force: true });
    hostsBefore = digestOfFile(hostsFile);
    hostsBytes = readFileSync(hostsFile);

    const result = await up({
      cwd: work,
      consent: true,
      httpPort: HTTP_PORT,
      httpsPort: HTTPS_PORT,
      hostsFile,
      // Trust is exercised in its own suite. Installing a real root into the
      // real store during a test would be precisely the thing this project
      // warns people about.
      trust: false,
      env: { ...process.env, XDG_DATA_HOME: dataDir },
    });

    assert.ok(result.state.running.pid, 'a pid must be recorded');
    assert.ok(isAlive(result.state.running.pid), 'the proxy must actually be running');
    assert.ok(existsSync(result.caddyfilePath));
  });

  test('the hosts file was changed, inside a marked block', () => {
    const text = readFileSync(hostsFile, 'utf8');
    assert.ok(findBlock(text, 'gatetest').present, 'the block must be present while up');
    assert.ok(text.includes('app.gatetest.test'));
    assert.notEqual(digestOfFile(hostsFile), hostsBefore);
    assert.ok(readFileSync(hostsFile, 'utf8').includes('127.0.0.1\tlocalhost'), 'existing entries must survive');
  });

  test('a real HTTPS request reaches the upstream through the proxy', async () => {
    // Give Caddy a moment to bind and issue its certificate.
    for (let i = 0; i < 40; i++) {
      try {
        const res = await fetchInsecure(`https://app.gatetest.test:${HTTPS_PORT}/`);
        assert.equal(res.status, 200);
        assert.match(res.body, /upstream/);
        // The upstream must be told the request arrived over TLS, or a
        // framework deriving its own scheme keeps emitting http:// URLs.
        assert.equal(res.headers['x-forwarded-proto-seen'], 'https');
        // And a Secure cookie can now actually be set, which is the point.
        assert.match(String(res.headers['set-cookie'] ?? ''), /Secure/);
        return;
      } catch {
        await new Promise((r) => setTimeout(r, 250));
      }
    }
    assert.fail(`no HTTPS response from the proxy. Caddy log:\n${readLog()}`);
  });

  test('down stops the proxy and restores the machine byte-for-byte', async () => {
    const state = readState(work);
    const pid = state.running.pid;

    const result = await down({ cwd: work, env: { ...process.env, XDG_DATA_HOME: dataDir } });

    assert.equal(result.clean, true, result.summary + '\n' + JSON.stringify(result.steps, null, 2));
    assert.equal(isAlive(pid), false, 'the proxy must be stopped');

    assert.equal(findBlock(readFileSync(hostsFile, 'utf8'), 'gatetest').present, false, 'the block must be gone');
    assert.equal(digestOfFile(hostsFile), hostsBefore, 'the hosts digest must match its pre-change value');
    assert.deepEqual(readFileSync(hostsFile), hostsBytes, 'the hosts file must be byte-for-byte what it was');

    assert.equal(readState(work), null, 'the ledger must be cleared once everything is undone');
  });

  test('down on an already-down project does nothing and says so', async () => {
    const result = await down({ cwd: work });
    assert.equal(result.didNothing, true);
    assert.match(result.summary, /nothing to undo/i);
  });

  test('the project configuration survives down, so up can be run again', () => {
    assert.ok(existsSync(join(harnessDir(work), 'config.json')), 'config is intent, not debt');
    assert.equal(readConfig(work).project, 'gatetest');
  });
});

describe('up is idempotent and refuses to double-start', { skip }, () => {
  test('a second up while running is refused, naming the pid', async () => {
    await init({ cwd: work, project: 'gatetest', upstreams: [{ label: 'app', port: UPSTREAM }], force: true });
    const first = await up({
      cwd: work,
      consent: true,
      httpPort: HTTP_PORT,
      httpsPort: HTTPS_PORT,
      hostsFile,
      trust: false,
      env: { ...process.env, XDG_DATA_HOME: dataDir },
    });
    try {
      await assert.rejects(
        () =>
          up({
            cwd: work,
            consent: true,
            httpPort: HTTP_PORT,
            httpsPort: HTTPS_PORT,
            hostsFile,
            trust: false,
            env: { ...process.env, XDG_DATA_HOME: dataDir },
          }),
        /already running/,
      );
    } finally {
      await down({ cwd: work, env: { ...process.env, XDG_DATA_HOME: dataDir } });
      assert.equal(isAlive(first.state.running.pid), false);
    }
  });

  test('stopping a process that is already gone counts as stopped', () => {
    // The goal is that it is not running, not that we were the one to end it.
    assert.equal(stopProcess(0).ok, true);
    assert.equal(stopProcess(999_999).ok, true);
  });
});

// ---------------------------------------------------------------------------

function readLog() {
  const p = join(harnessDir(work), 'caddy.log');
  return existsSync(p) ? readFileSync(p, 'utf8').split('\n').slice(-25).join('\n') : '(no log)';
}

/**
 * A TLS request that accepts the harness's own certificate.
 *
 * The CA is deliberately not installed during tests, so the certificate is
 * genuine but untrusted by this machine. Checking that TLS *works* is the
 * point; checking that a root we refused to install is trusted would be a
 * contradiction.
 */
function fetchInsecure(url) {
  return new Promise((resolve, reject) => {
    import('node:https').then(({ request }) => {
      const u = new URL(url);
      const req = request(
        {
          hostname: '127.0.0.1',
          port: u.port,
          path: u.pathname,
          method: 'GET',
          servername: u.hostname,
          headers: { host: u.host },
          rejectUnauthorized: false,
          timeout: 8000,
        },
        (res) => {
          let body = '';
          res.on('data', (c) => (body += c));
          res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body }));
        },
      );
      req.on('timeout', () => req.destroy(new Error('timeout')));
      req.on('error', reject);
      req.end();
    }, reject);
  });
}
