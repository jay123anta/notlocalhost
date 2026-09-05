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
import { readConfig, readState, writeState, harnessDir } from '../src/harness/config.js';
import { digestOfFile, findBlock } from '../src/harness/hosts.js';
import { findInstalledCaddy, findLocalCaddy } from '../src/harness/caddy.js';

/**
 * Ports the operating system hands out, not ports we hope are free.
 *
 * These were fixed numbers, which is a bet that nothing else on the machine
 * wants them -- and on Windows it is a bet against the machine itself. Hyper-V,
 * WSL and Docker reserve blocks of the dynamic port range at boot, the blocks
 * differ per machine, and binding inside one fails with a permission error that
 * looks nothing like a port clash. A test that passes depending on which
 * features a host has installed is not testing what it claims to.
 *
 * Assigned in before(), so every reference below reads them after they are set.
 */
let HTTP_PORT;
let HTTPS_PORT;
let UPSTREAM;

/** Ask the OS for a port it considers free, then release it. */
async function freePort() {
  const probe = createServer();
  await new Promise((r) => probe.listen(0, '127.0.0.1', r));
  const { port } = probe.address();
  await new Promise((r) => probe.close(r));
  return port;
}

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

  [HTTP_PORT, HTTPS_PORT] = [await freePort(), await freePort()];

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
  // Bind the upstream on an OS-assigned port and read back what it got,
  // rather than choosing a number and hoping.
  await new Promise((r) => upstream.listen(0, '127.0.0.1', r));
  UPSTREAM = upstream.address().port;
});

after(async () => {
  const state = work ? readState(work) : null;
  if (state?.running?.pid) await stopProcess(state.running.pid);
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
    // OS-assigned: a fixed number is a bet against whatever else is on the
    // machine, and on Windows against the machine itself -- Hyper-V and WSL
    // reserve blocks of the dynamic range, differently on every host.
    await new Promise((r) => silent.listen(0, '127.0.0.1', r));
    const silentPort = silent.address().port;
    try {
      const { speaksHttp } = await import('../src/collect/port-scan.js');
      assert.equal(await speaksHttp(silentPort), false, 'a non-HTTP listener must be rejected');
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
    // Two separate questions, deliberately not in the same try.
    //
    // Waiting for Caddy to bind and generate its certificate is a race, so it
    // retries. Whether the response is *correct* is not a race, and retrying
    // an assertion means a genuine failure -- a missing X-Forwarded-Proto, a
    // cookie without Secure -- gets swallowed and reported as a timeout. That
    // puts the wrong bug on the screen, and this suite is the Stage 2 gate.
    //
    // The budget is generous because certificate generation on a cold CI
    // runner under load is slow, and a gate that fails on a busy machine
    // teaches people to re-run it rather than read it. Observed at ~10.5s on a
    // loaded Windows box, which is exactly where the old 10s budget expired.
    const DEADLINE_MS = 90_000;
    const startedAt = Date.now();
    let res = null;
    let lastError = null;

    while (Date.now() - startedAt < DEADLINE_MS) {
      try {
        res = await fetchInsecure(`https://app.gatetest.test:${HTTPS_PORT}/`);
        break;
      } catch (err) {
        lastError = err;
        await new Promise((r) => setTimeout(r, 250));
      }
    }

    if (!res) {
      const waited = Math.round((Date.now() - startedAt) / 1000);
      assert.fail(
        `no HTTPS response from the proxy after ${waited}s.\n` +
          `last error: ${lastError?.message ?? 'none recorded'}\n` +
          `Caddy log:\n${readLog()}`,
      );
    }

    // From here every failure is a real one and is reported as itself.
    assert.equal(res.status, 200);
    assert.match(res.body, /upstream/);
    // The upstream must be told the request arrived over TLS, or a framework
    // deriving its own scheme keeps emitting http:// URLs.
    assert.equal(res.headers['x-forwarded-proto-seen'], 'https');
    // And a Secure cookie can now actually be set, which is the point.
    assert.match(String(res.headers['set-cookie'] ?? ''), /Secure/);
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

  test('stopping a process that is already gone counts as stopped', async () => {
    // The goal is that it is not running, not that we were the one to end it.
    assert.equal((await stopProcess(0)).ok, true);
    assert.equal((await stopProcess(999_999)).ok, true);
  });

  test('a process that ignores SIGTERM is escalated rather than reported as a failure', async () => {
    // Found on Linux: a signal is a request, not an event. Checking liveness
    // immediately after sending one reports failure for a shutdown that is
    // merely in progress.
    const { spawn } = await import('node:child_process');
    const child = spawn(
      process.execPath,
      ['-e', 'process.on("SIGTERM", () => {}); setInterval(() => {}, 1000);'],
      { stdio: 'ignore' },
    );
    await new Promise((r) => setTimeout(r, 300));
    try {
      const result = await stopProcess(child.pid, { graceMs: 600, killMs: 3000 });
      assert.equal(result.ok, true, result.error);
      if (process.platform !== 'win32') {
        assert.equal(result.escalated, true, 'SIGTERM was ignored, so it must have escalated');
      }
      assert.equal(isAlive(child.pid), false);
    } finally {
      try { child.kill('SIGKILL'); } catch { /* already gone */ }
    }
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

describe('an interrupted trust install is still recorded', { skip }, () => {
  // The most dangerous thing the harness does is the one thing no test could
  // previously touch: every case above passes trust: false, so the certificate
  // path had no coverage at all. That is how a broken verification shipped and
  // left five roots on a machine.
  //
  // No real trust store is touched here. `up` takes the install step as a
  // parameter, so a failure part-way through can be simulated exactly.
  let scratch;
  let upstreamSrv;
  let port;
  let caPath;

  before(async () => {
    scratch = mkdtempSync(join(tmpdir(), 'nlh-trust-'));
    upstreamSrv = createServer((_, res) => res.end('ok'));
    await new Promise((r) => upstreamSrv.listen(0, '127.0.0.1', r));
    port = upstreamSrv.address().port;

    // A real certificate, in a scratch data directory Caddy would use.
    caPath = join(scratch, 'data', 'caddy', 'pki', 'authorities', 'local', 'root.crt');
    mkdirSync(join(scratch, 'data', 'caddy', 'pki', 'authorities', 'local'), { recursive: true });
    writeFileSync(caPath, readFileSync(join(process.cwd(), 'test', 'fixtures', 'ca-root.pem')));
  });

  after(async () => {
    // Clear the certificate entries before down runs.
    //
    // The ledger deliberately says an install was attempted, and down honours
    // that by asking the platform to remove the certificate -- against the real
    // trust store, on the real machine. Nothing would be deleted, since this
    // fixture was never installed, but running certutil -delstore on a
    // developer's machine is exactly what this suite promises never to do. The
    // assertion above has already been made by this point.
    const ledger = readState(scratch);
    if (ledger) {
      ledger.caTrusted = false;
      ledger.ca = null;
      writeState(ledger, scratch);
    }

    try {
      await down({ cwd: scratch, env: { ...process.env, XDG_DATA_HOME: join(scratch, 'data') } });
    } catch {
      /* the point of the test is what the ledger holds, not that down succeeds */
    }
    await new Promise((r) => upstreamSrv.close(r));
    rmSync(scratch, { recursive: true, force: true });
  });

  test('the ledger names the certificate before the install is attempted', async () => {
    await init({ cwd: scratch, project: 'trusttest', upstreams: [{ label: 'app', port }], force: true });

    const env = { ...process.env, XDG_DATA_HOME: join(scratch, 'data') };
    let ledgerDuringInstall = null;

    await up({
      cwd: scratch,
      consent: true,
      httpPort: await freePort(),
      httpsPort: await freePort(),
      env,
      trust: true,
      // Stands in for the moment after the root is in the store and before
      // anything has recorded it. Whatever the ledger holds here is all `down`
      // would ever have to work from.
      installTrust: async () => {
        ledgerDuringInstall = readState(scratch);
        const err = new Error('interrupted');
        err.code = 'TRUST_FAILED';
        throw err;
      },
    }).catch(() => {});

    assert.ok(ledgerDuringInstall, 'state must exist before the install runs');
    assert.equal(ledgerDuringInstall.caTrusted, 'attempting', 'the attempt must be on record, not just its success');
    assert.match(
      String(ledgerDuringInstall.ca?.sha1 ?? ''),
      /^[0-9a-f]{40}$/,
      'and it must name the exact certificate, or down has nothing to remove',
    );
  });
});
