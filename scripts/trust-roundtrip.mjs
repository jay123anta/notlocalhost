/**
 * Install a certificate authority, prove it is there, remove it, prove it is
 * gone, and prove the store is exactly the size it started.
 *
 * The test suites never do this. Every lifecycle test passes `trust: false`,
 * because a test that writes to a developer's real trust store is not one
 * anybody should run by accident -- which leaves the code that puts a root
 * certificate on a machine without automated coverage.
 *
 * So it is a separate, explicit, opt-in step: safe on a throwaway runner, and
 * refusing to run anywhere else without being told twice.
 *
 * The assertion that matters is not "removal reported success". It is that the
 * number of roots afterwards equals the number before. A removal that deletes
 * the wrong certificate reports success and fails only this check, and several
 * authorities can share a subject, so removal by name is exactly how that
 * happens.
 */
import { execFileSync } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync, mkdirSync } from 'node:fs';
import { createServer } from 'node:http';
import { tmpdir, platform, homedir } from 'node:os';
import { join } from 'node:path';

import { init, up, down } from '../src/harness/lifecycle.js';
import { readState } from '../src/harness/config.js';
import { caRootPath, describeCertificate, trustState } from '../src/harness/trust.js';

const OS = platform();
const CI = process.env.CI === 'true' || process.env.GITHUB_ACTIONS === 'true';

if (!CI && process.argv[2] !== '--yes-i-mean-it') {
  console.error(
    [
      'This installs a real certificate authority into this machine’s trust store',
      'and then removes it. It is meant for a throwaway CI runner.',
      '',
      'If you really want to run it here, pass --yes-i-mean-it. It will print the',
      'exact thumbprint it installs, and the count before and after.',
    ].join('\n'),
  );
  process.exit(64);
}

/** How many roots the platform reports. The number, not the contents. */
function rootCount() {
  try {
    if (OS === 'win32') {
      const out = execFileSync(
        'powershell',
        ['-NoProfile', '-NonInteractive', '-Command', '(Get-ChildItem Cert:\\CurrentUser\\Root).Count'],
        { encoding: 'utf8', timeout: 60_000, windowsHide: true },
      );
      return Number(out.trim());
    }
    if (OS === 'darwin') {
      const out = execFileSync('security', ['find-certificate', '-a', '/Library/Keychains/System.keychain'], {
        encoding: 'utf8',
        timeout: 60_000,
      });
      return (out.match(/^keychain:/gm) ?? []).length;
    }

    const nssdb = join(homedir(), '.pki', 'nssdb');
    if (!existsSync(nssdb)) return 0;
    const out = execFileSync('certutil', ['-L', '-d', `sql:${nssdb}`], { encoding: 'utf8', timeout: 60_000 });
    // certutil prints a two-line header: the column names, then the trust
    // categories indented beneath them. Only the first was being skipped, so
    // an empty database counted as one certificate and a database holding one
    // counted as two -- precisely the arithmetic this job exists to check. A
    // counting function that miscounts is worse than no count: it fails a
    // correct run, and would pass a wrong one.
    return out
      .split('\n')
      .map((l) => l.trimEnd())
      .filter((l) => l.trim())
      .filter((l) => !/^Certificate Nickname/.test(l))
      .filter((l) => !/^\s+SSL,/.test(l))
      .filter((l) => !/^-{3,}/.test(l)).length;
  } catch {
    return null;
  }
}

/**
 * Report a failure so it survives into the annotation.
 *
 * Workflow commands are one line: a raw newline ends the annotation and
 * everything after it becomes ordinary log output -- which is exactly the part
 * nobody without repository admin rights can read. Encoding the newlines keeps
 * the whole message somewhere it can actually be seen.
 */
const fail = (message, detail) => {
  const full = detail ? `${message}\n${detail}` : String(message);
  const encoded = full.replace(/%/g, '%25').replace(/\r/g, '%0D').replace(/\n/g, '%0A');
  console.error(`::error title=trust round trip::${encoded}`);
  console.error(`\n${full}\n`);
  process.exitCode = 1;
};

const work = mkdtempSync(join(tmpdir(), 'nlh-trust-rt-'));
const dataDir = join(work, 'data');
mkdirSync(dataDir, { recursive: true });
const env = { ...process.env, XDG_DATA_HOME: dataDir };

const upstream = createServer((_, res) => {
  res.writeHead(200, { 'content-type': 'text/html' });
  res.end('<!doctype html><h1>upstream</h1>');
});
const freePort = async () => {
  const probe = createServer();
  await new Promise((r) => probe.listen(0, '127.0.0.1', r));
  const { port } = probe.address();
  await new Promise((r) => probe.close(r));
  return port;
};

let installed = null;

try {
  await new Promise((r) => upstream.listen(0, '127.0.0.1', r));
  const upstreamPort = upstream.address().port;

  const before = rootCount();
  console.log(`platform            ${OS}`);
  console.log(`roots before        ${before ?? '(could not count)'}`);
  if (before === null) {
    fail('the trust store could not be counted, so nothing below would mean anything');
    throw new Error('uncountable');
  }

  await init({ cwd: work, project: 'trustrt', upstreams: [{ label: 'app', port: upstreamPort }], force: true });
  await up({
    cwd: work,
    consent: true,
    httpPort: await freePort(),
    httpsPort: await freePort(),
    env,
    trust: true,
    log: (m) => console.log(`  ${m}`),
  });

  const state = readState(work);
  installed = state?.ca ?? describeCertificate(caRootPath(env));
  if (!installed?.sha1) {
    fail('nothing was recorded as installed, so `down` would have nothing to remove');
    throw new Error('no ledger entry');
  }
  console.log(`installed           ${installed.sha1}`);
  console.log(`ledger says         ${JSON.stringify(state.caTrusted)}`);

  const during = trustState(installed.fingerprint, installed.sha1);
  console.log(`store reports       ${during}`);
  if (during !== 'present') {
    fail(`the certificate was installed but the store reports "${during}"`);
  }

  const mid = rootCount();
  console.log(`roots while up      ${mid ?? '(unknown)'}`);
  if (mid !== null && before !== null && mid !== before + 1) {
    fail(`installing one certificate changed the count by ${mid - before}, not 1`);
  }

  const result = await down({ cwd: work, env, log: (m) => console.log(`  ${m}`) });
  console.log(`down clean          ${result.clean}`);
  for (const s of result.steps) console.log(`  ${s.ok ? 'ok  ' : 'FAIL'}  ${s.what}: ${s.detail}`);
  if (!result.clean) fail('down did not complete every step', JSON.stringify(result.steps, null, 2));

  const after = trustState(installed.fingerprint, installed.sha1);
  console.log(`store reports       ${after}`);
  if (after === 'present') fail('the certificate is still in the trust store after down');

  const finalCount = rootCount();
  console.log(`roots after         ${finalCount ?? '(unknown)'}`);
  if (finalCount !== before) {
    fail(
      `the store has ${finalCount} roots and started with ${before}`,
      finalCount < before
        ? 'Fewer than it started with: removal deleted something it did not install.'
        : 'More than it started with: something was left behind.',
    );
  }

  if (process.exitCode) {
    console.error('\nthe round trip did not hold');
  } else {
    console.log('\ninstalled, verified, removed, verified, and the store is the size it was.');
  }
} catch (err) {
  fail(err?.message ?? String(err));
} finally {
  try {
    await down({ cwd: work, env });
  } catch {
    /* already reported */
  }
  await new Promise((r) => upstream.close(r));
  rmSync(work, { recursive: true, force: true });

  if (process.exitCode && installed?.sha1) {
    const { removeCommandFor } = await import('../src/harness/trust.js');
    console.error(`\nIf a certificate was left behind, this removes exactly it:\n  ${removeCommandFor(installed)}`);
  }
}
