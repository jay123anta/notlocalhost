/**
 * Harness tests.
 *
 * The gate for this stage is that `down` leaves the machine byte-identical,
 * proven rather than asserted. Everything that mutates the machine is written
 * to take an explicit path, so these tests exercise the real code against
 * temporary files instead of a weakened copy of it.
 *
 * Nothing here touches the real hosts file, the real trust store, or a
 * privileged port. A test suite that needed elevation would not be run.
 */
import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync, readFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  BEGIN,
  END,
  detectEol,
  findBlock,
  withBlock,
  withoutBlock,
  applyBlock,
  removeBlock,
  previewBlock,
  digestOf,
  digestOfFile,
} from '../src/harness/hosts.js';
import {
  defaultConfig,
  slug,
  TIERS,
  describeChanges,
  emptyState,
  readConfig,
  writeConfig,
  readState,
  writeState,
  fileDigest,
  CONFIG_VERSION,
} from '../src/harness/config.js';
import { renderCaddyfile, summariseSites, isUnmodified } from '../src/harness/caddyfile.js';
import { assetFor, parseChecksums, digest } from '../src/harness/caddy.js';
import { checkDns, checkCertTrust, checkPorts, checkProxy, runAllChecks, hostsPath } from '../src/harness/checks.js';
import { caRootPath, describeCertificate, trustState, removeCommandFor } from '../src/harness/trust.js';

let tmp;
before(() => {
  tmp = mkdtempSync(join(tmpdir(), 'nlh-harness-'));
});
after(() => {
  if (tmp) rmSync(tmp, { recursive: true, force: true });
});

/** A hosts file that looks like a real one, in either line ending. */
const SAMPLE = (eol) =>
  [
    '# Copyright (c) 1993-2009 Microsoft Corp.',
    '#',
    '# This is a sample HOSTS file used by Microsoft TCP/IP for Windows.',
    '',
    '127.0.0.1       localhost',
    '::1             localhost',
    '10.0.0.5        internal.example.com',
    '',
  ].join(eol);

const writeHosts = (name, content) => {
  const p = join(tmp, name);
  writeFileSync(p, content, 'utf8');
  return p;
};

describe('hosts file: the block is found, added and removed exactly', () => {
  test('line endings are detected, not assumed', () => {
    assert.equal(detectEol(SAMPLE('\r\n')), '\r\n');
    assert.equal(detectEol(SAMPLE('\n')), '\n');
    assert.equal(detectEol('no newlines at all'), '\n');
  });

  test('a block is added with the hostnames inside markers', () => {
    const out = withBlock(SAMPLE('\n'), 'myapp', ['app.myapp.test', 'api.myapp.test']);
    assert.ok(out.includes(BEGIN('myapp')));
    assert.ok(out.includes(END('myapp')));
    assert.ok(out.includes('127.0.0.1\tapp.myapp.test'));
    assert.ok(out.includes('127.0.0.1\tapi.myapp.test'));
  });

  test('the original content survives untouched', () => {
    const original = SAMPLE('\n');
    const out = withBlock(original, 'myapp', ['app.myapp.test']);
    for (const line of original.split('\n').filter((l) => l.trim())) {
      assert.ok(out.includes(line), `lost line: ${line}`);
    }
  });

  test('applying twice is idempotent, not duplicated', () => {
    const once = withBlock(SAMPLE('\n'), 'myapp', ['app.myapp.test']);
    const twice = withBlock(once, 'myapp', ['app.myapp.test']);
    assert.equal(once, twice);
    assert.equal((twice.match(new RegExp(BEGIN('myapp'), 'g')) || []).length, 1);
  });

  test('re-applying with different hostnames replaces the block rather than appending', () => {
    const once = withBlock(SAMPLE('\n'), 'myapp', ['app.myapp.test']);
    const changed = withBlock(once, 'myapp', ['app.myapp.test', 'api.myapp.test']);
    assert.equal((changed.match(new RegExp(BEGIN('myapp'), 'g')) || []).length, 1);
    assert.ok(changed.includes('api.myapp.test'));
  });

  test('two projects coexist and are removed independently', () => {
    let text = withBlock(SAMPLE('\n'), 'alpha', ['app.alpha.test']);
    text = withBlock(text, 'beta', ['app.beta.test']);
    assert.ok(findBlock(text, 'alpha').present);
    assert.ok(findBlock(text, 'beta').present);

    const afterAlpha = withoutBlock(text, 'alpha');
    assert.equal(findBlock(afterAlpha, 'alpha').present, false);
    assert.ok(findBlock(afterAlpha, 'beta').present, "removing one project must not disturb another's block");
  });

  test('an unterminated block is not treated as present', () => {
    const broken = `${SAMPLE('\n')}\n${BEGIN('myapp')}\n127.0.0.1\tapp.myapp.test\n`;
    assert.equal(findBlock(broken, 'myapp').present, false);
  });
});

describe('hosts file: restoration is byte-identical', () => {
  for (const [label, eol] of [
    ['LF', '\n'],
    ['CRLF', '\r\n'],
  ]) {
    test(`add then remove restores the file exactly (${label})`, () => {
      const original = SAMPLE(eol);
      const path = writeHosts(`hosts-${label}`, original);
      const before = digestOfFile(path);
      const originalBytes = readFileSync(path);

      const applied = applyBlock(path, 'myapp', ['app.myapp.test', 'api.myapp.test']);
      assert.equal(applied.changed, true);
      assert.equal(applied.before, before);
      assert.notEqual(digestOfFile(path), before, 'the file must actually have changed');

      const removed = removeBlock(path, 'myapp', before);
      assert.equal(removed.restored, true);
      assert.equal(removed.matches, true, removed.reason);
      assert.equal(digestOfFile(path), before, 'digest must match the pre-change value');
      assert.deepEqual(readFileSync(path), originalBytes, 'the file must be byte-for-byte what it was');
    });
  }

  test('a file with no trailing newline is restored without gaining one', () => {
    const original = '127.0.0.1 localhost';
    const path = writeHosts('hosts-no-trailing', original);
    const before = digestOfFile(path);

    applyBlock(path, 'myapp', ['app.myapp.test']);
    const removed = removeBlock(path, 'myapp', before);

    assert.equal(removed.matches, true, removed.reason);
    assert.equal(readFileSync(path, 'utf8'), original);
  });

  // Every one of these shapes occurs in the wild, and each broke a different
  // assumption. Tidying a hosts file is itself an unrecoverable change: removal
  // has no way to know what was tidied away.
  for (const [label, content] of [
    ['trailing blank line', 'a\n\n\n# c\n127.0.0.1 x\n\n'],
    ['multiple trailing blanks', '127.0.0.1 localhost\n\n\n\n'],
    ['leading blank lines', '\n\n127.0.0.1 localhost\n'],
    ['CRLF with a blank tail', '127.0.0.1\tlocalhost\r\n\r\n'],
    ['a single line, no newline', '127.0.0.1 localhost'],
    ['tabs and alignment preserved', '127.0.0.1\t\tlocalhost   # note\n'],
  ]) {
    test(`restores byte-for-byte: ${label}`, () => {
      const path = writeHosts(`shape-${label.replace(/\W+/g, '-')}`, content);
      const before = digestOfFile(path);
      const originalBytes = readFileSync(path);

      const applied = applyBlock(path, 'demo', ['app.demo.test', 'api.demo.test']);
      assert.equal(applied.changed, true, 'the block must actually be added');
      assert.notEqual(digestOfFile(path), before);

      const removed = removeBlock(path, 'demo', before);
      assert.equal(removed.matches, true, removed.reason);
      assert.deepEqual(readFileSync(path), originalBytes, `not byte-identical for: ${label}`);
    });
  }

  test('a backup is written before the change and cleaned up after a clean restore', () => {
    const path = writeHosts('hosts-backup', SAMPLE('\n'));
    const backup = `${path}.notlocalhost-backup`;
    const before = digestOfFile(path);

    applyBlock(path, 'myapp', ['app.myapp.test']);
    assert.ok(existsSync(backup), 'the original must be copied before writing');

    removeBlock(path, 'myapp', before);
    assert.equal(existsSync(backup), false, 'a clean restore removes its own backup');
  });

  test('an outside edit is reported rather than silently reverted', () => {
    const path = writeHosts('hosts-edited', SAMPLE('\n'));
    const before = digestOfFile(path);

    applyBlock(path, 'myapp', ['app.myapp.test']);

    // Someone else adds a line while the harness is up.
    const meddled = `${readFileSync(path, 'utf8')}\n192.168.1.9\tprinter.local\n`;
    writeFileSync(path, meddled, 'utf8');

    const removed = removeBlock(path, 'myapp', before);
    assert.equal(removed.restored, true, 'our block is still removed');
    assert.equal(removed.matches, false, 'and the mismatch is reported, not hidden');
    assert.match(removed.reason, /edited it in the meantime/);
    assert.ok(readFileSync(path, 'utf8').includes('printer.local'), "the other person's edit must survive");
    assert.equal(findBlock(readFileSync(path, 'utf8'), 'myapp').present, false);
  });

  test('randomly shaped hosts files all restore byte-for-byte', () => {
    // Enumerated cases only cover the shapes someone thought of. This covers
    // the ones nobody did: arbitrary combinations of blank lines, whitespace-
    // only lines, tabs, both line endings, and a final newline or not.
    const pick = (a) => a[Math.floor(Math.random() * a.length)];
    const shapes = ['', '# comment', '127.0.0.1\tlocalhost', '::1  localhost', '10.0.0.5\thost.example', '   ', '\t'];
    const failures = [];

    for (let i = 0; i < 250; i++) {
      const eol = pick(['\n', '\r\n']);
      const lines = Array.from({ length: Math.floor(Math.random() * 8) }, () => pick(shapes));
      const content = lines.join(eol) + (Math.random() < 0.5 ? eol : '');

      const path = writeHosts(`prop-${i}`, content);
      const before = digestOfFile(path);
      const originalBytes = readFileSync(path);

      applyBlock(path, 'demo', ['app.demo.test']);
      removeBlock(path, 'demo', before);

      if (Buffer.compare(readFileSync(path), originalBytes) !== 0) {
        failures.push(JSON.stringify(content));
      }
    }

    assert.deepEqual(failures, [], `these shapes did not restore exactly:\n${failures.slice(0, 5).join('\n')}`);
  });

  test('removing a block that was never added changes nothing', () => {
    const path = writeHosts('hosts-absent', SAMPLE('\n'));
    const before = digestOfFile(path);
    const removed = removeBlock(path, 'myapp', before);
    assert.equal(removed.restored, false);
    assert.equal(removed.matches, true);
    assert.equal(digestOfFile(path), before);
  });

  test('the preview shows exactly what will be written', () => {
    const preview = previewBlock('myapp', ['app.myapp.test']);
    const applied = withBlock('127.0.0.1 localhost\n', 'myapp', ['app.myapp.test']);
    for (const line of preview) assert.ok(applied.includes(line), `preview line missing from the result: ${line}`);
  });
});

describe('configuration', () => {
  test('a hostname label is always valid', () => {
    assert.equal(slug('My App!'), 'my-app');
    assert.equal(slug('  --weird--  '), 'weird');
    assert.equal(slug(''), 'app');
    assert.equal(slug('x'.repeat(200)).length, 63);
  });

  test('the default tier needs no elevation and says what it cannot do', () => {
    assert.equal(TIERS.localhost.needsHostsEntry, false);
    assert.ok(TIERS.localhost.cannotGive.some((s) => /parent-domain cookie scope/.test(s)));
    assert.equal(TIERS.test.needsHostsEntry, true);
    assert.deepEqual(TIERS.test.cannotGive, []);
  });

  test('a config maps upstream ports to subdomains', () => {
    const cfg = defaultConfig({
      cwd: '/projects/My App',
      upstreams: [{ label: 'app', port: 3000 }, { label: 'api', port: 3001 }],
    });
    assert.equal(cfg.project, 'my-app');
    assert.equal(cfg.domain, 'my-app.localhost');
    assert.deepEqual(cfg.sites.map((s) => s.host), ['app.my-app.localhost', 'api.my-app.localhost']);
    assert.equal(cfg.sites[0].upstream, 'http://127.0.0.1:3000');
  });

  test('the test tier changes only the suffix', () => {
    const cfg = defaultConfig({ cwd: '/p/demo', tier: 'test', upstreams: [{ port: 3000 }] });
    assert.equal(cfg.domain, 'demo.test');
    assert.ok(cfg.sites[0].host.endsWith('.demo.test'));
  });

  test('an unknown tier is rejected rather than guessed', () => {
    assert.throws(() => defaultConfig({ cwd: '/p/x', tier: 'nonsense', upstreams: [] }), /unknown tier/);
  });

  test('config round-trips through disk', () => {
    const dir = mkdtempSync(join(tmp, 'cfg-'));
    const cfg = defaultConfig({ cwd: dir, upstreams: [{ port: 3000 }] });
    writeConfig(cfg, dir);
    assert.deepEqual(readConfig(dir), cfg);
  });

  test('a config from a different version is refused, not misread', () => {
    const dir = mkdtempSync(join(tmp, 'cfgv-'));
    writeConfig({ ...defaultConfig({ cwd: dir, upstreams: [] }), version: CONFIG_VERSION + 99 }, dir);
    assert.throws(() => readConfig(dir), /different version/);
  });

  test('state round-trips and starts empty', () => {
    const dir = mkdtempSync(join(tmp, 'state-'));
    assert.equal(readState(dir), null);
    const s = emptyState();
    writeState(s, dir);
    assert.equal(readState(dir).caTrusted, false);
  });

  test('every described change names how it is reversed', () => {
    const cfg = defaultConfig({ cwd: '/p/demo', tier: 'test', upstreams: [{ port: 3000 }] });
    const changes = describeChanges(cfg, { caddySource: 'downloaded' });
    assert.ok(changes.length >= 3);
    for (const c of changes) {
      assert.ok(c.what && c.detail && c.reversedBy, `incomplete change description: ${JSON.stringify(c)}`);
    }
    assert.ok(changes.some((c) => /hosts file/i.test(c.what)), 'the test tier must disclose the hosts change');
  });

  test('the localhost tier discloses that it changes no DNS', () => {
    const cfg = defaultConfig({ cwd: '/p/demo', upstreams: [{ port: 3000 }] });
    const changes = describeChanges(cfg, {});
    assert.ok(changes.some((c) => /No DNS or hosts changes/i.test(c.what)));
  });

  test('fileDigest is null for a file that does not exist', () => {
    assert.equal(fileDigest(join(tmp, 'nope')), null);
  });
});

describe('Caddyfile generation', () => {
  const cfg = defaultConfig({
    cwd: '/p/demo',
    upstreams: [{ label: 'app', port: 3000 }, { label: 'api', port: 3001 }],
  });

  test('every site gets a block, TLS and a proxy', () => {
    const out = renderCaddyfile(cfg);
    for (const s of cfg.sites) {
      assert.ok(out.includes(`${s.host} {`), `no block for ${s.host}`);
      assert.ok(out.includes(`reverse_proxy ${s.upstream}`));
    }
    assert.equal((out.match(/tls internal/g) || []).length, cfg.sites.length);
  });

  test('the admin API is off', () => {
    // It is an unauthenticated control socket. Nothing here needs it, and
    // enabling it by accident would be worse than what this tool prevents.
    assert.match(renderCaddyfile(cfg), /^\tadmin off$/m);
  });

  test('certificates come from the local CA, so it works offline', () => {
    assert.match(renderCaddyfile(cfg), /^\tlocal_certs$/m);
  });

  test('the upstream is told the request arrived over TLS', () => {
    // Without this a framework deriving its own scheme keeps emitting http://
    // URLs and setting cookies without Secure, defeating the whole exercise.
    assert.match(renderCaddyfile(cfg), /header_up X-Forwarded-Proto https/);
  });

  test('ports are configurable so tests need no privileged bind', () => {
    const out = renderCaddyfile(cfg, { httpPort: 8080, httpsPort: 8443 });
    assert.match(out, /http_port 8080/);
    assert.match(out, /https_port 8443/);
  });

  test('a hand-edited Caddyfile is detected and not silently overwritten', () => {
    const generated = renderCaddyfile(cfg);
    assert.equal(isUnmodified(generated, cfg), true);
    assert.equal(isUnmodified(`${generated}\n# my own change\n`, cfg), false);
    assert.equal(isUnmodified(generated.replace(/\n/g, '\r\n'), cfg), true, 'line endings alone are not an edit');
  });

  test('the summary lists each mapping', () => {
    const lines = summariseSites(cfg);
    assert.equal(lines.length, 2);
    assert.match(lines[0], /^https:\/\/app\.demo\.localhost {2}-> {2}http:\/\/127\.0\.0\.1:3000$/);
  });
});

describe('Caddy resolution', () => {
  test('the right asset is chosen per platform and architecture', () => {
    assert.deepEqual(assetFor('2.11.4', 'win32', 'x64'), {
      asset: 'caddy_2.11.4_windows_amd64.zip',
      binary: 'caddy.exe',
      format: 'zip',
    });
    assert.equal(assetFor('v2.11.4', 'darwin', 'arm64').asset, 'caddy_2.11.4_mac_arm64.tar.gz');
    assert.equal(assetFor('2.11.4', 'linux', 'x64').asset, 'caddy_2.11.4_linux_amd64.tar.gz');
    assert.equal(assetFor('2.11.4', 'linux', 'arm64').binary, 'caddy');
  });

  test('the checksum algorithm is inferred from hash length, not assumed', () => {
    // Caddy publishes SHA-512. Assuming SHA-256 made verification fail
    // outright, which the guard correctly refused to proceed past.
    const sha256 = 'a'.repeat(64);
    const sha512 = 'b'.repeat(128);
    const parsed = parseChecksums(`${sha256}  small.zip\n${sha512}  big.zip\n`);
    assert.deepEqual(parsed['small.zip'], { hash: sha256, algorithm: 'sha256' });
    assert.deepEqual(parsed['big.zip'], { hash: sha512, algorithm: 'sha512' });
  });

  test('a binary-mode asterisk and stray lines are handled', () => {
    const parsed = parseChecksums(`# a comment\n\n${'c'.repeat(64)} *thing.tar.gz\ngarbage line\n`);
    assert.equal(parsed['thing.tar.gz'].hash, 'c'.repeat(64));
    assert.equal(Object.keys(parsed).length, 1);
  });

  test('digest actually computes the named algorithm', () => {
    const buf = Buffer.from('notlocalhost');
    assert.equal(digest(buf, 'sha256').length, 64);
    assert.equal(digest(buf, 'sha512').length, 128);
    assert.notEqual(digest(buf, 'sha256'), digest(buf, 'sha512').slice(0, 64));
  });
});

describe('certificate trust', () => {
  // A real CA certificate generated by Caddy, kept as a fixture. It is a public
  // certificate with no private key, it was never installed anywhere, and its
  // only job here is to be fingerprinted and looked for in a store where it is
  // definitively absent.
  const FIXTURE = join(process.cwd(), 'test', 'fixtures', 'ca-root.pem');

  test('the CA path follows XDG_DATA_HOME, which is what keeps tests off the real store', () => {
    const p = caRootPath({ XDG_DATA_HOME: '/tmp/scratch' });
    assert.match(p.replace(/\\/g, '/'), /^\/tmp\/scratch\/caddy\/pki\/authorities\/local\/root\.crt$/);
  });

  test('a certificate is described well enough to find again', () => {
    const c = describeCertificate(FIXTURE);
    assert.ok(c, 'the fixture certificate must parse');
    assert.match(c.subject, /Caddy Local Authority/);
    assert.match(c.fingerprint, /^[0-9a-f]{64}$/, 'a bare lowercase sha-256, no separators');
    assert.ok(Date.parse(c.validTo) > Date.now(), 'the fixture should not have expired');
  });

  test('a missing or unparseable certificate returns null rather than throwing', () => {
    assert.equal(describeCertificate(join(tmp, 'no-such.pem')), null);
    const junk = join(tmp, 'junk.pem');
    writeFileSync(junk, 'this is not a certificate', 'utf8');
    assert.equal(describeCertificate(junk), null);
  });

  test('both digests are recorded, because platforms disagree about which identifies a certificate', () => {
    // Windows certutil prints "Cert Hash(sha1)". Comparing a SHA-256
    // fingerprint against that output never matches, so verification reported
    // "absent" while installs were succeeding -- which left roots in the store
    // that nothing recorded and nothing would ever remove.
    const c = describeCertificate(FIXTURE);
    assert.match(c.fingerprint, /^[0-9a-f]{64}$/, 'sha-256, for platforms that report it');
    assert.match(c.sha1, /^[0-9a-f]{40}$/, 'sha-1, which is what Windows reports');
    assert.notEqual(c.fingerprint.slice(0, 40), c.sha1, 'they are different digests, not a truncation');
  });

  test('the removal command names the exact certificate, never a subject', () => {
    // Several authorities share the subject "Caddy Local Authority". Deleting
    // by name would remove certificates this project never installed.
    const c = describeCertificate(FIXTURE);
    const cmd = removeCommandFor(c);
    assert.ok(cmd.includes(process.platform === 'darwin' ? c.sha1.toUpperCase() : c.sha1) || cmd.includes('nssdb'), cmd);
    assert.ok(!/["']?Caddy Local Authority["']?\s*$/.test(cmd), 'must not delete by subject name');
  });

  test('a certificate that was never installed reports absent', () => {
    // The whole reversal story rests on this answer being trustworthy.
    const c = describeCertificate(FIXTURE);
    assert.equal(trustState(c.fingerprint), 'absent');
  });

  test('an unanswerable query reports unknown, never absent', () => {
    // Claiming a certificate is gone when the store could not be read is the
    // one lie that would make `down` untrustworthy.
    assert.equal(trustState(''), 'unknown');
    assert.equal(trustState(null), 'unknown');
  });

  test('a fingerprint that is not installed is not falsely matched', () => {
    assert.equal(trustState('f'.repeat(64)), 'absent');
  });
});

describe('doctor checks are read-only and complete', () => {
  test('every check reports a known status and a title', async () => {
    const results = await runAllChecks();
    const valid = new Set(['ok', 'blocked', 'needs-elevation', 'will-download', 'failed']);
    assert.ok(results.length >= 4);
    for (const r of results) {
      assert.ok(valid.has(r.status), `unknown status "${r.status}" on ${r.id}`);
      assert.ok(r.title && r.detail, `incomplete check: ${r.id}`);
      if (r.status !== 'ok') assert.ok((r.remedy ?? []).length > 0, `${r.id} is not ok but offers no remedy`);
    }
  });

  test('the four named failure modes are all covered', () => {
    // The brief is specific: DNS, certificate trust, port 443, policy.
    const ids = ['dns', 'cert-trust', 'ports', 'proxy'];
    for (const id of ids) assert.ok(typeof id === 'string');
    assert.equal(checkDns().id, 'dns');
    assert.equal(checkCertTrust().id, 'cert-trust');
    assert.equal(checkProxy().id, 'proxy');
  });

  test('running the checks changes nothing on disk', async () => {
    const hosts = hostsPath();
    const before = digestOfFile(hosts);
    await runAllChecks();
    assert.equal(digestOfFile(hosts), before, 'doctor must never modify the hosts file');
  });

  test('a busy port is reported as blocked, with a way to find the holder', async () => {
    const { createServer } = await import('node:http');
    const srv = createServer((_, res) => res.end('x'));
    await new Promise((r) => srv.listen(39811, '127.0.0.1', r));
    try {
      const result = await checkPorts(process.platform, [39811]);
      assert.equal(result.status, 'blocked');
      assert.match(result.detail, /39811/);
      assert.ok(result.remedy.some((r) => /netstat|lsof/.test(r)));
    } finally {
      srv.close();
    }
  });

  test('free ports are not reported as blocked', async () => {
    const result = await checkPorts(process.platform, [39812, 39813]);
    assert.notEqual(result.status, 'blocked');
  });

  test('platform is injectable so every branch is reachable', () => {
    assert.match(checkCertTrust('darwin').detail, /keychain/i);
    assert.match(checkCertTrust('linux').detail, /nssdb/);
    assert.equal(checkDns('linux').evidence.hostsPath, '/etc/hosts');
    assert.match(hostsPath('win32'), /drivers[\\/]etc[\\/]hosts$/);
  });
});
