/**
 * Certificate trust: installing a local CA, and proving it was removed.
 *
 * This is the single most consequential thing the harness does. A trusted root
 * can sign a certificate for any hostname, so putting one in a trust store is
 * not an implementation detail to be done quietly. Three rules follow:
 *
 *   - Nothing is trusted without the caller having said so explicitly. This
 *     module exposes the capability; consent belongs to the command above it.
 *   - The certificate's fingerprint is recorded before installation, so removal
 *     can be verified against the exact certificate rather than a name that
 *     several CAs might share.
 *   - Removal is checked, not assumed. `down` reports whether the store still
 *     contains the fingerprint, and says so plainly when it does.
 *
 * Caddy generates the CA, so no X.509 authoring happens here -- that would cost
 * a second runtime dependency. Node reads certificates natively via
 * crypto.X509Certificate, which is enough to fingerprint one.
 *
 * Installing it is done here rather than by `caddy trust`, which reaches the
 * authority through Caddy's admin API. The generated Caddyfile disables that
 * API deliberately, because it is an unauthenticated control socket. Reading
 * the root off disk keeps the hardening and makes the step verifiable.
 */
import { X509Certificate } from 'node:crypto';
import { execFile, execFileSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { join, posix } from 'node:path';
import { platform, homedir } from 'node:os';
import { promisify } from 'node:util';

const run = promisify(execFile);
const OS = platform();

/**
 * Where Caddy keeps the root it generated.
 *
 * Caddy follows the platform data-directory convention, and honours XDG_DATA_HOME
 * everywhere -- which is what lets a test point it at a scratch directory and
 * never touch the real one.
 */
export function caRootPath(env = process.env) {
  const explicit = env.XDG_DATA_HOME;
  const base =
    explicit ??
    (OS === 'win32'
      ? env.APPDATA ?? join(homedir(), 'AppData', 'Roaming')
      : OS === 'darwin'
        ? join(homedir(), 'Library', 'Application Support')
        : join(homedir(), '.local', 'share'));
  return join(base, 'caddy', 'pki', 'authorities', 'local', 'root.crt');
}

/**
 * Read a certificate and describe it well enough to find again.
 * @returns {{ fingerprint: string, subject: string, validTo: string, path: string }|null}
 */
export function describeCertificate(path) {
  if (!existsSync(path)) return null;
  try {
    const cert = new X509Certificate(readFileSync(path));
    return {
      path,
      // Both digests, because platforms disagree about which one identifies a
      // certificate. Windows certutil prints "Cert Hash(sha1)"; comparing a
      // SHA-256 fingerprint against that output never matches, so every
      // verification reported "absent" while the install had actually
      // succeeded -- which left roots installed that nothing recorded.
      fingerprint: cert.fingerprint256.replace(/:/g, '').toLowerCase(),
      sha1: cert.fingerprint.replace(/:/g, '').toLowerCase(),
      subject: cert.subject.replace(/\n/g, ', '),
      validTo: cert.validTo,
    };
  } catch {
    return null;
  }
}

/**
 * Is a certificate with this fingerprint in the platform trust store?
 *
 * Each platform is asked in its own terms. A query that fails to run returns
 * `unknown` rather than `false`: claiming a certificate is absent when we could
 * not look is exactly the lie that would make `down` untrustworthy.
 *
 * @param {string} fingerprint  SHA-256, lowercase hex, no separators.
/**
 * Every certificate digest a tool printed, one per line, normalised.
 *
 * Matching a digest against the whole dump as one string can match across the
 * boundary between two fields once whitespace is stripped, which would report a
 * certificate as present that is not there -- and `down` would then say it
 * failed to remove something it had already removed. Reading digests as values
 * rather than as substrings removes the question.
 */
export function digestsIn(text) {
  const found = new Set();
  for (const line of String(text).split('\n')) {
    const compact = line.replace(/[\s:]/g, '').toLowerCase();
    for (const [hex] of compact.matchAll(/[0-9a-f]{40,64}/g)) {
      if (hex.length === 40 || hex.length === 64) found.add(hex);
    }
  }
  return found;
}

export function trustState(fingerprint, sha1 = null) {
  if (!fingerprint) return 'unknown';

  try {
    if (OS === 'win32') {
      // The per-user store is the one that matters: Chrome and Edge read it,
      // and writing to it needs no administrator rights.
      const out = execFileSync('certutil', ['-user', '-store', 'Root'], {
        encoding: 'utf8',
        stdio: ['ignore', 'pipe', 'ignore'],
        timeout: 20_000,
        windowsHide: true,
      });
      // certutil -store reports "Cert Hash(sha1)", so SHA-1 is what can be
      // matched here. Falling back to the SHA-256 value would silently never
      // match, which is worse than not looking at all.
      const needle = sha1 ?? fingerprint;
      return digestsIn(out).has(needle) ? 'present' : 'absent';
    }

    if (OS === 'darwin') {
      const out = execFileSync(
        'security',
        ['find-certificate', '-a', '-Z', MACOS_KEYCHAIN],
        { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'], timeout: 20_000 },
      );
      const seen = digestsIn(out);
      return seen.has(fingerprint) || (sha1 && seen.has(sha1)) ? 'present' : 'absent';
    }

    // Linux: Chrome reads its own NSS database, which needs no root.
    const nssdb = join(homedir(), '.pki', 'nssdb');
    if (!existsSync(nssdb)) return 'absent';

    const list = execFileSync('certutil', ['-L', '-d', `sql:${nssdb}`], {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
      timeout: 20_000,
    });
    if (!list.includes(NSS_NICKNAME)) return 'absent';

    // The nickname says something is installed under our name; it does not say
    // it is our certificate. Read it back and compare the fingerprint, or a
    // stale root from an earlier run would report a certificate as trusted that
    // was never added -- and TLS would then fail with nothing to explain it.
    const pem = execFileSync('certutil', ['-L', '-d', `sql:${nssdb}`, '-n', NSS_NICKNAME, '-a'], {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
      timeout: 20_000,
    });
    const actual = new X509Certificate(pem).fingerprint256.replace(/:/g, '').toLowerCase();
    return actual === fingerprint ? 'present' : 'absent';
  } catch {
    return 'unknown';
  }
}

/**
 * Install the CA into the platform trust store.
 *
 * The caller must already have obtained consent. This deliberately does not
 * prompt: a function that both asks and acts makes it impossible to test the
 * asking, and easy to call the acting by accident.
 *
 * @param {object} opts
 * @param {string} opts.caddyPath
 * @param {Record<string,string>} [opts.env]
 * @param {(m: string) => void} [opts.log]
 */
export async function trustCa({ env = process.env, log = () => {}, certPath = caRootPath(env) } = {}) {
  // Deliberately not `caddy trust`. That command fetches the authority through
  // Caddy's admin API, and the generated Caddyfile turns the admin API off --
  // it is an unauthenticated control socket that nothing here needs. Installing
  // the root directly keeps that hardening and makes the step verifiable: we
  // know exactly which certificate went in, so we can prove it came out.
  const cert = describeCertificate(certPath);
  if (!cert) {
    const e = new Error(
      `No root certificate at ${certPath}.\n\n` +
        'Caddy creates it the first time it serves TLS, so the proxy has to be running before\n' +
        'the authority exists to install.',
    );
    e.code = 'NO_CA';
    throw e;
  }

  log(`installing the local certificate authority (${cert.fingerprint.slice(0, 16)}...)`);
  try {
    await installRoot(certPath);
  } catch (err) {
    const e = new Error(
      `Could not install the certificate authority.\n\n${firstLines(err)}\n\n` +
        // Both, joined. `??` kept an empty stderr -- which execFile sets on a
        // spawn failure -- so the message naming the missing program never
        // reached the code whose job is to explain it. The two carry different
        // halves of the story and neither is reliably the useful one.
        remedyForTrustFailure([err?.stderr, err?.message].filter(Boolean).join(' ')),
    );
    e.code = 'TRUST_FAILED';
    throw e;
  }

  const state = trustState(cert.fingerprint, cert.sha1);
  if (state === 'absent') {
    // The install claimed success and the store disagrees, so something is in
    // an unknown state. Undo it rather than leave a root behind that nothing
    // recorded and therefore nothing will ever remove. Refusing to record it
    // without also removing it is exactly how a machine accumulates orphans.
    let rolledBack = false;
    try {
      await removeRoot(cert);
      rolledBack = trustState(cert.fingerprint, cert.sha1) !== 'present';
    } catch {
      /* reported in the message below */
    }

    const e = new Error(
      'The install command reported success but the certificate is not in the trust store.\n\n' +
        (rolledBack
          ? 'It has been removed again, so nothing was left behind.'
          : 'It could NOT be removed again, so a certificate may be installed that nothing is\n' +
            `tracking. Remove it by hand:\n\n  ${removeCommandFor(cert)}`),
    );
    e.code = 'TRUST_FAILED';
    e.certificate = cert;
    throw e;
  }

  log(`certificate authority installed, store reports ${state}`);
  return { ...cert, trustedAt: new Date().toISOString(), verified: state };
}

/**
 * Add a root to the platform trust store.
 *
 * Each platform in its own terms, and each chosen to need as little privilege
 * as it can: the per-user store on Windows, Chrome's own NSS database on Linux.
 * macOS has no per-user equivalent that browsers honour, so it prompts.
 */
/**
 * The exact command each platform needs, as data rather than as control flow.
 *
 * Separated so it can be tested from any machine. The one bug this module has
 * had twice -- addressing a certificate by a subject that every Caddy on the
 * machine shares -- lives entirely in command construction, and could not be
 * caught from a different OS while the commands were built inline behind a
 * platform check. There is no Mac here, and there will not always be one.
 *
 * @param {'win32'|'darwin'|string} os
 * @returns {{ command: string, args: string[], opts?: object }}
 */
export function installCommand(os, certPath, home = homedir()) {
  if (os === 'win32') {
    // -user writes the current account's store, which Chrome and Edge read and
    // which needs no elevation.
    return { command: 'certutil', args: ['-user', '-addstore', '-f', 'Root', certPath], opts: { windowsHide: true } };
  }
  if (os === 'darwin') {
    return {
      command: 'sudo',
      args: ['security', 'add-trusted-cert', '-d', '-r', 'trustRoot', '-k', MACOS_KEYCHAIN, certPath],
    };
  }
  // Linux: Chrome reads ~/.pki/nssdb and needs no root for it.
  return {
    command: 'certutil',
    args: ['-d', `sql:${nssdbPath(home)}`, '-A', '-t', 'C,,', '-n', NSS_NICKNAME, '-i', certPath],
  };
}

/**
 * @param {'win32'|'darwin'|string} os
 * @param {{ sha1?: string }|string} cert
 */
export function removalCommand(os, cert, home = homedir()) {
  const sha1 = typeof cert === 'string' ? cert : cert?.sha1;
  if (os === 'win32') {
    if (!sha1) throw new Error('no thumbprint recorded, so the exact certificate cannot be identified');
    return { command: 'certutil', args: ['-user', '-delstore', 'Root', sha1], opts: { windowsHide: true } };
  }
  if (os === 'darwin') {
    // By hash, never by common name. "Caddy Local Authority" is the subject of
    // every Caddy authority on the machine, including ones this project never
    // installed, so -c would delete somebody else's root and report success.
    if (!sha1) throw new Error('no SHA-1 recorded, so the exact certificate cannot be identified');
    // Name the keychain, because the install named it.
    //
    // `security delete-certificate` with no keychain searches the user's
    // default search list, which does not include the system keychain the
    // certificate was added to. Without it removal finds nothing, reports
    // success, and leaves the root installed -- so the store ends with one
    // more certificate than it started with.
    return {
      command: 'sudo',
      args: ['security', 'delete-certificate', '-Z', sha1.toUpperCase(), '-t', MACOS_KEYCHAIN],
    };
  }
  return { command: 'certutil', args: ['-d', `sql:${nssdbPath(home)}`, '-D', '-n', NSS_NICKNAME] };
}

/**
 * Everything a failed command knows about itself.
 *
 * An exit status is often the only thing that distinguishes "denied" from
 * "not found" from "refused by policy", and it was being dropped: a Windows
 * runner reported a failure whose entire text was the command line, because
 * certutil wrote nothing to stderr and the status went unread.
 */
function describeFailure(err) {
  const parts = [];
  if (err?.status !== undefined && err.status !== null) parts.push(`exit ${err.status}`);
  else if (err?.code !== undefined) parts.push(`code ${err.code}`);
  const text = [err?.stderr, err?.stdout].filter(Boolean).join('\n').trim();
  if (text) parts.push(text);
  else if (err?.message) parts.push(err.message);
  return parts.join(': ');
}

async function installRoot(certPath) {
  if (OS !== 'win32' && OS !== 'darwin') {
    // The database directory has to exist before certutil will add to it, but
    // creating it first meant a machine without NSS tools -- where the install
    // cannot succeed at all -- was left with a new empty directory in the
    // user's home that nothing would ever remove. `up` failing is not a reason
    // to leave something behind.
    try {
      await run('certutil', ['-H'], { timeout: 20_000 });
    } catch (err) {
      if (err?.code === 'ENOENT') throw err;
      // Any other failure means certutil is present; -H exits non-zero by design.
    }
    await run('mkdir', ['-p', join(homedir(), '.pki', 'nssdb')], { timeout: 20_000 }).catch(() => {});
  }

  const { command, args, opts } = installCommand(OS, certPath);
  try {
    return await run(command, args, { timeout: 120_000, ...(opts ?? {}) });
  } catch (err) {
    if (OS !== 'win32') throw err;

    // Windows has a second way in, and the two fail differently.
    //
    // certutil writes its own diagnostics to stdout and can exit non-zero
    // having printed nothing that explains it -- which is what a hosted runner
    // produced, leaving a failure whose only text was the command line.
    // Import-Certificate is the documented route for a non-interactive
    // session and reports a real error when it refuses.
    try {
      await run(
        'powershell',
        [
          '-NoProfile',
          '-NonInteractive',
          '-Command',
          '$ErrorActionPreference = "Stop"; Import-Certificate -FilePath $env:NLH_CERT -CertStoreLocation Cert:\CurrentUser\Root | Out-Null',
        ],
        { timeout: 120_000, windowsHide: true, env: { ...process.env, NLH_CERT: certPath } },
      );
      return { stdout: '', stderr: '' };
    } catch (second) {
      const e = new Error(
        `certutil and Import-Certificate both refused.\n  certutil: ${describeFailure(err)}\n  powershell: ${describeFailure(second)}`,
      );
      e.stderr = '';
      throw e;
    }
  }
}

/**
 * Where Chrome keeps its own certificate database.
 *
 * Always POSIX: this database exists only on Linux, so joining with the host
 * separator is wrong whenever the command is built anywhere else -- which is
 * exactly what testing it from another machine does.
 */
function nssdbPath(home) {
  return posix.join(home.replace(/\\/g, '/'), '.pki', 'nssdb');
}

/**
 * The keychain macOS trust is added to, removed from, and queried in.
 *
 * One constant for all three, because they were three separate literals and
 * the removal quietly stopped naming it -- which is how a certificate came to
 * be added to one store and searched for in another.
 */
const MACOS_KEYCHAIN = '/Library/Keychains/System.keychain';

/** The nickname the Linux trust check looks for, so the two cannot drift. */
const NSS_NICKNAME = 'notlocalhost local authority';

/**
 * Remove the CA, and report honestly whether it is gone.
 *
 * Returns rather than throws when the store still holds it: `down` has other
 * things to undo, and abandoning them because one step failed leaves more
 * behind than continuing and saying so.
 */
export async function untrustCa({ fingerprint, certificate, env = process.env, log = () => {} } = {}) {
  log('removing the local certificate authority');
  let error = null;
  try {
    await removeRoot(certificate ?? fingerprint);
  } catch (err) {
    error = firstLines(err);
  }

  const state = fingerprint ? trustState(fingerprint, certificate?.sha1) : 'unknown';

  return {
    removed: state === 'absent',
    state,
    error,
    advice:
      state === 'present'
        ? [
            'The certificate is still in the trust store.',
            // One source for this command. The copy that used to live here passed a
            // truncated SHA-256 to a tool that matches SHA-1, so the instruction
            // shown at the exact moment automated removal had failed was one that
            // could never work.
            `Remove it by hand:  ${removeCommandFor(certificate)}`,
          ]
        : state === 'unknown'
          ? ['The trust store could not be queried, so removal could not be confirmed. Check it by hand before assuming it is gone.']
          : [],
  };
}

/**
 * Remove the root, in the same store it was added to.
 *
 * Windows deletes by SHA-1 thumbprint, which certutil accepts; macOS deletes by
 * the certificate file; NSS deletes by nickname. Each is addressed the way that
 * platform addresses certificates, rather than by a name several could share.
 */
async function removeRoot(cert) {
  // macOS holds a certificate in two places, and deleting one leaves the other.
  //
  // `add-trusted-cert -d` writes the certificate into the system keychain and
  // a trust setting into the admin trust domain. `delete-certificate` removes
  // certificates; it does not own the trust settings, and with one still
  // referring to the certificate the delete is refused. So the setting comes
  // off first, using the certificate file the ledger recorded, and only then
  // is the certificate itself removed.
  if (OS === 'darwin') {
    const attempts = [];
    const certPath = typeof cert === 'string' ? null : cert?.path;

    if (certPath && existsSync(certPath)) {
      try {
        await run('sudo', ['security', 'remove-trusted-cert', '-d', certPath], { timeout: 120_000 });
      } catch (err) {
        // Not fatal on its own: the setting may already be gone, and the
        // delete below is what actually decides the outcome.
        attempts.push(`remove-trusted-cert: ${describeFailure(err)}`);
      }
    } else {
      attempts.push('remove-trusted-cert: skipped, the certificate file is no longer on disk');
    }

    const { command, args } = removalCommand(OS, cert);
    try {
      return await run(command, args, { timeout: 120_000 });
    } catch (err) {
      attempts.push(`delete-certificate: ${describeFailure(err)}`);
      throw new Error(attempts.join('\n  '));
    }
  }

  const { command, args, opts } = removalCommand(OS, cert);
  try {
    return await run(command, args, { timeout: 120_000, ...(opts ?? {}) });
  } catch (err) {
    throw new Error(describeFailure(err));
  }
}

/** The exact command to remove one certificate, for when we could not. */
export function removeCommandFor(cert) {
  if (OS === 'win32') return `certutil -user -delstore Root ${cert?.sha1 ?? '<thumbprint>'}`;
  if (OS === 'darwin') {
    // Names the keychain, because the removal that actually runs names it.
    // This is the command a person is told to type when automatic removal
    // failed, so it being subtly different from the real one is the worst
    // possible time for the two to disagree.
    return `sudo security delete-certificate -Z ${cert?.sha1?.toUpperCase() ?? '<thumbprint>'} -t ${MACOS_KEYCHAIN}`;
  }
  return `certutil -d sql:$HOME/.pki/nssdb -D -n "${NSS_NICKNAME}"`;
}

function firstLines(err) {
  const text = [err?.stderr, err?.stdout, err?.message].filter(Boolean).join('\n') || String(err);
  const lines = text.split('\n').map((l) => l.trimEnd()).filter((l) => l.trim());
  if (lines.length <= 8) return lines.join('\n');
  // Both ends. certutil narrates what it is doing and reports the failure at
  // the very end, so the first few lines are the part that looks like success
  // -- which is exactly what a Windows CI failure showed, and all it showed.
  return [...lines.slice(0, 4), `  ... ${lines.length - 8} more lines ...`, ...lines.slice(-4)].join('\n');
}

/**
 * Trust failures are nearly always one of three things, and each has a
 * different answer. Guessing wrongly sends people to the wrong place.
 */
export function remedyForTrustFailure(stderr) {
  // The most common Linux failure by a distance, and "spawn certutil ENOENT"
  // names a program the user has never heard of rather than the package that
  // provides it. Chrome's trust store is an NSS database and this is the only
  // tool that writes it.
  if (/ENOENT/.test(stderr) && OS !== 'win32' && OS !== 'darwin') {
    return [
      'The certutil that manages the Chrome certificate store is not installed.',
      'It ships separately from the browser:',
      '',
      '  Debian, Ubuntu   sudo apt install libnss3-tools',
      '  Fedora, RHEL     sudo dnf install nss-tools',
      '  Arch             sudo pacman -S nss',
      '',
      'The harness still serves HTTPS without it; the browser will warn on each new hostname.',
    ].join(String.fromCharCode(10));
  }
  if (/denied|not permitted|EPERM|administrator/i.test(stderr)) {
    return OS === 'win32'
      ? 'Access was denied. On Windows the per-user store normally needs no elevation, so this\nusually means group policy is restricting it. Run `notlocalhost doctor`, which names that case.'
      : 'Permission was refused. Installing a root certificate needs your password on this platform.';
  }
  if (/policy|ProtectedRoots/i.test(stderr)) {
    return 'Group policy forbids adding a root certificate. This cannot be worked around locally;\nsomeone who manages the machine has to allow a development CA.';
  }
  return 'Run `notlocalhost doctor` for a per-platform diagnosis of certificate trust.';
}
