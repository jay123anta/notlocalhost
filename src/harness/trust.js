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
 * Caddy generates and installs the CA (`caddy trust` / `caddy untrust`), so no
 * X.509 authoring happens here -- that would cost a second runtime dependency.
 * Node reads certificates natively via crypto.X509Certificate, which is enough
 * to fingerprint one.
 */
import { X509Certificate } from 'node:crypto';
import { execFile, execFileSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
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
 * @returns {'present'|'absent'|'unknown'}
 */
export function trustState(fingerprint, sha1 = null) {
  if (!fingerprint) return 'unknown';
  const normalise = (s) => String(s).replace(/[\s:]/g, '').toLowerCase();

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
      return normalise(out).includes(needle) ? 'present' : 'absent';
    }

    if (OS === 'darwin') {
      const out = execFileSync(
        'security',
        ['find-certificate', '-a', '-Z', '/Library/Keychains/System.keychain'],
        { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'], timeout: 20_000 },
      );
      return normalise(out).includes(fingerprint) ? 'present' : 'absent';
    }

    // Linux: Chrome reads its own NSS database, which needs no root.
    const nssdb = join(homedir(), '.pki', 'nssdb');
    if (!existsSync(nssdb)) return 'absent';
    const out = execFileSync('certutil', ['-L', '-d', `sql:${nssdb}`], {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
      timeout: 20_000,
    });
    // NSS lists nicknames rather than fingerprints, so match the one we install
    // under. The constant is shared with the installer so they cannot drift.
    return out.includes(NSS_NICKNAME) ? 'present' : 'absent';
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
        remedyForTrustFailure(String(err?.stderr ?? err?.message ?? '')),
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
async function installRoot(certPath) {
  if (OS === 'win32') {
    // -user writes the current account's store, which Chrome and Edge read and
    // which needs no elevation.
    return run('certutil', ['-user', '-addstore', '-f', 'Root', certPath], { timeout: 120_000, windowsHide: true });
  }

  if (OS === 'darwin') {
    return run(
      'sudo',
      ['security', 'add-trusted-cert', '-d', '-r', 'trustRoot', '-k', '/Library/Keychains/System.keychain', certPath],
      { timeout: 120_000 },
    );
  }

  // Linux: Chrome reads ~/.pki/nssdb and needs no root for it.
  const nssdb = join(homedir(), '.pki', 'nssdb');
  await run('mkdir', ['-p', nssdb], { timeout: 20_000 }).catch(() => {});
  return run(
    'certutil',
    ['-d', `sql:${nssdb}`, '-A', '-t', 'C,,', '-n', NSS_NICKNAME, '-i', certPath],
    { timeout: 120_000 },
  );
}

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
            OS === 'win32'
              ? `Remove it by hand:  certutil -user -delstore Root ${fingerprint?.slice(0, 16) ?? '<thumbprint>'}`
              : OS === 'darwin'
                ? 'Remove it by hand: open Keychain Access, search for "Caddy Local Authority", and delete it.'
                : 'Remove it by hand:  certutil -D -d sql:$HOME/.pki/nssdb -n "Caddy Local Authority"',
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
  if (OS === 'win32') {
    // By thumbprint, not by name. Several authorities can share a subject, and
    // deleting by name would remove certificates this project never installed.
    const id = typeof cert === 'string' ? cert : cert?.sha1;
    if (!id) throw new Error('no thumbprint recorded, so the exact certificate cannot be identified');
    return run('certutil', ['-user', '-delstore', 'Root', id], { timeout: 120_000, windowsHide: true });
  }
  if (OS === 'darwin') {
    return run('sudo', ['security', 'delete-certificate', '-c', 'Caddy Local Authority', '-t'], { timeout: 120_000 });
  }
  const nssdb = join(homedir(), '.pki', 'nssdb');
  return run('certutil', ['-d', `sql:${nssdb}`, '-D', '-n', NSS_NICKNAME], { timeout: 120_000 });
}

/** The exact command to remove one certificate, for when we could not. */
export function removeCommandFor(cert) {
  if (OS === 'win32') return `certutil -user -delstore Root ${cert?.sha1 ?? '<thumbprint>'}`;
  if (OS === 'darwin') return `sudo security delete-certificate -Z ${cert?.sha1?.toUpperCase() ?? '<thumbprint>'}`;
  return `certutil -d sql:$HOME/.pki/nssdb -D -n "${NSS_NICKNAME}"`;
}

function firstLines(err) {
  const text = String(err?.stderr || err?.stdout || err?.message || err);
  return text.split('\n').filter((l) => l.trim()).slice(0, 4).join('\n');
}

/**
 * Trust failures are nearly always one of three things, and each has a
 * different answer. Guessing wrongly sends people to the wrong place.
 */
function remedyForTrustFailure(stderr) {
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
