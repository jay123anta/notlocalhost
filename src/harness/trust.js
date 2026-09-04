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
      fingerprint: cert.fingerprint256.replace(/:/g, '').toLowerCase(),
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
export function trustState(fingerprint) {
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
      return normalise(out).includes(fingerprint) ? 'present' : 'absent';
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
    // NSS lists nicknames rather than fingerprints, so match on Caddy's.
    return /Caddy Local Authority/i.test(out) ? 'present' : 'absent';
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
export async function trustCa({ caddyPath, env = process.env, log = () => {} }) {
  const before = describeCertificate(caRootPath(env));

  log('installing the local certificate authority');
  try {
    await run(caddyPath, ['trust'], { env, timeout: 120_000, windowsHide: true });
  } catch (err) {
    const e = new Error(
      `Could not install the certificate authority.\n\n${firstLines(err)}\n\n` +
        remedyForTrustFailure(String(err?.stderr ?? err?.message ?? '')),
    );
    e.code = 'TRUST_FAILED';
    throw e;
  }

  // Caddy creates the root on first use, so read it after rather than before.
  const cert = describeCertificate(caRootPath(env)) ?? before;
  if (!cert) {
    const e = new Error(`Caddy reported success but no root certificate was found at ${caRootPath(env)}.`);
    e.code = 'TRUST_FAILED';
    throw e;
  }

  const state = trustState(cert.fingerprint);
  log(`certificate authority installed (${cert.fingerprint.slice(0, 16)}...), store reports ${state}`);
  return { ...cert, trustedAt: new Date().toISOString(), verified: state };
}

/**
 * Remove the CA, and report honestly whether it is gone.
 *
 * Returns rather than throws when the store still holds it: `down` has other
 * things to undo, and abandoning them because one step failed leaves more
 * behind than continuing and saying so.
 */
export async function untrustCa({ caddyPath, fingerprint, env = process.env, log = () => {} }) {
  log('removing the local certificate authority');
  let error = null;
  try {
    await run(caddyPath, ['untrust'], { env, timeout: 120_000, windowsHide: true });
  } catch (err) {
    error = firstLines(err);
  }

  const state = fingerprint ? trustState(fingerprint) : 'unknown';

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
