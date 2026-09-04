/**
 * Finding, fetching and verifying Caddy.
 *
 * Caddy does the two hard things this project refuses to reimplement: TLS
 * termination, and a local certificate authority. `tls internal` makes it
 * generate its own CA; `caddy trust` and `caddy untrust` install and remove
 * that CA from the platform trust store. Standing on that keeps the promise of
 * one runtime dependency, because authoring X.509 certificates in Node would
 * need a second one.
 *
 * Two rules govern everything here:
 *
 *   - A binary that is already installed is used as-is. Nothing is downloaded
 *     when the machine already has what it needs.
 *   - A binary that IS downloaded is verified against the published
 *     digest before it is ever executed. Downloading code and running it
 *     unverified is not something a security-adjacent tool gets to do.
 */
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, writeFileSync, statSync, chmodSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { platform, arch } from 'node:os';

const RELEASE_API = 'https://api.github.com/repos/caddyserver/caddy/releases/latest';

/** Where a downloaded Caddy lives: inside the project, never system-wide. */
export function caddyHome(cwd = process.cwd()) {
  return join(cwd, '.notlocalhost', 'caddy');
}

/**
 * The release asset for this machine.
 * @returns {{ asset: string, binary: string, format: 'zip'|'tar.gz' }}
 */
export function assetFor(version, os = platform(), cpu = arch()) {
  const goarch = { x64: 'amd64', arm64: 'arm64', arm: 'armv7', ppc64: 'ppc64le' }[cpu] ?? cpu;
  const v = String(version).replace(/^v/, '');

  if (os === 'win32') {
    return { asset: `caddy_${v}_windows_${goarch}.zip`, binary: 'caddy.exe', format: 'zip' };
  }
  const goos = os === 'darwin' ? 'mac' : os;
  return { asset: `caddy_${v}_${goos}_${goarch}.tar.gz`, binary: 'caddy', format: 'tar.gz' };
}

/**
 * Is a usable Caddy already on PATH?
 *
 * Deliberately does not require the binary to answer `version`. A binary that
 * will not answer a probe is still a binary, and letting a probe decide
 * whether something exists is a mistake that has already cost this project a
 * great deal of CI time.
 */
export function findInstalledCaddy() {
  const finder = platform() === 'win32' ? 'where' : 'which';
  try {
    const out = execFileSync(finder, ['caddy'], {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
      timeout: 5000,
      windowsHide: true,
    });
    const path = out.split(/\r?\n/).map((s) => s.trim()).find(Boolean);
    if (!path || !existsSync(path) || !statSync(path).isFile()) return null;
    return { path, source: 'PATH', version: caddyVersion(path) };
  } catch {
    return null;
  }
}

/** A previously downloaded copy, if this project already fetched one. */
export function findLocalCaddy(cwd = process.cwd()) {
  const dir = caddyHome(cwd);
  const bin = join(dir, platform() === 'win32' ? 'caddy.exe' : 'caddy');
  if (!existsSync(bin)) return null;
  return { path: bin, source: 'project', version: caddyVersion(bin) };
}

/** Best-effort version string. Never used to decide whether a binary exists. */
export function caddyVersion(path) {
  try {
    return execFileSync(path, ['version'], {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
      timeout: 8000,
      windowsHide: true,
    })
      .trim()
      .split('\n')[0];
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------- download

async function getJson(url) {
  const res = await fetch(url, { headers: { accept: 'application/vnd.github+json', 'user-agent': 'notlocalhost' } });
  if (!res.ok) throw new Error(`${url} returned ${res.status}`);
  return res.json();
}

/** Latest release metadata, reduced to what we need. */
export async function latestRelease() {
  const r = await getJson(RELEASE_API);
  return {
    version: r.tag_name,
    assets: Object.fromEntries((r.assets ?? []).map((a) => [a.name, a.browser_download_url])),
  };
}

/**
 * Parse the published checksums file into { filename: { hash, algorithm } }.
 *
 * The format is standard `shaNsum` output -- hash, whitespace, filename -- but
 * the digest is not always SHA-256. Caddy publishes SHA-512. Inferring the
 * algorithm from the hash length means a project that changes digest does not
 * silently start failing verification, and it removes an assumption that was
 * wrong the first time it met real data.
 */
export function parseChecksums(text) {
  const byLength = { 64: 'sha256', 96: 'sha384', 128: 'sha512' };
  const out = {};
  for (const line of String(text).split('\n')) {
    const m = line.trim().match(/^([0-9a-f]{64,128})\s+\*?(.+)$/i);
    if (!m) continue;
    const algorithm = byLength[m[1].length];
    if (!algorithm) continue;
    out[m[2].trim()] = { hash: m[1].toLowerCase(), algorithm };
  }
  return out;
}

export function digest(buffer, algorithm) {
  return createHash(algorithm).update(buffer).digest('hex');
}

/**
 * Download Caddy into the project and verify it before it is ever run.
 *
 * @param {object} [opts]
 * @param {string} [opts.cwd]
 * @param {(msg: string) => void} [opts.log]
 * @returns {Promise<{path: string, source: string, version: string|null, checksum: string, algorithm: string}>}
 */
export async function downloadCaddy(opts = {}) {
  const { cwd = process.cwd(), log = () => {} } = opts;

  const release = await latestRelease();
  const { asset, binary, format } = assetFor(release.version);

  const url = release.assets[asset];
  if (!url) {
    const err = new Error(
      `Caddy ${release.version} does not publish a build for this platform (${platform()}/${arch()}).\n` +
        `Looked for: ${asset}\n\n` +
        'Install Caddy yourself and it will be used as-is.',
    );
    err.code = 'NO_CADDY_BUILD';
    throw err;
  }

  const checksumsName = `caddy_${String(release.version).replace(/^v/, '')}_checksums.txt`;
  const checksumsUrl = release.assets[checksumsName];
  if (!checksumsUrl) {
    const err = new Error(
      `Caddy ${release.version} publishes no checksums file, so the download cannot be verified.\n` +
        'Refusing to execute an unverified binary. Install Caddy yourself instead.',
    );
    err.code = 'NO_CHECKSUMS';
    throw err;
  }

  log(`fetching ${asset} (${release.version})`);
  const [archive, checksumsText] = await Promise.all([
    fetch(url).then(async (r) => {
      if (!r.ok) throw new Error(`downloading ${asset} returned ${r.status}`);
      return Buffer.from(await r.arrayBuffer());
    }),
    fetch(checksumsUrl).then(async (r) => {
      if (!r.ok) throw new Error(`downloading ${checksumsName} returned ${r.status}`);
      return r.text();
    }),
  ]);

  const expected = parseChecksums(checksumsText)[asset];
  if (!expected) {
    const err = new Error(`${checksumsName} contains no entry for ${asset}. Refusing to run an unverified binary.`);
    err.code = 'CHECKSUM_MISSING';
    throw err;
  }

  const actual = digest(archive, expected.algorithm);
  if (actual !== expected.hash) {
    const err = new Error(
      `The downloaded ${asset} does not match its published checksum.\n\n` +
        `  algorithm ${expected.algorithm}\n  expected  ${expected.hash}\n  got       ${actual}\n\n` +
        'Nothing has been extracted or executed. This is either a corrupted download or\n' +
        'something worse; either way it is not going to be run.',
    );
    err.code = 'CHECKSUM_MISMATCH';
    throw err;
  }
  log(`checksum verified (${expected.algorithm} ${actual.slice(0, 16)}...)`);

  const dir = caddyHome(cwd);
  mkdirSync(dir, { recursive: true });
  const archivePath = join(dir, asset);
  writeFileSync(archivePath, archive);

  try {
    extract(archivePath, dir, format);
  } finally {
    rmSync(archivePath, { force: true });
  }

  const binPath = join(dir, binary);
  if (!existsSync(binPath)) {
    throw new Error(`Extracted ${asset} but found no ${binary} in ${dir}.`);
  }
  if (platform() !== 'win32') chmodSync(binPath, 0o755);

  return { path: binPath, source: 'downloaded', version: caddyVersion(binPath), checksum: actual, algorithm: expected.algorithm };
}

/**
 * Extract without adding a dependency.
 *
 * `tar` handles both formats and ships with Windows 10 build 17063 and later,
 * as well as every macOS and Linux worth supporting. PowerShell's
 * Expand-Archive is the fallback for older Windows.
 */
function extract(archivePath, dir, format) {
  try {
    execFileSync('tar', ['-xf', archivePath, '-C', dir], { stdio: 'ignore', timeout: 120_000, windowsHide: true });
    return;
  } catch (err) {
    if (platform() !== 'win32' || format !== 'zip') throw err;
  }
  execFileSync(
    'powershell',
    ['-NoProfile', '-NonInteractive', '-Command', `Expand-Archive -LiteralPath '${archivePath}' -DestinationPath '${dir}' -Force`],
    { stdio: 'ignore', timeout: 120_000, windowsHide: true },
  );
}

/**
 * Locate Caddy, fetching it only if the machine does not already have one.
 * @param {{ cwd?: string, allowDownload?: boolean, log?: (m: string) => void }} [opts]
 */
export async function resolveCaddy(opts = {}) {
  const { cwd = process.cwd(), allowDownload = true, log = () => {} } = opts;

  const installed = findInstalledCaddy();
  if (installed) {
    log(`using the Caddy already on PATH: ${installed.path}`);
    return installed;
  }

  const local = findLocalCaddy(cwd);
  if (local) {
    log(`using the Caddy in this project: ${local.path}`);
    return local;
  }

  if (!allowDownload) {
    const err = new Error('No Caddy found, and downloading is disabled.');
    err.code = 'NO_CADDY';
    throw err;
  }

  return downloadCaddy({ cwd, log });
}
