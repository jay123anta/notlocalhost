/**
 * The four things that break, diagnosed by name.
 *
 * When a local HTTPS setup fails it fails in one of four places: DNS,
 * certificate trust, a port that is already bound, or an organisation policy
 * that forbids installing a CA. Everything else is a variation on those.
 *
 * Each check answers three questions and nothing else: what is true right now,
 * whether that blocks us, and what to do about it. A check never changes
 * anything -- `doctor` must be safe to run on a machine you are frightened of,
 * because that is exactly the machine people run it on.
 */
import { existsSync, statSync, openSync, closeSync, constants } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { platform, homedir } from 'node:os';
import { join } from 'node:path';
import net from 'node:net';

/**
 * @typedef {object} CheckResult
 * @property {string} id          Stable identifier, greppable.
 * @property {string} title
 * @property {'ok'|'blocked'|'needs-elevation'|'will-download'|'failed'} status
 * @property {string} detail      What is actually true, in one or two sentences.
 * @property {string[]} [remedy]  What to do. Empty when status is 'ok'.
 * @property {Record<string, unknown>} [evidence]
 */

const OS = platform();

/** Where the hosts file lives on each platform. */
export function hostsPath(os = OS) {
  return os === 'win32'
    ? join(process.env.SystemRoot || 'C:\\Windows', 'System32', 'drivers', 'etc', 'hosts')
    : '/etc/hosts';
}

// ---------------------------------------------------------------------- DNS

/**
 * Can we get a hostname to resolve to loopback, and at what cost?
 *
 * Three strategies, cheapest first. `.localhost` is free and needs no
 * permission at all, because RFC 6761 reserves the name and browsers resolve
 * it without asking a resolver. It is the right default for anyone who does
 * not need a parent-domain cookie scope.
 */
export function checkDns(os = OS) {
  const path = hostsPath(os);
  const exists = existsSync(path);
  const writable = exists && canWrite(path);

  return {
    id: 'dns',
    title: 'Name resolution',
    status: 'ok',
    detail:
      'Hostnames under .localhost resolve to loopback with no configuration, because RFC 6761 ' +
      'reserves the name and browsers resolve it internally. That covers everything except a ' +
      'parent-domain cookie scope, which needs a real registrable domain and therefore a hosts entry.',
    remedy: writable
      ? []
      : [
          `A .test domain needs a line in ${path}, which this account cannot write.`,
          os === 'win32'
            ? 'That means one elevation prompt, once, at init time.'
            : 'That means one sudo prompt, once, at init time.',
          'Everything except parent-domain cookie scoping works without it.',
        ],
    evidence: { hostsPath: path, hostsExists: exists, hostsWritable: writable },
  };
}

// ------------------------------------------------------------ certificate trust

/**
 * Can a locally-generated CA be trusted, and does it need administrator rights?
 *
 * On Windows the per-user root store is writable without elevation and Chrome
 * honours it, which means the whole HTTPS story can work with no admin rights
 * at all. That is worth knowing before asking anyone for a password.
 */
export function checkCertTrust(os = OS) {
  if (os === 'win32') {
    const policy = readProtectedRootsPolicy();
    if (policy.blocked) {
      return {
        id: 'cert-trust',
        title: 'Certificate trust',
        status: 'blocked',
        detail:
          'Group policy sets ProtectedRoots, which prevents adding a root certificate to the trust ' +
          'store. This is a managed-machine setting and it cannot be worked around locally.',
        remedy: [
          'Ask whoever manages this machine to allow a development root CA, or to supply one.',
          'Without trust, HTTPS still works but the browser shows an interstitial on every page.',
        ],
        evidence: policy,
      };
    }
    return {
      id: 'cert-trust',
      title: 'Certificate trust',
      status: 'ok',
      detail:
        'The per-user root store (Cert:\\CurrentUser\\Root) is writable without administrator rights, ' +
        'and Chrome, Edge and anything else using the Windows certificate store honour it. No elevation ' +
        'is needed to trust a development CA.',
      remedy: [],
      evidence: policy,
    };
  }

  if (os === 'darwin') {
    return {
      id: 'cert-trust',
      title: 'Certificate trust',
      status: 'needs-elevation',
      detail:
        'macOS keeps trust settings in the system keychain. Adding a root CA prompts for your password ' +
        'once. Firefox keeps its own store and needs separate handling.',
      remedy: ['One password prompt at init time. Nothing is installed until you accept it.'],
      evidence: { store: 'System keychain' },
    };
  }

  const nssdb = join(homedir(), '.pki', 'nssdb');
  return {
    id: 'cert-trust',
    title: 'Certificate trust',
    status: 'needs-elevation',
    detail:
      'Linux splits trust in two. The system bundle under /usr/local/share/ca-certificates needs root, ' +
      'and Chrome additionally reads its own NSS database in ~/.pki/nssdb, which does not.',
    remedy: [
      'Chrome-only trust needs no root: certutil writes to ~/.pki/nssdb.',
      'System-wide trust needs one sudo at init time.',
      existsSync(nssdb) ? `NSS database found at ${nssdb}.` : `No NSS database yet at ${nssdb}; it will be created.`,
    ],
    evidence: { nssdb, nssdbExists: existsSync(nssdb), hasCertutil: hasBinary('certutil') },
  };
}

// ------------------------------------------------------------------- ports

/**
 * Is anything already holding the ports a local HTTPS proxy needs?
 *
 * Binding 443 needs elevation on Linux and macOS but not on Windows, which is
 * the reverse of most people's expectations, so the check says which applies.
 */
export async function checkPorts(os = OS, ports = [80, 443]) {
  const results = [];
  for (const port of ports) {
    results.push({ port, busy: await isPortBusy(port) });
  }
  const busy = results.filter((r) => r.busy);
  const privileged = os !== 'win32';

  if (busy.length) {
    return {
      id: 'ports',
      title: 'Ports 80 and 443',
      status: 'blocked',
      detail: `Already in use: ${busy.map((b) => b.port).join(', ')}. A local HTTPS proxy cannot bind them while something else holds them.`,
      remedy: [
        os === 'win32'
          ? 'Find the holder with:  netstat -ano | findstr ":443"   then look up the PID in Task Manager.'
          : 'Find the holder with:  sudo lsof -i :443',
        'On Windows this is often IIS, or "World Wide Web Publishing Service".',
        'Stop it, or configure the proxy on different ports and accept that URLs carry a port number.',
      ],
      evidence: { results, privilegedBind: privileged },
    };
  }

  return {
    id: 'ports',
    title: 'Ports 80 and 443',
    status: privileged ? 'needs-elevation' : 'ok',
    detail: privileged
      ? 'Both are free. Binding a port below 1024 needs root on this platform, so the proxy runs elevated or is granted the capability once.'
      : 'Both are free. Windows does not reserve ports below 1024, so no elevation is needed to bind them.',
    remedy: privileged ? ['One sudo when the proxy starts, or grant CAP_NET_BIND_SERVICE to the binary once.'] : [],
    evidence: { results, privilegedBind: privileged },
  };
}

// ------------------------------------------------------------------- proxy

/**
 * Is there already a usable Caddy, or must one be fetched?
 *
 * Looks on PATH and in this project. A copy fetched by an earlier run lives in
 * the project directory, and reporting "will download" when one is already
 * sitting there makes the diagnosis contradict itself.
 */
export function checkProxy(cwd = process.cwd()) {
  const projectBinary = join(cwd, '.notlocalhost', 'caddy', OS === 'win32' ? 'caddy.exe' : 'caddy');
  const found =
    findBinary('caddy') ??
    (existsSync(projectBinary) ? { path: projectBinary, version: null, source: 'project' } : null);

  if (found) {
    return {
      id: 'proxy',
      title: 'Caddy',
      status: 'ok',
      detail:
        `Found at ${found.path}${found.version ? ` (${found.version})` : ''}. ` +
        `It will be used as-is; nothing is downloaded.`,
      remedy: [],
      evidence: found,
    };
  }
  return {
    id: 'proxy',
    title: 'Caddy',
    status: 'will-download',
    detail:
      'Not installed. A copy will be downloaded into this project rather than installed system-wide, ' +
      'so removing the project removes it.',
    remedy: ['Nothing to do. Install Caddy yourself if you would rather it were managed by your package manager.'],
    evidence: { searched: ['PATH'] },
  };
}

// --------------------------------------------------------------- primitives

function canWrite(path) {
  // A POSIX access() check lies on Windows, where ACLs decide. Opening the
  // file for writing is the only answer that can be trusted, and it changes
  // nothing as long as the handle is closed without writing.
  try {
    const fd = openSync(path, constants.O_RDWR);
    closeSync(fd);
    return true;
  } catch {
    return false;
  }
}

function readProtectedRootsPolicy() {
  if (OS !== 'win32') return { policy: null, blocked: false };
  try {
    const out = execFileSync(
      'reg',
      ['query', 'HKLM\\SOFTWARE\\Policies\\Microsoft\\SystemCertificates\\Root\\ProtectedRoots', '/v', 'Flags'],
      { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'], timeout: 5000, windowsHide: true },
    );
    const m = out.match(/Flags\s+REG_DWORD\s+0x([0-9a-f]+)/i);
    const flags = m ? parseInt(m[1], 16) : 0;
    // Bit 0 set means only administrators may add roots.
    return { policy: 'ProtectedRoots', flags, blocked: (flags & 1) === 1 };
  } catch {
    return { policy: null, blocked: false };
  }
}

function isPortBusy(port, host = '127.0.0.1', timeoutMs = 400) {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    let settled = false;
    const done = (busy) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve(busy);
    };
    socket.setTimeout(timeoutMs);
    socket.once('connect', () => done(true));
    socket.once('timeout', () => done(false));
    socket.once('error', () => done(false));
    socket.connect(port, host);
  });
}

function hasBinary(name) {
  return Boolean(findBinary(name));
}

function findBinary(name) {
  const finder = OS === 'win32' ? 'where' : 'which';
  try {
    const out = execFileSync(finder, [name], {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
      timeout: 5000,
      windowsHide: true,
    });
    const path = out.split(/\r?\n/).map((s) => s.trim()).find(Boolean);
    if (!path || !existsSync(path) || !statSync(path).isFile()) return null;
    let version = null;
    try {
      version = execFileSync(path, ['version'], {
        encoding: 'utf8',
        stdio: ['ignore', 'pipe', 'ignore'],
        timeout: 5000,
        windowsHide: true,
      })
        .trim()
        .split('\n')[0];
    } catch {
      // A binary that will not answer `version` is still a binary. Do not let
      // a probe decide whether it exists -- that mistake cost 35 minutes of CI.
    }
    return { path, version };
  } catch {
    return null;
  }
}

/** Run every check. Never throws: a diagnostic that crashes diagnoses nothing. */
export async function runAllChecks(os = OS, cwd = process.cwd()) {
  const checks = [
    () => checkDns(os),
    () => checkCertTrust(os),
    () => checkPorts(os),
    () => checkProxy(cwd),
  ];
  const out = [];
  for (const run of checks) {
    try {
      out.push(await run());
    } catch (err) {
      out.push({
        id: 'internal',
        title: 'A check failed',
        status: 'failed',
        detail: `This check could not complete: ${err?.message ?? err}`,
        remedy: ['Please report this, with your platform.'],
      });
    }
  }
  return out;
}
