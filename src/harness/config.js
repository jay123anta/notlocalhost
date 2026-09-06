/**
 * The harness configuration, and the record of what it changed.
 *
 * Two files live in `.notlocalhost/`, and the distinction between them is the
 * whole reversibility story:
 *
 *   config.json  what you asked for. Safe to edit, safe to delete, safe to
 *                commit. Describes intent.
 *   state.json   what was actually done to this machine. Never edited by hand,
 *                never committed. Describes debt.
 *
 * `down` reads state.json, not config.json. It undoes what happened, not what
 * was requested, because those differ whenever something failed halfway.
 */
import { existsSync, mkdirSync, readFileSync, writeFileSync, rmSync } from 'node:fs';
import { join, basename } from 'node:path';
import { createHash } from 'node:crypto';

export const CONFIG_VERSION = 1;

export function harnessDir(cwd = process.cwd()) {
  return join(cwd, '.notlocalhost');
}
export function configPath(cwd = process.cwd()) {
  return join(harnessDir(cwd), 'config.json');
}
export function statePath(cwd = process.cwd()) {
  return join(harnessDir(cwd), 'state.json');
}

/**
 * Two topologies, and the choice costs something either way.
 *
 * `localhost` needs no elevation at all: names under the reserved .localhost
 * TLD resolve to loopback without a resolver, and on Windows the CA can go in
 * the per-user store. It gives real HTTPS on real hostnames, which confirms
 * most of what the analyzer predicts.
 *
 * `test` needs a hosts entry, and therefore one elevation prompt. It buys the
 * one thing .localhost provably cannot express: a parent-domain cookie scope,
 * and with it a genuine same-site topology.
 */
export const TIERS = {
  localhost: {
    id: 'localhost',
    suffix: 'localhost',
    needsHostsEntry: false,
    gives: [
      'Real HTTPS on real hostnames, so Secure cookies are actually set',
      'SameSite=None; Secure actually delivered rather than dropped',
      'Secure contexts on a name that is not localhost',
      'Mixed content actually blocked',
    ],
    cannotGive: [
      'A parent-domain cookie scope. Nothing can set a cookie that app.x.localhost and api.x.localhost both read -- confirmed against Chrome in evidence/.',
    ],
  },
  test: {
    id: 'test',
    suffix: 'test',
    needsHostsEntry: true,
    gives: [
      'Everything the localhost tier gives',
      'A parent-domain cookie scope, and therefore a real same-site topology',
      'Cookies that stop crossing when they should, and start when they should',
    ],
    cannotGive: [],
  },
};

/**
 * Derive a default configuration from the project and the ports it uses.
 *
 * @param {object} opts
 * @param {string} [opts.cwd]
 * @param {string} [opts.project]  Defaults to the directory name.
 * @param {'localhost'|'test'} [opts.tier]
 * @param {Array<{label?: string, port: number|string}>} opts.upstreams
 */
export function defaultConfig(opts) {
  const { cwd = process.cwd(), tier = 'localhost', upstreams = [] } = opts;
  const project = slug(opts.project ?? basename(cwd));
  const suffix = TIERS[tier]?.suffix;
  if (!suffix) throw new Error(`unknown tier "${tier}"`);

  const domain = `${project}.${suffix}`;
  const sites = upstreams.map((u, i) => ({
    host: `${slug(u.label ?? (i === 0 ? 'app' : `svc-${u.port}`))}.${domain}`,
    upstream: `http://127.0.0.1:${u.port}`,
  }));

  return { version: CONFIG_VERSION, project, tier, domain, sites };
}

/** A hostname label: lowercase, alphanumeric and hyphens, never leading/trailing. */
export function slug(input) {
  const s = String(input)
    .toLowerCase()
    .replace(/[^a-z0-9-]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 63);
  return s || 'app';
}

export function readConfig(cwd = process.cwd()) {
  const p = configPath(cwd);
  if (!existsSync(p)) return null;
  const cfg = JSON.parse(readFileSync(p, 'utf8'));
  if (cfg.version !== CONFIG_VERSION) {
    throw new Error(`${p} was written by a different version of notlocalhost (found ${cfg.version}, expected ${CONFIG_VERSION}).`);
  }
  return cfg;
}

export function writeConfig(cfg, cwd = process.cwd()) {
  mkdirSync(harnessDir(cwd), { recursive: true });
  writeFileSync(configPath(cwd), `${JSON.stringify(cfg, null, 2)}\n`, 'utf8');
  return configPath(cwd);
}

// ------------------------------------------------------------------- state

/**
 * The ledger of everything done to this machine.
 *
 * Every entry records enough to undo itself *and* to prove the undo worked.
 * A hosts-file change stores the digest of the file before it was touched, so
 * `down` can assert the file is byte-identical afterwards rather than assuming.
 */
export function emptyState() {
  return {
    version: CONFIG_VERSION,
    createdAt: new Date().toISOString(),
    caddy: null,
    caTrusted: false,
    hosts: null,
    running: null,
  };
}

export function readState(cwd = process.cwd()) {
  const p = statePath(cwd);
  if (!existsSync(p)) return null;
  return JSON.parse(readFileSync(p, 'utf8'));
}

export function writeState(state, cwd = process.cwd()) {
  mkdirSync(harnessDir(cwd), { recursive: true });
  writeFileSync(statePath(cwd), `${JSON.stringify(state, null, 2)}\n`, 'utf8');
  return statePath(cwd);
}

export function clearState(cwd = process.cwd()) {
  rmSync(statePath(cwd), { force: true });
}

/** Digest a file so a later restore can be proven rather than trusted. */
export function fileDigest(path) {
  if (!existsSync(path)) return null;
  return createHash('sha256').update(readFileSync(path)).digest('hex');
}

/**
 * Describe, in plain sentences, everything `up` would change on this machine.
 *
 * Printed before anything happens and before any password prompt. Someone who
 * reads only this should be able to decide, and should never be surprised
 * afterwards.
 */
export function describeChanges(cfg, { caddySource, httpPort, httpsPort } = {}) {
  const tier = TIERS[cfg.tier];
  if (!tier) {
    // config.json is documented as safe to edit, so a wrong value here is a
    // user mistake and deserves the message `init` would give, not a stack
    // trace from a property lookup two frames away.
    const e = new Error(
      `Unknown tier "${cfg.tier}" in config.json. It must be ${Object.keys(TIERS).map((t) => `"${t}"`).join(' or ')}.`,
    );
    e.code = 'BAD_TIER';
    throw e;
  }
  const out = [];

  out.push({
    what: 'A certificate authority, trusted for this machine',
    detail:
      'Caddy generates a local CA and adds it to the trust store so the browser accepts the certificates it issues. ' +
      'It signs nothing but the hostnames below.',
    reversedBy:
      '`notlocalhost down` removes it by its exact fingerprint -- never by name, which would also remove ' +
      'certificates this tool never installed -- and then verifies it is gone from the store.',
    elevation: process.platform !== 'win32',
  });

  if (tier.needsHostsEntry) {
    out.push({
      what: `Lines added to the hosts file for ${cfg.sites.length} hostname${cfg.sites.length === 1 ? '' : 's'}`,
      detail: `${cfg.sites.map((s) => s.host).join(', ')} pointed at 127.0.0.1, inside a marked block.`,
      reversedBy: '`notlocalhost down` removes exactly those lines and verifies the file matches its original digest.',
      elevation: true,
    });
  } else {
    out.push({
      what: 'No DNS or hosts changes',
      detail: `Names under .localhost resolve to loopback without a resolver, so ${cfg.domain} needs no configuration.`,
      reversedBy: 'Nothing to reverse.',
      elevation: false,
    });
  }

  // Ports matter here beyond accuracy: on macOS and Linux, 80 and 443 need
  // elevation and high ports do not, so a fixed sentence would ask for a
  // password the run does not need.
  const known = httpPort !== undefined && httpsPort !== undefined;
  const http = httpPort ?? 80;
  const https = httpsPort ?? 443;
  const privileged = http < 1024 || https < 1024;

  out.push({
    what: known
      ? `A local proxy on ports ${http} and ${https}`
      : 'A local proxy on ports 80 and 443, unless `up` is given different ones',
    detail: `Caddy${caddySource === 'downloaded' ? ', downloaded into .notlocalhost/ and checksum-verified,' : ''} terminates TLS and forwards to your dev server. It runs only while \`up\` is running.`,
    reversedBy: '`notlocalhost down` stops it. Nothing is installed as a service.',
    elevation: process.platform !== 'win32' && privileged,
  });

  out.push({
    what: 'A .notlocalhost/ directory in this project',
    detail: 'Configuration, the generated Caddyfile, and the record of what was changed.',
    reversedBy: '`notlocalhost down --purge` deletes it.',
    elevation: false,
  });

  return out;
}
