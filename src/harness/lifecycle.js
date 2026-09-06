/**
 * init, up and down.
 *
 * Everything that touches the machine goes through here, and everything here
 * is written so that `down` can undo it. Two rules shape the whole file:
 *
 *   Nothing happens without consent. `up` prints exactly what it will change,
 *   in plain sentences, and stops unless the caller has agreed. It does not
 *   prompt from inside a function that also acts -- the asking and the doing
 *   are separate so both can be tested.
 *
 *   Every mutation is recorded before it is attempted and verified after it is
 *   reversed. The ledger in state.json is what `down` reads, not the
 *   configuration, because the two diverge the moment something fails halfway.
 *
 * Every path and port is injectable. That is not a testing convenience, it is
 * what allows the whole lifecycle to be exercised against scratch files on
 * unprivileged ports -- and a test suite that needed elevation would not be run.
 */
import { spawn, execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, writeFileSync, rmSync, openSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { platform } from 'node:os';

import {
  harnessDir,
  configPath,
  defaultConfig,
  readConfig,
  writeConfig,
  readState,
  writeState,
  clearState,
  emptyState,
  describeChanges,
  TIERS,
} from './config.js';
import { renderCaddyfile, isOursForAnyPorts } from './caddyfile.js';
import { resolveCaddy } from './caddy.js';
import { trustCa, untrustCa, caRootPath, describeCertificate } from './trust.js';
import { applyBlock, removeBlock, digestOfFile, previewBlock, findBlock } from './hosts.js';
import { hostsPath as defaultHostsPath } from './checks.js';
import { scanLoopbackPorts, speaksHttp } from '../collect/port-scan.js';

const OS = platform();

// ---------------------------------------------------------------------- init

/**
 * Work out what the project looks like and write the configuration.
 *
 * Changes nothing outside the project directory. No certificate, no hosts
 * entry, no process. `init` is a planning step on purpose: someone should be
 * able to run it, read the plan, and walk away having altered nothing.
 */
export async function init(opts = {}) {
  const {
    cwd = process.cwd(),
    tier = 'localhost',
    project,
    upstreams,
    force = false,
    log = () => {},
  } = opts;

  if (!TIERS[tier]) {
    const e = new Error(`unknown tier "${tier}". Use "localhost" (no elevation) or "test" (a real registrable domain).`);
    e.code = 'USAGE';
    throw e;
  }

  const existing = existsSync(configPath(cwd)) ? readConfig(cwd) : null;
  if (existing && !force) {
    const e = new Error(
      `This project is already initialised as ${existing.domain}.\n` +
        'Run `notlocalhost init --force` to replace the configuration, or edit .notlocalhost/config.json.',
    );
    e.code = 'ALREADY_INITIALISED';
    throw e;
  }

  // Find the dev servers that are actually running, rather than asking someone
  // to remember their own port numbers.
  let discovered = upstreams;
  if (!discovered) {
    const open = await scanLoopbackPorts().catch(() => []);

    // An open port is not a web server. Databases, brokers and language
    // servers all answer a connect, and offering to put a TLS proxy in front
    // of PostgreSQL helps nobody. Only things that reply with an HTTP status
    // line are proposed.
    const checked = await Promise.all(open.map(async (port) => [port, await speaksHttp(port)]));
    const web = checked.filter(([, isHttp]) => isHttp).map(([port]) => port);
    const ignored = checked.filter(([, isHttp]) => !isHttp).map(([port]) => port);

    discovered = web.map((port, i) => ({ label: i === 0 ? 'app' : `svc-${port}`, port }));
    if (web.length) log(`found web servers on ${web.join(', ')}`);
    if (ignored.length) log(`ignored ${ignored.join(', ')}: open, but not speaking HTTP`);
  }

  if (!discovered.length) {
    const e = new Error(
      'Nothing on the usual ports is serving HTTP, so there is nothing to put behind a proxy.\n' +
        'Start your application first, or name the ports yourself.',
    );
    e.code = 'NO_UPSTREAMS';
    throw e;
  }

  const config = defaultConfig({ cwd, tier, project, upstreams: discovered });
  writeConfig(config, cwd);
  log(`wrote ${configPath(cwd)}`);

  return { config, changes: describeChanges(config, {}), path: configPath(cwd) };
}

// ------------------------------------------------------------------------ up

/**
 * Start the harness.
 *
 * @param {object} opts
 * @param {boolean} opts.consent  Must be true. The caller obtains it.
 */
export async function up(opts = {}) {
  const {
    cwd = process.cwd(),
    consent = false,
    httpPort = 80,
    httpsPort = 443,
    hostsFile = defaultHostsPath(),
    env = process.env,
    trust = true,
    log = () => {},
    // Injectable so the crash-safety of the trust sequence can be tested
    // without a test ever touching a real trust store. There is no other way
    // to assert what the ledger holds at the moment an install is interrupted.
    installTrust = trustCa,
  } = opts;

  const config = readConfig(cwd);
  if (!config) {
    const e = new Error('This project is not initialised. Run `notlocalhost init` first.');
    e.code = 'NOT_INITIALISED';
    throw e;
  }

  if (!consent) {
    const e = new Error('up() requires explicit consent; the caller must obtain it first.');
    e.code = 'NO_CONSENT';
    e.changes = describeChanges(config, { httpPort, httpsPort });
    throw e;
  }

  const state = readState(cwd) ?? emptyState();
  if (state.running?.pid && isAlive(state.running.pid)) {
    const e = new Error(`The harness is already running (pid ${state.running.pid}). Run \`notlocalhost down\` first.`);
    e.code = 'ALREADY_RUNNING';
    throw e;
  }

  // ---- proxy ---------------------------------------------------------------
  const caddy = await resolveCaddy({ cwd, log });
  state.caddy = { path: caddy.path, source: caddy.source, version: caddy.version };
  writeState(state, cwd);

  // ---- configuration -------------------------------------------------------
  const caddyfilePath = join(harnessDir(cwd), 'Caddyfile');
  const rendered = renderCaddyfile(config, { httpPort, httpsPort });
  // "Not what we would generate" is not the same as "hand-edited". A Caddyfile
  // written by an earlier run on different ports also fails that test, and
  // keeping it silently discarded the --http-port and --https-port the caller
  // just asked for. A file we could have generated ourselves, for any ports,
  // is ours to replace.
  const existing = existsSync(caddyfilePath) ? readFileSync(caddyfilePath, 'utf8') : null;
  if (existing !== null && !isOursForAnyPorts(existing, config)) {
    log('keeping your edited Caddyfile; delete it to regenerate');
  } else {
    mkdirSync(harnessDir(cwd), { recursive: true });
    writeFileSync(caddyfilePath, rendered, 'utf8');
  }

  // ---- hosts ---------------------------------------------------------------
  // Recorded before it is attempted, so a crash between the two still leaves
  // `down` something to work from.
  if (TIERS[config.tier].needsHostsEntry) {
    const previousHosts = state.hosts;
    const before = digestOfFile(hostsFile);
    state.hosts = { path: hostsFile, digestBefore: before, hostnames: config.sites.map((s) => s.host), applied: false };
    writeState(state, cwd);

    const result = applyBlock(hostsFile, config.project, config.sites.map((s) => s.host));
    // `changed: false` means the block was already there, which happens on a
    // second `up` after a reboot or a killed proxy. Recording applied:false
    // then made `down` skip the hosts step entirely and report success while
    // leaving the entries behind. What matters is whether the block is
    // present and therefore owed, not whether this particular run wrote it.
    const present = result.changed || findBlock(readFileSync(hostsFile, 'utf8'), config.project).present;
    state.hosts.applied = present;
    state.hosts.wroteThisRun = result.changed;
    // A digest taken from an already-modified file is not the original. Keep
    // whichever earlier run recorded a genuine before-state.
    if (!result.changed && previousHosts?.digestBefore) {
      state.hosts.digestBefore = previousHosts.digestBefore;
      state.hosts.backup = previousHosts.backup ?? result.backup;
    } else {
      state.hosts.backup = result.backup;
    }
    state.hosts.digestAfter = result.after;
    writeState(state, cwd);
    log(result.changed ? `added ${config.sites.length} hostnames to ${hostsFile}` : 'hosts file already had the entries');
  }

  // ---- process -------------------------------------------------------------
  const logPath = join(harnessDir(cwd), 'caddy.log');
  const child = spawn(caddy.path, ['run', '--config', caddyfilePath, '--adapter', 'caddyfile'], {
    cwd,
    env,
    detached: true,
    stdio: ['ignore', openLog(logPath), openLog(logPath)],
    windowsHide: true,
  });
  // spawn reports failure asynchronously. Without a listener an ENOENT becomes
  // an uncaught exception, and without checking for an early exit `up` prints
  // "Up." naming a pid that is already gone -- usually because the port is
  // busy, which is the most ordinary way for this to fail.
  let spawnError = null;
  child.on('error', (err) => {
    spawnError = err;
  });
  child.unref();

  await new Promise((r) => setTimeout(r, 400));
  if (spawnError || child.exitCode !== null || !isAlive(child.pid)) {
    const detail = spawnError ? spawnError.message : `it exited with code ${child.exitCode ?? 'unknown'}`;
    const e = new Error(
      [
        `The proxy did not stay running: ${detail}.`,
        '',
        `Caddy said why in ${logPath} -- read that first; it names the actual cause.`,
        '',
        'Commonly one of:',
        '  - a port already in use     `notlocalhost doctor` names the holder,',
        '                              or pass --http-port / --https-port',
        '  - an edited Caddyfile       delete .notlocalhost/Caddyfile to regenerate it',
        '  - an upstream that moved    check the ports in .notlocalhost/config.json',
      ].join('\n'),
    );
    e.code = 'PROXY_FAILED';
    throw e;
  }

  // The project name is what `down` looks for in the hosts file. config.json
  // is documented as intent, safe to edit or delete, so the name has to be in
  // the ledger too or a deleted config leaves an unremovable block.
  state.project = config.project;
  state.running = { pid: child.pid, startedAt: new Date().toISOString(), httpPort, httpsPort, logPath };
  writeState(state, cwd);
  log(`proxy started (pid ${child.pid})`);

  // ---- certificate authority ----------------------------------------------
  // After the proxy, not before. Caddy generates its authority the first time
  // it serves TLS, so there is nothing to install until it is running.
  if (trust) {
    const certPath = caRootPath(env);
    const appeared = await waitForFile(certPath, 20_000);
    if (!appeared) {
      log(`no certificate authority appeared at ${certPath}; skipping trust`);
    } else {
      // Record the intent before acting, not the outcome afterwards.
      //
      // Installing first and writing the ledger second leaves a window --
      // Ctrl-C, a crash, a closed laptop -- where the root is in the store and
      // nothing knows it, so `down` will never remove it. That is exactly how
      // orphaned authorities accumulate, and the guard inside trustCa only
      // covers the case where the install itself reports failure.
      //
      // Written first, the worst case is `down` trying to remove something
      // that was never installed, which is harmless and says so.
      state.ca = describeCertificate(certPath);
      state.caTrusted = 'attempting';
      writeState(state, cwd);

      const cert = await installTrust({ env, log, certPath });
      state.ca = cert;
      state.caTrusted = true;
      writeState(state, cwd);
    }
  }

  return { config, state, caddy, caddyfilePath, sites: config.sites, logPath };
}

// ---------------------------------------------------------------------- down

/**
 * Undo everything, in reverse, and report what could not be undone.
 *
 * Never throws for a step that fails. `down` has several things to reverse and
 * abandoning the rest because one failed leaves more behind, not less. Each
 * step reports its own outcome and the caller decides what that means.
 */
export async function down(opts = {}) {
  const { cwd = process.cwd(), purge = false, env = process.env, log = () => {} } = opts;

  const state = readState(cwd);
  if (!state) {
    return { didNothing: true, steps: [], clean: true, summary: 'Nothing was recorded as changed, so there is nothing to undo.' };
  }

  const steps = [];

  // ---- process -------------------------------------------------------------
  if (state.running?.pid) {
    const killed = await stopProcess(state.running.pid);
    steps.push({
      what: 'stop the proxy',
      ok: killed.ok,
      detail: killed.ok
        ? `stopped pid ${state.running.pid}${killed.escalated ? ' (it ignored SIGTERM and was killed)' : ''}`
        : `could not stop pid ${state.running.pid}: ${killed.error}`,
    });
    log(killed.ok ? 'proxy stopped' : `proxy could not be stopped: ${killed.error}`);
    // Settled debts leave the ledger. It is kept only for what is still owed,
    // so a second `down` reports the step that failed rather than replaying
    // the ones that already succeeded.
    if (killed.ok) state.running = null;
  }

  // ---- certificate authority ----------------------------------------------
  if (state.caTrusted) {
    // An install that never completed is a different thing from one that did.
    //
    // `attempting` means trustCa was entered and did not report success, so on
    // a machine without the platform's certificate tool -- no certutil on
    // Linux, the common case -- there is nothing installed and nothing to
    // remove. Reporting that as a failed removal puts a red step in front of
    // someone every time they run `down`, for work that never happened.
    const neverCompleted = state.caTrusted === 'attempting';
    const result = await untrustCa({ fingerprint: state.ca?.fingerprint, certificate: state.ca, env, log });
    if (neverCompleted && result.state !== 'present') {
      steps.push({
        what: 'remove the certificate authority',
        ok: true,
        detail:
          result.state === 'absent'
            ? 'the install never completed and the store confirms nothing is there'
            : 'the install never completed, so there is nothing to remove (the store could not be queried to confirm)',
      });
      state.caTrusted = false;
      state.ca = null;
    } else {
      steps.push({
        what: 'remove the certificate authority',
        ok: result.removed,
        detail: result.removed
          ? 'removed from the trust store, verified absent'
          : `the trust store reports "${result.state}"`,
        advice: result.advice,
      });
      if (result.removed) {
        state.caTrusted = false;
        state.ca = null;
      }
    }
  }

  // ---- hosts ---------------------------------------------------------------
  if (state.hosts?.applied) {
    const result = removeBlock(state.hosts.path, readConfigProject(cwd, state), state.hosts.digestBefore, {
      backupPath: state.hosts.backup ?? `${state.hosts.path}.notlocalhost-backup`,
    });
    steps.push({
      what: 'restore the hosts file',
      ok: result.matches,
      detail: result.matches
        ? `${state.hosts.path} is byte-for-byte what it was`
        : (result.reason ?? 'the file does not match its original digest'),
    });
  }

  // ---- project files -------------------------------------------------------
  // The ledger is cleared only when there is nothing left owed.
  //
  // It used to be cleared unconditionally, so a step that failed -- a declined
  // password, a locked trust store -- had its record deleted along with the
  // steps that succeeded. The next `down` then said there was nothing to undo,
  // and the certificate or the hosts block could never be removed by this tool
  // again. Keeping the ledger is what makes a second attempt possible.
  const unfinished = steps.filter((s) => !s.ok);
  if (unfinished.length === 0) {
    clearState(cwd);
  } else {
    writeState(state, cwd);
  }

  if (purge) {
    rmSync(harnessDir(cwd), { recursive: true, force: true });
    steps.push({ what: 'remove .notlocalhost/', ok: true, detail: 'deleted, including the downloaded proxy' });
  }

  const failed = steps.filter((s) => !s.ok);
  return {
    didNothing: false,
    steps,
    clean: failed.length === 0,
    summary: failed.length
      ? `${failed.length} step${failed.length === 1 ? '' : 's'} could not be completed: ${failed.map((f) => f.what).join(', ')}`
      : 'The machine is back to how it was.',
  };
}

// --------------------------------------------------------------- primitives

function readConfigProject(cwd, state) {
  try {
    return readConfig(cwd)?.project ?? state.project ?? 'notlocalhost';
  } catch {
    return state.project ?? 'notlocalhost';
  }
}

/**
 * A file descriptor the detached proxy can write to.
 *
 * The child outlives this process, so its output cannot go to a pipe nobody
 * will read -- that fills the buffer and stalls it. Appending to a file keeps
 * the log across restarts, which is what someone wants when asking why the
 * proxy would not start.
 */
function openLog(path) {
  mkdirSync(dirname(path), { recursive: true });
  return openSync(path, 'a');
}

/** Wait for a file to appear, because Caddy writes its authority lazily. */
async function waitForFile(path, budgetMs, stepMs = 250) {
  const deadline = Date.now() + budgetMs;
  while (Date.now() < deadline) {
    if (existsSync(path)) return true;
    await new Promise((r) => setTimeout(r, stepMs));
  }
  return existsSync(path);
}

export function isAlive(pid) {
  if (!pid) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    return err.code === 'EPERM';
  }
}

/**
 * Stop the proxy.
 *
 * Windows needs taskkill to reach the whole tree; elsewhere a signal is enough.
 * A process that is already gone counts as stopped -- the goal is that it is
 * not running, not that we were the one to end it.
 */
export async function stopProcess(pid, opts = {}) {
  const { graceMs = 5000, killMs = 3000 } = opts;
  if (!isAlive(pid)) return { ok: true, alreadyGone: true };

  // A signal is a request, not an event. On POSIX the process is still alive
  // for as long as it takes to handle SIGTERM and exit, so checking
  // immediately reports failure for a shutdown that is merely in progress.
  // Windows hides this because taskkill /F terminates before it returns.
  try {
    if (OS === 'win32') {
      execFileSync('taskkill', ['/PID', String(pid), '/T', '/F'], { stdio: 'ignore', timeout: 20_000, windowsHide: true });
    } else {
      process.kill(pid, 'SIGTERM');
    }
  } catch (err) {
    if (!isAlive(pid)) return { ok: true, alreadyGone: true };
    return { ok: false, error: err.message };
  }

  if (await waitForExit(pid, graceMs)) return { ok: true };

  // It asked nicely and was ignored. Escalate rather than report a failure the
  // caller can do nothing about.
  try {
    if (OS !== 'win32') process.kill(pid, 'SIGKILL');
  } catch {
    /* it may have exited between the check and the signal */
  }
  if (await waitForExit(pid, killMs)) return { ok: true, escalated: true };

  return { ok: false, error: `pid ${pid} is still running after SIGTERM and SIGKILL` };
}

/** Poll until the process is gone, or the budget runs out. */
async function waitForExit(pid, budgetMs, stepMs = 50) {
  const deadline = Date.now() + budgetMs;
  while (Date.now() < deadline) {
    if (!isAlive(pid)) return true;
    await new Promise((r) => setTimeout(r, stepMs));
  }
  return !isAlive(pid);
}

export { previewBlock, caRootPath, describeCertificate };
