/**
 * Locate an already-installed Chromium-family browser.
 *
 * notlocalhost never downloads a browser. `npx notlocalhost` must be fast and
 * offline-capable, and a 150 MB browser download on first run is neither.
 * We look for what the developer already has: Chrome, Chromium, or Edge.
 */
import { existsSync, statSync, readdirSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { join } from 'node:path';
import { homedir, platform } from 'node:os';

/** @typedef {{ path: string, channel: string, name: string }} BrowserLocation */

const WIN_ROOTS = () =>
  [
    process.env['PROGRAMFILES'],
    process.env['PROGRAMFILES(X86)'],
    process.env['LOCALAPPDATA'],
  ].filter(Boolean);

/**
 * Candidate executables, most-preferred first. Chrome before Edge because
 * Chrome is the browser most teams actually test against; Edge is the same
 * engine and a perfectly good fallback.
 */
function candidates() {
  const os = platform();

  if (os === 'win32') {
    const out = [];
    for (const root of WIN_ROOTS()) {
      out.push(
        { path: join(root, 'Google/Chrome/Application/chrome.exe'), channel: 'chrome', name: 'Google Chrome' },
        { path: join(root, 'Google/Chrome Beta/Application/chrome.exe'), channel: 'chrome-beta', name: 'Google Chrome Beta' },
        { path: join(root, 'Google/Chrome Dev/Application/chrome.exe'), channel: 'chrome-dev', name: 'Google Chrome Dev' },
        { path: join(root, 'Chromium/Application/chrome.exe'), channel: 'chromium', name: 'Chromium' },
        { path: join(root, 'Microsoft/Edge/Application/msedge.exe'), channel: 'msedge', name: 'Microsoft Edge' },
        { path: join(root, 'Microsoft/Edge Beta/Application/msedge.exe'), channel: 'msedge-beta', name: 'Microsoft Edge Beta' },
        { path: join(root, 'Microsoft/Edge Dev/Application/msedge.exe'), channel: 'msedge-dev', name: 'Microsoft Edge Dev' },
      );
    }
    return out;
  }

  if (os === 'darwin') {
    const home = homedir();
    const apps = [
      ['Google Chrome.app/Contents/MacOS/Google Chrome', 'chrome', 'Google Chrome'],
      ['Google Chrome Beta.app/Contents/MacOS/Google Chrome Beta', 'chrome-beta', 'Google Chrome Beta'],
      ['Google Chrome Dev.app/Contents/MacOS/Google Chrome Dev', 'chrome-dev', 'Google Chrome Dev'],
      ['Chromium.app/Contents/MacOS/Chromium', 'chromium', 'Chromium'],
      ['Microsoft Edge.app/Contents/MacOS/Microsoft Edge', 'msedge', 'Microsoft Edge'],
    ];
    const out = [];
    for (const [rel, channel, name] of apps) {
      out.push({ path: `/Applications/${rel}`, channel, name });
      out.push({ path: join(home, 'Applications', rel), channel, name });
    }
    // Standalone Chrome for Testing downloads, including the layout CI runners
    // and the hosted tool cache use.
    out.push({
      path: '/Applications/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing',
      channel: 'chrome',
      name: 'Chrome for Testing',
    });
    return out;
  }

  // Linux and anything else POSIX-ish.
  return [
    { path: '/opt/google/chrome/chrome', channel: 'chrome', name: 'Google Chrome' },
    { path: '/usr/bin/google-chrome', channel: 'chrome', name: 'Google Chrome' },
    { path: '/usr/bin/google-chrome-stable', channel: 'chrome', name: 'Google Chrome' },
    { path: '/usr/bin/google-chrome-beta', channel: 'chrome-beta', name: 'Google Chrome Beta' },
    { path: '/usr/bin/chromium', channel: 'chromium', name: 'Chromium' },
    { path: '/usr/bin/chromium-browser', channel: 'chromium', name: 'Chromium' },
    { path: '/snap/bin/chromium', channel: 'chromium', name: 'Chromium (snap)' },
    { path: '/usr/bin/microsoft-edge', channel: 'msedge', name: 'Microsoft Edge' },
    { path: '/usr/bin/microsoft-edge-stable', channel: 'msedge', name: 'Microsoft Edge' },
    { path: '/opt/microsoft/msedge/msedge', channel: 'msedge', name: 'Microsoft Edge' },
  ];
}

/** Names to try on PATH when no well-known install path matched. */
const PATH_NAMES = [
  ['google-chrome', 'chrome', 'Google Chrome'],
  ['google-chrome-stable', 'chrome', 'Google Chrome'],
  ['chromium', 'chromium', 'Chromium'],
  ['chromium-browser', 'chromium', 'Chromium'],
  ['microsoft-edge', 'msedge', 'Microsoft Edge'],
  ['chrome', 'chrome', 'Chrome'],
];

function onPath(name) {
  const finder = platform() === 'win32' ? 'where' : 'which';
  try {
    const out = execFileSync(finder, [name], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] });
    const first = out.split(/\r?\n/).map((s) => s.trim()).find(Boolean);
    return first && existsSync(first) ? first : null;
  } catch {
    return null;
  }
}

/**
 * A readable name for a browser we were pointed at rather than found. The name
 * ends up in every report header, so "Chrome for Testing" beats the name of the
 * environment variable it arrived in.
 */
function nameFromPath(p) {
  const lower = p.toLowerCase().replace(/\\/g, '/');
  if (lower.includes('chrome-headless-shell')) return 'Chrome Headless Shell';
  if (lower.includes('chrome-linux') || lower.includes('chrome-for-testing') || lower.includes('chrome-win'))
    return 'Chrome for Testing';
  if (lower.includes('msedge') || lower.includes('microsoft edge')) return 'Microsoft Edge';
  if (lower.includes('chromium')) return 'Chromium';
  if (lower.includes('chrome')) return 'Google Chrome';
  return 'user-specified browser';
}

function isExecutableFile(p) {
  try {
    return statSync(p).isFile();
  } catch {
    return false;
  }
}

/**
 * Resolve a path that names a browser into the binary that can actually be
 * launched.
 *
 * On macOS an application is a bundle -- a directory ending in `.app` -- and
 * the executable lives at `Contents/MacOS/<name>`. Pointing at the bundle is
 * the natural thing for a Mac user to do, and it is what several tools hand
 * back when asked where Chrome is. Treating a bundle as "not a browser"
 * because it is not a regular file is wrong.
 *
 * @param {string} p
 * @returns {string|null} A launchable executable, or null.
 */
/** Names that are helpers rather than the browser launcher. */
const IS_BUNDLE_HELPER = /helper|crashpad|updater|notification|alerts|relauncher|_handler$/i;

/** Launcher names, most-specific first, matched case-insensitively. */
const LAUNCHER_NAMES = [
  'google chrome for testing',
  'google chrome',
  'chromium',
  'microsoft edge',
  'chrome',
  'msedge',
];

/**
 * Ask a browser binary what version it is.
 *
 * Used only when something has already gone wrong, because spawning a process
 * costs time that a healthy run should not pay. A binary that cannot answer
 * this is not a browser launcher, which distinguishes "we picked the wrong
 * executable" from "the browser will not run under automation" -- two problems
 * with completely different fixes.
 *
 * @param {string} path
 * @returns {string|null}
 */
export function probeBrowserVersion(path) {
  try {
    const out = execFileSync(path, ['--version'], {
      encoding: 'utf8',
      timeout: 5000,
      stdio: ['ignore', 'pipe', 'ignore'],
      windowsHide: true,
    });
    const line = String(out).trim().split('\n')[0];
    // Chrome on Windows answers --version with "Opening in existing browser
    // session." when an instance is already running. Requiring something that
    // looks like a version number keeps that from being read as success.
    return line && /\d+\.\d+/.test(line) ? line : null;
  } catch {
    return null;
  }
}

export function resolveBrowserExecutable(p) {
  if (!p) return null;
  if (isExecutableFile(p)) return p;

  let stat;
  try {
    stat = statSync(p);
  } catch {
    return null;
  }
  if (!stat.isDirectory()) return null;

  // A macOS bundle keeps its executable here. Try it whether or not the path
  // ends in `.app` -- some tools hand back the bundle without the suffix.
  const macOSDir = join(p, 'Contents/MacOS');
  try {
    const entries = readdirSync(macOSDir).filter((e) => isExecutableFile(join(macOSDir, e)));
    // Contents/MacOS holds helper executables beside the real launcher, and
    // picking a helper yields a process that starts and never speaks. Order the
    // candidates rather than taking whatever the directory lists first.
    const bundleName = p.replace(/\\/g, '/').split('/').pop()?.replace(/\.app$/, '');
    const usable = entries.filter((e) => !IS_BUNDLE_HELPER.test(e));
    const chosen =
      usable.find((e) => e === bundleName) ??
      LAUNCHER_NAMES.map((n) => usable.find((e) => e.toLowerCase() === n)).find(Boolean) ??
      usable[0];
    if (chosen) return join(macOSDir, chosen);
  } catch {
    /* not a bundle */
  }

  // A plain directory: accept it if it obviously contains a Chromium binary.
  for (const name of ['chrome', 'chrome.exe', 'chromium', 'chromium-browser', 'msedge', 'msedge.exe']) {
    const candidate = join(p, name);
    if (isExecutableFile(candidate)) return candidate;
  }
  return null;
}

/**
 * @param {{ explicitPath?: string, channel?: string }} [opts]
 * @returns {BrowserLocation}
 * @throws {Error & { code: 'NO_BROWSER' }}
 */
export function locateBrowser(opts = {}) {
  const { explicitPath, channel } = opts;

  // An explicitly configured browser is honoured or reported. Quietly ignoring
  // it and searching elsewhere produces a confusing "no browser found" when the
  // real problem is that the given path needed resolving.
  for (const [source, given] of [
    ['--browser-path', explicitPath],
    ['NOTLOCALHOST_BROWSER_PATH', process.env.NOTLOCALHOST_BROWSER_PATH],
  ]) {
    if (!given) continue;
    const resolved = resolveBrowserExecutable(given);
    if (resolved) return { path: resolved, channel: 'custom', name: nameFromPath(resolved) };

    const err = new Error(`${source} does not point at a browser that can be launched: ${given}`);
    err.code = 'NO_BROWSER';
    err.hint = [
      'Tried, in order:',
      `  the path itself                     ${given}`,
      `  inside a macOS app bundle           ${given}/Contents/MacOS/...`,
      `  a chrome/chromium/msedge binary in  ${given}/`,
      '',
      'Point at the executable directly. On macOS that is inside the bundle, e.g.',
      '  "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"',
    ].join('\n');
    throw err;
  }

  let list = candidates();
  if (channel) list = list.filter((c) => c.channel === channel);

  for (const c of list) {
    if (isExecutableFile(c.path)) return c;
  }

  if (!channel) {
    for (const [name, ch, label] of PATH_NAMES) {
      const p = onPath(name);
      if (p) return { path: p, channel: ch, name: label };
    }
  }

  const err = new Error(
    channel
      ? `No installed browser found for --channel ${channel}.`
      : 'No installed Chrome, Chromium or Edge found.',
  );
  err.code = 'NO_BROWSER';
  err.hint = [
    'notlocalhost deliberately does not download a browser.',
    'Install Chrome, Chromium or Edge, or point at one you already have:',
    '  notlocalhost <url> --browser-path /path/to/chrome',
    '  NOTLOCALHOST_BROWSER_PATH=/path/to/chrome notlocalhost <url>',
  ].join('\n');
  throw err;
}

/** All candidates that exist, for `--list-browsers` and doctor output. */
export function listBrowsers() {
  const found = [];
  for (const c of candidates()) {
    if (isExecutableFile(c.path) && !found.some((f) => f.path === c.path)) found.push(c);
  }
  for (const [name, ch, label] of PATH_NAMES) {
    const p = onPath(name);
    if (p && !found.some((f) => f.path === p)) found.push({ path: p, channel: ch, name: label });
  }
  return found;
}
