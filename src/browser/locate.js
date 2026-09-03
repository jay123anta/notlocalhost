/**
 * Locate an already-installed Chromium-family browser.
 *
 * notlocalhost never downloads a browser. `npx notlocalhost` must be fast and
 * offline-capable, and a 150 MB browser download on first run is neither.
 * We look for what the developer already has: Chrome, Chromium, or Edge.
 */
import { existsSync, statSync } from 'node:fs';
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
 * @param {{ explicitPath?: string, channel?: string }} [opts]
 * @returns {BrowserLocation}
 * @throws {Error & { code: 'NO_BROWSER' }}
 */
export function locateBrowser(opts = {}) {
  const { explicitPath, channel } = opts;

  if (explicitPath) {
    if (!isExecutableFile(explicitPath)) {
      const err = new Error(`--browser-path does not point at a file: ${explicitPath}`);
      err.code = 'NO_BROWSER';
      throw err;
    }
    return { path: explicitPath, channel: 'custom', name: nameFromPath(explicitPath) };
  }

  const envPath = process.env.NOTLOCALHOST_BROWSER_PATH;
  if (envPath && isExecutableFile(envPath)) {
    return { path: envPath, channel: 'custom', name: nameFromPath(envPath) };
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
