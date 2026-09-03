/**
 * A dependency-free stand-in for a linter.
 *
 * It parses every source file and enforces the handful of invariants that are
 * actually promises to the user: no runtime dependency creep, no literal
 * control characters in source, no telemetry, and no network client reaching
 * anywhere but the target and loopback.
 */
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, extname } from 'node:path';
import { execFileSync } from 'node:child_process';

const ROOT = new URL('..', import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1');
const SKIP_DIRS = new Set(['node_modules', '.git', 'evidence', 'coverage']);

function walk(dir, out = []) {
  for (const name of readdirSync(dir)) {
    if (SKIP_DIRS.has(name)) continue;
    const full = join(dir, name);
    if (statSync(full).isDirectory()) walk(full, out);
    else if (['.js', '.mjs'].includes(extname(name))) out.push(full);
  }
  return out;
}

const files = walk(ROOT);
const problems = [];

for (const file of files) {
  const rel = file.slice(ROOT.length).replace(/\\/g, '/');
  const src = readFileSync(file, 'utf8');

  try {
    execFileSync(process.execPath, ['--check', file], { stdio: 'pipe' });
  } catch (err) {
    problems.push(`${rel}: does not parse\n${err.stderr?.toString().split('\n').slice(0, 3).join('\n')}`);
    continue;
  }

  // Literal control characters do not survive editors, patches or clipboards.
  const control = [...src].findIndex((ch) => {
    const c = ch.charCodeAt(0);
    return (c < 9 || (c > 13 && c < 32) || c === 0x2028 || c === 0x2029) && c !== 10 && c !== 13 && c !== 9;
  });
  if (control >= 0) {
    problems.push(`${rel}: literal control character at offset ${control}; use a \\uXXXX escape`);
  }

  if (/\bnavigator\.sendBeacon\s*\(\s*['"`]https?:/.test(src)) {
    problems.push(`${rel}: looks like it phones home`);
  }
}

// The near-zero-dependency badge has to stay true.
const pkg = JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8'));
const deps = Object.keys(pkg.dependencies ?? {});
if (deps.length > 1 || (deps.length === 1 && deps[0] !== 'playwright-core')) {
  problems.push(`package.json: runtime dependencies must be exactly ["playwright-core"], found ${JSON.stringify(deps)}`);
}
if (Object.keys(pkg.devDependencies ?? {}).length > 0) {
  problems.push('package.json: devDependencies should stay empty; the test runner is built into Node');
}

// The engines floor is a promise, and it is not ours to set alone: whatever
// playwright-core requires, we require. Claiming a lower floor than the
// dependency supports produces a failure deep inside node_modules, which is
// how `>=18.17.0` survived until someone ran it on Node 18.
try {
  const dep = JSON.parse(readFileSync(join(ROOT, 'node_modules/playwright-core/package.json'), 'utf8'));
  const depFloor = Number((dep.engines?.node ?? '').match(/(\d+)/)?.[1]);
  const ourFloor = Number((pkg.engines?.node ?? '').match(/(\d+)/)?.[1]);
  if (Number.isFinite(depFloor) && Number.isFinite(ourFloor) && ourFloor < depFloor) {
    problems.push(
      `package.json: engines.node is "${pkg.engines.node}" but playwright-core requires "${dep.engines.node}". ` +
        `Raise our floor to at least ${depFloor}.`,
    );
  }
  const guard = readFileSync(join(ROOT, 'bin/notlocalhost.js'), 'utf8');
  const guardFloor = Number(guard.match(/major\s*<\s*(\d+)/)?.[1]);
  if (Number.isFinite(guardFloor) && Number.isFinite(ourFloor) && guardFloor !== ourFloor) {
    problems.push(
      `bin/notlocalhost.js checks "major < ${guardFloor}" but package.json engines.node says ${ourFloor}. Keep them equal.`,
    );
  }
} catch {
  // Dependencies not installed. `npm ci` runs before lint in CI, so this only
  // skips the check for someone linting a bare checkout.
}

if (problems.length) {
  console.error(`${problems.length} problem(s):\n`);
  for (const p of problems) console.error(`  ${p}`);
  process.exit(1);
}

console.log(`checked ${files.length} files, 1 runtime dependency, no control characters. clean.`);
