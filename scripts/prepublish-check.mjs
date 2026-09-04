/**
 * Refuse to publish anything unexpected.
 *
 * `npm publish` packs the working directory, not git. The `files` field says
 * `src/`, which means whatever happens to be sitting in `src/` gets published --
 * including a feature branch's work-in-progress that was never meant to ship.
 * That nearly happened once: an uncommitted harness directory would have added
 * certificate-trust and binary-download code to a release whose entire selling
 * point is that it installs nothing.
 *
 * npm runs this automatically via `prepublishOnly`, so the check cannot be
 * forgotten. It fails loudly rather than warning, because a warning during a
 * publish is a warning nobody reads.
 */
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';

const NPM = process.platform === 'win32' ? 'npm.cmd' : 'npm';

/**
 * Exactly what a release is allowed to contain. Adding a legitimate new source
 * file means adding it here too -- deliberately, so that growth in the
 * published surface is always a decision rather than an accident.
 */
const ALLOWED = [
  /^LICENSE$/,
  /^README\.md$/,
  /^package\.json$/,
  /^bin\/notlocalhost\.js$/,
  /^src\/(analyze|cli|exit-codes|index|session|version)\.js$/,
  /^src\/browser\/(instrument|locate)\.js$/,
  /^src\/collect\/(conditional-flags|cookie-parser|leaked-urls|origins|port-scan)\.js$/,
  /^src\/report\/(html|json|terminal)\.js$/,
  /^src\/rules\/(cookies|finding|index|leaks|origins|secure-context)\.js$/,
];

/** Things that must never ship, named so the error explains itself. */
const FORBIDDEN = [
  { re: /^src\/harness\//, why: 'harness code installs a certificate authority and downloads a binary' },
  { re: /^test\//, why: 'tests are not part of the product' },
  { re: /^evidence\//, why: 'evidence artifacts are large and belong in the repository only' },
  { re: /^scripts\//, why: 'build scripts are not part of the product' },
  { re: /^\.github\//, why: 'workflows are not part of the product' },
  { re: /^\.notlocalhost\//, why: 'that is a local workspace, not source' },
  { re: /\.(env|pem|key|p12|pfx)$/i, why: 'that looks like a secret or a private key' },
];

const problems = [];

const meta = JSON.parse(execFileSync(NPM, ['pack', '--dry-run', '--json'], { encoding: 'utf8', shell: true }))[0];
const files = meta.files.map((f) => f.path.replace(/\\/g, '/'));

for (const file of files) {
  const forbidden = FORBIDDEN.find((f) => f.re.test(file));
  if (forbidden) {
    problems.push(`${file} must never be published: ${forbidden.why}`);
    continue;
  }
  if (!ALLOWED.some((re) => re.test(file))) {
    problems.push(`${file} is not in the allow-list. If it genuinely belongs in the package, add it to scripts/prepublish-check.mjs.`);
  }
}

// A single runtime dependency is a claim on the README with a badge attached.
const pkg = JSON.parse(readFileSync('package.json', 'utf8'));
const deps = Object.keys(pkg.dependencies ?? {});
if (deps.length !== 1 || deps[0] !== 'playwright-core') {
  problems.push(`runtime dependencies must be exactly ["playwright-core"], found ${JSON.stringify(deps)}`);
}

// Publishing from a dirty tree means the tarball does not match any commit,
// so nobody can ever reproduce it.
try {
  const dirty = execFileSync('git', ['status', '--porcelain'], { encoding: 'utf8' })
    .split('\n')
    .map((l) => l.trim())
    .filter(Boolean)
    .filter((l) => !l.startsWith('?? .notlocalhost/'));
  if (dirty.length) {
    problems.push(`the working tree has uncommitted changes, so this tarball matches no commit:\n    ${dirty.join('\n    ')}`);
  }
} catch {
  problems.push('not a git repository, or git is unavailable: cannot confirm the tree is clean');
}

if (problems.length) {
  console.error(`\nRefusing to publish. ${problems.length} problem(s):\n`);
  for (const p of problems) console.error(`  - ${p}`);
  console.error('');
  process.exit(1);
}

console.log(`prepublish check: ${files.length} files, all expected, tree clean, 1 runtime dependency.`);
