/**
 * Run the suites and refuse to believe a green exit code on its own.
 *
 * `node --test` can print `not ok` for a suite and still exit 0. It happened
 * here: three assertions passed, the suite was cancelled because a server
 * handle stayed open, the summary said `# fail 0`, and the run was green. A
 * broken suite that exits 0 is the same failure this project keeps finding --
 * a check that succeeds by failing to look.
 *
 * So the exit code is not the verdict. The TAP output is.
 *
 * The judgement lives in analyseTapOutput, which is pure and unit-tested
 * against recorded output. A checker nobody can test is one more thing taken
 * on trust.
 */
import { spawnSync } from 'node:child_process';

export const TEST_FILES = [
  'test/compat.test.js',
  'test/unit.test.js',
  'test/e2e.test.js',
  'test/report.test.js',
  'test/harness.test.js',
  'test/lifecycle.test.js',
];

/** Below this, the run proved too little to be believed, whatever it printed. */
export const MINIMUM_TESTS = 200;

/**
 * @param {{ out: string, status: number|null, minimumTests?: number }} input
 * @returns {string[]} problems; empty means the run can be believed
 */
export function analyseTapOutput({ out, status, minimumTests = MINIMUM_TESTS }) {
  // Normalised: the summary anchors are line-end sensitive and Windows supplies
  // a carriage return that a trailing anchor will not match past.
  const lines = String(out).replace(/\r/g, '').split('\n');
  const problems = [];

  const notOk = lines.filter((l) => /^\s*not ok\b/.test(l));
  if (notOk.length) {
    problems.push(
      `TAP reported ${notOk.length} failing entr${notOk.length === 1 ? 'y' : 'ies'}:\n    ` +
        notOk.map((l) => l.trim()).join('\n    '),
    );
  }

  // Parsed by prefix rather than a constructed regex. A backslash-d inside a
  // template literal collapses to a plain "d", which silently produces a
  // pattern that matches nothing -- and a checker that matches nothing always
  // passes. That bug was written here before it was caught.
  const num = (label) => {
    const prefix = `# ${label} `;
    const line = lines.find((l) => l.startsWith(prefix));
    if (!line) return null;
    const v = Number(line.slice(prefix.length).trim());
    return Number.isFinite(v) ? v : null;
  };

  const failed = num('fail');
  if (failed === null) problems.push('no "# fail" line: the run did not finish, so nothing was proven');
  else if (failed > 0) problems.push(`${failed} test(s) failed`);

  const ran = num('tests');
  if (ran === null) problems.push('no "# tests" line: the run did not finish');
  else if (ran < minimumTests) {
    problems.push(`only ${ran} tests ran, expected at least ${minimumTests}; a suite is skipping itself`);
  }

  if (status !== 0) problems.push(`the runner exited ${status}`);

  return problems;
}

/**
 * Which suites to run and how many tests to insist on.
 *
 * Parameterised because not every job can run every suite: the harness suites
 * need Caddy on the machine, and a job without it would skip them and trip the
 * floor. A floor that has to be wrong somewhere is a floor people delete.
 */
export function parseArgv(argv) {
  const files = [];
  let minimumTests = null;
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === '--min') {
      minimumTests = Number(argv[++i]);
      if (!Number.isFinite(minimumTests)) throw new Error('--min needs a number');
    } else {
      files.push(argv[i]);
    }
  }
  return {
    files: files.length ? files : TEST_FILES,
    minimumTests: minimumTests ?? MINIMUM_TESTS,
  };
}

// Run only when invoked directly, so the tests can import the analysis.
if (process.argv[1] && process.argv[1].endsWith('check-test-output.mjs')) {
  const { files, minimumTests } = parseArgv(process.argv.slice(2));
  const res = spawnSync(process.execPath, ['--test', ...files], {
    encoding: 'utf8',
    maxBuffer: 64 * 1024 * 1024,
  });
  const out = `${res.stdout ?? ''}${res.stderr ?? ''}`;
  process.stdout.write(out);

  const problems = analyseTapOutput({ out, status: res.status, minimumTests });
  if (problems.length) {
    console.error(`\nRefusing to call this a pass. ${problems.length} problem(s):\n`);
    for (const p of problems) console.error(`  - ${p}`);
    process.exit(1);
  }
  const ran = out.replace(/\r/g, '').split('\n').find((l) => l.startsWith('# tests '));
  console.log(`\nall suites clean: ${ran?.slice(8).trim()} tests, no TAP failures, runner exited 0.`);
}
