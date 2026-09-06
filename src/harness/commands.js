/**
 * Harness command dispatch.
 *
 * Kept apart from the analyzer's CLI so that `notlocalhost <url>` -- the
 * shipped, published path -- imports none of this. The harness can download a
 * binary and install a certificate authority; the analyzer must remain a thing
 * that reads and reports. Separating them in the module graph rather than only
 * in the documentation is what makes that true instead of merely claimed.
 */
import { EXIT } from '../exit-codes.js';
import { diagnose, renderDoctor } from './doctor.js';
import { init, up, down } from './lifecycle.js';
import { readConfig, describeChanges, TIERS } from './config.js';
import { summariseSites } from './caddyfile.js';

/**
 * @param {'init'|'up'|'down'|'doctor'} command
 * @param {object} options   Parsed CLI options.
 * @param {{stdout: NodeJS.WriteStream, stderr: NodeJS.WriteStream, styler: object}} io
 * @returns {Promise<number>} exit code
 */
export async function runHarnessCommand(command, options, io) {
  const { stdout, stderr, styler: c } = io;

  switch (command) {
    case 'doctor': {
      const result = await diagnose({ cwd: process.cwd() });

      if (options.json === true) {
        stdout.write(`${JSON.stringify(result, null, 2)}\n`);
      } else {
        stdout.write(`${renderDoctor(result, c)}\n`);
      }

      // A blocking issue is a real finding, so it earns a non-zero exit for the
      // same reason the analyzer's does: someone will want to branch on it.
      // Everything else -- needing elevation, wanting to download Caddy -- is a
      // fact about the machine, not a failure.
      return result.blocking.length ? EXIT.FINDINGS : EXIT.CLEAN;
    }

    case 'init': {
      const log = (m) => stderr.write(`${c.dim(`  ${m}`)}\n`);
      const result = await init({ cwd: process.cwd(), tier: options.tier, force: options.force, log });

      stdout.write(`\n${c.bold('Initialised')} ${result.config.project} ${c.dim(`(${result.config.tier} tier)`)}\n\n`);
      for (const line of summariseSites(result.config)) stdout.write(`  ${line}\n`);
      stdout.write(`\n  ${c.dim(`configuration written to ${result.path}`)}\n`);

      stdout.write(`\n${c.bold('Running up would change this machine:')}\n\n`);
      writeChanges(stdout, c, result.changes);

      const tier = TIERS[result.config.tier];
      if (tier.cannotGive.length) {
        stdout.write(`  ${c.yellow('What this tier cannot give you:')}\n`);
        for (const x of tier.cannotGive) stdout.write(`    ${c.dim(x)}\n`);
        stdout.write('\n');
      }
      stdout.write(`  Nothing has been changed yet. Run ${c.bold('notlocalhost up --yes')} when you are ready.\n\n`);
      return EXIT.CLEAN;
    }

    case 'up': {
      const config = readConfig(process.cwd());
      if (!config) {
        stderr.write(`\n${c.red('not initialised')}: run ${c.bold('notlocalhost init')} first.\n`);
        return EXIT.USAGE;
      }

      // Consent is obtained here and never inside the function that acts, so
      // that neither can be exercised without the other being visible.
      if (!options.yes) {
        stdout.write(`\n${c.bold('This will change your machine:')}\n\n`);
        // The ports actually being asked for. The other call site was fixed
        // and this one was not, so the screen a person reads before consenting
        // was the one still naming 80 and 443 -- and asking for a password on
        // macOS and Linux that high ports do not need.
        writeChanges(stdout, c, describeChanges(config, { httpPort: options.httpPort, httpsPort: options.httpsPort }));
        stdout.write(`  Re-run with ${c.bold('--yes')} to proceed. Nothing has been changed.\n\n`);
        return EXIT.CLEAN;
      }

      const log = (m) => stderr.write(`${c.dim(`  ${m}`)}\n`);
      const result = await up({
        cwd: process.cwd(),
        consent: true,
        httpPort: options.httpPort,
        httpsPort: options.httpsPort,
        log,
      });

      stdout.write(`\n${c.green(c.bold('Up.'))}\n\n`);
        // A run asked to install trust that could not says so here, beside
        // the success, rather than in a log line above it that scrolls past.
        // The proxy is up either way; the browser behaves differently.
        if (result.trustSkipped) {
            stdout.write(`  ${c.yellow(result.trustSkipped)}` + String.fromCharCode(10, 10));
        }
      for (const line of summariseSites(result.config)) stdout.write(`  ${line}\n`);
      stdout.write(`\n  ${c.dim(`proxy log: ${result.logPath}`)}\n`);
      stdout.write(`  ${c.dim('notlocalhost down reverses everything above.')}\n\n`);
      return EXIT.CLEAN;
    }

    case 'down': {
      const log = (m) => stderr.write(`${c.dim(`  ${m}`)}\n`);
      const result = await down({ cwd: process.cwd(), purge: options.purge, log });

      if (result.didNothing) {
        stdout.write(`\n  ${result.summary}\n\n`);
        return EXIT.CLEAN;
      }

      stdout.write('\n');
      for (const step of result.steps) {
        stdout.write(`  ${step.ok ? c.green('done  ') : c.red('FAILED')}  ${step.what}\n`);
        stdout.write(`          ${c.dim(step.detail)}\n`);
        for (const a of step.advice ?? []) stdout.write(`          ${c.yellow(a)}\n`);
      }
      stdout.write(`\n  ${result.clean ? c.green(result.summary) : c.red(result.summary)}\n\n`);

      // A step that could not be completed leaves something behind, and the
      // caller should be able to notice that from an exit code alone.
      return result.clean ? EXIT.CLEAN : EXIT.TOOL_FAILURE;
    }

    default:
      stderr.write(`\n${c.red('error')}: unknown command "${command}"\n`);
      return EXIT.USAGE;
  }
}

/**
 * Print a change list.
 *
 * Every entry names what changes, what it means, and how it is undone. Someone
 * who reads only this should be able to decide, and should never be surprised
 * afterwards -- which is the entire contract of asking before acting.
 */
function writeChanges(stdout, c, changes) {
  for (const change of changes) {
    stdout.write(`  ${c.bold(change.what)}${change.elevation ? c.yellow('  (needs elevation)') : ''}\n`);
    stdout.write(`    ${c.dim(change.detail)}\n`);
    stdout.write(`    ${c.dim(`reversed by: ${change.reversedBy}`)}\n\n`);
  }
}
