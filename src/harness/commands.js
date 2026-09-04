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

    case 'init':
    case 'up':
    case 'down':
      stderr.write(
        `\n${c.yellow(`\`notlocalhost ${command}\` is not built yet.`)}\n\n` +
          `  The harness is in progress. What works today:\n\n` +
          `    ${c.bold('notlocalhost doctor')}   report on this machine, changing nothing\n` +
          `    ${c.bold('notlocalhost <url>')}    analyze a running dev server\n\n` +
          `  Nothing has been changed on this machine.\n`,
      );
      return EXIT.USAGE;

    default:
      stderr.write(`\n${c.red('error')}: unknown command "${command}"\n`);
      return EXIT.USAGE;
  }
}
