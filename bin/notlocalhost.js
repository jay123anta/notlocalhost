#!/usr/bin/env node
import { run } from '../src/cli.js';
import { EXIT } from '../src/exit-codes.js';

// The floor is set by playwright-core, which declares engines >=20. Checking it
// here turns a confusing failure deep inside a dependency into one clear line.
const [major] = process.versions.node.split('.').map(Number);
if (major < 20) {
  process.stderr.write(
    `notlocalhost needs Node 20 or newer; this is ${process.versions.node}.\n` +
      'The floor comes from playwright-core, which does not support older versions.\n',
  );
  process.exit(EXIT.TOOL_FAILURE);
}

try {
  process.exitCode = await run(process.argv.slice(2));
} catch (err) {
  process.stderr.write(`notlocalhost crashed: ${err?.stack ?? err}\n`);
  process.exitCode = EXIT.TOOL_FAILURE;
}
