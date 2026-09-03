import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));

/** Read from package.json so there is exactly one place the version lives. */
export const VERSION = JSON.parse(readFileSync(join(here, '..', 'package.json'), 'utf8')).version;

/**
 * The JSON document schema version.
 *
 * Bumped only for breaking changes to the document shape. Adding a field is
 * not breaking; removing or retyping one is. CI consumers pin on this.
 */
export const SCHEMA_VERSION = 1;
