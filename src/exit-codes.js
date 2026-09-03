/**
 * Exit codes. Documented in the README as a table, asserted in tests, and
 * stable across minor versions -- CI adoption depends on that.
 */
export const EXIT = {
  /** No findings at or above the --fail-on threshold. */
  CLEAN: 0,
  /** Findings at or above the threshold. The normal "this found something" code. */
  FINDINGS: 1,
  /** The target could not be reached or did not respond. Nothing was analyzed. */
  UNREACHABLE: 2,
  /** The tool itself failed: no browser, a crash, an unwritable report path. */
  TOOL_FAILURE: 5,
  /** Bad arguments. Matches the BSD sysexits EX_USAGE convention. */
  USAGE: 64,
};

export const EXIT_DESCRIPTIONS = [
  [EXIT.CLEAN, 'Clean', 'No findings at or above --fail-on.'],
  [EXIT.FINDINGS, 'Findings', 'One or more findings at or above --fail-on.'],
  [EXIT.UNREACHABLE, 'Unreachable', 'The target did not respond. Nothing was analyzed.'],
  [EXIT.TOOL_FAILURE, 'Tool failure', 'No usable browser, an internal error, or the report could not be written.'],
  [EXIT.USAGE, 'Usage error', 'Invalid or missing arguments.'],
];
