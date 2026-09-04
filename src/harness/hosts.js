/**
 * Hosts-file edits, and proving they were undone.
 *
 * This is the most invasive thing the harness does and the only change that
 * needs elevation on every platform, so it is built to be reversed rather than
 * built to be applied:
 *
 *   - Every line we add lives inside a marked block naming the project, so
 *     removal never has to guess which lines were ours.
 *   - The digest of the file is recorded before it is touched. `down` asserts
 *     the file matches that digest afterwards, so restoration is proven rather
 *     than assumed. If it does not match, we say so and change nothing further.
 *   - The original is copied alongside before writing, so a failure midway
 *     leaves a recoverable file rather than a truncated one.
 *   - Line endings are preserved. A CRLF hosts file rewritten with LF is not
 *     byte-identical, and on Windows that is the normal case.
 *
 * Every function takes an explicit path so the whole module can be tested
 * against a temporary file. Nothing here reads the real hosts file unless it
 * is told to.
 */
import { readFileSync, writeFileSync, copyFileSync, existsSync, rmSync } from 'node:fs';
import { createHash } from 'node:crypto';

export const BEGIN = (project) => `# >>> notlocalhost: ${project} >>>`;
export const END = (project) => `# <<< notlocalhost: ${project} <<<`;

export function digestOf(text) {
  return createHash('sha256').update(text).digest('hex');
}

export function digestOfFile(path) {
  return existsSync(path) ? createHash('sha256').update(readFileSync(path)).digest('hex') : null;
}

/** Detect the dominant line ending so a rewrite does not change every line. */
export function detectEol(text) {
  const crlf = (text.match(/\r\n/g) || []).length;
  const lf = (text.match(/(?<!\r)\n/g) || []).length;
  return crlf >= lf && crlf > 0 ? '\r\n' : '\n';
}

/**
 * Is our block already present?
 * @returns {{ present: boolean, start: number, end: number }} line indices, -1 when absent
 */
export function findBlock(text, project) {
  const eol = detectEol(text);
  const lines = text.split(eol);
  const start = lines.findIndex((l) => l.trim() === BEGIN(project));
  if (start === -1) return { present: false, start: -1, end: -1 };
  const end = lines.findIndex((l, i) => i > start && l.trim() === END(project));
  if (end === -1) return { present: false, start, end: -1 };
  return { present: true, start, end };
}

/**
 * Produce the new file content with our block added or updated.
 * Pure: takes text, returns text. The caller decides whether to write it.
 *
 * @param {string} text      Current file content.
 * @param {string} project
 * @param {string[]} hostnames
 * @param {string} [ip]
 */
export function withBlock(text, project, hostnames, ip = '127.0.0.1') {
  const eol = detectEol(text);
  const existing = findBlock(text, project);
  const lines = text.split(eol);

  const block = [
    BEGIN(project),
    '# Added by notlocalhost. Remove with `notlocalhost down`.',
    ...hostnames.map((h) => `${ip}\t${h}`),
    END(project),
  ];

  if (existing.present) {
    lines.splice(existing.start, existing.end - existing.start + 1, ...block);
    return lines.join(eol);
  }

  // Append, keeping exactly one blank line before the block. Whether the file
  // ended with a newline is preserved rather than normalised: adding one to a
  // file that lacked it means the removal can never restore it byte-for-byte,
  // and byte-for-byte is the promise.
  // Nothing in the existing content is normalised -- not trailing blank lines,
  // not the final newline. Tidying the file would be a change we cannot undo,
  // because removal has no way to know what was tidied away. Exactly one blank
  // separator is added, and removal takes exactly one back.
  const endedWithEol = text.endsWith(eol);
  const body = endedWithEol ? lines.slice(0, -1) : lines;
  const rebuilt = [...body, '', ...block].join(eol);
  return endedWithEol ? rebuilt + eol : rebuilt;
}

/**
 * Produce the content with our block removed.
 * Pure, like `withBlock`, so a restore can be checked before it is performed.
 */
export function withoutBlock(text, project) {
  const eol = detectEol(text);
  const found = findBlock(text, project);
  if (!found.present) return text;

  const lines = text.split(eol);
  lines.splice(found.start, found.end - found.start + 1);

  // Remove the single blank line we introduced before the block, but only if
  // it is one we added -- never collapse blank lines that were already there.
  if (found.start > 0 && lines[found.start - 1] !== undefined && lines[found.start - 1].trim() === '') {
    lines.splice(found.start - 1, 1);
  }
  return lines.join(eol);
}

/**
 * Add the block, recording everything needed to undo it.
 *
 * @returns {{ changed: boolean, before: string, after: string, backup: string|null }}
 *   `before` and `after` are digests.
 */
export function applyBlock(path, project, hostnames, opts = {}) {
  const { ip = '127.0.0.1', backupPath = `${path}.notlocalhost-backup` } = opts;
  const original = readFileSync(path, 'utf8');
  const before = digestOf(original);
  const updated = withBlock(original, project, hostnames, ip);

  if (updated === original) return { changed: false, before, after: before, backup: null };

  // Copy first. A failure between here and the write leaves something to
  // recover from, which matters when the file is the machine's name resolution.
  copyFileSync(path, backupPath);
  writeFileSync(path, updated, 'utf8');

  return { changed: true, before, after: digestOf(updated), backup: backupPath };
}

/**
 * Remove the block and prove the file came back to what it was.
 *
 * @param {string} path
 * @param {string} project
 * @param {string} expectedDigest  The digest recorded before the block was added.
 * @returns {{ restored: boolean, digest: string, matches: boolean, reason?: string }}
 */
export function removeBlock(path, project, expectedDigest, opts = {}) {
  const { backupPath = `${path}.notlocalhost-backup` } = opts;

  if (!existsSync(path)) {
    return { restored: false, digest: null, matches: false, reason: `${path} does not exist` };
  }

  const current = readFileSync(path, 'utf8');
  const found = findBlock(current, project);

  if (!found.present) {
    // Either it was never added, or someone removed it by hand. Either way the
    // right move is to report the truth and touch nothing.
    const digest = digestOf(current);
    return {
      restored: false,
      digest,
      matches: expectedDigest ? digest === expectedDigest : true,
      reason: 'no notlocalhost block found; nothing was removed',
    };
  }

  const updated = withoutBlock(current, project);
  writeFileSync(path, updated, 'utf8');
  const digest = digestOf(updated);
  const matches = expectedDigest ? digest === expectedDigest : true;

  if (matches) rmSync(backupPath, { force: true });

  return {
    restored: true,
    digest,
    matches,
    reason: matches
      ? undefined
      : `the file no longer matches its digest from before the change. ` +
        `Something else edited it in the meantime; the notlocalhost block was removed but other edits were kept. ` +
        (existsSync(backupPath) ? `The original is at ${backupPath}.` : ''),
  };
}

/** The lines that would be added, for showing someone before asking consent. */
export function previewBlock(project, hostnames, ip = '127.0.0.1') {
  return [
    BEGIN(project),
    '# Added by notlocalhost. Remove with `notlocalhost down`.',
    ...hostnames.map((h) => `${ip}\t${h}`),
    END(project),
  ];
}
