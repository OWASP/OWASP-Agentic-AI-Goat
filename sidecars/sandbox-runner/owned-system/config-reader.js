'use strict';
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const MAX_BYTES = 512 * 1024;
function failure(code) { return { ok: false, error: code }; }

// Target-internal primitive. The executor supplies a read-only synthetic root;
// HTTP callers must never choose this directory. This is not a launch-authority
// check or proof that a namespace was used.
function readSyntheticConfig(root, input) {
  if (typeof root !== 'string' || !path.isAbsolute(root)) throw new TypeError('Synthetic target root required');
  if (typeof input !== 'string' || !input.isWellFormed() || input.includes('\0') || Buffer.byteLength(input) > 4096) return failure('invalid config path');
  if (input.startsWith('/') || /^[A-Za-z]:[\\/]/.test(input) || input.startsWith('\\\\')) return failure('absolute paths not allowed');
  // Preserve the teaching parser: ....// escapes config/ into the synthetic
  // parent. Containment applies to the target, not the vulnerable config base.
  const sanitized = input.replace(/\.\.\//g, '').replace(/\.\.\\/g, '');
  const targetRoot = path.resolve(root);
  const resolved = path.resolve(targetRoot, 'config', sanitized);
  const relative = path.relative(targetRoot, resolved);
  if (relative === '..' || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative)) return failure('path outside synthetic target');
  let fd;
  try {
    // No host aliases, links, devices or directories in the fixture reader.
    const rootStat = fs.lstatSync(targetRoot);
    if (!rootStat.isDirectory() || rootStat.isSymbolicLink()) return failure('invalid synthetic target');
    let current = targetRoot;
    for (const part of relative.split(path.sep).filter(Boolean)) {
      current = path.join(current, part);
      if (fs.lstatSync(current).isSymbolicLink()) return failure('links not allowed');
    }
    fd = fs.openSync(resolved, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK);
    const before = fs.fstatSync(fd);
    if (!before.isFile() || before.nlink !== 1) return failure('regular fixture file required');
    if (before.size > MAX_BYTES) return failure('file too large');
    const bytes = Buffer.alloc(MAX_BYTES + 1);
    let count = 0;
    while (count < bytes.length) {
      const read = fs.readSync(fd, bytes, count, bytes.length - count, null);
      if (!read) break;
      count += read;
    }
    const after = fs.fstatSync(fd);
    if (count > MAX_BYTES) return failure('file too large');
    if (after.size !== before.size || after.mtimeMs !== before.mtimeMs || after.ctimeMs !== before.ctimeMs || count !== before.size) return failure('fixture changed during read');
    const output = bytes.subarray(0, count);
    let content;
    try { content = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(output); }
    catch { return failure('config is not UTF-8 text'); }
    return { ok: true, input, sanitized, targetPath: `/app/${relative.split(path.sep).join('/')}`,
      size: count, content, contentSha256: crypto.createHash('sha256').update(output).digest('hex') };
  } catch (error) {
    return failure(error.code === 'ENOENT' ? 'config not found' : 'config read unavailable');
  } finally { if (fd !== undefined) fs.closeSync(fd); }
}
module.exports = { readSyntheticConfig, MAX_BYTES };
