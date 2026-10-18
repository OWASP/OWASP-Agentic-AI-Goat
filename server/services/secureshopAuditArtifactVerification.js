'use strict';
const fs = require('node:fs/promises');
const { constants } = require('node:fs');
const path = require('node:path');
const { createHash } = require('node:crypto');
const MAX_ARTIFACT_BYTES = 128 * 1024 * 1024;
const invalid = () => Object.assign(new Error('Audit artifact verification failed'), { code: 'AUDIT_ARTIFACT_INVALID' });
async function verifyAuditWorkerArtifacts({ directory, artifacts, manifest, checkCurrent, signal } = {}) {
  if (typeof directory !== 'string' || !path.isAbsolute(directory) || !artifacts
      || Object.getPrototypeOf(artifacts) !== Object.prototype
      || Object.keys(artifacts).sort().join(',') !== 'effects,messages,traces'
      || typeof checkCurrent !== 'function') throw invalid();
  const references = {}; let total = 0;
  for (const name of ['messages', 'traces', 'effects']) {
    const ref = artifacts[name];
    if (!ref || Object.keys(ref).sort().join(',') !== 'bytes,sha256'
        || !Number.isSafeInteger(ref.bytes) || ref.bytes < 0
        || typeof ref.sha256 !== 'string' || !/^[a-f0-9]{64}$/.test(ref.sha256)) throw invalid();
    total += ref.bytes;
    if (total > MAX_ARTIFACT_BYTES) throw invalid();
    references[name] = Object.freeze({ bytes: ref.bytes, sha256: ref.sha256 });
  }
  if (!manifest || !Number.isSafeInteger(manifest.sourceBytes) || manifest.sourceBytes < 0
      || manifest.sourceBytes > 64 * 1024 * 1024
      || ![manifest.logSha256, manifest.sourcesSha256].every(value => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value))) throw invalid();
  const check = async () => { signal?.throwIfAborted(); await checkCurrent(); signal?.throwIfAborted(); };
  await check();
  const directoryStat = await fs.lstat(directory);
  if (!directoryStat.isDirectory() || directoryStat.isSymbolicLink()) throw invalid();
  async function verify(name, expected, maximum) {
    await check();
    const handle = await fs.open(path.join(directory, name), constants.O_RDONLY | constants.O_NOFOLLOW);
    try {
      const before = await handle.stat();
      if (!before.isFile() || before.size > maximum || (expected.bytes !== undefined && before.size !== expected.bytes)) throw invalid();
      const hash = createHash('sha256'); let bytes = 0;
      const buffer = Buffer.alloc(64 * 1024);
      for (;;) {
        await check();
        const { bytesRead } = await handle.read(buffer, 0, buffer.length, null);
        if (!bytesRead) break;
        bytes += bytesRead;
        if (bytes > maximum || bytes > before.size) throw invalid();
        hash.update(buffer.subarray(0, bytesRead));
      }
      const after = await handle.stat();
      if (bytes !== before.size || after.size !== before.size || after.mtimeMs !== before.mtimeMs
          || hash.digest('hex') !== expected.sha256) throw invalid();
      await check(); return bytes;
    } finally { await handle.close(); }
  }
  const logBytes = await verify('log.txt', { sha256: manifest.logSha256 }, manifest.sourceBytes);
  const sourceBytes = await verify('sources.json', { sha256: manifest.sourcesSha256 }, manifest.sourceBytes);
  if (logBytes + sourceBytes !== manifest.sourceBytes) throw invalid();
  for (const name of ['messages', 'traces', 'effects']) await verify(`${name}.json`, references[name], references[name].bytes);
  await check();
  return Object.freeze(references);
}
module.exports = { verifyAuditWorkerArtifacts };
