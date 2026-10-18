'use strict';
const fs = require('node:fs/promises');
const path = require('node:path');
const { createHash } = require('node:crypto');
const { createAuditSourceManifest } = require('./secureshopAuditSourceManifest');
const { createLaunchScope } = require('./secureshopConversationBinding');

// Internal preparation only. Paths/limits/authority come from server composition,
// never tool arguments. Files are private temporary inputs, not durable credit.
async function spoolAuditObservation({ root, rows, scope, runId, requestedCount,
  checkCurrent, signal, maxBytes = 64 * 1024 * 1024 } = {}) {
  const binding = createLaunchScope(scope);
  if (typeof root !== 'string' || !path.isAbsolute(root)
      || typeof rows?.[Symbol.asyncIterator] !== 'function'
      || typeof runId !== 'string' || !/^[a-zA-Z0-9-]{1,128}$/.test(runId)
      || !Number.isSafeInteger(requestedCount) || requestedCount < 1
      || !Number.isSafeInteger(maxBytes) || maxBytes < 1
      || typeof checkCurrent !== 'function') throw new TypeError('Owned audit spool required');
  const check = async () => { signal?.throwIfAborted(); await checkCurrent(binding); signal?.throwIfAborted(); };
  await check();
  const rootInfo = await fs.lstat(root);
  if (!rootInfo.isDirectory() || rootInfo.isSymbolicLink()) throw new TypeError('Private audit spool directory required');
  const directory = await fs.mkdtemp(path.join(root, 'audit-observation-'));
  const handles = [];
  let rowCount = 0, bytes = 0, previous = null;
  const logHash = createHash('sha256'), sourceHash = createHash('sha256');
  const paths = Object.freeze({ log: path.join(directory, 'log.txt'), sources: path.join(directory, 'sources.json'),
    manifest: path.join(directory, 'manifest.json') });
  try {
    await fs.chmod(directory, 0o700);
    const log = await fs.open(paths.log, 'wx', 0o600); handles.push(log);
    const sources = await fs.open(paths.sources, 'wx', 0o600); handles.push(sources);
    async function write(handle, value, hash) {
      const size = Buffer.byteLength(value);
      if (bytes + size > maxBytes) {
        throw Object.assign(new Error('Audit observation storage budget exceeded'), {
          code: 'AUDIT_OBSERVATION_RESOURCE_LIMIT', metrics: Object.freeze({ rowCount, bytesWritten: bytes,
            attemptedWriteBytes: size, limitBytes: maxBytes, requestedCount }),
        });
      }
      await handle.writeFile(value, 'utf8'); bytes += size; hash?.update(value, 'utf8');
    }
    await write(sources, '[', sourceHash);
    for await (const row of rows) {
      await check();
      if (rowCount >= requestedCount) throw new TypeError('Audit source exceeded requested count');
      const one = createAuditSourceManifest([row],{consumerScope:binding});
      const source = one.sources[0];
      if (previous && (previous.ts.localeCompare(source.ts)
          || previous.store.localeCompare(source.store) || previous.id.localeCompare(source.id)) <= 0) {
        throw new TypeError('Audit source order or identity is invalid');
      }
      await write(log, (rowCount ? '\n' : '') + one.logText, logHash);
      await write(sources, (rowCount ? ',' : '') + JSON.stringify(source), sourceHash);
      previous = source; rowCount++;
    }
    await check();
    await write(sources, ']', sourceHash);
    const manifest = Object.freeze({ version: 1, scope: binding, runId, requestedCount, rowCount,
      logSha256: logHash.digest('hex'), sourcesSha256: sourceHash.digest('hex'),
      sourceBytes: bytes, storageLimitBytes: maxBytes });
    // Publication marker appears only after both complete files have synced.
    for (const handle of handles) { await handle.sync(); await handle.close(); }
    handles.length = 0;
    await check();
    await fs.writeFile(paths.manifest, JSON.stringify(manifest), { flag: 'wx', mode: 0o600 });
    await check();
    return Object.freeze({ directory, paths, manifest,
      async dispose() { await fs.rm(directory, { recursive: true, force: true }); } });
  } catch (error) {
    const cleanup = await Promise.allSettled(handles.map(handle => handle.close()));
    await fs.rm(directory, { recursive: true, force: true });
    const failed = cleanup.find(result => result.status === 'rejected');
    if (failed) throw new AggregateError([error, failed.reason], 'Audit spool cleanup failed');
    throw error;
  }
}
module.exports = { spoolAuditObservation };
