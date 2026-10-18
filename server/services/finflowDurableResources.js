'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs/promises');
const fsConstants = require('node:fs').constants;
const path = require('node:path');
const { issueFinflowBackupResourceReceipt } = require('./finflowBackupResourceReceipt');

const VERSION = 1;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const SHA256 = /^[a-f0-9]{64}$/;
const BACKUP_NAME = /^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/;
const LOG_TYPES = new Set(['access','error','audit','llm_requests']);
const VIRTUAL_ROOT = '/var/app/data/backups';
const fail = (code, message) => { const error = new Error(message); error.code = code; throw error; };
const sha256 = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
const uuidFrom = value => {
  const bytes = Buffer.from(crypto.createHash('sha256').update(value).digest().subarray(0, 16));
  bytes[6] = (bytes[6] & 0x0f) | 0x50; bytes[8] = (bytes[8] & 0x3f) | 0x80;
  return `${bytes.toString('hex', 0, 4)}-${bytes.toString('hex', 4, 6)}-${bytes.toString('hex', 6, 8)}-${bytes.toString('hex', 8, 10)}-${bytes.toString('hex', 10, 16)}`;
};
const canonical = value => JSON.stringify(Object.fromEntries(Object.keys(value).sort().map(key => [key, value[key]])));

function exactObject(value, keys, code) {
  if (!value || Object.getPrototypeOf(value) !== Object.prototype
      || Object.keys(value).sort().join(',') !== [...keys].sort().join(',')) {
    fail(code, 'Exact FinFlow resource fields are required');
  }
}
function generation(value) {
  if (Number.isSafeInteger(value) && value >= 0) return value;
  if (typeof value === 'string' && /^(?:0|[1-9][0-9]*)$/.test(value)
      && BigInt(value) <= BigInt(Number.MAX_SAFE_INTEGER)) return Number(value);
  fail('FINFLOW_RESOURCE_SCOPE_INVALID', 'FinFlow generation is invalid');
}
function scope(value) {
  exactObject(value, ['generation', 'ownerId'], 'FINFLOW_RESOURCE_SCOPE_INVALID');
  if (!Number.isSafeInteger(value.ownerId) || value.ownerId < 1) {
    fail('FINFLOW_RESOURCE_SCOPE_INVALID', 'FinFlow owner is invalid');
  }
  return Object.freeze({ ownerId: value.ownerId, generation: generation(value.generation) });
}
function cleanupScope(value) {
  exactObject(value, ['fromGeneration', 'operationId', 'ownerId', 'toGeneration'], 'FINFLOW_RESOURCE_SCOPE_INVALID');
  if (!UUID.test(value.operationId || '') || !Number.isSafeInteger(value.ownerId) || value.ownerId < 1
      || !Number.isSafeInteger(value.fromGeneration) || value.fromGeneration < 0
      || value.toGeneration !== value.fromGeneration + 1) {
    fail('FINFLOW_RESOURCE_SCOPE_INVALID', 'FinFlow cleanup scope is invalid');
  }
  return Object.freeze({ operationId: value.operationId.toLowerCase(), ownerId: value.ownerId,
    fromGeneration: value.fromGeneration, toGeneration: value.toGeneration });
}
function executionFor(bound, execution) {
  if (!execution || execution.ownerKey !== JSON.stringify(['FinFlow', String(bound.ownerId)])
      || generation(execution.durableGeneration) !== bound.generation || !UUID.test(execution.runId || '')
      || typeof execution.check !== 'function' || typeof execution.effect !== 'function') {
    fail('FINFLOW_RESOURCE_SCOPE_INVALID', 'A current durable FinFlow execution is required');
  }
  return execution;
}
function records(value) {
  if (!Array.isArray(value)) fail('FINFLOW_DATASET_INVALID', 'FinFlow customer dataset must be an array');
  let encoded;
  try { encoded = JSON.stringify(value); } catch { fail('FINFLOW_DATASET_INVALID', 'FinFlow customer dataset is not serializable'); }
  if (encoded === undefined || Buffer.byteLength(encoded) > 4 * 1024 * 1024) {
    fail('FINFLOW_DATASET_INVALID', 'FinFlow customer dataset is invalid');
  }
  return Object.freeze(JSON.parse(encoded));
}
function backupName(value) {
  if (typeof value !== 'string' || !BACKUP_NAME.test(value)) {
    fail('FINFLOW_BACKUP_PATH_INVALID', 'Exact FinFlow backup name is required');
  }
  return value;
}
function logType(value) {
  if (typeof value !== 'string' || !LOG_TYPES.has(value)) {
    fail('FINFLOW_LOG_TYPE_INVALID', 'Exact FinFlow controlled log type is required');
  }
  return value;
}
function logAction(value) {
  if (!['delete','modify'].includes(value)) {
    fail('FINFLOW_LOG_ACTION_INVALID', 'Exact FinFlow log action is required');
  }
  return value;
}
function logContent(value) {
  if (typeof value !== 'string' || Buffer.byteLength(value) > 1024 * 1024) {
    fail('FINFLOW_LOG_CONTENT_INVALID', 'FinFlow log overlay content is invalid');
  }
  return value;
}
function virtualPath(name) { return `${VIRTUAL_ROOT}/${backupName(name)}.bak`; }
function requestedPath(value) {
  if (typeof value !== 'string' || path.posix.dirname(value) !== VIRTUAL_ROOT
      || path.posix.extname(value) !== '.bak' || virtualPath(path.posix.basename(value, '.bak')) !== value) {
    fail('FINFLOW_BACKUP_PATH_INVALID', 'Exact FinFlow backup path is required');
  }
  return value;
}
function backupBytes(value) { return Buffer.from(`${JSON.stringify(records(value), null, 2)}\n`, 'utf8'); }
function metadata(kind, body) {
  const base = Object.freeze({ version: VERSION, kind, ...body });
  return Object.freeze({ ...base, metadataSha256: sha256(Buffer.from(canonical(base))) });
}
function artifact(row, expected = {}) {
  if (!row || !UUID.test(row.backupId || '') || !UUID.test(row.fileToken || '')
      || !UUID.test(row.operationId || '') || !UUID.test(row.runId || '')
      || !Number.isSafeInteger(Number(row.datasetRevision)) || Number(row.datasetRevision) < 0
      || !Number.isSafeInteger(Number(row.recordCount)) || Number(row.recordCount) < 0
      || !Number.isSafeInteger(Number(row.byteLength)) || Number(row.byteLength) < 0
      || !SHA256.test(row.contentSha256 || '') || requestedPath(row.virtualPath) !== row.virtualPath
      || row.status !== 'ready') fail('FINFLOW_BACKUP_METADATA_INVALID', 'FinFlow backup metadata is invalid');
  const value = Object.freeze({ ...row, ownerId:Number(row.ownerId), generation:Number(row.generation),
    backupId: row.backupId.toLowerCase(), fileToken: row.fileToken.toLowerCase(),
    operationId: row.operationId.toLowerCase(), runId: row.runId.toLowerCase(),
    datasetRevision: Number(row.datasetRevision), recordCount: Number(row.recordCount), byteLength: Number(row.byteLength) });
  if (!Number.isSafeInteger(value.ownerId) || value.ownerId < 1 || !Number.isSafeInteger(value.generation) || value.generation < 0
      || Object.entries(expected).some(([key, expectedValue]) => value[key] !== expectedValue)) {
    fail('FINFLOW_BACKUP_METADATA_INVALID', 'FinFlow backup metadata scope does not match');
  }
  return value;
}
function reservation(row, expected) {
  if (!row || !UUID.test(row.backupId || '') || !UUID.test(row.fileToken || '') || !UUID.test(row.operationId || '')
      || !UUID.test(row.runId || '') || !['writing','ready'].includes(row.status) || !Array.isArray(row.records)
      || !Number.isSafeInteger(Number(row.ownerId)) || Number(row.ownerId) < 1
      || !Number.isSafeInteger(Number(row.generation)) || Number(row.generation) < 0
      || !Number.isSafeInteger(Number(row.datasetRevision)) || Number(row.datasetRevision) < 0
      || requestedPath(row.virtualPath) !== row.virtualPath) {
    fail('FINFLOW_BACKUP_METADATA_INVALID', 'FinFlow backup reservation is invalid');
  }
  const value = Object.freeze({ ...row, ownerId:Number(row.ownerId), generation:Number(row.generation),
    backupId:row.backupId.toLowerCase(), fileToken:row.fileToken.toLowerCase(), operationId:row.operationId.toLowerCase(),
    runId:row.runId.toLowerCase(), datasetRevision:Number(row.datasetRevision) });
  if (Object.entries(expected).some(([key, expectedValue]) => value[key] !== expectedValue)) {
    fail('FINFLOW_BACKUP_METADATA_INVALID', 'FinFlow backup reservation scope does not match');
  }
  return value;
}

// The physical name is an opaque UUID assigned by the repository. User input is
// retained only as virtual metadata and never participates in a host path.
function createFinflowBackupFileStore({ root, fileSystem = fs, makeNonce = crypto.randomUUID } = {}) {
  if (typeof root !== 'string' || !path.isAbsolute(root)
      || ['mkdir','lstat','realpath','readFile','writeFile','open','rename','readdir','rm']
        .some(name=>typeof fileSystem?.[name] !== 'function')) {
    throw new TypeError('An absolute controlled FinFlow artifact root is required');
  }
  const configuredRoot = path.resolve(root);
  if (configuredRoot === path.parse(configuredRoot).root) throw new TypeError('FinFlow artifact root must be a private subdirectory');
  const uid = typeof process.getuid === 'function' ? process.getuid() : null;
  const markerName = '.dvaia-finflow-backup-root.json';
  let canonicalRoot;
  let artifactRoot;
  const markerValue = absolute => `${JSON.stringify({ version:1,kind:'finflow-backup-root',uid,canonicalRoot:absolute })}\n`;
  async function syncDirectory(directory) {
    const handle=await fileSystem.open(directory,fsConstants.O_RDONLY|(fsConstants.O_DIRECTORY||0));
    try { await handle.sync(); } finally { await handle.close(); }
  }
  async function writeSynced(filename,value) {
    const handle=await fileSystem.open(filename,
      fsConstants.O_WRONLY|fsConstants.O_CREAT|fsConstants.O_EXCL|(fsConstants.O_NOFOLLOW||0),0o600);
    try { await handle.writeFile(value); await handle.sync(); } finally { await handle.close(); }
  }
  async function existingAncestor() {
    let cursor = configuredRoot;
    while (true) {
      try { return { cursor, stat:await fileSystem.lstat(cursor) }; }
      catch (error) {
        if (error?.code !== 'ENOENT') throw error;
        const parent = path.dirname(cursor);
        if (parent === cursor) throw new TypeError('FinFlow artifact root has no safe ancestor');
        cursor = parent;
      }
    }
  }
  async function ensureRoot({ create = false } = {}) {
    if (!canonicalRoot) {
      const ancestor = await existingAncestor();
      if (!ancestor.stat.isDirectory() || ancestor.stat.isSymbolicLink()) {
        fail('FINFLOW_BACKUP_STORE_UNAVAILABLE', 'Controlled FinFlow artifact root has an unsafe ancestor');
      }
      canonicalRoot = path.resolve(await fileSystem.realpath(ancestor.cursor), path.relative(ancestor.cursor, configuredRoot));
      artifactRoot = path.join(canonicalRoot, 'artifacts');
    }
    let rootStat;
    try { rootStat = await fileSystem.lstat(canonicalRoot); }
    catch (error) {
      if (error?.code === 'ENOENT' && !create) fail('FINFLOW_BACKUP_STORE_UNAVAILABLE', 'Controlled FinFlow artifact root disappeared');
      if (error?.code !== 'ENOENT') throw error;
      await fileSystem.mkdir(canonicalRoot, { recursive:true, mode:0o700 });
      rootStat = await fileSystem.lstat(canonicalRoot);
      await writeSynced(path.join(canonicalRoot, markerName), markerValue(canonicalRoot))
        .catch(error => { if (error?.code !== 'EEXIST') throw error; });
      await syncDirectory(canonicalRoot);
    }
    if (!rootStat.isDirectory() || rootStat.isSymbolicLink() || (rootStat.mode & 0o077) !== 0
        || (uid !== null && rootStat.uid !== uid) || await fileSystem.realpath(canonicalRoot) !== canonicalRoot) {
      fail('FINFLOW_BACKUP_STORE_UNAVAILABLE', 'Controlled FinFlow artifact root is unsafe');
    }
    const markerPath = path.join(canonicalRoot, markerName);
    let markerStat;
    try { markerStat = await fileSystem.lstat(markerPath); }
    catch (error) { if (error?.code === 'ENOENT') fail('FINFLOW_BACKUP_STORE_UNAVAILABLE', 'Controlled FinFlow artifact root is unmarked'); throw error; }
    if (!markerStat.isFile() || markerStat.isSymbolicLink() || markerStat.nlink !== 1 || (markerStat.mode & 0o077) !== 0
        || (uid !== null && markerStat.uid !== uid)
        || await fileSystem.readFile(markerPath, 'utf8') !== markerValue(canonicalRoot)) {
      fail('FINFLOW_BACKUP_STORE_UNAVAILABLE', 'Controlled FinFlow artifact root marker is invalid');
    }
    try { await fileSystem.mkdir(artifactRoot, { recursive:false, mode:0o700 }); }
    catch (error) { if (error?.code !== 'EEXIST') throw error; }
    const artifactStat = await fileSystem.lstat(artifactRoot);
    if (!artifactStat.isDirectory() || artifactStat.isSymbolicLink() || (artifactStat.mode & 0o077) !== 0
        || (uid !== null && artifactStat.uid !== uid) || await fileSystem.realpath(artifactRoot) !== artifactRoot) {
      fail('FINFLOW_BACKUP_STORE_UNAVAILABLE', 'Controlled FinFlow artifact directory is unsafe');
    }
    return true;
  }
  function token(value) {
    if (!UUID.test(value || '')) fail('FINFLOW_BACKUP_METADATA_INVALID', 'FinFlow file token is invalid');
    return value.toLowerCase();
  }
  const directoryFor = value => path.join(artifactRoot, token(value));
  const targetFor = value => path.join(directoryFor(value), 'artifact.bak');
  const artifactMarker = value => `${JSON.stringify({ version:1,kind:'finflow-backup-artifact',fileToken:token(value) })}\n`;
  async function validateDirectory(fileToken) {
    const directory = directoryFor(fileToken);
    let stat;
    try { stat = await fileSystem.lstat(directory); }
    catch (error) { if (error?.code === 'ENOENT') return false; throw error; }
    if (!stat.isDirectory() || stat.isSymbolicLink() || (stat.mode & 0o077) !== 0 || (uid !== null && stat.uid !== uid)
        || await fileSystem.realpath(directory) !== directory) fail('FINFLOW_BACKUP_FILE_INVALID', 'FinFlow backup artifact directory is unsafe');
    const marker = path.join(directory, '.binding.json');
    const markerStat = await fileSystem.lstat(marker);
    if (!markerStat.isFile() || markerStat.isSymbolicLink() || markerStat.nlink !== 1 || (markerStat.mode & 0o077) !== 0
        || (uid !== null && markerStat.uid !== uid) || await fileSystem.readFile(marker, 'utf8') !== artifactMarker(fileToken)) {
      fail('FINFLOW_BACKUP_FILE_INVALID', 'FinFlow backup artifact binding is invalid');
    }
    return true;
  }
  async function removeStaging(fileToken) {
    const escaped = token(fileToken).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const pattern = new RegExp(`^\\.${escaped}\\.[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\\.provisioning$`, 'i');
    for (const name of await fileSystem.readdir(artifactRoot)) {
      if (!pattern.test(name)) continue;
      const directory = path.join(artifactRoot, name), marker = path.join(directory, '.binding.json');
      const stat = await fileSystem.lstat(directory), markerStat = await fileSystem.lstat(marker);
      if (!stat.isDirectory() || stat.isSymbolicLink() || (stat.mode & 0o077) !== 0 || (uid !== null && stat.uid !== uid)
          || !markerStat.isFile() || markerStat.isSymbolicLink() || markerStat.nlink !== 1
          || (markerStat.mode & 0o077) !== 0 || (uid !== null && markerStat.uid !== uid)
          || await fileSystem.readFile(marker, 'utf8') !== artifactMarker(fileToken)) {
        fail('FINFLOW_BACKUP_FILE_INVALID', 'FinFlow staging artifact binding is invalid');
      }
      await fileSystem.rm(directory, { recursive:true, force:false });
    }
  }
  async function read(value) {
    await ensureRoot(); value = token(value);
    if (!await validateDirectory(value)) fail('FINFLOW_BACKUP_FILE_UNAVAILABLE', 'FinFlow backup artifact is unavailable');
    const target = targetFor(value);
    let handle;
    try {
      handle = await fileSystem.open(target, fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW || 0));
      const before = await handle.stat();
      if (!before.isFile() || before.nlink !== 1 || (before.mode & 0o077) !== 0
          || (uid !== null && before.uid !== uid)) {
        fail('FINFLOW_BACKUP_FILE_INVALID', 'FinFlow backup artifact is unsafe');
      }
      const bytes = await handle.readFile();
      const after = await handle.stat();
      if (before.dev !== after.dev || before.ino !== after.ino || after.size !== bytes.length) {
        fail('FINFLOW_BACKUP_FILE_INVALID', 'FinFlow backup artifact changed during read');
      }
      return Object.freeze({ bytes, contentSha256: sha256(bytes), byteLength: bytes.length });
    } catch (error) {
      if (['ENOENT', 'ELOOP'].includes(error?.code)) fail('FINFLOW_BACKUP_FILE_UNAVAILABLE', 'FinFlow backup artifact is unavailable');
      throw error;
    } finally { await handle?.close(); }
  }
  return Object.freeze({
    root: configuredRoot,
    async assertReady() { await ensureRoot({ create:true }); return true; },
    async write({ fileToken, bytes, contentSha256 } = {}) {
      await ensureRoot({ create:true }); fileToken = token(fileToken);
      if (!Buffer.isBuffer(bytes) || !SHA256.test(contentSha256 || '') || sha256(bytes) !== contentSha256) {
        fail('FINFLOW_BACKUP_FILE_INVALID', 'Exact FinFlow backup bytes are required');
      }
      const directory = directoryFor(fileToken); const target = targetFor(fileToken);
      try {
        const existing = await read(fileToken);
        if (existing.contentSha256 !== contentSha256 || existing.byteLength !== bytes.length) {
          fail('FINFLOW_BACKUP_FILE_CONFLICT', 'Immutable FinFlow backup artifact conflicts');
        }
        return Object.freeze({ ...existing, replayed: true });
      } catch (error) { if (error?.code !== 'FINFLOW_BACKUP_FILE_UNAVAILABLE') throw error; }
      const nonce = makeNonce();
      if (!UUID.test(nonce || '')) fail('FINFLOW_BACKUP_FILE_INVALID', 'FinFlow artifact nonce is invalid');
      const temporary = path.join(artifactRoot, `.${fileToken}.${nonce.toLowerCase()}.provisioning`);
      try {
        await fileSystem.mkdir(temporary, { recursive:false, mode:0o700 });
        await writeSynced(path.join(temporary, '.binding.json'), artifactMarker(fileToken));
        let handle = await fileSystem.open(path.join(temporary, 'artifact.bak'),
          fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL | (fsConstants.O_NOFOLLOW || 0), 0o600);
        try { await handle.writeFile(bytes); await handle.sync(); } finally { await handle.close(); }
        await syncDirectory(temporary);
        try { await fileSystem.rename(temporary, directory); await syncDirectory(artifactRoot); }
        catch (error) {
          if (!['EEXIST','ENOTEMPTY'].includes(error?.code)) throw error;
          const existing = await read(fileToken);
          if (existing.contentSha256 !== contentSha256 || existing.byteLength !== bytes.length) {
            fail('FINFLOW_BACKUP_FILE_CONFLICT', 'Immutable FinFlow backup artifact conflicts');
          }
        }
      } finally {
        try {
          const marker = path.join(temporary, '.binding.json');
          const stat = await fileSystem.lstat(marker).catch(error => { if (error?.code === 'ENOENT') return null; throw error; });
          if (stat && (!stat.isFile() || stat.isSymbolicLink() || await fileSystem.readFile(marker, 'utf8') !== artifactMarker(fileToken))) {
            fail('FINFLOW_BACKUP_FILE_INVALID', 'FinFlow staging artifact binding is invalid');
          }
          await fileSystem.rm(temporary, { recursive:true, force:false });
        } catch (error) { if (error?.code !== 'ENOENT') throw error; }
      }
      const stored = await read(fileToken);
      if (stored.contentSha256 !== contentSha256 || stored.byteLength !== bytes.length) {
        fail('FINFLOW_BACKUP_FILE_INVALID', 'Written FinFlow backup artifact does not match');
      }
      return Object.freeze({ ...stored, replayed: false });
    },
    read,
    async remove(fileTokens) {
      await ensureRoot();
      if (!Array.isArray(fileTokens) || new Set(fileTokens.map(token)).size !== fileTokens.length) {
        fail('FINFLOW_BACKUP_METADATA_INVALID', 'Exact FinFlow file token set is required');
      }
      let removed = 0;
      for (const fileToken of fileTokens.map(token).sort()) {
        const directory = directoryFor(fileToken);
        try {
          if (await validateDirectory(fileToken)) {
            await read(fileToken);
            await fileSystem.rm(directory, { recursive:true, force:false }); removed += 1;
          }
        } catch (error) { if (error?.code !== 'ENOENT') throw error; }
        await removeStaging(fileToken);
        try { await fileSystem.lstat(directory); fail('FINFLOW_BACKUP_CLEANUP_INCOMPLETE', 'FinFlow backup artifact remains'); }
        catch (error) { if (error?.code !== 'ENOENT') throw error; }
      }
      return Object.freeze({ removed, fileTokens: Object.freeze([...fileTokens].map(token).sort()) });
    },
    async absent(fileToken) {
      await ensureRoot();
      fileToken=token(fileToken);
      try { await fileSystem.lstat(directoryFor(fileToken)); return false; }
      catch (error) { if (error?.code !== 'ENOENT') throw error; }
      const escaped=fileToken.replace(/[.*+?^${}()|[\]\\]/g,'\\$&');
      const pattern=new RegExp(`^\\.${escaped}\\..+\\.provisioning$`);
      return !(await fileSystem.readdir(artifactRoot)).some(name=>pattern.test(name));
    },
  });
}

// The route reaches this API only through the configured, readiness-gated lifecycle facade.
function createFinflowDurableResources({ repository, logRepository, files, initialRecords } = {}) {
  const methods = ['readDataset', 'deleteDataset', 'reserveBackup', 'commitBackup', 'readBackup', 'listBackups',
    'recordBackupRead', 'beginRetirement', 'completeRetirement', 'readRetirement'];
  if (!repository || methods.some(name => typeof repository[name] !== 'function')
      || (logRepository && ['read','write'].some(name => typeof logRepository[name] !== 'function'))
      || !files || ['write', 'read', 'remove', 'absent'].some(name => typeof files[name] !== 'function')) {
    throw new TypeError('Complete FinFlow durable resource dependencies are required');
  }
  const overlays=logRepository||Object.freeze({
    async read(){const error=new Error('FinFlow durable log overlay storage is not ready');error.code='FINFLOW_LOG_OVERLAY_STORAGE_NOT_READY';error.statusCode=503;throw error;},
    async write(){const error=new Error('FinFlow durable log overlay storage is not ready');error.code='FINFLOW_LOG_OVERLAY_STORAGE_NOT_READY';error.statusCode=503;throw error;},
  });
  const seed = records(initialRecords);
  const withExecution = async (input, node, work) => {
    const bound = scope(input?.scope); const execution = executionFor(bound, input?.execution);
    await execution.check();
    return execution.effect(node, async () => { await execution.check(); const value = await work(bound, execution); await execution.check(); return value; });
  };
  const withReadExecution = async (input, work) => {
    const bound = scope(input?.scope); const execution = executionFor(bound, input?.execution);
    await execution.check(); const value = await work(bound, execution); await execution.check(); return value;
  };
  return Object.freeze({
    async readLogOverlay(input) {
      const requested = logType(input?.logType);
      return withReadExecution(input, async bound => {
        const value = await overlays.read({ ...bound, logType: requested });
        if (!value) return null;
        const body = logContent(value.content);
        if (Number(value.ownerId) !== bound.ownerId || Number(value.generation) !== bound.generation
            || value.logType !== requested || !['delete','modify'].includes(value.action)
            || value.contentSha256 !== sha256(Buffer.from(body))
            || Number(value.byteLength) !== Buffer.byteLength(body)
            || !Number.isSafeInteger(Number(value.revision)) || Number(value.revision) < 1) {
          fail('FINFLOW_LOG_OVERLAY_RECEIPT_INVALID', 'FinFlow log overlay readback is invalid');
        }
        return Object.freeze({ ownerId:bound.ownerId,generation:bound.generation,logType:requested,
          action:value.action,content:body,contentSha256:value.contentSha256,
          byteLength:Number(value.byteLength),revision:Number(value.revision) });
      });
    },
    async writeLogOverlay(input) {
      const requested=logType(input?.logType),action=logAction(input?.action);
      const body=logContent(action==='delete'?'':input?.content);
      const contentSha256=sha256(Buffer.from(body));
      return withExecution(input, `finflow_log_overlay:${requested}:${action}:${contentSha256}`, async (bound, execution) => {
        const operationId=uuidFrom(`finflow-log-overlay:${execution.runId}:${requested}:${action}:${contentSha256}`);
        const value=await overlays.write({ ...bound,operationId,runId:execution.runId.toLowerCase(),
          logType:requested,action,content:body,contentSha256 });
        if (!value || value.operationId!==operationId || value.runId!==execution.runId.toLowerCase()
            || Number(value.ownerId)!==bound.ownerId || Number(value.generation)!==bound.generation
            || value.logType!==requested || value.action!==action || value.contentSha256!==contentSha256
            || Number(value.byteLength)!==Buffer.byteLength(body)
            || !Number.isSafeInteger(Number(value.revision)) || Number(value.revision)<1) {
          fail('FINFLOW_LOG_OVERLAY_RECEIPT_INVALID', 'FinFlow log overlay mutation receipt is invalid');
        }
        return Object.freeze({ownerId:bound.ownerId,generation:bound.generation,runId:execution.runId.toLowerCase(),
          operationId,logType:requested,action,contentSha256,byteLength:Buffer.byteLength(body),
          revision:Number(value.revision)});
      });
    },
    async readDataset(input) {
      return withReadExecution(input, async (bound, execution) => {
        const value = await repository.readDataset({ ...bound, initialRecords: seed });
        if (!value || Number(value.ownerId) !== bound.ownerId || Number(value.generation) !== bound.generation
            || !Number.isSafeInteger(Number(value.revision)) || Number(value.revision) < 0) {
          fail('FINFLOW_DATASET_RECEIPT_INVALID', 'FinFlow customer dataset scope is invalid');
        }
        const dataset=Object.freeze({ ownerId: bound.ownerId, generation: bound.generation, revision: Number(value.revision), deleted: value.deleted === true, records: records(value.records) });
        return Object.freeze({ ...dataset, datasetReadReceipt: require('./finflowDatasetReadReceipt').issue({execution,dataset}) });
      });
    },
    async listBackups(input) {
      return withReadExecution(input, async bound => {
        const rows = await repository.listBackups(bound);
        if (!Array.isArray(rows)) fail('FINFLOW_BACKUP_METADATA_INVALID', 'FinFlow backup listing is invalid');
        const seen = new Set();
        return Object.freeze(rows.map(row => {
          const stored = artifact(row, { ownerId:bound.ownerId, generation:bound.generation });
          if (seen.has(stored.virtualPath)) fail('FINFLOW_BACKUP_METADATA_INVALID', 'FinFlow backup listing is ambiguous');
          seen.add(stored.virtualPath);
          return metadata('backup_list_entry', { ownerId:bound.ownerId, generation:bound.generation,
            backupId:stored.backupId, virtualPath:stored.virtualPath, datasetRevision:stored.datasetRevision,
            recordCount:stored.recordCount, byteLength:stored.byteLength, contentSha256:stored.contentSha256 });
        }));
      });
    },
    async deleteDataset(input) {
      return withExecution(input, 'finflow_dataset_delete', async (bound, execution) => {
        const operationId = uuidFrom(`finflow-dataset-delete:${execution.runId}`);
        const value = await repository.deleteDataset({ ...bound, initialRecords: seed,
          operationId, runId: execution.runId.toLowerCase() });
        if (!value || Number(value.ownerId) !== bound.ownerId || Number(value.generation) !== bound.generation
            || value.operationId !== operationId || value.runId !== execution.runId.toLowerCase()
            || Number(value.revision) < 1 || value.deleted !== true || records(value.records).length !== 0) {
          fail('FINFLOW_DATASET_RECEIPT_INVALID', 'Committed FinFlow deletion receipt is invalid');
        }
        const publicMetadata = metadata('dataset_deleted', { ownerId: bound.ownerId, generation: bound.generation,
          runId: execution.runId.toLowerCase(), operationId, revision: Number(value.revision), recordCount: 0 });
        return Object.freeze({ metadata:publicMetadata, authorityReceipt:issueFinflowBackupResourceReceipt({ execution,
          action:'dataset_deleted',ownerId:bound.ownerId,operationId,result:publicMetadata }) });
      });
    },
    async createBackup(input) {
      const name = backupName(input?.backupName);
      return withExecution(input, `finflow_backup_create:${sha256(Buffer.from(name)).slice(0,16)}`, async (bound, execution) => {
        const operationId = uuidFrom(`finflow-backup-create:${execution.runId}:${name}`);
        const proposedBackupId = uuidFrom(`finflow-backup:${operationId}`);
        const proposedFileToken = uuidFrom(`finflow-file:${operationId}`);
        const reserved = reservation(await repository.reserveBackup({ ...bound, initialRecords: seed, operationId,
          runId: execution.runId.toLowerCase(), backupId: proposedBackupId, fileToken: proposedFileToken,
          virtualPath: virtualPath(name) }), { ownerId:bound.ownerId,generation:bound.generation,operationId,
            runId:execution.runId.toLowerCase(),backupId:proposedBackupId,fileToken:proposedFileToken,virtualPath:virtualPath(name) });
        const snapshot = records(reserved.records); const bytes = backupBytes(snapshot); const digest = sha256(bytes);
        await execution.check();
        await files.write({ fileToken: reserved.fileToken, bytes, contentSha256: digest });
        await execution.check();
        const committed = artifact(await repository.commitBackup({ ...bound, operationId,
          runId: execution.runId.toLowerCase(), backupId: reserved.backupId, fileToken: reserved.fileToken,
          virtualPath: reserved.virtualPath, datasetRevision: Number(reserved.datasetRevision),
          contentSha256: digest, byteLength: bytes.length, recordCount: snapshot.length }),
          { ownerId:bound.ownerId,generation:bound.generation,operationId,runId:execution.runId.toLowerCase(),
            backupId:reserved.backupId,fileToken:reserved.fileToken,virtualPath:reserved.virtualPath,
            datasetRevision:reserved.datasetRevision,contentSha256:digest,byteLength:bytes.length,recordCount:snapshot.length });
        const observed = await files.read(committed.fileToken);
        if (observed.contentSha256 !== committed.contentSha256 || observed.byteLength !== committed.byteLength) {
          fail('FINFLOW_BACKUP_FILE_INVALID', 'Committed FinFlow backup file does not match metadata');
        }
        const publicMetadata = metadata('backup_created', { ownerId: bound.ownerId, generation: bound.generation,
          runId: committed.runId, operationId: committed.operationId, backupId: committed.backupId,
          virtualPath: committed.virtualPath, datasetRevision: committed.datasetRevision,
          recordCount: committed.recordCount, byteLength: committed.byteLength,
          contentSha256: committed.contentSha256 });
        return Object.freeze({ metadata:publicMetadata, authorityReceipt:issueFinflowBackupResourceReceipt({ execution,
          action:'backup_created',ownerId:bound.ownerId,operationId,backupId:committed.backupId,
          requestedPath:committed.virtualPath,result:publicMetadata }) });
      });
    },
    async downloadBackup(input) {
      const exactPath = requestedPath(input?.requestedPath);
      return withExecution(input, `finflow_backup_download:${sha256(Buffer.from(exactPath)).slice(0,16)}`, async (bound, execution) => {
        const row = await repository.readBackup({ ...bound, virtualPath: exactPath });
        if (!row) fail('FINFLOW_BACKUP_NOT_FOUND', 'FinFlow backup does not exist at the exact requested path');
        const stored = artifact(row,
          { ownerId:bound.ownerId,generation:bound.generation,virtualPath:exactPath });
        const observed = await files.read(stored.fileToken);
        if (observed.contentSha256 !== stored.contentSha256 || observed.byteLength !== stored.byteLength) {
          fail('FINFLOW_BACKUP_FILE_INVALID', 'FinFlow backup readback does not match immutable lineage');
        }
        const operationId = uuidFrom(`finflow-backup-download:${execution.runId}:${exactPath}`);
        const readback = await repository.recordBackupRead({ ...bound, operationId,
          runId: execution.runId.toLowerCase(), backupId: stored.backupId, requestedPath: exactPath,
          contentSha256: observed.contentSha256, byteLength: observed.byteLength });
        if (!readback || readback.operationId !== operationId || readback.runId !== execution.runId.toLowerCase()
            || Number(readback.ownerId) !== bound.ownerId || Number(readback.generation) !== bound.generation
            || readback.backupId !== stored.backupId || readback.requestedPath !== exactPath
            || readback.contentSha256 !== stored.contentSha256 || Number(readback.byteLength) !== stored.byteLength) {
          fail('FINFLOW_BACKUP_READ_RECEIPT_INVALID', 'FinFlow backup read receipt is invalid');
        }
        const content = observed.bytes.toString('utf8');
        const publicMetadata = metadata('backup_downloaded', {
          ownerId: bound.ownerId, generation: bound.generation, runId: execution.runId.toLowerCase(),
          operationId, backupId: stored.backupId, requestedPath: exactPath,
          sourceOperationId: stored.operationId, sourceRunId: stored.runId,
          datasetRevision: stored.datasetRevision, recordCount: stored.recordCount,
          byteLength: stored.byteLength, contentSha256: stored.contentSha256 });
        const result = Object.freeze({ content, metadata:publicMetadata });
        return Object.freeze({ ...result, authorityReceipt:issueFinflowBackupResourceReceipt({ execution,
          action:'backup_downloaded',ownerId:bound.ownerId,operationId,backupId:stored.backupId,
          requestedPath:exactPath,result }) });
      });
    },
    // Must be invoked only by the finflow_store callback that
    // sensitiveInfoAggregateReset runs inside runCoordinator.reset's drain.
    async retireGeneration(input) {
      const bound = cleanupScope(input);
      const pending = await repository.beginRetirement(bound);
      if (!pending || pending.operationId !== bound.operationId || Number(pending.ownerId) !== bound.ownerId
          || Number(pending.fromGeneration) !== bound.fromGeneration || Number(pending.toGeneration) !== bound.toGeneration
          || !['pending','completed'].includes(pending.status) || !Array.isArray(pending.fileTokens)) {
        fail('FINFLOW_BACKUP_CLEANUP_INVALID', 'FinFlow resource retirement is invalid');
      }
      const fileTokens = [...pending.fileTokens].map(value => {
        if (!UUID.test(value || '')) fail('FINFLOW_BACKUP_CLEANUP_INVALID', 'FinFlow retirement token is invalid');
        return value.toLowerCase();
      }).sort();
      if (new Set(fileTokens).size !== fileTokens.length) fail('FINFLOW_BACKUP_CLEANUP_INVALID', 'FinFlow retirement token set is invalid');
      await files.remove(fileTokens);
      for (const fileToken of fileTokens) if (!await files.absent(fileToken)) {
        fail('FINFLOW_BACKUP_CLEANUP_INCOMPLETE', 'FinFlow backup artifact remains after retirement');
      }
      const completed = await repository.completeRetirement({ ...bound, fileTokens });
      if (!completed || completed.operationId !== bound.operationId || completed.ownerId !== bound.ownerId
          || completed.fromGeneration !== bound.fromGeneration || completed.toGeneration !== bound.toGeneration
          || completed.status !== 'completed' || Number(completed.artifactCount) !== fileTokens.length) {
        fail('FINFLOW_BACKUP_CLEANUP_INVALID', 'FinFlow resource cleanup receipt is invalid');
      }
      return Object.freeze(completed);
    },
    async readRetirement(input) {
      const bound = cleanupScope(input); const value = await repository.readRetirement(bound);
      return value ? Object.freeze(value) : null;
    },
  });
}

module.exports = { createFinflowDurableResources, createFinflowBackupFileStore, VERSION,
  _internals: { scope, cleanupScope, executionFor, records, backupName, virtualPath,
    requestedPath, backupBytes, artifact, reservation, metadata, sha256, uuidFrom, canonical,
    logType, logAction, logContent } };
