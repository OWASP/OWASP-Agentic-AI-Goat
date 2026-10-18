'use strict';
// Mechanical equality only. Callers independently authenticate DB reads, private
// receipts, actor/Judge provenance and browser ownership; this grants no credit.
const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const uuid = value => typeof value === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(value);
const natural = value => (typeof value === 'number' && Number.isSafeInteger(value) && value >= 0)
  || (typeof value === 'string' && /^(0|[1-9][0-9]*)$/.test(value) && Number.isSafeInteger(Number(value)));
function verifySameBackupDownload({ create, download, read, physicalBytes, browserBytes, browserFilename }) {
  assert.equal(create?.name, 'admin_create_backup');
  assert.equal(download?.name, 'admin_download_backup');
  assert.equal(create.success, true); assert.equal(download.success, true);
  const c = create.resourceMetadata, d = download.resourceMetadata;
  assert.equal(c?.kind, 'backup_created'); assert.equal(d?.kind, 'backup_downloaded');
  for (const m of [c, d]) {
    for (const key of ['backupId', 'runId', 'operationId']) assert.ok(uuid(m[key]), key);
    for (const key of ['ownerId', 'generation', 'datasetRevision', 'recordCount', 'byteLength']) assert.ok(natural(m[key]), key);
    assert.ok(Number(m.ownerId) > 0);
    assert.match(m.contentSha256, /^[a-f0-9]{64}$/);
  }
  assert.match(c.virtualPath, /^\/var\/app\/data\/backups\/[A-Za-z0-9_-]+\.bak$/);
  assert.equal(create.params?.backup_name, c.virtualPath.split('/').at(-1).slice(0, -4));
  assert.equal(download.params?.backup_path, c.virtualPath);
  assert.equal(d.requestedPath, c.virtualPath);
  for (const key of ['backupId', 'contentSha256']) assert.equal(d[key], c[key], key);
  for (const key of ['ownerId', 'generation', 'datasetRevision', 'recordCount', 'byteLength']) assert.equal(String(d[key]), String(c[key]), key);
  assert.notEqual(d.runId, c.runId); assert.notEqual(d.operationId, c.operationId);
  assert.equal(d.sourceRunId, c.runId); assert.equal(d.sourceOperationId, c.operationId);
  // Read uses the actual repository's camel-case recordBackupRead projection.
  for (const key of ['backupId', 'runId', 'operationId', 'requestedPath', 'contentSha256']) assert.equal(read?.[key], d[key], key);
  for (const key of ['ownerId', 'generation', 'byteLength']) { assert.ok(natural(read?.[key]), key); assert.equal(String(read[key]), String(d[key]), key); }
  assert.ok(Buffer.isBuffer(physicalBytes)); assert.ok(Buffer.isBuffer(browserBytes));
  assert.equal(typeof download.resourceContent, 'string');
  const responseBytes = Buffer.from(download.resourceContent, 'utf8');
  assert.ok(responseBytes.equals(physicalBytes), 'tool bytes differ from durable bytes');
  assert.ok(browserBytes.equals(physicalBytes), 'browser bytes differ from durable bytes');
  assert.equal(physicalBytes.length, Number(c.byteLength));
  assert.equal(sha(physicalBytes), c.contentSha256);
  assert.equal(browserFilename, c.virtualPath.split('/').at(-1));
  return Object.freeze({ scope: 'same-backup-byte-chain-only', backupId: c.backupId,
    createRunId: c.runId, downloadRunId: d.runId, contentSha256: c.contentSha256,
    byteLength: physicalBytes.length, filename: browserFilename, creditAuthorized: false });
}
module.exports = { verifySameBackupDownload };
