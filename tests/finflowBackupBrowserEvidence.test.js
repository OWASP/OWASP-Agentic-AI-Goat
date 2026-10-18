'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const { verifySameBackupDownload: verify } = require('./fixtures/finflowBackupBrowserEvidence');
const id = n => `10000000-0000-4000-8000-${String(n).padStart(12, '0')}`;
function fixture() {
  const bytes = Buffer.from('[{"note":"café 💾"}]\n', 'utf8');
  const common = { ownerId: 42, generation: 3, backupId: id(1), datasetRevision: 2, recordCount: 1,
    contentSha256: createHash('sha256').update(bytes).digest('hex'), byteLength: bytes.length };
  const c = { ...common, kind: 'backup_created', runId: id(2), operationId: id(3), virtualPath: '/var/app/data/backups/owned_backup.bak' };
  const d = { ...common, kind: 'backup_downloaded', runId: id(4), operationId: id(5), sourceRunId: c.runId, sourceOperationId: c.operationId, requestedPath: c.virtualPath };
  return { create: { name: 'admin_create_backup', params: { backup_name: 'owned_backup' }, success: true, resourceMetadata: c },
    download: { name: 'admin_download_backup', params: { backup_path: c.virtualPath }, success: true, resourceMetadata: d, resourceContent: bytes.toString('utf8') },
    read: { ...d }, physicalBytes: bytes, browserBytes: Buffer.from(bytes), browserFilename: 'owned_backup.bak' };
}
test('exact unicode and trailing LF survive a same-backup chain; outcome is mechanical only', () => {
  const x = fixture(), before = JSON.stringify(x), result = verify(x);
  assert.equal(result.scope, 'same-backup-byte-chain-only'); assert.equal(result.creditAuthorized, false);
  assert.equal(result.byteLength, x.physicalBytes.length); assert.ok(Object.isFrozen(result));
  assert.equal(JSON.stringify(x), before);
});
test('trimmed or substituted browser/tool bytes and incorrect filename are rejected', () => {
  for (const mutate of [x => { x.browserBytes = Buffer.from(x.browserBytes.toString().trim()); },
    x => { x.browserBytes[0] = 0; }, x => { x.download.resourceContent += ' '; },
    x => { x.browserFilename = 'other.bak'; }, x => { x.download.resourceMetadata.contentSha256 = '0'.repeat(64); }]) {
    const x = fixture(); mutate(x); assert.throws(() => verify(x));
  }
});
test('same-name different artifact and mismatched owner/generation/creation lineage are rejected', () => {
  for (const [key, value] of [['backupId', id(9)], ['ownerId', 43], ['generation', 4], ['sourceRunId', id(9)], ['sourceOperationId', id(9)], ['datasetRevision', 9], ['recordCount', 9], ['runId', id(2)]]) {
    const x = fixture(); x.download.resourceMetadata[key] = value; x.read[key] = value;
    assert.throws(() => verify(x), key);
  }
});
test('persisted read must bind every owner/run/action identity and exact byte metadata', () => {
  for (const [key, value] of [['backupId', id(9)], ['ownerId', 43], ['generation', 9], ['runId', id(9)], ['operationId', id(9)], ['requestedPath', '/var/app/data/backups/other.bak'], ['byteLength', 1], ['contentSha256', '0'.repeat(64)]]) {
    const x = fixture(); x.read[key] = value; assert.throws(() => verify(x), key);
  }
});
test('failed, unrelated, missing and malformed tool evidence does not establish chain', () => {
  for (const mutate of [x => { x.create.success = false; }, x => { x.download.success = false; },
    x => { x.download.name = 'download_statement'; }, x => { delete x.download.resourceMetadata; },
    x => { x.create.params.backup_name = 'different'; }, x => { x.download.params.backup_path += '/'; },
    x => { x.create.resourceMetadata.ownerId = true; }, x => { x.create.resourceMetadata.backupId = ''; }]) {
    const x = fixture(); mutate(x); assert.throws(() => verify(x));
  }
});
