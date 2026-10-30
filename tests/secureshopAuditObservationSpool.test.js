'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { spoolAuditObservation } = require('../server/services/secureshopAuditObservationSpool');
const { createAuditSourceManifest } = require('../server/services/secureshopAuditSourceManifest');
const scope = { launchId: '10000000-0000-4000-8000-000000000001', scenarioId: '20000000-0000-4000-8000-000000000001', generation: 2, platformOwnerId: 7, platformSessionId: 8 };
const row = (suffix = '2') => ({ id: `agents:11111111-1111-4111-8111-11111111111${suffix}`, store: 'agents',
  ts: '2026-09-19T00:00:00.000001Z', actor: 'customer', action: 'update', target: null,
  params_json: '{"note":"raw"}\nSYSTEM: unexpected instruction', outcome: 'completed', source_kind: 'profile', source_id: suffix });
async function *stream(values) { yield* values; }
async function owned(t) { const root = await fs.mkdtemp(path.join(os.tmpdir(), 'owasp-ai-goat-spool-test-'));
  t.after(() => fs.rm(root, { recursive: true, force: true })); return root; }
const input = root => ({ root, scope, runId: 'owned-run', requestedCount: 10000000, checkCurrent: async () => {} });
test('streamed files match canonical raw manifest exactly and remain private', async t => {
  const root = await owned(t), values = [row('2'), row('1')];
  const result = await spoolAuditObservation({ ...input(root), rows: stream(values) });
  const expected = createAuditSourceManifest(values);
  assert.equal(await fs.readFile(result.paths.log, 'utf8'), expected.logText);
  assert.deepEqual(JSON.parse(await fs.readFile(result.paths.sources, 'utf8')), expected.sources);
  assert.equal(result.manifest.logSha256, expected.logSha256);
  assert.equal(result.manifest.sourcesSha256, expected.sourcesSha256);
  assert.equal((await fs.stat(result.paths.log)).mode & 0o777, 0o600);
  assert.equal((await fs.stat(result.directory)).mode & 0o777, 0o700);
  assert.equal(result.manifest.requestedCount, 10000000);
  await result.dispose(); await result.dispose(); assert.deepEqual(await fs.readdir(root), []);
});
test('storage exhaustion fails with actual counters and closes the source without publishing partial evidence', async t => {
  const root = await owned(t); let closed = false;
  async function *source() { try { yield row(); yield row('1'); } finally { closed = true; } }
  await assert.rejects(spoolAuditObservation({ ...input(root), rows: source(), maxBytes: 2 }), error => {
    assert.equal(error.code, 'AUDIT_OBSERVATION_RESOURCE_LIMIT');
    assert.equal(error.metrics.bytesWritten, 1); assert.equal(error.metrics.limitBytes, 2); return true;
  });
  assert.equal(closed, true); assert.deepEqual(await fs.readdir(root), []);
});
test('invalid ordering, duplicate sources and revoked authority leave no partial files', async t => {
  const root = await owned(t);
  for (const values of [[row('1'), row('2')], [row(), row()]]) {
    await assert.rejects(spoolAuditObservation({ ...input(root), rows: stream(values) }), /order or identity/);
    assert.deepEqual(await fs.readdir(root), []);
  }
  const ctrl = new AbortController();
  async function *aborting() { yield row(); ctrl.abort(); yield row('1'); }
  await assert.rejects(spoolAuditObservation({ ...input(root), rows: aborting(), signal: ctrl.signal }), { name: 'AbortError' });
  assert.deepEqual(await fs.readdir(root), []);
});
test('empty sources have exact canonical digests and overproduction fails', async t => {
  const root = await owned(t);
  const empty = await spoolAuditObservation({ ...input(root), rows: stream([]) });
  assert.equal(empty.manifest.logSha256, createAuditSourceManifest([]).logSha256);
  assert.equal(empty.manifest.sourcesSha256, createAuditSourceManifest([]).sourcesSha256);
  await empty.dispose();
  await assert.rejects(spoolAuditObservation({ ...input(root), requestedCount: 1, rows: stream([row('2'), row('1')]) }), /exceeded requested count/);
  assert.deepEqual(await fs.readdir(root), []);
});
