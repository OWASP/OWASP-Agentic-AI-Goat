'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { createLegacyAiHistoryOperator } = require('../server/services/legacyAiHistoryOperator');
const { main, parse } = require('../scripts/legacy-ai-history-cutover');
const FAILURE = { code: 'LEGACY_AI_HISTORY_OPERATOR_FAILED' };
async function fixture(t, overrides = {}) {
  const directory = await fs.realpath(await fs.mkdtemp(path.join(os.tmpdir(), 'history-operator-unit-')));
  t.after(() => fs.rm(directory, { recursive: true, force: true }));
  const planPath = path.join(directory, 'plan.json'), receiptPath = path.join(directory, 'receipt.json');
  const env = { LEGACY_CHALLENGE_MIGRATION_DATABASE_URL: 'postgres://dvaia_legacy_challenge_migration:source-password@127.0.0.1:5432/source_db',
    IDENTITY_MIGRATION_DATABASE_URL: 'postgres://dvaia_identity_migration:target-password@127.0.0.1:5432/target_db' };
  const state = { rows: [{ id: 3, userId: 700, prompt: 'PRIVATE-SOURCE-PROMPT', response: 'PRIVATE-SOURCE-RESPONSE',
    modelUsed: null, createdAt: 'infinity', platformOwnerId: 700 }], snapshots: 0, pools: [], archives: [], starts: 0, cleanups: 0 };
  const target = Object.freeze({
    async begin() { state.starts++; return { state: state.verified ? 'verified' : 'copying' }; },
    async archive(row) { state.archives.push({ ...row }); },
    async readArchived() { return state.archives.map(row => ({ ...row })); },
    async promote() { throw new Error('Ownership must never be inferred'); },
    async readPromoted() { throw new Error('No promotions should exist'); },
    async verify(input) { state.verified = true; return { batchId: input.batchId, sourceRemovalReceipt: input.aggregateDigest }; },
  });
  const operator = createLegacyAiHistoryOperator({ env,
    createPool(options) { const pool = { options, ended: false, async end() { this.ended = true; } }; state.pools.push(pool); return pool; },
    createSnapshot(pool, options) { assert.equal(pool.options.connectionString, env.LEGACY_CHALLENGE_MIGRATION_DATABASE_URL);
      assert.equal(options.database, 'source_db');
      return Object.freeze({ async readSnapshot() { state.snapshots++; return { batchId: options.batchId,
        sourceStoreIdentity: options.sourceStoreIdentity, rows: state.rows.map(row => ({ ...row })) }; } }); },
    createTarget(pool, options) { assert.equal(pool.options.connectionString, env.IDENTITY_MIGRATION_DATABASE_URL);
      assert.equal(options.database, 'target_db'); return target; },
    createCoordinator(options) { assert.equal(options.sourceDatabase, 'source_db'); assert.equal(options.targetDatabase, 'target_db');
      return { async removeQuarantinedSource(input) {
        assert.ok(state.snapshots > state.cleanups + 1, 'readonly snapshot precedes cleanup');
        state.cleanups++; state.rows = [];
        return { batchId: input.batchId, removedCount: 1, replayed: state.cleanups > 1, state: 'source_removed' };
      } }; },
    ...overrides,
  });
  const run = command => operator.execute({ command, planPath, ...(command === 'plan' ? {} : { receiptPath }) });
  return { directory, planPath, receiptPath, env, state, operator, run };
}
test('plan binds both stores and writes only a private hash manifest without mutation', async t => {
  const f = await fixture(t);
  const result = await f.run('plan');
  assert.equal(result.sourceRemoved, false); assert.equal(result.ownershipProven, false);
  assert.equal(f.state.pools.length, 1); assert.equal(f.state.starts, 0); assert.equal(f.state.cleanups, 0);
  assert.equal(f.state.pools[0].ended, true);
  const bytes = await fs.readFile(f.planPath, 'utf8'), plan = JSON.parse(bytes);
  assert.equal((await fs.stat(f.planPath)).mode & 0o777, 0o600);
  assert.doesNotMatch(bytes, /PRIVATE-SOURCE|source-password|target-password|platformOwnerId/);
  assert.equal(plan.source.endpoint, 'postgresql://127.0.0.1:5432/source_db');
  assert.equal(plan.target.database, 'target_db'); assert.deepEqual(plan.manifest.claims, []);
  assert.equal(plan.manifest.rows.length, 1);
  await assert.rejects(f.run('plan'), FAILURE);
  assert.equal(await fs.readFile(f.planPath, 'utf8'), bytes, 'existing plan remains untouched');
});
test('quarantine composes real importer and empty attestation; replay preserves immutable receipt', async t => {
  const f = await fixture(t); await f.run('plan');
  const result = await f.run('quarantine');
  assert.equal(result.quarantinedRows, 1); assert.equal(result.classification, 'unknown');
  assert.equal(f.state.rows.length, 1); assert.equal(f.state.cleanups, 0);
  assert.equal(f.state.archives[0].classification, 'unknown'); assert.equal(f.state.archives[0].ownerId, null);
  const before = await fs.readFile(f.receiptPath, 'utf8'), stat = await fs.stat(f.receiptPath);
  assert.doesNotMatch(before, /PRIVATE-SOURCE|password/); assert.equal(stat.mode & 0o777, 0o600);
  await f.run('quarantine');
  assert.equal(await fs.readFile(f.receiptPath, 'utf8'), before);
  assert.equal((await fs.stat(f.receiptPath)).ino, stat.ino);
  assert.equal(f.state.archives.length, 1);
  assert.equal(f.state.pools.every(pool => pool.ended), true);
});
test('cleanup is explicit and replays with empty source after readonly preflight', async t => {
  const f = await fixture(t); await f.run('plan'); await f.run('quarantine');
  assert.equal(f.state.cleanups, 0);
  assert.equal((await f.run('cleanup')).replayed, false);
  assert.equal(f.state.rows.length, 0);
  assert.equal((await f.run('cleanup')).replayed, true);
  assert.equal(f.state.cleanups, 2); assert.equal(f.state.pools.every(pool => pool.ended), true);
});
test('wrong endpoint, database or unsupported connection redirection rejects before pool creation', async t => {
  for (const replacement of ['postgres://dvaia_identity_migration:p@other:5432/target_db',
    'postgres://dvaia_identity_migration:p@127.0.0.1:5432/different',
    'postgres://dvaia_identity_migration:p@127.0.0.1:5432/target_db?host=other']) {
    const f = await fixture(t); await f.run('plan'); const count = f.state.pools.length;
    f.env.IDENTITY_MIGRATION_DATABASE_URL = replacement;
    await assert.rejects(f.run('quarantine'), FAILURE); assert.equal(f.state.pools.length, count);
  }
});
test('claims and plan tampering cannot assert ownership', async t => {
  const f = await fixture(t); await f.run('plan');
  const plan = JSON.parse(await fs.readFile(f.planPath, 'utf8'));
  plan.manifest.claims = [{ ownerId: 700 }];
  await fs.writeFile(f.planPath, JSON.stringify(plan));
  await assert.rejects(f.run('quarantine'), FAILURE);
  assert.equal(f.state.starts, 0); assert.equal(f.state.cleanups, 0);
});
test('stale source manifest fails before any target writes', async t => {
  const f = await fixture(t); await f.run('plan'); f.state.rows[0].prompt = 'changed source';
  await assert.rejects(f.run('quarantine'), FAILURE);
  assert.equal(f.state.starts, 0); assert.equal(f.state.rows.length, 1);
  await assert.rejects(fs.stat(f.receiptPath), { code: 'ENOENT' });
});
test('missing or modified quarantine receipt never invokes cleanup', async t => {
  const f = await fixture(t); await f.run('plan');
  await assert.rejects(f.run('cleanup'), FAILURE); assert.equal(f.state.cleanups, 0);
  await f.run('quarantine');
  const receipt = JSON.parse(await fs.readFile(f.receiptPath, 'utf8')); receipt.aggregateDigest = 'f'.repeat(64);
  await fs.writeFile(f.receiptPath, JSON.stringify(receipt));
  await assert.rejects(f.run('cleanup'), FAILURE); assert.equal(f.state.cleanups, 0);
});
test('unsafe file permissions, symlinks and nonprivate parent directories reject', async t => {
  const f = await fixture(t); await f.run('plan');
  await fs.chmod(f.planPath, 0o644); await assert.rejects(f.run('quarantine'), FAILURE);
  await fs.chmod(f.planPath, 0o600);
  const linked = path.join(f.directory, 'linked.json'); await fs.symlink(f.planPath, linked);
  await assert.rejects(f.operator.execute({ command: 'quarantine', planPath: linked, receiptPath: f.receiptPath }), FAILURE);
  const linkedDirectory = path.join(f.directory, 'linked-dir'); await fs.symlink(f.directory, linkedDirectory);
  await assert.rejects(f.operator.execute({ command: 'plan', planPath: path.join(linkedDirectory, 'new.json') }), FAILURE);
  await fs.chmod(f.directory, 0o777);
  await assert.rejects(f.run('quarantine'), FAILURE);
  await fs.chmod(f.directory, 0o700);
});
test('malformed and oversized input files reject without target mutation', async t => {
  const f = await fixture(t); await fs.writeFile(f.planPath, '{invalid', { mode: 0o600 });
  await assert.rejects(f.run('quarantine'), FAILURE);
  await fs.truncate(f.planPath, 16 * 1024 * 1024 + 1);
  await assert.rejects(f.run('quarantine'), FAILURE); assert.equal(f.state.pools.length, 0);
});
test('provider errors are sanitized and owned pools always close', async t => {
  const f = await fixture(t, { createSnapshot() { return { async readSnapshot() { throw new Error('source-password PRIVATE-SOURCE-PROMPT'); } }; } });
  await assert.rejects(f.run('plan'), error => {
    assert.equal(error.code, FAILURE.code); assert.doesNotMatch(error.message, /password|PRIVATE-SOURCE/); return true;
  });
  assert.equal(f.state.pools.length, 1); assert.equal(f.state.pools[0].ended, true);
});
test('CLI requires explicit command and named private files; errors never echo argv', async () => {
  assert.deepEqual(parse(['plan','--plan-file','/private/plan']), { command: 'plan', planPath: '/private/plan' });
  for (const argv of [[], ['plan'], ['cleanup','--plan-file','/private/plan'],
    ['plan','--plan-file','a','--plan-file','b'], ['plan','--database-url','postgres://secret']]) assert.throws(() => parse(argv));
  const output = [], execute = [];
  const code = await main(['cleanup','--plan-file','p','--receipt-file','r'], {
    operator: { async execute(options) { execute.push(options); throw new Error('private-password'); } },
    output: { log: value => output.push(value), error: value => output.push(value) },
  });
  assert.equal(code, 1); assert.equal(execute.length, 1); assert.doesNotMatch(output.join(''), /private-password/);
  let called = false;
  assert.equal(await main(['--help'], { operator: { execute() { called = true; } }, output: { log() {}, error() {} } }), 0);
  assert.equal(called, false);
});
