'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { createXssScopedProfileResetRepository } = require(
  '../server/database/postgres/xssScopedProfileResetRepository');

const OPERATION = '11111111-1111-4111-8111-111111111111';
function reset(overrides = {}) {
  return {
    operationId:OPERATION, ownerId:17, graphParentGeneration:'4', workshopGeneration:3,
    children:{ stored_user:{ from:'7', to:'8' }, stored_llm:{ from:9, to:10 } }, ...overrides,
  };
}
function poolFixture() {
  const receipts = new Map(); const retirements = new Map(); const parentReceipts = new Map(); const calls = [];
  return {
    calls, receipts, retirements, parentReceipts,
    async query(sql, params) {
      calls.push([sql.replace(/\s+/g, ' ').trim(), params]);
      if (/clear_parent_profile_reset/.test(sql)) {
        const [operationId, ownerId] = params;
        const prior = parentReceipts.get(operationId);
        if (prior && prior.ownerId !== ownerId) throw Object.assign(new Error('operation mismatch'), { code:'22023' });
        if (prior) return { rowCount:1, rows:[{ ...prior, replayed:true }] };
        const row = { operationId, ownerId, nameRevision:'2', bioRevision:'3', websiteRevision:'4',
          progressRemoved:3, originsRemoved:2, appliedAt:'2026-09-19T12:00:00.000Z', replayed:false };
        parentReceipts.set(operationId, row);
        return { rowCount:1, rows:[row] };
      }
      const [operationId, ownerId, graphParentGeneration, workshopGeneration,
        storedUserFrom, storedUserTo, storedLlmFrom, storedLlmTo] = params;
      const tuple = { operationId, ownerId, graphParentGeneration:String(graphParentGeneration),
        workshopGeneration:String(workshopGeneration), storedUserFrom:String(storedUserFrom),
        storedUserTo:String(storedUserTo), storedLlmFrom:String(storedLlmFrom),
        storedLlmTo:String(storedLlmTo) };
      const prior = receipts.get(operationId);
      if (/retire_or_read_scoped_profile_reset/.test(sql)) {
        const retired = retirements.get(operationId);
        if (prior) {
          for (const key of Object.keys(tuple)) if (String(prior[key]) !== String(tuple[key])) {
            throw Object.assign(new Error('operation mismatch'), { code:'22023' });
          }
          return { rowCount:1, rows:[{ ...prior, replayed:false, retired:false, retiredAt:null }] };
        }
        if (retired) {
          for (const key of Object.keys(tuple)) if (String(retired[key]) !== String(tuple[key])) {
            throw Object.assign(new Error('operation mismatch'), { code:'22023' });
          }
          return { rowCount:1, rows:[{ ...retired, replayed:false, retired:true, retiredAt:'fixture-retired' }] };
        }
        const tombstone = { ...tuple, retiredAt:'fixture-retired' };
        retirements.set(operationId, tombstone);
        return { rowCount:1, rows:[{ ...tombstone, replayed:false, retired:true }] };
      }
      if (retirements.has(operationId)) throw Object.assign(new Error('retired'), { code:'55000' });
      if (prior) {
        for (const key of Object.keys(tuple)) if (String(prior[key]) !== String(tuple[key])) {
          throw Object.assign(new Error('operation mismatch'), { code:'22023' });
        }
        return { rowCount:1, rows:[{ ...prior, replayed:true }] };
      }
      const row = { ...tuple, nameRevision:'2', bioRevision:'3', websiteRevision:'4',
        originsRemoved:2, appliedAt:'fixture-applied', replayed:false };
      receipts.set(operationId, row);
      return { rowCount:1, rows:[row] };
    },
  };
}

test('repository sends the exact two child transitions and projects an immutable receipt', async () => {
  const pool = poolFixture();
  const repository = createXssScopedProfileResetRepository(pool);
  const first = await repository.apply(reset());
  assert.deepEqual(first, {
    operationId:OPERATION, ownerId:17, graphParentGeneration:'4', workshopGeneration:'3',
    children:{ stored_user:{ from:'7', to:'8' }, stored_llm:{ from:'9', to:'10' } },
    profileRevisions:{ name:'2', bio:'3', website:'4' }, originsRemoved:2,
    appliedAt:'fixture-applied', replayed:false,
  });
  assert.equal(Object.isFrozen(first), true);
  assert.equal(Object.isFrozen(first.children.stored_user), true);
  assert.deepEqual(pool.calls[0][1], [OPERATION, 17, '4', '3', '7', '8', '9', '10']);
  assert.match(pool.calls[0][0], /FROM xss\.apply_scoped_profile_reset\(\$1,\$2,\$3,\$4,\$5,\$6,\$7,\$8\)/);
  const replay = await repository.apply(reset());
  assert.equal(replay.replayed, true);
  assert.deepEqual(replay.profileRevisions, first.profileRevisions);
});

test('operation replay rejects any owner or authority tuple mismatch', async () => {
  const repository = createXssScopedProfileResetRepository(poolFixture());
  await repository.apply(reset());
  for (const changed of [
    { ownerId:18 }, { graphParentGeneration:'5' }, { workshopGeneration:'4' },
    { children:{ stored_user:{ from:'6', to:'7' }, stored_llm:{ from:'9', to:'10' } } },
    { children:{ stored_user:{ from:'7', to:'8' }, stored_llm:{ from:'10', to:'11' } } },
  ]) await assert.rejects(repository.apply(reset(changed)), { code:'XSS_PROFILE_RESET_CONFLICT' });
});

test('retireOrRead returns the committed receipt unchanged and durable no-effect tombstones', async () => {
  const pool = poolFixture(); const repository = createXssScopedProfileResetRepository(pool);
  const applied = await repository.apply(reset());
  const committed = await repository.retireOrRead(reset());
  assert.equal(committed.kind, 'committed');
  assert.deepEqual(committed.receipt, applied);

  const retiredInput = reset({ operationId:'22222222-2222-4222-8222-222222222222', ownerId:18 });
  const retired = await repository.retireOrRead(retiredInput);
  assert.equal(retired.kind, 'retired_no_effect');
  assert.equal(retired.ownerId, 18);
  await assert.rejects(repository.apply(retiredInput), { code:'55000' });
  const replayed = await repository.retireOrRead(retiredInput);
  assert.deepEqual(replayed, retired);
  await assert.rejects(repository.retireOrRead({ ...retiredInput, ownerId:19 }), {
    code:'XSS_PROFILE_RESET_CONFLICT',
  });
});

test('clearParent returns an immutable parent receipt and replays without mutation', async () => {
  const pool = poolFixture(); const repository = createXssScopedProfileResetRepository(pool);
  const first = await repository.clearParent({ operationId:OPERATION, ownerId:17 });
  assert.deepEqual(first, {
    operationId:OPERATION, ownerId:17,
    profileRevisions:{ name:'2', bio:'3', website:'4' }, progressRemoved:3,
    originsRemoved:2, appliedAt:'2026-09-19T12:00:00.000Z', replayed:false,
  });
  const replay = await repository.clearParent({ operationId:OPERATION, ownerId:17 });
  assert.equal(replay.replayed, true);
  assert.deepEqual({ ...replay, replayed:false }, first);
  await assert.rejects(repository.clearParent({ operationId:OPERATION, ownerId:18 }), {
    code:'XSS_PROFILE_RESET_CONFLICT',
  });
  assert.match(pool.calls[0][0], /FROM xss\.clear_parent_profile_reset\(\$1,\$2\)/);
});

test('repository rejects coercive, incomplete, overflowing and non-unit authority input before SQL', async () => {
  const pool = poolFixture(); const repository = createXssScopedProfileResetRepository(pool);
  const invalid = [
    { operationId:'not-an-operation' }, { ownerId:true }, { ownerId:0 },
    { graphParentGeneration:Number.MAX_SAFE_INTEGER + 1 },
    { lifecycleAuthority:'caller-asserted' },
    { children:{ stored_user:{ from:'7', to:'9' }, stored_llm:{ from:'9', to:'10' } } },
    { children:{ stored_user:{ from:'9223372036854775807', to:'9223372036854775807' }, stored_llm:{ from:'9', to:'10' } } },
    { children:{ stored_user:{ from:'7', to:'8' }, stored_llm:{ from:'9', to:'10' }, email:{ from:1, to:2 } } },
    { children:{ stored_user:{ from:'7', to:'8', extra:true }, stored_llm:{ from:'9', to:'10' } } },
  ];
  for (const changed of invalid) await assert.rejects(repository.apply(reset(changed)), { code:/^(?:BAD_REQUEST|AUTH_REQUIRED)$/ });
  assert.equal(pool.calls.length, 0);
});

test('0008 remains immutable and 0009 adds bounded receipt retention', () => {
  const directory = path.join(__dirname, '../db/postgres/workshop-migrations/xss');
  const files = fs.readdirSync(directory).filter(name => /^\d{4}_.*\.sql$/.test(name)).sort();
  assert.ok(files.includes('0008_scoped_profile_reset_receipt.sql'));
  assert.ok(files.includes('0009_student_deletion_receipt_retention.sql'));
  assert.ok(files.includes('0012_scoped_profile_reset_retirement.sql'));
  assert.ok(files.includes('0013_scoped_profile_reset_owner_deletion_fence.sql'));
  const sql = fs.readFileSync(path.join(directory, '0008_scoped_profile_reset_receipt.sql'), 'utf8');
  assert.match(sql, /CREATE TABLE xss\.scoped_profile_reset_receipts/);
  assert.match(sql, /operation_id uuid PRIMARY KEY/);
  assert.match(sql, /stored_user_to=stored_user_from\+1/);
  assert.match(sql, /stored_llm_to=stored_llm_from\+1/);
  assert.match(sql, /pg_advisory_xact_lock\(hashtextextended\(requested_operation_id::text,8008\)\)/);
  assert.match(sql, /result_replayed boolean/);
  assert.match(sql, /SELECT r\.\* INTO prior[\s\S]*IF FOUND THEN[\s\S]*prior\.applied_at,true/);
  assert.match(sql, /INSERT INTO xss\.profiles[\s\S]*DELETE FROM xss\.profile_model_origins[\s\S]*INSERT INTO xss\.scoped_profile_reset_receipts/);
  assert.match(sql, /SECURITY DEFINER[\s\S]*SET search_path=pg_catalog,xss/);
  assert.match(sql, /BEFORE UPDATE ON xss\.scoped_profile_reset_receipts/);
  assert.match(sql, /REVOKE ALL ON xss\.scoped_profile_reset_receipts FROM PUBLIC,dvaia_xss_runtime/);
  assert.match(sql, /GRANT EXECUTE ON FUNCTION xss\.apply_scoped_profile_reset/);
  assert.doesNotMatch(sql, /GRANT (?:SELECT|INSERT|UPDATE|DELETE)[^;]*scoped_profile_reset_receipts/i);
  assert.doesNotMatch(sql, /^\s*(?:DROP|TRUNCATE)\b/im);
  const retirement = fs.readFileSync(path.join(directory, '0012_scoped_profile_reset_retirement.sql'), 'utf8');
  assert.match(retirement, /CREATE TABLE xss\.scoped_profile_reset_retirements/);
  assert.match(retirement, /pg_advisory_xact_lock\(hashtextextended\(requested_operation_id::text,8008\)\)/g);
  assert.match(retirement, /CREATE FUNCTION xss\.retire_or_read_scoped_profile_reset/);
  assert.match(retirement, /IF EXISTS \(SELECT 1 FROM xss\.scoped_profile_reset_retirements/);
  assert.match(retirement, /BEFORE UPDATE OR DELETE ON xss\.scoped_profile_reset_retirements/);
  assert.match(retirement, /GRANT EXECUTE ON FUNCTION xss\.retire_or_read_scoped_profile_reset/);
  assert.doesNotMatch(retirement, /DELETE FROM xss\.scoped_profile_reset_retirements/);
  const deletionFence = fs.readFileSync(path.join(directory, '0013_scoped_profile_reset_owner_deletion_fence.sql'), 'utf8');
  assert.match(deletionFence, /CREATE TABLE xss\.scoped_profile_reset_owner_deletions/);
  assert.match(deletionFence, /hashtextextended\(requested_owner_id::text,8012\)/);
  assert.match(deletionFence, /hashtextextended\(requested_user_id::text,8012\)/);
  assert.match(deletionFence, /IF EXISTS \(SELECT 1 FROM xss\.scoped_profile_reset_owner_deletions/);
  assert.match(deletionFence, /INSERT INTO xss\.scoped_profile_reset_owner_deletions\(owner_id\)/);
  assert.match(deletionFence, /BEFORE UPDATE OR DELETE ON xss\.scoped_profile_reset_owner_deletions/);
  assert.match(deletionFence, /CREATE OR REPLACE FUNCTION xss\.retire_or_read_scoped_profile_reset/);
  assert.match(deletionFence, /REVOKE ALL ON FUNCTION xss\.apply_scoped_profile_reset/);
  assert.match(deletionFence, /GRANT EXECUTE ON FUNCTION xss\.apply_scoped_profile_reset/);
  assert.match(deletionFence, /REVOKE ALL ON FUNCTION xss\.retire_or_read_scoped_profile_reset/);
  assert.match(deletionFence, /GRANT EXECUTE ON FUNCTION xss\.retire_or_read_scoped_profile_reset/);
  assert.doesNotMatch(deletionFence, /DELETE FROM xss\.scoped_profile_reset_owner_deletions/);
  const parent = fs.readFileSync(path.join(directory, '0014_parent_profile_reset_receipt.sql'), 'utf8');
  assert.match(parent, /CREATE TABLE xss\.parent_profile_reset_receipts/);
  assert.match(parent, /CREATE FUNCTION xss\.clear_parent_profile_reset\(\s*requested_operation_id uuid,\s*requested_owner_id bigint/);
  assert.match(parent, /DELETE FROM xss\.progress/);
  assert.match(parent, /DELETE FROM xss\.profile_model_origins/);
  assert.match(parent, /BEFORE UPDATE ON xss\.parent_profile_reset_receipts/);
  assert.match(parent, /GRANT EXECUTE ON FUNCTION xss\.clear_parent_profile_reset\(uuid,bigint\)/);
  assert.doesNotMatch(parent, /DELETE FROM xss\.scoped_profile_reset_owner_deletions/);
  const ownerWriteFence = fs.readFileSync(path.join(directory, '0015_owner_deletion_write_fence.sql'), 'utf8');
  assert.match(ownerWriteFence, /CREATE OR REPLACE FUNCTION xss\.reject_deleted_owner_write\(\)/);
  assert.match(ownerWriteFence, /SECURITY DEFINER[\s\S]*SET search_path=pg_catalog,xss/);
  assert.match(ownerWriteFence, /pg_advisory_xact_lock\(hashtextextended\(locked_owner_id::text, 8012\)\)/);
  assert.match(ownerWriteFence, /SELECT DISTINCT CASE/);
  assert.match(ownerWriteFence, /BEFORE INSERT OR UPDATE ON xss\.profiles/);
  for (const table of ['progress','emails','profile_model_origins','email_profiles','email_templates',
    'template_previews','xss_challenge_progress','xss_email_judge_receipts']) {
    assert.match(ownerWriteFence, new RegExp(`BEFORE INSERT OR UPDATE ON xss\\.${table}`));
  }
  assert.match(ownerWriteFence, /scoped_profile_reset_owner_deletions/);
  assert.doesNotMatch(ownerWriteFence, /BEFORE DELETE ON xss\.(?:profiles|emails|email_profiles)/);
  assert.match(ownerWriteFence, /REVOKE ALL ON FUNCTION xss\.reject_deleted_owner_write\(\) FROM PUBLIC,\s*dvaia_xss_runtime/);
  const retention = fs.readFileSync(path.join(directory, '0009_student_deletion_receipt_retention.sql'), 'utf8');
  assert.match(retention, /CREATE OR REPLACE FUNCTION xss\.destroy_student_owner\(requested_user_id bigint\)/);
  assert.match(retention, /requested_user_id IS NULL|requested_user_id<1/);
  assert.match(retention, /DELETE FROM xss\.scoped_profile_reset_receipts WHERE owner_id=requested_user_id/);
  assert.match(retention, /SECURITY DEFINER SET search_path=pg_catalog,xss/);
  assert.match(retention, /GRANT EXECUTE ON FUNCTION xss\.destroy_student_owner\(bigint\) TO dvaia_xss_runtime/);
  assert.doesNotMatch(fs.readFileSync(path.join(__dirname, '../server/routes/xssWorkshop.js'), 'utf8'), /xssScopedProfileResetRepository/);
});

test('reset store readiness rejects any missing admission fence or privilege', async () => {
  const complete = { parent_clear:true, retirement:true, deletion_fence:true, can_clear:true,
    can_retire:true, private_receipts:true, write_fences:true };
  let row = complete;
  const repository = createXssScopedProfileResetRepository({ query:async () => ({ rows:[row] }) });
  assert.equal(await repository.assertReady(), true);
  for (const key of Object.keys(complete)) {
    row = { ...complete, [key]:false };
    await assert.rejects(repository.assertReady(), { code:'XSS_PROFILE_RESET_STORAGE_NOT_READY' });
  }
});
