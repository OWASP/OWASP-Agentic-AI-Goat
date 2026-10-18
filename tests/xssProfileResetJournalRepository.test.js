'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { createXssProfileResetJournalRepository } = require(
  '../server/database/postgres/xssProfileResetJournalRepository');
const { createXssScopedProfileResetRepository } = require(
  '../server/database/postgres/xssScopedProfileResetRepository');

const OPERATION = '11111111-1111-4111-8111-111111111111';
const LEASE = '22222222-2222-4222-8222-222222222222';
const row = (overrides = {}) => ({ operationId:OPERATION, ownerId:17,
  ownerKey:'["XSS","17"]', graphParentGeneration:'4', workshopGeneration:'2',
  storedUserFrom:'6', storedUserTo:'7', storedLlmFrom:'8', storedLlmTo:'9',
  status:'running', leaseToken:LEASE, leaseExpiresAt:'later', failureCode:null,
  createdAt:'created', updatedAt:'updated', completedAt:null, ...overrides });
const receipt = (overrides = {}) => ({ operationId:OPERATION, ownerId:17,
  graphParentGeneration:'4', workshopGeneration:'2',
  children:{ stored_user:{ from:'6', to:'7' }, stored_llm:{ from:'8', to:'9' } },
  profileRevisions:{ name:'3', bio:'4', website:'5' }, originsRemoved:2,
  appliedAt:'2026-09-19T12:00:00.000Z', replayed:false, ...overrides });

function fixture() {
  const calls = [];
  return { calls, async query(sql, values) {
    calls.push([sql.replace(/\s+/g, ' ').trim(), values]);
    if (sql.includes('acknowledge_xss_profile_reset_store')) {
      return { rowCount:1, rows:[{ receiptSha256:'a'.repeat(64), replayed:false }] };
    }
    if (sql.includes('fail_xss_profile_reset')) return { rowCount:1, rows:[{ failed:true }] };
    if (sql.includes('list_recoverable')) return { rowCount:1, rows:[{ operationId:OPERATION }] };
    if (sql.includes('assertReady')) throw new Error('unused');
    return { rowCount:1, rows:[row()] };
  } };
}

test('begin, claim and current checks preserve the complete immutable authority tuple', async () => {
  const pool = fixture(); const journal = createXssProfileResetJournalRepository(pool);
  const begun = await journal.begin({ operationId:OPERATION, ownerId:17,
    graphParentGeneration:4, workshopGeneration:'2' });
  assert.deepEqual(begun.children, {
    stored_user:{ from:'6', to:'7' }, stored_llm:{ from:'8', to:'9' },
  });
  assert.equal(Object.isFrozen(begun), true);
  assert.deepEqual(pool.calls[0][1], [OPERATION, 17, '4', '2']);
  const claimed = await journal.claim(OPERATION, { leaseMs:2000 });
  assert.deepEqual(claimed.children, begun.children);
  assert.match(pool.calls[1][1][1], /^[0-9a-f-]{36}$/);
  const current = await journal.assertCurrent({ operationId:OPERATION, leaseToken:LEASE });
  assert.equal(current.leaseToken, LEASE);
  assert.deepEqual(pool.calls[2][1], [OPERATION, LEASE]);
});

test('store acknowledgement sends one normalized bounded receipt and accepts only SQL digest authority', async () => {
  const pool = fixture(); const journal = createXssProfileResetJournalRepository(pool);
  const acknowledged = await journal.acknowledgeStore({ operationId:OPERATION,
    leaseToken:LEASE, receipt:receipt() });
  assert.deepEqual(acknowledged, { receiptSha256:'a'.repeat(64), replayed:false });
  const sent = JSON.parse(pool.calls[0][1][2]);
  assert.deepEqual(sent, receipt());
  assert.match(pool.calls[0][0], /acknowledge_xss_profile_reset_store\(\$1,\$2,\$3::jsonb\)/);
  assert.equal(Object.hasOwn(sent, 'receiptSha256'), false, 'caller never supplies digest authority');
});

test('closed validators reject coercion, overflow, extras and malformed receipts before SQL', async () => {
  const pool = fixture(); const journal = createXssProfileResetJournalRepository(pool);
  for (const invalid of [
    { operationId:OPERATION, ownerId:true, graphParentGeneration:'4', workshopGeneration:'2' },
    { operationId:OPERATION, ownerId:17, graphParentGeneration:'4', workshopGeneration:'2', authority:true },
    { operationId:OPERATION, ownerId:17, graphParentGeneration:Number.MAX_SAFE_INTEGER + 1, workshopGeneration:'2' },
  ]) assert.throws(() => journal.begin(invalid), TypeError);
  for (const invalidReceipt of [
    receipt({ authority:'caller' }),
    receipt({ children:{ stored_user:{ from:'6', to:'8' }, stored_llm:{ from:'8', to:'9' } } }),
    receipt({ profileRevisions:{ name:'0', bio:'4', website:'5' } }),
    receipt({ originsRemoved:2.5 }), receipt({ appliedAt:'not-a-time' }),
    receipt({ replayed:'false' }),
  ]) await assert.rejects(journal.acknowledgeStore({ operationId:OPERATION,
    leaseToken:LEASE, receipt:invalidReceipt }), TypeError);
  assert.equal(pool.calls.length, 0);
});

test('recovery, failure and completion use only the fixed journal functions', async () => {
  const pool = fixture(); const journal = createXssProfileResetJournalRepository(pool);
  assert.deepEqual(await journal.listRecoverable({ limit:5 }), [OPERATION]);
  assert.deepEqual(await journal.fail({ operationId:OPERATION, leaseToken:LEASE, code:'XSS_STORE_FAILED' }),
    { status:'failed' });
  assert.equal((await journal.complete({ operationId:OPERATION, leaseToken:LEASE })).operationId, OPERATION);
  assert.match(pool.calls[0][0], /list_recoverable_xss_profile_resets/);
  assert.match(pool.calls[1][0], /fail_xss_profile_reset/);
  assert.match(pool.calls[2][0], /complete_xss_profile_reset/);
});

test('owner lookup returns one immutable nonterminal operation without exposing table reads', async () => {
  const pool = fixture(); const journal = createXssProfileResetJournalRepository(pool);
  const found = await journal.readNonterminalForOwner(17);
  assert.equal(found.operationId, OPERATION);
  assert.equal(found.ownerId, 17);
  assert.match(pool.calls[0][0], /read_nonterminal_xss_profile_reset_for_owner\(\$1\)/);
  assert.deepEqual(pool.calls[0][1], [17]);
  assert.throws(() => journal.readNonterminalForOwner(true), TypeError);
  assert.throws(() => journal.readNonterminalForOwner(2147483648), TypeError);
  assert.equal(pool.calls.length, 1);
});

test('parent reconciliation accepts the real durable store retirement contract and binds SQL authority', async () => {
  const storePool = { async query() { return { rowCount:1, rows:[{
    operationId:OPERATION, ownerId:17, graphParentGeneration:'4', workshopGeneration:'2',
    storedUserFrom:'6', storedUserTo:'7', storedLlmFrom:'8', storedLlmTo:'9',
    retired:true, retiredAt:'2026-09-19T12:00:00.000Z', replayed:false,
  }] }; } };
  const retired = await createXssScopedProfileResetRepository(storePool).retireOrRead({
    operationId:OPERATION, ownerId:17, graphParentGeneration:'4', workshopGeneration:'2',
    children:{ stored_user:{ from:'6', to:'7' }, stored_llm:{ from:'8', to:'9' } },
  });
  assert.deepEqual(Object.keys(retired).sort(), [
    'children','graphParentGeneration','kind','operationId','ownerId','workshopGeneration',
  ]);

  const pool = fixture();
  pool.query = async function query(sql, values) {
    this.calls.push([sql.replace(/\s+/g, ' ').trim(), values]);
    return { rowCount:1, rows:[row({ status:'superseded', leaseToken:null,
      leaseExpiresAt:null, completedAt:'done', failureCode:'PARENT_RESET_SUPERSEDED',
      reconciliationKind:'retired_no_effect', reconciliationSha256:'b'.repeat(64),
      reconciledGraphParentGeneration:'5', reconciledWorkshopGeneration:'3' })] };
  };
  const reconciled = await createXssProfileResetJournalRepository(pool).reconcileAfterParentReset({
    operationId:OPERATION, ownerId:17, observedGraphParentGeneration:'5',
    observedWorkshopGeneration:'3', outcome:retired,
  });
  assert.equal(reconciled.status, 'superseded');
  assert.deepEqual(reconciled.reconciliation, { kind:'retired_no_effect',
    outcomeDigest:'b'.repeat(64), observedGraphParentGeneration:'5',
    observedWorkshopGeneration:'3' });
  assert.deepEqual(JSON.parse(pool.calls[0][1][4]), retired);
  assert.match(pool.calls[0][0], /reconcile_xss_profile_reset_after_parent/);
});

test('parent reconciliation rejects extra, foreign and overflowing retirement authority before SQL', async () => {
  const pool = fixture(); const journal = createXssProfileResetJournalRepository(pool);
  const base = { kind:'retired_no_effect', operationId:OPERATION, ownerId:17,
    graphParentGeneration:'4', workshopGeneration:'2',
    children:{ stored_user:{ from:'6', to:'7' }, stored_llm:{ from:'8', to:'9' } } };
  for (const outcome of [
    { ...base, retiredAt:'caller-metadata' }, { ...base, ownerId:true },
    { ...base, graphParentGeneration:'9223372036854775808' },
    { ...base, children:{ ...base.children, stored_user:{ from:'6', to:'8' } } },
  ]) assert.throws(() => journal.reconcileAfterParentReset({ operationId:OPERATION,
    ownerId:17, observedGraphParentGeneration:'5', observedWorkshopGeneration:'3', outcome }), TypeError);
  assert.equal(pool.calls.length, 0);
});

test('0072 remains immutable and the forward identity tail stays ordered through 0080', () => {
  const directory = path.join(__dirname, '../db/postgres/identity-migrations');
  const files = fs.readdirSync(directory).filter(name => /^\d{4}_.*\.sql$/.test(name)).sort();
  assert.equal(new Set(files.map(name => name.slice(0,4))).size, files.length, 'ordered migration identifiers stay unique');
  assert.equal(files.filter(name => name < '0081_').at(-1), '0080_legacy_ai_private_history.sql');
  const sql = fs.readFileSync(path.join(directory, '0072_xss_profile_reset_journal.sql'), 'utf8');
  assert.match(sql, /xss_profile_reset_one_nonterminal_owner[\s\S]*WHERE status<>'completed'/);
  assert.match(sql, /scope_key='stored_user'[\s\S]*scope_key='stored_llm'/);
  assert.match(sql, /state='resetting'/);
  assert.match(sql, /assert_xss_profile_reset_current/);
  assert.match(sql, /sha256\(convert_to\(normalized::text,'UTF8'\)\)/);
  assert.match(sql, /NOT EXISTS\(SELECT 1 FROM identity\.student_deletion_jobs/);
  assert.match(sql, /w\.workshop_key='xss_workshop' AND w\.generation=r\.workshop_generation/);
  assert.match(sql, /REVOKE ALL ON identity\.xss_profile_reset_operations,identity\.xss_profile_reset_steps/);
  assert.doesNotMatch(sql, /GRANT (?:SELECT|INSERT|UPDATE|DELETE)[^;]*xss_profile_reset/i);
  assert.doesNotMatch(sql, /DELETE FROM workshop_platform\.(?:completions|activity_counters|time_tracking)/);
  assert.doesNotMatch(sql, /^\s*(?:DROP|TRUNCATE)\b/im);
  const recovery = fs.readFileSync(path.join(directory,
    '0074_xss_profile_reset_parent_supersession.sql'), 'utf8');
  assert.match(recovery, /status IN \('pending','running','failed','completed','superseded'\)/);
  assert.match(recovery, /reconcile_xss_profile_reset_after_parent/);
  assert.match(recovery, /sha256\(convert_to\(normalized::text,'UTF8'\)\)/);
  assert.match(recovery, /jsonb_object_keys\(requested_outcome\)\)<>6/);
  assert.doesNotMatch(recovery, /retiredAt/);
  assert.doesNotMatch(recovery, /DELETE FROM workshop_platform\.(?:completions|activity_counters|time_tracking)/);
  const repair = fs.readFileSync(path.join(directory,
    '0075_xss_profile_reset_constraint_repair.sql'), 'utf8');
  assert.match(repair, /pg_constraint[\s\S]*contype='c'/);
  assert.match(repair, /xss_profile_reset_operations_stored_user_transition/);
  assert.match(repair, /xss_profile_reset_operations_running_lease/);
  assert.match(repair, /xss_profile_reset_operations_terminal_time/);
  assert.match(repair, /xss_profile_reset_steps_terminal_receipt/);
  assert.match(repair, /status IN \('completed','superseded'\)/);
  assert.equal((repair.match(/status<>'superseded' OR \(failure_code IS NOT NULL/g) || []).length, 2,
    'operation and step supersession reject SQL NULL failure codes');
  const lookup = fs.readFileSync(path.join(directory, '0076_xss_profile_reset_owner_lookup.sql'), 'utf8');
  assert.match(lookup, /read_nonterminal_xss_profile_reset_for_owner/);
  assert.match(lookup, /status NOT IN \('completed','superseded'\)/);
  assert.match(lookup, /NOT EXISTS\(SELECT 1 FROM identity\.student_deletion_jobs/);
  assert.match(lookup, /REVOKE ALL ON FUNCTION[\s\S]*FROM PUBLIC/);
  assert.doesNotMatch(lookup, /GRANT (?:SELECT|INSERT|UPDATE|DELETE)/);
  for (const relative of ['../server/routes/xssWorkshop.js',
    '../server/database/postgres/xssProfileOriginRepository.js']) {
    assert.doesNotMatch(fs.readFileSync(path.join(__dirname, relative), 'utf8'),
      /xssProfileResetJournalRepository/);
  }
});
