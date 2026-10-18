'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const { createResetLeasePools } = require('./postgres/adminStudentResetRecoverySupport');
const { createPostgresRunLedger } = require('../server/agent-runtime/postgresRunLedger');
const { withPostgresStudentResetAdmission } = require('../server/services/postgresWorkshopResetService');
const { createSensitiveInfoResetRepository } = require('../server/database/postgres/sensitiveInfoResetRepository');
const operationId = '12345678-1234-4234-8234-123456789012';
function boundedPool(max) {
 let used = 0;
 const query = async sql => {
  if (sql.includes('pg_try_advisory_lock')) return { rows: [{ acquired: true }] };
  if (sql.includes('pg_advisory_unlock')) return { rows: [{ unlocked: true }] };
  if (sql.includes('SELECT id FROM identity.users')) return { rows: [{ id: 7 }] };
  if (sql.includes('student_deletion_jobs')) return { rows: [], rowCount: 0 };
  if (sql.includes('INSERT INTO graph_runtime.owners') || sql.startsWith('SELECT generation FROM graph_runtime.owners')) return { rows: [{ generation: 1 }] };
  if (sql.includes('UPDATE identity.sensitive_info_resets')) return { rows: [{ owner_id: 7, from_generation: 0, to_generation: 1 }] };
  if (sql.includes('pg_advisory_lock') || sql.startsWith('UPDATE graph_runtime.')) return { rows: [], rowCount: 0 };
  throw Error('Unexpected controlled SQL: '+sql);
 };
 const pool = {
  async connect() {
   if (used === max) throw Error('CONTROLLED_POOL_EXHAUSTED'); used++;
   const client = new EventEmitter(); client.query = query; client.release = () => { used--; }; return client;
  },
  async query(sql, args) { const c = await pool.connect(); try { return await c.query(sql,args); } finally { c.release(); } },
  async end() { assert.equal(used, 0); },
  used: () => used,
 };
 return pool;
}
async function claimUnderLocks(runtime, lifecycle, graph) {
 const ledger = createPostgresRunLedger(runtime, { leasePool: graph });
 return withPostgresStudentResetAdmission(lifecycle, 7, async () => {
  const lease = await ledger.invalidate({ ownerKey: 'FinFlow:7' });
  await lease.acquire();
  try { return await createSensitiveInfoResetRepository(runtime).claim(operationId); }
  finally { await lease.release(); }
 });
}
test('reproduces fixture exhaustion with both real lease paths; separate lease pools preserve journal capacity', async () => {
 const shared = boundedPool(2);
 await assert.rejects(claimUnderLocks(shared, shared, shared), /CONTROLLED_POOL_EXHAUSTED/);
 assert.equal(shared.used(), 0);
 const requests = [];
 const pools = await createResetLeasePools({ env: {}, createPool: (_env,key,options) => {
  requests.push({ key, options }); return boundedPool(4);
 } });
 try {
  const claim = await claimUnderLocks(shared, pools.lifecycleLease, pools.graphLease);
  assert.equal(claim.operationId, operationId); assert.equal(claim.ownerId, 7);
  assert.deepEqual(requests, Array.from({length:2}, () => ({ key:'PG_ADMIN_BROWSER_TEST_RUNTIME_URL',options:{purpose:'lease'} })));
  assert.notEqual(pools.graphLease, pools.lifecycleLease);
 } finally { await pools.close(); }
 assert.equal(shared.used(),0);
});
test('partial lease-pool allocation closes first owned pool when second allocation fails', async () => {
 let calls=0,closed=0;
 await assert.rejects(createResetLeasePools({ env:{}, createPool: () => {
  if (++calls===2) throw Error('allocation rejected'); return { end: async()=>{closed++;} };
 } }), /allocation rejected/);
 assert.equal(closed,1);
});

test('normal teardown attempts both owned pools even when one close fails', async () => {
 const closed=[]; let count=0;
 const pools=await createResetLeasePools({env:{},createPool:()=>{
  const index=count++;return {end:async()=>{closed.push(index);if(index===0)throw Error('close failed');}};
 }});
 await assert.rejects(pools.close(), /lease pool cleanup failed/);
 assert.deepEqual(closed.sort(),[0,1]);
});
test('allocation failure remains primary when cleanup also fails', async () => {
 const original=Error('second allocation failed');let count=0;
 await assert.rejects(createResetLeasePools({env:{},createPool:()=>{
  if(++count===2)throw original;return {end:async()=>{throw Error('close failed');}};
 }}),error=>{assert.equal(error,original);assert.ok(error.cleanupError instanceof AggregateError);return true;});
});
