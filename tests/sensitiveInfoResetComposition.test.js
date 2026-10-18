'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { readMigrations } = require('../db/postgres/migrate');
const { FLAG, STORES, enabled, createSensitiveInfoResetComposition,
  assertSensitiveInfoResetReadiness } = require('../server/services/sensitiveInfoResetComposition');

function journalFixture(order = []) {
  let state;
  return { assertReady: async () => { order.push('journal-ready'); },
    begin: async ({ ownerId }) => (state ||= { operationId:'11111111-1111-4111-8111-111111111111',
      ownerId,fromGeneration:1,toGeneration:2,status:'pending',next:0 }),
    read: async () => state,
    claim: async () => ({ ...state,leaseToken:'22222222-2222-4222-8222-222222222222' }),
    nextStep: async () => ['legacy_store','finflow_store'][state.next] || null,
    acknowledge: async () => { state.next += 1; }, fail: async () => {},
    complete: async () => ({ ...state,status:'completed' }) };
}
function cleanupFixture(order = []) {
  const receipts = new Map();
  return { assertReady: async () => { order.push('cleanup-ready'); },
    apply: async scope => { order.push(scope.stepKey); receipts.set(scope.stepKey,{...scope}); },
    readReceipt: async scope => receipts.get(scope.stepKey) };
}

test('promoted aggregate reset defaults on for paired PostgreSQL storage and rejects invalid configuration', async () => {
  const pg = { PLATFORM_DATABASE_ENGINE: 'postgres', WORKSHOP_DATABASE_ENGINE: 'postgres' };
  assert.equal(enabled({}),false);
  assert.equal(enabled(pg),true);
  assert.equal(enabled({...pg,[FLAG]:'false'}),false);
  assert.equal(enabled({...pg,[FLAG]:'true'}),true);
  assert.throws(() => enabled({PLATFORM_DATABASE_ENGINE:'postgres'}),{code:'INVALID_CONFIGURATION'});
  assert.throws(() => enabled({...pg,[FLAG]:'yes'}),{code:'INVALID_CONFIGURATION'});
  assert.equal(await createSensitiveInfoResetComposition({env:{...pg,[FLAG]:'false'}}),null);
  assert.equal(await createSensitiveInfoResetComposition({env:{}}),null);
});

test('reset-only composition is independent of objective catalog visibility', async () => {
  const order=[];let retired;
  const runs={reset:async(owner,work)=>{order.push(`legacy:${owner}`);return work();}};
  const composition=await createSensitiveInfoResetComposition({
    env:{[FLAG]:'true',PLATFORM_DATABASE_ENGINE:'postgres',WORKSHOP_DATABASE_ENGINE:'postgres'},
    runs,finflowReset:async(owner,work)=>{order.push(`finflow:${owner}`);return work();},
    journal:journalFixture(order),cleanup:cleanupFixture(order),
    traversalReset:async owner=>order.push(`traversal:${owner}`),
    resourceLifecycle:{resources:{
      retireGeneration:async scope=>{order.push('resource-retire');retired={...scope,status:'completed'};},
      readRetirement:async()=>retired,
    }},
  });
  const result=await composition.reset.reset(41);
  assert.equal(result.status,'completed');
  assert.deepEqual(order,['legacy:41','finflow:41','traversal:41','legacy_store','resource-retire','finflow_store']);
});

test('production readiness verifies exact store identity, ledgers, and both capabilities', async () => {
  const calls=[];let resourcesReady=true;
  const runtime=(role,database,readyName)=>({connect:async()=>{},query:async(sql)=>{
    calls.push([readyName,sql]);
    if(/^SELECT current_user/.test(sql))return{rows:[{role,database}]};
    if(sql.includes('finflow.customer_datasets'))return{rows:[{
      ...Object.fromEntries(require('../server/database/postgres/finflowDurableResourceRepository').READINESS_FIELDS.map(key=>[key,true])),
      no_runtime_tables:resourcesReady,
    }]};
    if(sql.includes('begin_sensitive_info_reset'))return{rows:[Object.fromEntries([
      'operations','steps','authority','begin','judgment_guard','completion_guard','run_guard','runtime_begin','no_public_execute'
    ].map(key=>[key,true]))]};
    return{rows:[Object.fromEntries([
      'operations','receipts','apply','read','operation_guard','receipt_guard','runtime_apply','runtime_read','no_public_execute'
    ].map(key=>[key,true]))]};
  }});
  const ledgers={identity:await readMigrations(STORES.identity.directory),
    finflow:await readMigrations(STORES.finflow.directory)};
  const migration=(role,database,ledger)=>({query:async(sql)=>sql.includes('current_user')
    ?{rows:[{role,database}]}:{rows:ledger}});
  const options={
    identityPool:runtime('dvaia_identity_runtime','identity','identity'),
    finflowPool:runtime('dvaia_finflow_runtime','finflow','finflow'),
    migrationPools:{identity:migration('dvaia_identity_migration','identity',ledgers.identity),
      finflow:migration('dvaia_finflow_migration','finflow',ledgers.finflow)},
  };
  await assert.doesNotReject(assertSensitiveInfoResetReadiness(options));
  resourcesReady=false;
  await assert.rejects(assertSensitiveInfoResetReadiness(options),{code:'FINFLOW_RESOURCE_STORAGE_NOT_READY'});
  assert.ok(calls.some(([name,sql])=>name==='identity'&&sql.includes('begin_sensitive_info_reset')));
  assert.ok(calls.some(([name,sql])=>name==='finflow'&&sql.includes('apply_sensitive_info_cleanup')));
});
