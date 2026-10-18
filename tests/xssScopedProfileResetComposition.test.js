'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { createXssScopedProfileResetComposition } = require('../server/services/xssScopedProfileResetComposition');

const OPERATION_ID = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
function completedRow() {
  return { operationId:OPERATION_ID, ownerId:17, ownerKey:'["XSS","17"]',
    graphParentGeneration:'4', workshopGeneration:'6', storedUserFrom:'1', storedUserTo:'2',
    storedLlmFrom:'3', storedLlmTo:'4', status:'completed', leaseToken:null,
    leaseExpiresAt:null, failureCode:null, createdAt:new Date(), updatedAt:new Date(), completedAt:new Date() };
}
function fixture() {
  const calls=[];
  const identityPool={connect(){},async query(sql,params){
    if (/workshop_platform\.user_state/.test(sql)) return {rowCount:1,rows:[{generation:'6'}]};
    if (/read_xss_profile_reset\(/.test(sql)) {calls.push(['read',params[0]]);return {rowCount:1,rows:[completedRow()]};}
    if (/to_regclass\('identity\.xss_profile_reset_operations'/.test(sql)
        || /to_regclass\('identity\.xss_parent_reset_operations'/.test(sql)) {
      return {rowCount:1,rows:[Object.fromEntries([...sql.matchAll(/AS ([a-z_]+)/g)].map(match=>[match[1],true]))]};
    }
    throw new Error(`Unexpected identity query: ${sql}`);
  }};
  const store={apply:async()=>assert.fail('completed replay must not clear profile'),
    assertReady:async()=>{calls.push('store-ready');return true;}};
  const runs={cancelScopes(){},withScopesQuiesced:async(owner,scopes,work)=>{
    assert.equal(owner,17);assert.deepEqual(scopes,['stored_user','stored_llm']);calls.push('quiesce');return work();
  }};
  const ledger={withOwnerLease:async({ownerKey},work)=>{
    assert.equal(ownerKey,'["XSS","17"]');return work({durableGeneration:'4',check:async()=>{}});
  }};
  const lifecycle=async(_pool,owner,work)=>{
    assert.equal(owner,17);calls.push('lifecycle');return work(null,{check:async()=>{}});
  };
  return {calls,identityPool,store,runs,ledger,lifecycle,
    composition:createXssScopedProfileResetComposition({identityPool,store,runs,ledger,lifecycle})};
}

test('composition validates and normalizes an explicit completed replay without clearing twice',async()=>{
  const f=fixture();
  const result=await f.composition.reset({ownerId:17,operationId:OPERATION_ID.toUpperCase()});
  assert.equal(result.operationId,OPERATION_ID);assert.equal(result.status,'completed');
  assert.deepEqual(f.calls,[ 'lifecycle','quiesce',['read',OPERATION_ID] ]);
});

test('composition rejects malformed or extra public authority before lifecycle admission',async()=>{
  const f=fixture();
  for (const input of [{ownerId:0},{ownerId:17,operationId:'bad'},{ownerId:17,generation:'4'}]) {
    assert.throws(()=>f.composition.reset(input),error=>error instanceof TypeError
      && error.code==='BAD_REQUEST' && error.statusCode===400);
  }
  assert.deepEqual(f.calls,[]);
});

test('composition readiness covers child journal, parent journal, and workshop store',async()=>{
  const f=fixture();assert.equal(await f.composition.assertReady(),true);
  assert.deepEqual(f.calls,['store-ready']);
});
