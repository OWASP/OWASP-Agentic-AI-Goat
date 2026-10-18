'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const {assertCurrentAuditScope} = require('../server/database/postgres/secureshopAuditQueryRepository');

const binding = {platformOwnerId:401,platformSessionId:502,launchId:'owned-launch',
  scenarioId:'owned-scenario',generation:3};
const now = new Date('2026-10-10T00:00:00Z');
const later = new Date(now.getTime()+60000);
function client(overrides={}) {
  const rows = {
    owner:{is_active:1,account_locked_until:null},
    session:{user_id:401,is_active:1,expires_at:later},
    launch:{status:'active',expires_at:later,original_platform_owner_id:401,
      platform_session_id:502,scenario_id:'owned-scenario',generation:3},
    graphOwner:{generation:7},run:{owner_key:'shop-owner',generation:7,status:'running'},
    ...overrides,
  };
  return {async query(sql,args) {
    let row;
    if(sql.includes('FROM identity.secureshop_authority_owners')) {
      assert.deepEqual(args,[401]); row=rows.owner;
    } else if(sql.includes('FROM identity.secureshop_authority_sessions')) {
      assert.deepEqual(args,[502]); row=rows.session;
    } else if(sql.includes('FROM identity.secureshop_launches')) row=rows.launch;
    else if(sql.includes('FROM graph_runtime.owners')) row=rows.graphOwner;
    else if(sql.includes('FROM graph_runtime.runs')) row=rows.run;
    else if(sql==='SELECT clock_timestamp() AS now') row={now};
    else assert.fail(`Unexpected authority query: ${sql}`);
    return {rows:row?[row]:[]};
  }};
}
test('audit scope accepts canonical shop authority without workshop user/session lookups',async()=>{
  await assertCurrentAuditScope(client(),binding,null);
  await assertCurrentAuditScope(client(),binding,{ownerKey:'shop-owner',runId:'owned-run',durableGeneration:7});
});
test('canonical audit authority still rejects missing, revoked, expired and foreign sessions',async()=>{
  for(const overrides of [
    {owner:null},{owner:{is_active:0}},
    {owner:{is_active:1,account_locked_until:later}},
    {session:null},{session:{user_id:401,is_active:0,expires_at:later}},
    {session:{user_id:999,is_active:1,expires_at:later}},
    {session:{user_id:401,is_active:1,expires_at:now}},
  ]) await assert.rejects(assertCurrentAuditScope(client(overrides),binding,null),{code:'AUDIT_QUERY_STALE'});
});
test('audit scope retains launch and graph generation fences after realm correction',async()=>{
  const execution={ownerKey:'shop-owner',runId:'owned-run',durableGeneration:7};
  for(const overrides of [
    {launch:null},{launch:{status:'revoked',expires_at:later}},
    {graphOwner:{generation:8}},
    {run:{owner_key:'sibling-owner',generation:7,status:'running'}},
    {run:{owner_key:'shop-owner',generation:7,status:'completed'}},
  ]) await assert.rejects(assertCurrentAuditScope(client(overrides),binding,execution),{code:'AUDIT_QUERY_STALE'});
});
