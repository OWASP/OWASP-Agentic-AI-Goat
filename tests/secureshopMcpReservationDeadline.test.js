'use strict';
const test=require('node:test');const assert=require('node:assert/strict');
const {createSecureShopLaunchRepository}=require('../server/database/postgres/secureshopLaunchRepository');
const launchId='10000000-0000-4000-8000-000000000001';
const input={platformOwnerId:7,platformSessionId:8,launchId,expectedGeneration:1};
function fixture(failAt){
 const queries=[];let connects=0,releases=0;
 const failure=Object.assign(new Error('controlled query failure'),{code:'57014'});
 const client={release(){releases++;},async query(sql){queries.push(sql);if(failAt&&sql.includes(failAt))throw failure;
  if(sql.includes('FROM identity.secureshop_authority_owners'))return{rows:[{id:7,is_active:true,account_locked_until:null}]};
  if(sql.includes('FROM identity.secureshop_authority_sessions'))return{rows:[{id:8,user_id:7,is_active:true,expires_at:new Date('2099-01-01')}]};
  if(sql.includes('clock_timestamp'))return{rows:[{now:new Date('2026-09-20')}]};
  if(sql.includes('SELECT l.*'))return{rows:[{launch_id:launchId,platform_session_id:8,scenario_id:'20000000-0000-4000-8000-000000000001',generation:1,status:'active',expires_at:new Date('2099-01-01'),credential_version:1}]};
  if(sql.includes('SELECT r.*'))return{rows:[{target_id:'30000000-0000-4000-8000-000000000001',launch_id:launchId,generation:1}]};
  return{rows:[]};}};
 const pool={query:async()=>{throw Error('Unexpected pool query');},async connect(){connects++;return client;}};
 return{repository:createSecureShopLaunchRepository(pool),queries,failure,get connects(){return connects;},get releases(){return releases;}};
}
test('bounded MCP reservation sets transaction-local deadlines before any row locks',async()=>{
 const f=fixture();await f.repository.reserveMcpTarget(input,'rug_pull',{bounded:true});
 assert.equal(f.queries[0],'BEGIN');
 assert.equal(f.queries[1],"SELECT set_config('statement_timeout','3000',true),set_config('lock_timeout','3000',true)");
 assert.ok(f.queries.findIndex(sql=>sql.includes('FOR UPDATE'))>1);
 assert.equal(f.queries.at(-1),'COMMIT');assert.equal(f.releases,1);
});
test('default reservation keeps existing transaction behavior without timeout override',async()=>{
 const f=fixture();await f.repository.reserveMcpTarget(input,'rogue_registration');
 assert.equal(f.queries.some(sql=>sql.includes('set_config')),false);
 assert.equal(f.queries[0],'BEGIN');assert.equal(f.queries.at(-1),'COMMIT');assert.equal(f.releases,1);
});
test('malformed bounded value rejects before connecting',async()=>{
 for(const bounded of [null,1,'true',{},[]]){const f=fixture();await assert.rejects(f.repository.reserveMcpTarget(input,'rug_pull',{bounded}),{code:'INVALID_ARGUMENT'});assert.equal(f.connects,0);assert.deepEqual(f.queries,[]);}
});
test('malformed reservation options reject before connecting',async()=>{
 for(const options of [null,true,1,'bounded',[],{bound:true},{bounded:true,extra:true}]){const f=fixture();await assert.rejects(f.repository.reserveMcpTarget(input,'rug_pull',options),{code:'INVALID_ARGUMENT'});assert.equal(f.connects,0);}
});
test('deadline setup or locked-query failure rolls back and releases exactly once',async()=>{
 for(const failAt of ['set_config','FROM identity.secureshop_authority_owners']){const f=fixture(failAt);await assert.rejects(f.repository.reserveMcpTarget(input,'rug_pull',{bounded:true}),error=>error===f.failure);assert.equal(f.queries.at(-1),'ROLLBACK');assert.equal(f.queries.includes('COMMIT'),false);assert.equal(f.releases,1);}
});
