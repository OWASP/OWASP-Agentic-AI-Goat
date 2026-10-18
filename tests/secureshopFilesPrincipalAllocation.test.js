'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { createSecureShopLaunchRepository } = require('../server/database/postgres/secureshopLaunchRepository');
const id = n => `00000000-0000-4000-8000-${String(n).padStart(12,'0')}`;
const TENANT=id(1), A=id(2), B=id(3), SCENE=id(4), OWNER=41;
function fixture({ realm='shop', rows=[], missingPrincipal=false }={}) {
  const reservations=rows.map(r=>({...r})), calls=[];
  const principals=new Map([[101,{tenant_id:TENANT,principal_id:A}],[102,{tenant_id:TENANT,principal_id:B}],
    [103,{tenant_id:TENANT,principal_id:A}]]);
  const launchBySession=new Map([101,102,103].map(s=>[s,{launch_id:id(s),platform_session_id:s,
    platform_owner_id:OWNER,status:'active',generation:1,scenario_id:SCENE,expires_at:new Date('2099-01-01')} ]));
  let next=1000;
  const pool={async query(){throw Error('allocation must use transaction client');},async connect(){
    let locked=false,session;
    return {release(){calls.push('release');},async query(sql,args=[]){
      calls.push({sql,args});
      if(['BEGIN','COMMIT','ROLLBACK'].includes(sql))return{rows:[]};
      if(sql.startsWith('SELECT id,realm,is_active')){assert.match(sql,/FOR UPDATE/);locked=true;return{rows:[{id:OWNER,realm,is_active:1,account_locked_until:null}]};}
      if(sql.startsWith('SELECT id,user_id,realm')){assert.equal(locked,true);session=args[0];return{rows:[{id:session,user_id:OWNER,realm,is_active:1,expires_at:new Date('2099-01-01')}]};}
      if(sql==='SELECT clock_timestamp() AS now')return{rows:[{now:new Date('2026-01-01')}]};
      if(sql.includes('FOR UPDATE OF l')){assert.equal(locked,true);return{rows:[...launchBySession.values()].filter(l=>l.launch_id===args[0])};}
      if(sql.includes('AS tenant_id')&&!sql.includes('files_tenant_id')){assert.equal(locked,true);assert.deepEqual(args,[session,OWNER]);assert.match(sql,/s\.shop_execution_session_id/);assert.match(sql,/t\.owner_id=s\.user_id/);return{rows:missingPrincipal?[]:[principals.get(session)]};}
      if(sql.includes('FROM identity.secureshop_target_reservations r')){assert.equal(locked,true);assert.deepEqual(args,[OWNER]);return{rows:reservations.map(r=>({...r}))};}
      if(sql.includes('INSERT INTO identity.secureshop_target_reservations')){assert.equal(locked,true);const p=principals.get(session);const row={target_id:args[0],launch_id:args[1],generation:args[2],target_kind:'files',original_platform_owner_id:args[3],files_tenant_id:p.tenant_id,files_principal_id:p.principal_id};reservations.push(row);return{rows:[row]};}
      throw Error('Unexpected SQL '+sql);
    }};
  }};
  const repository=createSecureShopLaunchRepository(pool,{randomUUID:()=>id(next++)});
  return {calls,reservations,principals,launchBySession,async reserve(session=101,generation=1){return repository.reserveFilesTarget({platformSessionId:session,platformOwnerId:OWNER,launchId:id(session),expectedGeneration:generation});}};
}
const row=(n,principal=A,extra={})=>({target_id:id(10000+n),launch_id:id(n),generation:1,target_kind:'files',original_platform_owner_id:OWNER,files_tenant_id:TENANT,files_principal_id:principal,...extra});
const inserts=f=>f.calls.filter(c=>c.sql?.includes('INSERT INTO identity.secureshop_target_reservations')).length;
test('distinct shop principals share a tenant with separate targets; exact replay does not allocate',async()=>{
 const f=fixture(),a=await f.reserve(101),b=await f.reserve(102);assert.notEqual(a.targetId,b.targetId);assert.deepEqual(await f.reserve(101),a);assert.equal(inserts(f),2);assert.equal(a.kind,'files');assert.equal(a.generation,1);
});
test('same principal renewed session cannot bypass unresolved debt',async()=>{
 const f=fixture();await f.reserve(101);await assert.rejects(f.reserve(103),{code:'CLEANUP_REQUIRED'});assert.equal(inserts(f),1);assert.equal(f.calls.at(-2).sql,'ROLLBACK');
});
test('older generation debt remains fenced even in the same launch',async()=>{
 const f=fixture({rows:[row(101)]});f.launchBySession.get(101).generation=2;await assert.rejects(f.reserve(101,2),{code:'CLEANUP_REQUIRED'});assert.equal(inserts(f),0);
});
test('unknown current or retained principal scope fails closed without allocation',async()=>{
 const missing=fixture({missingPrincipal:true});await assert.rejects(missing.reserve(),{code:'CLEANUP_REQUIRED'});
 for(const mutation of [{files_principal_id:null},{files_tenant_id:id(900)},{original_platform_owner_id:99}]){
  const f=fixture({rows:[row(102,B,mutation)]});await assert.rejects(f.reserve(),{code:'CLEANUP_REQUIRED'});assert.equal(inserts(f),0);
 }
});
test('an exact launch cannot be replayed as a different principal',async()=>{
 const f=fixture({rows:[row(101,B)]});await assert.rejects(f.reserve(),{code:'CLEANUP_REQUIRED'});assert.equal(inserts(f),0);
});
test('tenant aggregate ceiling denies a new target but preserves exact replay',async()=>{
 const retained=Array.from({length:256},(_,i)=>row(i+200,id(i+2000)));
 const full=fixture({rows:retained});await assert.rejects(full.reserve(),{code:'FILES_TARGET_CAPACITY'});assert.equal(inserts(full),0);
 const replay=fixture({rows:[row(101),...retained.slice(1)]});assert.equal((await replay.reserve()).targetId,id(10101));assert.equal(inserts(replay),0);
 const last=fixture({rows:retained.slice(1)});await last.reserve();assert.equal(last.reservations.length,256);
});
test('platform realm retains owner-wide debt and does not query shop execution identity',async()=>{
 const f=fixture({realm:'platform'}),a=await f.reserve();assert.deepEqual(await f.reserve(),a);await assert.rejects(f.reserve(102),{code:'CLEANUP_REQUIRED'});assert.equal(inserts(f),1);assert.equal(f.calls.some(c=>c.sql?.includes('secureshop_auth.execution_sessions')),false);
});
test('reconciled reservation removal admits its principal while preserving sibling debt',async()=>{
 const f=fixture();const a=await f.reserve(),b=await f.reserve(102);f.reservations.splice(f.reservations.findIndex(r=>r.target_id===a.targetId),1);
 await f.reserve(103);assert.equal(f.reservations.length,2);assert.equal(f.reservations.find(r=>r.target_id===b.targetId).files_principal_id,B);
 // This controlled repository test models receipt-verified removal only; the native test exercises actual reset/reconciliation.
});

test('known retained principal debt stays classifiable after current session retirement',async()=>{
 const f=fixture({rows:[row(102,B,{platform_session_id:null,original_platform_session_id:102})]});
 await f.reserve(101);
 const query=f.calls.find(c=>c.sql?.includes('FROM identity.secureshop_target_reservations r'));
 assert.match(query.sql,/SELECT r\.\*/);
 assert.equal(query.sql.includes('platform_session_id'),false);
 assert.equal(query.sql.includes('execution_sessions'),false);
 assert.equal(f.reservations.length,2);
});
