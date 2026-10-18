'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {createRegisteredUserAdministrationRepository:create}=require('../server/database/postgres/secureshopRegisteredUserAdministrationRepository');
const scope={launchId:'11111111-1111-4111-8111-111111111111',scenarioId:'22222222-2222-4222-8222-222222222222',generation:1,platformOwnerId:7,platformSessionId:8};
const input={scope,actorId:11,targetId:12,actorSessionId:'33333333-3333-4333-8333-333333333333',actorAuthorityVersion:'1',operationId:'44444444-4444-4444-8444-444444444444',expectedVersion:'1',action:'set_role',role:'merchant'};
function fixture({canonicalAdmin=true,personaLive=true,version='1',memberRole='customer',remaining=1,old=null,foreign=false,writeError=false,teaching=null,claim=null}={}){
 const calls=[];let persisted,claimed=claim;
 const query=async(sql,args)=>{calls.push([sql,args]);
  if(sql.includes('SELECT p.principal_id,m.role'))return{rows:[{principal_id:'target',...(foreign?{}:{version,role:memberRole})}]};
  if(sql.includes('SELECT e.tenant_id'))return{rows:canonicalAdmin?[{tenant_id:'tenant',principal_id:'actor'}]:[]};
  if(sql.includes('FROM secureshop_auth.tenant_admin_operations'))return{rows:old?[{scenario_id:scope.scenarioId,generation:'1',owner_id:7,execution_session_id:8,actor_id:11,target_id:12,...old}]:[]};
  if(sql.startsWith('INSERT INTO secureshop_auth.admin_operation_kinds')){claimed??={scenario_id:args[3],generation:String(args[1]),owner_id:args[4],execution_session_id:args[5],operation_kind:args[6],actor_id:args[7],target_id:args[8],request_sha256:args[9]};return{rows:[]};}
  if(sql.includes('FROM secureshop_auth.admin_operation_kinds'))return{rows:claimed?[claimed]:[]};
  if(sql.includes('SELECT m.*,m.membership_version'))return{rows:foreign?[]:[{version,membership_version:version,role:memberRole,is_active:true,principal_id:'target'}]};
  if(sql.includes('count(*)::integer'))return{rows:[{count:sql.includes('JOIN secureshop_auth.principals')?remaining:2}]};
  if(sql.startsWith('UPDATE secureshop_auth.tenant_memberships')){if(writeError)throw Error('database unavailable');return{rows:[{role:args[2],banned_at:args[3]?'2026-10-10T00:00:00Z':null,version:'2'}]};}
  if(sql.startsWith('INSERT INTO secureshop_auth.tenant_admin_operations'))persisted={request_sha256:args[10],result_json:JSON.parse(args[11])};
  return{rows:[],rowCount:1};
 };
 const repo=create({pool:{query,connect:async()=>({query,release(){}})},checkCurrent:async()=>{},personaAuthority:{capture(value){
  const binding={...scope,personaId:value.personaId,sessionId:value.sessionId,role:value.role,authorityVersion:value.authorityVersion};
  return{binding,async assertRemoteAdmission(){if(!personaLive)throw Object.assign(Error('denied'),{code:'SHOP_AUTH_INVALID'});},async withCrossStoreEffect(work){try{return await work();}catch{throw Object.assign(Error('uncertain'),{code:'PERSONA_EFFECT_OUTCOME_UNCERTAIN'});}}};
 }}});
 return{repo:{...repo,mutate:value=>repo.mutate(value,async()=>teaching)},calls,get claimed(){return claimed;},get persisted(){return persisted;}};
}
test('registered role updates only canonical tenant and writes exact immutable receipt',async()=>{
 const f=fixture(),result=await f.repo.mutate(input);assert.equal(result.receipt.role,'merchant');assert.equal(result.receipt.version,'2');assert.equal(result.receipt.revokedSessions,2);
 assert.deepEqual(result.receipt,f.persisted.result_json);assert.equal(f.calls.at(-1)[0],'COMMIT');
 const update=f.calls.find(([sql])=>sql.startsWith('UPDATE'));assert.match(update[0],/WHERE tenant_id=\$1 AND shop_user_id=\$2/);assert.deepEqual(update[1].slice(0,2),['tenant',12]);
 assert.ok(!f.calls.some(([sql])=>/UPDATE secureshop_auth\.(principals|sessions)/.test(sql)));
 const auth=f.calls.find(([sql])=>sql.includes('SELECT e.tenant_id'))[0];assert.match(auth,/m.role='admin'/);assert.doesNotMatch(auth,/p.role='admin'/);assert.match(auth,/session_membership_snapshots/);
});
test('legitimate tenant admin promotion retains global principal identity',async()=>{
 const f=fixture(),result=await f.repo.mutate({...input,role:'admin'});assert.equal(result.receipt.role,'admin');assert.ok(!f.calls.some(([sql])=>sql.startsWith('UPDATE secureshop_auth.principals')));
});
test('ban keeps role and canonical version with timestamp',async()=>{
 const f=fixture(),result=await f.repo.mutate({...input,action:'ban',role:undefined,reason:'owned reason'});assert.equal(result.receipt.role,'customer');assert.equal(result.receipt.bannedAt,'2026-10-10T00:00:00.000Z');
});
for(const [name,options,code] of [['synthetic escalation',{canonicalAdmin:false},'ADMIN_REQUIRED'],['stale persona session',{personaLive:false},'SHOP_AUTH_INVALID'],['stale version',{version:'2'},'REVISION_CONFLICT'],['foreign tenant',{foreign:true},'PERSONA_UNAVAILABLE'],['final admin',{memberRole:'admin',remaining:0},'LAST_TENANT_ADMIN']])test(name+' denies without mutation',async()=>{
 const f=fixture(options);await assert.rejects(f.repo.mutate(input),{code});assert.ok(!f.calls.some(([sql])=>sql.startsWith('UPDATE')));
});
test('exact replay returns original receipt without new member update',async()=>{
 const first=fixture();await first.repo.mutate(input);const next=fixture({old:first.persisted});const result=await next.repo.mutate(input);assert.equal(result.replayed,true);assert.deepEqual(result.receipt,first.persisted.result_json);assert.ok(!next.calls.some(([sql])=>sql.startsWith('UPDATE')));
 const changed=fixture({old:first.persisted});await assert.rejects(changed.repo.mutate({...input,role:'admin'}),{code:'OPERATION_CONFLICT'});
});
test('post-admission database failure remains uncertain',async()=>{await assert.rejects(fixture({writeError:true}).repo.mutate(input),{code:'PERSONA_EFFECT_OUTCOME_UNCERTAIN'});});
test('tenant serialization precedes principal locks and final-admin count',async()=>{
 const f=fixture({memberRole:'admin'});await f.repo.mutate({...input,targetId:11});const sql=f.calls.map(([s])=>s);assert.ok(sql.findIndex(s=>s.includes('pg_advisory_xact_lock'))<sql.findIndex(s=>s.includes('ORDER BY principal_id FOR SHARE')));assert.equal(sql.filter(s=>s.includes('JOIN secureshop_auth.principals p USING(principal_id) WHERE')).length,1);
});
