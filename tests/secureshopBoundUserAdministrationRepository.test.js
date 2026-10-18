'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {createSecureShopBoundUserAdministrationRepository:create}=require('../server/database/postgres/secureshopBoundUserAdministrationRepository');
const scope={launchId:'11111111-1111-4111-8111-111111111111',scenarioId:'22222222-2222-4222-8222-222222222222',generation:1,platformOwnerId:5,platformSessionId:7};
const input={scope,actorId:3,actorSessionId:'33333333-3333-4333-8333-333333333333',targetId:1,operationId:'44444444-4444-4444-8444-444444444444',expectedVersion:'1',action:'set_role',role:'merchant'};
function fixture({denied=false,actorRole='admin',actorSession=true,version='1',auditFail=false,old=null,visible=true}={}){
 const calls=[],audits=[];let persisted;const client={release(){calls.push(['release']);},async query(sql,args){calls.push([sql,args]);
  if(sql.includes(' AS denied'))return{rows:[{denied}]};
  if(sql.includes('FROM secureshop_agents.bound_actor_identities'))return{rows:visible?[{id:args[5],role:args[5]===3?actorRole:'customer',version:args[5]===3?'1':version,banned_at:null,ban_reason:null}]:[]};
  if(sql.startsWith('SELECT session_id'))return{rows:actorSession?[{session_id:input.actorSessionId}]:[]};
  if(sql.includes('FROM secureshop_agents.bound_persona_admin_operations'))return{rows:old?[{scenario_id:scope.scenarioId,generation:'1',owner_id:5,execution_session_id:7,actor_id:3,target_id:1,...old}]:[]};
  if(sql.startsWith('SELECT secureshop_agents.revoke'))return{rows:[{count:1}]};
  if(sql.startsWith('INSERT INTO secureshop_agents.bound_persona_state'))return{rows:[{effective_role:args[6],banned_at:args[7]?'2026-09-19T00:00:00Z':null,version:args[10]}]};
  if(sql.startsWith('UPDATE secureshop_agents.bound_persona_sessions'))return{rowCount:2,rows:[]};
  if(sql.startsWith('INSERT INTO secureshop_agents.bound_persona_admin_operations'))persisted={request_sha256:args[9],result_json:JSON.parse(args[10])};
  return{rows:[]};}};
 return{calls,audits,get persisted(){return persisted;},repo:create({pool:{connect:async()=>client},checkCurrent:async()=>calls.push(['checkCurrent']),auditStore:{append:async(c,event)=>{assert.equal(c,client);audits.push(event);if(auditFail)throw Error('audit unavailable');}}})};
}
test('role effect binds actor/target separately and audits before commit',async()=>{const f=fixture(),r=await f.repo.mutate(input);assert.equal(r.receipt.actorId,3);assert.equal(r.receipt.targetId,1);assert.equal(r.receipt.role,'merchant');assert.equal(r.receipt.version,'2');assert.equal(r.receipt.revokedSessions,2);assert.equal(f.audits[0].persona.id,3);assert.equal(f.audits[0].target,'1');assert.equal(f.calls.at(-2)[0],'COMMIT');});
test('ban persists real state request and preserves effective role',async()=>{const f=fixture();const r=await f.repo.mutate({...input,action:'ban',role:undefined,reason:'owned fixture'});assert.equal(r.receipt.role,'customer');assert.equal(r.receipt.bannedAt,'2026-09-19T00:00:00.000Z');});
for(const [name,options,code] of [['retired',{denied:true},'STALE_AUTHORITY'],['non-admin',{actorRole:'customer'},'ADMIN_REQUIRED'],['revoked-session',{actorSession:false},'ADMIN_REQUIRED'],['stale revision',{version:'2'},'REVISION_CONFLICT']])test(name+' denies before state writes',async()=>{const f=fixture(options);await assert.rejects(f.repo.mutate(input),{code});assert.ok(f.calls.some(x=>x[0]==='ROLLBACK'));assert.ok(!f.calls.some(x=>x[0].startsWith('INSERT INTO')));});
test('audit failure rolls back entire mutation',async()=>{const f=fixture({auditFail:true});await assert.rejects(f.repo.mutate(input),/audit unavailable/);assert.ok(f.calls.some(x=>x[0]==='ROLLBACK'));assert.ok(!f.calls.some(x=>x[0]==='COMMIT'));});
test('exact replay from fresh same-actor session returns original immutable receipt without effects',async()=>{const first=fixture();await first.repo.mutate(input);const f=fixture({old:first.persisted});const r=await f.repo.mutate({...input,actorSessionId:'55555555-5555-4555-8555-555555555555'});assert.equal(r.replayed,true);assert.equal(r.receipt.originalActorSessionId,input.actorSessionId);assert.equal(f.audits.length,0);assert.ok(!f.calls.some(x=>x[0].startsWith('INSERT INTO')));});
test('same operation different request conflicts without effects',async()=>{const first=fixture();await first.repo.mutate(input);const f=fixture({old:first.persisted});await assert.rejects(f.repo.mutate({...input,role:'admin'}),{code:'OPERATION_CONFLICT'});assert.equal(f.audits.length,0);});
test('unsupported password reset and malformed revision never acquire connection',async()=>{const f=fixture();await assert.rejects(f.repo.mutate({...input,action:'reset_password'}),{code:'INVALID_INPUT'});await assert.rejects(f.repo.mutate({...input,expectedVersion:1}),{code:'INVALID_INPUT'});assert.equal(f.calls.length,0);});
test('actor state is owner-scoped and unavailable registered targets are denied',async()=>{
 const f=fixture({visible:false});
 await assert.rejects(f.repo.readEffectivePersona({scope,shopUserId:1000000000}),{code:'PERSONA_UNAVAILABLE'});
 const lookup=f.calls.find(([sql])=>sql.includes('FROM secureshop_agents.bound_actor_identities'));
 assert.match(lookup[0],/bound_actor_in_owner\(a\.shop_user_id,\$4\)/);
 assert.equal(lookup[1][3],scope.platformOwnerId);
});
