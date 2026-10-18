'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {createHash}=require('node:crypto');
const {createRegisteredUserAdministrationRepository}=require('../server/database/postgres/secureshopRegisteredUserAdministrationRepository');
const {createSecureShopBoundUserAdministrationRepository}=require('../server/database/postgres/secureshopBoundUserAdministrationRepository');
const scope={launchId:'11111111-1111-4111-8111-111111111111',scenarioId:'22222222-2222-4222-8222-222222222222',generation:1,platformOwnerId:7,platformSessionId:8};
const base={scope,actorId:11,actorSessionId:'33333333-3333-4333-8333-333333333333',actorAuthorityVersion:'1',operationId:'44444444-4444-4444-8444-444444444444',expectedVersion:'1',action:'set_role',role:'merchant'};
const registered={...base,targetId:12},teaching={...base,targetId:1};
const digest=input=>createHash('sha256').update(JSON.stringify([input.actorId,input.targetId,input.action,input.role??null,input.reason??null,input.expectedVersion])).digest();
function historical(input){return{
 scenario_id:scope.scenarioId,generation:'1',owner_id:7,execution_session_id:8,actor_id:input.actorId,target_id:input.targetId,request_sha256:digest(input),
 result_json:{operationId:input.operationId,actorId:input.actorId,originalActorSessionId:input.actorSessionId,targetId:input.targetId,action:input.action,role:input.role,bannedAt:null,version:'2',revokedSessions:1,revokedApiKeys:0}
};}
function deferred(){let resolve;const promise=new Promise(r=>{resolve=r;});return{promise,resolve};}

// Models separate stores and PostgreSQL's unique-index conflict wait. The
// agents coordinator deliberately does NOT serialize competing requests: this
// exercises the case where that connection disappeared during identity work.
function system({registeredHistory=null,teachingHistory=null,identityPause=null,agentsFailure=false,identityCommitAckLost=false}={}){
 const state={claim:null,registered:registeredHistory,teaching:teachingHistory,registeredEffects:0,teachingEffects:0,agentsLeases:0,identityLeases:0,identityQueries:[],agentsQueries:[]};
 let uniqueOwner=null,uniqueReleased=deferred(),agentsBroken=agentsFailure,commitAckLost=identityCommitAckLost;
 const identityPool={
  async query(sql,args){const c=await this.connect();try{return await c.query(sql,args);}finally{c.release();}},
  async connect(){state.identityLeases++;const token={};let claim=null,journal=null,writes=0;
   return{release(){state.identityLeases--;},async query(sql,args){
    state.identityQueries.push(sql);
    if(sql==='COMMIT'||sql==='ROLLBACK'){
     if(sql==='COMMIT'){if(claim)state.claim=claim;if(journal)state.registered=journal;state.registeredEffects+=writes;}
     if(uniqueOwner===token){uniqueOwner=null;uniqueReleased.resolve();uniqueReleased=deferred();}
     claim=null;journal=null;writes=0;
     if(sql==='COMMIT'&&commitAckLost&&state.claim){commitAckLost=false;throw Error('commit response lost');}
     return{rows:[]};
    }
    if(sql.includes('SELECT p.principal_id,m.role'))return{rows:args[1]===12?[{principal_id:'registered',version:'1'}]:[]};
    if(sql.includes('SELECT e.tenant_id'))return{rows:[{tenant_id:'tenant',principal_id:'admin'}]};
    if(sql.includes('FROM secureshop_auth.tenant_admin_operations'))return{rows:state.registered?[state.registered]:[]};
    if(sql.startsWith('INSERT INTO secureshop_auth.admin_operation_kinds')){
     while(uniqueOwner&&uniqueOwner!==token)await uniqueReleased.promise;
     if(!state.claim){
      uniqueOwner=token;claim={scenario_id:args[3],generation:String(args[1]),owner_id:args[4],execution_session_id:args[5],operation_kind:args[6],actor_id:args[7],target_id:args[8],request_sha256:args[9]};
      if(identityPause&&args[6]==='registered'){identityPause.entered.resolve();await identityPause.release.promise;}
     }
     return{rows:[]};
    }
    if(sql.includes('FROM secureshop_auth.admin_operation_kinds'))return{rows:claim||state.claim?[claim||state.claim]:[]};
    if(sql.includes('SELECT m.*,m.membership_version'))return{rows:[{version:'1',membership_version:1,role:'customer',is_active:true,principal_id:'target'}]};
    if(sql.includes('count(*)::integer'))return{rows:[{count:1}]};
    if(sql.startsWith('UPDATE secureshop_auth.tenant_memberships')){writes++;return{rows:[{role:args[2],banned_at:null,version:'2'}]};}
    if(sql.startsWith('INSERT INTO secureshop_auth.tenant_admin_operations'))journal={...historical(registered),actor_id:args[7],target_id:args[9],request_sha256:args[10],result_json:JSON.parse(args[11])};
    return{rows:[],rowCount:1};
   }};
  }
 };
 const personaAuthority={capture(value){return{binding:{...scope,personaId:value.personaId,sessionId:value.sessionId,role:value.role,authorityVersion:value.authorityVersion},
  async assertRemoteAdmission(){},async withCrossStoreEffect(work){try{return await work();}catch{throw Object.assign(Error('uncertain'),{code:'PERSONA_EFFECT_OUTCOME_UNCERTAIN'});}}
 };}};
 const canonical=createRegisteredUserAdministrationRepository({pool:identityPool,checkCurrent:async()=>{},personaAuthority});
 const agentsPool={async connect(){state.agentsLeases++;let journal=null,writes=0;
  return{release(){state.agentsLeases--;},async query(sql,args){
   state.agentsQueries.push(sql);
   if(sql==='COMMIT'){if(journal)state.teaching=journal;state.teachingEffects+=writes;journal=null;writes=0;}
   if(sql==='ROLLBACK'){journal=null;writes=0;}
   if(sql.includes(' AS denied'))return{rows:[{denied:false}]};
   if(sql.includes('FROM secureshop_agents.bound_actor_identities'))return{rows:[{id:args[5],role:args[5]===11?'admin':'customer',version:'1',banned_at:null,ban_reason:null}]};
   if(sql.startsWith('SELECT session_id'))return{rows:[{session_id:base.actorSessionId}]};
   if(sql.includes('FROM secureshop_agents.bound_persona_admin_operations'))return{rows:state.teaching?[state.teaching]:[]};
   if(sql.startsWith('SELECT secureshop_agents.revoke'))return{rows:[{count:0}]};
   if(sql.startsWith('INSERT INTO secureshop_agents.bound_persona_state')){
    assert.equal(state.claim?.operation_kind,'teaching','durable reservation precedes teaching mutation');
    if(agentsBroken){agentsBroken=false;throw Error('agents transaction failed');}
    writes++;return{rows:[{effective_role:args[6],banned_at:null,version:args[10]}]};
   }
   if(sql.startsWith('UPDATE secureshop_agents.bound_persona_sessions'))return{rows:[],rowCount:1};
   if(sql.startsWith('INSERT INTO secureshop_agents.bound_persona_admin_operations'))journal={...historical(teaching),request_sha256:args[9],result_json:JSON.parse(args[10])};
   return{rows:[],rowCount:1};
  }};
 }};
 const repo=createSecureShopBoundUserAdministrationRepository({pool:agentsPool,auditStore:{async append(){}},checkCurrent:async()=>{},registeredRepository:canonical});
 return{repo,state,canonical};
}
for(const [name,first,second] of [['registered then teaching',registered,teaching],['teaching then registered',teaching,registered]])test(name+' rejects reused UUID before the second effect',async()=>{
 const f=system();const receipt=await f.repo.mutate(first);await assert.rejects(f.repo.mutate(second),{code:'OPERATION_CONFLICT'});
 assert.equal(f.state.registeredEffects+f.state.teachingEffects,1);
 assert.deepEqual(await f.repo.readOperation(base),receipt.receipt);
 assert.equal(f.state.agentsLeases,0);assert.equal(f.state.identityLeases,0);
});
test('unique claim waits for identity commit even without a surviving agents coordinator lock',async()=>{
 const pause={entered:deferred(),release:deferred()},f=system({identityPause:pause});
 const first=f.repo.mutate(registered);await pause.entered.promise;
 let secondSettled=false;const second=f.repo.mutate(teaching).finally(()=>{secondSettled=true;});
 // Allow the second path to reach its competing unique-index insertion.
 await new Promise(resolve=>setImmediate(resolve));assert.equal(secondSettled,false);assert.equal(f.state.teachingEffects,0);
 assert.equal(f.state.identityQueries.filter(sql=>sql.startsWith('INSERT INTO secureshop_auth.admin_operation_kinds')).length,2);
 pause.release.resolve();await first;await assert.rejects(second,{code:'OPERATION_CONFLICT'});
 assert.equal(f.state.registeredEffects,1);assert.equal(f.state.teachingEffects,0);
});
test('lost registered commit response retains its kind and blocks a teaching effect',async()=>{
 const f=system({identityCommitAckLost:true});await assert.rejects(f.repo.mutate(registered),{code:'PERSONA_EFFECT_OUTCOME_UNCERTAIN'});
 await assert.rejects(f.repo.mutate(teaching),{code:'OPERATION_CONFLICT'});
 assert.equal(f.state.registeredEffects,1);assert.equal((await f.repo.mutate(registered)).replayed,true);
});
test('agents rollback retains exact teaching reservation; only that intent can retry',async()=>{
 const f=system({agentsFailure:true});await assert.rejects(f.repo.mutate(teaching),/agents transaction failed/);
 assert.equal(f.state.claim.operation_kind,'teaching');assert.equal(f.state.teaching,null);
 assert.equal(await f.repo.readOperation(base),null,'reservation alone is not a saved effect');
 await assert.rejects(f.repo.mutate(registered),{code:'OPERATION_CONFLICT'});
 await assert.rejects(f.repo.mutate({...teaching,role:'admin'}),{code:'OPERATION_CONFLICT'});
 assert.equal(f.state.teachingEffects,0);assert.equal((await f.repo.mutate(teaching)).replayed,false);assert.equal(f.state.teachingEffects,1);
});
test('lost teaching reservation ACK cannot admit a registered effect or assert teaching completion',async()=>{
 const f=system({identityCommitAckLost:true});await assert.rejects(f.repo.mutate(teaching),/commit response lost/);
 assert.equal(f.state.claim.operation_kind,'teaching');assert.equal(f.state.teachingEffects,0);
 assert.equal(await f.repo.readOperation(base),null);
 await assert.rejects(f.repo.mutate(registered),{code:'OPERATION_CONFLICT'});
 assert.equal((await f.repo.mutate(teaching)).replayed,false);assert.equal(f.state.teachingEffects,1);
});
for(const [kind,input] of [['registered',registered],['teaching',teaching]])test('legacy '+kind+' exact replay adopts its original immutable receipt',async()=>{
 const old=historical(input),f=system({[kind+'History']:old});
 assert.deepEqual(await f.repo.readOperation(base),old.result_json);assert.equal(f.state.claim,null,'GET does not create a reservation');
 const result=await f.repo.mutate(input);assert.equal(result.replayed,true);assert.deepEqual(result.receipt,old.result_json);
 assert.equal(f.state.claim.operation_kind,kind);assert.equal(f.state.registeredEffects+f.state.teachingEffects,0);
});
test('both legacy journals with one UUID deny read and mutation without adopting either',async()=>{
 const oldRegistered=historical(registered),oldTeaching=historical(teaching),f=system({registeredHistory:oldRegistered,teachingHistory:oldTeaching});
 await assert.rejects(f.repo.readOperation(base),{code:'OPERATION_CONFLICT'});
 await assert.rejects(f.repo.mutate(registered),{code:'OPERATION_CONFLICT'});
 await assert.rejects(f.repo.mutate(teaching),{code:'OPERATION_CONFLICT'});
 assert.equal(f.state.claim,null);assert.deepEqual(f.state.registered,oldRegistered);assert.deepEqual(f.state.teaching,oldTeaching);
 assert.equal(f.state.registeredEffects+f.state.teachingEffects,0);
});
test('claim scope or digest mismatch fails closed during receipt recovery',async()=>{
 const f=system();await f.repo.mutate(registered);f.state.claim={...f.state.claim,owner_id:8};
 await assert.rejects(f.repo.readOperation(base),{code:'OPERATION_CONFLICT'});
 f.state.claim={...f.state.claim,owner_id:7,request_sha256:Buffer.alloc(32)};
 await assert.rejects(f.repo.readOperation(base),{code:'OPERATION_CONFLICT'});
});
test('historical teaching scope mismatch denies registered mutation before identity effect',async()=>{
 const f=system({teachingHistory:{...historical(teaching),execution_session_id:9}});
 await assert.rejects(f.repo.mutate(registered),{code:'OPERATION_CONFLICT'});
 assert.equal(f.state.claim,null);assert.equal(f.state.registeredEffects,0);
});
test('unavailable historical peer read never reaches the canonical mutation',async()=>{
 const f=system();await assert.rejects(f.canonical.mutate(registered,async()=>{throw Error('history unavailable');}),/history unavailable/);
 assert.equal(f.state.claim,null);assert.equal(f.state.registeredEffects,0);
});
test('registered history lookup releases its agents lease before cross-store execution',async()=>{
 const f=system();const original=f.canonical.mutate;
 // One lease for the preliminary history snapshot is released before the
 // separate persona fence. It never needs a nested agents pool connection.
 await original(registered,async()=>{assert.equal(f.state.agentsLeases,0);return null;});
 assert.equal(f.state.agentsLeases,0);assert.equal(f.state.identityLeases,0);
});
