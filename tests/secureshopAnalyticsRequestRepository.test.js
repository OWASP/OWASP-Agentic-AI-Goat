'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),{randomUUID}=require('node:crypto');
const {createAnalyticsRequestRepository}=require('../server/database/postgres/secureshopAnalyticsRequestRepository');
function fixture(){
 const scope={launchId:randomUUID(),scenarioId:randomUUID(),generation:1,platformOwnerId:1,platformSessionId:2},persona={id:3,role:'merchant'},personaSession={sessionId:randomUUID(),authorityVersion:'1'};
 const input={scope,persona,personaSession,requestId:randomUUID(),sessionId:randomUUID(),question:'count products'};let stored,turn=null,writes=0;
 const client={query:async(sql,args)=>{
  assert.ok(!/FOR UPDATE/i.test(sql),'immutable runtime must not require UPDATE grants for a read');
  if(sql.startsWith('SELECT count'))return {rows:[{count:stored?1:0}]};
  if(sql.startsWith('INSERT')){writes++;stored={session_id:args[10],persona_session_id:args[8],authority_version:args[9],question_sha256:args[11],question:args[12]};return {rowCount:1};}
  return {rows:stored?[{...stored,...turn}]:[]};
 }};
 const personaAuthority={capture:async value=>({binding:{...value.scope,personaId:value.personaId,role:value.role,sessionId:value.sessionId,authorityVersion:value.authorityVersion},assertRemoteAdmission:async()=>{},withPersonaEffect:async work=>work(client)})};
 return {repository:createAnalyticsRequestRepository({personaAuthority}),input,writes:()=>writes,complete(){const {createTurnRequest}=require('../server/services/secureshopTurnRequest');const r=createTurnRequest({sessionId:input.sessionId,requestId:input.requestId,binding:{...scope,shopUserId:persona.id,role:persona.role},message:input.question});turn={turn_status:'completed',request_hash:r.hash,request_version:r.version,result_json:{taskMetadata:{analytics:{proof:'canonical journal'}}}};}};
}
test('admission binds exact original credential without copying a terminal result',async()=>{
 const f=fixture();assert.equal((await f.repository.admit(f.input)).created,true);assert.equal((await f.repository.admit(f.input)).created,false);assert.equal(f.writes(),1);
 await assert.rejects(f.repository.admit({...f.input,personaSession:{...f.input.personaSession,sessionId:randomUUID()}}),{code:'SHOP_AUTH_INVALID'});
 await assert.rejects(f.repository.admit({...f.input,question:'changed'}),{code:'ANALYTICS_REQUEST_CONFLICT'});assert.equal(f.writes(),1);
});
test('readback projects canonical journal only, with no admission write and no replacement-session access',async()=>{
 const f=fixture();assert.equal(await f.repository.read(f.input),null);assert.equal(f.writes(),0);await f.repository.admit(f.input);
 assert.equal((await f.repository.read(f.input)).status,'admitted');f.complete();assert.equal((await f.repository.read(f.input)).result.taskMetadata.analytics.proof,'canonical journal');assert.equal(f.writes(),1);
 await assert.rejects(f.repository.read({...f.input,personaSession:{...f.input.personaSession,sessionId:randomUUID()}}),{code:'SHOP_AUTH_INVALID'});assert.equal(f.writes(),1);
});
