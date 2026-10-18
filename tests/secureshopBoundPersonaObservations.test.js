'use strict';
const test = require('node:test'), assert = require('node:assert/strict');
const { createBoundPersonaObservations } = require('../server/services/secureshopBoundPersonaObservations');
const { createBoundConversationsRepository } = require('../server/database/postgres/secureshopBoundConversationsRepository');
const scope = {launchId:'10000000-0000-4000-8000-000000000001',scenarioId:'20000000-0000-4000-8000-000000000001',
  generation:1,platformOwnerId:7,platformSessionId:8};
const session = {sessionId:'30000000-0000-4000-8000-000000000001',authorityVersion:'2'};
test('persona observation SQL retains every owner coordinate and includes actual feature purposes', async()=>{
  let call;
  const repository=createBoundConversationsRepository({pool:{async query(sql,args){call={sql,args};return {rows:[]};}},queue:async(_id,op)=>op()});
  await repository.personaLatestTrace({...scope,shopUserId:12,role:'merchant'},10);
  assert.deepEqual(call.args,[scope.launchId,scope.scenarioId,1,7,8,12,'merchant',10]);
  for(const [i,name] of ['platform_launch_id','platform_scenario_id','platform_launch_generation','original_platform_owner_id',
    'original_platform_session_id','user_id','role'].entries()) assert.ok(call.sql.includes(`s.${name}=$${i+1}`));
  assert.doesNotMatch(call.sql,/params_json|result_json|conversation_purpose=/);
  assert.match(call.sql,/binding_state='active'/);
  await assert.rejects(repository.personaLatestTrace({...scope,shopUserId:12,role:'admin'},10));
});
test('observation service captures authority and removes private payloads',async()=>{
  const input={scope:{...scope},persona:{id:12,role:'merchant'},personaSession:{...session},limit:10};
  let observed;
  const service=createBoundPersonaObservations({launches:{async assertCurrent(){}},personaAuthority:{async capture(value){
    input.persona.id=99;input.personaSession.authorityVersion='9';
    return {binding:{...value.scope,personaId:value.personaId,role:value.role,sessionId:value.sessionId,authorityVersion:value.authorityVersion},async assertRemoteAdmission(){}};
  }},conversations:{async personaLatestTrace(binding){observed=binding;return [{id:1,kind:'tool_result',provider:'ollama',params_json:'secret',result_json:'secret'}];}}});
  assert.deepEqual(await service.latestTrace(input),[{id:1,kind:'tool_result',provider:'ollama'}]);
  assert.equal(observed.shopUserId,12);
});
test('observation read never publishes results after session revocation',async()=>{
  let revoked=false, reads=0;
  const service=createBoundPersonaObservations({launches:{async assertCurrent(){}},personaAuthority:{async capture(value){
    return {binding:{...value.scope,personaId:value.personaId,role:value.role,sessionId:value.sessionId,authorityVersion:value.authorityVersion},
      async assertRemoteAdmission(){if(revoked)throw Object.assign(Error('revoked'),{code:'SHOP_AUTH_INVALID'});}};
  }},conversations:{async personaLatestTrace(){reads++;revoked=true;return []}}});
  const input={scope,persona:{id:12,role:'merchant'},personaSession:session};
  await assert.rejects(service.latestTrace(input),{code:'SHOP_AUTH_INVALID'});
  await assert.rejects(service.latestTrace(input),{code:'SHOP_AUTH_INVALID'});
  assert.equal(reads,1);
});
