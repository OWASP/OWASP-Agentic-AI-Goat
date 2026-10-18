'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const {randomUUID}=require('node:crypto');
const {createV01AuditAssessment}=require('../server/services/secureshopV01AuditAssessment');

function fixture(){
  const scope={launchId:randomUUID(),scenarioId:randomUUID(),generation:2,
    platformOwnerId:19,platformSessionId:23};
  const persona={id:41,role:'customer'},personaSession={sessionId:randomUUID(),authorityVersion:'2'};
  const sessionId=randomUUID(),requestId=randomUUID(),binding={...scope,shopUserId:41,role:'customer'};
  const scene={...scope,targetId:randomUUID(),scene:{sceneId:randomUUID(),sceneGeneration:1,
    grantId:randomUUID()}};
  let mode='fixed',reads=0,modelCalls=0,judgeCalls=0;
  const service=createV01AuditAssessment({
    identityPool:{async query(){throw Error('fixed mode must not query assessment');}},
    agentsPool:{async query(){throw Error('fixed mode must not query assessment turns');}},
    launches:{async assertCurrent(value){assert.equal(value.launchId,scope.launchId);}},
    conversationRepository:{async getBoundSession(id){return {id,state:'active',purpose:'secureshop_checkout_audit_jwt',binding};},
      async acquireBoundSession(){throw Error('fixed mode cannot create assessment session');},
      async getTraceEvents(){throw Error('fixed mode cannot read traces');}},
    coordinator:{async run(){throw Error('fixed mode cannot run coordinator');}},
    journal:{async readV01AuditRequest(){reads++;throw Error('fixed mode cannot read original');},
      async claim(){throw Error('fixed mode cannot claim turn');},async complete(){},async markUncertain(){}},
    personaAuthority:{capture({scope:s,personaId,role,sessionId:id,authorityVersion}){return {
      binding:{...s,personaId,role,sessionId:id,authorityVersion},async assertRemoteAdmission(){}};}},
    personaBindings:{async capture(){throw Error('fixed mode cannot capture assessment persona');}},
    scenes:{async readExisting(){return scene;}},
    modeAuthority:{async capture(){const captured=mode;return {
      snapshot:{featureId:'checkout_audit_jwt',mode:captured},
      async assertCurrent(){assert.equal(mode,captured);}};},assertToken(value){return value;}},
    lesson:{async bindObservedEffect(){reads++;throw Error('fixed mode cannot read audit');}},
    receipts:{async beginEvaluation(){throw Error('fixed mode cannot begin evaluation');},async recordVerdict(){}},
    progress:{async getGeneration(){throw Error('fixed mode cannot read progress');}},
    publicationModes:{async getEvaluationScope(){return {mode,generation:2,modeStamp:'test'};}},
    async judge(){judgeCalls++;throw Error('fixed mode cannot call Judge');},
    qualifyModel(){modelCalls++;return true;},
  });
  return {service,scope,persona,personaSession,sessionId,requestId,
    counts:()=>({reads,modelCalls,judgeCalls}),setMode:value=>{mode=value;}};
}
test('fixed V01 assessment denies before original protected read or Judge',async()=>{
  const f=fixture();
  const input={scope:f.scope,persona:f.persona,personaSession:f.personaSession,
    sessionId:f.sessionId,requestId:f.requestId};
  assert.deepEqual(await f.service.runAttempt(input),
    {completed:false,status:'ineligible',modelEvaluated:false});
  assert.deepEqual(await f.service.readOutcome(input),
    {completed:false,status:'ineligible',modelEvaluated:false});
  assert.deepEqual(f.counts(),{reads:0,modelCalls:0,judgeCalls:0});
});
test('sibling owner cannot inspect original V01 turn or invoke Judge',async()=>{
  const f=fixture();
  await assert.rejects(f.service.runAttempt({scope:{...f.scope,platformOwnerId:20},
    persona:f.persona,personaSession:f.personaSession,
    sessionId:f.sessionId,requestId:f.requestId}));
  assert.deepEqual(f.counts(),{reads:0,modelCalls:0,judgeCalls:0});
});
