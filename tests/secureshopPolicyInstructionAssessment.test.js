'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const {randomUUID}=require('node:crypto');
const {createPolicyInstructionAssessment}=require('../server/services/secureshopPolicyInstructionAssessment');

function dependencies({adminMode='vuln',systemMode='vuln',enabled=true}={}){
 const scope={launchId:randomUUID(),scenarioId:randomUUID(),generation:1,platformOwnerId:4,platformSessionId:5};
 const persona={id:7,role:'admin'},personaSession={sessionId:randomUUID(),authorityVersion:'2'};
 const counters={verify:0,read:0,snapshot:0,publication:0,operation:0,judge:0,claims:0};
 const current=async()=>{};
 const modeAuthority={async capture(_scope,featureId){const mode=featureId==='admin_assistant'?adminMode:systemMode;
  return {snapshot:{version:1,featureId,policyVersion:'controlled',mode,generation:1,
   modeStamp:'a'.repeat(64),scope},assertCurrent:current};},assertToken:token=>token};
 const identityPool={async query(sql){return {rows:sql.includes('SELECT realm')?[{realm:'platform',shop_tenant_id:null}]:
  enabled?[{objective_id:'ss_policy_instruction_followed'}]:[]};}};
 const deps={identityPool,launches:{assertCurrent:current},
  conversationRepository:{getTraceEvents:async()=>{counters.read++;return [];}},
  coordinator:{run:async()=>{throw Error('Unexpected grading run');}},
  journal:{readBoundRequest:async()=>{counters.read++;return null;},claim:async()=>{counters.claims++;},
   complete:async()=>{},markUncertain:async()=>{}},
  roleBindings:{read:async()=>{counters.read++;return null;}},
  policyRepository:{readAssessmentSnapshot:async()=>{counters.snapshot++;return null;},
   readAssessmentPublication:async()=>{counters.publication++;return null;}},
  personaAuthority:{capture:()=>({binding:{...scope,personaId:7,role:'admin',...personaSession},assertRemoteAdmission:current})},
  personaBindings:{capture:async()=>({})},receipts:{beginEvaluation:async()=>{},recordVerdict:async()=>{}},
  progress:{getGeneration:async()=>1},judge:async()=>{counters.judge++;},
  qualifyModel:()=>true,modeAuthority,readRetainedTarget:async()=>{throw Error('Unexpected scene read');},
  systemReads:{operation:async()=>{counters.operation++;return null;}}};
 return {deps,counters,input:{scope,persona,personaSession,sessionId:randomUUID(),requestId:randomUUID(),
  verifyOriginal:async()=>{counters.verify++;return null;}}};
}

test('V24 requires an immutable protected run-snapshot reader at construction',()=>{
 const {deps}=dependencies();delete deps.policyRepository.readAssessmentSnapshot;
 assert.throws(()=>createPolicyInstructionAssessment(deps),{code:'POLICY_INSTRUCTION_EVIDENCE_UNAVAILABLE'});
 const other=dependencies().deps;delete other.readRetainedTarget;
 assert.throws(()=>createPolicyInstructionAssessment(other),{code:'POLICY_INSTRUCTION_EVIDENCE_UNAVAILABLE'});
});

test('V24 disabled objective or fixed admin/System mode cannot read source or invoke Judge',async()=>{
 for(const setting of [{enabled:false},{adminMode:'fixed'},{systemMode:'fixed'}]){
  const {deps,counters,input}=dependencies(setting),service=createPolicyInstructionAssessment(deps);
  const result=await service.runAttempt(input);
  assert.deepEqual(result,{completed:false,status:'ineligible',modelEvaluated:false});
  assert.deepEqual(counters,{verify:0,read:0,snapshot:0,publication:0,operation:0,judge:0,claims:0});
 }
});

test('V24 protected assessment rejects a later/current policy snapshot before any grading claim',async()=>{
 const f=require('./secureshopPolicyInstructionEvidence.test').fixture(),a=f.args;
 const counters={snapshot:0,judge:0,claims:0,configReads:0};
 const current=async()=>{};
 const service=createPolicyInstructionAssessment({
  identityPool:{async query(sql){return {rows:sql.includes('SELECT realm')?[{realm:'platform',shop_tenant_id:null}]:
   [{objective_id:'ss_policy_instruction_followed'}]};}},
  launches:{assertCurrent:current},conversationRepository:{async getBoundSession(id){return {id,state:'active',
   purpose:'secureshop_admin_assistant',binding:a.binding};},
   async getTraceEvents(){return structuredClone(a.traces);}},
  coordinator:{run:async()=>{throw Error('Unexpected grading run');}},
  journal:{async readBoundRequest(){return {status:'completed',request_hash:a.requestHash,request_version:1,
   result_json:structuredClone(a.turn)};},async claim(){counters.claims++;},complete:async()=>{},markUncertain:async()=>{}},
  roleBindings:{read:async()=>structuredClone(a.turnBinding)},
  policyRepository:{async readAssessmentPublication(){return structuredClone(a.publication);},
   async readAssessmentSnapshot(){counters.snapshot++;return {...a.snapshotRecord,
    snapshot:{...a.snapshotRecord.snapshot,policyVersion:'3'}};}},
  personaAuthority:{capture:()=>({binding:{...a.binding,personaId:a.binding.shopUserId,
   sessionId:a.personaSession.sessionId,authorityVersion:a.personaSession.authorityVersion},assertRemoteAdmission:current})},
  personaBindings:{capture:async()=>({})},receipts:{beginEvaluation:async()=>{},recordVerdict:async()=>{}},
  progress:{getGeneration:async()=>1},judge:async()=>{counters.judge++;},
  qualifyModel:a.qualifyModel,modeAuthority:{async capture(_scope,key){return {snapshot:key==='system_config'
   ?a.systemExecution:a.adminExecution,assertCurrent:current};},assertToken:token=>token},
  readRetainedTarget:async()=>a.target,
  systemReads:{async operation(){counters.configReads++;return structuredClone(a.operation);}},
 });
 const result=await service.runAttempt({scope:f.scope,persona:f.persona,personaSession:a.personaSession,
  sessionId:a.sessionId,requestId:a.requestId,verifyOriginal:async()=>({status:'completed',systemConfigRead:f.source})});
 assert.deepEqual(result,{completed:false,status:'ineligible',modelEvaluated:false});
 assert.deepEqual(counters,{snapshot:1,judge:0,claims:0,configReads:1});
});
