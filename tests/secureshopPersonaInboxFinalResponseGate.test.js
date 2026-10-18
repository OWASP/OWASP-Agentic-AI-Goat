'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const {createSecureShopPersonaInboxRequestAuthority}=require('../server/services/secureshopPersonaInboxRequestAuthority');
const {createSecureShopPersonaInboxFinalResponseGate}=require('../server/services/secureshopPersonaInboxFinalResponseGate');
const {requestDigest}=require('../server/database/postgres/secureshopPersonaInboxRepository');

const BINDING=Object.freeze({launchId:'10000000-0000-4000-8000-000000000001',
  scenarioId:'20000000-0000-4000-8000-000000000001',generation:2,platformOwnerId:7,
  platformSessionId:8,shopUserId:12,role:'merchant'});
const TARGET=Object.freeze({...BINDING,targetId:'30000000-0000-4000-8000-000000000001'});
const SESSION='40000000-0000-4000-8000-000000000001';
const REQUEST='50000000-0000-4000-8000-000000000001';
const EVENT='60000000-0000-4000-8000-000000000001';
const EXECUTION=Object.freeze({runId:'70000000-0000-4000-8000-000000000001',ownerKey:'owner:7',
  durableGeneration:9,async check(){}});
const PAYLOAD=Object.freeze({ok:true,event_id:EVENT,message_id:3,owner_persona_id:13,owner_role:'admin',
  subject:'Support',body:null,body_sha256:null,acl:{version:2,mode:'enforced',decision:'deny',
    cross_persona:true,disclosed:false}});
function result(payload=PAYLOAD){return{content:[{type:'text',text:JSON.stringify(payload)}]};}
function source(overrides={}){return{version:1,...TARGET,eventId:EVENT,operationId:EVENT,messageId:3,
  callerShopUserId:12,callerShopRole:'merchant',ownerShopUserId:13,ownerShopRole:'admin',
  subject:'Support',body:null,bodySha256:null,currentBodySha256:'a'.repeat(64),aclVersion:2,
  aclMode:'enforced',aclDecision:'deny',crossPersona:true,disclosed:false,
  requestSha256:requestDigest(TARGET,{id:12,role:'merchant'},3,EVENT).toString('hex'),...overrides};}
function setup(overrides={}){
  const authority=createSecureShopPersonaInboxRequestAuthority();
  const issued=authority.issue({binding:BINDING,sessionId:SESSION,requestId:REQUEST,
    targetId:TARGET.targetId,messageId:3});let reads=0;
  const gate=createSecureShopPersonaInboxFinalResponseGate({requestAuthority:authority,
    resolveTarget:async()=>overrides.target||TARGET,checkCurrent:async value=>{
      if(overrides.stale)throw Object.assign(new Error('stale'),{code:'STALE_LAUNCH'});
      assert.equal(value.targetId,TARGET.targetId);},
    readAccessEvent:async()=>{reads+=1;return overrides.source===undefined?source():overrides.source;}});
  const observation={step:1,callId:'read-1',tool:'persona-inbox.read_message',args:{message_id:3},
    result:result(),effectReceipt:{version:1,status:'completed',runId:EXECUTION.runId,
      ownerKey:EXECUTION.ownerKey,generation:String(EXECUTION.durableGeneration),
      effectKey:`${REQUEST}:${JSON.stringify([1,'read-1','persona-inbox.read_message'])}`}};
  return{authority,issued,gate,observation,get reads(){return reads;}};
}

test('final-response gate rereads the exact authoritative requested event after its committed effect',async()=>{
  const f=setup();assert.equal(await f.gate({execution:EXECUTION,binding:BINDING,sessionId:SESSION,
    requestId:REQUEST,localToolAuthority:f.issued.token,observation:f.observation}),true);
  assert.equal(f.reads,1);
});

test('wrong message, missing receipt and mismatched authoritative event never enter final response',async()=>{
  const wrong=setup();assert.equal(await wrong.gate({execution:EXECUTION,binding:BINDING,sessionId:SESSION,
    requestId:REQUEST,localToolAuthority:wrong.issued.token,
    observation:{...wrong.observation,args:{message_id:2}}}),false);assert.equal(wrong.reads,0);
  const missing=setup();assert.equal(await missing.gate({execution:EXECUTION,binding:BINDING,sessionId:SESSION,
    requestId:REQUEST,localToolAuthority:missing.issued.token,
    observation:{...missing.observation,effectReceipt:null}}),false);assert.equal(missing.reads,0);
  const mismatch=setup({source:source({messageId:2})});assert.equal(await mismatch.gate({execution:EXECUTION,
    binding:BINDING,sessionId:SESSION,requestId:REQUEST,localToolAuthority:mismatch.issued.token,
    observation:mismatch.observation}),false);assert.equal(mismatch.reads,1);
});

test('revoked request authority and reset during authoritative reread fail closed',async()=>{
  const revoked=setup();revoked.issued.revoke();
  await assert.rejects(revoked.gate({execution:EXECUTION,binding:BINDING,sessionId:SESSION,
    requestId:REQUEST,localToolAuthority:revoked.issued.token,observation:revoked.observation}),
  {code:'PERSONA_INBOX_REQUEST_AUTHORITY_UNAVAILABLE'});
  const stale=setup({stale:true});
  await assert.rejects(stale.gate({execution:EXECUTION,binding:BINDING,sessionId:SESSION,
    requestId:REQUEST,localToolAuthority:stale.issued.token,observation:stale.observation}),{code:'STALE_LAUNCH'});
});
