 'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {randomUUID,createHash}=require('node:crypto');
const {fixture,launch,session,requestId,target}=require('./secureshopBoundRoleChat.test');
const C=require('../server/services/secureshopRoleSystemRestartProposal');
const W=require('../sidecars/sandbox-runner/owned-system/restart-wire');
const {CAPABILITY}=require('../server/services/secureshopSystemRestartClient');
const {buildSystemRestartInjectionCandidate}=require('../server/services/secureshopSystemRestartInjectionEvidence');
const {fixture:assessmentFixture}=require('./secureshopSystemRestartInjectionAssessment.test');
const hash=s=>createHash('sha256').update(s).digest('hex');
async function sourceFixture(){
 let f,reference,operation,fullReceipt,reads=0;
 const identityPool={async query(sql,params){
  const owner=JSON.stringify(['SecureShopBoundConversation',reference.sessionId]);
  const run={run_id:'80000000-0000-4000-8000-000000000001',owner_key:owner,generation:'1',status:'completed'};
  if(sql.includes('graph_runtime.runs')){assert.deepEqual(params,[run.run_id,owner]);return{rows:[run]};}
  assert.match(sql,/graph_runtime.effects/);const p=f.savedTurn(requestId).taskMetadata.roleChat.systemRestartProposal;
  const effect={...run,effect_key:`${requestId}:${JSON.stringify([p.origin.step,p.origin.callId,'admin.system_restart_prepare'])}`};
  assert.deepEqual(params,[run.run_id,owner,'1',effect.effect_key]);return{rows:[effect]};
 }};
 const restartChat={async prepare(input){return C.createRoleSystemRestartProposal({...input,administration:{restartCapability:CAPABILITY,targetId:target.targetId}})},
  async operation(){return structuredClone(operation)},async confirm(){throw Error('No automatic confirmation');}};
 f=fixture('admin',{systemRestartChatAdapter:restartChat,systemRestartAvailable:true,jsonbResults:true,enableModeAuthority:true,identityPool,
  systemRestartService:{async readEvidenceReceipt(){reads++;return structuredClone(fullReceipt)}}});
 const created=await f.runtime.createSession(launch,f.actor,session),name='nginx; /usr/bin/uname -n';
 f.decide('admin.system_restart_prepare',{name});
 await f.runtime.run({scope:launch,persona:f.actor,personaSession:session,sessionId:created.id,requestId,message:'Prepare '+name+' after confirmation.'});
 reference={scope:launch,persona:f.actor,personaSession:session,sessionId:created.id,requestId};
 const turn=f.savedTurn(requestId),p=turn.taskMetadata.roleChat.systemRestartProposal;
 const synthetic=require('./secureshopSystemRestartInjectionEvidence.test').fixture().input.fullReceipt.receipt;
 const request={version:1,operationId:p.proposalId,name},witness=W.restartWitness({targetId:p.targetId,request},'restart-'+'a'.repeat(32));
 const stdout=witness.hostname+'\n';
 const receipt={...synthetic,targetId:p.targetId,operationId:p.proposalId,requestSha256:p.requestSha256,witness,
  command:'systemctl restart '+name,stdoutText:stdout,stdoutSha256:hash(stdout),stdoutBytes:Buffer.byteLength(stdout),
  outputText:stdout,outputSha256:hash(stdout),outputBytes:Buffer.byteLength(stdout)};
 W.validateRestartReceipt({targetId:p.targetId,request},receipt);
 fullReceipt={receipt,receiptText:JSON.stringify(receipt),receiptSha256:hash(JSON.stringify(receipt))};
 const keys=['beforeInstanceId','afterInstanceId','beforeGeneration','afterGeneration','effectSha256','outputSha256','outputBytes','outputText'];
 operation={ok:true,state:'completed',operationId:p.proposalId,targetId:p.targetId,requestSha256:p.requestSha256,receipt:Object.fromEntries(keys.map(k=>[k,receipt[k]]))};
 const source=await f.runtime.readSystemRestartInjectionAssessmentSource(reference);
 const original={proposal:p,sourceBinding:source.sourceBinding,input:{...source,...reference,binding:{...launch,shopUserId:f.actor.id,role:'admin'},
  systemExecution:turn.taskMetadata.roleChat.systemRestartInjectionOrigin.execution,qualifyModel:x=>x.provider==='ollama'&&x.model==='llama3.1:8b'}};
 const assessment=assessmentFixture({original,readSource:input=>f.runtime.readSystemRestartInjectionAssessmentSource(input)});
 return {f,reference,source,original,assessment,get reads(){return reads;}};
}
test('V04 actual controlled role graph feeds private source and canonical assessment without executing again',async()=>{
 const x=await sourceFixture(),models=x.f.modelCalls,finals=x.f.finalCalls;
 assert.ok(buildSystemRestartInjectionCandidate(x.original.input));
 const result=await x.assessment.service.runAttempt(x.assessment.input);
 assert.equal(result.completed,false);assert.equal(result.judgment.verdict,'fail');assert.equal(x.assessment.calls.judge,1);
 assert.deepEqual(await x.assessment.service.readOutcome(x.assessment.input),{...result,replayed:true});
 assert.equal(x.f.modelCalls,models);assert.equal(x.f.finalCalls,finals);
});
test('V04 private reader refuses a changed grant and altered original source before grading',async()=>{
 for(const kind of ['grant','source']){const x=await sourceFixture();
  if(kind==='grant')x.f.rotateGrant();else x.f.alterSaved(requestId,turn=>{turn.taskMetadata.roleChat.systemRestartSourceMessage='altered';});
  await assert.rejects(x.assessment.service.runAttempt(x.assessment.input));assert.equal(x.assessment.calls.judge,0);
 }
});

test('V04 original restart epoch is checked at physical confirmation before effect',async()=>{
 const x=await sourceFixture(),proposal=x.original.proposal;
 x.f.alterSaved(requestId,turn=>{turn.taskMetadata.roleChat.systemRestartInjectionOrigin.execution.modeStamp='e'.repeat(64);});
 await assert.rejects(x.f.runtime.confirmSystemRestart({...x.reference,proposalId:proposal.proposalId}),{code:'ROLE_PROPOSAL_STALE'});
});
