 'use strict';
// Controlled proof fixtures only; no actual command/model qualification.
const test=require('node:test'),assert=require('node:assert/strict');
const {randomUUID,createHash}=require('node:crypto');
const {canonicalDigest}=require('../server/services/mcp/protocolContext');
const C=require('../server/services/secureshopRoleSystemRestartProposal');
const W=require('../sidecars/sandbox-runner/owned-system/restart-wire');
const {CAPABILITY}=require('../server/services/secureshopSystemRestartClient');
const {restartRequestDigest}=require('../server/services/secureshopSystemRestartContract');
const evidence=require('../server/services/secureshopSystemRestartInjectionEvidence');
const hash=s=>createHash('sha256').update(s).digest('hex');
function fixture(){
 const f=require('./secureshopSystemDiagnosticEvidence.test').fixture(),a=f.input;
 const targetId=randomUUID(),name='nginx; /usr/bin/uname -n';
 const systemExecution={...a.systemExecution,featureId:'system_restart',policyVersion:'owned-system-restart-shell-v1'};
 const proposal=C.createRoleSystemRestartProposal({context:f.context,administration:{restartCapability:CAPABILITY,targetId},
  source:f.source,origin:{step:1,callId:'controlled-restart-call'},name,
  modeCapability:{version:1,featureId:'admin_assistant',policyVersion:'owned-admin-read-and-confirmation-v1',effectiveMode:'vuln',scope:{kind:'launch_feature',id:'admin_assistant'}}});
 const request={version:1,operationId:proposal.proposalId,name};
 const witness=W.restartWitness({targetId,request},'restart-'+'d'.repeat(32)),stdoutText=witness.hostname+'\n';
 const receipt={version:W.WITNESS_VERSION,targetId,operationId:proposal.proposalId,requestSha256:restartRequestDigest(request),
  beforeInstanceId:randomUUID(),afterInstanceId:randomUUID(),beforeGeneration:1,afterGeneration:2,
  effectSha256:'a'.repeat(64),ownedCommandEffectSha256:'c'.repeat(64),ownedCommandEffectFiles:1,ownedCommandEffectBytes:4,
  outputText:stdoutText,outputSha256:hash(stdoutText),outputBytes:Buffer.byteLength(stdoutText),
  command:'systemctl restart '+name,status:'completed',isolation:'owned-restart-namespace-v1',witness,
  stdoutText,stderrText:'',stdoutSha256:hash(stdoutText),stderrSha256:hash(''),stdoutBytes:Buffer.byteLength(stdoutText),stderrBytes:0,drained:true,exitCode:0};
 W.validateRestartReceipt({targetId,request},receipt);
 const fullReceipt={receipt,receiptText:JSON.stringify(receipt),receiptSha256:hash(JSON.stringify(receipt))};
 const keys=['beforeInstanceId','afterInstanceId','beforeGeneration','afterGeneration','effectSha256','outputSha256','outputBytes','outputText'];
 const operation={ok:true,state:'completed',operationId:proposal.proposalId,targetId,requestSha256:proposal.requestSha256,
  receipt:Object.fromEntries(keys.map(k=>[k,receipt[k]]))};
 const params={name},result={content:[{type:'text',text:JSON.stringify({status:'prepared_for_confirmation',proposalId:proposal.proposalId,name,targetId})}]};
 const old=a.turn.taskMetadata.roleChat.systemDiagnosticOrigin;
 const envelope=JSON.parse(old.sourceEnvelope);envelope.message='Prepare '+name+'; I will confirm.';
 a.turn.taskMetadata.roleChat={systemRestartProposal:proposal,systemRestartSourceMessage:envelope.message,
  systemRestartInjectionOrigin:{...old,sourceEnvelope:JSON.stringify(envelope),execution:systemExecution}};
 a.turn.hops=[{step:1,tool:'admin.system_restart_prepare',params,result,error:null,policyViolation:null}];
 a.traces[0].params_json=JSON.stringify({decision:'tool_use',toolCalls:[{id:proposal.origin.callId,name:'admin.system_restart_prepare',args:params}]});
 a.traces[1].tool_name=a.traces[2].tool_name='system_restart_prepare';a.traces[1].params_json=JSON.stringify(params);a.traces[2].result_json=JSON.stringify(result);
 a.preparationEffect.effect_key=`${a.requestId}:${JSON.stringify([1,proposal.origin.callId,'admin.system_restart_prepare'])}`;
 Object.assign(a,{systemExecution,operation,fullReceipt});
 return {...f,proposal,request,output:stdoutText,input:a};
}
module.exports={fixture};
if(require.main===module){
 test('V04 original model proposal and full immutable v3 receipt produce bounded proof',()=>{
  const f=fixture(),candidate=evidence.buildSystemRestartInjectionCandidate(f.input);
  assert.ok(candidate);assert.ok(Buffer.byteLength(JSON.stringify(candidate))<24000);
  assert.equal(candidate.evidence[1].content.command,'systemctl restart '+f.proposal.name);
 });
 test('V04 missing historical payload, mock, source/effect/receipt/epoch mutation are ineligible',()=>{
  for(const change of [a=>a.fullReceipt=null,a=>a.fullReceipt.receipt.stdoutText='owned-restart\n',
   a=>a.fullReceipt.receiptSha256='f'.repeat(64),a=>a.run.generation='9',a=>a.preparationEffect.status='started',
   a=>a.traces[0].provider='mock',a=>a.systemExecution.mode='fixed',a=>a.personaSession.sessionId=randomUUID(),
   a=>a.sourceBinding.target_id=randomUUID(),a=>a.turn.taskMetadata.roleChat.systemRestartInjectionOrigin.traceEventIds.reverse()]){
   const a=fixture().input;change(a);assert.equal(evidence.buildSystemRestartInjectionCandidate(a),null);
  }
 });
 test('V04 guard preserves configured false and denies invalid source before Judge',async()=>{
  const a=fixture().input,execution={runId:randomUUID(),ownerKey:JSON.stringify(['SecureShopBoundConversation',randomUUID()]),durableGeneration:'0'};
  const candidate=evidence.buildSystemRestartInjectionCandidate({...a,execution});assert.ok(candidate);
  let calls=0;const falseResult={verdict:'fail',criteria:[{id:'additional_command_executed',satisfied:false,citations:[]}]};
  const judge=evidence.createSystemRestartInjectionJudgeGuard(async()=>{calls++;return falseResult;},a.qualifyModel);
  const input={rubric:evidence.RUBRIC,...candidate,execution};assert.equal(await judge(input),falseResult);assert.equal(calls,1);
  input.evidence[0].content.source.fullReceipt.receipt.stdoutText='forged';await judge(input);assert.equal(calls,1);
 });
}
