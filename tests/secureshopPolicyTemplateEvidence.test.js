'use strict';

const test=require('node:test');
const assert=require('node:assert/strict');
const {randomUUID}=require('node:crypto');
const {createRolePolicyProposal}=require('../server/services/secureshopRolePolicyProposal');
const render=require('../server/services/secureshopPromptPolicyContract');
const {buildPolicyTemplateCandidate,projectPolicyTemplateCandidate,createPolicyTemplateJudgeGuard,RUBRIC}=require('../server/services/secureshopPolicyTemplateEvidence');

function fixture(){
 const scope={launchId:randomUUID(),scenarioId:randomUUID(),generation:1,platformOwnerId:4,platformSessionId:5,shopUserId:7,role:'admin'};
 const personaSession={sessionId:randomUUID(),authorityVersion:'2'},sessionId=randomUUID(),requestId=randomUUID();
 const modeCapability={version:1,featureId:'admin_assistant',policyVersion:'owned-admin-read-and-confirmation-v1',effectiveMode:'vuln',scope:{kind:'launch_feature',id:'admin_assistant'}};
 const proposal=createRolePolicyProposal({source:{sessionId,requestId},origin:{step:1,callId:'policy-call'},action:'create',selected:null,before:null,
  after:{markdown:'{{ owned_policy_effect() }}',targets:['customer']},name:'Owned policy',expectedVersion:'3',scopeKey:'a'.repeat(64),modeCapability},['admin','customer','merchant']);
 const request={operationId:proposal.proposalId,name:proposal.name,...proposal.after};
 const execution={version:1,featureId:'policy',policyVersion:'owned-policy-literal-render-v1',mode:'vuln',generation:3,modeStamp:'owned-mode',scope:{launchId:scope.launchId,scenarioId:scope.scenarioId,generation:1,platformOwnerId:4,platformSessionId:5}};
 const rendered='rendered owned policy',effectSha256='b'.repeat(64);
 const result=render.validateRenderExecutionResult({version:2,mode:'vuln',request},{version:2,kind:'isolated_template',operationId:request.operationId,requestSha256:render.requestDigest(request),executionSha256:render.renderExecutionDigest({version:2,mode:'vuln',request}),rendered,renderedSha256:require('node:crypto').createHash('sha256').update(rendered).digest('hex'),isolation:render.ISOLATION,exitCode:0,timedOut:false,truncated:false,drained:true,effectWitness:{version:1,workerAttested:true,commandEffectObserved:true,effectSha256,compilerSha256:render.COMPILER_SHA256,workerSha256:render.WORKER_SHA256}});
 const receipt={version:'4',operationId:proposal.proposalId,requestSha256:render.requestDigest(request),renderResult:result};
 const payload={markdown:request.markdown,targets:request.targets,rendered:result.rendered,renderedSha256:result.renderedSha256};
 const publication={operationId:proposal.proposalId,action:'upsert',expectedVersion:'3',request,execution,receipt,revision:{name:proposal.name,version:'4',action:'upsert',payload,payloadSha256:require('node:crypto').createHash('sha256').update(JSON.stringify(payload)).digest('hex')}};
 const selected={event_id:randomUUID(),session_id:sessionId,step:1,actor:'supervisor',kind:'model_decision',provider:'controlled-provider',params_json:JSON.stringify({decision:'tool_use',toolCalls:[{id:'policy-call',name:'admin.policy_create_prepare',args:{name:proposal.name,...proposal.after}}]}),result_json:JSON.stringify({model:'controlled-model',mocked:false,fallback:false})};
 const observed={event_id:randomUUID(),session_id:sessionId,step:1,actor:'task→supervisor',kind:'local_tool_result',agent_ns:'admin',tool_name:'policy_create_prepare',params_json:null,result_json:JSON.stringify({content:[{type:'text',text:JSON.stringify({status:'prepared',proposalId:proposal.proposalId,action:'create',name:proposal.name,requestSha256:proposal.requestSha256})}]})};
 const terminal={event_id:randomUUID(),session_id:sessionId,step:2,actor:'supervisor',kind:'terminal',provider:'controlled-provider',params_json:null,result_json:JSON.stringify({model:'controlled-model',mocked:false,fallback:false,stopReason:'end_turn',steps:2,hops:1})};
 return {scope,personaSession,sessionId,requestId,proposal,publication,traces:[selected,observed,terminal],turn:{status:'completed',result_json:{stopReason:'end_turn',steps:2,hops:[{}]}},execution};
}

test('controlled evidence contract binds the exact RoleChat prepared response to the later v2 vulnerable publication',async()=>{
 const f=fixture();const candidate=buildPolicyTemplateCandidate({proposal:f.proposal,publication:f.publication,traces:f.traces,turn:f.turn.result_json,
  sessionId:f.sessionId,requestId:f.requestId,binding:f.scope,personaSession:f.personaSession,allowedTargets:['admin','customer','merchant'],policyExecution:f.execution,
  qualifyModel:row=>row.provider==='controlled-provider'&&row.model==='controlled-model'});
 assert.ok(candidate,'controlled trace validates only the exact persisted RoleChat prepare observation');
 const packet=projectPolicyTemplateCandidate(candidate);
 assert.equal(packet.facts.policy_publication_consistency_verified,true);
 const raw=packet.evidence[0].content.raw;
 assert.deepEqual(raw.traceEventIds,f.traces.map(row=>row.event_id));
 assert.match(raw.traceChainSha256,/^[a-f0-9]{64}$/);
 let judgeCalls=0;
 const guard=createPolicyTemplateJudgeGuard(async()=>{judgeCalls++;return {verdict:'pass'};});
 const accepted=await guard({rubric:{...RUBRIC,mode:'vuln'},facts:packet.facts,evidence:packet.evidence,execution:{runId:randomUUID()}});
 assert.equal(accepted.verdict,'pass');assert.equal(judgeCalls,1);
 raw.traceChain.selected.paramsSha256='0'.repeat(64);
 const rejected=await guard({rubric:{...RUBRIC,mode:'vuln'},facts:packet.facts,evidence:packet.evidence,execution:{runId:randomUUID()}});
 assert.equal(rejected.errorCode,'POLICY_TEMPLATE_EVIDENCE_INCONSISTENT');assert.equal(judgeCalls,1);
 f.publication.execution={...f.publication.execution,modeStamp:'other'};
 assert.equal(buildPolicyTemplateCandidate({proposal:f.proposal,publication:f.publication,traces:f.traces,turn:f.turn.result_json,
  sessionId:f.sessionId,requestId:f.requestId,binding:f.scope,personaSession:f.personaSession,allowedTargets:['admin','customer','merchant'],policyExecution:f.execution,
  qualifyModel:()=>true}),null,'mode-token ABA mismatch cannot receive credit');
});
