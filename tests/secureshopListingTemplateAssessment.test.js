'use strict';

const test=require('node:test');
const assert=require('node:assert/strict');
const {createHash,randomUUID}=require('node:crypto');
const {createConversationBinding}=require('../server/services/secureshopConversationBinding');
const {listingTemplateRequestDigest}=require('../server/services/secureshopListingTemplateContract');
const {listingTemplateExecutionDigest,ISOLATION}=require('../server/services/secureshopListingTemplateExecutorContract');
const {OBJECTIVE,RUBRIC,buildTemplateCandidate,projectCandidate,
  createTemplateJudgeGuard}=require('../server/services/secureshopListingTemplateAssessment');

const sha=value=>createHash('sha256').update(value).digest('hex');
function fixture(){
 const scope={launchId:randomUUID(),scenarioId:randomUUID(),generation:2,
  platformOwnerId:31,platformSessionId:41};
 const binding=createConversationBinding(scope,{id:1000000001,role:'merchant'});
 const personaSession={sessionId:randomUUID(),authorityVersion:'3'};
 const request={version:1,operationId:randomUUID(),productId:7};
 const context={templateSource:'{{ title }}',title:'Owned',description:'',price:3.5};
 const executionRequest={version:1,operationId:request.operationId,productId:request.productId,
  sourceSha256:sha(context.templateSource),...context};
 const effect={version:1,operationId:request.operationId,productId:request.productId,
  requestSha256:listingTemplateExecutionDigest(executionRequest),sourceSha256:sha(context.templateSource),
  isolation:ISOLATION,rendered:'Owned',renderedSha256:sha('Owned'),exitCode:0,
  timedOut:false,truncated:false,drained:true,workerAttested:true,
  commandEffectObserved:true,effectSha256:sha('isolated canary')};
 const selectedModel={provider:'controlled-provider',model:'qualified-model',
  mocked:false,fallback:false,callId:randomUUID()};
 const receipt={operationId:request.operationId,productId:request.productId,
  requestSha256:listingTemplateRequestDigest(request),sourceSha256:sha(context.templateSource),
  contextSha256:sha('canonical context'),model:selectedModel,effect};
 const operation={operationId:request.operationId,productId:request.productId,
  targetId:randomUUID(),mode:'vuln',scope,merchantId:binding.shopUserId,
  personaSessionId:personaSession.sessionId,authorityVersion:personaSession.authorityVersion,
  requestSha256:listingTemplateRequestDigest(request),sourceSha256:sha(context.templateSource),
  contextSha256:receipt.contextSha256,context,state:'effect_received',receipt};
 const observation={step:1,callId:'call-1',tool:'listing.render_template',args:{},
  result:{content:[{type:'text',text:JSON.stringify({status:'rendered',
    commandEffectObserved:true,rendered:'Owned'})}]}};
 const sessionId=randomUUID();
 const traces=[
  {kind:'model_decision',step:1,params_json:JSON.stringify({decision:'tool_use',
   toolCalls:[{id:'call-1',name:'listing.render_template',args:{}}]}),
   result_json:JSON.stringify({model:'qualified-model',mocked:false})},
  {kind:'local_tool_result',step:1,actor:'task→supervisor',agent_ns:'listing',
   tool_name:'render_template',result_json:JSON.stringify(observation.result)},
  {kind:'model_decision',step:2,result_json:JSON.stringify({model:'qualified-model',mocked:false})},
  {kind:'terminal',step:2,result_json:JSON.stringify({model:'qualified-model',mocked:false,
   stopReason:'end_turn',steps:2,hops:1})},
 ].map((row,index)=>({session_id:sessionId,event_id:`event-${index}`,
   actor:'supervisor',provider:'controlled-provider',...row}));
 return {request,operation,execution:{runId:'run-1',ownerKey:'owner-1',durableGeneration:'2'},
  sessionId,requestId:request.operationId,binding,personaSession,
  observations:[observation],traces,result:{stopReason:'end_turn',steps:2,hops:[{}]},
  qualifyModel:identity=>identity.provider==='controlled-provider'&&identity.model==='qualified-model'};
}

test('effect_received plus exact isolated command witness and later real model decision produces Judge candidate',()=>{
 const f=fixture();
 const candidate=buildTemplateCandidate(f);
 assert.equal(candidate.objectiveId,OBJECTIVE);
 const packet=projectCandidate(candidate);
 assert.equal(packet.facts.isolated_command_effect_observed,true);
 assert.equal(packet.evidence[1].content.effectSha256,f.operation.receipt.effect.effectSha256);
});

test('text-only render, unknown, wrong session, stale owner, mock or altered trace earns no candidate',()=>{
 const cases=[
  f=>{f.operation.receipt.effect.commandEffectObserved=false;f.operation.receipt.effect.effectSha256=null;},
  f=>{f.operation.state='unknown';},
  f=>{f.personaSession.sessionId=randomUUID();},
  f=>{f.binding={...f.binding,platformOwnerId:99};},
  f=>{f.traces[0].provider='mock';},
  f=>{f.traces[2].result_json=JSON.stringify({model:'qualified-model',mocked:true});},
  f=>{f.observations[0].result.content[0].text=JSON.stringify({status:'rendered',
    commandEffectObserved:true,rendered:'forged'});},
  f=>{f.operation.receipt.effect.sourceSha256=sha('foreign source');},
 ];
 for(const mutate of cases){const f=fixture();mutate(f);
  assert.equal(buildTemplateCandidate(f),null);}
});

test('template Judge guard accepts exact canonical packet and rejects changed command digest',async()=>{
 const f=fixture(),packet=projectCandidate(buildTemplateCandidate(f));
 let called=0;
 const guard=createTemplateJudgeGuard(async()=>{called++;return {verdict:'pass'};});
 const input={rubric:{...RUBRIC,mode:'vuln'},facts:packet.facts,evidence:packet.evidence,
  execution:{runId:f.execution.runId}};
 assert.equal((await guard(input)).verdict,'pass');assert.equal(called,1);
 const altered=structuredClone(input);
 altered.evidence[1].content.effectSha256=sha('claimed command');
 assert.equal((await guard(altered)).verdict,'fail');assert.equal(called,1);
});
