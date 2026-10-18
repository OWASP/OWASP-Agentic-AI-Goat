'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),{randomUUID}=require('node:crypto');
const {createInventoryJudgeRetry}=require('../server/services/secureshopInventoryJudgeRetry');
const {createConversationBinding}=require('../server/services/secureshopConversationBinding');
const {OBJECTIVE}=require('../server/services/secureshopInventoryEvidence');
function fixture({canonical=false,judgeUnavailable=false}={}){
 const scope={launchId:randomUUID(),scenarioId:randomUUID(),generation:1,platformOwnerId:1,platformSessionId:2},persona={id:2,role:'merchant'},personaSession={sessionId:randomUUID(),authorityVersion:'1'},sessionId=randomUUID(),evaluationId=randomUUID(),originalRequestId=randomUUID(),requestId=randomUUID();
 const input={scope,persona,personaSession,evaluationId,originalRequestId,requestId},binding=createConversationBinding(scope,persona),runId=randomUUID(),entry={receipt:{binding:{scope,persona,personaSession,execution:{runId,requestId:originalRequestId}}}};
 const original={status:'completed',outcome:{taskMetadata:{inventory:{grading:{judgment:{evaluationId,verdict:'unavailable',canRetry:true}},receipts:[entry]}}}},packet={rubric:{objectiveId:OBJECTIVE},evidence:[{id:'inventory_stock',source:'server_observation',content:{raw:{entry,context:{binding,requestId:originalRequestId},execution:{runId}}}}]};
 const retained={workshop_key:'secureshop_agent_security',objective_id:OBJECTIVE,owner_key:sessionId,owner_generation:1,packet:JSON.stringify(packet)};let enabled=true,revoked=false,calls=0,eligibilityReads=0;const claims=new Map(),session={id:sessionId,binding,purpose:'secureshop_inventory',state:'active'};
 const check=async()=>{if(revoked)throw Object.assign(Error('revoked'),{code:'SHOP_AUTH_INVALID'});};
 const repository={acquireBoundSession:async()=>session,activateBoundSession:async()=>true,getBoundSession:async()=>session};
 const journal={claim:async({requestId,message})=>{if(claims.has(requestId)){const row=claims.get(requestId);assert.equal(row.message,message);return row;}const row={status:'claimed',claimId:randomUUID(),message};claims.set(requestId,row);return row;},complete:async({requestId,result})=>{Object.assign(claims.get(requestId),{status:'completed',result});},markUncertain:async()=>{}};
 const coordinator={run:async(owner,options,work)=>{const a=await options.admit();if(a.skip)return a.value;return work({runId:randomUUID(),ownerKey:sessionId,durableGeneration:1,check,signal:options.signal});}};
 let child;
 const receiptStore={getRecovery:async()=>retained,beginEvaluation:async()=>{},recordVerdict:async({evaluationId,result})=>{child={...child,evaluationId,verdict:result.verdict,result,disposition:result.verdict==='pass'?'awarded':'not_pass'};return child;},beginRetry:async({evaluationId:id,ownerGeneration})=>{assert.equal(id,evaluationId);assert.equal(ownerGeneration,1);return{packet:retained.packet,receipt:child};}};
 const controlledRetry=async()=>{calls++;return{completed:true,judgment:{evaluationId:randomUUID(),verdict:'pass',canRetry:false}};};
 let completionService={retry:controlledRetry};
 if(canonical){
  packet.rubric={family:'SecureShop',scenario:'bound_inventory',objectiveId:OBJECTIVE,version:'controlled-retry-envelope',mode:'vuln',requiredFacts:[],criteria:[{id:'owned_stock_authorization_bypass',description:'Controlled canonical retry envelope',allowedSources:['server_observation']}]};packet.facts={};
  const prepared=require('../server/agent-runtime/objectiveJudge').prepareJudgeInput(packet);assert.equal(prepared.evidenceError,undefined);retained.packet=prepared.packet;
  child={evaluationId:randomUUID(),verdict:null,evidenceDigest:prepared.evidenceDigest,rubricVersion:prepared.rubric.version,runId,objectiveId:OBJECTIVE,family:'SecureShop',scenario:'bound_inventory',mode:'vuln'};
  completionService=require('../server/services/objectiveCompletionService').createObjectiveCompletionService({receipts:receiptStore,progress:{getGeneration:async()=>1},judge:async()=>{calls++;if(judgeUnavailable)throw Error('unavailable');return{verdict:'pass',criteria:[],explanation:'Controlled envelope only'};}});
 }
 const service=createInventoryJudgeRetry({launches:{assertCurrent:check},personaAuthority:{capture:async x=>({binding:{...x.scope,personaId:x.personaId,role:x.role,...personaSession},assertRemoteAdmission:check})},conversationRepository:repository,coordinator,journal,recoveryRepository:{read:async()=>original},receipts:receiptStore,assessment:{isEnabled:async selected=>{assert.deepEqual(selected,scope);eligibilityReads++;return enabled;},completionService}});
 return{input,service,original,retained,packet,get calls(){return calls;},get eligibilityReads(){return eligibilityReads;},get claims(){return claims.size;},disable(){enabled=false;},revoke(){revoked=true;}};
}
test('retry journals a distinct turn, retains exact evidence and replays without another Judge or stock execution',async()=>{const f=fixture(),a=await f.service(f.input),b=await f.service(f.input);assert.equal(a.grading.completed,true);assert.equal(b.replayed,true);assert.deepEqual(a.grading,b.grading);assert.equal(f.calls,1);f.disable();const hidden=await f.service(f.input);assert.deepEqual(hidden.grading,{status:'disabled',completed:false});assert.ok(!JSON.stringify(hidden).includes(f.input.evaluationId));assert.equal(f.calls,1);});
test('disabled scoped retry creates no turn or Judge effect',async()=>{const f=fixture();f.disable();const hidden=await f.service(f.input);assert.deepEqual(hidden.grading,{status:'disabled',completed:false});assert.equal(f.eligibilityReads,1);assert.equal(f.claims,0);assert.equal(f.calls,0);});
test('wrong owner/generation/evaluation/request/effect and revoked session never reach canonical retry',async()=>{
 for(const mutate of[f=>f.retained.owner_key=randomUUID(),f=>f.retained.owner_generation=2,f=>f.input.evaluationId=randomUUID(),f=>f.input.originalRequestId=randomUUID(),f=>{f.packet.evidence[0].content.raw.entry.receipt.binding.persona.id=9;f.retained.packet=JSON.stringify(f.packet);},f=>f.revoke()]){const f=fixture();mutate(f);await assert.rejects(f.service(f.input));assert.equal(f.calls,0);}
});
test('stock UUID is not accepted as retry identity',async()=>{const f=fixture();await assert.rejects(f.service({...f.input,requestId:f.input.originalRequestId}),{code:'INVENTORY_INVALID'});assert.equal(f.calls,0);});

test('real completion.retry consumes one child receipt and unavailable child is terminal',async()=>{
 for(const judgeUnavailable of[false,true]){const f=fixture({canonical:true,judgeUnavailable}),first=await f.service(f.input);assert.equal(first.grading.judgment.verdict,judgeUnavailable?'unavailable':'pass');assert.equal(first.grading.judgment.canRetry,false);assert.equal(first.grading.completed,!judgeUnavailable);assert.equal(f.calls,1);const differentTransport=await f.service({...f.input,requestId:randomUUID()});assert.deepEqual(differentTransport.grading,first.grading);assert.equal(f.calls,1);}
});
