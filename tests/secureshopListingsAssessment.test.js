'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),{randomUUID}=require('node:crypto');
const {createListingsAssessmentCollection}=require('../server/services/secureshopListingsAssessment');
const {prepareListingAdmission}=require('../server/services/secureshopListingJournalContract');
const {createConversationBinding}=require('../server/services/secureshopConversationBinding');
const {LISTINGS_OBJECTIVES}=require('../server/services/secureshopListingsEvidence');
function fixture(enabled=[],realm='platform'){
 const admission=prepareListingAdmission({scope:{launchId:randomUUID(),scenarioId:randomUUID(),generation:1,platformOwnerId:1,platformSessionId:2},
 persona:{id:3,role:'merchant'},personaSession:{sessionId:randomUUID(),authorityVersion:'1'},targetId:randomUUID(),mode:'vuln',catalogRevision:'0',
 request:{version:1,action:'import',operationId:randomUUID(),json_url:'http://owned/catalog',xml_url:null}});
 const context={binding:createConversationBinding(admission.binding.scope,admission.binding.persona),sessionId:randomUUID(),requestId:admission.request.operationId};
 const fence={binding:{...admission.binding.scope,personaId:3,role:'merchant',...admission.binding.personaSession},async assertRemoteAdmission(){}};
 let begins=0,reads=0,judgeCalls=0,queries=[];
 const factory=createListingsAssessmentCollection({identityPool:{async query(sql,values){queries.push({sql,values});
  if(sql.includes('secureshop_authority_owners'))return{rows:[{realm,shop_tenant_id:realm==='shop'?randomUUID():null}]};
  return{rows:enabled.map(objective_id=>({objective_id}))};}},
 objectiveIds:LISTINGS_OBJECTIVES.slice(0,3),qualifyModel:()=>false,personaBindings:{async capture(){return{};}},
 progress:{async getGeneration(){return 1;},async getEvaluationScope(){begins++;return{generation:1,mode:'vuln',modeStamp:'controlled'};}},
 receipts:{async beginEvaluation(){throw Error('No candidate should begin an evaluation');},async recordVerdict(){throw Error('No verdict');}},
 judge:async()=>{judgeCalls++;throw Error('No Judge expected');}}).assessmentFactory;
 const assessment=factory(context,fence,{admission,async readOperation(){reads++;return{operationId:admission.request.operationId,state:'unknown'};}});
 const execution={runId:'run',ownerKey:'owner',durableGeneration:1,async check(){}};
 return{assessment,execution,context,queries,counts:()=>({begins,reads,judgeCalls}),enabled};
}
test('default disabled catalog leaves ungraded Listings execution available without attempts or evidence reads',async()=>{
 const f=fixture(),attempt=await f.assessment.begin(f.execution);
 const outcome=await f.assessment.finalize(f.execution,{...f.context,attempt,traces:[],result:{stopReason:'end_turn'}});
 assert.deepEqual(outcome,{});assert.deepEqual(f.counts(),{begins:0,reads:0,judgeCalls:0});
 assert.match(f.queries[1].sql,/o.is_enabled AND o.catalog_active AND w.is_visible AND w.catalog_active/);
});
test('mixed catalog selects only enabled objective and never evaluates an unqualified outcome',async()=>{
 const f=fixture([LISTINGS_OBJECTIVES[1]]),attempt=await f.assessment.begin(f.execution);
 const outcome=await f.assessment.finalize(f.execution,{...f.context,attempt,traces:[],result:{stopReason:'end_turn'}});
 assert.deepEqual(Object.keys(outcome),[LISTINGS_OBJECTIVES[1]]);
 assert.equal(outcome[LISTINGS_OBJECTIVES[1]].modelEvaluated,false);assert.deepEqual(f.counts(),{begins:1,reads:1,judgeCalls:0});
});
test('standalone tenant selection reads the shop assessment catalog',async()=>{
 const f=fixture([LISTINGS_OBJECTIVES[0]],'shop'),attempt=await f.assessment.begin(f.execution);
 const outcome=await f.assessment.finalize(f.execution,{...f.context,attempt,traces:[],result:{stopReason:'end_turn'}});
 assert.deepEqual(Object.keys(outcome),[LISTINGS_OBJECTIVES[0]]);
 assert.ok(f.queries.some(row=>row.sql.includes('secureshop_auth.assessment_objectives')));
 assert.equal(f.queries.some(row=>row.sql.includes('workshop_platform.objectives')),false);
});
test('changed execution, request or owner cannot finalize the captured attempt',async()=>{
 const f=fixture(),attempt=await f.assessment.begin(f.execution),packet={...f.context,attempt,traces:[],result:{}};
 for(const [execution,changed] of [[{...f.execution},packet],[f.execution,{...packet,requestId:randomUUID()}],[f.execution,{...packet,binding:{...packet.binding,platformOwnerId:999}}]]){
  await assert.rejects(f.assessment.finalize(execution,changed),{code:'GRADE_STORE_NOT_READY'});
 }
});
