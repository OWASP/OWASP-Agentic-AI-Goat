'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),{randomUUID}=require('node:crypto');
const {REGISTRY_SHA256}=require('../server/services/secureshopBoundAclRegistry');
const {createBoundReviewRuntime}=require('../server/services/secureshopBoundReviewRuntime');
const {createSecureShopBoundRefundRuntime}=require('../server/services/secureshopBoundRefundRuntime');
const scope={launchId:randomUUID(),scenarioId:randomUUID(),generation:1,platformOwnerId:1,platformSessionId:2};
function dependencies(role,enforced,workflow){
 const sessions=new Map(),messages=[],traces=[],admissions=[];let effects=0,calls=0;
 const persona={id:3,role},credential={sessionId:randomUUID(),authorityVersion:'1'};
 const conversationRepository={async acquireBoundSession({id,binding,purpose}){const row={id,binding,purpose,state:'active'};sessions.set(id,row);return row;},async getBoundSession(id){return sessions.get(id);},async activateBoundSession(){return true;},async getMessages(){return structuredClone(messages);},async appendMessage(_id,_binding,value){messages.push(structuredClone(value));},async getTokens(){return 0;},async addTokens(){},async appendTraces(_id,_binding,rows){traces.push(...rows);}};
 const selected=workflow==='review'?'review-moderator.moderate_pending':'support.order_status';
 const args=workflow==='review'?{}:{order_id:1};
 const config=workflow==='review'?require('../server/services/secureshopReviewExecutionConfig').createSecureShopReviewExecutionConfig():{buildBasePrompt:()=>'',buildPolicyBlock:async()=>'',checkToolAcl:async()=>({allowed:true,action:'dispatch',enforcement:true,policyViolation:null}),manifest:{getForRole:()=>[]}};
 const dependencies={...config,conversationRepository,launches:{async assertCurrent(){},async resolveCapability(){return scope;},async reserveReviewsTarget(){return{...scope,kind:'reviews',targetId:randomUUID()};}},
  journal:{async lookupGeneralRequest(){return null;},async claim({requestId}){return{status:'claimed',claimId:requestId};},async complete(){},async markUncertain(){}},
  coordinator:{async reset(_id,work){return work();},async run(_id,_options,work){return work({runId:randomUUID(),ownerKey:'owned-test',durableGeneration:'1',async check(){},async effect(_key,callback){return callback();},async effectWithReceipt(_key,callback){return{value:await callback(),receipt:{status:'completed'}};}});}},
  authenticatePersona(_req,_res,next){next();},
  provider:{async chat(){calls++;return calls===1?{stop_reason:'tool_use',tool_uses:[{id:'first',name:selected,args}]}:{stop_reason:'end_turn',text:'Controlled test'};},async finalResponse(){return{responseMode:'structured_final',stop_reason:'end_turn',text:'Controlled test'};}},
  personaAuthority:{capture:({scope:s,...identity})=>({binding:{...s,...identity},async assertRemoteAdmission(){},async withPersonaEffect(work){return work();},async withCrossStoreEffect(work){return work();}})},
  toolPolicyRepository:{async admitTool(input){admissions.push(input);assert.deepEqual(input.scope,scope);assert.deepEqual(input.persona,persona);assert.deepEqual(input.personaSession,credential);assert.equal(input.workflow,workflow);
    assert.deepEqual(input.declaredTools.map(row=>`${row.agent}.${row.tool}`).sort(),workflow==='review'?['review-moderator.approve','review-moderator.moderate_pending','review-moderator.reject']:['support.order_status','support.refund_request']);
    return{admissionId:randomUUID(),runId:input.runId,invocationId:input.invocationId,toolKey:selected,registrySha256:REGISTRY_SHA256,policyVersion:'2',allowed:false,enforcement:enforced,action:enforced?'block':'dispatch',policyViolation:'denied-by-acl'};}},
  reviewRepository:{async provision(){},async listReviews(){return{rows:[],total:0,counts:{}};},async submitReview(){},async decide(){},async readDecisionReceipt(){},async listPending(){effects++;return[];}},
  assessmentFactory:()=>({async begin(){return{};},async observe(){},async finalize(){return{};}}),
  refundRepository:{async create(){throw Error('unselected refund');}},commerce:{async order(){effects++;return{order:{id:1,status:'completed'}};}},resolveTarget:async()=>scope,
 };
 return{dependencies,persona,credential,admissions,traces,get effects(){return effects;}};
}
for(const workflow of ['review','refund'])for(const enforced of [false,true])test(`${workflow} actual factory ${enforced?'blocks':'advisory executes'} selected tool`,async()=>{
 const f=dependencies(workflow==='review'?'merchant':'customer',enforced,workflow);
 const runtime=workflow==='review'?createBoundReviewRuntime(f.dependencies):createSecureShopBoundRefundRuntime(f.dependencies);
 const purpose=workflow==='review'?'review_moderation':'secureshop_refund_request';
 const session=await runtime.conversations.create(scope,f.persona,purpose);
 await runtime.runner.run({scope,persona:f.persona,personaSession:f.credential,sessionId:session.id,requestId:randomUUID(),message:workflow==='refund'?'Please refund order 1. Reason: controlled request':'Controlled request',
  ...(workflow==='review'?{localToolAuthority:require('../server/services/secureshopBoundReviewBatchAuthority').createBoundReviewBatchAuthority({requested:1,batchLimit:1})}:{})});
 assert.equal(f.admissions.length,1);assert.equal(f.effects,enforced?0:1);
 assert.equal(JSON.parse(f.traces.find(row=>row.kind==='policy_decision').params_json).admission.action,enforced?'block':'dispatch');
});
test('review/refund reject malformed policy injection before construction side effects',()=>{
 for(const factory of [createBoundReviewRuntime,createSecureShopBoundRefundRuntime])for(const input of [{toolPolicyRepository:{}},{toolPolicyRepository:{admitTool(){}}}])assert.throws(()=>factory(input),/Policy repository and persona authority required/);
});
