'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {mailQualificationOptions,authenticateMailPersona,mailSourceEnvelope}=require('./fixtures/secureshopMailQualificationContracts');
const {createMailProduction}=require('../server/services/secureshopMailProduction');
const templates=[{id:1,role:'customer',username:'student_customer',email:'customer@lab'},{id:2,role:'merchant',username:'student_merchant',email:'merchant@lab'},{id:3,role:'admin',username:'student_admin',email:'admin@lab'}];
function dependencies(){
 const unused=async()=>{throw Error('Preflight must not execute provider, Judge or persistence');};
 const pool={async query(sql,args){return {rows:args?args[0].map(name=>({name,ready:true})):[{messages_private:true,purpose_ready:true,cleanup_ready:true,browse_ready:true}]};}};
 return {enabled:true,identityPool:{query:unused},agentsPool:pool,personaAuthority:{capture:unused},personaRepository:{listPersonas:async()=>templates,listMailActors:async()=>templates},provider:{chat:unused},promptPolicyRepository:{admitRunSnapshot:unused},toolPolicyRepository:{admitTool:unused},authenticatePersona(){},mode:'vuln',judge:unused,grading:{assessmentDependencies:{personaBindings:{capture:unused},receipts:{beginEvaluation:unused,recordVerdict:unused},progress:{getGeneration:unused},publicationModes:{getEvaluationScope:unused}}},resetComposition:{launches:{assertCurrent:unused},personaInbox:{repository:{provision:unused}},cleanupAuthority:{checkTarget:unused},conversations:{getBoundSession:unused,acquireBoundSession:unused,getMessages:unused,getTraceEvents:unused},journal:{claim:unused,complete:unused,markUncertain:unused,readBoundRequest:unused},runCoordinator:{run:unused}}};
}
test('native fixture options explicitly carry actual Judge into the real production factory',async()=>{
 const source=dependencies(),options=mailQualificationOptions(source);assert.equal(options.assessmentDependencies.judge,source.judge);assert.equal(options.assessmentDependencies.receipts,source.grading.assessmentDependencies.receipts);
 const built=await createMailProduction(options);assert.equal(built.ready,true);for(const name of ['readiness','read','send','reply','recover','assess'])assert.equal(typeof built.application[name],'function');built.close();
 assert.throws(()=>mailQualificationOptions({...source,judge:undefined}));
 for(const key of ['provider','promptPolicyRepository','toolPolicyRepository','authenticatePersona'])await assert.rejects(createMailProduction({...options,[key]:undefined}));
});
test('source send uses authenticated customer and envelope derived from exact caller, then merchant binding can resume',async()=>{
 const scope={owned:true},calls=[];const auth={async login(input){calls.push(input);return {user:templates[0],token:'opaque'};},async authenticateBoundToken(input){assert.equal(input.scope,scope);return {sessionId:'session',authorityVersion:'1'};}};
 const customer=await authenticateMailPersona({auth,scope,templates,role:'customer'});assert.equal(calls[0].username,'student_customer');assert.equal(customer.persona.role,'customer');assert.equal(customer.personaSession.sessionId,'session');
 const envelope=mailSourceEnvelope({templates,context:customer,recipientRole:'merchant',subject:'Owned',body_markdown:'untrusted source'});assert.equal(envelope.from,'customer@lab');assert.equal(envelope.to,'merchant@lab');
 assert.throws(()=>mailSourceEnvelope({templates,context:{persona:{id:2,role:'customer'}},recipientRole:'merchant'}));
 await assert.rejects(authenticateMailPersona({auth,scope,templates,role:'merchant'}),/identity mismatch/);
 const merchant=await authenticateMailPersona({auth:{...auth,async login(input){assert.equal(input.username,'student_merchant');return {user:templates[1],token:'merchant-opaque'};},async authenticateBoundToken(){return {sessionId:'fresh-merchant-session',authorityVersion:'2'};}},scope,templates,role:'merchant'});
 assert.equal(merchant.persona.id,2);assert.equal(merchant.personaSession.sessionId,'fresh-merchant-session');assert.notEqual(merchant.personaSession.sessionId,customer.personaSession.sessionId);
});
