'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {createObjectiveGradingCore}=require('../server/services/objectiveGradingCore');
const factories=[require('../server/services/secureshopPersonaInboxComposition').createSecureShopPersonaInboxComposition,require('../server/services/secureshopSsrfComposition').createSecureShopSsrfComposition,require('../server/services/secureshopMcpTrustProduction').createSecureShopMcpTrustProduction];
function fixture(personaBindings){const identityPool={query:async()=>{},connect:async()=>{}},progress={getGeneration:async()=>0};const core=createObjectiveGradingCore({identityPool,progress,...(personaBindings?{personaBindings}:{})},{createObjectiveJudgmentRepository:()=>({listRecoverable:async()=>[]}),createObjectiveCompletionService:()=>({}),createObjectiveRegradeService:()=>async()=>{}});return{identityPool,core};}
for(const factory of factories){test(factory.name+' accepts only branded same-pool grading core and exact adapter',()=>{const f=fixture();assert.deepEqual(factory({identityPool:f.identityPool,gradingCore:f.core}),{ready:false});assert.throws(()=>factory({identityPool:f.identityPool,gradingCore:{...f.core}}),TypeError);assert.throws(()=>factory({identityPool:{query(){}},gradingCore:f.core}),TypeError);assert.throws(()=>factory({identityPool:f.identityPool,gradingCore:f.core,personaBindings:{capture(){}}}),TypeError);const adapter={capture(){}},bound=fixture(adapter),authority={capture(){}};assert.deepEqual(factory({identityPool:bound.identityPool,gradingCore:bound.core,personaAuthority:authority}),{ready:false});assert.throws(()=>factory({identityPool:bound.identityPool,gradingCore:bound.core,personaAuthority:authority,personaBindings:undefined}),TypeError);assert.deepEqual(factory(),{ready:false});});}
test('enabled Inbox SSRF and MCP pass exact startup stores without constructing another repository',()=>{
 const Module=require('node:module'),original=Module._load,noop=async()=>{};
 const identityPool={query:noop,connect:noop},receipts={listRecoverable:noop},progress={getGeneration:noop};
 const core=createObjectiveGradingCore({identityPool,progress},{createObjectiveJudgmentRepository:()=>receipts,createObjectiveCompletionService:()=>({}),createObjectiveRegradeService:()=>noop});
 const launches={assertCurrent:noop,reservePersonaInboxTarget:noop,reserveSsrfTarget:noop,readExistingSsrfTarget:noop,reserveMcpTarget:noop};
 const conversations={create:noop},rows={appendTraces:noop},journal={claim:noop,lookupMcpRequest:noop};
 const provider={chat:noop},targetPool={issue:noop,ensure:noop};
 const base={enabled:true,identityPool,agentsPool:identityPool,provider,gradingCore:core,authenticatePersona:noop,personaRepository:{listPersonas:noop},upstreamPool:{callTool:noop},resetComposition:{launches,conversationService:conversations,turns:{run:noop},journal,conversations:rows,cleanupAuthority:{checkTarget:noop},personaInbox:{repository:{readAccessEvent:noop},authorizeAclTransition:noop},ssrf:{repository:{readInvocation:noop},targetPool},mcpTrust:{repository:{readInvocation:noop},targetPool,authorizeRotation:noop}}};
 for(const [file,entry,dependency,exportName] of [
 ['secureshopPersonaInboxComposition','createSecureShopPersonaInboxComposition','secureshopPersonaInboxAssessment','createSecureShopPersonaInboxAssessment'],
 ['secureshopSsrfComposition','createSecureShopSsrfComposition','secureshopSsrfAssessment','createSecureShopSsrfAssessment'],
 ['secureshopMcpTrustProduction','createSecureShopMcpTrustProduction','secureshopMcpTrustComposition','createSecureShopMcpTrustComposition']]){
  const filename=require.resolve('../server/services/'+file),saved=require.cache[filename],stop=Error('Assessment constructor reached');let seen;
  try{delete require.cache[filename];Module._load=function(request,parent,isMain){if(request.endsWith('/objectiveJudgmentRepository'))return{createObjectiveJudgmentRepository(){throw Error('Extra repository constructed');}};if(request.endsWith('/workshopProgressRepository'))return{createWorkshopProgressRepository(){throw Error('Extra progress constructed');}};if(request.endsWith('/'+dependency))return{[exportName](input){seen=input;throw stop;}};return original.apply(this,arguments);};
   const create=require(filename)[entry];assert.throws(()=>create(base),error=>error===stop);assert.equal(seen.receipts,receipts);assert.equal(seen.progress,progress);
  }finally{Module._load=original;delete require.cache[filename];if(saved)require.cache[filename]=saved;}
 }
});
