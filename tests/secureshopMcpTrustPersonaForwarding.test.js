'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),{randomUUID}=require('node:crypto');
const {createSecureShopMcpTrustComposition}=require('../server/services/secureshopMcpTrustComposition');
const {createSecureShopMcpTrustBoundRunner}=require('../server/services/secureshopMcpTrustBoundRunner');
const scope={launchId:randomUUID(),scenarioId:randomUUID(),generation:1,platformOwnerId:1,platformSessionId:2};
test('composition forwards the same optional capture adapter without changing disabled defaults',async()=>{
 assert.deepEqual(createSecureShopMcpTrustComposition(),{ready:false});for(const personaBindings of [null,{},true,{capture:1}])assert.throws(()=>createSecureShopMcpTrustComposition({personaBindings}),{code:'BOUND_MCP_UNAVAILABLE'});
 let captures=0;const stop=Object.assign(Error('capture reached'),{code:'CAPTURE_SENTINEL'}),adapter={async capture(){captures++;throw stop;}};
 const noop=async()=>{};
 const feature=createSecureShopMcpTrustComposition({enabled:true,personaBindings:adapter,launches:{assertCurrent:noop,reserveMcpTarget:async()=>{throw Error('capture must precede target');}},repository:{provision:noop,recordDiscovery:noop,currentSchema:noop,readInvocation:noop,readPriorSchema:noop},transport:{discover:noop},serverIdentity:'owned',trustScenario:'rogue_registration',endpoint:'owned://fixture',authorizeRotation:noop,receipts:{beginEvaluation:noop,recordVerdict:noop},progress:{getGeneration:async()=>0},qualifyModel:async()=>false,judge:async()=>{throw Error('No Judge');}});
 const assessment=feature.assessment.assessmentFactory({binding:{...scope,shopUserId:3,role:'admin'},sessionId:randomUUID(),requestId:randomUUID()},{binding:{...scope,personaId:3,role:'admin',sessionId:randomUUID(),authorityVersion:'1'},assertRemoteAdmission:noop});
 await assert.rejects(assessment.begin({runId:randomUUID(),check:noop}),error=>error===stop);assert.equal(captures,1);
});
test('bound runner forwards verified runtime capture callback and rejects malformed options',async()=>{
 for(const capturePersonaAuthority of [null,{},true])assert.throws(()=>createSecureShopMcpTrustBoundRunner({capturePersonaAuthority}),{code:'BOUND_MCP_UNAVAILABLE'});
 const noop=async()=>{},stop=Object.assign(Error('trusted capture'),{code:'CAPTURE_SENTINEL'});let captured;
 const schema={serverIdentity:'owned',trustScenario:'rogue_registration',version:1,schemaSha256:'a'.repeat(64),tools:[{name:'forecast_lookup',description:'fixture',inputSchema:{type:'object'}}]};
 const base={feature:{ready:true,assessment:{assessmentFactory:()=>{throw Error('Not admitted');}},createExternalAdapter:()=>({createToolPool:noop,observeExternalTool:noop})},schema,turns:{run:noop},conversations:{assertOwned:noop,getMessages:noop},conversationRepository:{appendMessage:noop,getTokens:noop,addTokens:noop,appendTraces:noop},journal:{claim:noop,complete:noop,markUncertain:noop},provider:{chat:noop},checkCurrent:noop};
 assert.ok(createSecureShopMcpTrustBoundRunner(base).runner);
 const canonical={sessionId:randomUUID(),authorityVersion:'3'};
 assert.ok(createSecureShopMcpTrustBoundRunner({...base,personaSession:canonical,
   modeEpoch:{generation:4,modeStamp:'canonical-mode-stamp'}}).runner);
 assert.throws(()=>createSecureShopMcpTrustBoundRunner({...base,
   personaSession:{...canonical,authorityVersion:3}}),{code:'BOUND_MCP_UNAVAILABLE'});
 const {runner}=createSecureShopMcpTrustBoundRunner({...base,capturePersonaAuthority:async value=>{captured=value;throw stop;}});
 const personaSession={sessionId:randomUUID(),authorityVersion:'1'};
 await assert.rejects(runner.run({sessionId:randomUUID(),requestId:randomUUID(),scope,persona:{id:3,role:'admin'},personaSession,message:'owned fixture'}),error=>error===stop);
 assert.deepEqual(captured.personaSession,personaSession);assert.ok(Object.isFrozen(captured));assert.equal(captured.binding.platformOwnerId,1);
});
