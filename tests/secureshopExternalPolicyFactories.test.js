'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),Module=require('node:module');
const {REGISTRY_SHA256}=require('../server/services/secureshopBoundAclRegistry');
const noop=async()=>{};
function load(file, overrides){const filename=require.resolve('../server/services/'+file),saved=require.cache[filename],original=Module._load;try{delete require.cache[filename];Module._load=function(request){const name=request.split('/').pop();return overrides[name]||original.apply(this,arguments);};return require(filename);}finally{Module._load=original;delete require.cache[filename];if(saved)require.cache[filename]=saved;}}
function base(){const pool={query:noop,connect:noop};return{enabled:true,identityPool:pool,agentsPool:pool,provider:{chat:noop},authenticatePersona:noop,personaRepository:{listPersonas:noop},personaAuthority:{capture:noop},upstreamPool:{callTool:noop},resetComposition:{launches:{assertCurrent:noop,reservePersonaInboxTarget:noop,reserveSsrfTarget:noop,readExistingSsrfTarget:noop},conversationService:{create:noop},turns:{run:noop},conversations:{appendTraces:noop},journal:{claim:noop},cleanupAuthority:{checkTarget:noop},personaInbox:{repository:{readAccessEvent:noop},authorizeAclTransition:noop},ssrf:{repository:{readInvocation:noop},targetPool:{issue:noop}}}};}
const deps={secureshopPersonaInboxAvailability:{createSecureShopPersonaInboxAvailability:()=>({})},secureshopSsrfExternalAdapter:{createSecureShopSsrfExternalAdapter:()=>({})},objectiveJudgmentRepository:{createObjectiveJudgmentRepository:()=>({})},workshopProgressRepository:{createWorkshopProgressRepository:()=>({})},secureshopPersonaInboxAssessment:{createSecureShopPersonaInboxAssessment:()=>({assessmentFactory:noop})},secureshopSsrfAssessment:{createSecureShopSsrfAssessment:()=>({assessmentFactory:noop})}};

function actualRunnerDeps(provider, traces) {
 const store={messages:[],async assertOwned(){},async getMessages(){return this.messages;},async appendMessage(_id,_b,row){this.messages.push(row);},async getTokens(){return 0;},async addTokens(){},async appendTraces(_id,_b,rows){traces.push(...rows);}};
 const turns={async run(_id,_binding,_persona,options,operation){const admitted=options.admit?await options.admit():{skip:false};if(admitted.skip)return admitted.value;return operation({identity:{runId:'91000000-0000-4000-8000-000000000091',ownerKey:'external-owner',durableGeneration:'1'},signal:options.signal,async check(){},async effect(_k,fn){return fn();},async effectWithReceipt(_k,fn){return{value:await fn(),receipt:{status:'completed'}}},async trace(){}});}};
 const conversations={...store,async create(){return{id:'session-external-1'};}};
 return {turns,conversations,repository:store,journal:{async claim(){return{status:'claimed',claimId:'c'}},async complete(){},async markUncertain(){}} ,provider,manifest:undefined};
}
function authority(){return{capture({scope,personaId,role,sessionId,authorityVersion}){return{binding:{...scope,personaId,role,sessionId,authorityVersion},async assertRemoteAdmission(){},async withPersonaEffect(work){return work({});},async withCrossStoreEffect(work){return work();}};}};}
function policy(rendered, role='customer'){const {buildPolicySnapshot}=require('../server/services/secureshopPromptPolicySnapshot');const {createHash}=require('node:crypto');return buildPolicySnapshot({policyVersion:'4',role,policies:[{name:'owned',rendered,renderedSha256:createHash('sha256').update(rendered).digest('hex'),targets:[role]}]});}

test('MCP bound runner actual graph consumes one admitted policy snapshot', async () => {
 let seen=0;const traces=[],rendered='MCP_ADMITTED_POLICY',credential={sessionId:'92000000-0000-4000-8000-000000000093',authorityVersion:'2'};const provider={async chat(input){assert.ok(input.system.includes(rendered));seen++;return{stop_reason:'end_turn',text:'done'};},async finalResponse(input){assert.ok(input.system.includes(rendered));return{stop_reason:'end_turn',text:'done'};}};const d=actualRunnerDeps(provider,traces);const feature={ready:true,assessment:{assessmentFactory:()=>({async begin(){},async observe(){},async finalize(){}})},createExternalAdapter:()=>({createToolPool:()=>({async callTool(){return{content:[]}}}),async observeExternalTool(){}})};const schema=mcpSchema('rogue_registration');let admissions=0;const {createSecureShopMcpTrustBoundRunner}=require('../server/services/secureshopMcpTrustBoundRunner');const r=createSecureShopMcpTrustBoundRunner({feature,schema,...d,conversationRepository:d.repository,checkCurrent:async()=>{},capturePersonaAuthority:({binding,personaSession})=>authority().capture({scope:binding,personaId:binding.shopUserId,role:binding.role,sessionId:personaSession.sessionId,authorityVersion:personaSession.authorityVersion}),promptPolicyAdmission:async input=>{admissions++;assert.equal(input.persona.id,9);assert.deepEqual(input.personaSession,credential);return policy(rendered,'admin')},conversationPurpose:'mcp_rogue_registration'});await r.runner.run({sessionId:'50000000-0000-4000-8000-000000000093',requestId:'40000000-0000-4000-8000-000000000093',scope:{launchId:'10000000-0000-4000-8000-000000000093',scenarioId:'20000000-0000-4000-8000-000000000093',generation:1,platformOwnerId:7,platformSessionId:8},persona:{id:9,role:'admin'},personaSession:credential,message:'inspect connector'});assert.equal(admissions,1);assert.equal(seen,1);assert.ok(traces.some(x=>x.kind==='prompt_policy_snapshot'));
});
for(const [file,name,workflow,agent,tool] of [
 ['secureshopPersonaInboxComposition','createSecureShopPersonaInboxComposition','inbox','persona-inbox','read_message'],
 ['secureshopSsrfComposition','createSecureShopSsrfComposition','ssrf','summarizer','explain_return_policy']]){
 test(workflow+' factory captures exact server declaration and keeps policy opt-in',async()=>{
  let runner,observed;const stop=Error('runner captured');
  const create=load(file,{...deps,secureshopBoundAgentRunner:{createBoundAgentRunner(input){runner=input;throw stop;}}})[name];
  const input=base();assert.throws(()=>create(input),e=>e===stop);assert.equal(runner.toolPolicyAdmission,undefined);
  input.toolPolicyRepository={async admitTool(value){observed=value;await Promise.resolve();return{runId:value.runId,invocationId:value.invocationId,toolKey:agent+'.'+tool,registrySha256:REGISTRY_SHA256};}};
  assert.throws(()=>create(input),e=>e===stop);assert.equal(typeof runner.capturePersonaAuthority,'function');
  const request={scope:{launchId:'owned'},persona:{id:7,role:'customer'},personaSession:{sessionId:'original',authorityVersion:'2'},runId:'run',invocationId:'1:call',agent,tool,args:{value:'original'},workflow:'forged'};
  const pending=runner.toolPolicyAdmission(request);request.personaSession.sessionId='substitute';request.args.value='changed';await pending;
  assert.equal(observed.workflow,workflow);assert.equal(observed.personaSession.sessionId,'original');assert.equal(observed.args.value,'original');
  assert.throws(()=>create({...input,personaAuthority:undefined}),e=>e!==stop);assert.throws(()=>create({...input,toolPolicyRepository:{}}),e=>e!==stop);
 });
}
function mcpSchema(scenario){return{trustScenario:scenario,serverIdentity:'owned-'+scenario,version:2,schemaSha256:'b'.repeat(64),tools:[{name:'forecast_lookup',description:'Synthetic connector',inputSchema:{type:'object'}}]};}
test('MCP runner binds each exact admitted schema and alias before constructing transport',async()=>{
 let runner,observed,effects=0;const create=load('secureshopMcpTrustBoundRunner',{secureshopBoundAgentRunner:{createBoundAgentRunner(input){runner=input;return{};}}}).createSecureShopMcpTrustBoundRunner;
 for(const scenario of ['rogue_registration','rug_pull']){
  const schema=mcpSchema(scenario),workflow=scenario==='rogue_registration'?'mcp-rogue':'mcp-rug-pull';
  const input={schema,feature:{ready:true,assessment:{assessmentFactory:noop},createExternalAdapter(){effects++;return{};}},checkCurrent:noop,capturePersonaAuthority:noop,toolPolicyRepository:{async admitTool(value){observed=value;return{runId:value.runId,invocationId:value.invocationId,toolKey:workflow+'.forecast_lookup',registrySha256:REGISTRY_SHA256};}}};
  create(input);schema.schemaSha256='c'.repeat(64);schema.tools[0].name='forged';
  await runner.toolPolicyAdmission({scope:{},persona:{id:7,role:'admin'},personaSession:{sessionId:'original',authorityVersion:'2'},runId:'run',invocationId:'1:call',agent:'owned-'+scenario,tool:'forecast_lookup',args:{}});
  assert.equal(observed.workflow,workflow);assert.equal(observed.admittedMcp.schema.schemaSha256,'b'.repeat(64));assert.equal(observed.admittedMcp.schema.tools[0].name,'forecast_lookup');
  const before=effects;assert.throws(()=>create({...input,schema:mcpSchema(scenario),capturePersonaAuthority:undefined}));assert.throws(()=>create({...input,schema:mcpSchema(scenario),toolPolicyRepository:{}}));assert.equal(effects,before);
 }
 const schema=mcpSchema('rug_pull');create({schema,feature:{ready:true,assessment:{assessmentFactory:noop},createExternalAdapter:()=>({})},checkCurrent:noop});assert.equal(runner.toolPolicyAdmission,undefined);
});
test('MCP production forwards trusted repository to dynamic runner and rejects missing authority before effects',async()=>{
 let seen;const create=load('secureshopMcpTrustProduction',{...deps,secureshopMcpTrustAvailability:{createSecureShopMcpTrustAvailability:()=>({read:noop,assertScenario:noop})},secureshopMcpTrustComposition:{createSecureShopMcpTrustComposition:()=>({ready:true,application:{initialize:async()=>mcpSchema('rogue_registration')}})},secureshopMcpTrustBoundRunner:{createSecureShopMcpTrustBoundRunner(input){seen=input;return{runner:{run:async()=>({text:'controlled',stopReason:'end_turn'})}};}}}).createSecureShopMcpTrustProduction;
 const input=base();input.personaBindings={capture:noop};input.resetComposition.journal.lookupMcpRequest=async()=>null;
 input.resetComposition.mcpTrust={repository:{readInvocation:noop},targetPool:{ensure:noop},authorizeRotation:noop};
 input.resetComposition.launches.reserveMcpTarget=noop;
 input.toolPolicyRepository={admitTool:noop};
 input.personaAuthority={capture:async()=>({assertRemoteAdmission:noop})};input.resetComposition.conversationService.create=async()=>({id:'40000000-0000-4000-8000-000000000001'});
 const production=create(input);await production.application.run({scope:{launchId:'10000000-0000-4000-8000-000000000001',scenarioId:'20000000-0000-4000-8000-000000000001',generation:1,platformOwnerId:7,platformSessionId:8},persona:{id:9,role:'admin'},personaSession:{sessionId:'50000000-0000-4000-8000-000000000001',authorityVersion:'1'},trustScenario:'rogue_registration',requestId:'30000000-0000-4000-8000-000000000001'});assert.equal(seen.toolPolicyRepository,input.toolPolicyRepository);assert.equal(typeof seen.capturePersonaAuthority,'function');
 // Production constructor validates the authority/repository before constructing any feature.
 assert.throws(()=>create({...input,personaAuthority:undefined}),{code:'BOUND_MCP_UNAVAILABLE'});
 assert.throws(()=>create({...input,toolPolicyRepository:{}}),{code:'BOUND_MCP_UNAVAILABLE'});
 assert.deepEqual(create({toolPolicyRepository:{}}),{ready:false});
});
