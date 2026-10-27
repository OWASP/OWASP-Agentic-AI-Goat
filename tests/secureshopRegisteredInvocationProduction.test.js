'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),path=require('node:path');
const moduleUnderTest=require('../server/services/secureshopRegisteredInvocationProduction');
const root=path.resolve(__dirname,'..');
function configuration(enabled){return{version:1,workspace:require('../server/services/mcp/ownedManagedConfiguration').workspaceId(root),enabled,mode:'fixed',baseURL:'http://127.0.0.1:8094',token:'a'.repeat(43),runtimeDigest:'b'.repeat(64)};}
test('disabled serving never touches runtime dependencies',async()=>{
 assert.equal(moduleUnderTest.REGISTERED_INVOCATION_QUALIFIED,true);
 let touched=false;const infrastructure={configuration:configuration(false),get client(){touched=true;throw Error('no startup network');}};
 const result=await moduleUnderTest.createRegisteredInvocationProduction({infrastructure});assert.equal(result.ready,false);await result.close();assert.equal(touched,false);
});
test('enabled serving rejects an unbound reset or provider composition',async()=>{
 const infrastructure={configuration:configuration(true)};
 await assert.rejects(moduleUnderTest.createRegisteredInvocationProduction({infrastructure}),{code:'MCP_REGISTRY_INVOCATION_NOT_READY'});
});
test('cleanup infrastructure is lazy and retains disabled configuration without enabling serving',()=>{
 let calls=0;const pool={async query(){calls++;throw Error('no query during construction');},async connect(){calls++;throw Error('no connection during construction');}};
 for(const enabled of [false,true]){
  const original=configuration(enabled),infra=moduleUnderTest.createRegisteredInvocationInfrastructure({configuration:original,identityPool:pool,agentsPool:pool});
  original.mode='vuln';assert.equal(infra.configuration.mode,'fixed');assert.equal(infra.configuration.enabled,enabled);
  assert.equal(infra.agentsPool,pool);assert.equal(typeof infra.launches.admitOwnedMcpInvocation,'function');assert.equal(typeof infra.retirer.retire,'function');assert(Object.isFrozen(infra));
 }
 assert.equal(calls,0);assert.equal(moduleUnderTest.createRegisteredInvocationInfrastructure({}),undefined);
});
test('serving readiness requires exact0044 checksum, current wrappers and private legacy grants',async()=>{
 const expected=require('node:crypto').createHash('sha256').update(require('node:fs').readFileSync(path.join(root,'db/postgres/workshop-migrations/secureshop_agents/0044_owned_mcp_registry_executor_mapping.sql'))).digest('hex');
 const make=(fault)=>({async query(sql,args){if(sql.includes('ledger'))return{rows:[{checksum:fault==='checksum'?'0'.repeat(64):expected}]};const legacy=args[0].includes('_legacy');return{rows:fault==='missing'?[]:[{prosecdef:fault!=='definer',private:fault!=='public',allowed:legacy?fault==='legacy':fault!=='current'}]};}});
 await moduleUnderTest.assertRegisteredInvocationReadiness({runtimePool:make(),migrationPool:make()});
 for(const fault of ['checksum','missing','definer','public','legacy','current'])await assert.rejects(moduleUnderTest.assertRegisteredInvocationReadiness({runtimePool:make(fault),migrationPool:make(fault)}),{code:'MCP_REGISTRY_INVOCATION_NOT_READY'});
});

test('readiness reads ledger only through migration authority and privilege checks only through runtime',async()=>{
 const expected=require('node:crypto').createHash('sha256').update(require('node:fs').readFileSync(path.join(root,'db/postgres/workshop-migrations/secureshop_agents/0044_owned_mcp_registry_executor_mapping.sql'))).digest('hex');
 const queries=[];
 const migrationPool={async query(sql){assert(sql.includes('dvaia_migrations.ledger'));queries.push('migration');return{rows:[{checksum:expected}]};}};
 const runtimePool={async query(sql,args){assert(!sql.includes('dvaia_migrations'));assert(sql.includes('has_function_privilege'));queries.push('runtime');return{rows:[{prosecdef:true,private:true,allowed:!args[0].includes('_legacy')}]};}};
 await moduleUnderTest.assertRegisteredInvocationReadiness({runtimePool,migrationPool});assert.deepEqual(queries,['migration','runtime','runtime','runtime','runtime']);
 await assert.rejects(moduleUnderTest.assertRegisteredInvocationReadiness({runtimePool,migrationPool:runtimePool}));
});

test('composition opens migration pool only for enabled qualified serving and closes on failure',async()=>{
 const fs=require('node:fs'),vm=require('node:vm'),source=fs.readFileSync('server/services/secureshopBoundReviewComposition.js','utf8');
 const start=source.indexOf("      const invocationModule=require('./secureshopRegisteredInvocationProduction');"),end=source.indexOf('      if(createdRegisteredInvocation.ready)',start);assert(start>0&&end>start);
 for(const qualified of [false,true])for(const enabled of [false,true])for(const failed of [false,true]){
  let opens=0,closes=0;const pool={async end(){closes++;}};
  const module={REGISTERED_INVOCATION_QUALIFIED:qualified,async createRegisteredInvocationProduction(opts){assert.equal(opts.migrationPool,qualified&&enabled?pool:undefined);if(failed)throw Error('readiness denied');return{ready:false};}};
  const work=vm.runInNewContext('(async()=>{let createdRegisteredInvocation;'+source.slice(start,end)+'})()',{identityPool:{},preparedGrading:undefined,assessmentReleaseAdmission:undefined,featureModeAuthority:null,require:()=>module,resetComposition:{registeredInvocation:{configuration:{enabled}}},createPool:()=>{opens++;return pool;},process:{env:{}},snapshot:{configured:{}},value:{}});
  if(failed)await assert.rejects(work,/readiness denied/);else await work;
  assert.equal(opens,Number(qualified&&enabled));assert.equal(closes,Number(qualified&&enabled));
 }
});

test('registered production constructs separate V43 and description assessment from matching prepared grading and drains assessment reads',async()=>{
 const fs=require('node:fs'),vm=require('node:vm'),{createRequire}=require('node:module');
 const filename=path.join(root,'server/services/secureshopRegisteredInvocationProduction.js'),real=createRequire(filename);
 const identityPool={},agentsPool={async query(_sql,args){return {rows:[{prosecdef:true,private:true,allowed:!args[0].includes('_legacy')}]};}};
 const checksum=require('node:crypto').createHash('sha256').update(fs.readFileSync(path.join(root,'db/postgres/workshop-migrations/secureshop_agents/0044_owned_mcp_registry_executor_mapping.sql'))).digest('hex');
 const migrationPool={async query(){return {rows:[{checksum}]};}};
 const launches={},personaAuthority={},journal={},client={async health(){},async invocationHealth(){}};
 const infrastructure={configuration:configuration(true),agentsPool,launches,personaAuthority,journal,client};
 const resetComposition={launches,registeredInvocation:infrastructure,conversations:{},journal:{},runCoordinator:{},turns:{},conversationService:{}};
 const gradingBootstrap={},judge=()=>{},provider={async chat(){}},assessment={runAttempt:async()=>{},readOutcome:async()=>{}};
 const dependencies={receipts:{},progress:{},personaBindings:{capture(){}}};
 let captured,descriptionCaptured,routeRuntime,resolveRead,readStarted; const descriptionAssessment={},publicationModes={};
 const activeRead=new Promise(resolve=>{resolveRead=resolve;}),began=new Promise(resolve=>{readStarted=resolve;});
 const overrides={
  './secureshopGradingBootstrap':{resolveSecureShopGradingBootstrap(token,inputs){assert.equal(token,gradingBootstrap);assert.deepEqual(inputs,{identityPool,agentsPool,resetComposition,assessmentReleaseAdmission:undefined});return {...dependencies,assessmentDependencies:dependencies};}},
  '../database/postgres/secureshopModeRepository':{createSecureShopModeRepository(pool){assert.equal(pool,identityPool);return publicationModes;}},
  '../database/postgres/secureshopMcpDescriptionEvidenceRepository':{createMcpDescriptionEvidenceRepository(input){assert.equal(input.identityPool,identityPool);assert.equal(input.journal,resetComposition.journal);assert.equal(typeof input.current,'function');return{readSource:async()=>{}};}},
  './secureshopMcpDescriptionAssessment':{createMcpDescriptionAssessment(input){descriptionCaptured=input;return descriptionAssessment;}},
  './secureshopMcpImpersonationAssessment':{createMcpImpersonationAssessment(inputs){captured=inputs;return assessment;}},
  '../database/postgres/secureshopOwnedMcpRegistryRepository':{createOwnedMcpRegistryRepository:()=>({readAssessmentRevisions(){}})},
  '../database/postgres/secureshopRegisteredToolSnapshot':{createRegisteredToolSnapshotRepository:()=>({})},
  './secureshopRegisteredInvocationObservation':{createRegisteredInvocationObserver:()=>()=>{}},
  './secureshopModelQualification':{createSecureShopModelQualifier:p=>{assert.equal(p,provider);return ()=>true;}},
  './secureshopRegisteredAdminRuntime':{createRegisteredAdminRuntime(inputs){assert.equal(inputs.impersonationAssessment,assessment);assert.equal(inputs.descriptionAssessment,descriptionAssessment);return {
   createSession:async()=>({id:'saved'}),readRequest:async()=>({status:'completed'}),runner:{run:async()=>({})},
   async readMcpImpersonationAssessment(input){readStarted();await activeRead;assert.equal(input.signal.aborted,true);return {status:'unconfirmed'};},
   async retryMcpImpersonationAssessment(){return {status:'ineligible'};},async readMcpDescriptionAssessment(){return {status:'unconfirmed'};},async assessMcpDescription(){return {status:'ineligible'};}};}},
  '../routes/secureshop/boundAdminChat':{createBoundAdminChatRouter({runtime}){routeRuntime=runtime;return {};}}
 };
 const module={exports:{}};vm.runInThisContext('(function(require,module,exports,__dirname){'+fs.readFileSync(filename,'utf8')+'\n})',{filename})(name=>overrides[name]||real(name),module,module.exports,path.dirname(filename));
 const result=await module.exports.createRegisteredInvocationProduction({infrastructure,resetComposition,provider,authenticatePersona(){},migrationPool,identityPool,gradingBootstrap,judge,modeAuthority:{}});
 assert.equal(result.descriptionAssessment,descriptionAssessment);assert.equal(descriptionCaptured.publicationModes,publicationModes);assert.equal(descriptionCaptured.judge,judge);assert.equal(descriptionCaptured.personaBindings,dependencies.personaBindings);assert.equal(typeof descriptionCaptured.readSource,'function');
 assert.equal(captured.identityPool,identityPool);assert.equal(captured.personaBindings,dependencies.personaBindings);
 assert.equal(captured.receipts,dependencies.receipts);assert.equal(captured.progress,dependencies.progress);
 assert.equal(captured.turnJournal,resetComposition.journal);assert.equal(captured.invocationJournal,journal);
 assert.equal(captured.coordinator,resetComposition.runCoordinator);assert.equal(captured.judge,judge);
 const pending=routeRuntime.readMcpImpersonationAssessment({});await began;let closed=false;
 const closing=result.close().then(()=>{closed=true;});await Promise.resolve();assert.equal(closed,false);
 resolveRead();await pending;await closing;assert.equal(closed,true);
 await assert.rejects(routeRuntime.retryMcpImpersonationAssessment({}),{code:'MCP_REGISTRY_INVOCATION_NOT_READY'});
});
