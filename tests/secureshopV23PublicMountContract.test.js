'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
const ROOT=path.resolve(__dirname,'..');
const fixture=path.join(ROOT,'tests/postgres/secureshopV23PublicRendered.integration.test.js');
const requireFixture=require('node:module').createRequire(fixture);
const noEffect=()=>{throw Error('OFFLINE_EFFECT_FORBIDDEN')};
const pool={query:noEffect,connect:noEffect};
require('node:test')('V23 public standalone mount binds optional panels without weakening readiness',async()=>{
 const prior=Object.fromEntries(['PLATFORM_DATABASE_ENGINE','WORKSHOP_DATABASE_ENGINE','SS_PERSONA_INBOX_READY','SS_MCP_TRUST_READY','SS_CONTROLLED_SSRF_READY','SS_AUDIT_SUMMARY_ENABLED'].map(k=>[k,process.env[k]]));
 const cleanup=requireFixture('../../server/services/secureshopCleanupComposition')
  .createSecureShopCleanupComposition({identityPool:pool,agentsPool:pool,reviewPool:pool,leasePool:pool});
 const composition=requireFixture('../../server/services/secureshopBoundReviewComposition')
  .createSecureShopBoundReviewComposition({identityPool:pool,agentsPool:pool,reviewPool:pool,commercePool:pool,
   resetComposition:cleanup,fixtures:[],requiredObjectives:['ss_stored_browser_execution'],
   jwtSecret:'v23-public-admin-disposable-persona-secret-32-bytes',
   agentRuntime:{provider:{chat:noEffect,finalResponse:noEffect,routeWorkflow:noEffect}}});
 try{
  const auth=requireFixture('../../server/services/secureshopStandaloneAuth').createSecureShopStandaloneAuthService({
   repository:requireFixture('../../server/database/postgres/secureshopStandaloneAuthRepository').createSecureShopStandaloneAuthRepository({pool})});
  const modes=requireFixture('../../server/database/postgres/secureshopModeRepository').createSecureShopModeRepository(pool);
  const scenes=requireFixture('../../server/services/secureshopScenes').createSecureShopScenes({
   repository:requireFixture('../../server/database/postgres/secureshopSceneRepository').createSecureShopSceneRepository({pool,launches:cleanup.launches}),reviewPool:pool,launches:cleanup.launches});
  const source=fs.readFileSync(fixture,'utf8');
  const start=source.indexOf("  const bootstrap=require('../../server/services/secureshopStandaloneBootstrap')",source.indexOf('async function runPublicNative'));
  const end=source.indexOf("  stage='mount-bound';",start);assert(start>0&&end>start);
  const make=new (Object.getPrototypeOf(async function(){}).constructor)('require','composition','auth','cleanup','identity','review','commerce','scenes','modes','grading','registry','randomBytes','step',source.slice(start,end)+'\nreturn mounted;');
  // Use the actual fixture's standalone assembly and real production constructors.
  // No database readiness calls, transport, server listen, browser or model are run.
  const mounted=await make(requireFixture,composition,auth,cleanup,pool,pool,pool,scenes,modes,
   {personaAuthority:{capture:noEffect}},{ready:false},require('node:crypto').randomBytes,async()=>undefined);
  const readiness=requireFixture('../../server/routes/secureshopRuntimeReadiness').standaloneReadiness;
  assert.equal(readiness(mounted,{personaInboxFeature:false}).ready,true);
  process.env.PLATFORM_DATABASE_ENGINE='postgres';process.env.WORKSHOP_DATABASE_ENGINE='postgres';
  delete process.env.SS_PERSONA_INBOX_READY;
  process.env.SS_MCP_TRUST_READY='false';process.env.SS_CONTROLLED_SSRF_READY='false';process.env.SS_AUDIT_SUMMARY_ENABLED='false';
  const options={engine:'postgres',shopEnabled:true,applicationMode:'standalone',authenticateToken:noEffect,
   audit:noEffect,agentRuntime:{},getComposition:async()=>({...mounted,ownerResetService:{...mounted.ownerResetService,async assertReady(){return true}}})};
  const create=requireFixture('../../server/services/secureshopBoundApplication').createSecureShopBoundApplication;
  await assert.rejects(create(options),{name:'TypeError',message:'Standalone SecureShop core readiness incomplete'});
  process.env.SS_PERSONA_INBOX_READY='false';
  const bound=await create(options);assert.equal(bound.standaloneReadiness.ready,true);
  process.env.SS_PERSONA_INBOX_READY='true';
  await assert.rejects(create(options),{name:'TypeError',message:'Standalone SecureShop core readiness incomplete'});
  process.env.SS_PERSONA_INBOX_READY='false';
  for(const flag of ['SS_MCP_TRUST_READY','SS_CONTROLLED_SSRF_READY']){
   process.env[flag]='true';
   await assert.rejects(create(options),{name:'TypeError',message:'Standalone SecureShop core readiness incomplete'});
   process.env[flag]='false';
  }
  const incomplete={...mounted,standaloneAuth:{...mounted.standaloneAuth,reset:null}};
  await assert.rejects(create({...options,getComposition:async()=>({...incomplete,ownerResetService:{...mounted.ownerResetService,async assertReady(){return true}}})}),
   {name:'TypeError',message:'Standalone SecureShop core readiness incomplete'});
 }finally{await composition.closeBrowserAssessment();for(const [key,value]of Object.entries(prior)){if(value===undefined)delete process.env[key];else process.env[key]=value;}}
});

