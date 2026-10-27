'use strict';
const registry=require('./secureshopOwnedMcpRegistryProduction');
// Rendered actual-model invocation and populated 0044 upgrade are qualified.
// Each installation must still pass migration, privilege and executor readiness.
const REGISTERED_INVOCATION_QUALIFIED=true;
const fail=()=>Object.assign(Error('Registered admin invocation unavailable'),{code:'MCP_REGISTRY_INVOCATION_NOT_READY'});
async function assertRegisteredInvocationReadiness({runtimePool,migrationPool}={}){
 if(typeof runtimePool?.query!=='function'||typeof migrationPool?.query!=='function'||runtimePool===migrationPool)throw fail();
 const name='0044_owned_mcp_registry_executor_mapping.sql';
 const expected=require('node:crypto').createHash('sha256').update(require('node:fs').readFileSync(require('node:path').join(__dirname,'../../db/postgres/workshop-migrations/secureshop_agents',name))).digest('hex');
 const applied=(await migrationPool.query('SELECT checksum FROM dvaia_migrations.ledger WHERE name=$1',[name])).rows[0];
 if(applied?.checksum!==expected)throw fail();
 const names=['admit_owned_mcp_invocation(jsonb,uuid)','settle_owned_mcp_invocation(uuid,uuid,text,jsonb)',
  'admit_owned_mcp_invocation_legacy(jsonb,uuid)','settle_owned_mcp_invocation_legacy(uuid,uuid,text,jsonb)'];
 for(let index=0;index<names.length;index++){
  const row=(await runtimePool.query(`SELECT p.prosecdef,has_function_privilege(current_user,p.oid,'EXECUTE') AS allowed,
   NOT EXISTS(SELECT 1 FROM aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) a WHERE a.grantee=0 AND a.privilege_type='EXECUTE') AS private
   FROM pg_proc p WHERE p.oid=to_regprocedure($1)`,['secureshop_agents.'+names[index]])).rows[0];
  if(row?.prosecdef!==true||row.private!==true||row.allowed!==(index<2))throw fail();
 }
}
function createRegisteredInvocationInfrastructure({configuration,identityPool,agentsPool}={}){
 if(!configuration)return undefined;
 const value=registry.validateConfiguration(configuration);
 let launches;
 const personaAuthority=require('../database/postgres/secureshopBoundPersonaAuthority').createSecureShopBoundPersonaAuthority({pool:agentsPool,checkCurrent:scope=>launches.assertCurrent(scope)});
 const journal=require('../database/postgres/secureshopOwnedMcpRegistryInvocationJournal').createRegistryInvocationJournal({pool:agentsPool,personaAuthority});
 const registrationJournal=require('../database/postgres/secureshopOwnedMcpRegistrationJournal').createOwnedMcpRegistrationJournal({pool:agentsPool,personaAuthority});
 launches=require('../database/postgres/secureshopLaunchRepository').createSecureShopLaunchRepository(identityPool,{ownedMcpInvocationJournal:journal,ownedMcpRegistrationJournal:registrationJournal});
 const client=require('./secureshopOwnedMcpRegistryClient').createOwnedMcpRegistryClient({baseURL:value.baseURL,token:value.token,expectedRuntimeDigest:value.runtimeDigest});
 const retirer=require('./secureshopOwnedMcpRegistryInvocationBridge').createRegistryInvocationRetirer({journal,client});
 return Object.freeze({configuration:value,agentsPool,launches,personaAuthority,journal,registrationJournal,client,retirer});
}
async function createRegisteredInvocationProduction({infrastructure,resetComposition,provider,authenticatePersona,migrationPool,modeAuthority,identityPool,gradingBootstrap,judge,assessmentReleaseAdmission}={}){
 if(!REGISTERED_INVOCATION_QUALIFIED||!infrastructure||infrastructure.configuration.enabled!==true)return Object.freeze({ready:false,async close(){}});
 const {configuration,launches,personaAuthority,journal,client}=infrastructure;
 if(!resetComposition||resetComposition.launches!==launches||resetComposition.registeredInvocation!==infrastructure
  ||typeof provider?.chat!=='function'||typeof authenticatePersona!=='function')throw fail();
 await assertRegisteredInvocationReadiness({runtimePool:infrastructure.agentsPool,migrationPool});
 await client.health();await client.invocationHealth();
 // Approval is an explicit private process policy. No registry description or
 // browser field can authorize fixed-mode tools; all are denied for now.
 const policy=Object.freeze({version:1,mode:configuration.mode,approvalPolicy:'deny-all',approved:false});
 const grading=require('./secureshopGradingBootstrap').resolveSecureShopGradingBootstrap(gradingBootstrap,
  {identityPool,agentsPool:infrastructure.agentsPool,resetComposition,assessmentReleaseAdmission});
 const impersonationAssessment=require('./secureshopMcpImpersonationAssessment').createMcpImpersonationAssessment({
  identityPool,agentsPool:infrastructure.agentsPool,launches,conversationRepository:resetComposition.conversations,
  turnJournal:resetComposition.journal,coordinator:resetComposition.runCoordinator,
  registryRepository:require('../database/postgres/secureshopOwnedMcpRegistryRepository')
    .createOwnedMcpRegistryRepository({pool:infrastructure.agentsPool,personaAuthority}),
  invocationJournal:journal,personaAuthority,personaBindings:grading.personaBindings,
  ...grading.assessmentDependencies,judge:judge||require('../agent-runtime/objectiveJudge').createObjectiveJudge(),
  qualifyModel:require('./secureshopModelQualification').createSecureShopModelQualifier(provider),modeAuthority});
 const qualifyDescription=require('./secureshopModelQualification').createSecureShopModelQualifier(provider);
 const descriptionCurrent=async(context,{signal}={})=>{
  const {createConversationBinding,createLaunchScope}=require('./secureshopConversationBinding');
  const binding=createConversationBinding(context.scope,context.persona),session=structuredClone(context.personaSession);
  if(binding.role!=='admin')throw fail();
  const fence=personaAuthority.capture({scope:binding,personaId:binding.shopUserId,role:'admin',...session});
  const token=await require('./secureshopFeatureModeAuthority').captureFeatureMode(modeAuthority,binding,'registered_mcp');
  const check=async()=>{signal?.throwIfAborted();await launches.assertCurrent(binding);await fence.assertRemoteAdmission();await token.assertCurrent();signal?.throwIfAborted();};
  await check();return {state:{scope:createLaunchScope(binding),persona:{id:binding.shopUserId,role:'admin'},personaSession:session,sourceBinding:{registeredMode:token.snapshot,personaSession:session}},check};
 };
 const descriptionSource=require('../database/postgres/secureshopMcpDescriptionEvidenceRepository').createMcpDescriptionEvidenceRepository({identityPool,launches,conversationRepository:resetComposition.conversations,journal:resetComposition.journal,
  registryRepository:require('../database/postgres/secureshopOwnedMcpRegistryRepository').createOwnedMcpRegistryRepository({pool:infrastructure.agentsPool,personaAuthority}),invocationJournal:journal,current:descriptionCurrent,qualifyModelTrace:qualifyDescription});
 const descriptionAssessment=require('./secureshopMcpDescriptionAssessment').createMcpDescriptionAssessment({identityPool,assessmentReleaseAdmission,agentsPool:infrastructure.agentsPool,launches,conversationRepository:resetComposition.conversations,coordinator:resetComposition.runCoordinator,journal:resetComposition.journal,personaAuthority,personaBindings:grading.personaBindings,...grading.assessmentDependencies,
  publicationModes:require('../database/postgres/secureshopModeRepository').createSecureShopModeRepository(identityPool),judge:judge||require('../agent-runtime/objectiveJudge').createObjectiveJudge(),current:descriptionCurrent,readSource:descriptionSource.readSource,qualifyModelTrace:qualifyDescription});
 const runtime=require('./secureshopRegisteredAdminRuntime').createRegisteredAdminRuntime({
  turns:resetComposition.turns,conversations:resetComposition.conversationService,
  conversationRepository:resetComposition.conversations,journal:resetComposition.journal,
  impersonationAssessment,descriptionAssessment,personaAuthority,provider,snapshots:require('../database/postgres/secureshopRegisteredToolSnapshot').createRegisteredToolSnapshotRepository({pool:infrastructure.agentsPool}),
  executor:client,mode:configuration.mode,modeAuthority,readApproval:async()=>false,
  observeInvocation:require('./secureshopRegisteredInvocationObservation').createRegisteredInvocationObserver({journal}),
  dispatch:packet=>require('./secureshopOwnedMcpRegistryInvocationBridge').createRegistryInvocationBridge({journal,launches,client,
   executorIdentity:{version:1,instanceId:packet.request.instanceId,runtimeDigest:packet.runtimeDigest},personaSession:packet.personaSession,policy:{...policy,mode:packet.mode}}).dispatch(packet)
 });
 let closing=false;const controllers=new Set(),pending=new Set();
 const assess=async(method,input)=>{
  if(closing)throw fail();const controller=new AbortController(),abort=()=>controller.abort();
  input.signal?.addEventListener('abort',abort,{once:true});if(input.signal?.aborted)abort();controllers.add(controller);
  const work=runtime[method]({...input,signal:controller.signal});pending.add(work);
  try{return await work;}finally{pending.delete(work);controllers.delete(controller);input.signal?.removeEventListener('abort',abort);}
 };
 const boundRuntime={readMcpDescriptionAssessment:input=>assess('readMcpDescriptionAssessment',input),assessMcpDescription:input=>assess('assessMcpDescription',input),readMcpImpersonationAssessment:input=>assess('readMcpImpersonationAssessment',input),
  retryMcpImpersonationAssessment:input=>assess('retryMcpImpersonationAssessment',input),async createSession(...args){if(closing)throw fail();return runtime.createSession(...args);},
  async readRequest(...args){if(closing)throw fail();const work=runtime.readRequest(...args);pending.add(work);
   try{return await work;}finally{pending.delete(work);}},runner:{async run(input){
  if(closing)throw fail();const controller=new AbortController(),abort=()=>controller.abort();
  input.signal?.addEventListener('abort',abort,{once:true});if(input.signal?.aborted)abort();controllers.add(controller);
  const work=runtime.runner.run({...input,signal:controller.signal});pending.add(work);
  try{return await work;}finally{pending.delete(work);controllers.delete(controller);input.signal?.removeEventListener('abort',abort);}
 }}};
 const router=require('../routes/secureshop/boundAdminChat').createBoundAdminChatRouter({launches,authenticatePersona,runtime:boundRuntime});
 return Object.freeze({ready:true,router,policy,descriptionAssessment,async close(){closing=true;for(const controller of controllers)controller.abort();await Promise.allSettled([...pending]);}});
}
module.exports={REGISTERED_INVOCATION_QUALIFIED,assertRegisteredInvocationReadiness,readConfiguration:registry.readConfiguration,createRegisteredInvocationInfrastructure,createRegisteredInvocationProduction};
