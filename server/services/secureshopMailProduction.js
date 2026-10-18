'use strict';
const {createHash}=require('node:crypto');
const {createLaunchScope}=require('./secureshopConversationBinding');
const {mapPersonaInboxFixtures}=require('./secureshopPersonaInboxComposition');
const {normalize,createBoundMailRepository}=require('../database/postgres/secureshopBoundMailRepository');
const unavailable=()=>Object.assign(Error('Bound mail production dependencies unavailable'),{code:'MAIL_UNAVAILABLE'});
// Qualified owned transport; only individually reviewed objective gates admit grading.
// Instructor visibility and configured model capability remain independent.
const PRODUCTION_QUALIFIED=true;
function mailServingEnabled(value,qualified=PRODUCTION_QUALIFIED){if(value!==undefined&&!['true','false'].includes(value))throw unavailable();return qualified===true&&value!=='false';}
function createRetainedMailBindingResolver(readExistingTarget){
 if(readExistingTarget!==undefined&&typeof readExistingTarget!=='function')throw new TypeError('Retained mail target reader required');
 return async raw=>{
  const normalized=normalize(raw);
  if(!readExistingTarget)return normalized;
  const target=await readExistingTarget(createLaunchScope(normalized.scope));
  if(typeof target?.targetId!=='string'||target.targetId!==normalized.targetId)throw unavailable();
  return normalize({...normalized,target});
 };
}
const TABLES=['lab_mail_targets','lab_mail_operation_receipts','lab_mail_cleanup_receipts',
 'mail_scene_targets','mail_scene_execution_grants','mail_scene_operation_provenance','persona_inbox_scene_access_provenance',
 'bound_mail_thread_attempts','bound_mail_preexecution_rejections','bound_mail_unresolved_detaches'];
const RECEIPT_TABLES=new Set(['bound_mail_thread_attempts','bound_mail_preexecution_rejections','bound_mail_unresolved_detaches',
 'mail_scene_targets','mail_scene_execution_grants','mail_scene_operation_provenance','persona_inbox_scene_access_provenance']);
const FUNCTIONS=['bound_lab_mail(uuid,uuid,uuid,bigint,integer,integer,integer,uuid,text,bigint,text,uuid,text,jsonb)',
 'bound_lab_mail(uuid,uuid,uuid,bigint,integer,integer,integer,uuid,text,bigint,text,uuid,text,jsonb,uuid)',
 'project_bound_lab_mail_send(uuid,uuid,uuid,bigint,integer,integer,integer,uuid,text,bigint,text,uuid,uuid)',
 'project_bound_lab_mail_read(uuid,uuid,uuid,bigint,integer,integer,integer,uuid,text,bigint,text,uuid,uuid,bigint,integer)',
 'assert_mail_scene_execution_grant(uuid,uuid,bigint,uuid,uuid,uuid,bigint,integer,integer)',
 'verify_bound_lab_mail_cleanup(uuid,uuid)'];
async function assertMailSchema(pool){
 const tables=(await pool.query("SELECT name,to_regclass('secureshop_agents.'||name) IS NOT NULL AND has_table_privilege(current_user,to_regclass('secureshop_agents.'||name),'SELECT') AND (name <> ALL($2::text[]) OR has_table_privilege(current_user,to_regclass('secureshop_agents.'||name),'INSERT')) AND NOT has_table_privilege(current_user,to_regclass('secureshop_agents.'||name),'UPDATE,DELETE,TRUNCATE,TRIGGER') AND (name = ANY($2::text[]) OR NOT has_table_privilege(current_user,to_regclass('secureshop_agents.'||name),'INSERT')) AS ready FROM unnest($1::text[]) name",[TABLES,[...RECEIPT_TABLES]])).rows;
 if(tables.length!==TABLES.length||new Set(tables.map(r=>r.name)).size!==TABLES.length||tables.some(r=>!TABLES.includes(r.name)||r.ready!==true))throw unavailable();
 const functions=(await pool.query("SELECT name,p.oid IS NOT NULL AND p.prosecdef AND has_function_privilege(current_user,p.oid,'EXECUTE') AND NOT EXISTS(SELECT 1 FROM aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) a WHERE a.grantee=0 AND a.privilege_type='EXECUTE') AS ready FROM unnest($1::text[]) name LEFT JOIN pg_proc p ON p.oid=to_regprocedure('secureshop_agents.'||name)",[FUNCTIONS])).rows;
 if(functions.length!==FUNCTIONS.length||new Set(functions.map(r=>r.name)).size!==FUNCTIONS.length||functions.some(r=>!FUNCTIONS.includes(r.name)||r.ready!==true))throw unavailable();
 const rows=(await pool.query("SELECT NOT has_table_privilege(current_user,'secureshop_agents.lab_mail_messages','SELECT,INSERT,UPDATE,DELETE,TRUNCATE,TRIGGER') AS messages_private, EXISTS(SELECT 1 FROM pg_constraint WHERE conrelid='secureshop_agents.agent_sessions'::regclass AND conname='agent_sessions_conversation_purpose_shape' AND position('secureshop_mail_reply' in pg_get_constraintdef(oid))>0) AS purpose_ready, EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='secureshop_agents.persona_inbox_cleanup_receipts'::regclass AND tgname='canonical_persona_cleanup_lab_mail' AND tgtype=5 AND tgenabled='O' AND tgfoid='secureshop_agents.cleanup_bound_lab_mail()'::regprocedure) AS cleanup_ready, position('browse' in pg_get_functiondef('secureshop_agents.bound_lab_mail(uuid,uuid,uuid,bigint,integer,integer,integer,uuid,text,bigint,text,uuid,text,jsonb,uuid)'::regprocedure))>0 AS browse_ready")).rows;
 if(rows.length!==1||Object.values(rows[0]).length!==4||Object.values(rows[0]).some(v=>v!==true))throw unavailable();
 return true;
}
async function createMailProduction({enabled=false,identityPool,agentsPool,resetComposition,personaAuthority,personaRepository,provider,promptPolicyRepository,toolPolicyRepository,assessmentDependencies,authenticatePersona,createBrowserQualification,mode='vuln',modeAuthority,mailScenes}={}){
 if(typeof enabled!=='boolean')throw unavailable();if(!enabled)return Object.freeze({ready:false});
 if(!['vuln','fixed'].includes(mode)||typeof personaAuthority?.capture!=='function'||typeof personaRepository?.listPersonas!=='function'||typeof personaRepository?.listMailActors!=='function'||typeof authenticatePersona!=='function'||typeof provider?.chat!=='function'||typeof promptPolicyRepository?.admitRunSnapshot!=='function'||typeof toolPolicyRepository?.admitTool!=='function'||typeof assessmentDependencies?.judge!=='function'||typeof assessmentDependencies?.personaBindings?.capture!=='function'||typeof resetComposition?.personaInbox?.repository?.provision!=='function'||typeof resetComposition?.cleanupAuthority?.checkTarget!=='function')throw unavailable();
 await assertMailSchema(agentsPool);
 const {launches,conversations:conversationRepository,journal,runCoordinator:coordinator}=resetComposition;
 const mailRepository=createBoundMailRepository({pool:agentsPool,personaAuthority,checkCleanup:input=>resetComposition.cleanupAuthority.checkTarget({...input,targetKind:'persona_inbox',fromGeneration:input.generation})});
 const listTemplates=()=>personaRepository.listPersonas();
 const listPersonas=scope=>personaRepository.listMailActors(scope);
 const shared={launches,personaAuthority,conversationRepository,journal,coordinator};
 const readExistingTarget=mailScenes?.readRetained
  ?scope=>mailScenes.readRetained(scope):undefined;
 const resolveRetainedBinding=createRetainedMailBindingResolver(readExistingTarget);
 const capabilities=require('./secureshopMailCapabilities').createMailCapabilities({provider,judge:assessmentDependencies.judge});
 const guardedDependencies={...assessmentDependencies,judge:require('./secureshopMailCapabilities').guardMailJudge(capabilities,assessmentDependencies.judge)};
 const uncertainRepository=require('../database/postgres/secureshopMailUncertainRepository').createMailUncertainRepository({pool:agentsPool,personaAuthority});
 const graph=require('./secureshopBoundMailGraph').createBoundMailGraph({...shared,provider,mailRepository,listPersonas,promptPolicyRepository,toolPolicyRepository,uncertainRepository,modeAuthority,assertActorAvailable:()=>capabilities.assertAvailable('actor')});
 const evidenceRepository=require('../database/postgres/secureshopMailEvidenceRepository').createMailEvidenceRepository({personaAuthority,mailRepository});
 const recoveryRepository=require('../database/postgres/secureshopMailRecoveryRepository').createMailRecoveryRepository({personaAuthority});
 const assessment=require('./secureshopMailReplyAssessment').createMailReplyAssessment({...guardedDependencies,...shared,identityPool,evidenceRepository,listPersonas,qualifyModel:require('./secureshopModelQualification').createSecureShopModelQualifier(provider)});
 const headerEvidenceRepository=require('../database/postgres/secureshopMailHeaderEvidenceRepository').createMailHeaderEvidenceRepository({personaAuthority,mailRepository});
 const headerAssessment=require('./secureshopMailHeaderAssessment').createMailHeaderAssessment({...guardedDependencies,...shared,identityPool,evidenceRepository:headerEvidenceRepository});
 const disclosureEvidenceRepository=require('./secureshopMailDisclosureEvidence').createMailDisclosureEvidenceRepository({personaAuthority,mailRepository});
 const disclosureAssessment=require('./secureshopMailDisclosureAssessment').createMailDisclosureAssessment({...guardedDependencies,...shared,identityPool,evidenceRepository:disclosureEvidenceRepository});
 let closed=false,browserInstance;
 const prepareBrowser=()=>{
  if(closed)throw unavailable();
  if(!browserInstance){
   const candidate=assessmentDependencies.mailBrowserQualification||(typeof createBrowserQualification==='function'?createBrowserQualification():null);
   if(typeof candidate?.qualifyMail!=='function'||typeof candidate?.qualifyInjection!=='function'||typeof candidate?.close!=='function'||typeof candidate?.readComponent!=='function')throw unavailable();
   browserInstance=candidate;
  }
  return browserInstance;
 };
 const browserQualification=Object.freeze({qualifyMail:input=>prepareBrowser().qualifyMail(input),qualifyInjection:input=>prepareBrowser().qualifyInjection(input),readComponent:()=>prepareBrowser().readComponent()});
 const browserAvailable=()=>{try{prepareBrowser();return true;}catch{return false;}};
 const browserEvidenceRepository=require('./secureshopMailBrowserEvidence').createMailBrowserEvidenceRepository({savedMailEvidence:headerEvidenceRepository});
 const browserAssessment=require('./secureshopMailBrowserAssessment').createMailBrowserAssessment({...guardedDependencies,...shared,identityPool,evidenceRepository:browserEvidenceRepository,browserQualification});
 const htmlInjectionOriginalReader=require('./secureshopMailHtmlInjectionOriginalReader').createMailHtmlInjectionOriginalReader({journal,conversations:conversationRepository});
 const htmlInjectionAssessment=require('./secureshopMailHtmlInjectionAssessment').createMailHtmlInjectionAssessment({...guardedDependencies,...shared,identityPool,agentsPool,savedMailEvidence:headerEvidenceRepository,originalReader:htmlInjectionOriginalReader,browserQualification,resolveRetainedBinding,qualifyModel:require('./secureshopModelQualification').createSecureShopModelQualifier(provider)});
 const readReadiness=async context=>{
  if(closed)return {ready:false};const scope=createLaunchScope(context.scope);
  const fence=personaAuthority.capture({scope,personaId:context.persona.id,role:context.persona.role,...context.personaSession});
  await launches.assertCurrent(scope);await fence.assertRemoteAdmission();
  const modeToken=await require('./secureshopFeatureModeAuthority').captureFeatureMode(modeAuthority,scope,'mail',mode);
  const modelCapabilities=await capabilities.read();await launches.assertCurrent(scope);await fence.assertRemoteAdmission();
  const objectiveReadiness={...await require('./secureshopMailObjectiveReadiness').readMailObjectiveReadiness({identityPool,scope,transportReady:true,judgeReady:true})};
  if(objectiveReadiness.ss_mail_stored_browser_execution&&!browserAvailable())objectiveReadiness.ss_mail_stored_browser_execution=false;
  await modeToken.assertCurrent();return {ready:true,modeCapability:require('./secureshopFeatureModeAuthority').projectFeatureMode(modeToken),versionedMail:true,readinessMeaning:'transport_and_catalog_admission',modelCapabilities,objectiveReadiness,scopeKey:createHash('sha256').update(JSON.stringify({scope,persona:context.persona,personaSession:context.personaSession,mode:modeToken.snapshot})).digest('hex')};
 };
 const resolveTarget=async context=>{
  const scope=createLaunchScope(context.scope);await launches.assertCurrent(scope);
  if(mailScenes){const target=await mailScenes.resolve(context);await launches.assertCurrent(scope);return target;}
  const reserved=await launches.reservePersonaInboxTarget({launchId:scope.launchId,platformSessionId:scope.platformSessionId,platformOwnerId:scope.platformOwnerId,expectedGeneration:scope.generation});
  const target={...scope,targetId:reserved.targetId};
  await resetComposition.personaInbox.repository.provision(target,{fixtures:mapPersonaInboxFixtures(await listTemplates()),mode:'advisory'});await launches.assertCurrent(scope);return target;
 };
 const application=require('./secureshopMailApplication').createMailApplication({resolveTarget,readExistingTarget,mailRepository,graph,readReadiness,recoveryRepository,uncertainRepository,assessment,headerAssessment,disclosureAssessment,browserAssessment,htmlInjectionAssessment,mode,modeAuthority});
 const router=require('../routes/secureshop/boundMail').createBoundMailRouter({application,authenticatePersona});
 // The dedicated inline-image workflow uses its own purpose and routes. Legacy
 // explicitly composed fixtures without scene authority retain only ordinary mail.
 if(mailScenes)await require('./secureshopMailInlineProduction').assertMailInlineSchema(agentsPool);
 const inline=mailScenes?require('./secureshopMailInlineProduction').createMailInlineProduction({
  identityPool,agentsPool,assessmentDependencies:guardedDependencies,shared,mailRepository,mailScenes,resolveTarget,resetComposition,listPersonas,provider,
  promptPolicyRepository,toolPolicyRepository,modeAuthority,authenticatePersona,
  assertActorAvailable:()=>capabilities.assertAvailable('actor'),mode}):null;
 if(inline)router.use(inline.router);
 return Object.freeze({ready:true,application,router,assessment,htmlInjectionAssessment,...(inline?{inline}:{}),async close(){
  closed=true;const results=await Promise.allSettled([browserInstance,inline].filter(Boolean).map(value=>value.close()));
  const failed=results.filter(value=>value.status==='rejected');if(failed.length)throw new AggregateError(failed.map(value=>value.reason),'Mail shutdown failed');
 }});
}
module.exports={createMailProduction,createRetainedMailBindingResolver,assertMailSchema,PRODUCTION_QUALIFIED,mailServingEnabled};
