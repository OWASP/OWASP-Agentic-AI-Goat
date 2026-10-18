'use strict';
const {isAssessmentReleaseAllowed}=require('../config/secureshopCurriculum');
const {isDeepStrictEqual}=require('node:util');
const {assertSecureShopStandalonePrincipal}=require('./secureshopStandaloneAuth');
const {createLaunchScope,createConversationBinding}=require('./secureshopConversationBinding');
const {captureFeatureMode}=require('./secureshopFeatureModeAuthority');
const {createSecureShopAssessmentSubjects}=require('./secureshopAssessmentSubject');
const {createSecureShopAssessmentStore}=require('../database/postgres/secureshopAssessmentStore');
const {createObjectiveCompletionService}=require('./objectiveCompletionService');
const {JUDGE_VERSION,createObjectiveJudge,prepareJudgeInput}=require('../agent-runtime/objectiveJudge');
const {canRetryJudgeError}=require('../agent-runtime/judgeErrors');
const {createHash}=require('node:crypto');
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const fail=code=>Object.assign(Error('Shop assessment recovery unavailable'),{code});
const iso=value=>value===null?null:new Date(value).toISOString();
async function assertIdorRecoveryPacket({row,prepared,modeAuthority,scenes,qualifyModel}){
 if(!modeAuthority||typeof scenes?.readExisting!=='function'||typeof qualifyModel!=='function'
  ||prepared?.input?.role!=='customer')throw fail('SECURESHOP_FEATURE_MODE_STALE');
 let packet,effect;try{packet=JSON.parse(row.packet);
  effect=packet.evidence.find(item=>item.id==='idor_effect').content;
 }catch{throw fail('SECURESHOP_FEATURE_MODE_STALE');}
 const binding=createConversationBinding(prepared.input.scope,
  {id:prepared.input.personaId,role:prepared.input.role});
 const token=await captureFeatureMode(modeAuthority,binding,'customer_idor');
 const scene=await scenes.readExisting(binding);
 if(token.snapshot.mode!=='vuln'||!isDeepStrictEqual(effect?.scope,prepared.input.scope)
  ||effect.personaId!==prepared.input.personaId
  ||effect.personaSessionId!==prepared.input.sessionId
  ||effect.authorityVersion!==prepared.input.authorityVersion
  ||!isDeepStrictEqual(effect.mode,token.snapshot)
  ||effect.action!==(row.objective_id==='ss_idor_cart_delete'?'cart_remove':'order_status')
  ||scene?.targetId!==effect.targetId||scene?.scene?.sceneId!==effect.sceneId
  ||scene.scene.sceneGeneration!==effect.sceneGeneration
  ||scene.scene.grantId!==effect.grantId)throw fail('SECURESHOP_FEATURE_MODE_STALE');
 const guard=require('./secureshopIdorLessonEvidence').createIdorLessonJudgeGuard(
  async()=>true,qualifyModel);
 if(await guard(packet)!==true)throw fail('SECURESHOP_FEATURE_MODE_STALE');
 await token.assertCurrent();
 return {async assertCurrent(){await token.assertCurrent();
  const current=await scenes.readExisting(binding);
  if(current?.targetId!==effect.targetId||!isDeepStrictEqual(current.scene,scene.scene))
   throw fail('SECURESHOP_FEATURE_MODE_STALE');
  await token.assertCurrent();}};
}
function createSecureShopAssessmentRecovery({identityPool,authService,bootstrap,launches,personaAuth,personaAuthority,
 modeAuthority,scenes,systemConfigAssessment,analyticsNlSqlAssessment,qualifyAnalyticsModel,mcpDescriptionAssessment,qualifyIdorModel,couponAssessment,couponBlindAssessment,v01AuditAssessment,uploadAssessment,polyglotUploadAssessment,traversalAssessment,svgUploadAssessment,fileSummaryAssessment,filePathSummaryAssessment,mailAgentReadAssessment,productUnionAssessment,orderStatusErrorAssessment,qualifyCouponModel,ticketAssessment,mcpManifestAssessment,mcpRegistrySsrfAssessment,userLookupAssessment,searchEchoAssessment,manualRagAssessment,productSummaryAssessment,agencyRoleAssessment,systemDiagnosticAssessment,systemRestartInjectionAssessment,mailInlineAssessment,mailHtmlInjectionAssessment,coordinatorFactory=family=>require('../agent-runtime/runCoordinator').createRunCoordinator({family}),judge}={}){
 if(typeof identityPool?.query!=='function'||typeof authService?.establishTenantContext!=='function'
  ||typeof bootstrap!=='function'||typeof launches?.resolveCapability!=='function'
  ||typeof personaAuth?.authenticateBoundToken!=='function'||typeof personaAuthority?.capture!=='function'
  ||typeof coordinatorFactory!=='function'||(judge!==undefined&&typeof judge!=='function'))throw TypeError('Shop recovery dependencies required');
 const coordinators=new Map(),subjects=createSecureShopAssessmentSubjects({identityPool,launches,personaAuthority});
 async function prepare(base){
  const context=assertSecureShopStandalonePrincipal(await authService.establishTenantContext(base));
  const ready=await bootstrap(base),raw=await launches.resolveCapability(ready.bearer),scope=createLaunchScope(raw);
  if(scope.platformOwnerId!==context.ownerId||scope.platformSessionId!==context.sessionId)throw fail('SHOP_ASSESSMENT_STALE');
  const actor=await personaAuth.authenticateBoundToken({scope,token:ready.persona.token});
  if(actor?.user?.id!==context.shopUserId)throw fail('SHOP_ASSESSMENT_STALE');
  const input={scope,personaId:actor.user.id,role:actor.user.role,sessionId:actor.sessionId,authorityVersion:actor.authorityVersion};
  const fence=personaAuthority.capture(input);await fence.assertRemoteAdmission();
  return {context,input,fence};
 }
 function originalAuthority(row,prepared){
  const x=row.execution_json,p=prepared.input,c=prepared.context;
  return x?.tenantId===c.tenantId&&x.principalId===c.principalId&&x.shopUserId===c.shopUserId
   &&x.membershipVersion===c.membershipVersion&&isDeepStrictEqual(x.scope,p.scope)
   &&x.personaSessionId===p.sessionId&&x.personaAuthorityVersion===p.authorityVersion&&x.role===p.role;
 }
 async function rows(prepared,id){
  const c=prepared.context;
  return (await identityPool.query(`SELECT j.*,m.mode AS live_mode,m.generation AS live_generation,m.revision::text AS live_revision,
   o.catalog_active,o.qualification,COALESCE(cfg.is_enabled,o.is_enabled) AS enabled,
   g.generation::text AS live_owner_generation,r.child_id,child.verdict AS child_verdict,
   (SELECT count(*)::int FROM secureshop_auth.assessment_retry_invocations i
     WHERE i.tenant_id=j.tenant_id AND i.principal_id=j.principal_id AND i.parent_id=j.evaluation_id) AS retry_count,
   EXISTS(SELECT 1 FROM secureshop_auth.assessment_retries parent
     WHERE parent.tenant_id=j.tenant_id AND parent.principal_id=j.principal_id AND parent.child_id=j.evaluation_id) AS is_child
   FROM secureshop_auth.assessment_judgments j
   JOIN secureshop_auth.assessment_objectives o USING(objective_id)
   JOIN secureshop_auth.tenant_modes m ON m.tenant_id=j.tenant_id AND m.principal_id=j.principal_id
   LEFT JOIN secureshop_auth.assessment_configuration cfg ON cfg.tenant_id=j.tenant_id AND cfg.objective_id=j.objective_id
   LEFT JOIN graph_runtime.owners g ON g.owner_key=j.owner_key
   LEFT JOIN secureshop_auth.assessment_retries r ON r.tenant_id=j.tenant_id AND r.principal_id=j.principal_id AND r.parent_id=j.evaluation_id
   LEFT JOIN secureshop_auth.assessment_judgments child ON child.tenant_id=r.tenant_id AND child.principal_id=r.principal_id AND child.evaluation_id=r.child_id
   WHERE j.tenant_id=$1 AND j.principal_id=$2 AND ($3::uuid IS NULL OR j.evaluation_id=$3)
   ORDER BY j.created_at DESC,j.evaluation_id DESC LIMIT 20`,[c.tenantId,c.principalId,id??null])).rows;
 }
 async function featureFence(row,prepared){
  if(row.objective_id==='ss_audit_unbounded_observation'){
   const {AUDIT_UNBOUNDED_RUBRIC_V2,AUDIT_UNBOUNDED_RUBRIC_V3}=require('./secureshopAuditUnboundedEvidence');
   // Historical packets remain readable, but the unscoped v1 contract must
   // never create a new retry judgment or award. Do not upgrade stored bytes.
   if(prepared.input.role!=='admin'||![AUDIT_UNBOUNDED_RUBRIC_V2,AUDIT_UNBOUNDED_RUBRIC_V3].includes(row.rubric_version))
    throw fail('RETRY_NOT_ALLOWED');
   let checked;try{checked=prepareJudgeInput(JSON.parse(row.packet));}catch{throw fail('RETRY_NOT_ALLOWED');}
   if(checked.evidenceError||checked.packet!==row.packet||checked.evidenceDigest!==row.evidence_digest
    ||checked.rubric.objectiveId!==row.objective_id||checked.rubric.version!==row.rubric_version
    ||checked.rubric.family!==row.family||checked.rubric.scenario!==row.scenario||checked.rubric.mode!==row.mode)
    throw fail('RETRY_NOT_ALLOWED');
   return null;
  }
  if(row.objective_id==='ss_system_credential_disclosure'){
   if(prepared.input.role!=='admin'||typeof systemConfigAssessment?.assertCredentialRetainedPacket!=='function')
    throw fail('SECURESHOP_FEATURE_MODE_STALE');
   let packet;try{packet=JSON.parse(row.packet)}catch{throw fail('SECURESHOP_FEATURE_MODE_STALE')}
   const checked=prepareJudgeInput(packet),input=prepared.input;
   if(checked.evidenceError||checked.packet!==row.packet||checked.evidenceDigest!==row.evidence_digest
    ||checked.rubric.objectiveId!==row.objective_id||checked.rubric.version!==row.rubric_version
    ||checked.rubric.family!==row.family||checked.rubric.scenario!==row.scenario||checked.rubric.mode!==row.mode)
    throw fail('SECURESHOP_FEATURE_MODE_STALE');
   const fence=await systemConfigAssessment.assertCredentialRetainedPacket({packet,scope:input.scope,
    persona:{id:input.personaId,role:input.role},
    personaSession:{sessionId:input.sessionId,authorityVersion:input.authorityVersion}});
   if(typeof fence?.assertCurrent!=='function')throw fail('SECURESHOP_FEATURE_MODE_STALE');
   await fence.assertCurrent();return fence;
  }
  if(row.objective_id==='ss_auth_bypass_jwt_none'){
   if(prepared.input.role!=='customer'||typeof v01AuditAssessment?.assertRetainedPacket!=='function')
    throw fail('SECURESHOP_FEATURE_MODE_STALE');
   let packet;try{packet=JSON.parse(row.packet);}catch{throw fail('SECURESHOP_FEATURE_MODE_STALE');}
   const checked=prepareJudgeInput(packet),input=prepared.input;
   if(checked.evidenceError||checked.packet!==row.packet||checked.evidenceDigest!==row.evidence_digest
    ||checked.rubric.objectiveId!==row.objective_id||checked.rubric.version!==row.rubric_version
    ||checked.rubric.family!==row.family||checked.rubric.scenario!==row.scenario
    ||checked.rubric.mode!==row.mode)throw fail('SECURESHOP_FEATURE_MODE_STALE');
   const fence=await v01AuditAssessment.assertRetainedPacket({packet,scope:input.scope,
    persona:{id:input.personaId,role:input.role},
    personaSession:{sessionId:input.sessionId,authorityVersion:input.authorityVersion}});
   if(typeof fence?.assertCurrent!=='function')throw fail('SECURESHOP_FEATURE_MODE_STALE');
   await fence.assertCurrent();return fence;
  }
  if(row.objective_id==='ss_upload_extension_bypass'){
   if(prepared.input.role!=='customer'||typeof uploadAssessment?.assertRetainedPacket!=='function')
    throw fail('SECURESHOP_FEATURE_MODE_STALE');
   let packet;try{packet=JSON.parse(row.packet);}catch{throw fail('SECURESHOP_FEATURE_MODE_STALE');}
   const checked=prepareJudgeInput(packet),input=prepared.input;
   if(checked.evidenceError||checked.packet!==row.packet||checked.evidenceDigest!==row.evidence_digest
    ||checked.rubric.objectiveId!==row.objective_id||checked.rubric.version!==row.rubric_version
    ||checked.rubric.family!==row.family||checked.rubric.scenario!==row.scenario
    ||checked.rubric.mode!==row.mode)throw fail('SECURESHOP_FEATURE_MODE_STALE');
   const fence=await uploadAssessment.assertRetainedPacket({packet,scope:input.scope,
    persona:{id:input.personaId,role:input.role},
    personaSession:{sessionId:input.sessionId,authorityVersion:input.authorityVersion}});
   if(typeof fence?.assertCurrent!=='function')throw fail('SECURESHOP_FEATURE_MODE_STALE');
   await fence.assertCurrent();return fence;
  }
  if(row.objective_id==='ss_upload_polyglot_server_execution'){
   if(prepared.input.role!=='customer'||typeof polyglotUploadAssessment?.assertRetainedPacket!=='function')
    throw fail('SECURESHOP_FEATURE_MODE_STALE');
   let packet;try{packet=JSON.parse(row.packet);}catch{throw fail('SECURESHOP_FEATURE_MODE_STALE');}
   const checked=prepareJudgeInput(packet),input=prepared.input;
   if(checked.evidenceError||checked.packet!==row.packet||checked.evidenceDigest!==row.evidence_digest
    ||checked.rubric.objectiveId!==row.objective_id||checked.rubric.version!==row.rubric_version
    ||checked.rubric.family!==row.family||checked.rubric.scenario!==row.scenario
    ||checked.rubric.mode!==row.mode)throw fail('SECURESHOP_FEATURE_MODE_STALE');
   const fence=await polyglotUploadAssessment.assertRetainedPacket({packet,scope:input.scope,
    persona:{id:input.personaId,role:input.role},
    personaSession:{sessionId:input.sessionId,authorityVersion:input.authorityVersion}});
   if(typeof fence?.assertCurrent!=='function')throw fail('SECURESHOP_FEATURE_MODE_STALE');
   await fence.assertCurrent();return fence;
  }
  if(row.objective_id==='ss_upload_path_traversal_write'){
   if(prepared.input.role!=='customer'||typeof traversalAssessment?.assertRetainedPacket!=='function')
    throw fail('SECURESHOP_FEATURE_MODE_STALE');
   let packet;try{packet=JSON.parse(row.packet);}catch{throw fail('SECURESHOP_FEATURE_MODE_STALE');}
   const checked=prepareJudgeInput(packet),input=prepared.input;
   if(checked.evidenceError||checked.packet!==row.packet||checked.evidenceDigest!==row.evidence_digest
    ||checked.rubric.objectiveId!==row.objective_id||checked.rubric.version!==row.rubric_version
    ||checked.rubric.family!==row.family||checked.rubric.scenario!==row.scenario
    ||checked.rubric.mode!==row.mode)throw fail('SECURESHOP_FEATURE_MODE_STALE');
   const fence=await traversalAssessment.assertRetainedPacket({packet,scope:input.scope,
    persona:{id:input.personaId,role:input.role},
    personaSession:{sessionId:input.sessionId,authorityVersion:input.authorityVersion}});
   if(typeof fence?.assertCurrent!=='function')throw fail('SECURESHOP_FEATURE_MODE_STALE');
   await fence.assertCurrent();return fence;
  }
  if(row.objective_id==='ss_file_upload_instruction_adoption'){
   if(prepared.input.role!=='customer'||typeof fileSummaryAssessment?.assertRetainedPacket!=='function')
    throw fail('SECURESHOP_FEATURE_MODE_STALE');
   let packet;try{packet=JSON.parse(row.packet);}catch{throw fail('SECURESHOP_FEATURE_MODE_STALE');}
   const checked=prepareJudgeInput(packet),input=prepared.input;
   if(checked.evidenceError||checked.packet!==row.packet||checked.evidenceDigest!==row.evidence_digest
    ||checked.rubric.objectiveId!==row.objective_id||checked.rubric.version!==row.rubric_version
    ||checked.rubric.family!==row.family||checked.rubric.scenario!==row.scenario
    ||checked.rubric.mode!==row.mode)throw fail('SECURESHOP_FEATURE_MODE_STALE');
   const fence=await fileSummaryAssessment.assertRetainedPacket({packet,scope:input.scope,
    persona:{id:input.personaId,role:input.role},
    personaSession:{sessionId:input.sessionId,authorityVersion:input.authorityVersion}});
   if(typeof fence?.assertCurrent!=='function')throw fail('SECURESHOP_FEATURE_MODE_STALE');
   await fence.assertCurrent();return fence;
  }
  if(row.objective_id==='ss_file_path_traversal_read'){
   if(prepared.input.role!=='customer'||typeof filePathSummaryAssessment?.assertRetainedPacket!=='function')
    throw fail('SECURESHOP_FEATURE_MODE_STALE');
   let packet,checked;try{packet=JSON.parse(row.packet);checked=prepareJudgeInput(packet);}
   catch{throw fail('SECURESHOP_FEATURE_MODE_STALE');}
   const input=prepared.input;
   if(checked.evidenceError||checked.packet!==row.packet||checked.evidenceDigest!==row.evidence_digest
    ||checked.rubric.objectiveId!==row.objective_id||checked.rubric.version!==row.rubric_version
    ||checked.rubric.family!==row.family||checked.rubric.scenario!==row.scenario
    ||checked.rubric.mode!==row.mode)throw fail('SECURESHOP_FEATURE_MODE_STALE');
   const fence=await filePathSummaryAssessment.assertRetainedPacket({packet,scope:input.scope,
    persona:{id:input.personaId,role:input.role},
    personaSession:{sessionId:input.sessionId,authorityVersion:input.authorityVersion}});
   if(typeof fence?.assertCurrent!=='function')throw fail('SECURESHOP_FEATURE_MODE_STALE');
   await fence.assertCurrent();return fence;
  }
  if(row.objective_id==='ss_sqli_nl_generated'){
   if(!['merchant','admin'].includes(prepared.input.role)||typeof analyticsNlSqlAssessment?.assertRetainedPacket!=='function')
    throw fail('SECURESHOP_FEATURE_MODE_STALE');
   let packet;try{packet=JSON.parse(row.packet);}catch{throw fail('SECURESHOP_FEATURE_MODE_STALE');}
   const checked=prepareJudgeInput(packet),input=prepared.input;
   if(checked.evidenceError||checked.packet!==row.packet||checked.evidenceDigest!==row.evidence_digest
    ||checked.rubric.objectiveId!==row.objective_id||checked.rubric.version!==row.rubric_version
    ||checked.rubric.family!==row.family||checked.rubric.scenario!==row.scenario
    ||checked.rubric.mode!==row.mode)throw fail('SECURESHOP_FEATURE_MODE_STALE');
   const fence=await analyticsNlSqlAssessment.assertRetainedPacket({packet,scope:input.scope,
    persona:{id:input.personaId,role:input.role},
    personaSession:{sessionId:input.sessionId,authorityVersion:input.authorityVersion}});
   if(typeof fence?.assertCurrent!=='function')throw fail('SECURESHOP_FEATURE_MODE_STALE');
   await fence.assertCurrent();return fence;
  }
  if(row.objective_id==='ss_mail_agent_cross_persona_read'){
   if(prepared.input.role!=='merchant'||typeof mailAgentReadAssessment?.assertRetainedPacket!=='function')
    throw fail('SECURESHOP_FEATURE_MODE_STALE');
   let packet,checked;try{packet=JSON.parse(row.packet);checked=prepareJudgeInput(packet);}
   catch{throw fail('SECURESHOP_FEATURE_MODE_STALE');}
   const input=prepared.input;
   if(checked.evidenceError||checked.packet!==row.packet||checked.evidenceDigest!==row.evidence_digest
    ||checked.rubric.objectiveId!==row.objective_id||checked.rubric.version!==row.rubric_version
    ||checked.rubric.family!==row.family||checked.rubric.scenario!==row.scenario
    ||checked.rubric.mode!==row.mode)throw fail('SECURESHOP_FEATURE_MODE_STALE');
   const fence=await mailAgentReadAssessment.assertRetainedPacket({packet,scope:input.scope,
    persona:{id:input.personaId,role:input.role},
    personaSession:{sessionId:input.sessionId,authorityVersion:input.authorityVersion}});
   if(typeof fence?.assertCurrent!=='function')throw fail('SECURESHOP_FEATURE_MODE_STALE');
   await fence.assertCurrent();return fence;
  }
  if(row.objective_id==='ss_upload_svg_browser_execution'){
   if(prepared.input.role!=='customer'||typeof svgUploadAssessment?.assertRetainedPacket!=='function')
    throw fail('SECURESHOP_FEATURE_MODE_STALE');
   let packet;try{packet=JSON.parse(row.packet);}catch{throw fail('SECURESHOP_FEATURE_MODE_STALE');}
   const checked=prepareJudgeInput(packet),input=prepared.input;
   if(checked.evidenceError||checked.packet!==row.packet||checked.evidenceDigest!==row.evidence_digest
    ||checked.rubric.objectiveId!==row.objective_id||checked.rubric.version!==row.rubric_version
    ||checked.rubric.family!==row.family||checked.rubric.scenario!==row.scenario
    ||checked.rubric.mode!==row.mode)throw fail('SECURESHOP_FEATURE_MODE_STALE');
   const fence=await svgUploadAssessment.assertRetainedPacket({packet,scope:input.scope,
    persona:{id:input.personaId,role:input.role},
    personaSession:{sessionId:input.sessionId,authorityVersion:input.authorityVersion}});
   if(typeof fence?.assertCurrent!=='function')throw fail('SECURESHOP_FEATURE_MODE_STALE');
   await fence.assertCurrent();return fence;
  }
  if(row.objective_id==='ss_mail_inline_image_ssrf'){
   if(prepared.input.role!=='merchant'||typeof mailInlineAssessment?.assertRetainedPacket!=='function')
    throw fail('SECURESHOP_FEATURE_MODE_STALE');
   let packet;try{packet=JSON.parse(row.packet);}catch{throw fail('SECURESHOP_FEATURE_MODE_STALE');}
   const checked=prepareJudgeInput(packet);
   if(checked.evidenceError||checked.evidenceDigest!==row.evidence_digest
    ||checked.rubric.objectiveId!==row.objective_id||checked.rubric.family!==row.family
    ||checked.rubric.scenario!==row.scenario||checked.rubric.version!==row.rubric_version
    ||checked.rubric.mode!==row.mode)throw fail('SECURESHOP_FEATURE_MODE_STALE');
   const input=prepared.input;
   const fence=await mailInlineAssessment.assertRetainedPacket({packet,scope:input.scope,
    persona:{id:input.personaId,role:'merchant'},
    personaSession:{sessionId:input.sessionId,authorityVersion:input.authorityVersion}});
   if(typeof fence?.assertCurrent!=='function')throw fail('SECURESHOP_FEATURE_MODE_STALE');
   await fence.assertCurrent();return fence;
  }
  if(row.objective_id==='ss_mail_agent_html_injection'){
   if(prepared.input.role!=='merchant'||typeof mailHtmlInjectionAssessment?.assertRetainedPacket!=='function')
    throw fail('SECURESHOP_FEATURE_MODE_STALE');
   let packet;try{packet=JSON.parse(row.packet);}catch{throw fail('SECURESHOP_FEATURE_MODE_STALE');}
   const checked=prepareJudgeInput(packet),input=prepared.input;
   if(checked.evidenceError||checked.packet!==row.packet||checked.evidenceDigest!==row.evidence_digest
    ||checked.rubric.objectiveId!==row.objective_id||checked.rubric.family!==row.family
    ||checked.rubric.scenario!==row.scenario||checked.rubric.version!==row.rubric_version
    ||checked.rubric.mode!==row.mode)throw fail('SECURESHOP_FEATURE_MODE_STALE');
   const fence=await mailHtmlInjectionAssessment.assertRetainedPacket({packet,scope:input.scope,
    persona:{id:input.personaId,role:'merchant'},
    personaSession:{sessionId:input.sessionId,authorityVersion:input.authorityVersion}});
   if(typeof fence?.assertCurrent!=='function')throw fail('SECURESHOP_FEATURE_MODE_STALE');
   await fence.assertCurrent();return fence;
  }
  if(row.objective_id==='ss_search_echo_browser'){
   if(prepared.input.role!=='customer'||typeof searchEchoAssessment?.assertRetainedPacket!=='function')
    throw fail('SECURESHOP_FEATURE_MODE_STALE');
   let packet;try{packet=JSON.parse(row.packet);}catch{throw fail('SECURESHOP_FEATURE_MODE_STALE');}
   const checked=prepareJudgeInput(packet);
   if(checked.evidenceError||checked.evidenceDigest!==row.evidence_digest
    ||checked.rubric.objectiveId!==row.objective_id||checked.rubric.family!==row.family
    ||checked.rubric.scenario!==row.scenario||checked.rubric.version!==row.rubric_version
    ||checked.rubric.mode!==row.mode)throw fail('SECURESHOP_FEATURE_MODE_STALE');
   const input=prepared.input;
   const fence=await searchEchoAssessment.assertRetainedPacket({packet,scope:input.scope,
    persona:{id:input.personaId,role:'customer'},
    personaSession:{sessionId:input.sessionId,authorityVersion:input.authorityVersion}});
   if(typeof fence?.assertCurrent!=='function')throw fail('SECURESHOP_FEATURE_MODE_STALE');
   await fence.assertCurrent();return fence;
  }
  if(row.objective_id==='ss_system_diagnostic_command_execution'){
   if(prepared.input.role!=='admin'||typeof systemDiagnosticAssessment?.assertRetainedPacket!=='function')
    throw fail('SECURESHOP_FEATURE_MODE_STALE');
   let packet;try{packet=JSON.parse(row.packet);}catch{throw fail('SECURESHOP_FEATURE_MODE_STALE');}
   const checked=prepareJudgeInput(packet);
   if(checked.evidenceError||checked.evidenceDigest!==row.evidence_digest
    ||checked.rubric.objectiveId!==row.objective_id||checked.rubric.family!==row.family
    ||checked.rubric.scenario!==row.scenario||checked.rubric.version!==row.rubric_version
    ||checked.rubric.mode!==row.mode)throw fail('SECURESHOP_FEATURE_MODE_STALE');
   const input=prepared.input;
   const fence=await systemDiagnosticAssessment.assertRetainedPacket({packet,scope:input.scope,
    persona:{id:input.personaId,role:'admin'},
    personaSession:{sessionId:input.sessionId,authorityVersion:input.authorityVersion}});
   if(typeof fence?.assertCurrent!=='function')throw fail('SECURESHOP_FEATURE_MODE_STALE');
   await fence.assertCurrent();return fence;
  }
  if(row.objective_id==='ss_system_restart_command_injection'){
   if(prepared.input.role!=='admin'||typeof systemRestartInjectionAssessment?.assertRetainedPacket!=='function')
    throw fail('SECURESHOP_FEATURE_MODE_STALE');
   let packet;try{packet=JSON.parse(row.packet);}catch{throw fail('SECURESHOP_FEATURE_MODE_STALE');}
   const checked=prepareJudgeInput(packet);
   if(checked.evidenceError||checked.evidenceDigest!==row.evidence_digest
    ||checked.rubric.objectiveId!==row.objective_id||checked.rubric.family!==row.family
    ||checked.rubric.scenario!==row.scenario||checked.rubric.version!==row.rubric_version
    ||checked.rubric.mode!==row.mode)throw fail('SECURESHOP_FEATURE_MODE_STALE');
   const input=prepared.input;
   const fence=await systemRestartInjectionAssessment.assertRetainedPacket({packet,scope:input.scope,
    persona:{id:input.personaId,role:'admin'},
    personaSession:{sessionId:input.sessionId,authorityVersion:input.authorityVersion}});
   if(typeof fence?.assertCurrent!=='function')throw fail('SECURESHOP_FEATURE_MODE_STALE');
   await fence.assertCurrent();return fence;
  }
  if(row.objective_id==='ss_manual_rag_instruction_adoption'){
   if(prepared.input.role!=='customer'||typeof manualRagAssessment?.assertRetainedPacket!=='function')
    throw fail('SECURESHOP_FEATURE_MODE_STALE');
   let packet;try{packet=JSON.parse(row.packet);}catch{throw fail('SECURESHOP_FEATURE_MODE_STALE');}
   const checked=prepareJudgeInput(packet);
   if(checked.evidenceError||checked.evidenceDigest!==row.evidence_digest
    ||checked.rubric.objectiveId!==row.objective_id||checked.rubric.family!==row.family
    ||checked.rubric.scenario!==row.scenario||checked.rubric.version!==row.rubric_version
    ||checked.rubric.mode!==row.mode)throw fail('SECURESHOP_FEATURE_MODE_STALE');
   const input=prepared.input;
   const fence=await manualRagAssessment.assertRetainedPacket({packet,scope:input.scope,
    persona:{id:input.personaId,role:'customer'},
    personaSession:{sessionId:input.sessionId,authorityVersion:input.authorityVersion}});
   if(typeof fence?.assertCurrent!=='function')throw fail('SECURESHOP_FEATURE_MODE_STALE');
   await fence.assertCurrent();return fence;
  }
  if(row.objective_id==='ss_customer_role_escalation'){
   if(row.rubric_version!==require('./secureshopAgencyRoleEvidence').VERSION)
    throw fail('RETRY_NOT_ALLOWED');
   if(prepared.input.role!=='customer'||typeof agencyRoleAssessment?.assertRetainedPacket!=='function')
    throw fail('SECURESHOP_FEATURE_MODE_STALE');
   let packet;try{packet=JSON.parse(row.packet);}catch{throw fail('SECURESHOP_FEATURE_MODE_STALE');}
   const checked=prepareJudgeInput(packet),input=prepared.input;
   if(checked.evidenceError||checked.packet!==row.packet||checked.evidenceDigest!==row.evidence_digest
    ||checked.rubric.objectiveId!==row.objective_id||checked.rubric.family!==row.family
    ||checked.rubric.scenario!==row.scenario||checked.rubric.version!==row.rubric_version
    ||checked.rubric.mode!==row.mode)throw fail('SECURESHOP_FEATURE_MODE_STALE');
   const fence=await agencyRoleAssessment.assertRetainedPacket({packet,scope:input.scope,
    persona:{id:input.personaId,role:'customer'},
    personaSession:{sessionId:input.sessionId,authorityVersion:input.authorityVersion}});
   if(typeof fence?.assertCurrent!=='function')throw fail('SECURESHOP_FEATURE_MODE_STALE');
   await fence.assertCurrent();return fence;
  }
  if(row.objective_id==='ss_product_description_instruction_adoption'){
   if(prepared.input.role!=='customer'||typeof productSummaryAssessment?.assertRetainedPacket!=='function')
    throw fail('SECURESHOP_FEATURE_MODE_STALE');
   let packet;try{packet=JSON.parse(row.packet);}catch{throw fail('SECURESHOP_FEATURE_MODE_STALE');}
   const checked=prepareJudgeInput(packet);
   if(checked.evidenceError||checked.evidenceDigest!==row.evidence_digest
    ||checked.rubric.objectiveId!==row.objective_id||checked.rubric.family!==row.family
    ||checked.rubric.scenario!==row.scenario||checked.rubric.version!==row.rubric_version
    ||checked.rubric.mode!==row.mode)throw fail('SECURESHOP_FEATURE_MODE_STALE');
   const input=prepared.input;
   const fence=await productSummaryAssessment.assertRetainedPacket({packet,scope:input.scope,
    persona:{id:input.personaId,role:'customer'},
    personaSession:{sessionId:input.sessionId,authorityVersion:input.authorityVersion}});
   if(typeof fence?.assertCurrent!=='function')throw fail('SECURESHOP_FEATURE_MODE_STALE');
   await fence.assertCurrent();return fence;
  }
  if(row.objective_id==='ss_ticket_stored_browser_execution'){
   if(prepared.input.role!=='admin'||typeof ticketAssessment?.assertRetainedPacket!=='function')
    throw fail('SECURESHOP_FEATURE_MODE_STALE');
   let packet;try{packet=JSON.parse(row.packet);}catch{throw fail('SECURESHOP_FEATURE_MODE_STALE');}
   const preparedPacket=prepareJudgeInput(packet);
   if(preparedPacket.evidenceError||preparedPacket.evidenceDigest!==row.evidence_digest
    ||preparedPacket.rubric.objectiveId!==row.objective_id
    ||preparedPacket.rubric.family!==row.family
    ||preparedPacket.rubric.scenario!==row.scenario
    ||preparedPacket.rubric.version!==row.rubric_version
    ||preparedPacket.rubric.mode!==row.mode)throw fail('SECURESHOP_FEATURE_MODE_STALE');
   const input=prepared.input;
   const fence=await ticketAssessment.assertRetainedPacket({packet,scope:input.scope,
    persona:{id:input.personaId,role:'admin'},
    personaSession:{sessionId:input.sessionId,authorityVersion:input.authorityVersion}});
   if(typeof fence?.assertCurrent!=='function')throw fail('SECURESHOP_FEATURE_MODE_STALE');
   await fence.assertCurrent();return fence;
  }
  if(row.objective_id==='ss_mcp_manifest_disclosure'){
   if(prepared.input.role!=='admin'||typeof mcpManifestAssessment?.assertRetainedPacket!=='function')
    throw fail('SECURESHOP_FEATURE_MODE_STALE');
   let packet;try{packet=JSON.parse(row.packet);}catch{throw fail('SECURESHOP_FEATURE_MODE_STALE');}
   const checked=prepareJudgeInput(packet);
   if(checked.evidenceError||checked.evidenceDigest!==row.evidence_digest
    ||checked.rubric.objectiveId!==row.objective_id||checked.rubric.family!==row.family
    ||checked.rubric.scenario!==row.scenario||checked.rubric.version!==row.rubric_version
    ||checked.rubric.mode!==row.mode)throw fail('SECURESHOP_FEATURE_MODE_STALE');
   const input=prepared.input;
   const fence=await mcpManifestAssessment.assertRetainedPacket({packet,scope:input.scope,
    persona:{id:input.personaId,role:'admin'},
    personaSession:{sessionId:input.sessionId,authorityVersion:input.authorityVersion}});
   if(typeof fence?.assertCurrent!=='function')throw fail('SECURESHOP_FEATURE_MODE_STALE');
   await fence.assertCurrent();return fence;
  }
  if(row.objective_id==='ss_mcp_registry_internal_discovery'){
   if(prepared.input.role!=='admin'||typeof mcpRegistrySsrfAssessment?.assertRetainedPacket!=='function')
    throw fail('SECURESHOP_FEATURE_MODE_STALE');
   let packet;try{packet=JSON.parse(row.packet);}catch{throw fail('SECURESHOP_FEATURE_MODE_STALE');}
   const checked=prepareJudgeInput(packet);
   if(checked.evidenceError||checked.evidenceDigest!==row.evidence_digest
    ||checked.rubric.objectiveId!==row.objective_id||checked.rubric.family!==row.family
    ||checked.rubric.scenario!==row.scenario||checked.rubric.version!==row.rubric_version
    ||checked.rubric.mode!==row.mode)throw fail('SECURESHOP_FEATURE_MODE_STALE');
   const input=prepared.input;
   const fence=await mcpRegistrySsrfAssessment.assertRetainedPacket({packet,scope:input.scope,
    persona:{id:input.personaId,role:'admin'},
    personaSession:{sessionId:input.sessionId,authorityVersion:input.authorityVersion}});
   if(typeof fence?.assertCurrent!=='function')throw fail('SECURESHOP_FEATURE_MODE_STALE');
   await fence.assertCurrent();return fence;
  }
  if(row.objective_id==='ss_user_lookup_sensitive_disclosure'){
   if(prepared.input.role!=='admin'||typeof userLookupAssessment?.assertRetainedPacket!=='function')
    throw fail('SECURESHOP_FEATURE_MODE_STALE');
   let packet;try{packet=JSON.parse(row.packet);}catch{throw fail('SECURESHOP_FEATURE_MODE_STALE');}
   const checked=prepareJudgeInput(packet);
   if(checked.evidenceError||checked.evidenceDigest!==row.evidence_digest
    ||checked.rubric.objectiveId!==row.objective_id||checked.rubric.family!==row.family
    ||checked.rubric.scenario!==row.scenario||checked.rubric.version!==row.rubric_version
    ||checked.rubric.mode!==row.mode)throw fail('SECURESHOP_FEATURE_MODE_STALE');
   const input=prepared.input;
   const fence=await userLookupAssessment.assertRetainedPacket({packet,scope:input.scope,
    persona:{id:input.personaId,role:'admin'},
    personaSession:{sessionId:input.sessionId,authorityVersion:input.authorityVersion}});
   if(typeof fence?.assertCurrent!=='function')throw fail('SECURESHOP_FEATURE_MODE_STALE');
   await fence.assertCurrent();return fence;
  }
  if(row.objective_id==='ss_sqli_blind_boolean'){
   if(prepared.input.role!=='customer'||typeof couponBlindAssessment?.assertRetainedPacket!=='function')
    throw fail('SECURESHOP_FEATURE_MODE_STALE');
   let packet;try{packet=JSON.parse(row.packet);}catch{throw fail('SECURESHOP_FEATURE_MODE_STALE');}
   const checked=prepareJudgeInput(packet);
   if(checked.evidenceError||checked.evidenceDigest!==row.evidence_digest
    ||checked.rubric.objectiveId!==row.objective_id||checked.rubric.family!==row.family
    ||checked.rubric.scenario!==row.scenario||checked.rubric.version!==row.rubric_version
    ||checked.rubric.mode!==row.mode)throw fail('SECURESHOP_FEATURE_MODE_STALE');
   const input=prepared.input;
   const fence=await couponBlindAssessment.assertRetainedPacket({packet,scope:input.scope,
    persona:{id:input.personaId,role:input.role},
    personaSession:{sessionId:input.sessionId,authorityVersion:input.authorityVersion}});
   if(typeof fence?.assertCurrent!=='function')throw fail('SECURESHOP_FEATURE_MODE_STALE');
   await fence.assertCurrent();return fence;
  }
  if(row.objective_id==='ss_sqli_union'){
   if(prepared.input.role!=='customer'||typeof productUnionAssessment?.assertRetainedPacket!=='function')
    throw fail('SECURESHOP_FEATURE_MODE_STALE');
   let packet;try{packet=JSON.parse(row.packet);}catch{throw fail('SECURESHOP_FEATURE_MODE_STALE');}
   const checked=prepareJudgeInput(packet);
   if(checked.evidenceError||checked.evidenceDigest!==row.evidence_digest
    ||checked.rubric.objectiveId!==row.objective_id||checked.rubric.family!==row.family
    ||checked.rubric.scenario!==row.scenario||checked.rubric.version!==row.rubric_version
    ||checked.rubric.mode!==row.mode)throw fail('SECURESHOP_FEATURE_MODE_STALE');
   const input=prepared.input;
   const fence=await productUnionAssessment.assertRetainedPacket({packet,scope:input.scope,
    persona:{id:input.personaId,role:input.role},
    personaSession:{sessionId:input.sessionId,authorityVersion:input.authorityVersion}});
   if(typeof fence?.assertCurrent!=='function')throw fail('SECURESHOP_FEATURE_MODE_STALE');
   await fence.assertCurrent();return fence;
  }
  if(row.objective_id==='ss_sqli_error_based'){
   if(prepared.input.role!=='customer'||typeof orderStatusErrorAssessment?.assertRetainedPacket!=='function')
    throw fail('SECURESHOP_FEATURE_MODE_STALE');
   let packet;try{packet=JSON.parse(row.packet);}catch{throw fail('SECURESHOP_FEATURE_MODE_STALE');}
   const checked=prepareJudgeInput(packet);
   if(checked.evidenceError||checked.evidenceDigest!==row.evidence_digest
    ||checked.rubric.objectiveId!==row.objective_id||checked.rubric.family!==row.family
    ||checked.rubric.scenario!==row.scenario||checked.rubric.version!==row.rubric_version
    ||checked.rubric.mode!==row.mode)throw fail('SECURESHOP_FEATURE_MODE_STALE');
   const input=prepared.input;
   const fence=await orderStatusErrorAssessment.assertRetainedPacket({packet,scope:input.scope,
    persona:{id:input.personaId,role:input.role},
    personaSession:{sessionId:input.sessionId,authorityVersion:input.authorityVersion}});
   if(typeof fence?.assertCurrent!=='function')throw fail('SECURESHOP_FEATURE_MODE_STALE');
   await fence.assertCurrent();return fence;
  }
  if(row.objective_id==='ss_sqli_coupon'){
   if(typeof couponAssessment?.assertRetainedPacket!=='function'||typeof qualifyCouponModel!=='function')
    throw fail('SECURESHOP_FEATURE_MODE_STALE');
   let packet;try{packet=JSON.parse(row.packet);}catch{throw fail('SECURESHOP_FEATURE_MODE_STALE');}
   const input=prepared.input;
   const fence=await couponAssessment.assertRetainedPacket({packet,scope:input.scope,
    persona:{id:input.personaId,role:input.role},
    personaSession:{sessionId:input.sessionId,authorityVersion:input.authorityVersion}});
   if(typeof fence?.assertCurrent!=='function')throw fail('SECURESHOP_FEATURE_MODE_STALE');
   await fence.assertCurrent();return fence;
  }
  if(['ss_idor_cart_delete','ss_idor_order_status_disclosure'].includes(row.objective_id)){
   if(row.objective_id==='ss_idor_order_status_disclosure'){
    // Historical order packets stay readable by the assessment service, but
    // their older semantic rubric must never acquire a new retry judgment.
    const {IDOR_LESSON_ORDER_VERSION}=require('./secureshopIdorLessonEvidence');
    if(row.rubric_version!==IDOR_LESSON_ORDER_VERSION)throw fail('RETRY_NOT_ALLOWED');
    let checked;try{checked=prepareJudgeInput(JSON.parse(row.packet));}catch{throw fail('RETRY_NOT_ALLOWED');}
    if(checked.evidenceError||checked.packet!==row.packet
     ||checked.evidenceDigest!==row.evidence_digest
     ||checked.rubric.objectiveId!==row.objective_id
     ||checked.rubric.version!==row.rubric_version)throw fail('RETRY_NOT_ALLOWED');
   }
   return assertIdorRecoveryPacket({row,prepared,modeAuthority,scenes,
    qualifyModel:qualifyIdorModel});
  }
  if(row.objective_id==='ss_mcp_description_instruction_adoption'){
   if(prepared.input.role!=='admin'||typeof mcpDescriptionAssessment?.assertRetainedPacket!=='function')throw fail('SECURESHOP_FEATURE_MODE_STALE');
   let packet;try{packet=JSON.parse(row.packet);}catch{throw fail('SECURESHOP_FEATURE_MODE_STALE');}
   const checked=prepareJudgeInput(packet),input=prepared.input;
   if(checked.evidenceError||checked.packet!==row.packet||checked.evidenceDigest!==row.evidence_digest
    ||checked.rubric.objectiveId!==row.objective_id||checked.rubric.version!==row.rubric_version
    ||checked.rubric.family!==row.family||checked.rubric.scenario!==row.scenario||checked.rubric.mode!==row.mode)throw fail('SECURESHOP_FEATURE_MODE_STALE');
   const fence=await mcpDescriptionAssessment.assertRetainedPacket({packet,scope:input.scope,persona:{id:input.personaId,role:input.role},personaSession:{sessionId:input.sessionId,authorityVersion:input.authorityVersion}});
   if(typeof fence?.assertCurrent!=='function')throw fail('SECURESHOP_FEATURE_MODE_STALE');await fence.assertCurrent();return fence;
  }
  if(row.objective_id!=='ss_mcp_server_impersonation')return null;
  if(!modeAuthority)throw fail('SECURESHOP_FEATURE_MODE_STALE');
  let proof;try{proof=JSON.parse(row.packet).evidence.find(item=>item.id==='mcp_invocation').content.proof;}catch{throw fail('SECURESHOP_FEATURE_MODE_STALE');}
  const binding=createConversationBinding(prepared.input.scope,{id:prepared.input.personaId,role:prepared.input.role});
  const token=await captureFeatureMode(modeAuthority,binding,'registered_mcp');
  if(token.snapshot.mode!=='vuln'||!isDeepStrictEqual(proof?.binding,binding)
   ||!isDeepStrictEqual(proof?.execution,token.snapshot))throw fail('SECURESHOP_FEATURE_MODE_STALE');
  await token.assertCurrent();return token;
 }
 function eligible(row,prepared){
  const stamp=createHash('sha256').update(JSON.stringify(['shop-tenant-mode-v1',prepared.context.tenantId,
   prepared.context.principalId,row.live_generation,row.live_revision,row.live_mode])).digest('hex');
  return Boolean(isAssessmentReleaseAllowed(row.objective_id)&&originalAuthority(row,prepared)&&!row.is_child&&row.verdict==='unavailable'&&row.disposition==='not_pass'
   &&(row.objective_id!=='ss_customer_role_escalation'
    ||row.rubric_version===require('./secureshopAgencyRoleEvidence').VERSION)
   &&(row.objective_id!=='ss_idor_order_status_disclosure'
    ||row.rubric_version===require('./secureshopIdorLessonEvidence').IDOR_LESSON_ORDER_VERSION)
   &&canRetryJudgeError(row.result_json?.errorCode)&&row.packet&&row.judge_version===JUDGE_VERSION
   &&new Date(row.created_at).getTime()+86400000>Date.now()&&row.generation===row.live_generation
   &&row.mode===row.live_mode&&row.mode_stamp===stamp&&String(row.owner_generation)===row.live_owner_generation
   &&row.catalog_active&&row.enabled&&['native-model','native-browser-judge'].includes(row.qualification)
   &&(!row.child_id||(!row.child_verdict&&row.retry_count<3)));
 }
 return Object.freeze({
  async list(base){const prepared=await prepare(base),found=await rows(prepared);await prepared.fence.assertRemoteAdmission();
   const judgments=await Promise.all(found.map(async row=>{
    let canRetry=eligible(row,prepared);
    if(canRetry){try{await featureFence(row,prepared);
     if(row.objective_id==='ss_mcp_server_impersonation')canRetry=require('./secureshopMcpImpersonationEvidence')
      .isMcpImpersonationJudgeInputValid(JSON.parse(row.packet));
    }catch{canRetry=false;}}
    return {evaluationId:row.evaluation_id,objectiveId:row.objective_id,verdict:row.verdict,
     disposition:row.disposition,createdAt:iso(row.created_at),evaluatedAt:iso(row.evaluated_at),
     canRetry,childEvaluationId:row.child_id||null};
   }));await prepared.fence.assertRemoteAdmission();return {judgments};},
  async retry(base,input){
   if(!input||Object.keys(input).join(',')!=='evaluationId'||typeof input.evaluationId!=='string'||!UUID.test(input.evaluationId))throw fail('INVALID_ARGUMENT');
   const prepared=await prepare(base),id=input.evaluationId.toLowerCase(),original=(await rows(prepared,id))[0];
   if(!original)throw fail('SHOP_ASSESSMENT_NOT_FOUND');
   if(!originalAuthority(original,prepared))throw fail('SHOP_ASSESSMENT_STALE');
   if(!isAssessmentReleaseAllowed(original.objective_id))throw fail('RETRY_NOT_ALLOWED');
   const feature=await featureFence(original,prepared);
   let owner;try{owner=JSON.parse(original.owner_key);}catch{throw fail('RETRY_NOT_ALLOWED');}
   if(!Array.isArray(owner)||owner.length!==2||owner.some(value=>typeof value!=='string'||!value||value.length>512))throw fail('RETRY_NOT_ALLOWED');
   if(!coordinators.has(owner[0]))coordinators.set(owner[0],coordinatorFactory(owner[0]));
   const audit=original.scenario==='bound_audit_summary'&&original.objective_id==='ss_audit_instruction_followed';
   const timing=audit?require('./secureshopAuditTiming').createSecureShopAuditTiming():null;
   return coordinators.get(owner[0]).run(owner[1],timing?{timeoutMs:timing.runTimeoutMs}:{},async execution=>{
    const bounded=Object.freeze({...execution,...(timing?{auditDeadline:timing.deadline()}:{}),async check(){await execution.check();await feature?.assertCurrent();await launches.assertCurrent(prepared.input.scope);await prepared.fence.assertRemoteAdmission();await feature?.assertCurrent();await execution.check();}});
    const subject=await subjects.capture(prepared.input,bounded);if(!subject)throw fail('SHOP_ASSESSMENT_STALE');
    const store=createSecureShopAssessmentStore({pool:identityPool,subject});
    const selectedJudge=judge||(timing?require('./secureshopAuditTiming').createSecureShopAuditJudge(timing):createObjectiveJudge());
    // Recovery reuses the exact persisted packet, but the policy-template
    // objective also has a structural evidence guard. Reconstruct it here so
    // a retry cannot turn an otherwise malformed immutable packet into credit.
    const guardedJudge=original.objective_id==='ss_sqli_coupon'
      ? require('./secureshopCouponAgentEvidence').createCouponAgentJudgeGuard(selectedJudge,qualifyCouponModel)
      : original.objective_id==='ss_policy_template_execution'
      ? require('./secureshopPolicyTemplateEvidence').createPolicyTemplateJudgeGuard(selectedJudge)
      : original.objective_id==='ss_system_credential_disclosure'
        ? require('./secureshopSystemCredentialEvidence').createSystemCredentialJudgeGuard(selectedJudge)
      : original.objective_id==='ss_system_config_traversal'
        ? require('./secureshopSystemConfigEvidence').createSystemConfigJudgeGuard(selectedJudge)
        : original.objective_id==='ss_mcp_manifest_disclosure'
          ? require('./secureshopMcpManifestEvidence').createMcpManifestJudgeGuard(selectedJudge)
          : original.objective_id==='ss_mcp_registry_internal_discovery'
          ? require('./secureshopMcpRegistrySsrfEvidence').createMcpRegistrySsrfJudgeGuard(selectedJudge)
        : original.objective_id==='ss_user_lookup_sensitive_disclosure'
          ? require('./secureshopUserLookupEvidence').createUserLookupJudgeGuard(selectedJudge)
        : original.objective_id==='ss_search_echo_browser'
          ? require('./secureshopSearchEchoBrowserEvidence').createSearchEchoBrowserJudgeGuard(selectedJudge,qualifyIdorModel)
        : original.objective_id==='ss_sqli_nl_generated'
          ? require('./secureshopAnalyticsNlSqlEvidence').createAnalyticsNlSqlRecoveryJudgeGuard(selectedJudge,qualifyAnalyticsModel)
        : original.objective_id==='ss_mail_agent_cross_persona_read'
          ? require('./secureshopMailAgentReadEvidence').createMailAgentReadJudgeGuard(selectedJudge,qualifyIdorModel)
        : original.objective_id==='ss_system_restart_command_injection'
          ? require('./secureshopSystemRestartInjectionEvidence').createSystemRestartInjectionJudgeGuard(selectedJudge,qualifyIdorModel)
        : original.objective_id==='ss_system_diagnostic_command_execution'
          ? require('./secureshopSystemDiagnosticEvidence').createSystemDiagnosticJudgeGuard(selectedJudge,qualifyIdorModel)
        : original.objective_id==='ss_manual_rag_instruction_adoption'
          ? require('./secureshopManualRagEvidence').createManualRagJudgeGuard(selectedJudge)
        : original.objective_id==='ss_customer_role_escalation'
          ? require('./secureshopAgencyRoleEvidence').createAgencyRoleJudgeGuard(selectedJudge,qualifyIdorModel)
        : original.objective_id==='ss_product_description_instruction_adoption'
          ? require('./secureshopProductSummaryEvidence').createProductSummaryJudgeGuard(selectedJudge)
        : original.objective_id==='ss_mcp_description_instruction_adoption'
          ? require('./secureshopMcpDescriptionEvidence').createMcpDescriptionJudgeGuard(selectedJudge,qualifyIdorModel)
        : original.objective_id==='ss_mcp_server_impersonation'
          ? require('./secureshopMcpImpersonationEvidence').createMcpImpersonationJudgeGuard(selectedJudge)
          : ['ss_idor_cart_delete','ss_idor_order_status_disclosure'].includes(original.objective_id)
            ? require('./secureshopIdorLessonEvidence').createIdorLessonJudgeGuard(selectedJudge,qualifyIdorModel)
            : selectedJudge;
    const completion=createObjectiveCompletionService({receipts:store.receipts,progress:store.progress,
      judge:packet=>store.observeJudge(packet,guardedJudge)});
    const result=await completion.retry({userId:prepared.context.ownerId,evaluationId:id,execution:bounded});
    return {evaluationId:id,childEvaluationId:result.receipt.evaluationId,verdict:result.receipt.verdict,
     disposition:result.receipt.disposition,completed:result.completed===true,replayed:result.replayed===true};
   });
  },
 });
}
module.exports={createSecureShopAssessmentRecovery,assertIdorRecoveryPacket};
