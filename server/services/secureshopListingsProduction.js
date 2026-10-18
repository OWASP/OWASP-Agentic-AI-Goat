'use strict';
const crypto=require('node:crypto');
const {createLaunchScope}=require('./secureshopConversationBinding');
const fail=code=>Object.assign(new Error('Owned Listings production dependencies unavailable'),{code});
const TABLES=['admissions','events','cleanup_receipts','catalog_revisions','publications','generated_products','rewrite_saves','scene_admissions'].map(n=>'secureshop_review.owned_listing_'+n);
const FUNCTIONS=['admit_owned_listing_scene_operation(uuid,uuid,text,text,text,text,text,text,uuid)','admit_owned_listing_operation(uuid,uuid,text,text,text,text,text,text)','append_owned_listing_event(uuid,uuid,integer,text,text,text,text)','publish_owned_listing_import(uuid,uuid,integer,text)','consume_owned_listing_rewrite(uuid,uuid,text,integer,text,text,text)'].map(n=>'secureshop_review.'+n);
async function assertListingsSchema({agentsPool,reviewPool}){
 const rows=(await reviewPool.query("SELECT name,to_regclass(name) IS NOT NULL AND has_table_privilege(current_user,to_regclass(name),'SELECT') AND NOT has_table_privilege(current_user,to_regclass(name),'INSERT,UPDATE,DELETE,TRUNCATE,TRIGGER') AS ready FROM unnest($1::text[]) AS name",[TABLES])).rows;
 if(rows.length!==TABLES.length||rows.some(r=>!TABLES.includes(r.name)||r.ready!==true)||new Set(rows.map(r=>r.name)).size!==TABLES.length)throw fail('LISTINGS_SCHEMA_UNAVAILABLE');
 const functions=(await reviewPool.query("SELECT name,p.oid IS NOT NULL AND p.prosecdef AND has_function_privilege(current_user,p.oid,'EXECUTE') AND NOT EXISTS(SELECT 1 FROM aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) a WHERE a.grantee=0 AND a.privilege_type='EXECUTE') AS ready FROM unnest($1::text[]) AS name LEFT JOIN pg_proc p ON p.oid=to_regprocedure(name)",[FUNCTIONS])).rows;
 if(functions.length!==FUNCTIONS.length||functions.some(r=>!FUNCTIONS.includes(r.name)||r.ready!==true)||new Set(functions.map(r=>r.name)).size!==FUNCTIONS.length)throw fail('LISTINGS_SCHEMA_UNAVAILABLE');
 const purpose=(await agentsPool.query("SELECT pg_get_constraintdef(oid) AS definition FROM pg_constraint WHERE conrelid='secureshop_agents.agent_sessions'::regclass AND conname='agent_sessions_conversation_purpose_shape'")).rows;
 if(purpose.length!==1||!['secureshop_listing_rewrite','secureshop_listing_import','secureshop_listing_optimize'].every(s=>purpose[0].definition?.includes("'"+s+"'")))throw fail('LISTINGS_SCHEMA_UNAVAILABLE');
 const terminal=(await reviewPool.query("SELECT pg_get_constraintdef(oid) AS definition FROM pg_constraint WHERE conrelid='secureshop_review.owned_listing_events'::regclass AND contype='c'")).rows;
 if(!terminal.some(r=>r.definition?.includes("'declined'")&&r.definition?.includes("'denied'")))throw fail('LISTINGS_SCHEMA_UNAVAILABLE');
 const triggers=(await reviewPool.query("SELECT tgname,tgrelid::regclass::text AS relation,tgfoid::regprocedure::text AS function,tgtype::integer AS type FROM pg_trigger WHERE NOT tgisinternal AND tgenabled='O' AND (tgrelid='secureshop_review.product_targets'::regclass OR tgrelid='secureshop_review.bound_audit_owner_deletion_receipts'::regclass OR tgrelid='secureshop_review.product_target_products'::regclass OR tgrelid='secureshop_review.product_target_listing_overlays'::regclass)")).rows;
 const expected=[['product_target_listing_retirement','product_targets','cleanup_owned_listing_lifecycle()',17],['z_owned_listing_owner_cleanup','bound_audit_owner_deletion_receipts','cleanup_owned_listing_lifecycle()',5],['invalidate_owned_listing_generated_product','product_target_products','invalidate_owned_listing_generated_html()',19],['invalidate_owned_listing_generated_overlay','product_target_listing_overlays','invalidate_owned_listing_generated_html()',23]];
 if(!expected.every(([name,table,fn,type])=>triggers.some(r=>r.tgname===name&&r.relation==='secureshop_review.'+table&&r.function==='secureshop_review.'+fn&&r.type===type)))throw fail('LISTINGS_SCHEMA_UNAVAILABLE');
 return true;
}
async function assertListingTemplateSchema({agentsPool,reviewPool}){
 const tables=['owned_listing_template_operations','owned_listing_template_events','owned_listing_template_cleanup_receipts'].map(name=>'secureshop_review.'+name);
 const functions=[
  'admit_owned_listing_template(uuid,uuid,uuid,integer,integer,uuid,uuid,bigint,integer,integer,uuid,bigint,text,text,text)',
  'append_owned_listing_template_event(uuid,uuid,integer,text,jsonb,text)',
 ].map(name=>'secureshop_review.'+name);
 const rows=(await reviewPool.query("SELECT name,to_regclass(name) IS NOT NULL AND has_table_privilege(current_user,to_regclass(name),'SELECT') AND NOT has_table_privilege(current_user,to_regclass(name),'INSERT,UPDATE,DELETE,TRUNCATE,TRIGGER') AS ready FROM unnest($1::text[]) AS name",[tables])).rows;
 if(rows.length!==tables.length||rows.some(row=>!tables.includes(row.name)||row.ready!==true)||new Set(rows.map(row=>row.name)).size!==tables.length)throw fail('LISTING_TEMPLATE_SCHEMA_UNAVAILABLE');
 const calls=(await reviewPool.query("SELECT name,p.oid IS NOT NULL AND p.prosecdef AND has_function_privilege(current_user,p.oid,'EXECUTE') AND NOT EXISTS(SELECT 1 FROM aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) a WHERE a.grantee=0 AND a.privilege_type='EXECUTE') AS ready FROM unnest($1::text[]) AS name LEFT JOIN pg_proc p ON p.oid=to_regprocedure(name)",[functions])).rows;
 if(calls.length!==functions.length||calls.some(row=>!functions.includes(row.name)||row.ready!==true)||new Set(calls.map(row=>row.name)).size!==functions.length)throw fail('LISTING_TEMPLATE_SCHEMA_UNAVAILABLE');
 const corrected=(await reviewPool.query("SELECT pg_get_functiondef(to_regprocedure($1)) AS definition",[functions[1]])).rows[0]?.definition;
 if(typeof corrected!=='string'||!corrected.includes("requested_state='effect_received' AND requested_payload#>>'{effect,requestSha256}' IS DISTINCT FROM prior.payload_json->>'executorRequestSha256'")
   ||!corrected.includes('prior.payload_json IS DISTINCT FROM requested_payload')
   ||!corrected.includes('prior.payload_sha256 IS DISTINCT FROM encode(sha256(convert_to(requested_payload::text'))throw fail('LISTING_TEMPLATE_SCHEMA_UNAVAILABLE');
 const purpose=(await agentsPool.query("SELECT pg_get_constraintdef(oid) AS definition FROM pg_constraint WHERE conrelid='secureshop_agents.agent_sessions'::regclass AND conname='agent_sessions_conversation_purpose_shape'")).rows;
 if(purpose.length!==1||!purpose[0].definition?.includes("'secureshop_listing_template'"))throw fail('LISTING_TEMPLATE_SCHEMA_UNAVAILABLE');
 const triggers=(await reviewPool.query("SELECT tgname,tgrelid::regclass::text AS relation,tgfoid::regprocedure::text AS function,tgtype::integer AS type FROM pg_trigger WHERE NOT tgisinternal AND tgenabled='O' AND tgrelid IN ('secureshop_review.owned_listing_template_operations'::regclass,'secureshop_review.owned_listing_template_events'::regclass,'secureshop_review.owned_listing_template_cleanup_receipts'::regclass,'secureshop_review.product_targets'::regclass,'secureshop_review.bound_audit_owner_deletion_receipts'::regclass)")).rows;
 const required=[
  ['owned_listing_template_operation_immutable','owned_listing_template_operations','guard_owned_listing_template_storage()',27],
  ['owned_listing_template_event_immutable','owned_listing_template_events','guard_owned_listing_template_storage()',27],
  ['owned_listing_template_cleanup_immutable','owned_listing_template_cleanup_receipts','guard_owned_listing_template_storage()',27],
  ['z_product_target_template_retirement','product_targets','cleanup_owned_listing_template_lifecycle()',17],
  ['z_owner_template_cleanup','bound_audit_owner_deletion_receipts','cleanup_owned_listing_template_lifecycle()',5],
 ];
 if(!required.every(([name,table,fn,type])=>triggers.some(row=>row.tgname===name
      &&row.relation==='secureshop_review.'+table
      &&row.function==='secureshop_review.'+fn&&row.type===type)))throw fail('LISTING_TEMPLATE_SCHEMA_UNAVAILABLE');
 return true;
}
function internalResource(admission){
 const {binding:b,request}=admission;
 const urls=['http://169.254.169.254/catalog.json','http://10.0.1.100:8080/catalog.json','http://10.0.2.10/catalog.json'];
 if(!urls.includes(request.json_url))return null;
 // These bytes belong to the exact qualified namespace-worker package. Source
 // and runtime hashes are checked before this factory is admitted.
 const bytes=Buffer.from(JSON.stringify({products:[{name:'Internal synthetic catalog',price:12,description:'Owned internal teaching information'}]}));
 return Object.freeze({scope:b.scope,targetId:b.targetId,mode:b.mode,classification:'protected-training-resource',url:request.json_url,sourceSha256:crypto.createHash('sha256').update(bytes).digest('hex'),byteCount:bytes.length});
}
async function createListingsProduction({runtime,identityPool,agentsPool,reviewPool,resetComposition,catalog,personaAuthority,provider,promptPolicyRepository,toolPolicyRepository,assessmentDependencies,authenticatePersona,browserQualification,productRenderer,listingTemplateClient,systemDiagnosticClient,readChatSetup,
 createComposition=require('./secureshopListingsComposition').createListingsComposition,
 createBrowserAssessment=require('./secureshopListingsBrowserAssessment').createListingsBrowserAssessment}={}){
 if(!runtime||runtime.admissions!==true)return Object.freeze({ready:false});
 if(typeof runtime.manager?.health!=='function'||typeof runtime.lifecycle?.onRetired!=='function'||typeof provider?.chat!=='function'||typeof authenticatePersona!=='function'||typeof personaAuthority?.capture!=='function'||typeof assessmentDependencies?.judge!=='function'||typeof assessmentDependencies?.qualifyModel!=='function'||typeof assessmentDependencies?.personaBindings?.capture!=='function'||typeof promptPolicyRepository?.admitRunSnapshot!=='function'||typeof toolPolicyRepository?.admitTool!=='function')throw fail('LISTINGS_DEPENDENCIES_UNAVAILABLE');
 await assertListingsSchema({agentsPool,reviewPool});await runtime.manager.health();
 const resolveTarget=context=>catalog.prepareTarget(context);
 const composition=createComposition({systemDiagnosticClient,resolveTarget,modeAuthority:runtime.modeAuthority,pool:reviewPool,personaAuthority,capabilityKey:runtime.capabilityKey,targetManager:runtime.manager,launches:resetComposition.launches,conversationRepository:resetComposition.conversations,journal:resetComposition.journal,coordinator:resetComposition.runCoordinator,provider,promptPolicyRepository,toolPolicyRepository,assessmentDependencies:{...assessmentDependencies,identityPool,objectiveIds:[...require('./secureshopListingsEvidence').LISTINGS_OBJECTIVES.slice(0,3),require('./secureshopListingOptimizeEvidence').LISTING_OPTIMIZE_OBJECTIVE],resolveInternalResource:internalResource}});
 let removeListener;
 try {
 const rewriteSaveRepository=require('../database/postgres/secureshopListingRewriteSaveRepository').createListingRewriteSaveRepository({resolveTarget,
  resolveRetainedTarget:b=>catalog.readRetainedTarget({scope:b.scope,persona:b.persona,personaSession:b.personaSession}),
  pool:reviewPool,personaAuthority,capabilityKey:runtime.capabilityKey});
 const {createListingsApplication,createListingsTargetResolver}=require('./secureshopListingsApplication');
 const application=createListingsApplication({modeAuthority:runtime.modeAuthority,composition,prepareTarget:createListingsTargetResolver({catalog,pool:reviewPool,mode:runtime.mode,modeAuthority:runtime.modeAuthority}),launches:resetComposition.launches,personaAuthority,rewriteSaveRepository,catalog,readChatSetup});
 if(typeof composition.readSavedEvidence!=='function'||typeof composition.releaseRetiredTarget!=='function')throw fail('LISTINGS_DEPENDENCIES_UNAVAILABLE');
 const browserAssessment=createBrowserAssessment({launches:resetComposition.launches,conversationRepository:resetComposition.conversations,coordinator:resetComposition.runCoordinator,journal:resetComposition.journal,listingComposition:composition,evidenceRepository:{readSaved:composition.readSavedEvidence},identityPool,personaAuthority,...assessmentDependencies,browserQualification,productRenderer:productRenderer||require('./secureshopProductDescriptionRenderer').loadSecureShopProductDescriptionRenderer()});
 let templateWorkflow={readiness:async()=>({ready:false}),run:async()=>{throw fail('LISTING_TEMPLATE_EXECUTOR_UNAVAILABLE');},read:async()=>{throw fail('LISTING_TEMPLATE_EXECUTOR_UNAVAILABLE');}};
 if(listingTemplateClient!==undefined){
  if(typeof listingTemplateClient?.health!=='function'||typeof listingTemplateClient?.execute!=='function')throw fail('LISTING_TEMPLATE_EXECUTOR_UNAVAILABLE');
  await assertListingTemplateSchema({agentsPool,reviewPool});await listingTemplateClient.health();
  const repository=require('../database/postgres/secureshopListingTemplateRepository').createListingTemplateRepository({pool:reviewPool,catalog,personaAuthority,launches:resetComposition.launches,modeAuthority:runtime.modeAuthority,capabilityKey:runtime.capabilityKey});
  const assessment=require('./secureshopListingTemplateAssessment').createListingTemplateAssessment({...assessmentDependencies,identityPool});
  templateWorkflow=require('./secureshopListingTemplateWorkflow').createListingTemplateWorkflow({repository,executor:listingTemplateClient,launches:resetComposition.launches,conversationRepository:resetComposition.conversations,journal:resetComposition.journal,coordinator:resetComposition.runCoordinator,provider,personaAuthority,promptPolicyRepository,assessmentFactory:assessment.assessmentFactory});
 }
 removeListener=runtime.lifecycle.onRetired((binding,options)=>composition.releaseRetiredTarget(binding,options));
 let disposed=false;
 const readReadiness=async context=>{
  if(disposed)return{ready:false};const scope=createLaunchScope(context.scope);
  const fence=await personaAuthority.capture({scope,personaId:context.persona.id,role:context.persona.role,...context.personaSession});await resetComposition.launches.assertCurrent(scope);await fence.assertRemoteAdmission();await runtime.manager.health();await fence.assertRemoteAdmission();
  const modeToken=await require('./secureshopFeatureModeAuthority').captureFeatureMode(runtime.modeAuthority,scope,'listings',runtime.mode);
  return{ready:true,modeCapability:require('./secureshopFeatureModeAuthority').projectFeatureMode(modeToken),versionedListings:true,scopeKey:crypto.createHash('sha256').update(JSON.stringify({scope,persona:context.persona,personaSession:context.personaSession,mode:modeToken.snapshot})).digest('hex')};
 };
 const router=require('../routes/secureshop/boundListings').createBoundListingsRouter({application,authenticatePersona,readReadiness,browserAssessment,templateWorkflow});
 return Object.freeze({ready:true,application,composition,router,browserAssessment,templateWorkflow,close(){try{composition.dispose();}finally{removeListener();disposed=true;}}});
 }catch(error){removeListener?.();try{composition.dispose();}catch(closeError){throw new AggregateError([error,closeError],'Listings construction cleanup failed');}throw error;}
}
module.exports={createListingsProduction,assertListingsSchema,assertListingTemplateSchema,internalResource};
