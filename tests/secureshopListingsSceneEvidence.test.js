'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),{randomUUID}=require('node:crypto');
const {prepareListingAdmission,hash}=require('../server/services/secureshopListingJournalContract');
const {createSceneBinding,authorizeSceneMerchant}=require('../server/services/secureshopSceneBinding');
const {createConversationBinding}=require('../server/services/secureshopConversationBinding');
const {createTurnRequest}=require('../server/services/secureshopTurnRequest');
const {createListingsEvidenceRepository}=require('../server/database/postgres/secureshopListingsEvidenceRepository');
// Controlled repository readback; PostgreSQL privilege/effect qualification is
// separately performed by the owned native cohort. No model/browser is invoked.
test('saved evidence joins retained storage birth under current operation authority and actual seller',async()=>{
 const scope={launchId:randomUUID(),scenarioId:randomUUID(),generation:1,platformOwnerId:1,platformSessionId:7};
 const admission=prepareListingAdmission({scope,persona:{id:1000000001,role:'merchant'},personaSession:{sessionId:randomUUID(),authorityVersion:'1'},targetId:randomUUID(),mode:'vuln',catalogRevision:'1',request:{version:1,action:'rewrite',operationId:randomUUID(),title:'T',description:'D'}}),b=admission.binding;
 const birth={...scope,launchId:randomUUID(),platformSessionId:2,targetId:b.targetId};
 const target=authorizeSceneMerchant(createSceneBinding(birth,{sceneId:randomUUID(),sceneGeneration:1,grantId:randomUUID(),execution:scope,withLease:async work=>work()}),b.persona.id);
 const model={provider:'controlled',model:'controlled',callId:randomUUID(),mocked:false,fallback:false},html='<b>Controlled raw HTML</b>';
 const rewrite={version:1,operationId:admission.request.operationId,requestSha256:admission.requestSha256,sourceSha256:hash(JSON.stringify(['T','D'])),...model,html,htmlSha256:hash(html)};
 const operation={operationId:admission.request.operationId,state:'completed',receipt:rewrite};
 const sessionId=randomUUID(),binding=createConversationBinding(scope,b.persona),turn=createTurnRequest({sessionId,requestId:admission.request.operationId,binding,message:admission.requestJson});
 const result={stopReason:'end_turn',text:html,taskMetadata:{listings:{action:'rewrite',decision:'rewritten',operationId:admission.request.operationId,model}}};
 const saveOperationId=randomUUID(),save={version:1,saveOperationId,rewriteOperationId:admission.request.operationId,targetId:b.targetId,productId:8,bindingSha256:admission.bindingSha256,requestSha256:hash('save'),sourceSha256:rewrite.sourceSha256,htmlSha256:rewrite.htmlSha256};
 const row={receipt_json:JSON.stringify(save),receipt_sha256:hash(JSON.stringify(save)),request_sha256:save.requestSha256,product_id:8,current_rewrite_operation_id:admission.request.operationId,source_name:'T',source_description:'D',source_sha256:rewrite.sourceSha256,html_sha256:rewrite.htmlSha256,current_name:'T',current_description:'D',current_html:html};
 let savedArgs,allow=true;const pool={async connect(){return{release(){},async query(sql,args){if(sql.includes('assert_scene_execution_grant'))return{rows:[{allowed:allow}]};if(sql.includes('owned_listing_scene_admissions'))return{rows:[{grant_id:target.scene.grantId,target_id:target.targetId,merchant_id:b.persona.id,binding_sha256:admission.bindingSha256}]};if(sql.includes('SELECT s.*,g.rewrite_operation_id')){savedArgs=args;return{rows:[row]};}return{rows:[]};}};}};
 const authority={capture(){return{binding:{...scope,personaId:b.persona.id,role:'merchant',...b.personaSession},async assertRemoteAdmission(){},async withCrossStoreEffect(work){return work();},async withPersonaEffect(work){return work({async query(){return{rows:[{session_id:sessionId,request_id:admission.request.operationId,request_hash:turn.hash,request_version:turn.version,status:'completed',result_json:result}]};}});}};}};
 const repo=createListingsEvidenceRepository({reviewPool:pool,personaAuthority:authority,listingJournal:{get:async()=>operation},resolveTarget:async()=>target});
 const output=await repo.readSaved({admission,saveOperationId});assert.equal(output.source.html,html);assert.deepEqual(savedArgs.slice(4),[birth.launchId,birth.scenarioId,birth.generation,birth.platformOwnerId,birth.platformSessionId,b.persona.id,true]);
 allow=false;await assert.rejects(repo.readSaved({admission,saveOperationId}),{code:'SHOP_SCENE_STALE'});
});
