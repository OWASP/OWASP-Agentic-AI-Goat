'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {randomUUID,createHash}=require('node:crypto');
const {prepareListingAdmission}=require('../server/services/secureshopListingJournalContract');
const {createListingRewriteSaveRepository}=require('../server/database/postgres/secureshopListingRewriteSaveRepository');
const sha=v=>createHash('sha256').update(v).digest('hex');
test('rewrite-save readback uses retained target and exact immutable receipt with no provisioning or mutation',async()=>{
 const scope={launchId:randomUUID(),scenarioId:randomUUID(),generation:1,platformOwnerId:1,platformSessionId:2};
 const execution={...scope,launchId:randomUUID(),scenarioId:randomUUID(),generation:2,platformSessionId:3};
 const targetId=randomUUID(),operationId=randomUUID(),saveOperationId=randomUUID();
 const merchantId=1000000001;
 const admission=prepareListingAdmission({scope:execution,persona:{id:merchantId,role:'merchant'},personaSession:{sessionId:randomUUID(),authorityVersion:'1'},
  targetId,mode:'vuln',catalogRevision:'1',request:{version:1,action:'rewrite',operationId,title:'Owned',description:'Literal'}});
 const receipt={version:1,saveOperationId,rewriteOperationId:operationId,targetId,requestedProductId:7,productId:7,
  bindingSha256:admission.bindingSha256,requestSha256:'a'.repeat(64),sourceSha256:'b'.repeat(64),htmlSha256:'c'.repeat(64)};
 const commands=[],pool={async connect(){return{async query(sql,values){commands.push({sql,values});
  if(sql.includes('assert_scene_execution_grant'))return{rows:[{allowed:true}]};
  if(sql.includes('owned_listing_scene_admissions'))return{rows:[]};
  if(sql.includes('FROM secureshop_review.owned_listing_rewrite_saves s'))return{rows:values?.slice(4).every((value,index)=>value===
   [scope.launchId,scope.scenarioId,scope.generation,scope.platformOwnerId,scope.platformSessionId][index])?[{receipt_json:JSON.stringify(receipt),
   receipt_sha256:sha(JSON.stringify(receipt)),request_sha256:receipt.requestSha256,product_id:7}]:[]};return{rows:[]};},release(){}};}};
 const personaAuthority={capture(x){return{binding:{...x.scope,personaId:x.personaId,role:x.role,sessionId:x.sessionId,
  authorityVersion:x.authorityVersion},async assertRemoteAdmission(){}};}};
 const {createSceneBinding,authorizeSceneMerchant}=require('../server/services/secureshopSceneBinding');
 const retainedTarget=authorizeSceneMerchant(createSceneBinding({...scope,targetId},{sceneId:randomUUID(),sceneGeneration:1,
  grantId:randomUUID(),execution,withLease:async work=>work()}),merchantId);
 let retained=0,provision=0;
 const repo=createListingRewriteSaveRepository({pool,personaAuthority,capabilityKey:Buffer.alloc(32),
  resolveTarget:async()=>{provision++;throw Error('unexpected provision');},
  resolveRetainedTarget:async()=>{retained++;return retainedTarget;}});
 assert.deepEqual(await repo.read({admission,saveOperationId}),receipt);
 assert.equal(retained,1);assert.equal(provision,0);
 assert.ok(commands.some(({sql})=>sql==='BEGIN ISOLATION LEVEL REPEATABLE READ'));
 const grant=commands.findIndex(({sql})=>sql.includes('assert_scene_execution_grant'));
 const admissionCheck=commands.findIndex(({sql})=>sql.includes('owned_listing_scene_admissions'));
 const receiptRead=commands.findIndex(({sql})=>sql.includes('FROM secureshop_review.owned_listing_rewrite_saves s'));
 assert.ok(grant>0&&admissionCheck>grant&&receiptRead>admissionCheck,'the retained scene grant and operation checks precede receipt read');
 assert.equal(commands.filter(({sql})=>sql.includes('assert_scene_execution_grant')).length,2,'current scene grant remains locked before and after readback');
 assert.deepEqual(commands.find(({sql})=>sql.includes('FROM secureshop_review.owned_listing_rewrite_saves s')).values.slice(4),
  [scope.launchId,scope.scenarioId,scope.generation,scope.platformOwnerId,scope.platformSessionId],
  'receipt lookup uses retained target birth, not scene actor execution');
 assert.ok(commands.filter(({sql})=>!sql.startsWith('BEGIN')&&!sql.startsWith('SET LOCAL')&&!sql.startsWith('COMMIT')).every(({sql})=>sql.trimStart().startsWith('SELECT')),
  'readback emits only authority and receipt SELECT statements');
});
