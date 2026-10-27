'use strict';

// Controlled storage evidence only: no provider, browser, Judge, objective
// credit or authenticated launch/reset claim. Real runtime-role SELECTs must
// accept retained original rows under a different current consumer scene grant.
const test=require('node:test');
const assert=require('node:assert/strict');
const path=require('node:path');
const fs=require('node:fs');
const {Module,createRequire}=require('node:module');
const {randomUUID}=require('node:crypto');
const {Pool}=require('pg');
const {migrate}=require('../../db/postgres/migrate');
const {fixture}=require('../secureshopManualRagSourceContract.test');
const {createSceneBinding}=require('../../server/services/secureshopSceneBinding');
const {createSecureShopBoundProductRepository}=require('../../server/database/postgres/secureshopBoundProductRepository');
const {createSecureShopBoundProductRetrievalRepository}=require('../../server/database/postgres/secureshopBoundProductRetrievalRepository');
const {createSecureShopBoundManualIngestRepository}=require('../../server/database/postgres/secureshopBoundManualIngestRepository');
const {createSecureShopEmbeddingRevisionRepository}=require('../../server/database/postgres/secureshopEmbeddingRevisionRepository');
const {createManualRagSourceAdapter}=require('../../server/database/postgres/secureshopManualRagSourceAdapter');
const PREFIX='PG_SECURESHOP_MANUAL_RAG_SOURCE_';
const ENABLED=process.env.SECURESHOP_MANUAL_RAG_SOURCE_NATIVE==='1'&&process.env.PG_TEST_DISPOSABLE==='yes';
const ROOT=path.resolve(__dirname,'../..');
const STORES={IDENTITY:'identity',AGENTS:'secureshop_agents',REVIEW:'secureshop_review',FRESH_REVIEW:'secureshop_review'};
const PRIVATE_MIGRATION='0055_private_manual_original_preimages.sql';
const TITLE='native manual RAG source adapter joins historical uploader and current consumer using immutable SQL evidence';
function urls(){
 const databases=new Set(),ports=new Set();const result={};
 for(const [key,store] of Object.entries(STORES)){
  const pair={};
  for(const kind of ['RUNTIME','MIGRATION']){
   const value=new URL(process.env[`${PREFIX}${key}_${kind}_URL`]);
   assert.equal(value.protocol,'postgresql:');assert.equal(value.hostname,'127.0.0.1');
   assert.match(value.pathname,/^\/dvaia_test_[a-z0-9_]+$/);assert.equal(value.password,'');
   assert.equal(value.search,'');assert.equal(value.hash,'');
   assert.equal(value.username,`dvaia_${store}_${kind.toLowerCase()}`);
   pair[kind.toLowerCase()]=value;ports.add(value.port);
  }
  assert.equal(pair.runtime.pathname,pair.migration.pathname);assert.ok(!databases.has(pair.runtime.pathname));
  databases.add(pair.runtime.pathname);result[key]=pair;
 }
 assert.equal(ports.size,1);return result;
}
function pool(url){return new Pool({connectionString:url.href,max:3,connectionTimeoutMillis:5000,
 statement_timeout:30000,lock_timeout:10000,idle_in_transaction_session_timeout:30000});}
function beforePrivateMigration(){
 const filename=require.resolve('../../db/postgres/migrate'),localRequire=createRequire(filename);
 const originalFs=require('node:fs/promises'),loaded=new Module(filename,module);
 loaded.filename=filename;
 loaded.require=name=>name==='node:fs/promises'?{
  async readdir(directory,...args){assert.equal(path.resolve(directory),path.join(ROOT,'db/postgres/workshop-migrations/secureshop_review'));
   return (await originalFs.readdir(directory,...args)).filter(name=>name<PRIVATE_MIGRATION);},
  readFile:(...args)=>originalFs.readFile(...args),
 }:localRequire(name);
 loaded._compile(fs.readFileSync(filename,'utf8'),filename);
 return loaded.exports;
}
async function grant(runtime,birth,sceneId,grantId,execution){
 await runtime.query(`INSERT INTO secureshop_review.scene_execution_grants
  (grant_id,scene_id,scene_generation,target_id,launch_id,scenario_id,generation,original_platform_owner_id,original_platform_session_id)
  VALUES($1,$2,1,$3,$4,$5,$6,$7,$8)`,[grantId,sceneId,birth.targetId,execution.launchId,execution.scenarioId,
   execution.generation,execution.platformOwnerId,execution.platformSessionId]);
 return createSceneBinding(birth,{sceneId,sceneGeneration:1,grantId,execution,withLease:work=>work()});
}
async function seedTurn(agents,identity,original,purpose,originKey,origin,{abandoned=false}={}){
 const b=original.binding,result=structuredClone(original.result);result.taskMetadata[originKey]=origin;
 // Follow the actual pending -> active -> completed -> optionally abandoned
 // lifecycle. These are explicitly controlled provenance rows, never model proof.
 await agents.query(`INSERT INTO secureshop_agents.agent_sessions
  (id,user_id,role,authority_mode,binding_state,platform_launch_id,platform_scenario_id,
   platform_launch_generation,original_platform_owner_id,original_platform_session_id,conversation_purpose)
  VALUES($1,$2,$3,'launch_bound','pending',$4,$5,$6,$7,$8,$9)`,
 [original.sessionId,b.shopUserId,b.role,b.launchId,b.scenarioId,b.generation,b.platformOwnerId,b.platformSessionId,purpose]);
 await agents.query("UPDATE secureshop_agents.agent_sessions SET binding_state='active' WHERE id=$1",[original.sessionId]);
 await agents.query(`UPDATE secureshop_agents.agent_sessions SET messages_json=$2 WHERE id=$1`,
 [original.sessionId,JSON.stringify([{role:'user',content:original.message}])]);
 await agents.query(`INSERT INTO secureshop_agents.turn_requests
  (session_id,request_id,request_hash,request_version,claim_id,status) VALUES($1,$2,$3,1,$4,'started')`,
 [original.sessionId,original.requestId,original.requestHash,randomUUID()]);
 for(const row of original.traces){
  const keys=['event_id','session_id','step','actor','kind','agent_ns','tool_name','params_json','result_json','provider','policy_violation'];
  await agents.query(`INSERT INTO secureshop_agents.agent_trace (${keys.join(',')}) VALUES(${keys.map((_,i)=>`$${i+1}`).join(',')})`,keys.map(key=>row[key]??null));
 }
 await agents.query(`UPDATE secureshop_agents.turn_requests SET status='completed',result_json=$3::jsonb,
  finished_at=clock_timestamp() WHERE session_id=$1 AND request_id=$2`,[original.sessionId,original.requestId,JSON.stringify(result)]);
 if(abandoned)await agents.query("UPDATE secureshop_agents.agent_sessions SET binding_state='abandoned' WHERE id=$1",[original.sessionId]);
 const run=original.run,effect=original.effect;
 // A later owner generation must not erase historical completed effect evidence.
 await identity.query('INSERT INTO graph_runtime.owners(owner_key,generation) VALUES($1,$2)',[run.owner_key,Number(run.generation)+1]);
 await identity.query(`INSERT INTO graph_runtime.runs(run_id,owner_key,generation,status)
  VALUES($1,$2,$3,'completed')`,[run.run_id,run.owner_key,run.generation]);
 await identity.query(`INSERT INTO graph_runtime.effects(run_id,owner_key,generation,effect_key,status)
  VALUES($1,$2,$3,$4,'completed')`,[run.run_id,run.owner_key,run.generation,effect.effect_key]);
 return result;
}

if(require.main===module)test(TITLE,{skip:!ENABLED,timeout:180000},async t=>{
 assert.equal(process.cwd(),ROOT);assert.equal(path.resolve(process.env.DVAIA_CURRENT_MAIN_WORKSPACE||'/'),ROOT);
 const pairs=urls(),pools={},all=[];
 t.after(async()=>{const ended=await Promise.allSettled(all.map(p=>p.end()));assert.deepEqual(ended.filter(r=>r.status==='rejected'),[],'all owned pools close');});
 for(const [key,store] of Object.entries(STORES)){
  const runtime=pool(pairs[key].runtime),migration=pool(pairs[key].migration);all.push(runtime,migration);pools[key]={runtime,migration};
  const directory=path.join(ROOT,'db/postgres',store==='identity'?'identity-migrations':`workshop-migrations/${store}`);
  const loader=key==='REVIEW'?beforePrivateMigration():{migrate};
  const applied=await loader.migrate(migration,directory);
  assert.deepEqual(await loader.migrate(migration,directory),[]);
  if(key==='FRESH_REVIEW')assert.ok(applied.includes(PRIVATE_MIGRATION),'fresh schema applies private migration');
  if(key==='REVIEW')assert.equal(applied.at(-1),'0054_owned_listing_image_optimize.sql');
  assert.equal((await runtime.query('SELECT current_user AS role')).rows[0].role,`dvaia_${store}_runtime`);
 }
 const f=fixture(),p=f.proof,r=p.receipt;
 const birth={...p.birth,targetId:r.targetId};
 const authority={checkCurrent:async()=>{},checkCleanup:async()=>{},getRuntimeFingerprint:()=>r.runtimeFingerprint};
 const review=pools.REVIEW.runtime;
 const products=createSecureShopBoundProductRepository(review,authority);
 const retrieval=createSecureShopBoundProductRetrievalRepository(review,authority);
 const manuals=createSecureShopBoundManualIngestRepository(review,authority);
 const embeddings=createSecureShopEmbeddingRevisionRepository(review,authority);
 const vector=Array.from({length:384},(_,i)=>i===0?1:0);
 const product={id:r.productId,sourceRetailerId:1,retailerId:r.merchantId,name:'Controlled adapter product',
  description:'Controlled source',descriptionHtml:'<p>Controlled source</p>',price:12,category:'fixture',
  imageUrl:null,images:[],stockQuantity:4,status:'active',templateSource:'{{source}}',createdAt:null,updatedAt:null};
 await products.provision(birth,{ownMerchantId:r.merchantId,products:[product]});
 await retrieval.provision(birth,{embeddingModel:r.embeddingModel,embeddingDimension:384,
  documents:[{sourceKind:'product',sourceId:r.productId,chunkIndex:0,text:product.description,embedding:vector}]});
 const sibling={...birth,targetId:randomUUID(),launchId:randomUUID(),scenarioId:randomUUID(),platformOwnerId:birth.platformOwnerId+10};
 await products.provision(sibling,{ownMerchantId:r.merchantId,products:[product]});
 const siblingBefore=(await review.query('SELECT * FROM secureshop_review.product_target_products WHERE target_id=$1',[sibling.targetId])).rows;
 const uploader=await grant(review,birth,r.sceneId,r.sceneGrantId,r.execution);
 const consumer=await grant(review,birth,r.sceneId,p.consumer.grantId,p.consumer.execution.scope);
 const input={operationId:r.operationId,productId:r.productId,merchantId:r.merchantId,fileReceipt:r.fileReceipt,
  filename:r.filename,mime:r.mime,isPublic:true,extractor:r.extractor,extractionSha256:r.extractionSha256,
  embeddingModel:r.embeddingModel,embeddingDimension:384,chunks:JSON.parse(p.documentsJson),expectedRuntimeFingerprint:r.runtimeFingerprint};
 const captured=await manuals.appendManualWithLineage(uploader,input);assert.equal(captured.lineage.eligible,true);
 const snapshot=await embeddings.snapshot(consumer),revisionId=randomUUID();
 await embeddings.publish(consumer,{operationId:revisionId,sourceSetDigest:snapshot.sourceSetDigest,
  expectedHead:snapshot.expectedHead,expectedRuntimeFingerprint:r.runtimeFingerprint,
  documents:snapshot.documents.map(({text,...row})=>({...row,embedding:vector}))});
 const searched=await embeddings.searchWithLineage(consumer,{embedding:vector,limit:1});
 assert.equal(searched.lineage.eligible,true);assert.equal(searched.rows[0].sourceKind,'manual');
 const uploadOrigin={version:1,binding:p.uploader.binding,personaSession:p.uploader.personaSession,
  source:{sessionId:p.uploader.original.sessionId,requestId:p.uploader.original.requestId},
  runId:p.uploader.original.run.run_id,traceEventIds:p.uploader.original.traceEventIds,
  target:JSON.parse(JSON.stringify(uploader)),receipt:captured.receipt,lineage:captured.lineage};
 const consumerOrigin={version:1,binding:p.consumer.binding,personaSession:p.consumer.personaSession,
  source:{sessionId:p.consumer.original.sessionId,requestId:p.consumer.original.requestId},
  runId:p.consumer.original.run.run_id,traceEventIds:p.consumer.original.traceEventIds,
  target:JSON.parse(JSON.stringify(consumer)),execution:p.consumer.execution,productId:r.productId,lineage:searched.lineage};
 const uploadResult=await seedTurn(pools.AGENTS.migration,pools.IDENTITY.migration,p.uploader.original,
  'secureshop_product_manual_ingest','manualRagUploadOrigin',uploadOrigin,{abandoned:true});
 const consumerResult=await seedTurn(pools.AGENTS.migration,pools.IDENTITY.migration,p.consumer.original,
  'secureshop_product_assist','manualRagConsumerOrigin',consumerOrigin);
 const state={binding:p.consumer.binding,persona:{id:p.consumer.binding.shopUserId,role:'customer'},
  personaSession:p.consumer.personaSession,target:consumer,execution:p.consumer.execution,check:async()=>{}};
 const adapter=createManualRagSourceAdapter({agentsPool:pools.AGENTS.runtime,identityPool:pools.IDENTITY.runtime,reviewPool:review});
 const request=consumerOrigin.source,manualSource=searched.lineage.manualSources[0];
 const actualConsumer=await adapter.readConsumer({state,request,purpose:'secureshop_product_assist'});
 const actualUpload=await adapter.readUploader({state,operationId:r.operationId,manualSource,purpose:'secureshop_product_manual_ingest'});
 assert.deepEqual(actualConsumer.original.result,consumerResult);assert.deepEqual(actualUpload.original.result,uploadResult);
 assert.deepEqual(actualUpload.original.traceEventIds,p.uploader.original.traceEventIds);
 assert.deepEqual(actualUpload.original.run,p.uploader.original.run);assert.deepEqual(actualUpload.original.effect,p.uploader.original.effect);
 assert.deepEqual(await adapter.readReceipt({state,operationId:r.operationId}),captured.receipt);
 assert.deepEqual(await adapter.readRevision({state,revisionId}),searched.lineage.revision);
 assert.equal((await pools.AGENTS.runtime.query('SELECT binding_state FROM secureshop_agents.agent_sessions WHERE id=$1',[p.uploader.original.sessionId])).rows[0].binding_state,'abandoned');
 await assert.rejects(adapter.readUploader({state,operationId:r.operationId,manualSource:{...manualSource,receiptSha256:'f'.repeat(64)},purpose:'secureshop_product_manual_ingest'}),{code:'MANUAL_RAG_SOURCE_UNAVAILABLE'});
 await assert.rejects(adapter.readRevision({state,revisionId:randomUUID()}),{code:'MANUAL_RAG_SOURCE_UNAVAILABLE'});
 await assert.rejects(adapter.readReceipt({state:{...state,target:{...consumer}},operationId:r.operationId}),{code:'SHOP_SCENE_STALE'});
 // Advance the mutable head; exact original revision remains the only read.
 await embeddings.publish(consumer,{operationId:randomUUID(),sourceSetDigest:snapshot.sourceSetDigest,
  expectedHead:revisionId,expectedRuntimeFingerprint:r.runtimeFingerprint,
  documents:snapshot.documents.map(({text,...row})=>({...row,embedding:vector}))});
 assert.deepEqual(await adapter.readRevision({state,revisionId}),searched.lineage.revision);
 await products.cleanup(birth,{operationId:randomUUID()});
 await assert.rejects(adapter.readReceipt({state,operationId:r.operationId}));
 const retained=(await review.query('SELECT receipt_sha256 FROM secureshop_review.product_target_manual_ingests WHERE operation_id=$1',[r.operationId])).rows;
 assert.equal(retained[0].receipt_sha256.toString('hex'),captured.receipt.receiptSha256);
 assert.deepEqual((await review.query('SELECT * FROM secureshop_review.product_target_products WHERE target_id=$1',[sibling.targetId])).rows,siblingBefore);
 const privateFacts=await require('./secureshopProtectedManualSourceNative').runProtectedManualSourceStorage(pools);
 console.log('V31_PRIVATE_STORAGE_FACTS '+JSON.stringify(privateFacts));
});
module.exports={grant,seedTurn};
