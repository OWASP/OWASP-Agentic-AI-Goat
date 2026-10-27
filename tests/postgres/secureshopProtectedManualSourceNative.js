'use strict';

// Native STORAGE provenance only. Turns/traces and file-receipt metadata are
// controlled seeds, not actual file upload, embedding inference, actor or Judge.
const assert=require('node:assert/strict');
const {randomUUID,createHash}=require('node:crypto');
const path=require('node:path');
const {migrate}=require('../../db/postgres/migrate');
const {fixture}=require('../secureshopManualRagSourceContract.test');
const {grant,seedTurn}=require('./secureshopManualRagSourceAdapter.integration.test');
const {createSecureShopBoundProductRepository}=require('../../server/database/postgres/secureshopBoundProductRepository');
const {createSecureShopBoundProductRetrievalRepository}=require('../../server/database/postgres/secureshopBoundProductRetrievalRepository');
const {createSecureShopBoundManualIngestRepository}=require('../../server/database/postgres/secureshopBoundManualIngestRepository');
const {createSecureShopEmbeddingRevisionRepository}=require('../../server/database/postgres/secureshopEmbeddingRevisionRepository');
const {createProtectedManualSourceAdapter,createProtectedManualSourceReader}=require('../../server/services/secureshopProtectedManualSourceReader');
const {createManualRagSourceAdapter}=require('../../server/database/postgres/secureshopManualRagSourceAdapter');
const sha=value=>createHash('sha256').update(value,'utf8').digest('hex');

async function qualifyPrivateMigration(pools) {
  const directory=path.resolve(__dirname,'../../db/postgres/workshop-migrations/secureshop_review');
  const migration='0055_private_manual_original_preimages.sql';
  const review=pools.REVIEW.runtime,f=fixture(),p=f.proof,r=p.receipt;
  const birth={...p.birth,targetId:r.targetId};
  const authority={checkCurrent:async()=>{},checkCleanup:async()=>{},getRuntimeFingerprint:()=>r.runtimeFingerprint};
  const products=createSecureShopBoundProductRepository(review,authority);
  const retrieval=createSecureShopBoundProductRetrievalRepository(review,authority);
  const manuals=createSecureShopBoundManualIngestRepository(review,authority);
  const vector=Array.from({length:384},(_,i)=>i===0?1:0);
  await products.provision(birth,{ownMerchantId:r.merchantId,products:[{id:r.productId,sourceRetailerId:1,
    retailerId:r.merchantId,name:'Migration fixture',description:'Original source',descriptionHtml:null,
    price:12,category:'fixture',imageUrl:null,images:[],stockQuantity:4,status:'active',
    templateSource:'{{source}}',createdAt:null,updatedAt:null}]});
  await retrieval.provision(birth,{embeddingModel:r.embeddingModel,embeddingDimension:384,
    documents:[{sourceKind:'product',sourceId:r.productId,chunkIndex:0,text:'Original source',embedding:vector}]});
  const uploader=await grant(review,birth,r.sceneId,r.sceneGrantId,r.execution);
  const input={operationId:r.operationId,productId:r.productId,merchantId:r.merchantId,fileReceipt:r.fileReceipt,
    filename:r.filename,mime:r.mime,isPublic:false,extractor:r.extractor,extractionSha256:r.extractionSha256,
    embeddingModel:r.embeddingModel,embeddingDimension:384,chunks:JSON.parse(p.documentsJson),expectedRuntimeFingerprint:r.runtimeFingerprint};
  const historicalPrivate=await manuals.appendManual(uploader,input);
  const publicId=randomUUID();
  const historicalPublic=await manuals.appendManualWithLineage(uploader,{...input,operationId:publicId,isPublic:true,
    fileReceipt:{...input.fileReceipt,virtualPath:`/uploads/product_manuals/${r.productId}/${publicId}-manual`}});
  assert.equal(historicalPrivate.isPublic,false);assert.equal(historicalPublic.lineage.eligible,true);
  const publicFunction="secureshop_review.capture_product_manual_preimage(uuid,uuid,jsonb)";
  const privateFunction="secureshop_review.capture_private_product_manual_preimage(uuid,uuid,jsonb)";
  const definition=async(pool,name)=>(await pool.query('SELECT pg_get_functiondef($1::regprocedure) AS definition',[name])).rows[0].definition;
  const originalPublic=await definition(review,publicFunction);
  assert.equal((await review.query('SELECT to_regprocedure($1) AS function',[privateFunction])).rows[0].function,null);
  const saved=async()=>({
    receipts:(await review.query('SELECT * FROM secureshop_review.product_target_manual_ingests WHERE target_id=$1 ORDER BY operation_id',[birth.targetId])).rows,
    preimages:(await review.query('SELECT * FROM secureshop_review.product_target_manual_preimages WHERE target_id=$1 ORDER BY operation_id',[birth.targetId])).rows,
  });
  const before=await saved();assert.equal(before.preimages.length,1);
  assert.deepEqual(await migrate(pools.REVIEW.migration,directory),[migration]);
  assert.deepEqual(await migrate(pools.REVIEW.migration,directory),[]);
  assert.deepEqual(await migrate(pools.FRESH_REVIEW.migration,directory),[]);
  assert.equal((await pools.FRESH_REVIEW.migration.query('SELECT count(*)::integer AS count FROM dvaia_migrations.ledger WHERE name=$1',[migration])).rows[0].count,1);
  assert.equal(await definition(review,publicFunction),originalPublic);
  assert.equal(await definition(review,privateFunction),await definition(pools.FRESH_REVIEW.runtime,privateFunction));
  const capture=(name,id)=>review.query(`SELECT * FROM ${name}($1,$2,$3::jsonb)`,[id,birth.targetId,JSON.stringify(input.chunks)]);
  await assert.rejects(capture('secureshop_review.capture_private_product_manual_preimage',r.operationId),
    error=>error.code==='55000'&&error.message==='Historical manual preimage capture forbidden');
  await assert.rejects(capture('secureshop_review.capture_private_product_manual_preimage',publicId),
    error=>error.code==='55000'&&error.message==='Original manual receipt mismatch');
  await assert.rejects(capture('secureshop_review.capture_product_manual_preimage',r.operationId),
    error=>error.code==='55000'&&error.message==='Original manual receipt mismatch');
  assert.deepEqual(await saved(),before,'upgrade never retrofits historical uploads or rewrites public preimages');
  for(const pool of [review,pools.FRESH_REVIEW.runtime]) {
    const row=(await pool.query(`SELECT p.prosecdef,p.proconfig,pg_get_userbyid(p.proowner) AS owner,
      has_function_privilege(current_user,p.oid,'EXECUTE') AS executable,
      EXISTS(SELECT 1 FROM aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a WHERE a.grantee=0 AND a.privilege_type='EXECUTE') AS public_execute
      FROM pg_proc p WHERE p.oid=$1::regprocedure`,[privateFunction])).rows[0];
    assert.deepEqual(row,{prosecdef:true,proconfig:['search_path=pg_catalog, secureshop_review'],
      owner:'dvaia_secureshop_review_migration',executable:true,public_execute:false});
    for(const privilege of ['INSERT','UPDATE','DELETE'])assert.equal((await pool.query(
      "SELECT has_table_privilege(current_user,'secureshop_review.product_target_manual_preimages',$1) AS allowed",[privilege])).rows[0].allowed,false);
  }
  await products.cleanup(birth,{operationId:randomUUID()});
  assert.equal((await saved()).preimages.length,0);
  assert.deepEqual((await saved()).receipts,before.receipts);
  return {freshMigration:true,populatedMigration:true,migrationNoOp:true,runtimePrivileges:true};
}

function replaceControlledObservation(original,value) {
  const result=original.result;
  assert.equal(result.hops.length,1);
  const mcp={content:[{type:'text',text:JSON.stringify(value)}]};
  result.hops[0].result=mcp;
  const traces=original.traces.filter(row=>row.kind==='local_tool_result');
  assert.equal(traces.length,1);traces[0].result_json=JSON.stringify(mcp);
  const metadata=result.taskMetadata;
  if(metadata.productManualIngest)metadata.productManualIngest.observation=structuredClone(value);
  else {assert.equal(metadata.productAssist.operation,'similar');metadata.productAssist.observation=structuredClone(value);}
}

async function runProtectedManualSourceStorage(pools) {
  const migrationFacts=await qualifyPrivateMigration(pools);
  const f=fixture(),p=f.proof,r=p.receipt,review=pools.REVIEW.runtime;
  const birth={...p.birth,targetId:r.targetId};
  const authority={checkCurrent:async()=>{},checkCleanup:async()=>{},getRuntimeFingerprint:()=>r.runtimeFingerprint};
  const products=createSecureShopBoundProductRepository(review,authority);
  const retrieval=createSecureShopBoundProductRetrievalRepository(review,authority);
  const manuals=createSecureShopBoundManualIngestRepository(review,authority);
  const embeddings=createSecureShopEmbeddingRevisionRepository(review,authority);
  const vector=Array.from({length:384},(_,i)=>i===0?1:0);
  const product={id:r.productId,sourceRetailerId:1,retailerId:r.merchantId,name:'Owned product',
    description:'Public topic only',descriptionHtml:null,price:12,category:'fixture',imageUrl:null,
    images:[],stockQuantity:4,status:'active',templateSource:'{{source}}',createdAt:null,updatedAt:null};
  await products.provision(birth,{ownMerchantId:r.merchantId,products:[product]});
  await retrieval.provision(birth,{embeddingModel:r.embeddingModel,embeddingDimension:384,
    documents:[{sourceKind:'product',sourceId:r.productId,chunkIndex:0,
      text:`${product.name}\n${product.description}`,embedding:vector}]});
  const sibling={...birth,targetId:randomUUID(),launchId:randomUUID(),scenarioId:randomUUID(),platformOwnerId:birth.platformOwnerId+10};
  await products.provision(sibling,{ownMerchantId:r.merchantId,products:[product]});
  const siblingBefore=(await review.query('SELECT * FROM secureshop_review.product_target_products WHERE target_id=$1',[sibling.targetId])).rows;
  const uploader=await grant(review,birth,r.sceneId,r.sceneGrantId,r.execution);
  const consumer=await grant(review,birth,r.sceneId,p.consumer.grantId,p.consumer.execution.scope);
  const input={operationId:r.operationId,productId:r.productId,merchantId:r.merchantId,fileReceipt:r.fileReceipt,
    filename:r.filename,mime:r.mime,isPublic:false,extractor:r.extractor,extractionSha256:r.extractionSha256,
    embeddingModel:r.embeddingModel,embeddingDimension:384,chunks:JSON.parse(p.documentsJson),expectedRuntimeFingerprint:r.runtimeFingerprint};
  const captured=await manuals.appendManualWithProtectedLineage(uploader,input);
  assert.equal(captured.receipt.isPublic,false);assert.equal(captured.protectedLineage.version,2);
  assert.deepEqual(captured.lineage,{eligible:false,reason:'private_manual'});
  const publicId=randomUUID(),publicText='Public comparison manual neighbor';
  const publicInput={...input,operationId:publicId,isPublic:true,filename:'public.txt',
    extractionSha256:sha(publicText),chunks:[{text:publicText,embedding:vector}],
    fileReceipt:{...r.fileReceipt,virtualPath:`/uploads/product_manuals/${r.productId}/${publicId}-manual`}};
  const publicManual=await manuals.appendManualWithLineage(uploader,publicInput);
  assert.equal(publicManual.receipt.isPublic,true);
  const snapshot=await embeddings.snapshot(consumer),revisionId=randomUUID();
  const publish=operationId=>({operationId,sourceSetDigest:snapshot.sourceSetDigest,
    expectedHead:snapshot.expectedHead,expectedRuntimeFingerprint:r.runtimeFingerprint,
    documents:snapshot.documents.map(({text,...row})=>({...row,embedding:vector}))});
  await embeddings.publish(consumer,publish(revisionId));
  const searched=await embeddings.searchWithProtectedLineage(consumer,{embedding:vector,limit:5});
  assert.equal(searched.lineage.eligible,false,'V26 public proof must not accept private mixed source');
  assert.equal(searched.protectedLineage.eligible,true);
  assert.deepEqual(searched.protectedLineage.selected.map(row=>row.sourceId),[captured.receipt.manualSourceId]);
  assert.equal(searched.rows.filter(row=>row.sourceKind==='manual').length,2);
  assert.ok(searched.rows.some(row=>row.sourceId===publicManual.receipt.manualSourceId&&row.sourceKind==='manual'));
  const queryText=`${product.name}\n${product.description}`;
  const query={version:1,kind:'product_name_description',productId:r.productId,name:product.name,
    description:product.description,text:queryText,sha256:sha(queryText),runtimeFingerprint:r.runtimeFingerprint};
  const uploadOrigin={version:1,binding:p.uploader.binding,personaSession:p.uploader.personaSession,
    source:{sessionId:p.uploader.original.sessionId,requestId:p.uploader.original.requestId},
    runId:p.uploader.original.run.run_id,traceEventIds:p.uploader.original.traceEventIds,
    target:JSON.parse(JSON.stringify(uploader)),receipt:captured.receipt,lineage:captured.protectedLineage};
  const consumerOrigin={version:1,binding:p.consumer.binding,personaSession:p.consumer.personaSession,
    source:{sessionId:p.consumer.original.sessionId,requestId:p.consumer.original.requestId},
    runId:p.consumer.original.run.run_id,traceEventIds:p.consumer.original.traceEventIds,
    target:JSON.parse(JSON.stringify(consumer)),execution:p.consumer.execution,productId:r.productId,
    lineage:searched.protectedLineage,query};
  const uploadValue={...p.uploader.original.result.taskMetadata.productManualIngest.observation,
    chunk_ids:captured.receipt.chunkIds};
  replaceControlledObservation(p.uploader.original,uploadValue);
  const observation={seed:{id:r.productId,name:product.name},results:[],count:0,mode:'mixed',retrieved_context:searched.rows};
  replaceControlledObservation(p.consumer.original,observation);
  await seedTurn(pools.AGENTS.migration,pools.IDENTITY.migration,p.uploader.original,
    'secureshop_product_manual_ingest','protectedManualUploadOrigin',uploadOrigin,{abandoned:true});
  await seedTurn(pools.AGENTS.migration,pools.IDENTITY.migration,p.consumer.original,
    'secureshop_product_assist','protectedManualConsumerOrigin',consumerOrigin);
  const state={binding:p.consumer.binding,persona:{id:p.consumer.binding.shopUserId,role:'customer'},
    personaSession:p.consumer.personaSession,target:consumer,execution:p.consumer.execution,check:async()=>{}};
  const dependencies={agentsPool:pools.AGENTS.runtime,identityPool:pools.IDENTITY.runtime,reviewPool:review};
  const adapter=createProtectedManualSourceAdapter(dependencies);
  const reader=createProtectedManualSourceReader({current:async context=>context.state||state,...adapter,qualifyModel:f.qualifyModel});
  const request=consumerOrigin.source,source=await reader({},request);
  assert.deepEqual(source.lineage.receipt,captured.receipt);
  assert.deepEqual(source.lineage.query,query);
  assert.deepEqual(JSON.parse(source.semantic.observation.mcp.content[0].text),observation);
  assert.equal(source.semantic.response.text,p.consumer.original.result.text);
  assert.equal(source.semantic.response.text.includes(p.selected.text),false,'raw context is not final-answer disclosure');
  const preimage=await adapter.readRevisionPreimage({state,revisionId});
  const manualPreimage=await adapter.readManualPreimage({state,operationId:r.operationId});
  assert.equal(sha(preimage.sourceSetJson),source.lineage.revision.sourceSetDigest);
  assert.equal(sha(preimage.vectorsJson),source.lineage.revision.vectorDigest);
  assert.equal(sha(manualPreimage.documentsJson),captured.receipt.documentDigest);
  assert.equal(sha(manualPreimage.sceneReceiptJson),captured.receipt.receiptSha256);
  assert.equal(JSON.parse(manualPreimage.manualFieldsJson).isPublic,false);
  const nextId=randomUUID();await embeddings.publish(consumer,{...publish(nextId),expectedHead:revisionId});
  assert.equal((await embeddings.readHead(consumer)).revisionId,nextId);
  assert.deepEqual(await reader({},request),source,'new mutable head cannot replace retained original evidence');
  await assert.rejects(adapter.readReceipt({state,operationId:publicId}),{code:'MANUAL_RAG_SOURCE_UNAVAILABLE'});
  await assert.rejects(createManualRagSourceAdapter(dependencies).readReceipt({state,operationId:r.operationId}),{code:'MANUAL_RAG_SOURCE_UNAVAILABLE'});
  await assert.rejects(reader({}, {...request,sessionId:randomUUID()}),{code:'MANUAL_RAG_SOURCE_UNAVAILABLE'});
  await assert.rejects(reader({state:{...state,personaSession:{...state.personaSession,authorityVersion:'999'}}},request),{code:'MANUAL_RAG_SOURCE_UNAVAILABLE'});
  await assert.rejects(reader({state:{...state,binding:{...state.binding,platformOwnerId:999}}},request),{code:'MANUAL_RAG_SOURCE_UNAVAILABLE'});
  await assert.rejects(reader({state:{...state,target:{...consumer}}},request),{code:'SHOP_SCENE_STALE'});
  await products.cleanup(birth,{operationId:randomUUID()});
  await assert.rejects(reader({},request));
  const retained=(await review.query('SELECT receipt_sha256 FROM secureshop_review.product_target_manual_ingests WHERE operation_id=$1',[r.operationId])).rows;
  assert.equal(retained[0].receipt_sha256.toString('hex'),captured.receipt.receiptSha256);
  assert.deepEqual((await review.query('SELECT * FROM secureshop_review.product_target_products WHERE target_id=$1',[sibling.targetId])).rows,siblingBefore);
  return Object.freeze({schemaVersion:1,kind:'v31-private-source-storage',storageOnly:true,
    ...migrationFacts,
    controlledProviderTraces:true,actualModel:false,judge:false,objectiveCredit:false,
    physicalFileUpload:false,authenticatedApplicationReset:false,
    privateReceipt:true,mixedRetrieval:true,originalPreimages:true,originalRevisionAfterHeadAdvance:true,
    sessionBindingDenied:true,foreignOwnerDenied:true,retiredTargetDenied:true,siblingPreserved:true,
    originalRevisionId:revisionId,sourceSetDigest:source.lineage.revision.sourceSetDigest,
    vectorDigest:source.lineage.revision.vectorDigest,manualReceiptSha256:captured.receipt.receiptSha256});
}
module.exports={runProtectedManualSourceStorage,replaceControlledObservation};
