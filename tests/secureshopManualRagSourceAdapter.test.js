'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const {fixture}=require('./secureshopManualRagSourceContract.test');
const {createManualRagSourceReader}=require('../server/services/secureshopManualRagSourceReader');
const {createManualRagSourceAdapter}=require('../server/database/postgres/secureshopManualRagSourceAdapter');
const {canonicalDigest}=require('../server/services/mcp/protocolContext');
const clone=value=>structuredClone(value);
function setup(mutate=()=>{}, {source=fixture(), adapterFactory=createManualRagSourceAdapter,
 readerFactory=createManualRagSourceReader, expectedPrivate=false}={}){
 const f=source,p=f.proof,r=p.receipt,log=[];
 const target=JSON.parse(JSON.stringify(f.target));
 const uploadOrigin={version:1,binding:p.uploader.binding,personaSession:p.uploader.personaSession,
  source:{sessionId:p.uploader.original.sessionId,requestId:p.uploader.original.requestId},
  runId:p.uploader.original.run.run_id,traceEventIds:p.uploader.original.traceEventIds,
  target:{...target,scene:{sceneId:r.sceneId,sceneGeneration:r.sceneGeneration,grantId:r.sceneGrantId,execution:r.execution}},receipt:r,
  lineage:{eligible:true,version:1,documentsJson:p.documentsJson,normalizedChunksJson:[p.normalizedChunkJson],
   manualFieldsJson:p.integrity.manualFieldsJson,sceneReceiptJson:p.integrity.sceneReceiptJson,
   runtimeReceiptJson:p.integrity.runtimeReceiptJson,runtimeReceiptSha256:p.integrity.runtimeReceiptSha256}};
 const consumerOrigin={version:1,binding:p.consumer.binding,personaSession:p.consumer.personaSession,
  source:{sessionId:p.consumer.original.sessionId,requestId:p.consumer.original.requestId},
  runId:p.consumer.original.run.run_id,traceEventIds:p.consumer.original.traceEventIds,
  target,execution:p.consumer.execution,productId:r.productId,
  lineage:{eligible:true,version:1,revision:p.revision,sourceSetJson:p.integrity.sourceSetJson,
   vectorsJson:p.integrity.vectorsJson,selected:[p.selected],manualSources:[{sourceId:r.manualSourceId,
    operationId:r.operationId,productId:r.productId,merchantId:r.merchantId,receiptSha256:r.receiptSha256}]}};
 p.uploader.original.result.taskMetadata.manualRagUploadOrigin=uploadOrigin;
 p.consumer.original.result.taskMetadata.manualRagConsumerOrigin=consumerOrigin;
 function session(o){const b=o.binding;return {session_id:o.sessionId,request_id:o.requestId,
  request_version:o.requestVersion,request_hash:o.requestHash,status:o.status,result_json:o.result,
  messages_json:JSON.stringify([{role:'user',content:o.message}]),platform_launch_id:b.launchId,
  platform_scenario_id:b.scenarioId,platform_launch_generation:b.generation,original_platform_owner_id:b.platformOwnerId,
  original_platform_session_id:b.platformSessionId,user_id:b.shopUserId,role:b.role};}
 const fields={operation_id:r.operationId,manual_source_id:r.manualSourceId,target_id:r.targetId,
  launch_id:r.launchId,scenario_id:r.scenarioId,generation:r.generation,original_platform_owner_id:r.platformOwnerId,
  original_platform_session_id:r.platformSessionId,scene_id:r.sceneId,scene_generation:r.sceneGeneration,scene_grant_id:r.sceneGrantId,
  product_id:r.productId,merchant_id:r.merchantId,receipt_version:2,is_public:r.isPublic,receipt_valid:true,runtime_valid:true,
  runtime_fingerprint:Buffer.from(r.runtimeFingerprint,'hex'),file_target_id:r.fileReceipt.targetId,
  virtual_path:r.fileReceipt.virtualPath,byte_count:r.fileReceipt.bytes,file_sha256:Buffer.from(r.fileReceipt.sha256,'hex'),
  filename:r.filename,mime:r.mime,extractor:r.extractor,extraction_sha256:Buffer.from(r.extractionSha256,'hex'),
  embedding_model:r.embeddingModel,embedding_dimension:r.embeddingDimension,document_digest:Buffer.from(r.documentDigest,'hex'),
  document_count:r.documentCount,receipt_sha256:Buffer.from(r.receiptSha256,'hex'),completed_at:new Date(r.completedAt)};
 for(const [prefix,scope] of [['execution_',r.execution],['file_',r.fileReceipt]])
  for(const [sql,js] of [['launch_id','launchId'],['scenario_id','scenarioId'],['generation','generation'],['platform_owner_id','platformOwnerId'],['platform_session_id','platformSessionId']])fields[prefix+sql]=scope[js];
 const v=p.revision,revision={revision_id:v.revisionId,target_id:v.targetId,launch_id:v.launchId,scenario_id:v.scenarioId,
  generation:v.generation,original_platform_owner_id:v.platformOwnerId,original_platform_session_id:v.platformSessionId,
  runtime_fingerprint:v.runtimeFingerprint,source_set_digest:v.sourceSetDigest,vector_digest:v.vectorDigest,document_count:v.documentCount};
 const data={consumer:session(p.consumer.original),upload:session(p.uploader.original),fields,revision,active:true,grant:true,
  duplicate:false,missingEffect:false,stale:false,preimageMissing:false,preimageDuplicate:false,manualMissing:false,manualDuplicate:false,
  manual:{operation_id:r.operationId,target_id:r.targetId,documents_json:p.documentsJson,
   normalized_chunks_json:[p.normalizedChunkJson],manual_fields_json:p.integrity.manualFieldsJson,
   scene_receipt_json:p.integrity.sceneReceiptJson,runtime_receipt_json:p.integrity.runtimeReceiptJson,
   runtime_receipt_sha256:p.integrity.runtimeReceiptSha256},
  preimage:{...revision,source_set_json:p.integrity.sourceSetJson,vectors_json:p.integrity.vectorsJson}};mutate({data,p,consumerOrigin,uploadOrigin});
 const state={binding:p.consumer.binding,persona:{id:p.consumer.binding.shopUserId,role:'customer'},
  personaSession:p.consumer.personaSession,target:f.target,execution:p.consumer.execution,
  async check(){log.push('check');if(data.stale)throw Object.assign(Error('stale'),{code:'SHOP_SCENE_STALE'});}};
 const reviewClient={release(){},async query(sql,params){log.push(sql);
  if(['BEGIN','COMMIT','ROLLBACK'].includes(sql))return{rows:[]};
  if(sql.includes('assert_scene_execution_grant'))return{rows:[{allowed:data.grant}]};
  if(sql.includes('FOR SHARE OF t')){assert.deepEqual(params,[r.targetId,r.launchId,r.scenarioId,r.generation,r.platformOwnerId,r.platformSessionId]);return{rows:data.active?[{target_id:r.targetId}]:[]};}
  if(sql.includes('product_target_manual_preimages')){
   assert.equal(sql.includes('AND NOT i.is_public'),expectedPrivate);
   assert.equal(sql.includes('AND i.is_public'),!expectedPrivate);
   assert.deepEqual(params,[r.operationId,r.targetId,r.launchId,r.scenarioId,r.generation,r.platformOwnerId,r.platformSessionId,r.sceneId,r.sceneGeneration]);
   assert.match(sql,/p.operation_id=i.operation_id AND p.target_id=i.target_id/);
   assert.doesNotMatch(sql,/embedding_heads|retrieval_documents|float8|double precision/);
   if(data.manualError)throw data.manualError;
   return{rows:data.manualMissing?[]:data.manualDuplicate?[data.manual,data.manual]:[data.manual]};
  }
  if(sql.includes('product_target_manual_ingests')){assert.equal(params[0],r.operationId);assert.equal(params[7],r.sceneId);
   assert.equal(sql.includes('AND NOT i.is_public'),expectedPrivate);
   assert.equal(sql.includes('AND i.is_public'),!expectedPrivate);return{rows:[fields]};}
  if(sql.includes('product_target_embedding_preimages')){
   assert.deepEqual(params,[v.revisionId,r.targetId,r.launchId,r.scenarioId,r.generation,r.platformOwnerId,r.platformSessionId]);
   assert.match(sql,/p.revision_id=r.revision_id AND p.target_id=r.target_id/);
   assert.doesNotMatch(sql,/embedding_heads|embedding_documents|float8|jsonb_agg/);
   if(data.preimageError)throw data.preimageError;
   return{rows:data.preimageMissing?[]:data.preimageDuplicate?[data.preimage,data.preimage]:[data.preimage]};
  }
  if(sql.includes('product_target_embedding_revisions')){assert.equal(params[0],v.revisionId);assert.doesNotMatch(sql,/embedding_heads/);return{rows:[revision]};}
  throw Error('Unexpected review SQL');}};
 const agentsPool={async query(sql,params){log.push(sql);assert.doesNotMatch(sql,/binding_state='active'/);
  if(sql.includes('WITH original_traces')){const original=params[0]===p.consumer.original.sessionId?p.consumer.original:p.uploader.original;
   assert.deepEqual(params[9],original.traceEventIds);return{rows:original.traces.map(row=>({...row,id:String(row.id)}))};}
  const uploadKey=expectedPrivate?'protectedManualUploadOrigin':'manualRagUploadOrigin';
  const row=sql.includes(`${uploadKey},receipt,operationId`)?data.upload:data.consumer;
  if(row===data.upload){assert.equal(params[8],r.operationId);assert.equal(params[9],r.targetId);assert.equal(params[5],r.execution.platformSessionId);}
  return{rows:data.duplicate?[row,row]:[row]};}};
 const identityPool={async query(sql,params){log.push(sql);assert.doesNotMatch(sql,/graph_runtime.owners/);
  const o=params[0]===p.consumer.original.run.run_id?p.consumer.original:p.uploader.original;
  assert.equal(params[1],o.run.owner_key);
  if(sql.includes('graph_runtime.effects')){assert.equal(params[2],o.run.generation);assert.equal(params[3],o.effect.effect_key);return{rows:data.missingEffect?[]:[o.effect]};}
  return{rows:[o.run]};}};
 const adapter=adapterFactory({agentsPool,reviewPool:{connect:async()=>reviewClient},identityPool});
 const reader=readerFactory({current:async()=>state,...adapter,qualifyModel:f.qualifyModel});
 return {reader,adapter,state,data,p,log,request:{sessionId:p.consumer.original.sessionId,requestId:p.consumer.original.requestId}};
}

if (require.main === module) {
test('private SQL adapter reads historical uploader under current consumer grant and joins exact immutable IDs',async()=>{
 const f=setup();const result=await f.reader({},f.request);
 assert.equal(result.sourceDigest.length,64);assert.equal(result.lineage.receipt.operationId,f.p.receipt.operationId);
 assert.notEqual(f.p.uploader.binding.platformSessionId,f.state.binding.platformSessionId);
 assert.equal(f.log.filter(sql=>typeof sql==='string'&&sql==='COMMIT').length,4);
 assert.ok(f.log.filter(sql=>typeof sql==='string'&&sql.includes('FOR SHARE OF t')).length===4);
 assert.equal(f.log.some(sql=>typeof sql==='string'&&/\b(?:UPDATE|INSERT|DELETE)\b/.test(sql)),false);
});

test('SQL adapter preserves version2 original result for shared observation resolver',async()=>{
 const f=setup(({p})=>{const result=p.consumer.original.result,old=result.taskMetadata.productAssist;
  result.taskMetadata.productAssist={version:2,operation:old.operation,productId:old.productId,provider:old.provider,model:old.model,
   observationHop:{step:result.hops[0].step,observationSha256:canonicalDigest(result.hops[0].result)}};});
 const result=await f.reader({},f.request);assert.equal(result.sourceDigest.length,64);
 const read=await f.adapter.readConsumer({state:f.state,request:f.request,purpose:'secureshop_product_assist'});
 assert.equal(read.original.result.taskMetadata.productAssist.version,2);
 assert.equal(Object.hasOwn(read.original.result.taskMetadata.productAssist,'observation'),false);
});

test('SQL adapter refuses duplicate originals, substituted SQL receipts/revisions, missing effects and lost history',async()=>{
 const mutations=[
  ({data})=>{data.duplicate=true;},
  ({data})=>{data.fields.receipt_valid=false;},
  ({data})=>{data.fields.receipt_sha256=Buffer.alloc(32,9);},
  ({data})=>{data.revision.vector_digest='a'.repeat(64);},
  ({data})=>{data.missingEffect=true;},
  ({data})=>{data.upload.messages_json='[]';},
  ({data})=>{data.upload.original_platform_owner_id+=1;},
  ({data})=>{data.active=false;},
 ];
 for(const mutate of mutations){const f=setup(mutate);await assert.rejects(f.reader({},f.request),{code:'MANUAL_RAG_SOURCE_UNAVAILABLE'});}
});

test('SQL adapter requires branded current scene and propagates authority/storage failures',async()=>{
 const f=setup();f.state.target=clone(f.state.target);
 await assert.rejects(f.reader({},f.request),{code:'SHOP_SCENE_STALE'});
 const g=setup();g.data.stale=true;await assert.rejects(g.reader({},g.request),{code:'SHOP_SCENE_STALE'});
 const h=setup();h.data.grant=false;await assert.rejects(h.reader({},h.request),{code:'SHOP_SCENE_STALE'});
});


test('revision preimage reads exact immutable original bytes under consumer grant without mutable source reconstruction',async()=>{
 const f=setup(),value=await f.adapter.readRevisionPreimage({state:f.state,revisionId:f.p.revision.revisionId});
 assert.deepEqual(value,{revision:f.p.revision,sourceSetJson:f.p.integrity.sourceSetJson,vectorsJson:f.p.integrity.vectorsJson});
 assert.equal(Object.isFrozen(value),true);assert.equal(Object.isFrozen(value.revision),true);
 assert.equal(f.log.filter(sql=>sql==='COMMIT').length,1);
 assert.equal(f.log.filter(sql=>typeof sql==='string'&&sql.includes('assert_scene_execution_grant')).length,2);
 assert.equal(f.log.some(sql=>typeof sql==='string'&&/\b(?:INSERT|UPDATE|DELETE)\b/.test(sql)),false);
 assert.deepEqual(await f.adapter.readRevision({state:f.state,revisionId:f.p.revision.revisionId}),f.p.revision);
});

test('revision preimage missing historical payload, wrong birth or changed canonical bytes is ineligible',async()=>{
 const mutations=[f=>{f.preimageMissing=true;},f=>{f.preimageDuplicate=true;},
  f=>{f.preimage.revision_id='b0000000-0000-4000-8000-000000000077';},
  f=>{f.preimage.target_id='b0000000-0000-4000-8000-000000000077';},
  f=>{f.preimage.original_platform_owner_id++;},f=>{f.preimage.original_platform_session_id++;},
  f=>{f.preimage.generation++;},f=>{f.preimage.source_set_json+=' ';},f=>{f.preimage.vectors_json+=' ';},
  f=>{f.preimage.source_set_digest='0'.repeat(64);},f=>{f.preimage.vector_digest='0'.repeat(64);},
  f=>{f.preimage.source_set_json=null;},f=>{f.preimage.runtime_fingerprint='invalid';}];
 for(const mutate of mutations){const f=setup(({data})=>mutate(data));
  await assert.rejects(f.adapter.readRevisionPreimage({state:f.state,revisionId:f.p.revision.revisionId}),{code:'MANUAL_RAG_SOURCE_UNAVAILABLE'});
  assert.ok(f.log.includes('ROLLBACK'));assert.equal(f.log.includes('COMMIT'),false);
 }
});

test('revision preimage preserves branded grant, reset fence and database failures',async()=>{
 for(const mutate of [f=>{f.state.target=clone(f.state.target);},f=>{f.data.grant=false;},f=>{f.data.stale=true;}]){
  const f=setup();mutate(f);
  await assert.rejects(f.adapter.readRevisionPreimage({state:f.state,revisionId:f.p.revision.revisionId}),{code:'SHOP_SCENE_STALE'});
 }
 const f=setup();f.data.preimageError=Object.assign(Error('read unavailable'),{code:'57P01'});
 await assert.rejects(f.adapter.readRevisionPreimage({state:f.state,revisionId:f.p.revision.revisionId}),{code:'57P01'});
});

test('persisted revision preimages can exceed turn metadata capacity without truncating or reserializing bytes',async()=>{
 const {createHash}=require('node:crypto'),sha=text=>createHash('sha256').update(text).digest('hex');
 const f=setup(),p=f.data.preimage;
 const source=JSON.parse(p.source_set_json)[0],vector=JSON.parse(p.vectors_json)[0];
 p.source_set_json=JSON.stringify(Array.from({length:125},(_,i)=>({...source,sourceId:String(i+1)})));
 p.vectors_json=JSON.stringify(Array.from({length:125},(_,i)=>({...vector,sourceId:String(i+1)})));
 p.source_set_digest=sha(p.source_set_json);p.vector_digest=sha(p.vectors_json);p.document_count=125;
 assert.ok(Buffer.byteLength(p.source_set_json)+Buffer.byteLength(p.vectors_json)>48*1024);
 const value=await f.adapter.readRevisionPreimage({state:f.state,revisionId:f.p.revision.revisionId});
 assert.equal(value.sourceSetJson,p.source_set_json);assert.equal(value.vectorsJson,p.vectors_json);
 assert.equal(value.revision.documentCount,125);
});


test('manual preimage resolves exact original canonical JSON and immutable uploader receipt under consumer authority',async()=>{
 const f=setup(),value=await f.adapter.readManualPreimage({state:f.state,operationId:f.p.receipt.operationId});
 assert.deepEqual(value,{receipt:f.p.receipt,documentsJson:f.p.documentsJson,normalizedChunksJson:[f.p.normalizedChunkJson],
  manualFieldsJson:f.p.integrity.manualFieldsJson,sceneReceiptJson:f.p.integrity.sceneReceiptJson,
  runtimeReceiptJson:f.p.integrity.runtimeReceiptJson,runtimeReceiptSha256:f.p.integrity.runtimeReceiptSha256});
 assert.equal(Object.isFrozen(value.normalizedChunksJson),true);
 assert.notEqual(value.receipt.execution.platformSessionId,f.state.binding.platformSessionId);
 assert.equal(f.log.filter(sql=>sql==='COMMIT').length,1);
 assert.equal(f.log.some(sql=>typeof sql==='string'&&/\b(?:INSERT|UPDATE|DELETE)\b/.test(sql)),false);
});

test('manual preimage cannot be backfilled, replaced, reordered or divorced from original receipt hashes',async()=>{
 const mutations=[d=>{d.manualMissing=true;},d=>{d.manualDuplicate=true;},
  d=>{d.manual.target_id='b0000000-0000-4000-8000-000000000099';},
  d=>{d.manual.operation_id='b0000000-0000-4000-8000-000000000099';},
  d=>{d.manual.documents_json+=' ';},d=>{d.manual.scene_receipt_json+=' ';},d=>{d.manual.manual_fields_json+=' ';},
  d=>{d.manual.runtime_receipt_json+=' ';},d=>{d.manual.runtime_receipt_sha256='0'.repeat(64);},
  d=>{d.manual.normalized_chunks_json=[];},d=>{d.manual.normalized_chunks_json=['{}'];},
  d=>{d.fields.runtime_valid=false;}];
 for(const mutate of mutations){const f=setup(({data})=>mutate(data));
  await assert.rejects(f.adapter.readManualPreimage({state:f.state,operationId:f.p.receipt.operationId}),{code:'MANUAL_RAG_SOURCE_UNAVAILABLE'});
  assert.ok(f.log.includes('ROLLBACK'));
 }
 const f=setup();f.data.grant=false;
 await assert.rejects(f.adapter.readManualPreimage({state:f.state,operationId:f.p.receipt.operationId}),{code:'SHOP_SCENE_STALE'});
 const g=setup();g.data.manualError=Object.assign(Error('store unavailable'),{code:'57P01'});
 await assert.rejects(g.adapter.readManualPreimage({state:g.state,operationId:g.p.receipt.operationId}),{code:'57P01'});
});
}
// Controlled SQL row harness; importing it registers no tests and starts no I/O.
module.exports={setup};
