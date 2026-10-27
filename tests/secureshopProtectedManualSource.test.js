'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const {createHash} = require('node:crypto');
const {fixture} = require('./secureshopManualRagSourceContract.test');
const {validateManualRagSourceContract: publicValidate} = require('../server/services/secureshopManualRagSourceContract');
const {VERSION,validateProtectedManualSourceContract: validate} = require('../server/services/secureshopProtectedManualSourceContract');
const {createProtectedManualSourceReader: createReader} = require('../server/services/secureshopProtectedManualSourceReader');
const sha = value => createHash('sha256').update(value).digest('hex');
const clone = value => structuredClone(value);

// Controlled coherence fixture only: no real actor, embedding, DB or credit.
function privateFixture() {
  const f=fixture(), p=f.proof, i=p.integrity, r=p.receipt;
  p.version=VERSION; r.isPublic=false;
  i.manualFieldsJson=JSON.stringify({...JSON.parse(i.manualFieldsJson),isPublic:false});
  i.sceneReceiptJson=JSON.stringify({...JSON.parse(i.sceneReceiptJson),manualFieldsSha256:sha(i.manualFieldsJson)});
  r.receiptSha256=sha(i.sceneReceiptJson);
  i.runtimeReceiptJson=JSON.stringify({...JSON.parse(i.runtimeReceiptJson),originalReceiptSha256:r.receiptSha256});
  i.runtimeReceiptSha256=sha(i.runtimeReceiptJson);
  p.query={version:1,kind:'product_name_description',productId:r.productId,name:'Owned product',
    description:'Public topic only',text:'Owned product\nPublic topic only',
    sha256:sha('Owned product\nPublic topic only'),runtimeFingerprint:r.runtimeFingerprint};
  p.consumer.original.result.taskMetadata.protectedManualConsumerOrigin={query:clone(p.query)};
  return f;
}
function setup() {
  const f=privateFixture(),p=f.proof,r=p.receipt,c=p.consumer,u=p.uploader;
  const projected=(side,execution)=>({...p.birth,targetId:r.targetId,scene:{sceneId:r.sceneId,
    sceneGeneration:r.sceneGeneration,grantId:side.grantId,execution:clone(execution)}});
  const common=side=>({version:1,binding:clone(side.binding),personaSession:clone(side.personaSession),
    source:{sessionId:side.original.sessionId,requestId:side.original.requestId},runId:side.original.run.run_id,
    traceEventIds:clone(side.original.traceEventIds)});
  const consumer={...common(c),execution:clone(c.execution),productId:r.productId,
    target:projected(c,c.execution.scope),query:clone(p.query),lineage:{eligible:true,version:2,
      revision:clone(p.revision),selected:[clone(p.selected)],manualSources:[{sourceId:r.manualSourceId,
        operationId:r.operationId,productId:r.productId,merchantId:r.merchantId,receiptSha256:r.receiptSha256}],
      preimageRef:{version:1,revisionId:p.revision.revisionId,sourceSetDigest:p.revision.sourceSetDigest,
        vectorDigest:p.revision.vectorDigest}}};
  c.original.result.taskMetadata.protectedManualConsumerOrigin=clone(consumer);
  const upload={...common(u),target:projected(u,r.execution),receipt:clone(r),lineage:{eligible:true,
    version:2,preimageRef:{version:1,operationId:r.operationId,targetId:r.targetId,documentDigest:r.documentDigest,
      receiptSha256:r.receiptSha256,runtimeReceiptSha256:p.integrity.runtimeReceiptSha256}}};
  u.original.result.taskMetadata.protectedManualUploadOrigin=clone(upload);
  let checks=0, revoked=false;
  const state={binding:c.binding,persona:{id:c.binding.shopUserId,role:'customer'},personaSession:c.personaSession,
    target:f.target,execution:c.execution,async check(){checks++;if(revoked)throw Object.assign(Error('reset'),{code:'LAUNCH_STALE'});}};
  const deps={current:async()=>state,readConsumer:async()=>({origin:consumer,original:c.original}),
    readUploader:async()=>({origin:upload,original:u.original}),readReceipt:async()=>r,readRevision:async()=>p.revision,
    readRevisionPreimage:async()=>({revision:p.revision,sourceSetJson:p.integrity.sourceSetJson,vectorsJson:p.integrity.vectorsJson}),
    readManualPreimage:async()=>({receipt:r,documentsJson:p.documentsJson,normalizedChunksJson:f.normalizedChunksJson,
      ...Object.fromEntries(['manualFieldsJson','sceneReceiptJson','runtimeReceiptJson','runtimeReceiptSha256'].map(k=>[k,p.integrity[k]]))}),
    qualifyModel:f.qualifyModel};
  return {f,p,state,deps,consumer,upload,request:consumer.source,checks:()=>checks,revoke:()=>{revoked=true;}};
}
test('private source separates API observation from actor answer and does not create scoring facts',()=>{
  const f=privateFixture(),result=validate(f);
  assert.equal(result.lineage.receipt.isPublic,false);
  assert.equal(result.lineage.version,VERSION);
  assert.deepEqual(result.lineage.query,f.proof.query);
  assert.ok(result.semantic.observation.mcp.content[0].text.includes(f.proof.selected.text));
  assert.equal(result.semantic.response.text.includes(f.proof.selected.text),false);
  assert.equal(Object.hasOwn(result,'facts'),false);
  assert.equal(Object.hasOwn(result,'completed'),false);
});
test('closed public/private contracts reject crossover even with request visibility fields',()=>{
  assert.throws(()=>publicValidate({...privateFixture(),protectedSource:true}),{code:'MANUAL_RAG_SOURCE_INVALID'});
  const disguised=privateFixture();
  disguised.proof.version=require('../server/services/secureshopManualRagSourceContract').VERSION;
  delete disguised.proof.query;
  assert.throws(()=>publicValidate({...disguised,protectedSource:true}),{code:'MANUAL_RAG_SOURCE_INVALID'});
  assert.throws(()=>validate({...fixture(),isPublic:false}),{code:'MANUAL_RAG_SOURCE_INVALID'});
  const f=privateFixture();f.proof.receipt.isPublic=true;
  assert.throws(()=>validate(f),{code:'MANUAL_RAG_SOURCE_INVALID'});
});
test('private source rejects changed query, original observation, revision and receipt',()=>{
  for(const mutate of [p=>{p.query.text+=' changed';},p=>{p.query.productId++;},
    p=>{p.query.runtimeFingerprint='0'.repeat(64);},p=>{p.query.description+=' changed';},
    p=>{p.query.sha256='0'.repeat(64);},p=>{p.selected.revisionId=p.receipt.operationId;},
    p=>{p.integrity.sourceSetJson+=' ';},p=>{p.integrity.vectorsJson+=' ';},
    p=>{p.receipt.isPublic=true;},p=>{p.consumer.original.result.hops[0].result.content[0].text+=' ';},
    p=>{p.consumer.original.result.taskMetadata.protectedManualConsumerOrigin.query.text='replacement';}]) {
    const f=privateFixture();mutate(f.proof);
    assert.throws(()=>validate(f),{code:'MANUAL_RAG_SOURCE_INVALID'});
  }
});
test('private reader resolves original immutable references with authority checks around all reads',async()=>{
  const s=setup(),result=await createReader(s.deps)({},s.request);
  assert.equal(result.lineage.receipt.isPublic,false);assert.equal(s.checks(),13);
  assert.equal(result.lineage.revision.revisionId,s.p.selected.revisionId);
  assert.equal(result.sourceDigest.length,64);
});
test('private reader retains full mixed public/private observation while binding only selected private source',async()=>{
  const s=setup(),o=s.p.consumer.original;
  const observation=JSON.parse(o.result.hops[0].result.content[0].text);
  observation.retrieved_context.push({sourceKind:'manual',sourceId:99,chunkIndex:0,text:'Public neighbor',score:0.3});
  o.result.hops[0].result.content[0].text=JSON.stringify(observation);
  o.result.taskMetadata.productAssist.observation=clone(observation);
  o.traces.find(row=>row.kind==='local_tool_result').result_json=JSON.stringify(o.result.hops[0].result);
  const result=await createReader(s.deps)({},s.request);
  assert.equal(result.lineage.selected.sourceId,s.p.receipt.manualSourceId);
  assert.equal(JSON.parse(result.semantic.observation.mcp.content[0].text).retrieved_context.length,2);
});
test('private reader propagates current reset before and after reads; never recovers latest source',async()=>{
  for(const stage of ['before','consumer','revision','manual']) {
    const s=setup();
    if(stage==='before')s.revoke();
    else {const key={consumer:'readConsumer',revision:'readRevisionPreimage',manual:'readManualPreimage'}[stage];
      const read=s.deps[key];s.deps[key]=async input=>{const value=await read(input);s.revoke();return value;};}
    await assert.rejects(createReader(s.deps)({},s.request),{code:'LAUNCH_STALE'});
  }
});
test('private reader rejects missing originals and owner/session/scene/revision crossover',async()=>{
  for(const mutate of [s=>{s.consumer.lineage={eligible:false,reason:'missing_original'};},
    s=>{s.state.binding={...s.state.binding,platformOwnerId:999};},
    s=>{s.state.personaSession={...s.state.personaSession,authorityVersion:'999'};},
    s=>{s.consumer.target.scene.sceneGeneration++;},
    s=>{s.upload.receipt.isPublic=true;},s=>{s.consumer.query.text='latest replacement';},
    s=>{s.consumer.lineage.preimageRef.revisionId=s.p.receipt.operationId;}]) {
    const s=setup();mutate(s);
    await assert.rejects(createReader(s.deps)({},s.request),{code:'MANUAL_RAG_SOURCE_UNAVAILABLE'});
  }
});
test('repository captures private subset of mixed ranked manuals while public capture stays ineligible',async()=>{
  const {createSecureShopEmbeddingRevisionRepository}=require('../server/database/postgres/secureshopEmbeddingRevisionRepository');
  const f=privateFixture(),p=f.proof,r=p.receipt;
  const revision={...p.revision,documentCount:2};
  const embedding=Array.from({length:384},(_,i)=>i===0?1:0);
  const rows=[{source_kind:'manual',source_id:r.manualSourceId,chunk_index:0,body:p.selected.text,embedding},
    {source_kind:'manual',source_id:99,chunk_index:0,body:'Public neighbor',embedding}];
  const queries=[];
  const client={release(){},async query(sql){queries.push(sql);
    if(['BEGIN','COMMIT','ROLLBACK'].includes(sql))return {rows:[]};
    if(sql.includes('assert_scene_execution_grant'))return {rows:[{allowed:true}]};
    if(sql.includes('FOR SHARE OF t'))return {rows:[{target_id:r.targetId}]};
    if(sql.includes('product_target_embedding_heads'))return {rows:[{revision_id:revision.revisionId,
      document_count:2,fingerprint:revision.runtimeFingerprint,current_source:true}]};
    if(sql.includes('SELECT d.source_kind'))return {rows};
    if(sql.startsWith('WITH source AS')){
      const privateQuery=sql.includes('AND NOT i.is_public AND i.receipt_version=2');
      return {rows:[{digest_valid:true,oversized:false,lineage:{eligible:true,version:2,revision,
        preimageRef:{version:1,revisionId:revision.revisionId,sourceSetDigest:revision.sourceSetDigest,vectorDigest:revision.vectorDigest},
        manualSources:[{sourceId:privateQuery?r.manualSourceId:99,operationId:r.operationId,
          productId:r.productId,merchantId:r.merchantId,receiptSha256:r.receiptSha256}]},
        selected_sources:rows.map(row=>({sourceKind:'manual',sourceId:String(row.source_id),chunkIndex:0,
          text:row.body,sourceSha256:p.selected.sourceSha256}))}]};
    }
    throw Error('Unexpected SQL');
  }};
  const repository=createSecureShopEmbeddingRevisionRepository({connect:async()=>client,query:client.query},
    {checkCurrent:async()=>{},getRuntimeFingerprint:async()=>r.runtimeFingerprint});
  const result=await repository.searchWithProtectedLineage(f.target,{embedding,limit:5});
  assert.equal(result.lineage.eligible,false);
  assert.deepEqual(result.rows.map(row=>row.sourceId),[r.manualSourceId,99]);
  assert.deepEqual(result.protectedLineage.selected.map(row=>row.sourceId),[r.manualSourceId]);
  assert.equal(result.protectedLineage.revision.revisionId,revision.revisionId);
  assert.ok(queries.some(sql=>sql.includes('AND i.is_public AND i.receipt_version=2')));
  assert.ok(queries.some(sql=>sql.includes('AND NOT i.is_public AND i.receipt_version=2')));
  const publicResult=await repository.searchWithLineage(f.target,{embedding,limit:5});
  assert.equal(publicResult.lineage.eligible,false);
  assert.equal(Object.hasOwn(publicResult,'protectedLineage'),false);
});
test('adapter visibility is selected by closed factory, never input or dependency fields',async()=>{
  const {createManualRagSourceAdapter,createProtectedManualSourceAdapter}=require('../server/database/postgres/secureshopManualRagSourceAdapter');
  for(const [factory,privateSource] of [[createManualRagSourceAdapter,false],[createProtectedManualSourceAdapter,true]]) {
    const s=setup();let sqlRead;
    const client={release(){},async query(sql){
      if(['BEGIN','COMMIT','ROLLBACK'].includes(sql))return {rows:[]};
      if(sql.includes('assert_scene_execution_grant'))return {rows:[{allowed:true}]};
      if(sql.includes('FOR SHARE OF t'))return {rows:[{target_id:s.p.receipt.targetId}]};
      sqlRead=sql;
      return {rows:[{receipt_valid:true,runtime_valid:true,receipt_version:2,is_public:privateSource}]};
    }};
    const adapter=factory({agentsPool:{query:async()=>{}},identityPool:{query:async()=>{}},
      reviewPool:{connect:async()=>client},protectedSource:!privateSource});
    await assert.rejects(adapter.readReceipt({state:s.state,operationId:s.p.receipt.operationId,
      protectedSource:!privateSource,isPublic:privateSource}),{code:'MANUAL_RAG_SOURCE_UNAVAILABLE'});
    assert.equal(sqlRead.includes('AND NOT i.is_public'),privateSource);
    assert.equal(sqlRead.includes('AND i.is_public'),!privateSource);
  }
});

function sqlSetup(mutate=()=>{}) {
  const {setup:sqlFixture}=require('./secureshopManualRagSourceAdapter.test');
  const {createProtectedManualSourceAdapter}=require('../server/services/secureshopProtectedManualSourceReader');
  return sqlFixture(value=>{
    const {p,consumerOrigin,uploadOrigin}=value;
    // Persist the exact compact producer references used by the private path.
    // The public origin remains a distinct metadata object.
    const privateOrigin={...clone(consumerOrigin),query:clone(p.query)};
    const {sourceSetJson,vectorsJson,...search}=privateOrigin.lineage;
    privateOrigin.lineage={...search,version:2,preimageRef:{version:1,
      revisionId:p.revision.revisionId,sourceSetDigest:p.revision.sourceSetDigest,
      vectorDigest:p.revision.vectorDigest}};
    p.consumer.original.result.taskMetadata.protectedManualConsumerOrigin=privateOrigin;
    uploadOrigin.lineage={eligible:true,version:2,preimageRef:{version:1,
      operationId:p.receipt.operationId,targetId:p.receipt.targetId,documentDigest:p.receipt.documentDigest,
      receiptSha256:p.receipt.receiptSha256,runtimeReceiptSha256:p.integrity.runtimeReceiptSha256}};
    p.uploader.original.result.taskMetadata.protectedManualUploadOrigin=clone(uploadOrigin);
    mutate({...value,privateOrigin});
  },{source:privateFixture(),adapterFactory:createProtectedManualSourceAdapter,
    readerFactory:createReader,expectedPrivate:true});
}

test('private SQL adapter and reader reconstruct original immutable private DTO/preimages/consumer end to end',async()=>{
  const f=sqlSetup(),result=await f.reader({},f.request);
  assert.equal(result.lineage.version,VERSION);
  assert.equal(result.lineage.receipt.isPublic,false);
  assert.deepEqual(result.lineage.receipt,f.p.receipt);
  assert.deepEqual(result.lineage.query,f.p.query);
  assert.deepEqual(result.lineage.revision,f.p.revision);
  assert.deepEqual(result.lineage.selected,f.p.selected);
  assert.equal(result.lineage.consumer.original.runId,f.p.consumer.original.run.run_id);
  assert.deepEqual(result.lineage.consumer.original.traceEventIds,f.p.consumer.original.traceEventIds);
  assert.equal(result.semantic.response.text,f.p.consumer.original.result.text);
  assert.deepEqual(result.semantic.observation.mcp,f.p.consumer.original.result.hops[0].result);
  assert.equal(result.sourceDigest,require('../server/services/mcp/protocolContext').canonicalDigest(result.lineage));
  assert.equal(Object.isFrozen(result.lineage.receipt.fileReceipt),true);
  const sql=f.log.filter(row=>typeof row==='string');
  assert.equal(sql.filter(row=>row==='COMMIT').length,6);
  assert.equal(sql.filter(row=>row.includes('FOR SHARE OF t')).length,6);
  assert.equal(sql.filter(row=>row.includes('assert_scene_execution_grant')).length,12);
  for(const table of ['product_target_manual_preimages','product_target_embedding_preimages',
    'agent_trace','graph_runtime.runs','graph_runtime.effects'])assert.ok(sql.some(row=>row.includes(table)),table);
  assert.equal(sql.some(row=>/embedding_heads|retrieval_documents|\b(?:INSERT|UPDATE|DELETE)\b/.test(row)),false);
});

test('private SQL roundtrip denies visibility crossover, substituted immutable bytes and original consumer replacement',async()=>{
  for(const mutate of [({data})=>{data.fields.is_public=true;},
    ({data})=>{data.manual.documents_json+=' ';},
    ({data})=>{data.preimage.vectors_json+=' ';},
    ({data})=>{data.manualMissing=true;},({data})=>{data.preimageMissing=true;},
    ({data})=>{data.consumer.request_hash='0'.repeat(64);},
    ({data})=>{data.consumer.original_platform_session_id++;},
    ({privateOrigin})=>{privateOrigin.query.text='different original query';}]) {
    const f=sqlSetup(mutate);
    await assert.rejects(f.reader({},f.request),{code:'MANUAL_RAG_SOURCE_UNAVAILABLE'});
    assert.equal(f.log.some(row=>typeof row==='string'&&/embedding_heads|retrieval_documents/.test(row)),false);
  }
  // Opposite direction goes through the unchanged real public factories.
  const {setup:publicSetup}=require('./secureshopManualRagSourceAdapter.test');
  const publicReader=publicSetup(({data})=>{data.fields.is_public=false;});
  await assert.rejects(publicReader.reader({},publicReader.request),{code:'MANUAL_RAG_SOURCE_UNAVAILABLE'});
});
