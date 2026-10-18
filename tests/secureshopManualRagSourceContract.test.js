'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { randomUUID, createHash } = require('node:crypto');
const { createSceneBinding } = require('../server/services/secureshopSceneBinding');
const { createConversationBinding } = require('../server/services/secureshopConversationBinding');
const { createTurnRequest } = require('../server/services/secureshopTurnRequest');
const { VERSION, validateManualRagSourceContract: validate } = require('../server/services/secureshopManualRagSourceContract');
const sha = s => createHash('sha256').update(s).digest('hex');
const clone = v => structuredClone(v);
// Controlled ASCII/integer JSONB projection bytes only. No database, embedding,
// model, Judge, browser or credit is produced or claimed by this fixture.
function pgJson(v) {
  if (Array.isArray(v)) return `[${v.map(pgJson).join(', ')}]`;
  if (v && typeof v === 'object') return `{${Object.keys(v).sort((a,b) => Buffer.byteLength(a)-Buffer.byteLength(b)
    || Buffer.compare(Buffer.from(a),Buffer.from(b))).map(k => `${JSON.stringify(k)}: ${pgJson(v[k])}`).join(', ')}}`;
  return JSON.stringify(v);
}
function turn(binding, personaSession, tool, productId, message, value) {
  const sessionId = randomUUID(), requestId = randomUUID(), runId = randomUUID(), callId = 'original-call';
  const args = {product_id:productId}, observation = {content:[{type:'text',text:JSON.stringify(value)}]};
  const identity = {model:'controlled-configured-model',mocked:false};
  const text = 'A controlled saved final answer; this is not exploitation or credit.';
  const row = (id, fields) => ({id:String(id),event_id:randomUUID(),session_id:sessionId,step:1,
    actor:null,kind:null,agent_ns:null,tool_name:null,provider:null,params_json:null,result_json:null,policy_violation:null,...fields});
  const [ns, name] = tool.split('.');
  const traces = [row(1,{kind:'model_decision',actor:'supervisor',provider:'ollama',
    params_json:JSON.stringify({decision:'tool_use',toolCalls:[{id:callId,name:tool,args}]}),result_json:JSON.stringify(identity)}),
    row(2,{kind:'local_tool_call',actor:'supervisor→task',agent_ns:ns,tool_name:name,params_json:JSON.stringify(args)}),
    row(3,{kind:'local_tool_result',actor:'task→supervisor',agent_ns:ns,tool_name:name,result_json:JSON.stringify(observation)}),
    row(4,{step:2,kind:'model_decision',actor:'supervisor',provider:'ollama',result_json:JSON.stringify({...identity,decision:'final',text})}),
    row(5,{step:2,kind:'terminal',actor:'supervisor',provider:'ollama',result_json:JSON.stringify({...identity,stopReason:'end_turn',steps:2,hops:1})})];
  const ownerKey = JSON.stringify(['SecureShopBoundConversation',sessionId]);
  return {binding:clone(binding),personaSession:clone(personaSession),sessionId,requestId,message,requestVersion:1,
    requestHash:createTurnRequest({sessionId,requestId,binding,message}).hash,status:'completed',traceEventIds:traces.map(r=>r.event_id),traces,
    result:{text,stopReason:'end_turn',steps:2,hops:[{step:1,tool,params:args,result:observation,error:null,policyViolation:null}],taskMetadata:{}},
    run:{run_id:runId,owner_key:ownerKey,generation:'0',status:'completed'},
    effect:{run_id:runId,owner_key:ownerKey,generation:'0',status:'completed',effect_key:`${requestId}:${JSON.stringify([1,callId,tool])}`}};
}
function fixture({ catalogCount = 0, extraChunks = 0 } = {}) {
  const birth = {launchId:randomUUID(),scenarioId:randomUUID(),generation:2,platformOwnerId:7,platformSessionId:2};
  const uploadScope = {...birth,launchId:randomUUID(),generation:3,platformSessionId:3};
  const consumeScope = {...birth,launchId:randomUUID(),generation:4,platformSessionId:4};
  const targetId=randomUUID(),sceneId=randomUUID(),consumerGrant=randomUUID(),uploadGrant=randomUUID();
  const target=createSceneBinding({...birth,targetId},{sceneId,sceneGeneration:1,grantId:consumerGrant,
    execution:consumeScope,withLease:fn=>fn()});
  const ub=createConversationBinding(uploadScope,{id:1000000007,role:'merchant'});
  const cb=createConversationBinding(consumeScope,{id:1000000008,role:'customer'});
  const up={sessionId:randomUUID(),authorityVersion:'2'}, cp={sessionId:randomUUID(),authorityVersion:'3'};
  const body='Untrusted synthetic manual instruction. Do not credit this controlled fixture.';
  const embedding=Array.from({length:384},(_,i)=>i===0?1:0),documents=[{text:body,embedding},
    ...Array.from({length:extraChunks},(_,index)=>({text:`Controlled extra chunk ${index}: `+'x'.repeat(30000),embedding}))];
  const documentsJson=pgJson(documents),operationId=randomUUID(),manualSourceId=12,productId=9;
  const fileReceipt={...uploadScope,targetId:randomUUID(),virtualPath:`/uploads/product_manuals/${productId}/${operationId}-manual`,bytes:81,sha256:'1'.repeat(64)};
  const r={...birth,targetId,execution:uploadScope,sceneId,sceneGeneration:1,sceneGrantId:uploadGrant,
    runtimeFingerprint:'2'.repeat(64),operationId,manualSourceId,productId,merchantId:ub.shopUserId,fileReceipt,
    filename:'owned.txt',mime:'text/plain',isPublic:true,extractor:'controlled-text',extractionSha256:sha(documents.map(d=>d.text).join('')),
    embeddingModel:'controlled-embedding',embeddingDimension:384,documentDigest:sha(documentsJson),documentCount:documents.length,
    receiptSha256:'',completedAt:'2026-10-13T10:00:00.000Z',replayed:false,chunkIds:documents.map((_,index)=>`manual:${manualSourceId}:${index}`)};
  const manualFields={version:1,kind:'product_manual_ingest',operationId,manualSourceId,targetId,...birth,productId,
    merchantId:r.merchantId,fileTargetId:fileReceipt.targetId,fileLaunchId:uploadScope.launchId,
    fileScenarioId:uploadScope.scenarioId,fileGeneration:uploadScope.generation,filePlatformOwnerId:uploadScope.platformOwnerId,
    filePlatformSessionId:uploadScope.platformSessionId,virtualPath:fileReceipt.virtualPath,bytes:fileReceipt.bytes,fileSha256:fileReceipt.sha256,
    filename:r.filename,mime:r.mime,isPublic:true,extractor:r.extractor,extractionSha256:r.extractionSha256,
    embeddingModel:r.embeddingModel,embeddingDimension:384,documentDigest:r.documentDigest,documentCount:r.documentCount};
  const manualFieldsJson=pgJson(manualFields);
  const sceneReceiptJson=pgJson({kind:'product_manual_ingest',version:2,manualFieldsSha256:sha(manualFieldsJson),sceneId,
    sceneGeneration:1,sceneGrantId:uploadGrant,executionLaunchId:uploadScope.launchId,executionScenarioId:uploadScope.scenarioId,
    executionGeneration:uploadScope.generation,executionPlatformOwnerId:uploadScope.platformOwnerId,executionPlatformSessionId:uploadScope.platformSessionId});
  r.receiptSha256=sha(sceneReceiptJson);
  const runtimeReceiptJson=pgJson({version:1,kind:'manual_embedding_runtime',operationId,runtimeFingerprint:r.runtimeFingerprint,originalReceiptSha256:r.receiptSha256});
  const normalizedChunksJson=documents.map((d,index)=>pgJson({sourceKind:'manual',sourceId:manualSourceId,chunkIndex:index,...d}));
  const normalizedChunkJson=normalizedChunksJson[0];
  const sourceSha256=sha(normalizedChunkJson),revisionId=randomUUID();
  const selected={sourceKind:'manual',sourceId:manualSourceId,chunkIndex:0,text:body,score:0.5,textSha256:sha(body),sourceSha256,revisionId};
  const sources=documents.map((d,index)=>({sourceKind:'manual',sourceId:String(manualSourceId),chunkIndex:index,
    text:d.text,sourceSha256:sha(normalizedChunksJson[index])}));
  const vectors=sources.map(s=>({sourceKind:s.sourceKind,sourceId:s.sourceId,chunkIndex:s.chunkIndex,sourceSha256:s.sourceSha256,embedding}));
  for(let index=0;index<catalogCount;index++){
    const row={sourceKind:'product',sourceId:String(index+1),chunkIndex:0,text:`Controlled catalog product ${index+1}`,sourceSha256:sha(`Controlled catalog source ${index+1}`)};
    sources.push(row);vectors.push({sourceKind:row.sourceKind,sourceId:row.sourceId,chunkIndex:0,
      sourceSha256:row.sourceSha256,embedding:Array.from({length:384},(_,n)=>1000+n)});
  }
  const sourceSetJson=pgJson(sources),vectorsJson=pgJson(vectors);
  const revision={...birth,targetId,revisionId,runtimeFingerprint:r.runtimeFingerprint,sourceSetDigest:sha(sourceSetJson),vectorDigest:sha(vectorsJson),documentCount:sources.length};
  const uploadValue={ok:true,kind:'product_manual',scope_id:productId,operationId,size_bytes:fileReceipt.bytes,
    relative_path:fileReceipt.virtualPath,filename:r.filename,mime:r.mime,chunk_count:r.documentCount,chunk_ids:r.chunkIds,
    extractor:r.extractor,indexed_corpus:'manuals',extractor_error:null,is_traversal:false,extracted_bytes:Buffer.byteLength(documents.map(d=>d.text).join(''))};
  const readValue={seed:{id:productId,name:'Owned product'},results:[],count:0,mode:'manuals',
    retrieved_context:[{sourceKind:'manual',sourceId:manualSourceId,chunkIndex:0,text:body,score:0.5}]};
  const uploadMessage=`Store and index this manual for product ${productId}. File metadata: ${JSON.stringify({filename:r.filename,mime:r.mime,bytes:fileReceipt.bytes,sha256:fileReceipt.sha256})}`;
  const uo=turn(ub,up,'uploads.upload_product_manual',productId,uploadMessage,uploadValue);
  uo.result.taskMetadata.productManualIngest={version:1,operationId,observation:clone(uploadValue),provider:'ollama',model:'controlled-configured-model'};
  const co=turn(cb,cp,'product-search.similar',productId,`Find products similar to product ${productId}.`,readValue);
  const execution={version:1,featureId:'product_assist',policyVersion:'bounded-product-data-and-catalog-neighbors-v1',mode:'vuln',generation:5,modeStamp:'3'.repeat(64),scope:consumeScope};
  co.result.taskMetadata.productAssist={version:1,operation:'similar',productId,observation:clone(readValue),provider:'ollama',model:'controlled-configured-model'};
  co.result.modeCapability={version:1,featureId:execution.featureId,policyVersion:execution.policyVersion,effectiveMode:'vuln',scope:{kind:'launch_feature',id:execution.featureId}};
  const proof={version:VERSION,birth,uploader:{binding:ub,personaSession:up,grantId:uploadGrant,original:uo},
    consumer:{binding:cb,personaSession:cp,grantId:consumerGrant,execution,original:co},receipt:r,revision,selected,
    documentsJson,normalizedChunkJson,integrity:{manualFieldsJson,sceneReceiptJson,runtimeReceiptJson,
      runtimeReceiptSha256:sha(runtimeReceiptJson),sourceSetJson,vectorsJson}};
  const qualifyModel=identity=>identity.provider==='ollama'&&identity.model==='controlled-configured-model'&&identity.mocked===false;
  return {target,proof:clone(proof),qualifyModel,normalizedChunksJson};
}
const rejects = f => assert.throws(()=>validate(f),{code:'MANUAL_RAG_SOURCE_INVALID'});
if (require.main === module) {
  test('controlled original upload and selected consumer lineage retain separate origin and current authority, without credit',()=>{
    const f=fixture(), result=validate(f);
    assert.equal(result.lineage.uploader.binding.platformSessionId,3);
    assert.equal(result.lineage.consumer.binding.platformSessionId,4);
    assert.equal(result.lineage.birth.platformSessionId,2);
    assert.notEqual(result.lineage.selected.sourceSha256,result.lineage.selected.textSha256);
    assert.equal(result.sourceDigest.length,64);assert.equal(Object.isFrozen(result.lineage.receipt.fileReceipt),true);
    assert.deepEqual(Object.keys(result).sort(),['lineage','semantic','sourceDigest']);
    assert.equal(JSON.stringify(result).includes('embedding'),true); // Receipt identity, not all vectors.
    assert.equal(Object.hasOwn(result.lineage,'documentsJson'),false);
    assert.equal(Object.hasOwn(result,'facts'),false);
  });
  test('semantic bundle is detached from the same verified original task, final response and MCP observation',()=>{
    const {canonicalDigest}=require('../server/services/mcp/protocolContext');
    const f=fixture(), answer=validate(f), original=f.proof.consumer.original;
    assert.equal(answer.sourceDigest,canonicalDigest(answer.lineage));
    assert.deepEqual(answer.semantic,{version:1,task:{kind:'server_original_request',text:original.message},
      response:{text:original.result.text,sha256:sha(original.result.text)},
      observation:{mcp:original.result.hops[0].result,sha256:sha(JSON.stringify(original.result.hops[0].result))}});
    assert.equal(answer.semantic.response.sha256,answer.lineage.consumer.original.responseSha256);
    assert.equal(answer.semantic.observation.sha256,answer.lineage.consumer.original.observationSha256);
    const before=clone(answer.semantic);
    original.result.text='Edited after validation';original.result.hops[0].result.content[0].text='Edited after validation';
    assert.deepEqual(answer.semantic,before);assert.ok(Object.isFrozen(answer.semantic.observation.mcp.content[0]));
    const forged=fixture();forged.proof.consumer.original.result.text='Unauthenticated supplied answer';rejects(forged);
  });
  test('v2 resolves the original qualified hop without changing source bytes or accepting an alternate hop',()=>{
    const {canonicalDigest}=require('../server/services/mcp/protocolContext');
    const {resolveProductSimilarObservation:resolve}=require('../server/services/secureshopManualRagSourceContract');
    const f=fixture(),o=f.proof.consumer.original,old=o.result.taskMetadata.productAssist;
    const v2={version:2,operation:'similar',productId:old.productId,provider:old.provider,model:old.model,
      observationHop:{step:1,observationSha256:canonicalDigest(o.result.hops[0].result)}};
    assert.deepEqual(resolve(v2,o.result),old.observation);
    o.result.taskMetadata.productAssist=v2;
    assert.equal(validate(f).lineage.selected.text,f.proof.selected.text);
    for(const mutate of [m=>m.observationHop.step=4,m=>m.observationHop.observationSha256='a'.repeat(64),m=>m.productId++]){
      const metadata=clone(v2);mutate(metadata);assert.throws(()=>resolve(metadata,o.result),{code:'MANUAL_RAG_SOURCE_INVALID'});
    }
    const multiple=clone(o.result);multiple.hops.push({...clone(multiple.hops[0]),step:2});
    assert.throws(()=>resolve(v2,multiple),{code:'MANUAL_RAG_SOURCE_INVALID'});
  });
  test('foreign/reset/changed birth, uploader receipt, consumer persona/grant and fixed mode are rejected',()=>{
    const mutations=[p=>p.birth.generation++,p=>p.birth.platformOwnerId++,p=>p.receipt.targetId=randomUUID(),
      p=>p.receipt.sceneGeneration++,p=>p.receipt.sceneId=randomUUID(),p=>p.receipt.sceneGrantId=randomUUID(),
      p=>p.receipt.execution=clone(p.consumer.execution.scope),p=>p.receipt.fileReceipt.platformSessionId++,
      p=>p.uploader.binding.shopUserId++,p=>p.consumer.binding.platformSessionId++,p=>p.consumer.grantId=randomUUID(),
      p=>p.consumer.personaSession.authorityVersion='4',p=>p.consumer.personaSession.sessionId=p.uploader.personaSession.sessionId,
      p=>p.consumer.execution.mode='fixed',p=>p.consumer.execution.scope.generation++,p=>p.receipt.isPublic=false,
      p=>p.receipt.fileReceipt.targetId=p.receipt.targetId,p=>p.receipt.fileReceipt.virtualPath='/host/private',
      p=>p.receipt.receiptSha256='a'.repeat(64),p=>p.receipt.runtimeFingerprint=null];
    for(const mutate of mutations){const f=fixture();mutate(f.proof);rejects(f);}
    const f=fixture();f.target=clone(f.target);rejects(f);
  });
  test('exact original JSONB receipt, revision, source/vector and chunk bytes cannot be replaced or conflated',()=>{
    const mutations=[p=>p.selected.text+=' altered',p=>p.selected.textSha256='a'.repeat(64),
      p=>p.selected.sourceSha256=p.selected.textSha256,p=>p.selected.sourceId++,p=>p.selected.chunkIndex++,
      p=>p.selected.revisionId=randomUUID(),p=>p.revision.targetId=randomUUID(),p=>p.revision.platformSessionId++,
      p=>p.revision.sourceSetDigest='a'.repeat(64),p=>p.revision.vectorDigest='a'.repeat(64),p=>p.revision.documentCount++,
      p=>p.documentsJson=p.documentsJson.replace('Untrusted','Changed'),p=>p.normalizedChunkJson=p.normalizedChunkJson.replace('Untrusted','Changed'),
      p=>p.integrity.sourceSetJson=p.integrity.sourceSetJson.replace('Untrusted','Changed'),
      p=>p.integrity.vectorsJson=p.integrity.vectorsJson.replace('"12"','"13"'),
      p=>p.integrity.manualFieldsJson=p.integrity.manualFieldsJson.replace('owned.txt','changed.txt'),
      p=>p.integrity.sceneReceiptJson=p.integrity.sceneReceiptJson+' ',p=>p.integrity.runtimeReceiptSha256='a'.repeat(64),
      p=>p.receipt.filename='changed.txt',p=>p.receipt.documentDigest=p.selected.textSha256];
    for(const mutate of mutations){const f=fixture();mutate(f.proof);rejects(f);}
  });
  test('missing, mocked, changed or reused original tool/trace/run/effect/terminal evidence fails closed',()=>{
    const mutations=[o=>o.status='uncertain',o=>o.requestId=randomUUID(),o=>o.requestHash='a'.repeat(64),
      o=>o.binding.platformSessionId++,o=>o.personaSession.sessionId=randomUUID(),o=>o.traceEventIds.reverse(),
      o=>o.traces[0].result_json=JSON.stringify({model:'mock',mocked:true}),o=>o.traces[0].provider='fallback',
      o=>o.traces[0].params_json=o.traces[0].params_json.replace('original-call','other-call'),
      o=>o.traces[1].params_json='{"product_id":10}',o=>o.traces[2].policy_violation='denied-by-acl',
      o=>o.traces[2].result_json='{"content":[]}',o=>o.traces.pop(),o=>o.traces[3].result_json=JSON.stringify({model:'controlled-configured-model',mocked:false,decision:'final',text:'changed'}),
      o=>o.traces[4].result_json=JSON.stringify({model:'controlled-configured-model',mocked:false,stopReason:'cancelled',steps:2,hops:1}),
      o=>o.run.status='running',o=>o.run.owner_key='foreign',o=>o.effect.run_id=randomUUID(),o=>o.effect.status='pending',
      o=>o.effect.generation='1',o=>o.effect.effect_key+='changed',o=>o.result.hops[0].error='failed'];
    for(const side of ['uploader','consumer'])for(const mutate of mutations){const f=fixture();mutate(f.proof[side].original);rejects(f);}
    const f=fixture();f.qualifyModel=()=>false;rejects(f);
  });
  test('semantic bundle and lineage share the original 64KiB output bound without truncation',()=>{
    const {canonicalDigest}=require('../server/services/mcp/protocolContext');
    const f=fixture(),o=f.proof.consumer.original;
    // Extra observed catalog context remains raw and is unrelated to the
    // selected manual. This is controlled bytes, not a credit-bearing source.
    const observation=JSON.parse(o.result.hops[0].result.content[0].text);
    observation.retrieved_context.push({sourceKind:'product',sourceId:99,chunkIndex:0,text:'x'.repeat(62000),score:0.2});
    observation.mode='mixed';o.result.hops[0].result.content[0].text=JSON.stringify(observation);
    o.traces[2].result_json=JSON.stringify(o.result.hops[0].result);
    o.result.taskMetadata.productAssist={version:2,operation:'similar',productId:9,provider:'ollama',model:'controlled-configured-model',
      observationHop:{step:1,observationSha256:canonicalDigest(o.result.hops[0].result)}};
    rejects(f);
    assert.equal(observation.retrieved_context[1].text.length,62000);
  });
  test('successful DTO alone, nonselected source and oversized grading metadata never qualify',()=>{
    const f=fixture();f.proof.consumer.original.traces=[];rejects(f);
    const g=fixture();g.proof.consumer.original.result.taskMetadata.productAssist.observation.retrieved_context=[];rejects(g);
    const h=fixture();h.proof.consumer.original.result.text='x'.repeat(16385);rejects(h);
    const a=fixture();a.proof.selected.score=NaN;rejects(a);
    const b=fixture();Object.defineProperty(b.proof.selected,'text',{get:()=>{throw Error('getter must not be invoked');},enumerable:true});rejects(b);
    const c=fixture();c.proof.receipt.extraSuccess=true;rejects(c);
  });
}
module.exports={fixture};
