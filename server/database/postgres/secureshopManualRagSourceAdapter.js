'use strict';

// Private assessment projection. Historical uploader sessions provide provenance
// only; every read is admitted by the current consumer's branded scene grant.
const { isDeepStrictEqual: equal } = require('node:util');
const { createHash } = require('node:crypto');
const { withTransaction } = require('./index');
const { executionScope, assertSceneGrant, withSceneLease } = require('../../services/secureshopSceneBinding');
const { createLaunchScope, createConversationBinding } = require('../../services/secureshopConversationBinding');
const { createTurnRequest } = require('../../services/secureshopTurnRequest');
const { SECURESHOP_CONVERSATION_PURPOSES: PURPOSES } = require('../../services/secureshopConversationPurpose');
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const BIRTH = ['targetId','launchId','scenarioId','generation','platformOwnerId','platformSessionId'];
const SESSION_COLUMNS = ['platform_launch_id','platform_scenario_id','platform_launch_generation',
  'original_platform_owner_id','original_platform_session_id','user_id','role'];
const fail = () => Object.assign(Error('Manual RAG source unavailable'), { code: 'MANUAL_RAG_SOURCE_UNAVAILABLE' });
const need = ok => { if (!ok) throw fail(); };
const parse = value => { try { return JSON.parse(value); } catch { throw fail(); } };
const byteSize = value => Buffer.byteLength(JSON.stringify(value), 'utf8');
const freeze = value => { if (value && typeof value === 'object') { Object.values(value).forEach(freeze); Object.freeze(value); } return value; };
const coordinates = b => [b.launchId,b.scenarioId,b.generation,b.platformOwnerId,b.platformSessionId,b.shopUserId,b.role];
const predicate = (alias, start) => SESSION_COLUMNS.map((column, index) => `${alias}.${column}=$${start+index}`).join(' AND ');
const TURN_COLUMNS = `tr.session_id,tr.request_id,tr.request_version,tr.request_hash,tr.status,tr.result_json,
 CASE WHEN octet_length(s.messages_json)<=1048576 THEN s.messages_json ELSE NULL END AS messages_json,
 s.platform_launch_id,s.platform_scenario_id,s.platform_launch_generation,
 s.original_platform_owner_id,s.original_platform_session_id,s.user_id,s.role`;
const RECEIPT_SQL = `SELECT i.*,r.runtime_fingerprint,
 i.receipt_sha256=secureshop_review.product_manual_scene_receipt_digest(i) AS receipt_valid,
 (r.original_receipt_sha256=i.receipt_sha256 AND r.receipt_sha256=
  secureshop_review.manual_runtime_receipt_digest(r.operation_id,r.runtime_fingerprint,r.original_receipt_sha256)) AS runtime_valid
 FROM secureshop_review.product_target_manual_ingests i
 JOIN secureshop_review.product_target_manual_runtime_receipts r USING(operation_id)
 WHERE i.operation_id=$1 AND i.target_id=$2 AND i.launch_id=$3 AND i.scenario_id=$4
 AND i.generation=$5 AND i.original_platform_owner_id=$6 AND i.original_platform_session_id=$7
 AND i.scene_id=$8 AND i.scene_generation=$9 AND i.receipt_version=2 AND i.is_public`;
function number(value) { const n = Number(value); need(Number.isSafeInteger(n) && n > 0); return n; }
function digest(value) { need(Buffer.isBuffer(value) && value.length===32); return value.toString('hex'); }
function scopeColumns(row, prefix='') {
  return { launchId: row[`${prefix}launch_id`], scenarioId: row[`${prefix}scenario_id`],
    generation: number(row[`${prefix}generation`]), platformOwnerId: number(row[`${prefix}platform_owner_id`]),
    platformSessionId: number(row[`${prefix}platform_session_id`]) };
}
function receiptDto(row) {
  need(row?.receipt_valid===true && row.runtime_valid===true && row.receipt_version===2 && row.is_public===true);
  const count = number(row.document_count), sourceId = number(row.manual_source_id);
  need(count<=129);
  const completed = new Date(row.completed_at); need(Number.isFinite(completed.getTime()));
  return freeze({ runtimeFingerprint:digest(row.runtime_fingerprint),operationId:row.operation_id,
    manualSourceId:sourceId,targetId:row.target_id,launchId:row.launch_id,scenarioId:row.scenario_id,
    generation:number(row.generation),platformOwnerId:number(row.original_platform_owner_id),
    platformSessionId:number(row.original_platform_session_id),execution:scopeColumns(row,'execution_'),
    sceneId:row.scene_id,sceneGeneration:number(row.scene_generation),sceneGrantId:row.scene_grant_id,
    productId:number(row.product_id),merchantId:number(row.merchant_id),
    fileReceipt:{targetId:row.file_target_id,...scopeColumns(row,'file_'),virtualPath:row.virtual_path,
      bytes:number(row.byte_count),sha256:digest(row.file_sha256)},filename:row.filename,mime:row.mime,
    isPublic:row.is_public,extractor:row.extractor,extractionSha256:digest(row.extraction_sha256),
    embeddingModel:row.embedding_model,embeddingDimension:number(row.embedding_dimension),
    documentDigest:digest(row.document_digest),documentCount:count,receiptSha256:digest(row.receipt_sha256),
    completedAt:completed.toISOString(),replayed:false,
    chunkIds:Array.from({length:count},(_,index)=>`manual:${sourceId}:${index}`) });
}

function createManualRagSourceAdapter({ agentsPool, reviewPool, identityPool } = {}) {
  if (typeof agentsPool?.query!=='function' || typeof identityPool?.query!=='function'
      || typeof reviewPool?.connect!=='function') throw new TypeError('Manual RAG source pools required');
  async function query(state, pool, sql, params) {
    await state.check(); const result=await pool.query(sql,params); await state.check(); return result;
  }
  async function admitted(state, work) {
    need(state && typeof state.check==='function' && state.target?.scene && state.binding?.role==='customer'
      && state.persona?.role==='customer' && state.persona.id===state.binding.shopUserId);
    const b=createConversationBinding(state.binding,state.persona), target=state.target;
    need(equal(b,state.binding) && equal(createLaunchScope(b),executionScope(target)));
    await state.check();
    return withSceneLease(target,()=>withTransaction(reviewPool,async client=>{
      await assertSceneGrant(client,target);
      const rows=(await query(state,client,`SELECT t.target_id FROM secureshop_review.product_targets t
        WHERE t.target_id=$1 AND t.launch_id=$2 AND t.scenario_id=$3 AND t.generation=$4
        AND t.original_platform_owner_id=$5 AND t.original_platform_session_id=$6
        AND t.lifecycle='active' FOR SHARE OF t`,BIRTH.map(key=>target[key]))).rows;
      need(rows.length===1);
      const result=await work(client);
      await assertSceneGrant(client,target);await state.check();return result;
    }));
  }
  async function receipt(state,client,operationId) {
    need(UUID.test(operationId||''));const t=state.target;
    const rows=(await query(state,client,RECEIPT_SQL,[operationId,...BIRTH.map(key=>t[key]),t.scene.sceneId,t.scene.sceneGeneration])).rows;
    need(rows.length===1);return receiptDto(rows[0]);
  }
  async function original(state,row,purpose,kind,expectedBinding) {
    need(row?.status==='completed' && row.request_version===1 && UUID.test(row.session_id||'') && UUID.test(row.request_id||'')
      && row.result_json && byteSize(row.result_json)<=262144 && typeof row.messages_json==='string');
    const binding=createConversationBinding({launchId:row.platform_launch_id,scenarioId:row.platform_scenario_id,
      generation:number(row.platform_launch_generation),platformOwnerId:number(row.original_platform_owner_id),
      platformSessionId:number(row.original_platform_session_id)},{id:number(row.user_id),role:row.role});
    need(equal(binding,expectedBinding));
    const result=row.result_json,origin=result.taskMetadata?.[kind==='upload'?'manualRagUploadOrigin':'manualRagConsumerOrigin'];
    need(origin?.version===1 && equal(origin.binding,binding) && origin.source?.sessionId===row.session_id
      && origin.source?.requestId===row.request_id && UUID.test(origin.runId||'')
      && UUID.test(origin.personaSession?.sessionId||'') && /^[1-9]\d*$/.test(origin.personaSession?.authorityVersion||''));
    if(kind==='consumer')need(equal(origin.personaSession,state.personaSession));
    const messages=parse(row.messages_json);need(Array.isArray(messages));
    const matches=new Set();
    for(const message of messages){
      if(message?.role!=='user'||typeof message.content!=='string'||Buffer.byteLength(message.content)>65536)continue;
      if(createTurnRequest({sessionId:row.session_id,requestId:row.request_id,binding,message:message.content}).hash===row.request_hash)matches.add(message.content);
    }
    need(matches.size===1);
    const ids=origin.traceEventIds;need(Array.isArray(ids)&&ids.length>=4&&ids.length<=4096
      && ids.every(id=>UUID.test(id||''))&&new Set(ids).size===ids.length);
    const traces=(await query(state,agentsPool,`WITH original_traces AS (
      SELECT t.event_id,t.id::text AS id,t.session_id,t.step,t.actor,t.kind,t.agent_ns,t.tool_name,
       t.params_json,t.result_json,t.provider,t.policy_violation
      FROM secureshop_agents.agent_trace t JOIN secureshop_agents.agent_sessions s ON s.id=t.session_id
      WHERE s.id=$1 AND s.authority_mode='launch_bound' AND s.conversation_purpose=$2
       AND ${predicate('s',3)} AND t.event_id=ANY($10::text[])
    ) SELECT * FROM original_traces WHERE
      (SELECT COALESCE(sum(octet_length(row_to_json(o)::text)),0) FROM original_traces o)<=1048576
      ORDER BY id::bigint`,[row.session_id,purpose,...coordinates(binding),ids])).rows;
    need(traces.length===ids.length && equal(traces.map(trace=>trace.event_id),ids));
    const tool=kind==='upload'?'uploads.upload_product_manual':'product-search.similar';
    const hops=result.hops?.filter(hop=>hop.tool===tool);need(hops?.length===1);
    const hop=hops[0];need(hop.error===null&&hop.policyViolation===null);
    const decisions=traces.filter(trace=>trace.kind==='model_decision'&&trace.actor==='supervisor'
      &&trace.step===hop.step&&parse(trace.params_json||'null')?.decision==='tool_use');
    need(decisions.length===1);
    const calls=parse(decisions[0].params_json).toolCalls;
    need(Array.isArray(calls)&&calls.length===1&&calls[0].name===tool&&equal(calls[0].args,hop.params)
      &&typeof calls[0].id==='string'&&calls[0].id.length>0&&Buffer.byteLength(calls[0].id)<=128);
    const owner=JSON.stringify(['SecureShopBoundConversation',row.session_id]);
    // Historical completed generation is evidence. Current authority belongs to
    // the consumer scene; joining graph owners' *current* generation is wrong.
    const runs=(await query(state,identityPool,`SELECT run_id,owner_key,generation::text AS generation,status
      FROM graph_runtime.runs WHERE run_id=$1 AND owner_key=$2 AND status='completed'`,[origin.runId,owner])).rows;
    need(runs.length===1);
    const effectKey=`${row.request_id}:${JSON.stringify([hop.step,calls[0].id,tool])}`;
    const effects=(await query(state,identityPool,`SELECT run_id,owner_key,generation::text AS generation,effect_key,status
      FROM graph_runtime.effects WHERE run_id=$1 AND owner_key=$2 AND generation=$3 AND effect_key=$4 AND status='completed'`,
    [origin.runId,owner,runs[0].generation,effectKey])).rows;
    need(effects.length===1);
    return freeze({origin,original:{binding,personaSession:origin.personaSession,sessionId:row.session_id,
      requestId:row.request_id,message:[...matches][0],requestVersion:row.request_version,requestHash:row.request_hash,
      status:row.status,traceEventIds:ids,traces,result,run:runs[0],effect:effects[0]}});
  }
  return Object.freeze({
    readConsumer({state,request,purpose}) {
      need(purpose===PURPOSES.productAssist&&UUID.test(request?.sessionId||'')&&UUID.test(request?.requestId||''));
      return admitted(state,async()=>{
        const rows=(await query(state,agentsPool,`SELECT ${TURN_COLUMNS}
          FROM secureshop_agents.turn_requests tr JOIN secureshop_agents.agent_sessions s ON s.id=tr.session_id
          WHERE tr.request_id=$1 AND s.conversation_purpose=$2 AND s.authority_mode='launch_bound'
           AND ${predicate('s',3)} LIMIT 2`,[request.requestId,purpose,...coordinates(state.binding)])).rows;
        need(rows.length===1&&rows[0].session_id===request.sessionId);
        return original(state,rows[0],purpose,'consumer',state.binding);
      });
    },
    readUploader({state,operationId,manualSource,purpose}) {
      need(purpose===PURPOSES.productManualIngest);
      return admitted(state,async client=>{
        const stored=await receipt(state,client,operationId);
        need(manualSource?.sourceId===stored.manualSourceId&&manualSource.operationId===stored.operationId
          &&manualSource.productId===stored.productId&&manualSource.merchantId===stored.merchantId
          &&manualSource.receiptSha256===stored.receiptSha256);
        const binding=createConversationBinding(stored.execution,{id:stored.merchantId,role:'merchant'});
        const rows=(await query(state,agentsPool,`SELECT ${TURN_COLUMNS}
          FROM secureshop_agents.turn_requests tr JOIN secureshop_agents.agent_sessions s ON s.id=tr.session_id
          WHERE tr.status='completed' AND s.conversation_purpose=$1 AND s.authority_mode='launch_bound'
           AND ${predicate('s',2)}
           AND tr.result_json#>>'{taskMetadata,manualRagUploadOrigin,receipt,operationId}'=$9
           AND tr.result_json#>>'{taskMetadata,manualRagUploadOrigin,target,targetId}'=$10 LIMIT 2`,
        [purpose,...coordinates(binding),operationId,state.target.targetId])).rows;
        need(rows.length===1);
        const value=await original(state,rows[0],purpose,'upload',binding);
        need(equal(value.origin.receipt,stored));return value;
      });
    },
    readReceipt({state,operationId}) { return admitted(state,client=>receipt(state,client,operationId)); },
    readManualPreimage({state,operationId}) {
      need(UUID.test(operationId||''));
      return admitted(state,async client=>{
        const stored=await receipt(state,client,operationId),t=state.target;
        const rows=(await query(state,client,`WITH original AS (
          SELECT i.*,p.documents_json,r.runtime_fingerprint,r.original_receipt_sha256,
           r.receipt_sha256 AS runtime_receipt_sha256
          FROM secureshop_review.product_target_manual_ingests i
          JOIN secureshop_review.product_target_manual_preimages p
           ON p.operation_id=i.operation_id AND p.target_id=i.target_id
          JOIN secureshop_review.product_target_manual_runtime_receipts r ON r.operation_id=i.operation_id
          WHERE i.operation_id=$1 AND i.target_id=$2 AND i.launch_id=$3 AND i.scenario_id=$4
           AND i.generation=$5 AND i.original_platform_owner_id=$6 AND i.original_platform_session_id=$7
           AND i.scene_id=$8 AND i.scene_generation=$9 AND i.receipt_version=2 AND i.is_public
        ), fields AS (
          SELECT i.*,jsonb_build_object(
           'version',1,'kind','product_manual_ingest','operationId',i.operation_id,'manualSourceId',i.manual_source_id,
           'targetId',i.target_id,'launchId',i.launch_id,'scenarioId',i.scenario_id,'generation',i.generation,
           'platformOwnerId',i.original_platform_owner_id,'platformSessionId',i.original_platform_session_id,
           'productId',i.product_id,'merchantId',i.merchant_id,'fileTargetId',i.file_target_id,
           'fileLaunchId',i.file_launch_id,'fileScenarioId',i.file_scenario_id,'fileGeneration',i.file_generation,
           'filePlatformOwnerId',i.file_platform_owner_id,'filePlatformSessionId',i.file_platform_session_id,
           'virtualPath',i.virtual_path,'bytes',i.byte_count,'fileSha256',encode(i.file_sha256,'hex'),
           'filename',i.filename,'mime',i.mime,'isPublic',i.is_public,'extractor',i.extractor,
           'extractionSha256',encode(i.extraction_sha256,'hex'),'embeddingModel',i.embedding_model,
           'embeddingDimension',i.embedding_dimension,'documentDigest',encode(i.document_digest,'hex'),
           'documentCount',i.document_count)::text AS manual_fields_json
          FROM original i
        ) SELECT operation_id,target_id,documents_json,manual_fields_json,
          ARRAY(SELECT jsonb_build_object('sourceKind','manual','sourceId',i.manual_source_id,
           'chunkIndex',c.ordinality-1,'text',c.value->>'text','embedding',c.value->'embedding')::text
           FROM jsonb_array_elements(i.documents_json::jsonb) WITH ORDINALITY c(value,ordinality)
           ORDER BY c.ordinality) AS normalized_chunks_json,
          jsonb_build_object('kind','product_manual_ingest','version',2,
           'manualFieldsSha256',encode(sha256(convert_to(i.manual_fields_json,'UTF8')),'hex'),
           'sceneId',i.scene_id,'sceneGeneration',i.scene_generation,'sceneGrantId',i.scene_grant_id,
           'executionLaunchId',i.execution_launch_id,'executionScenarioId',i.execution_scenario_id,
           'executionGeneration',i.execution_generation,'executionPlatformOwnerId',i.execution_platform_owner_id,
           'executionPlatformSessionId',i.execution_platform_session_id)::text AS scene_receipt_json,
          jsonb_build_object('version',1,'kind','manual_embedding_runtime','operationId',i.operation_id,
           'runtimeFingerprint',encode(i.runtime_fingerprint,'hex'),
           'originalReceiptSha256',encode(i.original_receipt_sha256,'hex'))::text AS runtime_receipt_json,
          encode(i.runtime_receipt_sha256,'hex') AS runtime_receipt_sha256
         FROM fields i LIMIT 2`,[operationId,...BIRTH.map(key=>t[key]),t.scene.sceneId,t.scene.sceneGeneration])).rows;
        need(rows.length===1);const r=rows[0];
        need(r.operation_id===operationId&&r.target_id===t.targetId
          &&['documents_json','manual_fields_json','scene_receipt_json','runtime_receipt_json','runtime_receipt_sha256']
            .every(key=>typeof r[key]==='string')&&Array.isArray(r.normalized_chunks_json)
          &&r.normalized_chunks_json.length===stored.documentCount&&r.normalized_chunks_json.every(value=>typeof value==='string'));
        const sha=value=>createHash('sha256').update(value,'utf8').digest('hex');
        need(sha(r.documents_json)===stored.documentDigest&&sha(r.scene_receipt_json)===stored.receiptSha256
          &&sha(r.runtime_receipt_json)===r.runtime_receipt_sha256);
        const docs=parse(r.documents_json),scene=parse(r.scene_receipt_json),runtime=parse(r.runtime_receipt_json);
        need(Array.isArray(docs)&&docs.length===stored.documentCount
          &&scene.manualFieldsSha256===sha(r.manual_fields_json)
          &&runtime.operationId===operationId&&runtime.runtimeFingerprint===stored.runtimeFingerprint
          &&runtime.originalReceiptSha256===stored.receiptSha256);
        // The fresh-only migration capability already checked these stored
        // chunks against original source hashes. Never consult a mutable head.
        for(let index=0;index<docs.length;index++)need(equal(parse(r.normalized_chunks_json[index]),
          {sourceKind:'manual',sourceId:stored.manualSourceId,chunkIndex:index,
            text:docs[index].text,embedding:docs[index].embedding}));
        return freeze({receipt:stored,documentsJson:r.documents_json,normalizedChunksJson:r.normalized_chunks_json,
          manualFieldsJson:r.manual_fields_json,sceneReceiptJson:r.scene_receipt_json,
          runtimeReceiptJson:r.runtime_receipt_json,runtimeReceiptSha256:r.runtime_receipt_sha256});
      });
    },
    readRevisionPreimage({state,revisionId}) {
      need(UUID.test(revisionId||''));
      return admitted(state,async client=>{
        // Read the exact original publication payload. Historical revisions are
        // never rebuilt from current documents, current heads or float8 vectors.
        const rows=(await query(state,client,`SELECT r.revision_id,r.target_id,r.launch_id,r.scenario_id,r.generation,
          r.original_platform_owner_id,r.original_platform_session_id,encode(r.runtime_fingerprint,'hex') AS runtime_fingerprint,
          encode(r.source_set_digest,'hex') AS source_set_digest,encode(r.vector_digest,'hex') AS vector_digest,r.document_count,
          p.source_set_json,p.vectors_json
          FROM secureshop_review.product_target_embedding_revisions r
          JOIN secureshop_review.product_target_embedding_preimages p
           ON p.revision_id=r.revision_id AND p.target_id=r.target_id
          WHERE r.revision_id=$1 AND r.target_id=$2 AND r.launch_id=$3 AND r.scenario_id=$4
           AND r.generation=$5 AND r.original_platform_owner_id=$6 AND r.original_platform_session_id=$7
          LIMIT 2`,[revisionId,...BIRTH.map(key=>state.target[key])])).rows;
        need(rows.length===1);const r=rows[0];
        const revision={revisionId:r.revision_id,targetId:r.target_id,launchId:r.launch_id,scenarioId:r.scenario_id,
          generation:number(r.generation),platformOwnerId:number(r.original_platform_owner_id),
          platformSessionId:number(r.original_platform_session_id),runtimeFingerprint:r.runtime_fingerprint,
          sourceSetDigest:r.source_set_digest,vectorDigest:r.vector_digest,documentCount:number(r.document_count)};
        need(revision.revisionId===revisionId&&BIRTH.every(key=>revision[key]===state.target[key])
          &&[revision.runtimeFingerprint,revision.sourceSetDigest,revision.vectorDigest].every(value=>typeof value==='string'&&/^[0-9a-f]{64}$/.test(value))
          &&typeof r.source_set_json==='string'&&typeof r.vectors_json==='string');
        const sha=value=>createHash('sha256').update(value,'utf8').digest('hex');
        need(sha(r.source_set_json)===revision.sourceSetDigest&&sha(r.vectors_json)===revision.vectorDigest);
        need(Array.isArray(parse(r.source_set_json))&&Array.isArray(parse(r.vectors_json)));
        return freeze({revision,sourceSetJson:r.source_set_json,vectorsJson:r.vectors_json});
      });
    },
    readRevision({state,revisionId}) {
      need(UUID.test(revisionId||''));
      return admitted(state,async client=>{
        const rows=(await query(state,client,`SELECT r.revision_id,r.target_id,r.launch_id,r.scenario_id,r.generation,
          r.original_platform_owner_id,r.original_platform_session_id,encode(r.runtime_fingerprint,'hex') AS runtime_fingerprint,
          encode(r.source_set_digest,'hex') AS source_set_digest,encode(r.vector_digest,'hex') AS vector_digest,r.document_count
          FROM secureshop_review.product_target_embedding_revisions r
          WHERE r.revision_id=$1 AND r.target_id=$2 AND r.launch_id=$3 AND r.scenario_id=$4
           AND r.generation=$5 AND r.original_platform_owner_id=$6 AND r.original_platform_session_id=$7`,
        [revisionId,...BIRTH.map(key=>state.target[key])])).rows;
        need(rows.length===1);const r=rows[0];return freeze({revisionId:r.revision_id,targetId:r.target_id,
          launchId:r.launch_id,scenarioId:r.scenario_id,generation:number(r.generation),
          platformOwnerId:number(r.original_platform_owner_id),platformSessionId:number(r.original_platform_session_id),
          runtimeFingerprint:r.runtime_fingerprint,sourceSetDigest:r.source_set_digest,vectorDigest:r.vector_digest,
          documentCount:number(r.document_count)});
      });
    },
  });
}
module.exports={createManualRagSourceAdapter};
