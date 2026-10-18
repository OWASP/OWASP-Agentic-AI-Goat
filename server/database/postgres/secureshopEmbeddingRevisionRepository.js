'use strict';
const { withTransaction } = require('./index');
const {copySceneBinding,executionScope,assertSceneGrant,withSceneLease}=require('../../services/secureshopSceneBinding');
const {createHash}=require('node:crypto');
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const HASH=/^[0-9a-f]{64}$/;
const KEYS=['targetId','launchId','scenarioId','generation','platformOwnerId','platformSessionId'];
const CORPUS_KINDS=Object.freeze({products:Object.freeze(['product','listing']),reviews:Object.freeze(['review']),manuals:Object.freeze(['manual']),policies:Object.freeze(['policy'])});
const {validatePolicyRetrievalSnapshot}=require('../../services/secureshopPolicyRetrievalSnapshot');
function invalid(){throw Object.assign(new Error('Invalid embedding revision input'),{code:'INVALID_ARGUMENT'});}
function exact(value,keys){if(!value||Object.getPrototypeOf(value)!==Object.prototype||Reflect.ownKeys(value).length!==keys.length||keys.some(k=>!Object.hasOwn(value,k)||!Object.hasOwn(Object.getOwnPropertyDescriptor(value,k),'value')))invalid();}
function scope(value){if(value?.scene!==undefined){for(const k of KEYS)if(!Object.hasOwn(value,k))invalid();}else exact(value,KEYS);for(const k of KEYS.slice(0,3))if(typeof value[k]!=='string'||!UUID.test(value[k]))invalid();for(const k of KEYS.slice(3))if(!Number.isSafeInteger(value[k])||value[k]<1)invalid();return copySceneBinding(value,Object.fromEntries(KEYS.map(k=>[k,value[k]])));}
const values=b=>KEYS.map(k=>b[k]);
const predicate=`t.target_id=$1 AND t.launch_id=$2 AND t.scenario_id=$3 AND t.generation=$4 AND t.original_platform_owner_id=$5 AND t.original_platform_session_id=$6`;
function unavailable(){throw Object.assign(new Error('Embedding revision scope or runtime changed'),{code:'EMBEDDING_REVISION_UNAVAILABLE'});}
function selectiveInput(input){
 exact(input,['sourceKinds']);
 if(!Array.isArray(input.sourceKinds)||!input.sourceKinds.length||input.sourceKinds.length>4
  ||input.sourceKinds.some(k=>typeof k!=='string'||!['product','listing','review','manual','policy'].includes(k))
  ||new Set(input.sourceKinds).size!==input.sourceKinds.length)invalid();
 return Object.freeze({sourceKinds:Object.freeze([...input.sourceKinds])});
}
const LINEAGE_BYTES=48*1024;
const ineligible=reason=>Object.freeze({eligible:false,reason});
const textHash=value=>createHash('sha256').update(value,'utf8').digest('hex');
// This SELECT runs while the searched target remains locked in the original
// transaction. It never substitutes a subsequently published current head.
const SEARCH_LINEAGE_SELECT=`WITH source AS (
 SELECT r.*,p.source_set_json,p.vectors_json,
  sha256(convert_to(p.source_set_json,'UTF8'))=r.source_set_digest
   AND sha256(convert_to(p.vectors_json,'UTF8'))=r.vector_digest AS digest_valid
 FROM secureshop_review.product_target_embedding_revisions r
 JOIN secureshop_review.product_target_embedding_preimages p ON p.revision_id=r.revision_id AND p.target_id=r.target_id
 WHERE r.revision_id=$3 AND r.target_id=$1 AND r.generation=$2
), manuals AS (
 SELECT COALESCE(jsonb_agg(jsonb_build_object('sourceId',i.manual_source_id,
  'operationId',i.operation_id,'productId',i.product_id,'merchantId',i.merchant_id,
  'receiptSha256',encode(i.receipt_sha256,'hex')) ORDER BY i.manual_source_id),'[]'::jsonb) AS manual_sources
 FROM secureshop_review.product_target_manual_ingests i WHERE i.target_id=$1 AND i.generation=$2
  AND i.manual_source_id IN(SELECT (value->>'sourceId')::bigint FROM jsonb_array_elements($4::jsonb))
  AND i.is_public AND i.receipt_version=2
), proof AS (
 SELECT jsonb_build_object('eligible',true,'version',2,'revision',jsonb_build_object(
  'revisionId',r.revision_id,'targetId',r.target_id,'launchId',r.launch_id,'scenarioId',r.scenario_id,
  'generation',r.generation,'platformOwnerId',r.original_platform_owner_id,
  'platformSessionId',r.original_platform_session_id,'runtimeFingerprint',encode(r.runtime_fingerprint,'hex'),
  'sourceSetDigest',encode(r.source_set_digest,'hex'),'vectorDigest',encode(r.vector_digest,'hex'),
  'documentCount',r.document_count),'preimageRef',jsonb_build_object('version',1,'revisionId',r.revision_id,
   'sourceSetDigest',encode(r.source_set_digest,'hex'),'vectorDigest',encode(r.vector_digest,'hex')),
  'manualSources',m.manual_sources) AS lineage,r.digest_valid,
  (SELECT COALESCE(jsonb_agg(d),'[]'::jsonb) FROM jsonb_array_elements(r.source_set_json::jsonb) d
   WHERE d->>'sourceKind'='manual' AND EXISTS(SELECT 1 FROM jsonb_array_elements($4::jsonb) k
    WHERE d->>'sourceId'=k->>'sourceId' AND d->>'chunkIndex'=k->>'chunkIndex')) AS selected_sources
 FROM source r CROSS JOIN manuals m
), bounded AS (
 SELECT *,octet_length(lineage::text)+octet_length(selected_sources::text)>$5 AS oversized FROM proof
)
SELECT CASE WHEN NOT oversized THEN lineage ELSE NULL END AS lineage,
 CASE WHEN NOT oversized THEN selected_sources ELSE NULL END AS selected_sources,digest_valid,oversized FROM bounded`;
async function captureSearchLineage(client,b,head,rows){
 if(!b.scene)return ineligible('legacy_receipt');
 const manuals=rows.filter(row=>row.sourceKind==='manual');
 if(!manuals.length)return ineligible('no_selected_manual');
 const keys=manuals.map(row=>({sourceId:row.sourceId,chunkIndex:row.chunkIndex}));
 const row=(await client.query(SEARCH_LINEAGE_SELECT,[b.targetId,b.generation,head.revision_id,JSON.stringify(keys),LINEAGE_BYTES])).rows[0];
 if(row?.oversized)return ineligible('oversized');
 const proof=row?.lineage,r=proof?.revision,ref=proof?.preimageRef;
 if(!proof||!r||!Array.isArray(proof.manualSources)||manuals.some(found=>!proof.manualSources.some(item=>item.sourceId===found.sourceId)))return ineligible('missing_original');
 if(proof.version!==2||row.digest_valid!==true||r.revisionId!==head.revision_id||r.runtimeFingerprint!==head.fingerprint||r.documentCount!==head.document_count
  ||KEYS.some(key=>r[key]!==b[key])||ref?.version!==1||ref.revisionId!==r.revisionId
  ||!HASH.test(r.sourceSetDigest)||!HASH.test(r.vectorDigest)||ref.sourceSetDigest!==r.sourceSetDigest||ref.vectorDigest!==r.vectorDigest)return ineligible('digest_mismatch');
 const sources=row.selected_sources;
 if(!Array.isArray(sources)||sources.length!==manuals.length)return ineligible('digest_mismatch');
 const selected=[];
 for(const found of manuals){
  const matches=sources.filter(item=>item.sourceKind==='manual'&&item.sourceId===String(found.sourceId)&&item.chunkIndex===found.chunkIndex);
  if(matches.length!==1||matches[0].text!==found.text||!HASH.test(matches[0].sourceSha256))return ineligible('digest_mismatch');
  selected.push(Object.freeze({...found,textSha256:textHash(found.text),sourceSha256:matches[0].sourceSha256,revisionId:r.revisionId}));
 }
 const result={...proof,revision:Object.freeze({...r}),preimageRef:Object.freeze({...ref}),manualSources:Object.freeze(proof.manualSources.map(item=>Object.freeze({...item}))),selected:Object.freeze(selected)};
 if(Buffer.byteLength(JSON.stringify(result),'utf8')>LINEAGE_BYTES)return ineligible('oversized');
 return Object.freeze(result);
}
function createSecureShopEmbeddingRevisionRepository(pool,{checkCurrent,getRuntimeFingerprint}={}){
 if(!pool?.connect||!pool?.query||typeof checkCurrent!=='function'||typeof getRuntimeFingerprint!=='function')throw new TypeError('Embedding repository requires server authority');
 async function fingerprint(){const value=await getRuntimeFingerprint();if(typeof value!=='string'||!HASH.test(value))unavailable();return value;}
 async function online(b,work){return withSceneLease(b,()=>withTransaction(pool,async client=>{await assertSceneGrant(client,b);const result=await work(client);await assertSceneGrant(client,b);await checkCurrent(executionScope(b));return result;}));}
 async function recordSceneEffect(client,b,revisionId,replayed){if(!b.scene||replayed===true)return;await client.query(`SELECT secureshop_review.record_scene_retrieval_embedding_effect($1,$2,$3,$4)`,['embedding_revision',revisionId,b.targetId,b.scene.grantId]);}
 async function assertRebuildTargetInTransaction(client,value){const b=scope(value);if(typeof client?.query!=='function')invalid();await checkCurrent(executionScope(b));await assertSceneGrant(client,b);const row=(await client.query(`SELECT t.target_id FROM secureshop_review.product_targets t WHERE ${predicate} AND t.lifecycle='active' FOR SHARE OF t`,values(b))).rows[0];if(!row)unavailable();await checkCurrent(executionScope(b));return b;}
 async function active(client,b){await assertSceneGrant(client,b);const row=(await client.query(`SELECT t.target_id FROM secureshop_review.product_targets t JOIN secureshop_review.product_target_retrieval_config c USING(target_id) WHERE ${predicate} AND t.lifecycle='active' AND c.lifecycle='active' FOR SHARE OF t`,values(b))).rows[0];if(!row)unavailable();}
 async function assertActiveInTransaction(client,value){const b=scope(value);if(typeof client?.query!=='function')invalid();await checkCurrent(executionScope(b));await active(client,b);await checkCurrent(executionScope(b));return b;}
 async function snapshot(value){const b=scope(value);await checkCurrent(executionScope(b));return online(b,async client=>{await active(client,b);
  const state=(await client.query(`SELECT encode(secureshop_review.product_embedding_source_digest($1,$2),'hex') AS digest,(SELECT revision_id FROM secureshop_review.product_target_embedding_heads WHERE target_id=$1) AS head`,[b.targetId,b.generation])).rows[0];
  const docs=(await client.query(`SELECT source_kind,source_id::text,chunk_index,body,encode(source_sha256,'hex') AS hash FROM secureshop_review.product_target_retrieval_documents WHERE target_id=$1 AND generation=$2 ORDER BY source_kind COLLATE "C",source_id,chunk_index`,[b.targetId,b.generation])).rows;
  if(docs.length>4096)unavailable();await checkCurrent(executionScope(b));
  return Object.freeze({sourceSetDigest:state.digest,expectedHead:state.head,documents:Object.freeze(docs.map(d=>Object.freeze({sourceKind:d.source_kind,sourceId:d.source_id,chunkIndex:d.chunk_index,text:d.body,sourceSha256:d.hash})))});
 });}
 async function snapshotSelectiveInTransaction(client,value,input) {
  const b=scope(value);
  if(typeof client?.query!=='function')invalid();
  input=selectiveInput(input);
  const sourceKinds=new Set(input.sourceKinds);
  await checkCurrent(executionScope(b));const trusted=await fingerprint();
   await active(client,b);
   // Source edits invalidate the searchable head, but immutable revisions remain.
   // Reuse only exact-hash sibling vectors from the current (or latest retained)
   // revision. Publication still compares the actual nullable head and full source
   // digest, so retaining a base never resurrects an invalidated search head.
   const head=(await client.query(`SELECT r.revision_id,h.revision_id AS current_head,
    encode(r.runtime_fingerprint,'hex') AS runtime_fingerprint,
    encode(secureshop_review.product_embedding_source_digest($1,$4),'hex') AS digest
    FROM secureshop_review.product_target_embedding_revisions r
    LEFT JOIN secureshop_review.product_target_embedding_heads h ON h.target_id=r.target_id
    WHERE r.target_id=$1 AND r.launch_id=$2 AND r.scenario_id=$3 AND r.generation=$4
     AND r.original_platform_owner_id=$5 AND r.original_platform_session_id=$6
     AND (h.revision_id IS NULL OR h.revision_id=r.revision_id)
    ORDER BY r.created_at DESC,r.revision_id DESC LIMIT 1`,values(b))).rows[0];
   if(!head||typeof head.revision_id!=='string'||!UUID.test(head.revision_id)
    ||!(head.current_head===null||(typeof head.current_head==='string'&&UUID.test(head.current_head)))
    ||head.runtime_fingerprint!==trusted)unavailable();
   const docs=(await client.query(`SELECT d.source_kind,d.source_id::text,d.chunk_index,d.body,
    encode(d.source_sha256,'hex') AS hash,v.embedding
    FROM secureshop_review.product_target_retrieval_documents d
    LEFT JOIN secureshop_review.product_target_embedding_vectors v ON v.revision_id=$3
     AND v.source_kind=d.source_kind AND v.source_id=d.source_id AND v.chunk_index=d.chunk_index
     AND v.source_sha256=d.source_sha256
    WHERE d.target_id=$1 AND d.generation=$2
    ORDER BY d.source_kind COLLATE "C",d.source_id,d.chunk_index`,[b.targetId,b.generation,head.revision_id])).rows;
   if(!docs.length||docs.length>4096||docs.some(d=>typeof d.source_id!=='string'
    ||!/^[1-9][0-9]{0,15}$/.test(d.source_id)||!Number.isSafeInteger(Number(d.source_id))
    ||typeof d.hash!=='string'||!HASH.test(d.hash)
    ||(!sourceKinds.has(d.source_kind)&&(!Array.isArray(d.embedding)||d.embedding.length!==384
     ||d.embedding.some(n=>typeof n!=='number'||!Number.isFinite(n))||!d.embedding.some(n=>n!==0)))))unavailable();
   await checkCurrent(executionScope(b));if(await fingerprint()!==trusted)unavailable();
   const result=Object.freeze({sourceSetDigest:head.digest,expectedHead:head.current_head,
    baseRevisionId:head.revision_id,currentRuntimeFingerprint:trusted,
    documents:Object.freeze(docs.map(d=>Object.freeze({sourceKind:d.source_kind,sourceId:d.source_id,
     chunkIndex:d.chunk_index,text:d.body,sourceSha256:d.hash,
     embedding:Array.isArray(d.embedding)?Object.freeze([...d.embedding]):null})))});
   await checkCurrent(executionScope(b));if(await fingerprint()!==trusted)unavailable();
   return result;
 }
 async function snapshotForRebuildInTransaction(client,value,input){
  const b=scope(value);input=selectiveInput(input);await assertRebuildTargetInTransaction(client,b);
  const prior=(await client.query(`SELECT 1 FROM secureshop_review.product_target_embedding_revisions r WHERE r.target_id=$1 AND r.launch_id=$2 AND r.scenario_id=$3 AND r.generation=$4 AND r.original_platform_owner_id=$5 AND r.original_platform_session_id=$6 LIMIT 1`,values(b))).rows[0];
  if(prior)return Object.freeze({operationMode:'selective',...(await snapshotSelectiveInTransaction(client,b,input))});
  if(JSON.stringify(input.sourceKinds)!==JSON.stringify(['product','listing']))unavailable();
  const trusted=await fingerprint(),config=(await client.query(`SELECT lifecycle FROM secureshop_review.product_target_retrieval_config WHERE target_id=$1`,[b.targetId])).rows[0];
  let rows,digest;
  if(config){if(config.lifecycle!=='active')unavailable();rows=(await client.query(`SELECT d.source_kind,d.source_id::text,d.chunk_index,d.body,encode(d.source_sha256,'hex') AS hash FROM secureshop_review.product_target_retrieval_documents d WHERE d.target_id=$1 AND d.generation=$2 ORDER BY d.source_kind COLLATE "C",d.source_id,d.chunk_index`,[b.targetId,b.generation])).rows;digest=(await client.query(`SELECT encode(secureshop_review.product_embedding_source_digest($1,$2),'hex') AS digest`,[b.targetId,b.generation])).rows[0]?.digest;
   const products=(await client.query(`SELECT product_id::text,name||E'\\n'||COALESCE(description,'') AS body FROM secureshop_review.product_target_products WHERE target_id=$1 ORDER BY product_id`,[b.targetId])).rows;
   if(products.length<1||products.some(p=>!rows.some(d=>d.source_kind==='product'&&d.source_id===p.product_id&&d.chunk_index===0&&d.body===p.body)))unavailable();
  }else{
   rows=(await client.query(`SELECT p.product_id::text AS source_id,0 AS chunk_index,p.name||E'\\n'||COALESCE(p.description,'') AS body,encode(sha256(convert_to(jsonb_build_object('sourceKind','product','sourceId',p.product_id::text,'chunkIndex',0,'text',p.name||E'\\n'||COALESCE(p.description,''))::text,'UTF8')),'hex') AS hash FROM secureshop_review.product_target_products p WHERE p.target_id=$1 ORDER BY p.product_id`,[b.targetId])).rows.map(r=>({source_kind:'product',...r}));
   digest=(await client.query(`WITH d AS (SELECT p.product_id::bigint AS source_id,0 AS chunk_index,p.name||E'\\n'||COALESCE(p.description,'') AS body,sha256(convert_to(jsonb_build_object('sourceKind','product','sourceId',p.product_id::text,'chunkIndex',0,'text',p.name||E'\\n'||COALESCE(p.description,''))::text,'UTF8')) AS source_sha256 FROM secureshop_review.product_target_products p WHERE p.target_id=$1) SELECT encode(sha256(convert_to(COALESCE(jsonb_agg(jsonb_build_object('sourceKind','product','sourceId',d.source_id::text,'chunkIndex',d.chunk_index,'text',d.body,'sourceSha256',encode(d.source_sha256,'hex')) ORDER BY d.source_id,d.chunk_index),'[]'::jsonb)::text,'UTF8')),'hex') AS digest FROM d`,[b.targetId])).rows[0]?.digest;
  }
  if(!rows.length||rows.length>4096||!HASH.test(digest)||rows.some(d=>!HASH.test(d.hash)||typeof d.body!=='string'||!d.body.trim()))unavailable();
  await checkCurrent(executionScope(b));if(await fingerprint()!==trusted)unavailable();
  return Object.freeze({operationMode:'initialize',sourceSetDigest:digest,expectedHead:null,baseRevisionId:null,currentRuntimeFingerprint:trusted,unprovisioned:!config,documents:Object.freeze(rows.map(d=>Object.freeze({sourceKind:d.source_kind,sourceId:d.source_id,chunkIndex:Number(d.chunk_index),text:d.body,sourceSha256:d.hash,embedding:null})))});
 }
 async function snapshotSelective(value,input) {
  const captured=selectiveInput(input);
  const b=scope(value);return online(b,client=>snapshotSelectiveInTransaction(client,b,captured));
 }
 async function publishInTransaction(client,value,input, {effectTimeoutMs} = {}){const b=scope(value);if(typeof client?.query!=='function')invalid();exact(input,['operationId','sourceSetDigest','expectedHead','expectedRuntimeFingerprint','documents']);
  if(!UUID.test(input.operationId)||!HASH.test(input.sourceSetDigest)||!HASH.test(input.expectedRuntimeFingerprint)||(input.expectedHead!==null&&!UUID.test(input.expectedHead))||!Array.isArray(input.documents)||input.documents.length>4096)invalid();
  const docs=input.documents.map(d=>{exact(d,['sourceKind','sourceId','chunkIndex','sourceSha256','embedding']);if(!['product','listing','review','manual','policy'].includes(d.sourceKind)||typeof d.sourceId!=='string'||!(/^[1-9][0-9]{0,15}$/).test(d.sourceId)||!Number.isSafeInteger(Number(d.sourceId))||!Number.isInteger(d.chunkIndex)||d.chunkIndex<0||d.chunkIndex>128||!HASH.test(d.sourceSha256)||!Array.isArray(d.embedding)||d.embedding.length!==384||d.embedding.some(n=>typeof n!=='number'||!Number.isFinite(n))||!d.embedding.some(n=>n!==0))invalid();return {...d,embedding:[...d.embedding]};});
  // SQL derives immutable policy lineage and rejects any changed policy vector.
  const publisher=docs.some(d=>d.sourceKind==='policy')?'publish_embedding_with_policy_lineage':'publish_product_embedding_revision';
  const body=JSON.stringify(docs);if(Buffer.byteLength(body)>64*1024*1024)invalid();
  // Snapshot caller-owned CAS fields before the first authority await.
  input=Object.freeze({...input,documents:undefined});
  await checkCurrent(executionScope(b));await assertSceneGrant(client,b);const trusted=await fingerprint();if(trusted!==input.expectedRuntimeFingerprint)unavailable();
  if(effectTimeoutMs!==undefined&&(!Number.isSafeInteger(effectTimeoutMs)||effectTimeoutMs<100||effectTimeoutMs>10000))throw new TypeError('Invalid effect timeout');
  if(effectTimeoutMs!==undefined)await client.query("SELECT set_config('statement_timeout',$1,true),set_config('lock_timeout',$1,true)",[String(effectTimeoutMs)]);
  const row=(await client.query(`SELECT * FROM secureshop_review.${publisher}($1,$2,$3,$4,$5,$6,$7,decode($8,'hex'),decode($9,'hex'),$10,$11::jsonb)`,[...values(b),input.operationId,trusted,input.sourceSetDigest,input.expectedHead,body])).rows[0];
  await recordSceneEffect(client,b,row.revision_id,row.replayed);
  await checkCurrent(executionScope(b));if(await fingerprint()!==trusted)unavailable();
  return Object.freeze({revisionId:row.revision_id,runtimeFingerprint:row.runtime_fingerprint.toString('hex'),sourceSetDigest:row.source_set_digest.toString('hex'),vectorDigest:row.vector_digest.toString('hex'),documentCount:row.document_count,replayed:row.replayed});
 }
 async function initializeInTransaction(client,value,input,{effectTimeoutMs}={}){const b=scope(value);if(typeof client?.query!=='function')invalid();exact(input,['operationId','sourceSetDigest','expectedHead','expectedRuntimeFingerprint','documents']);if(input.expectedHead!==null)invalid();const docs=input.documents.map(d=>{exact(d,['sourceKind','sourceId','chunkIndex','text','sourceSha256','embedding']);if(d.sourceKind!=='product'||typeof d.text!=='string'||!d.text.trim()||Buffer.byteLength(d.text)>32768||!HASH.test(d.sourceSha256)||!Array.isArray(d.embedding)||d.embedding.length!==384||d.embedding.some(n=>typeof n!=='number'||!Number.isFinite(n))||!d.embedding.some(n=>n!==0))invalid();return{...d,embedding:[...d.embedding]};});await checkCurrent(executionScope(b));await assertSceneGrant(client,b);const trusted=await fingerprint();if(trusted!==input.expectedRuntimeFingerprint)unavailable();if(effectTimeoutMs!==undefined)await client.query("SELECT set_config('statement_timeout',$1,true),set_config('lock_timeout',$1,true)",[String(effectTimeoutMs)]);const row=(await client.query(`SELECT * FROM secureshop_review.initialize_product_embedding_revision($1,$2,$3,$4,$5,$6,$7,decode($8,'hex'),decode($9,'hex'),$10::jsonb)`,[...values(b),input.operationId,trusted,input.sourceSetDigest,JSON.stringify(docs)])).rows[0];await recordSceneEffect(client,b,row.revision_id,row.replayed);await checkCurrent(executionScope(b));if(await fingerprint()!==trusted)unavailable();return Object.freeze({revisionId:row.revision_id,runtimeFingerprint:row.runtime_fingerprint.toString('hex'),sourceSetDigest:row.source_set_digest.toString('hex'),vectorDigest:row.vector_digest.toString('hex'),documentCount:row.document_count,replayed:row.replayed});}

 async function snapshotPolicyForRebuildInTransaction(client,value,rawSnapshot){
  const b=scope(value),policy=validatePolicyRetrievalSnapshot(structuredClone(rawSnapshot));if(typeof client?.query!=='function')invalid();
  await checkCurrent(executionScope(b));const trusted=await fingerprint();await active(client,b);
  const head=(await client.query(`SELECT r.revision_id,h.revision_id AS current_head,encode(r.runtime_fingerprint,'hex') AS runtime_fingerprint FROM secureshop_review.product_target_embedding_revisions r LEFT JOIN secureshop_review.product_target_embedding_heads h ON h.target_id=r.target_id WHERE r.target_id=$1 AND r.launch_id=$2 AND r.scenario_id=$3 AND r.generation=$4 AND r.original_platform_owner_id=$5 AND r.original_platform_session_id=$6 AND (h.revision_id IS NULL OR h.revision_id=r.revision_id) ORDER BY r.created_at DESC,r.revision_id DESC LIMIT 1`,values(b))).rows[0];
  if(!head||head.runtime_fingerprint!==trusted)unavailable();
  const prior=(await client.query(`SELECT d.source_kind,d.source_id::text,d.chunk_index,d.body,encode(d.source_sha256,'hex') AS hash,v.embedding FROM secureshop_review.product_target_retrieval_documents d LEFT JOIN secureshop_review.product_target_embedding_vectors v ON v.revision_id=$3 AND v.source_kind=d.source_kind AND v.source_id=d.source_id AND v.chunk_index=d.chunk_index AND v.source_sha256=d.source_sha256 WHERE d.target_id=$1 AND d.generation=$2 AND d.source_kind<>'policy' ORDER BY d.source_kind COLLATE "C",d.source_id,d.chunk_index`,[b.targetId,b.generation,head.revision_id])).rows;
  if(prior.some(d=>!Array.isArray(d.embedding)||d.embedding.length!==384))unavailable();
  const projected=policy.documents.map(d=>({sourceKind:'policy',sourceId:String(d.sourceId),chunkIndex:0,text:d.text,sourceSha256:d.sourceSha256,embedding:null,name:d.name,targets:d.targets}));
  const digest=(await client.query(`SELECT encode(secureshop_review.bound_policy_source_digest($1,$2,$3::jsonb),'hex') AS digest`,[b.targetId,b.generation,JSON.stringify(projected.map(({sourceKind,sourceId,chunkIndex,text,sourceSha256})=>({sourceKind,sourceId,chunkIndex,text,sourceSha256})))] )).rows[0]?.digest;
  if(!HASH.test(digest))unavailable();await checkCurrent(executionScope(b));if(await fingerprint()!==trusted)unavailable();
  const documents=[...prior.map(d=>({sourceKind:d.source_kind,sourceId:d.source_id,chunkIndex:d.chunk_index,text:d.body,sourceSha256:d.hash,embedding:Object.freeze([...d.embedding])})),...projected].sort((a,z)=>(a.sourceKind<z.sourceKind?-1:a.sourceKind>z.sourceKind?1:0)||Number(a.sourceId)-Number(z.sourceId)||a.chunkIndex-z.chunkIndex).map(Object.freeze);
  return Object.freeze({operationMode:'selective',sourceSetDigest:digest,expectedHead:head.current_head,baseRevisionId:head.revision_id,currentRuntimeFingerprint:trusted,policySnapshot:policy,documents:Object.freeze(documents)});
 }
 async function publishPolicyInTransaction(client,value,input,rawSnapshot,{effectTimeoutMs}={}){
  const b=scope(value),policy=validatePolicyRetrievalSnapshot(structuredClone(rawSnapshot));if(typeof client?.query!=='function')invalid();exact(input,['operationId','sourceSetDigest','expectedHead','expectedRuntimeFingerprint','documents']);
  const docs=input.documents.map(d=>{exact(d,['sourceKind','sourceId','chunkIndex','sourceSha256','embedding']);if(!['product','listing','review','manual','policy'].includes(d.sourceKind)||!Array.isArray(d.embedding)||d.embedding.length!==384||d.embedding.some(n=>typeof n!=='number'||!Number.isFinite(n))||!d.embedding.some(n=>n!==0))invalid();return{...d,embedding:[...d.embedding]};});
  await checkCurrent(executionScope(b));await assertSceneGrant(client,b);const trusted=await fingerprint();if(trusted!==input.expectedRuntimeFingerprint)unavailable();if(effectTimeoutMs!==undefined)await client.query("SELECT set_config('statement_timeout',$1,true),set_config('lock_timeout',$1,true)",[String(effectTimeoutMs)]);
  await client.query(`INSERT INTO secureshop_review.bound_system_policy_imports(operation_id,target_id,generation,policy_version,policy_snapshot_sha256,payload_json,payload_sha256) VALUES($1,$2,$3,$4,decode($5,'hex'),$6::jsonb,decode($7,'hex'))`,[input.operationId,b.targetId,b.generation,policy.policyVersion,policy.policySnapshotSha256,JSON.stringify(policy),policy.sha256]);
  for(const [index,d] of policy.documents.entries())await client.query(`INSERT INTO secureshop_review.bound_system_policy_import_documents(operation_id,ordinal,name,targets_json,rendered,rendered_sha256,source_sha256) VALUES($1,$2,$3,$4::jsonb,$5,decode($6,'hex'),decode($7,'hex'))`,[input.operationId,index+1,d.name,JSON.stringify(d.targets),d.text,createHash('sha256').update(d.text).digest('hex'),d.sourceSha256]);
  const row=(await client.query(`SELECT * FROM secureshop_review.publish_bound_policy_embedding_revision($1,(SELECT worker_token FROM secureshop_review.bound_system_rebuild_operations WHERE operation_id=$1),$2::jsonb)`,[input.operationId,JSON.stringify(docs)])).rows[0];await recordSceneEffect(client,b,row.revision_id,row.replayed);await checkCurrent(executionScope(b));if(await fingerprint()!==trusted)unavailable();return Object.freeze({revisionId:row.revision_id,runtimeFingerprint:row.runtime_fingerprint.toString('hex'),sourceSetDigest:row.source_set_digest.toString('hex'),vectorDigest:row.vector_digest.toString('hex'),documentCount:row.document_count,replayed:row.replayed});
 }

 async function publish(value,input,options={}){
  const b=scope(value);return online(b,client=>publishInTransaction(client,b,input,options));
 }
 // Recovery reads an immutable operation receipt before considering today's
 // head/source/runtime. It never republishes vectors or reactivates an old head.
 async function readPublicationInTransaction(client,value,operationId) {
  const b=scope(value);
  if(typeof client?.query!=='function')invalid();
  if(typeof operationId!=='string'||!UUID.test(operationId))invalid();
  const operation=operationId.toLowerCase();
  await checkCurrent(executionScope(b));
  await active(client,b);
   const row=(await client.query(`SELECT r.revision_id,
    encode(r.runtime_fingerprint,'hex') AS fingerprint,
    encode(r.source_set_digest,'hex') AS source_digest,
    encode(r.vector_digest,'hex') AS vector_digest,r.document_count
    FROM secureshop_review.product_target_embedding_revisions r
    WHERE r.target_id=$1 AND r.launch_id=$2 AND r.scenario_id=$3 AND r.generation=$4
     AND r.original_platform_owner_id=$5 AND r.original_platform_session_id=$6
     AND r.revision_id=$7`,[...values(b),operation])).rows[0];
   await checkCurrent(executionScope(b));
   if(!row)return null;
   if(row.revision_id!==operation||!HASH.test(row.fingerprint)||!HASH.test(row.source_digest)
    ||!HASH.test(row.vector_digest)||!Number.isSafeInteger(row.document_count)
    ||row.document_count<0||row.document_count>4096)unavailable();
   return Object.freeze({revisionId:row.revision_id,runtimeFingerprint:row.fingerprint,
    sourceSetDigest:row.source_digest,vectorDigest:row.vector_digest,
    documentCount:row.document_count,replayed:true});
 }
 async function readPublication(value,operationId) {
  const b=scope(value);return online(b,client=>readPublicationInTransaction(client,b,operationId));
 }
 async function readHead(value){const b=scope(value);await checkCurrent(executionScope(b));const trusted=await fingerprint();return online(b,async client=>{await active(client,b);
  const r=(await client.query(`SELECT r.revision_id,encode(r.runtime_fingerprint,'hex') AS fingerprint,encode(r.source_set_digest,'hex') AS digest,r.document_count FROM secureshop_review.product_target_embedding_heads h JOIN secureshop_review.product_target_embedding_revisions r USING(revision_id) WHERE h.target_id=$1 AND r.runtime_fingerprint=decode($3,'hex') AND r.source_set_digest=secureshop_review.product_embedding_source_digest($1,$2)`,[b.targetId,b.generation,trusted])).rows[0];
  await checkCurrent(executionScope(b));if(await fingerprint()!==trusted)unavailable();return r?Object.freeze({revisionId:r.revision_id,runtimeFingerprint:r.fingerprint,sourceSetDigest:r.digest,documentCount:r.document_count}):null;
 });}
 async function searchInternal(value,input,capture){
  const b=scope(value);exact(input,['embedding','limit']);
  if(!Array.isArray(input.embedding)||input.embedding.length!==384||input.embedding.some(n=>typeof n!=='number'||!Number.isFinite(n))||!input.embedding.some(n=>n!==0)||!Number.isInteger(input.limit)||input.limit<1||input.limit>20)invalid();
  const query=[...input.embedding],limit=input.limit;
  const unit=vector=>{const scale=Math.max(...vector.map(Math.abs));if(!(scale>0)||!Number.isFinite(scale))unavailable();const scaled=vector.map(n=>n/scale),norm=Math.hypot(...scaled);return scaled.map(n=>n/norm);};
  const queryUnit=unit(query);await checkCurrent(executionScope(b));const trusted=await fingerprint();
  return online(b,async client=>{await active(client,b);
   const head=(await client.query(`SELECT r.revision_id,r.document_count,encode(r.runtime_fingerprint,'hex') AS fingerprint,
    r.source_set_digest=secureshop_review.product_embedding_source_digest($1,$2) AS current_source
    FROM secureshop_review.product_target_embedding_heads h JOIN secureshop_review.product_target_embedding_revisions r USING(revision_id) WHERE h.target_id=$1`,[b.targetId,b.generation])).rows[0];
   if(!head||!head.current_source)throw Object.assign(new Error('Reindex the current owned source corpus before searching'),{code:'EMBEDDING_REINDEX_REQUIRED'});
   if(head.fingerprint!==trusted)throw Object.assign(new Error('Active embedding revision uses a different runtime; reindex required'),{code:'EMBEDDING_RUNTIME_MISMATCH'});
   const rows=(await client.query(`SELECT d.source_kind,d.source_id,d.chunk_index,d.body,v.embedding
    FROM secureshop_review.product_target_embedding_vectors v
    JOIN secureshop_review.product_target_retrieval_documents d ON d.target_id=$1 AND d.generation=$2
     AND d.source_kind=v.source_kind AND d.source_id=v.source_id AND d.chunk_index=v.chunk_index AND d.source_sha256=v.source_sha256
    WHERE v.revision_id=$3 ORDER BY d.source_kind COLLATE "C",d.source_id,d.chunk_index`,[b.targetId,b.generation,head.revision_id])).rows;
   if(rows.length!==head.document_count)throw Object.assign(new Error('Embedding revision is incomplete; reindex required'),{code:'EMBEDDING_REINDEX_REQUIRED'});
   const result=rows.map(row=>{if(!Array.isArray(row.embedding)||row.embedding.length!==384||row.embedding.some(n=>typeof n!=='number'||!Number.isFinite(n)))unavailable();const vector=unit(row.embedding);const score=Math.max(-1,Math.min(1,vector.reduce((sum,n,i)=>sum+n*queryUnit[i],0)));return Object.freeze({sourceKind:row.source_kind,sourceId:Number(row.source_id),chunkIndex:row.chunk_index,text:row.body,score});}).sort((a,b)=>b.score-a.score).slice(0,limit);
   const ranked=Object.freeze(result);
   const lineage=capture?await captureSearchLineage(client,b,head,ranked):null;
   await checkCurrent(executionScope(b));if(await fingerprint()!==trusted)unavailable();
   return capture?Object.freeze({rows:ranked,lineage}):ranked;
  });
 }
 const search=(value,input)=>searchInternal(value,input,false);
 const searchWithLineage=(value,input)=>searchInternal(value,input,true);
 async function searchManuals(value,input){
  const b=scope(value);exact(input,['embedding','limit','merchantId','productId']);
  if(!Array.isArray(input.embedding)||input.embedding.length!==384||input.embedding.some(n=>typeof n!=='number'||!Number.isFinite(n))||!input.embedding.some(n=>n!==0)
   ||input.limit!==3||[input.merchantId,input.productId].some(n=>!Number.isSafeInteger(n)||n<1||n>2147483647))invalid();
  const merchantId=input.merchantId,productId=input.productId,limit=input.limit;
  const unit=vector=>{const scale=Math.max(...vector.map(Math.abs));if(!(scale>0)||!Number.isFinite(scale))unavailable();const scaled=vector.map(n=>n/scale),norm=Math.hypot(...scaled);return scaled.map(n=>n/norm);};
  const queryUnit=unit([...input.embedding]);await checkCurrent(executionScope(b));const trusted=await fingerprint();
  return online(b,async client=>{await active(client,b);
   // The target share lock fences source writers/publication. Product ownership,
   // revision identity, manual receipt and raw chunk are read in this transaction.
   // active() holds the parent target share lock used by canonical listing
   // writers. Immutable product rows deliberately have no runtime UPDATE grant,
   // so a locking SELECT on those rows would exceed runtime privileges.
   const product=(await client.query(`SELECT p.product_id,
    CASE WHEN o.product_id IS NULL THEN p.name ELSE o.name END AS name
    FROM secureshop_review.product_target_products p
    LEFT JOIN secureshop_review.product_target_listing_overlays o
     ON o.target_id=p.target_id AND o.product_id=p.product_id
    WHERE p.target_id=$1 AND p.product_id=$2 AND p.retailer_id=$3
     AND (CASE WHEN o.product_id IS NULL THEN p.status ELSE o.status END)='active'
     AND o.archived_at IS NULL`,[b.targetId,productId,merchantId])).rows[0];
   if(!product)throw Object.assign(new Error('Selected merchant product is unavailable'),{code:'OWNER_MISMATCH'});
   const head=(await client.query(`SELECT r.revision_id,encode(r.runtime_fingerprint,'hex') AS fingerprint,
    encode(r.source_set_digest,'hex') AS digest,
    r.source_set_digest=secureshop_review.product_embedding_source_digest($1,$2) AS current_source
    FROM secureshop_review.product_target_embedding_heads h JOIN secureshop_review.product_target_embedding_revisions r USING(revision_id)
    WHERE h.target_id=$1`,[b.targetId,b.generation])).rows[0];
   if(!head||!head.current_source)throw Object.assign(new Error('Reindex the current owned source corpus before searching'),{code:'EMBEDDING_REINDEX_REQUIRED'});
   if(head.fingerprint!==trusted)throw Object.assign(new Error('Active embedding revision uses a different runtime; reindex required'),{code:'EMBEDDING_RUNTIME_MISMATCH'});
   if(!UUID.test(head.revision_id)||!HASH.test(head.digest))unavailable();
   // Filter the selected merchant/product/manual corpus BEFORE cosine ranking.
   // A LEFT vector join makes an incomplete selected revision fail instead of
   // silently hiding an ingested chunk as an empty result.
   const rows=(await client.query(`SELECT d.source_id,d.chunk_index,d.body,
    encode(d.source_sha256,'hex') AS source_sha256,v.embedding,
    i.operation_id,i.filename,encode(i.receipt_sha256,'hex') AS receipt_sha256,
    encode(i.document_digest,'hex') AS document_digest,i.completed_at
    FROM secureshop_review.product_target_retrieval_documents d
    JOIN secureshop_review.product_target_manual_ingests i ON i.target_id=d.target_id
     AND i.generation=d.generation AND i.manual_source_id=d.source_id
     AND i.product_id=$4 AND i.merchant_id=$5
    LEFT JOIN secureshop_review.product_target_embedding_vectors v ON v.revision_id=$3
     AND v.source_kind=d.source_kind AND v.source_id=d.source_id AND v.chunk_index=d.chunk_index
     AND v.source_sha256=d.source_sha256
    WHERE d.target_id=$1 AND d.generation=$2 AND d.source_kind='manual'
    ORDER BY d.source_id,d.chunk_index LIMIT 4097`,[b.targetId,b.generation,head.revision_id,productId,merchantId])).rows;
   if(rows.length>4096)unavailable();
   const ranked=rows.map(row=>{
    if(!Array.isArray(row.embedding)||row.embedding.length!==384||row.embedding.some(n=>typeof n!=='number'||!Number.isFinite(n)))throw Object.assign(new Error('Selected manual revision is incomplete'),{code:'EMBEDDING_REINDEX_REQUIRED'});
    if(!Number.isSafeInteger(Number(row.source_id))||Number(row.source_id)<1||!Number.isInteger(row.chunk_index)||row.chunk_index<0||row.chunk_index>128
     ||typeof row.body!=='string'||!row.body.trim()||Buffer.byteLength(row.body)>65536||!HASH.test(row.source_sha256)
     ||!UUID.test(row.operation_id)||typeof row.filename!=='string'||!row.filename.trim()||Buffer.byteLength(row.filename)>4096
     ||!HASH.test(row.receipt_sha256)||!HASH.test(row.document_digest)||!Number.isFinite(new Date(row.completed_at).getTime()))unavailable();
    const vector=unit(row.embedding),score=Math.max(-1,Math.min(1,vector.reduce((sum,n,i)=>sum+n*queryUnit[i],0)));
    return Object.freeze({sourceKind:'manual',sourceId:Number(row.source_id),chunkIndex:row.chunk_index,text:row.body,score,
     sourceSha256:row.source_sha256,filename:row.filename,operationId:row.operation_id,receiptSha256:row.receipt_sha256,
     documentDigest:row.document_digest,completedAt:new Date(row.completed_at).toISOString()});
   }).sort((a,z)=>z.score-a.score||a.sourceId-z.sourceId||a.chunkIndex-z.chunkIndex);
   await checkCurrent(executionScope(b));if(await fingerprint()!==trusted)unavailable();
   return Object.freeze({product:Object.freeze({id:productId,name:product.name}),
    revision:Object.freeze({revisionId:head.revision_id,runtimeFingerprint:trusted,sourceSetDigest:head.digest}),
    hasMore:ranked.length>limit,sources:Object.freeze(ranked.slice(0,limit))});
  });
 }
 async function searchPolicies(value,input){
  const b=scope(value);exact(input,['embedding','limit','policyVersion','policySnapshotSha256']);
  if(!Array.isArray(input.embedding)||input.embedding.length!==384||input.embedding.some(n=>typeof n!=='number'||!Number.isFinite(n))||!input.embedding.some(n=>n!==0)||!Number.isInteger(input.limit)||input.limit<1||input.limit>4||typeof input.policyVersion!=='string'||!/^[1-9]\d{0,15}$/.test(input.policyVersion)||BigInt(input.policyVersion)>BigInt(Number.MAX_SAFE_INTEGER)||!HASH.test(input.policySnapshotSha256))invalid();
  const unit=vector=>{const scale=Math.max(...vector.map(Math.abs));if(!(scale>0)||!Number.isFinite(scale))unavailable();const scaled=vector.map(n=>n/scale),norm=Math.hypot(...scaled);return scaled.map(n=>n/norm);},queryUnit=unit([...input.embedding]);
  await checkCurrent(executionScope(b));const trusted=await fingerprint();
  return online(b,async client=>{await active(client,b);
   const head=(await client.query(`SELECT r.revision_id,encode(r.runtime_fingerprint,'hex') AS fingerprint,
    r.source_set_digest=secureshop_review.product_embedding_source_digest($1,$2) AS current_source,
    r.policy_version::text AS policy_version,encode(r.policy_snapshot_sha256,'hex') AS policy_snapshot_sha256
    FROM secureshop_review.product_target_embedding_heads h JOIN secureshop_review.product_target_embedding_revisions r USING(revision_id)
    WHERE h.target_id=$1`,[b.targetId,b.generation])).rows[0];
   if(!head||!head.current_source||head.fingerprint!==trusted||head.policy_version!==input.policyVersion||head.policy_snapshot_sha256!==input.policySnapshotSha256)throw Object.assign(new Error('Current policy revision is unavailable; rebuild required'),{code:'EMBEDDING_REINDEX_REQUIRED'});
   const rows=(await client.query(`SELECT i.name,d.body,encode(d.source_sha256,'hex') AS source_sha256,v.embedding
    FROM secureshop_review.product_target_embedding_vectors v
    JOIN secureshop_review.product_target_retrieval_documents d ON d.target_id=$1 AND d.generation=$2 AND d.source_kind='policy'
     AND d.source_kind=v.source_kind AND d.source_id=v.source_id AND d.chunk_index=v.chunk_index AND d.source_sha256=v.source_sha256
    JOIN secureshop_review.bound_system_policy_import_documents i ON i.operation_id=COALESCE((SELECT l.import_operation_id FROM secureshop_review.policy_embedding_lineage l WHERE l.revision_id=$3),$3) AND i.ordinal=d.source_id
    WHERE v.revision_id=$3 ORDER BY d.source_id,d.chunk_index`,[b.targetId,b.generation,head.revision_id])).rows;
   const results=rows.map(row=>{if(typeof row.name!=='string'||typeof row.body!=='string'||!HASH.test(row.source_sha256)||!Array.isArray(row.embedding)||row.embedding.length!==384||row.embedding.some(n=>typeof n!=='number'||!Number.isFinite(n)))unavailable();const vector=unit(row.embedding),score=Math.max(-1,Math.min(1,vector.reduce((sum,n,i)=>sum+n*queryUnit[i],0)));return Object.freeze({name:row.name,text:row.body,sourceSha256:row.source_sha256,score});}).sort((a,z)=>z.score-a.score||(a.name<z.name?-1:a.name>z.name?1:0)).slice(0,input.limit);
   await checkCurrent(executionScope(b));if(await fingerprint()!==trusted)unavailable();return Object.freeze({revisionId:head.revision_id,policyVersion:head.policy_version,policySnapshotSha256:head.policy_snapshot_sha256,results:Object.freeze(results)});
  });
 }
 return Object.freeze({snapshot,snapshotSelective,snapshotSelectiveInTransaction,snapshotForRebuildInTransaction,snapshotPolicyForRebuildInTransaction,assertActiveInTransaction,assertRebuildTargetInTransaction,publish,publishInTransaction,publishPolicyInTransaction,initializeInTransaction,
  readPublication,readPublicationInTransaction,readHead,search,searchWithLineage,searchManuals,searchPolicies});
}
module.exports={createSecureShopEmbeddingRevisionRepository};
