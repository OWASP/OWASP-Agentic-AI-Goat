'use strict';
// Real service/repository JavaScript boundary with controlled SQL responses.
// This does not qualify PostgreSQL constraints or concurrent publication.
const test = require('node:test');
const assert = require('node:assert/strict');
const { createSecureShopEmbeddingRevisionRepository } = require('../server/database/postgres/secureshopEmbeddingRevisionRepository');
const { createSecureShopEmbeddingReindex } = require('../server/services/secureshopEmbeddingReindex');
const { createSceneBinding } = require('../server/services/secureshopSceneBinding');
const id = '11111111-1111-4111-8111-111111111111';
const hash = 'a'.repeat(64);
const scope = { launchId: id, scenarioId: id, generation: 1, platformOwnerId: 1, platformSessionId: 2 };
const binding = { ...scope, targetId: id };
const vector = () => Array.from({ length: 384 }, (_, i) => i === 0 ? 1 : 0);
function fixture() {
  const state = { statements: [], embeds: [], publications: [], publicationHeads: [], runtime: hash,
    rows: [
      { source_kind: 'product', source_id: '1', chunk_index: 0, body: 'Changed product', hash, embedding: null },
      { source_kind: 'manual', source_id: '2', chunk_index: 0, body: 'Retained manual', hash, embedding: vector() },
    ] };
  const client = { release() {}, async query(sql, params) {
    state.statements.push(sql);
    if (sql.includes('assert_scene_execution_grant')) {
      state.grantParams = params;
      return { rows: [{ allowed: true }] };
    }
    if (sql.includes('record_scene_retrieval_embedding_effect')) {
      state.effectParams = params;
      return { rows: [{ record_scene_retrieval_embedding_effect: true }] };
    }
    if (sql.includes('publish_product_embedding_revision')||sql.includes('publish_embedding_with_policy_lineage')) {
      if(state.rejectLineage&&sql.includes('publish_embedding_with_policy_lineage'))throw Object.assign(Error('policy lineage evidence changed'),{code:'55000'});
      state.publications.push(JSON.parse(params[10]));
      state.publicationHeads.push(params[9]);
      return { rows: [{ revision_id: id, runtime_fingerprint: Buffer.from(hash, 'hex'),
        source_set_digest: Buffer.from(hash, 'hex'), vector_digest: Buffer.from(hash, 'hex'),
        document_count: 2, replayed: false }] };
    }
    if (sql.includes('SELECT t.target_id')) return { rows: [{ target_id: id }] };
    if (sql.includes('AND r.revision_id=$7')) {
      state.readbackParams = params;
      return { rows: state.noReceipt ? [] : [{ revision_id: id, fingerprint: hash,
        source_digest: hash, vector_digest: hash, document_count: 2 }] };
    }
    if (sql.includes('SELECT r.revision_id,h.revision_id')) return { rows: state.missingHead ? [] : [{ revision_id: id, current_head: state.invalidatedHead ? null : id, runtime_fingerprint: hash, digest: hash }] };
    if (sql.includes('LEFT JOIN secureshop_review.product_target_embedding_vectors')) return { rows: state.rows };
    return { rows: [] };
  } };
  const repository = createSecureShopEmbeddingRevisionRepository({ query: client.query, connect: async () => client },
    { checkCurrent: async () => {}, getRuntimeFingerprint: () => state.runtime });
  const service = createSecureShopEmbeddingReindex({ repository, checkCurrent: async () => {},
    embedder: { getRuntimeFingerprint: () => ({ fingerprint: state.runtime }), async embed(text) {
      state.embeds.push(text);
      if (state.changeRuntime) state.runtime = 'b'.repeat(64);
      return { embeddingDimension: 384, embedding: vector() };
    } } });
  return { state, repository, service, input: { scope, binding, operationId: id, corpus: 'products' } };
}

test('changed selected source reaches real publish validator; sparse sibling vector is preserved', async () => {
  const f = fixture();
  const result = await f.service.reindexSelective(f.input);
  assert.equal(result.documentCount, 2);
  assert.deepEqual(f.state.embeds, ['Changed product']);
  assert.equal(f.state.publications.length, 1);
  assert.deepEqual(f.state.publications[0][1].embedding, vector());
  assert.ok(f.state.publications[0].every(row => !Object.hasOwn(row, 'text')));
});

test('selective reindex passes a branded birth binding while checking current execution', async () => {
  const f = fixture();
  const current = { ...scope, launchId: '22222222-2222-4222-8222-222222222222',
    scenarioId: '33333333-3333-4333-8333-333333333333', generation: 2,
    platformSessionId: 3 };
  const scene = createSceneBinding(binding, {
    sceneId: '44444444-4444-4444-8444-444444444444', sceneGeneration: 1,
    grantId: '55555555-5555-4555-8555-555555555555', execution: current,
    withLease: work => work(),
  });
  const result = await f.service.reindexSelective({ ...f.input, scope: current, binding: scene });
  assert.equal(result.revisionId, id);
  assert.deepEqual(f.state.grantParams, [scene.scene.grantId, scene.scene.sceneId, 1,
    binding.targetId, current.launchId, current.scenarioId, current.generation,
    current.platformOwnerId, current.platformSessionId]);
  assert.deepEqual(f.state.effectParams, ['embedding_revision', id,
    binding.targetId, scene.scene.grantId]);
});

test('missing, zero and malformed preserved sibling vectors prevent inference/publication', async () => {
  for (const embedding of [null, Array(384).fill(0), [1], Array(384).fill(NaN)]) {
    const f = fixture(); f.state.rows[1].embedding = embedding;
    await assert.rejects(f.service.reindexSelective(f.input), { code: 'EMBEDDING_REVISION_UNAVAILABLE' });
    assert.deepEqual(f.state.embeds, []);
    assert.deepEqual(f.state.publications, []);
  }
});

test('closed corpus selection rejects inherited and coerced keys before SQL', async () => {
  for (const corpus of ['unknown', '__proto__', 'toString', ['products'], { toString: () => 'products' }]) {
    const f = fixture();
    await assert.rejects(f.service.reindexSelective({ ...f.input, corpus }), { code: 'EMBEDDING_REINDEX_UNSUPPORTED' });
    assert.deepEqual(f.state.statements, []);
  }
});

test('nonpolicy reindex routes policy siblings through authoritative lineage publisher', async () => {
 const f=fixture();f.state.rows[1]={...f.state.rows[1],source_kind:'policy'};
 await f.service.reindexSelective(f.input);
 assert.equal(f.state.publications.length,1);
 assert.deepEqual(f.state.publications[0][1].embedding,vector());
 assert(f.state.statements.some(s=>s.includes('publish_embedding_with_policy_lineage')));
 assert(!f.state.statements.some(s=>s.includes('publish_product_embedding_revision')));
});
test('lineage rejection is propagated without fallback publication',async()=>{
 const f=fixture();f.state.rows[1]={...f.state.rows[1],source_kind:'policy'};f.state.rejectLineage=true;
 await assert.rejects(f.service.reindexSelective(f.input),{code:'55000'});
 assert.deepEqual(f.state.publications,[]);
 assert(!f.state.statements.some(s=>s.includes('publish_product_embedding_revision')));
});

test('missing head or runtime change never publishes selective vectors', async () => {
  const missing = fixture(); missing.state.missingHead = true;
  await assert.rejects(missing.service.reindexSelective(missing.input), { code: 'EMBEDDING_REVISION_UNAVAILABLE' });
  const changed = fixture(); changed.state.changeRuntime = true;
  await assert.rejects(changed.service.reindexSelective(changed.input), { code: 'EMBEDDING_RUNTIME_CHANGED' });
  assert.deepEqual(changed.state.publications, []);
});

test('snapshot captures selected kinds before authority yields', async () => {
  const f = fixture(), sourceKinds = ['product'];
  const pending = f.repository.snapshotSelective(binding, { sourceKinds });
  sourceKinds[0] = 'manual';
  const snapshot = await pending;
  assert.equal(snapshot.documents[0].embedding, null);
  assert.deepEqual(snapshot.documents[1].embedding, vector());
});

// SQL-level invalidation and exact source-hash joins require native qualification.
test('retained base vectors allow changed-source rebuild with a nullable CAS head', async () => {
  const f = fixture(); f.state.invalidatedHead = true;
  const snapshot = await f.repository.snapshotSelective(binding, { sourceKinds: ['product', 'listing'] });
  assert.equal(snapshot.expectedHead, null); assert.equal(snapshot.baseRevisionId, id);
  await f.service.reindexSelective(f.input);
  assert.equal(f.state.publications.length, 1);
  assert.deepEqual(f.state.publicationHeads, [null]);
});

test('immutable publication recovery does not depend on current runtime or active head', async () => {
  const f = fixture(); f.state.runtime = null; f.state.missingHead = true;
  const receipt = await f.repository.readPublication(binding, id);
  assert.equal(receipt.revisionId, id); assert.equal(receipt.replayed, true);
  assert.deepEqual(f.state.readbackParams, [id, id, id, 1, 1, 2, id]);
  assert.deepEqual(f.state.publications, []); assert.deepEqual(f.state.embeds, []);
  assert.ok(!f.state.statements.some(sql => sql.includes('SELECT r.revision_id,h.revision_id')));
  f.state.noReceipt = true;
  assert.equal(await f.repository.readPublication(binding, id), null);
});

test('scene publication stores birth revision and records current grant in the same lease', async () => {
  const current = { ...scope, launchId: '22222222-2222-4222-8222-222222222222',
    scenarioId: '33333333-3333-4333-8333-333333333333', generation: 2,
    platformSessionId: 3 };
  let leased = false, grants = 0, effects = 0, replayed = false;
  const scene = createSceneBinding(binding, {
    sceneId: '44444444-4444-4444-8444-444444444444', sceneGeneration: 1,
    grantId: '55555555-5555-4555-8555-555555555555', execution: current,
    async withLease(work) { leased = true; try { return await work(); } finally { leased = false; } },
  });
  const client = { release() {}, async query(sql, params) {
    if (['BEGIN', 'COMMIT', 'ROLLBACK'].includes(sql)) return { rows: [] };
    assert.equal(leased, true);
    if (sql.includes('assert_scene_execution_grant')) {
      grants++;
      assert.deepEqual(params, [scene.scene.grantId, scene.scene.sceneId, 1,
        binding.targetId, current.launchId, current.scenarioId, current.generation,
        current.platformOwnerId, current.platformSessionId]);
      return { rows: [{ allowed: true }] };
    }
    if (sql.includes('publish_product_embedding_revision')) {
      assert.deepEqual(params.slice(0, 6), [binding.targetId, binding.launchId,
        binding.scenarioId, binding.generation, binding.platformOwnerId, binding.platformSessionId]);
      return { rows: [{ revision_id: id, runtime_fingerprint: Buffer.from(hash, 'hex'),
        source_set_digest: Buffer.from(hash, 'hex'), vector_digest: Buffer.from(hash, 'hex'),
        document_count: 1, replayed }] };
    }
    if (sql.includes('record_scene_retrieval_embedding_effect')) {
      effects++;
      assert.deepEqual(params, ['embedding_revision', id, binding.targetId, scene.scene.grantId]);
      return { rows: [{ record_scene_retrieval_embedding_effect: true }] };
    }
    throw new Error(`Unexpected scene embedding SQL: ${sql}`);
  } };
  const repository = createSecureShopEmbeddingRevisionRepository({ query: client.query,
    connect: async () => client }, { checkCurrent: async actual => assert.deepEqual(actual, current),
    getRuntimeFingerprint: () => hash });
  await repository.publish(scene, { operationId: id, sourceSetDigest: hash,
    expectedHead: null, expectedRuntimeFingerprint: hash,
    documents: [{ sourceKind: 'product', sourceId: '1', chunkIndex: 0,
      sourceSha256: hash, embedding: vector() }] });
  replayed = true;
  await repository.publish(scene, { operationId: id, sourceSetDigest: hash,
    expectedHead: null, expectedRuntimeFingerprint: hash,
    documents: [{ sourceKind: 'product', sourceId: '1', chunkIndex: 0,
      sourceSha256: hash, embedding: vector() }] });
  assert.equal(grants, 6);
  assert.equal(effects, 1);
  assert.equal(leased, false);
  await assert.rejects(repository.publish({ ...scene }, { operationId: id,
    sourceSetDigest: hash, expectedHead: null, expectedRuntimeFingerprint: hash,
    documents: [{ sourceKind: 'product', sourceId: '1', chunkIndex: 0,
      sourceSha256: hash, embedding: vector() }] }), { code: 'SHOP_SCENE_STALE' });
});

function manualSearchFixture() {
 const rows = Array.from({length:4},(_,i)=>({source_id:String(10+i),chunk_index:0,body:`Raw manual ${i}`,
  source_sha256:hash,embedding:vector(),operation_id:id,filename:'owned.txt',receipt_sha256:hash,
  document_digest:hash,completed_at:'2026-10-11T00:00:00.000Z'}));
 const state={rows,queries:[],runtime:hash,head:true,owner:true,productName:'Owned product'};
 const client={release(){},async query(sql,params){state.queries.push({sql,params});
  if(sql.includes('SELECT t.target_id'))return{rows:[{target_id:id}]};
  if(sql.includes('SELECT p.product_id,')){
   // The runtime can read immutable product rows but cannot lock/update them.
   if(/FOR\s+(?:SHARE|UPDATE|NO KEY UPDATE|KEY SHARE)/i.test(sql))throw Object.assign(Error('permission denied for table product_target_products'),{code:'42501'});
   return{rows:state.owner?[{product_id:7,name:state.productName}]:[]};
  }
  if(sql.includes('FROM secureshop_review.product_target_embedding_heads'))return{rows:state.head?[{revision_id:id,fingerprint:hash,digest:hash,current_source:!state.stale}]:[]};
  if(sql.includes('JOIN secureshop_review.product_target_manual_ingests'))return{rows:state.rows};
  return{rows:[]};}};
 const repository=createSecureShopEmbeddingRevisionRepository({query:client.query,connect:async()=>client},
  {checkCurrent:async()=>{},getRuntimeFingerprint:()=>state.runtime});
 return{state,repository,input:{embedding:vector(),limit:3,merchantId:9,productId:7}};
}
test('manual revision search filters owned product and manual rows in SQL before ranking and carries same-head provenance',async()=>{
 const f=manualSearchFixture(),r=await f.repository.searchManuals(binding,f.input);
 assert.equal(r.sources.length,3);assert.equal(r.hasMore,true);assert.deepEqual(r.sources.map(s=>s.sourceId),[10,11,12]);
 assert.deepEqual(r.product,{id:7,name:'Owned product'});assert.deepEqual(r.revision,{revisionId:id,runtimeFingerprint:hash,sourceSetDigest:hash});
 assert.equal(r.sources[0].text,'Raw manual 0');assert.equal(r.sources[0].receiptSha256,hash);
 const q=f.state.queries.find(q=>q.sql.includes('JOIN secureshop_review.product_target_manual_ingests'));
 assert.match(q.sql,/i\.product_id=\$4 AND i\.merchant_id=\$5/);assert.match(q.sql,/d\.source_kind='manual'/);assert.match(q.sql,/LIMIT 4097/);
 assert.match(q.sql,/LEFT JOIN secureshop_review\.product_target_embedding_vectors/);
 assert.deepEqual(q.params,[id,1,id,7,9]);
 const owned=f.state.queries.find(q=>q.sql.includes('SELECT p.product_id,'));
 assert.match(owned.sql,/p\.retailer_id=\$3/);assert.deepEqual(owned.params,[id,7,9]);
 assert.match(owned.sql,/LEFT JOIN secureshop_review\.product_target_listing_overlays o\s+ON o\.target_id=p\.target_id AND o\.product_id=p\.product_id/);
 assert.match(owned.sql,/CASE WHEN o\.product_id IS NULL THEN p\.name ELSE o\.name END AS name/);
 assert.match(owned.sql,/CASE WHEN o\.product_id IS NULL THEN p\.status ELSE o\.status END\)='active'/);
 assert.match(owned.sql,/o\.archived_at IS NULL/);
 const parent=f.state.queries.find(q=>q.sql.includes('SELECT t.target_id'));
 assert.match(parent.sql,/FOR SHARE OF t/);
 assert.ok(f.state.queries.indexOf(parent)<f.state.queries.indexOf(owned));
});
test('manual result uses the effective listing name and rejects an unavailable listing before source reads',async()=>{
 const renamed=manualSearchFixture();renamed.state.productName='Current renamed listing';
 assert.equal((await renamed.repository.searchManuals(binding,renamed.input)).product.name,'Current renamed listing');
 const unavailable=manualSearchFixture();unavailable.state.owner=false;
 await assert.rejects(unavailable.repository.searchManuals(binding,unavailable.input),{code:'OWNER_MISMATCH'});
 assert.equal(unavailable.state.queries.some(q=>q.sql.includes('product_target_manual_ingests')),false);
});
test('manual repository honest empty, foreign product, stale head and incomplete selected vectors',async()=>{
 const empty=manualSearchFixture();empty.state.rows=[];const r=await empty.repository.searchManuals(binding,empty.input);assert.deepEqual(r.sources,[]);assert.equal(r.hasMore,false);
 for(const kind of ['owner','head','stale','vector','runtime']){
  const f=manualSearchFixture();if(kind==='owner')f.state.owner=false;if(kind==='head')f.state.head=false;if(kind==='stale')f.state.stale=true;if(kind==='vector')f.state.rows[0].embedding=null;if(kind==='runtime')f.state.runtime='b'.repeat(64);
  await assert.rejects(f.repository.searchManuals(binding,f.input),{code:kind==='owner'?'OWNER_MISMATCH':kind==='runtime'?'EMBEDDING_RUNTIME_MISMATCH':'EMBEDDING_REINDEX_REQUIRED'});
 }
});
test('manual query exact scalar ownership and vector inputs reject before SQL',async()=>{
 for(const patch of [{productId:'7'},{merchantId:0},{limit:4},{embedding:Array(384).fill(0)},{other:true}]){
  const f=manualSearchFixture();await assert.rejects(f.repository.searchManuals(binding,{...f.input,...patch}),{code:'INVALID_ARGUMENT'});assert.equal(f.state.queries.length,0);
 }
});

test('manual corpus over the bounded probe fails rather than ranking partial results',async()=>{const f=manualSearchFixture();f.state.rows=Array(4097).fill(f.state.rows[0]);await assert.rejects(f.repository.searchManuals(binding,f.input),{code:'EMBEDDING_REVISION_UNAVAILABLE'});});
