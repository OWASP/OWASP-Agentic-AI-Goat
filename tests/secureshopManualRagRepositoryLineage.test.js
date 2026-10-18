'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const { createSceneBinding } = require('../server/services/secureshopSceneBinding');
const { createSecureShopEmbeddingRevisionRepository } = require('../server/database/postgres/secureshopEmbeddingRevisionRepository');
const hash = value => createHash('sha256').update(value).digest('hex');
const uuid = digit => `${digit.repeat(8)}-${digit.repeat(4)}-4${digit.repeat(3)}-8${digit.repeat(3)}-${digit.repeat(12)}`;
const birth = { launchId: uuid('1'), scenarioId: uuid('2'), generation: 1, platformOwnerId: 12, platformSessionId: 13 };
const target = { ...birth, targetId: uuid('3') };
const fingerprint = 'a'.repeat(64);
const vector = Array.from({ length: 384 }, (_, i) => i === 0 ? 1 : 0);

function fixture(mutate = () => {}) {
  const binding = createSceneBinding(target, { sceneId: uuid('4'), sceneGeneration: 1,
    grantId: uuid('5'), execution: { ...birth, launchId: uuid('6'), platformSessionId: 14 }, withLease: work => work() });
  const rows = [
    { source_kind: 'manual', source_id: '71', chunk_index: 0, body: 'Owned original manual', embedding: vector },
    { source_kind: 'product', source_id: '12', chunk_index: 0, body: 'Product', embedding: vector.map((_, i) => i === 1 ? 1 : 0) },
  ];
  const sources = rows.map(row => ({ sourceKind: row.source_kind, sourceId: row.source_id,
    chunkIndex: row.chunk_index, text: row.body, sourceSha256: hash(row.body + '-original-ingest-vector') }));
  const vectors = sources.map(({ text, ...source }, i) => ({ ...source, embedding: rows[i].embedding }));
  const sourceSetJson = JSON.stringify(sources), vectorsJson = JSON.stringify(vectors);
  const revision = { revisionId: uuid('7'), ...target, runtimeFingerprint: fingerprint,
    sourceSetDigest: hash(sourceSetJson), vectorDigest: hash(vectorsJson), documentCount: 2 };
  const state = { statements: [], runtime: fingerprint, rows,
    head: { revision_id: revision.revisionId, fingerprint, document_count: 2, current_source: true },
    projected: { oversized: false, digest_valid: true, selected_sources: sources.filter(row=>row.sourceKind==='manual'),
      lineage: { eligible: true, version: 2, revision,
      preimageRef:{version:1,revisionId:revision.revisionId,sourceSetDigest:revision.sourceSetDigest,vectorDigest:revision.vectorDigest}, manualSources: [{ sourceId: 71, operationId: uuid('8'),
        productId: 12, merchantId: 41, receiptSha256: 'c'.repeat(64) }] } } };
  mutate(state);
  const client = { release() {}, async query(sql, params) {
    state.statements.push(sql);
    if (sql.includes('assert_scene_execution_grant')) return { rows: [{ allowed: true }] };
    if (sql.includes('SELECT t.target_id')) return { rows: [{ target_id: target.targetId }] };
    if (sql.includes('SELECT r.revision_id,r.document_count')) return { rows: [state.head] };
    if (sql.includes('SELECT d.source_kind,d.source_id,d.chunk_index,d.body,v.embedding')) return { rows: state.rows };
    if (sql.startsWith('WITH source AS')) {
      assert.deepEqual(params, [target.targetId, 1, state.head.revision_id, JSON.stringify([{sourceId:71,chunkIndex:0}]), 49152]);
      assert.match(sql, /WHERE r.revision_id=\$3/);
      assert.match(sql, /product_target_embedding_preimages/);
      assert.doesNotMatch(sql, /product_target_embedding_heads|to_jsonb\(v.embedding\)/);
      assert.match(sql, /i.is_public AND i.receipt_version=2/);
      if (state.driftOnCapture) state.runtime = 'b'.repeat(64);
      return { rows: state.projected ? [state.projected] : [] };
    }
    if (['BEGIN', 'COMMIT', 'ROLLBACK'].includes(sql)) return { rows: [] };
    throw Error(`Unexpected query ${sql}`);
  } };
  const repo = createSecureShopEmbeddingRevisionRepository({ query: client.query, connect: async () => client }, {
    checkCurrent: async () => {}, getRuntimeFingerprint: () => state.runtime });
  return { repo, binding, state, sources };
}

test('private rank projection uses original searched revision and preserves exact public ranked rows', async () => {
  const f = fixture();
  const result = await f.repo.searchWithLineage(f.binding, { embedding: vector, limit: 1 });
  assert.equal(result.lineage.eligible, true);
  assert.equal(result.lineage.version,2);
  assert.equal(Object.hasOwn(result.lineage,'vectorsJson'),false);
  assert.equal(Object.hasOwn(result.lineage,'sourceSetJson'),false);
  assert.equal(result.lineage.selected.length, 1);
  assert.equal(result.lineage.selected[0].textSha256, hash(result.rows[0].text));
  assert.equal(result.lineage.selected[0].sourceSha256, f.sources[0].sourceSha256);
  assert.notEqual(result.lineage.selected[0].textSha256, result.lineage.selected[0].sourceSha256);
  assert.equal(Object.isFrozen(result.lineage.selected[0]), true);
  const capture = f.state.statements.findIndex(sql => sql.startsWith('WITH source AS'));
  assert.ok(capture > f.state.statements.findIndex(sql => sql.includes('SELECT d.source_kind')));
  assert.ok(capture < f.state.statements.indexOf('COMMIT'));
  assert.match(f.state.statements[capture + 1], /assert_scene_execution_grant/);
  const ordinary = fixture();
  assert.deepEqual(await ordinary.repo.search(ordinary.binding, { embedding: vector, limit: 1 }), result.rows);
  assert.deepEqual(Object.keys(result.rows[0]), ['sourceKind','sourceId','chunkIndex','text','score']);
  assert.equal(ordinary.state.statements.some(sql => sql.startsWith('WITH source AS')), false);
});

test('optional proof refuses missing, private, oversize and exact revision/digest drift while keeping ranking', async () => {
  const cases = [
    [s => { s.projected = null; }, 'missing_original'],
    [s => { s.projected.lineage.manualSources = []; }, 'missing_original'],
    [s => { s.projected.oversized = true; s.projected.lineage = null; }, 'oversized'],
    [s => { s.projected.digest_valid = false; }, 'digest_mismatch'],
    [s => { s.projected.lineage.preimageRef.vectorDigest = '0'.repeat(64); }, 'digest_mismatch'],
    [s => { s.projected.selected_sources[0].text += ' changed'; }, 'digest_mismatch'],
    [s => { s.projected.selected_sources.push({...s.projected.selected_sources[0]}); }, 'digest_mismatch'],
    [s => { s.projected.lineage.revision.revisionId = uuid('9'); }, 'digest_mismatch'],
    [s => { s.projected.lineage.revision.platformSessionId += 1; }, 'digest_mismatch'],
    [s => { s.projected.lineage.revision.runtimeFingerprint = 'b'.repeat(64); }, 'digest_mismatch'],
  ];
  for (const [mutate, reason] of cases) {
    const f = fixture(mutate);
    const result = await f.repo.searchWithLineage(f.binding, { embedding: vector, limit: 1 });
    assert.deepEqual(result.lineage, { eligible: false, reason });
    assert.equal(result.rows[0].sourceId, 71);
    assert.ok(f.state.statements.includes('COMMIT'));
  }
});

test('runtime drift after private capture still rolls back; copied scene authority is rejected', async () => {
  const f = fixture(s => { s.driftOnCapture = true; });
  await assert.rejects(f.repo.searchWithLineage(f.binding, { embedding: vector, limit: 1 }), { code: 'EMBEDDING_REVISION_UNAVAILABLE' });
  assert.ok(f.state.statements.includes('ROLLBACK'));
  assert.equal(f.state.statements.includes('COMMIT'), false);
  const g = fixture();
  await assert.rejects(g.repo.searchWithLineage({ ...g.binding }, { embedding: vector, limit: 1 }), { code: 'SHOP_SCENE_STALE' });
  assert.deepEqual(g.state.statements, []);
});

test('ordinary nonmanual ranking is unchanged and cannot claim manual proof', async () => {
  const f = fixture(s => { s.rows[0].source_kind = 'review'; });
  const result = await f.repo.searchWithLineage(f.binding, { embedding: vector, limit: 1 });
  assert.deepEqual(result.lineage, { eligible: false, reason: 'no_selected_manual' });
  assert.equal(f.state.statements.some(sql => sql.startsWith('WITH source AS')), false);
});

test('125-document dense vector provenance is a compact immutable reference, never copied into the turn', async()=>{
 const seed=require('../db/postgres/seeds/secureshop.json').products;
 assert.equal(seed.length,125);
 const originalVectors=seed.map(product=>({sourceKind:'product',sourceId:String(product.id),chunkIndex:0,
  sourceSha256:hash(String(product.id)),embedding:Array.from({length:384},(_,i)=>Math.fround(Math.sin(i+product.id)/20))}));
 const originalJson=JSON.stringify(originalVectors);
 assert.ok(Buffer.byteLength(originalJson)>48*1024);
 const f=fixture(s=>{
  s.rows=[s.rows[0],...originalVectors.map(row=>({source_kind:'product',source_id:row.sourceId,chunk_index:0,body:'Product '+row.sourceId,embedding:row.embedding}))];
  s.head.document_count=126;s.projected.lineage.revision.documentCount=126;
  s.projected.lineage.revision.vectorDigest=hash(originalJson);
  s.projected.lineage.preimageRef.vectorDigest=hash(originalJson);
 });
 const result=await f.repo.searchWithLineage(f.binding,{embedding:vector,limit:1});
 assert.equal(result.lineage.eligible,true);
 assert.deepEqual(Object.keys(result.lineage).sort(),['eligible','manualSources','preimageRef','revision','selected','version']);
 assert.equal(result.lineage.preimageRef.vectorDigest,hash(originalJson));
 assert.ok(Buffer.byteLength(JSON.stringify(result.lineage))<4096);
 assert.equal(JSON.stringify(result).includes(originalJson),false);
 // This control qualifies reference size only. Native0050 verifies SQL storage
 // of all dense canonical values, digests and target lifecycle.
});
