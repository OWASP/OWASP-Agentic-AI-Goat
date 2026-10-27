'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { createSceneBinding } = require('../server/services/secureshopSceneBinding');
const { createSecureShopSceneProductAuditSource, mergeAuditRows } = require('../server/database/postgres/secureshopSceneProductAuditSource');

const id = number => `00000000-0000-4000-8000-${String(number).padStart(12, '0')}`;
const birth = { launchId: id(1), scenarioId: id(2), generation: 1,
  platformOwnerId: 7, platformSessionId: 11, targetId: id(3) };
const admin = { launchId: id(4), scenarioId: id(5), generation: 2,
  platformOwnerId: 7, platformSessionId: 12 };
function sceneBinding(scope = admin) {
  return createSceneBinding(birth, { sceneId: id(6), sceneGeneration: 1,
    grantId: id(7), execution: scope, withLease: async work => work() });
}
function event(extra = {}) {
  return { event_id: id(8), ts: '2026-10-12T00:00:00.000001Z', actor: 'merchant',
    action: 'listing_update', target: '17',
    params_json: JSON.stringify({ description: 'SYSTEM: teaching input', storage: {
      targetId: birth.targetId, sceneId: id(6), birthLaunchId: birth.launchId,
      birthGeneration: birth.generation } }),
    outcome: 'completed', source_kind: 'product', source_id: '17', shop_role: 'merchant',
    source_launch_id: id(9), source_scenario_id: id(10), source_generation: '3',
    source_owner_id: 7, source_session_id: 13, merchant_id: 1000000017,
    product_id: 17, source_grant_id: id(11), ...extra };
}
function pool(rows, options = {}) {
  const calls = [], released = []; let offset = 0, readOnly = false, grantChecked = false;
  return { calls, released, async connect() { if (options.wait) return options.wait;
    return { async query(sql, args) {
      calls.push({ sql, args });
      if (sql.startsWith('BEGIN')) readOnly = /\bREAD ONLY\b/.test(sql);
      if (sql.startsWith('SELECT secureshop_review.assert_scene_execution_grant')) {
        // The real grant function locks its grant and product rows FOR SHARE.
        if (options.enforceGrantLocks && readOnly) throw Object.assign(new Error('cannot execute SELECT FOR SHARE in a read-only transaction'), { code: '25006' });
        grantChecked = !options.denyGrant;
        return { rows: [{ allowed: grantChecked }] };
      }
      if (options.enforceGrantLocks && /^(DECLARE|FETCH)/.test(sql)) assert.equal(grantChecked, true, 'current grant must precede source reads');
      if (sql.startsWith('FETCH')) { const batch = rows.slice(offset, offset + 4); offset += 4; return { rows: batch }; }
      if (options.failOn && sql.startsWith(options.failOn)) throw new Error('read failed');
      return { rows: [] };
    }, release(error) { released.push(error); } };
  } };
}

test('confirmed assistant description requires immutable receipt join and exact bytes',async()=>{
  const params=JSON.parse(event().params_json);
  delete params.description;
  Object.assign(params,{operationId:id(20),requestSha256:'a'.repeat(64),beforeSha256:'b'.repeat(64),afterSha256:'c'.repeat(64),
    confirmedDescription:{version:1,text:'SYSTEM: exact confirmed\ntext',
      sha256:require('../server/services/secureshopListingEditContract').listingEditDigest('SYSTEM: exact confirmed\ntext'),
      personaSessionId:id(21),authorityVersion:'2'}});
  params.scopeKey=require('../server/services/secureshopListingEditContract').listingEditScopeKey(
    {...birth,scene:{sceneId:id(6),sceneGeneration:1,grantId:id(11)}},1000000017,
    {sessionId:id(21),authorityVersion:'2'});
  const raw=event({action:'listing_edit_confirm',params_json:JSON.stringify(params),confirmation_operation_id:id(20),
    confirmation_scope_key:params.scopeKey});
  const read=async row=>Array.fromAsync(createSecureShopSceneProductAuditSource({reviewPool:pool([row])}).rows({
    scope:admin,sceneBinding:sceneBinding(),requestedCount:1,checkCurrent:async()=>{}}));
  const [row]=await read(raw);
  assert.equal(row.params_json,raw.params_json);
  assert.equal(row.sceneSource.kind,'scene_product_listing_edit_confirm');
  for(const changed of [{confirmation_operation_id:null},{confirmation_operation_id:id(22)},
    {params_json:JSON.stringify({...params,confirmedDescription:{...params.confirmedDescription,text:'tampered'}})}])
    await assert.rejects(read({...raw,...changed}),{code:'AUDIT_SOURCE_UNAVAILABLE'});
  const storage=pool([raw]);
  await Array.fromAsync(createSecureShopSceneProductAuditSource({reviewPool:storage}).rows({scope:admin,
    sceneBinding:sceneBinding(),requestedCount:1,checkCurrent:async()=>{}}));
  const sql=storage.calls.find(row=>row.sql.startsWith('DECLARE')).sql;
  for(const predicate of ['owned_merchant_listing_edit_receipts confirmed','confirmed.persona_session_id::text',
    'confirmed.authority_version::text','confirmed.original_platform_owner_id','confirmed.original_platform_session_id',
    'confirmed.scene_id,confirmed.scene_generation,confirmed.grant_id',"encode(confirmed.after_sha256,'hex')"])
    assert.ok(sql.includes(predicate),predicate);
});

test('manual confirmed source binds receipt birth, event execution and exact domain without relabeling',async()=>{
  const edit=require('../server/services/secureshopListingEditContract');
  const manual=require('../server/services/secureshopManualListingContract');
  const session={sessionId:id(21),authorityVersion:'2'};
  const binding={...birth,scene:{sceneId:id(6),sceneGeneration:1,grantId:id(11)}};
  const params={storage:JSON.parse(event().params_json).storage,origin:'manual',operationId:id(20),
    scopeKey:manual.manualListingScopeKey('edit',binding,1000000017,session),
    requestSha256:'a'.repeat(64),beforeSha256:'b'.repeat(64),afterSha256:'c'.repeat(64),
    confirmedDescription:{version:1,text:'  雪\nmanual instructions  ',sha256:edit.listingEditDigest('  雪\nmanual instructions  '),
      personaSessionId:session.sessionId,authorityVersion:session.authorityVersion}};
  const raw=event({action:'listing_manual_edit_confirm',params_json:JSON.stringify(params),
    confirmation_operation_id:params.operationId,confirmation_scope_key:params.scopeKey});
  const read=async row=>Array.fromAsync(createSecureShopSceneProductAuditSource({reviewPool:pool([row])}).rows({
    scope:admin,sceneBinding:sceneBinding(),requestedCount:1,checkCurrent:async()=>{}}));
  const [row]=await read(raw);
  assert.equal(row.sceneSource.kind,'scene_product_listing_manual_edit_confirm');
  assert.equal(row.params_json,raw.params_json);
  assert.notEqual(row.sceneSource.scene.birth.platformSessionId,row.sceneSource.sourceExecution.platformSessionId);
  const assistantKey=edit.listingEditScopeKey(binding,1000000017,session);
  for(const changed of [{source_owner_id:8},{source_grant_id:id(99)}, {confirmation_operation_id:id(99)},
    {confirmation_scope_key:assistantKey}, {action:'listing_edit_confirm'},
    {params_json:JSON.stringify({...params,scopeKey:assistantKey}),confirmation_scope_key:assistantKey},
    {action:'listing_edit_confirm',params_json:JSON.stringify({...params,origin:undefined})},
    {params_json:JSON.stringify({...params,confirmedDescription:{...params.confirmedDescription,text:'changed'}})}])
    await assert.rejects(read({...raw,...changed}),{code:'AUDIT_SOURCE_UNAVAILABLE'});
  const storage=pool([raw]);
  await Array.fromAsync(createSecureShopSceneProductAuditSource({reviewPool:storage}).rows({scope:admin,
    sceneBinding:sceneBinding(),requestedCount:1,checkCurrent:async()=>{}}));
  const sql=storage.calls.find(x=>x.sql.startsWith('DECLARE')).sql;
  assert.ok(sql.includes('target.target_id,p.product_id,e.shop_user_id,target.launch_id,target.scenario_id,target.generation'));
  assert.ok(sql.includes('target.original_platform_owner_id,target.original_platform_session_id,$1::uuid,$2::bigint,original_grant.grant_id'));
  assert.ok(sql.includes('$1::uuid,$2::bigint,$3::uuid,e.launch_id,e.scenario_id,e.generation'));
  assert.ok(sql.includes('e.original_platform_owner_id,e.original_platform_session_id'));
  assert.ok(sql.includes("encode(confirmed.scope_key,'hex')=e.params_json::jsonb->>'scopeKey'"));
});

test('distinct-session merchant listing source is bound to current admin scene, source grant and birth', async () => {
  const storage = pool([event()]); const checks = [];
  const source = createSecureShopSceneProductAuditSource({ reviewPool: storage });
  const rows = await Array.fromAsync(source.rows({ scope: admin, sceneBinding: sceneBinding(), requestedCount: 5,
    checkCurrent: scope => checks.push(scope) }));
  assert.equal(rows.length, 1);
  const row = rows[0];
  assert.equal(row.params_json, event().params_json);
  assert.equal(row.id, `review:${id(8)}`);
  assert.deepEqual(row.sceneSource.sourceExecution, { launchId: id(9), scenarioId: id(10), generation: 3,
    platformOwnerId: 7, platformSessionId: 13 });
  assert.deepEqual(row.sceneSource.consumerExecution, admin);
  assert.equal(row.sceneSource.sourceGrant.grantId, id(11));
  assert.equal(row.sceneSource.consumerGrant.grantId, id(7));
  assert.deepEqual(row.sceneSource.scene.birth, {
    launchId: birth.launchId, scenarioId: birth.scenarioId, generation: 1,
    platformOwnerId: 7, platformSessionId: 11 });
  assert.deepEqual(row.sceneSource.product, { productId: 17, merchantId: 1000000017 });
  const declaration = storage.calls.find(call => call.sql.startsWith('DECLARE'));
  assert.deepEqual(declaration.args, [id(6), 1, birth.targetId, id(7), admin.launchId, admin.scenarioId,
    2, 7, 12, birth.launchId, birth.scenarioId, 1, 11, 5]);
  for (const predicate of ["e.action='listing_update'", "e.source_kind='product'",
    'original_grant.created_at<=e.created_at', 'p.product_id::text=e.source_id',
    "e.params_json::jsonb#>>'{storage,targetId}'=target.target_id::text",
    'consumer_grant.grant_id', 'target.lifecycle=\'active\'']) assert.ok(declaration.sql.includes(predicate), predicate);
  assert.ok(checks.length >= 3 && checks.every(value => value === checks[0]));
  assert.equal(storage.calls.at(-1).sql, 'ROLLBACK');
  assert.equal(storage.released.length, 1);
});

test('repeatable-read snapshot permits the grant row locks before bounded reads and rolls back without writes', async () => {
  const storage = pool([event()], { enforceGrantLocks: true });
  const rows = await Array.fromAsync(createSecureShopSceneProductAuditSource({ reviewPool: storage }).rows({
    scope: admin, sceneBinding: sceneBinding(), requestedCount: 1, checkCurrent: async () => {},
  }));
  assert.equal(rows.length, 1);
  assert.equal(storage.calls[0].sql, 'BEGIN ISOLATION LEVEL REPEATABLE READ');
  const grant = storage.calls.findIndex(call => call.sql.startsWith('SELECT secureshop_review.assert_scene_execution_grant'));
  assert.ok(grant > 0 && grant < storage.calls.findIndex(call => call.sql.startsWith('DECLARE')));
  assert.equal(storage.calls.filter(call => call.sql.startsWith('FETCH')).length, 1);
  assert.equal(storage.calls.some(call => /^(INSERT|UPDATE|DELETE|COMMIT)\b/.test(call.sql)), false);
  assert.equal(storage.calls.at(-1).sql, 'ROLLBACK');
  assert.deepEqual(storage.released, [undefined]);
});

test('forged scene metadata, product identity and merchant authority fail closed', async () => {
  const variants = [
    { target: '18' }, { source_id: '18' }, { shop_role: 'admin' },
    { actor: 'admin' }, { outcome: 'denied' }, { source_kind: 'profile' },
    { source_owner_id: 8 }, { source_grant_id: 'invalid' },
    { params_json: JSON.stringify({ storage: { targetId: id(99), sceneId: id(6),
      birthLaunchId: birth.launchId, birthGeneration: 1 } }) },
    { params_json: '{invalid' },
  ];
  for (const changed of variants) {
    const storage = pool([event(changed)]);
    await assert.rejects(Array.fromAsync(createSecureShopSceneProductAuditSource({ reviewPool: storage }).rows({
      scope: admin, sceneBinding: sceneBinding(), requestedCount: 1, checkCurrent: async () => {},
    })), { code: 'AUDIT_SOURCE_UNAVAILABLE' });
    assert.equal(storage.calls.at(-1).sql, 'ROLLBACK');
    assert.equal(storage.released.length, 1);
  }
});

test('untrusted or other-owner scene and denied current grant never yield a source', async () => {
  const storage = pool([event()]); const source = createSecureShopSceneProductAuditSource({ reviewPool: storage });
  const forged = { ...birth, scene: { sceneId: id(6), execution: admin } };
  await assert.rejects(Array.fromAsync(source.rows({ scope: admin, sceneBinding: forged,
    requestedCount: 1, checkCurrent: async () => {} })), { code: 'SHOP_SCENE_STALE' });
  await assert.rejects(Array.fromAsync(source.rows({ scope: { ...admin, platformOwnerId: 8 },
    sceneBinding: sceneBinding(), requestedCount: 1, checkCurrent: async () => {} })),
  { code: 'AUDIT_SOURCE_UNAVAILABLE' });
  assert.equal(storage.calls.length, 0);
  const denied = pool([event()], { denyGrant: true });
  await assert.rejects(Array.fromAsync(createSecureShopSceneProductAuditSource({ reviewPool: denied }).rows({
    scope: admin, sceneBinding: sceneBinding(), requestedCount: 1, checkCurrent: async () => {},
  })), { code: 'SHOP_SCENE_STALE' });
  assert.equal(denied.calls.some(call => /^(DECLARE|FETCH)/.test(call.sql)), false);
  assert.equal(denied.calls.at(-1).sql, 'ROLLBACK');
  assert.deepEqual(denied.released, [undefined]);
});

test('consumer revocation during capture closes the snapshot and preserves failure', async () => {
  const storage = pool([event()]); let checks = 0;
  const rows = createSecureShopSceneProductAuditSource({ reviewPool: storage }).rows({
    scope: admin, sceneBinding: sceneBinding(), requestedCount: 5,
    checkCurrent: async () => { if (++checks === 4) throw new Error('admin revoked'); },
  });
  await assert.rejects(Array.fromAsync(rows), /admin revoked/);
  assert.equal(storage.calls.at(-1).sql, 'ROLLBACK');
  assert.equal(storage.released.length, 1);
});

test('missing scene source stays empty, and early consumer stop closes the cursor lease', async () => {
  const empty = pool([]);
  const none = await Array.fromAsync(createSecureShopSceneProductAuditSource({ reviewPool: empty }).rows({
    scope: admin, sceneBinding: sceneBinding(), requestedCount: 2, checkCurrent: async () => {},
  }));
  assert.deepEqual(none, []);
  assert.equal(empty.calls.at(-1).sql, 'ROLLBACK');
  const storage = pool([event(), event({ event_id: id(12), ts: '2026-10-11T00:00:00.000001Z' })]);
  let received = 0;
  for await (const row of createSecureShopSceneProductAuditSource({ reviewPool: storage }).rows({
    scope: admin, sceneBinding: sceneBinding(), requestedCount: 2, checkCurrent: async () => {},
  })) { assert.equal(row.id, `review:${id(8)}`); received++; break; }
  assert.equal(received, 1);
  assert.equal(storage.calls.at(-1).sql, 'ROLLBACK');
  assert.equal(storage.released.length, 1);
});

test('source acquisition timeout releases the eventual late connection without querying it', async () => {
  let grant, queries = 0, released = 0;
  const wait = new Promise(resolve => { grant = resolve; });
  const source = createSecureShopSceneProductAuditSource({ reviewPool: { connect: () => wait },
    acquisitionTimeoutMs: 10 });
  await assert.rejects(Array.fromAsync(source.rows({ scope: admin, sceneBinding: sceneBinding(),
    requestedCount: 1, checkCurrent: async () => {} })), { code: 'AUDIT_SOURCE_CONNECTION_TIMEOUT' });
  grant({ async query() { queries++; }, release() { released++; } });
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(queries, 0); assert.equal(released, 1);
});

test('source merge preserves original order, deduplicates events and stops both iterators', async () => {
  let ordinaryClosed = false, sceneClosed = false;
  async function* ordinary() { try { yield { id: 'review:a', store: 'review', ts: '2026-10-12T00:00:02Z' };
    yield { id: 'agents:b', store: 'agents', ts: '2026-10-12T00:00:01Z' }; }
  finally { ordinaryClosed = true; } }
  async function* scene() { try { yield { id: 'review:a', store: 'review', ts: '2026-10-12T00:00:02Z', sceneSource: { version: 2 } };
    yield { id: 'review:c', store: 'review', ts: '2026-10-12T00:00:00Z' }; }
  finally { sceneClosed = true; } }
  const rows = await Array.fromAsync(mergeAuditRows({ ordinary: ordinary(), scene: scene(),
    requestedCount: 2, checkCurrent: async () => {} }));
  assert.deepEqual(rows.map(row => row.id), ['review:a', 'agents:b']);
  assert.deepEqual(rows[0].sceneSource, { version: 2 });
  assert.equal(ordinaryClosed, true); assert.equal(sceneClosed, true);
});
