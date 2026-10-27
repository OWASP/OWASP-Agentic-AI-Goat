'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const C = require('../server/services/secureshopManualListingContract');
const assistantCreate = require('../server/services/secureshopListingCreateContract');
const assistantEdit = require('../server/services/secureshopListingEditContract');
const { createSceneBinding } = require('../server/services/secureshopSceneBinding');
const { createSecureShopBoundProductRepository } = require('../server/database/postgres/secureshopBoundProductRepository');
const { createSecureShopBoundCatalog } = require('../server/services/secureshopBoundCatalog');
const birth = { targetId: '40000000-0000-4000-8000-000000000001', launchId: '10000000-0000-4000-8000-000000000001',
  scenarioId: '20000000-0000-4000-8000-000000000001', generation: 1, platformOwnerId: 4, platformSessionId: 5 };
const binding = createSceneBinding(birth, { sceneId: '50000000-0000-4000-8000-000000000001', sceneGeneration: 1,
  grantId: '60000000-0000-4000-8000-000000000001', execution: birth, withLease: work => work() });
const personaSession = { sessionId: '70000000-0000-4000-8000-000000000001', authorityVersion: '2' };
const operationId = '80000000-0000-4000-8000-000000000001';
const item = { name: 'Manual lamp', description: 'Merchant supplied text', price: 12.25,
  category: 'Home', images: ['/first.png', '/second.png'], templateSource: '{{ name }}' };
const sha = value => createHash('sha256').update(value).digest('hex');
function fixture({ generated = false } = {}) {
  const state = { products: [], receipts: new Map(), audits: [], writes: 0, revision: 3, queries: [], revoked: false,
    failAudit: false, row: { product_id: 11, retailer_id: 12, source_product_sha256: Buffer.alloc(32, 7),
      name: 'Old lamp', description: 'Old description', description_html: 'Generated presentation', price: '10.50',
      category: 'Home', image_url: '/old.png', images: ['/old.png', '/retained.png'], template_source: '{{ old }}',
      stock_quantity: 9, status: 'active', source_updated_at: new Date('2026-10-10T12:00:00Z'), archived_at: null },
    provenance: generated ? { source_name: 'Old lamp', source_description: 'Old description', html_sha256: sha('Generated presentation') } : null };
  let backup;
  const client = { async query(sql, args = []) {
    state.queries.push(sql);
    if (sql === 'BEGIN') { backup = { products: state.products.slice(), receipts: new Map(state.receipts),
      audits: state.audits.slice(), writes: state.writes, revision: state.revision, row: { ...state.row }, provenance: state.provenance }; return { rows: [] }; }
    if (sql === 'ROLLBACK') { Object.assign(state, backup); return { rows: [] }; }
    if (sql === 'COMMIT' || sql.startsWith('SET TRANSACTION') || sql.includes("set_config('statement_timeout'")) return { rows: [] };
    if (sql.includes('assert_scene_execution_grant')) return { rows: [{ allowed: true }] };
    if (sql.includes('FROM secureshop_review.product_targets')) return { rows: [{ target_id: birth.targetId,
      launch_id: birth.launchId, scenario_id: birth.scenarioId, generation: birth.generation,
      original_platform_owner_id: birth.platformOwnerId, original_platform_session_id: birth.platformSessionId,
      own_merchant_id: 12, lifecycle: 'active', source_sha256: Buffer.alloc(32, 5), source_count: 1 }] };
    if (sql.includes('SELECT COALESCE(max(product_id),0)+1')) return { rows: [{ product_id: state.products.length + 12 }] };
    if (sql.includes('INSERT INTO secureshop_review.product_target_products')) {
      state.writes++; state.products.push({ name: args[4], description: args[5], price: args[6], category: args[7],
        imageUrl: args[8], images: JSON.parse(args[9]), templateSource: args[10], sql }); return { rows: [] };
    }
    if (sql.includes('INSERT INTO secureshop_review.product_target_merchant_listings')) return { rows: [] };
    if (sql.includes('FROM secureshop_review.owned_listing_catalog_revisions')) return { rows: [{ revision: String(state.revision) }] };
    if (sql.includes('FROM secureshop_review.owned_listing_generated_products')) return { rows: state.provenance ? [state.provenance] : [] };
    if (sql.includes('WITH effective AS') && sql.includes('SELECT * FROM effective'))
      return { rows: args[2] === state.row.retailer_id && args[1] === state.row.product_id ? [state.row] : [] };
    if (sql.includes('INSERT INTO secureshop_review.product_target_listing_overlays')) {
      state.writes++;
      state.row = { ...state.row, name: args[3], description: args[4], description_html: args[5], price: args[6],
        category: args[7], image_url: args[8], images: JSON.parse(args[9]), stock_quantity: args[10], status: args[11], template_source: args[12],
        source_updated_at: new Date('2026-10-10T12:00:01Z') };
      if (state.provenance && (state.row.name !== state.provenance.source_name || state.row.description !== state.provenance.source_description)
          && sha(state.row.description_html || '') === state.provenance.html_sha256) { state.row.description_html = null; state.provenance = null; }
      state.revision++; return { rows: [] };
    }
    if (sql.includes('INSERT INTO secureshop_review.owned_merchant_listing_')) {
      if (state.failReceipt) throw Error('receipt insert failure');
      const columns = sql.match(/\(([^)]+)\)\s*VALUES/)[1].split(',').map(x => x.trim());
      const row = Object.fromEntries(columns.map((key, i) => [key, args[i]]));
      const kind = sql.includes('_create_receipts') ? 'create' : 'edit';
      if (state.receipts.has(`${kind}:${row.operation_id}`)) throw Error('duplicate operation');
      state.receipts.set(`${kind}:${row.operation_id}`, row); return { rows: [row] };
    }
    if (sql.includes('FROM secureshop_review.owned_merchant_listing_')) {
      assert.doesNotMatch(sql, /FOR\s+(SHARE|UPDATE)/);
      const kind = sql.includes('_create_receipts') ? 'create' : 'edit', row = state.receipts.get(`${kind}:${args[0]}`);
      return { rows: row && (args.length === 1 || args[1] === row.target_id && args[2] === row.merchant_id
        && args[3] === row.persona_session_id && args[4].equals(row.scope_key)) ? [row] : [] };
    }
    throw Error(`Unexpected manual listing query: ${sql}`);
  }, release() {} };
  const check = async () => { if (state.revoked) throw Object.assign(Error('revoked'), { code: 'SHOP_AUTH_INVALID' }); };
  const pool = { connect: async () => client, query: async () => { throw Error('transaction required'); } };
  const repository = createSecureShopBoundProductRepository(pool, { checkCurrent: check, checkCleanup: check,
    auditStore: { append: async (_client, row) => { if (state.failAudit) throw Error('audit failure'); state.audits.push(row); } } });
  return { state, repository, check };
}

test('manual contract is closed, canonical, full-field, bounded and domain-separated', () => {
  const createKey = C.manualListingScopeKey('create', binding, 12, personaSession);
  const editKey = C.manualListingScopeKey('edit', binding, 12, personaSession);
  assert.equal(new Set([createKey, editKey, assistantCreate.listingCreateScopeKey(binding, 12, personaSession),
    assistantEdit.listingEditScopeKey(binding, 12, personaSession)]).size, 4);
  assert.equal(C.manualListingStorageScope(createKey, editKey).length, 64);
  const preview = C.makeManualListingPreview({ version: 1, origin: 'manual', kind: 'create', listing: item,
    currency: 'USD', initialStock: 0, status: 'active', scopeKey: createKey });
  assert.deepEqual(C.validateManualListingPreview(JSON.parse(JSON.stringify(preview)), 'create'), preview);
  assert.equal(preview.requestSha256, sha(JSON.stringify(Object.fromEntries(Object.entries(preview).filter(([key]) => key !== 'requestSha256')))));
  for (const value of [{ ...item, source: {} }, { ...item, price: 1.001 }, { ...item, images: [, 'x'] },
    { ...item, images: Object.assign(new Array(1), { wrong: 'x' }) }, { ...item, name: '\ud800' }, { ...item, templateSource: '\0' }])
    assert.throws(() => C.normalizeManualListing(value));
  assert.throws(() => C.validateManualListingPreview({ ...preview, source: {} }, 'create'));
  assert.throws(() => C.validateManualListingPreview({ ...preview, origin: 'assistant' }, 'create'));
  assert.throws(() => C.validateManualListingPreview(preview, 'edit'));
  assert.throws(() => C.boundManualListingRequest({ text: 'x'.repeat(128 * 1024) }));
});

test('manual create preview is inert; full fields commit once and lost acknowledgement recovers exact receipt', async () => {
  const f = fixture(), preview = await f.repository.previewManualListingCreate(binding, 12, { listing: item, personaSession });
  assert.equal(f.state.writes, 0); assert.equal(f.state.audits.length, 0);
  const args = { operationId, preview, personaSession };
  const receipt = await f.repository.confirmManualListingCreate(binding, 12, args);
  assert.equal(receipt.origin, 'manual'); assert.equal(receipt.kind, 'create'); assert.equal(receipt.version, 1);
  assert.equal(receipt.replayed, false); assert.equal(receipt.source, undefined);
  assert.deepEqual(f.state.products[0].images, item.images); assert.equal(f.state.products[0].templateSource, item.templateSource);
  assert.match(f.state.products[0].sql, /NULL,\$7,\$8,\$9,\$10,0,'active'/);
  assert.deepEqual(await f.repository.readManualListingCreate(binding, 12, { operationId, personaSession }), { ...receipt, replayed: true });
  assert.deepEqual(await f.repository.confirmManualListingCreate(binding, 12, args), { ...receipt, replayed: true });
  assert.equal(f.state.writes, 1); assert.equal(f.state.audits.length, 1);
  const row = f.state.receipts.get(`create:${operationId}`); assert.equal(row.source_document, undefined);
  const changed = await f.repository.previewManualListingCreate(binding, 12, { listing: { ...item, images: ['/other.png'] }, personaSession });
  await assert.rejects(f.repository.confirmManualListingCreate(binding, 12, { ...args, preview: changed }), { code: 'LISTING_CREATE_RECEIPT_INVALID' });
  assert.equal(f.state.writes, 1);
});

test('manual/assistant readers and confirms cannot cross domains or expose actor source', async () => {
  const f = fixture(), preview = await f.repository.previewManualListingCreate(binding, 12, { listing: item, personaSession });
  await f.repository.confirmManualListingCreate(binding, 12, { operationId, preview, personaSession });
  assert.equal((await f.repository.readListingCreate(binding, 12, { operationId, personaSession })).status, 'not_found');
  await assert.rejects(f.repository.readListingCreateSource(binding, 12, { operationId, personaSession }), { code: 'LISTING_CREATE_SOURCE_UNAVAILABLE' });
  const other = await f.repository.previewListingCreate(binding, 12, { name: item.name, price: item.price },
    assistantCreate.listingCreateScopeKey(binding, 12, personaSession));
  await assert.rejects(f.repository.confirmManualListingCreate(binding, 12, { operationId, preview: other, personaSession }));
  await assert.rejects(f.repository.confirmListingCreate(binding, 12, { operationId, preview: other, personaSession }), { code: 'LISTING_CREATE_RECEIPT_INVALID' });
  assert.equal(f.state.writes, 1);
});

test('manual edit CAS updates complete images/template, preserves stock, invalidates generated HTML and replays after revision change', async () => {
  const f = fixture({ generated: true });
  const preview = await f.repository.previewManualListingEdit(binding, 12, { productId: 11, listing: item, personaSession });
  assert.equal(preview.invalidatesGeneratedHtml, true); assert.equal(preview.after.descriptionHtml, null);
  assert.deepEqual(preview.before.images, ['/old.png', '/retained.png']); assert.equal(f.state.writes, 0);
  const args = { operationId, preview, personaSession }, receipt = await f.repository.confirmManualListingEdit(binding, 12, args);
  assert.deepEqual(f.state.row.images, item.images); assert.equal(f.state.row.image_url, item.images[0]);
  assert.equal(f.state.row.template_source, item.templateSource); assert.equal(f.state.row.stock_quantity, 9);
  assert.equal(f.state.row.description_html, null); assert.equal(f.state.writes, 1);
  const audit=f.state.audits[0], params=JSON.parse(audit.paramsJson);
  assert.equal(audit.action,'listing_manual_edit_confirm');
  assert.equal(params.origin,'manual');assert.equal(params.operationId,operationId);
  assert.equal(params.scopeKey,receipt.scopeKey);assert.equal(params.requestSha256,preview.requestSha256);
  assert.equal(params.beforeSha256,receipt.beforeSha256);assert.equal(params.afterSha256,receipt.afterSha256);
  assert.deepEqual(params.confirmedDescription,{version:1,text:f.state.row.description,
    sha256:assistantEdit.listingEditDigest(f.state.row.description),personaSessionId:personaSession.sessionId,
    authorityVersion:personaSession.authorityVersion});
  assert.deepEqual(await f.repository.confirmManualListingEdit(binding, 12, args), { ...receipt, replayed: true });
  assert.deepEqual(await f.repository.readManualListingEdit(binding, 12, { operationId, personaSession }), { ...receipt, replayed: true });
  assert.equal((await f.repository.readListingEdit(binding, 12, { operationId, personaSession })).status, 'not_found');
  assert.equal(f.state.writes, 1);
  assert.equal(f.state.audits.length,1);assert.equal(f.state.audits[0].paramsJson,audit.paramsJson);
});

test('manual provenance keeps nullable/UTF8 applied bytes and separates receipt birth from current execution',async()=>{
  const execution={...birth,launchId:'10000000-0000-4000-8000-000000000002',
    scenarioId:'20000000-0000-4000-8000-000000000002',generation:3,platformSessionId:9};
  const current=createSceneBinding(birth,{...binding.scene,execution,withLease:work=>work()});
  for(const description of [null,'  雪\nimmutable confirmed description  ']){
    const f=fixture(),preview=await f.repository.previewManualListingEdit(current,12,{productId:11,
      listing:{...item,description},personaSession});
    await f.repository.confirmManualListingEdit(current,12,{operationId,preview,personaSession});
    const record=f.state.receipts.get(`edit:${operationId}`),audit=f.state.audits[0];
    assert.equal(record.launch_id,birth.launchId);assert.equal(record.original_platform_session_id,birth.platformSessionId);
    assert.equal(audit.scope.launchId,execution.launchId);assert.equal(audit.scope.platformSessionId,execution.platformSessionId);
    assert.equal(record.grant_id,current.scene.grantId);
    const original=audit.paramsJson,params=JSON.parse(original);
    assert.equal(params.confirmedDescription.text,description);
    assert.equal(params.confirmedDescription.sha256,assistantEdit.listingEditDigest(description));
    f.state.row.description='later catalog text';
    assert.equal(audit.paramsJson,original);
  }
});

test('manual edit receipt insertion failure rolls back description, audit and overlay together',async()=>{
  const f=fixture(),before=structuredClone(f.state.row);
  const preview=await f.repository.previewManualListingEdit(binding,12,{productId:11,listing:item,personaSession});
  f.state.failReceipt=true;
  await assert.rejects(f.repository.confirmManualListingEdit(binding,12,{operationId,preview,personaSession}),/receipt insert failure/);
  assert.equal(f.state.writes,0);assert.equal(f.state.audits.length,0);assert.equal(f.state.receipts.size,0);
  assert.deepEqual({...f.state.row,source_product_sha256:undefined},{...before,source_product_sha256:undefined});
  f.state.failReceipt=false;
  await f.repository.confirmManualListingEdit(binding,12,{operationId,preview,personaSession});
  assert.equal(f.state.writes,1);assert.equal(f.state.audits.length,1);assert.equal(f.state.receipts.size,1);
});

test('manual edit rejects changed revision, complete snapshot and recomputed invalidation before effects', async () => {
  for (const change of ['revision', 'images', 'invalidation']) {
    const f = fixture({ generated: true });
    let preview = await f.repository.previewManualListingEdit(binding, 12, { productId: 11, listing: item, personaSession });
    if (change === 'revision') f.state.revision++;
    if (change === 'images') f.state.row.images = ['/different.png'];
    if (change === 'invalidation') { const { requestSha256, ...raw } = preview;
      preview = C.makeManualListingPreview({ ...raw, invalidatesGeneratedHtml: false,
        after: C.manualListingAfter(raw.before, raw.listing, false) }); }
    await assert.rejects(f.repository.confirmManualListingEdit(binding, 12, { operationId, preview, personaSession }), { code: 'LISTING_EDIT_STALE' });
    assert.equal(f.state.writes, 0); assert.equal(f.state.receipts.size, 0);
  }
});

test('manual receipts retain unknown outcomes, reject foreign authority and rollback audit failure', async () => {
  const f = fixture();
  const unknown = await f.repository.readManualListingCreate(binding, 12, { operationId, personaSession });
  assert.deepEqual(unknown, { origin: 'manual', kind: 'create', operationId, status: 'not_found',
    scopeKey: C.manualListingScopeKey('create', binding, 12, personaSession) });
  const preview = await f.repository.previewManualListingCreate(binding, 12, { listing: item, personaSession });
  await assert.rejects(f.repository.confirmManualListingCreate(binding, 13, { operationId, preview, personaSession }), { code: 'SHOP_AUTH_INVALID' });
  await assert.rejects(f.repository.confirmManualListingCreate(binding, 12, { operationId, preview,
    personaSession: { ...personaSession, authorityVersion: '3' } }), { code: 'SHOP_AUTH_INVALID' });
  f.state.failAudit = true;
  await assert.rejects(f.repository.confirmManualListingCreate(binding, 12, { operationId, preview, personaSession }), /audit failure/);
  assert.equal(f.state.writes, 0); assert.equal(f.state.receipts.size, 0); assert.equal(f.state.products.length, 0);
  f.state.revoked = true;
  await assert.rejects(f.repository.readManualListingCreate(binding, 12, { operationId, personaSession }), { code: 'SHOP_AUTH_INVALID' });
});

test('manual catalog readiness has no model dependency; all confirms use captured effect and uncertainty fencing', async () => {
  const f = fixture(); let leased = false, captures = 0, revokeAfterCommit = false;
  const repository = { ...f.repository, confirmManualListingCreate: async (...args) => {
    assert.equal(leased, true); assert.deepEqual(args[3], { effectTimeoutMs: 3000 });
    const result = await f.repository.confirmManualListingCreate(...args);
    if (revokeAfterCommit) f.state.revoked = true;
    return result;
  } };
  const catalog = createSecureShopBoundCatalog({ sourcePool: { query: async () => { throw Error('no source/model IO'); } },
    repository, resolveTarget: async () => ({ kind: 'products', ...binding }), checkCurrent: async () => {},
    scenes: { resolve: async () => binding, finalize: async () => { throw Error('readiness must not provision'); } }, personaAuthority: { capture: async input => {
      captures++; return { binding: { ...input.scope, personaId: input.personaId, role: input.role,
        sessionId: input.sessionId, authorityVersion: input.authorityVersion }, assertRemoteAdmission: f.check,
      withCrossStoreEffect: async work => { await f.check(); leased = true; try { return await work(); } finally { leased = false; } } };
    } } });
  const input = { scope: birth, persona: { id: 12, role: 'merchant' }, personaSession };
  const readiness = await catalog.manualListingReadiness(input);
  assert.equal(readiness.ready, true); assert.equal(readiness.scopeKey, C.manualListingStorageScope(readiness.createScopeKey, readiness.editScopeKey));
  const preview = await catalog.previewManualMerchantListingCreate({ ...input, listing: item });
  assert.equal(preview.scopeKey, readiness.createScopeKey); assert.equal(f.state.writes, 0);
  revokeAfterCommit = true;
  await assert.rejects(catalog.confirmManualMerchantListingCreate({ ...input, operationId, preview }), { code: 'PERSONA_EFFECT_OUTCOME_UNCERTAIN' });
  assert.equal(f.state.writes, 1); assert.equal(captures, 3);
});

test('manual gateway has closed routes, bodies and role admission without a socket or AI router', async () => {
  const express = require('express'), { EventEmitter } = require('node:events');
  const { createSecureShopBoundGateway } = require('../server/routes/secureshop/boundGateway');
  const calls = [], methods = names => Object.fromEntries(names.map(name => [name, async () => ({})]));
  const catalog = methods(['listProducts', 'getProduct', 'listMerchantProducts', 'createMerchantProduct', 'updateMerchantProduct', 'archiveMerchantProduct', 'categories']);
  for (const kind of ['Create', 'Edit']) for (const action of ['preview', 'confirm', 'read'])
    catalog[`${action}ManualMerchantListing${kind}`] = async input => { calls.push({ action, kind, input }); return { status: action === 'read' ? 'not_found' : 'controlled' }; };
  catalog.manualListingReadiness = async input => { calls.push({ action: 'ready', input }); return { ready: true }; };
  const router = createSecureShopBoundGateway({ launches: { resolveCapability: async () => birth },
    authenticatePersona(req, res, next) { req.ssUser = req.actor; req.ssPersonaSession = personaSession; return next(); },
    personaAuth: methods(['login', 'renew', 'logout', 'listSessions', 'revokeOwnedSession', 'changePassword', 'listApiKey', 'rotateApiKey', 'authenticateApiKey']),
    reviewsRouter: express.Router(), browserRouter: express.Router(), catalog,
    commerce: methods(['cart', 'add', 'update', 'remove', 'summary', 'checkout', 'orders', 'order']),
    account: methods(['profile', 'updateProfile', 'addresses', 'createAddress', 'updateAddress', 'deleteAddress']) });
  async function invoke(method, path, body, { role = 'merchant', query = {}, params = { operationId } } = {}) {
    const handlers = router.stack.find(layer => layer.route?.path === path && layer.route.methods[method]).route.stack.map(layer => layer.handle);
    const req = Object.assign(new EventEmitter(), { method: method.toUpperCase(), params, query, body, ssLaunch: birth,
      actor: { id: 12, role }, rawHeaders: [], aborted: false, destroyed: false, get: () => null, is: type => type === 'application/json' });
    const res = Object.assign(new EventEmitter(), { statusCode: 200, headersSent: false, writableEnded: false,
      status(code) { this.statusCode = code; return this; }, json(value) { this.payload = value; this.headersSent = true; this.writableEnded = true; return this; }, set() { return this; } });
    async function at(i) { if (!handlers[i]) return; let downstream;
      await handlers[i](req, res, error => { downstream = error ? Promise.reject(error) : at(i + 1); return downstream; }); if (downstream) await downstream; }
    await at(0); return res;
  }
  const base = '/merchant/listings/manual';
  assert.equal((await invoke('get', `${base}/readiness`)).statusCode, 200);
  for (const kind of ['create', 'edit']) {
    const request = kind === 'create' ? { listing: item } : { productId: 11, listing: item };
    assert.equal((await invoke('post', `${base}/${kind}/preview`, request)).statusCode, 200);
    assert.deepEqual(calls.at(-1).input.personaSession, personaSession);
    assert.equal((await invoke('post', `${base}/${kind}/preview`, { ...request, chatSource: {} })).statusCode, 400);
    assert.equal((await invoke('get', `${base}/${kind}/operations/:operationId`)).payload.status, 'not_found');
    assert.equal((await invoke('get', `${base}/${kind}/operations/:operationId`, undefined, { query: { origin: 'assistant' } })).statusCode, 400);
    assert.equal((await invoke('get', `${base}/${kind}/operations/:operationId`, undefined, { role: 'customer' })).statusCode, 403);
  }
  const preview = await fixture().repository.previewManualListingCreate(binding, 12, { listing: item, personaSession });
  assert.equal((await invoke('post', `${base}/create/confirm`, { operationId, preview })).statusCode, 200);
  const count = calls.length;
  for (const body of [{ operationId, preview, source: {} }, { operationId, preview: { ...preview, origin: 'assistant' } },
    { operationId: 'invalid', preview }, { operationId, preview: { ...preview, padding: 'x'.repeat(128 * 1024) } }])
    assert.equal((await invoke('post', `${base}/create/confirm`, body)).statusCode, 400);
  assert.equal(calls.length, count);
});
