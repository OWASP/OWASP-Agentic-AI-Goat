'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const C = require('../server/services/secureshopListingCreateContract');
const { createFeatureModeAuthority } = require('../server/services/secureshopFeatureModeAuthority');
const { createSceneBinding } = require('../server/services/secureshopSceneBinding');
const { createSecureShopBoundProductRepository } = require('../server/database/postgres/secureshopBoundProductRepository');
const { createSecureShopBoundCatalog } = require('../server/services/secureshopBoundCatalog');
const id = n => `10000000-0000-4000-8000-${String(n).padStart(12, '0')}`;
const scope = { launchId: id(1), scenarioId: id(2), generation: 1, platformOwnerId: 4, platformSessionId: 5 };
const session = { sessionId: id(7), authorityVersion: '2' };
const operationId = id(8);
const html = '<img src=x onerror="alert(1)">\r\n\t café & \'quoted\'';
const listing = { name: 'Raw lamp', description: html, price: 12.25, presentation: 'html' };
const preparation = { sessionId: id(10), requestId: id(11), step: 1, callId: 'prepare_one',
  message: `Create Raw lamp for 12.25 with HTML description:\n${html}` };
const hash = value => createHash('sha256').update(JSON.stringify(value)).digest('hex');

function fixture(initialMode = 'vuln') {
  const f = { mode: initialMode, epoch: 1, current: true, sceneActive: true, products: [],
    merchants: [], audits: [], receipts: new Map(), failAt: null, afterInsert: null, captures: 0 };
  const check = async () => { if (!f.current) throw Object.assign(Error('revoked'), { code: 'SHOP_AUTH_INVALID' }); };
  const binding = createSceneBinding({ ...scope, targetId: id(3) }, { sceneId: id(4), sceneGeneration: 1,
    grantId: id(6), execution: scope, withLease: async work => { await check(); return work(); } });
  const modeAuthority = createFeatureModeAuthority({ launches: { assertCurrent: check },
    progress: { async getEvaluationScope() { f.captures++; return { mode: f.mode, generation: f.epoch, modeStamp: `epoch-${f.epoch}` }; },
      async getEvaluationScopeAtEffect() { return { mode: f.mode, generation: f.epoch, modeStamp: `epoch-${f.epoch}` }; } } });
  let transaction;
  const client = { release() {}, async query(sql, args = []) {
    if (sql === 'BEGIN') { transaction = { products: [...f.products], merchants: [...f.merchants], audits: [...f.audits], receipts: new Map(f.receipts) }; return { rows: [] }; }
    if (sql === 'SET TRANSACTION ISOLATION LEVEL REPEATABLE READ') { f.repeatable = true; return { rows: [] }; }
    if (sql.startsWith('WITH effective AS')) return { rows: f.products.filter(p => p.productId === args[1] && !p.archived) };
    if (sql === 'COMMIT') return { rows: [] };
    if (sql === 'ROLLBACK') { Object.assign(f, transaction); return { rows: [] }; }
    if (sql.includes('assert_scene_execution_grant')) return { rows: [{ allowed: f.sceneActive }] };
    if (sql.includes('FROM secureshop_review.product_targets')) return { rows: [{
      target_id: id(3), launch_id: scope.launchId, scenario_id: scope.scenarioId, generation: 1,
      original_platform_owner_id: 4, original_platform_session_id: 5, own_merchant_id: 12,
      lifecycle: 'active', source_sha256: Buffer.alloc(32, 5), source_count: 1 }] };
    if (sql.includes('SELECT COALESCE(max(product_id),0)+1')) return { rows: [{ product_id: f.products.length + 1 }] };
    if (sql.includes('INSERT INTO secureshop_review.product_target_products')) {
      f.products.push({ productId: args[1], name: args[4], description: args[5], description_html: args[11] ?? null,
        source_product_sha256: args[3], sql });
      f.afterInsert?.(); return { rows: [] };
    }
    if (sql.includes('INSERT INTO secureshop_review.product_target_merchant_listings')) { f.merchants.push(args); return { rows: [] }; }
    if (sql.includes('INSERT INTO secureshop_review.owned_merchant_listing_create_receipts')) {
      if (f.failAt === 'receipt') throw Error('receipt write failed');
      const keys = ['operation_id', 'target_id', 'launch_id', 'scenario_id', 'generation', 'original_platform_owner_id',
        'original_platform_session_id', 'scene_id', 'scene_generation', 'grant_id', 'merchant_id', 'persona_session_id',
        'authority_version', 'product_id', 'scope_key', 'request_sha256', 'source_sha256', 'receipt_sha256'];
      const row = Object.fromEntries(keys.map((key, i) => [key, args[i]]));
      row.receipt_version = args.length === 19 ? 2 : 1;
      row.source_document = args.length === 19 ? JSON.parse(args[18]) : null;
      f.receipts.set(row.operation_id, row); return { rows: [row] };
    }
    if (sql.includes('FROM secureshop_review.owned_merchant_listing_create_receipts')) {
      assert.doesNotMatch(sql, /FOR (?:UPDATE|SHARE)/);
      const row = f.receipts.get(args[0]);
      return { rows: !row || args.length > 1 && (row.target_id !== args[1] || row.merchant_id !== args[2]
        || row.persona_session_id !== args[3] || !row.scope_key.equals(args[4])) ? [] : [row] };
    }
    throw Error(`Unexpected query ${sql}`);
  } };
  const repository = createSecureShopBoundProductRepository({ connect: async () => client, query: async () => { throw Error('transaction required'); } },
    { checkCurrent: check, checkCleanup: check, modeAuthority, auditStore: { async append(_c, row) {
      if (f.failAt === 'audit') throw Error('audit write failed'); f.audits.push(row);
    } } });
  const key = C.listingCreateScopeKey(binding, 12, session);
  Object.assign(f, { binding, repository, modeAuthority, key,
    token: () => modeAuthority.capture(scope, 'listings'),
    async preview() { const modeToken = await f.token(); return repository.previewListingCreate(binding, 12, listing, key, { preparation, modeToken }); },
    async confirm(preview, extra = {}) { return repository.confirmListingCreate(binding, 12,
      { operationId, preview, personaSession: session, modeToken: await f.token(), ...extra }); },
    read: () => repository.readListingCreate(binding, 12, { operationId, personaSession: session }) });
  const facade = { ...repository, open: async () => ({ ownMerchantId: 12 }) };
  f.catalog = createSecureShopBoundCatalog({ sourcePool: { query: async () => { throw Error('No source copy'); } },
    repository: facade, resolveTarget: async () => binding, checkCurrent: check, modeAuthority });
  f.input = { scope, persona: { id: 12, role: 'merchant' }, personaSession: session, listing, preparation };
  return f;
}

test('v1 omitted presentation retains exact normalized bytes and canonical hash', () => {
  const value = C.normalizeListingCreateInput({ name: 'Lamp', price: 12.25 });
  assert.deepEqual(value, { name: 'Lamp', description: null, category: null, price: 12.25 });
  const scopeKey = 'a'.repeat(64);
  assert.equal(C.listingCreateRequestDigest({ listing: value, currency: 'USD', initialStock: 0, status: 'active', scopeKey }),
    hash({ version: 1, listing: value, currency: 'USD', initialStock: 0, status: 'active', templateSource: null, images: [], scopeKey }));
});
for (const mode of ['vuln', 'fixed']) test(`raw ${mode} stores full exact source, preparation and execution atomically`, async () => {
  const f = fixture(mode), preview = await f.preview();
  assert.equal(preview.version, 2); assert.equal(f.products.length, 0);
  assert.equal(preview.source.authoredHtml, html); assert.deepEqual(preview.source.preparation, preparation);
  const outcome = await f.confirm(preview);
  assert.equal(outcome.version, 2); assert.equal(outcome.replayed, false);
  assert.deepEqual(C.validateListingCreateReceipt(outcome, operationId), outcome);
  assert.equal(outcome.source.storedHtml, mode === 'vuln' ? html : C.escapeListingHtml(html));
  assert.equal(f.products[0].description_html, outcome.source.storedHtml);
  assert.equal(f.products[0].description, html);
  assert.deepEqual(f.receipts.get(operationId).source_document, outcome.source);
  assert.equal(f.merchants.length, 1); assert.equal(f.audits.length, 1);
  assert.deepEqual(await f.read(), { ...outcome, replayed: true });
});
test('raw source rejects altered bytes, source type, request metadata and unqualified epochs', async () => {
  const source = (await fixture().preview()).source;
  for (const mutate of [s => { s.authoredHtml += ' '; }, s => { s.storedHtml += ' '; },
    s => { s.preparation.message = 'Create a lamp without supplied HTML'; }, s => { s.preparation.step = 0; },
    s => { s.execution.generation = null; }, s => { s.execution.modeStamp = null; },
    s => { s.execution.featureId = 'merchant_assistant'; }, s => { s.kind = 'generated_html'; },
    s => { s.extra = true; }, s => { s.listing.presentation = 'plain'; }]) {
    const changed = structuredClone(source); mutate(changed);
    assert.throws(() => C.validateListingCreateSource(changed));
  }
  assert.throws(() => C.normalizeListingCreateInput({ ...listing, description: '' }));
  assert.throws(() => C.normalizeListingCreateInput({ ...listing, description: 'a'.repeat(8193) }));
  assert.throws(() => C.normalizeListingCreateInput({ ...listing, mode: 'vuln' }));
});
test('only branded current listings tokens admit source; copied JSON and wrong epoch do not', async () => {
  const f = fixture(), token = await f.token();
  await assert.rejects(f.repository.previewListingCreate(f.binding, 12, listing, f.key,
    { preparation, modeToken: { ...token } }));
  const preview = await f.preview();
  for (const next of [{ mode: 'fixed', epoch: 2 }, { mode: 'vuln', epoch: 3 }]) {
    Object.assign(f, next); await assert.rejects(f.confirm(preview), { code: 'LISTING_CREATE_MODE_INVALID' });
    assert.equal(f.products.length, 0); assert.equal(f.receipts.size, 0);
  }
});
test('mode changes while queued or before commit roll back the whole owned publication', async () => {
  const f = fixture(), preview = await f.preview(), token = await f.token();
  f.epoch++;
  await assert.rejects(f.repository.confirmListingCreate(f.binding, 12,
    { operationId, preview, personaSession: session, modeToken: token }), { code: 'ANALYTICS_MODE_STALE' });
  assert.equal(f.products.length, 0);
  const g = fixture(), second = await g.preview();
  g.afterInsert = () => { g.epoch++; };
  await assert.rejects(g.confirm(second), { code: 'ANALYTICS_MODE_STALE' });
  assert.equal(g.products.length, 0); assert.equal(g.merchants.length, 0);
  assert.equal(g.audits.length, 0); assert.equal(g.receipts.size, 0);
});
for (const failure of ['audit', 'receipt']) test(`${failure} failure leaves no product, ownership, audit or receipt`, async () => {
  const f = fixture(), preview = await f.preview(); f.failAt = failure;
  await assert.rejects(f.confirm(preview), /write failed/);
  assert.equal(f.products.length, 0); assert.equal(f.merchants.length, 0);
  assert.equal(f.audits.length, 0); assert.equal(f.receipts.size, 0);
});
test('historical v2 GET and exact same-ID replay preserve source after a mode toggle and product change', async () => {
  const f = fixture(), preview = await f.catalog.previewMerchantListingCreate(f.input);
  const outcome = await f.catalog.confirmMerchantListingCreate({ ...f.input, operationId, preview });
  f.mode = 'fixed'; f.epoch++;
  f.products[0].description_html = 'later edited product';
  const captures = f.captures;
  assert.deepEqual(await f.catalog.confirmMerchantListingCreate({ ...f.input, operationId, preview }), { ...outcome, replayed: true });
  assert.equal(f.captures, captures, 'completed read must not capture a new mode for effect');
  assert.deepEqual(await f.read(), { ...outcome, replayed: true });
  assert.equal(f.products.length, 1); assert.equal(f.audits.length, 1);
  const changed = await f.preview();
  await assert.rejects(f.confirm(changed), { code: 'LISTING_CREATE_RECEIPT_INVALID' });
});
test('current authority and scene lease still fence historical readback', async () => {
  const f = fixture(), preview = await f.preview(); await f.confirm(preview);
  const foreign = { ...session, sessionId: id(70) };
  assert.equal((await f.repository.readListingCreate(f.binding, 12,
    { operationId, personaSession: foreign })).status, 'not_found');
  await assert.rejects(f.repository.readListingCreate(f.binding, 13,
    { operationId, personaSession: session }), { code: 'OWNER_MISMATCH' });
  f.sceneActive = false; await assert.rejects(f.read(), { code: 'SHOP_SCENE_STALE' });
  f.sceneActive = true; f.current = false; await assert.rejects(f.read(), { code: 'SHOP_AUTH_INVALID' });
});
test('JSONB key ordering is irrelevant but immutable byte or receipt substitution fails', async () => {
  const f = fixture(), preview = await f.preview(), outcome = await f.confirm(preview);
  const row = f.receipts.get(operationId);
  row.source_document = Object.fromEntries(Object.entries(row.source_document).reverse());
  assert.deepEqual(await f.read(), { ...outcome, replayed: true });
  row.source_document.authoredHtml += ' ';
  await assert.rejects(f.read());
  row.source_document = structuredClone(outcome.source);
  row.source_sha256 = Buffer.alloc(32, 1);
  await assert.rejects(f.read(), { code: 'LISTING_CREATE_RECEIPT_INVALID' });
});

test('private source read binds current effective HTML and receipt atomically, without changing historical GET', async () => {
  const f = fixture(), preview = await f.preview();
  const receipt = await f.confirm(preview);
  const input = { ...f.input, operationId };
  const source = await f.catalog.readMerchantListingCreateSource(input);
  assert.equal(f.repeatable, true);
  assert.deepEqual(source, { receipt: { ...receipt, replayed: true }, product: {
    productId: receipt.productId, descriptionHtml: html, sourceSha256: receipt.sourceSha256 } });
  for (const change of [p => { p.description_html += ' '; }, p => { p.source_product_sha256 = Buffer.alloc(32); },
    p => { p.archived = true; }]) {
    const original = { ...f.products[0] }; change(f.products[0]);
    await assert.rejects(f.catalog.readMerchantListingCreateSource(input), { code: 'LISTING_CREATE_SOURCE_UNAVAILABLE' });
    assert.deepEqual(await f.read(), { ...receipt, replayed: true });
    f.products[0] = original;
  }
  await assert.rejects(f.catalog.readMerchantListingCreateSource({ ...input,
    personaSession: { ...session, sessionId: id(99) } }), { code: 'LISTING_CREATE_SOURCE_UNAVAILABLE' });
  f.current = false;
  await assert.rejects(f.catalog.readMerchantListingCreateSource(input), { code: 'SHOP_AUTH_INVALID' });
});
