'use strict';
const assert = require('node:assert/strict');
const test = require.main === module ? require('node:test') : () => {};
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const CHAT = '/agents/merchant/assistant/chat';
const checkedId = value => assert.ok(typeof value === 'string' && UUID.test(value));

// This checks an evidence packet collected by the existing rendered catalog cohort.
// A controlled packet below defines the contract; it is not actual-model/browser proof.
function assertInactiveMerchantCatalogQualification(packet) {
  const { source, discovery, detail, renderedButtons, customerProductIds, replay,
    sibling, before, after } = packet;
  assert.ok(Number.isSafeInteger(source.productId) && source.productId > 0);
  assert.ok(Number.isSafeInteger(source.retailerId) && source.retailerId > 0);
  assert.equal(source.sourceRetailerId, source.retailerId);
  checkedId(source.targetId);
  assert.equal(source.status, 'inactive');
  assert.ok(typeof source.name === 'string' && source.name.length > 0);
  assert.ok(typeof source.search === 'string' && source.search.length > 0);
  assert.ok(Array.isArray(before.productRows));
  const ownedRows = before.productRows.filter(row => Number(row.product_id) === source.productId);
  assert.equal(ownedRows.length, 1, 'the original target-scoped SQL snapshot contains one source product');
  assert.equal(Number(ownedRows[0].retailer_id), source.retailerId);
  assert.equal(ownedRows[0].status, 'inactive');
  assert.equal(ownedRows[0].name, source.name);

  assert.equal(discovery.physical.method, 'POST');
  assert.equal(discovery.physical.path, CHAT);
  checkedId(discovery.physical.body.sessionId);
  checkedId(discovery.physical.body.requestId);
  assert.equal(discovery.physical.body.message,
    `Find my inactive products matching the literal search "${source.search}".`);
  assert.equal(Object.hasOwn(discovery.physical.body, 'selection'), false);
  assert.deepEqual(discovery.modelSelection,
    { tool: 'merchant.catalog_search', args: { search: source.search, status: 'inactive' } });
  assert.equal(discovery.hop.tool, 'merchant.catalog_search');
  assert.deepEqual(discovery.hop.params, discovery.modelSelection.args);
  assert.equal(discovery.saved.status, 'completed');
  assert.equal(discovery.saved.requestId, discovery.physical.body.requestId);
  assert.deepEqual(discovery.saved.catalogPage,
    { version: 1, total: 1, pageSize: 5, returnedCount: 1, hasMore: false });
  assert.equal(discovery.saved.cards.length, 1);
  const card = discovery.saved.cards[0];
  checkedId(card.choiceId);
  assert.deepEqual(card, { version: 1, kind: 'merchant_product', choiceId: card.choiceId,
    title: source.name, detail: card.detail, readOnly: true });
  assert.equal(discovery.observed.total, 1);
  assert.equal(discovery.observed.products.length, 1);
  const found = discovery.observed.products[0];
  assert.equal(Number(found.id), source.productId);
  assert.equal(found.status, 'inactive');
  assert.equal(found.name, source.name);
  assert.deepEqual(renderedButtons, [`View details for ${source.name}`],
    'inactive card exposes details only, without rewrite/use/pricing/manual/reviews');

  assert.equal(detail.physical.method, 'POST');
  assert.equal(detail.physical.path, CHAT);
  checkedId(detail.physical.body.requestId);
  assert.equal(detail.physical.body.sessionId, discovery.physical.body.sessionId);
  assert.notEqual(detail.physical.body.requestId, discovery.physical.body.requestId);
  assert.deepEqual(detail.physical.body.selection,
    { choiceId: card.choiceId, intent: 'product_details' });
  assert.deepEqual(detail.modelSelection,
    { tool: 'merchant.catalog_search', args: { choiceId: card.choiceId } });
  assert.equal(detail.hop.tool, 'merchant.catalog_search');
  assert.deepEqual(detail.hop.params, detail.modelSelection.args);
  assert.equal(detail.saved.status, 'completed');
  assert.equal(detail.saved.requestId, detail.physical.body.requestId);
  assert.equal(detail.observed.products.length, 1);
  assert.equal(Number(detail.observed.products[0].id), source.productId);
  assert.equal(detail.observed.products[0].status, 'inactive');
  assert.equal(detail.observed.products[0].name, source.name);
  assert.equal(customerProductIds.includes(source.productId), false,
    'inactive merchant product stays out of the active customer catalog');

  assert.deepEqual(replay.savedAfter, replay.savedBefore,
    'same-ID protected GET and replay retain the exact saved result');
  assert.equal(replay.actorCallsDelta, 0);
  assert.equal(replay.effectsDelta, 0);
  assert.equal(sibling.discoveryStatus, 401);
  assert.deepEqual(sibling.discoveryBody, { error: 'Shop session unavailable' });
  assert.equal(sibling.detailStatus, 401);
  assert.deepEqual(sibling.detailBody, { error: 'Shop session unavailable' });
  assert.deepEqual(after.productRows, before.productRows);
  assert.equal(after.commerceEffects, before.commerceEffects);
  assert.equal(after.judgeCalls, before.judgeCalls);
  assert.equal(after.judgments, before.judgments);
}

const sessionId = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const discoveryId = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const detailId = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc';
const choiceId = 'dddddddd-dddd-4ddd-8ddd-dddddddddddd';
function packet() {
  const source = { targetId: 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee', productId: 71,
    retailerId: 6, sourceRetailerId: 6, status: 'inactive', name: 'Owned dormant lamp', search: 'Dormant lamp only' };
  const card = { version: 1, kind: 'merchant_product', choiceId, title: source.name,
    detail: 'USD 5 · 3 in stock', readOnly: true };
  const found = { id: source.productId, status: 'inactive', name: source.name };
  const savedBefore = { requestId: discoveryId, cards: [card] };
  const productRows = [{ product_id: source.productId, retailer_id: source.retailerId,
    status: 'inactive', name: source.name }];
  return { source,
    discovery: { physical: { method: 'POST', path: CHAT, body: { sessionId,
      requestId: discoveryId,
      message: `Find my inactive products matching the literal search "${source.search}".` } },
    modelSelection: { tool: 'merchant.catalog_search', args: { search: source.search, status: 'inactive' } },
    hop: { tool: 'merchant.catalog_search', params: { search: source.search, status: 'inactive' } },
    saved: { status: 'completed', requestId: discoveryId,
      catalogPage: { version: 1, total: 1, pageSize: 5, returnedCount: 1, hasMore: false }, cards: [card] },
    observed: { total: 1, products: [found] } },
    detail: { physical: { method: 'POST', path: CHAT, body: { sessionId,
      requestId: detailId, message: 'Show my selected product details.',
      selection: { choiceId, intent: 'product_details' } } },
    modelSelection: { tool: 'merchant.catalog_search', args: { choiceId } },
    hop: { tool: 'merchant.catalog_search', params: { choiceId } },
    saved: { status: 'completed', requestId: detailId }, observed: { products: [found] } },
    renderedButtons: [`View details for ${source.name}`], customerProductIds: [1, 2],
    replay: { savedBefore, savedAfter: structuredClone(savedBefore), actorCallsDelta: 0, effectsDelta: 0 },
    sibling: { discoveryStatus: 401, discoveryBody: { error: 'Shop session unavailable' },
      detailStatus: 401, detailBody: { error: 'Shop session unavailable' } },
    before: { productRows, commerceEffects: 0, judgeCalls: 0, judgments: 0 },
    after: { productRows: structuredClone(productRows), commerceEffects: 0, judgeCalls: 0, judgments: 0 } };
}

test('bounded two-turn inactive discovery/detail evidence contract', () => {
  assert.doesNotThrow(() => assertInactiveMerchantCatalogQualification(packet()));
});

test('qualification rejects active/foreign/source-unspecified or model-rewritten discovery', () => {
  for (const change of [
    value => { value.source.status = 'active'; },
    value => { value.source.sourceRetailerId = 99; },
    value => { value.before.productRows[0].retailer_id = 99; },
    value => { value.discovery.observed.products[0].id = 99; },
    value => { value.discovery.observed.products[0].name = 'Another product'; },
    value => { value.discovery.modelSelection.args.status = 'all'; },
    value => { value.discovery.hop.params.status = 'active'; },
    value => { value.discovery.physical.body.message = 'Find products'; },
    value => { value.discovery.saved.cards[0].readOnly = false; },
    value => { value.discovery.saved.catalogPage.hasMore = true; },
  ]) { const value = packet(); change(value);
    assert.throws(() => assertInactiveMerchantCatalogQualification(value)); }
});

test('qualification rejects fabricated detail, extra controls, customer leak or non-isolated replay', () => {
  for (const change of [
    value => { value.detail.physical.body.selection.choiceId = sessionId; },
    value => { value.detail.modelSelection.args.choiceId = sessionId; },
    value => { value.detail.observed.products[0].status = 'active'; },
    value => { value.detail.observed.products[0].name = 'Another product'; },
    value => { value.renderedButtons.push('Rewrite listing'); },
    value => { value.customerProductIds.push(value.source.productId); },
    value => { value.replay.actorCallsDelta = 1; },
    value => { value.replay.savedAfter.cards[0].title = 'Other'; },
    value => { value.sibling.detailStatus = 200; },
    value => { value.sibling.discoveryStatus = 403; },
    value => { value.sibling.discoveryBody.error = 'Role assistant unavailable'; },
    value => { value.sibling.detailBody.extra = true; },
    value => { value.after.commerceEffects = 1; },
    value => { value.after.judgeCalls = 1; },
  ]) { const value = packet(); change(value);
    assert.throws(() => assertInactiveMerchantCatalogQualification(value)); }
});

test('inactive source is seeded for the authenticated merchant before target capture', async () => {
  const fixture = fs.readFileSync(path.join(__dirname,
    'secureshopStandaloneRoleChoicesRendered.integration.test.js'), 'utf8');
  const start = fixture.indexOf('async function seedInactiveCatalogSource(');
  const end = fixture.indexOf('\nasync function seedCatalogPageProducts(', start);
  assert.ok(start >= 0 && end > start);
  const seed = vm.runInNewContext(`${fixture.slice(start, end)}; seedInactiveCatalogSource`,
    { assert });
  const actorId = 1000000003;
  const calls = [];
  const migration = { async query(sql, params = []) {
    calls.push({ sql, params });
    if (sql.includes('SELECT DISTINCT p.retailer_id')) return { rows: [
      { retailer_id: 2 }, { retailer_id: 3 }] };
    if (sql.includes('SELECT id,role')) return { rows: [] };
    if (sql.includes('INSERT INTO secureshop.shop_users')) return { rows: [
      { id: actorId, role: 'merchant' }] };
    if (sql.includes('INSERT INTO secureshop.products')) return { rows: [{ id: 71 }] };
    assert.fail(`unexpected source query: ${sql}`);
  } };
  const source = await seed(migration, 'owned', actorId);
  assert.equal(source.sourceRetailerId, actorId);
  assert.equal(source.productId, 71);
  assert.deepEqual(calls.map(call => call.sql.includes('INSERT INTO secureshop.shop_users')
    ? 'source-user' : call.sql.includes('INSERT INTO secureshop.products')
      ? 'source-product' : 'check'), ['check', 'check', 'source-user', 'source-product']);
  assert.equal(calls[1].params[0], actorId);
  assert.equal(calls[2].params[0], actorId);
  assert.equal(calls[3].params[3], actorId);
  const conflict = { query: async sql => sql.includes('SELECT DISTINCT p.retailer_id')
    ? { rows: [{ retailer_id: 2 }, { retailer_id: 3 }] }
    : { rows: [{ id: actorId, role: 'customer' }] } };
  await assert.rejects(seed(conflict, 'owned', actorId),
    /authenticated merchant ID must not collide/);
  const actor = fixture.indexOf('const firstActor = await composition.personaAuth.authenticateBoundToken(');
  const admission = fixture.indexOf('await seedInactiveCatalogSource(pools.COMMERCE_MIGRATION, suffix, firstActor.user.id)');
  const capture = fixture.indexOf('composition.catalog.prepareTarget({ scope: firstScope, persona: merchantPersona })');
  assert.ok(actor >= 0 && actor < admission && admission < capture,
    'exact authenticated source owner must be inserted before target capture');
});

test('qualification source carries the verified target-row status', () => {
  const fixture = fs.readFileSync(path.join(__dirname,
    'secureshopStandaloneRoleChoicesRendered.integration.test.js'), 'utf8');
  const start = fixture.indexOf('async function seedCatalogPageProducts(');
  const end = fixture.indexOf('\nasync function seedMerchantMail(', start);
  assert.ok(start >= 0 && end > start);
  const seed = fixture.slice(start, end);
  assert.match(seed, /SELECT product_id,name,retailer_id,source_retailer_id,status/);
  assert.match(seed, /assert\.equal\(inactive\[0\]\.status, 'inactive'\)/);
  assert.match(seed, /inactive: Object\.freeze\(\{ \.\.\.inactiveSource, status: inactive\[0\]\.status,/);
});

module.exports = { assertInactiveMerchantCatalogQualification };
