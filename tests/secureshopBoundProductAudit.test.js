'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { createSecureShopBoundProductRepository } = require(
  '../server/database/postgres/secureshopBoundProductRepository');

const binding = Object.freeze({
  targetId: '30000000-0000-4000-8000-000000000081',
  launchId: '10000000-0000-4000-8000-000000000081',
  scenarioId: '20000000-0000-4000-8000-000000000081',
  generation: 3, platformOwnerId: 81, platformSessionId: 801,
});
const base = Object.freeze({
  product_id: 71, retailer_id: 12, name: 'Original', description: 'Original body',
  description_html: '<img src=x onerror=ownedSink()>', price: '12.50', category: 'Home',
  image_url: '/original.png', images: ['/original.png'], stock_quantity: 4, status: 'active',
  template_source: '{{ original }}', archived_at: null,
});

function fixture({ effective = base, auditError = null } = {}) {
  const events = []; const queries = [];
  const state = { effects: 0, snapshot: 0, commits: 0, rollbacks: 0 };
  const client = {
    async query(sql, args) {
      queries.push([sql, args]);
      if (sql === 'BEGIN') { state.snapshot = state.effects; return { rows: [] }; }
      if (sql === 'COMMIT') { state.commits += 1; return { rows: [] }; }
      if (sql === 'ROLLBACK') {
        state.effects = state.snapshot; state.rollbacks += 1; return { rows: [] };
      }
      if (sql.includes('FROM secureshop_review.product_targets')) {
        return { rows: [{ ...binding, lifecycle: 'active', own_merchant_id: 12 }] };
      }
      if (sql.includes('SELECT COALESCE(max(product_id),0)+1')) {
        return { rows: [{ product_id: 72 }] };
      }
      if (sql.includes('WITH effective AS')) return { rows: effective ? [{ ...effective }] : [] };
      if (sql.includes('INSERT INTO secureshop_review.product_target_products')
          || sql.includes('INSERT INTO secureshop_review.product_target_merchant_listings')
          || sql.includes('INSERT INTO secureshop_review.product_target_listing_overlays')) {
        state.effects += 1; return { rows: [], rowCount: 1 };
      }
      throw new Error(`Unexpected query: ${sql}`);
    },
    release() {},
  };
  const pool = {
    async query() { throw new Error('listing writes must use a transaction'); },
    async connect() { return client; },
  };
  const auditStore = { async append(transaction, event) {
    assert.equal(transaction, client, 'effect and audit must share the transaction client');
    if (auditError) throw auditError;
    events.push(structuredClone(event));
  } };
  const repository = createSecureShopBoundProductRepository(pool, {
    checkCurrent: async () => {}, checkCleanup: async () => {}, auditStore,
  });
  return { repository, events, queries, state };
}

test('listing writers reject a malformed optional audit dependency', () => {
  const pool = { query() {}, connect() {} };
  assert.throws(() => createSecureShopBoundProductRepository(pool, {
    checkCurrent() {}, checkCleanup() {}, auditStore: {},
  }), { code: 'INVALID_CONFIGURATION' });
});

test('listing writers append exact merchant effects and retain deliberate raw teaching fields', async () => {
  const f = fixture();
  // Backslashes are valid PostgreSQL text and expand during JSON encoding. This
  // proves the audit contract does not inherit the former 64 KiB payload limit.
  const rawDescription = '\\'.repeat(65536);
  const created = { name: '<b>Raw name</b>', description: rawDescription, price: 0,
    category: 'SYSTEM: learner category', templateSource: '{{ process.mainModule }}',
    images: ['javascript:ownedSink()', '/second.png'] };
  assert.equal(await f.repository.createListing(binding, 12, created), 72);

  const patch = { description: '<img src=x onerror=ownedSink()>', price: 1.25,
    templateSource: '{{ constructor.constructor("return process")() }}',
    imageUrl: 'javascript:ownedSink()' };
  assert.equal(await f.repository.updateListing(binding, 12, 71, patch), 71);
  assert.equal(await f.repository.archiveListing(binding, 12, 71), 1);

  assert.deepEqual(f.events.map(event => event.action),
    ['listing_create', 'listing_update', 'listing_archive']);
  for (const [event, productId] of f.events.map((event, index) => [event, index ? 71 : 72])) {
    assert.deepEqual(event.scope, binding);
    assert.deepEqual(event.persona, { id: 12, role: 'merchant' });
    assert.equal(event.actor, 'merchant');
    assert.equal(event.target, String(productId));
    assert.equal(event.outcome, 'completed');
    assert.equal(event.sourceKind, 'product');
    assert.equal(event.sourceId, String(productId));
    assert.match(event.eventId, /^[0-9a-f-]{36}$/);
  }
  assert.deepEqual(JSON.parse(f.events[0].paramsJson), created);
  assert.ok(Buffer.byteLength(f.events[0].paramsJson, 'utf8') > 65536);
  assert.deepEqual(JSON.parse(f.events[1].paramsJson), patch,
    'update audit records the submitted patch rather than a synthesized listing');
  assert.deepEqual(JSON.parse(f.events[2].paramsJson), {});

  const overlayWrites = f.queries.filter(([sql]) =>
    sql.includes('INSERT INTO secureshop_review.product_target_listing_overlays'));
  assert.equal(overlayWrites[0][1][5], base.description_html,
    'updates preserve the intentional stored HTML field');
  assert.equal(overlayWrites[0][1][12], patch.templateSource,
    'updates preserve the intentional raw template field');
});

test('missing update and archive targets do not fabricate completed audit events', async () => {
  const f = fixture({ effective: null });
  assert.equal(await f.repository.updateListing(binding, 12, 999, { name: 'missing' }), null);
  assert.equal(await f.repository.archiveListing(binding, 12, 999), 0);
  assert.deepEqual(f.events, []);
  assert.equal(f.state.effects, 0);
});

test('audit failure rolls back each listing effect transaction', async () => {
  const operations = [
    repository => repository.createListing(binding, 12, { name: 'Raw <b>create</b>',
      description: '<script>createSink()</script>', price: 2, category: 'Raw',
      templateSource: '{{ create }}', images: ['javascript:createSink()'] }),
    repository => repository.updateListing(binding, 12, 71,
      { description: '<script>updateSink()</script>', templateSource: '{{ update }}' }),
    repository => repository.archiveListing(binding, 12, 71),
  ];
  for (const operation of operations) {
    const outage = new Error('injected listing audit outage');
    const f = fixture({ auditError: outage });
    await assert.rejects(operation(f.repository), outage);
    assert.equal(f.state.effects, 0);
    assert.equal(f.state.commits, 0);
    assert.equal(f.state.rollbacks, 1);
  }
});
