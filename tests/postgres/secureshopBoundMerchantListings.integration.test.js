'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { randomUUID } = require('node:crypto');
const { Pool } = require('pg');
const { migrate } = require('../../db/postgres/migrate');
const { createSecureShopBoundProductRepository } = require(
  '../../server/database/postgres/secureshopBoundProductRepository');
const { createSecureShopBoundCommerceRepository } = require(
  '../../server/database/postgres/secureshopBoundCommerceRepository');

const PREFIX = 'PG_SECURESHOP_BOUND_MERCHANT_LISTINGS_';
const root = path.join(__dirname, '../..');
const migrations = path.join(root, 'db/postgres/workshop-migrations/secureshop_review');
const HISTORICAL_MIGRATIONS = Object.freeze([
  '0001_schema.sql',
  '0002_cleanup_receipts.sql',
  '0003_secureshop_review_learner_submissions.sql',
  '0004_secureshop_bound_product_target.sql',
  '0005_secureshop_bound_commerce.sql',
  '0006_secureshop_bound_account.sql',
  '0007_secureshop_bound_merchant_listings.sql',
]);
const CURRENT_MIGRATIONS = Object.freeze(fs.readdirSync(migrations)
  .filter(name => /^[0-9]{4}_.*\.sql$/.test(name)).sort());
// Keep the historical prefix exact while qualifying every additive successor.
assert.deepEqual(CURRENT_MIGRATIONS.slice(0, HISTORICAL_MIGRATIONS.length),
  HISTORICAL_MIGRATIONS);
const CURRENT_TAIL_MIGRATIONS = Object.freeze(
  CURRENT_MIGRATIONS.slice(HISTORICAL_MIGRATIONS.length));
assert.deepEqual(CURRENT_TAIL_MIGRATIONS.slice(0, 3), [
  '0008_secureshop_bound_refund_requests.sql',
  '0009_secureshop_refund_cleanup_receipts.sql',
  '0010_secureshop_refund_cleanup_receipt_guard.sql',
]);
const stores = ['FRESH_REVIEW', 'POPULATED_REVIEW'];
const enabled = process.env.PG_TEST_DISPOSABLE === 'yes'
  && stores.every(store => ['MIGRATION', 'RUNTIME']
    .every(role => process.env[`${PREFIX}${store}_${role}_URL`]));

function pool(url, max = 8) {
  return new Pool({ connectionString: url, max, statement_timeout: 15000,
    lock_timeout: 3000, application_name: 'owasp-ai-goat-merchant-listings-native' });
}
function assertDisposable(url) {
  const parsed = new URL(url);
  assert.ok(['127.0.0.1', 'localhost'].includes(parsed.hostname));
  assert.match(parsed.pathname, /^\/owasp_ai_goat_test_[a-z0-9_]+$/);
}
function binding(owner = 7101) {
  return Object.freeze({ targetId: randomUUID(), launchId: randomUUID(), scenarioId: randomUUID(),
    generation: 1, platformOwnerId: owner, platformSessionId: owner + 100 });
}
async function seedTarget(client, scope, name = 'Immutable source') {
  await client.query(`INSERT INTO secureshop_review.product_targets
    (target_id,launch_id,scenario_id,generation,original_platform_owner_id,
     original_platform_session_id,own_merchant_id,source_count,source_sha256)
    VALUES($1,$2,$3,$4,$5,$6,12,1,$7)`, [scope.targetId, scope.launchId, scope.scenarioId,
    scope.generation, scope.platformOwnerId, scope.platformSessionId, Buffer.alloc(32, 1)]);
  await client.query(`INSERT INTO secureshop_review.product_target_products
    (target_id,product_id,source_retailer_id,retailer_id,source_product_sha256,name,
     description,price,images,stock_quantity,status,template_source)
    VALUES($1,71,12,12,$2,$3,'source body',9.25,'[]',5,'active','{{source}}')`,
  [scope.targetId, Buffer.alloc(32, 2), name]);
}
function migrationFixture(t, names, label) {
  const workspace = process.env.OWASP_AI_GOAT_ISOLATED_TEST_WORKSPACE;
  assert.equal(typeof workspace, 'string');
  const directory = fs.mkdtempSync(path.join(workspace, label));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const available = new Set(fs.readdirSync(migrations));
  for (const name of names) {
    assert.ok(available.has(name), `Missing migration fixture ${name}`);
    fs.copyFileSync(path.join(migrations, name), path.join(directory, name));
  }
  return directory;
}
const prefixThrough0006 = t => migrationFixture(t,
  HISTORICAL_MIGRATIONS.slice(0, -1), 'review-through-0006-');
const prefixThrough0007 = t => migrationFixture(t,
  HISTORICAL_MIGRATIONS, 'review-through-0007-');
function repository(runtime) {
  return createSecureShopBoundProductRepository(runtime, {
    checkCurrent: async () => {}, checkCleanup: async () => {},
  });
}

// Root launches these only through the owned disposable PostgreSQL lifecycle.
test('merchant migration fixtures isolate historical 0007 and retain the complete current directory', t => {
  const workspace = fs.mkdtempSync(path.join(require('node:os').tmpdir(), 'merchant-fixtures-'));
  t.after(() => fs.rmSync(workspace, { recursive: true, force: true }));
  const prior = process.env.OWASP_AI_GOAT_ISOLATED_TEST_WORKSPACE;
  process.env.OWASP_AI_GOAT_ISOLATED_TEST_WORKSPACE = workspace;
  t.after(() => {
    if (prior === undefined) delete process.env.OWASP_AI_GOAT_ISOLATED_TEST_WORKSPACE;
    else process.env.OWASP_AI_GOAT_ISOLATED_TEST_WORKSPACE = prior;
  });
  assert.deepEqual(fs.readdirSync(prefixThrough0006(t)).sort(),
    HISTORICAL_MIGRATIONS.slice(0, -1));
  assert.deepEqual(fs.readdirSync(prefixThrough0007(t)).sort(), HISTORICAL_MIGRATIONS);
  assert.deepEqual(fs.readdirSync(migrations).filter(name => /^[0-9]{4}_/.test(name)).sort(),
    [...HISTORICAL_MIGRATIONS, ...CURRENT_TAIL_MIGRATIONS]);
});

test('fresh 0007 merchant listings are target-owned, cart-compatible and reset-clean', {
  skip: !enabled, timeout: 60000,
}, async t => {
  const migrationUrl = process.env[`${PREFIX}FRESH_REVIEW_MIGRATION_URL`];
  const runtimeUrl = process.env[`${PREFIX}FRESH_REVIEW_RUNTIME_URL`];
  assertDisposable(migrationUrl); assertDisposable(runtimeUrl);
  const migration = pool(migrationUrl); const runtime = pool(runtimeUrl, 12);
  try {
    assert.deepEqual(await migrate(migration, prefixThrough0007(t)), HISTORICAL_MIGRATIONS);
    assert.deepEqual(await migrate(migration, prefixThrough0007(t)), []);
    assert.deepEqual(await migrate(migration, migrations), CURRENT_TAIL_MIGRATIONS);
    assert.deepEqual(await migrate(migration, migrations), []);
    const owner = binding(); const sibling = binding(owner.platformOwnerId + 1);
    await seedTarget(migration, owner); await seedTarget(migration, sibling, 'Sibling source');
    const products = repository(runtime);
    const unrated = await products.list(owner, { retailerId: null, search: null, status: 'active',
      category: null, sort: '', minRating: 5, maxPrice: null, limit: 1, offset: 0 });
    assert.equal(unrated.total, 0, 'a missing review target cannot borrow shared or sibling ratings');
    assert.equal((await products.get(owner, 71)).avg_rating, 0);
    const ownerReviewTarget = randomUUID(), siblingReviewTarget = randomUUID();
    for (const [scope, targetId] of [[owner, ownerReviewTarget], [sibling, siblingReviewTarget]]) {
      await migration.query(`INSERT INTO secureshop_review.review_targets
        (target_id,launch_id,scenario_id,generation,original_platform_owner_id,
         original_platform_session_id,seed_count,seed_sha256)
        VALUES($1,$2,$3,$4,$5,$6,0,$7)`, [targetId, scope.launchId, scope.scenarioId,
        scope.generation, scope.platformOwnerId, scope.platformSessionId, Buffer.alloc(32, 9)]);
    }
    for (const [targetId, rating, status] of [
      [ownerReviewTarget, 5, 'approved'], [ownerReviewTarget, 5, 'approved'],
      [ownerReviewTarget, 1, 'pending'], [siblingReviewTarget, 1, 'approved'],
    ]) {
      const inserted = await migration.query(`INSERT INTO secureshop_review.reviews
        (target_id,product_id,author_id,body,rating) VALUES($1,71,41,'owned rating', $2)
        RETURNING id`, [targetId, rating]);
      if (status === 'approved') await migration.query(`UPDATE secureshop_review.reviews
        SET status='approved',moderator_kind='manual',moderated_at=clock_timestamp()
        WHERE id=$1`, [inserted.rows[0].id]);
    }
    const rated = await products.list(owner, { retailerId: null, search: null, status: 'active',
      category: null, sort: '', minRating: 5, maxPrice: 9.25, limit: 1, offset: 0 });
    assert.equal(rated.total, 1); assert.equal(rated.rows.length, 1);
    assert.equal(rated.rows[0].id, 71); assert.equal(rated.rows[0].avg_rating, 5);
    assert.equal(rated.rows[0].review_count, 2, 'pending review is excluded');
    assert.equal((await products.get(owner, 71)).avg_rating, 5, 'detail uses the same owned aggregate');
    const secondPage = await products.list(owner, { retailerId: null, search: null, status: 'active',
      category: null, sort: '', minRating: 5, maxPrice: 9.25, limit: 1, offset: 1 });
    assert.equal(secondPage.total, 1); assert.deepEqual(secondPage.rows, []);
    const tooCheap = await products.list(owner, { retailerId: null, search: null, status: 'active',
      category: null, sort: '', minRating: 5, maxPrice: 9.24, limit: 1, offset: 0 });
    assert.equal(tooCheap.total, 0);
    const siblingRated = await products.list(sibling, { retailerId: null, search: null, status: 'active',
      category: null, sort: '', minRating: 5, maxPrice: null, limit: 1, offset: 0 });
    assert.equal(siblingRated.total, 0, 'owner ratings cannot enter a sibling launch');
    assert.equal((await products.get(sibling, 71)).avg_rating, 1);
    await migration.query(`INSERT INTO secureshop_review.reviews
      (target_id,product_id,author_id,body,rating,status,moderator_kind,moderated_at)
      SELECT $1,71,41,'rounding boundary',5,'approved','manual',clock_timestamp()
      FROM generate_series(1,247)`, [ownerReviewTarget]);
    await migration.query(`INSERT INTO secureshop_review.reviews
      (target_id,product_id,author_id,body,rating,status,moderator_kind,moderated_at)
      VALUES($1,71,41,'rounding boundary',4,'approved','manual',clock_timestamp())`,
    [ownerReviewTarget]);
    assert.equal((await products.get(owner, 71)).avg_rating, 5,
      '4.996 rounds to five only in the displayed projection');
    assert.equal((await products.list(owner, { retailerId: null, search: null, status: 'active',
      category: null, sort: '', minRating: 5, maxPrice: 9.25, limit: 1, offset: 0 })).total, 0,
    'raw mean below five must not qualify merely because display rounds to five');
    const listing = { name: 'Raw teaching listing', description: '<img src=x onerror=owned()>',
      price: 18.75, category: 'Home', templateSource: '{{ constructor.constructor("return 1")() }}',
      images: ['/owned.png'] };
    const created = await Promise.all([
      products.createListing(owner, 12, listing),
      products.createListing(owner, 12, { ...listing, name: 'Concurrent listing' }),
    ]);
    assert.equal(new Set(created).size, 2);
    const beforeForeignMerchant = (await runtime.query(`SELECT *
      FROM secureshop_review.product_target_products
      WHERE target_id=$1 AND product_id=$2`, [owner.targetId, created[0]])).rows[0];
    assert.equal(Number(beforeForeignMerchant.retailer_id), 12);
    assert.equal(beforeForeignMerchant.status, 'active');
    await assert.rejects(products.updateListing(owner, 13, created[0],
      { name: 'Foreign merchant edit' }), { code: 'OWNER_MISMATCH' });
    assert.deepEqual((await runtime.query(`SELECT *
      FROM secureshop_review.product_target_products
      WHERE target_id=$1 AND product_id=$2`, [owner.targetId, created[0]])).rows[0],
    beforeForeignMerchant, 'a different merchant cannot change the active listing in the same target');
    assert.equal((await runtime.query(`SELECT count(*)::integer AS n
      FROM secureshop_review.product_target_listing_overlays
      WHERE target_id=$1 AND product_id=$2`, [owner.targetId, created[0]])).rows[0].n, 0);
    const stockAscending = await products.list(owner, { retailerId: 12, search: null, status: null,
      category: null, sort: 'stock_asc', limit: 100, offset: 0 });
    assert.deepEqual(stockAscending.rows.slice(0, 2).map(row => row.id).sort((a, b) => a - b),
      [...created].sort((a, b) => a - b));
    await runtime.query(`INSERT INTO secureshop_review.product_target_cart_items
      (target_id,shop_user_id,product_id,quantity) VALUES($1,41,$2,1)`, [owner.targetId, created[0]]);
    assert.equal((await products.get(owner, created[0])).stock_quantity, 0);
    await products.updateListing(owner, 12, created[0], {
      name: 'Edited listing', description: '', category: null,
      templateSource: '', imageUrl: null, price: 0,
    });
    const edited = await products.get(owner, created[0]);
    assert.equal(edited.name, 'Edited listing'); assert.equal(edited.category, null);
    assert.equal(edited.description, ''); assert.equal(edited.price, 0);
    assert.equal(edited.template_source, ''); assert.equal(edited.image_url, null);
    const commerce = createSecureShopBoundCommerceRepository(runtime, { checkCurrent: async () => {} });
    const checkedOut = await commerce.checkout(owner, { shopUserId: 41,
      shippingAddress: 'owned', paymentMethod: 'test' });
    const orderId = checkedOut.orderId; assert.equal(checkedOut.total, 0);
    assert.equal(await products.archiveListing(owner, 12, created[0]), 1);
    assert.deepEqual((await runtime.query(`SELECT product_name,price FROM secureshop_review.product_target_order_items
      WHERE target_id=$1 AND order_id=$2`, [owner.targetId, orderId])).rows,
    [{ product_name: 'Edited listing', price: '0.00' }]);
    await runtime.query(`INSERT INTO secureshop_review.product_target_cart_items
      (target_id,shop_user_id,product_id,quantity) VALUES($1,41,$2,1)`, [owner.targetId, created[1]]);
    assert.equal(await products.archiveListing(owner, 12, created[1]), 1);
    const beforeDeniedOrders = await commerce.listOrders(owner, 41);
    const beforeDeniedCart = (await runtime.query(`SELECT *
      FROM secureshop_review.product_target_cart_items WHERE target_id=$1
      ORDER BY cart_item_id`, [owner.targetId])).rows;
    assert.equal(await commerce.checkout(owner, { shopUserId: 41,
      shippingAddress: 'owned', paymentMethod: 'test' }),
    require('../../server/database/postgres/secureshopBoundCommerceRepository').CART_STOCK_REJECTED);
    assert.deepEqual(await commerce.listOrders(owner, 41), beforeDeniedOrders);
    assert.deepEqual((await runtime.query(`SELECT *
      FROM secureshop_review.product_target_cart_items WHERE target_id=$1
      ORDER BY cart_item_id`, [owner.targetId])).rows, beforeDeniedCart);
    assert.equal(await products.get(owner, created[1]), null);
    assert.equal((await products.list(owner, { retailerId: 12, search: null, status: null,
      category: null, sort: 'updated_desc', limit: 100, offset: 0 })).rows.length, 1);
    const archived = await products.list(owner, { retailerId: 12, search: null, status: 'archived',
      category: null, sort: 'stock_desc', limit: 100, offset: 0 });
    assert.deepEqual(archived.rows.map(row => row.id).sort((a, b) => a - b),
      [...created].sort((a, b) => a - b));
    assert.equal(await products.updateListing(sibling, 12, created[0], { name: 'foreign' }), null);
    const operationId = randomUUID();
    const receipt = await products.cleanup(owner, { operationId });
    assert.deepEqual(receipt.listingCleanup.deletedCreatedCount, 2);
    assert.ok(receipt.listingCleanup.deletedOverlayCount >= 2);
    assert.equal((await products.readCleanupReceipt(owner, { operationId })).receiptSha256,
      receipt.receiptSha256);
    assert.deepEqual((await runtime.query(`SELECT name FROM secureshop_review.product_target_products
      WHERE target_id=$1`, [sibling.targetId])).rows, [{ name: 'Sibling source' }]);
    await assert.rejects(runtime.query(`UPDATE secureshop_review.product_listing_cleanup_receipts
      SET deleted_created_count=0 WHERE target_id=$1`, [owner.targetId]), error => error.code === '42501');
    await assert.rejects(migration.query(`UPDATE secureshop_review.product_listing_cleanup_receipts
      SET deleted_created_count=0 WHERE target_id=$1`, [owner.targetId]), error => error.code === '55000');
    assert.deepEqual((await runtime.query(`SELECT name FROM secureshop_review.product_target_products
      WHERE target_id=$1`, [sibling.targetId])).rows, [{ name: 'Sibling source' }]);
  } finally { await Promise.allSettled([runtime.end(), migration.end()]); }
});

test('populated 0006 target survives additive 0007 migration and replay', {
  skip: !enabled, timeout: 60000,
}, async t => {
  const migrationUrl = process.env[`${PREFIX}POPULATED_REVIEW_MIGRATION_URL`];
  const runtimeUrl = process.env[`${PREFIX}POPULATED_REVIEW_RUNTIME_URL`];
  assertDisposable(migrationUrl); assertDisposable(runtimeUrl);
  const migration = pool(migrationUrl); const runtime = pool(runtimeUrl);
  try {
    assert.deepEqual(await migrate(migration, prefixThrough0006(t)),
      HISTORICAL_MIGRATIONS.slice(0, -1));
    const owner = binding(7201); await seedTarget(migration, owner, 'Preserved populated source');
    assert.deepEqual(await migrate(migration, prefixThrough0007(t)),
      ['0007_secureshop_bound_merchant_listings.sql']);
    assert.deepEqual(await migrate(migration, prefixThrough0007(t)), []);
    const row = (await runtime.query(`SELECT name,price,stock_quantity,status,template_source
      FROM secureshop_review.product_target_products WHERE target_id=$1 AND product_id=71`,
    [owner.targetId])).rows[0];
    assert.deepEqual(row, { name: 'Preserved populated source', price: '9.25',
      stock_quantity: 5, status: 'active', template_source: '{{source}}' });
    assert.equal((await runtime.query(`SELECT count(*)::integer AS count
      FROM secureshop_review.product_target_listing_overlays WHERE target_id=$1`,
    [owner.targetId])).rows[0].count, 0);
    const through0036 = CURRENT_MIGRATIONS.filter(name => Number(name.slice(0, 4)) <= 36);
    assert.deepEqual(await migrate(migration, migrationFixture(t, through0036, 'review-through-0036-')),
      CURRENT_TAIL_MIGRATIONS.filter(name => Number(name.slice(0, 4)) <= 36));
    // A legitimate legacy admission already exists before 0037. Its immutable
    // birth binding cannot silently acquire a scene grant during migration.
    const { createListingJournalRepository } = require(
      '../../server/database/postgres/secureshopListingJournalRepository');
    const oldScope = { launchId: owner.launchId, scenarioId: owner.scenarioId,
      generation: owner.generation, platformOwnerId: owner.platformOwnerId,
      platformSessionId: owner.platformSessionId };
    const legacy = { scope: oldScope, persona: { id: 12, role: 'merchant' },
      personaSession: { sessionId: randomUUID(), authorityVersion: '1' },
      targetId: owner.targetId, mode: 'vuln', catalogRevision: '0',
      request: { version: 1, action: 'rewrite', operationId: randomUUID(),
        title: 'Historical fixture', description: 'Retained before scene grants' } };
    const personaAuthority = { capture(input) { return {
      binding: { ...input.scope, personaId: input.personaId, role: input.role,
        sessionId: input.sessionId, authorityVersion: input.authorityVersion },
      assertRemoteAdmission: async () => {}, withCrossStoreEffect: async work => work(),
    }; } };
    const journal = createListingJournalRepository({ pool: runtime, personaAuthority,
      capabilityKey: Buffer.alloc(32, 7) });
    assert.equal((await journal.admit(legacy)).newlyAdmitted, true);
    const oldAdmission = (await runtime.query(`SELECT * FROM secureshop_review.owned_listing_admissions
      WHERE operation_id=$1`, [legacy.request.operationId])).rows;
    assert.deepEqual(await migrate(migration, migrations),
      CURRENT_TAIL_MIGRATIONS.filter(name => Number(name.slice(0, 4)) > 36));
    assert.deepEqual(await migrate(migration, migrations), []);
    assert.deepEqual((await runtime.query(`SELECT name,price,stock_quantity,status,template_source
      FROM secureshop_review.product_target_products WHERE target_id=$1 AND product_id=71`,
    [owner.targetId])).rows[0], row);
    assert.deepEqual((await runtime.query(`SELECT * FROM secureshop_review.owned_listing_admissions
      WHERE operation_id=$1`, [legacy.request.operationId])).rows, oldAdmission);
    assert.equal((await runtime.query(`SELECT count(*)::integer AS count
      FROM secureshop_review.owned_listing_scene_admissions WHERE operation_id=$1`,
    [legacy.request.operationId])).rows[0].count, 0);
    assert.equal((await journal.get(legacy)).state, 'admitted',
      '0037 leaves the original unmapped operation readable without claiming a new grant');
    // A current retained-scene read keeps the 0028 FOR SHARE authority fence.
    // The actor execution is intentionally distinct from the storage birth:
    // packets bind the former, while product_targets and saved receipts retain
    // the latter.
    const { createSceneBinding, authorizeSceneMerchant } = require(
      '../../server/services/secureshopSceneBinding');
    const sceneMerchant = 1000000001;
    const sceneGrantId = randomUUID();
    const execution = { ...oldScope, launchId: randomUUID(), scenarioId: randomUUID(),
      generation: oldScope.generation + 1, platformSessionId: oldScope.platformSessionId + 1 };
    const sceneTarget = authorizeSceneMerchant(createSceneBinding(owner, {
      sceneId: randomUUID(), sceneGeneration: 1, grantId: sceneGrantId,
      execution, withLease: async work => work(),
    }), sceneMerchant);
    await runtime.query(`INSERT INTO secureshop_review.scene_execution_grants
      (grant_id,scene_id,scene_generation,target_id,launch_id,scenario_id,generation,
       original_platform_owner_id,original_platform_session_id)
      VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`, [sceneGrantId, sceneTarget.scene.sceneId,
      sceneTarget.scene.sceneGeneration, owner.targetId, execution.launchId, execution.scenarioId,
      execution.generation, execution.platformOwnerId, execution.platformSessionId]);
    const { prepareListingAdmission, hash } = require('../../server/services/secureshopListingJournalContract');
    const catalogRevision = String((await runtime.query(`SELECT revision
      FROM secureshop_review.owned_listing_catalog_revisions WHERE target_id=$1`, [owner.targetId]))
      .rows[0]?.revision || 0);
    const currentRaw = { scope: execution, persona: { id: sceneMerchant, role: 'merchant' },
        personaSession: { sessionId: randomUUID(), authorityVersion: '1' }, targetId: owner.targetId,
        mode: 'vuln', catalogRevision, request: { version: 1, action: 'rewrite',
          operationId: randomUUID(), title: 'Current scene read', description: 'Committed receipt' } };
    const current = prepareListingAdmission(currentRaw);
    const grantArgs = [sceneGrantId, sceneTarget.scene.sceneId, sceneTarget.scene.sceneGeneration,
      owner.targetId, execution.launchId, execution.scenarioId, execution.generation,
      execution.platformOwnerId, execution.platformSessionId];
    const oldReadOnly = await runtime.connect();
    try {
      await oldReadOnly.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');
      await assert.rejects(oldReadOnly.query(`SELECT secureshop_review.assert_scene_execution_grant(
        $1::uuid,$2::uuid,$3::bigint,$4::uuid,$5::uuid,$6::uuid,$7::bigint,$8::integer,$9::integer)`,
      grantArgs), error => error.code === '25006');
    } finally { await oldReadOnly.query('ROLLBACK'); oldReadOnly.release(); }
    const sceneKey = Buffer.alloc(32, 8);
    const sceneJournal = createListingJournalRepository({ pool: runtime, personaAuthority,
      capabilityKey: sceneKey, resolveTarget: async () => sceneTarget });
    const rewriteReceipt = { version: 1, operationId: current.request.operationId,
      requestSha256: current.requestSha256,
      sourceSha256: hash(JSON.stringify([current.request.title, current.request.description])),
      provider: 'native', model: 'native', callId: randomUUID(), mocked: false, fallback: false,
      html: '<b>Current scene receipt</b>', htmlSha256: hash('<b>Current scene receipt</b>') };
    assert.equal((await sceneJournal.admit(currentRaw)).newlyAdmitted, true);
    await sceneJournal.transition(currentRaw, { eventId: randomUUID(), expectedSequence: 0, state: 'running' });
    await sceneJournal.transition(currentRaw, { eventId: randomUUID(), expectedSequence: 1,
      state: 'effect_received', receipt: rewriteReceipt });
    await sceneJournal.transition(currentRaw, { eventId: randomUUID(), expectedSequence: 2,
      state: 'completed', receipt: rewriteReceipt });
    const rewriteSaves = require('../../server/database/postgres/secureshopListingRewriteSaveRepository')
      .createListingRewriteSaveRepository({ pool: runtime, personaAuthority, capabilityKey: sceneKey,
        resolveTarget: async () => sceneTarget, resolveRetainedTarget: async () => sceneTarget });
    const saved = await rewriteSaves.save({ admission: current, saveOperationId: randomUUID(), productId: null,
      item: { name: current.request.title, description: current.request.description, price: 12,
        category: null, images: [], templateSource: null } });
    const readCounts = async () => (await runtime.query(`SELECT
      (SELECT count(*)::int FROM secureshop_review.scene_execution_grants) AS grants,
      (SELECT count(*)::int FROM secureshop_review.owned_listing_rewrite_saves) AS saves,
      (SELECT count(*)::int FROM secureshop_review.owned_listing_generated_products) AS generated,
      (SELECT count(*)::int FROM secureshop_review.product_target_listing_overlays) AS overlays,
      (SELECT count(*)::int FROM secureshop_review.owned_listing_events) AS events`)).rows;
    const beforeSceneRead = await readCounts();
    assert.deepEqual(await rewriteSaves.read({ admission: current, saveOperationId: saved.saveOperationId }), saved,
      'committed scene receipt is found through the target birth after actor-scope admission');
    assert.deepEqual(await readCounts(), beforeSceneRead,
      'the repaired retained-scene GET locks authority but does not mutate durable Listings rows');
  } finally { await Promise.allSettled([runtime.end(), migration.end()]); }
});

test('native merchant metrics preserve seller attribution and bounded top products', {
  skip: !enabled, timeout: 60000,
}, async () => {
  const environment = {
    SECURESHOP_REVIEW_MIGRATION_DATABASE_URL: process.env[`${PREFIX}FRESH_REVIEW_MIGRATION_URL`],
    SECURESHOP_REVIEW_DATABASE_URL: process.env[`${PREFIX}FRESH_REVIEW_RUNTIME_URL`],
  };
  assertDisposable(environment.SECURESHOP_REVIEW_MIGRATION_DATABASE_URL);
  assertDisposable(environment.SECURESHOP_REVIEW_DATABASE_URL);
  const result = await require('../fixtures/secureshopBoundMerchantMetricsNative')
    .qualifyMerchantMetrics(environment);
  assert.deepEqual(result, { passed: true, modelCalls: 0, checks: [
    'distinct mixed-merchant order counts', 'line revenue attribution',
    'previous UTC window', 'cancelled declined and refunded order exclusion',
    'ordered UTC daily rows and deterministic equal-revenue product IDs',
    'top product limit', 'foreign owner denial',
  ] });
});
