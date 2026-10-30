'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const fsp = require('node:fs/promises');
const path = require('node:path');
const { Module, createRequire } = require('node:module');
const { createHash, randomUUID } = require('node:crypto');
const { Pool } = require('pg');
const { migrate } = require('../../db/postgres/migrate');
const { createSceneBinding } = require('../../server/services/secureshopSceneBinding');
const { createBoundCouponRepository } = require('../../server/database/postgres/secureshopBoundCouponRepository');
const { createSecureShopBoundCommerceRepository } = require(
  '../../server/database/postgres/secureshopBoundCommerceRepository');

const PREFIX = 'PG_SECURESHOP_CONVERSATIONAL_COMMERCE_';
const STORES = Object.freeze(['FRESH_REVIEW', 'POPULATED_REVIEW']);
const ROOT = path.resolve(__dirname, '../..');
const MIGRATIONS = path.join(ROOT, 'db/postgres/workshop-migrations/secureshop_review');
const CURRENT = Object.freeze(fs.readdirSync(MIGRATIONS)
  .filter(name => /^\d{4}_[a-z0-9_]+\.sql$/.test(name)).sort());
const COMMERCE_MIGRATION = '0041_conversational_commerce.sql';
const CART_CONFIRMATION_MIGRATION = '0042_cart_confirmation_proposals.sql';
const ENABLED = process.env.PG_TEST_DISPOSABLE === 'yes'
  && STORES.every(store => ['MIGRATION', 'RUNTIME']
    .every(role => process.env[`${PREFIX}${store}_${role}_URL`]));

assert.deepEqual(CURRENT.filter(name => name >= COMMERCE_MIGRATION && name <= CART_CONFIRMATION_MIGRATION),
  [COMMERCE_MIGRATION, CART_CONFIRMATION_MIGRATION]);
assert.equal(CURRENT.at(-1), '0046_customer_profile_receipts.sql', 'qualification pins the current review tail');

function pool(url, max = 8) {
  const parsed = new URL(url);
  assert.ok(['127.0.0.1', 'localhost'].includes(parsed.hostname));
  assert.match(parsed.pathname, /^\/owasp_ai_goat_test_[a-z0-9_]+$/);
  return new Pool({ connectionString: url, max, statement_timeout: 15000,
    lock_timeout: 3000, application_name: 'owasp-ai-goat-conversational-commerce-native' });
}

// Apply a historical prefix from the current checkout without copying source.
// The canonical migrator still verifies the exact bytes/checksums in that view.
function historicalMigrator(lastName) {
  const filename = require.resolve('../../db/postgres/migrate');
  const localRequire = createRequire(filename);
  const virtualFs = { ...fsp, async readdir(directory, ...args) {
    const names = await fsp.readdir(directory, ...args);
    if (path.resolve(directory) !== MIGRATIONS) return names;
    return names.filter(name => !/^\d{4}_[a-z0-9_]+\.sql$/.test(name) || name <= lastName);
  } };
  const loaded = new Module(filename, module);
  loaded.filename = filename;
  loaded.require = name => name === 'node:fs/promises' || name === 'fs/promises'
    ? virtualFs : localRequire(name);
  loaded._compile(fs.readFileSync(filename, 'utf8'), filename);
  return loaded.exports.migrate;
}

function sha256(value) {
  return createHash('sha256').update(typeof value === 'string' ? value : JSON.stringify(value)).digest('hex');
}

function scope(owner) {
  return Object.freeze({ targetId: randomUUID(), launchId: randomUUID(), scenarioId: randomUUID(),
    generation: 1, platformOwnerId: owner, platformSessionId: owner + 1000 });
}

async function seedTarget(client, value, { buyer, productId = 71, quantity = 2 } = {}) {
  await client.query(`INSERT INTO secureshop_review.product_targets
    (target_id,launch_id,scenario_id,generation,original_platform_owner_id,
     original_platform_session_id,own_merchant_id,source_count,source_sha256)
    VALUES($1,$2,$3,$4,$5,$6,$7,1,$8)`, [value.targetId, value.launchId, value.scenarioId,
    value.generation, value.platformOwnerId, value.platformSessionId, buyer + 5000, Buffer.alloc(32, 1)]);
  await client.query(`INSERT INTO secureshop_review.product_target_products
    (target_id,product_id,source_retailer_id,retailer_id,source_product_sha256,name,
     description,price,images,stock_quantity,status,template_source)
    VALUES($1,$2,$3,$4,$5,'Native practice lamp','Synthetic local product',9.25,'[]',5,'active','{{source}}')`,
  [value.targetId, productId, buyer + 5000, buyer + 5000, Buffer.alloc(32, 2)]);
  const address = (await client.query(`INSERT INTO secureshop_review.product_target_addresses
    (target_id,shop_user_id,label,line1,city,state,zip,phone,is_default)
    VALUES($1,$2,NULL,'4 Fixture Way','Test City','CA','90001','5550100',true)
    RETURNING address_id`, [value.targetId, buyer])).rows[0];
  await client.query(`INSERT INTO secureshop_review.product_target_cart_items
    (target_id,shop_user_id,product_id,quantity) VALUES($1,$2,$3,$4)`,
  [value.targetId, buyer, productId, quantity]);
  const scene = { sceneId: randomUUID(), sceneGeneration: 1, grantId: randomUUID() };
  await client.query(`INSERT INTO secureshop_review.scene_execution_grants
    (grant_id,scene_id,scene_generation,target_id,launch_id,scenario_id,generation,
     original_platform_owner_id,original_platform_session_id)
    VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`, [scene.grantId, scene.sceneId,
    scene.sceneGeneration, value.targetId, value.launchId, value.scenarioId, value.generation,
    value.platformOwnerId, value.platformSessionId]);
  return Object.freeze({ addressId: Number(address.address_id), productId, scene });
}

function binding(value, scene) {
  return createSceneBinding(value, { ...scene, execution: value, withLease: work => work() });
}

function actor(shopUserId) {
  return Object.freeze({ shopUserId, mode: 'fixed', personaSession: Object.freeze({
    sessionId: randomUUID(), authorityVersion: '1',
  }) });
}

async function inventory(client, targetId, shopUserId, productId) {
  const row = (await client.query(`SELECT
    (SELECT count(*)::int FROM secureshop_review.product_target_orders
      WHERE target_id=$1 AND shop_user_id=$2) AS orders,
    (SELECT count(*)::int FROM secureshop_review.product_target_order_items i
      JOIN secureshop_review.product_target_orders o USING(target_id,order_id)
      WHERE i.target_id=$1 AND o.shop_user_id=$2) AS order_items,
    (SELECT count(*)::int FROM secureshop_review.product_target_cart_items
      WHERE target_id=$1 AND shop_user_id=$2) AS cart_items,
    (SELECT quantity::int FROM secureshop_review.product_target_cart_items
      WHERE target_id=$1 AND shop_user_id=$2 AND product_id=$3) AS cart_quantity,
    (SELECT CASE WHEN o.product_id IS NULL THEN p.stock_quantity ELSE o.stock_quantity END
      FROM secureshop_review.product_target_products p
      LEFT JOIN secureshop_review.product_target_listing_overlays o
        ON o.target_id=p.target_id AND o.product_id=p.product_id
      WHERE p.target_id=$1 AND p.product_id=$3) AS stock`, [targetId, shopUserId, productId])).rows[0];
  return Object.freeze(Object.fromEntries(Object.entries(row)
    .map(([key, value]) => [key, value === null ? null : Number(value)])));
}

async function snapshotHistoricalRows(client) {
  const tables = ['product_targets', 'product_target_products', 'product_target_addresses',
    'product_target_cart_items', 'product_target_orders', 'product_target_order_items',
    'bound_commerce_operations', 'scene_execution_grants', 'product_target_price_history'];
  const result = {};
  for (const table of tables) {
    result[table] = (await client.query(`SELECT to_jsonb(t) AS value FROM secureshop_review.${table} t
      ORDER BY to_jsonb(t)::text`)).rows.map(row => row.value);
  }
  return result;
}

async function assertSchemaBoundary(runtime) {
  const rows = (await runtime.query(`SELECT c.relname,
    has_table_privilege(current_user,c.oid,'SELECT') AS can_select,
    has_table_privilege(current_user,c.oid,'INSERT') AS can_insert,
    has_table_privilege(current_user,c.oid,'UPDATE') AS can_update,
    has_table_privilege(current_user,c.oid,'DELETE') AS can_delete,
    EXISTS(SELECT 1 FROM aclexplode(COALESCE(c.relacl,acldefault('r',c.relowner))) a
      WHERE a.grantee=0) AS public_privilege
    FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
    WHERE n.nspname='secureshop_review' AND c.relname=ANY($1::text[])
    ORDER BY c.relname`, [['practice_payment_methods', 'chat_commerce_choices',
    'chat_commerce_operations']])).rows;
  assert.deepEqual(rows, [
    { relname: 'chat_commerce_choices', can_select: true, can_insert: true,
      can_update: false, can_delete: false, public_privilege: false },
    { relname: 'chat_commerce_operations', can_select: true, can_insert: true,
      can_update: true, can_delete: false, public_privilege: false },
    { relname: 'practice_payment_methods', can_select: true, can_insert: true,
      can_update: false, can_delete: false, public_privilege: false },
  ]);
  const functions = (await runtime.query(`SELECT p.proname,
    has_function_privilege(current_user,p.oid,'EXECUTE') AS runtime_execute,
    EXISTS(SELECT 1 FROM aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) a
      WHERE a.grantee=0 AND a.privilege_type='EXECUTE') AS public_execute
    FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
    WHERE n.nspname='secureshop_review' AND p.proname=ANY($1::text[])
    ORDER BY p.proname`, [['guard_chat_commerce', 'retire_chat_commerce']])).rows;
  assert.deepEqual(functions, [
    { proname: 'guard_chat_commerce', runtime_execute: false, public_execute: false },
    { proname: 'retire_chat_commerce', runtime_execute: false, public_execute: false },
  ]);
}

test('0041 qualifies fresh/populated/no-op and real synthetic checkout effects', {
  skip: !ENABLED, timeout: 120000,
}, async t => {
  const pools = {};
  for (const store of STORES) for (const role of ['MIGRATION', 'RUNTIME']) {
    const key = `${store}_${role}`;
    pools[key] = pool(process.env[`${PREFIX}${key}_URL`], role === 'RUNTIME' ? 12 : 3);
  }
  t.after(async () => Promise.all(Object.values(pools).map(value => value.end())));

  assert.deepEqual(await migrate(pools.FRESH_REVIEW_MIGRATION, MIGRATIONS), CURRENT);
  assert.deepEqual(await migrate(pools.FRESH_REVIEW_MIGRATION, MIGRATIONS), []);
  assert.deepEqual((await pools.FRESH_REVIEW_MIGRATION.query(`SELECT
    (SELECT count(*)::int FROM secureshop_review.practice_payment_methods) AS methods,
    (SELECT count(*)::int FROM secureshop_review.chat_commerce_choices) AS choices,
    (SELECT count(*)::int FROM secureshop_review.chat_commerce_operations) AS operations`)).rows[0],
  { methods: 0, choices: 0, operations: 0 });
  await assertSchemaBoundary(pools.FRESH_REVIEW_RUNTIME);

  const through0040 = historicalMigrator('0040_owned_product_price_history.sql');
  assert.deepEqual(await through0040(pools.POPULATED_REVIEW_MIGRATION, MIGRATIONS),
    CURRENT.filter(name => name < COMMERCE_MIGRATION));
  const buyerId = 7101;
  const ownerScope = scope(8101); const siblingScope = scope(8102);
  const ownerSeed = await seedTarget(pools.POPULATED_REVIEW_MIGRATION, ownerScope, { buyer: buyerId });
  const siblingSeed = await seedTarget(pools.POPULATED_REVIEW_MIGRATION, siblingScope,
    { buyer: buyerId + 1, productId: 72, quantity: 1 });
  const oldOrder = (await pools.POPULATED_REVIEW_MIGRATION.query(`INSERT INTO secureshop_review.product_target_orders
    (target_id,shop_user_id,total_amount,payment_method,shipping_address)
    VALUES($1,$2,4.50,'Historical synthetic','Historical address') RETURNING order_id`,
  [ownerScope.targetId, buyerId])).rows[0];
  await pools.POPULATED_REVIEW_MIGRATION.query(`INSERT INTO secureshop_review.product_target_order_items
    (target_id,order_id,product_id,product_name,quantity,price)
    VALUES($1,$2,$3,'Historical line',1,4.50)`,
  [ownerScope.targetId, oldOrder.order_id, ownerSeed.productId]);
  const beforeUpgrade = await snapshotHistoricalRows(pools.POPULATED_REVIEW_MIGRATION);
  const through0042 = historicalMigrator(CART_CONFIRMATION_MIGRATION);
  assert.deepEqual(await through0042(pools.POPULATED_REVIEW_MIGRATION, MIGRATIONS),
    [COMMERCE_MIGRATION, CART_CONFIRMATION_MIGRATION]);
  assert.deepEqual(await through0042(pools.POPULATED_REVIEW_MIGRATION, MIGRATIONS), []);
  assert.deepEqual(await snapshotHistoricalRows(pools.POPULATED_REVIEW_MIGRATION), beforeUpgrade);
  assert.deepEqual(await migrate(pools.POPULATED_REVIEW_MIGRATION, MIGRATIONS),
    CURRENT.filter(name => name > CART_CONFIRMATION_MIGRATION));
  assert.deepEqual(await migrate(pools.POPULATED_REVIEW_MIGRATION, MIGRATIONS), []);
  assert.deepEqual(await snapshotHistoricalRows(pools.POPULATED_REVIEW_MIGRATION), beforeUpgrade,
    '0041 is additive and preserves populated commerce, authority, and price history rows');
  assert.deepEqual((await pools.POPULATED_REVIEW_MIGRATION.query(`SELECT
    (SELECT count(*)::int FROM secureshop_review.practice_payment_methods) AS methods,
    (SELECT count(*)::int FROM secureshop_review.chat_commerce_choices) AS choices,
    (SELECT count(*)::int FROM secureshop_review.chat_commerce_operations) AS operations`)).rows[0],
  { methods: 0, choices: 0, operations: 0 }, '0041 does not fabricate choices or operations for old rows');
  await assertSchemaBoundary(pools.POPULATED_REVIEW_RUNTIME);

  const runtime = pools.POPULATED_REVIEW_RUNTIME;
  const couponRepository = createBoundCouponRepository({ pool: runtime, checkCurrent: async () => {} });
  const repository = createSecureShopBoundCommerceRepository(runtime,
    { checkCurrent: async () => {}, couponRepository, effectTimeoutMs: 3000 });
  const commerce = repository.conversation;
  const owner = binding(ownerScope, ownerSeed.scene); const sibling = binding(siblingScope, siblingSeed.scene);
  const ownerActor = actor(buyerId); const siblingActor = actor(buyerId + 1);

  const products = await commerce.search(owner, { ...ownerActor, search: 'practice lamp' });
  assert.equal(products.cards.length, 1);
  const addresses = await commerce.addresses(owner, ownerActor);
  assert.deepEqual(addresses.cards.map(card => [card.kind, card.title]), [['address', 'Saved address']],
    'a real nullable saved-address label remains usable without revealing its fields');
  const approvedMethodOperation = randomUUID();
  const approvedMethod = await commerce.createPaymentMethod(owner, { ...ownerActor,
    operationId: approvedMethodOperation, scenario: 'approved' });
  const approvedChoice = approvedMethod.result.cards[0].choiceId;
  const declinedMethod = await commerce.createPaymentMethod(owner, { ...ownerActor,
    operationId: randomUUID(), scenario: 'declined' });
  const declinedChoice = declinedMethod.result.cards[0].choiceId;
  await assert.rejects(runtime.query(`INSERT INTO secureshop_review.chat_commerce_choices
    (choice_id,target_id,shop_user_id,kind,context_json,snapshot_json,snapshot_sha256,state)
    VALUES($1,$2,$3,'product',NULL,NULL,$4,'redacted')`,
  [randomUUID(), ownerScope.targetId, buyerId, '0'.repeat(64)]), error => error?.code === 'P0001');
  await assert.rejects(runtime.query(`INSERT INTO secureshop_review.chat_commerce_operations
    (operation_id,target_id,shop_user_id,kind,context_json,request_json,intent_sha256,
     proposal_json,proposal_sha256,result_json,result_sha256,state)
    VALUES($1,$2,$3,'cart.add',NULL,NULL,$4,NULL,NULL,NULL,NULL,'redacted')`,
  [randomUUID(), ownerScope.targetId, buyerId, '0'.repeat(64)]), error => error?.code === 'P0001');
  await assert.rejects(pools.POPULATED_REVIEW_MIGRATION.query(`UPDATE
    secureshop_review.practice_payment_methods SET created_at=created_at
    WHERE target_id=$1 AND scenario='approved'`, [ownerScope.targetId]),
  error => error?.code === 'P0001');

  await assert.rejects(commerce.createPaymentMethod(sibling, { ...siblingActor,
    operationId: approvedMethodOperation, scenario: 'approved' }),
  { code: 'COMMERCE_OPERATION_CONFLICT' });
  assert.equal((await runtime.query(`SELECT count(*)::int AS n FROM secureshop_review.practice_payment_methods
    WHERE target_id=$1`, [siblingScope.targetId])).rows[0].n, 0,
  'a globally claimed operation UUID cannot create a sibling effect');
  const siblingMethod = await commerce.createPaymentMethod(sibling, { ...siblingActor,
    operationId: randomUUID(), scenario: 'approved' });

  // Exercise the payment choice itself: each address is valid in the current
  // admission context, so an earlier address denial cannot mask this boundary.
  const paymentEffectSnapshot = async () => ({
    owner: await inventory(runtime, ownerScope.targetId, buyerId, ownerSeed.productId),
    sibling: await inventory(runtime, siblingScope.targetId, buyerId + 1, siblingSeed.productId),
    operations: (await runtime.query(`SELECT * FROM secureshop_review.chat_commerce_operations
      WHERE target_id=ANY($1::uuid[]) ORDER BY operation_id`,
    [[ownerScope.targetId, siblingScope.targetId]])).rows,
    checkoutReceipts: (await runtime.query(`SELECT * FROM secureshop_review.bound_commerce_operations
      WHERE target_id=ANY($1::uuid[]) ORDER BY operation_id`,
    [[ownerScope.targetId, siblingScope.targetId]])).rows,
    methods: (await runtime.query(`SELECT * FROM secureshop_review.practice_payment_methods
      WHERE target_id=ANY($1::uuid[]) ORDER BY method_id`,
    [[ownerScope.targetId, siblingScope.targetId]])).rows,
  });
  const nextSessionActor = { ...ownerActor, personaSession: {
    ...ownerActor.personaSession, sessionId: randomUUID(),
  } };
  const currentSessionAddresses = await commerce.addresses(owner, nextSessionActor);
  for (const [label, currentActor, validAddress, deniedPayment] of [
    ['foreign owner payment choice', ownerActor, addresses.cards[0].choiceId,
      siblingMethod.result.cards[0].choiceId],
    ['prior-session payment choice', nextSessionActor, currentSessionAddresses.cards[0].choiceId,
      approvedChoice],
  ]) {
    assert.equal((await commerce.resolveChoice(owner, { ...currentActor,
      choiceId: validAddress })).kind, 'address');
    const deniedId = randomUUID(), before = await paymentEffectSnapshot();
    await assert.rejects(commerce.prepareCheckout(owner, { ...currentActor,
      operationId: deniedId, addressChoiceId: validAddress, paymentChoiceId: deniedPayment }),
    { code: 'COMMERCE_CHOICE_DENIED' }, label);
    const read = await commerce.readOperation(owner, { ...currentActor, operationId: deniedId });
    assert.deepEqual(read, { scopeKey: read.scopeKey, operationId: deniedId, status: 'not_found' });
    assert.deepEqual(await paymentEffectSnapshot(), before,
      `${label} cannot create a proposal, receipt, order, payment, stock, or cart effect`);
  }

  const siblingProduct = (await commerce.search(sibling,
    { ...siblingActor, search: 'practice lamp' })).cards[0];
  const siblingInitial = await inventory(runtime, siblingScope.targetId,
    buyerId + 1, siblingSeed.productId);
  const addId = randomUUID();
  const addProposal = await commerce.prepareCart(sibling, { ...siblingActor,
    operationId: addId, action: 'add', choiceId: siblingProduct.choiceId, quantity: 2 });
  assert.deepEqual({ status: addProposal.status, kind: addProposal.kind,
    choiceId: addProposal.choice.choiceId, quantity: addProposal.quantity },
  { status: 'prepared', kind: 'cart.add', choiceId: siblingProduct.choiceId, quantity: 2 });
  assert.deepEqual(await inventory(runtime, siblingScope.targetId, buyerId + 1,
    siblingSeed.productId), siblingInitial, 'cart preparation has zero cart, stock, or order effect');
  const { scopeKey: _addScope, ...publicAddProposal } = addProposal;
  assert.deepEqual(await commerce.readOperation(sibling, { ...siblingActor, operationId: addId }),
    { operationId: addId, status: 'prepared', proposal: publicAddProposal,
      scopeKey: addProposal.scopeKey });
  const ownerReadOfSibling = await commerce.readOperation(owner, { ...ownerActor, operationId: addId });
  const absentOwnerRead = await commerce.readOperation(owner, { ...ownerActor, operationId: randomUUID() });
  assert.deepEqual(ownerReadOfSibling, { ...absentOwnerRead, operationId: addId },
    'a foreign operation ID projects exactly like an absent ID');
  await assert.rejects(commerce.readOperation(sibling, { ...siblingActor,
    personaSession: { ...siblingActor.personaSession, sessionId: randomUUID() }, operationId: addId }),
  { code: 'COMMERCE_OPERATION_CONFLICT' }, 'an owned row with stale session context remains denied');
  await assert.rejects(async () => commerce.confirmCart(sibling,
    { ...siblingActor, proposalId: addId, quantity: 2 }), { code: 'INVALID_ARGUMENT' });
  await assert.rejects(commerce.confirmCart(owner, { ...ownerActor, proposalId: addId }),
    { code: 'COMMERCE_OPERATION_CONFLICT' });
  await assert.rejects(commerce.confirmCart(sibling,
    { ...siblingActor, mode: 'vuln', proposalId: addId }),
  { code: 'COMMERCE_OPERATION_CONFLICT' });
  assert.deepEqual(await inventory(runtime, siblingScope.targetId, buyerId + 1,
    siblingSeed.productId), siblingInitial, 'DTO, owner, and mode denials cannot apply prepared intent');
  const added = await commerce.confirmCart(sibling, { ...siblingActor, proposalId: addId });
  assert.equal(added.status, 'completed');
  assert.ok(Number.isSafeInteger(added.result.id) && added.result.id > 0,
    'confirmed add returns the persisted cart item identity');
  const afterAdd = await inventory(runtime, siblingScope.targetId, buyerId + 1,
    siblingSeed.productId);
  assert.deepEqual(afterAdd, { ...siblingInitial, cart_quantity: siblingInitial.cart_quantity + 2 });
  assert.deepEqual(await commerce.confirmCart(sibling, { ...siblingActor, proposalId: addId }),
    { ...added, replayed: true });
  const completedAdd = await commerce.readOperation(sibling, { ...siblingActor, operationId: addId });
  assert.deepEqual(completedAdd.proposal, publicAddProposal);
  assert.deepEqual(completedAdd.receipt,
    Object.fromEntries(Object.entries({ ...added, replayed: true }).filter(([key]) => key !== 'scopeKey')));

  const staleItem = (await commerce.cartView(sibling, siblingActor)).cards[0];
  const staleId = randomUUID();
  await commerce.prepareCart(sibling, { ...siblingActor, operationId: staleId,
    action: 'update', choiceId: staleItem.choiceId, quantity: 4 });
  assert.equal((await inventory(runtime, siblingScope.targetId, buyerId + 1,
    siblingSeed.productId)).cart_quantity, 3, 'update preparation has zero effect');
  await runtime.query(`UPDATE secureshop_review.product_target_cart_items SET quantity=2
    WHERE target_id=$1 AND shop_user_id=$2 AND product_id=$3`,
  [siblingScope.targetId, buyerId + 1, siblingSeed.productId]);
  const stale = await commerce.confirmCart(sibling, { ...siblingActor, proposalId: staleId });
  assert.deepEqual({ status: stale.status, result: stale.result }, { status: 'stale', result: null });
  assert.equal((await inventory(runtime, siblingScope.targetId, buyerId + 1,
    siblingSeed.productId)).cart_quantity, 2, 'stale selection cannot overwrite current cart state');
  assert.deepEqual(await commerce.confirmCart(sibling, { ...siblingActor, proposalId: staleId }),
    { ...stale, replayed: true });

  const currentItem = (await commerce.cartView(sibling, siblingActor)).cards[0];
  const updateId = randomUUID();
  await commerce.prepareCart(sibling, { ...siblingActor, operationId: updateId,
    action: 'update', choiceId: currentItem.choiceId, quantity: 4 });
  assert.equal((await inventory(runtime, siblingScope.targetId, buyerId + 1,
    siblingSeed.productId)).cart_quantity, 2);
  const updated = await commerce.confirmCart(sibling, { ...siblingActor, proposalId: updateId });
  assert.deepEqual(updated.result, { changed: 1 });
  assert.equal((await inventory(runtime, siblingScope.targetId, buyerId + 1,
    siblingSeed.productId)).cart_quantity, 4);
  const removable = (await commerce.cartView(sibling, siblingActor)).cards[0];
  const removeId = randomUUID();
  const removeProposal = await commerce.prepareCart(sibling, { ...siblingActor,
    operationId: removeId, action: 'remove', choiceId: removable.choiceId });
  assert.equal(removeProposal.quantity, null);
  assert.equal((await inventory(runtime, siblingScope.targetId, buyerId + 1,
    siblingSeed.productId)).cart_items, 1, 'remove preparation has zero effect');
  const removed = await commerce.confirmCart(sibling, { ...siblingActor, proposalId: removeId });
  assert.deepEqual(removed.result, { changed: 1 });
  assert.equal((await inventory(runtime, siblingScope.targetId, buyerId + 1,
    siblingSeed.productId)).cart_items, 0);
  assert.deepEqual(await commerce.confirmCart(sibling, { ...siblingActor, proposalId: removeId }),
    { ...removed, replayed: true });

  const addressChoice = addresses.cards[0].choiceId;
  const initial = await inventory(runtime, ownerScope.targetId, buyerId, ownerSeed.productId);
  const declinedId = randomUUID();
  const declinedProposal = await commerce.prepareCheckout(owner, { ...ownerActor,
    operationId: declinedId, addressChoiceId: addressChoice, paymentChoiceId: declinedChoice });
  assert.equal(declinedProposal.currency, 'USD'); assert.equal(declinedProposal.totalCents, 1850);
  const declined = await commerce.confirmCheckout(owner, { ...ownerActor, proposalId: declinedId });
  assert.equal(declined.status, 'declined'); assert.equal(declined.order, null);
  assert.deepEqual(await inventory(runtime, ownerScope.targetId, buyerId, ownerSeed.productId), initial,
    'declined synthetic payment has no order, stock, or cart effect');
  const declinedReplay = await commerce.confirmCheckout(owner, { ...ownerActor, proposalId: declinedId });
  assert.deepEqual(declinedReplay, { ...declined, replayed: true });
  await assert.rejects(runtime.query(`UPDATE secureshop_review.chat_commerce_operations
    SET result_json='{}' WHERE operation_id=$1`, [declinedId]), error => error?.code === 'P0001');
  await assert.rejects(runtime.query(`DELETE FROM secureshop_review.chat_commerce_operations
    WHERE operation_id=$1`, [declinedId]), error => error?.code === '42501');
  await assert.rejects(runtime.query(`UPDATE secureshop_review.chat_commerce_choices SET snapshot_json='{}'
    WHERE choice_id=$1`, [addressChoice]), error => error?.code === '42501');
  await assert.rejects(runtime.query(`DELETE FROM secureshop_review.practice_payment_methods
    WHERE target_id=$1`, [ownerScope.targetId]), error => error?.code === '42501');

  const conflictedId = randomUUID();
  await commerce.prepareCheckout(owner, { ...ownerActor, operationId: conflictedId,
    addressChoiceId: addressChoice, paymentChoiceId: approvedChoice });
  const incompatibleRequest = JSON.stringify({ version: 1, kind: 'owned conflict' });
  await pools.POPULATED_REVIEW_MIGRATION.query(`INSERT INTO secureshop_review.bound_commerce_operations
    (operation_id,target_id,shop_user_id,kind,persona_session_id,authority_version,mode,
     request_sha256,request_json) VALUES($1,$2,$3,'coupon',$4,1,'fixed',$5,$6)`,
  [conflictedId, ownerScope.targetId, buyerId, ownerActor.personaSession.sessionId,
    sha256(incompatibleRequest), incompatibleRequest]);
  await assert.rejects(commerce.confirmCheckout(owner, { ...ownerActor, proposalId: conflictedId }),
    { code: 'COMMERCE_OPERATION_CONFLICT' });
  assert.deepEqual(await inventory(runtime, ownerScope.targetId, buyerId, ownerSeed.productId), initial,
    'a UUID conflict rolls back before order, stock, or cart effects');
  assert.equal((await runtime.query(`SELECT state FROM secureshop_review.chat_commerce_operations
    WHERE operation_id=$1`, [conflictedId])).rows[0].state, 'prepared');

  const matchingLegacyId = randomUUID();
  await commerce.prepareCheckout(owner, { ...ownerActor, operationId: matchingLegacyId,
    addressChoiceId: addressChoice, paymentChoiceId: approvedChoice });
  const legacyOrder = (await pools.POPULATED_REVIEW_MIGRATION.query(`INSERT INTO
    secureshop_review.product_target_orders
    (target_id,shop_user_id,total_amount,payment_method,shipping_address,
     subtotal_amount,discount_amount)
    VALUES($1,$2,18.50,'Practice card — approved',$3,18.50,0) RETURNING order_id`,
  [ownerScope.targetId, buyerId, '4 Fixture Way\nTest City\nCA\n90001'])).rows[0];
  await pools.POPULATED_REVIEW_MIGRATION.query(`INSERT INTO secureshop_review.product_target_order_items
    (target_id,order_id,product_id,product_name,quantity,price,discount_amount)
    VALUES($1,$2,$3,'Unrelated legacy order',2,9.25,0)`,
  [ownerScope.targetId, legacyOrder.order_id, ownerSeed.productId]);
  const legacyRequest = { scope: { launchId: ownerScope.launchId, scenarioId: ownerScope.scenarioId,
    generation: ownerScope.generation, platformOwnerId: ownerScope.platformOwnerId,
    platformSessionId: ownerScope.platformSessionId }, targetId: ownerScope.targetId,
  persona: { id: buyerId, role: 'customer' }, personaSession: ownerActor.personaSession,
  mode: 'fixed', operationId: matchingLegacyId,
  shippingAddress: '4 Fixture Way\nTest City\nCA\n90001', paymentMethod: 'Practice card — approved' };
  const legacyRequestJson = JSON.stringify(legacyRequest);
  const legacyResultJson = JSON.stringify({ orderId: Number(legacyOrder.order_id),
    total: 18.5, subtotal: 18.5, discount: 0 });
  await pools.POPULATED_REVIEW_MIGRATION.query(`INSERT INTO secureshop_review.bound_commerce_operations
    (operation_id,target_id,shop_user_id,kind,persona_session_id,authority_version,mode,
     request_sha256,request_json) VALUES($1,$2,$3,'checkout',$4,1,'fixed',$5,$6)`,
  [matchingLegacyId, ownerScope.targetId, buyerId, ownerActor.personaSession.sessionId,
    sha256(legacyRequestJson), legacyRequestJson]);
  await pools.POPULATED_REVIEW_MIGRATION.query(`UPDATE secureshop_review.bound_commerce_operations
    SET state='completed',result_json=$2,result_sha256=$3 WHERE operation_id=$1`,
  [matchingLegacyId, legacyResultJson, sha256(legacyResultJson)]);
  const beforeApproved = await inventory(runtime, ownerScope.targetId, buyerId, ownerSeed.productId);
  await assert.rejects(commerce.confirmCheckout(owner, { ...ownerActor,
    proposalId: matchingLegacyId }), { code: 'COMMERCE_OPERATION_CONFLICT' });
  assert.deepEqual(await inventory(runtime, ownerScope.targetId, buyerId, ownerSeed.productId),
    beforeApproved, 'an equal-total old checkout cannot complete a new displayed proposal');
  assert.deepEqual((await runtime.query(`SELECT state,result_json,result_sha256
    FROM secureshop_review.chat_commerce_operations WHERE operation_id=$1`,
  [matchingLegacyId])).rows[0], { state: 'prepared', result_json: null, result_sha256: null });

  const approvedId = randomUUID();
  const approvedProposal = await commerce.prepareCheckout(owner, { ...ownerActor,
    operationId: approvedId, addressChoiceId: addressChoice, paymentChoiceId: approvedChoice });
  assert.deepEqual({ currency: approvedProposal.currency, subtotalCents: approvedProposal.subtotalCents,
    discountCents: approvedProposal.discountCents, totalCents: approvedProposal.totalCents },
  { currency: 'USD', subtotalCents: 1850, discountCents: 0, totalCents: 1850 });
  const preparedBeforeConflict = await commerce.readOperation(owner, { ...ownerActor, operationId: approvedId });
  await assert.rejects(commerce.prepareCheckout(owner, { ...ownerActor, operationId: approvedId,
    addressChoiceId: addressChoice, paymentChoiceId: declinedMethod.result.cards[0].choiceId }),
  { code: 'COMMERCE_OPERATION_CONFLICT' });
  assert.deepEqual(await commerce.readOperation(owner, { ...ownerActor, operationId: approvedId }), preparedBeforeConflict);
  assert.deepEqual(await inventory(runtime, ownerScope.targetId, buyerId, ownerSeed.productId), beforeApproved,
    'changed prepare intent cannot replace the saved quote or cause a purchase');
  // Real concurrent repository transactions; these are controlled actors, not rendered/model proof.
  const raced = await Promise.all([1, 2].map(() => commerce.confirmCheckout(owner,
    { ...ownerActor, proposalId: approvedId })));
  assert.deepEqual(raced.map(value => value.replayed).sort(), [false, true]);
  const approved = raced.find(value => !value.replayed);
  assert.deepEqual(raced.find(value => value.replayed), { ...approved, replayed: true });
  assert.equal(approved.status, 'approved'); assert.equal(approved.totalCents, 1850);
  assert.ok(Number.isSafeInteger(approved.order.orderId));
  const committed = await inventory(runtime, ownerScope.targetId, buyerId, ownerSeed.productId);
  assert.deepEqual(committed, { orders: beforeApproved.orders + 1,
    order_items: beforeApproved.order_items + 1,
    cart_items: 0, cart_quantity: null, stock: beforeApproved.stock - 2 });
  assert.deepEqual((await runtime.query(`SELECT
    (SELECT count(*)::int FROM secureshop_review.chat_commerce_operations
      WHERE operation_id=$1 AND state='completed') AS chat_receipts,
    (SELECT count(*)::int FROM secureshop_review.bound_commerce_operations
      WHERE operation_id=$1 AND kind='checkout' AND state='completed') AS checkout_receipts,
    (SELECT count(*)::int FROM secureshop_review.product_target_orders
      WHERE target_id=$2 AND order_id=$3) AS orders`,
  [approvedId, ownerScope.targetId, approved.order.orderId])).rows[0],
  { chat_receipts: 1, checkout_receipts: 1, orders: 1 });
  assert.deepEqual(await commerce.confirmCheckout(owner, { ...ownerActor, proposalId: approvedId }),
    { ...approved, replayed: true });
  assert.deepEqual(await inventory(runtime, ownerScope.targetId, buyerId, ownerSeed.productId), committed,
    'confirmation replay cannot duplicate the order or consume stock again');

  const ownerDigests = (await runtime.query(`SELECT operation_id,intent_sha256,proposal_sha256,result_sha256
    FROM secureshop_review.chat_commerce_operations WHERE target_id=$1 ORDER BY operation_id`,
  [ownerScope.targetId])).rows;
  await runtime.query(`UPDATE secureshop_review.product_targets SET lifecycle='retired'
    WHERE target_id=$1`, [ownerScope.targetId]);
  assert.equal((await runtime.query(`SELECT count(*)::int AS n FROM secureshop_review.practice_payment_methods
    WHERE target_id=$1`, [ownerScope.targetId])).rows[0].n, 0);
  const redacted = (await runtime.query(`SELECT operation_id,state,context_json,request_json,proposal_json,
    result_json,intent_sha256,proposal_sha256,result_sha256
    FROM secureshop_review.chat_commerce_operations WHERE target_id=$1 ORDER BY operation_id`,
  [ownerScope.targetId])).rows;
  assert.ok(redacted.length > 0);
  assert.ok(redacted.every(row => row.state === 'redacted' && row.context_json === null
    && row.request_json === null && row.proposal_json === null && row.result_json === null));
  assert.deepEqual(redacted.map(({ state, context_json, request_json, proposal_json, result_json, ...row }) => row),
    ownerDigests, 'retirement clears private JSON while retaining immutable receipt digests');
  assert.equal((await runtime.query(`SELECT count(*)::int AS n FROM secureshop_review.chat_commerce_choices
    WHERE target_id=$1 AND state='redacted' AND context_json IS NULL AND snapshot_json IS NULL`,
  [ownerScope.targetId])).rows[0].n > 0, true);
  assert.equal((await runtime.query(`SELECT lifecycle FROM secureshop_review.product_targets
    WHERE target_id=$1`, [siblingScope.targetId])).rows[0].lifecycle, 'active');
  assert.equal((await runtime.query(`SELECT count(*)::int AS n FROM secureshop_review.practice_payment_methods
    WHERE target_id=$1`, [siblingScope.targetId])).rows[0].n, 1);
  assert.equal((await commerce.readOperation(sibling, { ...siblingActor,
    operationId: siblingMethod.operationId })).status, 'completed');
});
