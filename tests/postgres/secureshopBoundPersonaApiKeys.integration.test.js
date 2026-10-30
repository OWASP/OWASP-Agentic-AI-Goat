'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { randomUUID } = require('node:crypto');
const express = require('express');
const { Pool } = require('pg');
const { migrate } = require('../../db/postgres/migrate');
const { seedSecureShop } = require('../../server/database/postgres/secureshopSeed');
const { createSecureShopBoundPersonaRepository } = require(
  '../../server/database/postgres/secureshopBoundPersonaRepository');
const { createSecureShopBoundPersonaAuth } = require('../../server/services/secureshopBoundPersonaAuth');
const { createSecureShopConversationLifecycleRepository } = require(
  '../../server/database/postgres/secureshopConversationLifecycleRepository');
const { createSecureShopBoundCommerceRepository } = require(
  '../../server/database/postgres/secureshopBoundCommerceRepository');
const { createSecureShopBoundCommerce } = require('../../server/services/secureshopBoundCommerce');
const { createSecureShopBoundGateway } = require('../../server/routes/secureshop/boundGateway');

const PREFIX = 'PG_SECURESHOP_BOUND_PERSONA_API_KEYS_';
const stores = ['COMMERCE', 'REVIEW', 'FRESH_AGENTS', 'POPULATED_AGENTS'];
const enabled = process.env.PG_TEST_DISPOSABLE === 'yes'
  && stores.every(store => ['MIGRATION', 'RUNTIME']
    .every(role => process.env[`${PREFIX}${store}_${role}_URL`]));
const root = path.join(__dirname, '../..');
const agentsMigrations = path.join(root, 'db/postgres/workshop-migrations/secureshop_agents');
const secret = 'owned-api-key-secret-at-least-32-bytes';

function pool(url, max = 8) {
  return new Pool({ connectionString: url, max, statement_timeout: 15000,
    lock_timeout: 3000, application_name: 'owasp-ai-goat-api-key-native' });
}
function scope(overrides = {}) {
  return Object.freeze({ launchId: randomUUID(), scenarioId: randomUUID(), generation: 1,
    platformOwnerId: 9101, platformSessionId: 9201, ...overrides });
}
function assertDisposable(url) {
  const parsed = new URL(url);
  assert.ok(['127.0.0.1', 'localhost'].includes(parsed.hostname));
  assert.match(parsed.pathname, /^\/owasp_ai_goat_test_[a-z0-9_]+$/);
}
function copyPrefixThrough0015(t) {
  const workspace = process.env.OWASP_AI_GOAT_ISOLATED_TEST_WORKSPACE;
  assert.equal(typeof workspace, 'string');
  const directory = fs.mkdtempSync(path.join(workspace, 'agents-0015-prefix-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  for (const name of fs.readdirSync(agentsMigrations).sort()) {
    if (/^[0-9]{4}_/.test(name) && name <= '0015_secureshop_bound_password_overlay.sql') {
      fs.copyFileSync(path.join(agentsMigrations, name), path.join(directory, name));
    }
  }
  assert.equal(fs.readdirSync(directory).sort().at(-1),
    '0015_secureshop_bound_password_overlay.sql');
  return directory;
}
async function prepareCommerce(migration) {
  await migrate(migration, path.join(root, 'db/postgres/workshop-migrations/secureshop'));
  await migration.query('BEGIN');
  try { await seedSecureShop(migration); await migration.query('COMMIT'); }
  catch (error) { await migration.query('ROLLBACK'); throw error; }
}
function launches() {
  return { async assertCurrent(value) { return { ...value,
    expiresAt: new Date(Date.now() + 60 * 60000).toISOString() }; } };
}
async function waitForAdvisoryWaitCount(observer, expected) {
  const deadline = Date.now() + 3000;
  while (Date.now() < deadline) {
    const count = Number((await observer.query(`SELECT count(*)::integer AS count
      FROM pg_stat_activity WHERE application_name='owasp-ai-goat-api-key-native'
        AND wait_event_type='Lock' AND wait_event='advisory'`)).rows[0].count);
    if (count >= expected) return;
    await new Promise(resolve => setTimeout(resolve, 10));
  }
  throw new Error(`Expected ${expected} API-key advisory waiter(s)`);
}
async function prepareReview(migration, owner, shopUserId) {
  await migrate(migration, path.join(root, 'db/postgres/workshop-migrations/secureshop_review'));
  const targetId = randomUUID();
  await migration.query(`INSERT INTO secureshop_review.product_targets
    (target_id,launch_id,scenario_id,generation,original_platform_owner_id,
     original_platform_session_id,own_merchant_id,source_count,source_sha256)
    VALUES($1,$2,$3,$4,$5,$6,12,1,$7)`, [targetId, owner.launchId, owner.scenarioId,
    owner.generation, owner.platformOwnerId, owner.platformSessionId, Buffer.alloc(32, 1)]);
  await migration.query(`INSERT INTO secureshop_review.product_target_products
    (target_id,product_id,source_retailer_id,retailer_id,source_product_sha256,name,
     price,images,stock_quantity,status) VALUES($1,71,12,12,$2,'Owned snapshot',9.25,'[]',5,'active')`,
  [targetId, Buffer.alloc(32, 2)]);
  const ownOrder = Number((await migration.query(`INSERT INTO secureshop_review.product_target_orders
    (target_id,shop_user_id,total_amount,payment_method,shipping_address)
    VALUES($1,$2,9.25,'test','synthetic') RETURNING order_id`, [targetId, shopUserId])).rows[0].order_id);
  await migration.query(`INSERT INTO secureshop_review.product_target_order_items
    (target_id,order_id,product_id,product_name,quantity,price)
    VALUES($1,$2,71,'Purchased snapshot',1,9.25)`, [targetId, ownOrder]);
  const foreignOrder = Number((await migration.query(`INSERT INTO secureshop_review.product_target_orders
    (target_id,shop_user_id,total_amount,payment_method,shipping_address)
    VALUES($1,$2,9.25,'test','sibling') RETURNING order_id`, [targetId, shopUserId + 1000])).rows[0].order_id);
  return Object.freeze({ targetId, ownOrder, foreignOrder });
}
async function openApiGateway(t, { owner, sibling, targetId, personaAuth, reviewPool }) {
  const ownerBearer = 'g'.repeat(43); const siblingBearer = 'h'.repeat(43);
  const gatewayLaunches = { assertCurrent: launches().assertCurrent,
    async resolveCapability(value) { return value === ownerBearer ? owner
      : value === siblingBearer ? sibling : null; } };
  const repository = createSecureShopBoundCommerceRepository(reviewPool, {
    checkCurrent: gatewayLaunches.assertCurrent,
  });
  const catalog = {
    async prepareTarget(input) { return Object.freeze({ targetId, ...input.scope }); },
    async hasProduct() { return true; }, async listProducts() { return { products: [], count: 0, total: 0 }; },
    async getProduct() { return null; }, async listMerchantProducts() { return { products: [], total: 0 }; },
    async createMerchantProduct() { throw new Error('unused'); },
    async updateMerchantProduct() { throw new Error('unused'); },
    async archiveMerchantProduct() { throw new Error('unused'); },
    async categories() { return { categories: [] }; },
  };
  const commerce = createSecureShopBoundCommerce({ repository, catalog });
  const account = Object.fromEntries(['profile','updateProfile','addresses','createAddress',
    'updateAddress','deleteAddress'].map(name => [name, async () => ({})]));
  const app = express(); app.use(express.json());
  app.use('/api/secureshop', createSecureShopBoundGateway({ launches: gatewayLaunches,
    authenticatePersona(_req, res) { res.status(401).json({ error: 'unused' }); }, personaAuth,
    reviewsRouter: express.Router(), browserRouter: express.Router(), catalog, commerce, account }));
  const server = await new Promise(resolve => {
    const value = app.listen(0, '127.0.0.1', () => resolve(value));
  });
  t.after(() => new Promise(resolve => server.close(resolve)));
  return Object.freeze({ base: `http://127.0.0.1:${server.address().port}/api/secureshop`,
    ownerBearer, siblingBearer });
}

// Root launches this only against nonce-owned disposable PostgreSQL stores.
test('fresh 0016 binds API keys to one current launch and deletes them on retirement', {
  skip: !enabled, timeout: 60000,
}, async t => {
  const urls = Object.fromEntries(stores.flatMap(store => ['MIGRATION', 'RUNTIME'].map(role => {
    const key = `${PREFIX}${store}_${role}_URL`; assertDisposable(process.env[key]);
    return [`${store}_${role}`, process.env[key]];
  })));
  const commerceMigration = pool(urls.COMMERCE_MIGRATION);
  const commerceRuntime = pool(urls.COMMERCE_RUNTIME);
  const reviewMigration = pool(urls.REVIEW_MIGRATION);
  const reviewRuntime = pool(urls.REVIEW_RUNTIME);
  const migration = pool(urls.FRESH_AGENTS_MIGRATION);
  const runtime = pool(urls.FRESH_AGENTS_RUNTIME, 12);
  t.after(async () => Promise.allSettled([
    runtime.end(), migration.end(), reviewRuntime.end(), reviewMigration.end(),
    commerceRuntime.end(), commerceMigration.end(),
  ]));
  await prepareCommerce(commerceMigration);
  assert.equal((await migrate(migration, agentsMigrations)).at(-1),
    '0016_secureshop_bound_api_keys.sql');
  assert.deepEqual(await migrate(migration, agentsMigrations), []);

  const repository = createSecureShopBoundPersonaRepository({
    commercePool: commerceRuntime, agentsPool: runtime,
  });
  const keyBytes = [Buffer.alloc(16, 0x11), Buffer.alloc(16, 0x22),
    Buffer.alloc(16, 0x33), Buffer.alloc(16, 0x44)];
  const auth = createSecureShopBoundPersonaAuth({ repository, launches: launches(), jwtSecret: secret,
    randomKeyBytes: size => { assert.equal(size, 16); return keyBytes.shift(); } });
  const owner = scope();
  const sibling = scope({ platformOwnerId: owner.platformOwnerId + 1,
    platformSessionId: owner.platformSessionId + 1 });
  const customer = await repository.findCredential('student_customer', owner);
  const persona = { id: Number(customer.id), role: 'customer' };

  const first = await auth.rotateApiKey({ scope: owner, shopPersona: persona });
  assert.equal(first.version, 1);
  assert.deepEqual((await auth.authenticateApiKey({ scope: owner,
    presentedKey: first.api_key })).user.role, 'customer');
  await assert.rejects(auth.authenticateApiKey({ scope: sibling,
    presentedKey: first.api_key }), { code: 'SHOP_API_KEY_INVALID' });

  const orders = await prepareReview(reviewMigration, owner, persona.id);
  const api = await openApiGateway(t, { owner, sibling, targetId: orders.targetId,
    personaAuth: auth, reviewPool: reviewRuntime });
  const apiHeaders = { 'x-owasp-ai-goat-secureshop-launch': api.ownerBearer, 'x-api-key': first.api_key };
  const listed = await fetch(`${api.base}/v2/api/orders`, { headers: apiHeaders });
  assert.equal(listed.status, 200);
  assert.deepEqual((await listed.json()).orders.map(row => row.id), [orders.ownOrder]);
  const detail = await fetch(`${api.base}/v2/api/orders/${orders.ownOrder}`, { headers: apiHeaders });
  assert.equal(detail.status, 200);
  assert.equal((await detail.json()).items[0].name, 'Purchased snapshot');
  assert.equal((await fetch(`${api.base}/v2/api/orders/${orders.foreignOrder}`,
    { headers: apiHeaders })).status, 404);
  assert.equal((await fetch(`${api.base}/v2/api/orders`, { headers: {
    'x-owasp-ai-goat-secureshop-launch': api.siblingBearer, 'x-api-key': first.api_key,
  } })).status, 401);

  const second = await auth.rotateApiKey({ scope: owner, shopPersona: persona });
  assert.equal(second.version, 2);
  await assert.rejects(auth.authenticateApiKey({ scope: owner,
    presentedKey: first.api_key }), { code: 'SHOP_API_KEY_INVALID' });
  assert.equal((await fetch(`${api.base}/v2/api/orders`, { headers: apiHeaders })).status, 401);
  assert.equal((await fetch(`${api.base}/v2/api/orders`, { headers: {
    'x-owasp-ai-goat-secureshop-launch': api.ownerBearer, 'x-api-key': second.api_key,
  } })).status, 200);
  assert.equal((await auth.authenticateApiKey({ scope: owner,
    presentedKey: second.api_key })).apiKeyVersion, 2);

  const raced = await Promise.all([
    auth.rotateApiKey({ scope: owner, shopPersona: persona }),
    auth.rotateApiKey({ scope: owner, shopPersona: persona }),
  ]);
  assert.deepEqual(raced.map(row => row.version).sort((a, b) => a - b), [3, 4]);
  const winner = raced.find(row => row.version === 4);
  const loser = raced.find(row => row.version === 3);
  await assert.rejects(auth.authenticateApiKey({ scope: owner,
    presentedKey: loser.api_key }), { code: 'SHOP_API_KEY_INVALID' });
  assert.equal((await auth.authenticateApiKey({ scope: owner,
    presentedKey: winner.api_key })).apiKeyVersion, 4);

  const siblingKey = await repository.rotateApiKey({ scope: sibling,
    shopUserId: persona.id, nextKey: 'sk_ss_live_' + '5'.repeat(32) });
  const lifecycle = createSecureShopConversationLifecycleRepository({ pool: runtime });
  const resetId = randomUUID();
  await lifecycle.beginRetirement({ resetId, binding: owner });
  await lifecycle.completeRetirement({ resetId, binding: owner });
  const receipt = await repository.readApiKeyCleanupReceipt(owner);
  assert.equal(receipt.deletedApiKeyCount, 1);
  assert.match(receipt.receiptSha256, /^[0-9a-f]{64}$/);
  await assert.rejects(auth.authenticateApiKey({ scope: owner,
    presentedKey: winner.api_key }), { code: 'SHOP_API_KEY_INVALID' });
  assert.equal((await repository.authenticateApiKey({ scope: sibling,
    presentedKey: siblingKey.apiKey })).apiKeyVersion, 1);

  const raceScope = scope({ platformOwnerId: 9501, platformSessionId: 9601 });
  const raceKey = await repository.rotateApiKey({ scope: raceScope,
    shopUserId: persona.id, nextKey: 'sk_ss_live_' + '6'.repeat(32) });
  const blocker = await runtime.connect();
  let blockerTransaction = false;
  try {
    await blocker.query('BEGIN');
    blockerTransaction = true;
    await blocker.query('SELECT pg_advisory_xact_lock(hashtextextended($1,0))',
      [`secureshop-conversation-admission:${raceScope.launchId}`]);
    const raceReset = randomUUID();
    const retire = lifecycle.beginRetirement({ resetId: raceReset, binding: raceScope });
    const retireOutcome = retire.then(value => ({ value }), error => ({ error }));
    await waitForAdvisoryWaitCount(runtime, 1);
    const rotate = repository.rotateApiKey({ scope: raceScope, shopUserId: persona.id,
      nextKey: 'sk_ss_live_' + '7'.repeat(32) });
    const rotateOutcome = rotate.then(value => ({ value }), error => ({ error }));
    await waitForAdvisoryWaitCount(runtime, 2);
    await blocker.query('COMMIT');
    blockerTransaction = false;
    const retired = await retireOutcome;
    if (retired.error) throw retired.error;
    const rotated = await rotateOutcome;
    assert.equal(rotated.error?.code, '55000');
    const completed = await lifecycle.completeRetirement({ resetId: raceReset, binding: raceScope });
    const replayBegin = await lifecycle.beginRetirement({ resetId: raceReset, binding: raceScope });
    const replayComplete = await lifecycle.completeRetirement({ resetId: raceReset, binding: raceScope });
    assert.equal(replayBegin.status, 'completed');
    assert.equal(replayComplete.replayed, true);
    assert.deepEqual(replayComplete.receipt, completed.receipt);
    assert.equal((await repository.readApiKeyCleanupReceipt(raceScope)).deletedApiKeyCount, 1);
    assert.equal(await repository.authenticateApiKey({ scope: raceScope,
      presentedKey: raceKey.apiKey }), null);
  } finally {
    if (blockerTransaction) await blocker.query('ROLLBACK').catch(() => {});
    blocker.release();
  }

  const malformedKey = 'sk_ss_live_' + '8'.repeat(32);
  await assert.rejects(runtime.query(`INSERT INTO secureshop_agents.bound_persona_api_keys
    (platform_launch_id,platform_scenario_id,platform_launch_generation,
     original_platform_owner_id,original_platform_session_id,shop_user_id,
     api_key_plaintext,api_key_sha256,api_key_version)
    VALUES($1,$2,$3,$4,$5,$6,$7,$8,1)`, [sibling.launchId, sibling.scenarioId,
    sibling.generation, sibling.platformOwnerId, sibling.platformSessionId, persona.id,
    malformedKey, Buffer.alloc(32)]), { code: '55000' });
  await assert.rejects(runtime.query(`UPDATE secureshop_agents.bound_persona_api_keys
    SET api_key_sha256=$1,api_key_version=api_key_version+1
    WHERE platform_launch_id=$2 AND platform_scenario_id=$3
      AND platform_launch_generation=$4 AND original_platform_owner_id=$5
      AND original_platform_session_id=$6 AND shop_user_id=$7`, [Buffer.alloc(32),
    sibling.launchId, sibling.scenarioId, sibling.generation, sibling.platformOwnerId,
    sibling.platformSessionId, persona.id]), { code: '55000' });
  await assert.rejects(runtime.query(`DELETE FROM secureshop_agents.bound_persona_api_keys
    WHERE platform_launch_id=$1`, [sibling.launchId]), { code: '42501' });
  for (const sql of [
    `INSERT INTO secureshop_agents.bound_persona_api_key_cleanup_receipts
      (platform_launch_id,platform_scenario_id,platform_launch_generation,
       original_platform_owner_id,original_platform_session_id,deleted_api_key_count,receipt_sha256)
      VALUES(gen_random_uuid(),gen_random_uuid(),1,1,1,0,sha256('x'::bytea))`,
    `UPDATE secureshop_agents.bound_persona_api_key_cleanup_receipts SET deleted_api_key_count=1`,
    `DELETE FROM secureshop_agents.bound_persona_api_key_cleanup_receipts`,
    `SELECT secureshop_agents.guard_bound_persona_api_key_receipt()`,
  ]) await assert.rejects(runtime.query(sql), { code: '42501' });
});

test('populated 0015 retirement receives a zero key receipt and 0016 replays as no-op', {
  skip: !enabled, timeout: 30000,
}, async t => {
  const commerceMigration = pool(process.env[`${PREFIX}COMMERCE_MIGRATION_URL`]);
  const commerceRuntime = pool(process.env[`${PREFIX}COMMERCE_RUNTIME_URL`]);
  const migration = pool(process.env[`${PREFIX}POPULATED_AGENTS_MIGRATION_URL`]);
  const runtime = pool(process.env[`${PREFIX}POPULATED_AGENTS_RUNTIME_URL`]);
  t.after(async () => Promise.allSettled([
    runtime.end(), migration.end(), commerceRuntime.end(), commerceMigration.end(),
  ]));
  await prepareCommerce(commerceMigration);
  const prefix = copyPrefixThrough0015(t);
  assert.equal((await migrate(migration, prefix)).at(-1),
    '0015_secureshop_bound_password_overlay.sql');
  const repository = createSecureShopBoundPersonaRepository({
    commercePool: commerceRuntime, agentsPool: runtime,
  });
  await repository.ensureTemplates();
  const retired = scope({ platformOwnerId: 9301, platformSessionId: 9401 });
  const lifecycle = createSecureShopConversationLifecycleRepository({ pool: runtime });
  const resetId = randomUUID();
  await lifecycle.beginRetirement({ resetId, binding: retired });
  await lifecycle.completeRetirement({ resetId, binding: retired });

  assert.deepEqual(await migrate(migration, agentsMigrations),
    ['0016_secureshop_bound_api_keys.sql']);
  assert.deepEqual(await migrate(migration, agentsMigrations), []);
  const receipt = await repository.readApiKeyCleanupReceipt(retired);
  assert.equal(receipt.deletedApiKeyCount, 0);
  assert.match(receipt.receiptSha256, /^[0-9a-f]{64}$/);
  await assert.rejects(runtime.query(`UPDATE secureshop_agents.bound_persona_api_key_cleanup_receipts
    SET deleted_api_key_count=1 WHERE platform_launch_id=$1`, [retired.launchId]),
  { code: '42501' });
  await assert.rejects(migration.query(`UPDATE secureshop_agents.bound_persona_api_key_cleanup_receipts
    SET deleted_api_key_count=1 WHERE platform_launch_id=$1`, [retired.launchId]),
  { code: '55000' });
});
