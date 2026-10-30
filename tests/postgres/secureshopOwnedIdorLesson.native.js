'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { randomUUID, createHash } = require('node:crypto');
const { Pool } = require('pg');
const { migrate } = require('../../db/postgres/migrate');
const { initializeIdentityRepository } = require('../../server/database/postgres/identityRepository');
const { initializeSecureShopAgentsDb } = require('../../server/database/postgres/secureshopAgentsDb');
const { createSecureShopStandaloneAuthRepository } = require('../../server/database/postgres/secureshopStandaloneAuthRepository');
const { createSecureShopStandaloneAuthService } = require('../../server/services/secureshopStandaloneAuth');
const { createSecureShopLaunchRepository } = require('../../server/database/postgres/secureshopLaunchRepository');
const { createSecureShopSceneRepository } = require('../../server/database/postgres/secureshopSceneRepository');
const { createSecureShopScenes } = require('../../server/services/secureshopScenes');
const { createSecureShopBoundProductRepository } = require('../../server/database/postgres/secureshopBoundProductRepository');
const { createSecureShopBoundPersonaRepository } = require('../../server/database/postgres/secureshopBoundPersonaRepository');
const { createSecureShopBoundIdorLessonRepository, createImmutableTemplateVictimReader } =
  require('../../server/database/postgres/secureshopBoundIdorLessonRepository');

const ROOT = path.resolve(__dirname, '../..');
const DRAFT = path.join(ROOT, 'docs/secureshop/drafts/0048_owned_idor_lesson_receipts.sql');
const REVIEW_MIGRATIONS = path.join(ROOT, 'db/postgres/workshop-migrations/secureshop_review');
const ACTIVE = path.join(REVIEW_MIGRATIONS, path.basename(DRAFT));
const AGENT_MIGRATIONS = path.join(ROOT, 'db/postgres/workshop-migrations/secureshop_agents');
const PREFIX = 'OWNED_IDOR_NATIVE_';
const STORES = Object.freeze({ IDENTITY: 'identity', AGENTS: 'secureshop_agents',
  COMMERCE: 'secureshop', REVIEW: 'secureshop_review', FRESH: 'secureshop_review' });
const enabled = process.env.OWNED_IDOR_LESSON_NATIVE === '1' && process.env.PG_TEST_DISPOSABLE === 'yes';
const sha256 = value => createHash('sha256').update(value).digest('hex');

function admittedUrls() {
  const owner = process.env[`${PREFIX}OWNER`];
  assert.match(owner, /^[a-f0-9]{12}$/);
  assert.equal(path.resolve(process.cwd()), ROOT);
  assert.equal(path.resolve(process.env.OWASP_AI_GOAT_CURRENT_MAIN_WORKSPACE || '/'), ROOT);
  const urls = {}, databases = new Set();
  let port;
  for (const [store, family] of Object.entries(STORES)) {
    for (const role of ['RUNTIME', 'MIGRATION']) {
      const value = process.env[`${PREFIX}${store}_${role}_URL`];
      assert.ok(value, `${store} ${role} disposable URL required`);
      const url = new URL(value);
      assert.equal(url.protocol, 'postgresql:');
      assert.equal(url.hostname, '127.0.0.1');
      assert.equal(url.username, `dvaia_${family}_${role.toLowerCase()}`);
      assert.equal(url.password, '');
      assert.equal(url.search, '');
      assert.equal(url.hash, '');
      assert.equal(url.pathname, `/owasp_ai_goat_test_owned_idor_${owner}_${store.toLowerCase()}`);
      assert.ok(Number(url.port) > 0 && Number(url.port) <= 65535);
      if (port === undefined) port = url.port;
      else assert.equal(url.port, port);
      urls[`${store}_${role}`] = url.href;
    }
    assert.ok(!databases.has(urls[`${store}_RUNTIME`].split('/').at(-1)));
    databases.add(urls[`${store}_RUNTIME`].split('/').at(-1));
    assert.equal(new URL(urls[`${store}_RUNTIME`]).pathname,
      new URL(urls[`${store}_MIGRATION`]).pathname);
  }
  return urls;
}

async function candidateDirectory() {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'owasp-ai-goat-owned-idor-migration-'));
  for (const name of (await fs.readdir(REVIEW_MIGRATIONS)).filter(name => /^\d{4}_[a-z0-9_]+\.sql$/.test(name))) {
    if (name === path.basename(ACTIVE)) continue;
    assert.ok(Number(name.slice(0, 4)) < 48, 'only the reviewed 0048 successor may follow predecessors');
    await fs.symlink(path.join(REVIEW_MIGRATIONS, name), path.join(directory, name));
  }
  const bytes = await fs.readFile(DRAFT);
  assert.deepEqual(await fs.readFile(ACTIVE), bytes, 'active 0048 must match reviewed draft bytes');
  return { directory, checksum: sha256(bytes) };
}

test('owned IDOR migration qualifies only in five disposable stores with controlled mode tokens',
  { skip: !enabled, timeout: 180000 }, async t => {
    const urls = admittedUrls();
    const pools = Object.fromEntries(Object.entries(urls).map(([key, connectionString]) =>
      [key, new Pool({ connectionString, max: key.endsWith('RUNTIME') ? 8 : 2,
        connectionTimeoutMillis: 1500, statement_timeout: 8000 })]));
    t.after(async () => {
      const settled = await Promise.allSettled(Object.values(pools).map(pool => pool.end()));
      assert.ok(settled.every(item => item.status === 'fulfilled'), 'owned pools must close');
    });
    const view = await candidateDirectory();
    t.after(() => fs.rm(view.directory, { recursive: true, force: true }));
    const before = await fs.readFile(DRAFT);
    assert.equal(sha256(before), view.checksum);

    await initializeIdentityRepository(pools.IDENTITY_RUNTIME, pools.IDENTITY_MIGRATION);
    await migrate(pools.COMMERCE_MIGRATION, path.join(ROOT, 'db/postgres/workshop-migrations/secureshop'));
    await require('../../server/database/postgres/secureshopSeed').seedSecureShop(pools.COMMERCE_MIGRATION);
    await initializeSecureShopAgentsDb({ runtimePool: pools.AGENTS_RUNTIME,
      migrationPool: pools.AGENTS_MIGRATION });
    assert.deepEqual(await migrate(pools.AGENTS_MIGRATION, AGENT_MIGRATIONS), []);
    const purpose = (await pools.AGENTS_MIGRATION.query(`SELECT pg_get_constraintdef(c.oid) AS definition
      FROM pg_constraint c WHERE c.conrelid='secureshop_agents.agent_sessions'::regclass
      AND c.conname='agent_sessions_conversation_purpose_shape' AND c.convalidated`)).rows[0];
    assert.match(purpose.definition, /secureshop_idor_lesson/);
    const personas = createSecureShopBoundPersonaRepository({
      commercePool: pools.COMMERCE_RUNTIME, agentsPool: pools.AGENTS_RUNTIME });
    await personas.ensureTemplates();
    await migrate(pools.REVIEW_MIGRATION, view.directory);
    const freshApplied = await migrate(pools.FRESH_MIGRATION, REVIEW_MIGRATIONS);
    assert.equal(freshApplied.at(-1), path.basename(DRAFT));
    assert.deepEqual(await migrate(pools.FRESH_MIGRATION, REVIEW_MIGRATIONS), []);
    assert.equal((await pools.FRESH_MIGRATION.query(`SELECT checksum FROM dvaia_migrations.ledger
      WHERE name=$1`, [path.basename(DRAFT)])).rows[0].checksum, view.checksum);

    const standalone = slug => createSecureShopStandaloneAuthService({
      repository: createSecureShopStandaloneAuthRepository({ pool: pools.IDENTITY_RUNTIME,
        ...(slug ? { executionTenantSlug: slug } : {}) }),
      hashPassword: value => require('bcryptjs').hash(value, 4),
    });
    const defaultAuth = standalone();
    const launches = createSecureShopLaunchRepository(pools.IDENTITY_RUNTIME);
    const scenes = createSecureShopScenes({
      repository: createSecureShopSceneRepository({ pool: pools.IDENTITY_RUNTIME, launches }),
      reviewPool: pools.REVIEW_RUNTIME, launches,
    });
    const products = createSecureShopBoundProductRepository(pools.REVIEW_RUNTIME, {
      checkCurrent: scope => launches.assertCurrent(scope),
      checkCleanup: async () => { throw Error('Canonical reset required'); },
    });
    const suffix = randomUUID().slice(0, 8), password = 'disposable-owned-idor-only';
    async function owner(label, isolated = false) {
      const username = `${label}_${suffix}`;
      const registered = await defaultAuth.register({ username, email: `${username}@owned.invalid`,
        password, role: 'customer' });
      let service = defaultAuth, login = registered;
      if (isolated) {
        const tenantId = randomUUID(), slug = `owned_idor_${suffix}`;
        await pools.IDENTITY_MIGRATION.query(`INSERT INTO secureshop_auth.tenants(tenant_id,slug)
          VALUES($1,$2)`, [tenantId, slug]);
        await pools.IDENTITY_MIGRATION.query(`INSERT INTO secureshop_auth.tenant_memberships
          (tenant_id,principal_id,shop_user_id,role) VALUES($1,$2,$3,'customer')`,
        [tenantId,registered.context.principalId,registered.context.shopUserId]);
        service = standalone(slug);
        login = await service.login({ username, password });
      }
      const context = await service.establishTenantContext(login.context);
      const scope = (await launches.issueOrRenew({ platformOwnerId: context.ownerId,
        platformSessionId: context.sessionId, shopPrincipal: context,
        expiresAt: new Date(Date.now() + 30 * 60000).toISOString() })).binding;
      const reserved = await launches.reserveProductsTarget({ ...scope,
        expectedGeneration: scope.generation });
      await products.provision({ ...scope, targetId: reserved.targetId }, {
        ownMerchantId: 12, products: [{ id: 7, sourceRetailerId: 1, retailerId: 12,
          name: 'Owned IDOR fixture product', description: 'Synthetic disposable product',
          descriptionHtml: '<p>Synthetic disposable product</p>', price: 1, category: 'fixture',
          imageUrl: null, images: [], stockQuantity: 20, status: 'active',
          templateSource: '{{source}}', createdAt: null, updatedAt: null }],
      });
      const retainedScene = await scenes.resolve(scope);
      assert.equal(retainedScene.targetId, reserved.targetId);
      return { context, scope, retainedScene,
        persona: { id: context.shopUserId, role: 'customer' },
        personaSession: { sessionId: randomUUID(), authorityVersion: '1' } };
    }
    const primary = await owner('idor_primary'), sibling = await owner('idor_sibling', true);
    assert.notEqual(primary.scope.platformOwnerId, sibling.scope.platformOwnerId);
    assert.notEqual(primary.context.tenantId, sibling.context.tenantId);
    assert.notEqual(primary.retainedScene.targetId, sibling.retainedScene.targetId);
    const siblingRowsBefore = (await pools.REVIEW_RUNTIME.query(`SELECT * FROM
      secureshop_review.product_target_products WHERE target_id=$1 ORDER BY product_id`,
    [sibling.retainedScene.targetId])).rows;
    assert.ok(siblingRowsBefore.length > 0);

    const existingProducts = (await pools.REVIEW_RUNTIME.query(`SELECT *
      FROM secureshop_review.product_target_products WHERE target_id=$1 ORDER BY product_id`,
    [primary.retainedScene.targetId])).rows;
    assert.ok(existingProducts.length > 0, 'populated owner product exists before forward draft');
    assert.deepEqual(await migrate(pools.REVIEW_MIGRATION, REVIEW_MIGRATIONS), [path.basename(DRAFT)]);
    assert.deepEqual(await migrate(pools.REVIEW_MIGRATION, REVIEW_MIGRATIONS), []);
    assert.equal((await pools.REVIEW_MIGRATION.query(`SELECT checksum FROM dvaia_migrations.ledger
      WHERE name=$1`, [path.basename(DRAFT)])).rows[0].checksum, view.checksum);
    assert.deepEqual((await pools.REVIEW_RUNTIME.query(`SELECT *
      FROM secureshop_review.product_target_products WHERE target_id=$1 ORDER BY product_id`,
    [primary.retainedScene.targetId])).rows, existingProducts);
    const allowed = (await pools.REVIEW_RUNTIME.query(`SELECT
      has_table_privilege(current_user,'secureshop_review.owned_idor_lesson_births','SELECT') AS birth_select,
      has_table_privilege(current_user,'secureshop_review.owned_idor_lesson_births','INSERT') AS birth_insert,
      has_table_privilege(current_user,'secureshop_review.owned_idor_lesson_operations','SELECT') AS operation_select,
      has_table_privilege(current_user,'secureshop_review.owned_idor_lesson_operations','INSERT') AS operation_insert`)).rows[0];
    assert.deepEqual(allowed, { birth_select: true, birth_insert: true,
      operation_select: true, operation_insert: true });
    const privilege = (await pools.REVIEW_RUNTIME.query(`SELECT
      has_table_privilege(current_user,'secureshop_review.owned_idor_lesson_births','UPDATE') AS birth_update,
      has_table_privilege(current_user,'secureshop_review.owned_idor_lesson_operations','DELETE') AS operation_delete`)).rows[0];
    assert.equal(privilege.birth_update, false);
    assert.equal(privilege.operation_delete, false);

    const tokens = new WeakSet();
    const modeAuthority = { assertToken(token) {
      if (!tokens.has(token)) throw Error('Untrusted controlled mode token');
      return token;
    } };
    function mode(value) {
      const token = Object.freeze({ snapshot: Object.freeze({ version: 1,
        featureId: 'customer_idor', policyVersion: 'reserved-synthetic-cart-and-order-ownership-v1', mode: value,
        generation: 1, modeStamp: `${value}-controlled`, scope: primary.scope }),
      assertCurrentAtEffect: async () => {} });
      tokens.add(token); return token;
    }
    const repository = createSecureShopBoundIdorLessonRepository(pools.REVIEW_RUNTIME, {
      modeAuthority, readVictimIdentity: createImmutableTemplateVictimReader(pools.AGENTS_RUNTIME) });
    const base = { scope: primary.scope, persona: primary.persona,
      personaSession: primary.personaSession, retainedScene: primary.retainedScene };
    const prepared = await repository.prepare(base);
    const siblingBase = { scope: sibling.scope, persona: sibling.persona,
      personaSession: sibling.personaSession, retainedScene: sibling.retainedScene };
    const siblingPrepared = await repository.prepare(siblingBase);
    assert.notEqual(siblingPrepared.birth.birthId, prepared.birth.birthId);
    assert.equal(prepared.birth.victimId, 11);
    assert.equal(prepared.birth.attackerId, primary.persona.id);
    assert.equal(prepared.birth.orderPreimage.shippingAddress, 'Synthetic lesson address');
    assert.deepEqual(await repository.prepare(base), prepared);
    assert.deepEqual(await repository.readCards(base), prepared.cards);
    const birthRows = (await pools.REVIEW_RUNTIME.query(`SELECT count(*)::int AS n FROM
      secureshop_review.owned_idor_lesson_births WHERE target_id=$1`,
    [primary.retainedScene.targetId])).rows[0].n;
    assert.equal(birthRows, 1);
    const fixed = mode('fixed'), vuln = mode('vuln');
    const origin = (toolKey, callId) => ({ sessionId: randomUUID(), requestId: randomUUID(),
      runId: randomUUID(), step: 1, callId, toolKey });
    const fixedCart = await repository.execute({ ...base, modeToken: fixed, action: 'cart_remove',
      numericId: prepared.birth.cartItemId, turnOrigin: origin('lesson.cart_remove', 'fixed-cart') });
    assert.equal(fixedCart.result.status, 'denied');
    assert.equal((await pools.REVIEW_RUNTIME.query(`SELECT count(*)::int AS n FROM
      secureshop_review.product_target_cart_items WHERE target_id=$1 AND cart_item_id=$2`,
    [primary.retainedScene.targetId, prepared.birth.cartItemId])).rows[0].n, 1);
    const fixedOrder = await repository.execute({ ...base, modeToken: fixed, action: 'order_status',
      numericId: prepared.birth.orderId, turnOrigin: origin('lesson.order_status', 'fixed-order') });
    assert.deepEqual(fixedOrder.result, { status: 'denied', order: null });
    const disclosed = await repository.execute({ ...base, modeToken: vuln, action: 'order_status',
      numericId: prepared.birth.orderId, turnOrigin: origin('lesson.order_status', 'vuln-order') });
    assert.equal(disclosed.result.order.shippingAddress, 'Synthetic lesson address');
    assert.deepEqual(await repository.readSaved({ ...base, modeToken: vuln,
      operationId: disclosed.operationId }), disclosed);
    const source = origin('lesson.cart_remove', 'vuln-cart');
    const executeCart = () => repository.execute({ ...base, modeToken: vuln,
      action: 'cart_remove', numericId: prepared.birth.cartItemId, turnOrigin: source });
    const [left, right] = await Promise.all([executeCart(), executeCart()]);
    assert.deepEqual(left, right);
    assert.equal(left.result.status, 'deleted');
    assert.deepEqual(left.result.preimage, prepared.birth.cartPreimage);
    assert.deepEqual(await executeCart(), left);
    assert.equal((await pools.REVIEW_RUNTIME.query(`SELECT count(*)::int AS n FROM
      secureshop_review.owned_idor_lesson_operations WHERE operation_id=$1`,
    [left.operationId])).rows[0].n, 1);
    assert.equal((await pools.REVIEW_RUNTIME.query(`SELECT count(*)::int AS n FROM
      secureshop_review.product_target_cart_items WHERE target_id=$1 AND cart_item_id=$2`,
    [primary.retainedScene.targetId, prepared.birth.cartItemId])).rows[0].n, 0);
    assert.deepEqual(await repository.prepare(base), prepared, 'deleted cart is never recreated');
    await assert.rejects(repository.readSaved({ ...base, modeToken: vuln,
      retainedScene: sibling.retainedScene, operationId: left.operationId }));
    assert.deepEqual((await pools.REVIEW_RUNTIME.query(`SELECT * FROM
      secureshop_review.product_target_products WHERE target_id=$1 ORDER BY product_id`,
    [sibling.retainedScene.targetId])).rows, siblingRowsBefore);
    assert.deepEqual(await repository.readBirth(siblingBase), siblingPrepared.birth);
    const immutable = (await pools.REVIEW_MIGRATION.query(`SELECT birth_sha256,cart_preimage,
      order_preimage FROM secureshop_review.owned_idor_lesson_births WHERE birth_id=$1`,
    [prepared.birth.birthId])).rows[0];
    await launches.beginReset({ launchId: primary.scope.launchId,
      platformSessionId: primary.scope.platformSessionId,
      platformOwnerId: primary.scope.platformOwnerId,
      expectedGeneration: primary.scope.generation, idempotencyKey: randomUUID() });
    await assert.rejects(repository.readSaved({ ...base, modeToken: vuln,
      operationId: left.operationId }));
    await assert.rejects(repository.readCards(base));
    assert.deepEqual((await pools.REVIEW_MIGRATION.query(`SELECT birth_sha256,cart_preimage,
      order_preimage FROM secureshop_review.owned_idor_lesson_births WHERE birth_id=$1`,
    [prepared.birth.birthId])).rows[0], immutable, 'synthetic immutable audit remains after protected GET denial');
    assert.deepEqual((await pools.REVIEW_RUNTIME.query(`SELECT * FROM
      secureshop_review.product_target_products WHERE target_id=$1 ORDER BY product_id`,
    [sibling.retainedScene.targetId])).rows, siblingRowsBefore);
    assert.deepEqual(await repository.readBirth(siblingBase), siblingPrepared.birth);
    assert.equal(sha256(await fs.readFile(DRAFT)), view.checksum);
  });
