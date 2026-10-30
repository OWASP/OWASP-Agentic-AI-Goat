'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const { randomUUID, randomBytes, createHash } = require('node:crypto');
const bcrypt = require('bcryptjs');
const express = require('express');
const { Pool } = require('pg');
const {Module,createRequire}=require('node:module');
const { initializeIdentityRepository, createIdentityRepository } = require('../../server/database/postgres/identityRepository');
const { initializeSecureShopReviewDb } = require('../../server/database/postgres/secureshopReviewDb');
const { createSecureShopLaunchRepository } = require('../../server/database/postgres/secureshopLaunchRepository');
const { createSecureShopResetCleanupAuthorityRepository } = require('../../server/database/postgres/secureshopResetCleanupAuthorityRepository');
const { createSecureShopSceneRepository } = require('../../server/database/postgres/secureshopSceneRepository');
const { createSecureShopScenes } = require('../../server/services/secureshopScenes');
const { createSecureShopBoundProductRepository } = require('../../server/database/postgres/secureshopBoundProductRepository');
const { createSecureShopBoundReviewRepository } = require('../../server/database/postgres/secureshopBoundReviewRepository');
const { createSecureShopBoundCommerceRepository } = require('../../server/database/postgres/secureshopBoundCommerceRepository');
const { createBoundCouponRepository } = require('../../server/database/postgres/secureshopBoundCouponRepository');
const { createSecureShopBoundAccountRepository } = require('../../server/database/postgres/secureshopBoundAccountRepository');
const { createBoundAuditStore } = require('../../server/database/postgres/secureshopBoundAuditRepository');
const { initializeSecureShopAgentsDb } = require('../../server/database/postgres/secureshopAgentsDb');
const { createSecureShopBoundPersonaAuthority } = require('../../server/database/postgres/secureshopBoundPersonaAuthority');
const { createSecureShopBoundPersonaRepository } = require('../../server/database/postgres/secureshopBoundPersonaRepository');
const { createSecureShopBoundPersonaAuth } = require('../../server/services/secureshopBoundPersonaAuth');
const { createSecureShopSystemRestartRepository } = require('../../server/database/postgres/secureshopSystemRestartRepository');
const { createSecureShopModeRepository } = require('../../server/database/postgres/secureshopModeRepository');
const { createFeatureModeAuthority } = require('../../server/services/secureshopFeatureModeAuthority');
const { createSecureShopStandaloneMode } = require('../../server/services/secureshopStandaloneMode');
const { createSecureShopBoundCommerce } = require('../../server/services/secureshopBoundCommerce');
const { createSecureShopBoundAccount } = require('../../server/services/secureshopBoundAccount');
const { createSecureShopBoundGateway } = require('../../server/routes/secureshop/boundGateway');
const { createSecureShopManualReviewActions, createSecureShopBoundReviewTools } = require('../../server/services/secureshopBoundReviewTools');
const { createBoundReviewBatchAuthority } = require('../../server/services/secureshopBoundReviewBatchAuthority');
const reviewModeration = require('../../server/services/secureshopReviewModerationBinding');
const { PREFERRED_REVIEW_FIXTURES, LEGACY_REVIEW_FIXTURES, PROFILE_DIGESTS } = require('../../server/services/secureshopBoundReviewFixtureProfiles');

const prefix = 'PG_SECURESHOP_SCENE_';
const keys = ['IDENTITY_RUNTIME_URL', 'IDENTITY_MIGRATION_URL', 'REVIEW_RUNTIME_URL', 'REVIEW_MIGRATION_URL',
  'AGENTS_RUNTIME_URL','AGENTS_MIGRATION_URL','COMMERCE_RUNTIME_URL','COMMERCE_MIGRATION_URL'];
const enabled = process.env.SECURESHOP_SCENE_NATIVE === '1' && process.env.PG_TEST_DISPOSABLE === 'yes'
  && keys.every(key => process.env[prefix + key]);
function disposableUrl(key) {
  const url = new URL(process.env[prefix + key]);
  assert.equal(url.protocol, 'postgresql:');
  assert.equal(url.hostname, '127.0.0.1');
  assert.match(url.pathname, /^\/owasp_ai_goat_test_[a-z0-9_]+$/);
  assert.equal(url.password, '');
  assert.equal(url.search, '');
  assert.equal(url.hash, '');
  return url.href;
}
async function count(pool, table, where, args) {
  return Number((await pool.query(`SELECT count(*)::int AS n FROM ${table} WHERE ${where}`, args)).rows[0].n);
}
function historicalMigrator(directory,ceiling) {
  const filename=require.resolve('../../db/postgres/migrate'),local=createRequire(filename);
  const original=require('node:fs/promises');
  const virtual={...original,async readdir(target,...args){
    const names=await original.readdir(target,...args);
    return path.resolve(target)===directory?names.filter(name=>!/^\d{4}_/.test(name)
      ||Number(name.slice(0,4))<=ceiling):names;
  }};
  const loaded=new Module(filename,module);loaded.filename=filename;
  loaded.require=name=>name==='node:fs/promises'?virtual:local(name);
  loaded._compile(require('node:fs').readFileSync(filename,'utf8'),filename);
  return loaded.exports.migrate;
}

test('durable shop scene reopens customer state across logins and fences both current grants on reset',
  { skip: !enabled, timeout: 90000 }, async t => {
    assert.equal(path.resolve(process.env.OWASP_AI_GOAT_CURRENT_MAIN_WORKSPACE || '/'), process.cwd());
    const evidencePath = process.env.WORKSHOP_RAG_EVIDENCE_PATH || '';
    assert.ok(path.isAbsolute(evidencePath));
    assert.ok(!path.resolve(evidencePath).startsWith(`${process.cwd()}${path.sep}`));
    const identityMigration = new Pool({ connectionString: disposableUrl('IDENTITY_MIGRATION_URL'), max: 2 });
    const identity = new Pool({ connectionString: disposableUrl('IDENTITY_RUNTIME_URL'), max: 8 });
    const reviewMigration = new Pool({ connectionString: disposableUrl('REVIEW_MIGRATION_URL'), max: 2 });
    const review = new Pool({ connectionString: disposableUrl('REVIEW_RUNTIME_URL'), max: 8 });
    const agentsMigration = new Pool({connectionString:disposableUrl('AGENTS_MIGRATION_URL'),max:2});
    const agents = new Pool({connectionString:disposableUrl('AGENTS_RUNTIME_URL'),max:8});
    const commerceMigration = new Pool({connectionString:disposableUrl('COMMERCE_MIGRATION_URL'),max:2});
    const commerceStore = new Pool({connectionString:disposableUrl('COMMERCE_RUNTIME_URL'),max:8});
    t.after(() => Promise.allSettled([identity.end(), identityMigration.end(), review.end(), reviewMigration.end(),
      agents.end(),agentsMigration.end(),commerceStore.end(),commerceMigration.end()]));
    const identityDirectory=path.resolve(__dirname,'../../db/postgres/identity-migrations');
    await historicalMigrator(identityDirectory,140)(identityMigration,identityDirectory);
    const modeSql=await fs.readFile(path.join(identityDirectory,'0141_secureshop_tenant_modes.sql'),'utf8');
    const preview=await identityMigration.connect();
    try {
      await preview.query('BEGIN');await preview.query(modeSql);
      assert.equal((await preview.query('SELECT count(*)::int n FROM secureshop_auth.tenant_modes')).rows[0].n,0);
      await preview.query('ROLLBACK');
    } finally {await preview.query('ROLLBACK');preview.release();}
    // Seed a genuine 0140 principal, membership and session using only columns
    // present in that historical schema. The current auth repository requires
    // 0148's renewed_from_session_id and cannot run before its migration.
    const preModePrincipalId=randomUUID();
    const preModePasswordHash=await bcrypt.hash('disposable-scene-fixture',4);
    const preModePrincipal=(await identity.query(`INSERT INTO secureshop_auth.principals
      (principal_id,username,email,password_hash,role) VALUES($1,$2,$3,$4,'customer')
      RETURNING shop_user_id`,[preModePrincipalId,'mode_before_migration',
      'mode_before@fixture.invalid',preModePasswordHash])).rows[0];
    const preModeTenant=(await identity.query(`SELECT tenant_id FROM secureshop_auth.tenants
      WHERE slug='default'`)).rows[0];
    assert.ok(preModePrincipal?.shop_user_id>0 && preModeTenant?.tenant_id);
    await identity.query(`INSERT INTO secureshop_auth.tenant_memberships
      (tenant_id,principal_id,shop_user_id,role) VALUES($1,$2,$3,'customer')`,
    [preModeTenant.tenant_id,preModePrincipalId,preModePrincipal.shop_user_id]);
    const preModeSession=(await identity.query(`INSERT INTO secureshop_auth.sessions
      (principal_id,token_hash,credential_version,authority_version,expires_at)
      VALUES($1,$2,1,1,clock_timestamp()+interval '30 minutes') RETURNING session_id`,
    [preModePrincipalId,createHash('sha256').update(randomUUID()).digest('hex')])).rows[0];
    assert.ok(preModeSession?.session_id>0);
    await initializeIdentityRepository(identity, identityMigration);
    assert.equal((await identity.query('SELECT mode FROM secureshop_auth.tenant_modes WHERE principal_id=$1',
      [preModePrincipalId])).rows[0].mode,'vuln');
    assert.deepEqual((await identity.query(`SELECT tenant_id,membership_version::text AS version
      FROM secureshop_auth.session_membership_snapshots WHERE session_id=$1`,
    [preModeSession.session_id])).rows,[{tenant_id:preModeTenant.tenant_id,version:'1'}]);
    await initializeSecureShopReviewDb(review, reviewMigration);
    await initializeSecureShopAgentsDb({runtimePool:agents,migrationPool:agentsMigration});
    await require('../../db/postgres/migrate').migrate(commerceMigration,
      'db/postgres/workshop-migrations/secureshop');
    await require('../../server/database/postgres/secureshopSeed').seedSecureShop(commerceMigration);
    assert.deepEqual(await initializeIdentityRepository(identity, identityMigration), []);
    await initializeSecureShopReviewDb(review, reviewMigration);

    const identities = createIdentityRepository(identity);
    const launches = createSecureShopLaunchRepository(identity);
    const cleanupAuthority = createSecureShopResetCleanupAuthorityRepository(identity);
    const scenes = createSecureShopScenes({ repository: createSecureShopSceneRepository({ pool: identity, launches }),
      reviewPool: review, launches });
    const checkCurrent = scope => launches.assertCurrent(scope);
    const auditStore = createBoundAuditStore({ store: 'review', pool: review });
    const products = createSecureShopBoundProductRepository(review, {
      checkCurrent, auditStore, checkCleanup: async () => { throw new Error('cleanup outside scene fixture'); },
    });
    const commerce = createSecureShopBoundCommerceRepository(review, { checkCurrent, auditStore });
    const accounts = createSecureShopBoundAccountRepository(review, { checkCurrent, auditStore });
    const passwordHash = await bcrypt.hash('disposable-scene-fixture', 4);
    async function owner(label) {
      return identities.createUser({ username: `${label}-${randomUUID().slice(0, 8)}`,
        email: `${randomUUID()}@scene.invalid`, passwordHash });
    }
    async function login(user) {
      const token = randomUUID();
      const expiresAt = new Date(Date.now() + 3600000);
      const session = await identities.createSession({ userId: user.id, token, expiresAt, expectedPasswordHash: passwordHash });
      const issued = await launches.issueOrRenew({ platformOwnerId: user.id,
        platformSessionId: session.id, expiresAt });
      return { user, token, session, scope: issued.binding };
    }
    const product = { id: 7, sourceRetailerId: 1, retailerId: 12, name: 'Retained synthetic item',
      description: 'Owned disposable scene product', descriptionHtml: '<p>Owned disposable scene product</p>',
      price: 12.5, category: 'fixture', imageUrl: null, images: [], stockQuantity: 40,
      status: 'active', templateSource: '{{source}}', createdAt: null, updatedAt: null };
    async function provision(current) {
      const reserved = await launches.reserveProductsTarget({ ...current.scope,
        expectedGeneration: current.scope.generation });
      await products.provision({ ...current.scope, targetId: reserved.targetId },
        { ownMerchantId: 12, products: [product] });
      const bound = await scenes.resolve(current.scope);
      assert.ok(bound?.scene);
      return bound;
    }

    const customer = await owner('scene-customer');
    const sibling = await owner('scene-sibling');
    const first = await login(customer);
    const firstTarget = await provision(first);
    const sceneId = firstTarget.scene.sceneId;
    const birthTargetId = firstTarget.targetId;
    const persona = { id: 11, role: 'customer' };
    const address = { label: 'Home', line1: '11 Fixture Way', line2: null,
      city: 'Test City', state: 'CA', zip: '90001', phone: null, isDefault: true };
    await accounts.updateProfile(firstTarget, persona.id,
      { email: 'retained@scene.invalid', fullName: 'Retained Customer', phone: '555-0101' }, persona);
    const savedAddress = await accounts.saveAddress(firstTarget, persona.id, null, address, persona);
    await commerce.addCart(firstTarget, { shopUserId: persona.id, productId: product.id, quantity: 2 });
    const purchase = await commerce.checkout(firstTarget, { shopUserId: persona.id,
      shippingAddress: '11 Fixture Way', paymentMethod: 'fixture-card' });
    assert.equal(purchase.total, 25);
    await commerce.addCart(firstTarget, { shopUserId: persona.id, productId: product.id, quantity: 1 });
    await identities.revokeSession(first.token, customer.id, 'logout');
    await assert.rejects(commerce.listCart(firstTarget, persona.id));
    assert.equal((await identity.query(`SELECT status FROM identity.secureshop_scenes WHERE scene_id=$1`,
      [sceneId])).rows[0].status, 'active', 'logout retains the shop scene');

    const second = await login(customer);
    const secondTarget = await scenes.resolve(second.scope);
    assert.equal(secondTarget.targetId, birthTargetId);
    assert.equal(secondTarget.launchId, first.scope.launchId, 'storage keeps its birth launch');
    assert.equal(secondTarget.scene.execution.launchId, second.scope.launchId,
      'reopened effects use the new platform execution');
    assert.equal((await commerce.listCart(secondTarget, persona.id)).items[0].quantity, 1);
    const orders = await commerce.listOrders(secondTarget, persona.id);
    assert.equal(orders.length, 1);
    assert.equal(orders[0].id, purchase.orderId);
    assert.equal((await accounts.readProfile(secondTarget, persona.id)).full_name, 'Retained Customer');
    assert.equal((await accounts.listAddresses(secondTarget, persona.id))[0].id, savedAddress.id);
    assert.equal((await scenes.list(second.scope)).length, 1);
    await assert.rejects(commerce.listCart({ ...secondTarget }, persona.id), { code: 'SHOP_SCENE_STALE' });

    const siblingLogin = await login(sibling);
    const siblingTarget = await provision(siblingLogin);
    await commerce.addCart(siblingTarget, { shopUserId: persona.id, productId: product.id, quantity: 4 });
    await assert.rejects(scenes.select(second.scope, siblingTarget.scene.sceneId), { code: 'SHOP_SCENE_STALE' });
    assert.equal((await commerce.listCart(siblingTarget, persona.id)).items[0].quantity, 4);
    assert.equal((await scenes.list(second.scope)).length, 1);
    assert.equal((await scenes.list(siblingLogin.scope)).length, 1);

    const third = await login(customer);
    const thirdTarget = await scenes.resolve(third.scope);
    assert.equal(thirdTarget.targetId, birthTargetId);
    assert.notEqual(thirdTarget.scene.grantId, secondTarget.scene.grantId);
    await Promise.all([
      commerce.addCart(secondTarget, { shopUserId: persona.id, productId: product.id, quantity: 1 }),
      commerce.addCart(thirdTarget, { shopUserId: persona.id, productId: product.id, quantity: 1 }),
    ]);
    assert.equal((await commerce.listCart(secondTarget, persona.id)).items[0].quantity, 3);
    assert.equal((await commerce.listCart(thirdTarget, persona.id)).items[0].quantity, 3);
    const audit = (await review.query(`SELECT launch_id,scenario_id,generation,params_json
      FROM secureshop_review.bound_audit_events WHERE action='cart_add' AND launch_id=$1
      ORDER BY created_at DESC LIMIT 1`, [second.scope.launchId])).rows[0];
    assert.equal(audit.scenario_id, second.scope.scenarioId);
    assert.equal(Number(audit.generation), second.scope.generation);
    assert.equal(JSON.parse(audit.params_json).storageTargetId, birthTargetId);
    assert.equal(JSON.parse(audit.params_json).sceneId, sceneId);
    const grants = (await identity.query(`SELECT launch_id FROM identity.secureshop_scene_execution_grants
      WHERE scene_id=$1 ORDER BY launch_id`, [sceneId])).rows.map(row => row.launch_id);
    assert.deepEqual(new Set(grants), new Set([first.scope.launchId, second.scope.launchId, third.scope.launchId]));
    assert.equal((await review.query(`SELECT count(*)::int n FROM secureshop_review.scene_execution_grants
      WHERE scene_id=$1`, [sceneId])).rows[0].n, 3);

    await launches.beginReset({ launchId: third.scope.launchId, platformSessionId: third.session.id,
      platformOwnerId: customer.id, expectedGeneration: third.scope.generation,
      idempotencyKey: 'retire-scene-third-execution' });
    assert.equal((await identity.query(`SELECT status FROM identity.secureshop_scenes WHERE scene_id=$1`,
      [sceneId])).rows[0].status, 'retired');
    await assert.rejects(commerce.listCart(secondTarget, persona.id), { code: 'SHOP_SCENE_STALE' });
    await assert.rejects(commerce.listCart(thirdTarget, persona.id));
    assert.equal((await review.query(`SELECT count(*)::int n FROM secureshop_review.product_target_orders
      WHERE target_id=$1`, [birthTargetId])).rows[0].n, 1,
    'reset fences authority without deleting the retained order evidence');
    assert.equal((await review.query(`SELECT count(*)::int n FROM secureshop_review.product_target_cart_items
      WHERE target_id=$1`, [birthTargetId])).rows[0].n, 1);
    assert.equal((await commerce.listCart(siblingTarget, persona.id)).items[0].quantity, 4);
    const fresh = await login(customer);
    assert.equal(await scenes.resolve(fresh.scope), null, 'retired scene is not silently rebound');
    const retainedOrderCount = (await review.query(`SELECT count(*)::int n
      FROM secureshop_review.product_target_orders WHERE target_id=$1`, [birthTargetId])).rows[0].n;
    const freshTarget = await provision(fresh);
    assert.notEqual(freshTarget.targetId, birthTargetId,
      'a post-reset login provisions a distinct product target');
    assert.notEqual(freshTarget.scene.sceneId, sceneId,
      'a post-reset login provisions a distinct shop scene');
    assert.equal((await identity.query(`SELECT status FROM identity.secureshop_scenes WHERE scene_id=$1`,
      [sceneId])).rows[0].status, 'retired');
    assert.equal((await review.query(`SELECT count(*)::int n FROM secureshop_review.product_target_orders
      WHERE target_id=$1`, [birthTargetId])).rows[0].n, retainedOrderCount,
    'new target provisioning preserves immutable rows from the retired target');
    // The standalone storefront shares one tenant target while preserving each
    // account's private rows. These are real auth/scene/catalog repositories;
    // only the immutable seed product source is a bounded fixture.
    const { createSecureShopStandaloneAuthRepository } = require('../../server/database/postgres/secureshopStandaloneAuthRepository');
    const { createSecureShopStandaloneAuthService } = require('../../server/services/secureshopStandaloneAuth');
    const { createSecureShopBoundCatalog } = require('../../server/services/secureshopBoundCatalog');
    const { createSecureShopStorePublicCatalogRepository } = require('../../server/database/postgres/secureshopStorePublicCatalogRepository');
    const standaloneRepository=createSecureShopStandaloneAuthRepository({pool:identity});
    const standalone = createSecureShopStandaloneAuthService({
      repository: standaloneRepository,
      hashPassword: async () => passwordHash,
    });
    const personaAuthority=createSecureShopBoundPersonaAuthority({pool:agents,checkCurrent});
    const personaRepository=createSecureShopBoundPersonaRepository({commercePool:commerceStore,agentsPool:agents,personaAuthority});
    const personaAuth=createSecureShopBoundPersonaAuth({repository:personaRepository,personaAuthority,launches,
      jwtSecret:'disposable-scene-persona-secret-with-more-than-thirty-two-bytes'});
    async function shopAccount(role) {
      const suffix=randomUUID().slice(0,8);
      const account=await standalone.register({username:`shop_${suffix}`,email:`${suffix}@tenant.invalid`,
        password:'disposable-scene-fixture',role});
      const execution=await standalone.establishTenantContext(account.context);
      const issued=await launches.issueOrRenew({platformOwnerId:execution.ownerId,
        platformSessionId:execution.sessionId,expiresAt:new Date(Date.now()+1800000),shopPrincipal:execution});
      const issuedActor=await personaAuth.establishSession({scope:issued.binding,shopPrincipal:execution});
      const actor=await personaAuth.authenticateBoundToken({scope:issued.binding,token:issuedActor.token});
      return {account,execution,scope:issued.binding,persona:actor.user,
        personaSession:{sessionId:actor.sessionId,authorityVersion:actor.authorityVersion},
        bearer:issued.bearer,token:issuedActor.token};
    }
    const buyer=await shopAccount('customer'),otherBuyer=await shopAccount('customer');
    const seller=await shopAccount('merchant'),otherSeller=await shopAccount('merchant');
    assert.equal(buyer.execution.ownerId,seller.execution.ownerId);
    assert.notEqual(buyer.execution.shopUserId,seller.execution.shopUserId);
    await identity.query(`UPDATE secureshop_auth.tenants SET seed_merchant_id=$1
      WHERE tenant_id=$2 AND seed_merchant_id IS NULL`,[seller.persona.id,seller.execution.tenantId]);
    const sourcePool={async query(){return {rows:[5,9].map((retailer,id)=>({id:id+7,
      retailer_id:retailer,retailer_role:'merchant',name:`Tenant product ${id}`,description:'Synthetic fixture',
      description_html:'<p>Synthetic fixture</p>',price:'12.50',category:'fixture',image_url:null,images:[],
      stock_quantity:40,status:'active',template_source:'{{source}}',created_at:null,updated_at:null}))};}};
    const catalog=createSecureShopBoundCatalog({sourcePool,repository:products,scenes,checkCurrent,
      resolveTarget:scope=>launches.reserveProductsTarget({...scope,expectedGeneration:scope.generation})});
    const modeRepository=createSecureShopModeRepository(identity);
    const modeAuthority=createFeatureModeAuthority({progress:modeRepository,launches});
    const ownMode=createSecureShopStandaloneMode({authService:standalone,repository:modeRepository});
    const receiptRepository=createSecureShopBoundCommerceRepository(review,{checkCurrent,auditStore,
      couponRepository:createBoundCouponRepository({pool:review,checkCurrent})});
    const commerceService=createSecureShopBoundCommerce({repository:receiptRepository,catalog,
      personaAuthority,modeAuthority,resolveExistingTarget:scope=>scenes.readExisting(scope)});
    const [buyerTarget,sellerTarget]=await Promise.all([catalog.prepareTarget(buyer),catalog.prepareTarget(seller)]);
    assert.equal(buyerTarget.targetId,sellerTarget.targetId,'concurrent first visitors must share one snapshot');
    assert.equal((await identity.query(`SELECT count(*)::int n FROM identity.secureshop_scenes
      WHERE original_platform_owner_id=$1 AND status='active'`,[buyer.execution.ownerId])).rows[0].n,1);
    assert.equal((await products.open(buyerTarget)).ownMerchantId,seller.persona.id,
      'seed inventory ownership must not depend on which customer arrived first');
    assert.equal((await commerceService.cart(buyer)).items.length,0);
    await t.test('real System restart authority fence remains non-reentrant and preserves operation readback',
      { timeout: 30000 }, async () => {
        const defaults = await require('../../server/database/postgres/secureshopStandaloneSeed')
          .seedSecureShopStandaloneDefaults(identityMigration);
        assert.equal(defaults.seeded, true);
        const adminLogin = await standalone.login({ username: 'student_admin', password: 'student123' });
        const adminExecution = await standalone.establishTenantContext(adminLogin.context);
        assert.equal(adminExecution.ownerId, seller.execution.ownerId);
        const issued = await launches.issueOrRenew({ platformOwnerId: adminExecution.ownerId,
          platformSessionId: adminExecution.sessionId,
          expiresAt: new Date(Date.now() + 1800000), shopPrincipal: adminExecution });
        const session = await personaAuth.establishSession({ scope: issued.binding,
          shopPrincipal: adminExecution });
        const authenticated = await personaAuth.authenticateBoundToken({ scope: issued.binding,
          token: session.token });
        const admin = { scope: issued.binding, persona: { id: authenticated.user.id, role: 'admin' },
          personaSession: { sessionId: authenticated.sessionId,
            authorityVersion: authenticated.authorityVersion } };
        const target = await catalog.prepareTarget(admin);
        assert.equal(target.targetId, sellerTarget.targetId);
        const restart = createSecureShopSystemRestartRepository({ pool: review,
          personaAuthority, audit: auditStore });
        assert.deepEqual(await restart.checkReadiness(), { ready: true });
        const operationId = randomUUID(), instanceId = randomUUID();
        const request = { ...admin, operationId, version: 1, name: 'nginx' };
        assert.deepEqual(await restart.ensureTarget(request, { targetId: target.targetId,
          instanceId, generation: 1, binding: target }),
        { targetId: target.targetId, instanceId, generation: 1 });
        const begun = await restart.begin(request, { targetId: target.targetId, binding: target });
        assert.equal(begun.state, 'running');
        assert.equal((await restart.operation({ ...admin, operationId }, target)).state, 'running');
        assert.deepEqual(await restart.begin(request, { targetId: target.targetId, binding: target }), begun);
        await assert.rejects(restart.operation({ ...admin,
          personaSession: { ...admin.personaSession, sessionId: randomUUID() }, operationId }, target),
        { code: 'SHOP_AUTH_INVALID' });
        const failed = await restart.fail(request, { workerToken: begun.workerToken,
          code: 'EXECUTION_FAILED', binding: target });
        assert.equal(failed.state, 'failed');
        assert.deepEqual(await restart.operation({ ...admin, operationId }, target), failed);
        assert.deepEqual(await restart.checkReadiness(), { ready: true });
      });
    const captured=await modeAuthority.capture(buyer.scope,'coupons');
    const siblingMode=await modeAuthority.capture(otherBuyer.scope,'coupons');
    assert.equal(captured.snapshot.mode,'vuln');
    await captured.assertCurrentAtEffect();
    const initialMode=await ownMode.get(buyer.account.context);
    const fixed=await ownMode.set(buyer.account.context,{mode:'fixed',expectedRevision:initialMode.revision});
    assert.equal(fixed.mode,'fixed');
    await assert.rejects(captured.assertCurrentAtEffect(),{code:'ANALYTICS_MODE_STALE'});
    await assert.rejects(ownMode.set(buyer.account.context,{mode:'vuln',expectedRevision:initialMode.revision}),
      {code:'SHOP_MODE_CONFLICT'});
    assert.equal((await ownMode.get(otherBuyer.account.context)).mode,'vuln');
    assert.equal((await modeAuthority.capture(otherBuyer.scope,'coupons')).snapshot.modeStamp,
      siblingMode.snapshot.modeStamp);
    await siblingMode.assertCurrentAtEffect();
    assert.equal((await ownMode.get(seller.account.context)).mode,'vuln');
    const fixedCapture=await modeAuthority.capture(buyer.scope,'coupons');
    assert.equal(fixedCapture.snapshot.mode,'fixed');
    await fixedCapture.assertCurrentAtEffect();
    await commerceService.add({...buyer,productId:7,quantity:2});
    assert.equal((await commerceService.cart(buyer)).items[0].quantity,2);
    await commerceService.merchantOverview({...seller,days:30});
    assert.deepEqual(await initializeIdentityRepository(identity,identityMigration),[]);
    assert.deepEqual(await ownMode.get(buyer.account.context),fixed,'no-op initialization preserves selected mode/revision');
    const accountService=createSecureShopBoundAccount({repository:accounts,
      personaRepository,catalog,personaAuthority});
    const gateway=createSecureShopBoundGateway({launches,authenticatePersona:personaAuth.authenticatePersona,
      personaAuth,reviewsRouter:express.Router(),browserRouter:express.Router(),catalog,
      commerce:commerceService,account:accountService,scenes});
    const httpApp=express();httpApp.use(express.json());httpApp.use('/api/secureshop',gateway);
    const httpServer=await new Promise(resolve=>{
      const server=httpApp.listen(0,'127.0.0.1',()=>resolve(server));
    });
    t.after(()=>new Promise(resolve=>httpServer.close(resolve)));
    const base=`http://127.0.0.1:${httpServer.address().port}/api/secureshop`;
    const headers=actor=>({'x-owasp-ai-goat-secureshop-launch':actor.bearer,
      authorization:`Bearer ${actor.token}`,'content-type':'application/json'});
    const checkoutRequest={shipping_address:'Tenant fixture address',payment_method:'fixture-card',
      operationId:randomUUID()};
    const checkoutPost=actor=>fetch(`${base}/orders`,{method:'POST',headers:headers(actor),
      body:JSON.stringify(checkoutRequest)});
    const firstCheckout=await checkoutPost(buyer);
    assert.equal(firstCheckout.status,200);
    const checkoutReceipt=await firstCheckout.json();
    assert.equal(checkoutReceipt.ok,true);
    assert.equal(checkoutReceipt.total,25);
    const replayCheckout=await checkoutPost(buyer);
    assert.equal(replayCheckout.status,200);
    assert.deepEqual(await replayCheckout.json(),checkoutReceipt,'exact HTTP retry returns the same order');
    const changedCheckout=await fetch(`${base}/orders`,{method:'POST',headers:headers(buyer),
      body:JSON.stringify({...checkoutRequest,shipping_address:'Changed fixture address'})});
    assert.equal(changedCheckout.status,409,'same operation UUID cannot be reused for a different intent');
    assert.equal((await changedCheckout.json()).error,'Commerce operation conflicts with this request');
    const tenantPurchase={orderId:checkoutReceipt.order_id,total:checkoutReceipt.total};
    const durableReceipt=(await review.query(`SELECT operation_id,target_id,shop_user_id,kind,
      persona_session_id,authority_version,state,request_json,result_json,request_sha256,result_sha256
      FROM secureshop_review.bound_commerce_operations WHERE operation_id=$1`,
    [checkoutRequest.operationId])).rows;
    assert.equal(durableReceipt.length,1);
    assert.equal(durableReceipt[0].target_id,buyerTarget.targetId);
    assert.equal(Number(durableReceipt[0].shop_user_id),buyer.persona.id);
    assert.equal(durableReceipt[0].persona_session_id,buyer.personaSession.sessionId);
    assert.equal(durableReceipt[0].authority_version,buyer.personaSession.authorityVersion);
    assert.equal(durableReceipt[0].kind,'checkout');
    assert.equal(durableReceipt[0].state,'completed');
    assert.match(durableReceipt[0].request_sha256,/^[a-f0-9]{64}$/);
    assert.match(durableReceipt[0].result_sha256,/^[a-f0-9]{64}$/);
    assert.equal(createHash('sha256').update(durableReceipt[0].request_json).digest('hex'),
      durableReceipt[0].request_sha256);
    assert.equal(createHash('sha256').update(durableReceipt[0].result_json).digest('hex'),
      durableReceipt[0].result_sha256);
    assert.equal(JSON.parse(durableReceipt[0].request_json).scope.launchId,buyer.scope.launchId);
    assert.equal(JSON.parse(durableReceipt[0].request_json).operationId,checkoutRequest.operationId);
    assert.equal(JSON.parse(durableReceipt[0].result_json).orderId,tenantPurchase.orderId);
    assert.equal(await count(review,'secureshop_review.product_target_orders',
      'target_id=$1 AND shop_user_id=$2',[buyerTarget.targetId,buyer.persona.id]),1);
    assert.equal(await count(review,'secureshop_review.product_target_order_items',
      'target_id=$1 AND order_id=$2',[buyerTarget.targetId,tenantPurchase.orderId]),1);
    const savedLine=(await review.query(`SELECT product_id,quantity,price FROM secureshop_review.product_target_order_items
      WHERE target_id=$1 AND order_id=$2`,[buyerTarget.targetId,tenantPurchase.orderId])).rows[0];
    assert.equal(Number(savedLine.product_id),7);
    assert.equal(Number(savedLine.quantity),2);
    assert.equal(Number(savedLine.price),12.5);
    assert.equal(await count(review,'secureshop_review.product_target_cart_items',
      'target_id=$1 AND shop_user_id=$2',[buyerTarget.targetId,buyer.persona.id]),0);
    assert.equal(Number((await review.query(`SELECT stock_quantity FROM secureshop_review.product_target_listing_overlays
      WHERE target_id=$1 AND product_id=7`,[buyerTarget.targetId])).rows[0].stock_quantity),38,
    'same operation replay consumes stock once');
    const cartAfterCheckout=await fetch(`${base}/cart`,{headers:headers(buyer)});
    assert.equal(cartAfterCheckout.status,200);
    assert.deepEqual((await cartAfterCheckout.json()).items,[],
      'committed checkout clears only the buyer cart');
    const buyerOrder=await fetch(`${base}/orders/${tenantPurchase.orderId}`,{headers:headers(buyer)});
    assert.equal(buyerOrder.status,200);
    assert.equal((await buyerOrder.json()).order.id,tenantPurchase.orderId);
    const siblingOrder=await fetch(`${base}/orders/${tenantPurchase.orderId}`,{headers:headers(otherBuyer)});
    assert.equal(siblingOrder.status,404);
    const siblingOrders=await fetch(`${base}/orders`,{headers:headers(otherBuyer)});
    assert.equal(siblingOrders.status,200);
    assert.deepEqual((await siblingOrders.json()).orders,[]);
    const historyPath=`${base}/orders/operations`;
    const currentHistory=await fetch(historyPath,{headers:headers(buyer)});
    assert.equal(currentHistory.status,200);
    const historyList=await currentHistory.json();
    assert.deepEqual(historyList.operations.map(row=>row.operationId),[checkoutRequest.operationId]);
    const currentReceipt=await fetch(`${historyPath}/${checkoutRequest.operationId}`,{headers:headers(buyer)});
    assert.equal(currentReceipt.status,200);
    const historyReceipt=await currentReceipt.json();
    assert.equal(historyReceipt.status,'completed');
    assert.equal(historyReceipt.order.id,tenantPurchase.orderId);
    assert.equal(historyReceipt.order.total,25);
    const otherBuyerTarget=await catalog.prepareTarget(otherBuyer);
    const siblingHistory=await fetch(historyPath,{headers:headers(otherBuyer)});
    assert.equal(siblingHistory.status,200);
    assert.deepEqual((await siblingHistory.json()).operations,[]);
    const siblingReceipt=await fetch(`${historyPath}/${checkoutRequest.operationId}`,{headers:headers(otherBuyer)});
    assert.equal(siblingReceipt.status,404);
    assert.equal((await commerce.listOrders(otherBuyerTarget,otherBuyer.persona.id)).length,0);
    assert.equal((await commerce.listCart(otherBuyerTarget,otherBuyer.persona.id)).items.length,0);
    assert.equal(await commerce.getOrder(otherBuyerTarget,{shopUserId:otherBuyer.persona.id,orderId:tenantPurchase.orderId}),null);
    const window={previousCutoff:new Date(Date.now()-172800000).toISOString(),
      cutoff:new Date(Date.now()-86400000).toISOString(),until:new Date(Date.now()+86400000).toISOString()};
    assert.equal(Number((await commerce.merchantOverview(sellerTarget,seller.persona.id,window)).current.orders),1);
    const otherSellerTarget=await catalog.prepareTarget(otherSeller);
    assert.equal(Number((await commerce.merchantOverview(otherSellerTarget,otherSeller.persona.id,window)).current.orders),0);
    const sellerKpis=await fetch(`${base}/merchant/overview/kpis`,{headers:headers(seller)});
    assert.equal(sellerKpis.status,200);
    assert.equal((await sellerKpis.json()).orders.value,1);
    const otherSellerKpis=await fetch(`${base}/merchant/overview/kpis`,{headers:headers(otherSeller)});
    assert.equal(otherSellerKpis.status,200);
    assert.equal((await otherSellerKpis.json()).orders.value,0);
    assert.equal((await commerce.adminSummary(sellerTarget)).total_orders,1);
    const listing=await catalog.createMerchantProduct({...otherSeller,listing:{name:'Second merchant item',
      description:'Published tenant fixture',price:19.95,category:'fixture',templateSource:'{{source}}',images:[]}});
    const publicCatalog=createSecureShopStorePublicCatalogRepository({identityPool:identity,reviewPool:review,
      commercePool:{async connect(){throw Error('Seed fallback forbidden after target exists');},
        async query(){throw Error('Seed fallback forbidden after target exists');}}});
    assert.equal((await publicCatalog.product(listing.productId)).product.name,'Second merchant item');
    await catalog.updateMerchantProduct({...otherSeller,productId:listing.productId,patch:{price:21.5}});
    assert.equal((await publicCatalog.product(listing.productId)).product.price,21.5);
    assert.equal(await catalog.updateMerchantProduct({...seller,productId:listing.productId,patch:{price:1}}),null,
      'another merchant cannot edit this merchant listing');
    const importId=randomUUID();
    const importSession={sessionId:randomUUID(),authorityVersion:'1'};
    const guestLines=[{productId:7,quantity:1}];
    const importResult=await commerce.importGuestCart(buyerTarget,{shopUserId:buyer.persona.id,
      requestId:importId,items:guestLines,personaSession:importSession});
    assert.equal(importResult.imported,true);
    assert.equal(importResult.items[0].price,12.5,'import quotes current target price');
    assert.equal((await commerce.listCart(buyerTarget,buyer.persona.id)).items[0].quantity,1);
    const deniedImport=await commerce.importGuestCart(buyerTarget,{shopUserId:buyer.persona.id,
      requestId:randomUUID(),items:[{productId:7,quantity:1},{productId:8,quantity:99}],
      personaSession:importSession});
    assert.equal(deniedImport.imported,false);
    assert.deepEqual(deniedImport.issues.map(issue=>issue.productId),[8]);
    assert.equal((await commerce.listCart(buyerTarget,buyer.persona.id)).items[0].quantity,1,
      'one unavailable line cannot partially import the other');
    await assert.rejects(commerce.importGuestCart(otherBuyerTarget,{shopUserId:otherBuyer.persona.id,
      requestId:importId,items:guestLines,personaSession:importSession}),{code:'CART_IMPORT_CONFLICT'});
    assert.equal((await commerce.listCart(otherBuyerTarget,otherBuyer.persona.id)).items.length,0);
    await standalone.logout(buyer.account.token);
    await assert.rejects(commerce.listOrders(buyerTarget,buyer.persona.id));
    const revokedHistory=await fetch(`${historyPath}/${checkoutRequest.operationId}`,{headers:headers(buyer)});
    assert.equal(revokedHistory.status,401,'logged-out execution cannot read checkout history');
    assert.equal((await publicCatalog.product(listing.productId)).product.price,21.5,
      'customer logout never resets the shared shop');
    const relogged=await standalone.login({username:buyer.account.user.username,password:'disposable-scene-fixture'});
    const reexecution=await standalone.establishTenantContext(relogged.context);
    const relaunched=await launches.issueOrRenew({platformOwnerId:reexecution.ownerId,
      platformSessionId:reexecution.sessionId,expiresAt:new Date(Date.now()+1800000),shopPrincipal:reexecution});
    const reloggedPersona=await personaAuth.establishSession({scope:relaunched.binding,shopPrincipal:reexecution});
    const reloggedActor=await personaAuth.authenticateBoundToken({scope:relaunched.binding,
      token:reloggedPersona.token});
    const reloggedBuyer={scope:relaunched.binding,persona:reloggedActor.user,
      personaSession:{sessionId:reloggedActor.sessionId,authorityVersion:reloggedActor.authorityVersion},
      bearer:relaunched.bearer,token:reloggedPersona.token};
    const reopened=await catalog.prepareTarget({scope:relaunched.binding,persona:buyer.persona});
    assert.equal(reopened.targetId,buyerTarget.targetId);
    assert.equal((await commerce.listOrders(reopened,buyer.persona.id))[0].id,tenantPurchase.orderId);
    const historicalList=await fetch(historyPath,{headers:headers(reloggedBuyer)});
    assert.equal(historicalList.status,200);
    assert.deepEqual((await historicalList.json()).operations.map(row=>row.operationId),
      [checkoutRequest.operationId]);
    const historicalRead=await fetch(`${historyPath}/${checkoutRequest.operationId}`,
      {headers:headers(reloggedBuyer)});
    assert.equal(historicalRead.status,200);
    assert.deepEqual(await historicalRead.json(),historyReceipt,
      'new execution reads the same immutable historical checkout outcome');
    const unchangedReceipt=(await review.query(`SELECT request_json,result_json,request_sha256,result_sha256
      FROM secureshop_review.bound_commerce_operations WHERE operation_id=$1`,
    [checkoutRequest.operationId])).rows[0];
    for(const key of ['request_json','result_json','request_sha256','result_sha256'])
      assert.equal(unchangedReceipt[key],durableReceipt[0][key],`history read preserves ${key}`);
    assert.equal(await count(review,'secureshop_review.product_target_orders',
      'target_id=$1 AND shop_user_id=$2',[buyerTarget.targetId,buyer.persona.id]),1);
    const historicalMode=await modeAuthority.capture(reloggedBuyer.scope,'coupons');
    const selectedMode=await ownMode.get(relogged.context);
    await ownMode.set(relogged.context,{mode:'vuln',expectedRevision:selectedMode.revision});
    await assert.rejects(historicalMode.assertCurrentAtEffect(),{code:'ANALYTICS_MODE_STALE'});
    const refreshedModeHistory=await fetch(`${historyPath}/${checkoutRequest.operationId}`,
      {headers:headers(reloggedBuyer)});
    assert.equal(refreshedModeHistory.status,200,'new mode requires a fresh read fence');
    assert.deepEqual(await refreshedModeHistory.json(),historyReceipt);
    const importedReplay=await commerce.importGuestCart(reopened,{shopUserId:buyer.persona.id,
      requestId:importId,items:guestLines,personaSession:importSession});
    assert.equal(importedReplay.replayed,true,'new execution replays the original receipt');
    assert.equal((await commerce.listCart(reopened,buyer.persona.id)).items[0].quantity,1);
    await assert.rejects(commerce.importGuestCart(reopened,{shopUserId:buyer.persona.id,
      requestId:importId,items:[{productId:7,quantity:2}],personaSession:importSession}),
    {code:'CART_IMPORT_CONFLICT'});

    const customerChatFence = {};
    await t.test('retained-scene refund correlates current request, run and immutable ticket without sibling access',
      { timeout: 30000 }, async () => {
        const { createSecureShopBoundRefundRepository } = require('../../server/database/postgres/secureshopBoundRefundRepository');
        const { createSecureShopBoundRefundRuntime } = require('../../server/services/secureshopBoundRefundRuntime');
        const { createBoundConversationsRepository } = require('../../server/database/postgres/secureshopBoundConversationsRepository');
        const { createTurnRequestsRepository } = require('../../server/database/postgres/secureshopTurnRequestsRepository');
        const { createPostgresRunLedger } = require('../../server/agent-runtime/postgresRunLedger');
        const { createRunCoordinator } = require('../../server/agent-runtime/runCoordinator');
        const { createConversationBinding } = require('../../server/services/secureshopConversationBinding');
        const refundRepository=createSecureShopBoundRefundRepository(review,{checkCurrent,auditStore});
        const conversations=createBoundConversationsRepository({pool:agents,queue:(_id,work)=>work()});
        const journal=createTurnRequestsRepository({pool:agents});
        const refundCoordinator=createRunCoordinator({family:`SceneRefundNative:${randomUUID()}`,
          ledger:createPostgresRunLedger(identity,{leasePool:identity})});
        let modelDecisions=0;
        const runtime=createSecureShopBoundRefundRuntime({launches,conversationRepository:conversations,
          journal,coordinator:refundCoordinator,personaAuthority,refundRepository,
          commerce:{order:input=>commerceService.order(input)},
          resolveTarget:scope=>scenes.readExisting(scope),
          resolveExistingTarget:scope=>scenes.readExisting(scope),
          authenticatePersona:personaAuth.authenticatePersona,modeAuthority,
          buildBasePrompt:()=> 'Controlled disposable refund qualification',
          buildPolicyBlock:async()=>'',checkToolAcl:async()=>({action:'dispatch'}),
          provider:{chat:async()=>{
            modelDecisions++;
            return {stop_reason:'tool_use',tool_uses:[modelDecisions===1
              ?{id:'owned-order-status',name:'support.order_status',args:{order_id:tenantPurchase.orderId}}
              :{id:'owned-refund-request',name:'support.refund_request',
                args:{order_id:tenantPurchase.orderId,reason:'it was damaged'}}]};
          },finalResponse:async()=>({stop_reason:'end_turn',text:'Controlled refund request',
            responseMode:'structured_final'})},limits:{maxSteps:2,maxParallelTools:1}});
        assert.notEqual(reopened.launchId,reloggedBuyer.scope.launchId,
          'the refund target retains birth coordinates across login');
        assert.equal(reopened.scene.execution.launchId,reloggedBuyer.scope.launchId);
        const session=await runtime.createSession(reloggedBuyer.scope,reloggedBuyer.persona,
          reloggedBuyer.personaSession);
        const requestId=randomUUID();
        const request={sessionId:session.id,requestId,scope:reloggedBuyer.scope,
          persona:{id:reloggedBuyer.persona.id,role:'customer'},
          personaSession:reloggedBuyer.personaSession,
          message:`Please refund order #${tenantPurchase.orderId} because it was damaged`,
          localToolAuthority:{requestId}};
        const refundRun=await runtime.runner.run(request);
        assert.deepEqual(refundRun.hops.map(hop=>hop.tool),
        ['support.order_status','support.refund_request']);
        assert.equal(refundRun.hops[1].result.isError,undefined);
        assert.equal(JSON.parse(refundRun.hops[1].result.content[0].text).ok,true);
        const saved=await runtime.readRequest(reloggedBuyer.scope,request.persona,
          request.personaSession,session.id,requestId);
        assert.equal(saved.status,'saved');
        assert.equal(saved.requestId,requestId);
        assert.equal(saved.orderId,tenantPurchase.orderId);
        assert.match(saved.ticketId,/^\d+$/);
        const turn=(await agents.query(`SELECT status FROM secureshop_agents.turn_requests
          WHERE session_id=$1 AND request_id=$2`,[session.id,requestId])).rows;
        assert.equal(turn.length,1);
        assert.equal(turn[0].status,'completed');
        const tickets=(await review.query(`SELECT ticket_id,order_id,request_id,run_id,shop_user_id
          FROM secureshop_review.product_target_refund_requests
          WHERE target_id=$1 AND request_id=$2`,[reopened.targetId,requestId])).rows;
        assert.equal(tickets.length,1);
        assert.equal(String(tickets[0].ticket_id),saved.ticketId);
        assert.equal(Number(tickets[0].order_id),saved.orderId);
        assert.equal(Number(tickets[0].shop_user_id),buyer.persona.id);
        const events=(await review.query(`SELECT event_id,launch_id,scenario_id,generation,
          original_platform_owner_id,original_platform_session_id,params_json
          FROM secureshop_review.bound_audit_events
          WHERE source_kind='refund_operation' AND original_platform_owner_id=$1`,
        [reloggedBuyer.scope.platformOwnerId])).rows;
        assert.equal(events.length,1);
        const event=events[0],packet=JSON.parse(event.params_json);
        assert.equal(event.launch_id,reloggedBuyer.scope.launchId);
        assert.equal(event.scenario_id,reloggedBuyer.scope.scenarioId);
        assert.equal(Number(event.generation),reloggedBuyer.scope.generation);
        assert.equal(packet.storageTargetId,reopened.targetId);
        assert.equal(packet.sceneId,reopened.scene.sceneId);
        assert.equal(event.event_id,packet.receipt.operationId);
        assert.equal(packet.receipt.requestId,requestId);
        assert.equal(packet.receipt.runId,tickets[0].run_id);
        assert.equal(packet.receipt.personaSessionId,request.personaSession.sessionId);
        assert.equal(packet.receipt.authorityVersion,request.personaSession.authorityVersion);
        assert.equal(typeof packet.receipt.toolInvocationId,'string');
        assert.equal(packet.receipt.ticketId,saved.ticketId);
        assert.equal(packet.receipt.scope.targetId,reopened.targetId);
        assert.equal(packet.receipt.scope.launchId,reloggedBuyer.scope.launchId);
        assert.equal((await identity.query('SELECT status FROM graph_runtime.runs WHERE run_id=$1',
          [tickets[0].run_id])).rows[0].status,'completed');
        const before=await review.query(`SELECT * FROM secureshop_review.product_target_refund_requests
          WHERE target_id=$1 AND request_id=$2`,[reopened.targetId,requestId]);
        assert.deepEqual(await runtime.readRequest(reloggedBuyer.scope,request.persona,
          request.personaSession,session.id,requestId),saved);
        assert.deepEqual((await review.query(`SELECT * FROM secureshop_review.product_target_refund_requests
          WHERE target_id=$1 AND request_id=$2`,[reopened.targetId,requestId])).rows,before.rows);
        await assert.rejects(runtime.readRequest(otherBuyer.scope,
          {id:otherBuyer.persona.id,role:'customer'},otherBuyer.personaSession,
          session.id,requestId));
        await assert.rejects(runtime.readRequest(buyer.scope,
          {id:buyer.persona.id,role:'customer'},buyer.personaSession,
          session.id,requestId));
        const binding=createConversationBinding(reloggedBuyer.scope,request.persona);
        await assert.rejects(journal.claim({sessionId:session.id,requestId,binding,
          message:'Changed intent under the saved request UUID'}),{code:'TURN_REQUEST_CONFLICT'});
        // Normal admission reuses one conversation for this exact scope and
        // purpose. The PostgreSQL unique index also rejects a direct attempt
        // to insert a second conversation with the same authority coordinates.
        const duplicateSessionId=randomUUID();
        await assert.rejects(conversations.createPendingBoundSession({id:duplicateSessionId,
          binding,purpose:'secureshop_refund_request'}),{code:'23505'});
        assert.deepEqual(await runtime.readRequest(reloggedBuyer.scope,request.persona,
          request.personaSession,session.id,requestId),saved);
        assert.equal(modelDecisions,2,'controlled decisions are not actual-model evidence');

        // Exercise 0056 through its real PostgreSQL reservation and the bound
        // runner. This controlled provider proves storage and fences only; it
        // is not a model or objective-credit qualification.
        const {createCustomerChatBindingRepository}=require('../../server/database/postgres/secureshopCustomerChatBindingRepository');
        const {createSecureShopBoundCustomerChat}=require('../../server/services/secureshopBoundCustomerChat');
        const bindingRepository=createCustomerChatBindingRepository({pool:agents});
        const customerToolPolicies=require('../../server/database/postgres/secureshopBoundAclRepository')
          .createSecureShopBoundAclRepository({personaAuthority,
            audit:createBoundAuditStore({store:'agents',pool:agents})});
        let chatDecisions=0,chatFinals=0;
        const customerChat=createSecureShopBoundCustomerChat({launches,personaAuthority,modeAuthority,
          conversations,journal,coordinator:createRunCoordinator({family:`SceneCustomerChatNative:${randomUUID()}`,
            ledger:createPostgresRunLedger(identity,{leasePool:identity})}),
          provider:{async chat(){chatDecisions++;return chatDecisions===1
            ?{provider:'controlled',model:'controlled-scene-native',mocked:true,stop_reason:'tool_use',
              tool_uses:[{id:'catalog-search-1',name:'catalog.search',args:{search:'Tenant product'}}]}
            :{provider:'controlled',model:'controlled-scene-native',mocked:true,stop_reason:'end_turn',
              text:'The owned catalog has matching products.',tool_uses:[]}},
            async finalResponse(){chatFinals++;return{provider:'controlled',model:'controlled-scene-native',mocked:true,
              stop_reason:'end_turn',text:'The owned catalog has matching products.',responseMode:'structured_final'}}},
          catalog,productRepository:products,commerceRepository:commerce,
          profileCommerce:commerceService,scenes,bindingRepository,
          toolPolicyRepository:customerToolPolicies});
        const chatSession=await customerChat.createSession(reloggedBuyer.scope,
          {id:reloggedBuyer.persona.id,role:'customer'},reloggedBuyer.personaSession);
        const chatRequestId=randomUUID(),chatMessage='Find Tenant product in my current shop';
        const chatInput={scope:reloggedBuyer.scope,persona:{id:reloggedBuyer.persona.id,role:'customer'},
          personaSession:reloggedBuyer.personaSession,sessionId:chatSession.id,
          requestId:chatRequestId,message:chatMessage};
        const chatEvents=[];
        const chatAnswer=await customerChat.run({...chatInput,
          stream:{send:(name,data)=>chatEvents.push({name,data})}});
        assert.equal(chatAnswer.text,'The owned catalog has matching products.');
        assert.deepEqual(chatEvents.map(event=>event.name).filter(name=>
          ['tool_call','tool_result','assistant_message','done'].includes(name)),
        ['tool_call','tool_result','assistant_message','done']);
        assert.equal(chatDecisions,1);
        assert.equal(chatFinals,1);
        const chatSaved=await customerChat.readRequest(reloggedBuyer.scope,chatInput.persona,
          reloggedBuyer.personaSession,chatSession.id,chatRequestId);
        assert.equal(chatSaved.status,'completed');
        assert.equal(chatSaved.hops[0].tool,'catalog.search');
        assert.equal(chatSaved.modeCapability.effectiveMode,'vuln');
        assert.equal(chatDecisions,1,'read-only recovery must not call the controlled provider again');
        assert.equal(chatFinals,1,'read-only recovery must not call final response again');
        const chatRows=(await agents.query(`SELECT * FROM secureshop_agents.customer_chat_turn_bindings
          WHERE session_id=$1 AND request_id=$2`,[chatSession.id,chatRequestId])).rows;
        assert.equal(chatRows.length,1);
        const chatRow=chatRows[0];
        assert.equal(chatRow.launch_id,reloggedBuyer.scope.launchId);
        assert.equal(chatRow.persona_session_id,reloggedBuyer.personaSession.sessionId);
        assert.equal(chatRow.scene_id,reopened.scene.sceneId);
        assert.equal(chatRow.grant_id,reopened.scene.grantId);
        assert.equal(chatRow.target_id,reopened.targetId);
        const chatEnvelope=JSON.stringify({version:1,sceneId:reopened.scene.sceneId,
          sceneGeneration:reopened.scene.sceneGeneration,targetId:reopened.targetId,
          requestId:chatRequestId,message:chatMessage});
        const chatReservation={...chatInput,target:reopened,message:chatEnvelope};
        assert.equal((await bindingRepository.reserve(chatReservation)).requestHash,chatRow.request_hash);
        await assert.rejects(bindingRepository.reserve({...chatReservation,
          message:chatEnvelope.replace(chatMessage,'A different catalog question')}),
        {code:'TURN_REQUEST_CONFLICT'});
        assert.equal(await bindingRepository.read({sessionId:chatSession.id,requestId:chatRequestId,
          scope:otherBuyer.scope,persona:{id:otherBuyer.persona.id,role:'customer'}}),null);
        await assert.rejects(customerChat.readRequest(otherBuyer.scope,
          {id:otherBuyer.persona.id,role:'customer'},otherBuyer.personaSession,
          chatSession.id,chatRequestId));
        await assert.rejects(customerChat.readRequest(buyer.scope,chatInput.persona,
          buyer.personaSession,chatSession.id,chatRequestId));
        assert.deepEqual((await agents.query(`SELECT * FROM secureshop_agents.customer_chat_turn_bindings
          WHERE session_id=$1 AND request_id=$2`,[chatSession.id,chatRequestId])).rows,chatRows);
        Object.assign(customerChatFence,{customerChat,chatInput,chatRows});
        // A completed pointer can outlive its persona session. The old turn
        // remains denied after a fresh bootstrap, while the current launch
        // and ordinary authenticated account reads stay available.
        const chatApp=express();chatApp.use(express.json());
        chatApp.use('/api/secureshop',require('../../server/routes/secureshop/boundCustomerChat')
          .createBoundCustomerChatRouter({launches,authenticatePersona:personaAuth.authenticatePersona,
            runtime:customerChat}));
        chatApp.use('/api/secureshop',gateway);
        const chatServer=await new Promise(resolve=>{
          const server=chatApp.listen(0,'127.0.0.1',()=>resolve(server));
        });
        t.after(()=>new Promise(resolve=>chatServer.close(resolve)));
        const chatBase=`http://127.0.0.1:${chatServer.address().port}/api/secureshop`;
        const savedPath=`${chatBase}/agents/customer/operations/${chatSession.id}/${chatRequestId}`;
        const beforeRenewal=await fetch(savedPath,{headers:headers(reloggedBuyer)});
        assert.equal(beforeRenewal.status,200);
        assert.equal((await beforeRenewal.json()).status,'completed');
        await personaAuth.logout({scope:reloggedBuyer.scope,token:reloggedBuyer.token});
        const oldDenied=await fetch(savedPath,{headers:headers(reloggedBuyer)});
        assert.equal(oldDenied.status,401);
        const renewed=await personaAuth.establishSession({scope:reloggedBuyer.scope,
          shopPrincipal:reexecution});
        const renewedActor=await personaAuth.authenticateBoundToken({scope:reloggedBuyer.scope,
          token:renewed.token});
        assert.notEqual(renewedActor.sessionId,reloggedBuyer.personaSession.sessionId);
        const currentActor={...reloggedBuyer,token:renewed.token};
        const staleRead=await fetch(savedPath,{headers:headers(currentActor)});
        assert.equal(staleRead.status,401);
        assert.deepEqual(await staleRead.json(),{error:'Shop session unavailable'});
        assert.equal(staleRead.headers.get('x-owasp-ai-goat-secureshop-launch-state'),null);
        const currentProfile=await accountService.profile({scope:reloggedBuyer.scope,
          persona:{id:renewedActor.user.id,role:renewedActor.user.role},
          personaSession:{sessionId:renewedActor.sessionId,
            authorityVersion:renewedActor.authorityVersion}});
        assert.equal(currentProfile.id,reloggedBuyer.persona.id);
        const currentWhoami=await fetch(`${chatBase}/v2/auth/whoami`,{headers:headers(currentActor)});
        assert.equal(currentWhoami.status,200);
        assert.equal((await currentWhoami.json()).user.id,reloggedBuyer.persona.id);
        assert.equal(chatDecisions,1);
        assert.equal(chatFinals,1);
        assert.deepEqual((await agents.query(`SELECT * FROM secureshop_agents.customer_chat_turn_bindings
          WHERE session_id=$1 AND request_id=$2`,[chatSession.id,chatRequestId])).rows,chatRows);
      });

    // Exercise the real credential-session repository and branded tenant/launch
    // admission without spending 257 bcrypt comparisons. Every opaque token is
    // generated and hashed exactly as normal session issuance requires.
    for (let i=0;i<257;i++) {
      const token=randomBytes(32).toString('base64url');
      await standaloneRepository.createSession({principalId:relogged.context.principalId,
        credentialVersion:relogged.context.credentialVersion,authorityVersion:relogged.context.authorityVersion,
        tokenHash:createHash('sha256').update(token).digest('hex'),
        expiresAt:new Date(Date.now()+3600000).toISOString()});
      const cookiePrincipal=await standalone.authenticate(token);
      const lease=await standalone.establishTenantContext(cookiePrincipal);
      const issued=await launches.issueOrRenew({platformOwnerId:lease.ownerId,platformSessionId:lease.sessionId,
        expiresAt:new Date(Date.now()+1800000),shopPrincipal:lease});
      assert.ok(issued.binding.launchId);
      await standalone.logout(token);
    }
    const history=(await identity.query(`SELECT count(*)::int total,
      count(*) FILTER(WHERE identity.secureshop_launch_consumes_capacity(launch_id))::int live
      FROM identity.secureshop_launches WHERE original_platform_owner_id=$1`,[buyer.execution.ownerId])).rows[0];
    assert.ok(history.total>256); assert.ok(history.live<16);
    assert.equal((await commerce.listOrders(reopened,buyer.persona.id))[0].id,tenantPurchase.orderId);
    assert.equal((await identity.query(`SELECT count(*)::int n FROM identity.secureshop_target_reservations
      WHERE original_platform_owner_id=$1 AND target_kind='products'`,[buyer.execution.ownerId])).rows[0].n,1);

    await t.test('seller reviews keep immutable seeds and confine moderation to each current merchant', async () => {
      const reviewStore = createSecureShopBoundReviewRepository(review, {
        enableLearnerSubmissions: true, checkCurrent,
        checkRetirement: async () => { throw new Error('retirement outside the canonical reset'); },
        checkCleanup: input => cleanupAuthority.checkReviewTarget(input), auditStore,
      });
      async function reviewTarget(current, productScene, fixtures) {
        const reserved = await launches.reserveReviewsTarget({ ...current.scope,
          expectedGeneration: current.scope.generation });
        return reviewStore.provisionScene(productScene,
          { ...current.scope, targetId: reserved.targetId }, { reviews: fixtures });
      }
      const rawSeeds = async targetId => (await review.query(`SELECT id,product_id,author_id,body,rating,status,source_kind
        FROM secureshop_review.reviews WHERE target_id=$1 AND source_kind='fixture' ORDER BY id`,
      [targetId])).rows;
      const markers = async targetId => (await review.query(`SELECT ordinal,product_target_id,retailer_id,
        product_id,review_id,encode(body_sha256,'hex') AS body_sha256,
        encode(seed_sha256,'hex') AS seed_sha256,encode(provenance_sha256,'hex') AS provenance_sha256
        FROM secureshop_review.seller_review_lessons WHERE target_id=$1 ORDER BY ordinal`,
      [targetId])).rows;
      const sellerListing = await catalog.createMerchantProduct({ ...seller, listing: {
        name: 'Seller-owned review lesson item', description: 'Synthetic fixture', price: 13.5,
        category: 'fixture', templateSource: '{{source}}', images: [],
      } });
      const sellerReview = await reviewTarget(seller, sellerTarget, PREFERRED_REVIEW_FIXTURES);
      const originalSeed = await rawSeeds(sellerReview.targetId);
      assert.equal(originalSeed.length, 2);
      const seed = (await review.query(`SELECT seed_count,encode(seed_sha256,'hex') AS sha
        FROM secureshop_review.review_targets WHERE target_id=$1`, [sellerReview.targetId])).rows[0];
      assert.equal(Number(seed.seed_count), 2);
      assert.equal(seed.sha, PROFILE_DIGESTS.preferred);
      assert.deepEqual(await reviewStore.adoptSellerLessons(sellerReview), { status: 'adopted' });
      assert.deepEqual(await reviewStore.adoptSellerLessons(sellerReview), { status: 'replayed' });
      assert.deepEqual(await rawSeeds(sellerReview.targetId), originalSeed,
        'supplementing a populated target cannot rewrite its historical fixture rows');
      const sellerMarkers = await markers(sellerReview.targetId);
      assert.deepEqual(sellerMarkers.map(row => Number(row.product_id)), [7, sellerListing.productId]);
      assert.ok(sellerMarkers.every(row => Number(row.retailer_id) === seller.persona.id
        && row.product_target_id === sellerTarget.targetId && row.seed_sha256 === PROFILE_DIGESTS.preferred));
      for (const marker of sellerMarkers) {
        const source = (await review.query(`SELECT product_id,body,source_kind FROM secureshop_review.reviews
          WHERE target_id=$1 AND id=$2`, [sellerReview.targetId, marker.review_id])).rows[0];
        assert.equal(source.source_kind, 'seller_lesson');
        assert.equal(Number(source.product_id), Number(marker.product_id));
        assert.equal(createHash('sha256').update(source.body).digest('hex'), marker.body_sha256);
        assert.match(marker.provenance_sha256, /^[a-f0-9]{64}$/);
      }
      const otherReview = await reviewStore.readSceneTarget(otherSellerTarget);
      assert.equal(otherReview.targetId, sellerReview.targetId);
      const sellerActor = { id: seller.persona.id, role: 'merchant' };
      const otherActor = { id: otherSeller.persona.id, role: 'merchant' };
      const buyerActor = { id: otherBuyer.persona.id, role: 'customer' };
      const otherSubmitted = await reviewStore.submitReview(otherReview, buyerActor, {
        submissionId: randomUUID(), productId: listing.productId, authorId: otherBuyer.persona.id,
        body: 'Second merchant product review remains private to its seller.', rating: 3,
      });
      assert.equal(otherSubmitted.created, true);
      const sellerFence = personaAuthority.capture({ scope: seller.scope,
        personaId: seller.persona.id, role: 'merchant', ...seller.personaSession });
      const otherFence = personaAuthority.capture({ scope: otherSeller.scope,
        personaId: otherSeller.persona.id, role: 'merchant', ...otherSeller.personaSession });
      const sellerCap = reviewModeration.capture(sellerReview, sellerActor, sellerFence);
      const otherCap = reviewModeration.capture(otherReview, otherActor, otherFence);
      const sellerPage = await reviewStore.listReviews(sellerReview, { limit: 1, offset: 1 }, { moderation: sellerCap });
      assert.equal(sellerPage.total, 2);
      assert.deepEqual(sellerPage.counts, { pending: 2, approved: 0, rejected: 0 });
      assert.equal(sellerPage.rows.length, 1);
      assert.deepEqual((await reviewStore.listReviews(sellerReview,
        { productId: sellerListing.productId }, { moderation: sellerCap })).rows.map(row => row.product_id),
      [sellerListing.productId]);
      assert.equal((await reviewStore.listReviews(otherReview, {}, { moderation: otherCap })).total, 1);
      assert.equal((await reviewStore.listReviews(sellerReview)).total, 5,
        'customer-facing projection still includes original and both merchants\' review rows');
      assert.equal(await reviewStore.getReview(sellerReview, otherSubmitted.reviewId,
        { moderation: sellerCap }), null);
      assert.equal(await reviewStore.getReview(otherReview, Number(sellerMarkers[0].review_id),
        { moderation: otherCap }), null);
      await assert.rejects(reviewStore.listPending(sellerReview, { limit: 1 }),
        { code: 'SHOP_AUTH_INVALID' }, 'scene moderation never falls back to an unscoped read');
      const manual = createSecureShopManualReviewActions({ repository: reviewStore,
        trustedScope: seller.scope, auditPersona: sellerActor, personaEffectFence: sellerFence,
        checkCurrent, resolveTarget: async () => sellerReview });
      await assert.rejects(manual.approve(otherSubmitted.reviewId), error =>
        error.code === 'PERSONA_EFFECT_OUTCOME_UNCERTAIN' && error.cause?.code === 'REVIEW_NOT_FOUND');
      assert.equal((await review.query('SELECT status FROM secureshop_review.reviews WHERE id=$1',
        [otherSubmitted.reviewId])).rows[0].status, 'pending', 'authoritative readback proves no sibling decision');
      assert.equal((await manual.approve(Number(sellerMarkers[0].review_id))).applied, true);
      const operation = { operationId: randomUUID(), kind: 'agent',
        personaSessionId: seller.personaSession.sessionId,
        authorityVersion: seller.personaSession.authorityVersion,
        runId: randomUUID(), toolInvocationId: 'native-seller-reject' };
      const tools = createSecureShopBoundReviewTools({ repository: reviewStore,
        trustedScope: seller.scope, auditPersona: sellerActor, personaEffectFence: sellerFence,
        checkCurrent, resolveTarget: async () => sellerReview,
        batchAuthority: createBoundReviewBatchAuthority({ requested: 1, batchLimit: 1 }),
        decisionOperation: () => operation });
      const parse = packet => JSON.parse(packet.content[0].text);
      const observed = parse(await tools['review-moderator.moderate_pending']({ limit: 1 }));
      assert.equal(observed.ok, true);
      assert.deepEqual(observed.reviews.map(row => row.id), [Number(sellerMarkers[1].review_id)]);
      assert.deepEqual(parse(await tools['review-moderator.moderate_pending']({ limit: 1 })).reviews,
        observed.reviews, 'cached batch is rechecked under the same captured seller authority');
      const reason = 'Unrelated promotion';
      const decided = parse(await tools['review-moderator.reject']({
        review_id: Number(sellerMarkers[1].review_id), reason }));
      assert.equal(decided.applied, true);
      assert.equal(decided.review.status, 'rejected');
      const decisionEvents = async () => Number((await review.query(`SELECT count(*)::int n
        FROM secureshop_review.bound_audit_events WHERE event_id=$1`, [operation.operationId])).rows[0].n);
      assert.equal(await decisionEvents(), 1);
      const replay = await reviewStore.decide(sellerReview, { reviewId: Number(sellerMarkers[1].review_id),
        decision: 'reject', notes: reason, moderatorKind: 'auto', auditPersona: sellerActor,
        moderation: sellerCap, operation });
      assert.equal(replay.replayed, true);
      assert.equal(await decisionEvents(), 1, 'receipt replay cannot add a second decision');
      assert.equal((await reviewStore.listReviews(otherReview, {}, { moderation: otherCap })).counts.pending, 1);
      assert.equal(await products.archiveListing(sellerTarget, seller.persona.id, sellerListing.productId), 1);
      assert.equal((await reviewStore.listReviews(sellerReview,
        { productId: sellerListing.productId }, { moderation: sellerCap })).total, 1,
      'archiving an owned listing does not reassign its historical review');

      const legacyExtra = await products.createListing(siblingTarget, 12, {
        name: 'Sibling owned review product', description: 'Capacity fixture', price: 9,
        category: 'fixture', templateSource: null, images: [],
      });
      assert.equal(legacyExtra, 8);
      const siblingReview = await reviewTarget(siblingLogin, siblingTarget, LEGACY_REVIEW_FIXTURES);
      const legacySeed = await rawSeeds(siblingReview.targetId);
      assert.equal(legacySeed.length, 74);
      assert.deepEqual(await reviewStore.adoptSellerLessons(siblingReview), { status: 'adopted' });
      assert.deepEqual(await reviewStore.adoptSellerLessons(siblingReview), { status: 'replayed' });
      assert.deepEqual(await rawSeeds(siblingReview.targetId), legacySeed);
      assert.equal((await markers(siblingReview.targetId)).length, 2);

      const customLogin = await login(await owner('scene-review-custom'));
      const customScene = await provision(customLogin);
      const customReview = await reviewTarget(customLogin, customScene,
        [{ productId: 7, authorId: 2, body: 'Owner-edited custom review fixture.', rating: 4 }]);
      const customBefore = await rawSeeds(customReview.targetId);
      assert.deepEqual(await reviewStore.adoptSellerLessons(customReview), { status: 'custom_profile' });
      assert.deepEqual(await rawSeeds(customReview.targetId), customBefore);
      assert.deepEqual(await markers(customReview.targetId), []);

      const capacityLogin = await login(await owner('scene-review-capacity'));
      const capacityScene = await provision(capacityLogin);
      await products.createListing(capacityScene, 12, { name: 'Capacity product two',
        description: 'Capacity fixture', price: 9, category: 'fixture', templateSource: null, images: [] });
      const capacityReview = await reviewTarget(capacityLogin, capacityScene, PREFERRED_REVIEW_FIXTURES);
      // Capacity-only synthetic rows have valid provenance shape but are not
      // model, learner-action or objective-credit evidence.
      await reviewMigration.query(`INSERT INTO secureshop_review.reviews
        (target_id,product_id,author_id,body,rating,source_kind,submission_id,
          request_sha256,body_sha256,submitted_by_shop_user_id,submitted_by_shop_role)
        SELECT $1,7,2,'capacity-only row '||n,3,'learner',gen_random_uuid(),
          sha256(convert_to('capacity-request-'||n,'UTF8')),
          sha256(convert_to('capacity-only row '||n,'UTF8')),11,'customer'
        FROM generate_series(1,253) n`, [capacityReview.targetId]);
      assert.equal((await reviewStore.listReviews(capacityReview)).total, 255);
      assert.deepEqual(await reviewStore.adoptSellerLessons(capacityReview), { status: 'capacity_unavailable' });
      assert.deepEqual(await markers(capacityReview.targetId), []);
      assert.equal((await reviewStore.listReviews(capacityReview)).total, 255);

      await assert.rejects(reviewStore.cleanup(sellerReview, { operationId: randomUUID() }),
        { code: 'RESET_CLEANUP_AUTHORITY_REQUIRED' }, 'raw review deletion requires a real reset operation');
      const reset = await launches.beginReset({ launchId: seller.scope.launchId,
        platformSessionId: seller.scope.platformSessionId,
        platformOwnerId: seller.scope.platformOwnerId,
        expectedGeneration: seller.scope.generation,
        idempotencyKey: 'retire-seller-review-scene' });
      await assert.rejects(reviewStore.listReviews(sellerReview, {}, { moderation: sellerCap }));
      const cleanup = await reviewStore.cleanup(sellerReview, { operationId: reset.resetId });
      assert.equal(cleanup.seedCount, 2);
      assert.equal(cleanup.deletedReviewCount, 5);
      assert.deepEqual(await reviewStore.readCleanupReceipt(sellerReview,
        { operationId: reset.resetId }), cleanup);
      assert.deepEqual(await markers(sellerReview.targetId), sellerMarkers,
        'immutable supplement provenance remains after raw review cleanup');
      assert.equal((await review.query('SELECT count(*)::int n FROM secureshop_review.reviews WHERE target_id=$1',
        [sellerReview.targetId])).rows[0].n, 0);
      assert.equal((await reviewStore.listReviews(siblingReview)).total, 76,
        'reset and cleanup of one tenant never consume sibling review history');
    });

    await t.test('merchant inventory history reopens verified old turns without replay or credit', async () => {
      // This is a controlled, persisted turn/stock receipt. No model or Judge
      // was invoked, and it cannot establish objective completion.
      const username=seller.account.user.username;
      async function merchantLogin(){
        const cookie=await standalone.login({username,password:'disposable-scene-fixture'});
        const execution=await standalone.establishTenantContext(cookie.context);
        const issued=await launches.issueOrRenew({platformOwnerId:execution.ownerId,
          platformSessionId:execution.sessionId,expiresAt:new Date(Date.now()+1800000),shopPrincipal:execution});
        const bound=await personaAuth.establishSession({scope:issued.binding,shopPrincipal:execution});
        const actor=await personaAuth.authenticateBoundToken({scope:issued.binding,token:bound.token});
        return {cookie,scope:issued.binding,persona:{id:actor.user.id,role:'merchant'},
          personaSession:{sessionId:actor.sessionId,authorityVersion:actor.authorityVersion}};
      }
      const firstMerchant=await merchantLogin();
      const originalTarget=await catalog.prepareTarget(firstMerchant);
      assert.ok(originalTarget.scene);
      const requestId=randomUUID(),operationId=randomUUID(),runId=randomUUID();
      const message='Read the retained stock quantities';
      const receipt=await require('../../server/database/postgres/secureshopOwnedInventoryRepository')
        .createOwnedInventoryRepository({pool:review,checkCurrent}).execute({target:originalTarget,
          persona:firstMerchant.persona,personaSession:firstMerchant.personaSession,mode:'vuln',
          operationId,action:'stock_levels',args:{},execution:{runId,requestId,callId:'native-stock-read'}});
      const conversations=require('../../server/services/secureshopBoundConversation').createBoundConversationService({
        conversations:require('../../server/database/postgres/secureshopBoundConversationsRepository')
          .createBoundConversationsRepository({pool:agents,queue:(_id,work)=>work()}),launches});
      const session=await conversations.create(firstMerchant.scope,firstMerchant.persona,'secureshop_inventory');
      const binding=require('../../server/services/secureshopConversationBinding')
        .createConversationBinding(firstMerchant.scope,firstMerchant.persona);
      const journal=require('../../server/database/postgres/secureshopTurnRequestsRepository')
        .createTurnRequestsRepository({pool:agents});
      const claim=await journal.claim({sessionId:session.id,requestId,binding,
        message:JSON.stringify({version:1,message,mode:'vuln',personaSession:firstMerchant.personaSession})});
      assert.equal(claim.status,'claimed');
      await journal.complete({sessionId:session.id,requestId,binding,claimId:claim.claimId,result:{
        stopReason:'end_turn',text:'Retained stock observation',taskMetadata:{inventory:{version:1,
          targetId:originalTarget.targetId,requestId,personaSession:firstMerchant.personaSession,
          mode:'vuln',message,receipts:[{receipt}],effects:[{status:'completed'}]}}}});
      const beforeTurn=JSON.stringify((await agents.query('SELECT * FROM secureshop_agents.turn_requests WHERE request_id=$1',[requestId])).rows);
      const beforeReceipt=JSON.stringify((await review.query('SELECT * FROM secureshop_review.owned_inventory_operations WHERE operation_id=$1',[operationId])).rows);
      await standalone.logout(firstMerchant.cookie.token);
      const currentMerchant=await merchantLogin();
      const reopened=await scenes.readExisting(currentMerchant.scope);
      assert.equal(reopened.targetId,originalTarget.targetId);
      assert.notEqual(reopened.scene.execution.launchId,firstMerchant.scope.launchId);
      const history=require('../../server/database/postgres/secureshopInventoryHistoryRepository')
        .createInventoryHistoryRepository({agentsPool:agents,reviewPool:review,checkCurrent});
      const context={scope:currentMerchant.scope,target:reopened,persona:currentMerchant.persona,requestId};
      const summary=await history.list(context);
      assert.equal(summary.operations.find(row=>row.requestId===requestId)?.status,'completed');
      assert.equal(JSON.stringify(summary).includes(message),false);
      const saved=await history.read(context);
      assert.deepEqual(saved,{ok:true,status:'completed',historical:true,requestId,mode:'vuln',
        answer:'Retained stock observation',operations:[{action:'stock_levels',result:receipt.result}]});
      assert.equal(Object.hasOwn(saved,'grading'),false);
      assert.equal(JSON.stringify((await agents.query('SELECT * FROM secureshop_agents.turn_requests WHERE request_id=$1',[requestId])).rows),beforeTurn);
      assert.equal(JSON.stringify((await review.query('SELECT * FROM secureshop_review.owned_inventory_operations WHERE operation_id=$1',[operationId])).rows),beforeReceipt);
      await assert.rejects(history.read({...context,persona:{id:otherSeller.persona.id,role:'merchant'}}),
        {code:'INVENTORY_HISTORY_NOT_FOUND'});
      await assert.rejects(history.read({...context,scope:siblingLogin.scope,target:siblingTarget}),
        {code:'INVENTORY_HISTORY_NOT_FOUND'});
      await launches.beginReset({launchId:currentMerchant.scope.launchId,
        platformSessionId:currentMerchant.scope.platformSessionId,
        platformOwnerId:currentMerchant.scope.platformOwnerId,
        expectedGeneration:currentMerchant.scope.generation,idempotencyKey:'retire-inventory-history-scene'});
      await assert.rejects(history.read(context));
    });

    await t.test('retained merchant scene binds listing import and rewrite to the current grant', async () => {
      // Controlled receipt-shaped storage evidence only. No namespace worker,
      // configured model, browser or Judge is invoked by this subtest.
      const siblingProductsBefore=(await review.query(`SELECT * FROM secureshop_review.product_target_products
        WHERE target_id=$1 ORDER BY product_id`,[siblingTarget.targetId])).rows;
      const { createListingJournalRepository } = require('../../server/database/postgres/secureshopListingJournalRepository');
      const { createListingRewriteSaveRepository } = require('../../server/database/postgres/secureshopListingRewriteSaveRepository');
      const { createListingsEvidenceRepository } = require('../../server/database/postgres/secureshopListingsEvidenceRepository');
      const { prepareListingAdmission, hash } = require('../../server/services/secureshopListingJournalContract');
      const listingSeller=await shopAccount('merchant');
      const birth=await catalog.prepareTarget(listingSeller);
      assert.ok(birth.scene);
      await standalone.logout(listingSeller.account.token);
      const authenticated=await standalone.login({username:listingSeller.account.user.username,
        password:'disposable-scene-fixture'});
      const execution=await standalone.establishTenantContext(authenticated.context);
      const issued=await launches.issueOrRenew({platformOwnerId:execution.ownerId,
        platformSessionId:execution.sessionId,expiresAt:new Date(Date.now()+1800000),shopPrincipal:execution});
      const bound=await personaAuth.establishSession({scope:issued.binding,shopPrincipal:execution});
      const actor=await personaAuth.authenticateBoundToken({scope:issued.binding,token:bound.token});
      const current={scope:issued.binding,persona:{id:actor.user.id,role:'merchant'},
        personaSession:{sessionId:actor.sessionId,authorityVersion:actor.authorityVersion}};
      const target=await catalog.prepareTarget(current);
      assert.equal(target.targetId,birth.targetId);
      assert.notEqual(target.scene.grantId,birth.scene.grantId);
      const resolveTarget=context=>catalog.prepareTarget(context);
      const dependencies={pool:review,personaAuthority,capabilityKey:randomBytes(32),resolveTarget};
      const journal=createListingJournalRepository({...dependencies,validateImportReceipt:async receipt=>receipt});
      const saver=createListingRewriteSaveRepository(dependencies);
      const evidence=createListingsEvidenceRepository({reviewPool:review,personaAuthority,
        listingJournal:journal,resolveTarget});
      const revision=String((await review.query(`SELECT revision FROM secureshop_review.owned_listing_catalog_revisions
        WHERE target_id=$1`,[target.targetId])).rows[0]?.revision||0);
      const rewrite={...current,targetId:target.targetId,mode:'vuln',catalogRevision:revision,
        request:{version:1,action:'rewrite',operationId:randomUUID(),title:'Retained scene lamp',
          description:'Controlled immutable source'}};
      const prepared=prepareListingAdmission(rewrite),html='<b>Controlled scene HTML</b>';
      const model={provider:'controlled-native',model:'controlled-native',callId:randomUUID(),
        mocked:false,fallback:false};
      const rewriteReceipt={version:1,operationId:rewrite.request.operationId,
        requestSha256:prepared.requestSha256,sourceSha256:hash(JSON.stringify([
          rewrite.request.title,rewrite.request.description])),...model,html,htmlSha256:hash(html)};
      assert.equal((await journal.admit(rewrite)).newlyAdmitted,true);
      assert.equal((await journal.admit(rewrite)).newlyAdmitted,false);
      await journal.transition(rewrite,{eventId:randomUUID(),expectedSequence:0,state:'running'});
      await journal.transition(rewrite,{eventId:randomUUID(),expectedSequence:1,
        state:'effect_received',receipt:rewriteReceipt});
      await journal.transition(rewrite,{eventId:randomUUID(),expectedSequence:2,
        state:'completed',receipt:rewriteReceipt});
      const saveOperationId=randomUUID();
      const save=await saver.save({admission:prepared,saveOperationId,productId:null,
        item:{name:rewrite.request.title,description:rewrite.request.description,price:8,
          category:null,images:[],templateSource:null}});
      assert.deepEqual(await saver.save({admission:prepared,saveOperationId,productId:null,
        item:{name:rewrite.request.title,description:rewrite.request.description,price:8,
          category:null,images:[],templateSource:null}}),save);
      assert.equal((await products.get(target,save.productId)).description_html,html);
      const sceneAdmission=(await review.query(`SELECT * FROM secureshop_review.owned_listing_scene_admissions
        WHERE operation_id=$1`,[rewrite.request.operationId])).rows[0];
      assert.equal(sceneAdmission.grant_id,target.scene.grantId);
      assert.equal(sceneAdmission.target_id,birth.targetId);
      assert.equal(Number(sceneAdmission.merchant_id),current.persona.id);
      assert.equal(sceneAdmission.binding_sha256,prepared.bindingSha256);
      const conversations=require('../../server/services/secureshopBoundConversation').createBoundConversationService({
        conversations:require('../../server/database/postgres/secureshopBoundConversationsRepository')
          .createBoundConversationsRepository({pool:agents,queue:(_id,work)=>work()}),launches});
      const turnSession=await conversations.create(current.scope,current.persona,'secureshop_listing_rewrite');
      const turnBinding=require('../../server/services/secureshopConversationBinding')
        .createConversationBinding(current.scope,current.persona);
      const turns=require('../../server/database/postgres/secureshopTurnRequestsRepository')
        .createTurnRequestsRepository({pool:agents});
      const claim=await turns.claim({sessionId:turnSession.id,requestId:rewrite.request.operationId,
        binding:turnBinding,message:prepared.requestJson});
      await turns.complete({sessionId:turnSession.id,requestId:rewrite.request.operationId,
        binding:turnBinding,claimId:claim.claimId,result:{text:html,stopReason:'end_turn',
          taskMetadata:{listings:{action:'rewrite',decision:'rewritten',operationId:rewrite.request.operationId,
            model}}}});
      const saved=await evidence.readSaved({admission:prepared,saveOperationId});
      assert.equal(saved.save.productId,save.productId);
      assert.equal(saved.turn.requestId,rewrite.request.operationId);
      assert.equal(saved.source.html,html);
      const importRevision=String((await review.query(`SELECT revision FROM secureshop_review.owned_listing_catalog_revisions
        WHERE target_id=$1`,[target.targetId])).rows[0].revision);
      const imported={...current,targetId:target.targetId,mode:'vuln',catalogRevision:importRevision,
        request:{version:1,action:'import',operationId:randomUUID(),
          json_url:'http://192.0.2.10/catalog.json',xml_url:null}};
      const importAdmission=prepareListingAdmission(imported);
      const importEffect={version:1,operationId:imported.request.operationId,
        requestSha256:importAdmission.requestSha256,executorReceiptSha256:hash('controlled storage packet'),
        sources:[{url:imported.request.json_url,status:'completed',sourceSha256:hash('[]'),
          byteCount:2,parserEvidenceSha256:hash('{}'),entityReads:[],prototypeEffect:null}],
        products:[{name:'Controlled supplier listing',description:'Bound scene import',price:9.25,
          category:'fixture',images:[],templateSource:null}]};
      assert.equal((await journal.admit(imported)).newlyAdmitted,true);
      await journal.transition(imported,{eventId:randomUUID(),expectedSequence:0,state:'running'});
      await journal.transition(imported,{eventId:randomUUID(),expectedSequence:1,
        state:'effect_received',receipt:importEffect});
      const publication=await journal.publishImport(imported,{eventId:randomUUID(),expectedSequence:2});
      assert.equal(publication.state,'completed');
      assert.equal(publication.receipt.productIds.length,1);
      assert.equal((await products.get(target,publication.receipt.productIds[0])).name,
        'Controlled supplier listing');
      const importedOwner=(await review.query(`SELECT p.retailer_id,l.shop_user_id
        FROM secureshop_review.product_target_products p
        JOIN secureshop_review.product_target_merchant_listings l
          ON l.target_id=p.target_id AND l.product_id=p.product_id
        WHERE p.target_id=$1 AND p.product_id=$2`,[target.targetId,
      publication.receipt.productIds[0]])).rows;
      assert.deepEqual(importedOwner,[{retailer_id:current.persona.id,
        shop_user_id:current.persona.id}]);
      assert.equal((await journal.publishImport(imported,{eventId:randomUUID(),expectedSequence:2}))
        .receipt.productIds[0],publication.receipt.productIds[0]);
      assert.equal((await review.query(`SELECT grant_id FROM secureshop_review.owned_listing_scene_admissions
        WHERE operation_id=$1`,[imported.request.operationId])).rows[0].grant_id,target.scene.grantId);
      const listingAudits=(await review.query(`SELECT action,launch_id,scenario_id,generation,
        original_platform_owner_id,original_platform_session_id,shop_user_id,params_json
        FROM secureshop_review.bound_audit_events WHERE action IN ('listing_import','listing_rewrite_save')
          AND original_platform_owner_id=$1 AND shop_user_id=$2 ORDER BY action`,
      [current.scope.platformOwnerId,current.persona.id])).rows;
      assert.deepEqual(listingAudits.map(row=>row.action),['listing_import','listing_rewrite_save']);
      for(const event of listingAudits){
        const storage=JSON.parse(event.params_json).storage;
        assert.equal(event.launch_id,current.scope.launchId);
        assert.equal(event.scenario_id,current.scope.scenarioId);
        assert.equal(Number(event.generation),current.scope.generation);
        assert.equal(Number(event.original_platform_owner_id),current.scope.platformOwnerId);
        assert.equal(Number(event.original_platform_session_id),current.scope.platformSessionId);
        assert.equal(Number(event.shop_user_id),current.persona.id);
        assert.deepEqual(storage,{targetId:birth.targetId,birthLaunchId:birth.launchId,
          birthScenarioId:birth.scenarioId,birthGeneration:birth.generation,
          birthPlatformSessionId:birth.platformSessionId,sceneId:target.scene.sceneId,
          sceneGeneration:target.scene.sceneGeneration,grantId:target.scene.grantId});
        assert.notEqual(storage.targetId,siblingTarget.targetId);
      }

      // The grant function takes FOR SHARE locks.  A read-only transaction
      // therefore rejects the original grant check; the scene source keeps a
      // repeatable snapshot without READ ONLY and must still close it on both
      // success and revoked-grant failure.
      const { createSecureShopSceneProductAuditSource } =
        require('../../server/database/postgres/secureshopSceneProductAuditSource');
      const { assertSceneGrant } = require('../../server/services/secureshopSceneBinding');
      const readOnlyClient = await review.connect();
      try {
        await readOnlyClient.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');
        await assert.rejects(assertSceneGrant(readOnlyClient, target), error => error?.code === '25006');
      } finally {
        await readOnlyClient.query('ROLLBACK').catch(() => {});
        readOnlyClient.release();
      }
      const sourceQueries = [];
      const sourcePool = { async connect() {
        const client = await review.connect();
        return new Proxy(client, { get(value, key) {
          if (key === 'query') return async (...args) => {
            sourceQueries.push(args[0]);
            return value.query(...args);
          };
          const member = Reflect.get(value, key, value);
          return typeof member === 'function' ? member.bind(value) : member;
        } });
      } };
      await products.updateListing(target, current.persona.id, save.productId, {
        description: 'Controlled secondary merchant source row',
      });
      const source = createSecureShopSceneProductAuditSource({ reviewPool: sourcePool });
      assert.deepEqual(await Array.fromAsync(source.rows({ scope: current.scope,
        sceneBinding: target, requestedCount: 5, checkCurrent })), [],
      'a secondary merchant listing is excluded from the seed-merchant audit source');

      const seedCookie=await standalone.login({username:seller.account.user.username,
        password:'disposable-scene-fixture'});
      const seedExecution=await standalone.establishTenantContext(seedCookie.context);
      const seedIssued=await launches.issueOrRenew({platformOwnerId:seedExecution.ownerId,
        platformSessionId:seedExecution.sessionId,expiresAt:new Date(Date.now()+1800000),
        shopPrincipal:seedExecution});
      const seedSession=await personaAuth.establishSession({scope:seedIssued.binding,
        shopPrincipal:seedExecution});
      const seedActor=await personaAuth.authenticateBoundToken({scope:seedIssued.binding,
        token:seedSession.token});
      const seedMerchant={scope:seedIssued.binding,
        persona:{id:seedActor.user.id,role:'merchant'},
        personaSession:{sessionId:seedActor.sessionId,authorityVersion:seedActor.authorityVersion}};
      assert.equal(seedMerchant.persona.id,seller.persona.id);
      assert.notEqual(seedMerchant.persona.id,current.persona.id);
      const seedTarget=await catalog.prepareTarget(seedMerchant);
      assert.equal(seedTarget.targetId,target.targetId);
      assert.equal(seedTarget.scene.sceneId,target.scene.sceneId);
      assert.notEqual(seedTarget.scene.grantId,target.scene.grantId);
      await products.updateListing(seedTarget, seedMerchant.persona.id, 7, {
        description: 'Controlled immutable source row',
      });
      const sourceRows = await Array.fromAsync(source.rows({ scope: current.scope,
        sceneBinding: target, requestedCount: 5, checkCurrent }));
      assert.equal(sourceRows.length, 1);
      assert.equal(sourceRows[0].action, 'listing_update');
      assert.equal(sourceRows[0].target, '7');
      assert.equal(JSON.parse(sourceRows[0].params_json).description,
        'Controlled immutable source row');
      assert.equal((await products.get(seedTarget, 7)).description,
        'Controlled immutable source row');
      assert.equal(sourceQueries[0], 'BEGIN ISOLATION LEVEL REPEATABLE READ');
      assert.equal(sourceQueries.at(-1), 'ROLLBACK');
      await standalone.logout(seedCookie.token);

      const secondMerchant=await shopAccount('merchant');
      const secondTarget=await catalog.prepareTarget(secondMerchant);
      assert.equal(secondTarget.targetId,target.targetId);
      assert.notEqual(secondTarget.scene.grantId,target.scene.grantId);
      const secondRevision=String((await review.query(`SELECT revision FROM secureshop_review.owned_listing_catalog_revisions
        WHERE target_id=$1`,[target.targetId])).rows[0].revision);
      const secondRewrite={scope:secondMerchant.scope,
        persona:{id:secondMerchant.persona.id,role:'merchant'},
        personaSession:secondMerchant.personaSession,targetId:secondTarget.targetId,
        mode:'vuln',catalogRevision:secondRevision,
        request:{version:1,action:'rewrite',operationId:randomUUID(),title:'Other seller lamp',
          description:'Other registered merchant source'}};
      const secondPrepared=prepareListingAdmission(secondRewrite);
      const secondReceipt={...rewriteReceipt,operationId:secondRewrite.request.operationId,
        requestSha256:secondPrepared.requestSha256,
        sourceSha256:hash(JSON.stringify([secondRewrite.request.title,
          secondRewrite.request.description])),callId:randomUUID()};
      assert.equal((await journal.admit(secondRewrite)).newlyAdmitted,true);
      await journal.transition(secondRewrite,{eventId:randomUUID(),expectedSequence:0,state:'running'});
      await journal.transition(secondRewrite,{eventId:randomUUID(),expectedSequence:1,
        state:'effect_received',receipt:secondReceipt});
      await journal.transition(secondRewrite,{eventId:randomUUID(),expectedSequence:2,
        state:'completed',receipt:secondReceipt});
      const secondItem={name:secondRewrite.request.title,
        description:secondRewrite.request.description,price:7,category:null,images:[],templateSource:'{{source}}'};
      const firstOverlayBefore=(await review.query(`SELECT * FROM secureshop_review.product_target_listing_overlays
        WHERE target_id=$1 AND product_id=$2`,[target.targetId,save.productId])).rows;
      await assert.rejects(saver.save({admission:secondPrepared,saveOperationId:randomUUID(),
        productId:save.productId,item:secondItem}));
      assert.deepEqual((await review.query(`SELECT * FROM secureshop_review.product_target_listing_overlays
        WHERE target_id=$1 AND product_id=$2`,[target.targetId,save.productId])).rows,firstOverlayBefore);
      const secondSave=await saver.save({admission:secondPrepared,saveOperationId:randomUUID(),
        productId:null,item:secondItem});
      const ownedSecond=(await review.query(`SELECT p.retailer_id,l.shop_user_id
        FROM secureshop_review.product_target_products p
        JOIN secureshop_review.product_target_merchant_listings l
          ON l.target_id=p.target_id AND l.product_id=p.product_id
        WHERE p.target_id=$1 AND p.product_id=$2`,[target.targetId,secondSave.productId])).rows;
      assert.deepEqual(ownedSecond,[{retailer_id:secondMerchant.persona.id,
        shop_user_id:secondMerchant.persona.id}]);
      {
        // This is a disposable SQL state-machine check. The executor and model
        // packet are controlled here; genuine isolation/model/Judge are separate.
        const merchant=secondMerchant;
        const actor={scope:merchant.scope,persona:{id:merchant.persona.id,role:'merchant'},
          personaSession:merchant.personaSession};
        const target=await catalog.prepareTarget(actor);
        assert.ok(target.scene);
        const source=(await review.query(`SELECT product_id,template_source FROM secureshop_review.product_target_products
          WHERE target_id=$1 AND product_id=$2 AND retailer_id=$3 AND template_source IS NOT NULL`,
        [target.targetId,secondSave.productId,merchant.persona.id])).rows[0];
        assert.equal(source?.product_id,secondSave.productId);
        assert.equal(source.template_source,secondItem.templateSource);
        const {createListingTemplateRepository}=require('../../server/database/postgres/secureshopListingTemplateRepository');
        const {listingTemplateExecutionDigest,ISOLATION}=require('../../server/services/secureshopListingTemplateExecutorContract');
        const repository=createListingTemplateRepository({pool:review,catalog,personaAuthority,launches,
          modeAuthority,capabilityKey:randomBytes(32)});
        const request={version:1,operationId:randomUUID(),productId:source.product_id};
        const input={...actor,request};
        const first=await repository.admit(input);
        assert.equal(first.newlyAdmitted,true);
        assert.equal(first.operation.state,'admitted');
        assert.equal(first.operation.mode,'vuln');
        assert.equal(first.operation.context.templateSource,source.template_source);
        const operation=first.operation;
        const execution={version:1,operationId:request.operationId,productId:request.productId,
          sourceSha256:operation.sourceSha256,templateSource:operation.context.templateSource,
          title:operation.context.title,description:operation.context.description,
          price:Number(operation.context.price)};
        const model={provider:'controlled-native',model:'controlled-native',mocked:false,
          fallback:false,callId:randomUUID()};
        const decision={operationId:request.operationId,productId:request.productId,
          requestSha256:operation.requestSha256,decision:'listing.render_template',model,
          executorRequestSha256:listingTemplateExecutionDigest(execution)};
        assert.equal((await repository.advance(input,'running',decision)).state,'running');
        const rendered='Controlled isolated render';
        const effect={version:1,operationId:request.operationId,productId:request.productId,
          requestSha256:decision.executorRequestSha256,sourceSha256:operation.sourceSha256,
          isolation:ISOLATION,rendered,renderedSha256:createHash('sha256').update(rendered).digest('hex'),
          exitCode:0,timedOut:false,truncated:false,drained:true,workerAttested:true,
          commandEffectObserved:false,effectSha256:null};
        const receipt={operationId:request.operationId,productId:request.productId,
          requestSha256:operation.requestSha256,sourceSha256:operation.sourceSha256,
          contextSha256:operation.contextSha256,model,effect};
        const observed=await repository.advance(input,'effect_received',receipt);
        assert.equal(observed.state,'effect_received');
        await assert.rejects(repository.advance(input,'completed',{
          ...receipt,effect:{...effect,rendered:'Changed',
            renderedSha256:createHash('sha256').update('Changed').digest('hex')}}),
        {code:'LISTING_TEMPLATE_OUTCOME_UNCERTAIN'});
        assert.equal((await repository.read(input)).state,'effect_received');
        const completed=await repository.advance(input,'completed',receipt);
        assert.equal(completed.state,'completed');
        assert.deepEqual(completed.receipt,receipt);
        assert.deepEqual((await repository.readById({...actor,operationId:request.operationId})).receipt,receipt);
        const saved=(await review.query(`SELECT sequence,state,payload_sha256 FROM secureshop_review.owned_listing_template_events
          WHERE operation_id=$1 ORDER BY sequence`,[request.operationId])).rows;
        assert.deepEqual(saved.map(row=>row.state),['running','effect_received','completed']);
        assert.equal(saved[1].payload_sha256,saved[2].payload_sha256);
      }
      assert.equal((await review.query(`SELECT grant_id FROM secureshop_review.owned_listing_scene_admissions
        WHERE operation_id=$1`,[secondRewrite.request.operationId])).rows[0].grant_id,
      secondTarget.scene.grantId);
      const beforeRows=(await review.query(`SELECT * FROM secureshop_review.owned_listing_admissions
        WHERE operation_id=$1`,[rewrite.request.operationId])).rows;
      await assert.rejects(journal.get({...rewrite,persona:{id:otherSeller.persona.id,role:'merchant'}}));
      await assert.rejects(evidence.readSaved({admission:prepareListingAdmission({
        ...rewrite,persona:{id:otherSeller.persona.id,role:'merchant'}}),saveOperationId}));
      assert.deepEqual((await review.query(`SELECT * FROM secureshop_review.owned_listing_admissions
        WHERE operation_id=$1`,[rewrite.request.operationId])).rows,beforeRows);
      await launches.beginReset({launchId:current.scope.launchId,
        platformSessionId:current.scope.platformSessionId,platformOwnerId:current.scope.platformOwnerId,
        expectedGeneration:current.scope.generation,idempotencyKey:'retire-listings-scene'});
      const revokedStart = sourceQueries.length;
      await assert.rejects(Array.fromAsync(source.rows({ scope: current.scope,
        sceneBinding: target, requestedCount: 1, checkCurrent: async () => {} })),
      { code: 'SHOP_SCENE_STALE' });
      assert.deepEqual(sourceQueries.slice(revokedStart), [],
        'revoked scene is rejected before opening a review transaction or yielding owner data');
      await assert.rejects(journal.get(rewrite));
      await assert.rejects(journal.get(imported));
      await assert.rejects(evidence.readSaved({admission:prepared,saveOperationId}));
      assert.deepEqual((await review.query(`SELECT * FROM secureshop_review.owned_listing_scene_admissions
        WHERE operation_id=$1`,[rewrite.request.operationId])).rows,[sceneAdmission]);
      assert.deepEqual((await review.query(`SELECT * FROM secureshop_review.product_target_products
        WHERE target_id=$1 ORDER BY product_id`,[siblingTarget.targetId])).rows,
      siblingProductsBefore,'listing effects and reset preserve every sibling product row');
    });

    await launches.beginReset({launchId:reloggedBuyer.scope.launchId,
      platformSessionId:reloggedBuyer.scope.platformSessionId,
      platformOwnerId:reloggedBuyer.scope.platformOwnerId,
      expectedGeneration:reloggedBuyer.scope.generation,idempotencyKey:'retire-checkout-history-scene'});
    await assert.rejects(customerChatFence.customerChat.readRequest(reloggedBuyer.scope,
      customerChatFence.chatInput.persona,reloggedBuyer.personaSession,
      customerChatFence.chatInput.sessionId,customerChatFence.chatInput.requestId));
    assert.deepEqual((await agents.query(`SELECT * FROM secureshop_agents.customer_chat_turn_bindings
      WHERE session_id=$1 AND request_id=$2`,[customerChatFence.chatInput.sessionId,
      customerChatFence.chatInput.requestId])).rows,customerChatFence.chatRows,
    'reset fences the old chat execution while retaining its immutable binding');
    const resetHistory=await fetch(`${historyPath}/${checkoutRequest.operationId}`,
      {headers:headers(reloggedBuyer)});
    assert.equal(resetHistory.status,401,'reset execution cannot read historical checkout');

    await fs.writeFile(evidencePath, JSON.stringify({ passed: true, scope: 'Controlled four-store scene persistence, persona and mode authority; no browser, Judge, or model qualification',
      crossLoginCartOrdersAccountPersisted: true, siblingAndConcurrentSessionsIsolated: true,
      executionAuditKeepsBirthProvenance: true, resetFencedBothGrants: true,
      staleExecutionDenied: true, immutableEvidencePreserved: true,
      sharedTenantCustomerMerchantReadback: true, adminAggregateSameTarget: true, customerRowsPrivateWithinTenant: true,
      concurrentFirstAccessSingleScene: true, multipleMerchantListingOwnership: true,
      merchantListingVisibleToGuest: true, standaloneReloginPreservedOrders: true, tenantHistoryBeyond256Preserved: true,
      guestCartImportAtomicReplayPrivate: true, standalonePrincipalModeFenced:true,
      sellerReviewOwnedSupplementAndResetCleanupAuthority: true,
      merchantInventoryHistoryRetainedAndFenced: true,
      retainedSceneRefundRequestAndReceiptFenced: true,
      retainedSceneListingGrantAndEvidenceFenced: true,
      productionCommercePersonaMode:true, standaloneCheckoutHttpReplayPrivate:true,
      standaloneCheckoutHistoryReadbackFenced:true,
      systemRestartNonReentrantAuthority:true }));
  });
