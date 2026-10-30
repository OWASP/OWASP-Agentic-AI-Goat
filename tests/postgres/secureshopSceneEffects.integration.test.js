'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const { Module, createRequire } = require('node:module');
const { createHash, randomUUID } = require('node:crypto');
const { Pool } = require('pg');
const { migrate } = require('../../db/postgres/migrate');
const { createSecureShopStandaloneAuthRepository } = require('../../server/database/postgres/secureshopStandaloneAuthRepository');
const { createSecureShopStandaloneAuthService } = require('../../server/services/secureshopStandaloneAuth');
const { createSecureShopLaunchRepository } = require('../../server/database/postgres/secureshopLaunchRepository');
const { createSecureShopSceneRepository } = require('../../server/database/postgres/secureshopSceneRepository');
const { createSelectedSceneEffect } = require('../../server/database/postgres/secureshopSelectedSceneEffect');
const { createSecureShopScenes } = require('../../server/services/secureshopScenes');
const { createLaunchScope } = require('../../server/services/secureshopConversationBinding');
const { createSecureShopBoundProductRepository } = require('../../server/database/postgres/secureshopBoundProductRepository');
const { createSecureShopBoundReviewRepository } = require('../../server/database/postgres/secureshopBoundReviewRepository');
const { createSecureShopBoundProductRetrievalRepository } = require('../../server/database/postgres/secureshopBoundProductRetrievalRepository');
const { createSecureShopBoundManualIngestRepository } = require('../../server/database/postgres/secureshopBoundManualIngestRepository');
const { createSecureShopEmbeddingRevisionRepository } = require('../../server/database/postgres/secureshopEmbeddingRevisionRepository');
const { createSecureShopSystemRestartRepository } = require('../../server/database/postgres/secureshopSystemRestartRepository');
const { createBoundAuditStore } = require('../../server/database/postgres/secureshopBoundAuditRepository');
const { restartRequestDigest } = require('../../server/services/secureshopSystemRestartContract');
const { VERSION, ISOLATION } = require('../../sidecars/sandbox-runner/owned-system/restart-wire');

const prefix = 'PG_SECURESHOP_SCENE_EFFECTS_';
const keys = ['IDENTITY_RUNTIME_URL', 'IDENTITY_MIGRATION_URL', 'REVIEW_RUNTIME_URL', 'REVIEW_MIGRATION_URL'];
const enabled = process.env.SECURESHOP_SCENE_EFFECTS_NATIVE === '1'
  && process.env.PG_TEST_DISPOSABLE === 'yes' && keys.every(key => process.env[prefix + key]);
const reviewDirectory = path.resolve(__dirname, '../../db/postgres/workshop-migrations/secureshop_review');
const identityDirectory = path.resolve(__dirname, '../../db/postgres/identity-migrations');
const digest = value => createHash('sha256').update(value).digest('hex');
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
// Restrict migration discovery in memory; apply the original on-disk SQL bytes.
function historicalMigrator(directory, ceiling) {
  const filename = require.resolve('../../db/postgres/migrate');
  const local = createRequire(filename);
  const original = require('node:fs/promises');
  const virtual = { ...original, async readdir(target, ...args) {
    const names = await original.readdir(target, ...args);
    return path.resolve(target) === directory
      ? names.filter(name => !/^\d{4}_[a-z0-9_]+\.sql$/.test(name)
        || Number(name.slice(0, 4)) <= ceiling) : names;
  } };
  const loaded = new Module(filename, module);
  loaded.filename = filename;
  loaded.require = name => name === 'node:fs/promises' ? virtual : local(name);
  loaded._compile(require('node:fs').readFileSync(filename, 'utf8'), filename);
  return loaded.exports.migrate;
}

test('scene effects preserve birth and current execution through migration and reset',
  { skip: !enabled, timeout: 120000 }, async t => {
    assert.equal(path.resolve(process.env.OWASP_AI_GOAT_CURRENT_MAIN_WORKSPACE || '/'), process.cwd());
    const evidencePath = process.env.WORKSHOP_RAG_EVIDENCE_PATH || '';
    assert.ok(path.isAbsolute(evidencePath));
    assert.ok(!path.resolve(evidencePath).startsWith(`${process.cwd()}${path.sep}`));
    const identityMigration = new Pool({ connectionString: disposableUrl('IDENTITY_MIGRATION_URL'), max: 2 });
    const identity = new Pool({ connectionString: disposableUrl('IDENTITY_RUNTIME_URL'), max: 8 });
    const reviewMigration = new Pool({ connectionString: disposableUrl('REVIEW_MIGRATION_URL'), max: 2 });
    const review = new Pool({ connectionString: disposableUrl('REVIEW_RUNTIME_URL'), max: 8 });
    t.after(() => Promise.allSettled([identity.end(), identityMigration.end(), review.end(), reviewMigration.end()]));

    await migrate(identityMigration, identityDirectory);
    await historicalMigrator(reviewDirectory, 28)(reviewMigration, reviewDirectory);
    const migrationFiles = ['0030_scene_retrieval_embedding_effects.sql',
      '0031_scene_restart_effects.sql', '0032_scene_review_targets.sql',
      '0034_manual_scene_execution_receipts.sql'];
    await t.test('fresh and populated forward migrations preserve an existing owner scene', async () => {
      const preview = await reviewMigration.connect();
      try {
        await preview.query('BEGIN');
        for (const name of migrationFiles) await preview.query(await fs.readFile(path.join(reviewDirectory, name), 'utf8'));
        assert.equal((await preview.query('SELECT count(*)::int n FROM secureshop_review.scene_retrieval_embedding_effects')).rows[0].n, 0);
        assert.equal((await preview.query('SELECT count(*)::int n FROM secureshop_review.scene_review_targets')).rows[0].n, 0);
        await preview.query('ROLLBACK');
      } catch (error) { await preview.query('ROLLBACK').catch(() => {}); throw error; }
      finally { preview.release(); }
    });

    const standalone = createSecureShopStandaloneAuthService({
      repository: createSecureShopStandaloneAuthRepository({ pool: identity }),
      hashPassword: async value => require('bcryptjs').hash(value, 4),
    });
    const launches = createSecureShopLaunchRepository(identity);
    const scenes = createSecureShopScenes({ repository: createSecureShopSceneRepository({ pool: identity, launches }),
      reviewPool: review, launches });
    const checkCurrent = scope => launches.assertCurrent(scope);
    const checkCleanup = async () => { throw new Error('cleanup must use owner reset'); };
    const products = createSecureShopBoundProductRepository(review, { checkCurrent, checkCleanup });
    const retrieval = createSecureShopBoundProductRetrievalRepository(review, { checkCurrent, checkCleanup });
    const vector = [1, ...Array(383).fill(0)];
    const suffix = randomUUID().slice(0, 8);
    const password = 'disposable scene effects';
    async function owner(label) {
      const username = `${label}_${suffix}`;
      const auth = await standalone.register({ username, email: `${username}@scene.invalid`, password, role: 'customer' });
      return { username, auth };
    }
    async function launch(auth) {
      return (await launches.issueOrRenew({ platformOwnerId: auth.context.ownerId,
        platformSessionId: auth.context.sessionId,
        expiresAt: new Date(Date.now() + 30 * 60 * 1000).toISOString(),
        shopPrincipal: auth.context })).binding;
    }
    const product = { id: 7, sourceRetailerId: 1, retailerId: 12, name: 'Scene effect item',
      description: 'Owned synthetic review fixture', descriptionHtml: '<p>Owned synthetic review fixture</p>',
      price: 12.5, category: 'fixture', imageUrl: null, images: [], stockQuantity: 40,
      status: 'active', templateSource: '{{source}}', createdAt: null, updatedAt: null };
    async function provision(scope) {
      const reservation = await launches.reserveProductsTarget({ ...scope, expectedGeneration: scope.generation });
      await products.provision({ ...scope, targetId: reservation.targetId }, { ownMerchantId: 12, products: [product] });
      return scenes.resolve(scope);
    }
    const firstOwner = await owner('sceneowner');
    const siblingOwner = await owner('scenesibling');
    const firstExecution = { ...firstOwner.auth,
      context: await standalone.establishTenantContext(firstOwner.auth.context) };
    const secondTenantId = randomUUID();
    const secondTenantSlug = `scene_${suffix}`;
    await identityMigration.query(`INSERT INTO secureshop_auth.tenants(tenant_id,slug)
      VALUES($1,$2)`, [secondTenantId, secondTenantSlug]);
    await identityMigration.query(`INSERT INTO secureshop_auth.tenant_memberships
      (tenant_id,principal_id,shop_user_id,role) VALUES($1,$2,$3,'customer')`,
    [secondTenantId, siblingOwner.auth.context.principalId,
      siblingOwner.auth.context.shopUserId]);
    const isolated = createSecureShopStandaloneAuthService({
      repository: createSecureShopStandaloneAuthRepository({ pool: identity,
        executionTenantSlug: secondTenantSlug }),
      hashPassword: async value => require('bcryptjs').hash(value, 4),
    });
    // Session membership snapshots are immutable. This membership was granted
    // after registration, so only a genuine new login may select this tenant.
    await assert.rejects(isolated.establishTenantContext(siblingOwner.auth.context),
      { code: 'SHOP_AUTH_INVALID' });
    const siblingAuth = await isolated.login({ username: siblingOwner.username, password });
    assert.equal(siblingAuth.context.principalId, siblingOwner.auth.context.principalId);
    assert.notEqual(siblingAuth.context.sessionId, siblingOwner.auth.context.sessionId);
    const siblingExecution = { ...siblingAuth,
      context: await isolated.establishTenantContext(siblingAuth.context) };
    assert.notEqual(firstExecution.context.ownerId, siblingExecution.context.ownerId);
    const birthScope = await launch(firstExecution);
    const birth = await provision(birthScope);
    const siblingScope = await launch(siblingExecution);
    const sibling = await provision(siblingScope);
    // This original v1 receipt is committed before 0034 and must remain
    // byte-valid after the populated migration. The sibling has its own target.
    const siblingBirth = { ...createLaunchScope(siblingScope), targetId: sibling.targetId };
    await retrieval.provision(siblingBirth, { embeddingModel: 'native-fixture', embeddingDimension: 384,
      documents: [{ sourceKind: 'product', sourceId: product.id, chunkIndex: 0,
        text: 'Historical sibling product', embedding: vector }] });
    const historicalOperation = randomUUID();
    const historicalFile = Buffer.from('synthetic historical sibling file');
    const historicalBody = 'Historical sibling manual remains private to this target';
    const historicalSql = `SELECT * FROM
      secureshop_review.append_product_manual_retrieval_attested(
        ${Array.from({ length: 27 }, (_, index) => `$${index + 1}${index === 25 ? '::jsonb' : ''}`).join(',')})`;
    const historicalArgs = [historicalOperation, sibling.targetId, siblingScope.launchId, siblingScope.scenarioId,
      siblingScope.generation, siblingScope.platformOwnerId, siblingScope.platformSessionId,
      product.id, product.retailerId, randomUUID(), siblingScope.launchId,
      siblingScope.scenarioId, siblingScope.generation, siblingScope.platformOwnerId,
      siblingScope.platformSessionId,
      `/uploads/product_manuals/${product.id}/${historicalOperation}-manual`,
      historicalFile.length, Buffer.from(digest(historicalFile), 'hex'),
      'historical-sibling.txt', 'text/plain', true, 'controlled-native',
      Buffer.from(digest(historicalBody), 'hex'), 'native-fixture', 384,
      JSON.stringify([{ text: historicalBody, embedding: vector }]), Buffer.alloc(32, 0xaa)];
    const historicalAppend = (await review.query(historicalSql, historicalArgs)).rows[0];
    assert.equal(historicalAppend.replayed, false);
    const historicalReceiptSha = historicalAppend.receipt_sha256.toString('hex');
    const legacyReservation = await launches.reserveReviewsTarget({ ...birthScope,
      expectedGeneration: birthScope.generation });
    const legacyReviewBirth = { ...birthScope, targetId: legacyReservation.targetId };
    const historicalReviews = [
      { productId: product.id, authorId: 11, body: 'Legacy approved review', rating: 5 },
      { productId: product.id, authorId: 11, body: 'Legacy pending review', rating: 4 },
    ];
    // Historical migration input only: seed the 0028 schema through its
    // migration role, not current APIs that require the later scene mapping.
    // These rows prove preservation, not authenticated moderation or credit.
    const historicalClient = await reviewMigration.connect();
    let historicalReviewRows, historicalReviewTarget;
    try {
      await historicalClient.query('BEGIN');
      await historicalClient.query(`INSERT INTO secureshop_review.review_targets
        (target_id,launch_id,scenario_id,generation,original_platform_owner_id,
         original_platform_session_id,seed_count,seed_sha256)
        VALUES($1,$2,$3,$4,$5,$6,$7,$8)`,
      [legacyReviewBirth.targetId, birthScope.launchId, birthScope.scenarioId,
        birthScope.generation, birthScope.platformOwnerId, birthScope.platformSessionId,
        historicalReviews.length, Buffer.from(digest(JSON.stringify(historicalReviews)), 'hex')]);
      for (const fixture of historicalReviews) await historicalClient.query(`
        INSERT INTO secureshop_review.reviews(target_id,product_id,author_id,body,rating)
        VALUES($1,$2,$3,$4,$5)`,
      [legacyReviewBirth.targetId, fixture.productId, fixture.authorId, fixture.body, fixture.rating]);
      await historicalClient.query(`UPDATE secureshop_review.reviews
        SET status='approved',moderator_kind='manual',moderated_at=clock_timestamp()
        WHERE target_id=$1 AND body=$2 AND status='pending'`,
      [legacyReviewBirth.targetId, historicalReviews[0].body]);
      historicalReviewRows = (await historicalClient.query(
        'SELECT * FROM secureshop_review.reviews WHERE target_id=$1 ORDER BY id',
        [legacyReviewBirth.targetId])).rows;
      historicalReviewTarget = (await historicalClient.query(
        'SELECT * FROM secureshop_review.review_targets WHERE target_id=$1',
        [legacyReviewBirth.targetId])).rows;
      assert.deepEqual(historicalReviewRows.map(row => row.status), ['approved', 'pending']);
      await historicalClient.query('COMMIT');
    } catch (error) { await historicalClient.query('ROLLBACK').catch(() => {}); throw error; }
    finally { historicalClient.release(); }
    await standalone.logout(firstOwner.auth.token);
    const reopenedAuth = await standalone.login({ username: firstOwner.username, password });
    const currentScope = await launch({ ...reopenedAuth,
      context: await standalone.establishTenantContext(reopenedAuth.context) });
    const current = await scenes.resolve(currentScope);
    assert.equal(current.targetId, birth.targetId);
    assert.notEqual(current.scene.execution.launchId, current.launchId);
    assert.notEqual(current.scene.grantId, birth.scene.grantId);
    const applied = await migrate(reviewMigration, reviewDirectory);
    assert.deepEqual(applied.filter(name => migrationFiles.includes(name)), migrationFiles);
    assert.deepEqual(await migrate(reviewMigration, reviewDirectory), []);
    assert.deepEqual((await review.query(
      'SELECT * FROM secureshop_review.reviews WHERE target_id=$1 ORDER BY id',
      [legacyReviewBirth.targetId])).rows, historicalReviewRows);
    assert.deepEqual((await review.query(
      'SELECT * FROM secureshop_review.review_targets WHERE target_id=$1',
      [legacyReviewBirth.targetId])).rows, historicalReviewTarget);
    const reviewStore = createSecureShopBoundReviewRepository(review, {
      checkCurrent, checkRetirement: async () => { throw Error('retirement outside reset'); },
      checkCleanup, enableLearnerSubmissions: true,
      auditStore: createBoundAuditStore({ store: 'review', pool: review }),
    });
    await t.test('selected-scene lease serializes a real scene switch across a local review commit', async () => {
      // A second genuine execution in the same tenant creates a distinct owned
      // scene. Its current selection is independent of the first execution.
      const alternateAuth = await owner('scenelease');
      const alternateScope = await launch({ ...alternateAuth.auth,
        context: await standalone.establishTenantContext(alternateAuth.auth.context) });
      assert.equal(alternateScope.platformOwnerId, currentScope.platformOwnerId);
      const reservation = await launches.reserveProductsTarget({ ...alternateScope,
        expectedGeneration: alternateScope.generation });
      await products.provision({ ...alternateScope, targetId: reservation.targetId },
        { ownMerchantId: 12, products: [product] });
      await scenes.resolve(alternateScope);
      const sceneRepo = createSecureShopSceneRepository({ pool: identity, launches });
      const alternateScene = (await sceneRepo.list(currentScope))
        .find(row => row.storage.targetId === reservation.targetId);
      assert.ok(alternateScene);
      const expectedTarget = { targetId: current.targetId,
        sceneId: current.scene.sceneId, sceneGeneration: current.scene.sceneGeneration,
        grantId: current.scene.grantId };
      let leasePid, selectorPid;
      const lease = createSelectedSceneEffect({ launches, pool: {
        async connect() {
          const client = await identity.connect();
          leasePid = (await client.query('SELECT pg_backend_pid() AS pid')).rows[0].pid;
          return client;
        },
      } });
      const selector = createSecureShopSceneRepository({ launches, pool: {
        async connect() {
          const client = await identity.connect();
          selectorPid = (await client.query('SELECT pg_backend_pid() AS pid')).rows[0].pid;
          return client;
        },
      } });
      let switching, switched = false, localCommitted = false;
      try {
        await lease({ scope: currentScope, expectedTarget }, async () => {
          switching = selector.select(currentScope, alternateScene.sceneId)
            .then(value => { switched = true; return value; });
          // Observe actual PostgreSQL lock contention, not a timer-based
          // assumption that the other operation happened to be slow.
          switching.catch(() => {});
          const deadline = Date.now() + 1500;
          let blocked = false;
          while (Date.now() < deadline) {
            if (selectorPid) {
              const row = (await identityMigration.query(
                'SELECT $1::int=ANY(pg_blocking_pids($2::int)) AS blocked',
                [leasePid, selectorPid])).rows[0];
              if (row.blocked) { blocked = true; break; }
            }
            await new Promise(resolve => setTimeout(resolve, 10));
          }
          assert.equal(blocked, true);
          assert.equal(switched, false);
          const local = await review.connect();
          try {
            await local.query('BEGIN');
            assert.equal((await local.query(`SELECT lifecycle FROM secureshop_review.product_targets
              WHERE target_id=$1 FOR SHARE`, [current.targetId])).rows[0].lifecycle, 'active');
            await local.query('COMMIT'); localCommitted = true;
          } catch (error) { await local.query('ROLLBACK').catch(() => {}); throw error; }
          finally { local.release(); }
          assert.equal(switched, false, 'selection cannot move before local transaction commits');
        });
        await switching;
        assert.equal(localCommitted, true);
        assert.equal(switched, true);
        let staleEffects = 0;
        await assert.rejects(lease({ scope: currentScope, expectedTarget }, async () => {
          staleEffects++;
        }), { code: 'SHOP_SCENE_STALE' });
        assert.equal(staleEffects, 0);
      } finally {
        await switching?.catch(() => {});
        await sceneRepo.select(currentScope, current.scene.sceneId);
      }
      assert.equal((await scenes.readRetained(currentScope)).targetId, current.targetId);
      assert.equal((await scenes.readRetained(siblingScope)).targetId, sibling.targetId);
    });
    const historicalReplay = (await review.query(historicalSql, historicalArgs)).rows[0];
    assert.equal(historicalReplay.replayed, true);
    assert.equal(historicalReplay.receipt_sha256.toString('hex'), historicalReceiptSha);
    const manualStore = createSecureShopBoundManualIngestRepository(review, {
      checkCurrent, getRuntimeFingerprint: () => 'a'.repeat(64),
      auditStore: createBoundAuditStore({ store: 'review', pool: review }),
    });
    const original = await manualStore.readReceipt(siblingBirth,
      { operationId: historicalOperation });
    assert.equal(original.receiptSha256, historicalReceiptSha);
    const originalRow = (await review.query(`SELECT receipt_version,scene_id,scene_grant_id,
      execution_launch_id,execution_platform_session_id
      FROM secureshop_review.product_target_manual_ingests WHERE operation_id=$1`,
    [historicalOperation])).rows[0];
    assert.equal(originalRow.receipt_version, 1);
    assert.equal(originalRow.scene_id, null);
    assert.equal(originalRow.scene_grant_id, null);
    assert.equal(originalRow.execution_launch_id, null);
    assert.equal(originalRow.execution_platform_session_id, null);
    assert.equal((await review.query('SELECT count(*)::int n FROM secureshop_review.product_targets WHERE target_id=ANY($1::uuid[])',
      [[birth.targetId, sibling.targetId]])).rows[0].n, 2);
    assert.equal((await review.query(`SELECT count(*)::int n FROM secureshop_review.scene_review_targets
      WHERE product_target_id=$1 AND review_target_id=$2`,
    [birth.targetId, legacyReviewBirth.targetId])).rows[0].n, 1,
    'populated migration adopts the exact historical review birth');

    const text = `${product.name}\n${product.description}`;
    const docs = [{ sourceKind: 'product', sourceId: product.id, chunkIndex: 0, text, embedding: vector }];
    const embeddings = createSecureShopEmbeddingRevisionRepository(review, {
      checkCurrent, getRuntimeFingerprint: () => 'a'.repeat(64),
    });
    await t.test('retrieval and embedding effects bind new revisions to the current grant', async () => {
      const provisioned = await retrieval.provision(current, { embeddingModel: 'native-fixture', embeddingDimension: 384, documents: docs });
      assert.equal(provisioned.documentCount, 1);
      const ingestionId = randomUUID();
      const ingestion = { operationId: ingestionId, embeddingModel: 'native-fixture', embeddingDimension: 384, documents: docs };
      assert.equal((await retrieval.replaceDocuments(current, ingestion)).replayed, false);
      assert.equal((await retrieval.replaceDocuments(current, ingestion)).replayed, true);
      const snapshot = await embeddings.snapshot(current);
      const publication = { operationId: randomUUID(), sourceSetDigest: snapshot.sourceSetDigest,
        expectedHead: snapshot.expectedHead, expectedRuntimeFingerprint: 'a'.repeat(64),
        documents: snapshot.documents.map(d => ({ sourceKind: d.sourceKind, sourceId: d.sourceId,
          chunkIndex: d.chunkIndex, sourceSha256: d.sourceSha256, embedding: vector })) };
      const published = await embeddings.publish(current, publication);
      assert.equal(published.replayed, false);
      assert.equal((await embeddings.publish(current, publication)).replayed, true);
      const effects = (await review.query(`SELECT * FROM secureshop_review.scene_retrieval_embedding_effects
        WHERE target_id=$1 ORDER BY effect_kind`, [birth.targetId])).rows;
      assert.deepEqual(effects.map(row => row.effect_kind), ['embedding_revision', 'retrieval_ingest', 'retrieval_provision']);
      for (const row of effects) {
        assert.equal(row.grant_id, current.scene.grantId);
        assert.equal(row.birth_launch_id, birthScope.launchId);
        assert.equal(row.execution_launch_id, currentScope.launchId);
        assert.equal(Number(row.birth_session_id), birthScope.platformSessionId);
        assert.equal(Number(row.execution_session_id), currentScope.platformSessionId);
      }
      const reviewBinding = await reviewStore.readSceneTarget(current);
      assert.equal(reviewBinding.targetId, legacyReviewBirth.targetId);
      const seeded = await reviewStore.listReviews(reviewBinding, { productId: product.id });
      assert.equal(seeded.total, 2);
      assert.equal(seeded.counts.approved, 1);
      assert.equal(seeded.counts.pending, 1);
      const rating = (await review.query(`WITH effective AS (
        ${require('../../server/database/postgres/secureshopBoundProductRepository').EFFECTIVE_PRODUCTS})
        SELECT review_count,avg_rating FROM effective WHERE target_id=$1 AND product_id=$2`,
      [birth.targetId, product.id])).rows[0];
      assert.equal(Number(rating.review_count), 1);
      assert.equal(Number(rating.avg_rating), 5);
      const thirdAuth = await standalone.login({ username: firstOwner.username, password });
      const thirdScope = await launch({ ...thirdAuth,
        context: await standalone.establishTenantContext(thirdAuth.context) });
      const thirdScene = await scenes.resolve(thirdScope);
      const reopenedReview = await reviewStore.readSceneTarget(thirdScene);
      assert.equal(reopenedReview.targetId, legacyReviewBirth.targetId);
      assert.equal(reopenedReview.launchId, legacyReviewBirth.launchId);
      assert.equal((await reviewStore.listReviews(reopenedReview, { productId: product.id })).total, 2);
      await reviewStore.submitReview(reopenedReview, { id: 11, role: 'customer' },
        { submissionId: randomUUID(), productId: product.id, authorId: 11,
          body: 'Current execution writes to retained review target', rating: 4 });
      const audit = (await review.query(`SELECT launch_id FROM secureshop_review.bound_audit_events
        WHERE action='review_submit' ORDER BY created_at DESC LIMIT 1`)).rows[0];
      assert.equal(audit.launch_id, thirdScope.launchId);
      assert.equal((await review.query(`SELECT count(*)::int n FROM secureshop_review.scene_review_targets
        WHERE product_target_id=$1 AND review_target_id=$2`,
      [birth.targetId, legacyReviewBirth.targetId])).rows[0].n, 1);
    });

    const manualOperation = randomUUID();
    function manualRequest(operationId, merchantId = product.retailerId) {
      const body = 'Current merchant manual retains the original product snapshot';
      const bytes = Buffer.from('synthetic current-execution file');
      return { operationId, productId: product.id, merchantId,
        fileReceipt: { targetId: randomUUID(), launchId: currentScope.launchId,
          scenarioId: currentScope.scenarioId, generation: currentScope.generation,
          platformOwnerId: currentScope.platformOwnerId,
          platformSessionId: currentScope.platformSessionId,
          virtualPath: `/uploads/product_manuals/${product.id}/${operationId}-manual`,
          bytes: bytes.length, sha256: digest(bytes) },
        filename: 'scene-manual.txt', mime: 'text/plain', isPublic: true,
        extractor: 'controlled-native', extractionSha256: digest(body),
        embeddingModel: 'native-fixture', embeddingDimension: 384,
        chunks: [{ text: body, embedding: vector }],
        expectedRuntimeFingerprint: 'a'.repeat(64) };
    }
    const manualInput = manualRequest(manualOperation);
    await t.test('manual receipt versions immutable birth and current file execution', async () => {
      const accepted = await manualStore.appendManual(current, manualInput);
      assert.equal(accepted.replayed, false);
      assert.equal(accepted.targetId, birth.targetId);
      assert.equal(accepted.launchId, birthScope.launchId);
      assert.equal(accepted.execution.launchId, currentScope.launchId);
      assert.equal(accepted.fileReceipt.launchId, currentScope.launchId);
      assert.equal(accepted.sceneGrantId, current.scene.grantId);
      assert.equal((await manualStore.appendManual(current, manualInput)).replayed, true);
      const row = (await review.query(`SELECT i.*,r.runtime_fingerprint,
        i.receipt_sha256=secureshop_review.product_manual_scene_receipt_digest(i) AS valid
        FROM secureshop_review.product_target_manual_ingests i
        JOIN secureshop_review.product_target_manual_runtime_receipts r USING(operation_id)
        WHERE i.operation_id=$1`, [manualOperation])).rows[0];
      assert.equal(row.receipt_version, 2);
      assert.equal(row.valid, true);
      assert.equal(row.target_id, birth.targetId);
      assert.equal(row.launch_id, birthScope.launchId);
      assert.equal(row.file_launch_id, currentScope.launchId);
      assert.equal(row.file_platform_session_id, currentScope.platformSessionId);
      assert.equal(row.execution_launch_id, currentScope.launchId);
      assert.equal(row.execution_platform_session_id, currentScope.platformSessionId);
      assert.equal(row.scene_id, current.scene.sceneId);
      assert.equal(row.scene_grant_id, current.scene.grantId);
      assert.equal(row.runtime_fingerprint.toString('hex'), 'a'.repeat(64));
      assert.equal((await review.query(`SELECT count(*)::int n FROM
        secureshop_review.product_target_manual_ingests WHERE operation_id=$1`,
      [manualOperation])).rows[0].n, 1);
      assert.equal((await review.query(`SELECT count(*)::int n FROM
        secureshop_review.product_target_retrieval_documents
        WHERE target_id=$1 AND source_kind='manual' AND source_id=$2`,
      [birth.targetId, accepted.manualSourceId])).rows[0].n, 1);
      const audit = (await review.query(`SELECT launch_id FROM secureshop_review.bound_audit_events
        WHERE action='manual_ingest' AND source_id=$1 ORDER BY created_at DESC LIMIT 1`,
      [manualOperation])).rows[0];
      assert.equal(audit.launch_id, currentScope.launchId);
      await assert.rejects(manualStore.appendManual(current, manualRequest(randomUUID(), 13)),
        { code: '55000' }, 'another merchant cannot attach a manual to this product');
      const wrongFileExecution = manualRequest(randomUUID());
      await assert.rejects(manualStore.appendManual(current, { ...wrongFileExecution,
        fileReceipt: { ...wrongFileExecution.fileReceipt, launchId: birthScope.launchId } }),
      { code: 'INVALID_ARGUMENT' }, 'birth file coordinates cannot stand in for current execution');
      assert.equal((await review.query(`SELECT count(*)::int n FROM
        secureshop_review.product_target_manual_ingests WHERE target_id=$1`,
      [birth.targetId])).rows[0].n, 1);
      assert.equal((await manualStore.readReceipt(siblingBirth,
        { operationId: historicalOperation })).receiptSha256, historicalReceiptSha);
      assert.equal((await review.query(`SELECT count(*)::int n FROM
        secureshop_review.product_target_manual_ingests WHERE target_id=$1`,
      [sibling.targetId])).rows[0].n, 1);
    });

    const persona = { id: 13, role: 'admin' };
    const personaSession = { sessionId: randomUUID(), authorityVersion: '1' };
    const actor = { scope: currentScope, persona, personaSession };
    const restartId = randomUUID();
    const request = { ...actor, version: 1, operationId: restartId, name: 'nginx' };
    const personaAuthority = { async capture(input) {
      assert.deepEqual(input.scope, createLaunchScope(currentScope));
      assert.equal(input.personaId, persona.id);
      return { binding: { ...currentScope, personaId: persona.id, role: persona.role,
        sessionId: personaSession.sessionId, authorityVersion: personaSession.authorityVersion },
      assertRemoteAdmission: () => launches.assertCurrent(currentScope),
      withCrossStoreEffect: async work => work() };
    } };
    const restart = createSecureShopSystemRestartRepository({ pool: review, personaAuthority,
      audit: createBoundAuditStore({ store: 'review', pool: review }) });
    await t.test('restart admission and completion bind one exact grant', async () => {
      const instanceId = randomUUID();
      await restart.ensureTarget({ ...actor, operationId: restartId },
        { targetId: birth.targetId, instanceId, generation: 1, binding: current });
      const begun = await restart.begin(request, { targetId: birth.targetId, binding: current });
      assert.equal(begun.state, 'running');
      const outputText = 'synthetic owned restart receipt';
      const receipt = { version: VERSION, targetId: birth.targetId, operationId: restartId,
        requestSha256: restartRequestDigest({ version: 1, operationId: restartId, name: 'nginx' }),
        beforeInstanceId: instanceId, afterInstanceId: randomUUID(), beforeGeneration: 1,
        afterGeneration: 2, effectSha256: 'b'.repeat(64), outputSha256: digest(outputText),
        outputBytes: Buffer.byteLength(outputText), outputText,
        ownedCommandEffectSha256: 'c'.repeat(64), ownedCommandEffectFiles: 1,
        ownedCommandEffectBytes: 1, command: 'systemctl restart nginx', status: 'completed', isolation: ISOLATION };
      const completed = await restart.complete(request, { targetId: birth.targetId,
        workerToken: begun.workerToken, receipt, binding: current });
      assert.equal(completed.state, 'completed');
      assert.equal((await restart.operation({ ...actor, operationId: restartId }, current)).state, 'completed');
      assert.equal((await restart.begin(request, { targetId: birth.targetId, binding: current })).state, 'completed');
      for (const table of ['scene_restart_admissions', 'scene_restart_effects']) {
        const rows = (await review.query(`SELECT * FROM secureshop_review.${table} WHERE operation_id=$1`, [restartId])).rows;
        assert.equal(rows.length, 1);
        assert.equal(rows[0].grant_id, current.scene.grantId);
        assert.equal(rows[0].birth_launch_id, birthScope.launchId);
        assert.equal(rows[0].execution_launch_id, currentScope.launchId);
      }
    });

    await t.test('reset preserves immutable effect receipts and sibling state', async () => {
      await launches.beginReset({ launchId: currentScope.launchId,
        platformSessionId: currentScope.platformSessionId,
        platformOwnerId: currentScope.platformOwnerId, expectedGeneration: currentScope.generation,
        idempotencyKey: 'scene-effects-owner-reset' });
      assert.equal((await review.query(`SELECT count(*)::int n FROM secureshop_review.scene_retrieval_embedding_effects
        WHERE target_id=$1`, [birth.targetId])).rows[0].n, 3);
      assert.equal((await review.query(`SELECT count(*)::int n FROM secureshop_review.scene_restart_effects
        WHERE target_id=$1`, [birth.targetId])).rows[0].n, 1);
      assert.equal((await review.query(`SELECT count(*)::int n FROM secureshop_review.scene_restart_admissions
        WHERE target_id=$1`, [birth.targetId])).rows[0].n, 1);
      assert.equal((await review.query(`SELECT lifecycle FROM secureshop_review.product_targets WHERE target_id=$1`,
        [sibling.targetId])).rows[0].lifecycle, 'active');
      await assert.rejects(manualStore.appendManual(current, manualRequest(randomUUID())));
      assert.equal((await review.query(`SELECT count(*)::int n FROM
        secureshop_review.product_target_manual_ingests WHERE target_id=$1`,
      [birth.targetId])).rows[0].n, 1);
      assert.equal((await review.query(`SELECT count(*)::int n FROM
        secureshop_review.product_target_manual_ingests WHERE target_id=$1`,
      [sibling.targetId])).rows[0].n, 1);
      assert.equal((await scenes.resolve(siblingScope)).targetId, sibling.targetId);
      await assert.rejects(retrieval.readMetadata(current));
    });
    await fs.writeFile(evidencePath, JSON.stringify({ passed: true,
      scope: 'Controlled disposable two-store SecureShop scene effects; no model, browser, sidecar, or persona-login qualification',
      freshMigration: true, populatedMigration: true, secondRunNoop: true,
      retrievalEffect: true, embeddingEffect: true, restartAdmission: true,
      restartEffect: true, replayNoNewEvidence: true, resetPreservedEffects: true,
      siblingIsolated: true, manualSceneReceiptVersioned: true,
      selectedSceneEffectLease: true }));
  });
