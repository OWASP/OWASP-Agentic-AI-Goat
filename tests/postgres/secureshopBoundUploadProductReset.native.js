'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const { createHash, randomBytes, randomUUID } = require('node:crypto');
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');
const { migrate } = require('../../db/postgres/migrate');
const { seedWorkshopPlatform } = require('../../server/database/postgres/workshopPlatformSeed');
const { createIdentityRepository } = require('../../server/database/postgres/identityRepository');
const { createSecureShopLaunchRepository } = require('../../server/database/postgres/secureshopLaunchRepository');
const { createSecureShopBoundUploadRepository } = require('../../server/database/postgres/secureshopBoundUploadRepository');
const { createSecureShopCleanupComposition } = require('../../server/services/secureshopCleanupComposition');
const { createSecureShopV46TraversalWriter } = require('../../server/services/secureshopV46TraversalWriter');
const { createLaunchScope } = require('../../server/services/secureshopConversationBinding');
const { createSecureShopFiles } = require('../../sidecars/sandbox-runner/secureshopFiles');

const PREFIX = 'PG_SECURESHOP_UPLOAD_PRODUCT_RESET_';
const enabled = process.env.PG_TEST_DISPOSABLE === 'yes'
  && process.env[`${PREFIX}IDENTITY_RUNTIME_URL`]
  && process.env[`${PREFIX}AGENTS_RUNTIME_URL`]
  && process.env[`${PREFIX}REVIEW_RUNTIME_URL`];
const digest = value => createHash('sha256').update(value).digest('hex');

function open(store, family, t) {
  const urls = {};
  for (const role of ['MIGRATION', 'RUNTIME']) {
    const value = new URL(process.env[`${PREFIX}${store}_${role}_URL`]);
    assert.equal(value.protocol, 'postgresql:');
    assert.equal(value.hostname, '127.0.0.1');
    assert.equal(value.username, `dvaia_${family}_${role.toLowerCase()}`);
    assert.match(value.pathname, /^\/owasp_ai_goat_test_persona_(identity|agents|review)_[a-f0-9]{12}$/);
    urls[role.toLowerCase()] = value.href;
  }
  const migration = new Pool({ connectionString: urls.migration, max: 3,
    statement_timeout: 20000, lock_timeout: 3000 });
  const runtime = new Pool({ connectionString: urls.runtime, max: 8,
    statement_timeout: 20000, lock_timeout: 3000 });
  t.after(async () => {
    const results = await Promise.allSettled([migration.end(), runtime.end()]);
    assert.equal(results.filter(result => result.status === 'rejected').length, 0);
  });
  return { migration, runtime, urls };
}

function product(id) {
  return { id, sourceRetailerId: id, retailerId: id, name: `Owned reset product ${id}`,
    description: 'Synthetic reset fixture', descriptionHtml: '<p>Synthetic reset fixture</p>',
    price: 12.5, category: 'training', imageUrl: null, images: [], stockQuantity: 4,
    status: 'active', templateSource: null, createdAt: null, updatedAt: null };
}

test('native product-target reset deletes owned upload bytes and preserves immutable and sibling evidence',
  { skip: !enabled, timeout: 120000 }, async t => {
    const identity = open('IDENTITY', 'identity', t);
    const agents = open('AGENTS', 'secureshop_agents', t);
    const review = open('REVIEW', 'secureshop_review', t);
    const leases = new Pool({ connectionString: identity.urls.runtime, max: 2,
      statement_timeout: 20000, lock_timeout: 3000 });
    t.after(() => leases.end());
    await migrate(identity.migration, path.resolve(__dirname, '../../db/postgres/identity-migrations'));
    await seedWorkshopPlatform(identity.migration);
    await migrate(agents.migration, path.resolve(__dirname, '../../db/postgres/workshop-migrations/secureshop_agents'));
    await migrate(review.migration, path.resolve(__dirname, '../../db/postgres/workshop-migrations/secureshop_review'));

    const workspace = process.env.OWASP_AI_GOAT_ISOLATED_TEST_WORKSPACE;
    assert.ok(typeof workspace === 'string' && path.isAbsolute(workspace));
    const uploadRoot = path.join(workspace, 'upload-product-reset');
    const filesRoot = path.join(workspace, 'upload-product-reset-owned-files');
    process.env.SECURESHOP_UPLOAD_ROOT = uploadRoot;
    await fs.mkdir(uploadRoot, { recursive: true, mode: 0o700 });
    const files = createSecureShopFiles({ root: filesRoot, maxReadBytes: 20 * 1024 * 1024,
      maxWriteBytes: 20 * 1024 * 1024 });
    const launches = createSecureShopLaunchRepository(identity.runtime);
    const reset = createSecureShopCleanupComposition({ identityPool: identity.runtime,
      agentsPool: agents.runtime, reviewPool: review.runtime, leasePool: leases, launches,
      files, personaInboxFactory: false });
    t.after(async () => {
      await reset.closeFeatureTransports();
      await reset.auditLedger?.close?.();
    });
    const users = createIdentityRepository(identity.runtime);
    const passwordHash = await bcrypt.hash('upload-product-reset-owned', 4);
    async function owner(label, userId) {
      const user = await users.createUser({ username: `${label}-${randomUUID().slice(0, 8)}`,
        email: `${randomUUID()}@upload-reset.invalid`, passwordHash });
      const session = await users.createSession({ userId: user.id, token: randomUUID(),
        expiresAt: new Date(Date.now() + 600000).toISOString(), expectedPasswordHash: passwordHash });
      const issued = await launches.issueOrRenew({ platformOwnerId: user.id,
        platformSessionId: session.id, expiresAt: new Date(Date.now() + 600000).toISOString() });
      const scope = createLaunchScope(issued.binding);
      const reserved = await launches.reserveProductsTarget({ ...scope, expectedGeneration: scope.generation });
      const target = { ...scope, targetId: reserved.targetId };
      await reset.products.provision(target, { ownMerchantId: userId, products: [product(userId)] });
      const scene = { ...target, sceneId: randomUUID(), sceneGeneration: 1, grantId: randomUUID(),
        shopUserId: userId, personaSessionId: randomUUID(), personaAuthorityVersion: '1',
        mode: 'vuln', modeGeneration: 1, modeStamp: digest(Buffer.from(`${label}-mode`)) };
      await review.runtime.query(`INSERT INTO secureshop_review.scene_execution_grants
        (grant_id,scene_id,scene_generation,target_id,launch_id,scenario_id,generation,
         original_platform_owner_id,original_platform_session_id)
        VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`, [scene.grantId, scene.sceneId,
        scene.sceneGeneration, scene.targetId, scene.launchId, scene.scenarioId, scene.generation,
        scene.platformOwnerId, scene.platformSessionId]);
      return { user, session, scope, target, scene };
    }
    const subject = await owner('upload-reset-owner', 7101);
    const sibling = await owner('upload-reset-sibling', 7201);
    const checkScene = async value => {
      const row = (await review.runtime.query(`SELECT secureshop_review.assert_scene_execution_grant
        ($1,$2,$3,$4,$5,$6,$7,$8,$9) AS allowed`, [value.grantId, value.sceneId,
        value.sceneGeneration, value.targetId, value.launchId, value.scenarioId, value.generation,
        value.platformOwnerId, value.platformSessionId])).rows[0];
      assert.equal(row.allowed, true);
    };
    const journal = createSecureShopBoundUploadRepository(review.runtime, {
      checkCurrent: value => launches.assertCurrent(value), assertSceneGrant: checkScene,
      checkCleanupAuthority: async () => {},
    });
    async function completed(subjectValue, filename, bytes) {
      const operationId = randomUUID(), storageKey = randomUUID(), requestId = randomUUID();
      const request = { kind: 'avatar', scopeId: subjectValue.scene.shopUserId,
        originalFilename: filename, declaredMime: 'image/svg+xml', public: true,
        byteCount: bytes.length, bodySha256: digest(bytes) };
      const admission = await journal.claim({ operationId, uploadRequestId: requestId, storageKey,
        scope: subjectValue.scene, request });
      const base = `operations/${storageKey}/avatars/${subjectValue.scene.shopUserId}`;
      const storedVirtualPath = `${base}/${randomBytes(4).toString('hex')}-${filename}`;
      const effect = await journal.recordEffect(admission, { effectId: randomUUID(), outcome: 'completed',
        denialCode: null, quarantineRequired: false, file: { storageKey, originalFilename: filename,
          cleanedFilename: filename, declaredMime: request.declaredMime, byteCount: bytes.length,
          bodySha256: request.bodySha256, baseVirtualPath: base,
          resolvedVirtualPath: `${base}/${filename}`, storedVirtualPath, isTraversal: false } });
      await journal.recordServe(admission, { serveId: randomUUID(), receiptPath: `/assets/${operationId}`,
        status: 200, contentType: request.declaredMime,
        contentDisposition: `inline; filename="${filename}"`, nosniffPresent: false,
        responseByteCount: bytes.length, responseSha256: request.bodySha256 }, effect);
      const physical = path.join(uploadRoot, storedVirtualPath);
      await fs.mkdir(path.dirname(physical), { recursive: true, mode: 0o700 });
      await fs.writeFile(physical, bytes, { flag: 'wx', mode: 0o600 });
      return { admission, effect, physical };
    }
    async function completedTraversal(subjectValue, filename, bytes) {
      const operationId = randomUUID(), storageKey = randomUUID(), requestId = randomUUID();
      const request = { kind: 'avatar', scopeId: subjectValue.scene.shopUserId,
        originalFilename: filename, declaredMime: 'text/plain', public: false,
        byteCount: bytes.length, bodySha256: digest(bytes) };
      const admission = await journal.claim({ operationId, uploadRequestId: requestId, storageKey,
        scope: subjectValue.scene, request });
      const written = await createSecureShopV46TraversalWriter().writeAndReadBack({ operationId,
        storageKey, shopUserId: subjectValue.scene.shopUserId, bytes, filename,
        mime: request.declaredMime });
      const effect = await journal.recordEffect(admission, { effectId: randomUUID(),
        outcome: 'completed', denialCode: null, quarantineRequired: false, file: {
          storageKey, originalFilename: filename, cleanedFilename: written.cleanedFilename,
          declaredMime: request.declaredMime, byteCount: written.byteCount,
          bodySha256: written.bodySha256, baseVirtualPath: written.baseVirtualPath,
          resolvedVirtualPath: written.resolvedVirtualPath,
          storedVirtualPath: written.storedVirtualPath, isTraversal: true } });
      const physical = path.join(uploadRoot, written.storedVirtualPath);
      assert.equal(path.dirname(physical), path.join(uploadRoot, 'operations', storageKey, 'avatars'));
      assert.equal(written.resolvedVirtualPath,
        `operations/${storageKey}/avatars/${subjectValue.scene.shopUserId}/../escaped-reset.txt`);
      assert.equal((await fs.readFile(physical)).equals(bytes), true);
      return { admission, effect, physical };
    }
    async function orphan(subjectValue, filename) {
      const bytes = Buffer.from('orphan');
      return journal.claim({ operationId: randomUUID(), uploadRequestId: randomUUID(),
        storageKey: randomUUID(), scope: subjectValue.scene, request: { kind: 'avatar',
          scopeId: subjectValue.scene.shopUserId, originalFilename: filename,
          declaredMime: 'image/svg+xml', public: true, byteCount: bytes.length,
          bodySha256: digest(bytes) } });
    }
    const owned = await completed(subject, 'owned-reset.svg', Buffer.from('<svg>owned reset</svg>'));
    const traversal = await completedTraversal(subject, '....//escaped-reset.txt',
      Buffer.from('owned escaped reset'));
    const pending = await orphan(subject, 'owned-orphan.svg');
    const siblingBytes = Buffer.from('<svg>sibling</svg>');
    const siblingUpload = await completed(sibling, 'sibling.svg', siblingBytes);
    const immutableBefore = (await review.runtime.query(`SELECT to_jsonb(x) AS row FROM (
      SELECT 'admission' AS kind,to_jsonb(a) AS value FROM secureshop_review.bound_upload_admissions a
        WHERE a.target_id=$1
      UNION ALL SELECT 'effect',to_jsonb(e) FROM secureshop_review.bound_upload_effects e
        JOIN secureshop_review.bound_upload_admissions a USING(operation_id) WHERE a.target_id=$1
      UNION ALL SELECT 'serve',to_jsonb(s) FROM secureshop_review.bound_upload_serves s
        JOIN secureshop_review.bound_upload_admissions a USING(operation_id) WHERE a.target_id=$1
    ) x ORDER BY kind,(value->>'operation_id')`, [subject.target.targetId])).rows;
    const siblingBefore = (await review.runtime.query(`SELECT to_jsonb(x) AS row FROM (
      SELECT 'admission' AS kind,to_jsonb(a) AS value FROM secureshop_review.bound_upload_admissions a
        WHERE a.target_id=$1
      UNION ALL SELECT 'effect',to_jsonb(e) FROM secureshop_review.bound_upload_effects e
        JOIN secureshop_review.bound_upload_admissions a USING(operation_id) WHERE a.target_id=$1
      UNION ALL SELECT 'serve',to_jsonb(s) FROM secureshop_review.bound_upload_serves s
        JOIN secureshop_review.bound_upload_admissions a USING(operation_id) WHERE a.target_id=$1
    ) x ORDER BY kind,(value->>'operation_id')`, [sibling.target.targetId])).rows;

    const key = randomUUID();
    const result = await reset.launchResetCoordinator.reset({ ...subject.scope,
      expectedGeneration: subject.scope.generation, idempotencyKey: key });
    assert.equal(result.status, 'committed');
    assert.equal(result.fromGeneration, subject.scope.generation);
    assert.equal(result.toGeneration, subject.scope.generation + 1);
    assert.equal(result.targets, 1);
    await assert.rejects(fs.stat(owned.physical), error => error?.code === 'ENOENT');
    await assert.rejects(fs.stat(traversal.physical), error => error?.code === 'ENOENT');
    assert.equal((await fs.stat(siblingUpload.physical)).isFile(), true);
    assert.equal((await fs.readFile(siblingUpload.physical)).equals(siblingBytes), true);
    assert.deepEqual((await review.runtime.query(`SELECT to_jsonb(x) AS row FROM (
      SELECT 'admission' AS kind,to_jsonb(a) AS value FROM secureshop_review.bound_upload_admissions a
        WHERE a.target_id=$1
      UNION ALL SELECT 'effect',to_jsonb(e) FROM secureshop_review.bound_upload_effects e
        JOIN secureshop_review.bound_upload_admissions a USING(operation_id) WHERE a.target_id=$1
      UNION ALL SELECT 'serve',to_jsonb(s) FROM secureshop_review.bound_upload_serves s
        JOIN secureshop_review.bound_upload_admissions a USING(operation_id) WHERE a.target_id=$1
    ) x ORDER BY kind,(value->>'operation_id')`, [subject.target.targetId])).rows, immutableBefore);
    assert.deepEqual((await review.runtime.query(`SELECT to_jsonb(x) AS row FROM (
      SELECT 'admission' AS kind,to_jsonb(a) AS value FROM secureshop_review.bound_upload_admissions a
        WHERE a.target_id=$1
      UNION ALL SELECT 'effect',to_jsonb(e) FROM secureshop_review.bound_upload_effects e
        JOIN secureshop_review.bound_upload_admissions a USING(operation_id) WHERE a.target_id=$1
      UNION ALL SELECT 'serve',to_jsonb(s) FROM secureshop_review.bound_upload_serves s
        JOIN secureshop_review.bound_upload_admissions a USING(operation_id) WHERE a.target_id=$1
    ) x ORDER BY kind,(value->>'operation_id')`, [sibling.target.targetId])).rows, siblingBefore);
    const reconciliation = (await review.runtime.query(`SELECT action,storage_key,
        encode(receipt_sha256,'hex') AS receipt FROM secureshop_review.bound_upload_reconciliations
      WHERE operation_id=$1`, [pending.operationId])).rows[0];
    assert.equal(reconciliation.action, 'deleted');
    assert.equal(reconciliation.storage_key, pending.storageKey);
    assert.match(reconciliation.receipt, /^[a-f0-9]{64}$/);
    const cleanup = (await review.runtime.query(`SELECT operation_id,launch_id,scenario_id,generation,
        platform_owner_id,platform_session_id,deleted_count,quarantined_count,
        encode(receipt_sha256,'hex') AS receipt FROM secureshop_review.bound_upload_cleanup_receipts
      WHERE target_id=$1`, [subject.target.targetId])).rows[0];
    assert.deepEqual({ operationId: cleanup.operation_id, launchId: cleanup.launch_id,
      scenarioId: cleanup.scenario_id, generation: Number(cleanup.generation),
      ownerId: cleanup.platform_owner_id, sessionId: cleanup.platform_session_id,
      deleted: cleanup.deleted_count, quarantined: cleanup.quarantined_count }, {
      operationId: result.resetId, launchId: subject.scope.launchId,
      scenarioId: subject.scope.scenarioId, generation: subject.scope.generation,
      ownerId: subject.scope.platformOwnerId, sessionId: subject.scope.platformSessionId,
      deleted: 3, quarantined: 0,
    });
    assert.match(cleanup.receipt, /^[a-f0-9]{64}$/);
    assert.deepEqual(await reset.launchResetCoordinator.reset({ ...subject.scope,
      expectedGeneration: subject.scope.generation, idempotencyKey: key }), result);
    assert.equal((await fs.readFile(siblingUpload.physical)).equals(siblingBytes), true);
    assert.equal((await review.runtime.query(`SELECT count(*)::integer AS count
      FROM secureshop_review.bound_upload_cleanup_receipts WHERE target_id=$1`,
    [subject.target.targetId])).rows[0].count, 1);
    await assert.rejects(launches.assertCurrent(subject.scope), { code: 'STALE_LAUNCH' });
    assert.equal((await identity.runtime.query(`SELECT count(*)::integer AS count
      FROM secureshop_auth.assessment_contributions c
      JOIN secureshop_auth.assessment_judgments j USING(tenant_id,principal_id,evaluation_id)
      WHERE j.execution_json->'scope'->>'launchId'=$1
        AND j.execution_json->'scope'->>'generation'=$2`,
    [subject.scope.launchId, String(subject.scope.generation)])).rows[0].count, 0);
    assert.equal((await review.runtime.query(`SELECT lifecycle FROM secureshop_review.product_targets
      WHERE target_id=$1`, [subject.target.targetId])).rows[0].lifecycle, 'retired');
    assert.equal((await review.runtime.query(`SELECT lifecycle FROM secureshop_review.product_targets
      WHERE target_id=$1`, [sibling.target.targetId])).rows[0].lifecycle, 'active');
  });
