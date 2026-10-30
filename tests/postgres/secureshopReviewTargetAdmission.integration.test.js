'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const { randomUUID, randomBytes } = require('node:crypto');
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');
const { migrate, readMigrations } = require('../../db/postgres/migrate');
const { createXssBoundedMigrationView } = require('../helpers/xssBoundedMigrationView');
const { createIdentityRepository } = require('../../server/database/postgres/identityRepository');
const { createSecureShopLaunchRepository } = require('../../server/database/postgres/secureshopLaunchRepository');
const { createSecureShopResetCleanupAuthorityRepository } = require('../../server/database/postgres/secureshopResetCleanupAuthorityRepository');
const { createSecureShopTargetReconciliationRepository } = require('../../server/database/postgres/secureshopTargetReconciliationRepository');
const { initializeSecureShopReviewDb, createSecureShopReviewRepository } = require('../../server/database/postgres/secureshopReviewDb');
const { createSecureShopReviewCleanupReceiptReader } = require('../../server/services/secureshopReviewCleanupReceiptReader');

const prefix = 'PG_SECURESHOP_REVIEW_ADMISSION_';
const keys = ['IDENTITY_MIGRATION_URL', 'IDENTITY_RUNTIME_URL', 'REVIEW_MIGRATION_URL', 'REVIEW_RUNTIME_URL'];
const enabled = process.env.SECURESHOP_REVIEW_ADMISSION_NATIVE === '1'
  && process.env.PG_TEST_DISPOSABLE === 'yes' && keys.every(key => process.env[prefix + key]);
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

test('review target admission preserves legacy rows, caps new sessions, and reuses only reconciled slots',
  { skip: !enabled, timeout: 180000 }, async t => {
    assert.equal(path.resolve(process.env.OWASP_AI_GOAT_CURRENT_MAIN_WORKSPACE || '/'), process.cwd());
    const evidencePath = process.env.WORKSHOP_RAG_EVIDENCE_PATH || '';
    assert.ok(path.isAbsolute(evidencePath));
    assert.ok(!path.resolve(evidencePath).startsWith(`${process.cwd()}${path.sep}`));
    const identityMigration = new Pool({ connectionString: disposableUrl('IDENTITY_MIGRATION_URL'), max: 2 });
    const identity = new Pool({ connectionString: disposableUrl('IDENTITY_RUNTIME_URL'), max: 8 });
    const reviewMigration = new Pool({ connectionString: disposableUrl('REVIEW_MIGRATION_URL'), max: 2 });
    const review = new Pool({ connectionString: disposableUrl('REVIEW_RUNTIME_URL'), max: 6 });
    t.after(() => Promise.allSettled([identity.end(), identityMigration.end(), review.end(), reviewMigration.end()]));
    const directory = path.resolve(__dirname, '../../db/postgres/identity-migrations');
    const view = createXssBoundedMigrationView({ identity: 133 });
    await view.migrate(identityMigration, directory);
    await initializeSecureShopReviewDb(review, reviewMigration);
    const identities = createIdentityRepository(identity);
    const launches = createSecureShopLaunchRepository(identity);
    const passwordHash = await bcrypt.hash('synthetic-review-admission', 4);
    const expiresAt = new Date(Date.now() + 3600000).toISOString();
    const owner = await identities.createUser({ username: `review-cap-${randomUUID().slice(0, 8)}`,
      email: `${randomUUID()}@review.invalid`, passwordHash });
    const sibling = await identities.createUser({ username: `review-sibling-${randomUUID().slice(0, 8)}`,
      email: `${randomUUID()}@review.invalid`, passwordHash });

    // This historical-overflow fixture predates launch admission 0134. It is
    // populated only in a disposable database to reach the independent review
    // capacity edge without weakening normal five-session login policy.
    const tokens = Array.from({ length: 257 }, () => randomBytes(32).toString('hex'));
    const sessions = (await identityMigration.query(`INSERT INTO identity.user_sessions
      (user_id,session_token_hash,expires_at)
      SELECT $1,token,$2 FROM unnest($3::text[]) AS token RETURNING id`,
    [owner.id, expiresAt, tokens])).rows.map(row => Number(row.id));
    assert.equal(sessions.length, 257);
    const launchIds = sessions.map(() => randomUUID());
    const scenarios = sessions.map(() => randomUUID());
    await identityMigration.query(`INSERT INTO identity.secureshop_launches
      (launch_id,platform_session_id,original_platform_session_id,original_platform_owner_id,
       handle_hash,scenario_id,expires_at)
      SELECT launch_id,session_id,session_id,$4,sha256(convert_to(launch_id::text,'UTF8')),scenario_id,$5
      FROM unnest($1::uuid[],$2::integer[],$3::uuid[])
        AS historical(launch_id,session_id,scenario_id)`,
    [launchIds, sessions, scenarios, owner.id, expiresAt]);
    const historical = sessions.map((sessionId, index) => ({ platformOwnerId: owner.id,
      platformSessionId: sessionId, launchId: launchIds[index], scenarioId: scenarios[index],
      generation: 1, expectedGeneration: 1 }));

    view.setCeiling('identity', 135);
    assert.deepEqual(await view.migrate(identityMigration, directory),
      ['0134_secureshop_product_launch_admission.sql', '0135_secureshop_durable_scenes.sql']);
    const oldTarget = await launches.reserveReviewsTarget(historical[0]);
    const oldScope = { ...historical[0], targetId: oldTarget.targetId, targetKind: 'reviews',
      fromGeneration: 1 };
    const cleanupAuthority = createSecureShopResetCleanupAuthorityRepository(identity);
    const reviewRepository = createSecureShopReviewRepository(review, {
      checkCurrent: scope => launches.assertCurrent(scope),
      checkRetirement: async () => { throw new Error('retirement outside admission fixture'); },
      checkCleanup: input => cleanupAuthority.checkReviewTarget(input),
    });
    await reviewRepository.provision(oldScope, { reviews: [
      { productId: 7, authorId: 11, body: 'Retained review before migration', rating: 5 },
    ] });
    const before = (await identity.query(`SELECT target_id,launch_id,generation,target_kind,
      original_platform_owner_id,product_owner_slot,created_at
      FROM identity.secureshop_target_reservations WHERE target_id=$1`, [oldTarget.targetId])).rows[0];
    const reviewBefore = (await review.query(`SELECT body,rating FROM secureshop_review.reviews
      WHERE target_id=$1`, [oldTarget.targetId])).rows;
    const ledgerBefore = (await identityMigration.query(
      'SELECT name,checksum FROM dvaia_migrations.ledger ORDER BY name')).rows;
    assert.deepEqual(await migrate(identityMigration, directory), ['0136_secureshop_review_target_admission.sql']);
    const after = (await identity.query(`SELECT target_id,launch_id,generation,target_kind,
      original_platform_owner_id,product_owner_slot,created_at,review_owner_slot
      FROM identity.secureshop_target_reservations WHERE target_id=$1`, [oldTarget.targetId])).rows[0];
    assert.deepEqual({ ...after, review_owner_slot: undefined }, { ...before, review_owner_slot: undefined });
    assert.equal(Number(after.review_owner_slot), 1);
    assert.deepEqual((await review.query(`SELECT body,rating FROM secureshop_review.reviews
      WHERE target_id=$1`, [oldTarget.targetId])).rows, reviewBefore);
    assert.deepEqual(await migrate(identityMigration, directory), []);
    const expectedMigrations = await readMigrations(directory);
    assert.deepEqual((await identityMigration.query('SELECT name,checksum FROM dvaia_migrations.ledger ORDER BY name')).rows,
      expectedMigrations.map(({ name, checksum }) => ({ name, checksum })));
    assert.deepEqual(expectedMigrations.slice(0, ledgerBefore.length).map(({ name, checksum }) => ({ name, checksum })),
      ledgerBefore);

    const next = await launches.reserveReviewsTarget(historical[1]);
    assert.notEqual(next.targetId, oldTarget.targetId);
    assert.deepEqual(await launches.reserveReviewsTarget(historical[0]), oldTarget);
    const siblingSession = await identities.createSession({ userId: sibling.id, token: randomUUID(),
      expiresAt, expectedPasswordHash: passwordHash });
    const siblingLaunch = await launches.issueOrRenew({ platformOwnerId: sibling.id,
      platformSessionId: siblingSession.id, expiresAt });
    const siblingScope = { ...siblingLaunch.binding, expectedGeneration: 1 };
    const siblingTarget = await launches.reserveReviewsTarget(siblingScope);
    await assert.rejects(launches.reserveReviewsTarget({ ...historical[1], platformOwnerId: sibling.id }),
      { code: 'OWNER_MISMATCH' });
    await assert.rejects(launches.reserveReviewsTarget({ ...historical[1], expectedGeneration: 2 }),
      { code: 'LAUNCH_UNAVAILABLE' });

    for (const scope of historical.slice(2, 256)) await launches.reserveReviewsTarget(scope);
    const retained = (await identity.query(`SELECT count(*)::int n,count(DISTINCT review_owner_slot)::int slots,
      min(review_owner_slot)::int first,max(review_owner_slot)::int last
      FROM identity.secureshop_target_reservations
      WHERE original_platform_owner_id=$1 AND target_kind='reviews'`, [owner.id])).rows[0];
    assert.deepEqual(retained, { n: 256, slots: 256, first: 1, last: 256 });
    assert.deepEqual(await launches.reserveReviewsTarget(historical[0]), oldTarget,
      'the current launch reopens at the review cap');
    await assert.rejects(launches.reserveReviewsTarget(historical[256]), { code: 'REVIEW_TARGET_CAPACITY' });
    await assert.rejects(identity.query(`INSERT INTO identity.secureshop_target_reservations
      (target_id,launch_id,generation,target_kind,original_platform_owner_id)
      VALUES($1,$2,1,'reviews',$3)`, [randomUUID(), historical[256].launchId, owner.id]), { code: '54000' });
    assert.deepEqual(await launches.reserveReviewsTarget(siblingScope), siblingTarget);

    const reset = await launches.beginReset({ ...historical[0], idempotencyKey: 'review-cap-receipt-recovery' });
    await assert.rejects(launches.reserveReviewsTarget(historical[0]), { code: 'LAUNCH_UNAVAILABLE' });
    await assert.rejects(launches.reserveReviewsTarget(historical[256]), { code: 'REVIEW_TARGET_CAPACITY' });
    const receiptReader = createSecureShopReviewCleanupReceiptReader({ repository: reviewRepository });
    const reconciler = createSecureShopTargetReconciliationRepository(identity, {
      checkAuthority: input => cleanupAuthority.checkTarget(input),
      readCleanupReceipt: receiptReader,
    });
    await assert.rejects(reconciler.reconcile(oldScope, { operationId: reset.resetId }),
      { code: 'REVIEW_CLEANUP_RECEIPT_UNAVAILABLE' });
    await reviewRepository.cleanup(oldScope, { operationId: reset.resetId });
    await reconciler.reconcile(oldScope, { operationId: reset.resetId });
    assert.equal((await identity.query(`SELECT count(*)::int n FROM identity.secureshop_target_cleanup_history
      WHERE target_id=$1 AND operation_id=$2`, [oldTarget.targetId, reset.resetId])).rows[0].n, 1);
    assert.equal((await review.query(`SELECT count(*)::int n FROM secureshop_review.review_cleanup_receipts
      WHERE target_id=$1 AND operation_id=$2`, [oldTarget.targetId, reset.resetId])).rows[0].n, 1);
    const recovered = await launches.reserveReviewsTarget(historical[256]);
    assert.notEqual(recovered.targetId, oldTarget.targetId);
    assert.equal((await identity.query(`SELECT review_owner_slot FROM identity.secureshop_target_reservations
      WHERE target_id=$1`, [recovered.targetId])).rows[0].review_owner_slot, 1);
    assert.equal((await review.query(`SELECT count(*)::int n FROM secureshop_review.reviews
      WHERE target_id=$1`, [oldTarget.targetId])).rows[0].n, 0,
    'only explicit review cleanup retires the old raw rows');
    assert.deepEqual(await launches.reserveReviewsTarget(siblingScope), siblingTarget);
    await fs.writeFile(evidencePath, JSON.stringify({ passed: true,
      scope: 'Controlled disposable identity/review allocator and genuine target cleanup receipt; no browser or model qualification',
      populatedMigrationPreserved: true, secondRunNoop: true, distinctRetainedSnapshots: true,
      reviewCapAndCurrentReuse: true, ownerAndResetFences: true,
      receiptVerifiedSlotRecovery: true, siblingPreserved: true }));
  });
