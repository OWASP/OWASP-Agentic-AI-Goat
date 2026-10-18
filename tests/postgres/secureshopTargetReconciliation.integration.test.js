'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { randomUUID } = require('node:crypto');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const { initializeIdentityRepository, createIdentityRepository } = require('../../server/database/postgres/identityRepository');
const { createSecureShopLaunchRepository } = require('../../server/database/postgres/secureshopLaunchRepository');
const { createSecureShopTargetReconciliationRepository } = require('../../server/database/postgres/secureshopTargetReconciliationRepository');
const { createSecureShopResetCleanupAuthorityRepository } = require('../../server/database/postgres/secureshopResetCleanupAuthorityRepository');
const { initializeSecureShopReviewDb, createSecureShopReviewRepository } = require('../../server/database/postgres/secureshopReviewDb');
const { createSecureShopReviewCleanupReceiptReader } = require('../../server/services/secureshopReviewCleanupReceiptReader');
const { createSecureShopFileCleanupReceiptReader } = require('../../server/services/secureshopFileCleanupReceiptReader');
const { createSecureShopFileTargetCleanup } = require('../../server/services/secureshopFileTargetCleanup');
const { createSecureShopReviewResetCoordinator } = require('../../server/services/secureshopReviewResetCoordinator');
const { createSecureShopFiles } = require('../../sidecars/sandbox-runner/secureshopFiles');

const enabled = process.env.PG_TEST_DISPOSABLE === 'yes'
  && process.env.PG_SECURESHOP_RECONCILIATION_TEST_MIGRATION_URL
  && process.env.PG_SECURESHOP_RECONCILIATION_TEST_RUNTIME_URL
  && process.env.PG_SECURESHOP_RECONCILIATION_REVIEW_MIGRATION_URL
  && process.env.PG_SECURESHOP_RECONCILIATION_REVIEW_RUNTIME_URL;

test('identity reconciliation verifies private receipts before atomically resolving exact target debt', { skip: !enabled }, async () => {
  for (const key of ['PG_SECURESHOP_RECONCILIATION_TEST_MIGRATION_URL', 'PG_SECURESHOP_RECONCILIATION_TEST_RUNTIME_URL',
    'PG_SECURESHOP_RECONCILIATION_REVIEW_MIGRATION_URL', 'PG_SECURESHOP_RECONCILIATION_REVIEW_RUNTIME_URL']) {
    const url = new URL(process.env[key]);
    assert.match(url.pathname, /^\/dvaia_test_[a-z0-9_]+$/);
    assert.ok(['127.0.0.1', 'localhost'].includes(url.hostname));
  }
  const migration = new Pool({ connectionString: process.env.PG_SECURESHOP_RECONCILIATION_TEST_MIGRATION_URL, max: 2 });
  let runtime = new Pool({ connectionString: process.env.PG_SECURESHOP_RECONCILIATION_TEST_RUNTIME_URL, max: 8 });
  const reviewMigration = new Pool({ connectionString: process.env.PG_SECURESHOP_RECONCILIATION_REVIEW_MIGRATION_URL, max: 2 });
  const reviewRuntime = new Pool({ connectionString: process.env.PG_SECURESHOP_RECONCILIATION_REVIEW_RUNTIME_URL, max: 4 });
  let reservedFilesRoot;
  try {
    await initializeIdentityRepository(runtime, migration);
    for (const filename of ['secureshop-review-target-reservation.sql', 'secureshop-target-reconciliation.sql']) {
      await migration.query(await fs.readFile(path.join(__dirname, '../../docs/modernization/drafts', filename), 'utf8'));
    }
    await initializeSecureShopReviewDb(reviewRuntime, reviewMigration);
    let identity = createIdentityRepository(runtime);
    let launches = createSecureShopLaunchRepository(runtime);
    const passwordHash = await bcrypt.hash('reconciliation-owned-fixture', 4);
    const expiresAt = new Date(Date.now() + 3600000).toISOString();
    async function owner(name) {
      const user = await identity.createUser({ username: name, email: `${name}@reconcile.invalid`, passwordHash });
      const session = await identity.createSession({ userId: user.id, token: randomUUID(), expiresAt, expectedPasswordHash: passwordHash });
      const launch = await launches.issueOrRenew({ platformOwnerId: user.id, platformSessionId: session.id, expiresAt });
      return { user, session, launch, trusted: { platformOwnerId: user.id, platformSessionId: session.id } };
    }
    const alice = await owner('reconcile-alice');
    const bob = await owner('reconcile-bob');
    const aliceTarget = await launches.reserveReviewsTarget({ ...alice.trusted,
      launchId: alice.launch.binding.launchId, expectedGeneration: 1 });
    const bobTarget = await launches.reserveReviewsTarget({ ...bob.trusted,
      launchId: bob.launch.binding.launchId, expectedGeneration: 1 });
    const aliceReset = await launches.beginReset({ ...alice.trusted, launchId: aliceTarget.launchId,
      expectedGeneration: 1, idempotencyKey: 'alice-review-reset' });
    const scope = target => Object.freeze({ targetId: target.targetId, targetKind: target.kind,
      launchId: target.launchId, scenarioId: target.scenarioId, fromGeneration: target.generation,
      platformOwnerId: target === aliceTarget ? alice.user.id : bob.user.id,
      platformSessionId: target === aliceTarget ? alice.session.id : bob.session.id });
    const aliceScope = scope(aliceTarget);
    const bobScope = scope(bobTarget);
    await assert.rejects(runtime.query('DELETE FROM identity.secureshop_target_reservations WHERE target_id=$1',
      [aliceTarget.targetId]), { code: '42501' });
    const bobOperation = randomUUID();
    const authority = new Set([aliceReset.resetId, bobOperation]);
    const targetAuthority = async input => {
      if (!authority.has(input.operationId)) throw Object.assign(new Error('cleanup operation unavailable'), { code: 'CLEANUP_AUTHORITY_REQUIRED' });
    };
    const reviewRepository = createSecureShopReviewRepository(reviewRuntime, {
      checkCurrent: async () => {}, checkRetirement: async () => {}, checkCleanup: targetAuthority,
    });
    await reviewRepository.provision({ ...aliceScope, generation: aliceScope.fromGeneration }, { reviews: [
      { productId: 3, authorId: 8, body: 'alice raw review one', rating: 1 },
      { productId: 3, authorId: 9, body: 'alice raw review two', rating: 5 },
    ] });
    await reviewRepository.provision({ ...bobScope, generation: bobScope.fromGeneration }, { reviews: [
      { productId: 4, authorId: 7, body: 'bob raw review survives', rating: 4 },
    ] });
    const actualReader = createSecureShopReviewCleanupReceiptReader({ repository: reviewRepository });
    let receiptReads = 0;
    const make = (checkAuthority = async input => {
      if (!authority.has(input.operationId)) throw Object.assign(new Error('cleanup operation unavailable'), { code: 'CLEANUP_AUTHORITY_REQUIRED' });
    }) => createSecureShopTargetReconciliationRepository(runtime, {
      checkAuthority,
      readCleanupReceipt: async input => { receiptReads += 1; return actualReader(input); },
    });
    const reconciler = make();

    await assert.rejects(reconciler.reconcile(aliceScope, { operationId: aliceReset.resetId }), { code: 'REVIEW_CLEANUP_RECEIPT_UNAVAILABLE' });
    assert.equal((await runtime.query('SELECT count(*)::int n FROM identity.secureshop_target_reservations WHERE target_id=$1', [aliceTarget.targetId])).rows[0].n, 1);
    assert.equal((await runtime.query('SELECT count(*)::int n FROM identity.secureshop_target_cleanup_history')).rows[0].n, 0);
    assert.equal((await reviewRuntime.query('SELECT count(*)::int n FROM secureshop_review.reviews WHERE target_id=$1', [aliceTarget.targetId])).rows[0].n, 2,
      'identity receipt lookup must not perform target cleanup');
    await reviewRepository.cleanup({ ...aliceScope, generation: aliceScope.fromGeneration }, { operationId: aliceReset.resetId });
    await reviewRepository.cleanup({ ...bobScope, generation: bobScope.fromGeneration }, { operationId: bobOperation });
    const mismatching = createSecureShopTargetReconciliationRepository(runtime, {
      checkAuthority: targetAuthority,
      readCleanupReceipt: async input => ({ ...await actualReader(input), platformOwnerId: alice.user.id }),
    });
    await assert.rejects(mismatching.reconcile(bobScope, { operationId: bobOperation }), { code: 'TARGET_RECEIPT_MISMATCH' });
    const malformedReceipt = createSecureShopTargetReconciliationRepository(runtime, {
      checkAuthority: targetAuthority,
      readCleanupReceipt: async input => ({ ...await actualReader(input), version: 2, completedAt: null }),
    });
    await assert.rejects(malformedReceipt.reconcile(bobScope, { operationId: bobOperation }), { code: 'TARGET_RECEIPT_MISMATCH' });
    assert.equal((await runtime.query('SELECT count(*)::int n FROM identity.secureshop_target_reservations WHERE target_id=$1', [bobTarget.targetId])).rows[0].n, 1);
    assert.equal((await reviewRuntime.query('SELECT count(*)::int n FROM secureshop_review.reviews WHERE target_id=$1', [bobTarget.targetId])).rows[0].n, 0,
      'target cleanup commits independently before identity reconciliation');
    await assert.rejects(reconciler.reconcile({ ...aliceScope, platformOwnerId: bob.user.id }, { operationId: aliceReset.resetId }),
      { code: 'TARGET_RESERVATION_MISMATCH' });

    let checks = 0;
    const losesAuthority = make(async input => {
      assert.equal(input.operationId, aliceReset.resetId);
      checks += 1;
      if (checks === 4) throw Object.assign(new Error('authority lost before identity commit'), { code: 'CLEANUP_AUTHORITY_REQUIRED' });
    });
    await assert.rejects(losesAuthority.reconcile(aliceScope, { operationId: aliceReset.resetId }), { code: 'CLEANUP_AUTHORITY_REQUIRED' });
    assert.equal((await runtime.query('SELECT count(*)::int n FROM identity.secureshop_target_reservations WHERE target_id=$1', [aliceTarget.targetId])).rows[0].n, 1);
    assert.equal((await runtime.query('SELECT count(*)::int n FROM identity.secureshop_target_cleanup_history')).rows[0].n, 0);

    const concurrent = await Promise.all([
      reconciler.reconcile(aliceScope, { operationId: aliceReset.resetId }),
      reconciler.reconcile(aliceScope, { operationId: aliceReset.resetId }),
    ]);
    assert.deepEqual(concurrent.map(item => item.replayed).sort(), [false, true]);
    assert.equal((await runtime.query('SELECT count(*)::int n FROM identity.secureshop_target_reservations WHERE target_id=$1', [aliceTarget.targetId])).rows[0].n, 0);
    assert.equal((await runtime.query('SELECT count(*)::int n FROM identity.secureshop_target_reservations WHERE target_id=$1', [bobTarget.targetId])).rows[0].n, 1);
    assert.equal((await runtime.query('SELECT count(*)::int n FROM identity.secureshop_target_cleanup_history WHERE target_id=$1', [aliceTarget.targetId])).rows[0].n, 1);

    await runtime.end();
    runtime = new Pool({ connectionString: process.env.PG_SECURESHOP_RECONCILIATION_TEST_RUNTIME_URL, max: 8 });
    launches = createSecureShopLaunchRepository(runtime);
    identity = createIdentityRepository(runtime);
    const reopened = createSecureShopTargetReconciliationRepository(runtime, {
      checkAuthority: async input => assert.equal(input.operationId, aliceReset.resetId),
      readCleanupReceipt: async input => { receiptReads += 1; return actualReader(input); },
    });
    const aliceReplayed = await reopened.reconcile(aliceScope, { operationId: aliceReset.resetId });
    assert.equal(aliceReplayed.replayed, true);
    const changedReceipt = createSecureShopTargetReconciliationRepository(runtime, {
      checkAuthority: async () => {},
      readCleanupReceipt: async input => ({ ...await actualReader(input), receiptSha256: 'f'.repeat(64) }),
    });
    await assert.rejects(changedReceipt.reconcile(aliceScope, { operationId: aliceReset.resetId }), { code: 'TARGET_RECONCILIATION_MISMATCH' });

    await launches.commitReset({ ...alice.trusted, launchId: aliceTarget.launchId,
      resetId: aliceReset.resetId, expectedGeneration: 2 });
    const next = await launches.reserveReviewsTarget({ ...alice.trusted, launchId: aliceTarget.launchId, expectedGeneration: 2 });
    assert.equal(next.generation, 2);
    assert.notEqual(next.targetId, aliceTarget.targetId);
    assert.equal((await runtime.query('SELECT count(*)::int n FROM identity.secureshop_target_reservations WHERE target_id=$1', [bobTarget.targetId])).rows[0].n, 1);
    assert.ok(receiptReads >= 4, 'history retries must independently reread the private target receipt');
    await assert.rejects(runtime.query('DELETE FROM identity.secureshop_target_cleanup_history WHERE target_id=$1', [aliceTarget.targetId]), { code: '42501' });
    await assert.rejects(runtime.query('UPDATE identity.secureshop_target_cleanup_history SET target_receipt_version=2 WHERE target_id=$1', [aliceTarget.targetId]), { code: '42501' });
    await assert.rejects(migration.query('UPDATE identity.secureshop_target_cleanup_history SET target_receipt_version=2 WHERE target_id=$1', [aliceTarget.targetId]), { code: '55000' });

    // Connected reset orchestration: provision while launch authority is still
    // current, then derive every cleanup check from the durable reset journal.
    const durableAuthority = createSecureShopResetCleanupAuthorityRepository(runtime);
    let unsupportedEffects = 0;
    const unknownKindCoordinator = createSecureShopReviewResetCoordinator({
      launches: { async beginReset() { return { resetId: randomUUID(), fromGeneration: 1,
        toGeneration: 2 }; }, async commitReset() { unsupportedEffects++; } },
      cleanupAuthority: { async listTargets(resetId) { return { resetId, status: 'fenced',
        targets: [{ targetKind: 'reviews' }, { targetKind: 'unknown' }] }; },
      async assertResolved() { unsupportedEffects++; },
      async finalizeReconciliation() { unsupportedEffects++; } },
      reviewRepository: { async cleanup() { unsupportedEffects++; } },
      fileCleanup: { async cleanup() { unsupportedEffects++; } },
      reconciler: { async reconcile() { unsupportedEffects++; } },
    });
    await assert.rejects(unknownKindCoordinator.reset({}), { code: 'UNSUPPORTED_TARGET_CLEANUP' });
    assert.equal(unsupportedEffects, 0, 'unsupported target inventory fails before target effects');
    // A receipt shaped for another reset must fail at history insertion without
    // consuming or poisoning the valid target reservation.
    const misbound = await owner('reconcile-misbound-target');
    const unrelated = await owner('reconcile-unrelated-reset');
    const misboundTarget = await launches.reserveReviewsTarget({ ...misbound.trusted,
      launchId: misbound.launch.binding.launchId, expectedGeneration: 1 });
    const misboundScope = Object.freeze({ targetId: misboundTarget.targetId, targetKind: 'reviews',
      launchId: misboundTarget.launchId, scenarioId: misboundTarget.scenarioId, fromGeneration: 1,
      platformOwnerId: misbound.user.id, platformSessionId: misbound.session.id });
    await reviewRepository.provision({ ...misboundScope, generation: 1 }, { reviews: [
      { productId: 6, authorId: 4, body: 'history must bind to its actual reset', rating: 2 },
    ] });
    const misboundReset = await launches.beginReset({ ...misbound.trusted,
      launchId: misbound.launch.binding.launchId, expectedGeneration: 1,
      idempotencyKey: 'misbound-valid-reset' });
    const unrelatedReset = await launches.beginReset({ ...unrelated.trusted,
      launchId: unrelated.launch.binding.launchId, expectedGeneration: 1,
      idempotencyKey: 'unrelated-empty-reset' });
    authority.add(misboundReset.resetId);
    await reviewRepository.cleanup({ ...misboundScope, generation: 1 },
      { operationId: misboundReset.resetId });
    const correctMisboundReceipt = await actualReader({ ...misboundScope,
      operationId: misboundReset.resetId });
    const faultInjectedReconciler = createSecureShopTargetReconciliationRepository(runtime, {
      checkAuthority: async () => {}, readCleanupReceipt: async input => ({
        ...correctMisboundReceipt, operationId: input.operationId,
      }),
    });
    await assert.rejects(faultInjectedReconciler.reconcile(misboundScope,
      { operationId: unrelatedReset.resetId }), /cleanup history binding is invalid/);
    assert.equal((await runtime.query(`SELECT count(*)::int n
      FROM identity.secureshop_target_cleanup_history WHERE target_id=$1`,
    [misboundTarget.targetId])).rows[0].n, 0);
    assert.equal((await runtime.query(`SELECT count(*)::int n
      FROM identity.secureshop_target_reservations WHERE target_id=$1`,
    [misboundTarget.targetId])).rows[0].n, 1);
    const recoveredMisbound = await faultInjectedReconciler.reconcile(misboundScope,
      { operationId: misboundReset.resetId });
    assert.equal(recoveredMisbound.replayed, false);
    assert.equal(recoveredMisbound.history.operationId, misboundReset.resetId);
    assert.equal((await runtime.query(`SELECT reconciliation_required FROM identity.secureshop_launch_resets
      WHERE reset_id=$1`, [unrelatedReset.resetId])).rows[0].reconciliation_required, true);
    await assert.rejects(durableAuthority.finalizeReconciliation(aliceReset.resetId, []),
      { code: 'TARGET_RECONCILIATION_MISMATCH' });
    assert.equal((await runtime.query(`SELECT reconciliation_required FROM identity.secureshop_launch_resets
      WHERE reset_id=$1`, [aliceReset.resetId])).rows[0].reconciliation_required, true);
    assert.deepEqual(await durableAuthority.finalizeReconciliation(aliceReset.resetId,
      [aliceReplayed.history]), { resetId: aliceReset.resetId, status: 'committed',
      reconciled: true, replayed: false });
    assert.deepEqual(await durableAuthority.finalizeReconciliation(aliceReset.resetId,
      [aliceReplayed.history]), { resetId: aliceReset.resetId, status: 'committed',
      reconciled: true, replayed: true });
    const currentLaunch = scopeInput => launches.assertCurrent({ launchId: scopeInput.launchId,
      scenarioId: scopeInput.scenarioId, generation: scopeInput.generation,
      platformOwnerId: scopeInput.platformOwnerId, platformSessionId: scopeInput.platformSessionId });
    const durableReviews = createSecureShopReviewRepository(reviewRuntime, {
      checkCurrent: currentLaunch, checkRetirement: async () => {},
      checkCleanup: input => durableAuthority.checkReviewTarget(input),
    });
    const durableReader = createSecureShopReviewCleanupReceiptReader({ repository: durableReviews });
    const durableReconciler = createSecureShopTargetReconciliationRepository(runtime, {
      checkAuthority: input => durableAuthority.checkTarget(input), readCleanupReceipt: durableReader,
    });
    const coordinator = createSecureShopReviewResetCoordinator({ launches,
      cleanupAuthority: durableAuthority, reviewRepository: durableReviews, reconciler: durableReconciler });

    const charlie = await owner('reconcile-charlie');
    const charlieTarget = await launches.reserveReviewsTarget({ ...charlie.trusted,
      launchId: charlie.launch.binding.launchId, expectedGeneration: 1 });
    const charlieScope = { targetId: charlieTarget.targetId, launchId: charlieTarget.launchId,
      scenarioId: charlieTarget.scenarioId, generation: 1, platformOwnerId: charlie.user.id,
      platformSessionId: charlie.session.id };
    await durableReviews.provision(charlieScope, { reviews: [
      { productId: 7, authorId: 5, body: 'must exist before reset fencing', rating: 2 },
    ] });
    const coordinated = await coordinator.reset({ ...charlie.trusted,
      launchId: charlieTarget.launchId, expectedGeneration: 1, idempotencyKey: 'charlie-review-reset' });
    assert.deepEqual({ status: coordinated.status, fromGeneration: coordinated.fromGeneration,
      toGeneration: coordinated.toGeneration, targets: coordinated.targets },
    { status: 'committed', fromGeneration: 1, toGeneration: 2, targets: 1 });
    assert.equal((await reviewRuntime.query('SELECT count(*)::int n FROM secureshop_review.reviews WHERE target_id=$1', [charlieTarget.targetId])).rows[0].n, 0);
    assert.equal((await runtime.query('SELECT count(*)::int n FROM identity.secureshop_target_cleanup_history WHERE target_id=$1', [charlieTarget.targetId])).rows[0].n, 1);
    assert.equal((await runtime.query(`SELECT reconciliation_required FROM identity.secureshop_launch_resets
      WHERE reset_id=$1`, [coordinated.resetId])).rows[0].reconciliation_required, false);
    const coordinatedReplay = await coordinator.reset({ ...charlie.trusted,
      launchId: charlieTarget.launchId, expectedGeneration: 1, idempotencyKey: 'charlie-review-reset' });
    assert.equal(coordinatedReplay.resetId, coordinated.resetId);
    assert.equal(coordinatedReplay.status, 'committed');
    const charlieNext = await launches.reserveReviewsTarget({ ...charlie.trusted,
      launchId: charlieTarget.launchId, expectedGeneration: 2 });
    assert.equal(charlieNext.generation, 2);

    // Compose the actual file target, durable reset authority, fixed-kind
    // read-only receipt adapter, identity reconciliation, and reset commit.
    reservedFilesRoot = await fs.mkdtemp(path.join(os.tmpdir(), 'dvaia-reconciliation-files-'));
    const reservedFiles = createSecureShopFiles({ root: path.join(reservedFilesRoot, 'targets') });
    const fileOwner = await owner('reconcile-files');
    const fileTarget = await launches.reserveFilesTarget({ ...fileOwner.trusted,
      launchId: fileOwner.launch.binding.launchId, expectedGeneration: 1 });
    const fileReviewTarget = await launches.reserveReviewsTarget({ ...fileOwner.trusted,
      launchId: fileOwner.launch.binding.launchId, expectedGeneration: 1 });
    const fileBinding = Object.freeze({ targetId: fileTarget.targetId, launchId: fileTarget.launchId,
      scenarioId: fileTarget.scenarioId, generation: fileTarget.generation,
      ownerId: String(fileOwner.user.id) });
    const provisionedFile = await reservedFiles.provisionReservedTarget(fileBinding);
    await reservedFiles.writeFile(provisionedFile.capability, '/uploads/old-generation.txt',
      'durable target bytes must be removed', { expectedGeneration: 1 });
    await durableReviews.provision({ targetId: fileReviewTarget.targetId,
      launchId: fileReviewTarget.launchId, scenarioId: fileReviewTarget.scenarioId,
      generation: fileReviewTarget.generation, platformOwnerId: fileOwner.user.id,
      platformSessionId: fileOwner.session.id }, { reviews: [
      { productId: 10, authorId: 8, body: 'mixed reset review bytes', rating: 2 },
    ] });
    const fileReset = await launches.beginReset({ ...fileOwner.trusted,
      launchId: fileTarget.launchId, expectedGeneration: 1, idempotencyKey: 'file-target-reset' });
    const fileScope = Object.freeze({ targetId: fileTarget.targetId, targetKind: 'files',
      launchId: fileTarget.launchId, scenarioId: fileTarget.scenarioId,
      fromGeneration: fileTarget.generation, platformOwnerId: fileOwner.user.id,
      platformSessionId: fileOwner.session.id, operationId: fileReset.resetId });
    const fileReceiptReader = createSecureShopFileCleanupReceiptReader({
      files: reservedFiles, cleanupAuthority: durableAuthority,
    });
    for (const changed of [{ platformOwnerId: fileOwner.user.id + 1 },
      { platformSessionId: fileOwner.session.id + 1 }]) {
      await assert.rejects(fileReceiptReader({ ...fileScope, ...changed }),
        { code: 'RESET_CLEANUP_AUTHORITY_REQUIRED' });
    }
    await assert.rejects(fileReceiptReader(fileScope), { code: 'CLEANUP_RECEIPT_UNAVAILABLE' });
    assert.equal((await reservedFiles.readFile(provisionedFile.capability,
      '/uploads/old-generation.txt')).data.toString(), 'durable target bytes must be removed',
    'a nominal receipt read cannot perform first cleanup');
    const actualFileCleanup = createSecureShopFileTargetCleanup({
      files: reservedFiles, cleanupAuthority: durableAuthority,
    });
    let failAfterFileEffect = true;
    let fileEffectReceipt;
    const injectedFileCleanup = Object.freeze({ async cleanup(...args) {
      fileEffectReceipt = await actualFileCleanup.cleanup(...args);
      if (failAfterFileEffect) {
        failAfterFileEffect = false;
        throw Object.assign(new Error('injected failure after durable file cleanup'),
          { code: 'INJECTED_POST_FILE_CLEANUP_FAILURE' });
      }
      return fileEffectReceipt;
    } });
    const mixedReconciler = createSecureShopTargetReconciliationRepository(runtime, {
      checkAuthority: input => durableAuthority.checkTarget(input),
      readCleanupReceipt: input => input.targetKind === 'files'
        ? fileReceiptReader(input) : durableReader(input),
    });
    const mixedCoordinator = createSecureShopReviewResetCoordinator({ launches,
      cleanupAuthority: durableAuthority, reviewRepository: durableReviews,
      fileCleanup: injectedFileCleanup, reconciler: mixedReconciler });
    await assert.rejects(mixedCoordinator.reset({ ...fileOwner.trusted,
      launchId: fileTarget.launchId, expectedGeneration: 1,
      idempotencyKey: 'file-target-reset' }), { code: 'INJECTED_POST_FILE_CLEANUP_FAILURE' });
    await assert.rejects(reservedFiles.readFile(provisionedFile.capability,
      '/uploads/old-generation.txt'), { code: 'UNKNOWN_CAPABILITY' });
    assert.equal((await runtime.query(`SELECT count(*)::int n
      FROM identity.secureshop_target_reservations WHERE target_id=$1`,
    [fileTarget.targetId])).rows[0].n, 1,
    'post-effect failure cannot claim identity reconciliation');
    assert.equal((await runtime.query(`SELECT reconciliation_required
      FROM identity.secureshop_launch_resets WHERE reset_id=$1`,
    [fileReset.resetId])).rows[0].reconciliation_required, true);
    assert.equal((await fileReceiptReader(fileScope)).receiptSha256,
      fileEffectReceipt.receiptSha256, 'retry evidence is the same private durable receipt');
    const mixed = await mixedCoordinator.reset({ ...fileOwner.trusted,
      launchId: fileTarget.launchId, expectedGeneration: 1,
      idempotencyKey: 'file-target-reset' });
    assert.equal(mixed.targets, 2);
    assert.equal((await runtime.query(`SELECT status,reconciliation_required
      FROM identity.secureshop_launch_resets WHERE reset_id=$1`, [fileReset.resetId])).rows[0].status,
    'committed');
    assert.equal((await runtime.query(`SELECT reconciliation_required
      FROM identity.secureshop_launch_resets WHERE reset_id=$1`,
    [fileReset.resetId])).rows[0].reconciliation_required, false);
    assert.equal((await runtime.query(`SELECT count(*)::int n
      FROM identity.secureshop_target_reservations WHERE launch_id=$1 AND generation=1`,
    [fileTarget.launchId])).rows[0].n, 0);
    assert.equal((await reviewRuntime.query(`SELECT count(*)::int n FROM secureshop_review.reviews
      WHERE target_id=$1`, [fileReviewTarget.targetId])).rows[0].n, 0);
    assert.equal((await launches.reserveFilesTarget({ ...fileOwner.trusted,
      launchId: fileTarget.launchId, expectedGeneration: 2 })).generation, 2);

    const dana = await owner('reconcile-dana');
    const danaFiles = await launches.reserveFilesTarget({ ...dana.trusted,
      launchId: dana.launch.binding.launchId, expectedGeneration: 1 });
    await assert.rejects(coordinator.reset({ ...dana.trusted, launchId: danaFiles.launchId,
      expectedGeneration: 1, idempotencyKey: 'dana-files-reset' }), { code: 'UNSUPPORTED_TARGET_CLEANUP' });
    assert.deepEqual((await runtime.query('SELECT status,generation FROM identity.secureshop_launches WHERE launch_id=$1', [danaFiles.launchId])).rows[0],
      { status: 'resetting', generation: '2' });
    assert.equal((await runtime.query('SELECT count(*)::int n FROM identity.secureshop_target_reservations WHERE target_id=$1', [danaFiles.targetId])).rows[0].n, 1);
    assert.equal((await runtime.query(`SELECT reconciliation_required FROM identity.secureshop_launch_resets
      WHERE launch_id=$1`, [danaFiles.launchId])).rows[0].reconciliation_required, true);

    const eve = await owner('reconcile-eve');
    const eveTarget = await launches.reserveReviewsTarget({ ...eve.trusted,
      launchId: eve.launch.binding.launchId, expectedGeneration: 1 });
    await durableReviews.provision({ targetId: eveTarget.targetId, launchId: eveTarget.launchId,
      scenarioId: eveTarget.scenarioId, generation: 1, platformOwnerId: eve.user.id,
      platformSessionId: eve.session.id }, { reviews: [
      { productId: 8, authorId: 6, body: 'revoked reset cleanup remains required', rating: 3 },
    ] });
    const eveReset = await launches.beginReset({ ...eve.trusted, launchId: eveTarget.launchId,
      expectedGeneration: 1, idempotencyKey: 'eve-revoked-reset' });
    await launches.revoke({ ...eve.trusted, launchId: eveTarget.launchId,
      expectedGeneration: 2, reason: 'test revocation after reset fence' });
    const recovery = await coordinator.recover(eveReset.resetId);
    assert.deepEqual({ status: recovery.status, resolved: recovery.resolved,
      activated: recovery.activated, targets: recovery.targets },
    { status: 'aborted', resolved: true, activated: false, targets: 1 });
    assert.equal((await runtime.query('SELECT count(*)::int n FROM identity.secureshop_target_reservations WHERE target_id=$1', [eveTarget.targetId])).rows[0].n, 0);
    assert.equal((await runtime.query('SELECT status FROM identity.secureshop_launches WHERE launch_id=$1', [eveTarget.launchId])).rows[0].status, 'revoked');
    assert.equal((await runtime.query(`SELECT reconciliation_required FROM identity.secureshop_launch_resets
      WHERE reset_id=$1`, [eveReset.resetId])).rows[0].reconciliation_required, false);
    assert.deepEqual(await coordinator.recover(eveReset.resetId), recovery);

    const empty = await owner('reconcile-empty');
    const emptyReset = await coordinator.reset({ ...empty.trusted,
      launchId: empty.launch.binding.launchId, expectedGeneration: 1,
      idempotencyKey: 'empty-target-reset' });
    assert.equal(emptyReset.targets, 0);
    assert.equal((await runtime.query(`SELECT reconciliation_required FROM identity.secureshop_launch_resets
      WHERE reset_id=$1`, [emptyReset.resetId])).rows[0].reconciliation_required, false);

    const failed = await owner('reconcile-failed-receipt');
    const failedTarget = await launches.reserveReviewsTarget({ ...failed.trusted,
      launchId: failed.launch.binding.launchId, expectedGeneration: 1 });
    await durableReviews.provision({ targetId: failedTarget.targetId, launchId: failedTarget.launchId,
      scenarioId: failedTarget.scenarioId, generation: 1, platformOwnerId: failed.user.id,
      platformSessionId: failed.session.id }, { reviews: [
      { productId: 9, authorId: 7, body: 'missing receipt must retain reconciliation debt', rating: 1 },
    ] });
    const missingReceiptCoordinator = createSecureShopReviewResetCoordinator({ launches,
      cleanupAuthority: durableAuthority,
      reviewRepository: { cleanup: async () => {} }, reconciler: durableReconciler });
    await assert.rejects(missingReceiptCoordinator.reset({ ...failed.trusted,
      launchId: failedTarget.launchId, expectedGeneration: 1,
      idempotencyKey: 'failed-receipt-reset' }), { code: 'REVIEW_CLEANUP_RECEIPT_UNAVAILABLE' });
    assert.equal((await runtime.query(`SELECT reconciliation_required FROM identity.secureshop_launch_resets
      WHERE launch_id=$1`, [failedTarget.launchId])).rows[0].reconciliation_required, true);
    assert.equal((await reviewRuntime.query(`SELECT count(*)::int n FROM secureshop_review.reviews
      WHERE target_id=$1`, [failedTarget.targetId])).rows[0].n, 1);
  } finally {
    await Promise.allSettled([runtime.end(), migration.end(), reviewRuntime.end(), reviewMigration.end(),
      reservedFilesRoot && fs.rm(reservedFilesRoot, { recursive: true, force: true })]);
  }
});
