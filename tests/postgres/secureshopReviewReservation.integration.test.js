'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const { randomUUID } = require('node:crypto');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const { initializeIdentityRepository, createIdentityRepository } = require('../../server/database/postgres/identityRepository');
const { createSecureShopLaunchRepository } = require('../../server/database/postgres/secureshopLaunchRepository');

const enabled = process.env.PG_TEST_DISPOSABLE === 'yes'
  && process.env.PG_SECURESHOP_REVIEW_RESERVATION_TEST_MIGRATION_URL
  && process.env.PG_SECURESHOP_REVIEW_RESERVATION_TEST_RUNTIME_URL;

test('review target reservations preserve exact launch authority and existing files behavior', { skip: !enabled }, async t => {
  for (const key of ['PG_SECURESHOP_REVIEW_RESERVATION_TEST_MIGRATION_URL', 'PG_SECURESHOP_REVIEW_RESERVATION_TEST_RUNTIME_URL']) {
    const url = new URL(process.env[key]);
    assert.match(url.pathname, /^\/owasp_ai_goat_test_[a-z0-9_]+$/);
    assert.ok(['127.0.0.1', 'localhost'].includes(url.hostname));
  }
  const migration = new Pool({ connectionString: process.env.PG_SECURESHOP_REVIEW_RESERVATION_TEST_MIGRATION_URL, max: 2 });
  const runtime = new Pool({ connectionString: process.env.PG_SECURESHOP_REVIEW_RESERVATION_TEST_RUNTIME_URL, max: 8 });
  t.after(async () => Promise.all([runtime.end(), migration.end()]));
  await initializeIdentityRepository(runtime, migration);
  const draft = await fs.readFile(path.join(__dirname, '../../docs/modernization/drafts/secureshop-review-target-reservation.sql'), 'utf8');
  await migration.query(draft);

  const identity = createIdentityRepository(runtime);
  const launches = createSecureShopLaunchRepository(runtime);
  const passwordHash = await bcrypt.hash('owned-review-reservation', 4);
  const expiresAt = new Date(Date.now() + 3600000).toISOString();
  async function createOwner(name) {
    const user = await identity.createUser({ username: name, email: `${name}@review.invalid`, passwordHash });
    const session = await identity.createSession({ userId: user.id, token: randomUUID(), expiresAt, expectedPasswordHash: passwordHash });
    const scope = { platformOwnerId: user.id, platformSessionId: session.id };
    const launch = await launches.issueOrRenew({ ...scope, expiresAt });
    return { user, session, scope, launch };
  }
  const alice = await createOwner('review-reservation-alice');
  const bob = await createOwner('review-reservation-bob');
  const aliceArgs = { ...alice.scope, launchId: alice.launch.binding.launchId, expectedGeneration: 1 };
  const bobArgs = { ...bob.scope, launchId: bob.launch.binding.launchId, expectedGeneration: 1 };

  const filesBefore = await launches.reserveFilesTarget(aliceArgs);
  assert.equal(filesBefore.kind, 'files');
  const reviewAttempts = await Promise.all(Array.from({ length: 8 }, () => launches.reserveReviewsTarget(aliceArgs)));
  const review = reviewAttempts[0];
  assert.ok(reviewAttempts.every(item => item.targetId === review.targetId));
  assert.deepEqual(review, {
    targetId: review.targetId, launchId: alice.launch.binding.launchId,
    scenarioId: alice.launch.binding.scenarioId, generation: 1, kind: 'reviews',
  });
  assert.deepEqual(await createSecureShopLaunchRepository(runtime).reserveReviewsTarget(aliceArgs), review);
  assert.deepEqual(await launches.reserveFilesTarget(aliceArgs), filesBefore);
  assert.notEqual(review.targetId, filesBefore.targetId);
  assert.deepEqual((await runtime.query(`SELECT target_kind,original_platform_owner_id,generation
    FROM identity.secureshop_target_reservations WHERE launch_id=$1 ORDER BY target_kind`, [alice.launch.binding.launchId])).rows,
  [
    { target_kind: 'files', original_platform_owner_id: alice.user.id, generation: '1' },
    { target_kind: 'reviews', original_platform_owner_id: alice.user.id, generation: '1' },
  ]);

  await assert.rejects(launches.reserveReviewsTarget({ ...aliceArgs, ...bob.scope }), { code: 'LAUNCH_UNAVAILABLE' });
  await assert.rejects(launches.reserveReviewsTarget({ ...aliceArgs, expectedGeneration: 2 }), { code: 'LAUNCH_UNAVAILABLE' });
  const bobReview = await launches.reserveReviewsTarget(bobArgs);
  assert.equal(bobReview.kind, 'reviews');
  assert.notEqual(bobReview.targetId, review.targetId);
  await assert.rejects(runtime.query(`INSERT INTO identity.secureshop_target_reservations
    (target_id,launch_id,generation,target_kind,original_platform_owner_id)
    VALUES($1,$2,1,'reviews',$3)`, [randomUUID(), bob.launch.binding.launchId, alice.user.id]), /binding is invalid/);
  await assert.rejects(runtime.query(`INSERT INTO identity.secureshop_target_reservations
    (target_id,launch_id,generation,target_kind,original_platform_owner_id)
    VALUES($1,$2,1,'other',$3)`, [randomUUID(), bob.launch.binding.launchId, bob.user.id]), /target_kind/);

  const reset = await launches.beginReset({ ...alice.scope, launchId: alice.launch.binding.launchId,
    expectedGeneration: 1, idempotencyKey: 'review-reservation-reset' });
  await assert.rejects(launches.reserveReviewsTarget(aliceArgs), { code: 'LAUNCH_UNAVAILABLE' });
  for (let retry = 0; retry < 2; retry += 1) {
    await assert.rejects(launches.commitReset({ ...alice.scope, launchId: alice.launch.binding.launchId,
      resetId: reset.resetId, expectedGeneration: 2 }), { code: 'CLEANUP_REQUIRED' });
  }
  assert.equal((await runtime.query('SELECT status FROM identity.secureshop_launches WHERE launch_id=$1',
    [alice.launch.binding.launchId])).rows[0].status, 'resetting');
  assert.equal((await runtime.query('SELECT status FROM identity.secureshop_launch_resets WHERE reset_id=$1',
    [reset.resetId])).rows[0].status, 'fenced');
  await assert.rejects(launches.reserveReviewsTarget({ ...alice.scope, launchId: alice.launch.binding.launchId,
    expectedGeneration: 2 }), { code: 'LAUNCH_UNAVAILABLE' });
  await assert.rejects(launches.reserveFilesTarget({ ...alice.scope, launchId: alice.launch.binding.launchId,
    expectedGeneration: 2 }), { code: 'LAUNCH_UNAVAILABLE' });

  await launches.revoke({ ...bob.scope, launchId: bob.launch.binding.launchId,
    expectedGeneration: 1, reason: 'owned review reservation retirement' });
  await assert.rejects(launches.reserveReviewsTarget(bobArgs), { code: 'LAUNCH_UNAVAILABLE' });
  assert.equal((await runtime.query("SELECT count(*)::integer AS count FROM identity.secureshop_target_reservations WHERE target_kind='reviews'")).rows[0].count, 2);
});
