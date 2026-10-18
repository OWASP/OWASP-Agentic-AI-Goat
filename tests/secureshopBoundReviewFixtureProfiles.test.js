'use strict';

const crypto = require('node:crypto');
const test = require('node:test');
const assert = require('node:assert/strict');
const { createSecureShopBoundReviewRepository } = require(
  '../server/database/postgres/secureshopBoundReviewRepository');
const { PREFERRED_REVIEW_FIXTURES, LEGACY_REVIEW_FIXTURES, PROFILE_DIGESTS, digestProfile }
  = require('../server/services/secureshopBoundReviewFixtureProfiles');

const baseScope = Object.freeze({
  targetId: '10000000-0000-4000-8000-000000000091',
  launchId: '20000000-0000-4000-8000-000000000091',
  scenarioId: '30000000-0000-4000-8000-000000000091',
  generation: 4, platformOwnerId: 91, platformSessionId: 901,
});

function profileDigest(profile) {
  return crypto.createHash('sha256').update(JSON.stringify(profile)).digest();
}

function fixture() {
  const targets = new Map();
  let insertedReviews = 0;
  const client = {
    async query(sql, params = []) {
      if (['BEGIN', 'COMMIT', 'ROLLBACK'].includes(sql)) return { rows: [], rowCount: 0 };
      if (sql.includes('INSERT INTO secureshop_review.review_targets')) {
        if (targets.has(params[0])) return { rows: [], rowCount: 0 };
        targets.set(params[0], { target_id: params[0], launch_id: params[1], scenario_id: params[2],
          generation: params[3], original_platform_owner_id: params[4],
          original_platform_session_id: params[5], lifecycle: 'active', seed_count: params[6],
          seed_sha256: Buffer.from(params[7]), fixtureCount: 0, learnerCount: 0 });
        return { rows: [], rowCount: 1 };
      }
      if (sql.includes('FROM secureshop_review.review_targets')) {
        const target = targets.get(params[0]);
        const matches = target && target.launch_id === params[1] && target.scenario_id === params[2]
          && target.generation === params[3] && target.original_platform_owner_id === params[4]
          && target.original_platform_session_id === params[5];
        return { rows: matches ? [target] : [], rowCount: matches ? 1 : 0 };
      }
      if (sql.includes('INSERT INTO secureshop_review.reviews')) {
        targets.get(params[0]).fixtureCount += 1;
        insertedReviews += 1;
        return { rows: [], rowCount: 1 };
      }
      if (sql.includes('count(*)::integer AS count')) {
        const target = targets.get(params[0]);
        const count = sql.includes("source_kind='fixture'")
          ? target.fixtureCount : target.fixtureCount + target.learnerCount;
        return { rows: [{ count }], rowCount: 1 };
      }
      throw new Error(`unexpected SQL: ${sql}`);
    },
    release() {},
  };
  const repository = createSecureShopBoundReviewRepository({
    query: (...args) => client.query(...args), async connect() { return client; },
  }, { enableLearnerSubmissions: true, async checkCurrent() {}, async checkRetirement() {},
    async checkCleanup() {} });
  function seedTarget(scope, profile, { fixtureCount = profile.length, learnerCount = 0 } = {}) {
    targets.set(scope.targetId, { target_id: scope.targetId, launch_id: scope.launchId,
      scenario_id: scope.scenarioId, generation: scope.generation,
      original_platform_owner_id: scope.platformOwnerId,
      original_platform_session_id: scope.platformSessionId, lifecycle: 'active',
      seed_count: profile.length, seed_sha256: profileDigest(profile), fixtureCount, learnerCount });
  }
  return { repository, targets, seedTarget, insertedReviews: () => insertedReviews };
}

test('pinned preferred and legacy profiles retain immutable reviewed digests', () => {
  assert.equal(PREFERRED_REVIEW_FIXTURES.length, 2);
  assert.equal(LEGACY_REVIEW_FIXTURES.length, 74);
  assert.equal(digestProfile(PREFERRED_REVIEW_FIXTURES), PROFILE_DIGESTS.preferred);
  assert.equal(digestProfile(LEGACY_REVIEW_FIXTURES), PROFILE_DIGESTS.legacy);
  assert.equal(Object.isFrozen(PREFERRED_REVIEW_FIXTURES[0]), true);
  assert.equal(Object.isFrozen(LEGACY_REVIEW_FIXTURES[0]), true);
});

test('fresh and reset-generation targets receive only the preferred profile and repeated ensure is inert', async () => {
  const f = fixture();
  assert.equal((await f.repository.provision(baseScope, { reviews: PREFERRED_REVIEW_FIXTURES,
    compatibleReviews: [LEGACY_REVIEW_FIXTURES] })).reviewCount, 2);
  assert.equal(f.insertedReviews(), 2);
  await f.repository.provision(baseScope, { reviews: PREFERRED_REVIEW_FIXTURES,
    compatibleReviews: [LEGACY_REVIEW_FIXTURES] });
  assert.equal(f.insertedReviews(), 2);

  const resetScope = { ...baseScope, targetId: '10000000-0000-4000-8000-000000000092', generation: 5 };
  assert.equal((await f.repository.provision(resetScope, { reviews: PREFERRED_REVIEW_FIXTURES,
    compatibleReviews: [LEGACY_REVIEW_FIXTURES] })).reviewCount, 2);
  assert.equal(f.insertedReviews(), 4);
  assert.equal(f.targets.get(baseScope.targetId).seed_count, 2);
});

test('exact legacy targets and preferred targets with moderated fixtures plus learners remain unchanged', async () => {
  const legacy = fixture();
  legacy.seedTarget(baseScope, LEGACY_REVIEW_FIXTURES);
  assert.equal((await legacy.repository.provision(baseScope, { reviews: PREFERRED_REVIEW_FIXTURES,
    compatibleReviews: [LEGACY_REVIEW_FIXTURES] })).reviewCount, 74);
  assert.equal(legacy.insertedReviews(), 0);

  const populated = fixture();
  populated.seedTarget(baseScope, PREFERRED_REVIEW_FIXTURES, { learnerCount: 3 });
  assert.equal((await populated.repository.provision(baseScope, { reviews: PREFERRED_REVIEW_FIXTURES,
    compatibleReviews: [LEGACY_REVIEW_FIXTURES] })).reviewCount, 2);
  assert.equal(populated.targets.get(baseScope.targetId).learnerCount, 3);
});

test('unknown and partial existing targets fail without reseeding or mutation', async () => {
  const unknown = fixture();
  const other = [{ productId: 1, authorId: 1, body: 'unknown', rating: 3 }];
  unknown.seedTarget(baseScope, other);
  await assert.rejects(unknown.repository.provision(baseScope, { reviews: PREFERRED_REVIEW_FIXTURES,
    compatibleReviews: [LEGACY_REVIEW_FIXTURES] }), { code: 'REVIEW_TARGET_MISMATCH' });
  assert.equal(unknown.insertedReviews(), 0);

  const partial = fixture();
  partial.seedTarget(baseScope, LEGACY_REVIEW_FIXTURES, { fixtureCount: 73 });
  await assert.rejects(partial.repository.provision(baseScope, { reviews: PREFERRED_REVIEW_FIXTURES,
    compatibleReviews: [LEGACY_REVIEW_FIXTURES] }), { code: 'REVIEW_TARGET_PARTIAL' });
  assert.equal(partial.insertedReviews(), 0);
});

test('custom fixtures stay strict unless compatibility is explicitly declared', async () => {
  const current = [{ productId: 7, authorId: 2, body: 'current', rating: 4 }];
  const prior = [{ productId: 8, authorId: 3, body: 'prior', rating: 2 }];
  const strict = fixture(); strict.seedTarget(baseScope, prior);
  await assert.rejects(strict.repository.provision(baseScope, { reviews: current }),
    { code: 'REVIEW_TARGET_MISMATCH' });
  assert.equal((await strict.repository.provision(baseScope,
    { reviews: current, compatibleReviews: [prior] })).reviewCount, 1);

  const duplicate = fixture();
  await assert.rejects(duplicate.repository.provision(baseScope,
    { reviews: current, compatibleReviews: [current] }), { code: 'INVALID_ARGUMENT' });
  assert.equal(duplicate.targets.size, 0);
});
