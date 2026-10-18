'use strict';

function validateEffectDeadline(value) {
  if (value !== undefined && (!Number.isSafeInteger(value) || value < 100 || value > 10000)) {
    throw Object.assign(new TypeError('Invalid review effect deadline'), { code: 'INVALID_ARGUMENT' });
  }
}
async function setEffectDeadline(client, value) {
  if (value !== undefined) await client.query("SELECT set_config('statement_timeout',$1,true),set_config('lock_timeout',$1,true)",[String(value)]);
}

const crypto = require('node:crypto');
const { withTransaction } = require('./index');
const reviewScene = require('../../services/secureshopReviewSceneBinding');
const moderationBinding = require('../../services/secureshopReviewModerationBinding');
const { assertSceneGrant, executionScope, withSceneLease } = require('../../services/secureshopSceneBinding');

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const MAX_REVIEWS = 256;
const MAX_BODY_BYTES = 65536;
const MAX_NOTES_BYTES = 16384;
const MAX_SEED_BYTES = 1048576;
const MAX_COMPATIBLE_PROFILES = 16;
const SHOP_ROLES = new Set(['customer', 'merchant', 'admin']);

function failure(code, message) {
  return Object.assign(new Error(message), { code });
}
function uuid(value, label) {
  if (typeof value !== 'string' || !UUID.test(value)) throw failure('INVALID_ARGUMENT', `${label} is invalid`);
  return value.toLowerCase();
}
function positiveId(value, label) {
  if (!Number.isSafeInteger(value) || value < 1 || value > 2147483647) {
    throw failure('INVALID_ARGUMENT', `${label} is invalid`);
  }
  return value;
}
function generation(value) {
  if (!Number.isSafeInteger(value) || value < 1) throw failure('INVALID_ARGUMENT', 'generation is invalid');
  return value;
}
function boundedText(value, label, max, { empty = false } = {}) {
  if (typeof value !== 'string' || (!empty && !value.length) || Buffer.byteLength(value) > max) {
    throw failure('INVALID_ARGUMENT', `${label} is invalid`);
  }
  return value;
}
function plain(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    && Object.getPrototypeOf(value) === Object.prototype;
}
function exactKeys(value, expected) {
  return plain(value) && Object.keys(value).length === expected.length
    && expected.every(key => Object.hasOwn(value, key));
}
function normalizeScope(input) {
  if (!plain(input)) throw failure('INVALID_ARGUMENT', 'trusted review scope is invalid');
  return reviewScene.copy(input, {
    targetId: uuid(input.targetId, 'targetId'),
    launchId: uuid(input.launchId, 'launchId'),
    scenarioId: uuid(input.scenarioId, 'scenarioId'),
    generation: generation(input.generation),
    platformOwnerId: positiveId(input.platformOwnerId, 'platformOwnerId'),
    platformSessionId: positiveId(input.platformSessionId, 'platformSessionId'),
  });
}
function normalizeReview(row) {
  if (!plain(row)) throw failure('INVALID_ARGUMENT', 'review fixture is invalid');
  const normalized = {
    productId: positiveId(row.productId, 'productId'),
    authorId: positiveId(row.authorId, 'authorId'),
    body: boundedText(row.body, 'review body', MAX_BODY_BYTES, { empty: true }),
    rating: positiveId(row.rating, 'rating'),
  };
  if (normalized.rating > 5) throw failure('INVALID_ARGUMENT', 'rating is invalid');
  return Object.freeze(normalized);
}
function normalizePersona(input) {
  if (!exactKeys(input, ['id', 'role']) || !SHOP_ROLES.has(input.role)) {
    throw failure('INVALID_ARGUMENT', 'trusted shop persona is invalid');
  }
  return Object.freeze({ id: positiveId(input.id, 'shop persona id'), role: input.role });
}
function normalizeSubmission(input) {
  if (!exactKeys(input, ['submissionId', 'productId', 'authorId', 'body', 'rating'])) {
    throw failure('INVALID_ARGUMENT', 'review submission is invalid');
  }
  return Object.freeze({
    submissionId: uuid(input.submissionId, 'submissionId'),
    ...normalizeReview(input),
  });
}
function normalizeFixtures(reviews) {
  if (!Array.isArray(reviews) || reviews.length > MAX_REVIEWS
    || Object.keys(reviews).length !== reviews.length) {
    throw failure('INVALID_ARGUMENT', 'review fixtures are invalid');
  }
  const normalized = reviews.map(normalizeReview);
  const serialized = JSON.stringify(normalized);
  if (Buffer.byteLength(serialized) > MAX_SEED_BYTES) throw failure('INVALID_ARGUMENT', 'review fixtures are too large');
  return { normalized, digest: crypto.createHash('sha256').update(serialized).digest() };
}
function normalizeProvisionProfiles(reviews, compatibleReviews) {
  if (!Array.isArray(compatibleReviews) || compatibleReviews.length > MAX_COMPATIBLE_PROFILES
      || Object.keys(compatibleReviews).length !== compatibleReviews.length) {
    throw failure('INVALID_ARGUMENT', 'compatible review fixture profiles are invalid');
  }
  const profiles = [normalizeFixtures(reviews), ...compatibleReviews.map(normalizeFixtures)];
  const digests = new Set();
  for (const profile of profiles) {
    const digest = profile.digest.toString('hex');
    if (digests.has(digest)) {
      throw failure('INVALID_ARGUMENT', 'review fixture profiles are duplicated or collide');
    }
    digests.add(digest);
  }
  return profiles;
}
function normalizeDecision(value) {
  if (!['approve', 'reject'].includes(value)) throw failure('INVALID_ARGUMENT', 'decision is invalid');
  return value === 'approve' ? 'approved' : 'rejected';
}
function boundedLimit(value) {
  if (!Number.isInteger(value) || value < 1 || value > 100) throw failure('INVALID_ARGUMENT', 'limit is invalid');
  return value;
}
function normalizeListOptions(input = {}) {
  if (!plain(input) || Object.keys(input).some(key => ![
    'status', 'productId', 'minRating', 'maxRating', 'limit', 'offset',
  ].includes(key))) throw failure('INVALID_ARGUMENT', 'review filters are invalid');
  const optionalId = (value, label) => value === undefined || value === null
    ? null : positiveId(value, label);
  const optionalRating = (value, label) => {
    const rating = optionalId(value, label);
    if (rating !== null && rating > 5) throw failure('INVALID_ARGUMENT', `${label} is invalid`);
    return rating;
  };
  const status = input.status === undefined || input.status === null ? null : input.status;
  if (status !== null && !['pending', 'approved', 'rejected'].includes(status)) {
    throw failure('INVALID_ARGUMENT', 'status is invalid');
  }
  const minRating = optionalRating(input.minRating, 'minRating');
  const maxRating = optionalRating(input.maxRating, 'maxRating');
  if (minRating !== null && maxRating !== null && minRating > maxRating) {
    throw failure('INVALID_ARGUMENT', 'rating range is invalid');
  }
  const limit = boundedLimit(input.limit ?? 50);
  const offset = input.offset ?? 0;
  if (!Number.isSafeInteger(offset) || offset < 0 || offset > 2147483647) {
    throw failure('INVALID_ARGUMENT', 'offset is invalid');
  }
  return Object.freeze({ status, productId: optionalId(input.productId, 'productId'),
    minRating, maxRating, limit, offset });
}
function publicReview(row) {
  return Object.freeze({
    id: Number(row.id), productId: Number(row.product_id), authorId: Number(row.author_id),
    body: row.body, rating: Number(row.rating), status: row.status,
    moderatorKind: row.moderator_kind, moderatorNotes: row.moderator_notes,
    createdAt: row.created_at, moderatedAt: row.moderated_at,
  });
}
// Preserve the established merchant Reviews page DTO. Raw body bytes are
// intentionally returned unchanged for the stored-XSS and indirect-PI labs.
function publicReviewListRow(row) {
  return Object.freeze({
    id: Number(row.id), product_id: Number(row.product_id), author_id: Number(row.author_id),
    body: row.body, rating: Number(row.rating), status: row.status,
    moderator_kind: row.moderator_kind, moderator_notes: row.moderator_notes,
    created_at: row.created_at, moderated_at: row.moderated_at,
    ...(typeof row.product_name === 'string' && Buffer.byteLength(row.product_name, 'utf8') <= 256
      ? { product_name: row.product_name } : {}),
  });
}
function publicBinding(scope, count) {
  return Object.freeze({ ...scope, reviewCount: count });
}
function submissionDigests(scope, persona, submission) {
  const bodySha256 = crypto.createHash('sha256').update(submission.body, 'utf8').digest();
  const requestSha256 = crypto.createHash('sha256').update(JSON.stringify([
    'dvaia-secureshop-review-submission', 1,
    scope.targetId, scope.launchId, scope.scenarioId, scope.generation,
    scope.platformOwnerId, scope.platformSessionId,
    persona.id, persona.role, submission.submissionId,
    submission.productId, submission.authorId, submission.body, submission.rating,
  ])).digest();
  return { bodySha256, requestSha256 };
}
function validDigest(value) {
  return Buffer.isBuffer(value) && value.length === 32;
}
function privateSubmission(scope, row, created) {
  return Object.freeze({
    version: 1, ...scope, reviewId: Number(row.id), submissionId: row.submission_id,
    productId: Number(row.product_id), authorId: Number(row.author_id), body: row.body,
    rating: Number(row.rating), submittedByShopUserId: Number(row.submitted_by_shop_user_id),
    submittedByShopRole: row.submitted_by_shop_role,
    bodySha256: row.body_sha256.toString('hex'), requestSha256: row.request_sha256.toString('hex'),
    status: row.status, createdAt: row.created_at, created,
    ...(row.created_at_micros === undefined ? {} : { createdAtMicros: row.created_at_micros }),
  });
}
function verifySubmissionRow(scope, row) {
  if (!row || row.source_kind !== 'learner' || Number(row.source_version) !== 1
      || !UUID.test(row.submission_id) || !validDigest(row.body_sha256)
      || !validDigest(row.request_sha256) || !SHOP_ROLES.has(row.submitted_by_shop_role)) {
    throw failure('REVIEW_SUBMISSION_MISMATCH', 'stored review submission is invalid');
  }
  const persona = Object.freeze({ id: Number(row.submitted_by_shop_user_id), role: row.submitted_by_shop_role });
  const submission = Object.freeze({ submissionId: row.submission_id, productId: Number(row.product_id),
    authorId: Number(row.author_id), body: row.body, rating: Number(row.rating) });
  const expected = submissionDigests(scope, persona, submission);
  if (!crypto.timingSafeEqual(row.body_sha256, expected.bodySha256)
      || !crypto.timingSafeEqual(row.request_sha256, expected.requestSha256)) {
    throw failure('REVIEW_SUBMISSION_MISMATCH', 'stored review submission is invalid');
  }
  return { persona, submission };
}
function receiptDigest(scope, operationId, deletedReviewCount, seedCount, seedSha256) {
  return crypto.createHash('sha256').update(JSON.stringify({
    version: 1, operationId, targetId: scope.targetId, launchId: scope.launchId,
    scenarioId: scope.scenarioId, generation: scope.generation,
    platformOwnerId: scope.platformOwnerId, platformSessionId: scope.platformSessionId,
    deletedReviewCount, seedCount, seedSha256: seedSha256.toString('hex'),
  })).digest();
}
function publicCleanupReceipt(row) {
  return Object.freeze({
    version: 1, operationId: row.operation_id, targetId: row.target_id,
    launchId: row.launch_id, scenarioId: row.scenario_id, generation: Number(row.generation),
    platformOwnerId: Number(row.original_platform_owner_id),
    platformSessionId: Number(row.original_platform_session_id),
    deletedReviewCount: Number(row.deleted_review_count), seedCount: Number(row.seed_count),
    seedSha256: row.seed_sha256.toString('hex'), receiptSha256: row.receipt_sha256.toString('hex'),
    completedAt: row.completed_at,
  });
}

const TARGET_WHERE = `target_id=$1 AND launch_id=$2 AND scenario_id=$3 AND generation=$4
  AND original_platform_owner_id=$5 AND original_platform_session_id=$6`;
function scopeValues(scope) {
  return [scope.targetId, scope.launchId, scope.scenarioId, scope.generation,
    scope.platformOwnerId, scope.platformSessionId];
}
async function requireTarget(client, scope, lock = 'FOR SHARE') {
  const row = (await client.query(`SELECT target_id,lifecycle,seed_count,seed_sha256
    FROM secureshop_review.review_targets WHERE ${TARGET_WHERE} ${lock}`, scopeValues(scope))).rows[0];
  if (!row || row.lifecycle !== 'active') {
    throw failure('REVIEW_TARGET_UNAVAILABLE', 'review target is unavailable');
  }
  return row;
}
const DEFAULT_SEED_HASHES = new Set(Object.values(require('../../services/secureshopBoundReviewFixtureProfiles').PROFILE_DIGESTS));
async function verifySellerLessons(client, scope, target, { cleaned = false, deletedCount } = {}) {
  if (!Buffer.isBuffer(target.seed_sha256) || !DEFAULT_SEED_HASHES.has(target.seed_sha256.toString('hex'))) return 0;
  const markers = (await client.query('SELECT * FROM secureshop_review.seller_review_lessons WHERE target_id=$1 ORDER BY ordinal', [scope.targetId])).rows;
  if (![0, 2].includes(markers.length)) throw failure('REVIEW_TARGET_PARTIAL', 'Seller lesson provenance incomplete');
  for (let i = 0; i < markers.length; i++) {
    const m = markers[i];
    const expected = crypto.createHash('sha256').update([scope.targetId, 1, i + 1,
      m.product_target_id, m.retailer_id, m.product_id, m.review_id,
      Buffer.isBuffer(m.body_sha256) ? m.body_sha256.toString('hex') : '',
      target.seed_sha256.toString('hex')].join(':')).digest();
    if (Number(m.ordinal) !== i + 1 || Number(m.profile_version) !== 1
        || !Buffer.isBuffer(m.seed_sha256) || !m.seed_sha256.equals(target.seed_sha256)
        || !Buffer.isBuffer(m.provenance_sha256) || !m.provenance_sha256.equals(expected))
      throw failure('REVIEW_TARGET_PARTIAL', 'Seller lesson provenance mismatch');
  }
  if (cleaned) {
    if (deletedCount < Number(target.seed_count) + markers.length)
      throw failure('REVIEW_CLEANUP_MISMATCH', 'Seller lessons not accounted for');
    return;
  }
  const rows = (await client.query("SELECT * FROM secureshop_review.reviews WHERE target_id=$1 AND source_kind='seller_lesson' ORDER BY id", [scope.targetId])).rows;
  if (rows.length !== markers.length || markers.some(m => !rows.some(r =>
    String(r.id) === String(m.review_id) && Number(r.product_id) === Number(m.product_id)
      && crypto.createHash('sha256').update(r.body).digest().equals(m.body_sha256))))
    throw failure('REVIEW_TARGET_PARTIAL', 'Seller lesson source rows mismatch');
  return markers.length;
}
async function readVerifiedCleanupReceipt(client, scope, operation, target) {
  const receipts = (await client.query(`SELECT * FROM secureshop_review.review_cleanup_receipts
    WHERE target_id=$1 FOR UPDATE`, [scope.targetId])).rows;
  if (!receipts.length) return null;
  const row = receipts[0];
  const remaining = Number((await client.query(
    'SELECT count(*)::integer AS count FROM secureshop_review.reviews WHERE target_id=$1',
    [scope.targetId]
  )).rows[0].count);
  const buffersValid = Buffer.isBuffer(target.seed_sha256) && target.seed_sha256.length === 32
    && Buffer.isBuffer(row.seed_sha256) && row.seed_sha256.length === 32
    && Buffer.isBuffer(row.receipt_sha256) && row.receipt_sha256.length === 32;
  const expected = buffersValid
    ? receiptDigest(scope, operation, Number(row.deleted_review_count), Number(row.seed_count), row.seed_sha256)
    : null;
  if (receipts.length !== 1 || row.operation_id !== operation || row.target_id !== scope.targetId
      || row.launch_id !== scope.launchId || row.scenario_id !== scope.scenarioId
      || Number(row.generation) !== scope.generation
      || Number(row.original_platform_owner_id) !== scope.platformOwnerId
      || Number(row.original_platform_session_id) !== scope.platformSessionId
      || target.lifecycle !== 'retired' || remaining !== 0 || !buffersValid
      || Number(row.seed_count) !== Number(target.seed_count)
      || !Number.isSafeInteger(Number(row.deleted_review_count))
      || Number(row.deleted_review_count) < Number(target.seed_count)
      || Number(row.deleted_review_count) > MAX_REVIEWS
      || !crypto.timingSafeEqual(row.seed_sha256, target.seed_sha256)
      || !crypto.timingSafeEqual(row.receipt_sha256, expected)) {
    throw failure('REVIEW_CLEANUP_MISMATCH', 'review cleanup operation does not match');
  }
  await verifySellerLessons(client, scope, target, { cleaned: true, deletedCount: Number(row.deleted_review_count) });
  return row;
}

/**
 * Internal persistence primitive. All authority callbacks must derive
 * authorization from trusted launch/reset state; stored copied IDs alone are
 * never online authority or an effect receipt.
 */
function createSecureShopBoundReviewRepository(pool, dependencies = {}) {
  if (!pool || typeof pool.query !== 'function' || typeof pool.connect !== 'function') {
    throw failure('INVALID_CONFIGURATION', 'PostgreSQL pool is required');
  }
  const auditStore = dependencies.auditStore;
  if (auditStore && typeof auditStore.append !== 'function') throw failure('INVALID_CONFIGURATION', 'audit dependency invalid');
  const checkCurrent = dependencies.checkCurrent;
  const checkRetirement = dependencies.checkRetirement;
  const checkCleanup = dependencies.checkCleanup;
  const enableLearnerSubmissions = dependencies.enableLearnerSubmissions === true;
  if (typeof checkCurrent !== 'function' || typeof checkRetirement !== 'function'
      || typeof checkCleanup !== 'function') {
    throw failure('INVALID_CONFIGURATION', 'review authority checks are invalid');
  }

  async function online(scope, work, { repeatable = false, lockTarget = false } = {}) {
    return reviewScene.withLease(scope, () => withTransaction(pool, async client => {
      if (repeatable) await client.query('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ');
      // Writers that lock the target take UPDATE before the grant's SHARE
      // lock, so concurrent seed/submission admission cannot upgrade in a cycle.
      if (lockTarget) await requireTarget(client, scope, 'FOR UPDATE');
      await reviewScene.assertGrant(client, scope);
      const value = await work(client);
      await reviewScene.assertGrant(client, scope);
      await checkCurrent(reviewScene.current(scope));
      return value;
    }));
  }
  async function moderation(scope, capability, persona) {
    if (!reviewScene.productScene(scope) && capability === undefined) return null;
    return moderationBinding.read(capability, scope, persona);
  }
  function sellerOnline(seller, scope, work, { publicRead = false, ...options } = {}) {
    const guarded = async client => {
      if (!seller && !publicRead) {
        // A copied target cannot claim the explicit historical fixture path.
        const mapped = (await client.query(`SELECT EXISTS(SELECT 1
          FROM secureshop_review.scene_review_targets WHERE review_target_id=$1) AS scene_bound`,
        [scope.targetId])).rows[0]?.scene_bound;
        if (mapped !== false) throw failure('SHOP_AUTH_INVALID', 'Trusted seller scene required');
      }
      return work(client);
    };
    return seller ? seller.fence.withCrossStoreEffect(() => online(scope, guarded, options))
      : online(scope, guarded, options);
  }
  function owned(alias, productParam, actorParam) {
    return `EXISTS (SELECT 1 FROM secureshop_review.product_target_products owned_product
      WHERE owned_product.target_id=$${productParam}
        AND owned_product.product_id=${alias}.product_id
        AND owned_product.retailer_id=$${actorParam})`;
  }
  async function mappedSceneTarget(client, scene) {
    let row = (await client.query(`SELECT r.* FROM secureshop_review.scene_review_targets m
      JOIN secureshop_review.review_targets r ON r.target_id=m.review_target_id
      WHERE m.scene_id=$1 AND m.product_target_id=$2
        AND m.original_platform_owner_id=$3 AND r.lifecycle='active'
      FOR SHARE OF r`, [scene.scene.sceneId, scene.targetId, scene.platformOwnerId])).rows[0];
    if (row) return row;
    // Earlier installations placed review and product targets in one launch.
    // Adopt that exact birth target before allocating a new review session.
    row = (await client.query(`SELECT r.* FROM secureshop_review.review_targets r
      JOIN secureshop_review.product_targets p ON p.target_id=$1
      WHERE (r.launch_id,r.scenario_id,r.generation,r.original_platform_owner_id,
        r.original_platform_session_id)
       =(p.launch_id,p.scenario_id,p.generation,p.original_platform_owner_id,
        p.original_platform_session_id)
        AND r.lifecycle='active' AND p.lifecycle='active'
      FOR SHARE OF r,p`, [scene.targetId])).rows[0];
    if (!row) return null;
    await client.query('SELECT secureshop_review.bind_scene_review_target($1,$2,$3,$4)',
      [scene.scene.sceneId, scene.targetId, row.target_id, scene.scene.grantId]);
    return row;
  }
  async function readSceneTarget(scene) {
    if (!scene?.scene) throw failure('REVIEW_TARGET_UNAVAILABLE', 'Product scene required');
    return withSceneLease(scene, () => withTransaction(pool, async client => {
      await assertSceneGrant(client, scene);
      const row = await mappedSceneTarget(client, scene);
      await assertSceneGrant(client, scene);
      await checkCurrent(executionScope(scene));
      if (!row) return null;
      return reviewScene.attach({ targetId: row.target_id, launchId: row.launch_id,
        scenarioId: row.scenario_id, generation: Number(row.generation),
        platformOwnerId: Number(row.original_platform_owner_id),
        platformSessionId: Number(row.original_platform_session_id) }, scene);
    }));
  }
  async function adoptSellerLessons(inputScope) {
    const scope = normalizeScope(inputScope);
    const scene = reviewScene.productScene(scope);
    if (!scene) return Object.freeze({ status: 'legacy_target' });
    return online(scope, async client => {
      const target = await requireTarget(client, scope);
      const status = (await client.query(
        'SELECT secureshop_review.adopt_seller_review_lessons($1,$2) AS status',
        [scope.targetId, scene.scene.grantId])).rows[0]?.status;
      if (!['adopted','replayed','custom_profile','owned_products_unavailable','capacity_unavailable'].includes(status))
        throw failure('REVIEW_TARGET_PARTIAL', 'Seller lesson adoption unavailable');
      await verifySellerLessons(client, scope, target);
      return Object.freeze({ status });
    }, { lockTarget: true });
  }
  async function bindSceneTarget(scene, inputScope) {
    const birth = normalizeScope(inputScope);
    if (!scene?.scene || birth.platformOwnerId !== scene.platformOwnerId)
      throw failure('REVIEW_TARGET_UNAVAILABLE', 'Scene owner mismatch');
    return withSceneLease(scene, () => withTransaction(pool, async client => {
      await assertSceneGrant(client, scene);
      await requireTarget(client, birth, 'FOR SHARE');
      await client.query('SELECT secureshop_review.bind_scene_review_target($1,$2,$3,$4)',
        [scene.scene.sceneId, scene.targetId, birth.targetId, scene.scene.grantId]);
      await assertSceneGrant(client, scene);
      await checkCurrent(executionScope(scene));
      return reviewScene.attach(birth, scene);
    }));
  }
  async function provisionScene(scene, inputScope,
      { reviews = [], compatibleReviews = [], effectTimeoutMs } = {}) {
    validateEffectDeadline(effectTimeoutMs);
    const birth = normalizeScope(inputScope);
    const execution = executionScope(scene);
    if (!scene?.scene || birth.platformOwnerId !== scene.platformOwnerId
        || ['launchId','scenarioId','generation','platformOwnerId','platformSessionId']
          .some(key => birth[key] !== execution[key])) {
      throw failure('REVIEW_TARGET_UNAVAILABLE', 'Review reservation is not current scene execution');
    }
    const profiles = normalizeProvisionProfiles(reviews, compatibleReviews);
    const fixtures = profiles[0];
    await checkCurrent(execution);
    return withSceneLease(scene, () => withTransaction(pool, async client => {
      await setEffectDeadline(client, effectTimeoutMs);
      await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1,0))',
        [`secureshop-scene-review:${scene.scene.sceneId}`]);
      await assertSceneGrant(client, scene);
      const mapped = await mappedSceneTarget(client, scene);
      if (mapped) {
        await checkCurrent(execution);
        return reviewScene.attach({ targetId: mapped.target_id, launchId: mapped.launch_id,
          scenarioId: mapped.scenario_id, generation: Number(mapped.generation),
          platformOwnerId: Number(mapped.original_platform_owner_id),
          platformSessionId: Number(mapped.original_platform_session_id) }, scene);
      }
      const inserted = await client.query(`INSERT INTO secureshop_review.review_targets
        (target_id,launch_id,scenario_id,generation,original_platform_owner_id,
         original_platform_session_id,seed_count,seed_sha256)
        VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT(target_id) DO NOTHING`,
      [...scopeValues(birth), fixtures.normalized.length, fixtures.digest]);
      const target = await requireTarget(client, birth, 'FOR UPDATE');
      const matched = Buffer.isBuffer(target.seed_sha256) && target.seed_sha256.length === 32
        ? profiles.find(profile => Number(target.seed_count) === profile.normalized.length
          && crypto.timingSafeEqual(target.seed_sha256, profile.digest)) : null;
      if (!matched) throw failure('REVIEW_TARGET_MISMATCH', 'review target fixtures do not match');
      if (inserted.rowCount === 1) {
        for (const review of fixtures.normalized) {
          await client.query(`INSERT INTO secureshop_review.reviews
            (target_id,product_id,author_id,body,rating)
            VALUES($1,$2,$3,$4,$5)`, [birth.targetId, review.productId, review.authorId,
            review.body, review.rating]);
        }
      } else {
        const count = (await client.query("SELECT count(*)::integer AS count FROM secureshop_review.reviews WHERE target_id=$1 AND source_kind='fixture'",
        [birth.targetId])).rows[0].count;
        if (count !== matched.normalized.length) throw failure('REVIEW_TARGET_PARTIAL', 'review target is incomplete');
      }
      await client.query('SELECT secureshop_review.bind_scene_review_target($1,$2,$3,$4)',
        [scene.scene.sceneId, scene.targetId, birth.targetId, scene.scene.grantId]);
      await assertSceneGrant(client, scene);
      await checkCurrent(execution);
      return reviewScene.attach(birth, scene);
    }));
  }

  return Object.freeze({
    readSceneTarget,
    adoptSellerLessons, bindSceneTarget, provisionScene,
    async provision(inputScope, { reviews = [], compatibleReviews = [], effectTimeoutMs } = {}) {
      validateEffectDeadline(effectTimeoutMs);
      const scope = normalizeScope(inputScope);
      const profiles = normalizeProvisionProfiles(reviews, compatibleReviews);
      const fixtures = profiles[0];
      await checkCurrent(scope);
      return withTransaction(pool, async client => {
        await setEffectDeadline(client, effectTimeoutMs);
        const inserted = await client.query(`INSERT INTO secureshop_review.review_targets
          (target_id,launch_id,scenario_id,generation,original_platform_owner_id,
           original_platform_session_id,seed_count,seed_sha256)
          VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT(target_id) DO NOTHING`,
        [...scopeValues(scope), fixtures.normalized.length, fixtures.digest]);
        const target = await requireTarget(client, scope, 'FOR UPDATE');
        const matched = Buffer.isBuffer(target.seed_sha256) && target.seed_sha256.length === 32
          ? profiles.find(profile => Number(target.seed_count) === profile.normalized.length
            && crypto.timingSafeEqual(target.seed_sha256, profile.digest))
          : null;
        if (!matched) {
          throw failure('REVIEW_TARGET_MISMATCH', 'review target fixtures do not match');
        }
        if (inserted.rowCount === 1) {
          for (const review of fixtures.normalized) {
            await client.query(`INSERT INTO secureshop_review.reviews
              (target_id,product_id,author_id,body,rating)
              VALUES($1,$2,$3,$4,$5)`, [scope.targetId, review.productId, review.authorId, review.body, review.rating]);
          }
        } else {
          const count = (await client.query(enableLearnerSubmissions
            ? "SELECT count(*)::integer AS count FROM secureshop_review.reviews WHERE target_id=$1 AND source_kind='fixture'"
            : 'SELECT count(*)::integer AS count FROM secureshop_review.reviews WHERE target_id=$1', [scope.targetId])).rows[0].count;
          if (count !== matched.normalized.length) throw failure('REVIEW_TARGET_PARTIAL', 'review target is incomplete');
        }
        await checkCurrent(scope);
        return publicBinding(scope, matched.normalized.length);
      });
    },

    async submitReview(inputScope, inputPersona, input, { effectTimeoutMs } = {}) {
      validateEffectDeadline(effectTimeoutMs);
      if (!enableLearnerSubmissions) {
        throw failure('REVIEW_SUBMISSIONS_UNAVAILABLE', 'learner review submissions are unavailable');
      }
      const scope = normalizeScope(inputScope);
      const persona = normalizePersona(inputPersona);
      const submission = normalizeSubmission(input);
      const digests = submissionDigests(scope, persona, submission);
      await checkCurrent(reviewScene.current(scope));
      return online(scope, async client => {
        await setEffectDeadline(client, effectTimeoutMs);
        await requireTarget(client, scope, 'FOR UPDATE');
        const existing = (await client.query(`SELECT * FROM secureshop_review.reviews
          WHERE target_id=$1 AND submission_id=$2`, [scope.targetId, submission.submissionId])).rows[0];
        if (existing) {
          const stored = verifySubmissionRow(scope, existing);
          const exact = stored.persona.id === persona.id && stored.persona.role === persona.role
            && stored.submission.productId === submission.productId
            && stored.submission.authorId === submission.authorId
            && stored.submission.body === submission.body && stored.submission.rating === submission.rating
            && crypto.timingSafeEqual(existing.body_sha256, digests.bodySha256)
            && crypto.timingSafeEqual(existing.request_sha256, digests.requestSha256);
          if (!exact) throw failure('REVIEW_SUBMISSION_CONFLICT', 'submission id was already used');
          await checkCurrent(reviewScene.current(scope));
          return privateSubmission(scope, existing, false);
        }
        const count = Number((await client.query(
          'SELECT count(*)::integer AS count FROM secureshop_review.reviews WHERE target_id=$1',
          [scope.targetId]
        )).rows[0].count);
        if (!Number.isSafeInteger(count) || count < 0 || count >= MAX_REVIEWS) {
          throw failure('REVIEW_CAPACITY', 'review target capacity is exhausted');
        }
        const row = (await client.query(`INSERT INTO secureshop_review.reviews
          (target_id,product_id,author_id,body,rating,source_kind,source_version,submission_id,
           request_sha256,body_sha256,submitted_by_shop_user_id,submitted_by_shop_role)
          VALUES($1,$2,$3,$4,$5,'learner',1,$6,$7,$8,$9,$10) RETURNING *`,
        [scope.targetId, submission.productId, submission.authorId, submission.body, submission.rating,
          submission.submissionId, digests.requestSha256, digests.bodySha256, persona.id, persona.role])).rows[0];
        verifySubmissionRow(scope, row);
        if (auditStore) await auditStore.append(client, { eventId: crypto.randomUUID(), scope: reviewScene.current(scope), persona,
          actor: persona.role, action: 'review_submit', target: String(row.id),
          paramsJson: JSON.stringify({ productId: submission.productId, authorId: submission.authorId,
            body: submission.body, rating: submission.rating, submissionId: submission.submissionId }),
          outcome: 'completed', sourceKind: 'review', sourceId: String(row.id) });
        await checkCurrent(reviewScene.current(scope));
        return privateSubmission(scope, row, true);
      });
    },

    async captureReviewAdmissionTime(inputScope) {
      const scope = require('../../services/secureshopConversationBinding').createLaunchScope(inputScope);
      await checkCurrent(reviewScene.current(scope));
      const row = (await pool.query("SELECT floor(extract(epoch FROM clock_timestamp()) * 1000000)::text AS admitted_at_micros")).rows[0];
      await checkCurrent(reviewScene.current(scope));
      if (typeof row?.admitted_at_micros !== 'string' || !/^[1-9]\d{0,23}$/.test(row.admitted_at_micros)) {
        throw failure('REVIEW_ADMISSION_TIME_UNAVAILABLE', 'Authoritative review admission time unavailable');
      }
      return row.admitted_at_micros;
    },

    async readSubmission(inputScope, reviewId) {
      if (!enableLearnerSubmissions) {
        throw failure('REVIEW_SUBMISSIONS_UNAVAILABLE', 'learner review submissions are unavailable');
      }
      const scope = normalizeScope(inputScope);
      const id = positiveId(reviewId, 'reviewId');
      await checkCurrent(reviewScene.current(scope));
      return online(scope, async client => {
        await requireTarget(client, scope);
        const row = (await client.query(`SELECT *, floor(extract(epoch FROM created_at) * 1000000)::text AS created_at_micros FROM secureshop_review.reviews
          WHERE target_id=$1 AND id=$2`, [scope.targetId, id])).rows[0];
        if (!row || row.source_kind !== 'learner') {
          await checkCurrent(reviewScene.current(scope));
          return null;
        }
        verifySubmissionRow(scope, row);
        if (typeof row.created_at_micros !== 'string' || !/^[1-9]\d{0,23}$/.test(row.created_at_micros)) {
          throw failure('REVIEW_SUBMISSION_MISMATCH', 'Authoritative source creation time unavailable');
        }
        await checkCurrent(reviewScene.current(scope));
        return privateSubmission(scope, row, false);
      });
    },

    async listPending(inputScope, { limit = 20, moderation: capability } = {}) {
      const scope = normalizeScope(inputScope);
      const count = boundedLimit(limit);
      const seller = await moderation(scope, capability);
      await checkCurrent(reviewScene.current(scope));
      const rows = await sellerOnline(seller, scope, async client => {
        await requireTarget(client, scope);
        const result = await client.query(`SELECT * FROM secureshop_review.reviews
          WHERE target_id=$1 AND status='pending'
            ${seller ? 'AND ' + owned('reviews', 3, 4) : ''}
          ORDER BY id ASC LIMIT $2`, [scope.targetId, count, ...(seller ? [seller.scene.targetId, seller.actorId] : [])]);
        await checkCurrent(reviewScene.current(scope));
        return result.rows;
      });
      return rows.map(publicReview);
    },

    async listReviews(inputScope, options = {}, { moderation: capability } = {}) {
      const scope = normalizeScope(inputScope);
      const filters = normalizeListOptions(options);
      const seller = capability === undefined ? null : await moderation(scope, capability);
      await checkCurrent(reviewScene.current(scope));
      return sellerOnline(seller, scope, async client => {
        // Page rows, filtered total and tab counts describe one moderation
        // snapshot even when another bound turn decides a review concurrently.
        await requireTarget(client, scope);
        const params = [scope.targetId, filters.status, filters.productId,
          filters.minRating, filters.maxRating, filters.limit, filters.offset,
          ...(seller ? [seller.scene.targetId, seller.actorId] : [])];
        const where = `reviews.target_id=$1
          AND ($2::text IS NULL OR reviews.status=$2)
          AND ($3::integer IS NULL OR reviews.product_id=$3)
          AND ($4::integer IS NULL OR reviews.rating >= $4)
          AND ($5::integer IS NULL OR reviews.rating <= $5)
          ${seller ? 'AND ' + owned('reviews', 8, 9) : ''}`;
        const rows = (await client.query(`SELECT reviews.*, p.name AS product_name
          FROM secureshop_review.reviews reviews
          LEFT JOIN secureshop_review.scene_review_targets mapping
            ON mapping.review_target_id=reviews.target_id
          LEFT JOIN secureshop_review.product_target_products p
            ON p.target_id=mapping.product_target_id AND p.product_id=reviews.product_id
          WHERE ${where}
          ORDER BY reviews.created_at DESC,reviews.id DESC LIMIT $6 OFFSET $7`, params)).rows;
        const statusRows = (await client.query(`SELECT reviews.status,count(*)::integer AS count
          FROM secureshop_review.reviews reviews WHERE reviews.target_id=$1
            ${seller ? 'AND ' + owned('reviews', 2, 3) : ''}
          GROUP BY reviews.status`, [scope.targetId, ...(seller ? [seller.scene.targetId, seller.actorId] : [])])).rows;
        const total = Number((await client.query(`SELECT count(*)::integer AS count
          FROM secureshop_review.reviews reviews WHERE ${where.replace(/\$8/g, '$6').replace(/\$9/g, '$7')}`,
        [...params.slice(0, 5), ...(seller ? [seller.scene.targetId, seller.actorId] : [])])).rows[0]?.count ?? 0);
        await checkCurrent(reviewScene.current(scope));
        const counts = { pending: 0, approved: 0, rejected: 0 };
        for (const row of statusRows) {
          if (Object.hasOwn(counts, row.status)) counts[row.status] = Number(row.count);
        }
        return Object.freeze({ rows: Object.freeze(rows.map(publicReviewListRow)), total,
          counts: Object.freeze(counts) });
      }, { repeatable: true, publicRead: capability === undefined });
    },

    async getReview(inputScope, reviewId, { moderation: capability } = {}) {
      const scope = normalizeScope(inputScope);
      const id = positiveId(reviewId, 'reviewId');
      const seller = await moderation(scope, capability);
      await checkCurrent(reviewScene.current(scope));
      return sellerOnline(seller, scope, async client => {
        await requireTarget(client, scope);
        const row = (await client.query(`SELECT * FROM secureshop_review.reviews WHERE target_id=$1 AND id=$2
          ${seller ? 'AND ' + owned('reviews', 3, 4) : ''}`,
        [scope.targetId, id, ...(seller ? [seller.scene.targetId, seller.actorId] : [])])).rows[0];
        await checkCurrent(reviewScene.current(scope));
        return row ? publicReview(row) : null;
      });
    },

    async decide(inputScope, { reviewId, decision, notes = null, moderatorKind = 'auto', auditPersona, effectTimeoutMs, operation, expectedSnapshotSha256, moderation: capability } = {}) {
      const scope = normalizeScope(inputScope);
      const id = positiveId(reviewId, 'reviewId');
      const status = normalizeDecision(decision);
      const kind = moderatorKind === 'auto' || moderatorKind === 'manual' ? moderatorKind : null;
      if (!kind) throw failure('INVALID_ARGUMENT', 'moderatorKind is invalid');
      const normalizedNotes = notes === null ? null : boundedText(notes, 'moderator notes', MAX_NOTES_BYTES, { empty: true });
      const seller = await moderation(scope, capability, auditPersona);
      const initiator = auditStore ? normalizePersona(auditPersona) : null;
      const receipts = require('./secureshopReviewDecisionReceipt');
      const requested = operation === undefined ? null : receipts.request(scope,{reviewId:id,decision:status,notes:normalizedNotes,moderatorKind:kind,auditPersona:initiator,...(expectedSnapshotSha256===undefined?{}:{expectedSnapshotSha256})},operation);
      if(expectedSnapshotSha256!==undefined&&!requested)throw failure('INVALID_ARGUMENT','Snapshot requires a decision operation');
      if (requested && !auditStore) throw failure('INVALID_CONFIGURATION','Decision receipt audit required');
      if (effectTimeoutMs !== undefined && (!Number.isSafeInteger(effectTimeoutMs) || effectTimeoutMs < 100 || effectTimeoutMs > 10000)) throw failure('INVALID_ARGUMENT','Invalid review effect deadline');
      await checkCurrent(reviewScene.current(scope));
      return sellerOnline(seller, scope, async client => {
        if (effectTimeoutMs !== undefined) {
          await client.query("SELECT set_config('statement_timeout',$1,true),set_config('lock_timeout',$1,true)",[String(effectTimeoutMs)]);
        }
        await requireTarget(client, scope);
        if (requested) {
          await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1,0))',['review-decision-operation:'+requested.operationId]);
        }
        const current = (await client.query(`SELECT * FROM secureshop_review.reviews
          WHERE target_id=$1 AND id=$2 ${seller ? 'AND ' + owned('reviews', 3, 4) : ''} FOR UPDATE`,
        [scope.targetId, id, ...(seller ? [seller.scene.targetId, seller.actorId] : [])])).rows[0];
        if (!current) throw failure('REVIEW_NOT_FOUND', 'review is unavailable');
        if (requested) {
          const prior=await receipts.find(client,reviewScene.current(scope),requested.operationId,initiator);
          if(prior){if(prior.requestSha256!==requested.sha256)receipts.fail();await checkCurrent(reviewScene.current(scope));return Object.freeze({...prior.result,receipt:prior.receipt,replayed:true});}
        }
        const record=async result=>{
          if(!requested)return Object.freeze(result);
          const packet=receipts.packet(requested,result);
          await auditStore.append(client,{eventId:requested.operationId,scope:reviewScene.current(scope),persona:initiator,actor:kind==='auto'?'review_moderator':initiator.role,action:'review_decide_operation',target:String(id),paramsJson:JSON.stringify(packet),outcome:'completed',sourceKind:'review_decision_operation',sourceId:String(id)});
          return Object.freeze({...result,receipt:packet.receipt,replayed:false});
        };
        if(expectedSnapshotSha256!==undefined&&require('../../services/secureshopReviewSnapshot').reviewSnapshotSha256(publicReview(current))!==expectedSnapshotSha256){
          await checkCurrent(reviewScene.current(scope));
          return record({applied:false,code:'REVIEW_STALE',review:publicReview(current)});
        }
        if (current.status !== 'pending') {
          await checkCurrent(reviewScene.current(scope));
          return record({ applied: false, code: 'REVIEW_NOT_PENDING', review: publicReview(current) });
        }
        const row = (await client.query(`UPDATE secureshop_review.reviews
          SET status=$3,moderator_kind=$4,moderator_notes=$5,moderated_at=clock_timestamp()
          WHERE target_id=$1 AND id=$2 AND status='pending'
            ${seller ? 'AND ' + owned('reviews', 6, 7) : ''} RETURNING *`,
        [scope.targetId, id, status, kind, normalizedNotes, ...(seller ? [seller.scene.targetId, seller.actorId] : [])])).rows[0];
        if (auditStore) await auditStore.append(client, { eventId: crypto.randomUUID(), scope: reviewScene.current(scope), persona: initiator,
          actor: kind === 'auto' ? 'review_moderator' : initiator.role,
          action: 'review_decide', target: String(id), paramsJson: JSON.stringify({ decision: status,
            moderatorKind: kind, notes: normalizedNotes }), outcome: 'completed', sourceKind: 'review', sourceId: String(id) });
        await checkCurrent(reviewScene.current(scope));
        return record({ applied: true, review: publicReview(row) });
      });
    },

    async readDecisionReceipt(inputScope,{operationId,auditPersona}={}) {
      const scope=normalizeScope(inputScope),id=uuid(operationId,'operationId'),persona=normalizePersona(auditPersona);
      await checkCurrent(reviewScene.current(scope));
      return online(scope,async client=>{await requireTarget(client,scope);const value=await require('./secureshopReviewDecisionReceipt').find(client,reviewScene.current(scope),id,persona);await checkCurrent(reviewScene.current(scope));return value?.receipt??null;});
    },

    async retire(inputScope) {
      const scope = normalizeScope(inputScope);
      await checkRetirement(scope);
      return withTransaction(pool, async client => {
        const row = (await client.query(`SELECT lifecycle FROM secureshop_review.review_targets
          WHERE ${TARGET_WHERE} FOR UPDATE`, scopeValues(scope))).rows[0];
        if (!row) throw failure('REVIEW_TARGET_UNAVAILABLE', 'review target is unavailable');
        if (row.lifecycle === 'retired') return false;
        await client.query(`UPDATE secureshop_review.review_targets
          SET lifecycle='retired',retired_at=clock_timestamp() WHERE target_id=$1`, [scope.targetId]);
        return true;
      });
    },

    async readCleanupReceipt(inputScope, { operationId } = {}) {
      const scope = normalizeScope(inputScope);
      const operation = uuid(operationId, 'operationId');
      const authority = Object.freeze({ ...scope, operationId: operation });
      await checkCleanup(authority);
      return withTransaction(pool, async client => {
        const target = (await client.query(`SELECT lifecycle,seed_count,seed_sha256
          FROM secureshop_review.review_targets WHERE ${TARGET_WHERE} FOR SHARE`, scopeValues(scope))).rows[0];
        if (!target) throw failure('REVIEW_TARGET_UNAVAILABLE', 'review target is unavailable');
        const row = await readVerifiedCleanupReceipt(client, scope, operation, target);
        if (!row) throw failure('REVIEW_CLEANUP_RECEIPT_UNAVAILABLE', 'review cleanup receipt is unavailable');
        await checkCleanup(authority);
        return publicCleanupReceipt(row);
      });
    },

    /**
     * Deletes raw target rows and records one durable target-side receipt.
     * The caller's cleanup authority is separate from online launch authority.
     * This does not resolve the identity reservation or complete a reset.
     */
    async cleanup(inputScope, { operationId } = {}) {
      const scope = normalizeScope(inputScope);
      const operation = uuid(operationId, 'operationId');
      const authority = Object.freeze({ ...scope, operationId: operation });
      await checkCleanup(authority);
      return withTransaction(pool, async client => {
        const target = (await client.query(`SELECT lifecycle,seed_count,seed_sha256
          FROM secureshop_review.review_targets WHERE ${TARGET_WHERE} FOR UPDATE`, scopeValues(scope))).rows[0];
        if (!target) throw failure('REVIEW_TARGET_UNAVAILABLE', 'review target is unavailable');

        const existing = await readVerifiedCleanupReceipt(client, scope, operation, target);
        if (existing) {
          await checkCleanup(authority);
          return publicCleanupReceipt(existing);
        }

        const lessonCount = await verifySellerLessons(client, scope, target);
        const seedCount = Number(target.seed_count);
        const count = Number((await client.query(
          'SELECT count(*)::integer AS count FROM secureshop_review.reviews WHERE target_id=$1',
          [scope.targetId]
        )).rows[0].count);
        if (!Number.isSafeInteger(count) || count < seedCount + lessonCount || count > MAX_REVIEWS
            || !Buffer.isBuffer(target.seed_sha256) || target.seed_sha256.length !== 32) {
          throw failure('REVIEW_TARGET_PARTIAL', 'review target cannot produce a complete cleanup receipt');
        }
        if (target.lifecycle === 'active') {
          await client.query(`UPDATE secureshop_review.review_targets
            SET lifecycle='retired',retired_at=clock_timestamp() WHERE target_id=$1`, [scope.targetId]);
        } else if (target.lifecycle !== 'retired') {
          throw failure('REVIEW_TARGET_UNAVAILABLE', 'review target is unavailable');
        }
        const removed = await client.query('DELETE FROM secureshop_review.reviews WHERE target_id=$1', [scope.targetId]);
        if (removed.rowCount !== count) throw failure('REVIEW_CLEANUP_INCOMPLETE', 'review cleanup is incomplete');
        const receiptSha = receiptDigest(scope, operation, removed.rowCount, seedCount, target.seed_sha256);
        const row = (await client.query(`INSERT INTO secureshop_review.review_cleanup_receipts
          (operation_id,target_id,launch_id,scenario_id,generation,original_platform_owner_id,
           original_platform_session_id,deleted_review_count,seed_count,seed_sha256,receipt_sha256)
          VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) RETURNING *`,
        [operation, ...scopeValues(scope), removed.rowCount, seedCount, target.seed_sha256, receiptSha])).rows[0];
        await checkCleanup(authority);
        return publicCleanupReceipt(row);
      });
    },
  });
}

module.exports = { createSecureShopBoundReviewRepository };
