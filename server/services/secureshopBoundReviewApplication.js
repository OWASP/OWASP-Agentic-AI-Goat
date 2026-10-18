'use strict';

const { createLaunchScope, createConversationBinding } = require('./secureshopConversationBinding');
const { createSecureShopManualReviewActions } = require('./secureshopBoundReviewTools');
const { executionScope } = require('./secureshopSceneBinding');
const moderationBinding = require('./secureshopReviewModerationBinding');
const reviewScene = require('./secureshopReviewSceneBinding');

const MAX_FIXTURES = 256;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
function invalid(message) { return Object.assign(new TypeError(message), { code: 'INVALID_CONFIGURATION' }); }
function positive(value, label) {
  if (!Number.isSafeInteger(value) || value < 1 || value > 2147483647) {
    throw Object.assign(new TypeError(`${label} is invalid`), { code: 'INVALID_ARGUMENT' });
  }
  return value;
}
function plain(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    && Object.getPrototypeOf(value) === Object.prototype;
}
function requireKeys(value, keys, optional = []) {
  const allowed = new Set([...keys, ...optional]);
  if (!plain(value) || Object.keys(value).some(key => !allowed.has(key))
    || !keys.every(key => Object.hasOwn(value, key))) {
    throw Object.assign(new TypeError('Bound review request is invalid'), { code: 'INVALID_ARGUMENT' });
  }
  return value;
}
function snapshotFixtures(input) {
  if (!Array.isArray(input) || input.length > MAX_FIXTURES || Object.keys(input).length !== input.length) {
    throw invalid('Bound review fixtures are invalid');
  }
  return Object.freeze(input.map(item => {
    if (!plain(item) || Object.keys(item).sort().join(',') !== 'authorId,body,productId,rating'
      || !Number.isSafeInteger(item.productId) || item.productId < 1 || item.productId > 2147483647
      || !Number.isSafeInteger(item.authorId) || item.authorId < 1 || item.authorId > 2147483647
      || typeof item.body !== 'string' || Buffer.byteLength(item.body, 'utf8') > 65536
      || !Number.isSafeInteger(item.rating) || item.rating < 1 || item.rating > 5) {
      throw invalid('Bound review fixture is invalid');
    }
    return Object.freeze({ productId: item.productId, authorId: item.authorId,
      body: item.body, rating: item.rating });
  }));
}
function snapshotFixtureProfiles(input) {
  if (!Array.isArray(input) || input.length > 16 || Object.keys(input).length !== input.length) {
    throw invalid('Bound review compatible fixture profiles are invalid');
  }
  return Object.freeze(input.map(snapshotFixtures));
}
function publicRow(row) {
  return Object.freeze({ id: row.id, product_id: row.product_id, author_id: row.author_id,
    body: row.body, rating: row.rating, status: row.status,
    moderator_kind: row.moderator_kind ?? null, moderator_notes: row.moderator_notes ?? null,
    created_at: row.created_at, moderated_at: row.moderated_at ?? null });
}

// Application dependency for the selective HTTP router. The fixture set is a
// server configuration snapshot; requests cannot choose or replace it.
function createSecureShopBoundReviewApplication({ launches, repository, checkCurrent, validateProduct,
  fixtures = [], compatibleFixtures = [], personaAuthority, resolveProductScene,
  withProvisionLease, mirrorReviewScene } = {}) {
  if (typeof launches?.reserveReviewsTarget !== 'function'
    || ['provision', 'listReviews', 'listPending', 'submitReview', 'decide']
      .some(name => typeof repository?.[name] !== 'function')
    || typeof checkCurrent !== 'function') {
    throw invalid('Bound review application dependencies are invalid');
  }
  const configuredFixtures = snapshotFixtures(fixtures);
  const configuredCompatibleFixtures = snapshotFixtureProfiles(compatibleFixtures);
  if (validateProduct !== undefined && typeof validateProduct !== 'function') {
    throw invalid('Bound product validation is invalid');
  }
  if (personaAuthority !== undefined && typeof personaAuthority?.capture !== 'function') {
    throw invalid('Bound review persona authority is invalid');
  }
  if (resolveProductScene !== undefined && (typeof resolveProductScene !== 'function'
      || typeof withProvisionLease !== 'function'
      || typeof repository.readSceneTarget !== 'function'
      || typeof repository.provisionScene !== 'function')) {
    throw invalid('Review scene resolver is invalid');
  }
  if (mirrorReviewScene !== undefined && typeof mirrorReviewScene !== 'function')
    throw invalid('Review scene mirror is invalid');

  async function captureAuthority(launch, persona, session) {
    if (!personaAuthority) return undefined;
    if (typeof session?.sessionId !== 'string' || !UUID.test(session.sessionId)
        || typeof session.authorityVersion !== 'string' || !/^[1-9]\d*$/.test(session.authorityVersion)) {
      throw Object.assign(new Error('Review persona authority unavailable'), { code: 'SHOP_AUTH_INVALID' });
    }
    const credential = Object.freeze({ sessionId: session.sessionId.toLowerCase(),
      authorityVersion: session.authorityVersion });
    const fence = await personaAuthority.capture({ scope: launch, personaId: persona.id,
      role: persona.role, ...credential });
    const actual = fence?.binding;
    if (typeof fence?.assertRemoteAdmission !== 'function' || typeof fence?.withCrossStoreEffect !== 'function' || !actual
        || ['launchId','scenarioId','generation','platformOwnerId','platformSessionId']
          .some(key => actual[key] !== launch[key])
        || actual.personaId !== persona.id || actual.role !== persona.role
        || actual.sessionId !== credential.sessionId
        || actual.authorityVersion !== credential.authorityVersion) {
      throw Object.assign(new Error('Review persona authority unavailable'), { code: 'SHOP_AUTH_INVALID' });
    }
    await fence.assertRemoteAdmission();
    return fence;
  }

  async function requireProduct(scope, persona, productId) {
    if (validateProduct && !await validateProduct({ scope, persona, productId })) {
      throw Object.assign(new Error('Product is unavailable'), { code: 'PRODUCT_NOT_FOUND' });
    }
  }

  function binding(input) {
    if (!plain(input) || !plain(input.scope) || !plain(input.persona)) {
      throw Object.assign(new TypeError('Bound review request is invalid'), { code: 'INVALID_ARGUMENT' });
    }
    const launch = createLaunchScope(input.scope);
    const bound = createConversationBinding(launch, input.persona);
    return { launch, persona: Object.freeze({ id: bound.shopUserId, role: bound.role }) };
  }
  async function current(scope) {
    return checkCurrent(createLaunchScope(reviewScene.current(scope)));
  }
  const lessonStatuses = new WeakMap();
  async function adopt(target, fence) {
    if (typeof repository.adoptSellerLessons === 'function' && reviewScene.productScene(target)) {
      const work = () => repository.adoptSellerLessons(target);
      lessonStatuses.set(target, fence ? await fence.withCrossStoreEffect(work) : await work());
    }
    return target;
  }
  async function ensureTarget(scope, fence, request) {
    await fence?.assertRemoteAdmission();
    await current(scope);
    if (resolveProductScene) {
      return withProvisionLease(scope, async () => {
      const scene = await resolveProductScene({ scope, persona: request?.persona,
        personaSession: request?.personaSession });
      if (!scene?.scene || ['launchId','scenarioId','generation','platformOwnerId','platformSessionId']
        .some(key => executionScope(scene)[key] !== scope[key])) {
        throw Object.assign(new Error('Review scene unavailable'), { code: 'REVIEW_TARGET_UNAVAILABLE' });
      }
      const existing = await repository.readSceneTarget(scene);
      if (existing) {
        if (mirrorReviewScene) await mirrorReviewScene(existing);
        return adopt(existing, fence);
      }
      // Reservation locks identity launch rows, so it precedes the scene lease.
      // A concurrent reservation can become cleanup debt; the review-store
      // scene lock below ensures it cannot create a second review target.
      const reservation = await launches.reserveReviewsTarget({ launchId: scope.launchId,
        platformSessionId: scope.platformSessionId, platformOwnerId: scope.platformOwnerId,
        expectedGeneration: scope.generation });
      if (!plain(reservation) || reservation.kind !== 'reviews'
        || reservation.launchId !== scope.launchId || reservation.scenarioId !== scope.scenarioId
        || reservation.generation !== scope.generation || !UUID.test(reservation.targetId)) {
        throw Object.assign(new Error('Review reservation mismatch'), { code: 'REVIEW_TARGET_UNAVAILABLE' });
      }
      const birth = Object.freeze({ targetId: reservation.targetId.toLowerCase(), ...scope });
      const provision = () => repository.provisionScene(scene, birth, { reviews: configuredFixtures,
        compatibleReviews: configuredCompatibleFixtures, ...(fence ? { effectTimeoutMs: 3000 } : {}) });
      const bound = fence ? await fence.withCrossStoreEffect(provision) : await provision();
      await fence?.assertRemoteAdmission();
      if (mirrorReviewScene) await mirrorReviewScene(bound);
      return adopt(bound, fence);
      });
    }
    const reservation = await launches.reserveReviewsTarget({ launchId: scope.launchId,
      platformSessionId: scope.platformSessionId, platformOwnerId: scope.platformOwnerId,
      expectedGeneration: scope.generation });
    if (!plain(reservation) || reservation.kind !== 'reviews'
      || reservation.launchId !== scope.launchId || reservation.scenarioId !== scope.scenarioId
      || reservation.generation !== scope.generation || typeof reservation.targetId !== 'string'
      || !UUID.test(reservation.targetId)) {
      throw Object.assign(new Error('Review reservation does not match launch'), { code: 'REVIEW_TARGET_UNAVAILABLE' });
    }
    // Reservation is in identity: keep its lock order outside the agents lease.
    // A raced denial may leave a durable reservation for lifecycle cleanup.
    await fence?.assertRemoteAdmission();
    const target = Object.freeze({ targetId: reservation.targetId.toLowerCase(), ...scope });
    await current(scope);
    const provision = () => repository.provision(target, { reviews: configuredFixtures,
      compatibleReviews: configuredCompatibleFixtures, ...(fence ? { effectTimeoutMs: 3000 } : {}) });
    if (fence) await fence.withCrossStoreEffect(provision); else await provision();
    await current(scope);
    return target;
  }
  async function prepared(input, requiredRole = null) {
    const trusted = binding(input);
    if (requiredRole && trusted.persona.role !== requiredRole) {
      throw Object.assign(new Error('Shop persona unavailable'), { code: 'OWNER_MISMATCH' });
    }
    const fence = await captureAuthority(trusted.launch, trusted.persona, input.personaSession);
    const target = await ensureTarget(trusted.launch, fence, input);
    await fence?.assertRemoteAdmission();
    return { ...trusted, target, fence };
  }

  function requireRequest(input, values) {
    requireKeys(input, personaAuthority ? [...values, 'personaSession'] : values,
      personaAuthority ? [] : ['personaSession']);
  }

  return Object.freeze({
    async prepareScene(input){
      requireRequest(input,['scope','persona']);
      const {target}=await prepared(input,'merchant');
      return target;
    },
    async listProductReviews(input) {
      requireRequest(input, ['scope', 'persona', 'productId', 'limit', 'offset']);
      const request = Object.freeze({ productId: input.productId, limit: input.limit, offset: input.offset });
      const { target, launch, persona, fence } = await prepared(input);
      const productId = positive(request.productId, 'productId');
      await requireProduct(launch, persona, productId);
      const result = await repository.listReviews(target, { productId,
        limit: request.limit, offset: request.offset });
      await fence?.assertRemoteAdmission();
      await current(target);
      return Object.freeze({ reviews: Object.freeze(result.rows.map(publicRow)), total: result.total });
    },

    async submitReview(input) {
      requireRequest(input, ['scope', 'persona', 'submissionId', 'productId', 'authorId', 'body', 'rating']);
      const request = Object.freeze({ submissionId: input.submissionId, productId: input.productId,
        authorId: input.authorId, body: input.body, rating: input.rating });
      const { target, launch, persona, fence } = await prepared(input);
      await requireProduct(launch, persona, positive(request.productId, 'productId'));
      const submit = () => repository.submitReview(target, persona, request,
        ...(fence ? [{ effectTimeoutMs: 3000 }] : []));
      const result = fence ? await fence.withCrossStoreEffect(submit) : await submit();
      // The lease serializes persona revocation, not distributed database commits.
      // Its uncertainty contract preserves possible separate-store effects.
      await fence?.assertRemoteAdmission();
      await current(target);
      if (!Number.isSafeInteger(result?.reviewId) || result.reviewId < 1) {
        throw new Error('Invalid learner review result');
      }
      return Object.freeze({ id: result.reviewId });
    },

    async listMerchantReviews(input) {
      requireRequest(input, ['scope', 'persona', 'filters']);
      const filters = plain(input.filters) ? Object.freeze({ ...input.filters }) : input.filters;
      const { target, persona, fence } = await prepared(input, 'merchant');
      const moderation = moderationBinding.capture(target, persona, fence);
      const lessonFixture = lessonStatuses.get(target);
      const result = await repository.listReviews(target, filters, { moderation });
      await fence?.assertRemoteAdmission();
      await current(target);
      return Object.freeze({ rows: Object.freeze(result.rows.map(publicRow)), total: result.total,
        ...(lessonFixture ? { lessonFixture } : {}),
        counts: Object.freeze({ pending: result.counts.pending, approved: result.counts.approved,
          rejected: result.counts.rejected }) });
    },

    async approveReview(input) {
      requireRequest(input, ['scope', 'persona', 'reviewId']);
      const reviewId = input.reviewId;
      const { target, launch, persona, fence } = await prepared(input, 'merchant');
      const actions = createSecureShopManualReviewActions({ repository, trustedScope: launch,
        auditPersona: persona, ...(fence ? { personaEffectFence: fence } : {}),
        checkCurrent: current, resolveTarget: async () => target });
      const result = await actions.approve(positive(reviewId, 'reviewId'));
      await fence?.assertRemoteAdmission();
      return Object.freeze({ applied: result.applied });
    },

    async rejectReview(input) {
      requireRequest(input, ['scope', 'persona', 'reviewId', 'reason']);
      const request = Object.freeze({ reviewId: input.reviewId, reason: input.reason });
      const { target, launch, persona, fence } = await prepared(input, 'merchant');
      const actions = createSecureShopManualReviewActions({ repository, trustedScope: launch,
        auditPersona: persona, ...(fence ? { personaEffectFence: fence } : {}),
        checkCurrent: current, resolveTarget: async () => target });
      const result = await actions.reject(positive(request.reviewId, 'reviewId'), request.reason ?? null);
      await fence?.assertRemoteAdmission();
      return Object.freeze({ applied: result.applied });
    },

    // Later bound-runner composition consumes the same resolver so Product,
    // merchant list/manual actions and local model tools cannot drift targets.
    async resolveExistingTarget(inputScope) {
      const scope = createLaunchScope(inputScope);
      if (resolveProductScene) {
        const scene = await resolveProductScene({ scope });
        if (!scene?.scene || ['launchId','scenarioId','generation','platformOwnerId','platformSessionId']
          .some(key => executionScope(scene)[key] !== scope[key])) {
          throw Object.assign(new Error('Review scene unavailable'), { code: 'REVIEW_TARGET_UNAVAILABLE' });
        }
        const existing = await repository.readSceneTarget(scene);
        if (!existing) throw Object.assign(new Error('Existing review target unavailable'),
          { code: 'REVIEW_TARGET_UNAVAILABLE' });
        return existing;
      }
      if (typeof launches.readExistingReviewsTarget !== 'function') throw invalid('Existing review target reader unavailable');
      await current(scope);
      const reservation = await launches.readExistingReviewsTarget(scope);
      if (!reservation || reservation.kind !== 'reviews' || reservation.launchId !== scope.launchId
          || reservation.scenarioId !== scope.scenarioId || reservation.generation !== scope.generation
          || typeof reservation.targetId !== 'string' || !UUID.test(reservation.targetId)) {
        throw Object.assign(new Error('Existing review target unavailable'), { code: 'REVIEW_TARGET_UNAVAILABLE' });
      }
      await current(scope);
      return Object.freeze({ targetId: reservation.targetId.toLowerCase(), ...scope });
    },

    async resolveTarget(inputScope) {
      return ensureTarget(createLaunchScope(inputScope));
    },
  });
}

module.exports = { createSecureShopBoundReviewApplication };
