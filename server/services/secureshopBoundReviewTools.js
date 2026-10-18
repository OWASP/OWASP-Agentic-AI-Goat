'use strict';

/**
 * Launch-bound local review tools for the real merchant supervisor graph.
 *
 * Vulnerable mode deliberately returns raw review bodies verbatim as the LLM01
 * indirect prompt-injection teaching sink. Authority is captured outside model args.
 * These closures neither classify content nor manufacture model provenance;
 * the supervisor's model_decision trace is the provenance for selected args.
 *
 * @intentional-vulnerability llm01-indirect-pi-review
 * @teaches OWASP-LLM:LLM01
 * @location server/services/secureshopBoundReviewTools.js
 */

const reviewScene = require('./secureshopReviewSceneBinding');
const moderationBinding = require('./secureshopReviewModerationBinding');
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const AUTHORITY_ERRORS = new Set(['STALE_LAUNCH', 'LAUNCH_UNAVAILABLE', 'REVIEW_TARGET_UNAVAILABLE', 'SHOP_AUTH_INVALID', 'PERSONA_EFFECT_OUTCOME_UNCERTAIN', 'REVIEW_OPERATION_CONFLICT', 'SECURESHOP_FEATURE_MODE_STALE']);
const { assertBoundReviewBatchAuthority } = require('./secureshopBoundReviewBatchAuthority');
const FIXED_REVIEW_BODY = '[Review text withheld from the agent in fixed mode]';

// This is deliberately a bounded policy for the teaching corpus, not a claim
// to understand arbitrary sentiment. Unclassified rows remain for a person.
function classifyFixedReview(body) {
  const text = body.normalize('NFKC').slice(0, 8192)
    .split(/\b(?:system|assistant|developer)\s*:|\bignore (?:previous|all) instructions\b/i)[0].toLowerCase();
  if (!text.trim() || body.length > 8192) return null;
  if (/\bunrelated promotional advertising\b|\bspam viagra\b/i.test(text)) return 'reject';
  const promotion = /\b(?:advertis(?:e|ement|ing)|promot(?:e|ion|ional)|spam|viagra|coupon|subscribe|buy now|visit (?:my|our)|unrelated (?:service|site|product))\b|https?:\/\//i.test(text);
  const feedback = /\b(?:product|item|quality|fit|size|delivery|shipping|arrived|broke|works?|worked|useful|defective|durable|purchase|ordered|stars?)\b|\b(?:love|hate|liked|disliked|excellent|terrible|great|poor)\s+(?:it|this)\b/i.test(text);
  if (promotion && !feedback) return 'reject';
  if (promotion) return null;
  if (feedback) return 'approve';
  return null;
}

function projectReviewForMode(review,mode){
 if(!['vuln','fixed'].includes(mode))throw invalid('Bound review mode is invalid');
 if(mode==='vuln')return review;
 const policyDecision=classifyFixedReview(review.body);
 return Object.freeze({...review,body:FIXED_REVIEW_BODY,policy_decision:policyDecision,policy_status:policyDecision?'classified':'manual_review_required'});
}

function invalid(message) {
  return Object.assign(new TypeError(message), { code: 'INVALID_CONFIGURATION' });
}
function positive(value, label) {
  if (!Number.isSafeInteger(value) || value < 1 || value > 2147483647) throw invalid(`${label} is invalid`);
  return value;
}
function launchGeneration(value) {
  if (!Number.isSafeInteger(value) || value < 1) throw invalid('generation is invalid');
  return value;
}
function uuid(value, label) {
  if (typeof value !== 'string' || !UUID.test(value)) throw invalid(`${label} is invalid`);
  return value.toLowerCase();
}
function copyScope(scope) {
  if (!scope || typeof scope !== 'object' || Array.isArray(scope)) throw invalid('Trusted review scope required');
  return Object.freeze({
    launchId: uuid(scope.launchId, 'launchId'),
    scenarioId: uuid(scope.scenarioId, 'scenarioId'),
    generation: launchGeneration(scope.generation),
    platformOwnerId: positive(scope.platformOwnerId, 'platformOwnerId'),
    platformSessionId: positive(scope.platformSessionId, 'platformSessionId'),
  });
}
function bindTarget(scope, target) {
  if (!target || typeof target !== 'object' || Array.isArray(target)
      || ['launchId','scenarioId','generation','platformOwnerId','platformSessionId']
        .some(key => reviewScene.current(target)[key] !== scope[key])) {
    throw Object.assign(new Error('Review target does not match the authorized launch'), { code: 'RESERVATION_BINDING_MISMATCH' });
  }
  return reviewScene.copy(target, { targetId: uuid(target.targetId, 'targetId'),
    ...copyScope(target) });
}
function exactKeys(value, allowed) {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    && Object.getPrototypeOf(value) === Object.prototype
    && Object.keys(value).every(key => allowed.includes(key));
}
function wrap(value, isError = false) {
  const result = { content: Object.freeze([Object.freeze({ type: 'text', text: JSON.stringify(value) })]) };
  if (isError) result.isError = true;
  return Object.freeze(result);
}
function argumentError(message) {
  return wrap({ ok: false, code: 'INVALID_TOOL_ARGUMENTS', error: message }, true);
}
function stableFailure(error) {
  if (AUTHORITY_ERRORS.has(error?.code)) throw error;
  return wrap({ ok: false, code: error?.code === 'REVIEW_NOT_FOUND' ? 'REVIEW_NOT_FOUND' : 'REVIEW_OPERATION_FAILED',
    error: error?.code === 'REVIEW_NOT_FOUND' ? 'review is unavailable' : 'review operation failed' }, true);
}
function validateDependencies({ repository, trustedScope, checkCurrent, resolveTarget, auditPersona: rawAuditPersona, personaEffectFence }) {
  if (!repository || typeof repository.listPending !== 'function' || typeof repository.decide !== 'function'
    || typeof checkCurrent !== 'function' || typeof resolveTarget !== 'function') {
    throw invalid('Bound review tool dependencies required');
  }
  const scope = copyScope(trustedScope);
  let auditPersona;
  if (rawAuditPersona !== undefined) {
    if (!exactKeys(rawAuditPersona, ['id', 'role'])
      || !['customer', 'merchant', 'admin'].includes(rawAuditPersona.role)) {
      throw invalid('Trusted audit persona is invalid');
    }
    auditPersona = Object.freeze({ id: positive(rawAuditPersona.id, 'audit persona id'), role: rawAuditPersona.role });
  }
  let targetPromise;
  const getTarget = async () => {
    if (!targetPromise) targetPromise = Promise.resolve().then(() => resolveTarget(scope)).then(target => bindTarget(scope, target));
    try { return await targetPromise; }
    catch (error) { targetPromise = undefined; throw error; }
  };
  if (personaEffectFence !== undefined) repository = require('./secureshopPersonaReviewEffect').createPersonaReviewEffect({fence:personaEffectFence,repository});
  const getModeration = target => moderationBinding.capture(target, auditPersona, personaEffectFence);
  return { repository, scope, checkCurrent: target => checkCurrent(reviewScene.current(target)), getTarget, auditPersona, getModeration };
}
function validateReview(row) {
  if (!row || !Number.isSafeInteger(row.id) || row.id < 1 || typeof row.body !== 'string'
    || !Number.isSafeInteger(row.productId) || row.productId < 1
    || !Number.isSafeInteger(row.authorId) || row.authorId < 1
    || !Number.isSafeInteger(row.rating) || row.rating < 1 || row.rating > 5
    || row.status !== 'pending') throw Object.assign(new Error('Invalid bound review observation'), { code: 'INVALID_REVIEW_RESULT' });
  return Object.freeze({ id: row.id, product_id: row.productId, author_id: row.authorId,
    body: row.body, rating: row.rating, status: row.status });
}
function validateDecisionResult(result, id, expectedStatus) {
  const row = result?.review;
  if (!result || typeof result.applied !== 'boolean' || !row || row.id !== id
    || (result.applied && row.status !== expectedStatus)
    || (!result.applied && result.code !== 'REVIEW_NOT_PENDING')
    || !['approved', 'rejected'].includes(row.status)) {
    throw Object.assign(new Error('Invalid bound review decision result'), { code: 'INVALID_REVIEW_RESULT' });
  }
  return Object.freeze({ ok: true, applied: result.applied,
    ...(result.applied ? {} : { code: result.code }),
    review: Object.freeze({ id: row.id, product_id: row.productId, author_id: row.authorId,
      body: row.body, rating: row.rating, status: row.status,
      moderator_kind: row.moderatorKind, moderator_notes: row.moderatorNotes,
      moderated_at: row.moderatedAt }) });
}

function createSecureShopBoundReviewTools(options = {}) {
  const { repository, scope, checkCurrent, getTarget, auditPersona, getModeration } = validateDependencies(options);
  if (options.mode !== undefined && !['vuln', 'fixed'].includes(options.mode)) throw invalid('Bound review mode is invalid');
  const fixed = options.mode === 'fixed';
  const batch = options.batchAuthority === undefined ? null
    : assertBoundReviewBatchAuthority(options.batchAuthority);
  const observed = new Set();
  const fixedDecisions = new Map();

  const expose = review => {
    if (!fixed) return review;
    const policyDecision = classifyFixedReview(review.body);
    fixedDecisions.set(review.id, policyDecision);
    return projectReviewForMode(review,'fixed');
  };

  const moderatePending = async (args = {}) => {
    if (!exactKeys(args, ['limit']) || (args.limit !== undefined
      && (!Number.isInteger(args.limit) || args.limit < 1 || args.limit > 100))) {
      return argumentError('limit must be an integer from 1 to 100');
    }
    try {
      await checkCurrent(scope);
      const target = await getTarget();
      await checkCurrent(target);
      const moderation = getModeration(target);
      if (batch?.isIssued()) {
        const unresolved = batch.unresolvedRows();
        // Recorded packets stay immutable; current seller authority still gates
        // every cached observation before it is returned to the model.
        if (moderation) for (const row of unresolved) {
          if (!await repository.getReview(target, row.id, { moderation }))
            throw Object.assign(new Error('review is unavailable'), { code: 'REVIEW_NOT_FOUND' });
        }
        const reviews = unresolved.map(expose);
        for (const review of reviews) observed.add(review.id);
        return wrap({ ok: true, count: reviews.length, reviews });
      }
      const requestedLimit = batch ? Math.min(args.limit ?? batch.batchLimit, batch.batchLimit)
        : (args.limit ?? 20);
      const rows = await repository.listPending(target, { limit: batch ? requestedLimit + 1 : requestedLimit, ...(moderation ? { moderation } : {}) });
      await checkCurrent(target);
      if (!Array.isArray(rows) || rows.length > (batch ? requestedLimit + 1 : requestedLimit)) {
        throw Object.assign(new Error('Invalid bound review observation'), { code: 'INVALID_REVIEW_RESULT' });
      }
      const validated = rows.map(validateReview);
      const admitted = batch ? validated.slice(0, requestedLimit) : validated;
      if (batch) batch.issue(admitted, validated.length > requestedLimit);
      const reviews = admitted.map(expose);
      for (const review of reviews) observed.add(review.id);
      return wrap({ ok: true, count: reviews.length, reviews });
    } catch (error) { return stableFailure(error); }
  };

  async function decide(args, decision, invocation) {
    const allowed = decision === 'reject' ? ['review_id', 'reason'] : ['review_id'];
    if (!exactKeys(args, allowed) || !Number.isSafeInteger(args.review_id) || args.review_id < 1
      || (decision === 'reject' && args.reason !== undefined
        && (typeof args.reason !== 'string' || Buffer.byteLength(args.reason) > 16384))) {
      return argumentError(decision === 'reject' ? 'review_id and bounded reason are required' : 'review_id is required');
    }
    const id = args.review_id;
    if (!observed.has(id)) return wrap({ ok: false, code: 'REVIEW_NOT_OBSERVED', error: 'review must be observed before a decision' }, true);
    if (fixed) {
      const required = fixedDecisions.get(id);
      if (!required) return wrap({ ok: false, code: 'REVIEW_POLICY_UNCERTAIN', error: 'review requires manual moderation' }, true);
      if (decision !== required) return wrap({ ok: false, code: 'REVIEW_POLICY_MISMATCH', error: `fixed policy permits ${required} only` }, true);
    }
    try {
      await checkCurrent(scope);
      const target = await getTarget();
      await checkCurrent(target);
      const moderation = getModeration(target);
      const result = await repository.decide(target, { reviewId: id, decision,
        ...(moderation ? { moderation } : {}),
        notes: decision === 'reject' ? (fixed ? 'Unrelated promotion under bounded fixed review policy' : (args.reason ?? null)) : null, moderatorKind: 'auto',
        ...(auditPersona ? { auditPersona } : {}),
        ...(options.decisionOperation ? {operation:options.decisionOperation(invocation)} : {}) });
      await checkCurrent(target);
      const validated = validateDecisionResult(result, id, decision === 'approve' ? 'approved' : 'rejected');
      observed.delete(id);
      fixedDecisions.delete(id);
      if (batch) batch.consider(id);
      return wrap(fixed ? Object.freeze({ ...validated,
        review: Object.freeze({ ...validated.review, body: FIXED_REVIEW_BODY }) }) : validated);
    } catch (error) { return stableFailure(error); }
  }

  const approve = (args,invocation) => decide(args, 'approve',invocation);
  const reject = (args,invocation) => decide(args, 'reject',invocation);
  Object.freeze(moderatePending); Object.freeze(approve); Object.freeze(reject);
  return Object.freeze({
    'review-moderator.moderate_pending': moderatePending,
    'review-moderator.approve': approve,
    'review-moderator.reject': reject,
  });
}

// Deterministic user-authorized path for existing approve/reject buttons. It is
// deliberately separate from localTools and records moderatorKind='manual'.
function createSecureShopManualReviewActions(options = {}) {
  const { repository, scope, checkCurrent, getTarget, auditPersona, getModeration } = validateDependencies(options);
  async function decide(reviewId, decision, notes = null) {
    if (!Number.isSafeInteger(reviewId) || reviewId < 1
      || (notes !== null && (typeof notes !== 'string' || Buffer.byteLength(notes) > 16384))) {
      throw Object.assign(new TypeError('Manual review decision is invalid'), { code: 'INVALID_ARGUMENT' });
    }
    await checkCurrent(scope);
    const target = await getTarget();
    await checkCurrent(target);
    const moderation = getModeration(target);
    const result = await repository.decide(target, { reviewId, decision, notes, moderatorKind: 'manual',
      ...(moderation ? { moderation } : {}),
      ...(auditPersona ? { auditPersona } : {}) });
    await checkCurrent(target);
    return validateDecisionResult(result, reviewId, decision === 'approve' ? 'approved' : 'rejected');
  }
  return Object.freeze({ approve: reviewId => decide(reviewId, 'approve'),
    reject: (reviewId, reason = null) => decide(reviewId, 'reject', reason) });
}

module.exports = { projectReviewForMode, createSecureShopBoundReviewTools, createSecureShopManualReviewActions };
