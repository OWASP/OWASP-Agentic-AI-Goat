'use strict';
const {captureAssessmentPublicationScope}=require('./secureshopAssessmentPublicationScope');

const { createHash, randomUUID } = require('node:crypto');
const { isDeepStrictEqual } = require('node:util');
const { createAssessmentPersonaCapture } = require('./secureshopAssessmentPersonaCapture');
const { createObjectiveCompletionService } = require('./secureshopObjectiveCompletionService');
const { createConversationBinding, createLaunchScope } = require('./secureshopConversationBinding');
const { createTurnAdmission } = require('./secureshopTurnAdmission');
const reviewScene = require('./secureshopReviewSceneBinding');

const WORKSHOP = 'secureshop_agent_security';
const OBJECTIVE = 'ss_stored_browser_execution';
const RECEIPT_VERSION = 'secureshop-stored-browser-v1';
const SHA256 = /^[0-9a-f]{64}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

function unavailable(message = 'Stored browser assessment unavailable') {
  return Object.assign(new Error(message), { code: 'GRADE_STORE_NOT_READY' });
}
function validExecution(boundary) {
  return boundary && typeof boundary.check === 'function'
    && typeof boundary.effectWithReceipt === 'function'
    && typeof boundary.identity?.runId === 'string' && boundary.identity.runId
    && typeof boundary.identity?.ownerKey === 'string' && boundary.identity.ownerKey
    && boundary.identity.durableGeneration !== null
    && boundary.identity.durableGeneration !== undefined;
}
function sameSubmission(before, after) {
  if (!before || !after) return false;
  const keys = ['version', 'targetId', 'launchId', 'scenarioId', 'generation',
    'platformOwnerId', 'platformSessionId', 'reviewId', 'submissionId', 'productId',
    'authorId', 'body', 'rating', 'submittedByShopUserId', 'submittedByShopRole',
    'bodySha256', 'requestSha256', 'status', 'createdAt'];
  return keys.every(key => Object.hasOwn(before, key) && Object.hasOwn(after, key)
    && isDeepStrictEqual(before[key], after[key]));
}
function validSource(source, binding, target, reviewId, productId) {
  return source?.version === 1 && source.reviewId === reviewId && source.productId === productId
    && source.targetId === target?.targetId
    && ['launchId','scenarioId','generation','platformOwnerId','platformSessionId']
      .every(key => source[key] === target[key] && reviewScene.current(target)[key] === binding[key])
    && source.submittedByShopUserId === binding.shopUserId
    && source.submittedByShopRole === binding.role
    && typeof source.body === 'string' && source.body.length > 0
    && SHA256.test(source.bodySha256)
    && source.bodySha256 === createHash('sha256').update(source.body, 'utf8').digest('hex')
    && SHA256.test(source.requestSha256) && UUID.test(source.submissionId);
}
function validBrowser(browser) {
  return browser?.executed === true && browser.targetEventExecuted === true
    && browser.targetEffectObserved === true && browser.syntheticCookieOnly === true
    && browser.finalCookieIsSyntheticOnly === true && Array.isArray(browser.markers)
    && browser.markers.length > 0 && Array.isArray(browser.blockedRequests);
}
function validEffectReceipt(receipt, execution, effectKey) {
  return receipt?.version === 1 && receipt.status === 'completed'
    && receipt.runId === execution.runId && receipt.ownerKey === execution.ownerKey
    && String(receipt.generation) === String(execution.durableGeneration)
    && receipt.effectKey === effectKey;
}
function rubric(mode) {
  return Object.freeze({ family: 'SecureShop', scenario: 'browser_sink', objectiveId: OBJECTIVE,
    version: RECEIPT_VERSION, mode, outcomeIntent: 'attack',
    requiredFacts: ['learner_review_persisted', 'owner_bound_submission',
      'actual_review_card_rendered', 'attributed_browser_execution',
      'observable_browser_effect', 'completed_browser_effect', 'current_after_browser',
      'vulnerable_mode'],
    criteria: [{ id: 'stored_review_executed', allowedSources: ['server_observation'],
      description: 'The exact raw bytes of a learner-written review from the owned scene, submitted by the current customer and revalidated under the current execution grant, were rendered by the actual SecureShop ReviewCard component and the attributed source executed with an observable effect in the isolated qualification browser. A marker claimed by review content, a hand-built innerHTML surrogate, a foreign or stale review, or an unattributed sibling payload does not satisfy this objective.' }],
  });
}

// The renderer is a trusted application dependency. It must render the actual
// ReviewCard component; requests cannot provide markup or component identity.
function createSecureShopStoredBrowserAssessment({ conversations, turns, journal, application,
  reviewRepository, receipts, progress, publicationModes, judge, browserQualification, renderReviewCard,
  componentSourceDigest, componentArtifactDigest, personaAuthority, personaBindings } = {}) {
  if (typeof conversations?.create !== 'function' || typeof turns?.run !== 'function'
      || !journal || typeof application?.resolveExistingTarget !== 'function'
      || typeof reviewRepository?.readSubmission !== 'function'
      || typeof browserQualification?.qualify !== 'function'
      || typeof renderReviewCard !== 'function'
      || typeof componentSourceDigest !== 'string' || !SHA256.test(componentSourceDigest)
      || typeof componentArtifactDigest !== 'string' || !SHA256.test(componentArtifactDigest)) {
    throw unavailable();
  }
  if (personaAuthority !== undefined && typeof personaAuthority?.capture !== 'function') throw unavailable('Persona authority unavailable');
  if (publicationModes !== undefined && typeof publicationModes?.getEvaluationScope !== 'function') throw unavailable('Publication mode reader unavailable');
  if (personaBindings !== undefined && typeof personaAuthority?.capture !== 'function') throw unavailable('Persona grading authority unavailable');
  const personaCapture = createAssessmentPersonaCapture(personaBindings);
  const admission = createTurnAdmission({ journal });
  const capturedScopes = new WeakMap();
  const completion = createObjectiveCompletionService({ receipts, progress, ...personaCapture.options,
    ...(judge ? { judge } : {}), captureInstanceScope: execution => {
      const scope = capturedScopes.get(execution);
      if (!scope) throw unavailable();
      return scope;
    } });

  async function runAttempt({ scope, persona, personaSession, requestId, productId, reviewId, signal } = {}) {
    const binding = createConversationBinding(scope, persona);
    if (binding.role !== 'customer' || typeof requestId !== 'string' || !UUID.test(requestId)
        || !Number.isSafeInteger(productId) || productId < 1
        || !Number.isSafeInteger(reviewId) || reviewId < 1) {
      throw Object.assign(new TypeError('Invalid stored browser request'), { code: 'INVALID_ARGUMENT' });
    }
    const launchScope = createLaunchScope(binding);
    const credential = personaAuthority === undefined ? undefined : Object.freeze({
      sessionId: typeof personaSession?.sessionId === 'string' ? personaSession.sessionId.toLowerCase() : personaSession?.sessionId,
      authorityVersion: personaSession?.authorityVersion });
    if (credential && (typeof credential.sessionId !== 'string' || !UUID.test(credential.sessionId)
        || typeof credential.authorityVersion !== 'string' || !/^[1-9][0-9]*$/.test(credential.authorityVersion))) {
      throw Object.assign(new Error('Persona session unavailable'), { code: 'SHOP_AUTH_INVALID' });
    }
    const fence = personaAuthority === undefined ? undefined : await personaAuthority.capture({scope: launchScope,
      personaId: binding.shopUserId, role: binding.role, sessionId: credential.sessionId,
      authorityVersion: credential.authorityVersion});
    if (personaAuthority !== undefined && (!fence || typeof fence.assertRemoteAdmission !== 'function'
        || typeof fence.withPersonaEffect !== 'function')) throw unavailable('Persona authority capture unavailable');
    if (personaAuthority !== undefined) {
      const capturedScope = createLaunchScope(fence.binding);
      if (Object.keys(launchScope).some(key => capturedScope[key] !== launchScope[key])
          || fence.binding.personaId !== binding.shopUserId || fence.binding.role !== binding.role
          || fence.binding.sessionId !== credential.sessionId
          || fence.binding.authorityVersion !== credential.authorityVersion) {
        throw unavailable('Persona authority capture mismatch');
      }
    }
    const privateCapture = personaCapture.prepare(binding, fence);
    const checkPersona = async () => { signal?.throwIfAborted(); if (fence) await fence.assertRemoteAdmission(); };
    await checkPersona();
    const trustedPersona = Object.freeze({ id: binding.shopUserId, role: binding.role });
    signal?.throwIfAborted();
    const conversation = await conversations.create(launchScope, trustedPersona);
    await checkPersona();
    const publicationScope=await captureAssessmentPublicationScope(publicationModes||progress,launchScope.platformOwnerId,signal,launchScope);await checkPersona();
    if(publicationScope.binding.mode!=='vuln')return {completed:false,status:'ineligible',modelEvaluated:false};
    const message = JSON.stringify([OBJECTIVE, productId, reviewId, publicationScope.binding]);
    const normalizedRequestId = requestId.toLowerCase();
    let prepared;
    const prepare = async () => {
      await checkPersona();
      prepared = await admission.prepare({ sessionId: conversation.id,
        requestId: normalizedRequestId, binding, message });
      await checkPersona();
      return prepared.status === 'completed'
        ? Object.freeze({ skip: true, value: prepared.outcome })
        : Object.freeze({ skip: false, value: prepared });
    };
    let outcome;
    try {
      outcome = await turns.run(conversation.id, binding, trustedPersona,
      { signal, idempotencyKey: normalizedRequestId, admit: prepare }, async originalBoundary => {
        const boundary = fence ? Object.freeze({...originalBoundary, async check() {
          await originalBoundary.check(); await checkPersona(); await originalBoundary.check();
        }}) : originalBoundary;
        await boundary.check();
        if (!prepared) {
          await boundary.check();
          prepared = await admission.prepare({ sessionId: conversation.id,
            requestId: normalizedRequestId, binding, message });
          await boundary.check();
          if (prepared.status === 'completed') return prepared.outcome;
        }
        return admission.execute(prepared, boundary, async () => {
        if (!validExecution(boundary)) throw unavailable('Protected browser execution unavailable');
        const execution = Object.freeze({ runId: boundary.identity.runId,
          ownerKey: boundary.identity.ownerKey,
          durableGeneration: boundary.identity.durableGeneration,
          signal: boundary.signal, check: boundary.check });
        capturedScopes.set(execution, launchScope);
        personaCapture.bind(execution, privateCapture);
        await boundary.check();
        if (boundary.trace) await boundary.trace({ node: 'stored_browser_assessment',
          type: 'node_start', data: {} });
        const attempt = await completion.beginAttempt({ userId: launchScope.platformOwnerId,
          workshopKey: WORKSHOP, objectiveId: OBJECTIVE, execution });
        const target = await application.resolveExistingTarget(launchScope);
        await boundary.check();
        const source = await reviewRepository.readSubmission(target, reviewId);
        await boundary.check();
        if (!validSource(source, binding, target, reviewId, productId)) {
          throw Object.assign(new Error('Learner review unavailable'), { code: 'REVIEW_NOT_FOUND' });
        }
        const markup = await renderReviewCard(Object.freeze({ id: source.reviewId,
          product_id: source.productId, author_id: source.authorId, body: source.body,
          rating: source.rating, status: source.status, created_at: source.createdAt }),
        { signal: boundary.signal });
        await boundary.check();
        if (typeof markup !== 'string' || !markup.includes(source.body)) {
          throw unavailable('Actual ReviewCard render unavailable');
        }
        const effectNode = `stored-browser:${reviewId}`;
        const browserEffect = await boundary.effectWithReceipt(effectNode, async () => {
          await boundary.check();
          const qualified = await browserQualification.qualify(markup, {
            signal: boundary.signal, eventSource: source.body,
          });
          await boundary.check();
          return qualified;
        });
        await boundary.check();
        const current = await reviewRepository.readSubmission(target, reviewId);
        await boundary.check();
        const effectKey = `${normalizedRequestId}:${effectNode}`;
        const currentAfterBrowser = sameSubmission(source, current)
          && validSource(current, binding, target, reviewId, productId);
        const browserValid = validBrowser(browserEffect.value);
        const receiptValid = validEffectReceipt(browserEffect.receipt, execution, effectKey);
        const facts = Object.freeze({ learner_review_persisted: true,
          owner_bound_submission: true,
          actual_review_card_rendered: true,
          attributed_browser_execution: browserValid,
          observable_browser_effect: browserValid,
          completed_browser_effect: receiptValid,
          current_after_browser: currentAfterBrowser,
          vulnerable_mode: attempt.mode === 'vuln' });
        const evidence = Object.freeze([{ id: 'stored_browser_receipt', source: 'server_observation',
          content: Object.freeze({ receiptVersion: RECEIPT_VERSION,
            component: Object.freeze({ id: 'SecureShop.ReviewCard',
              sourceSha256: componentSourceDigest, artifactSha256: componentArtifactDigest }),
            source: Object.freeze({ reviewId: source.reviewId, productId: source.productId,
              submissionId: source.submissionId, bodySha256: source.bodySha256,
              requestSha256: source.requestSha256 }),
            execution: Object.freeze({ runId: execution.runId, effectReceipt: browserEffect.receipt }),
            browser: Object.freeze({ provenance: 'isolated_qualification_browser',
              targetEventExecuted: browserEffect.value?.targetEventExecuted === true,
              targetEffectObserved: browserEffect.value?.targetEffectObserved === true,
              reason: browserEffect.value?.reason || 'unknown',
              markers: browserEffect.value?.markers || [],
              blockedExternalRequests: browserEffect.value?.blockedRequests || [],
              syntheticCookieOnly: browserEffect.value?.syntheticCookieOnly === true,
              finalCookieIsSyntheticOnly: browserEffect.value?.finalCookieIsSyntheticOnly === true }),
            currentAfterBrowser, facts }),
        }]);
        const result = await completion.evaluate({ userId: launchScope.platformOwnerId,
          workshopKey: WORKSHOP, objectiveId: OBJECTIVE, evaluationId: randomUUID(),
          execution, attempt, rubric: rubric(attempt.mode), evidence, facts });
        await boundary.check();
        return Object.freeze({ completed: result.completed === true,
          judgment: result.judgment, reviewId, productId,
          component: Object.freeze({ id: 'SecureShop.ReviewCard', sourceSha256: componentSourceDigest,
            artifactSha256: componentArtifactDigest }),
          browser: Object.freeze({ executed: browserValid,
            reason: browserEffect.value?.reason || 'unknown' }) });
        }, ...(fence ? [fence] : []));
      });
    } catch (error) {
      await admission.abandon(prepared);
      throw error;
    }
    await checkPersona();
    await publicationScope.assertCurrent();await checkPersona();
    return Object.freeze({ ...outcome.result, replayed: outcome.replayed === true });
  }

  return Object.freeze({ runAttempt, completionService: completion });
}

module.exports = { createSecureShopStoredBrowserAssessment, OBJECTIVE, RECEIPT_VERSION };
