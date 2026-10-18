'use strict';

const { isDeepStrictEqual: equal } = require('node:util');
const { createLaunchScope, createConversationBinding } = require('./secureshopConversationBinding');
const { executionScope } = require('./secureshopSceneBinding');
const { createV01TeachingTokenAuthority } = require('./secureshopV01TeachingToken');

const FEATURE = 'checkout_audit_jwt';
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const fail = code => Object.assign(new Error('Checkout audit lesson unavailable'), {
  code, executionBoundary: true,
});
function receiptValid(receipt, identity, effectKey) {
  return receipt?.version === 1 && receipt.status === 'completed'
    && receipt.runId === identity.runId && receipt.ownerKey === identity.ownerKey
    && receipt.generation === String(identity.durableGeneration)
    && receipt.effectKey === effectKey;
}
function createV01CheckoutAuditLesson({ secretMaterial, checkoutHistory, auditStore,
  launches, personaAuthority, modeAuthority, resolveExistingTarget } = {}) {
  if (typeof checkoutHistory?.read !== 'function'
      || typeof auditStore?.checkoutForOrder !== 'function'
      || typeof launches?.assertCurrent !== 'function'
      || typeof personaAuthority?.capture !== 'function'
      || typeof modeAuthority?.capture !== 'function'
      || typeof modeAuthority?.assertToken !== 'function'
      || typeof resolveExistingTarget !== 'function') {
    throw new TypeError('Bound V01 checkout audit dependencies required');
  }
  const tokens = createV01TeachingTokenAuthority({ secretMaterial });
  const privateEvidence = new WeakMap();
  async function admit(input) {
    const binding = createConversationBinding(input?.scope, input?.persona);
    if (binding.role !== 'customer' || !UUID.test(input?.personaSession?.sessionId || '')
        || !/^[1-9]\d*$/.test(input?.personaSession?.authorityVersion || '')
        || !UUID.test(input?.checkoutOperationId || '')) throw fail('V01_OWNER_UNAVAILABLE');
    const session = Object.freeze({ sessionId: input.personaSession.sessionId.toLowerCase(),
      authorityVersion: input.personaSession.authorityVersion });
    const mode = modeAuthority.assertToken(await modeAuthority.capture(binding, FEATURE));
    if (mode?.snapshot?.featureId !== FEATURE || !['vuln','fixed'].includes(mode.snapshot.mode)
        || !equal(mode.snapshot.scope, createLaunchScope(binding))
        || typeof mode.assertCurrent !== 'function'
        || typeof mode.assertCurrentAtEffect !== 'function') throw fail('V01_MODE_UNAVAILABLE');
    const fence = await personaAuthority.capture({ scope: binding,
      personaId: binding.shopUserId, role: 'customer', ...session });
    const actual = fence?.binding;
    if (typeof fence?.assertRemoteAdmission !== 'function' || !actual
        || Object.keys(createLaunchScope(binding)).some(key => actual[key] !== binding[key])
        || actual.personaId !== binding.shopUserId || actual.role !== 'customer'
        || actual.sessionId !== session.sessionId
        || actual.authorityVersion !== session.authorityVersion) throw fail('V01_PERSONA_UNAVAILABLE');
    const check = async () => {
      await launches.assertCurrent(binding);
      await mode.assertCurrent();
      await fence.assertRemoteAdmission();
    };
    await check();
    const target = await resolveExistingTarget(binding);
    if (!target?.scene || !UUID.test(target.targetId || '')
        || !equal(createLaunchScope(executionScope(target)), createLaunchScope(binding))) {
      throw fail('V01_TARGET_UNAVAILABLE');
    }
    await check();
    return Object.freeze({ binding, session, mode, fence, target, check,
      operationId: input.checkoutOperationId.toLowerCase() });
  }
  async function checkout(state) {
    const value = await checkoutHistory.read(state.target, state.binding.shopUserId, state.operationId);
    if (value?.status !== 'completed' || value.operationId !== state.operationId
        || !Number.isSafeInteger(value.order?.id) || value.order.id < 1) throw fail('V01_CHECKOUT_UNAVAILABLE');
    await state.check();
    return value;
  }
  function execution(input) {
    const run = input?.execution;
    if (typeof run?.check !== 'function' || typeof run.runId !== 'string'
        || !run.runId || typeof run.ownerKey !== 'string' || !run.ownerKey
        || !/^(0|[1-9]\d*)$/.test(String(run.durableGeneration))
        || !UUID.test(input?.requestId || '')) throw fail('V01_RUN_UNAVAILABLE');
    return run;
  }
  function payload(result) {
    if (!result || Object.keys(result).sort().join(',') !== 'content'
        || !Array.isArray(result.content) || result.content.length !== 1
        || result.content[0]?.type !== 'text'
        || typeof result.content[0].text !== 'string'
        || Buffer.byteLength(result.content[0].text, 'utf8') > 4096)
      throw fail('V01_OBSERVATION_UNAVAILABLE');
    let value;
    try { value = JSON.parse(result.content[0].text); } catch { throw fail('V01_OBSERVATION_UNAVAILABLE'); }
    if (JSON.stringify(value) !== result.content[0].text
        || !value || Object.keys(value).sort().join(',') !== 'eventId,report,sourceSha256,status'
        || value.status !== 'disclosed' || !UUID.test(value.eventId || '')
        || !/^[a-f0-9]{64}$/.test(value.sourceSha256 || ''))
      throw fail('V01_OBSERVATION_UNAVAILABLE');
    return value;
  }
  return Object.freeze({
    evidenceFor(observed) {
      const evidence = privateEvidence.get(observed);
      if (!evidence) throw fail('V01_EVIDENCE_UNAVAILABLE');
      return evidence;
    },
    async presentCustomerToken(input) {
      const state = await admit(input), original = await checkout(state);
      // This is a synthetic practice credential for the isolated verifier.
      // It cannot authenticate a platform or a SecureShop persona session.
      return Object.freeze({ orderId: original.order.id, operationId: state.operationId,
        token: tokens.issueCustomer(state.binding, state.target.targetId,
          state.binding.shopUserId, original.order.id) });
    },
    async readAudit(input) {
      const run = execution(input), state = await admit(input);
      await run.check();
      const original = await checkout(state);
      // In fixed mode, an unsigned teaching token is denied before the
      // protected audit repository is called.
      tokens.verifyAdmin(input.teachingToken, state.mode.snapshot.mode,
        state.binding, state.target.targetId, state.binding.shopUserId, original.order.id);
      await state.check();
      await state.mode.assertCurrentAtEffect();
      const row = await auditStore.checkoutForOrder(state.target,
        state.binding.shopUserId, original);
      await run.check(); await state.check();
      const value = Object.freeze({ status: 'disclosed', eventId: row.eventId,
        sourceSha256: row.sourceSha256, report: row.observation });
      // The graph persists this bounded public value inside its own completed
      // effect. Event ID + digest survive a replay even if this callback does not.
      return Object.freeze({ content: Object.freeze([Object.freeze({
        type: 'text', text: JSON.stringify(value) })]) });
    },
    async bindObservedEffect(input, observed) {
      const run = execution(input);
      const expectedArgs=input.toolProtocolVersion===2?{}
        :{checkoutOperationId:input.checkoutOperationId,teachingToken:input.teachingToken};
      if (!observed || observed.tool !== 'auth.audit_probe'
          || !Number.isSafeInteger(observed.step) || observed.step < 0
          || typeof observed.callId !== 'string' || !observed.callId
          || Buffer.byteLength(observed.callId, 'utf8') > 128
          || ![undefined,1,2].includes(input.toolProtocolVersion)
          || !equal(observed.args, expectedArgs)) throw fail('V01_OBSERVATION_UNAVAILABLE');
      const effectKey = `${input.requestId.toLowerCase()}:${JSON.stringify([
        observed.step, observed.callId, observed.tool])}`;
      if (!receiptValid(observed.effectReceipt, run, effectKey))
        throw fail('V01_EFFECT_UNAVAILABLE');
      const originalPublic = payload(observed.result);
      await run.check();
      const state = await admit(input), original = await checkout(state);
      const authorized = tokens.verifyAdmin(input.teachingToken, state.mode.snapshot.mode,
        state.binding, state.target.targetId, state.binding.shopUserId, original.order.id);
      // Exact reread by the event ID from the completed graph effect; never
      // select a newer audit row to repair a missing original.
      const retained = await auditStore.checkoutForOrder(state.target,
        state.binding.shopUserId, original, originalPublic.eventId);
      if (retained.eventId !== originalPublic.eventId
          || retained.sourceSha256 !== originalPublic.sourceSha256
          || !equal(retained.observation, originalPublic.report))
        throw fail('V01_SOURCE_CHANGED');
      await run.check(); await state.check();
      const evidence = Object.freeze({ version: 1, feature: FEATURE,
        scope: createLaunchScope(state.binding), personaId: state.binding.shopUserId,
        personaSessionId: state.session.sessionId,
        personaAuthorityVersion: state.session.authorityVersion,
        targetId: state.target.targetId, sceneId: state.target.scene.sceneId,
        sceneGeneration: state.target.scene.sceneGeneration,
        checkoutOperationId: state.operationId, orderId: original.order.id,
        requestId: input.requestId.toLowerCase(),
        eventId: retained.eventId, sourceSha256: retained.sourceSha256,
        teachingAlgorithm: authorized.algorithm, mode: state.mode.snapshot.mode,
        execution: Object.freeze({ runId: run.runId, ownerKey: run.ownerKey,
          durableGeneration: String(run.durableGeneration) }),
        effectReceipt: observed.effectReceipt,
        graphOrigin: Object.freeze({ step: observed.step, callId: observed.callId,
          tool: observed.tool }) });
      privateEvidence.set(observed, evidence);
      return evidence;
    },
  });
}
module.exports = { createV01CheckoutAuditLesson };
