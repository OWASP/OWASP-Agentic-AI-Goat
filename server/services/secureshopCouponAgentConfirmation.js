'use strict';

// Unmounted V49 handoff. Capture current authority before resolving any saved
// model decision; the browser never supplies a coupon code or operation ID.
const { createCouponAgentOriginalReader } = require('./secureshopCouponAgentOriginalReader');
const { createCouponAgentProposalService, originalSelection } =
  require('./secureshopCouponAgentProposalService');
const { createConversationBinding } = require('./secureshopConversationBinding');
const { isDeepStrictEqual: equal } = require('node:util');
const fail = () => Object.assign(new Error('Coupon confirmation unavailable'),
  { code: 'COUPON_AGENT_SOURCE_INVALID' });

function createCouponAgentConfirmation({ captureCurrent, bindingRepository, journal,
  conversations, applyConfirmedCoupon, readConfirmedCoupon, qualifyModel } = {}) {
  if (typeof captureCurrent !== 'function' || typeof applyConfirmedCoupon !== 'function'
    || typeof readConfirmedCoupon !== 'function' || typeof qualifyModel !== 'function')
    throw new TypeError('Coupon confirmation dependencies required');
  const reader = createCouponAgentOriginalReader({
    current: async holder => holder.state,
    bindingRepository, journal, conversations,
  });
  const service = createCouponAgentProposalService({
    readOriginal: reader,
    assertCurrent: async holder => {
      try { await holder.state.check(); }
      catch (cause) {
        if (!holder.effectReturned) throw cause;
        throw Object.assign(new Error('Coupon outcome requires protected readback'),
          { code: 'PERSONA_EFFECT_OUTCOME_UNCERTAIN', executionBoundary: true, cause });
      }
    },
    qualifyModel,
    applyCoupon: async (holder, { code, operationId }) => {
      // This is deliberately a new effect-boundary dependency. The existing
      // commerce.applyCoupon reselects target/mode and cannot enforce the
      // original saved turn's scene/grant/epoch at its effect boundary.
      const result = await applyConfirmedCoupon(Object.freeze({
        scope: holder.state.scope, persona: holder.state.persona,
        personaSession: holder.state.personaSession, code, operationId,
        expectedTarget: Object.freeze({ targetId: holder.state.target.targetId,
          sceneId: holder.state.target.scene.sceneId,
          sceneGeneration: holder.state.target.scene.sceneGeneration,
          grantId: holder.state.target.scene.grantId }),
        customerMode: holder.state.mode, couponMode: holder.state.couponMode,
        checkCurrent: holder.state.check,
      }));
      holder.effectReturned = true;
      return result;
    },
  });
  async function current(context) {
    const state = await captureCurrent(context);
    const binding = createConversationBinding(state.scope, state.persona);
    if (binding.role !== 'customer' || typeof state.check !== 'function'
        || state.mode?.snapshot?.featureId !== 'customer_chat'
        || state.couponMode?.snapshot?.featureId !== 'coupons'
        || !['vuln', 'fixed'].includes(state.mode.snapshot.mode)
        || !['vuln', 'fixed'].includes(state.couponMode.snapshot.mode)
        || typeof state.mode.assertCurrent !== 'function'
        || typeof state.couponMode.assertCurrent !== 'function'
        || !state.target?.scene?.grantId) throw fail();
    const check = async () => {
      await state.check();
      await state.mode.assertCurrent();
      await state.couponMode.assertCurrent();
      await state.check();
    };
    const trusted = Object.freeze({ ...state, scope: binding, check });
    await check();
    return trusted;
  }
  return Object.freeze({
    async confirm(context, request) {
      const trusted = await current(context);
      return service.confirm(request, { state: trusted, effectReturned: false });
    },
    async readSaved(context, request) {
      const state = await current(context);
      const source = await reader({ state }, { sessionId: request?.sessionId,
        requestId: request?.requestId });
      const selected = originalSelection(source, request, qualifyModel);
      await state.check();
      const saved = await readConfirmedCoupon(Object.freeze({
        scope: state.scope, persona: state.persona,
        personaSession: state.personaSession,
        code: selected.proposal.code,
        operationId: selected.proposal.proposalId,
        expectedTarget: Object.freeze({ targetId: state.target.targetId,
          sceneId: state.target.scene.sceneId,
          sceneGeneration: state.target.scene.sceneGeneration,
          grantId: state.target.scene.grantId }),
        customerMode: state.mode, couponMode: state.couponMode,
        checkCurrent: state.check,
      }));
      await state.check();
      if (saved === null) return Object.freeze({ status: 'unconfirmed' });
      if (saved?.state !== 'completed' || !saved.request || !saved.result
          || saved.request.operationId !== selected.proposal.proposalId
          || saved.request.code !== selected.proposal.code
          || saved.request.mode !== state.couponMode.snapshot.mode
          || !equal(saved.request.scope, {
            launchId: state.scope.launchId,
            scenarioId: state.scope.scenarioId,
            generation: state.scope.generation,
            platformOwnerId: state.scope.platformOwnerId,
            platformSessionId: state.scope.platformSessionId,
          })
          || !equal(saved.request.persona, state.persona)
          || !equal(saved.request.personaSession, {
            sessionId: state.personaSession.sessionId,
            authorityVersion: state.personaSession.authorityVersion })) throw fail();
      return Object.freeze({ status: 'completed', result: saved.result });
    },
  });
}

module.exports = { createCouponAgentConfirmation };
