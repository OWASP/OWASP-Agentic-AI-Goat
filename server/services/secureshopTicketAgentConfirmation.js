'use strict';

// Protected customer confirmation and SELECT-only saved read. The browser
// supplies only the original turn IDs and proposal ID, never ticket text.
const Ticket = require('./secureshopTicketContract');
const { createCouponAgentOriginalReader } = require('./secureshopCouponAgentOriginalReader');
const { createTicketAgentProposalService, originalSelection } =
  require('./secureshopTicketAgentProposal');
const { createConversationBinding, createLaunchScope } =
  require('./secureshopConversationBinding');
const invalid = () => Object.assign(new Error('Ticket confirmation unavailable'),
  { code: 'TICKET_AGENT_SOURCE_INVALID' });

function ticketSource(state, selected) {
  const { scope, persona, personaSession, retainedScene } = state;
  return Ticket.source({
    execution: createLaunchScope(scope),
    customer: { shopUserId: persona.id, personaSessionId: personaSession.sessionId,
      authorityVersion: personaSession.authorityVersion },
    scene: { sceneId: retainedScene.scene.sceneId,
      sceneGeneration: retainedScene.scene.sceneGeneration,
      targetId: retainedScene.targetId, grantId: retainedScene.scene.grantId,
      birth: createLaunchScope(retainedScene) },
    turn: { sessionId: selected.origin.turnSessionId,
      requestId: selected.origin.turnRequestId, runId: selected.runId },
    proposalId: selected.proposal.proposalId,
  });
}

function createTicketAgentConfirmation({ captureCurrent, bindingRepository, journal,
  conversations, confirmTicket, readSavedTicket, qualifyModel } = {}) {
  if (typeof captureCurrent !== 'function' || typeof confirmTicket !== 'function'
    || typeof readSavedTicket !== 'function' || typeof qualifyModel !== 'function')
    throw new TypeError('Ticket confirmation dependencies required');
  const reader = createCouponAgentOriginalReader({
    current: async holder => holder.state, bindingRepository, journal, conversations,
  });
  const proposalService = createTicketAgentProposalService({
    readOriginal: reader,
    assertCurrent: async holder => {
      try { await holder.state.check(); }
      catch (cause) {
        if (!holder.effectReturned) throw cause;
        throw Object.assign(new Error('Ticket outcome requires protected readback'),
          { code: 'PERSONA_EFFECT_OUTCOME_UNCERTAIN', executionBoundary: true, cause });
      }
    },
    qualifyModel,
    applyTicket: async (holder, selected) => {
      const { state } = holder;
      const source = ticketSource(state, selected);
      const result = await confirmTicket(Object.freeze({
        scope: state.scope, retainedScene: state.retainedScene,
        persona: state.persona, personaSession: state.personaSession,
        modeToken: state.ticketMode, source,
        ticketProposal: selected.proposal,
        originalMessage: selected.message,
        sourceOrigin: selected.origin,
        requestSha256: selected.requestSha256,
        withEffect: state.withEffect,
      }));
      holder.effectReturned = true;
      return Ticket.result(result, { source, ticketProposal: selected.proposal });
    },
  });

  async function current(context) {
    const state = await captureCurrent(context);
    const binding = createConversationBinding(state.scope, state.persona);
    if (binding.role !== 'customer' || typeof state.check !== 'function'
      || typeof state.withEffect !== 'function'
      || state.mode?.snapshot?.featureId !== 'customer_chat'
      || state.ticketMode?.snapshot?.featureId !== 'support_tickets'
      || state.ticketMode.snapshot.policyVersion !== 'owned-ticket-render-v1'
      || !['vuln', 'fixed'].includes(state.mode.snapshot.mode)
      || !['vuln', 'fixed'].includes(state.ticketMode.snapshot.mode)
      || typeof state.mode.assertCurrent !== 'function'
      || typeof state.ticketMode.assertCurrent !== 'function'
      || !state.retainedScene?.scene?.grantId
      || state.retainedScene.targetId !== state.target?.targetId) throw invalid();
    const check = async () => {
      await state.check();
      await state.mode.assertCurrent();
      await state.ticketMode.assertCurrent();
      await state.check();
    };
    const trusted = Object.freeze({ ...state, scope: binding, check });
    await check();
    return trusted;
  }

  return Object.freeze({
    async confirm(context, request) {
      const state = await current(context);
      return proposalService.confirm(request, { state, effectReturned: false });
    },
    async readSaved(context, request) {
      const state = await current(context);
      const source = await reader({ state }, { sessionId: request?.sessionId,
        requestId: request?.requestId });
      const selected = originalSelection(source, request, qualifyModel);
      const sourceBinding = ticketSource(state, selected);
      await state.check();
      const saved = await readSavedTicket(Object.freeze({
        scope: state.scope, retainedScene: state.retainedScene,
        persona: state.persona, personaSession: state.personaSession,
        modeToken: state.ticketMode, source: sourceBinding,
        operationId: selected.proposal.proposalId,
      }));
      await state.check();
      return Ticket.saved(saved === null ? { status: 'unconfirmed' }
        : { status: 'completed', result: saved },
      { source: sourceBinding, ticketProposal: selected.proposal });
    },
  });
}

module.exports = { createTicketAgentConfirmation, ticketSource };
