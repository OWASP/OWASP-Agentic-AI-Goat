'use strict';

// The model can prepare a ticket, never insert one. Confirmation re-reads the
// original completed customer turn and its persisted selected-tool trace.
const { isDeepStrictEqual: equal } = require('node:util');
const Ticket = require('./secureshopTicketContract');
const { isQualifiedSecureShopModelTrace } = require('./secureshopRealModelTrace');
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const invalid = () => Object.assign(new Error('Saved ticket proposal unavailable'),
  { code: 'TICKET_AGENT_SOURCE_INVALID' });
const exact = (value, keys) => value && Object.getPrototypeOf(value) === Object.prototype
  && Reflect.ownKeys(value).length === keys.length
  && keys.every(key => Object.hasOwn(value, key));
const parse = value => typeof value === 'string' ? JSON.parse(value) : value;

function originalSelection(source, request, qualifyModel) {
  if (typeof qualifyModel !== 'function') throw new TypeError('Ticket model qualification required');
  const { turn, traces } = source || {};
  const saved = turn?.result_json, meta = saved?.taskMetadata?.ticketAgent;
  try {
    if (!(meta?.version === 1 && exact(meta, ['version', 'runId', 'origin', 'proposal', 'traceEventIds'])
      || meta?.version === 2 && exact(meta, ['version', 'runId', 'origin', 'proposal', 'requestRef', 'traceEventIds']))
      || !UUID.test(meta.runId || '')) throw invalid();
    const requestRef = meta.version === 2 ? Ticket.requestRef({
      requestHash: turn.request_hash,
      envelopeSha256: saved?.taskMetadata?.customerChat?.envelopeSha256,
    }) : null;
    if (meta.version === 2 && meta.requestRef !== requestRef) throw invalid();
    const origin = Ticket.origin(meta.origin);
    const proposal = Ticket.proposal(meta.proposal,
      { message: source.message, sourceOrigin: origin });
    Ticket.confirmation(request, { sourceOrigin: origin });
    if (turn.status !== 'completed' || turn.session_id !== origin.turnSessionId
      || turn.request_id !== origin.turnRequestId || turn.request_version !== 1
      || !(/^[a-f0-9]{64}$/).test(turn.request_hash || '')
      || saved.stopReason !== 'end_turn') throw invalid();
    const selectedArgs = meta.version === 2 ? { requestRef } :
      { subject: proposal.subject, body: proposal.body };
    const expected = { status: 'confirmation_required', ticketProposal: proposal,
      ticketOrigin: origin };
    const hops = saved.hops?.filter(hop => hop?.tool === Ticket.TOOL
      && hop.step === origin.invocationStep && !hop.error
      && hop.result?.isError !== true && equal(hop.params, selectedArgs)
      && hop.result?.content?.length === 1
      && hop.result.content[0]?.type === 'text'
      && equal(parse(hop.result.content[0].text), expected));
    if (hops?.length !== 1 || saved.hops.filter(hop => hop?.tool === Ticket.TOOL
      && !hop.error && hop.result?.isError !== true).length !== 1) throw invalid();
    const ids = meta.traceEventIds;
    if (!Array.isArray(ids) || ids.length < 4 || ids.length > 4096
      || ids.some(id => !UUID.test(id || ''))
      || new Set(ids).size !== ids.length
      || !Array.isArray(traces) || traces.length !== ids.length
      || !equal(traces.map(row => row.event_id), ids)
      || traces.some((row, index) => row.session_id !== origin.turnSessionId
        || index > 0 && Number(row.id) <= Number(traces[index - 1].id))) throw invalid();
    const decisions = traces.filter(row => row.kind === 'model_decision'
      && row.actor === 'supervisor' && row.step === origin.invocationStep
      && parse(row.params_json)?.decision === 'tool_use'
      && parse(row.params_json)?.toolCalls?.some(call => call.id === origin.callId));
    if (decisions.length !== 1) throw invalid();
    const decision = decisions[0], calls = parse(decision.params_json).toolCalls;
    if (calls.length !== 1 || calls[0].id !== origin.callId
      || calls[0].name !== Ticket.TOOL
      || !equal(calls[0].args, selectedArgs)
      || !isQualifiedSecureShopModelTrace(decision, qualifyModel)) throw invalid();
    const callRows = traces.filter(row => row.kind === 'local_tool_call'
      && row.actor === 'supervisor→task' && row.step === origin.invocationStep
      && row.agent_ns === 'support' && row.tool_name === 'ticket_prepare'
      && Number(row.id) > Number(decision.id)
      && equal(parse(row.params_json), selectedArgs));
    if (callRows.length !== 1) throw invalid();
    const results = traces.filter(row => row.kind === 'local_tool_result'
      && row.actor === 'task→supervisor' && row.step === origin.invocationStep
      && row.agent_ns === 'support' && row.tool_name === 'ticket_prepare'
      && Number(row.id) > Number(callRows[0].id)
      && equal(parse(row.result_json), hops[0].result));
    if (results.length !== 1) throw invalid();
    const terminal = traces.at(-1), terminalResult = parse(terminal?.result_json);
    if (traces.filter(row => row.kind === 'terminal').length !== 1
      || terminal?.kind !== 'terminal' || terminal.actor !== 'supervisor'
      || Number(terminal.id) <= Number(results[0].id)
      || terminal.step <= origin.invocationStep
      || terminal.provider !== decision.provider
      || terminalResult?.model !== parse(decision.result_json)?.model
      || terminalResult.stopReason !== 'end_turn'
      || terminalResult.steps !== saved.steps
      || terminalResult.hops !== saved.hops.length
      || !isQualifiedSecureShopModelTrace(terminal, qualifyModel)) throw invalid();
    return Object.freeze({ runId: meta.runId, origin, proposal, message: source.message,
      ...(meta.version === 2 ? { sourceVersion: 2, requestRef } : {}),
      requestSha256: turn.request_hash,
      traceEventIds: Object.freeze([...ids]),
      decisionEventId: decision.event_id, callEventId: callRows[0].event_id,
      resultEventId: results[0].event_id, terminalEventId: terminal.event_id });
  } catch { throw invalid(); }
}

function createTicketAgentProposalService({ readOriginal, assertCurrent,
  applyTicket, qualifyModel } = {}) {
  if (typeof readOriginal !== 'function' || typeof assertCurrent !== 'function'
    || typeof applyTicket !== 'function' || typeof qualifyModel !== 'function')
    throw new TypeError('Ticket proposal service dependencies required');
  return Object.freeze({
    prepare({ subject, body, message, sourceOrigin } = {}) {
      const ticketOrigin = Ticket.origin(sourceOrigin);
      const ticketProposal = Ticket.prepare({ subject, body, message,
        sourceOrigin: ticketOrigin });
      return Object.freeze({ status: 'confirmation_required', ticketProposal,
        ticketOrigin });
    },
    async confirm(request, trustedContext) {
      if (!exact(request, ['sessionId', 'requestId', 'proposalId'])
        || ![request.sessionId, request.requestId, request.proposalId]
          .every(id => typeof id === 'string' && UUID.test(id))) throw invalid();
      await assertCurrent(trustedContext);
      const source = await readOriginal(trustedContext,
        { sessionId: request.sessionId, requestId: request.requestId });
      const selected = originalSelection(source, request, qualifyModel);
      await assertCurrent(trustedContext);
      const result = await applyTicket(trustedContext, selected);
      await assertCurrent(trustedContext);
      return Object.freeze({ result, source: Object.freeze({
        sessionId: selected.origin.turnSessionId,
        requestId: selected.origin.turnRequestId,
        runId: selected.runId,
        operationId: selected.proposal.proposalId,
        subjectSha256: selected.proposal.subjectSha256,
        bodySha256: selected.proposal.bodySha256,
        traceEventIds: selected.traceEventIds,
        decisionEventId: selected.decisionEventId,
        callEventId: selected.callEventId,
        resultEventId: selected.resultEventId,
        terminalEventId: selected.terminalEventId,
      }) });
    },
  });
}

module.exports = { createTicketAgentProposalService, originalSelection };
