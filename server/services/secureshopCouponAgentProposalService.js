'use strict';

// Unmounted customer-chat coupon handoff. The selected tool only proposes an
// exact code. A trusted confirmation reader must recover the completed turn;
// no browser-provided code or operation ID reaches the coupon workflow.
const { isDeepStrictEqual } = require('node:util');
const Contract = require('./secureshopCouponAgentContract');
const { isQualifiedSecureShopModelTrace } = require('./secureshopRealModelTrace');
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const invalid = () => Object.assign(new Error('Saved coupon proposal unavailable'),
  { code: 'COUPON_AGENT_SOURCE_INVALID' });
const parse = value => typeof value === 'string' ? JSON.parse(value) : value;
const exact = (value, keys) => value && Object.getPrototypeOf(value) === Object.prototype
  && Reflect.ownKeys(value).length === keys.length
  && keys.every(key => Object.hasOwn(value, key));

function originalSelection(source, request, qualifyModel) {
  const { turn, traces } = source || {};
  const saved = turn?.result_json;
  const meta = saved?.taskMetadata?.customerChat;
  let selected;
  try {
    const origin = Contract.origin(meta?.couponOrigin);
    const proposal = Contract.proposal(meta?.couponProposal,
      { message: source.message, sourceOrigin: origin });
    Contract.confirmation(request, { sourceOrigin: origin });
    if (turn?.status !== 'completed' || turn.session_id !== origin.turnSessionId
      || turn.request_id !== origin.turnRequestId || saved.stopReason !== 'end_turn') throw invalid();
    const expected = { status: 'confirmation_required', couponProposal: proposal,
      couponOrigin: origin };
    const hops = saved.hops?.filter(hop => hop?.tool === Contract.TOOL
      && hop.step === origin.invocationStep && !hop.error
      && hop.result?.isError !== true
      && isDeepStrictEqual(hop.params, { code: proposal.code })
      && hop.result?.content?.length === 1
      && hop.result.content[0]?.type === 'text'
      && isDeepStrictEqual(parse(hop.result.content[0].text), expected));
    if (hops?.length !== 1) throw invalid();
    const ids = meta?.traceEventIds;
    if (!Array.isArray(ids) || ids.length < 4 || ids.length > 4096
      || !ids.every(id => typeof id === 'string' && UUID.test(id))
      || new Set(ids).size !== ids.length
      || !Array.isArray(traces) || traces.length !== ids.length
      || !isDeepStrictEqual(traces.map(row => row.event_id), ids)
      || traces.some((row, index) => row.session_id !== origin.turnSessionId
        || index > 0 && Number(row.id) <= Number(traces[index - 1].id))) throw invalid();
    const decisions = traces.filter(row => row.kind === 'model_decision'
      && row.actor === 'supervisor' && row.step === origin.invocationStep
      && parse(row.params_json)?.decision === 'tool_use'
      && parse(row.params_json)?.toolCalls?.some(call => call.id === origin.callId));
    if (decisions.length !== 1) throw invalid();
    const decision = decisions[0], calls = parse(decision.params_json).toolCalls;
    if (calls.length !== 1 || calls[0].id !== origin.callId
      || calls[0].name !== Contract.TOOL
      || !isDeepStrictEqual(calls[0].args, { code: proposal.code })
      || !isQualifiedSecureShopModelTrace(decision, qualifyModel)) throw invalid();
    const callRows = traces.filter(row => row.kind === 'local_tool_call'
      && row.actor === 'supervisor→task' && row.step === origin.invocationStep
      && row.agent_ns === 'cart' && row.tool_name === 'coupon_prepare'
      && Number(row.id) > Number(decision.id)
      && isDeepStrictEqual(parse(row.params_json), { code: proposal.code }));
    if (callRows.length !== 1) throw invalid();
    const results = traces.filter(row => row.kind === 'local_tool_result'
      && row.actor === 'task→supervisor' && row.step === origin.invocationStep
      && row.agent_ns === 'cart' && row.tool_name === 'coupon_prepare'
      && Number(row.id) > Number(callRows[0].id)
      && isDeepStrictEqual(parse(row.result_json), hops[0].result));
    if (results.length !== 1) throw invalid();
    const terminal = traces.at(-1), terminalResult = parse(terminal?.result_json);
    if (traces.filter(row => row.kind === 'terminal').length !== 1
      || terminal?.kind !== 'terminal' || terminal.actor !== 'supervisor'
      || Number(terminal.id) <= Number(results[0].id)
      || terminal.step <= origin.invocationStep
      || terminal.provider !== decision.provider
      || terminalResult?.model !== parse(decision.result_json)?.model
      || terminalResult.stopReason !== 'end_turn'
      || terminalResult.steps !== saved.steps || terminalResult.hops !== saved.hops.length
      || !isQualifiedSecureShopModelTrace(terminal, qualifyModel)) throw invalid();
    selected = Object.freeze({ origin, proposal,
      traceEventIds: Object.freeze([...ids]), decisionEventId: decision.event_id,
      callEventId: callRows[0].event_id, resultEventId: results[0].event_id,
      terminalEventId: terminal.event_id });
  } catch { throw invalid(); }
  return selected;
}

function createCouponAgentProposalService({ readOriginal, assertCurrent, applyCoupon, qualifyModel } = {}) {
  if (typeof readOriginal !== 'function' || typeof assertCurrent !== 'function'
    || typeof applyCoupon !== 'function' || typeof qualifyModel !== 'function')
    throw new TypeError('Coupon proposal service dependencies required');
  return Object.freeze({
    prepare({ code, message, sourceOrigin } = {}) {
      const couponOrigin = Contract.origin(sourceOrigin);
      const couponProposal = Contract.prepare({ code, message, sourceOrigin: couponOrigin });
      return Object.freeze({ status: 'confirmation_required', couponProposal, couponOrigin });
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
      const result = await applyCoupon(trustedContext, Object.freeze({
        code: selected.proposal.code, operationId: selected.proposal.proposalId,
      }));
      await assertCurrent(trustedContext);
      return Object.freeze({ result, source: Object.freeze({
        sessionId: selected.origin.turnSessionId, requestId: selected.origin.turnRequestId,
        operationId: selected.proposal.proposalId, codeSha256: selected.proposal.codeSha256,
        traceEventIds: selected.traceEventIds, decisionEventId: selected.decisionEventId,
        callEventId: selected.callEventId,
        resultEventId: selected.resultEventId, terminalEventId: selected.terminalEventId,
      }) });
    },
  });
}

module.exports = { createCouponAgentProposalService, originalSelection };
