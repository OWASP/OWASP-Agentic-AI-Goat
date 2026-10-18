'use strict';
const { isDeepStrictEqual } = require('node:util');
const MAX_INPUT_BYTES = 2 * 1024 * 1024;
const MAX_INPUT_NODES = 50000;
function json(value) { try { return JSON.parse(value); } catch { return null; } }
function inputSize(values) {
  let bytes = 0, nodes = 0;
  const seen = new Set();
  function visit(value, depth) {
    if (++nodes > MAX_INPUT_NODES || depth > 20) throw new TypeError('Bound turn evidence exceeds limits');
    if (typeof value === 'string') bytes += Buffer.byteLength(value);
    else if (value == null || typeof value === 'boolean' || typeof value === 'number') bytes += 8;
    else if (typeof value !== 'object' || seen.has(value)) throw new TypeError('Bound turn evidence must be plain JSON');
    else {
      const prototype = Object.getPrototypeOf(value);
      if (prototype !== Object.prototype && prototype !== Array.prototype && prototype !== null) {
        throw new TypeError('Bound turn evidence must be plain JSON');
      }
      seen.add(value);
      for (const key of Object.keys(value)) {
        const descriptor = Object.getOwnPropertyDescriptor(value,key);
        if (!descriptor || !Object.hasOwn(descriptor,'value')) throw new TypeError('Bound turn evidence accessors are unsupported');
        bytes += Buffer.byteLength(key) + 4;
        if (bytes > MAX_INPUT_BYTES) throw new TypeError('Bound turn evidence exceeds limits');
        visit(descriptor.value,depth + 1);
      }
      seen.delete(value);
    }
    if (bytes > MAX_INPUT_BYTES) throw new TypeError('Bound turn evidence exceeds limits');
  }
  visit(values,0);
}
const { isQualifiedSecureShopModelTrace: realModel } = require('./secureshopRealModelTrace');

// Only call with the bound runner's private per-turn observations and persisted
// trace capture. Public hop DTOs and learner JSON are not this API's input.
function buildSecureShopLoopEvidence({ execution, sessionId, requestId, traces, observations, result,
  qualifyModelTrace } = {}) {
  if (!Array.isArray(traces) || traces.length > 4096 || !Array.isArray(observations)
      || observations.length > 256 || typeof requestId !== 'string' || !requestId
      || requestId.length > 128) throw new TypeError('Bound turn evidence required');
  inputSize([traces,observations,result]);
  const ids = new Set();
  const validTrace = traces.every(row => row?.session_id === sessionId
    && typeof row.event_id === 'string' && row.event_id.length > 0
    && !ids.has(row.event_id) && Boolean(ids.add(row.event_id)));
  const terminalRows = validTrace ? traces.filter(row => row.kind === 'terminal') : [];
  const terminal = terminalRows.length === 1 && traces.at(-1) === terminalRows[0]
    && terminalRows[0].actor === 'supervisor'
    && realModel(terminalRows[0],qualifyModelTrace)
    && json(terminalRows[0].result_json)?.stopReason === 'end_turn'
    ? terminalRows[0] : null;
  const terminalMeta = terminal && json(terminal.result_json);
  const terminalMatchesResult = Boolean(terminal && result?.stopReason === 'end_turn'
    && Number.isInteger(result.steps) && terminalMeta.steps === result.steps
    && Array.isArray(result.hops) && terminalMeta.hops === result.hops.length);
  let chain = null;
  if (validTrace && terminalMatchesResult) {
    for (const observation of observations) {
      const receipt = observation?.effectReceipt;
      const expectedEffectKey = `${requestId}:${JSON.stringify([
        observation?.step,observation?.callId,observation?.tool])}`;
      if (!receipt || receipt.version !== 1 || receipt.status !== 'completed'
          || receipt.effectKey !== expectedEffectKey
          || !execution?.runId || !execution.ownerKey || execution.durableGeneration == null
          || receipt.runId !== execution.runId || receipt.ownerKey !== execution.ownerKey
          || receipt.generation !== String(execution.durableGeneration)
          || observation.result?.isError === true) continue;
      const selectedIndex = traces.findIndex(row => row.kind === 'model_decision' && row.actor === 'supervisor'
        && row.step === observation.step && realModel(row,qualifyModelTrace)
        && json(row.params_json)?.decision === 'tool_use'
        && json(row.params_json)?.toolCalls?.some(call => call.id === observation.callId
          && call.name === observation.tool && isDeepStrictEqual(call.args, observation.args)));
      if (selectedIndex < 0) continue;
      const observedIndex = traces.findIndex((row, index) => index > selectedIndex
        && row.kind === 'local_tool_result' && row.step === observation.step
        && row.actor === 'task→supervisor'
        && `${row.agent_ns}.${row.tool_name}` === observation.tool
        && isDeepStrictEqual(json(row.result_json), observation.result));
      const nextIndex = traces.findIndex((row, index) => index > observedIndex && observedIndex >= 0
        && row.kind === 'model_decision' && row.actor === 'supervisor'
        && row.step > observation.step && realModel(row,qualifyModelTrace));
      if (nextIndex < 0 || traces.indexOf(terminal) <= nextIndex) continue;
      chain = { selected: traces[selectedIndex], observation: traces[observedIndex],
        next: traces[nextIndex], terminal, receipt };
      break;
    }
  }
  return { facts: { persisted_turn_trace: validTrace, completed_real_model_turn: Boolean(terminal)
    && terminalMatchesResult, observed_decision_loop: chain !== null },
  evidence: [{ id: 'agent_loop', source: 'server_observation', content: chain || {
    outcome: 'No complete real model decision, receipted tool observation and subsequent decision chain was verified.' },
  }] };
}
module.exports = { buildSecureShopLoopEvidence, MAX_INPUT_BYTES };
