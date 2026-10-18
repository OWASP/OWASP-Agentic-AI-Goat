'use strict';

const { Annotation, StateGraph, START, END } = require('@langchain/langgraph');
const { createHash } = require('node:crypto');

const DEFAULT_MAX_BYTES = 65536;

function stableJson(value) {
  if (Array.isArray(value)) return `[${value.map(stableJson).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${stableJson(value[key])}`).join(',')}}`;
  }
  const encoded = JSON.stringify(value);
  return encoded === undefined ? 'null' : encoded;
}

function byteLength(value) {
  return Buffer.byteLength(stableJson(value));
}

function invalid(code, message) {
  return Object.assign(new Error(message), { code });
}

function explicitlyUnqualified(result) {
  return !result || result.mocked === true || result.fallback === true || result._error
    || result.payloadSelection === 'scripted' || result.decisionSource === 'scripted';
}

function callIdentity(execution, decision) {
  const decisionDigest = createHash('sha256').update(stableJson(decision)).digest('hex');
  const callId = createHash('sha256')
    .update(`${execution?.runId || 'unbound'}:${decisionDigest}`)
    .digest('hex').slice(0, 32);
  return Object.freeze({ callId, decisionDigest,
    effectKey: `legacy-sensitive:${callId}:${decisionDigest}` });
}

async function runDecisionObserveGraph({
  request,
  execution,
  decide,
  validateDecision,
  executeDecision,
  respond,
  qualifyModel = () => false,
  maxBytes = DEFAULT_MAX_BYTES,
} = {}) {
  if (typeof request !== 'string' || !request.trim()) throw invalid('DECISION_REQUEST_INVALID', 'A request is required');
  if (![decide, validateDecision, executeDecision, respond].every(value => typeof value === 'function')) {
    throw new TypeError('Decision, validation, execution, and response functions are required');
  }
  if (typeof execution?.check !== 'function' || typeof execution?.effectWithReceipt !== 'function') {
    throw invalid('DECISION_EXECUTION_REQUIRED', 'Durable owner execution is required');
  }
  if (!Number.isInteger(maxBytes) || maxBytes < 1024 || maxBytes > DEFAULT_MAX_BYTES) {
    throw new RangeError('Decision/observation byte limit is invalid');
  }
  const check = () => execution.check();
  const emit = (type, node, data = {}) => execution.trace?.({ type, node, data });
  const node = (name, operation) => async state => {
    await check(); await emit('node_start', name);
    try {
      const next = await operation(state);
      await check(); await emit('node_end', name);
      return next;
    } catch (error) {
      await emit('error', name, { errorCode: error.code || error.name || 'DECISION_GRAPH_FAILED' });
      throw error;
    }
  };
  const State = Annotation.Root({ candidate: Annotation(), decision: Annotation(), identity: Annotation(),
    observed: Annotation(), terminal: Annotation(), result: Annotation() });
  const graph = new StateGraph(State)
    .addNode('decide', node('decide', async () => {
      const candidate = await decide({ request, signal: execution.signal });
      if (!candidate || byteLength(candidate) > maxBytes) throw invalid('MODEL_DECISION_INVALID', 'Model decision is missing or too large');
      const qualified = !explicitlyUnqualified(candidate)
        && qualifyModel({ phase: 'decision', result: candidate }) === true;
      await emit('decision', 'decide', { decisionSource: qualified ? 'qualified_model' : 'unqualified' });
      return { candidate, result: qualified ? null : Object.freeze({ status: 'unqualified_model',
        qualified: false, decisionQualified: false, responseQualified: false }) };
    }))
    .addNode('validate', node('validate', state => {
      const decision = validateDecision(state.candidate);
      if (!decision || typeof decision.action !== 'string' || !decision.params || typeof decision.params !== 'object') {
        throw invalid('MODEL_DECISION_INVALID', 'Model decision does not match an allowed tool');
      }
      if (byteLength(decision) > maxBytes) throw invalid('MODEL_DECISION_INVALID', 'Model decision is too large');
      const identity = callIdentity(execution, decision);
      return { decision: Object.freeze({ action: decision.action, params: structuredClone(decision.params) }), identity };
    }))
    .addNode('execute', node('execute', async state => {
      const completed = await execution.effectWithReceipt(state.identity.effectKey,
        () => executeDecision({ ...state.decision, callId: state.identity.callId, signal: execution.signal }));
      if (!completed?.receipt || completed.receipt.status !== 'completed'
          || completed.receipt.runId !== execution.runId
          || completed.receipt.ownerKey !== execution.ownerKey
          || String(completed.receipt.generation) !== String(execution.durableGeneration)
          || typeof completed.receipt.effectKey !== 'string'
          || !completed.receipt.effectKey.endsWith(`:${state.identity.effectKey}`)) {
        throw invalid('EFFECT_RECEIPT_INVALID', 'The selected tool effect lacks a durable receipt');
      }
      if (byteLength(completed.value) > maxBytes) throw invalid('TOOL_OBSERVATION_TOO_LARGE', 'Tool observation is too large');
      return { observed: Object.freeze({ value: structuredClone(completed.value), receipt: structuredClone(completed.receipt) }) };
    }))
    .addNode('observe', node('observe', async state => {
      const terminal = await respond({ request, decision: state.decision, callId: state.identity.callId,
        observation: state.observed.value, signal: execution.signal });
      if (!terminal || byteLength(terminal) > maxBytes) throw invalid('MODEL_RESPONSE_INVALID', 'Model response is missing or too large');
      const qualified = !explicitlyUnqualified(terminal)
        && qualifyModel({ phase: 'response', result: terminal }) === true;
      const response = typeof terminal.response === 'string' ? terminal.response.trim() : '';
      return { terminal, result: Object.freeze({ status: qualified && response ? 'completed' : 'unqualified_response',
        qualified: qualified && Boolean(response), decisionQualified: true,
        responseQualified: qualified && Boolean(response), response }) };
    }))
    .addNode('finish', node('finish', state => {
      const aggregate = { decision: state.decision || null, observation: state.observed?.value || null,
        modelDecision: state.candidate || null, modelResponse: state.terminal || null };
      if (byteLength(aggregate) > maxBytes) throw invalid('DECISION_EVIDENCE_TOO_LARGE', 'Decision evidence is too large');
      const hopDigest = state.identity && state.observed && state.terminal
        ? createHash('sha256').update(stableJson({ decisionDigest: state.identity.decisionDigest,
          effectKey: state.observed.receipt.effectKey, observation: state.observed.value,
          response: state.terminal.response || '' })).digest('hex') : null;
      return { result: Object.freeze({
        ...state.result, ...aggregate,
        callId: state.identity?.callId || null,
        decisionDigest: state.identity?.decisionDigest || null,
        hopDigest,
        effectReceipt: state.observed?.receipt || null,
      }) };
    }))
    .addEdge(START, 'decide')
    .addConditionalEdges('decide', state => state.result ? 'finish' : 'validate', ['finish', 'validate'])
    .addEdge('validate', 'execute')
    .addEdge('execute', 'observe')
    .addEdge('observe', 'finish')
    .addEdge('finish', END)
    .compile();
  return (await graph.invoke({}, { recursionLimit: 12, signal: execution.signal })).result;
}

module.exports = { runDecisionObserveGraph, stableJson, callIdentity, DEFAULT_MAX_BYTES, explicitlyUnqualified };
