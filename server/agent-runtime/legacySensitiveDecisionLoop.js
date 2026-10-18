'use strict';

const { createHash } = require('node:crypto');
const { Annotation, StateGraph, START, END } = require('@langchain/langgraph');
const { stableJson, explicitlyUnqualified, DEFAULT_MAX_BYTES } = require('./decisionObserveGraph');

const DEFAULT_MAX_TOOL_CALLS = 3;

function invalid(code, message) {
  return Object.assign(new Error(message), { code });
}

function byteLength(value) {
  return Buffer.byteLength(stableJson(value));
}

function clone(value, code = 'DECISION_EVIDENCE_INVALID') {
  try { return structuredClone(value); } catch { throw invalid(code, 'Decision evidence is not cloneable'); }
}

function freezeTree(value) {
  if (!value || typeof value !== 'object' || Object.isFrozen(value)) return value;
  for (const item of Object.values(value)) freezeTree(item);
  return Object.freeze(value);
}

function bounded(value, maxBytes, code, message) {
  if (byteLength(value) > maxBytes) throw invalid(code, message);
  return value;
}

function callIdentity(execution, decision, ordinal, previousHopDigest = null) {
  const decisionDigest = createHash('sha256').update(stableJson(decision)).digest('hex');
  const binding = stableJson({
    ownerKey: execution.ownerKey,
    runId: execution.runId,
    generation: String(execution.durableGeneration),
    ordinal,
    previousHopDigest,
    decisionDigest,
  });
  const callId = createHash('sha256').update(binding).digest('hex').slice(0, 32);
  return freezeTree({
    ordinal,
    callId,
    decisionDigest,
    previousHopDigest,
    effectKey: `legacy-sensitive:${ordinal}:${callId}:${decisionDigest}`,
  });
}

function parsedDecision(value) {
  if (!value || Object.getPrototypeOf(value) !== Object.prototype
      || typeof value.action !== 'string'
      || !value.params || Object.getPrototypeOf(value.params) !== Object.prototype) {
    throw invalid('MODEL_DECISION_INVALID', 'Model decision does not match an allowed action');
  }
  if (value.action === 'finish' && Object.keys(value.params).length !== 0) {
    throw invalid('MODEL_DECISION_INVALID', 'Finish does not accept arguments');
  }
  return freezeTree({ action: value.action, params: clone(value.params, 'MODEL_DECISION_INVALID') });
}

function receiptMatches(receipt, execution, identity) {
  return Boolean(receipt)
    && receipt.status === 'completed'
    && receipt.runId === execution.runId
    && receipt.ownerKey === execution.ownerKey
    && String(receipt.generation) === String(execution.durableGeneration)
    && typeof receipt.effectKey === 'string'
    && receipt.effectKey.endsWith(`:${identity.effectKey}`);
}

async function runLegacySensitiveDecisionLoop({
  request,
  execution,
  decide,
  validateDecision,
  executeDecision,
  respond,
  qualifyModel = () => false,
  maxBytes = DEFAULT_MAX_BYTES,
  maxToolCalls = DEFAULT_MAX_TOOL_CALLS,
} = {}) {
  if (typeof request !== 'string' || !request.trim()) {
    throw invalid('DECISION_REQUEST_INVALID', 'A request is required');
  }
  if (![decide, validateDecision, executeDecision, respond].every(value => typeof value === 'function')) {
    throw new TypeError('Decision, validation, execution, and response functions are required');
  }
  if (typeof execution?.check !== 'function' || typeof execution?.effectWithReceipt !== 'function') {
    throw invalid('DECISION_EXECUTION_REQUIRED', 'Durable owner execution is required');
  }
  if (!Number.isInteger(maxBytes) || maxBytes < 1024 || maxBytes > DEFAULT_MAX_BYTES) {
    throw new RangeError('Decision/observation byte limit is invalid');
  }
  if (!Number.isInteger(maxToolCalls) || maxToolCalls < 1 || maxToolCalls > DEFAULT_MAX_TOOL_CALLS) {
    throw new RangeError('Legacy Sensitive tool-call limit is invalid');
  }
  bounded(request, maxBytes, 'DECISION_REQUEST_TOO_LARGE', 'The request is too large');

  const check = () => execution.check();
  const emit = (type, node, data = {}) => execution.trace?.({ type, node, data });
  const node = (name, operation) => async state => {
    await check();
    await emit('node_start', name, { attempt: state.decisions?.length || 0, toolSteps: state.trajectory?.length || 0 });
    try {
      const next = await operation(state);
      await check();
      await emit('node_end', name, { attempt: next.decisions?.length ?? state.decisions?.length ?? 0,
        toolSteps: next.trajectory?.length ?? state.trajectory?.length ?? 0 });
      return next;
    } catch (error) {
      await emit('error', name, { errorCode: error.code || error.name || 'LEGACY_SENSITIVE_LOOP_FAILED' });
      throw error;
    }
  };

  const State = Annotation.Root({
    candidate: Annotation(),
    decisions: Annotation(),
    decision: Annotation(),
    identity: Annotation(),
    pendingObserved: Annotation(),
    trajectory: Annotation(),
    finishDecision: Annotation(),
    terminal: Annotation(),
    next: Annotation(),
    result: Annotation(),
  });

  const graph = new StateGraph(State)
    .addNode('decide', node('decide', async state => {
      bounded({ request, decisions: state.decisions, trajectory: state.trajectory }, maxBytes,
        'DECISION_EVIDENCE_TOO_LARGE', 'Decision trajectory is too large');
      const candidate = await decide({
        request,
        decisions: state.decisions,
        trajectory: state.trajectory,
        toolCallsRemaining: maxToolCalls - state.trajectory.length,
        signal: execution.signal,
      });
      if (!candidate) throw invalid('MODEL_DECISION_INVALID', 'Model decision is missing');
      bounded(candidate, maxBytes, 'MODEL_DECISION_INVALID', 'Model decision is too large');
      const qualified = !explicitlyUnqualified(candidate)
        && qualifyModel({ phase: 'decision', result: candidate }) === true;
      const modelResult = freezeTree(clone(candidate, 'MODEL_DECISION_INVALID'));
      const record = freezeTree({ ordinal: state.decisions.length + 1, qualified, modelResult, decision: null });
      const decisions = freezeTree([...state.decisions, record]);
      bounded(decisions, maxBytes, 'DECISION_EVIDENCE_TOO_LARGE', 'Decision history is too large');
      await emit('decision', 'decide', { attempt: record.ordinal,
        decisionSource: qualified ? 'qualified_model' : 'unqualified',
        ...(qualified ? { provider: candidate.provider, model: candidate.model } : {}) });
      return {
        candidate: modelResult,
        decisions,
        next: qualified ? 'validate' : 'finish',
        result: qualified ? null : freezeTree({ status: 'unqualified_model', qualified: false,
          decisionQualified: false, responseQualified: false }),
      };
    }))
    .addNode('validate', node('validate', state => {
      const decision = parsedDecision(validateDecision(state.candidate, {
        request,
        decisions: state.decisions,
        trajectory: state.trajectory,
      }));
      bounded(decision, maxBytes, 'MODEL_DECISION_INVALID', 'Model decision is too large');
      const records = [...state.decisions];
      records[records.length - 1] = freezeTree({ ...records.at(-1), decision });
      const decisions = freezeTree(records);
      bounded(decisions, maxBytes, 'DECISION_EVIDENCE_TOO_LARGE', 'Decision history is too large');
      if (decision.action === 'finish') {
        return { decision, decisions, finishDecision: decision, next: 'respond' };
      }
      if (state.trajectory.length >= maxToolCalls) {
        return { decision, decisions, next: 'finish', result: freezeTree({ status: 'step_limit',
          qualified: false, decisionQualified: false, responseQualified: false }) };
      }
      const previousHopDigest = state.trajectory.at(-1)?.hopDigest || null;
      return { decision, decisions,
        identity: callIdentity(execution, decision, state.trajectory.length + 1, previousHopDigest),
        next: 'execute' };
    }))
    .addNode('execute', node('execute', async state => {
      const completed = await execution.effectWithReceipt(state.identity.effectKey, async () => {
        await check();
        const value = await executeDecision({ ...state.decision, callId: state.identity.callId,
          ordinal: state.identity.ordinal, signal: execution.signal });
        await check();
        return value;
      });
      if (!receiptMatches(completed?.receipt, execution, state.identity)) {
        throw invalid('EFFECT_RECEIPT_INVALID', 'The selected tool effect lacks a durable receipt');
      }
      bounded(completed.value, maxBytes, 'TOOL_OBSERVATION_TOO_LARGE', 'Tool observation is too large');
      return { pendingObserved: freezeTree({
        value: clone(completed.value, 'TOOL_OBSERVATION_INVALID'),
        receipt: clone(completed.receipt, 'EFFECT_RECEIPT_INVALID'),
      }) };
    }))
    .addNode('record_observation', node('record_observation', state => {
      const hopCore = {
        ordinal: state.identity.ordinal,
        callId: state.identity.callId,
        decision: state.decision,
        decisionQualified: true,
        decisionDigest: state.identity.decisionDigest,
        previousHopDigest: state.identity.previousHopDigest,
        effectReceipt: state.pendingObserved.receipt,
        observation: state.pendingObserved.value,
        modelDecision: state.candidate,
      };
      const hopDigest = createHash('sha256').update(stableJson(hopCore)).digest('hex');
      const hop = freezeTree({ ...hopCore, hopDigest });
      const trajectory = freezeTree([...state.trajectory, hop]);
      bounded(trajectory, maxBytes, 'DECISION_EVIDENCE_TOO_LARGE', 'Decision trajectory is too large');
      return { trajectory, pendingObserved: null, next: 'decide' };
    }))
    .addNode('respond', node('respond', async state => {
      const selected = state.trajectory.at(-1) || null;
      bounded({ request, decisions: state.decisions, trajectory: state.trajectory }, maxBytes,
        'DECISION_EVIDENCE_TOO_LARGE', 'Decision trajectory is too large');
      const terminal = await respond({
        request,
        decision: selected?.decision || null,
        finishDecision: state.finishDecision,
        callId: selected?.callId || null,
        observation: selected?.observation || null,
        decisions: state.decisions,
        trajectory: state.trajectory,
        signal: execution.signal,
      });
      if (!terminal) throw invalid('MODEL_RESPONSE_INVALID', 'Model response is missing');
      bounded(terminal, maxBytes, 'MODEL_RESPONSE_INVALID', 'Model response is too large');
      const qualified = !explicitlyUnqualified(terminal)
        && qualifyModel({ phase: 'response', result: terminal }) === true;
      const response = typeof terminal.response === 'string' ? terminal.response.trim() : '';
      const responseQualified = qualified && Boolean(response);
      return {
        terminal: freezeTree(clone(terminal, 'MODEL_RESPONSE_INVALID')),
        result: freezeTree({
          status: responseQualified ? (selected ? 'completed' : 'no_operation') : 'unqualified_response',
          qualified: responseQualified,
          decisionQualified: true,
          responseQualified,
          response,
        }),
      };
    }))
    .addNode('finish', node('finish', async state => {
      const selected = state.trajectory.at(-1) || null;
      const aggregate = {
        request,
        decisions: state.decisions,
        trajectory: state.trajectory,
        finishDecision: state.finishDecision || null,
        modelResponse: state.terminal || null,
      };
      bounded(aggregate, maxBytes, 'DECISION_EVIDENCE_TOO_LARGE', 'Decision evidence is too large');
      const terminalDigest = state.terminal
        ? createHash('sha256').update(stableJson({ selectedHopDigest: selected?.hopDigest || null,
          response: state.terminal?.response || '' })).digest('hex')
        : null;
      const result = freezeTree({
        ...state.result,
        ...aggregate,
        decisionQualified: selected?.decisionQualified === true
          ? true : state.result?.decisionQualified === true,
        decision: selected?.decision || null,
        observation: selected?.observation || null,
        modelDecision: selected?.modelDecision || null,
        callId: selected?.callId || null,
        decisionDigest: selected?.decisionDigest || null,
        hopDigest: selected?.hopDigest || null,
        terminalDigest,
        effectReceipt: selected?.effectReceipt || null,
      });
      await emit('decision', 'finish', { toolSteps: state.trajectory.length,
        terminationReason: result.status === 'step_limit' ? 'tool_budget'
          : result.qualified ? 'model_finished' : 'decision_unavailable' });
      return { result };
    }))
    .addEdge(START, 'decide')
    .addConditionalEdges('decide', state => state.next, ['validate', 'finish'])
    .addConditionalEdges('validate', state => state.next, ['execute', 'respond', 'finish'])
    .addEdge('execute', 'record_observation')
    .addEdge('record_observation', 'decide')
    .addEdge('respond', 'finish')
    .addEdge('finish', END)
    .compile();

  const result = await graph.invoke({
    candidate: null,
    decisions: freezeTree([]),
    decision: null,
    identity: null,
    pendingObserved: null,
    trajectory: freezeTree([]),
    finishDecision: null,
    terminal: null,
    next: null,
    result: null,
  }, { recursionLimit: maxToolCalls * 5 + 8, signal: execution.signal });
  return result.result;
}

module.exports = {
  runLegacySensitiveDecisionLoop,
  callIdentity,
  DEFAULT_MAX_TOOL_CALLS,
};
