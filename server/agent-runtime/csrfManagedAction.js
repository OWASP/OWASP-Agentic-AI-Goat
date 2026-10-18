'use strict';

const { Annotation, StateGraph, START, END } = require('@langchain/langgraph');
const { createCsrfAgentDecisionCapability } = require('./csrfDecisionCapability');
const { applyCsrfSelectedEffect } = require('./csrfSelectedEffect');

function trustedModelIdentity(response) {
  const valid = value => typeof value === 'string' && value.trim().length > 0
    && !/mock|fixture|fallback|unavailable/i.test(value);
  return valid(response?.provider) && valid(response?.model)
    && response?.mocked !== true && response?.fallback !== true;
}

function managedDecisionModel(model) {
  return {
    ...model,
    chatWithTools: async (...args) => {
      const response = await model.chatWithTools(...args);
      if (trustedModelIdentity(response)) return response;
      // Let the existing strict decision parser fail closed without exposing
      // untrusted provider metadata to the capability authority.
      return { content: '{}', mocked: true };
    },
  };
}

async function graphBoundary(execution, node, operation) {
  execution.signal.throwIfAborted();
  await execution.check();
  await execution.trace?.({ node, type: 'node_start', data: {} });
  execution.signal.throwIfAborted();
  await execution.check();
  try {
    const result = await operation();
    await execution.trace?.({ node, type: 'node_end', data: {} });
    execution.signal.throwIfAborted();
    await execution.check();
    return result;
  } catch (error) {
    try { await execution.trace?.({ node, type: 'error', data: { errorCode: 'CSRF_MANAGED_NODE_FAILED' } }); } catch {}
    throw error;
  }
}

function createCsrfManagedAction({ model, sandboxMod, actions = sandboxMod?.ACTIONS,
  vectors = sandboxMod?.VECTORS, resolveObjectives = () => [], injectionPattern,
  guardedActions = new Set() } = {}) {
  if (!model || typeof model.chatWithTools !== 'function' || !sandboxMod
    || typeof sandboxMod.getOrCreateSandbox !== 'function' || !actions || !vectors
    || typeof resolveObjectives !== 'function' || !(injectionPattern instanceof RegExp)
    || injectionPattern.global || injectionPattern.sticky
    || !(guardedActions instanceof Set)) {
    throw new TypeError('Managed CSRF action dependencies required');
  }
  const authority = createCsrfAgentDecisionCapability();
  const decisionModel = managedDecisionModel(model);
  const ManagedState = Annotation.Root({ input: Annotation(), result: Annotation() });

  const classificationGraph = new StateGraph(ManagedState)
    .addNode('managed_classify', async state => ({ result: await graphBoundary(
      state.input.execution, 'managed_classify', async () => {
        const { execution, sessionId, tabId, message, document = null, chain = null,
          inputVector = null, gadgetDigest } = state.input;
        if (inputVector != null && !vectors[inputVector]) throw new TypeError('Invalid server-owned CSRF input vector');
        return authority.classify({ execution, sessionId, tabId, message, document, chain,
          inputVector, gadgetDigest, model: decisionModel, actions, vectors });
      }) }))
    .addEdge(START, 'managed_classify').addEdge('managed_classify', END).compile();

  const applicationGraph = new StateGraph(ManagedState)
    .addNode('managed_apply', async state => ({ result: await graphBoundary(
      state.input.execution, 'managed_apply', async () => {
        const { capability, execution, sessionId, tabId, message, document = null,
          chain = null, inputVector = null, gadgetDigest } = state.input;
        return authority.apply({ capability, execution, sessionId, tabId, message,
          document, chain, inputVector, gadgetDigest, applyEffect: async plan => {
            plan.signal.throwIfAborted();
            const sandbox = sandboxMod.getOrCreateSandbox(sessionId);
            if (!sandbox || typeof sandbox.flush !== 'function') {
              throw new TypeError('Persistent CSRF victim sandbox required');
            }
            const effect = await applyCsrfSelectedEffect({ sandbox, sandboxMod, tabId, message,
              document, chain, inputVector,
              selected: { intent: 'attack', action: plan.action, vector: plan.vector, params: plan.params },
              resolveObjectives, injectionPattern, guardedActions, requirePersistence: true, execution });
            return effect.result;
          } });
      }) }))
    .addEdge(START, 'managed_apply').addEdge('managed_apply', END).compile();

  async function classify(input) {
    return (await classificationGraph.invoke({ input }, { recursionLimit: 3 })).result;
  }

  async function apply(input) {
    return (await applicationGraph.invoke({ input }, { recursionLimit: 3 })).result;
  }

  return Object.freeze({ classify, apply });
}

module.exports = { createCsrfManagedAction };
