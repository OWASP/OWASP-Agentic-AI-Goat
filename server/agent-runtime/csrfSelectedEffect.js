'use strict';

// Authority acquisition belongs to the trusted execution, never selected tool args.
// Checks stay outside the lease: the capability owns its transaction validation.
async function withCsrfTeachingEffect(execution, sandbox, work) {
  const lease = execution?.withTeachingEffect;
  if (lease !== undefined && typeof lease !== 'function') throw new TypeError('Invalid teaching effect capability');
  if (lease && typeof sandbox?.flush !== 'function') throw new TypeError('Persistent teaching effect required');
  await execution?.check?.();
  const result = lease ? await lease.call(execution, work) : await work();
  await execution?.check?.();
  return result;
}

async function applyCsrfSelectedEffect({ sandbox, sandboxMod, tabId, message,
  document = null, chain = null, inputVector = null, selected, resolveObjectives,
  injectionPattern, guardedActions, requirePersistence = false, execution, mode='vuln', assertMode } = {}) {
  if (!sandbox || typeof sandbox.tab !== 'function' || typeof sandbox.forge !== 'function'
    || typeof sandbox.getTabState !== 'function' || !sandboxMod?.ACTIONS || !sandboxMod?.VECTORS
    || !selected || selected.intent !== 'attack' || !sandboxMod.ACTIONS[selected.action]
    || !selected.params || typeof selected.params !== 'object' || Array.isArray(selected.params)
    || typeof resolveObjectives !== 'function' || !(injectionPattern instanceof RegExp)
    || injectionPattern.global || injectionPattern.sticky || !(guardedActions instanceof Set)
    || (requirePersistence && typeof sandbox.flush !== 'function') || !['vuln','fixed'].includes(mode)) {
    throw new TypeError('Selected CSRF effect dependencies required');
  }
  if (inputVector != null && !sandboxMod.VECTORS[inputVector]) {
    throw new TypeError('Invalid server-owned CSRF input vector');
  }
  await assertMode?.();
  return withCsrfTeachingEffect(execution, sandbox, async () => {
  const tab = sandbox.tab(tabId);
  const defensesOn = tab.defenses.csrfToken === true;
  if(mode==='fixed'){
    const vector=document?'indirect':inputVector||selected.vector;
    if(!sandboxMod.VECTORS[vector])throw new TypeError('Invalid selected CSRF vector');
    const refused={kind:'attack',refused:true,blocked:true,executed:false,stateChanged:false,vector,
      vectorLabel:sandboxMod.VECTORS[vector].label,action:selected.action,
      actionLabel:sandboxMod.ACTIONS[selected.action].label,
      outcome:'Fixed mode refused the untrusted instruction; no victim action was executed.',fixedPolicy:true,
      defenses:{...tab.defenses}};
    return {refused:true,phraseMessage:null,phraseResult:refused,
      result:{intent:'attack',vector,action:selected.action,toolResult:refused,objectivesHit:[],victimState:sandbox.getTabState(tabId)}};
  }

  if (document) {
    const result = sandbox.forge(tabId, 'indirect', selected.action, selected.params);
    await sandbox.flush?.();
    const objectivesHit = resolveObjectives(tabId, {
      vector: 'indirect', blocked: result.blocked, defensesOn, isDocument: true,
    });
    return { refused: false, phraseMessage: `[poisoned document] ${document}`, phraseResult: result,
      result: { intent: 'attack', vector: 'indirect', action: selected.action,
        toolResult: { kind: 'attack', ...result }, objectivesHit,
        victimState: sandbox.getTabState(tabId) } };
  }

  const vector = inputVector || selected.vector;
  if (!sandboxMod.VECTORS[vector]) throw new TypeError('Invalid selected CSRF vector');
  const injected = injectionPattern.test(String(message));
  if (tabId === 'indirect' && guardedActions.has(selected.action) && !injected) {
    const refused = { kind: 'attack', refused: true, blocked: false, vector,
      vectorLabel: sandboxMod.VECTORS[vector]?.label, action: selected.action,
      actionLabel: sandboxMod.ACTIONS[selected.action]?.label,
      outcome: 'Agent policy refused a guarded action without an override.' };
    return { refused: true, phraseMessage: null, phraseResult: refused,
      result: { intent: 'attack', vector, action: selected.action,
        toolResult: refused, objectivesHit: [], victimState: sandbox.getTabState(tabId) } };
  }

  const observedVector = tabId === 'indirect' && injected ? 'agentic' : vector;
  const result = sandbox.forge(tabId, observedVector, selected.action, selected.params);
  let appliedChain = null;
  if (tabId === 'xss' && chain) {
    appliedChain = String(chain).split(',').map(value => value.trim())
      .filter(action => sandboxMod.ACTIONS[action] && action !== selected.action)
      .map(action => sandbox.forge(tabId, 'xss', action, {}));
    if (appliedChain.length) result.chain = appliedChain;
  }
  await sandbox.flush?.();
  const objectivesHit = resolveObjectives(tabId, {
    vector: observedVector, blocked: result.blocked, defensesOn, injected,
    isDocument: false, chainCount: 1 + (appliedChain ? appliedChain.length : 0),
  });
  return { refused: false, phraseMessage: message, phraseResult: result,
    result: { intent: 'attack', vector: observedVector, action: selected.action,
      toolResult: { kind: 'attack', ...result }, objectivesHit,
      victimState: sandbox.getTabState(tabId) } };
  });
}

module.exports = { applyCsrfSelectedEffect, withCsrfTeachingEffect };
