'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { createCsrfAgentDecisionCapability } = require('../server/agent-runtime/csrfDecisionCapability');

const DIGEST = 'a'.repeat(64);
const ACTIONS = { change_email: { label: 'Change email' }, disable_mfa: { label: 'Disable MFA' } };
const VECTORS = { xss: { label: 'XSS' }, indirect: { label: 'Indirect' }, agentic: { label: 'Agentic' } };

function owner(overrides = {}) {
  const controller = new AbortController();
  return { ownerKey: '["CSRF","7"]', runId: '11111111-1111-4111-8111-111111111111', generation: 4,
    durableGeneration: '9',
    signal: controller.signal, check: async () => controller.signal.throwIfAborted(), trace: async () => {},
    controller, ...overrides };
}

function model(value, response = {}) {
  return { provider: 'ollama', async chatWithTools(_messages, _tools, options) {
    assert.equal(options.temperature, 0);
    assert.equal(options.signal instanceof AbortSignal, true);
    return { content: JSON.stringify(value), provider: 'ollama', model: 'controlled-structured', ...response };
  } };
}

function decision(overrides = {}) {
  return { intent: 'attack', action: 'change_email', vector: 'xss', defenseOn: false,
    params: { email: 'learner@example.test' }, ...overrides };
}

function proposed(overrides = {}) {
  return { sessionId: 'csrf_7', tabId: 'xss', message: 'change email to "learner@example.test"',
    document: null, chain: 'disable_mfa', gadgetDigest: DIGEST, ...overrides };
}

async function issued({ execution = owner(), selected = decision(), proposedFields = {} } = {}) {
  const authority = createCsrfAgentDecisionCapability();
  const capability = await authority.classify({ execution, ...proposed(proposedFields),
    model: model(selected), actions: ACTIONS, vectors: VECTORS });
  return { authority, capability, execution };
}

test('actual structured selection issues opaque one-use authority and applies without narration', async () => {
  const { authority, capability, execution } = await issued();
  assert.ok(capability);
  assert.deepEqual(Object.keys(capability), []);
  assert.equal(JSON.stringify(capability), '{}');
  let effects = 0;
  const result = await authority.apply({ capability, execution, ...proposed(), applyEffect: async plan => {
    effects++;
    assert.deepEqual({ action: plan.action, vector: plan.vector, params: plan.params }, {
      action: 'change_email', vector: 'xss', params: { email: 'learner@example.test' } });
    assert.equal(typeof plan.signal.addEventListener, 'function');
    return { persisted: true, vector: 'agentic' };
  } });
  assert.deepEqual(result, { persisted: true, vector: 'agentic' }, 'post-effect vector is not rewritten');
  assert.equal(effects, 1);
  await assert.rejects(authority.apply({ capability, execution, ...proposed(), applyEffect: async () => ({}) }),
    /capability unavailable/);
});

test('copied, foreign, stale and mismatched authorities cannot start an effect', async () => {
  const mismatchCases = [
    { apply: { capabilityCopy: true }, error: /capability unavailable/ },
    { execution: owner({ ownerKey: '["CSRF","8"]' }), error: /binding mismatch/ },
    { execution: owner({ runId: '22222222-2222-4222-8222-222222222222' }), error: /binding mismatch/ },
    { execution: owner({ generation: 5 }), error: /binding mismatch/ },
    { execution: owner({ durableGeneration: '10' }), error: /binding mismatch/ },
    { execution: owner({ durableGeneration: undefined }), error: /Durable generation required/ },
    { fields: { sessionId: 'csrf_8' }, error: /binding mismatch/ },
    { fields: { tabId: 'indirect' }, error: /binding mismatch/ },
    { fields: { message: 'different request' }, error: /binding mismatch/ },
    { fields: { document: 'different document' }, error: /binding mismatch/ },
    { fields: { chain: 'promote_role' }, error: /binding mismatch/ },
    { fields: { inputVector: 'indirect' }, error: /binding mismatch/ },
    { fields: { gadgetDigest: 'b'.repeat(64) }, error: /binding mismatch/ },
  ];
  for (const item of mismatchCases) {
    const { authority, capability, execution } = await issued();
    let effects = 0;
    const target = item.apply?.capabilityCopy ? { ...capability } : capability;
    await assert.rejects(authority.apply({ capability: target, execution: item.execution || execution,
      ...proposed(item.fields), applyEffect: async () => { effects++; } }), item.error);
    assert.equal(effects, 0);
  }
});

test('authority remains bound to the originating execution and its factory', async () => {
  let originalCurrent = true;
  const original = owner({ check: async () => {
    if (!originalCurrent) throw Object.assign(new Error('origin reset'), { name: 'AbortError' });
  } });
  const { authority, capability } = await issued({ execution: original });
  const substitute = owner();
  originalCurrent = false;
  let effects = 0;
  await assert.rejects(authority.apply({ capability, execution: substitute, ...proposed(),
    applyEffect: async () => { effects++; } }), /origin reset/);
  assert.equal(effects, 0, 'a same-tuple substitute cannot bypass the originating lease');

  const fresh = await issued();
  await assert.rejects(createCsrfAgentDecisionCapability().apply({ capability: fresh.capability,
    execution: fresh.execution, ...proposed(), applyEffect: async () => { effects++; } }),
  /capability unavailable/);
  assert.equal(effects, 0);
});

test('controlled fixtures may omit durable generation only when both sides omit it', async () => {
  const execution = owner({ durableGeneration: undefined });
  await assert.rejects(createCsrfAgentDecisionCapability().classify({ execution, ...proposed(),
    model: model(decision()), actions: ACTIONS, vectors: VECTORS }), /Durable generation required/);
  const authority = createCsrfAgentDecisionCapability({ allowMissingDurableGeneration: true });
  const capability = await authority.classify({ execution, ...proposed(),
    model: model(decision()), actions: ACTIONS, vectors: VECTORS });
  const result = await authority.apply({ capability, execution: owner({ durableGeneration: undefined }),
    ...proposed(), applyEffect: async () => ({ completed: true }) });
  assert.deepEqual(result, { completed: true });
});

test('fallback, mock, unavailable and non-attack decisions never issue authority', async () => {
  const authority = createCsrfAgentDecisionCapability();
  for (const candidate of [
    { selected: decision(), response: { fallback: true } },
    { selected: decision(), response: { mocked: true } },
    { selected: decision({ intent: 'none', action: 'none', vector: 'none', params: {} }) },
  ]) {
    const capability = await authority.classify({ execution: owner(), ...proposed(),
      model: model(candidate.selected, candidate.response), actions: ACTIONS, vectors: VECTORS });
    assert.equal(capability, null);
  }
  await assert.rejects(authority.classify({ execution: owner(), ...proposed(),
    model: { ...model(decision()), provider: 'mock' }, actions: ACTIONS, vectors: VECTORS }),
  /Actual structured/);
});

test('failed persistence preserves the primary error and consumes uncertain authority', async () => {
  const execution = owner({ trace: async event => {
    if (event.type === 'decision' && event.data.evidenceSummary === 'csrf:decision_apply:failed') throw new Error('trace failed');
  } });
  const { authority, capability } = await issued({ execution });
  const primary = Object.assign(new Error('fixture persistence failed'), { code: 'FIXTURE_WRITE_FAILED' });
  await assert.rejects(authority.apply({ capability, execution, ...proposed(),
    applyEffect: async () => { throw primary; } }), error => error === primary);
  await assert.rejects(authority.apply({ capability, execution, ...proposed(), applyEffect: async () => ({}) }),
    /capability unavailable/);
});

test('cancellation before apply prevents effect and cancellation during persistence drains it', async () => {
  {
    const execution = owner();
    const { authority, capability } = await issued({ execution });
    execution.controller.abort(Object.assign(new Error('cancelled'), { name: 'AbortError' }));
    let effects = 0;
    await assert.rejects(authority.apply({ capability, execution, ...proposed(),
      applyEffect: async () => { effects++; } }), /cancelled/);
    assert.equal(effects, 0);
  }
  {
    const execution = owner();
    const { authority, capability } = await issued({ execution });
    let release;
    const persisted = new Promise(resolve => { release = resolve; });
    let settled = false;
    const applying = authority.apply({ capability, execution, ...proposed(), applyEffect: async () => {
      execution.controller.abort(Object.assign(new Error('cancelled during persistence'), { name: 'AbortError' }));
      await persisted;
      settled = true;
      return { persisted: true };
    } });
    await new Promise(resolve => setImmediate(resolve));
    assert.equal(settled, false);
    release();
    await assert.rejects(applying, /cancelled during persistence/);
    assert.equal(settled, true, 'effect callback settled before cancellation escaped');
  }
  {
    const origin = owner();
    const { authority, capability } = await issued({ execution: origin });
    const child = owner();
    let release;
    const drained = new Promise(resolve => { release = resolve; });
    let sawOriginAbort = false;
    let settled = false;
    const applying = authority.apply({ capability, execution: child, ...proposed(), applyEffect: async plan => {
      const observed = new Promise(resolve => plan.signal.addEventListener('abort', () => {
        sawOriginAbort = true;
        resolve();
      }, { once: true }));
      origin.controller.abort(Object.assign(new Error('origin cancelled during child effect'), { name: 'AbortError' }));
      await observed;
      await drained;
      settled = true;
      return { completed: true };
    } });
    await new Promise(resolve => setImmediate(resolve));
    assert.equal(sawOriginAbort, true, 'derived effect signal observes the originating cancellation');
    assert.equal(settled, false);
    release();
    await assert.rejects(applying, /origin cancelled during child effect/);
    assert.equal(settled, true, 'derived effect drained before cancellation escaped');
  }
});

test('reset after classification and abort during pre-effect trace cannot start the effect', async () => {
  {
    let current = true;
    const execution = owner({ check: async () => {
      if (!current) throw Object.assign(new Error('generation reset'), { name: 'AbortError' });
    } });
    const { authority, capability } = await issued({ execution });
    current = false;
    let effects = 0;
    await assert.rejects(authority.apply({ capability, execution, ...proposed(),
      applyEffect: async () => { effects++; } }), /generation reset/);
    assert.equal(effects, 0);
  }
  {
    const execution = owner();
    execution.trace = async event => {
      if (event.type === 'decision' && event.data.evidenceSummary === 'csrf:decision_apply:started') {
        await new Promise(resolve => setImmediate(resolve));
        execution.controller.abort(Object.assign(new Error('abort during trace'), { name: 'AbortError' }));
      }
    };
    const { authority, capability } = await issued({ execution });
    let effects = 0;
    await assert.rejects(authority.apply({ capability, execution, ...proposed(),
      applyEffect: async () => { effects++; } }), /abort during trace/);
    assert.equal(effects, 0);
  }
});

test('capability lifecycle uses durable decision events and retains phase details', async () => {
  const events = [];
  const execution = owner({ trace: async event => {
    assert.ok(['node_start', 'node_end', 'decision', 'provisional', 'tool', 'error'].includes(event.type),
      'event must be accepted by the durable graph trace schema');
    if (event.node === 'managed_decision') {
      const { traceData } = require('../server/agent-runtime/runTraceStore');
      assert.deepEqual(traceData(traceData(event.data)), event.data, 'lifecycle survives coordinator and durable projection');
      events.push(event);
    }
  } });
  const { authority, capability } = await issued({ execution });
  await authority.apply({ capability, execution, ...proposed(), applyEffect: async () => ({ persisted: true }) });
  assert.deepEqual(events.map(e => [e.type, e.data.evidenceSummary]), [
    ['decision', 'csrf:decision_capability:issued'],
    ['decision', 'csrf:decision_apply:started'],
    ['decision', 'csrf:decision_apply:completed'],
  ]);
  const rejected = await issued({ execution, selected: decision({ intent: 'none', action: 'none', vector: 'none', params: {} }) });
  assert.equal(rejected.capability, null);
  assert.deepEqual(events.at(-1).data, { evidenceSummary: 'csrf:decision_rejected:not_attack' });
});

test('capability trace projection retains the diagnostic code without private inputs', () => {
  const { traceData } = require('../server/agent-runtime/runTraceStore');
  assert.deepEqual(traceData({ evidenceSummary: 'csrf:decision_apply:started', message: 'private', params: { email: 'private' }, phase: 'private', status: 'private' }), { evidenceSummary: 'csrf:decision_apply:started' });
  assert.deepEqual(traceData({ phase: 'decision_apply', status: 'started', message: 'private', params: { email: 'private' } }), {});
  assert.deepEqual(traceData({ phase: 'decision_apply', status: 'private payload' }), {});
  assert.deepEqual(traceData({ phase: 'decision_rejected', reason: 'private payload' }), {});
  assert.deepEqual(traceData({ phase: 'unknown', status: 'issued' }), {});
});
