'use strict';
const test = require('node:test'), assert = require('node:assert/strict');
const { createBoundGraphStore } = require('../server/services/secureshopBoundGraphStore');
const scope = { launchId: '70000000-0000-4000-8000-000000000001', scenarioId: '70000000-0000-4000-8000-000000000002', generation: 1, platformOwnerId: 5, platformSessionId: 6 };
function fixture() {
  const writes = []; let revoked = false;
  const result = createBoundGraphStore({ sessionId: 's', scope, persona: { id: 1, role: 'customer' }, service: {
    async assertOwned() { if (revoked) throw new Error('revoked'); }, async getMessages() { return [{ role: 'user', content: 'stored' }]; },
  }, repository: {
    async appendMessage(id, binding, value) { writes.push({ id, binding, value }); },
    async getTokens() { return 20; }, async addTokens(id, binding, value) { writes.push({ id, binding, value }); },
    async appendTraces(id, binding, value) { writes.push({ id, binding, value }); },
  }, tokenBudget: 100 });
  return { ...result, writes, revoke() { revoked = true; } };
}
test('bound store preserves graph message protocol without putting authority in content', async () => {
  const f = fixture();
  await f.store.appendAssistantToolCalls('s', [{ id: 'c', name: 'system.read_config', args: { path: '../file' } }]);
  await f.store.appendToolResult('s', 'c', 'raw observation');
  assert.equal(f.writes[0].value.tool_calls[0].function.arguments, '{"path":"../file"}');
  assert.equal(f.writes[1].value.content, 'raw observation');
  assert.ok(!JSON.stringify(f.writes.map(w => w.value)).includes(scope.launchId));
  assert.equal(await f.store.remainingBudget('s'), 80);
  await assert.rejects(f.store.getMessages('other'), /mismatch/);
});
test('trace session cannot be overridden and revocation prevents buffered persistence', async () => {
  const f = fixture(); const trace = new f.Trace('s');
  trace.record({ session_id: 'attacker', kind: 'final', step: 1, actor: 'supervisor' });
  await trace.flush(); assert.equal(f.writes[0].value[0].session_id, 's');
  trace.record({ kind: 'terminal', step: 2, actor: 'supervisor' });
  f.revoke(); await assert.rejects(trace.flush(), /revoked/);
  await assert.rejects(f.store.appendUserMessage('s', 'late'), /revoked/);
  assert.equal(f.writes.length, 1);
});

test('lost execution lease blocks persistence despite a still-active launch', async () => {
  let calls = 0;
  const f = createBoundGraphStore({ sessionId: 's', scope, persona: { id: 1, role: 'customer' },
    check: async () => { throw new Error('lease lost'); },
    service: { async assertOwned() {}, async getMessages() { calls++; } },
    repository: { async appendMessage() { calls++; }, async addTokens() { calls++; }, async appendTraces() { calls++; }, async getTokens() { calls++; } },
  });
  for (const operation of [() => f.store.appendUserMessage('s', 'late'), () => f.store.addUsedTokens('s', 1),
    () => f.store.getMessages('s'), () => f.store.remainingBudget('s')]) await assert.rejects(operation(), /lease lost/);
  const trace = new f.Trace('s'); trace.record({ kind: 'late' });
  await assert.rejects(trace.flush(), /lease lost/);
  assert.equal(calls, 0);
});

test('private trace evidence is published only after persistence and contains only the stored projection', async () => {
  let release; const waiting = new Promise(resolve => { release = resolve; });
  const writes = [], observed = [];
  const f = createBoundGraphStore({ sessionId: 's', scope, persona: { id: 1, role: 'customer' },
    service: { async assertOwned() {} },
    repository: { async appendTraces(_id, _binding, rows) { writes.push(rows); await waiting; } },
    onTracesPersisted(rows) { observed.push(rows); },
  });
  const trace = new f.Trace('s');
  trace.record({ session_id: 'forged', kind: 'model_decision', step: 1, actor: 'supervisor',
    result_json: '{"tool":"approve"}', fabricated_success: true });
  const flushing = trace.flush();
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(writes.length, 1); assert.equal(observed.length, 0);
  release(); await flushing;
  assert.equal(observed[0], writes[0]);
  assert.ok(Object.isFrozen(observed[0])); assert.ok(Object.isFrozen(observed[0][0]));
  assert.equal(observed[0][0].session_id, 's');
  assert.equal(observed[0][0].result_json, '{"tool":"approve"}');
  assert.equal(Object.hasOwn(observed[0][0], 'fabricated_success'), false);
  assert.equal(observed[0][0].params_json, null);
  assert.match(observed[0][0].event_id, /^[a-f0-9-]{36}$/);
});

test('failed trace persistence produces no private grading evidence', async () => {
  let observed = 0;
  const f = createBoundGraphStore({ sessionId: 's', scope, persona: { id: 1, role: 'customer' },
    service: { async assertOwned() {} },
    repository: { async appendTraces() { throw new Error('storage unavailable'); } },
    onTracesPersisted() { observed++; },
  });
  const trace = new f.Trace('s'); trace.record({ kind: 'terminal' });
  await assert.rejects(trace.flush(), /storage unavailable/);
  assert.equal(observed, 0);
});

test('graph storage applies the same purpose to ownership, content, tokens and traces',async()=>{
  const seen=[];
  const service={async assertOwned(_id,_binding,_persona,purpose){seen.push(['owned',purpose]);},
    async getMessages(_id,_binding,_persona,purpose){seen.push(['messages',purpose]);return[];}};
  const repository={async appendMessage(_id,_binding,_message,purpose){seen.push(['append',purpose]);},
    async getTokens(_id,_binding,purpose){seen.push(['tokens',purpose]);return 0;},
    async addTokens(_id,_binding,_count,purpose){seen.push(['addTokens',purpose]);},
    async appendTraces(_id,_binding,_rows,purpose){seen.push(['traces',purpose]);}};
  const f=createBoundGraphStore({sessionId:'s',scope,persona:{id:1,role:'customer'},service,repository,
    conversationPurpose:'mcp_rogue_registration'});
  await f.store.appendUserMessage('s','fresh');await f.store.getMessages('s');await f.store.remainingBudget('s');await f.store.addUsedTokens('s',1);
  const trace=new f.Trace('s');trace.record({kind:'terminal'});await trace.flush();
  assert.ok(seen.length>8);assert.ok(seen.every(row=>row[1]==='mcp_rogue_registration'));
});

test('independent turn context preserves durable history and accounting without feeding old batches back to the model', async () => {
  const history = [{ role: 'user', content: 'prior batch' }];
  let lifetimeTokens = 500, revoked = false;
  const options = { sessionId: 's', scope, persona: { id: 1, role: 'customer' },
    executionScope: 'turn', tokenBudget: 100,
    service: { async assertOwned() { if (revoked) throw Error('revoked'); },
      async getMessages() { throw Error('must not load old batch context'); } },
    repository: { async appendMessage(_id, _binding, value) { history.push(value); },
      async getTokens() { throw Error('lifetime totals are not a turn budget'); },
      async addTokens(_id, _binding, count) { lifetimeTokens += count; } } };
  const first = createBoundGraphStore(options).store;
  assert.deepEqual(await first.getMessages('s'), []);
  assert.equal(await first.remainingBudget('s'), 100);
  await first.appendUserMessage('s', 'new batch');
  await first.appendAssistantToolCalls('s', [{ id: 'c', name: 'review-moderator.moderate_pending', args: { limit: 1 } }]);
  await first.appendToolResult('s', 'c', 'actual review bytes');
  await first.addUsedTokens('s', 25);
  assert.equal(lifetimeTokens, 525);
  assert.equal(await first.remainingBudget('s'), 75);
  const messages = await first.getMessages('s');
  assert.deepEqual(messages, history.slice(1));
  messages[1].tool_calls[0].function.arguments = 'tampered';
  assert.equal((await first.getMessages('s'))[1].tool_calls[0].function.arguments, '{"limit":1}');
  assert.equal(history[2].tool_calls[0].function.arguments, '{"limit":1}');
  const second = createBoundGraphStore(options).store;
  assert.deepEqual(await second.getMessages('s'), []);
  assert.equal(await second.remainingBudget('s'), 100);
  assert.equal(history.length, 4);
  revoked = true;
  await assert.rejects(first.getMessages('s'), /revoked/);
  await assert.rejects(second.remainingBudget('s'), /revoked/);
});

test('turn context publishes only successfully persisted messages and token increments', async () => {
  let fail = true;
  const store = createBoundGraphStore({ sessionId: 's', scope, persona: { id: 1, role: 'customer' },
    executionScope: 'turn', tokenBudget: 100, service: { async assertOwned() {} },
    repository: {
      async appendMessage() { if (fail) throw Error('write failed'); },
      async addTokens() { if (fail) throw Error('write failed'); },
    } }).store;
  await assert.rejects(store.appendUserMessage('s', 'unpersisted'), /write failed/);
  await assert.rejects(store.addUsedTokens('s', 20), /write failed/);
  assert.deepEqual(await store.getMessages('s'), []);
  assert.equal(await store.remainingBudget('s'), 100);
  fail = false;
  await store.appendUserMessage('s', 'persisted');
  await store.addUsedTokens('s', 20);
  assert.deepEqual(await store.getMessages('s'), [{ role: 'user', content: 'persisted' }]);
  assert.equal(await store.remainingBudget('s'), 80);
  await assert.rejects(store.addUsedTokens('s', -1), /Invalid token count/);
  await assert.rejects(store.addUsedTokens('s', NaN), /Invalid token count/);
});

test('fallback provenance is identical in persisted traces and private Judge evidence', async () => {
  const persisted = [], evidence = [];
  const f = createBoundGraphStore({ sessionId: 's', scope, persona: { id: 1, role: 'admin' },
    service: { async assertOwned() {} },
    repository: { async appendTraces(_id, _binding, rows) { persisted.push(...rows); } },
    onTracesPersisted(rows) { evidence.push(...rows); },
  });
  const trace = new f.Trace('s');
  trace.record({ kind: 'model_decision', step: 1, actor: 'supervisor', provider: 'ollama',
    result_json: JSON.stringify({ model: 'llama3.1:8b', mocked: false, fallback: true }) });
  await trace.flush();
  assert.equal(persisted.length, 1);
  assert.equal(evidence[0], persisted[0]);
  assert.equal(JSON.parse(evidence[0].result_json).fallback, true);
});

test('feature history metadata is an exact server snapshot and never comes from message content', async () => {
  const modeCapability = { version: 1, featureId: 'mail', policyVersion: 'mail-policy-v1',
    effectiveMode: 'fixed', scope: { kind: 'launch_feature', id: 'mail' } };
  const history = [];
  const options = { sessionId: 's', scope, persona: { id: 1, role: 'customer' },
    service: { async assertOwned() {}, async getMessages() { return history; } },
    repository: { async appendMessage(_id, _binding, row) { history.push(row); } } };
  let getterCalls = 0;
  const accessor = { ...modeCapability };
  Object.defineProperty(accessor, 'effectiveMode', { get() { getterCalls++; return 'fixed'; } });
  for (const invalid of [null, { ...modeCapability, ownerId: 1 }, accessor,
    { ...modeCapability, scope: { kind: 'launch_feature', id: 'analytics' } }]) {
    assert.throws(() => createBoundGraphStore({ ...options, modeCapability: invalid }), /Trusted feature/);
  }
  assert.equal(getterCalls, 0);
  const store = createBoundGraphStore({ ...options, modeCapability }).store;
  modeCapability.effectiveMode = 'vuln'; modeCapability.scope.id = 'analytics';
  const content = JSON.stringify({ modeCapability: { effectiveMode: 'vuln' }, instruction: 'untrusted text' });
  await store.appendUserMessage('s', content);
  assert.equal(history[0].modeCapability.effectiveMode, 'fixed');
  assert.equal(history[0].modeCapability.scope.id, 'mail');
  assert.deepEqual(await store.getMessages('s'), [{ role: 'user', content }]);
});
