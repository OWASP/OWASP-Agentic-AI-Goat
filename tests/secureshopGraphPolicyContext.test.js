'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { randomUUID } = require('node:crypto');
const { createSupervisorGraph } = require('../server/agent-runtime/secureshopSupervisorGraph');
function fixture(acl) {
  const trace = [], effects = [], messages = [];
  const selected = { id: 'call-1', name: 'support.refund_request', args: { nested: { reason: 'teaching text' } } };
  let modelCalls = 0;
  const run = createSupervisorGraph({ store: {
    appendUserMessage: async () => {}, appendAssistantMessage: async () => {},
    appendAssistantToolCalls: async () => {}, appendToolResult: async (_s, _id, text) => messages.push(text),
    getMessages: async () => [], remainingBudget: async () => 1000, addUsedTokens: async () => {},
  }, Trace: class { record(row) { trace.push(row); } async flush() {} },
  buildBasePrompt: () => '', buildPolicyBlock: async () => '', checkToolAcl: (...args) => acl(...args, selected) });
  return { trace, effects, messages, selected, run: () => run('owned-session', 'request', {
    role: 'customer', provider: { provider: 'mock', async chat() { return ++modelCalls === 1
      ? { stop_reason: 'tool_use', tool_uses: [selected] } : { stop_reason: 'end_turn', text: 'done' }; } },
    manifest: { getForRole: () => [{ agent: 'support', tool: 'refund_request' }] },
    pool: { async callTool(_ns, _tool, args) { effects.push(args); return { content: [{ type: 'text', text: 'owned result' }] }; } },
  }, { maxSteps: 3, maxParallelTools: 1 }) };
}
function decision(context, enforcement = false) {
  return { allowed: false, enforcement, action: enforcement ? 'block' : 'dispatch', policyViolation: 'denied-by-acl',
    admission: { admissionId: randomUUID(), runId: randomUUID(), invocationId: `${context.step}:${context.callId}`,
      toolKey: 'support.refund_request', policyVersion: '2', registrySha256: 'a'.repeat(64),
      enforcement, allowed: false, action: enforcement ? 'block' : 'dispatch', policyViolation: 'denied-by-acl' } };
}
test('server invocation context is immutable and dispatch uses its original args across awaited ACL', async () => {
  let observed;
  const f = fixture(async (role, ns, tool, context, original) => {
    assert.deepEqual([role, ns, tool], ['customer', 'support', 'refund_request']);
    observed = context; assert.equal(context.step, 1); assert.equal(context.callId, 'call-1');
    assert.ok(Object.isFrozen(context)); assert.ok(Object.isFrozen(context.args.nested));
    assert.throws(() => { context.args.nested.reason = 'rewrite'; }, TypeError);
    await Promise.resolve(); original.args.nested.reason = 'provider mutation';
    return decision(context);
  });
  await f.run();
  assert.equal(f.effects.length, 1); assert.equal(f.effects[0].nested.reason, 'teaching text');
  const row = f.trace.find(r => r.kind === 'policy_decision');
  assert.equal(row.actor, 'supervisor'); const params = JSON.parse(row.params_json);
  assert.equal(params.callId, observed.callId); assert.equal(params.admission.policyVersion, '2');
  assert.equal(params.admission.action, 'dispatch');
  assert.equal(JSON.stringify(f.messages).includes('admissionId'), false);
});
test('enforced receipt publishes policy provenance and performs zero tool effects', async () => {
  const f = fixture(async (_r, _n, _t, ctx) => decision(ctx, true)); await f.run();
  assert.equal(f.effects.length, 0); assert.ok(f.trace.some(r => r.kind === 'tool_blocked'));
  assert.equal(JSON.parse(f.trace.find(r => r.kind === 'policy_decision').params_json).admission.action, 'block');
});
test('legacy three-argument advisory callback remains dispatching without a synthetic receipt', async () => {
  const f = fixture(async (role, ns, tool) => { assert.equal(tool, 'refund_request'); return { action: 'log', policyViolation: 'denied-by-acl' }; });
  await f.run(); assert.equal(f.effects.length, 1); assert.equal(f.trace.some(r => r.kind === 'policy_decision'), false);
});
test('malformed, mismatched and extra-field policy receipts fail before dispatch', async () => {
  for (const alter of [r => { r.invocationId = 'foreign'; }, r => { r.action = 'block'; }, r => { r.privateToken = 'forbidden'; }, r => { r.policyVersion = '0'; }]) {
    const f = fixture(async (_r, _n, _t, ctx) => { const value = decision(ctx); alter(value.admission); return value; });
    await assert.rejects(f.run(), { code: 'SECURESHOP_INVALID_POLICY_ADMISSION' }); assert.equal(f.effects.length, 0);
    assert.equal(f.trace.some(r => r.kind === 'policy_decision'), false);
  }
});
test('model supplied admission metadata is never treated as policy provenance', async () => {
  const f = fixture(async () => ({ action: 'dispatch', policyViolation: null }));
  f.selected.admission = { admissionId: 'fake' }; await f.run();
  assert.equal(f.trace.some(r => r.kind === 'policy_decision'), false); assert.equal(f.effects.length, 1);
});

test('oversized or deeply nested arguments are rejected before ACL or tool effects', async () => {
  let nested = {}; for (let i = 0; i < 30; i++) nested = { child: nested };
  for (const args of [nested, { value: 'x'.repeat(65537) }]) {
    const f = fixture(() => assert.fail('ACL must not receive unbounded input'));
    f.selected.args = args;
    await assert.rejects(f.run(), /policy bounds/); assert.equal(f.effects.length, 0);
  }
});
