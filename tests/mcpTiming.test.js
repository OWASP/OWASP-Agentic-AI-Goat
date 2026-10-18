'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { createMcpTiming } = require('../server/services/mcp/timing');
const { decideMcp, decideObservedAction } = require('../server/agent-runtime/mcpDecision');

const keys = ['MCP_DECISION_TIMEOUT_MS', 'MCP_RESPONSE_TIMEOUT_MS', 'MCP_RUN_TIMEOUT_MS'];
async function withTiming(env, work) {
  const saved = Object.fromEntries(keys.map(key => [key, process.env[key]]));
  try {
    for (const key of keys) {
      if (env[key] === undefined) delete process.env[key];
      else process.env[key] = env[key];
    }
    return await work();
  } finally {
    for (const key of keys) {
      if (saved[key] === undefined) delete process.env[key];
      else process.env[key] = saved[key];
    }
  }
}

test('MCP timing retains defaults and rejects malformed or unenclosed budgets', () => {
  assert.deepEqual(createMcpTiming({ env: {} }), {
    decisionTimeoutMs: 30000, responseTimeoutMs: 30000, runTimeoutMs: 120000,
  });
  const env = { MCP_DECISION_TIMEOUT_MS: '90000', MCP_RESPONSE_TIMEOUT_MS: '90000', MCP_RUN_TIMEOUT_MS: '290000' };
  const configured = createMcpTiming({ env });
  assert.equal(Object.isFrozen(configured), true);
  assert.deepEqual(configured, { decisionTimeoutMs: 90000, responseTimeoutMs: 90000, runTimeoutMs: 290000 });
  for (const key of keys) {
    for (const value of ['', '0', '99', '-1', '1.5', '1e4', ' 30000', '030000', 30000, null,
      key === 'MCP_RUN_TIMEOUT_MS' ? '290001' : '90001']) {
      assert.throws(() => createMcpTiming({ env: { ...env, [key]: value } }), RangeError);
    }
  }
  assert.throws(() => createMcpTiming({ env: { MCP_RUN_TIMEOUT_MS: '29999' } }), /exceeds/);
});

for (const observed of [false, true]) {
  const name = observed ? 'post-observation decision' : 'initial decision';
  const content = JSON.stringify(observed ? { action: 'none', params: {} } : { tool: 'none', params: {} });
  const invoke = (model, execution) => observed
    ? decideObservedAction({ model, execution, scenario: 'tool_poisoning', untrustedText: 'Controlled observation.', userRequest: 'Describe it.' })
    : decideMcp({ model, execution, message: 'hello', catalog: [] });

  test(`${name} uses configured timeout on bounded repair and preserves the owner signal`, async () => {
    for (const timeout of [30000, 90000]) await withTiming(
      timeout === 30000 ? {} : { MCP_DECISION_TIMEOUT_MS: String(timeout) }, async () => {
        const controller = new AbortController(), calls = [];
        const model = { provider: 'ollama', async chatWithTools(messages, tools, options) {
          calls.push({ messages, tools, options });
          return { content: calls.length === 1 ? 'invalid JSON' : content, provider: 'ollama', model: 'controlled' };
        } };
        const result = await invoke(model, { signal: controller.signal, async check() {} });
        assert.equal(result.decisionSource, 'model');
        assert.equal(calls.length, 2);
        for (const call of calls) {
          assert.equal(call.options.timeout, timeout);
          assert.equal(call.options.signal, controller.signal);
          assert.equal(call.options.temperature, 0);
          assert.deepEqual(call.tools, []);
        }
        assert.deepEqual(calls[0].options.format, calls[1].options.format);
      });
  });

  test(`${name} never dispatches or repairs after owner cancellation`, async () => withTiming({}, async () => {
    for (const when of ['before', 'invalid-response', 'valid-response']) {
      const controller = new AbortController(), reason = new DOMException('Owner expired', 'AbortError');
      let calls = 0;
      if (when === 'before') controller.abort(reason);
      const model = { provider: 'ollama', async chatWithTools() {
        calls++; controller.abort(reason);
        return { content: when === 'invalid-response' ? 'invalid JSON' : content };
      } };
      await assert.rejects(invoke(model, { signal: controller.signal, async check() {} }), error => error === reason);
      assert.equal(calls, when === 'before' ? 0 : 1);
    }
  }));

  test(`${name} transport timeout remains unavailable without retry or fabricated identity`, async () => withTiming({}, async () => {
    let calls = 0;
    const result = await invoke({ provider: 'ollama', async chatWithTools() {
      calls++; throw new DOMException('Provider timeout', 'TimeoutError');
    } }, { async check() {} });
    assert.equal(calls, 1);
    assert.equal(result.decisionSource, 'unavailable');
    assert.equal(result.provider, undefined);
    assert.equal(result.model, undefined);
  }));
}

test('MCP route supplies configured timeout to its shared coordinator before other route imports', () => {
  const fs = require('node:fs'), vm = require('node:vm');
  const source = fs.readFileSync(require.resolve('../server/routes/mcpWorkshop'), 'utf8');
  for (const runTimeoutMs of [120000, 290000]) {
    const stopped = Error('Coordinator captured before resource imports');
    let captured;
    assert.throws(() => vm.runInNewContext(source, { require(name) {
      if (name === '../agent-runtime/ownerWorkflowRoutes') return {};
      if (name === '../services/mcp/timing') return { createMcpTiming: () => createMcpTiming({ env: { MCP_RUN_TIMEOUT_MS: String(runTimeoutMs) } }) };
      if (name === '../agent-runtime/runCoordinator') return { createRunCoordinator(options) { captured = options; throw stopped; } };
      throw Error('Unexpected resource import: ' + name);
    } }), error => error === stopped);
    assert.equal(captured.family, 'MCP');
    assert.equal(captured.defaultTimeoutMs, runTimeoutMs);
  }
});

test('configured owner deadline includes queue time and prevents a queued model dispatch', async () => {
  const timing = createMcpTiming({ env: Object.fromEntries(keys.map(key => [key, '100'])) });
  const coordinator = require('../server/agent-runtime/runCoordinator').createRunCoordinator({
    family: 'MCP', ledger: null, defaultTimeoutMs: timing.runTimeoutMs,
  });
  let release, entered, ownerSignal, dispatches = 0;
  const started = new Promise(resolve => { entered = resolve; });
  const held = new Promise(resolve => { release = resolve; });
  const first = coordinator.run('timing-fixture', {}, async execution => {
    dispatches++; ownerSignal = execution.signal; entered(); await held; await execution.check();
  });
  const firstRejected = assert.rejects(first, { name: 'AbortError' });
  await started;
  const second = coordinator.run('timing-fixture', {}, async () => { dispatches++; });
  try {
    await assert.rejects(second, { name: 'AbortError' });
    assert.equal(ownerSignal.aborted, true);
    assert.equal(dispatches, 1);
  } finally { release(); await firstRejected; await new Promise(resolve => setImmediate(resolve)); }
});
