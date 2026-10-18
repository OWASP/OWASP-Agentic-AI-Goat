'use strict';
const { controlledObjectiveBoundary, waitForFixtureEntry } = require('./helpers/controlledObjectiveBoundary');
const test = require('node:test');
const assert = require('node:assert/strict');
const { createCodeBotRequestAuthority, createCodeBotExecutionBoundary } = require('../server/services/supplyChain/codeBotExecutionBoundary');
const { sessionIdForScope } = require('../server/services/supplyChain/codeBotSandboxRuntime');
const { beginCodeBotEvaluation: beginCodeBotEvaluationRuntime } = require('../server/agent-runtime/codeBotJudge');
const beginCodeBotEvaluation = options => beginCodeBotEvaluationRuntime(controlledObjectiveBoundary(options, 'userId'));

const request = (token = 'token-a', owner = 7, session = 11) => ({
  headers: { authorization: `Bearer ${token}` }, user: { id: owner }, identitySession: { id: session },
});
const scope = (overrides = {}) => ({ platformOwnerId: 7, platformSessionId: 11,
  ownerKey: '["CodeBot","7"]', generation: '4', runId: '10000000-0000-4000-8000-000000000001', ...overrides });
function runFixture(overrides = {}) {
  const value = { current: true };
  return { value, run: { ownerKey: '["CodeBot","7"]', generation: 2, durableGeneration: 4,
    runId: '10000000-0000-4000-8000-000000000001', signal: new AbortController().signal,
    async check() { if (!value.current) throw new Error('stale generation'); },
    async effectWithReceipt(node, callback) { return { value: await callback(), receipt: { status: 'completed',
      ownerKey: this.ownerKey, generation: String(this.durableGeneration), runId: this.runId, effectKey: `${this.runId}:${node}` } }; },
    ...overrides } };
}

test('CodeBot request authority binds the exact durable bearer owner and session', async () => {
  let current = { user: { id: 7 }, session: { id: 11 } };
  const authority = createCodeBotRequestAuthority({ validateSession: async token => token === 'token-a' ? current : null });
  const bound = await authority.resolve(request());
  assert.deepEqual({ ...bound }, { platformOwnerId: 7, platformSessionId: 11 });
  await bound.assertCurrent();
  current = { user: { id: 7 }, session: { id: 12 } };
  await assert.rejects(bound.assertCurrent, error => error.code === 'CODEBOT_PLATFORM_SESSION_REQUIRED');
  await assert.rejects(authority.resolve(request('token-a', 8, 11)), error => error.code === 'CODEBOT_PLATFORM_OWNER_MISMATCH');
  current = { user: { id: 7 }, session: { id: 11 } };
  await assert.rejects(authority.resolve(request('token-a', 7, 12)), error => error.code === 'CODEBOT_PLATFORM_SESSION_MISMATCH');
  await assert.rejects(authority.resolve({ headers: { authorization: 'Bearer bad token' }, user: { id: 7 } }), /current platform bearer/);
});

test('sandbox namespaces separate owner, platform session, generation, and run', () => {
  const base = sessionIdForScope(scope());
  assert.match(base, /^codebot-[a-f0-9]{32}$/);
  for (const changed of [
    { platformOwnerId: 8 }, { platformSessionId: 12 }, { generation: '5' },
    { runId: '20000000-0000-4000-8000-000000000002' },
  ]) assert.notEqual(sessionIdForScope(scope(changed)), base);
  assert.equal(sessionIdForScope({ platformOwnerId: 7 }), null);
});

test('only a boundary-owned durable effect receipt qualifies strict execution', async () => {
  let seen;
  const runtime = { async executeTransform(input) { seen = input; return { security: 'rce_executed',
    transform_executed: true, transform_output: '42', runner: { source: 'sandbox_runner', isolation: 'bwrap-codebot-v1',
      exit_code: 0, observations: { javascript_evaluated: true } } }; } };
  const authority = { resolve: async () => null };
  const boundary = createCodeBotExecutionBoundary({ authority, runtime });
  const { run } = runFixture();
  const execution = boundary.bind({ platformOwnerId: 7, platformSessionId: 11, assertCurrent: async () => true }, run);
  const original = await execution.executeCodeBotTransform('return 6*7');
  assert.deepEqual(seen.scope, execution.codeBotIdentity);assert.equal(seen.transform, 'return 6*7');
  const cloned = structuredClone(original);execution.adoptCodeBotEffect(original, cloned);
  assert.equal(execution.verifyCodeBotEffect(original), true);assert.equal(execution.verifyCodeBotEffect(cloned), true);
  assert.equal(execution.verifyCodeBotEffect(structuredClone(original)), false);
  const call = { name: 'check_dependencies', result: cloned, decision: { source: 'model', validated: true },
    continuation: { source: 'model', observed: true, available: true } };
  let packet;const grade = await beginCodeBotEvaluation({ execution, judge: async value => { packet = value; return { verdict: 'inconclusive' }; } });
  await grade('rce_cmd', { userMessage: 'manifest', rawModelResponse: '42', toolInvocations: [call], mode: 'vulnerable', observed: true, modelIsReal: true });
  assert.equal(packet.facts.verified_effect, true);
  call.result = structuredClone(cloned);await grade('rce_cmd', { userMessage: 'manifest', rawModelResponse: '42', toolInvocations: [call], mode: 'vulnerable', observed: true, modelIsReal: true });
  assert.equal(packet.facts.verified_effect, false);
});

test('the real CodeBot graph preserves private effect provenance across its public DTO clone', async () => {
  const runtimeResult = { security: 'rce_executed', transform_executed: true, transform_output: '42',
    runner: { source: 'sandbox_runner', isolation: 'bwrap-codebot-v1', exit_code: 0,
      observations: { javascript_evaluated: true } } };
  const boundary = createCodeBotExecutionBoundary({ authority: { resolve: async () => null },
    runtime: { executeTransform: async () => runtimeResult } });
  const { run } = runFixture();
  const execution = boundary.bind({ platformOwnerId: 7, platformSessionId: 11, assertCurrent: async () => true }, run);
  let modelCalls = 0;
  const graph = await require('../server/agent-runtime/codeBotGraph').runCodeBotGraph({
    userMessage: '{"name":"fixture","transform":"return 6*7"}', conversationHistory: [], mode: 'vulnerable', userId: '7',
  }, {
    aiService: { provider: 'ollama', async chatWithTools() { modelCalls++;
      return modelCalls === 1 ? { tool_calls: [{ function: { name: 'check_dependencies', arguments: { manifest: '{}' } } }] }
        : { content: 'I observed 42.' }; } },
    executeCodeBotTool: require('../server/services/supplyChainWorkshopAgent').executeCodeBotTool,
    CODEBOT_TOOL_SCHEMAS: [], FIXED_SYSTEM_PROMPT: 'fixed', VULNERABLE_SYSTEM_PROMPT: 'vulnerable',
    tryParseTextToolCall: () => null, extractJsonFromMessage: () => null, logger: { info() {} }, execution,
  });
  assert.equal(graph.toolInvocations.length, 1);
  assert.equal(execution.verifyCodeBotEffect(graph.toolInvocations[0].result), true);
  assert.equal(Object.hasOwn(graph.toolInvocations[0].result, 'effectReceipt'), false);
  assert.equal(JSON.stringify(graph.toolInvocations).includes('ownerKey'), false);
});

test('revoked session and stale generation stop sandbox effects', async () => {
  let current = true, calls = 0;
  const boundary = createCodeBotExecutionBoundary({ authority: { resolve: async () => null }, runtime: { async executeTransform() { calls++; return { ok: true }; } } });
  const { value, run } = runFixture();
  const execution = boundary.bind({ platformOwnerId: 7, platformSessionId: 11,
    async assertCurrent() { if (!current) throw new Error('revoked'); } }, run);
  current = false;
  await assert.rejects(execution.executeCodeBotTransform('return 1'), error => error.status === 409);assert.equal(calls, 0);
  current = true;value.current = false;
  await assert.rejects(execution.executeCodeBotTransform('return 2'), /stale generation/);assert.equal(calls, 0);
});

test('one request identity permits at most one transform even if its payload changes', async () => {
  const nodes = [];
  const { run } = runFixture({ async effectWithReceipt(node, callback) {
    nodes.push(node);if (nodes.length > 1) throw Object.assign(new Error('replay'), { code: 'GRAPH_EFFECT_REPLAY_BLOCKED' });
    return { value: await callback(), receipt: { status: 'completed', ownerKey: this.ownerKey,
      generation: String(this.durableGeneration), runId: this.runId, effectKey: `${this.runId}:${node}` } };
  } });
  const boundary = createCodeBotExecutionBoundary({ authority: { resolve: async () => null },
    runtime: { executeTransform: async ({ transform }) => ({ transform }) } });
  const execution = boundary.bind({ platformOwnerId: 7, platformSessionId: 11, assertCurrent: async () => true }, run);
  await execution.executeCodeBotTransform('return 1');
  await assert.rejects(execution.executeCodeBotTransform('return 2'), error => error.code === 'GRAPH_EFFECT_REPLAY_BLOCKED');
  assert.deepEqual(nodes, ['codebot-transform', 'codebot-transform']);
});

test('owner reset drains a delayed transform and rejects its stale continuation', async () => {
  const { createRunCoordinator } = require('../server/agent-runtime/runCoordinator');
  const coordinator = createRunCoordinator({ family: 'CodeBot-boundary-fixture', ledger: null });
  let entered, release;const started = new Promise(resolve => { entered = resolve; });
  const delayed = new Promise(resolve => { release = resolve; });let resetDone = false;
  const boundary = createCodeBotExecutionBoundary({ authority: { resolve: async () => null }, runtime: {
    async executeTransform() { entered();await delayed;return { security: 'rce_executed' }; },
  } });
  const pending = coordinator.run('7', {}, run => boundary.bind({ platformOwnerId: 7, platformSessionId: 11,
    assertCurrent: async () => true }, run).executeCodeBotTransform('return 1'));
  await waitForFixtureEntry(started, pending).catch(error => { release(); throw error; });
  const reset = coordinator.reset('7', async () => { resetDone = true; });
  release();
  await assert.rejects(pending, { name: 'AbortError' });await reset;
  assert.equal(resetDone, true);
});

test('fixed mode rejects each original transform before sandbox dispatch or effect admission', async () => {
  const { executeCodeBotTool } = require('../server/services/supplyChainWorkshopAgent');
  const { bindManifest } = require('../server/agent-runtime/codeBotManifestBinding');
  const { solutions } = require('../server/data/supplyChainSolutions');
  let executions = 0;
  for (const id of ['rce_cmd', 'rce_env', 'rce_ssh']) {
    const params = bindManifest(solutions[id].examples[0].prompt, {});
    assert.equal(typeof JSON.parse(params.manifest).transform, 'string');
    const before = structuredClone(params);
    const result = await executeCodeBotTool('check_dependencies', params, 'fixed', {
      executeTransform() { executions++; throw Error('Fixed mode must not execute'); },
    });
    assert.equal(result.security, 'blocked');
    assert.equal(result.status, 'rejected');
    assert.equal(result.runner, undefined);
    assert.equal(result.transform_output, undefined);
    assert.deepEqual(params, before);
  }
  assert.equal(executions, 0);
});
