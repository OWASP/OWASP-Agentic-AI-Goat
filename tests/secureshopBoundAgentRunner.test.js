'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { createBoundAgentRunner } = require('../server/services/secureshopBoundAgentRunner');
const { createBoundTurns } = require('../server/services/secureshopBoundTurns');
const { createRunCoordinator } = require('../server/agent-runtime/runCoordinator');
const { projectSecureShopFailure } = require('../server/services/secureshopFailureDiagnostic');

const BASE_SCOPE = Object.freeze({
  launchId: '91000000-0000-4000-8000-000000000001',
  scenarioId: '91000000-0000-4000-8000-000000000002',
  generation: 3,
  platformOwnerId: 71,
  platformSessionId: 81,
});
const PERSONA = Object.freeze({ id: 91, role: 'customer' });

function memoryFixture({ createLocalTools, providerResponses, routeResponses, turns: turnsOverride, config = {}, lifecycle = [] } = {}) {
  const messages = [];
  const traces = [];
  const effects = [];
  const providerCalls = [];
  const routeCalls = [], pendingRoutes = [...(routeResponses || [])];
  let tokens = 0;
  const conversations = {
    async assertOwned(id, binding, persona) {
      assert.equal(id, '81000000-0000-4000-8000-000000000001');
      assert.equal(binding.shopUserId, persona.id);
      assert.equal(binding.role, persona.role);
    },
    async getMessages() { return messages.map(message => structuredClone(message)); },
  };
  const repository = {
    async appendMessage(id, binding, message) {
      assert.equal(id, '81000000-0000-4000-8000-000000000001');
      assert.equal(binding.launchId, BASE_SCOPE.launchId);
      messages.push(structuredClone(message));
    },
    async getTokens() { return tokens; },
    async addTokens(id, binding, count) {
      assert.equal(id, '81000000-0000-4000-8000-000000000001');
      assert.equal(binding.platformOwnerId, BASE_SCOPE.platformOwnerId);
      tokens += count;
    },
    async appendTraces(id, binding, rows) {
      assert.equal(id, '81000000-0000-4000-8000-000000000001');
      assert.equal(binding.generation, BASE_SCOPE.generation);
      traces.push(...structuredClone(rows));
    },
  };
  const turns = turnsOverride || {
    async run(id, binding, persona, options, operation) {
      assert.equal(id, '81000000-0000-4000-8000-000000000001');
      assert.deepEqual(persona, PERSONA);
      assert.equal(options.signal, undefined);
      const boundary = Object.freeze({
        identity: Object.freeze({ runId: 'trusted-run-id', ownerKey: 'trusted-owner-key', generation: 4, durableGeneration: '9' }),
        signal: undefined,
        async check() {},
        async effect(key, callback) {
          effects.push(key);
          return callback();
        },
        async effectWithReceipt(key, callback) {
          effects.push(key);
          return { value: await callback(), receipt: Object.freeze({ version: 1, runId: 'trusted-run-id', ownerKey: 'trusted-owner-key', generation: '9', effectKey: `request:${key}`, status: 'completed' }) };
        },
        async trace() {},
      });
      const value = await operation(boundary);
      lifecycle.push('coordinator-release');
      return value;
    },
  };
  const responses = [...(providerResponses || [])];
  const provider = {
    async routeWorkflow(input) {
      routeCalls.push(input);
      const next = pendingRoutes.shift();
      if (next instanceof Error) throw next;
      return next;
    },
    async chat(input) {
      providerCalls.push(input);
      return responses.shift();
    },
    async finalResponse(input) {
      providerCalls.push(input);
      const result = responses.shift();
      return result?.stop_reason === 'end_turn' ? { ...result, responseMode: 'structured_final' } : result;
    },
  };
  const poolCalls = [];
  const pool = { async callTool(namespace, tool, args, context) {
    poolCalls.push({ namespace, tool, args, context });
    throw new Error('MCP fallback must not run for registered local tools');
  } };
  const manifest = {
    getForRole(role) {
      assert.equal(role, 'customer');
      return [{ name: 'system.read_config', description: 'fixture', input_schema: { type: 'object' } }];
    },
    async buildExternalMcpPromptBlock() { return ''; },
  };
  const requests = new Map();
  const journal = {
    async claim({ requestId }) {
      if (requests.has(requestId)) return structuredClone(requests.get(requestId));
      requests.set(requestId, { status: 'started', claimId: requestId });
      return { status: 'claimed', claimId: requestId };
    },
    async complete({ requestId, result }) { lifecycle.push('journal-complete'); requests.set(requestId, { status: 'completed', claimId: requestId, result: structuredClone(result) }); },
    async markUncertain({ requestId }) { if (requests.get(requestId)?.status === 'started') requests.get(requestId).status = 'uncertain'; },
  };
  const runner = createBoundAgentRunner({
    turns, conversations, repository, journal,
    buildBasePrompt: role => `base:${role}`,
    buildPolicyBlock: async () => 'policy',
    checkToolAcl: async () => ({ action: 'dispatch', policyViolation: null }),
    provider, pool, manifest, createLocalTools, ...config,
  });
  return { runner, messages, traces, effects, providerCalls, routeCalls, poolCalls, lifecycle, get tokens() { return tokens; } };
}

test('bound runner performs the actual graph tool-observation-final loop with a captured identity', async () => {
  const mutableScope = { ...BASE_SCOPE };
  const toolArgs = { path: '../config', platformOwnerId: 999999, nested: { raw: "' <script>" } };
  const observedBindings = [];
  let localCalls = 0;
  const linked = [];
  const f = memoryFixture({
    async createLocalTools(binding) {
      observedBindings.push(binding);
      return {
        'system.read_config': async args => {
          localCalls++;
          assert.deepEqual(args, toolArgs);
          return { sessionId: 'forged-session', requestId: 'forged-request', binding: { platformOwnerId: 999999 }, run: { runId: 'forged-run' },
            content: [{ type: 'text', text: JSON.stringify({
            marker: binding.platformOwnerId === BASE_SCOPE.platformOwnerId
              ? 'REAL_BOUND_OBSERVATION' : 'WRONG_OWNER',
          }) }] };
        },
      };
    },
    providerResponses: [
      { stop_reason: 'tool_use', tool_uses: [{ id: 'read-1', name: 'system.read_config', args: toolArgs }] },
      { stop_reason: 'end_turn', text: 'The marker is REAL_BOUND_OBSERVATION.' },
    ],
    config: { observeLocalTool: packet => linked.push(packet) },
  });
  const events = [];
  const running = f.runner.run({
    sessionId: '81000000-0000-4000-8000-000000000001', requestId: '82000000-0000-4000-8000-000000000001', scope: mutableScope, persona: PERSONA,
    message: 'Read the configuration',
    stream: { send(name, data) { events.push([name, data]); } },
  });
  mutableScope.platformOwnerId = 999999;
  mutableScope.generation = 999;
  mutableScope.launchId = '92000000-0000-4000-8000-000000000001';
  const result = await running;

  assert.equal(result.text, 'The marker is REAL_BOUND_OBSERVATION.');
  assert.equal(result.stopReason, 'end_turn');
  assert.equal(result.hops.length, 1);
  assert.deepEqual(result.hops[0].params, toolArgs);
  assert.equal(localCalls, 1);
  assert.equal(f.poolCalls.length, 0);
  assert.equal(observedBindings.length, 1);
  assert.equal(Object.isFrozen(observedBindings[0]), true);
  assert.equal(observedBindings[0].platformOwnerId, BASE_SCOPE.platformOwnerId);
  assert.equal(observedBindings[0].generation, BASE_SCOPE.generation);
  assert.equal(observedBindings[0].launchId, BASE_SCOPE.launchId);
  assert.equal(JSON.parse(f.providerCalls[1].messages.at(-1).content).marker, 'REAL_BOUND_OBSERVATION');
  assert.equal(JSON.stringify(f.messages).includes(String(BASE_SCOPE.platformOwnerId)), false);
  assert.deepEqual(events.map(([name]) => name), ['tool_call', 'tool_result', 'assistant_message', 'done']);
  assert.deepEqual(f.messages.map(message => message.role), ['user', 'assistant', 'tool', 'assistant']);
  assert.equal(f.messages[1].tool_calls[0].function.arguments, JSON.stringify(toolArgs));
  assert.equal(f.messages[2].tool_call_id, 'read-1');
  assert.ok(f.traces.some(row => row.kind === 'local_tool_result'));
  assert.ok(f.traces.some(row => row.kind === 'terminal'));
  assert.deepEqual(f.effects, [JSON.stringify([1, 'read-1', 'system.read_config'])]);
  assert.equal(linked.length, 1);
  assert.deepEqual(linked[0].run, { runId: 'trusted-run-id', ownerKey: 'trusted-owner-key', generation: 4, durableGeneration: '9' });
  assert.equal(linked[0].sessionId, '81000000-0000-4000-8000-000000000001');
  assert.equal(linked[0].requestId, '82000000-0000-4000-8000-000000000001');
  assert.deepEqual(linked[0].binding, { ...BASE_SCOPE, shopUserId: PERSONA.id, role: PERSONA.role });
  assert.equal(Object.isFrozen(linked[0].binding), true);
  assert.equal(linked[0].observation.callId, 'read-1');
  assert.equal(linked[0].observation.result.content[0].text.includes('REAL_BOUND_OBSERVATION'), true);
  assert.equal(linked[0].observation.effectReceipt.runId, 'trusted-run-id');
});

test('routed graph freezes the offered family and denies a cross-family model tool before effects', async () => {
  let localCalls = 0;
  const tools = [
    { agent: 'system', tool: 'read_config', inputSchema: { type: 'object' } },
    { agent: 'system', tool: 'write_config', inputSchema: { type: 'object' } },
  ];
  const f = memoryFixture({
    createLocalTools: async () => ({
      'system.read_config': async () => { localCalls++; return { content: [{ type: 'text', text: 'read' }] }; },
      'system.write_config': async () => { localCalls++; return { content: [{ type: 'text', text: 'written' }] }; },
    }),
    routeResponses: [{ responseMode: 'decision_routing_v1', decision: { route: 'registered_tools' },
      provider: 'ollama', model: 'llama3.1:8b', mocked: false,
      usage: { inputTokens: null, outputTokens: null, totalTokens: null, attempts: 1 } }],
    providerResponses: [{ stop_reason: 'tool_use', tool_uses: [{ id: 'wrong-family', name: 'system.write_config', args: {} }] }],
    config: {
      manifest: { getForRole: () => tools, async buildExternalMcpPromptBlock() { return ''; } },
      decisionRouting: { version: 1, system: 'Choose a tool family.',
        families: { management: ['system.write_config'], registered_tools: ['system.read_config'] } },
    },
  });
  await assert.rejects(f.runner.run({
    sessionId: '81000000-0000-4000-8000-000000000001',
    requestId: '82000000-0000-4000-8000-000000000001', scope: BASE_SCOPE,
    persona: PERSONA, message: 'Read configuration', stream: { send() {} },
  }), { code: 'SECURESHOP_INVALID_DECISION' });
  assert.equal(f.routeCalls.length, 1);
  assert.deepEqual(f.providerCalls[0].tools.map(tool => tool.tool), ['read_config']);
  assert.equal(f.traces.find(row => row.kind === 'model_route')?.step, 1);
  assert.equal(localCalls, 0); assert.deepEqual(f.effects, []);
});

test('failed route preserves actual provider attribution and debits known output without dispatch', async () => {
  const error = Object.assign(new Error('Private provider failure'), {
    code: 'SECURESHOP_INVALID_DECISION', provider: 'ollama', model: 'llama3.1:8b', mocked: false,
    usage: { inputTokens: 7, outputTokens: 3, totalTokens: 10, attempts: 1 },
  });
  const f = memoryFixture({
    createLocalTools: async () => ({}), routeResponses: [error],
    config: {
      manifest: { getForRole: () => [
        { agent: 'system', tool: 'read_config', inputSchema: { type: 'object' } },
        { agent: 'system', tool: 'write_config', inputSchema: { type: 'object' } },
      ], async buildExternalMcpPromptBlock() { return ''; } },
      decisionRouting: { version: 1, system: 'Choose a tool family.',
        families: { management: ['system.write_config'], registered_tools: ['system.read_config'] } },
    },
  });
  await assert.rejects(f.runner.run({
    sessionId: '81000000-0000-4000-8000-000000000001',
    requestId: '82000000-0000-4000-8000-000000000001', scope: BASE_SCOPE,
    persona: PERSONA, message: 'Read configuration', stream: { send() {} },
  }), { code: 'SECURESHOP_INVALID_DECISION' });
  assert.equal(f.tokens, 3); assert.equal(f.providerCalls.length, 0);
  const failed = f.traces.find(row => row.kind === 'error');
  assert.equal(failed.provider, 'ollama'); assert.equal(failed.tokens_in, 7); assert.equal(failed.tokens_out, 3);
  assert.deepEqual(JSON.parse(failed.result_json), { errorCode: 'SECURESHOP_INVALID_DECISION',
    phase: 'workflow_route', model: 'llama3.1:8b', mocked: false });
  assert.deepEqual(f.effects, []);
});

test('external tool observation receives private execution context once and journal replay skips effect and persistence',async()=>{
  const observed=[];let factoryContext;let remoteCalls=0;
  const f=memoryFixture({createLocalTools:async()=>({}),providerResponses:[
    {stop_reason:'tool_use',tool_uses:[{id:'remote-call',name:'system.read_config',args:{path:'owned'}}]},
    {stop_reason:'end_turn',text:'observed remote result'},
  ],config:{async createToolPool(_binding,context){factoryContext=context;return{async callTool(agent,tool,args,callContext){remoteCalls++;
    assert.deepEqual({agent,tool,args},{agent:'system',tool:'read_config',args:{path:'owned'}});assert.equal(callContext.callId,'remote-call');
    return{content:[{type:'text',text:'owned remote result'}],_meta:{operationId:'stable-operation'}};}};},
    observeExternalTool:packet=>observed.push(packet)}});
  const input={sessionId:'81000000-0000-4000-8000-000000000001',requestId:'82000000-0000-4000-8000-000000000001',
    scope:BASE_SCOPE,persona:PERSONA,message:'Use the remote tool'};
  const first=await f.runner.run(input);const replay=await f.runner.run(input);
  assert.equal(first.replayed,false);assert.equal(replay.replayed,true);assert.equal(remoteCalls,1);assert.equal(observed.length,1);
  assert.equal(factoryContext.execution.runId,'trusted-run-id');assert.equal(factoryContext.requestId,input.requestId);
  assert.equal(observed[0].observation.callId,'remote-call');assert.equal(observed[0].observation.result._meta.operationId,'stable-operation');
  assert.equal(observed[0].observation.effectReceipt.status,'completed');
});

test('verified external observation enters the tools-empty final response phase after assessment observation', async () => {
  const order = [];
  const f = memoryFixture({ createLocalTools: async () => ({}), providerResponses: [
    { stop_reason: 'tool_use', tool_uses: [{ id: 'remote-call', name: 'system.read_config', args: { path: 'owned' } }] },
    { stop_reason: 'end_turn', text: 'grounded final answer' },
  ], config: {
    limits: { maxSteps: 2, maxParallelTools: 1 },
    createToolPool: async () => ({
      async callTool() { return { content: [{ type: 'text', text: 'authoritative remote result' }] }; },
    }),
    async observeExternalTool(packet) {
      order.push('external-observation');
      return { invocation: { operationId: 'recorded-operation' }, effectReceipt: packet.observation.effectReceipt };
    },
    assessmentFactory: async () => ({
      async begin() { return { attempt: 'bound' }; },
      async observe() { order.push('assessment-observation'); },
      async finalize() {},
    }),
    async enterFinalResponseAfterExternalTool(packet) {
      order.push('final-transition');
      assert.equal(packet.externalRecord.invocation.operationId, 'recorded-operation');
      assert.equal(packet.observation.callId, 'remote-call');
      return true;
    },
  }});
  const result = await f.runner.run({ sessionId: '81000000-0000-4000-8000-000000000001',
    requestId: '82000000-0000-4000-8000-000000000001', scope: BASE_SCOPE, persona: PERSONA,
    message: 'Use the remote tool' });
  assert.equal(result.text, 'grounded final answer');
  assert.deepEqual(order, ['external-observation', 'assessment-observation', 'final-transition']);
  assert.deepEqual(f.providerCalls.map(call => call.tools?.length ?? null), [1, null]);
});

test('external final-response capability reserves the last step before an unobserved tool can loop', async () => {
  let remoteCalls = 0;
  const f = memoryFixture({ createLocalTools: async () => ({}), providerResponses: [
    { stop_reason: 'tool_use', tool_uses: [{ id: 'remote-call', name: 'system.read_config', args: { path: 'owned' } }] },
    { stop_reason: 'end_turn', text: 'must not be reached' },
  ], config: {
    limits: { maxSteps: 2, maxParallelTools: 1 },
    createToolPool: async () => ({
      async callTool() { remoteCalls += 1; return { content: [{ type: 'text', text: 'remote result' }] }; },
    }),
    enterFinalResponseAfterExternalTool: async () => true,
  }});
  const result = await f.runner.run({ sessionId: '81000000-0000-4000-8000-000000000001',
    requestId: '82000000-0000-4000-8000-000000000001', scope: BASE_SCOPE, persona: PERSONA,
    message: 'Use the remote tool' });
  assert.equal(result.stopReason, 'max_steps');
  assert.equal(f.providerCalls.length, 1);
  assert.equal(remoteCalls, 1);
});

test('external observation persistence failure prevents assessment finalization and canonical credit',async()=>{
  let finalized=0,observed=0,transitioned=0;
  const f=memoryFixture({createLocalTools:async()=>({}),providerResponses:[
    {stop_reason:'tool_use',tool_uses:[{id:'remote-call',name:'system.read_config',args:{path:'owned'}}]},
  ],config:{createToolPool:async()=>({callTool:async()=>({content:[{type:'text',text:'remote effect'}]})}),
    async observeExternalTool(){observed++;throw new Error('canonical invocation persistence failed');},
    async enterFinalResponseAfterExternalTool(){transitioned++;return true;},
    assessmentFactory:async()=>({async begin(){return Object.freeze({attempt:'private'});},async observe(){},async finalize(){finalized++;}})}});
  const input={sessionId:'81000000-0000-4000-8000-000000000001',requestId:'82000000-0000-4000-8000-000000000001',
    scope:BASE_SCOPE,persona:PERSONA,message:'Use the remote tool'};
  await assert.rejects(f.runner.run(input),/canonical invocation persistence failed/);
  assert.equal(observed,1);assert.equal(finalized,0,'remote effect without canonical invocation cannot be graded');
  assert.equal(transitioned,0,'failed external persistence cannot enter final response');
});

test('assessment observation failure blocks the external final-response transition', async () => {
  let transitioned = 0;
  const f = memoryFixture({ createLocalTools: async () => ({}), providerResponses: [
    { stop_reason: 'tool_use', tool_uses: [{ id: 'remote-call', name: 'system.read_config', args: { path: 'owned' } }] },
  ], config: {
    createToolPool: async () => ({ callTool: async () => ({ content: [{ type: 'text', text: 'remote result' }] }) }),
    observeExternalTool: async () => ({ invocation: { operationId: 'recorded-operation' }, effectReceipt: { status: 'completed' } }),
    assessmentFactory: async () => ({ async begin() { return {}; }, async observe() { throw new Error('assessment rejected'); }, async finalize() {} }),
    async enterFinalResponseAfterExternalTool() { transitioned += 1; return true; },
  }});
  await assert.rejects(f.runner.run({ sessionId: '81000000-0000-4000-8000-000000000001',
    requestId: '82000000-0000-4000-8000-000000000001', scope: BASE_SCOPE, persona: PERSONA,
    message: 'Use the remote tool' }), /assessment rejected/);
  assert.equal(transitioned, 0);
});

test('external tool errors cannot enter the final-response transition', async () => {
  let transitioned = 0;
  const f = memoryFixture({ createLocalTools: async () => ({}), providerResponses: [
    { stop_reason: 'tool_use', tool_uses: [{ id: 'remote-call', name: 'system.read_config', args: { path: 'owned' } }] },
    { stop_reason: 'end_turn', text: 'error reported' },
  ], config: {
    createToolPool: async () => ({ callTool: async () => ({ isError: true, content: [{ type: 'text', text: 'remote failure' }] }) }),
    observeExternalTool: async () => ({ invocation: { operationId: 'recorded-operation' }, effectReceipt: { status: 'completed' } }),
    async enterFinalResponseAfterExternalTool() { transitioned += 1; return true; },
  }});
  const result = await f.runner.run({ sessionId: '81000000-0000-4000-8000-000000000001',
    requestId: '82000000-0000-4000-8000-000000000001', scope: BASE_SCOPE, persona: PERSONA,
    message: 'Use the remote tool' });
  assert.equal(result.text, 'error reported');
  assert.equal(transitioned, 0);
});

test('server final-response hook receives the protected execution once and journal replay skips it', async () => {
  const authority = Object.freeze(Object.create(null));
  const packets = [];
  let localCalls = 0;
  const f = memoryFixture({
    async createLocalTools(_binding, context, token) {
      assert.equal(context.requestId, '82000000-0000-4000-8000-000000000001');
      assert.equal(token, authority);
      return { 'system.read_config': async () => {
        localCalls++;
        return { content: [{ type: 'text', text: 'authoritative observation' }] };
      } };
    },
    providerResponses: [
      { stop_reason: 'tool_use', tool_uses: [{ id: 'selected-call', name: 'system.read_config', args: {} }] },
      { stop_reason: 'end_turn', text: 'final from the observation' },
    ],
    config: {
      limits: { maxSteps: 2, maxParallelTools: 1 },
      async enterFinalResponseAfterLocalTool(packet) {
        packets.push(packet);
        assert.equal(Object.isFrozen(packet), true);
        assert.equal(packet.localToolAuthority, authority);
        assert.equal(packet.execution.runId, 'trusted-run-id');
        assert.equal(packet.execution.ownerKey, 'trusted-owner-key');
        assert.equal(packet.execution.durableGeneration, '9');
        assert.equal(packet.observation.callId, 'selected-call');
        assert.equal(packet.observation.effectReceipt.status, 'completed');
        return true;
      },
    },
  });
  const input = { sessionId: '81000000-0000-4000-8000-000000000001',
    requestId: '82000000-0000-4000-8000-000000000001', scope: BASE_SCOPE,
    persona: PERSONA, message: 'read once then answer', localToolAuthority: authority };
  const result = await f.runner.run(input);
  assert.equal(result.stopReason, 'end_turn');
  assert.equal(result.steps, 2);
  assert.equal(localCalls, 1);
  assert.equal(packets.length, 1);
  assert.deepEqual(f.providerCalls.map(call => call.tools?.length ?? null), [1, null]);

  const replay = await f.runner.run(input);
  assert.equal(replay.replayed, true);
  assert.equal(replay.text, result.text);
  assert.equal(localCalls, 1);
  assert.equal(packets.length, 1);
  assert.equal(f.providerCalls.length, 2);
});

test('trusted result metadata is journaled once and exact replay does not rebuild it', async () => {
  let metadataCalls = 0;
  const f = memoryFixture({ createLocalTools: async () => ({}),
    providerResponses: [{ stop_reason: 'end_turn', text: 'done' }],
    config: { async resultMetadata(packet) {
      metadataCalls++;
      assert.equal(packet.execution.runId, 'trusted-run-id');
      assert.equal(Object.hasOwn(packet, 'traces'), false);
      return { reviewBatch: { contract: 'fixture-v1', runId: packet.execution.runId } };
    } } });
  const input = { sessionId: '81000000-0000-4000-8000-000000000001',
    requestId: '82000000-0000-4000-8000-000000000001', scope: BASE_SCOPE,
    persona: PERSONA, message: 'finish' };
  const first = await f.runner.run(input);
  assert.deepEqual(first.taskMetadata, { reviewBatch: { contract: 'fixture-v1', runId: 'trusted-run-id' } });
  const replay = await f.runner.run(input);
  assert.equal(replay.replayed, true);
  assert.deepEqual(replay.taskMetadata, first.taskMetadata);
  assert.equal(metadataCalls, 1);
});

test('opted-in result metadata receives only persisted current-turn event identities', async () => {
  const packets = [];
  const f = memoryFixture({ createLocalTools: async () => ({}),
    providerResponses: [{ stop_reason: 'end_turn', text: 'first' }, { stop_reason: 'end_turn', text: 'second' }],
    config: { captureResultTraces: true, resultMetadata(packet) {
      packets.push(packet);
      assert.ok(Object.isFrozen(packet.traces));
      assert.ok(packet.traces.length > 0);
      assert.ok(packet.traces.every(row => Object.isFrozen(row)
        && typeof row.event_id === 'string' && row.event_id.length > 0));
      return { eventIds: packet.traces.map(row => row.event_id) };
    } },
  });
  const input = { sessionId: '81000000-0000-4000-8000-000000000001',
    requestId: '82000000-0000-4000-8000-000000000001', scope: BASE_SCOPE,
    persona: PERSONA, message: 'first' };
  const first = await f.runner.run(input);
  const second = await f.runner.run({ ...input, requestId: '82000000-0000-4000-8000-000000000002', message: 'second' });
  assert.equal(packets.length, 2);
  assert.deepEqual(packets.flatMap(packet => packet.traces), f.traces);
  assert.ok(packets[1].traces.every(row => !first.taskMetadata.eventIds.includes(row.event_id)));
  assert.deepEqual(second.taskMetadata.eventIds, packets[1].traces.map(row => row.event_id));
  await f.runner.run(input);
  assert.equal(packets.length, 2);
  assert.deepEqual(first.taskMetadata.eventIds, packets[0].traces.map(row => row.event_id));
});

test('result trace capture requires a trusted metadata callback', () => {
  assert.throws(() => memoryFixture({ createLocalTools: async () => ({}),
    config: { captureResultTraces: true } }), TypeError);
});

test('authority lost during local-tool preparation starts neither model nor tool work', async () => {
  let current = true;
  let releaseTools;
  let toolsStarted;
  const enteredTools = new Promise(resolve => { toolsStarted = resolve; });
  let toolCalls = 0;
  const turns = {
    async run(id, binding, persona, options, operation) {
      assert.equal(id, '81000000-0000-4000-8000-000000000001');
      assert.equal(binding.platformOwnerId, BASE_SCOPE.platformOwnerId);
      assert.deepEqual(persona, PERSONA);
      return operation(Object.freeze({
        signal: options.signal,
        async check() {
          if (!current) throw Object.assign(new Error('launch is no longer current'), { code: 'LAUNCH_UNAVAILABLE' });
        },
        async effect(key, callback) { return callback(); },
      }));
    },
  };
  const f = memoryFixture({
    turns,
    async createLocalTools(binding) {
      assert.equal(binding.generation, BASE_SCOPE.generation);
      toolsStarted();
      await new Promise(resolve => { releaseTools = resolve; });
      return { 'system.read_config': async () => { toolCalls++; return 'unreachable'; } };
    },
    providerResponses: [{ stop_reason: 'end_turn', text: 'unreachable' }],
  });
  const running = f.runner.run({
    sessionId: '81000000-0000-4000-8000-000000000001', requestId: '82000000-0000-4000-8000-000000000001', scope: { ...BASE_SCOPE }, persona: PERSONA,
    message: 'Read the configuration',
  });
  await enteredTools;
  current = false;
  releaseTools();
  await assert.rejects(running, { code: 'LAUNCH_UNAVAILABLE' });
  assert.equal(f.providerCalls.length, 0);
  assert.equal(toolCalls, 0);
  assert.equal(f.messages.length, 0);
  assert.equal(f.traces.length, 0);
});

test('invalid messages fail before tool preparation, model or persistence', async () => {
  let prepared = 0;
  const f = memoryFixture({ createLocalTools: async () => { prepared++; return {}; } });
  for (const message of ['', ' \n\t', null, 'x'.repeat(65537), '😀'.repeat(16385)]) {
    await assert.rejects(f.runner.run({ sessionId: '81000000-0000-4000-8000-000000000001', requestId: '82000000-0000-4000-8000-000000000001', scope: BASE_SCOPE, persona: PERSONA, message }), { code: 'INVALID_MESSAGE' });
  }
  assert.equal(prepared, 0); assert.equal(f.messages.length, 0); assert.equal(f.providerCalls.length, 0);
});

test('bound runner retains the exact failing lifecycle phase without changing the thrown error', async () => {
  const input = { sessionId: '81000000-0000-4000-8000-000000000001',
    requestId: '82000000-0000-4000-8000-000000000001', scope: BASE_SCOPE,
    persona: PERSONA, message: 'exercise one bounded failure' };
  const lifecycle = error => ({ async begin() { return Object.freeze({ attempt: 'owned' }); },
    async observe() {}, async finalize() { throw error; } });
  const cases = [
    ['assessment_begin', error => memoryFixture({ createLocalTools: async () => ({}),
      config: { assessmentFactory() { throw error; } } })],
    ['tool_pool', error => memoryFixture({ createLocalTools: async () => ({}),
      config: { async createToolPool() { throw error; } } })],
    ['graph', error => memoryFixture({ createLocalTools: async () => ({}),
      config: { async buildPolicyBlock() { throw error; } } })],
    ['external_observation', error => memoryFixture({ createLocalTools: async () => ({}), providerResponses: [
      { stop_reason: 'tool_use', tool_uses: [{ id: 'external-call', name: 'system.read_config', args: {} }] },
    ], config: { async createToolPool() { return { async callTool() {
      return { content: [{ type: 'text', text: 'owned result' }] };
    } }; }, async observeExternalTool() { throw error; } } })],
    ['assessment_observe', error => memoryFixture({ createLocalTools: async () => ({}), providerResponses: [
      { stop_reason: 'tool_use', tool_uses: [{ id: 'external-call', name: 'system.read_config', args: {} }] },
    ], config: { assessmentFactory: () => ({ async begin() { return Object.freeze({ attempt: 'owned' }); },
      async observe() { throw error; }, async finalize() {} }), async createToolPool() { return { async callTool() {
      return { content: [{ type: 'text', text: 'owned result' }] };
    } }; }, async observeExternalTool() { return Object.freeze({ invocation: 'owned' }); } } })],
    ['assessment_finalize', error => memoryFixture({ createLocalTools: async () => ({}),
      providerResponses: [{ stop_reason: 'end_turn', text: 'settled' }],
      config: { assessmentFactory: () => lifecycle(error) } })],
    ['admission_publish', error => memoryFixture({ createLocalTools: async () => ({}),
      turns: { async run() { throw error; } } })],
  ];
  for (const [phase, makeFixture] of cases) {
    const failure = Object.assign(new Error(`private-${phase}`), { code: 'BOUND_SSRF_UNAVAILABLE' });
    let observed;
    await assert.rejects(makeFixture(failure).runner.run(input), error => { observed = error; return true; });
    assert.equal(observed, failure, `${phase} preserves the original error identity`);
    assert.deepEqual(projectSecureShopFailure(observed), {
      phase, failureCategory: phase === 'external_observation' ? 'external_record_rejected' : 'unclassified',
      errorCode: 'BOUND_SSRF_UNAVAILABLE', errorName: 'Error',
    });
  }
});

test('external observation distinguishes a selected tool error from a rejected canonical record', async () => {
  const toolFailure = Object.assign(new Error('selected arguments rejected'), { code:'BOUND_SSRF_UNAVAILABLE' });
  const observationFailure = Object.assign(new Error('missing canonical metadata'), { code:'BOUND_SSRF_UNAVAILABLE' });
  const f = memoryFixture({ createLocalTools: async () => ({}), providerResponses: [
    { stop_reason:'tool_use', tool_uses:[{ id:'external-call', name:'system.read_config', args:{} }] },
  ], config: { async createToolPool() { return { async callTool() { throw toolFailure; } }; },
    async observeExternalTool() { throw observationFailure; } } });
  let observed;
  await assert.rejects(f.runner.run({ sessionId:'81000000-0000-4000-8000-000000000001',
    requestId:'82000000-0000-4000-8000-000000000001', scope:BASE_SCOPE, persona:PERSONA,
    message:'exercise external tool rejection' }), error => { observed=error; return true; });
  assert.equal(observed,observationFailure);
  assert.deepEqual(projectSecureShopFailure(observed), { phase:'external_observation',
    failureCategory:'external_tool_error', errorCode:'BOUND_SSRF_UNAVAILABLE', errorName:'Error' });
});

test('persona-wrapped external pool preserves privately branded fixed denial feedback', async () => {
  const denial = Object.assign(new Error('Private destination blocked by fixed egress policy'),
    { code: 'BOUND_SSRF_UNAVAILABLE' });
  const branded = new WeakSet([denial]);
  let calls = 0, observations = 0;
  const f = memoryFixture({ createLocalTools: async () => ({}), providerResponses: [
    { stop_reason:'tool_use', tool_uses:[{id:'external-call',name:'system.read_config',args:{}}] },
    { stop_reason:'end_turn', text:'The fixed policy denied that destination.' },
  ], config: {
    capturePersonaAuthority: async () => ({
      binding: { ...BASE_SCOPE, personaId:PERSONA.id, role:PERSONA.role },
      async assertRemoteAdmission() {},
      async withPersonaEffect(work) { return work({},{}); },
    }), personaLocalToolModes: Object.freeze({}),
    async createToolPool() { return Object.freeze({
      async callTool() { calls++; throw denial; },
      projectRecoverableToolError(error) { return branded.has(error)?'INVALID_TOOL_SELECTION':null; },
    }); },
    async observeExternalTool() { observations++; throw Error('Denied call has no completed receipt'); },
  } });
  const result = await f.runner.run({ sessionId:'81000000-0000-4000-8000-000000000001',
    requestId:'82000000-0000-4000-8000-000000000001',scope:BASE_SCOPE,persona:PERSONA,
    message:'Try the fixed destination' });
  assert.equal(result.stopReason,'end_turn');
  assert.equal(calls,1);assert.equal(observations,0);
  const feedback = f.messages.find(row=>row.role==='tool')?.content;
  assert.match(feedback,/INVALID_TOOL_SELECTION/);
  assert.doesNotMatch(feedback,/Private destination blocked by fixed egress policy/);
  assert.equal(f.traces.filter(row=>row.kind==='mcp_result').length,1);
  assert.equal(f.traces.find(row=>row.kind==='mcp_result')?.result_json.includes('INVALID_TOOL_SELECTION'),true);
});

test('persona revoked during a branded external denial publishes no recoverable tool feedback', async () => {
  const denial = new Error('Private destination blocked by fixed egress policy');
  const branded = new WeakSet([denial]);
  let live = true, observations = 0;
  const f = memoryFixture({ createLocalTools: async () => ({}), providerResponses: [
    { stop_reason:'tool_use', tool_uses:[{id:'external-call',name:'system.read_config',args:{}}] },
  ], config: {
    capturePersonaAuthority: async () => ({
      binding: { ...BASE_SCOPE, personaId:PERSONA.id, role:PERSONA.role },
      async assertRemoteAdmission() { if (!live) throw Object.assign(new Error('revoked'),{code:'SHOP_AUTH_INVALID'}); },
      async withPersonaEffect(work) { return work({},{}); },
    }), personaLocalToolModes: Object.freeze({}),
    async createToolPool() { return Object.freeze({
      async callTool() { live=false; throw denial; },
      projectRecoverableToolError(error) { return branded.has(error)?'INVALID_TOOL_SELECTION':null; },
    }); },
    async observeExternalTool() { observations++; throw Error('Denied call has no completed receipt'); },
  } });
  await assert.rejects(f.runner.run({ sessionId:'81000000-0000-4000-8000-000000000001',
    requestId:'82000000-0000-4000-8000-000000000001',scope:BASE_SCOPE,persona:PERSONA,
    message:'Try the fixed destination' }),{code:'SHOP_AUTH_INVALID',executionBoundary:true});
  assert.equal(observations,0);
  assert.equal(f.messages.some(row=>row.role==='tool'),false);
  assert.equal(f.traces.some(row=>row.kind==='mcp_result'),false);
});

test('provider rejection remains a persisted error terminal instead of an execution exception', async () => {
  const f = memoryFixture({ createLocalTools: async () => ({}), config: { provider: {
    async chat() { throw Object.assign(new Error('private provider details'), { code:'ETIMEDOUT' }); },
  } } });
  const result = await f.runner.run({ sessionId: '81000000-0000-4000-8000-000000000001',
    requestId: '82000000-0000-4000-8000-000000000001', scope: BASE_SCOPE,
    persona: PERSONA, message: 'exercise provider failure' });
  assert.equal(result.stopReason, 'error'); assert.equal(result.text, '[AI provider unavailable]');
  assert.ok(f.traces.some(row => row.kind === 'error'
    && JSON.parse(row.result_json).errorCode === 'PROVIDER_ERROR'));
  assert.ok(f.traces.some(row => row.kind === 'terminal'));
});

test('exact byte limit preserves raw message content', async () => {
  const message = '😀'.repeat(16384);
  const f = memoryFixture({ createLocalTools: async () => ({}), providerResponses: [{ stop_reason: 'end_turn', text: 'done' }] });
  await f.runner.run({ sessionId: '81000000-0000-4000-8000-000000000001', requestId: '82000000-0000-4000-8000-000000000001', scope: BASE_SCOPE, persona: PERSONA, message });
  assert.equal(f.messages[0].content, message);
  assert.equal(f.providerCalls[0].ownerId, '81000000-0000-4000-8000-000000000001');
});

test('invalid server dependencies and excessive limits fail at composition', () => {
  for (const config of [
    { limits: null }, { limits: { maxSteps: 33, maxParallelTools: 4 } },
    { limits: { maxSteps: 8, maxParallelTools: 9 } },
    { provider: {} }, { repository: {} }, { conversations: {} },
    { pool: {} }, { manifest: {} }, { buildPolicyBlock: null }, { checkToolAcl: null },
    { observeLocalTool: true },
    { assessmentFactory: true },
    { enterFinalResponseAfterLocalTool: true },
    { provider: { async chat() {} }, enterFinalResponseAfterLocalTool: async () => true },
    { limits: { maxSteps: 1, maxParallelTools: 1 }, enterFinalResponseAfterLocalTool: async () => true },
  ]) assert.throws(() => memoryFixture({ createLocalTools: async () => ({}), config }), /configuration required/);
});

test('lost terminal delivery replays the persisted result without another message or model call', async () => {
  const f = memoryFixture({ createLocalTools: async () => ({}), providerResponses: [{ stop_reason: 'end_turn', text: 'stored answer' }] });
  const input = { sessionId: '81000000-0000-4000-8000-000000000001', requestId: '82000000-0000-4000-8000-000000000001', scope: BASE_SCOPE, persona: PERSONA, message: 'one action' };
  await assert.rejects(f.runner.run({ ...input, stream: { send(name) { if (name === 'assistant_message') throw new Error('connection lost'); } } }), /connection lost/);
  const priorMessages = structuredClone(f.messages), priorTraces = structuredClone(f.traces), events = [];
  const result = await f.runner.run({ ...input, stream: { send(name, data) { events.push([name, data]); } } });
  assert.equal(result.replayed, true); assert.equal(result.text, 'stored answer');
  assert.equal(f.providerCalls.length, 1);
  assert.deepEqual(f.messages, priorMessages); assert.deepEqual(f.traces, priorTraces);
  assert.deepEqual(events.map(event => event[0]), ['assistant_message', 'done']);
});

test('concurrent identical request and reconstructed runner replay create one canonical run', async () => {
  const rows = new Map(), tails = new Map(), releases = new Map(), runIds = [];
  const journal = {
    async claim(input) {
      const prior = rows.get(input.requestId);
      if (prior) return structuredClone(prior);
      rows.set(input.requestId, { status: 'started', claimId: input.requestId });
      return { status: 'claimed', claimId: input.requestId };
    },
    async complete({ requestId, result }) { rows.set(requestId, { status: 'completed', claimId: requestId, result: structuredClone(result) }); },
    async markUncertain({ requestId }) { if (rows.get(requestId)?.status === 'started') rows.get(requestId).status = 'uncertain'; },
  };
  const ledger = { supportsPreRunAdmission: true,
    async begin(context, { admit }) {
      const previous = tails.get(context.ownerKey) || Promise.resolve();
      let release; const tail = new Promise(resolve => { release = resolve; });
      tails.set(context.ownerKey, tail); await previous;
      const decision = await admit();
      if (decision.skip) { release(); return { skipped: true, value: decision.value }; }
      releases.set(context.runId, release); runIds.push(context.runId);
      return { durableGeneration: '7' };
    },
    async assertCurrent() {}, async recordEvent() {},
    async finish(context) { releases.get(context.runId)?.(); releases.delete(context.runId); },
  };
  const make = () => {
    const turns = createBoundTurns({ conversations: { async assertOwned() {} },
      coordinator: createRunCoordinator({ family: 'RestartReplay', ledger }) });
    return memoryFixture({ turns, createLocalTools: async () => ({}),
      providerResponses: [{ stop_reason: 'end_turn', text: 'one durable answer' }], config: { journal } });
  };
  const first = make(), concurrent = make();
  const input = { sessionId: '81000000-0000-4000-8000-000000000001',
    requestId: '82000000-0000-4000-8000-000000000001', scope: BASE_SCOPE,
    persona: PERSONA, message: 'same exact request' };
  const pair = await Promise.all([first.runner.run(input), concurrent.runner.run(input)]);
  assert.deepEqual(pair.map(result => result.replayed).sort(), [false, true]);
  assert.ok(pair.every(result => result.text === 'one durable answer'));
  assert.equal(runIds.length, 1);
  assert.equal(first.providerCalls.length + concurrent.providerCalls.length, 1);

  const restarted = make();
  const replay = await restarted.runner.run(input);
  assert.equal(replay.replayed, true); assert.equal(replay.text, 'one durable answer');
  assert.equal(runIds.length, 1); assert.equal(restarted.providerCalls.length, 0);
  assert.equal(restarted.messages.length, 0); assert.equal(restarted.traces.length, 0);

  const distinct = make();
  const fresh = await distinct.runner.run({ ...input,
    requestId: '82000000-0000-4000-8000-000000000002' });
  assert.equal(fresh.replayed, false); assert.equal(runIds.length, 2);
  assert.equal(distinct.providerCalls.length, 1);
});

test('durable begin failure after journal admission makes the claim uncertain', async () => {
  let state = 'missing', providerCalls = 0;
  const journal = {
    async claim({ requestId }) {
      if (state === 'missing') { state = 'started'; return { status: 'claimed', claimId: requestId }; }
      return { status: state, claimId: requestId };
    },
    async complete() { assert.fail('graph never began'); },
    async markUncertain() { state = 'uncertain'; },
  };
  const turns = { async run(_id, _binding, _persona, options) {
    const decision = await options.admit(); assert.equal(decision.skip, false);
    throw Object.assign(new Error('reset changed generation during admission'), { name: 'AbortError' });
  } };
  const f = memoryFixture({ turns, createLocalTools: async () => ({}), config: { journal,
    provider: { async chat() { providerCalls++; return { stop_reason: 'end_turn', text: 'unreachable' }; } } } });
  const input = { sessionId: '81000000-0000-4000-8000-000000000001',
    requestId: '82000000-0000-4000-8000-000000000001', scope: BASE_SCOPE,
    persona: PERSONA, message: 'must remain fenced' };
  await assert.rejects(f.runner.run(input), { name: 'AbortError' });
  assert.equal(state, 'uncertain'); assert.equal(providerCalls, 0);
  await assert.rejects(f.runner.run(input), { code: 'TURN_RECOVERY_REQUIRED' });
  assert.equal(providerCalls, 0);
});

test('assessment lifecycle uses one protected execution before effects and finalizes before journal completion', async () => {
  const lifecycle = [];
  let f, execution;
  const input = { sessionId: '81000000-0000-4000-8000-000000000001', requestId: '82000000-0000-4000-8000-000000000001',
    scope: BASE_SCOPE, persona: PERSONA, message: 'Assess one local observation' };
  const assessmentFactory = context => {
    lifecycle.push('factory');
    assert.equal(context.sessionId, input.sessionId); assert.equal(context.requestId, input.requestId);
    assert.equal(Object.isFrozen(context), true); assert.equal(Object.isFrozen(context.binding), true);
    return {
      async begin(value) {
        lifecycle.push('begin'); execution = value;
        assert.equal(Object.isFrozen(value), true); assert.equal(value.runId, 'trusted-run-id');
        assert.equal(value.ownerKey, 'trusted-owner-key'); assert.equal(value.durableGeneration, '9');
        assert.equal(typeof value.check, 'function'); assert.equal(typeof value.trace, 'function');
        return Object.freeze({ attempt: 'private-attempt' });
      },
      async observe(value, packet) {
        lifecycle.push('observe'); assert.equal(value, execution);
        assert.equal(packet.attempt.attempt, 'private-attempt'); assert.equal(packet.observation.callId, 'assessed-call');
        assert.equal(packet.observation.effectReceipt.status, 'completed');
      },
      async finalize(value, packet) {
        lifecycle.push('finalize'); assert.equal(value, execution);
        assert.equal(packet.attempt.attempt, 'private-attempt'); assert.equal(packet.result.text, 'assessed');
        assert.equal(f.traces.at(-1).kind, 'terminal');
        return Object.freeze({ status: 'unavailable', reason: 'judge-offline' });
      },
    };
  };
  f = memoryFixture({ lifecycle, assessmentFactory,
    config: { assessmentFactory, async enterFinalResponseAfterLocalTool(packet) {
      lifecycle.push('final-response-gate');
      assert.equal(packet.execution, execution);
      assert.equal(packet.observation.callId, 'assessed-call');
      assert.equal(packet.observation.effectReceipt.status, 'completed');
      return true;
    } },
    async createLocalTools() { lifecycle.push('prepare-tools'); return { 'system.read_config': async () => {
      lifecycle.push('tool-effect'); return { content: [{ type: 'text', text: 'observed' }] };
    } }; },
    providerResponses: [
      { stop_reason: 'tool_use', tool_uses: [{ id: 'assessed-call', name: 'system.read_config', args: {} }] },
      { stop_reason: 'end_turn', text: 'assessed' },
    ],
  });
  const result = await f.runner.run(input);
  assert.equal(result.replayed, false); assert.equal(Object.hasOwn(result, 'assessment'), false);
  assert.ok(lifecycle.indexOf('begin') < lifecycle.indexOf('prepare-tools'));
  assert.ok(lifecycle.indexOf('begin') < lifecycle.indexOf('tool-effect'));
  assert.ok(lifecycle.indexOf('tool-effect') < lifecycle.indexOf('observe'));
  assert.ok(lifecycle.indexOf('observe') < lifecycle.indexOf('final-response-gate'));
  assert.ok(lifecycle.indexOf('final-response-gate') < lifecycle.indexOf('finalize'));
  assert.ok(lifecycle.indexOf('observe') < lifecycle.indexOf('finalize'));
  assert.ok(lifecycle.indexOf('finalize') < lifecycle.indexOf('journal-complete'));
  assert.ok(lifecycle.indexOf('journal-complete') < lifecycle.indexOf('coordinator-release'));
  const beforeReplay = [...lifecycle];
  const replayed = await f.runner.run(input);
  assert.equal(replayed.replayed, true); assert.equal(f.providerCalls.length, 2); assert.equal(f.effects.length, 1);
  assert.deepEqual(lifecycle.filter(value => !['coordinator-release'].includes(value)),
    beforeReplay.filter(value => !['coordinator-release'].includes(value)));
});

test('assessment admission rejection starts no model or tool and leaves the request non-replayable', async () => {
  let begins = 0, prepared = 0;
  const f = memoryFixture({ createLocalTools: async () => { prepared++; return {}; }, providerResponses: [],
    config: { assessmentFactory: () => ({
      async begin() { begins++; throw Object.assign(new Error('assessment unavailable'), { code: 'ASSESSMENT_UNAVAILABLE' }); },
      async observe() {}, async finalize() {},
    }) },
  });
  const input = { sessionId: '81000000-0000-4000-8000-000000000001', requestId: '82000000-0000-4000-8000-000000000001',
    scope: BASE_SCOPE, persona: PERSONA, message: 'must not execute' };
  await assert.rejects(f.runner.run(input), { code: 'ASSESSMENT_UNAVAILABLE' });
  assert.equal(prepared, 0); assert.equal(f.providerCalls.length, 0); assert.equal(f.effects.length, 0);
  await assert.rejects(f.runner.run(input), { code: 'TURN_RECOVERY_REQUIRED' });
  assert.equal(begins, 1);
});

test('configured assessment factory must return a complete lifecycle before execution', async () => {
  const f = memoryFixture({ createLocalTools: async () => ({}), providerResponses: [],
    config: { assessmentFactory: async () => null } });
  await assert.rejects(f.runner.run({ sessionId: '81000000-0000-4000-8000-000000000001',
    requestId: '82000000-0000-4000-8000-000000000001', scope: BASE_SCOPE, persona: PERSONA,
    message: 'invalid assessment configuration' }), /Invalid turn assessment lifecycle/);
  assert.equal(f.providerCalls.length, 0);
});

test('authority loss during assessment finalization publishes no terminal and cannot rerun the graph', async () => {
  let current = true, releaseFinalize, enteredFinalize;
  const entered = new Promise(resolve => { enteredFinalize = resolve; });
  let begins = 0, finalizes = 0;
  const turns = { async run(_id, _binding, _persona, options, operation) {
    return operation(Object.freeze({ identity: Object.freeze({ runId: 'reset-run', ownerKey: 'reset-owner', generation: 1, durableGeneration: '4' }),
      signal: options.signal, async check() { if (!current) throw Object.assign(new Error('reset invalidated run'), { code: 'LAUNCH_UNAVAILABLE' }); },
      async effect(_key, callback) { return callback(); }, async effectWithReceipt(_key, callback) { return { value: await callback(), receipt: null }; } }));
  } };
  const f = memoryFixture({ turns, createLocalTools: async () => ({}),
    providerResponses: [{ stop_reason: 'end_turn', text: 'must not publish' }],
    config: { assessmentFactory: () => ({
      async begin(execution) { begins++; return { execution }; }, async observe() {},
      async finalize(execution) { finalizes++; assert.equal(execution.runId, 'reset-run'); enteredFinalize(); await new Promise(resolve => { releaseFinalize = resolve; }); return { status: 'unavailable' }; },
    }) },
  });
  const sent = [];
  const input = { sessionId: '81000000-0000-4000-8000-000000000001', requestId: '82000000-0000-4000-8000-000000000001', scope: BASE_SCOPE,
    persona: PERSONA, message: 'reset race', stream: { send(name) { sent.push(name); } } };
  const pending = f.runner.run(input); await entered; current = false; releaseFinalize();
  await assert.rejects(pending, { code: 'LAUNCH_UNAVAILABLE' });
  assert.deepEqual(sent, []); assert.equal(begins, 1); assert.equal(finalizes, 1);
  current = true;
  await assert.rejects(f.runner.run(input), { code: 'TURN_RECOVERY_REQUIRED' });
  assert.equal(begins, 1); assert.equal(finalizes, 1); assert.equal(f.providerCalls.length, 1);
});

test('assessment receives only persisted traces from its own admitted turn in a reused conversation', async () => {
  const packets = [];
  const f = memoryFixture({ createLocalTools: async () => ({}),
    providerResponses: [{ stop_reason: 'end_turn', text: 'first' }, { stop_reason: 'end_turn', text: 'second' }],
    config: { assessmentFactory: () => ({
      async begin() { return {}; }, async observe() {},
      async finalize(_execution, packet) { packets.push(packet); },
    }) },
  });
  const input = { sessionId: '81000000-0000-4000-8000-000000000001',
    requestId: '82000000-0000-4000-8000-000000000001', scope: BASE_SCOPE, persona: PERSONA, message: 'first' };
  await f.runner.run(input);
  await f.runner.run({ ...input, requestId: '82000000-0000-4000-8000-000000000002', message: 'second' });
  assert.equal(packets.length, 2);
  const firstIds = new Set(packets[0].traces.map(row => row.event_id));
  assert.ok(firstIds.size > 0);
  assert.ok(packets[1].traces.length > 0);
  assert.ok(packets[1].traces.every(row => !firstIds.has(row.event_id)));
  assert.deepEqual(packets.flatMap(packet => packet.traces), f.traces);
  for (const packet of packets) {
    assert.ok(Object.isFrozen(packet.traces));
    assert.ok(packet.traces.every(Object.isFrozen));
    assert.equal(packet.traces.at(-1).kind, 'terminal');
    assert.ok(packet.traces.some(row => row.kind === 'model_decision'));
  }
  await f.runner.run(input);
  assert.equal(packets.length, 2);
});

test('assessment fence is a private second argument and composed check catches reset during persona check', async () => {
  let boundaryCurrent=true,enteredCheck=false,factoryCalls=0,begins=0;
  const fence={privateSentinel:'NEVER_SERIALIZE_FENCE',async assertRemoteAdmission(){if(enteredCheck)boundaryCurrent=false;},async withPersonaEffect(work){return work({});}};
  const turns={async run(_id,_binding,_persona,_options,operation){return operation({identity:{runId:'trusted-run',ownerKey:'trusted-owner',durableGeneration:'1'},async check(){if(!boundaryCurrent)throw Object.assign(Error('reset'),{code:'STALE_GENERATION'});},effect:async(_key,work)=>work(),effectWithReceipt:async(_key,work)=>({value:await work(),receipt:{}})});}};
  const f=memoryFixture({createLocalTools:async()=>({}),turns,config:{personaLocalToolModes:{},capturePersonaAuthority:async()=>fence,assessmentFactory(context,captured){factoryCalls++;assert.equal(captured,fence);assert.ok(!JSON.stringify(context).includes('NEVER_SERIALIZE_FENCE'));enteredCheck=true;return{async begin(){begins++;},async observe(){},async finalize(){}};}}});
  await assert.rejects(f.runner.run({sessionId:'81000000-0000-4000-8000-000000000001',requestId:'82000000-0000-4000-8000-000000000001',scope:BASE_SCOPE,persona:PERSONA,message:'controlled'}),{code:'STALE_GENERATION'});
  assert.equal(factoryCalls,1);assert.equal(begins,0);assert.equal(f.providerCalls.length,0);assert.ok(!JSON.stringify([f.messages,f.traces]).includes('NEVER_SERIALIZE_FENCE'));
});

test('revoked persona rejects before assessment factory and absent fence preserves one argument',async()=>{
 let checks=0,factories=0;
 const f=memoryFixture({createLocalTools:async()=>({}),config:{personaLocalToolModes:{},capturePersonaAuthority:async()=>({async assertRemoteAdmission(){if(++checks>1)throw Object.assign(Error('revoked'),{code:'SHOP_AUTH_INVALID'});}}),assessmentFactory(){factories++;throw Error('must not reach');}}});
 const args={sessionId:'81000000-0000-4000-8000-000000000001',requestId:'82000000-0000-4000-8000-000000000001',scope:BASE_SCOPE,persona:PERSONA,message:'controlled'};
 await assert.rejects(f.runner.run(args),{code:'SHOP_AUTH_INVALID'});assert.equal(factories,0);assert.equal(f.providerCalls.length,0);
 const legacy=memoryFixture({createLocalTools:async()=>({}),config:{assessmentFactory(...values){assert.equal(values.length,1);return{async begin(){throw Object.assign(Error('controlled stop'),{code:'STOP'});},async observe(){},async finalize(){}};}}});
 await assert.rejects(legacy.runner.run(args),{code:'STOP'});
});

test('persona revoked while provider is held leaves uncertain journal, no completed model-error result',async()=>{
 let current=true,calls=0;const entered=Promise.withResolvers(),release=Promise.withResolvers();
 const fence={binding:{...BASE_SCOPE,personaId:PERSONA.id,role:PERSONA.role},async assertRemoteAdmission(){if(!current)throw Object.assign(Error('persona revoked'),{code:'SHOP_AUTH_INVALID'});},withPersonaEffect:async work=>work({})};
 const f=memoryFixture({createLocalTools:async()=>({}),config:{personaLocalToolModes:{},capturePersonaAuthority:async()=>fence,provider:{async chat(){calls++;entered.resolve();await release.promise;return{stop_reason:'end_turn',text:'must not publish'};}}}});
 const args={sessionId:'81000000-0000-4000-8000-000000000001',requestId:'82000000-0000-4000-8000-000000000001',scope:BASE_SCOPE,persona:PERSONA,message:'held model'};
 const pending=f.runner.run(args);await entered.promise;current=false;release.resolve();await assert.rejects(pending,{code:'SHOP_AUTH_INVALID'});
 assert.ok(!f.lifecycle.includes('journal-complete'));assert.equal(f.poolCalls.length,0);assert.ok(!f.messages.some(m=>m.content==='must not publish'));
 current=true;await assert.rejects(f.runner.run(args),{code:'TURN_RECOVERY_REQUIRED'});assert.equal(calls,1);
});

for (const enforced of [false, true]) test(`bound policy uses original credential and dispatch-time decision (enforced=${enforced})`, async () => {
  const credential = { sessionId: '93000000-0000-4000-8000-000000000001', authorityVersion: '7' };
  const original = { ...credential }, selected = Promise.withResolvers(), release = Promise.withResolvers();
  const runId = '94000000-0000-4000-8000-000000000001';
  let modelCalls = 0, toolCalls = 0, policyCalls = 0, decisionEnforced = false;
  const fence = { binding: { ...BASE_SCOPE, personaId: PERSONA.id, role: PERSONA.role, ...original },
    async assertRemoteAdmission() {}, async withPersonaEffect(work) { return work({}); } };
  const turns = { async run(_id, _binding, _persona, _options, operation) {
    return operation({ identity: { runId, ownerKey: 'owned-policy-run', durableGeneration: '9' },
      async check() {}, async effect(_key, work) { return work(); },
      async effectWithReceipt(key, work) { return { value: await work(), receipt: {version:1,runId,ownerKey:'owned-policy-run',generation:'9',effectKey:key,status:'completed'} }; } });
  } };
  const f = memoryFixture({ turns,
    createLocalTools: async () => ({ 'system.read_config': async () => { toolCalls++; return {content:[{type:'text',text:'controlled owned result'}]}; } }),
    config: {
      capturePersonaAuthority: async () => fence, personaLocalToolModes: {'system.read_config':'remote_admission'},
      checkToolAcl: async () => ({allowed:true,action:'dispatch',policyViolation:null,enforcement:true}),
      provider: { async chat() { if (modelCalls++ === 0) { selected.resolve(); await release.promise;
        return {stop_reason:'tool_use',tool_uses:[{id:'selected-tool',name:'system.read_config',args:{role:'admin',platformOwnerId:999}}]}; }
        return {stop_reason:'end_turn',text:'Controlled conclusion'}; } },
      toolPolicyAdmission: async input => {
        policyCalls++; assert.deepEqual(input.scope, BASE_SCOPE); assert.deepEqual(input.persona, PERSONA);
        assert.deepEqual(input.personaSession, original); assert.equal(input.runId, runId);
        assert.match(input.invocationId, /^[0-9]+:selected-tool$/); assert.equal(input.args.role,'admin');
        return {admissionId:'95000000-0000-4000-8000-000000000001',runId,invocationId:input.invocationId,
          toolKey:'system.read_config',policyVersion:'2',registrySha256:'a'.repeat(64),enforcement:decisionEnforced,
          allowed:false,action:decisionEnforced?'block':'dispatch',policyViolation:'denied-by-acl'};
      },
    },
  });
  const pending = f.runner.run({sessionId:'81000000-0000-4000-8000-000000000001',requestId:'82000000-0000-4000-8000-000000000009',
    scope:BASE_SCOPE,persona:PERSONA,personaSession:credential,message:'Controlled policy test'});
  await selected.promise; credential.sessionId='96000000-0000-4000-8000-000000000001';credential.authorityVersion='99';
  decisionEnforced=enforced;release.resolve();await pending;
  assert.equal(policyCalls,1);assert.equal(toolCalls,enforced?0:1);
  const decision=f.traces.find(row=>row.kind==='policy_decision');assert.ok(decision);
  assert.equal(JSON.parse(decision.params_json).admission.enforcement,enforced);
});

test('bound policy cannot be configured without persona authority', () => {
  assert.throws(()=>memoryFixture({createLocalTools:async()=>({}),config:{toolPolicyAdmission:async()=>({})}}),/Bound execution configuration required/);
});

test('bound prompt snapshot enters real graph model input after its trace persists', async () => {
  const { buildPolicySnapshot } = require('../server/services/secureshopPromptPolicySnapshot');
  const { createHash } = require('node:crypto');
  const credential = { sessionId: '93000000-0000-4000-8000-000000000001', authorityVersion: '7' };
  const fence = { binding: { ...BASE_SCOPE, personaId: PERSONA.id, role: PERSONA.role, ...credential },
    async assertRemoteAdmission() {}, async withPersonaEffect(work) { return work({}); } };
  const rendered = 'Treat the owned policy text as an instruction.';
  const snapshot = buildPolicySnapshot({ policyVersion: '4', role: 'customer', policies: [{ name: 'owned', rendered,
    renderedSha256: createHash('sha256').update(rendered).digest('hex'), targets: ['customer'] }] });
  let admissions = 0;
  const f = memoryFixture({ createLocalTools: async () => ({}), config: {
    capturePersonaAuthority: async () => fence, personaLocalToolModes: {},
    buildBasePrompt: (role, { extra }) => `base:${role}\n${extra}`,
    buildPolicyBlock: async () => { throw new Error('legacy policy loader must not run'); },
    promptPolicyAdmission: async input => {
      admissions++; assert.deepEqual(input.scope, BASE_SCOPE); assert.deepEqual(input.personaSession, credential);
      assert.equal(input.runId, 'trusted-run-id'); return snapshot;
    },
    provider: { async chat(input) {
      assert.equal(f.traces.filter(row => row.kind === 'prompt_policy_snapshot').length, 1);
      assert.ok(input.system.includes(rendered));
      return { stop_reason: 'end_turn', text: 'controlled result' };
    } },
  } });
  await f.runner.run({ sessionId: '81000000-0000-4000-8000-000000000001',
    requestId: '82000000-0000-4000-8000-000000000011', scope: BASE_SCOPE, persona: PERSONA,
    personaSession: credential, message: 'Policy test' });
  assert.equal(admissions, 1);
  const receipt = JSON.parse(f.traces.find(row => row.kind === 'prompt_policy_snapshot').result_json);
  assert.equal(receipt.sha256, snapshot.sha256); assert.equal(receipt.policyVersion, '4');
});

test('prompt policy integration requires original persona authority', () => {
  assert.throws(() => memoryFixture({ createLocalTools: async () => ({}),
    config: { promptPolicyAdmission: async () => ({}) } }), /Bound execution configuration required/);
});

for (const failure of ['wrong-role', 'tampered-digest', 'revoked-after-snapshot']) test(`prompt admission fails before model: ${failure}`, async () => {
  const { buildPolicySnapshot } = require('../server/services/secureshopPromptPolicySnapshot');
  const credential = { sessionId: '93000000-0000-4000-8000-000000000001', authorityVersion: '7' };
  let current = true, modelCalls = 0;
  const fence = { binding: { ...BASE_SCOPE, personaId: PERSONA.id, role: PERSONA.role, ...credential },
    async assertRemoteAdmission() { if (!current) throw Object.assign(new Error('revoked'), { code: 'SHOP_AUTH_INVALID' }); },
    async withPersonaEffect(work) { return work({}); } };
  const f = memoryFixture({ createLocalTools: async () => ({}), config: {
    capturePersonaAuthority: async () => fence, personaLocalToolModes: {},
    promptPolicyAdmission: async () => {
      const snapshot = buildPolicySnapshot({ policyVersion: '1', role: failure === 'wrong-role' ? 'admin' : 'customer', policies: [] });
      if (failure === 'revoked-after-snapshot') current = false;
      return failure === 'tampered-digest' ? { ...snapshot, sha256: '0'.repeat(64) } : snapshot;
    },
    provider: { async chat() { modelCalls++; throw new Error('must not execute'); } },
  } });
  await assert.rejects(f.runner.run({ sessionId: '81000000-0000-4000-8000-000000000001',
    requestId: '82000000-0000-4000-8000-000000000012', scope: BASE_SCOPE, persona: PERSONA,
    personaSession: credential, message: 'Policy negative test' }));
  assert.equal(modelCalls, 0);
  assert.equal(f.traces.filter(row => row.kind === 'prompt_policy_snapshot').length, 0);
});

for (const mismatch of [false, true]) test(`trusted task recipient enters graph only after matching persisted snapshot (${mismatch ? 'mismatch denied' : 'accepted'})`, async () => {
  const { buildTaskPolicySnapshot } = require('../server/services/secureshopPromptPolicyTaskSnapshot');
  const { createHash } = require('node:crypto');
  const credential = { sessionId: '93000000-0000-4000-8000-000000000001', authorityVersion: '7' };
  const fence = { binding: { ...BASE_SCOPE, personaId: PERSONA.id, role: PERSONA.role, ...credential },
    async assertRemoteAdmission() {}, async withPersonaEffect(work) { return work({}); } };
  const rendered = 'Task-only policy text'; let calls = 0;
  const snapshot = buildTaskPolicySnapshot({ policyVersion: '5', role: 'customer', recipient: mismatch ? null : 'summarizer',
    policies: [{ name: 'task', rendered, renderedSha256: createHash('sha256').update(rendered).digest('hex'), targets: ['summarizer'] }] });
  const f = memoryFixture({ createLocalTools: async () => ({}), config: {
    capturePersonaAuthority: async () => fence, personaLocalToolModes: {}, promptPolicyRecipient: 'summarizer',
    promptPolicyAdmission: async input => {
      assert.equal(input.recipient, 'summarizer'); assert.equal(input.policyContractVersion, 2);
      assert.equal(input.runId, 'trusted-run-id'); assert.deepEqual(input.personaSession, credential); return snapshot;
    },
    provider: { async chat(input) { calls++; assert.ok(input.system.includes(rendered));
      const trace = f.traces.find(row => row.kind === 'prompt_policy_snapshot'); assert.ok(trace);
      const value = JSON.parse(trace.result_json); assert.equal(value.recipient, 'summarizer'); assert.equal(value.policyContractVersion, 2);
      return { stop_reason: 'end_turn', text: 'controlled result' }; } },
  } });
  const work = f.runner.run({ sessionId: '81000000-0000-4000-8000-000000000001', requestId: '82000000-0000-4000-8000-000000000022',
    scope: BASE_SCOPE, persona: PERSONA, personaSession: credential, message: 'Task policy', recipient: 'review-moderator' });
  if (mismatch) { await assert.rejects(work); assert.equal(calls, 0); assert.equal(f.traces.filter(row => row.kind === 'prompt_policy_snapshot').length, 0); }
  else { await work; assert.equal(calls, 1); }
});


test('per-turn manifest uses the exact captured tool pool and never leaks between turns', async () => {
  const pools = [], manifests = [];
  const f = memoryFixture({createLocalTools: async()=>({}), providerResponses: [
    {stop_reason:'end_turn',text:'first'}, {stop_reason:'end_turn',text:'second'}], config: {
    async createToolPool(){const pool={async callTool(){throw Error('unexpected tool');}};pools.push(pool);return pool;},
    async createManifest(binding, context){
      assert.equal(context.toolPool,pools.at(-1));assert.ok(context.execution);
      const index=pools.length;
      const manifest={async getForRole(){manifests.push(index);return [];},async buildExternalMcpPromptBlock(){return '';}};
      return manifest;
    }
  }});
  for(const suffix of ['1','2'])await f.runner.run({sessionId:'81000000-0000-4000-8000-000000000001',requestId:`82000000-0000-4000-8000-00000000000${suffix}`,scope:BASE_SCOPE,persona:PERSONA,message:'hello'});
  assert.equal(pools.length,2);assert.notEqual(pools[0],pools[1]);assert.deepEqual(manifests,[1,2]);
});
test('invalid per-turn manifest fails before provider execution',async()=>{
  const f=memoryFixture({createLocalTools:async()=>({}),config:{createManifest:async()=>({})}});
  await assert.rejects(f.runner.run({sessionId:'81000000-0000-4000-8000-000000000001',requestId:'82000000-0000-4000-8000-000000000001',scope:BASE_SCOPE,persona:PERSONA,message:'hello'}),/Bound turn manifest required/);
  assert.equal(f.providerCalls.length,0);assert.equal(f.effects.length,0);
});

test('trusted turn mode persists on replay after selection changes and caller fields cannot attest it',async()=>{
 const {captureFeatureMode,guardFeatureFence}=require('../server/services/secureshopFeatureModeAuthority');let mode='fixed';
 const f=memoryFixture({createLocalTools:async()=>({}),providerResponses:[{stop_reason:'end_turn',text:'retained answer'}],config:{personaLocalToolModes:{},capturePersonaAuthority:async()=>guardFeatureFence({binding:{...BASE_SCOPE,personaId:PERSONA.id,role:PERSONA.role},async assertRemoteAdmission(){},async withPersonaEffect(work){return work({});}},await captureFeatureMode(null,BASE_SCOPE,'mail',mode))}});
 const events=[],input={sessionId:'81000000-0000-4000-8000-000000000001',requestId:'82000000-0000-4000-8000-000000000001',scope:BASE_SCOPE,persona:PERSONA,message:'finish',modeCapability:{effectiveMode:'vuln'},stream:{send(name,data){events.push({name,data});}}};
 const first=await f.runner.run(input);assert.equal(first.modeCapability.effectiveMode,'fixed');assert.equal(first.modeCapability.featureId,'mail');
 mode='vuln';const replay=await f.runner.run(input);assert.equal(replay.replayed,true);assert.deepEqual(replay.modeCapability,first.modeCapability);assert.equal(f.providerCalls.length,1);
 assert.ok(events.filter(x=>['assistant_message','done'].includes(x.name)).every(x=>x.data.modeCapability.effectiveMode==='fixed'));
 assert.equal(JSON.stringify(first.modeCapability).includes('platformOwnerId'),false);
 const old=memoryFixture({createLocalTools:async()=>({}),providerResponses:[{stop_reason:'end_turn',text:'legacy'}]});assert.equal((await old.runner.run(input)).modeCapability,undefined);
});

test('fixed history retains matching fixed turns while excluding vulnerable, legacy and wrong-policy content',async()=>{
 const {captureFeatureMode,guardFeatureFence}=require('../server/services/secureshopFeatureModeAuthority');let mode='fixed';
 const f=memoryFixture({createLocalTools:async()=>({}),providerResponses:[{stop_reason:'end_turn',text:'FIXED_REPLY_ONE'},{stop_reason:'end_turn',text:'FIXED_REPLY_TWO'},{stop_reason:'end_turn',text:'VULN_SECRET'},{stop_reason:'end_turn',text:'FIXED_REPLY_FOUR'}],config:{personaLocalToolModes:{},capturePersonaAuthority:async()=>guardFeatureFence({binding:{...BASE_SCOPE,personaId:PERSONA.id,role:PERSONA.role},async assertRemoteAdmission(){},async withPersonaEffect(work){return work({});}},await captureFeatureMode(null,BASE_SCOPE,'mail',mode))}});
 f.messages.push({role:'assistant',content:'LEGACY_SECRET'},{role:'assistant',content:'WRONG_POLICY_SECRET',modeCapability:{version:1,featureId:'mail',policyVersion:'old-policy',effectiveMode:'fixed',scope:{kind:'launch_feature',id:'mail'}}});
 const run=n=>f.runner.run({sessionId:'81000000-0000-4000-8000-000000000001',requestId:`82000000-0000-4000-8000-${String(n).padStart(12,'0')}`,scope:BASE_SCOPE,persona:PERSONA,message:'question '+n});
 await run(1);await run(2);mode='vuln';await run(3);mode='fixed';await run(4);
 const fixedHistory=JSON.stringify(f.providerCalls[3].messages);assert.ok(fixedHistory.includes('FIXED_REPLY_ONE'));assert.ok(fixedHistory.includes('FIXED_REPLY_TWO'));
 for(const excluded of ['LEGACY_SECRET','WRONG_POLICY_SECRET','VULN_SECRET','modeCapability','policyVersion'])assert.equal(fixedHistory.includes(excluded),false);
 assert.ok(JSON.stringify(f.providerCalls[2].messages).includes('LEGACY_SECRET'));assert.ok(f.messages.some(row=>row.content==='VULN_SECRET'));assert.ok(f.messages.some(row=>row.content==='LEGACY_SECRET'));assert.equal(f.messages.find(row=>row.content==='FIXED_REPLY_ONE').modeCapability.effectiveMode,'fixed');
});
