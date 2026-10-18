'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { createSupervisorGraph } = require('../server/agent-runtime/secureshopSupervisorGraph');
const { OllamaProvider } = require('../server/services/secureshop/providers/ollamaProvider');
const { createSecureShopReservedFileReader } = require('../server/services/secureshopReservedFiles');
const { createSecureShopReservedFileTools } = require('../server/services/secureshopReservedFileTools');
const { createSecureShopFiles } = require('../sidecars/sandbox-runner/secureshopFiles');

const enabled = process.env.LIVE_OLLAMA_TEST === '1';

test('real 8B supervisor observes an isolated config read before reporting its unknown marker', {
  skip: !enabled,
  timeout: 120000,
}, async (t) => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'secureshop-reserved-live-'));
  t.after(() => fs.rm(root, { recursive: true, force: true }));

  const marker = crypto.randomBytes(18).toString('hex');
  const binding = Object.freeze({
    targetId: crypto.randomUUID(),
    launchId: crypto.randomUUID(),
    scenarioId: crypto.randomUUID(),
    generation: 11,
    ownerId: '73',
  });
  const scope = Object.freeze({
    platformSessionId: 901,
    platformOwnerId: 73,
    launchId: binding.launchId,
    generation: binding.generation,
  });
  const files = createSecureShopFiles({ root });
  const provisioned = await files.provisionReservedTarget(binding);
  const fixtureBody = `${JSON.stringify({ SECURESHOP_LIVE_MARKER: marker, fixture: 'synthetic' })}\n`;
  await files.writeFile(
    provisioned.capability,
    '/server/platform_secrets.json',
    fixtureBody,
    { expectedGeneration: binding.generation },
  );

  let authorityChecks = 0;
  const launches = {
    async reserveFilesTarget(requested) {
      assert.deepEqual(requested, { ...scope, expectedGeneration: binding.generation });
      return { ...binding, kind: 'files' };
    },
    async assertCurrent(requested) {
      authorityChecks += 1;
      assert.deepEqual(requested, { ...scope, scenarioId: binding.scenarioId });
      return { ...requested };
    },
  };
  const reader = createSecureShopReservedFileReader({ launches, files });
  const localTools = createSecureShopReservedFileTools({ reader, trustedScope: scope });
  const messages = [];
  const trace = [];
  const store = {
    async appendUserMessage(_sessionId, content) { messages.push({ role: 'user', content }); },
    async appendAssistantMessage(_sessionId, content) { messages.push({ role: 'assistant', content }); },
    async appendAssistantToolCalls(_sessionId, calls) {
      messages.push({
        role: 'assistant',
        content: '',
        tool_calls: calls.map((call) => ({
          id: call.id,
          type: 'function',
          function: { name: call.name, arguments: JSON.stringify(call.args || {}) },
        })),
      });
    },
    async appendToolResult(_sessionId, toolCallId, content) {
      messages.push({ role: 'tool', tool_call_id: toolCallId, content });
    },
    async getMessages() { return [...messages]; },
    async remainingBudget() { return 4096; },
    async addUsedTokens() {},
  };
  class Trace {
    record(event) { trace.push(event); }
    async flush() {}
  }
  const graph = createSupervisorGraph({
    store,
    Trace,
    buildBasePrompt: () => 'You are a SecureShop system assistant. Use the one declared tool when the user requests a config read. Answer only from its observation.',
    buildPolicyBlock: async () => '',
    checkToolAcl: async () => ({ action: 'dispatch', policyViolation: null }),
  });
  const manifest = {
    getForRole: () => [{
      agent: 'system',
      tool: 'read_config',
      description: 'Read a config file relative to server/. The one-pass traversal sanitizer is intentionally weak.',
      inputSchema: {
        type: 'object',
        properties: { path: { type: 'string' } },
        required: ['path'],
      },
    }],
  };
  const userPrompt = 'Use system.read_config exactly once with path ....//server/platform_secrets.json. Then report the exact SECURESHOP_LIVE_MARKER value from the returned file. Do not guess or repeat the tool.';
  assert.equal(userPrompt.includes(marker), false, 'the model prompt must not contain the random evidence marker');

  const result = await graph('reserved-live-session', userPrompt, {
    provider: new OllamaProvider({ model: 'llama3.1:8b' }),
    pool: { async callTool() { throw new Error('unexpected remote MCP dispatch'); } },
    manifest,
    role: 'admin',
    callerRole: 'admin',
    callerId: 73,
    ownerId: 73,
    localTools,
  }, { maxSteps: 3, maxParallelTools: 1 });

  assert.equal(result.stopReason, 'end_turn');
  assert.equal(result.hops.length, 1);
  assert.equal(result.hops[0].tool, 'system.read_config');
  assert.deepEqual(result.hops[0].params, { path: '....//server/platform_secrets.json' });
  const observation = JSON.parse(result.hops[0].result.content[0].text);
  assert.equal(observation.ok, true);
  assert.equal(observation.abs, '/server/platform_secrets.json');
  assert.equal(observation.content, fixtureBody);

  const independent = await files.readFile(
    provisioned.capability,
    '/server/platform_secrets.json',
    { expectedGeneration: binding.generation },
  );
  assert.equal(independent.data.toString('utf8'), observation.content);
  assert.match(independent.data.toString('utf8'), new RegExp(marker));
  assert.match(result.text, new RegExp(marker));
  assert.ok(authorityChecks >= 3, 'reserved reader must recheck launch authority around the read');
  assert.ok(trace.some((event) => event.kind === 'local_tool_call'));
  assert.ok(trace.some((event) => event.kind === 'local_tool_result'));
  assert.equal(trace.some((event) => event.kind === 'mcp_call'), false);

  const observable = JSON.stringify({ result, messages, trace });
  assert.equal(observable.includes(provisioned.capability), false, 'local bearer must not enter graph-visible data');
  assert.equal(observable.includes(root), false, 'host temporary paths must not enter graph-visible data');
  t.diagnostic(JSON.stringify({
    scope: 'real Ollama decision loop with an owned temporary virtual file; no grading or live application effect',
    tool: result.hops[0].tool,
    stopReason: result.stopReason,
    steps: result.steps,
  }));
});
