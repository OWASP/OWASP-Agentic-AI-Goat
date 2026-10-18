'use strict';
const { waitForFixtureEntry } = require('./helpers/controlledObjectiveBoundary');
const { test } = require('node:test');
const assert = require('node:assert/strict');
const Module = require('node:module');
const originalLoad = Module._load;
Module._load = function guardedLoad(request, parent, isMain) {
  if (/(?:^|\/)authDb(?:\.js)?$/.test(request)) throw new Error('Test isolation violation: live authDb import');
  return originalLoad.call(this, request, parent, isMain);
};
const { classifySensitiveIntercept, runSensitiveInterceptGraph } = require('../server/agent-runtime/sensitiveInfoGraph');
const { runCodeBotGraph } = require('../server/agent-runtime/codeBotGraph');
// These cases have no registered grading candidate; entering evaluation is a failure.
const noCandidateCompletion = owner => ({
  async beginAttempt({userId, execution}) {
    assert.equal(String(userId), owner);
    assert.equal(typeof execution.runId, 'string');
    assert.ok(execution.runId);
    await execution.check();
    return Object.freeze({});
  },
  async evaluate() { throw Error('No registered objective should be evaluated'); },
});
test('FinFlow graph preserves intercept priority and fixed-mode bypass', async () => {
  assert.equal(classifySensitiveIntercept('list tools ../private https://example.test', 'vulnerable'), 'tool_enum');
  assert.equal(classifySensitiveIntercept('download ../private and check https://example.test', 'vulnerable'), 'path_traversal');
  assert.equal(classifySensitiveIntercept('check credit https://example.test', 'vulnerable'), 'ssrf');
  assert.equal(classifySensitiveIntercept('read admin log', 'fixed'), 'tool_loop');
  const handlers = Object.fromEntries(['tool_enum','llm_identify','tool_version','path_traversal','ssrf','error_leak','admin_tool','tool_loop'].map(name => [name, async () => ({ selected: name })]));
  assert.deepEqual(await runSensitiveInterceptGraph('list tools', 'vulnerable', handlers), { selected: 'tool_enum' });
});
test('actual FinFlow agent graph executes injected tool and preserves raw result DTO/grading', async () => {
  const { SensitiveInfoWorkshopAgent, createSensitiveInfoWorkshopStateStore } = require('../server/services/sensitiveInfoWorkshopAgent');
  const calls = [];
  const agent = new SensitiveInfoWorkshopAgent({runLedger: {}, completionService: noCandidateCompletion('7'), decisionMode:'scripted', stateStore: createSensitiveInfoWorkshopStateStore(),
    model: { async chatWithTools(messages) {
      if (!calls.length) return { content: '', tool_calls: [{ function: { name: 'get_account_info', arguments: { account_id: 'demo' } } }] };
      assert.equal(messages.at(-1).content, 'RAW_INJECTION'); return { content: 'Summary' };
    } },
    executeTool: async (name, args, mode) => { calls.push([name, args, mode]); return { result: 'RAW_INJECTION', llmContent: 'RAW_INJECTION', securityFlag: 'vulnerability_exploited' }; },
    judge: async () => ['fixture_objective'],
    objectiveJudge: async () => ({verdict:'fail',objectiveId:'tool_enum',provider:'explicit-fixture'}),
  });
  const result = await agent.processMessage('hello', [], 'vulnerable', null, '7');
  assert.equal(result.toolCalls[0].result, 'RAW_INJECTION');
  assert.match(result.response, /RAW_INJECTION/);
  assert.deepEqual(result.completedObjectiveIds, []); // Unregistered candidate cannot bypass the structured gate.
  const fixed = new SensitiveInfoWorkshopAgent({runLedger: {}, completionService: noCandidateCompletion('8'), decisionMode:'scripted', stateStore: createSensitiveInfoWorkshopStateStore(), model: { chatWithTools: async () => ({ content: 'tool name' }) }, judge: async () => { throw new Error('must not judge fixed mode'); } });
  assert.deepEqual((await fixed.processMessage('hello', [], 'fixed', null, '8')).completedObjectiveIds, []);
});
function codeBotDeps(model, executeTool) {
  return { aiService: model, executeCodeBotTool: executeTool, CODEBOT_TOOL_SCHEMAS: [], FIXED_SYSTEM_PROMPT: 'fixed', VULNERABLE_SYSTEM_PROMPT: 'vulnerable',
    tryParseTextToolCall: () => null, extractJsonFromMessage: () => null, logger: { info() {} } };
}
test('CodeBot graph executes tool loop then preserves exploited response', async () => {
  let called = 0;
  const deps = codeBotDeps({ async chatWithTools() { return !called ? { tool_calls: [{ function: { name: 'check_dependencies', arguments: { manifest: '{}' } } }] } : { content: 'Summary' }; } },
    async () => { called++; return { security: 'rce_executed', transform_output: 'RAW_FIXTURE_OUTPUT' }; });
  const result = await runCodeBotGraph({ userMessage: 'hi', conversationHistory: [], mode: 'vulnerable', userId: '7' }, deps);
  assert.equal(called, 1); assert.equal(result.calledToolName, 'check_dependencies'); assert.match(result.finalResponse, /RAW_FIXTURE_OUTPUT/);
});
test('CodeBot text-tool and manifest fallback retain order and fixed results', async () => {
  const modes = [];
  const deps = codeBotDeps({ async chatWithTools(messages) {
    const latest = messages.at(-1);
    if (latest?.role === 'tool') {
      assert.equal(JSON.parse(latest.content).security, 'blocked');
      return { content: 'The dependency manifest was rejected by fixed-mode validation.' };
    }
    if (latest?.role === 'system' && /selecting an action/.test(latest.content)) {
      return { content: '{"action":"check_dependencies"}' };
    }
    return { content: 'tool JSON' };
  } }, async (name, params, mode) => { modes.push(mode); return { security: 'blocked', pkg_name: 'fixture' }; });
  deps.tryParseTextToolCall = () => ({ name: 'check_dependencies', params: { manifest: '{}' } });
  deps.extractJsonFromMessage = () => { throw new Error('must not retry a blocked manifest'); };
  const result = await runCodeBotGraph({ userMessage: '{}', conversationHistory: [], mode: 'fixed', userId: '7' }, deps);
  assert.match(result.finalResponse, /rejected/); assert.equal(result.toolResult.security, 'blocked'); assert.deepEqual(modes, ['fixed']);
  deps.tryParseTextToolCall = () => null;
  deps.extractJsonFromMessage = () => ({ name: 'fixture' });
  assert.equal((await runCodeBotGraph({ userMessage: '{}', conversationHistory: [], mode: 'fixed', userId: '7' }, deps)).calledToolName, 'check_dependencies');
});
test('CodeBot reset fences slow model before its proposed tool can execute', async () => {
  const { createRunCoordinator } = require('../server/agent-runtime/runCoordinator');
  const coordinator = createRunCoordinator({ family: 'CodeBot-test', ledger: null });
  let enter, resume;
  const entered = new Promise(resolve => { enter = resolve; });
  const paused = new Promise(resolve => { resume = resolve; });
  let toolCalls = 0, resetDone = false;
  const deps = codeBotDeps({ async chatWithTools() { enter(); await paused; return { tool_calls: [{ function: { name: 'check_dependencies', arguments: {} } }] }; } }, async () => { toolCalls++; });
  const request = coordinator.run('7', {}, execution => runCodeBotGraph({ userMessage: 'hi', conversationHistory: [], mode: 'vulnerable', userId: '7' }, { ...deps, execution }));
  const rejected = assert.rejects(request, { name: 'AbortError' });
  await waitForFixtureEntry(entered, request).catch(error => { resume(); throw error; });
  const resetting = coordinator.reset('7', async () => { resetDone = true; });
  resume(); await Promise.all([rejected, resetting]);
  assert.equal(toolCalls, 0); assert.equal(resetDone, true);
});
