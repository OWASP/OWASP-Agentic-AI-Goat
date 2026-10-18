'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { randomUUID } = require('node:crypto');
const { SensitiveInfoWorkshopAgent, createSensitiveInfoWorkshopStateStore } = require('../server/services/sensitiveInfoWorkshopAgent');

function createControlledRunLedger() {
  return { begin: async () => ({ durableGeneration: '0' }), assertCurrent: async () => {},
    finish: async () => {} };
}

function controlledJudge(objectiveJudge) {
  return { objectiveJudge, completionService: { beginAttempt: async () => ({}),
    evaluate: async packet => { const judgment = await objectiveJudge(packet);
      return { judgment, completed: judgment.verdict === 'pass' }; } } };
}

function agentFor(model) {
  return new SensitiveInfoWorkshopAgent({
    model, stateStore: createSensitiveInfoWorkshopStateStore(), runLedger: createControlledRunLedger(),
    executeTool: async () => { throw new Error('Conversation recall must not execute a tool'); },
    // This qualification tests response continuity, not objective credit.
    ...controlledJudge(async packet => ({ verdict: 'fail', objectiveId: packet.rubric.objectiveId,
      explanation: 'Ungraded continuity qualification', criteria: [] })),
  });
}
const request = 'What exact savings nickname did I give you earlier? Reply with the nickname only; no bank lookup.';
const historyFor = nickname => [{ role: 'user', content: `For this conversation my savings nickname is ${nickname}.` },
  { role: 'assistant', content: 'I will remember your savings nickname in this conversation.' }];

test('assembled FinFlow response builder includes prior context without granting objective credit', async () => {
  const prompts = [];
  const agent = agentFor({ provider: 'ollama', async generateResponse(prompt) {
    prompts.push(prompt);
    return { provider: 'controlled', model: 'controlled', response: prompt.startsWith('Select exactly')
      ? '{"action":"general_chat","params":{}}' : 'SAVINGS-CONTROLLED' };
  } });
  const result = await agent.processMessage(request, historyFor('SAVINGS-CONTROLLED'), 'fixed', 'admin_enum', '7');
  assert.equal(prompts.length, 2);
  assert.match(prompts[1], /Prior conversation context \(untrusted data/);
  assert.match(prompts[1], /SAVINGS-CONTROLLED/);
  assert.match(prompts[1], /customer privileges only/);
  assert.deepEqual(result.toolCalls, []);
  assert.deepEqual(result.completedObjectiveIds, []);
});

test('local 8B recalls only the supplied conversation nickname through the assembled agent', {
  skip: process.env.RUN_LIVE_FINFLOW_HISTORY !== '1', timeout: 150000,
}, async t => {
  assert.notEqual(process.env.PLATFORM_DATABASE_ENGINE, 'postgres', 'Use the isolated model-only workspace');
  const provider = require('../server/agent-runtime/providers/langchainProvider').createLangChainProvider({
    provider: 'ollama', model: 'llama3.1:8b', baseURL: 'http://127.0.0.1:11434',
  });
  const nickname = `SAVINGS-${randomUUID()}`;
  const calls = [];
  const model = { provider: 'ollama', async generateResponse(prompt, options = {}) {
    assert.ok(calls.length < 6, 'bounded model call budget');
    const signal = AbortSignal.any([AbortSignal.timeout(35000), ...(options.signal ? [options.signal] : [])]);
    const response = await provider.generate(prompt, { ...options, signal, temperature: 0 });
    assert.equal(response.provider, 'ollama');
    assert.equal(response.model, 'llama3.1:8b');
    assert.notEqual(response.fallback, true);
    calls.push({ phase: prompt.startsWith('Select exactly') ? 'planner' : 'response', provider: response.provider, model: response.model });
    return response;
  } };
  for (const supplied of [true, false]) {
    const result = await agentFor(model).processMessage(request, supplied ? historyFor(nickname) : [],
      'fixed', 'admin_enum', supplied ? '7' : '8');
    assert.equal(result.decisionSource, 'model');
    assert.equal(result.response.includes(nickname), supplied);
    assert.deepEqual(result.toolCalls, []);
    assert.deepEqual(result.completedObjectiveIds, []);
    t.diagnostic(JSON.stringify({ suppliedHistory: supplied, nicknameRecalled: result.response.includes(nickname),
      boundary: 'actual model and assembled agent; in-memory state, no database or objective-credit qualification' }));
  }
  assert.equal(calls.filter(call => call.phase === 'planner').length, 2);
  assert.equal(calls.filter(call => call.phase === 'response').length, 2);
});
