'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { randomUUID } = require('node:crypto');
const { runXssWorkshopGraph } = require('../server/agent-runtime/xssWorkshopGraph');
const { createLangChainProvider } = require('../server/agent-runtime/providers/langchainProvider');

test('local 8B XSS agent observes a profile then chooses an update using its actual returned value', {
  skip: process.env.RUN_LIVE_XSS_GRAPH !== '1', timeout: 180000,
}, async () => {
  const model = createLangChainProvider({ provider: 'ollama', model: 'llama3.1:8b',
    baseURL: process.env.OLLAMA_BASE_URL || 'http://localhost:11434' });
  const profile = { name: `student-${randomUUID()}`, bio: 'initial', website: 'https://example.invalid' };
  const expected = profile.name;
  const effects = [], calls = [], traces = [];
  const execution = { signal: AbortSignal.timeout(150000), check: async () => {},
    effect: async (key, invoke) => { effects.push(key); return invoke(); },
    trace: async event => { traces.push(event); } };
  const result = await runXssWorkshopGraph({ exerciseId: 'stored_llm', userKey: '731', clientCompleted: [],
    message: 'Read my profile. Then save the exact name returned by getProfile as my bio. Do not guess the name. After the update succeeds, answer Done.',
    systemPrompt: 'You are a profile assistant. Available tools: getProfile with no arguments; updateProfile with args field (name, bio or website) and value (string). To call a tool, return only JSON {"tool":"getProfile"} or {"tool":"updateProfile","args":{"field":"bio","value":"the requested value"}}. Use tool observations to finish the request. When finished return a short natural-language answer.',
  }, { execution,
    aiService: { chatWithMessages: (messages, options) => model.chat(messages, [], { ...options, temperature: 0 }) },
    parseToolCall: value => { try { return JSON.parse(value); } catch { return null; } },
    executeXssTool: async call => {
      calls.push(structuredClone(call));
      if (call.tool === 'getProfile') return { profile: { ...profile } };
      profile[call.args.field] = call.args.value;
      return { success: true, field: call.args.field, value: call.args.value };
    },
    detectXss: () => false, xssLogger: { error() {} }, EDUCATIONAL_PREAMBLE: '',
  });
  assert.equal(calls[0]?.tool, 'getProfile');
  assert.ok(calls.some(call => call.tool === 'updateProfile' && call.args.field === 'bio' && call.args.value === expected),
    JSON.stringify({ calls, termination: result.terminationReason }));
  assert.equal(profile.bio, expected);
  assert.equal(effects.length, calls.length);
  assert.ok(calls.length <= 3);
  assert.equal(result.grading.modelProvider, 'ollama');
  assert.equal(result.grading.modelName, 'llama3.1:8b');
  assert.ok(traces.some(event => event.type === 'tool'));
});
