'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

test('actual8B multilingual Judge evaluates language and policy outcomes', {
  skip: process.env.DPI_MULTILINGUAL_ACTUAL8B !== 'yes', timeout: 240000,
}, async () => {
  const target = process.env.DPI_MULTILINGUAL_EVIDENCE_PATH;
  assert.ok(target && path.isAbsolute(target), 'Root-owned absolute evidence path required');
  const { createLangChainProvider } = require('../server/agent-runtime/providers/langchainProvider');
  const { createObjectiveJudge } = require('../server/agent-runtime/objectiveJudge');
  const { evaluateDpiObjective } = require('../server/services/promptInjectionWorkshop');
  const transport = createLangChainProvider({ provider: 'ollama', model: 'llama3.1:8b', baseURL: 'http://127.0.0.1:11434' });
  const evidence = { scope: 'Judge-only over supplied actor responses; no actor, HTTP, persistence or credit proof', status: 'running', cases: [] };
  const persist = () => {
    const pending = `${target}.${process.pid}.pending`;
    fs.writeFileSync(pending, JSON.stringify(evidence, null, 2) + '\n', { mode: 0o600 });
    fs.renameSync(pending, target);
  };
  persist();
  try {
    for (const fixture of require('./fixtures/dpiMultilingualJudgeCases')) {
      const record = { ...fixture, providerCalls: [] };
      evidence.cases.push(record);
      const judge = createObjectiveJudge({ model: { generate: async (prompt, options) => {
        const call = { prompt, response: null };
        record.providerCalls.push(call); persist();
        const response = await transport.generate(prompt, options);
        call.response = response; persist();
        return response;
      } } });
      record.judgment = await evaluateDpiObjective(fixture.request, fixture.response, 'multi_language', { judge });
      record.passed = record.judgment.verdict === fixture.expected;
      persist();
      assert.ok(record.providerCalls.length > 0);
      for (const call of record.providerCalls) {
        assert.equal(call.response.provider, 'ollama');
        assert.equal(call.response.model, 'llama3.1:8b');
        assert.notEqual(call.response.mocked, true);
        assert.notEqual(call.response.fallback, true);
      }
    }
    assert.deepEqual(evidence.cases.filter(item => !item.passed).map(item => ({ name: item.name, expected: item.expected, actual: item.judgment.verdict })), []);
    evidence.status = 'complete'; persist();
  } catch (error) {
    evidence.status = 'incomplete'; evidence.failure = { name: error.name, message: error.message }; persist(); throw error;
  }
});
