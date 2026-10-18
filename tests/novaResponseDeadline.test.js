'use strict';
// Injected provider-interface simulation only; no network or actual-model proof.
const test = require('node:test');
const assert = require('node:assert/strict');
const { createAgent } = require('../server/services/novaAgentService');

test('NOVA forwards the owned turn deadline and disables provider rotation for formatting', async () => {
  const calls = [];
  const query = '{"$regex":".*"}';
  const model = {
    provider: 'ollama',
    async generateResponse(prompt, options) {
      calls.push(options);
      if (prompt.includes('Select exactly one tool')) {
        return { response: JSON.stringify({ tool: 'search_papers', params: { query } }), provider: 'ollama', model: 'fixture-model' };
      }
      return { response: 'controlled formatted result', provider: 'ollama', model: 'fixture-model' };
    },
  };
  const agent = createAgent({
    model,
    runLedger: null,
    store: {
      getHistory: async () => [],
      saveMessage: async () => {},
      searchPapers: async () => [{ paper_id: 'PAPER-2024-001', title: 'Controlled paper' }],
    },
  });
  const result = await agent.invoke('fixture-owner', `Search papers using this exact query: ${query}`, 'vuln');
  assert.equal(result.presentation.narrative.text, 'controlled formatted result');
  assert.equal(result.presentation.narrative.source, 'model');
  assert.match(result.response, /controlled formatted result/);
  assert.match(result.response, /Tool result — search_papers \(server-rendered\)/);
  assert.match(result.response, /PAPER-2024-001/);
  assert.equal(calls.length, 3);
  assert.ok(calls.every(options => options.allowFallback === false));
  assert.ok(calls.every(options => options.signal && typeof options.signal.throwIfAborted === 'function'));
});

test('NOVA formatting failure remains an explicit deterministic fallback, never a provider fallback result', async () => {
  let calls = 0;
  const model = {
    provider: 'ollama',
    async generateResponse(prompt) {
      calls++;
      if (prompt.includes('Select exactly one tool')) {
        return { response: JSON.stringify({ tool: 'search_papers', params: { query: '{"$regex":".*"}' } }), provider: 'ollama', model: 'fixture-model' };
      }
      throw new Error('formatter unavailable');
    },
  };
  const agent = createAgent({
    model,
    runLedger: null,
    store: {
      getHistory: async () => [],
      saveMessage: async () => {},
      searchPapers: async () => [{ paper_id: 'PAPER-2024-001', title: 'Controlled paper' }],
    },
  });
  const result = await agent.invoke('fixture-owner-failure', 'Search papers using this exact query: {"$regex":".*"}', 'vuln');
  assert.equal(calls, 3);
  assert.equal(result.presentation.narrative.source, 'unavailable');
  assert.equal(result.presentation.narrative.text, '');
  assert.equal(result.presentation.narrative.errorCode, 'MODEL_RESPONSE_ERROR');
  assert.match(result.response, /Model explanation unavailable/);
  assert.match(result.response, /The workshop query returned 1 record/);
  assert.match(result.response, /PAPER-2024-001/);
  assert.doesNotMatch(result.response, /provider fallback|\blate\b/);
});
