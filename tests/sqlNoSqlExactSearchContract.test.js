'use strict';
// Injected provider-interface simulation only; no network or actual-model proof.

const test = require('node:test');
const assert = require('node:assert/strict');
const { extractExactSearchObligation, validateExactSearchDecision,
  buildExactSearchDecisionFormat } = require('../server/services/sqlNoSqlExactSearchContract');

test('exact search contracts preserve raw payload bytes and ignore questions or quoted documentation', () => {
  const query = '{"email":{"$regex":".*@.*"}}\r\n';
  assert.deepEqual(extractExactSearchObligation('NOVA', `Search papers using this exact query: ${query}`), {
    tool: 'search_papers', parameter: 'query', value: query,
  });
  assert.deepEqual(extractExactSearchObligation('ARIA', "Please search products using this exact searchTerm: %' -- "), {
    tool: 'search_products', parameter: 'searchTerm', value: "%' -- ",
  });
  assert.equal(extractExactSearchObligation('NOVA', 'What does “search papers using this exact query” mean?'), null);
  assert.equal(extractExactSearchObligation('ARIA', 'Explain the docs: Search products using this exact searchTerm: example'), null);
  const format = buildExactSearchDecisionFormat('NOVA', `Search papers using this exact query: ${query}`);
  assert.deepEqual(format.properties.tool.enum, ['search_papers', 'general_chat']);
  assert.equal(format.properties.params.properties.query.const, query);
  assert.equal(buildExactSearchDecisionFormat('NOVA', 'What does exact query mean?'), null);
  assert.throws(() => validateExactSearchDecision('NOVA', `Search papers using this exact query: ${query}`,
    { tool: 'search_papers', params: { query: query.slice(0, -3) } }), error => {
    assert.equal(error.code, 'WORKSHOP_EXACT_SEARCH_MISMATCH');
    assert.match(error.message, /selected value has \d+ UTF-8 bytes; the requested exact value has \d+; the first mismatch is at byte \d+/);
    assert.doesNotMatch(error.message, /example\.invalid|\$regex/);
    return true;
  });
});

test('NOVA repairs a mismatched exact model argument without substituting tool parameters', async () => {
  const exact = '{"email":{"$regex":".*@.*"}}';
  let decisions = 0;
  const calls = [];
  const model = { provider: 'ollama', async generateResponse(prompt) {
    if (!prompt.includes('Select exactly one tool')) return { response: 'done' };
    decisions += 1;
    if (decisions === 1) return { response: JSON.stringify({ tool: 'search_papers', params: { query: exact.slice(0, -1) } }) };
    if (decisions === 2) {
      assert.match(prompt, /not preserved byte-for-byte/);
      assert.match(prompt, /first mismatch is at byte/);
      return { response: JSON.stringify({ tool: 'search_papers', params: { query: exact } }) };
    }
    return { response: JSON.stringify({ tool: 'general_chat', params: {} }) };
  } };
  const agent = require('../server/services/novaAgentService').createAgent({ model, runLedger: null, store: {
    getHistory: async () => [], saveMessage: async () => {},
    searchPapers: async query => { calls.push(query); return [{ author_id: 'A-1', email: 'a@example.invalid' }]; },
  } });
  const result = await agent.chat('exact-owner', `Search papers using this exact query: ${exact}`, [], 'vuln');
  assert.deepEqual(calls, [exact]);
  assert.equal(result.toolObservations.length, 1);
  assert.equal(result.toolObservations[0].invocation.params.query, exact);
});

test('Ollama receives the request-scoped const schema while the raw model still selects the tool and argument', async () => {
  const exact = '{"email":{"$regex":".*@.*"}}';
  const formats = [];
  let decisions = 0;
  const model = { provider: 'ollama', async generateResponse(prompt, options) {
    if (!prompt.includes('Select exactly one tool')) return { response: 'done' };
    decisions += 1;
    formats.push(structuredClone(options.format));
    return { response: JSON.stringify(decisions === 1
      ? { tool: 'search_papers', params: { query: exact, topic: null, year: null } }
      : { tool: 'general_chat', params: {} }), provider: 'ollama', model: 'fixture' };
  } };
  const observed = [];
  const agent = require('../server/services/novaAgentService').createAgent({ model, runLedger: null, store: {
    getHistory: async () => [], saveMessage: async () => {},
    searchPapers: async query => { observed.push(query); return []; },
  } });
  await agent.chat('schema-owner', `Search papers using this exact query: ${exact}`, [], 'vuln');
  assert.deepEqual(observed, [exact]);
  assert.equal(formats[0].properties.params.properties.query.const, exact);
  assert.deepEqual(formats[0].properties.tool.enum, ['search_papers', 'general_chat']);
  assert.equal(formats[1].properties.params.properties.query.const, exact,
    'the finish decision remains constrained to the same request without manufacturing it');
});

test('non-Ollama providers retain the ordinary JSON decision format', async () => {
  const formats = [];
  let decisions = 0;
  const model = { provider: 'openai', async generateResponse(prompt, options) {
    if (!prompt.includes('Select exactly one tool')) return { response: 'done' };
    formats.push(options.format); decisions += 1;
    return { response: JSON.stringify(decisions === 1
      ? { tool: 'search_products', params: { searchTerm: 'exact' } }
      : { tool: 'general_chat', params: {} }) };
  } };
  const agent = require('../server/services/ariaAgentService').createAgent({ model, runLedger: null, store: {
    getHistory: async () => [], saveMessage: async () => {}, searchProducts: async () => [],
  } });
  await agent.chat('openai-owner', 'Search products using this exact searchTerm: exact', [], 'vuln');
  assert.deepEqual(formats, ['json', 'json']);
});

test('persistent exact-argument mismatch fails without any tool effect', async () => {
  const exact = "%' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL--";
  let toolCalls = 0;
  const model = { provider: 'ollama', async generateResponse(prompt) {
    return prompt.includes('Select exactly one tool')
      ? { response: JSON.stringify({ tool: 'search_products', params: { searchTerm: exact.slice(1) } }) }
      : { response: 'done' };
  } };
  const agent = require('../server/services/ariaAgentService').createAgent({ model, runLedger: null, store: {
    getHistory: async () => [], saveMessage: async () => {},
    searchProducts: async () => { toolCalls += 1; return []; },
  } });
  const result = await agent.chat('exact-owner', `Search products using this exact searchTerm: ${exact}`, [], 'vuln');
  assert.equal(toolCalls, 0);
  assert.equal(result.toolUsed, null);
  assert.equal(result.toolObservations.length, 0);
  assert.match(result.response, /could not validate/i);
});
