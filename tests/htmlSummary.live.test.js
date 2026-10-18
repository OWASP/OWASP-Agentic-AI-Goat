'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');

test('local 8B summary preserves actual provider text without reconstruction', {
  skip: process.env.DVAIA_HTML_SUMMARY_LIVE !== '1', timeout: 45000,
}, async t => {
  const base = 'http://127.0.0.1:11434';
  const model = 'llama3.1:8b';
  const digest = '46e0c10c039e019119339687c3c1757cc81b9da49709a3b3924863ba87ca666e';
  const originalFetch = global.fetch;
  async function verifyModel() {
    const response = await originalFetch(`${base}/api/tags`, { signal: AbortSignal.timeout(3000) });
    assert.equal(response.status, 200);
    const tags = await response.json();
    assert.equal(tags.models.find(row => row.name === model)?.digest, digest);
  }
  await verifyModel();
  let calls = 0;
  global.fetch = async (input, init) => {
    const request = new Request(input, init);
    assert.equal(request.url, `${base}/api/chat`);
    assert.equal(request.method, 'POST');
    assert.equal(++calls, 1, 'one provider request maximum');
    return originalFetch(request);
  };
  try {
    const { createLangChainProvider } = require('../server/agent-runtime/providers/langchainProvider');
    const { runHtmlSummaryGraph, inspectHtmlSummary } = require('../server/agent-runtime/htmlSummaryGraph');
    const provider = createLangChainProvider({ provider: 'ollama', model, baseURL: base });
    let actual;
    const fragment = '<strong>Workshop starts at 09:00.</strong>';
    const context = `Subject: Workshop\n${fragment}`;
    const controller = new AbortController();
    // Controlled execution lease; the provider call itself is the real local model.
    const execution = { ownerKey: JSON.stringify(['CSRF', '1']), runId: 'live-summary-proof',
      generation: 0, durableGeneration: '9007199254740993', signal: controller.signal,
      async check() { controller.signal.throwIfAborted(); } };
    const result = await runHtmlSummaryGraph(context, null, 'email', {
      execution,
      aiService: { async chatWithMessages(messages, options) {
        actual = await provider.chat(messages, [], options); return actual;
      } }, extractHtmlFragments: () => [fragment], LLM_STARTING: 'Unavailable',
    });
    assert.equal(calls, 1);
    assert.equal(actual.provider, 'ollama'); assert.equal(actual.model, model);
    assert.equal(actual.fallback, false); assert.equal(actual.mocked, false);
    assert.equal(result.modelGenerated, true);
    assert.equal(result.answer, actual.response.trim());
    assert.equal(result.htmlPreserved, actual.response.trim().includes(fragment));
    const scope = { execution, context, kind: 'email' };
    const authority = await inspectHtmlSummary(result, scope);
    assert.equal(authority.provider, 'ollama');
    assert.equal(authority.model, model);
    assert.equal(authority.answerDigest, createHash('sha256').update(actual.response.trim()).digest('hex'));
    assert.equal(await inspectHtmlSummary({ ...result }, scope), null);
    assert.equal(await inspectHtmlSummary(result, { ...scope, context: `${context} changed` }), null);
    controller.abort();
    assert.equal(await inspectHtmlSummary(result, scope), null);
    t.diagnostic(JSON.stringify({ provider: result.provider, model: result.model,
      responseSha256: createHash('sha256').update(result.answer).digest('hex'),
      htmlPreserved: result.htmlPreserved, calls }));
  } finally { global.fetch = originalFetch; }
  await verifyModel();
});
