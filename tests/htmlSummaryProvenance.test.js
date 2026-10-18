'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { runHtmlSummaryGraph } = require('../server/agent-runtime/htmlSummaryGraph');
const gadget = '<img src=x onerror="example()">';
function deps(response, execution) {
  return { aiService: { chatWithMessages: async (_messages, options) => {
    assert.equal(options.allowFallback, false);
    assert.equal(options.signal, execution?.signal);
    return response;
  } }, extractHtmlFragments: () => [gadget],
  isRefusalOrStripped: answer => !answer.includes(gadget), LLM_STARTING: 'Unavailable', execution };
}
test('only actual returned HTML is marked preserved; refusal stays visible', async () => {
  const actual = { response: `Summary ${gadget}`, provider: 'ollama', model: 'llama3.1:8b' };
  const result = await runHtmlSummaryGraph(gadget, null, 'email', deps(actual));
  assert.equal(result.answer, actual.response);
  assert.equal(result.modelGenerated, true);
  assert.equal(result.htmlPreserved, true);
  const refused = await runHtmlSummaryGraph(gadget, null, 'email', deps({ ...actual, response: 'I cannot help.' }));
  assert.equal(refused.answer, 'I cannot help.');
  assert.equal(refused.htmlPreserved, false);
  assert.equal(refused.answer.includes(gadget), false);
});
test('mock, fallback and missing provider identity cannot masquerade as real summary', async () => {
  for (const change of [{ mocked: true }, { fallback: true }, { provider: 'mock' }, { model: null }, { provider: null }, { response: null, text: gadget }, { provider: 'scripted' }]) {
    const result = await runHtmlSummaryGraph(gadget, null, 'email', deps({
      response: gadget, provider: 'ollama', model: 'llama3.1:8b', ...change }));
    assert.equal(result.llmOk, false); assert.equal(result.modelGenerated, false);
    assert.equal(result.htmlPreserved, false); assert.equal(result.answer, 'Unavailable');
  }
});
test('owner cancellation during provider call propagates after the provider drains', async () => {
  const controller = new AbortController();
  const execution = { signal: controller.signal, check: async () => controller.signal.throwIfAborted() };
  let release, entered;
  const started = new Promise(resolve => { entered = resolve; });
  const pending = new Promise(resolve => { release = resolve; });
  const config = deps(null, execution);
  config.aiService.chatWithMessages = async (_messages, options) => {
    assert.equal(options.signal, controller.signal); entered(); await pending;
    return { response: gadget, provider: 'ollama', model: 'llama3.1:8b' };
  };
  let settled = false;
  const running = runHtmlSummaryGraph(gadget, null, 'email', config);
  const outcome = assert.rejects(running, /reset/).then(() => { settled = true; });
  await started;
  controller.abort(new Error('reset'));
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(settled, false);
  release(); await outcome;
});

test('preserved HTML requires every source fragment, not just the first gadget', async () => {
  const config = deps({ response: gadget, provider: 'ollama', model: 'llama3.1:8b' });
  config.extractHtmlFragments = () => [gadget, '<p>second fragment</p>'];
  const result = await runHtmlSummaryGraph(gadget, null, 'email', config);
  assert.equal(result.htmlPreserved, false);
  assert.equal(result.answer, gadget);
});

test('warning prose does not erase actual preserved HTML evidence', async () => {
  const answer = `Security warning: ${gadget}`;
  const config = deps({ response: answer, provider: 'ollama', model: 'llama3.1:8b' });
  config.isRefusalOrStripped = () => true;
  const result = await runHtmlSummaryGraph(gadget, null, 'email', config);
  assert.equal(result.htmlPreserved, true);
  assert.equal(result.answer, answer);
});

test('opaque summary authority binds producer, exact mail context and owner execution', async () => {
  const { inspectHtmlSummary, buildCsrfEmailSummaryContext } = require('../server/agent-runtime/htmlSummaryGraph');
  const controller = new AbortController();
  const execution = { ownerKey: '["CSRF","7"]', runId: 'summary-run', generation: 2,
    durableGeneration: '9007199254740993', signal: controller.signal, check: async () => controller.signal.throwIfAborted() };
  const mail = { subject: 'Owned email', from: 'owned@example.test', body: gadget };
  const context = buildCsrfEmailSummaryContext(mail);
  const actual = await runHtmlSummaryGraph(context, null, 'email', deps({
    response: gadget, provider: 'ollama', model: 'llama3.1:8b' }, execution));
  const scope = { execution, context, kind: 'email' };
  assert.equal(Object.isFrozen(actual), true);
  assert.equal((await inspectHtmlSummary(actual, scope)).htmlPreserved, true);
  assert.equal(await inspectHtmlSummary({ ...actual }, scope), null);
  assert.equal(await inspectHtmlSummary(actual, { ...scope, context: buildCsrfEmailSummaryContext({ ...mail, subject: 'Other' }) }), null);
  assert.equal(await inspectHtmlSummary(actual, { ...scope, execution: { ...execution } }), null);
  assert.equal(await inspectHtmlSummary(actual, { ...scope, kind: 'rag' }), null);
  execution.durableGeneration = '9007199254740994';
  assert.equal(await inspectHtmlSummary(actual, scope), null);
  execution.durableGeneration = '9007199254740993';
  controller.abort(new Error('reset'));
  assert.equal(await inspectHtmlSummary(actual, scope), null);
});
