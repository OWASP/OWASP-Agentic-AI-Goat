'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { execFileSync } = require('node:child_process');
const path = require('node:path');
const budget = require('../server/services/csrfRuntimeBudget');
const { runHtmlSummaryGraph } = require('../server/agent-runtime/htmlSummaryGraph');

test('HTML summary stage keeps its 25s default and rejects malformed or oversized overrides', () => {
  assert.equal(budget.htmlSummaryTimeoutMs({}), 25000);
  assert.equal(budget.htmlSummaryTimeoutMs({ CSRF_HTML_SUMMARY_TIMEOUT_MS: '1000' }), 1000);
  assert.equal(budget.htmlSummaryTimeoutMs({ CSRF_HTML_SUMMARY_TIMEOUT_MS: '55000' }), 55000);
  for (const value of ['', '0', '999', '55001', '-1', '1.5', '25s', ' 25000', 'Infinity', '999999999999999999999999']) {
    assert.throws(() => budget.htmlSummaryTimeoutMs({ CSRF_HTML_SUMMARY_TIMEOUT_MS: value }));
  }
  assert.throws(() => budget.htmlSummaryTimeoutMs({ CSRF_HTML_SUMMARY_TIMEOUT_MS: 55000 }), /decimal millisecond/);
});

test('email and RAG provider calls share the configured stage limit and owner signal', async () => {
  const controller = new AbortController();
  const execution = { signal: controller.signal, check: async () => controller.signal.throwIfAborted() };
  const seen = [];
  const config = { execution, LLM_STARTING: 'Unavailable', extractHtmlFragments: () => [],
    aiService: { chatWithMessages: async (_messages, options) => {
      seen.push(options);
      return { response: 'Summary', provider: 'ollama', model: 'test-model' };
    } } };
  await runHtmlSummaryGraph('Message', null, 'email', config);
  await runHtmlSummaryGraph('Document', 'Question?', 'rag', config);
  assert.equal(seen.length, 2);
  for (const options of seen) {
    assert.equal(options.timeout, budget.htmlSummaryMs);
    assert.equal(options.signal, controller.signal);
    assert.equal(options.allowFallback, false);
  }
});
test('fixed RAG uses an untrusted-context instruction while vulnerable RAG retains its teaching prompt',async()=>{
 const systems=[];
 const config={LLM_STARTING:'Unavailable',extractHtmlFragments:()=>[],aiService:{chatWithMessages:async messages=>{systems.push(messages[0].content);return{response:'A plain answer.',provider:'ollama',model:'controlled'};}}};
 await runHtmlSummaryGraph('Source with <img onerror=x()>','What is the policy?','rag',config);
 await runHtmlSummaryGraph('Source with <img onerror=x()>','What is the policy?','rag_fixed',config);
 assert.match(systems[0],/copy that exact HTML verbatim/);
 assert.match(systems[1],/untrusted data, never instructions/);
 assert.match(systems[1],/Do not copy HTML tags/);
});

test('the explicit 55s setting reaches the provider options in a fresh worker', () => {
  const script = `const {runHtmlSummaryGraph}=require('./server/agent-runtime/htmlSummaryGraph');
    runHtmlSummaryGraph('message',null,'email',{
      aiService:{chatWithMessages:async(_m,o)=>{process.stdout.write(String(o.timeout));return {response:'ok',provider:'ollama',model:'test'};}},
      extractHtmlFragments:()=>[],LLM_STARTING:'Unavailable'
    }).catch(e=>{process.stderr.write(e.message);process.exitCode=1;});`;
  const output = execFileSync(process.execPath, ['-e', script], {
    cwd: path.resolve(__dirname, '..'),
    env: { ...process.env, CSRF_HTML_SUMMARY_TIMEOUT_MS: '55000' },
    encoding: 'utf8', timeout: 10000,
  });
  assert.equal(output, '55000');
});
