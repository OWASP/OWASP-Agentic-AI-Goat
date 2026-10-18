'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const parser = require('../client/node_modules/@babel/parser');
const { STEPS, runRenderedMcpTrust } = require('./fixtures/renderedSecureShopMcpTrust');
const { runRenderedPersonaInbox } = require('./fixtures/renderedSecureShopPersona');
const { runRenderedStoredBrowser } = require('./fixtures/renderedSecureShopBrowser');
const { runRenderedSecureShopReviewWorkflow } = require('./fixtures/renderedSecureShopReviewWorkflow');

const ORIGIN = 'http://127.0.0.1:3000';
const TIMEOUT = 1234;

function response(pathname, body, requestBody = {}, method = 'POST') {
  const request = Object.freeze({ method: () => method, postData: () => JSON.stringify(requestBody) });
  return Object.freeze({ url: () => ORIGIN + pathname, request: () => request,
    status: () => 200, json: async () => body });
}

function queuedPage(rows) {
  return Object.freeze({
    async waitForResponse(predicate, options) {
      const next = rows.shift();
      assert.ok(next, 'Unexpected response wait');
      assert.equal(options.timeout, TIMEOUT);
      assert.equal(predicate(next), true);
      return next;
    },
  });
}

function recordingFrame(waits) {
  return Object.freeze({
    async waitForFunction(predicate, options, value) {
      assert.equal(typeof predicate, 'function');
      waits.push({ options, value });
    },
    async evaluate(predicate) { assert.equal(typeof predicate, 'function'); },
  });
}

test('MCP trust DOM waits use mutation polling without changing their timeout contract', async () => {
  const waits = [];
  const responses = STEPS.map(([title, label, path, scenario], index) => response(
    `/api/secureshop/v2/mcp-trust${path}`,
    { text: `synthetic observation ${index}` },
    { scenario, request_id: `00000000-0000-4000-8000-${String(index).padStart(12, '0')}` },
  ));
  const evidence = Object.freeze({
    async snapshot() { return {}; },
    async verify(value) { return { runId: `run-${value.scenario}` }; },
  });
  const result = await runRenderedMcpTrust({ page: queuedPage(responses), frame: recordingFrame(waits),
    origin: ORIGIN, evidence, timeoutMs: TIMEOUT });
  assert.equal(result.results.length, 3);
  assert.equal(responses.length, 0);
  assert.equal(waits.length, STEPS.length + 3);
  assert.ok(waits.every(wait => assert.deepEqual(wait.options,
    { timeout: TIMEOUT, polling: 'mutation' }) === undefined));
});

test('persona ACL and result DOM waits use mutation polling without changing their timeout contract', async () => {
  const waits = [];
  const request = { message_id: 41, request_id: '00000000-0000-4000-8000-000000000041' };
  const responses = [
    response('/api/secureshop/v2/persona-inbox/read', { accesses: [{ body: 'synthetic advisory body' }] }, request),
    response('/api/secureshop/v2/persona-inbox/enforce', { ok: true, acl: { mode: 'enforced', version: 2 } }),
    response('/api/secureshop/v2/persona-inbox/readiness',
      { ready: true, acl: { mode: 'enforced', version: 2 } }, {}, 'GET'),
    response('/api/secureshop/v2/persona-inbox/read', { accesses: [{ body: null }] }, request),
  ];
  const evidence = Object.freeze({
    async snapshot() { return {}; },
    async verify({ mode }) { return { runId: `run-${mode}` }; },
  });
  const result = await runRenderedPersonaInbox({ page: queuedPage(responses), frame: recordingFrame(waits),
    origin: ORIGIN, evidence, messageId: 41, subject: 'Synthetic subject', timeoutMs: TIMEOUT });
  assert.equal(result.results.length, 2);
  assert.equal(responses.length, 0);
  assert.equal(waits.length, 4);
  assert.ok(waits.every(wait => assert.deepEqual(wait.options,
    { timeout: TIMEOUT, polling: 'mutation' }) === undefined));
});

test('stored-browser property waits use bounded interval polling', async () => {
  const waits = [], body = 'Synthetic review body';
  const page = queuedPage([
    response('/api/secureshop/products/8/reviews', { ok: true, review_id: 7 }, { body }),
    response('/api/secureshop/products/8/reviews/7/browser-attempt',
      { completed: true }, { request_id: '00000000-0000-4000-8000-000000000007' }),
  ]);
  const frame = Object.freeze({
    async waitForSelector() {}, async $eval() {},
    async waitForFunction(predicate, options) { assert.equal(typeof predicate, 'function');waits.push(options); },
  });
  const evidence = Object.freeze({ async snapshot() { return {}; },
    async verify() { return { reviewId: 7 }; } });
  await runRenderedStoredBrowser({ page, frame, origin: ORIGIN, productId: 8, body, evidence,
    timeoutMs: TIMEOUT });
  assert.deepEqual(waits, [{ timeout: TIMEOUT, polling: 100 },
    { timeout: TIMEOUT, polling: 100 }]);
});

test('review workflow separates property polling from DOM mutation polling', async () => {
  const customerWaits = [], merchantWaits = [], reviewBody = 'Synthetic plain-text review';
  const requestId = '00000000-0000-4000-8000-000000000009';
  const customerPage = queuedPage([response('/api/secureshop/products/7/reviews',
    { ok: true, review_id: 9 }, { body: reviewBody, rating: 1 })]);
  const listeners = new Set();
  const merchantPage = {
    on(event, listener) { assert.equal(event, 'response');listeners.add(listener); },
    off(event, listener) { assert.equal(event, 'response');listeners.delete(listener); },
  };
  const moderationResponse = response('/api/secureshop/merchant/reviews/moderate-all',
    { ok: true }, { request_id: requestId });
  const customerFrame = Object.freeze({
    async waitForSelector() {}, async $eval() {}, async evaluate() {},
    async waitForFunction(predicate, options) { assert.equal(typeof predicate, 'function');customerWaits.push(options); },
  });
  const merchantFrame = Object.freeze({
    async evaluate() { for (const listener of listeners) listener(moderationResponse); },
    async waitForFunction(predicate, options) { assert.equal(typeof predicate, 'function');merchantWaits.push(options); },
  });
  const submission = Object.freeze({ reviewId: 9 });
  const evidence = Object.freeze({
    async snapshot() { return {}; }, async verifySubmission() { return submission; },
    async verifyModeration() { return { runId: 'synthetic-run', reviewId: 9, awarded: true }; },
  });
  await runRenderedSecureShopReviewWorkflow({ page: customerPage, customerFrame, origin: ORIGIN,
    productId: 7, reviewBody, evidence, timeoutMs: TIMEOUT,
    activateMerchant: async () => ({ page: merchantPage, frame: merchantFrame }) });
  assert.deepEqual(customerWaits, [{ timeout: TIMEOUT, polling: 100 },
    { timeout: TIMEOUT, polling: 'mutation' }]);
  assert.deepEqual(merchantWaits, [{ timeout: TIMEOUT, polling: 'mutation' },
    { timeout: TIMEOUT, polling: 'mutation' }, { timeout: TIMEOUT, polling: 'mutation' },
    { timeout: TIMEOUT, polling: 'mutation' }]);
  assert.equal(listeners.size, 0);
});

test('every SecureShop fixture wait declares polling suited to its observed signal', () => {
  const files = ['fullBackendRenderedSecureShop.js', 'renderedSecureShopBrowser.js',
    'renderedSecureShopMcpTrust.js', 'renderedSecureShopPersona.js',
    'renderedSecureShopReviewWorkflow.js', 'renderedSecureShopSession.js',
    'renderedSecureShopSsrf.js'];
  const observed = [];
  function visit(node, source, file) {
    if (!node || typeof node !== 'object') return;
    if (node.type === 'CallExpression' && node.callee?.type === 'MemberExpression'
        && node.callee.property?.name === 'waitForFunction') {
      const options = node.arguments[1];
      assert.equal(options?.type, 'ObjectExpression', `${file} wait options`);
      const polling = options.properties.find(property => property.key?.name === 'polling');
      assert.ok(polling, `${file} must not use default rAF polling`);
      const predicate = source.slice(node.arguments[0].start, node.arguments[0].end);
      const propertySignal = predicate.includes('.value') || predicate.includes('window.origin');
      assert.equal(polling.value.type, propertySignal ? 'NumericLiteral' : 'StringLiteral', file);
      assert.equal(polling.value.value, propertySignal ? 100 : 'mutation', file);
      observed.push({ file, propertySignal });
    }
    for (const value of Object.values(node)) {
      if (Array.isArray(value)) value.forEach(child => visit(child, source, file));
      else if (value && typeof value === 'object' && typeof value.type === 'string') visit(value, source, file);
    }
  }
  for (const file of files) {
    const source = fs.readFileSync(path.join(__dirname, 'fixtures', file), 'utf8');
    visit(parser.parse(source, { sourceType: 'script' }).program, source, file);
  }
  assert.equal(observed.length, 21);
  assert.equal(observed.filter(row => row.propertySignal).length, 5);
  assert.equal(observed.filter(row => !row.propertySignal).length, 16);
});
