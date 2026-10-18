'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const { createLangChainProvider }
  = require('../server/agent-runtime/providers/langchainProvider');
const calibration = require('./fixtures/secureshopReviewContentJudgeCalibration');
const diagnostic = require('./fixtures/reviewJudgeSchemaDiagnostic');

const LIVE = process.env.RUN_LIVE_REVIEW_JUDGE_SCHEMA_DIAGNOSTIC === '1';
const ENDPOINT = 'http://127.0.0.1:11434/api/chat';
const MAX_HTTP_BODY_BYTES = 2 * 1024 * 1024;
const MAX_RETAINED_HTTP_RESPONSE_BYTES = 64 * 1024;
const sha256 = value => createHash('sha256').update(value).digest('hex');

async function boundedResponseBody(response) {
  const reader = response.clone().body.getReader();
  const chunks = []; let bytes = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      bytes += value.byteLength;
      if (bytes > MAX_RETAINED_HTTP_RESPONSE_BYTES) {
        reader.cancel().catch(() => {});
        return { bytes, retained: false, text: null, sha256: null };
      }
      chunks.push(Buffer.from(value));
    }
  } finally { reader.releaseLock(); }
  const text = Buffer.concat(chunks).toString('utf8');
  return { bytes, retained: true, text, sha256: sha256(text) };
}

test('local Judge schema A/B records transport behavior without qualification', {
  skip: !LIVE, timeout: 600000,
}, async t => {
  const originalFetch = globalThis.fetch;
  assert.equal(typeof originalFetch, 'function');
  const requests = [];
  globalThis.fetch = async (input, init = {}) => {
    const url = new URL(typeof input === 'string' || input instanceof URL ? input : input.url);
    assert.equal(url.href, ENDPOINT);
    assert.equal(String(init.method || input?.method || 'GET').toUpperCase(), 'POST');
    assert.ok(requests.length < diagnostic.MAX_PROVIDER_CALLS);
    assert.equal(typeof init.body, 'string');
    assert.ok(Buffer.byteLength(init.body) <= MAX_HTTP_BODY_BYTES);
    const body = JSON.parse(init.body);
    assert.deepEqual(body.messages.map(message => message.role), ['system', 'user']);
    assert.equal(body.model, calibration.MODEL);
    assert.equal(body.options.temperature, 0);
    assert.equal(body.options.num_ctx, 32768);
    assert.equal(body.options.num_predict, 900);
    assert.equal(body.tools, undefined);
    const row = { requestSha256: sha256(init.body),
      requestBytes: Buffer.byteLength(init.body),
      promptSha256: sha256(JSON.stringify(body.messages)),
      formatSha256: sha256(JSON.stringify(body.format)),
      roles: body.messages.map(message => message.role),
      options: { temperature: body.options.temperature, num_ctx: body.options.num_ctx,
        num_predict: body.options.num_predict },
      formatKind: Array.isArray(body.format?.anyOf) ? 'current_union' : 'flat_boolean' };
    requests.push(row);
    const response = await originalFetch(input, { ...init, redirect: 'error' });
    assert.equal(response.redirected, false);
    assert.equal(response.url, ENDPOINT);
    row.httpStatus = response.status;
    const responseBody = await boundedResponseBody(response);
    row.httpResponseBytes = responseBody.bytes;
    row.httpResponseSha256 = responseBody.sha256;
    row.rawHttpResponse = responseBody.text;
    row.httpResponseRetained = responseBody.retained;
    return response;
  };
  const cells = [];
  const controller = new AbortController();
  const deadline = setTimeout(() => controller.abort(
    new Error('Review Judge schema diagnostic deadline exceeded')), 540000);
  deadline.unref?.();
  try {
    const provider = createLangChainProvider({ provider: 'ollama',
      model: calibration.MODEL, baseURL: 'http://127.0.0.1:11434' });
    const output = await diagnostic.runSchemaDiagnostic({ provider,
      signal: controller.signal,
      recordCell: async cell => {
        cells.push(cell);
        t.diagnostic(JSON.stringify({ scope: 'review_judge_schema_ab_cell', ...cell }));
      } });
    t.diagnostic(JSON.stringify({ scope: 'review_judge_schema_ab_summary',
      model: calibration.MODEL, calls: requests.length,
      maximumCalls: diagnostic.MAX_PROVIDER_CALLS, requests, cells: output.cells,
      qualification: false, toolsExecuted: 0, databaseWrites: 0, creditsAttempted: 0 }));
    assert.equal(output.cells.length, diagnostic.EXPECTED_CELLS);
    assert.equal(requests.length, diagnostic.MAX_PROVIDER_CALLS);
  } finally {
    clearTimeout(deadline);
    globalThis.fetch = originalFetch;
  }
});
