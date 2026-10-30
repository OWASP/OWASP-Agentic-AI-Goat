'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { createAdminOperationalHandlers } = require('../server/routes/adminOperationalHandlers');

function response() {
  return { statusCode: 200, status(code) { this.statusCode = code; return this; }, json(body) { this.body = body; return this; } };
}

test('provider mutations use injected environment file and preserve unrelated settings', async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'owasp-ai-goat-admin-ops-'));
  const envPath = path.join(directory, '.env');
  fs.writeFileSync(envPath, 'PORT=8081\nAI_PROVIDER=mock\n');
  const environment = { AI_PROVIDER: 'mock' };
  let reloads = 0;
  const waits = [];
  const aiService = { inFlightRequests: new Set(['fixture-run']), reloadConfig: () => { reloads += 1; },
    verifyProviderConnection: async provider => ({ provider, configured: true, available: true, healthy: true, message: 'ready' }) };
  const handlers = createAdminOperationalHandlers({ envPath, logsDir: directory, environment, aiService, delay: async milliseconds => waits.push(milliseconds) });
  const switched = response();
  await handlers.switchProvider({ body: { provider: 'ollama' } }, switched);
  assert.equal(switched.statusCode, 200);
  assert.equal(environment.AI_PROVIDER, 'ollama');
  assert.match(fs.readFileSync(envPath, 'utf8'), /^PORT=8081$/m);
  assert.match(fs.readFileSync(envPath, 'utf8'), /^AI_PROVIDER=ollama$/m);
  assert.deepEqual(waits, [100]);
  const configured = response();
  await handlers.configureProvider({ body: { provider: 'chatgpt', apiKey: 'disposable-key', model: 'fixture-model' } }, configured);
  assert.equal(configured.statusCode, 200);
  assert.equal(environment.OPENAI_API_KEY, 'disposable-key');
  assert.match(fs.readFileSync(envPath, 'utf8'), /^OPENAI_MODEL=fixture-model$/m);
  assert.equal(reloads, 2);
  fs.rmSync(directory, { recursive: true, force: true });
});

test('log handlers read only injected disposable log paths and filter structured entries', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'owasp-ai-goat-admin-logs-'));
  fs.writeFileSync(path.join(directory, 'app.log'), [
    JSON.stringify({ timestamp: '2026-09-10T00:00:00.000Z', level: 'info', message: 'meaningful', username: 'student' }),
    JSON.stringify({ timestamp: '2026-09-10T00:01:00.000Z', level: 'error', message: 'llm_call_error', provider: 'ollama', success: false, error: 'fixture' }),
  ].join('\n'));
  fs.writeFileSync(path.join(directory, 'llm_requests.log'), '[2026-09-10T00:02:00.000Z] user=7 username=student ip=127.0.0.1 model=llama3.1:8b mode=vulnerable message="hello" tools_called=none response="hi"\n');
  const handlers = createAdminOperationalHandlers({ logsDir: directory, environment: {} });
  const app = response(); handlers.appLogs({ query: { level: 'info' } }, app);
  assert.equal(app.body.total, 1); assert.equal(app.body.logs[0].message, 'meaningful');
  const llm = response(); handlers.llmLogs({ query: { provider: 'ollama' } }, llm);
  assert.equal(llm.body.total, 2); assert.equal(llm.body.logs[1].username, 'student');
  fs.rmSync(directory, { recursive: true, force: true });
});

test('LLM test uses injected fetch and records the observable result', async () => {
  const entries = [];
  const handlers = createAdminOperationalHandlers({ environment: { OLLAMA_MODEL: 'llama3.1:8b', OLLAMA_BASE_URL: 'http://fixture.invalid' },
    fetch: async () => ({ ok: true, json: async () => ({ response: 'LLM connection test successful' }) }), logLLMCall: entry => entries.push(entry) });
  const res = response(); await handlers.testLlm({}, res);
  assert.equal(res.body.success, true); assert.equal(res.body.model, 'llama3.1:8b'); assert.equal(entries[0].success, true);
});
