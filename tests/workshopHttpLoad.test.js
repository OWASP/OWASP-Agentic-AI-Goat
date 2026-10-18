'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const express = require('express');
const { performance } = require('node:perf_hooks');
const { createWorkshopGraph } = require('../server/agent-runtime/workshopGraph');
const { createWorkshopRouteHandlers } = require('../server/agent-runtime/workshopRouteHandlers');
const { createPostgresAdminAuth } = require('../server/middleware/postgresAdminAuth');
const { createModelScheduler } = require('../server/agent-runtime/providers/modelScheduler');

// HTTP/runtime capacity proof with injected storage and inference. This does not
// claim PostgreSQL, physical Ollama throughput, or AWS infrastructure capacity.
test('200 HTTP attendees retain owner/mode/history/progress isolation through chat and reset', { timeout: 30000 }, async t => {
  const history = new Map(), progress = new Set(), sessions = new Map();
  const scheduler = createModelScheduler({ concurrency: 4, queueLimit: 256 });
  let active = 0, maximum = 0, inferred = 0;
  const store = {
    async getHistory(id) { return history.get(String(id)) || []; },
    async saveMessage(id, role, message) {
      const key = String(id); history.set(key, [...(history.get(key) || []), { role, message }]);
    },
    async clearHistory(id) { history.delete(String(id)); }, async clearCart() {},
  };
  const runtime = createWorkshopGraph({ name: 'http-load', store, decisionMode: 'scripted',
    runLedger: null,
    detectIntent: () => ({ tool: 'general_chat' }), blockedResponse: () => null,
    buildGeneralChatPrompt: async message => message,
    generateFallbackResponse: () => 'unexpected fallback', searchTool: 'search',
    model: { generateResponse: async prompt => scheduler.run(prompt, undefined, async () => {
      active++; maximum = Math.max(maximum, active);
      try { await new Promise(resolve => setTimeout(resolve, 5)); inferred++; return { response: prompt }; }
      finally { active--; }
    }) },
  });
  const handlers = createWorkshopRouteHandlers({agent: runtime, store, workshopKey: 'http-load', challengeKey: 'http-load',
    modeService: { getMode: async ({ userId }) => userId % 2 ? 'vuln' : 'fixed' },
    syncObjectiveComplete: async id => progress.add(String(id)), resetWorkshopProgress: async id => progress.delete(String(id)),
    grading: { begin: async () => null, evaluate: async ({ userId }) => { progress.add(String(userId)); return { completed: true, judgment: { verdict: 'pass', provider: 'fixture' } }; } },
    detectCompletedObjectives: () => ['one'], objectiveLabels: { one: 'One' }, clearState: 'clearCart', resetMessage: 'reset',
    validateSession: async token => sessions.get(token), logger: { error() {} },
  });
  for (let id = 1; id <= 200; id++) sessions.set(`fixture-${id}`, { user: { id, role: 'student', username: `student-${id}` }, session: { id, user_id:id } });
  const { authenticateToken } = createPostgresAdminAuth({ repository: {}, validateSession: async token => sessions.get(token) });
  const app = express(); app.use(express.json()); app.use(authenticateToken);
  app.post('/chat', handlers.chat); app.post('/reset', handlers.reset);
  const server = app.listen(0, '127.0.0.1'); await new Promise(resolve => server.once('listening', resolve));
  t.after(() => new Promise(resolve => { server.close(resolve); server.closeAllConnections(); }));
  const base = `http://127.0.0.1:${server.address().port}`;
  async function request(id, route, body = {}) {
    const response = await fetch(`${base}${route}`, { method: 'POST', headers: { authorization: `Bearer fixture-${id}`, 'content-type': 'application/json' }, body: JSON.stringify(body) });
    return { status: response.status, body: await response.json() };
  }
  const started = performance.now();
  const latencies = await Promise.all(Array.from({ length: 200 }, async (_, index) => {
    const id = index + 1, before = performance.now();
    const result = await request(id, '/chat', { userMessage: `attendee-${id}`, userId: 999, mode: id % 2 ? 'fixed' : 'vuln' });
    assert.equal(result.status, 200);
    assert.equal(result.body.response, `attendee-${id}`);
    assert.equal(result.body.mode, id % 2 ? 'vuln' : 'fixed');
    return performance.now() - before;
  }));
  assert.equal(inferred, 200); assert.ok(maximum > 0 && maximum <= 4); assert.equal(progress.size, 200);
  assert.equal(history.size, 200); assert.equal(history.has('999'), false);
  await Promise.all(Array.from({ length: 100 }, async (_, index) => assert.equal((await request(index + 1, '/reset', { userId: 200 })).status, 200)));
  assert.equal(history.size, 100); assert.equal(progress.size, 100);
  for (let id = 101; id <= 200; id++) assert.equal(history.get(String(id))[1].message, `attendee-${id}`);
  sessions.delete('fixture-200');
  assert.equal((await request(200, '/chat', { userMessage: 'revoked' })).status, 401);
  assert.equal(history.get('200').length, 2);
  latencies.sort((a, b) => a - b);
  t.diagnostic(JSON.stringify({ attendees: 200, totalMs: Math.round(performance.now() - started), p95ChatMs: Math.round(latencies[189]), maximumModelConcurrency: maximum, storage: 'injected', model: 'deterministic fixture' }));
});
