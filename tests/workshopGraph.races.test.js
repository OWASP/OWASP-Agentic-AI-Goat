'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { createAgent } = require('../server/services/ariaAgentService');
function deferred() { let resolve; const promise = new Promise(r => { resolve = r; }); return { promise, resolve }; }
function fixture(extra = {}) {
  const events = [];
  const store = {
    async getHistory() { events.push('history'); return []; },
    async searchProducts() { events.push('tool'); return []; },
    async saveMessage(id, role) { events.push(role); },
    ...extra.store,
  };
  return { events, agent: createAgent({ decisionMode:'scripted', store, model: extra.model || { async generateResponse() { return { response: 'ok' }; } }, runLedger: extra.runLedger ?? null }) };
}
test('same owner sends serialize through persistence', { timeout: 2000 }, async () => {
  const entered = deferred(), resume = deferred(); let calls = 0;
  const { agent, events } = fixture({ model: { async generateResponse() {
    if (++calls === 1) { entered.resolve(); await resume.promise; } return { response: 'ok' };
  } } });
  const first = agent.chat(1, 'show all products'); await entered.promise;
  const second = agent.chat(1, 'show all products');
  await new Promise(r => setImmediate(r));
  assert.deepEqual(events, ['history', 'tool']);
  resume.resolve(); await Promise.all([first, second]);
  assert.deepEqual(events, ['history', 'tool', 'user', 'assistant', 'history', 'tool', 'user', 'assistant']);
});
test('reset during slow model fences stale output and waits before store reset', { timeout: 2000 }, async () => {
  const entered = deferred(), resume = deferred();
  const { agent, events } = fixture({ model: { async generateResponse() { entered.resolve(); await resume.promise; return { response: 'stale' }; } } });
  const pending = agent.chat(1, 'hello'); const rejected = assert.rejects(pending, { name: 'AbortError' });
  await entered.promise; await agent.reset(1, async () => events.push('reset'));
  await rejected; resume.resolve(); await new Promise(r => setImmediate(r));
  assert.deepEqual(events, ['history', 'reset']);
});
test('abort during history prevents tool and persistence', { timeout: 2000 }, async () => {
  const entered = deferred(), resume = deferred(), controller = new AbortController();
  const { agent, events } = fixture({ store: { async getHistory() { entered.resolve(); await resume.promise; return []; } } });
  const pending = agent.invoke(1, 'show all products', 'fixed', { signal: controller.signal });
  const rejected = assert.rejects(pending, { name: 'AbortError' });
  await entered.promise; controller.abort(); resume.resolve(); await rejected;
  assert.deepEqual(events, []);
});
test('deadline cancels slow model and ledger records cancellation', async () => {
  const ledger = [];
  const { agent, events } = fixture({ model: { generateResponse: () => new Promise(() => {}) }, runLedger: {
    async begin(c) { ledger.push(['begin', c.ownerKey]); },
    async checkpoint(c, value) { ledger.push(['checkpoint', value.node]); },
    async finish(c, value) { ledger.push(['finish', value.status]); },
  } });
  await assert.rejects(agent.invoke(1, 'hello', 'fixed', { timeoutMs: 30 }), { name: 'AbortError' });
  assert.deepEqual(events, ['history']);
  assert.deepEqual(ledger.at(-1), ['finish', 'cancelled']);
});
test('reset waits for an in-flight mutation before clearing store', { timeout: 2000 }, async () => {
  const entered = deferred(), resume = deferred();
  const { agent, events } = fixture({ store: { async searchProducts() {
    entered.resolve(); await resume.promise; events.push('mutation-settled'); return [];
  } } });
  const pending = agent.chat(1, 'show all products');
  const rejected = assert.rejects(pending, { name: 'AbortError' });
  await entered.promise;
  const reset = agent.reset(1, async () => events.push('reset'));
  await new Promise(r => setImmediate(r));
  assert.deepEqual(events, ['history']);
  resume.resolve(); await Promise.all([reset, rejected]);
  assert.deepEqual(events, ['history', 'mutation-settled', 'reset']);
});
