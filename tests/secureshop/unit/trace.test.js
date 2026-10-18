'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const Module = require('node:module');
const path = require('node:path');
const crypto = require('node:crypto');

const REPO = path.resolve(__dirname, '../../..');
const persisted = [];
const repository = {
  async appendTraces(rows) { persisted.push(...structuredClone(rows)); },
};
const originalLoad = Module._load;
Module._load = function loadControlledRepository(request, parent, isMain) {
  if (request.endsWith('/database/postgres/secureshopAgentsDb')) {
    return { getSecureShopAgentsDb: () => repository };
  }
  return originalLoad.call(this, request, parent, isMain);
};
test.after(() => { Module._load = originalLoad; });

const { Trace } = require(path.join(REPO, 'server/services/secureshop/trace.js'));

test('Trace.record emits immediately and flush persists the same event through PostgreSQL', async () => {
  const sessionId = `trace-test-${crypto.randomUUID()}`;
  const trace = new Trace(sessionId);
  const events = [];
  trace.emitter.on('trace_event', (event) => events.push(event));

  trace.record({ step: 1, actor: 'supervisor', kind: 'llm_call_start', provider: 'mock' });
  assert.equal(events.length, 1);
  assert.equal(events[0].kind, 'llm_call_start');
  assert.equal(persisted.length, 0, 'record remains buffered before flush');

  await trace.flush();
  assert.equal(persisted.length, 1);
  assert.equal(persisted[0].session_id, sessionId);
  assert.equal(persisted[0].kind, 'llm_call_start');
  assert.match(persisted[0].event_id, /^[0-9a-f-]{36}$/);
});
