'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { withPostgresRepositoryDoubles } = require('../fixtures/postgresRepositoryDoubles');

test('scope injects async state-backed repositories before eager tool imports and records pass-through', async () => {
  const product = { id: 7, name: 'Controlled product', description: 'verbatim source',
    price: 12.5, category: 'fixture', stock_quantity: 3, description_html: '<p>raw</p>' };
  const state = { products: [product] };
  await withPostgresRepositoryDoubles({ commerce: { state, methods: {
    summarizer_summarizeProduct_1: async ({ state: current }, id) =>
      current.products.find(row => row.id === id),
  } } }, async scope => {
    const tools = scope.loadFresh('agent-host/agents/summarizer/tools/summarize_product.js');
    const pending = tools.summarizeProduct({ product_id: 7 });
    assert.equal(typeof pending?.then, 'function', 'the injected PostgreSQL contract remains asynchronous');
    const result = await pending;
    assert.equal(result.description, 'verbatim source');
    assert.deepEqual(scope.calls, [{ sequence: 1, repository: 'commerce',
      method: 'summarizer_summarizeProduct_1', args: [7], status: 'fulfilled', result: product }]);
    assert.equal(scope.commerceState, state);
  });
});

test('agent repository state supports real sessionStore calls without a database', async () => {
  const state = { sessions: new Map() };
  await withPostgresRepositoryDoubles({ agents: { state, methods: {
    createSession: async ({ state: current }, id, userId, role) => {
      current.sessions.set(id, { id, userId, role, messages: [], tokens: 0 });
      return { id };
    },
    appendMessage: async ({ state: current }, id, message) => {
      current.sessions.get(id).messages.push(structuredClone(message));
    },
    getMessages: async ({ state: current }, id) => structuredClone(current.sessions.get(id).messages),
  } } }, async scope => {
    const store = scope.loadFresh('server/services/secureshop/sessionStore.js');
    const { id } = await store.createSession({ userId: 41, role: 'merchant' });
    await store.appendUserMessage(id, 'raw learner input');
    assert.deepEqual(await store.getMessages(id), [{ role: 'user', content: 'raw learner input' }]);
    assert.deepEqual(scope.calls.map(row => row.method), ['createSession', 'appendMessage', 'getMessages']);
    assert.equal(scope.agentsState.sessions.get(id).role, 'merchant');
  });
});

test('callback repository methods execute while call capture records only opaque function identity', async () => {
  const state = { audit: [] };
  await withPostgresRepositoryDoubles({ commerce: { state, methods: {
    deliverAudit: async ({ state: current }, eventId, append) => {
      const event = { event_id: eventId, action: 'controlled' };
      await append(event);
      current.audit.push(event);
    },
  } } }, async scope => {
    await scope.commerce.deliverAudit('event-1', async event => {
      assert.equal(event.action, 'controlled');
    });
    assert.deepEqual(scope.commerceState.audit, [{ event_id: 'event-1', action: 'controlled' }]);
    assert.deepEqual(scope.calls[0].args, ['event-1', { type: 'function', name: null }]);
  });
});

test('scope rejects SQL emulation and restores displaced eager modules after failure', async () => {
  await assert.rejects(withPostgresRepositoryDoubles({ commerce: { methods: {
    readTeachingQuery: async () => [],
  } } }, async () => {}), /not an admitted non-SQL method/);

  const modulePath = require.resolve(path.join(__dirname,
    '../../../agent-host/agents/summarizer/tools/summarize_product.js'));
  const sentinel = { id: modulePath, filename: modulePath, loaded: true,
    exports: Object.freeze({ sentinel: true }), children: [], paths: [] };
  const prior = require.cache[modulePath];
  require.cache[modulePath] = sentinel;
  try {
    await assert.rejects(withPostgresRepositoryDoubles({ commerce: { methods: {
      summarizer_summarizeProduct_1: async () => { throw Object.assign(new Error('controlled outage'), { code: 'TEST_OUTAGE' }); },
    } } }, async scope => {
      const tool = scope.loadFresh('agent-host/agents/summarizer/tools/summarize_product.js');
      await tool.summarizeProduct({ product_id: 1 });
    }), { code: 'TEST_OUTAGE' });
    assert.strictEqual(require.cache[modulePath], sentinel, 'the exact prior module-cache entry is restored');
  } finally {
    if (prior) require.cache[modulePath] = prior;
    else delete require.cache[modulePath];
  }
});

test('global module-cache scopes fail closed when callers overlap', async () => {
  let release;
  const held = withPostgresRepositoryDoubles({}, async () => new Promise(resolve => { release = resolve; }));
  while (!release) await new Promise(resolve => setImmediate(resolve));
  await assert.rejects(withPostgresRepositoryDoubles({}, async () => {}), /cannot overlap/);
  release();
  await held;
});
