'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const Module = require('node:module');
const path = require('node:path');

const REPO = path.resolve(__dirname, '../../..');
const sessions = new Map();
const repository = {
  async createSession(id, userId, role) {
    sessions.set(id, { id, userId, role, messages: [], tokens: 0 });
    return { id };
  },
  async getSession(id) {
    const row = sessions.get(id);
    return row ? { id: row.id, userId: row.userId, role: row.role } : null;
  },
  async appendMessage(id, message) {
    const row = sessions.get(id);
    if (!row) throw new Error(`unknown session ${id}`);
    row.messages.push(structuredClone(message));
  },
  async getMessages(id) {
    const row = sessions.get(id);
    if (!row) throw new Error(`unknown session ${id}`);
    return structuredClone(row.messages);
  },
  async getTokens(id) { return sessions.get(id)?.tokens || 0; },
  async addTokens(id, amount) { sessions.get(id).tokens += amount; },
};

const originalLoad = Module._load;
Module._load = function loadControlledRepository(request, parent, isMain) {
  if (request.endsWith('/database/postgres/secureshopAgentsDb')) {
    return { getSecureShopAgentsDb: () => repository };
  }
  return originalLoad.call(this, request, parent, isMain);
};
test.after(() => { Module._load = originalLoad; });

const store = require(path.join(REPO, 'server/services/secureshop/sessionStore.js'));

test('createSession + append + getMessages round-trips through the async repository', async () => {
  const { id } = await store.createSession({ userId: 1, role: 'customer' });
  await store.appendUserMessage(id, 'hi');
  await store.appendAssistantMessage(id, 'hello');
  await store.appendAssistantToolCalls(id, [{ id: 'tc_1', name: 'support.reply', args: { body: 'ok' } }]);
  await store.appendToolResult(id, 'tc_1', { data: 42 });

  assert.deepEqual(await store.getSession(id), { id, userId: 1, role: 'customer' });
  const messages = await store.getMessages(id);
  assert.deepEqual(messages.map(({ role }) => role), ['user', 'assistant', 'assistant', 'tool']);
  assert.equal(messages[2].tool_calls[0].function.arguments, '{"body":"ok"}');
  assert.equal(messages[3].tool_call_id, 'tc_1');
});

test('budget accounting delegates to PostgreSQL token operations', async () => {
  const { id } = await store.createSession({ userId: 1, role: 'customer' });
  const before = await store.remainingBudget(id);
  await store.addUsedTokens(id, 1000);
  assert.equal(before - await store.remainingBudget(id), 1000);
});

test('runSessionExclusive serializes turns after a rejected predecessor', async () => {
  const order = [];
  let release;
  const held = new Promise((resolve) => { release = resolve; });
  const first = store.runSessionExclusive('same', async () => {
    order.push('first-start');
    await held;
    order.push('first-end');
    throw new Error('controlled failure');
  });
  const second = store.runSessionExclusive('same', async () => { order.push('second'); });
  await new Promise((resolve) => setImmediate(resolve));
  assert.deepEqual(order, ['first-start']);
  release();
  await assert.rejects(first, /controlled failure/);
  await second;
  assert.deepEqual(order, ['first-start', 'first-end', 'second']);
});
