'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');

const REPO = path.resolve(__dirname, '../../../..');
const { withPostgresRepositoryDoubles } = require('../../fixtures/postgresRepositoryDoubles');
const { MockProvider } = require('../../../../server/services/secureshop/providers/mockProvider');

function fakePool() {
  return {
    async callTool(agent, tool, args) {
      return { content: [{ type: 'text', text: JSON.stringify({ agent, tool, args, ok: true }) }] };
    },
    clients: new Map(),
  };
}

function fakeManifest() {
  return {
    getForRole() {
      return [
        { agent: 'product-search', tool: 'search', description: 'search products', inputSchema: {} },
        { agent: 'cart', tool: 'view', description: 'view cart', inputSchema: {} },
      ];
    },
  };
}

function repositoryOptions(state) {
  return { agents: { state, methods: {
    async createSession({ state }, id, userId, role) {
      const session = { id, userId, role, messages: [], tokens: 0 };
      state.sessions.set(id, session);
      return { id, user_id: userId, role };
    },
    async getSession({ state }, id) { return state.sessions.get(id) || null; },
    async appendMessage({ state }, id, message) {
      const session = state.sessions.get(id);
      assert(session, 'controlled session must exist');
      session.messages.push(structuredClone(message));
      return message;
    },
    async getMessages({ state }, id) { return structuredClone(state.sessions.get(id)?.messages || []); },
    async getTokens({ state }, id) { return state.sessions.get(id)?.tokens || 0; },
    async addTokens({ state }, id, count) {
      const session = state.sessions.get(id);
      session.tokens += count;
      return session.tokens;
    },
    async appendTraces({ state }, rows) { state.traces.push(...structuredClone(rows)); },
    async getPermission({ state }, tool, role) {
      state.acl.push({ tool, role });
      return { allowed: true };
    },
    async getEnforcement() { return false; },
  } } };
}

async function withCustomer(operation) {
  const state = { sessions: new Map(), traces: [], acl: [], policyRoles: [] };
  return withPostgresRepositoryDoubles(repositoryOptions(state), async (scope) => {
    const policyPath = require.resolve(path.join(REPO,
      'server/services/secureshop/supervisors/policyLoader.js'));
    const priorPolicy = require.cache[policyPath];
    require.cache[policyPath] = {
      id: policyPath, filename: policyPath, loaded: true, children: [], paths: [],
      exports: { buildPolicyBlock: async (role) => { state.policyRoles.push(role); return ''; } },
    };
    try {
      const store = scope.loadFresh('server/services/secureshop/sessionStore.js');
      const { customerSupervisor } = scope.loadFresh(
        'server/services/secureshop/supervisors/customerSupervisor.js');
      const { id: sessionId } = await store.createSession({ userId: 1, role: 'customer' });
      return await operation({ customerSupervisor, sessionId, state });
    } finally {
      if (priorPolicy) require.cache[policyPath] = priorPolicy;
      else delete require.cache[policyPath];
    }
  });
}

test('customerSupervisor: single-turn end_turn returns assistant text', async () => {
  await withCustomer(async ({ customerSupervisor, sessionId, state }) => {
    const provider = new MockProvider();
    provider.script([{ stop: 'end_turn', text: 'Hello! How can I help?' }]);
    const result = await customerSupervisor.run(sessionId, 'hi there', {
      provider, pool: fakePool(), manifest: fakeManifest(),
    });
    assert.equal(result.text, 'Hello! How can I help?');
    assert.equal(result.stopReason, 'end_turn');
    assert.ok(Array.isArray(result.hops));
    assert.deepEqual(state.policyRoles, ['customer']);
    assert.equal(state.sessions.get(sessionId).role, 'customer');
  });
});

test('customerSupervisor: tool_use → tool_result → end_turn produces a hop and final text', async () => {
  await withCustomer(async ({ customerSupervisor, sessionId, state }) => {
    const provider = new MockProvider();
    provider.script([
      { stop: 'tool_use', tool_uses: [{ name: 'product-search.search', args: { query: 'laptop' } }] },
      { stop: 'end_turn', text: 'Results attached.' },
    ]);
    const result = await customerSupervisor.run(sessionId, 'find laptops', {
      provider, pool: fakePool(), manifest: fakeManifest(),
    });
    assert.equal(result.stopReason, 'end_turn');
    assert.equal(result.text, 'Results attached.');
    assert.equal(result.hops.length, 1);
    assert.equal(result.hops[0].tool, 'product-search.search');
    assert.deepEqual(result.hops[0].params, { query: 'laptop' });
    assert.match(JSON.stringify(result.hops[0].result), /product-search/);
    assert.deepEqual(state.acl, [{ tool: 'product-search.search', role: 'customer' }]);
  });
});

test('customerSupervisor: parallel tool_uses in one step ≤ MAX_PARALLEL_TOOLS', async () => {
  await withCustomer(async ({ customerSupervisor, sessionId, state }) => {
    const provider = new MockProvider();
    provider.script([
      { stop: 'tool_use', tool_uses: ['a', 'b', 'c', 'd'].map(query => ({
        name: 'product-search.search', args: { query },
      })) },
      { stop: 'end_turn', text: 'done' },
    ]);
    const result = await customerSupervisor.run(sessionId, 'multi', {
      provider, pool: fakePool(), manifest: fakeManifest(),
    });
    assert.equal(result.hops.length, 4);
    assert.equal(state.acl.length, 4);
    assert(state.acl.every(row => row.role === 'customer' && row.tool === 'product-search.search'));
  });
});

test('customerSupervisor: enforces MAX_STEPS budget', async () => {
  await withCustomer(async ({ customerSupervisor, sessionId }) => {
    const provider = new MockProvider();
    provider.script(Array.from({ length: 12 }, (_, i) => ({
      stop: 'tool_use', tool_uses: [{ name: 'product-search.search', args: { i } }],
    })));
    const result = await customerSupervisor.run(sessionId, 'loop please', {
      provider, pool: fakePool(), manifest: fakeManifest(),
    });
    assert.ok(result.hops.length <= 8 * 4, 'should stop at MAX_STEPS');
    assert.match(result.text, /max steps|budget/i);
  });
});

test('customerSupervisor: streams events when stream: true', async () => {
  await withCustomer(async ({ customerSupervisor, sessionId }) => {
    const provider = new MockProvider();
    provider.script([
      { stop: 'tool_use', tool_uses: [{ name: 'cart.view', args: {} }] },
      { stop: 'end_turn', text: 'Your cart is empty.' },
    ]);
    const events = [];
    const stream = { send: (name, data) => events.push({ name, data }), close: () => {} };
    await customerSupervisor.run(sessionId, 'show cart', {
      provider, pool: fakePool(), manifest: fakeManifest(), stream,
    });
    const names = events.map(event => event.name);
    assert.ok(names.includes('tool_call'));
    assert.ok(names.includes('tool_result'));
    assert.ok(names.includes('assistant_message'));
    assert.ok(names.includes('done'));
  });
});
