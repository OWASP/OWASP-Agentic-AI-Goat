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
        { agent: 'listing', tool: 'create', description: 'create listing', inputSchema: {} },
        { agent: 'inventory', tool: 'stock_levels', description: 'stock', inputSchema: {} },
        { agent: 'analytics', tool: 'nl_query', description: 'nl-sql', inputSchema: {} },
        { agent: 'review-moderator', tool: 'moderate_pending', description: 'moderate', inputSchema: {} },
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

async function withMerchant(operation) {
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
      const { merchantSupervisor } = scope.loadFresh(
        'server/services/secureshop/supervisors/merchantSupervisor.js');
      const { id: sessionId } = await store.createSession({ userId: 2, role: 'merchant' });
      return await operation({ merchantSupervisor, sessionId, state });
    } finally {
      if (priorPolicy) require.cache[policyPath] = priorPolicy;
      else delete require.cache[policyPath];
    }
  });
}

test('merchantSupervisor: end_turn returns assistant text', async () => {
  await withMerchant(async ({ merchantSupervisor, sessionId, state }) => {
    const provider = new MockProvider();
    provider.script([{ stop: 'end_turn', text: 'Merchant help ready.' }]);
    const result = await merchantSupervisor.run(sessionId, 'hi merchant', {
      provider, pool: fakePool(), manifest: fakeManifest(),
    });
    assert.equal(result.text, 'Merchant help ready.');
    assert.equal(result.stopReason, 'end_turn');
    assert.deepEqual(state.policyRoles, ['merchant']);
    assert.equal(state.sessions.get(sessionId).role, 'merchant');
  });
});

test('merchantSupervisor: tool_use → tool_result → end_turn produces a hop', async () => {
  await withMerchant(async ({ merchantSupervisor, sessionId, state }) => {
    const provider = new MockProvider();
    provider.script([
      { stop: 'tool_use', tool_uses: [{ name: 'analytics.nl_query', args: { question: 'top products?' } }] },
      { stop: 'end_turn', text: 'Analysis attached.' },
    ]);
    const result = await merchantSupervisor.run(sessionId, 'analyze please', {
      provider, pool: fakePool(), manifest: fakeManifest(),
    });
    assert.equal(result.stopReason, 'end_turn');
    assert.equal(result.hops.length, 1);
    assert.equal(result.hops[0].tool, 'analytics.nl_query');
    assert.deepEqual(state.acl, [{ tool: 'analytics.nl_query', role: 'merchant' }]);
  });
});

test('merchantSupervisor: uses merchant system prompt (not customer)', async () => {
  await withMerchant(async ({ merchantSupervisor, sessionId }) => {
    const provider = new MockProvider();
    let capturedSystem = null;
    provider.chat = async (args) => {
      capturedSystem = args.system;
      return { stop_reason: 'end_turn', text: 'ok' };
    };
    await merchantSupervisor.run(sessionId, 'hi', {
      provider, pool: fakePool(), manifest: fakeManifest(),
    });
    assert.ok(capturedSystem, 'system prompt was captured');
    assert.match(capturedSystem, /merchant supervisor/i);
    assert.match(capturedSystem, /listing|inventory|pricing-strategy|review-moderator|analytics/);
    assert.doesNotMatch(capturedSystem, /customer supervisor/i);
  });
});

test('merchantSupervisor: streams events', async () => {
  await withMerchant(async ({ merchantSupervisor, sessionId }) => {
    const provider = new MockProvider();
    provider.script([
      { stop: 'tool_use', tool_uses: [{ name: 'inventory.stock_levels', args: {} }] },
      { stop: 'end_turn', text: 'Stock summary.' },
    ]);
    const events = [];
    const stream = { send: (name, data) => events.push({ name, data }), close: () => {} };
    await merchantSupervisor.run(sessionId, 'stock', {
      provider, pool: fakePool(), manifest: fakeManifest(), stream,
    });
    const names = events.map(event => event.name);
    assert.ok(names.includes('tool_call'));
    assert.ok(names.includes('tool_result'));
    assert.ok(names.includes('assistant_message'));
    assert.ok(names.includes('done'));
  });
});
