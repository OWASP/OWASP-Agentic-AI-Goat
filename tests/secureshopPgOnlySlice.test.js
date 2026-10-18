'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const Module = require('node:module');
const fs = require('node:fs');
const path = require('node:path');

test('SecureShop owned adapters use PostgreSQL even when legacy selectors are set', async () => {
  const previous = {
    engine: process.env.PLATFORM_DATABASE_ENGINE,
    agentsPath: process.env.SS_AGENTS_DB_PATH,
    shopPath: process.env.SS_SECURESHOP_DB_PATH,
    embedProvider: process.env.SS_EMBED_PROVIDER,
    acl: process.env.SS_ENFORCE_TOOL_ACL,
  };
  process.env.PLATFORM_DATABASE_ENGINE = 'sqlite';
  process.env.SS_AGENTS_DB_PATH = '/must/not/be/opened/secureshop_agents.db';
  process.env.SS_SECURESHOP_DB_PATH = '/must/not/be/opened/secureshop.db';
  process.env.SS_EMBED_PROVIDER = 'hash';
  delete process.env.SS_ENFORCE_TOOL_ACL;

  const calls = [];
  const messages = [];
  const repository = {
    async createSession(id, userId, role) { calls.push(['createSession', userId, role]); return { id }; },
    async getSession(id) { return { id, userId: 7, role: 'customer' }; },
    async appendMessage(id, message) { messages.push({ id, ...message }); },
    async getMessages() { return messages; },
    async getTokens() { return 9; },
    async addTokens(id, amount) { calls.push(['addTokens', id, amount]); },
    async appendTraces(rows) { calls.push(['traces', rows]); },
    async replaceNativeManifest(names, entries) { calls.push(['manifest', names, entries]); },
    async externalTools() {
      return [{ server_name: 'outside', tool_name: 'run', description: 'verbatim', input_schema_json: '{}' }];
    },
    async getEnforcement() { return false; },
    async getPermission() { return { allowed: 0 }; },
    async listPermissions() { return [{ tool_name: 'outside.run' }]; },
    async setPermission(tool, role, allowed) { return { ok: true, tool_name: tool, role, allowed }; },
    async setEnforcement(enabled) { return { ok: true, enforce_tool_acl: enabled }; },
  };
  const vectorRepository = {
    async add(input) { calls.push(['vector-add', input]); return 41; },
    async listActive() {
      return [{ sourceKind: 'manual', sourceId: 5, chunkIndex: 0, text: 'alpha', embedding: [1, 0] }];
    },
    async rebuild(input) { calls.push(['vector-rebuild', input]); return { corpus: input.corpus, count: input.documents.length }; },
    async count() { return { count: 1 }; },
  };
  const commercePool = {
    async query() {
      return { rows: [
        { id: 1, name: 'customer policy', markdown_source: 'verbatim policy', injected_into_json: '["customer"]' },
        { id: 2, name: 'merchant policy', markdown_source: 'other', injected_into_json: '["merchant"]' },
      ] };
    },
  };

  const originalLoad = Module._load;
  let sqliteLoads = 0;
  Module._load = function controlledLoad(request, parent, isMain) {
    if (request === 'better-sqlite3' || request === 'hnswlib-node') {
      sqliteLoads += 1;
      throw new Error(`retired dependency loaded: ${request}`);
    }
    if (request.endsWith('/database/postgres/secureshopAgentsDb')
        || request.endsWith('/database/postgres/secureshopAgentsDb.js')) {
      return { getSecureShopAgentsDb: () => repository };
    }
    if (request.endsWith('/database/postgres/secureshopVectorRepository')) {
      return { getSecureShopVectorRepository: () => vectorRepository };
    }
    if (request.endsWith('/database/postgres/secureshopPools')) {
      return { getCommercePool: () => commercePool, getAgentsPool: () => ({}) };
    }
    return originalLoad.call(this, request, parent, isMain);
  };

  const ownedModules = [
    '../server/services/secureshop/sessionStore',
    '../server/services/secureshop/trace',
    '../server/services/secureshop/toolManifest',
    '../server/services/secureshop/toolAcl',
    '../server/services/secureshop/supervisors/policyLoader',
    '../server/services/secureshop/vectorStore',
  ];
  try {
    for (const modulePath of ownedModules) delete require.cache[require.resolve(modulePath)];

    const sessions = require('../server/services/secureshop/sessionStore');
    const created = await sessions.createSession({ userId: 7, role: 'customer' });
    assert.match(created.id, /^[0-9a-f-]{36}$/);
    await sessions.appendUserMessage(created.id, 'hello');
    await sessions.appendAssistantToolCalls(created.id, [{ id: 'c1', name: 'outside.run', args: { a: 1 } }]);
    assert.equal(await sessions.remainingBudget(created.id), 99991);

    const { Trace } = require('../server/services/secureshop/trace');
    const trace = new Trace(created.id);
    trace.record({ step: 1, actor: 'customer', kind: 'decision' });
    await trace.flush();
    assert.equal(calls.find(([kind]) => kind === 'traces')[1][0].session_id, created.id);

    const { ToolManifest } = require('../server/services/secureshop/toolManifest');
    const manifest = new ToolManifest({ clients: new Map([['support', { listTools: async () => ({ tools: [{ name: 'help' }] }) }]]) });
    await manifest.refresh();
    assert.match(await manifest.buildExternalMcpPromptBlock(), /outside\.run: verbatim/);

    const acl = require('../server/services/secureshop/toolAcl');
    assert.deepEqual(await acl.checkToolAcl('customer', 'outside', 'run'), {
      allowed: false, action: 'log', policyViolation: 'denied-by-acl', enforcement: false,
    });

    const policies = require('../server/services/secureshop/supervisors/policyLoader');
    assert.deepEqual((await policies.loadForRole('customer')).map((row) => row.id), [1]);
    assert.match(await policies.buildPolicyBlock('customer'), /verbatim policy/);

    const { VectorStore } = require('../server/services/secureshop/vectorStore');
    const vectors = new VectorStore({ corpus: 'manuals', dim: 2, dbPath: '/ignored', indexDir: '/ignored' });
    assert.equal(await vectors.add({ sourceKind: 'manual', sourceId: 5, text: 'alpha' }), 41);
    assert.equal((await vectors.search('alpha', 1))[0].text, 'alpha');
    assert.equal((await vectors.rebuild([{ sourceKind: 'manual', sourceId: 6, text: 'beta' }])).count, 1);
    assert.equal(await vectors.count(), 1);

    for (const name of ['auth', 'merchant', 'customer', 'admin']) {
      const source = fs.readFileSync(path.join(__dirname, `../server/routes/secureshop/${name}.js`), 'utf8');
      assert.match(source, new RegExp(`module\\.exports = require\\('./postgres/${name}'\\)`));
      assert.doesNotMatch(source, /PLATFORM_DATABASE_ENGINE|better-sqlite3/);
    }
    assert.equal(sqliteLoads, 0);
  } finally {
    Module._load = originalLoad;
    for (const modulePath of ownedModules) delete require.cache[require.resolve(modulePath)];
    if (previous.engine === undefined) delete process.env.PLATFORM_DATABASE_ENGINE;
    else process.env.PLATFORM_DATABASE_ENGINE = previous.engine;
    if (previous.agentsPath === undefined) delete process.env.SS_AGENTS_DB_PATH;
    else process.env.SS_AGENTS_DB_PATH = previous.agentsPath;
    if (previous.shopPath === undefined) delete process.env.SS_SECURESHOP_DB_PATH;
    else process.env.SS_SECURESHOP_DB_PATH = previous.shopPath;
    if (previous.embedProvider === undefined) delete process.env.SS_EMBED_PROVIDER;
    else process.env.SS_EMBED_PROVIDER = previous.embedProvider;
    if (previous.acl === undefined) delete process.env.SS_ENFORCE_TOOL_ACL;
    else process.env.SS_ENFORCE_TOOL_ACL = previous.acl;
  }
});
