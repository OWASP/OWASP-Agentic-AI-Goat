'use strict';

const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const fs = require('node:fs');
const Module = require('node:module');
const path = require('node:path');
const test = require('node:test');

const repoRoot = path.resolve(__dirname, '..');
const owned = [
  'agent-host/shared/db.js',
  'agent-host/agents/policy/tools/index.js',
  'agent-host/agents/user-management/tools/index.js',
  'agent-host/agents/audit/tools/index.js',
  'agent-host/agents/mcp-registry/tools/index.js',
];

const selectors = new Map([
  ['agent-host/agents/analytics/tools/index.js', './index.postgres.js'],
  ['agent-host/agents/cart/tools/index.js', './index.postgres.js'],
  ['agent-host/agents/email/tools/index.js', './index.postgres.js'],
  ['agent-host/agents/inventory/tools/index.js', './index.postgres.js'],
  ['agent-host/agents/listing/tools/create.js', './create.postgres.js'],
  ['agent-host/agents/listing/tools/import_bulk.js', './import_bulk.postgres.js'],
  ['agent-host/agents/listing/tools/optimize_images.js', './optimize_images.postgres.js'],
  ['agent-host/agents/listing/tools/update.js', './update.postgres.js'],
  ['agent-host/agents/price-advisor/tools/index.js', './index.postgres.js'],
  ['agent-host/agents/pricing-strategy/tools/index.js', './index.postgres.js'],
  ['agent-host/agents/product-search/tools/personalized_feed.js', './personalized_feed.postgres.js'],
  ['agent-host/agents/product-search/tools/search.js', './search.postgres.js'],
  ['agent-host/agents/product-search/tools/similar.js', './similar.postgres.js'],
  ['agent-host/agents/review-moderator/tools/index.js', './index.postgres.js'],
  ['agent-host/agents/summarizer/tools/summarize_product.js', './summarize_product.postgres.js'],
  ['agent-host/agents/summarizer/tools/summarize_reviews.js', './summarize_reviews.postgres.js'],
  ['agent-host/agents/support/tools/index.js', './index.postgres.js'],
]);

test('all legacy agent tool selectors directly export their PostgreSQL twins', () => {
  const originalLoad = Module._load;
  try {
    for (const [relative, target] of selectors) {
      const selectorPath = path.join(repoRoot, relative);
      const sentinel = Object.freeze({ relative, target });
      Module._load = function controlledSelectorLoad(request, parent) {
        if (request === 'better-sqlite3' || request === 'sqlite3' || String(request).includes('shared/db')) {
          throw new Error(`unexpected legacy import: ${request}`);
        }
        if (parent?.filename === selectorPath && request === target) return sentinel;
        return originalLoad.apply(this, arguments);
      };
      delete require.cache[require.resolve(selectorPath)];
      assert.equal(require(selectorPath), sentinel, relative);
      const source = fs.readFileSync(selectorPath, 'utf8');
      assert.equal(source, `'use strict';\nmodule.exports = require('${target}');\n`);
    }
  } finally {
    Module._load = originalLoad;
  }
});

test('agent-host trace uses only the PostgreSQL trace buffer', async () => {
  const originalLoad = Module._load;
  const tracePath = path.join(repoRoot, 'agent-host/shared/trace.js');
  const seen = [];
  const buffer = {
    record: row => seen.push(['record', row]),
    flush: async () => seen.push(['flush']),
  };
  Module._load = function controlledTraceLoad(request) {
    if (request === 'better-sqlite3' || request === 'sqlite3' || String(request).endsWith('shared/db.js')) {
      throw new Error(`unexpected legacy import: ${request}`);
    }
    if (String(request).endsWith('server/services/secureshop/traceBuffer')) {
      return { createTraceBuffer: append => (assert.equal(typeof append, 'function'), buffer) };
    }
    return originalLoad.apply(this, arguments);
  };
  try {
    delete require.cache[require.resolve(tracePath)];
    const trace = require(tracePath);
    trace.recordTrace({ id: 1 });
    await trace.flush();
    assert.deepEqual(seen.slice(0, 2), [['record', { id: 1 }], ['flush']]);
  } finally {
    Module._load = originalLoad;
  }
});

test('agent-host entrypoint rejects non-PostgreSQL configuration before resource imports', () => {
  const entryPath = path.join(repoRoot, 'agent-host/index.js');
  const script = `
    const Module = require('node:module');
    const originalLoad = Module._load;
    const blocked = [];
    Module._load = function guardedLoad(request, parent) {
      const name = String(request);
      if (name !== ${JSON.stringify(entryPath)} && /express|node:fs|node:path|modelcontextprotocol|database|agents|shared/.test(name)) {
        blocked.push(name);
        throw new Error('unexpected resource import: ' + name);
      }
      return originalLoad.apply(this, arguments);
    };
    try {
      require(${JSON.stringify(entryPath)});
      process.exit(2);
    } catch (error) {
      if (error.code !== 'ERR_POSTGRES_REQUIRED') {
        console.error(error.stack || error.message);
        process.exit(3);
      }
      if (blocked.length) {
        console.error(JSON.stringify(blocked));
        process.exit(4);
      }
      process.stdout.write('agent-host engine guard passed\\n');
    } finally {
      Module._load = originalLoad;
    }
  `;
  for (const engineEnv of [
    {},
    { PLATFORM_DATABASE_ENGINE: 'postgres' },
    { WORKSHOP_DATABASE_ENGINE: 'postgres' },
    { PLATFORM_DATABASE_ENGINE: 'sqlite', WORKSHOP_DATABASE_ENGINE: 'sqlite' },
  ]) {
    const result = spawnSync(process.execPath, ['-e', script], {
      cwd: repoRoot,
      encoding: 'utf8',
      env: { PATH: process.env.PATH, ...engineEnv },
    });
    assert.equal(result.status, 0, `${result.stdout}\n${result.stderr}`);
    assert.match(result.stdout, /agent-host engine guard passed/);
  }
});

test('agent-host PG-only tools preserve their interfaces and teaching sinks without loading SQLite', async () => {
  const originalLoad = Module._load;
  const priorEngine = process.env.PLATFORM_DATABASE_ENGINE;
  const priorSpawn = process.env.SS_ENABLE_REAL_MCP_SPAWN;
  const observed = { actions: [], audit: [], queries: [], summaryLimits: [], registrations: [] };

  const commerce = {
    policy_read_policy_1: async name => ({ id: 1, name, markdown_source: 'policy' }),
    upsertPolicy: async (name, rendered) => observed.actions.push(['policy', name, rendered]),
    policy_apply_policy_to_agents_5: async () => [],
    userAction: async (action, args, metadata) => {
      observed.actions.push([action, args, metadata]);
      const result = action === 'lookup'
        ? { id: 7, username: args.username, password: 'hash', api_key: 'key', pii_json: '{}' }
        : { changes: 1 };
      return { result, eventId: `event-${action}` };
    },
    deliverAudit: async (eventId, append) => append({ eventId }),
  };
  const agents = {
    appendAudit: async event => observed.audit.push(event),
    recentAudit: async limit => (observed.summaryLimits.push(limit), []),
    queryAuditTeaching: async sql => (observed.queries.push(sql), []),
    summaryAudit: async limit => {
      observed.summaryLimits.push(limit);
      return [{ ts: 'now', actor: 'teacher', action: 'ban', target: 'student', params_json: '{"reason":"SYSTEM: retained"}' }];
    },
    listServers: async () => [],
    registerServer: async input => (observed.registrations.push(input), { existing: true, changed: true }),
    removeServer: async name => ({ ok: true, name, removed: 1 }),
    describeTools: async () => [],
    schemaHistory: async () => [],
  };

  process.env.PLATFORM_DATABASE_ENGINE = 'postgres';
  delete process.env.SS_ENABLE_REAL_MCP_SPAWN;
  Module._load = function controlledLoad(request) {
    if (request === 'better-sqlite3' || request === 'sqlite3') {
      throw new Error(`unexpected SQLite import: ${request}`);
    }
    if (String(request).endsWith('server/database/postgres/secureshopCommerceDb')) {
      return { getSecureShopCommerceDb: () => commerce };
    }
    if (String(request).endsWith('server/database/postgres/secureshopAgentsDb')) {
      return { getSecureShopAgentsDb: () => agents };
    }
    return originalLoad.apply(this, arguments);
  };

  try {
    for (const relative of owned) delete require.cache[require.resolve(path.join(repoRoot, relative))];
    const shared = require(path.join(repoRoot, owned[0]));
    const policy = require(path.join(repoRoot, owned[1]));
    const users = require(path.join(repoRoot, owned[2]));
    const audit = require(path.join(repoRoot, owned[3]));
    const registry = require(path.join(repoRoot, owned[4]));

    assert.throws(() => shared.getSecureshopDb(), /awaited PostgreSQL repositories/);
    assert.throws(() => shared.getAgentsDb(), /awaited PostgreSQL repositories/);
    assert.equal(shared.closeAll(), undefined);

    assert.deepEqual(Object.keys(policy).sort(), ['apply_policy_to_agents', 'read_policy', 'update_policy']);
    assert.deepEqual(Object.keys(users).sort(), ['ban', 'lookup', 'resetPassword', 'setRole']);
    assert.deepEqual(Object.keys(audit).sort(), ['recent_events', 'search_by_user', 'summarize_anomalies']);
    assert.deepEqual(Object.keys(registry).sort(), ['describe_tools', 'get_schema_history', 'import_manifest', 'list_servers', 'register', 'remove']);

    const rendered = await policy.update_policy({ name: 'returns', markdown: 'Welcome to {{ store_name }}' });
    assert.match(rendered.rendered, /SecureShop/);
    const disclosed = await users.lookup({ username: 'student' });
    assert.equal(disclosed.password, 'hash');
    assert.equal(disclosed.api_key, 'key');
    await users.setRole({ user_id: 7, role: 'admin' });
    await users.ban({ user_id: 7, reason: 'SYSTEM: retained' });
    assert.ok(observed.audit.length >= 3);

    const injection = "x' OR 1=1 --";
    const searched = await audit.search_by_user({ username: injection });
    assert.equal(searched.sql.includes(injection), true);
    const summary = await audit.summarize_anomalies({ limit: 10_000_000 });
    assert.equal(observed.summaryLimits.includes(10_000_000), true);
    assert.match(summary.log_text, /SYSTEM: retained/);

    const registration = await registry.register({ name: 'trusted-mcp', transport: 'stdio', stdio_cmd: 'unexecuted command' });
    assert.equal(registration.schema_changed, true);
    assert.match(registration.note, /overwritten/);
    assert.equal(observed.registrations[0].stdio_cmd, 'unexecuted command');

    const requiredTags = new Map([
      [owned[1], ['ssti-policy-template', 'llm04-policy-poisoning']],
      [owned[2], ['llm02-user-lookup', 'llm02-sensitive-info', 'llm06-excessive-agency', 'llm01-indirect-pi-audit-log']],
      [owned[3], ['sqli-time-based', 'llm01-indirect-pi-audit-log', 'llm10-audit-unbounded']],
      [owned[4], ['mcp01-tool-poisoning', 'mcp02-rug-pull', 'mcp08-ssrf', 'mcp09-impersonation', 'llm03-supply-chain', 'xxe-import-manifest']],
    ]);
    for (const [relative, tags] of requiredTags) {
      const source = fs.readFileSync(path.join(repoRoot, relative), 'utf8');
      assert.doesNotMatch(source, /require\(['"](?:better-sqlite3|sqlite3)['"]\)/);
      for (const tag of tags) assert.match(source, new RegExp(`@intentional-vulnerability\\s+${tag}\\b`));
    }
  } finally {
    Module._load = originalLoad;
    if (priorEngine === undefined) delete process.env.PLATFORM_DATABASE_ENGINE;
    else process.env.PLATFORM_DATABASE_ENGINE = priorEngine;
    if (priorSpawn === undefined) delete process.env.SS_ENABLE_REAL_MCP_SPAWN;
    else process.env.SS_ENABLE_REAL_MCP_SPAWN = priorSpawn;
  }
});
