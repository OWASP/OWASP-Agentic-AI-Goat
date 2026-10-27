'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { spawn } = require('node:child_process');
const fs = require('node:fs');
const net = require('node:net');
const path = require('node:path');
const { randomUUID } = require('node:crypto');
const { createPool } = require('../../server/database/postgres');
const {
  initializeSecureShopCommerceDb,
  initializeSecureShopAgentsDb,
} = require('../../server/database/postgres/secureshopInitialization');
const { McpClientPool, AGENT_NAMES } = require('../../server/services/secureshop/mcpClientPool');
const { connectAgent, disconnect } = require('../../server/services/secureshop/mcpTransport');
const { AgentHostSupervisor } = require('../../server/services/secureshop/agentHostSupervisor');
const { ToolManifest } = require('../../server/services/secureshop/toolManifest');

const ROOT = path.resolve(__dirname, '../..');
const enabled = process.env.SECURESHOP_AGENT_HOST_TRANSPORT_NATIVE === '1'
  && process.env.PG_TEST_DISPOSABLE === 'yes';
const diagnosticCase = process.env.SECURESHOP_LEGACY_SUPERVISOR_DIAGNOSTIC || null;
const diagnosticPath = process.env.SECURESHOP_LEGACY_SUPERVISOR_DIAGNOSTIC_PATH || null;

function writeDiagnosticCheckpoint(value) {
  assert.ok(diagnosticPath && path.isAbsolute(diagnosticPath));
  const parent = path.dirname(diagnosticPath);
  assert.equal(fs.realpathSync(parent), parent);
  assert.ok(parent.startsWith(`${ROOT}${path.sep}`), 'diagnostic evidence must stay in checkout');
  const temporary = `${diagnosticPath}.${process.pid}.tmp`;
  fs.writeFileSync(temporary, JSON.stringify(value), { flag: 'wx', mode: 0o600 });
  try { fs.renameSync(temporary, diagnosticPath); }
  catch (error) { fs.unlinkSync(temporary); throw error; }
}

function validateDisposableUrls(env) {
  const stores = [
    ['secureshop', 'PG_SECURESHOP_AGENT_HOST_COMMERCE_RUNTIME_URL',
      'PG_SECURESHOP_AGENT_HOST_COMMERCE_MIGRATION_URL'],
    ['secureshop_agents', 'PG_SECURESHOP_AGENT_HOST_AGENTS_RUNTIME_URL',
      'PG_SECURESHOP_AGENT_HOST_AGENTS_MIGRATION_URL'],
  ];
  const databases = new Set();
  for (const [store, runtimeKey, migrationKey] of stores) {
    const values = [new URL(env[runtimeKey]), new URL(env[migrationKey])];
    for (const [index, value] of values.entries()) {
      assert.equal(value.protocol, 'postgresql:');
      assert.equal(value.hostname, '127.0.0.1');
      assert.match(value.port, /^[0-9]+$/);
      assert.ok(Number(value.port) >= 1 && Number(value.port) <= 65535);
      assert.equal(value.username, `dvaia_${store}_${index ? 'migration' : 'runtime'}`);
      assert.equal(value.password + value.search + value.hash, '');
      assert.match(value.pathname,
        new RegExp(`^/dvaia_test_agent_host_[a-f0-9]{12}_${store}$`));
    }
    assert.equal(values[0].host, values[1].host);
    assert.equal(values[0].pathname, values[1].pathname);
    databases.add(values[0].pathname);
  }
  assert.equal(databases.size, stores.length);
}

function bounded(current, chunk) {
  return (current + chunk.toString()).slice(-16384);
}

async function freePort() {
  const server = net.createServer();
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  const port = server.address().port;
  await new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
  return port;
}

async function waitForHealth(port, instanceId, child, output, timeoutMs = 20000) {
  const deadline = Date.now() + timeoutMs;
  let last;
  while (Date.now() < deadline) {
    if (child && (child.exitCode !== null || child.signalCode !== null)) {
      throw new Error(`agent-host exited before readiness: ${output()}`);
    }
    try {
      const response = await fetch(`http://127.0.0.1:${port}/health`, { signal: AbortSignal.timeout(1000) });
      const body = await response.json();
      if (response.ok && body.instanceId === instanceId) return body;
      last = new Error(`health ${response.status}`);
    } catch (error) { last = error; }
    await new Promise(resolve => setTimeout(resolve, 100));
  }
  throw new Error(`agent-host readiness timeout: ${last?.message || 'no response'} ${output()}`);
}

async function stopOwnedChild(child) {
  if (!child || child.exitCode !== null || child.signalCode !== null) return;
  child.kill('SIGTERM');
  const exited = new Promise(resolve => child.once('exit', resolve));
  const completed = await Promise.race([
    exited.then(() => true),
    new Promise(resolve => setTimeout(() => resolve(false), 8000)),
  ]);
  if (!completed) {
    child.kill('SIGKILL');
    await exited;
  }
}

test('real PostgreSQL agent host serves all 17 MCP paths and isolates concurrent clients', {
  skip: !enabled,
  timeout: diagnosticCase ? 300000 : 120000,
}, async t => {
  assert.ok(diagnosticCase === null || ['V14', 'V30'].includes(diagnosticCase));
  if (diagnosticCase) assert.equal(typeof diagnosticPath, 'string');
  else assert.equal(diagnosticPath, null);
  const required = [
    'PG_SECURESHOP_AGENT_HOST_COMMERCE_RUNTIME_URL',
    'PG_SECURESHOP_AGENT_HOST_COMMERCE_MIGRATION_URL',
    'PG_SECURESHOP_AGENT_HOST_AGENTS_RUNTIME_URL',
    'PG_SECURESHOP_AGENT_HOST_AGENTS_MIGRATION_URL',
  ];
  for (const name of required) assert.equal(typeof process.env[name], 'string', `${name} required`);
  validateDisposableUrls(process.env);
  assert.deepEqual(AGENT_NAMES, [
    'product-search','summarizer','price-advisor','cart','support',
    'listing','inventory','pricing-strategy','review-moderator','analytics',
    'user-management','audit','system','policy','mcp-registry','uploads','email',
  ]);

  const commerce = createPool(process.env, 'PG_SECURESHOP_AGENT_HOST_COMMERCE_RUNTIME_URL');
  const commerceMigration = createPool(process.env, 'PG_SECURESHOP_AGENT_HOST_COMMERCE_MIGRATION_URL');
  const agents = createPool(process.env, 'PG_SECURESHOP_AGENT_HOST_AGENTS_RUNTIME_URL');
  const agentsMigration = createPool(process.env, 'PG_SECURESHOP_AGENT_HOST_AGENTS_MIGRATION_URL');
  let host;
  const pools = [commerce, commerceMigration, agents, agentsMigration];
  t.after(async () => {
    const errors = [];
    try { await stopOwnedChild(host); } catch (error) { errors.push(error); }
    const closed = await Promise.allSettled(pools.map(pool => pool.end()));
    errors.push(...closed.filter(row => row.status === 'rejected').map(row => row.reason));
    if (errors.length) throw new AggregateError(errors, 'agent-host fixture cleanup failed');
  });
  await initializeSecureShopCommerceDb({ runtimePool: commerce, migrationPool: commerceMigration });
  await initializeSecureShopAgentsDb({ runtimePool: agents, migrationPool: agentsMigration });

  const port = await freePort();
  const instanceId = randomUUID();
  let stdout = '', stderr = '';
  host = spawn(process.execPath, ['agent-host/index.js'], {
    cwd: ROOT,
    env: {
      ...process.env,
      SECURESHOP_DATABASE_URL: process.env.PG_SECURESHOP_AGENT_HOST_COMMERCE_RUNTIME_URL,
      SECURESHOP_AGENTS_DATABASE_URL: process.env.PG_SECURESHOP_AGENT_HOST_AGENTS_RUNTIME_URL,
      SS_AGENT_HOST_PORT: String(port),
      SS_AGENT_HOST_INSTANCE_ID: instanceId,
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  host.stdout.on('data', chunk => { stdout = bounded(stdout, chunk); });
  host.stderr.on('data', chunk => { stderr = bounded(stderr, chunk); });
  const output = () => `stdout=${stdout}\nstderr=${stderr}`;
  const health = await waitForHealth(port, instanceId, host, output);
  assert.deepEqual(health.agents, [...AGENT_NAMES]);

  const baseUrl = `http://127.0.0.1:${port}`;
  const pool = new McpClientPool({ baseUrl, agents: AGENT_NAMES });
  await pool.connect();
  t.after(() => pool.close());
  for (const name of AGENT_NAMES) {
    const listed = await pool.getClient(name).listTools();
    assert.ok(Array.isArray(listed.tools), `${name} must expose MCP tools`);
    assert.ok(listed.tools.length > 0, `${name} must expose at least one MCP tool`);
  }

  const clients = [];
  const connect = async name => {
    const client = await connectAgent('product-search', baseUrl);
    clients.push(client);
    assert.deepEqual((await client.listTools()).tools.map(tool => tool.name), [
      'search', 'similar', 'personalized_feed',
    ], name);
    return client;
  };
  t.after(() => Promise.allSettled(clients.map(client => disconnect(client))));
  const first = await connect('first');
  const second = await connect('second');
  await disconnect(first);
  assert.equal((await second.listTools()).tools.length, 3);
  const replacement = await connect('replacement');
  assert.equal((await replacement.listTools()).tools.length, 3);
  assert.equal((await second.listTools()).tools.length, 3);

  if (diagnosticCase) {
    assert.equal(process.env.DVAIA_ISOLATED_TEST_WORKSPACE, ROOT);
    assert.equal(process.env.AI_PROVIDER, 'ollama');
    assert.equal(process.env.OLLAMA_BASE_URL, 'http://127.0.0.1:11434');
    assert.equal(process.env.OLLAMA_MODEL, 'llama3.1:8b');
    const username = `legacy-diagnostic-${randomUUID()}`;
    await commerceMigration.query(
      'INSERT INTO secureshop.shop_users(username,email,password,role,full_name) VALUES($1,$2,$3,$4,$5)',
      [username, `${username}@example.invalid`, 'diagnostic-no-login',
        diagnosticCase === 'V14' ? 'customer' : 'admin', 'Disposable diagnostic persona']);
    const manifest = new ToolManifest(pool);
    await manifest.refresh();
    const result = await require('./secureshopLegacySupervisorActual').run({
      caseId: diagnosticCase, manifest, onCheckpoint: writeDiagnosticCheckpoint,
    });
    assert.equal(result.caseId, diagnosticCase);
    assert.equal(result.noProgressCredit, true);
    assert.equal(result.gates.completed, false);
    assert.equal(result.gates.progressCredit, false);
    assert.equal(result.diagnosticJudge.verdict, 'unreviewed');
    writeDiagnosticCheckpoint({ caseId: diagnosticCase, phase: 'complete', receipt: result });
  }

  await pool.close();
  await Promise.allSettled(clients.map(client => disconnect(client)));
  await stopOwnedChild(host);
  host = null;
  await assert.rejects(fetch(`${baseUrl}/health`, { signal: AbortSignal.timeout(500) }));

  const supervisorPort = await freePort();
  const supervisor = new AgentHostSupervisor({
    port: supervisorPort,
    restartLimit: 0,
    stopTimeoutMs: 8000,
    env: {
      ...process.env,
      SECURESHOP_DATABASE_URL: process.env.PG_SECURESHOP_AGENT_HOST_COMMERCE_RUNTIME_URL,
      SECURESHOP_AGENTS_DATABASE_URL: process.env.PG_SECURESHOP_AGENT_HOST_AGENTS_RUNTIME_URL,
    },
  });
  t.after(() => supervisor.stop());
  await supervisor.start();
  const supervised = await waitForHealth(supervisorPort, supervisor.instanceId, null, () => 'supervisor');
  assert.deepEqual(supervised.agents, [...AGENT_NAMES]);
  await supervisor.stop();
  assert.equal(supervisor.status, 'stopped');
  await assert.rejects(fetch(`http://127.0.0.1:${supervisorPort}/health`, { signal: AbortSignal.timeout(500) }));
});
