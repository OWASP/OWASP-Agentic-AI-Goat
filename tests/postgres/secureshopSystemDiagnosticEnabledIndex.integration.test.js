'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const http = require('node:http');
const net = require('node:net');
const { spawn } = require('node:child_process');
const { once } = require('node:events');
const { randomBytes, randomUUID } = require('node:crypto');
const { networkGuardSource, waitForChild, createOwnedChildren } = require('../fixtures/fullBackendBootControls');

const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
const CAPABILITY = 'secureshop-owned-system-diagnostic.v1';

test('actual enabled index admits only the ready owned System diagnostic executor', {
  skip: process.env.PG_SECURESHOP_DIAGNOSTIC_ENABLED_INDEX !== '1', timeout: 360000,
}, async t => {
  const source = path.resolve(__dirname, '../..');
  assert.equal(fs.realpathSync(source), process.env.DVAIA_ISOLATED_TEST_WORKSPACE);
  assert.equal(fs.statSync(source).mode & 0o222, 0, 'source must be frozen');
  const root = process.env.DVAIA_FULL_BACKEND_RUNTIME_ROOT;
  assert.ok(root && path.isAbsolute(root));
  assert.equal(fs.realpathSync(root), root);
  assert.equal(fs.statSync(root).uid, process.getuid());
  assert.equal(fs.readdirSync(root).length, 0);
  assert.ok(!root.startsWith(source + path.sep) && !source.startsWith(root + path.sep));
  fs.chmodSync(root, 0o700);

  const readerOrigin = new URL(process.env.PG_SECURESHOP_DIAGNOSTIC_EXECUTOR_ORIGIN);
  assert.equal(readerOrigin.protocol, 'http:'); assert.equal(readerOrigin.hostname, '127.0.0.1');
  assert.ok(Number(readerOrigin.port) > 0); assert.equal(readerOrigin.pathname, '/');
  assert.equal(readerOrigin.username + readerOrigin.password + readerOrigin.search + readerOrigin.hash, '');
  const readerToken = process.env.PG_SECURESHOP_DIAGNOSTIC_EXECUTOR_TOKEN;
  assert.match(readerToken, /^[A-Za-z0-9_-]{43,128}$/);

  const { requiredStoreManifest } = require('../../db/postgres/initialize-application');
  assert.equal(requiredStoreManifest.length, 16);
  const env = {
    PATH: process.env.PATH, NODE_ENV: 'test', PLATFORM_DATABASE_ENGINE: 'postgres',
    WORKSHOP_DATABASE_ENGINE: 'postgres', PG_TEST_DISPOSABLE: 'yes',
    HOME: path.join(root, 'home'), DVAIA_APP_DATA_ROOT: path.join(root, 'app-data'),
    LOGS_DIR: path.join(root, 'logs'), LEGACY_SENSITIVE_FILES_ROOT: path.join(root, 'legacy-sensitive-files'),
    SS_BOUND_SYSTEM_CONFIG_ENABLED:'true', SS_SYSTEM_CONFIG_BASE_URL:process.env.PG_SECURESHOP_SYSTEM_EXECUTOR_ORIGIN, SS_SYSTEM_CONFIG_TOKEN:process.env.PG_SECURESHOP_SYSTEM_EXECUTOR_TOKEN,
    SS_ENABLE: 'true', SS_BOUND_REVIEWS_ENABLED: 'true', SS_PERSONA_INBOX_READY: 'true',
    SS_MCP_TRUST_READY: 'true', SS_CONTROLLED_SSRF_READY: 'true', SS_AUDIT_SUMMARY_ENABLED: 'false',
    SS_ENABLE_REAL_MCP_SPAWN: 'false', MCP_SIDECARS_AUTOSTART: 'false', MCP_WORKSHOP_AUTOSTART: 'false',
    AI_PROVIDER: 'mock', OLLAMA_BASE_URL: 'http://127.0.0.1:1', AWS_EC2_METADATA_DISABLED: 'true',
    HF_HUB_OFFLINE: '1', TRANSFORMERS_OFFLINE: '1', HF_HOME: path.join(root, 'hf-cache'),
    EVENT_GATE_ENABLED: 'false', JWT_SECRET: randomUUID() + randomUUID(),
    LANGCHAIN_TRACING_V2: 'false', LANGSMITH_TRACING: 'false',
  };
  const databases = new Set(), roles = new Set(), endpoints = new Set();
  for (const row of requiredStoreManifest) {
    let database;
    for (const [key, role] of [[row.runtimeVariable, row.runtimeRole],
      [row.migrationVariable, `dvaia_${row.schema}_migration`]]) {
      const url = new URL(process.env[key]);
      assert.ok(['postgres:', 'postgresql:'].includes(url.protocol));
      assert.equal(url.hostname, '127.0.0.1'); assert.ok(url.port);
      assert.equal(url.search, ''); assert.equal(url.hash, '');
      assert.equal(decodeURIComponent(url.username), role);
      assert.equal(url.pathname, `/dvaia_test_full_backend_${row.schema}`);
      if (database) assert.equal(url.pathname, database);
      database = url.pathname; roles.add(role); endpoints.add(url.host); env[key] = url.href;
    }
    databases.add(database);
  }
  assert.equal(databases.size, 16); assert.equal(roles.size, 32); assert.equal(endpoints.size, 1);
  for (const directory of [env.HOME, env.LOGS_DIR, env.DVAIA_APP_DATA_ROOT]) {
    fs.mkdirSync(directory, { mode: 0o700 });
  }
  env.SS_PASSWORD_RESET_KEY_PATH = path.join(env.DVAIA_APP_DATA_ROOT, 'password-reset-keys.json');
  fs.writeFileSync(env.SS_PASSWORD_RESET_KEY_PATH, JSON.stringify({ version: 1, activeKeyId: 'native',
    keys: { native: randomBytes(32).toString('base64url') } }), { mode: 0o600, flag: 'wx' });
  for (const [key, name] of [['SS_MCP_TRUST_FIXTURE_ROOT', 'mcp-trust'],
    ['SS_CONTROLLED_SSRF_FIXTURE_ROOT', 'ssrf']]) {
    env[key] = path.join(root, name); fs.mkdirSync(env[key], { mode: 0o700 });
  }
  env.SECURESHOP_REVIEW_RENDERER_ROOT = path.join(source, 'client/build/secureshop-review-renderer');

  const reservePort = async () => {
    const server = http.createServer(); server.listen(0, '127.0.0.1'); await once(server, 'listening');
    const value = server.address().port; await new Promise(resolve => server.close(resolve)); return value;
  };
  const agentPort = await reservePort();
  env.SS_AGENT_HOST_PORT = String(agentPort);
  const readerCalls = [];
  const proxy = http.createServer(async (req, res) => {
    readerCalls.push(Object.freeze({ method: req.method, path: req.url,
      authorized: req.headers.authorization === `Bearer ${readerToken}` }));
    try {
      const chunks = []; let length = 0;
      for await (const chunk of req) {
        length += chunk.length;
        if (length > 32 * 1024) throw new Error('proxy body overflow');
        chunks.push(chunk);
      }
      const response = await fetch(new URL(req.url, readerOrigin), { method: req.method,
        headers: { authorization: req.headers.authorization || '',
          ...(req.headers['content-type'] ? { 'content-type': req.headers['content-type'] } : {}) },
        ...(length ? { body: Buffer.concat(chunks) } : {}), signal: AbortSignal.timeout(20000) });
      res.writeHead(response.status, { 'content-type': response.headers.get('content-type') || 'application/json',
        'cache-control': 'no-store' });
      res.end(Buffer.from(await response.arrayBuffer()));
    } catch {
      if (!res.headersSent) res.writeHead(502, { 'content-type': 'application/json' });
      res.end('{"error":"proxy unavailable"}');
    }
  });
  proxy.listen(0, '127.0.0.1'); await once(proxy, 'listening');
  t.after(()=>new Promise(resolve=>{proxy.closeAllConnections();proxy.close(resolve);}));
  const proxyPort = proxy.address().port;
  env.SS_SYSTEM_DIAGNOSTIC_BASE_URL = `http://127.0.0.1:${proxyPort}`;
  env.SS_SYSTEM_DIAGNOSTIC_TOKEN = readerToken;
  const postgresPort = [...endpoints][0].split(':')[1];
  const reservedPorts = new Set([agentPort, proxyPort, Number(readerOrigin.port), Number(postgresPort),Number(new URL(env.SS_SYSTEM_CONFIG_BASE_URL).port)]);
  assert.equal(reservedPorts.size, 5,
    'agent, proxy, executor and PostgreSQL ports must be distinct');
  const backendPorts = new Set(); let port; let base;
  const selectBackendPort = async () => {
    for (let attempt = 0; attempt < 20; attempt++) {
      const candidate = await reservePort();
      if (reservedPorts.has(candidate) || backendPorts.has(candidate)) continue;
      backendPorts.add(candidate); port = candidate; base = `http://127.0.0.1:${port}`;
      env.SS_ALLOWED_ORIGINS = base;
      assert.equal(new URL(env.SS_ALLOWED_ORIGINS).origin, base);
      return;
    }
    assert.fail('could not reserve a distinct owned backend port');
  };
  const guard = path.join(root, 'network-guard.cjs');
  fs.writeFileSync(guard, networkGuardSource({ host: '127.0.0.1', port: postgresPort }, { version: 1,
    services: [{ name: 'agent_host', host: '127.0.0.1', port: agentPort },
      { name: 'fixture_system_proxy', host: '127.0.0.1', port: proxyPort },
      { name: 'fixture_owned_config_listener', host:'127.0.0.1',port:Number(new URL(env.SS_SYSTEM_CONFIG_BASE_URL).port) }] }), { mode: 0o600 });
  env.NODE_OPTIONS = `--require=${guard}`;

  const owned = createOwnedChildren(spawn); let identityPool, agentsMigration, agentsRuntime, child; let sequence = 0;
  const launch = (file, args = [], overrides = {}) => {
    const logPath = path.join(root, `${sequence++}-${path.basename(file)}.log`);
    const log = fs.openSync(logPath, 'wx', 0o600);
    try {
      const childProcess = owned.launch(process.execPath, [file, ...args], { cwd: source,
        env: { ...env, PORT: String(port), ...overrides }, stdio: ['ignore', log, log] });
      childProcess.qualificationLog = logPath; return childProcess;
    } finally { fs.closeSync(log); }
  };
  const request = async (url, token, body, extra = {}) => {
    const response = await fetch(base + url, { method: body === undefined ? 'GET' : 'POST',
      signal: AbortSignal.any([t.signal, AbortSignal.timeout(5000)]), headers: {
        ...(body === undefined ? {} : { 'content-type': 'application/json' }),
        ...(token ? { authorization: `Bearer ${token}` } : {}), ...extra,
      }, ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
    return { status: response.status, body: await response.json() };
  };
  const waitReady = async process => {
    for (let i = 0; i < 300; i++) {
      assert.equal(process.exitCode, null, `backend exited before readiness; see ${process.qualificationLog}`);
      try { if ((await request('/api/monitoring/ping')).status === 200) return; } catch {}
      await sleep(100);
    }
    assert.fail(`backend readiness timed out; see ${process.qualificationLog}`);
  };
  const assertPortClosed = portToCheck => new Promise((resolve, reject) => {
    const socket = net.connect({ host: '127.0.0.1', port: portToCheck }); socket.setTimeout(500);
    socket.once('connect', () => { socket.destroy(); reject(new Error(`owned port ${portToCheck} remains open`)); });
    socket.once('timeout', () => { socket.destroy(); reject(new Error(`owned port ${portToCheck} did not close`)); });
    socket.once('error', error => error.code === 'ECONNREFUSED' ? resolve() : reject(error));
  });
  const stop = async process => {
    process.kill('SIGTERM'); assert.equal(await waitForChild(process, { timeoutMs: 20000, signal: t.signal }), 0);
    await assertPortClosed(port); await assertPortClosed(agentPort);
  };
  const rejectedStartup = async overrides => {
    child = launch('server/index.js', [], overrides);
    const exitCode = await waitForChild(child, { timeoutMs: 30000, signal: t.signal }); child = null;
    assert.notEqual(exitCode, 0); await assertPortClosed(port); await assertPortClosed(agentPort);
    let reachable = false; try { reachable = (await request('/api/monitoring/ping')).status === 200; } catch {}
    assert.equal(reachable, false);
    return fs.readFileSync(path.join(root, `${sequence - 1}-index.js.log`), 'utf8');
  };

  try {
    assert.equal(await waitForChild(launch('server/database/sensitiveInfoFiles.js', ['--initialize-missing']),
      { timeoutMs: 30000, signal: t.signal }), 0);
    assert.equal(await waitForChild(launch('db/postgres/initialize-application.js'),
      { timeoutMs: 120000, signal: t.signal }), 0);
    const { Pool } = require('pg');
    identityPool = new Pool({ connectionString: env.IDENTITY_DATABASE_URL, max: 2 });
    agentsMigration = new Pool({ connectionString: env.SECURESHOP_AGENTS_MIGRATION_DATABASE_URL, max: 2 });
    agentsRuntime = new Pool({ connectionString: env.SECURESHOP_AGENTS_DATABASE_URL, max: 2 });
    const users = require('../../server/database/postgres/identityRepository').createIdentityRepository(identityPool);
    const password = `${randomUUID()}Aa1!`, passwordHash = await require('bcryptjs').hash(password, 4);
    const platformUser = await users.createUser({ username: `system-index-${randomUUID().slice(0, 8)}`,
      email: `${randomUUID()}@example.invalid`, passwordHash });
    const visible = await identityPool.query(`UPDATE workshop_platform.exercises
      SET is_visible=true,updated_at=clock_timestamp()
      WHERE workshop_key='secureshop_agent_security' AND catalog_active=true AND is_visible=false`);
    assert.equal(visible.rowCount, 1,
      'the disposable rendered fixture must explicitly publish the default-hidden SecureShop exercise');

    await selectBackendPort();
    child = launch('server/index.js', [], { SS_BOUND_SYSTEM_DIAGNOSTIC_ENABLED: 'false',
      SS_SYSTEM_DIAGNOSTIC_BASE_URL: 'file:///private', SS_SYSTEM_DIAGNOSTIC_TOKEN: 'invalid' });
    await waitReady(child); assert.equal(readerCalls.length, 0, 'disabled baseline must not probe reader');
    await stop(child); child = null;

    await selectBackendPort();
    child = launch('server/index.js', [], { SS_BOUND_SYSTEM_DIAGNOSTIC_ENABLED: 'true' });
    await waitReady(child);
    const login = await request('/api/auth/login', null, { username: platformUser.username, password });
    assert.equal(login.status, 200); const token = login.body.token;
    const launched = await request('/api/auth/secureshop-launch', token, {}); assert.equal(launched.status, 201);
    const launchHeader = { 'x-dvaia-secureshop-launch': launched.body.bearer };
    const persona = await request('/api/secureshop/v2/auth/login', token,
      { username: 'student_admin', password: 'student123' }, launchHeader);
    assert.equal(persona.status, 200); const personaToken = persona.body.token;
    const availability = await request('/api/secureshop/admin/system/diagnostic', personaToken, undefined, launchHeader);
    assert.equal(availability.status, 200); assert.equal(availability.body.ok, true);
    assert.equal(availability.body.administration.diagnosticCapability, CAPABILITY);
    assert.match(availability.body.administration.scopeKey, /^[a-f0-9]{64}$/);
    const operationId = randomUUID();
    const read = await request('/api/secureshop/admin/system/diagnostic', personaToken,
      { operationId, cmd_template:'/usr/bin/uname', args:'-n' }, launchHeader);
    assert.equal(read.status, 200, JSON.stringify(read.body)); assert.equal(read.body.operationId, operationId);
    assert.equal(read.body.state,'completed');assert.equal(read.body.stdout,read.body.hostname+'\n');assert.equal(read.body.hostname,'system-diag-'+read.body.targetId.replaceAll('-',''));assert.equal(read.body.drained,true);
    const operation = await request(`/api/secureshop/admin/system/diagnostic-operations/${operationId}`,
      personaToken, undefined, launchHeader);
    assert.equal(operation.status, 200); assert.deepEqual(operation.body, read.body);
    const stored = await agentsRuntime.query('SELECT state,receipt_json FROM secureshop_agents.bound_system_diagnostic_outcomes WHERE operation_id=$1', [operationId]);
    assert.equal(stored.rowCount, 1); assert.equal(stored.rows[0].state, 'completed');
    assert.equal(stored.rows[0].receipt_json.result.operationId, operationId);
    assert.ok(readerCalls.some(item => item.authorized && item.method === 'GET'
      && item.path === '/secureshop/system/diagnostic-health'));
    assert.equal(readerCalls.filter(item => item.authorized && item.method === 'POST'
      && item.path === '/secureshop/system/diagnostic').length, 1);
    const executorCalls = () => readerCalls.filter(item => item.authorized && item.method === 'POST'
      && item.path === '/secureshop/system/diagnostic').length;
    const browser = await require('../fixtures/secureshopEnabledSystemDiagnosticBrowser')
      .qualifyEnabledSystemDiagnosticBrowser({ origin: base, user: platformUser, password, root,
        readExecutorCalls: executorCalls,
        readPersistedOperation: async id => {
          const value = await agentsRuntime.query('SELECT state,receipt_json FROM secureshop_agents.bound_system_diagnostic_outcomes WHERE operation_id=$1', [id]);
          assert.equal(value.rowCount, 1); return value.rows[0];
        }, signal: t.signal });
    assert.equal(browser.opaqueFrame, true); assert.equal(browser.executorCallsForBrowser, 1);
    assert.equal(browser.persistedBeforeResponseLoss, true);
    assert.equal(browser.reloadRecoveryWithoutResend, true); assert.equal(browser.laterSessionDenied, true);
    assert.equal(executorCalls(), 2);
    await stop(child); child = null;

    const unavailableStart = readerCalls.length; await selectBackendPort();
    const unavailableLog = await rejectedStartup({ SS_BOUND_SYSTEM_DIAGNOSTIC_ENABLED: 'true',
      SS_SYSTEM_DIAGNOSTIC_TOKEN: 'x'.repeat(43) });
    assert.ok(readerCalls.slice(unavailableStart).some(item => item.path === '/secureshop/system/diagnostic-health'
      && item.authorized === false));
    assert.match(unavailableLog, /required_secureshop_init_failed|System diagnostic|SYSTEM_DIAGNOSTIC_UNAVAILABLE/);

    await agentsMigration.query('REVOKE INSERT ON secureshop_agents.bound_system_diagnostic_admissions FROM dvaia_secureshop_agents_runtime');
    const driftStart = readerCalls.length; await selectBackendPort();
    const driftLog = await rejectedStartup({ SS_BOUND_SYSTEM_DIAGNOSTIC_ENABLED: 'true' });
    assert.ok(readerCalls.slice(driftStart).some(item => item.authorized
      && item.path === '/secureshop/system/diagnostic-health'));
    assert.match(driftLog, /required_secureshop_init_failed|System diagnostic|SYSTEM_DIAGNOSTIC_NOT_READY/);

    fs.writeFileSync(path.join(root, 'system-diagnostic-enabled-index-result.json'), JSON.stringify({
      ready: true, disabledBaselineReaderRequests: 0, readerRequests: readerCalls,
      read: { operationId, targetId:read.body.targetId, hostname:read.body.hostname },
      durableReadback: true, browser, unavailableReaderRejectedStartup: true,
      repositoryPrivilegeFailureRejectedStartup: true,
      scope: 'actual frozen server/index, full16 stores, real owned System reader and opaque production browser; no model calls',
    }, null, 2), { mode: 0o600, flag: 'wx' });
  } finally {
    if (child) child.kill('SIGTERM');
    await new Promise(resolve => proxy.close(resolve));
    const cleaned = await Promise.allSettled([owned.cleanup(), identityPool?.end(),
      agentsMigration?.end(), agentsRuntime?.end()]);
    assert.ok(cleaned.every(row => row.status === 'fulfilled'), 'Owned System enabled-index cleanup must complete');
  }
});
