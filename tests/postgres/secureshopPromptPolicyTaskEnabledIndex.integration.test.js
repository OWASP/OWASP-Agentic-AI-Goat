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
const { pathToFileURL } = require('node:url');
const { networkGuardSource, waitForChild, createOwnedChildren } = require('../fixtures/fullBackendBootControls');

const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));

test('actual configured index advertises and renders task policies with durable browser recovery', {
  skip: process.env.PG_SECURESHOP_POLICY_TASK_ENABLED_INDEX !== '1', timeout: 420000,
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

  const rendererOrigin = new URL(process.env.PG_SECURESHOP_POLICY_RENDERER_ORIGIN);
  assert.equal(rendererOrigin.protocol, 'http:');
  assert.equal(rendererOrigin.hostname, '127.0.0.1');
  assert.ok(rendererOrigin.port);
  const { requiredStoreManifest } = require('../../db/postgres/initialize-application');
  assert.equal(requiredStoreManifest.length, 16);
  const env = {
    PATH: process.env.PATH, NODE_ENV: 'test', PLATFORM_DATABASE_ENGINE: 'postgres',
    WORKSHOP_DATABASE_ENGINE: 'postgres', PG_TEST_DISPOSABLE: 'yes',
    HOME: path.join(root, 'home'), DVAIA_APP_DATA_ROOT: path.join(root, 'app-data'),
    LOGS_DIR: path.join(root, 'logs'), LEGACY_SENSITIVE_FILES_ROOT: path.join(root, 'legacy-sensitive-files'),
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
    for (const [key, role] of [[row.runtimeVariable, row.runtimeRole], [row.migrationVariable, `dvaia_${row.schema}_migration`]]) {
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
  for (const directory of [env.HOME, env.LOGS_DIR, env.DVAIA_APP_DATA_ROOT]) fs.mkdirSync(directory, { mode: 0o700 });
  env.SS_PASSWORD_RESET_KEY_PATH = path.join(env.DVAIA_APP_DATA_ROOT, 'password-reset-keys.json');
  fs.writeFileSync(env.SS_PASSWORD_RESET_KEY_PATH, JSON.stringify({ version: 1, activeKeyId: 'native',
    keys: { native: randomBytes(32).toString('base64url') } }), { mode: 0o600, flag: 'wx' });
  for (const [key, name] of [['SS_MCP_TRUST_FIXTURE_ROOT', 'mcp-trust'], ['SS_CONTROLLED_SSRF_FIXTURE_ROOT', 'ssrf']]) {
    env[key] = path.join(root, name); fs.mkdirSync(env[key], { mode: 0o700 });
  }
  env.SECURESHOP_REVIEW_RENDERER_ROOT = path.join(source, 'client/build/secureshop-review-renderer');

  const reservePort = async () => {
    const server = http.createServer(); server.listen(0, '127.0.0.1'); await once(server, 'listening');
    const port = server.address().port; await new Promise(resolve => server.close(resolve)); return port;
  };
  const port = await reservePort(), agentPort = await reservePort(), frontendPort = await reservePort();
  assert.equal(new Set([port, agentPort, frontendPort]).size, 3);
  env.SS_AGENT_HOST_PORT = String(agentPort);
  env.SS_ALLOWED_ORIGINS = `http://127.0.0.1:${frontendPort}`;
  const proxyCalls = [];
  const proxy = http.createServer(async (req, res) => {
    proxyCalls.push(`${req.method} ${req.url}`);
    try {
      const chunks = []; let length = 0;
      for await (const chunk of req) { length += chunk.length; if (length > 160 * 1024) throw new Error('proxy body overflow'); chunks.push(chunk); }
      const response = await fetch(new URL(req.url, rendererOrigin), { method: req.method,
        headers: { 'content-type': req.headers['content-type'] || 'application/json' },
        ...(length ? { body: Buffer.concat(chunks) } : {}), signal: AbortSignal.timeout(15000) });
      res.writeHead(response.status, { 'content-type': response.headers.get('content-type') || 'application/json' });
      res.end(Buffer.from(await response.arrayBuffer()));
    } catch { if (!res.headersSent) res.writeHead(502, { 'content-type': 'application/json' }); res.end('{"error":"proxy unavailable"}'); }
  });
  proxy.listen(0, '127.0.0.1'); await once(proxy, 'listening');
  const proxyPort = proxy.address().port;
  env.SS_POLICY_RENDERER_BASE_URL = `http://127.0.0.1:${proxyPort}`;
  const postgresPort = [...endpoints][0].split(':')[1];
  const guard = path.join(root, 'network-guard.cjs');
  fs.writeFileSync(guard, networkGuardSource({ host: '127.0.0.1', port: postgresPort }, { version: 1, services: [
    { name: 'agent_host', host: '127.0.0.1', port: agentPort },
    { name: 'fixture_policy_renderer', host: '127.0.0.1', port: proxyPort },
  ] }), { mode: 0o600 });
  env.NODE_OPTIONS = `--require=${guard}`;

  const owned = createOwnedChildren(spawn); let identityPool, child, vite; let sequence = 0;
  const launch = (file, args = [], overrides = {}) => {
    const logPath = path.join(root, `${sequence++}-${path.basename(file)}.log`);
    const log = fs.openSync(logPath, 'wx', 0o600);
    try {
      const childProcess = owned.launch(process.execPath, [file, ...args], { cwd: source,
        env: { ...env, PORT: String(port), ...overrides }, stdio: ['ignore', log, log] });
      childProcess.qualificationLog = logPath; return childProcess;
    } finally { fs.closeSync(log); }
  };
  const base = `http://127.0.0.1:${port}`;
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
    const socket = net.connect({ host: '127.0.0.1', port: portToCheck });
    socket.setTimeout(500);
    socket.once('connect', () => { socket.destroy(); reject(new Error(`owned port ${portToCheck} remains open`)); });
    socket.once('timeout', () => { socket.destroy(); reject(new Error(`owned port ${portToCheck} did not close`)); });
    socket.once('error', error => error.code === 'ECONNREFUSED' ? resolve() : reject(error));
  });
  const stop = async process => {
    process.kill('SIGTERM'); assert.equal(await waitForChild(process, { timeoutMs: 20000, signal: t.signal }), 0);
    await assertPortClosed(port); await assertPortClosed(agentPort);
  };

  try {
    assert.equal(await waitForChild(launch('server/database/sensitiveInfoFiles.js', ['--initialize-missing']), { timeoutMs: 30000, signal: t.signal }), 0);
    assert.equal(await waitForChild(launch('db/postgres/initialize-application.js'), { timeoutMs: 120000, signal: t.signal }), 0);
    const { Pool } = require('pg');
    identityPool = new Pool({ connectionString: env.IDENTITY_DATABASE_URL, max: 2 });
    const users = require('../../server/database/postgres/identityRepository').createIdentityRepository(identityPool);
    const password = `${randomUUID()}Aa1!`, passwordHash = await require('bcryptjs').hash(password, 4);
    const platformUser = await users.createUser({ username: `policy-index-${randomUUID().slice(0, 8)}`,
      email: `${randomUUID()}@example.invalid`, passwordHash });
    const visible = await identityPool.query(`UPDATE workshop_platform.exercises
      SET is_visible=true,updated_at=clock_timestamp()
      WHERE workshop_key='secureshop_agent_security' AND catalog_active=true AND is_visible=false`);
    assert.equal(visible.rowCount, 1,
      'the disposable rendered fixture must explicitly publish the default-hidden SecureShop exercise');

    child = launch('server/index.js', [], {});
    await waitReady(child); assert.equal(proxyCalls.length, 0, 'flag-absent baseline must not probe renderer');
    await stop(child); child = null;

    child = launch('server/index.js', [], { SS_BOUND_PROMPT_POLICIES_ENABLED: 'true' });
    await waitReady(child);
    const login = await request('/api/auth/login', null, { username: platformUser.username, password });
    assert.equal(login.status, 200); const token = login.body.token;
    const launched = await request('/api/auth/secureshop-launch', token, {}); assert.equal(launched.status, 201);
    const launchHeader = { 'x-dvaia-secureshop-launch': launched.body.bearer };
    const persona = await request('/api/secureshop/v2/auth/login', token,
      { username: 'student_admin', password: 'student123' }, launchHeader);
    assert.equal(persona.status, 200); const personaToken = persona.body.token;
    const list = await request('/api/secureshop/admin/policies', personaToken, undefined, launchHeader);
    assert.equal(list.status, 200); assert.equal(list.body.version, '1'); assert.deepEqual(list.body.policies, []);
    assert.deepEqual(list.body.supported_targets, ['customer', 'merchant', 'admin']);
    assert.deepEqual(list.body.supported_task_targets, ['review-moderator', 'summarizer']);
    const previewId = randomUUID();
    const preview = await request('/api/secureshop/admin/policies/index_preview/render', personaToken, {
      markdown: 'Preview for {{ store_name }}.', injected_into: ['admin'], operationId: previewId,
      expectedVersion: list.body.version,
    }, launchHeader);
    assert.equal(preview.status, 200, JSON.stringify(preview.body)); assert.equal(preview.body.rendered, 'Preview for SecureShop.');
    const previewRead = await request(`/api/secureshop/admin/policies/operations/${previewId}`, personaToken, undefined, launchHeader);
    assert.equal(previewRead.status, 200); assert.equal(previewRead.body.receipt.renderResult.rendered, preview.body.rendered);
    const createId = randomUUID();
    const created = await request('/api/secureshop/admin/policies', personaToken, {
      name: 'index_policy', markdown: 'Owned policy for {{ store_name }}.', injected_into: ['admin'],
      operationId: createId, expectedVersion: list.body.version,
    }, launchHeader);
    assert.equal(created.status, 200, JSON.stringify(created.body)); assert.equal(created.body.rendered, 'Owned policy for SecureShop.');
    const operation = await request(`/api/secureshop/admin/policies/operations/${createId}`, personaToken, undefined, launchHeader);
    assert.equal(operation.status, 200); assert.equal(operation.body.receipt.operationId, createId);
    const after = await request('/api/secureshop/admin/policies', personaToken, undefined, launchHeader);
    assert.equal(after.status, 200); assert.equal(after.body.version, '2'); assert.equal(after.body.policies.length, 1);
    assert.equal(after.body.policies[0].name, 'index_policy');
    assert.equal(after.body.policies[0].markdown_source, 'Owned policy for {{ store_name }}.');
    assert.equal(after.body.policies[0].markdown_rendered, 'Owned policy for SecureShop.');
    assert.ok(proxyCalls.includes('GET /health')); assert.equal(proxyCalls.filter(value => value === 'POST /secureshop/policy-render').length, 2);
    const priorPort = process.env.PORT;
    try {
      process.env.PORT = String(port);
      const clientRoot = path.resolve('client');
      const { preview: startPreview } = await import(pathToFileURL(path.join(clientRoot, 'node_modules/vite/dist/node/index.js')));
      const previewServer = await startPreview({ root: clientRoot, configFile: path.join(clientRoot, 'vite.config.mjs'),
        configLoader: 'native', preview: { host: '127.0.0.1', port: frontendPort, strictPort: true } });
      vite = { httpServer: previewServer.httpServer,
        close: () => new Promise(resolve => previewServer.httpServer.close(resolve)) };
    } finally {
      if (priorPort === undefined) delete process.env.PORT; else process.env.PORT = priorPort;
    }
    const browser = await require('../fixtures/secureshopPromptPolicyTaskEnabledBrowser')
      .qualifyPromptPolicyTaskEnabledBrowser({ origin: `http://127.0.0.1:${vite.httpServer.address().port}`,
        user: platformUser, password, root, signal: t.signal,
        rendererCount: async () => proxyCalls.filter(value => value === 'POST /secureshop/policy-render').length });
    await vite.close(); vite = null; await assertPortClosed(frontendPort);
    await stop(child); child = null;

    fs.writeFileSync(path.join(root, 'policy-task-enabled-index-result.json'), JSON.stringify({
      ready: true, canonicalMigrationSha256: process.env.PG_SECURESHOP_POLICY_CANONICAL_SHA256,
      disabledBaselineRendererRequests: 0, rendererRequests: proxyCalls,
      preview: { operationId: previewId, rendered: preview.body.rendered },
      create: { operationId: createId, version: after.body.version, rendered: after.body.policies[0].markdown_rendered },
      browser,
      scope: 'actual frozen server/index retained getter, full16 stores, real packaged renderer and production opaque Policies page; no model/Judge/credit',
    }, null, 2), { mode: 0o600, flag: 'wx' });
  } finally {
    if (child) child.kill('SIGTERM');
    await vite?.close();
    await new Promise(resolve => proxy.close(resolve));
    const cleaned = await Promise.allSettled([owned.cleanup(), identityPool?.end()]);
    assert.ok(cleaned.every(row => row.status === 'fulfilled'), 'Owned enabled-index cleanup must complete');
  }
});
