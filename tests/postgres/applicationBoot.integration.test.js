'use strict';

const assert = require('node:assert/strict');
const { spawn } = require('node:child_process');
const fs = require('node:fs/promises');
const net = require('node:net');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const REPO = path.resolve(__dirname, '../..');
const DATABASES = Object.freeze({
  IDENTITY: 'IDENTITY',
  SQL_WORKSHOP: 'ARIA',
  NOSQL_WORKSHOP: 'NOVA',
  XSS_WORKSHOP: 'XSS',
  MCP_WORKSHOP: 'MCP',
  CSRF_WORKSHOP: 'CSRF',
  SUPPLY_CHAIN_WORKSHOP: 'SUPPLY_CHAIN',
  FINFLOW_WORKSHOP: 'FINFLOW',
  EXCESSIVE_AGENCY: 'EXCESSIVE_AGENCY',
  CTF: 'CTF',
  LEGACY_CHALLENGE: 'LEGACY_CHALLENGE',
  SENSITIVE_LOOKUP: 'SENSITIVE_LOOKUP',
  SECURESHOP: 'SECURESHOP',
  SECURESHOP_AGENTS: 'SECURESHOP_AGENTS',
  SESSION_DISCLOSURE: 'SESSION_DISCLOSURE',
  SECURESHOP_REVIEW: 'SECURESHOP_REVIEW',
});
const REQUIRED_TEST_URLS = Object.values(DATABASES).flatMap(name => [
  `PG_${name}_TEST_RUNTIME_URL`,
  `PG_${name}_TEST_MIGRATION_URL`,
]);
const enabled = process.env.PG_TEST_DISPOSABLE === 'yes'
  && REQUIRED_TEST_URLS.every(name => process.env[name]);

function assertDisposableUrl(value, name) {
  const url = new URL(value);
  assert.ok(['127.0.0.1', 'localhost'].includes(url.hostname), `${name} must be loopback-only`);
  assert.match(url.pathname, /^\/dvaia_test_[a-z0-9_]+$/, `${name} must name a disposable test database`);
}

async function availablePort() {
  const server = net.createServer();
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  const port = server.address().port;
  await new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
  return port;
}

function shouldCopy(source) {
  const relative = path.relative(REPO, source);
  if (!relative) return true;
  const unix = relative.split(path.sep).join('/');
  const parts = unix.split('/');
  if (parts.includes('.git') || parts.includes('node_modules') || parts.includes('coverage')) return false;
  if (unix === 'client/build' || unix.startsWith('client/build/')) return false;
  if (unix === 'server/logs' || unix.startsWith('server/logs/')) return false;
  if (unix === 'server/uploads' || unix.startsWith('server/uploads/')) return false;
  if (unix === 'server/database/vector-indexes' || unix.startsWith('server/database/vector-indexes/')) return false;
  if (/(^|\/)\.env(?:\.|$)/.test(unix)) return false;
  if (/\.(?:db|db-wal|db-shm|sqlite|sqlite3)(?:$|-)/i.test(path.basename(unix))) return false;
  return true;
}

async function copyApplication() {
  const parent = await fs.mkdtemp(path.join(os.tmpdir(), 'dvaia-pg-boot-'));
  const workspace = path.join(parent, 'workspace');
  await fs.cp(REPO, workspace, { recursive: true, filter: shouldCopy });
  await fs.symlink(path.join(REPO, 'node_modules'), path.join(workspace, 'node_modules'), 'dir');
  return { parent, workspace };
}

async function waitForJson(url, predicate, child, output, timeoutMs = 60000) {
  const deadline = Date.now() + timeoutMs;
  let lastError;
  while (Date.now() < deadline) {
    if (child.exitCode !== null || child.signalCode !== null) {
      throw new Error(`application exited before ${url} became ready\n${output()}`);
    }
    try {
      const response = await fetch(url, { signal: AbortSignal.timeout(1500) });
      const body = await response.json();
      if (response.ok && predicate(body)) return body;
      lastError = new Error(`HTTP ${response.status}: ${JSON.stringify(body)}`);
    } catch (error) {
      lastError = error;
    }
    await new Promise(resolve => setTimeout(resolve, 200));
  }
  throw new Error(`timed out waiting for ${url}: ${lastError?.message || 'no response'}\n${output()}`);
}

function waitForExit(child, timeoutMs) {
  if (child.exitCode !== null || child.signalCode !== null) {
    return Promise.resolve({ code: child.exitCode, signal: child.signalCode });
  }
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('application did not exit within the shutdown deadline')), timeoutMs);
    child.once('exit', (code, signal) => {
      clearTimeout(timer);
      resolve({ code, signal });
    });
  });
}

function stopProcessTree(child, signal = 'SIGKILL') {
  if (!child || child.exitCode !== null || child.signalCode !== null) return;
  try {
    if (process.platform !== 'win32') process.kill(-child.pid, signal);
    else child.kill(signal);
  } catch {}
}

for (const launcher of [false,true]) test(launcher ? 'owned launcher starts frontend and stops only its application process group' : 'full PostgreSQL application boots without loading legacy database drivers and drains its agent host', {
  skip: !enabled,
  timeout: 120000,
}, async () => {
  REQUIRED_TEST_URLS.forEach(name => assertDisposableUrl(process.env[name], name));
  const { parent, workspace } = await copyApplication();
  const appPort = await availablePort();
  const clientPort = await availablePort();
  const temporaryHome = path.join(parent, 'home');
  await fs.mkdir(temporaryHome);
  if(launcher) await fs.symlink(path.join(REPO, 'client/node_modules'),path.join(workspace, 'client/node_modules'),'dir');
  const agentPort = await availablePort();
  const forbiddenLog = path.join(parent, 'forbidden-modules.jsonl');
  const guard = path.join(parent, 'forbid-legacy-databases.cjs');
  await fs.writeFile(guard, `'use strict';\n` +
    `const fs=require('node:fs');const Module=require('node:module');const load=Module._load;\n` +
    `const blocked=['sqlite3','better-sqlite3','mysql2'];\n` +
    `Module._load=function(request,parent,isMain){const name=String(request);if(blocked.some(x=>name===x||name.startsWith(x+'/'))){const record={pid:process.pid,request:name,parent:parent&&parent.filename};try{fs.appendFileSync(process.env.DVAIA_FORBIDDEN_MODULE_LOG,JSON.stringify(record)+'\\n')}catch{}const error=new Error('FORBIDDEN_LEGACY_DATABASE_MODULE '+name+' from '+(record.parent||'<unknown>'));error.code='FORBIDDEN_LEGACY_DATABASE_MODULE';throw error}return load.apply(this,arguments)};\n`);

  const databaseEnv = {};
  for (const [runtimePrefix, testPrefix] of Object.entries(DATABASES)) {
    databaseEnv[`${runtimePrefix}_DATABASE_URL`] = process.env[`PG_${testPrefix}_TEST_RUNTIME_URL`];
    databaseEnv[`${runtimePrefix}_MIGRATION_DATABASE_URL`] = process.env[`PG_${testPrefix}_TEST_MIGRATION_URL`];
  }
  const inheritedEnv = {};
  for (const name of [
    'PATH', 'HOME', 'USER', 'LOGNAME', 'TMPDIR', 'TMP', 'TEMP', 'LANG', 'LC_ALL', 'TZ',
    'SystemRoot', 'ComSpec', 'PATHEXT', 'NODE_EXTRA_CA_CERTS', 'SSL_CERT_FILE', 'SSL_CERT_DIR',
  ]) {
    if (process.env[name] !== undefined) inheritedEnv[name] = process.env[name];
  }
  const env = {
    ...inheritedEnv,
    ...databaseEnv,
    HOME: temporaryHome,
    DVAIA_CLIENT_PORT: String(clientPort),
    PLATFORM_DATABASE_ENGINE: 'postgres',
    WORKSHOP_DATABASE_ENGINE: 'postgres',
    PG_TEST_DISPOSABLE: 'yes',
    PORT: String(appPort),
    SS_AGENT_HOST_PORT: String(agentPort),
    SS_ENABLE: 'true',
    SS_ENABLE_REAL_MCP_SPAWN: 'false',
    MCP_SIDECARS_AUTOSTART: 'false',
    AI_PROVIDER: 'mock',
    OLLAMA_BASE_URL: 'http://127.0.0.1:1',
    JWT_SECRET: 'disposable-postgres-boot-test-secret-at-least-32-bytes',
    EVENT_GATE_ENABLED: 'false',
    NODE_ENV: 'test',
    HF_HUB_OFFLINE: '1',
    TRANSFORMERS_OFFLINE: '1',
    HF_HUB_DISABLE_TELEMETRY: '1',
    HF_HOME: path.join(parent, 'hf-cache'),
    AWS_EC2_METADATA_DISABLED: 'true',
    LANGCHAIN_TRACING_V2: 'false',
    LANGSMITH_TRACING: 'false',
    OTEL_SDK_DISABLED: 'true',
    NO_PROXY: '127.0.0.1,localhost',
    DVAIA_FORBIDDEN_MODULE_LOG: forbiddenLog,
    NODE_OPTIONS: `--require=${guard}`,
  };
  let stdout = '';
  let stderr = '';
  const append = (current, chunk) => (current + chunk).slice(-512 * 1024);
  const child = spawn(process.execPath, [launcher ? 'scripts/start-application.js' : 'server/index.js'], {
    cwd: workspace,
    env,
    detached: process.platform !== 'win32',
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  child.stdout.on('data', chunk => { stdout = append(stdout, chunk.toString()); });
  child.stderr.on('data', chunk => { stderr = append(stderr, chunk.toString()); });
  const output = () => `stdout:\n${stdout}\nstderr:\n${stderr}`;

  const sentinel=require('node:http').createServer((req,res)=>res.end('independent'));
  await new Promise(resolve=>sentinel.listen(0,'127.0.0.1',resolve));
  const sentinelUrl=`http://127.0.0.1:${sentinel.address().port}`;
  try {
    const ping = await waitForJson(`http://127.0.0.1:${appPort}/api/monitoring/ping`, body => body.status === 'ok', child, output);
    assert.equal(ping.status, 'ok');
    const host = await waitForJson(`http://127.0.0.1:${agentPort}/health`, body => body.ok === true && Array.isArray(body.agents), child, output);
    assert.equal(host.agents.length, 17);
    const products = await waitForJson(`http://127.0.0.1:${appPort}/api/secureshop/products?limit=1`, body => Array.isArray(body.products), child, output);
    assert.equal(products.products.length, 1);
    assert.match(stdout, /\[secureshop-v2\] booted; agent-host on port/);

    if(launcher){
      await waitForJson(`http://127.0.0.1:${clientPort}/api/monitoring/ping`,body=>body.status==='ok',child,output);
      assert.match(await (await fetch(`http://127.0.0.1:${clientPort}`)).text(),/<html/i);
      const canonical=await fs.realpath(workspace);
      const hash=require('node:crypto').createHash('sha256').update(canonical).digest('hex').slice(0,12);
      await require('../../scripts/launcher-control').requestStop({workspace,stateFile:path.join(temporaryHome,'.dvaia',hash,'launcher.json')});
    }else child.kill('SIGTERM');
    const exited = await waitForExit(child, 15000);
    assert.equal(exited.code, 0, output());
    assert.equal(await (await fetch(sentinelUrl)).text(),'independent');
    if(launcher)await assert.rejects(fetch(`http://127.0.0.1:${clientPort}`,{signal:AbortSignal.timeout(1000)}));
    await assert.rejects(fetch(`http://127.0.0.1:${appPort}/api/monitoring/ping`,{signal:AbortSignal.timeout(1000)}));
    await assert.rejects(fetch(`http://127.0.0.1:${agentPort}/health`, { signal: AbortSignal.timeout(1000) }));

    const attempts = await fs.readFile(forbiddenLog, 'utf8').catch(error => error.code === 'ENOENT' ? '' : Promise.reject(error));
    assert.equal(attempts, '', `legacy database modules were requested:\n${attempts}\n${output()}`);
  } finally {
    await new Promise(resolve=>sentinel.close(resolve));
    stopProcessTree(child);
    await fs.rm(parent, { recursive: true, force: true });
  }
});
