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
  assert.match(url.pathname, /^\/owasp_ai_goat_test_[a-z0-9_]+$/, `${name} must name a disposable test database`);
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
  const parent = await fs.mkdtemp(path.join(os.tmpdir(), 'owasp-ai-goat-pg-boot-'));
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

for (const launcher of [false]) test(launcher ? 'owned launcher starts frontend and stops only its application process group' : '200 native attendees exercise full application auth, storage and reset with mock inference', {
  skip: !enabled,
  timeout: 120000,
}, async (t) => {
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
    `Module._load=function(request,parent,isMain){const name=String(request);if(blocked.some(x=>name===x||name.startsWith(x+'/'))){const record={pid:process.pid,request:name,parent:parent&&parent.filename};try{fs.appendFileSync(process.env.OWASP_AI_GOAT_FORBIDDEN_MODULE_LOG,JSON.stringify(record)+'\\n')}catch{}const error=new Error('FORBIDDEN_LEGACY_DATABASE_MODULE '+name+' from '+(record.parent||'<unknown>'));error.code='FORBIDDEN_LEGACY_DATABASE_MODULE';throw error}return load.apply(this,arguments)};\n`);

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
    OWASP_AI_GOAT_CLIENT_PORT: String(clientPort),
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
    OWASP_AI_GOAT_FORBIDDEN_MODULE_LOG: forbiddenLog,
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
    await runNativeLoad({base:`http://127.0.0.1:${appPort}`,t});

    if(launcher){
      await waitForJson(`http://127.0.0.1:${clientPort}/api/monitoring/ping`,body=>body.status==='ok',child,output);
      assert.match(await (await fetch(`http://127.0.0.1:${clientPort}`)).text(),/<html/i);
      const canonical=await fs.realpath(workspace);
      const hash=require('node:crypto').createHash('sha256').update(canonical).digest('hex').slice(0,12);
      await require('../../scripts/launcher-control').requestStop({workspace,stateFile:path.join(temporaryHome,'.owasp-ai-goat',hash,'launcher.json')});
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

async function runNativeLoad({base,t}){
 const {Pool}=require('pg'),jwt=require('jsonwebtoken'),crypto=require('node:crypto');
 const identity=new Pool({connectionString:process.env.PG_IDENTITY_TEST_RUNTIME_URL,max:4});
 const aria=new Pool({connectionString:process.env.PG_ARIA_TEST_RUNTIME_URL,max:2});
 try{
 const repo=require('../../server/database/postgres/identityRepository').createIdentityRepository(identity);
 const hash=await require('bcryptjs').hash('fixture-only',4),attendees=[];
 for(let i=0;i<200;i++){
  const user=await repo.createUser({username:`native-load-${process.pid}-${i}`,email:`native-load-${process.pid}-${i}@example.invalid`,passwordHash:hash});
  const token=jwt.sign({userId:user.id,username:user.username,role:'student',emailVerified:1},'disposable-postgres-boot-test-secret-at-least-32-bytes',{expiresIn:3600,jwtid:crypto.randomUUID()});
  await repo.createSession({userId:user.id,token,expiresAt:new Date(Date.now()+3600000),expectedPasswordHash:hash,deviceInfo:{}});attendees.push({id:user.id,token});
 }
 const ownerIds=attendees.map(user=>user.id),ownerKeys=ownerIds.map(String),runOwnerKeys=ownerKeys.map(id=>JSON.stringify(['ARIA',id]));
 const request=async(user,route,body)=>{const start=performance.now();const response=await fetch(base+route,{method:'POST',headers:{authorization:`Bearer ${user.token}`,'content-type':'application/json'},body:JSON.stringify(body),signal:AbortSignal.timeout(90000)});return{status:response.status,ms:performance.now()-start,body:await response.json(),id:user.id};};
 const spoofBefore=(await aria.query("SELECT count(*)::int n FROM aria.chat_history WHERE user_id='999999'")).rows[0].n;
 const start=performance.now();const readiness=Promise.all([fetch(base+'/api/monitoring/ping'),identity.query('SELECT 1')]);const results=await Promise.all(attendees.map(user=>request(user,'/api/workshop/sql/chat',{userMessage:`search products native-attendee-${user.id}`,userId:999999})));
 assert.equal((await readiness)[0].status,200);
 const distribution=Object.fromEntries([...new Set(results.map(r=>r.status))].map(status=>[status,results.filter(r=>r.status===status).length]));
 const successful=results.filter(r=>r.status===200);assert.ok(successful.length>0,JSON.stringify(distribution));assert.ok(results.every(r=>[200,429,503].includes(r.status)),JSON.stringify(distribution));
 for(const result of successful){const rows=(await aria.query('SELECT message_type,message FROM aria.chat_history WHERE user_id=$1 ORDER BY id',[String(result.id)])).rows;assert.equal(rows.filter(r=>r.message_type==='user').length,1);assert.equal(rows.find(r=>r.message_type==='user').message,`search products native-attendee-${result.id}`);}
 assert.equal((await aria.query("SELECT count(*)::int n FROM aria.chat_history WHERE user_id='999999'")).rows[0].n,spoofBefore);
 const gradingUsers=attendees.slice(0,10);
 for(const user of gradingUsers)await identity.query("INSERT INTO workshop_platform.user_modes(user_id,workshop_key,mode) VALUES($1,'sql_injection_workshop','vuln') ON CONFLICT(user_id,workshop_key) DO UPDATE SET mode='vuln',updated_at=clock_timestamp()",[user.id]);
 const gradingResults=await Promise.all(gradingUsers.map(user=>request(user,'/api/workshop/sql/chat',{userMessage:"%'"})));
 assert.ok(gradingResults.every(r=>r.status===200),JSON.stringify(gradingResults.map(r=>({status:r.status,body:r.body}))));
 const receiptBeforeReset=(await identity.query('SELECT verdict,count(*)::int n FROM workshop_platform.objective_judgments WHERE user_id=ANY($1::int[]) GROUP BY verdict',[ownerIds])).rows;
 assert.ok(receiptBeforeReset.reduce((n,r)=>n+r.n,0)>=10,JSON.stringify(receiptBeforeReset));
 assert.equal((await identity.query('SELECT count(*)::int n FROM workshop_platform.completions WHERE user_id=ANY($1::int[])',[ownerIds])).rows[0].n,0,'mock judge cannot award progress');
 const resetIds=new Set(successful.slice(0,10).map(r=>r.id));const resetResults=[];for(const user of attendees.filter(u=>resetIds.has(u.id)))resetResults.push(await request(user,'/api/workshop/sql/reset',{}));assert.ok(resetResults.every(r=>r.status===200),JSON.stringify(resetResults.map(r=>r.status)));
 for(const id of resetIds)assert.equal((await aria.query('SELECT count(*)::int n FROM aria.chat_history WHERE user_id=$1',[String(id)])).rows[0].n,0);
 assert.equal((await fetch(base+'/api/monitoring/ping')).status,200);
 assert.equal((await aria.query('SELECT count(*)::int n FROM aria.chat_history WHERE user_id=ANY($1::text[])',[ownerKeys])).rows[0].n,380);
 assert.equal((await identity.query("SELECT count(*)::int n FROM pg_locks l WHERE locktype='advisory' AND database=(SELECT oid FROM pg_database WHERE datname=current_database()) AND EXISTS (SELECT 1 FROM graph_runtime.owners o WHERE o.owner_key=ANY($1::text[]) AND l.classid::bigint=((hashtextextended(o.owner_key,0)>>32)&4294967295) AND l.objid::bigint=(hashtextextended(o.owner_key,0)&4294967295))",[runOwnerKeys])).rows[0].n,0,'all owner leases released');
 const receiptCounts=(await identity.query('SELECT verdict,count(*)::int n FROM workshop_platform.objective_judgments WHERE user_id=ANY($1::int[]) GROUP BY verdict',[ownerIds])).rows;
 const runCounts=(await identity.query("SELECT status,count(*)::int n FROM graph_runtime.runs WHERE owner_key=ANY($1::text[]) GROUP BY status",[runOwnerKeys])).rows;
 const latency=results.map(r=>r.ms).sort((a,b)=>a-b);
 t.diagnostic(JSON.stringify({attendees:200,model:'explicit mock; no live inference',storage:'native PostgreSQL16 isolated databases',distribution,p50:Math.round(latency[99]),p95:Math.round(latency[189]),totalMs:Math.round(performance.now()-start),receiptCounts,receiptBeforeReset,runCounts,resets:resetResults.length,rateLimitConfig:await repo.getConfig('enable_rate_limiting')}));
 }finally{await identity.end();await aria.end();}
}
