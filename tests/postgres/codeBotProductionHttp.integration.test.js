'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const enabled = process.env.RUN_CODEBOT_HTTP_WIRING === '1'
  && process.env.CODEBOT_HTTP_ISOLATED === '1'
  && process.env.PG_TEST_DISPOSABLE === 'yes';

test('mounted CodeBot HTTP wiring enforces replay, readiness, session and reset boundaries', {
  skip: !enabled, timeout: 180000,
}, async t => {
  assert.equal(process.env.CODEBOT_WIRING_EVIDENCE_SCOPE, 'deterministic_http_only');
  assert.equal(process.env.CODEBOT_WIRING_ATTESTED_ISOLATION, 'bwrap-codebot-v1');

  const Module = require('node:module');
  const originalLoad = Module._load;
  Module._load = function guardedLoad(name, ...args) {
    if (['sqlite3', 'better-sqlite3'].includes(name) || /authDb$/.test(name)) throw Error('Working SQLite import forbidden');
    return originalLoad.call(this, name, ...args);
  };
  const http = require('node:http');
  let runnerReady = false;
  let resetCalls = 0;
  const runner = http.createServer((request, response) => {
    response.setHeader('content-type', 'application/json');
    if (request.method === 'GET' && request.url === '/health') return response.end(JSON.stringify({
      status: 'ok', bwrap: true, codebotAvailable: runnerReady,
      codebotIsolation: runnerReady ? 'bwrap-codebot-v1' : 'unavailable',
    }));
    if (request.method === 'POST' && request.url === '/codebot/reset' && runnerReady) {
      resetCalls += 1; return response.end(JSON.stringify({ ok: true }));
    }
    response.statusCode = 503; return response.end(JSON.stringify({ ok: false }));
  });
  await new Promise(resolve => runner.listen(0, '127.0.0.1', resolve));

  const { Pool } = require('pg');
  const adminUrl = new URL(process.env.PG_LIVE_ADMIN_URL);
  assert.ok(['127.0.0.1', 'localhost', '[::1]'].includes(adminUrl.hostname));
  assert.equal(adminUrl.pathname, '/postgres');
  const admin = new Pool({ connectionString: adminUrl.href });
  const name = `dvaia_test_codebot_http_${process.pid}`;
  const supplyName = `${name}_supply`;
  const pools = [];
  let server;
  try {
    await admin.query(`CREATE DATABASE ${name} OWNER dvaia_identity_migration`);
    await admin.query(`REVOKE CONNECT ON DATABASE ${name} FROM PUBLIC`);
    await admin.query(`GRANT CONNECT ON DATABASE ${name} TO dvaia_identity_runtime`);
    const pool = (database, role, max = 8) => {
      const url = new URL(adminUrl); url.pathname = `/${database}`; url.username = role; url.password = '';
      const value = new Pool({ connectionString: url.href, max }); pools.push(value); return value;
    };
    const runtime = pool(name, 'dvaia_identity_runtime');
    const migration = pool(name, 'dvaia_identity_migration');
    process.env.IDENTITY_DATABASE_URL = runtime.options.connectionString;
    process.env.IDENTITY_MIGRATION_DATABASE_URL = migration.options.connectionString;
    const identityApi = require('../../server/database/postgres/identityRepository');
    const applied = await identityApi.initializeIdentityRepository(runtime, migration);
    assert.deepEqual(applied,fs.readdirSync(path.join(__dirname,'../../db/postgres/identity-migrations')).filter(f=>f.endsWith('.sql')).sort());
    assert.deepEqual(await identityApi.initializeIdentityRepository(runtime, migration), []);
    await require('../../server/database/postgres/workshopPlatformSeed').seedWorkshopPlatform(migration);

    await admin.query(`CREATE DATABASE ${supplyName} OWNER dvaia_supply_chain_migration`);
    await admin.query(`REVOKE CONNECT ON DATABASE ${supplyName} FROM PUBLIC`);
    await admin.query(`GRANT CONNECT ON DATABASE ${supplyName} TO dvaia_supply_chain_runtime`);
    const supplyRuntime = pool(supplyName, 'dvaia_supply_chain_runtime', 5);
    const supplyMigration = pool(supplyName, 'dvaia_supply_chain_migration', 5);
    process.env.SUPPLY_CHAIN_WORKSHOP_DATABASE_URL = supplyRuntime.options.connectionString;
    process.env.SUPPLY_CHAIN_WORKSHOP_MIGRATION_DATABASE_URL = supplyMigration.options.connectionString;
    await require('../../server/database/postgres/supplyChainWorkshopDb')
      .createSupplyChainWorkshopDb(supplyRuntime).initialize(supplyMigration);

    const identity = identityApi.createIdentityRepository(runtime);
    const bcrypt = require('bcryptjs');
    const makeUser = async suffix => identity.createUser({ username: `codebot-http-${suffix}`,
      email: `codebot-http-${suffix}@example.invalid`, passwordHash: await bcrypt.hash('fixture', 4) });
    const owner = await makeUser('owner');
    const revoked = await makeUser('revoked');
    await runtime.query(`INSERT INTO workshop_platform.user_modes(user_id,workshop_key,mode)
      VALUES($1,'supply_chain_rce','vulnerable'),($2,'supply_chain_rce','vulnerable')`, [owner.id, revoked.id]);

    const progress = require('../../server/database/postgres/workshopProgressRepository')
      .createWorkshopProgressRepository(runtime);
    const config = require('../../server/database/postgres/workshopConfigRepository')
      .createWorkshopConfigRepository(runtime);
    const jwtSecret = crypto.randomBytes(48).toString('base64url');
    process.env.JWT_SECRET = jwtSecret;
    process.env.PLATFORM_DATABASE_ENGINE = 'postgres';
    process.env.CODEBOT_OWNED_EXECUTION_ENABLED = 'true';
    process.env.CODEBOT_SANDBOX_RUNNER_URL = `http://127.0.0.1:${runner.address().port}`;
    const adapter = require('../../server/services/postgresIdentityAdapter')
      .createPostgresIdentityAdapter({ repository: identity, progress, config, jwtSecret });
    const makeSession = async user => adapter.createSession(await identity.findCredentialById(user.id),
      { get: () => null, ip: '127.0.0.1' });
    const ownerSession = await makeSession(owner);
    const revokedSession = await makeSession(revoked);

    const aiService = require('../../server/services/multiProviderAIService');
    let actorCalls = 0;
    aiService.chatWithTools = async () => {
      actorCalls += 1;
      return { content: 'Deterministic HTTP wiring response.', provider: 'scripted-wiring', model: 'none' };
    };
    const activation = require('../../server/services/supplyChain/codeBotProduction').getCodeBotProductionActivation();
    const unavailableStartup = await activation.initialize();
    assert.deepEqual({ enabled: unavailableStartup.enabled, ready: unavailableStartup.ready,
      journalReady: unavailableStartup.journalReady, runnerReady: unavailableStartup.runnerReady },
    { enabled: true, ready: false, journalReady: true, runnerReady: false },
    'optional runner outage leaves application initialization alive but CodeBot unready');
    const app = require('express')(); app.use(require('express').json());
    app.use(require('../../server/routes/supplyChainWorkshop'));
    server = await new Promise(resolve => {
      const started = app.listen(0, '127.0.0.1', () => resolve(started));
    });
    const base = `http://127.0.0.1:${server.address().port}`;
    const headersFor = (session, key) => ({ 'content-type': 'application/json',
      authorization: `Bearer ${session.token}`, ...(key ? { 'idempotency-key': key } : {}) });
    const request = async ({ path = '/chat', session = ownerSession, key, message = 'wiring request' }) => {
      const response = await fetch(`${base}${path}`, { method: 'POST', headers: headersFor(session, key),
        body: JSON.stringify(path === '/chat' ? { userMessage: message, conversationHistory: [] } : {}) });
      return { status: response.status, body: await response.json() };
    };
    const ownerKey = JSON.stringify(['CodeBot', String(owner.id)]);
    const counts = async () => (await runtime.query(`SELECT
      (SELECT count(*)::int FROM graph_runtime.codebot_requests WHERE owner_key=$1) AS requests,
      (SELECT count(*)::int FROM graph_runtime.effects WHERE owner_key=$1) AS effects,
      (SELECT count(*)::int FROM workshop_platform.objective_judgments WHERE user_id=$2) AS judgments,
      (SELECT count(*)::int FROM workshop_platform.completions WHERE user_id=$2 AND workshop_key='supply_chain_rce') AS completions,
      (SELECT generation::text FROM graph_runtime.owners WHERE owner_key=$1) AS generation`, [ownerKey, owner.id])).rows[0];

    const rawReplayKey = 'codebot-http-replay-key-0001';
    const replayInput = { userMessage: 'stored wiring request', conversationHistory: [] };
    const { requestKey } = require('../../server/services/supplyChain/codeBotProduction');
    const { requestFingerprint } = require('../../server/agent-runtime/codeBotRequestJournal');
    const replayKey = requestKey(rawReplayKey, ownerSession.internalSessionId);
    const oldRun = crypto.randomUUID();
    const storedResponse = { success: true, response: 'durable stored response', toolCalls: [],
      newlyCompletedObjectives: [], judgments: [], projectionPending: [], run: { runId: oldRun }, mode: 'vulnerable' };
    await runtime.query(`INSERT INTO graph_runtime.owners(owner_key,generation) VALUES($1,0)`, [ownerKey]);
    await runtime.query(`INSERT INTO graph_runtime.runs(run_id,owner_key,generation,status,finished_at)
      VALUES($1,$2,0,'completed',clock_timestamp())`, [oldRun, ownerKey]);
    await runtime.query(`INSERT INTO graph_runtime.codebot_requests(owner_key,request_key_sha256,
      request_fingerprint_sha256,user_id,platform_session_id,generation,run_id,status,response_json)
      VALUES($1,$2,$3,$4,$5,0,$6,'completed',$7::jsonb)`, [ownerKey, replayKey,
      requestFingerprint(replayInput), owner.id, ownerSession.internalSessionId, oldRun, JSON.stringify(storedResponse)]);

    assert.equal((await request({ key: undefined })).status, 400, 'configured PostgreSQL rejects a missing key');
    const beforeReplay = await counts();
    const replay = await request({ key: rawReplayKey, message: replayInput.userMessage });
    assert.equal(replay.status, 200); assert.deepEqual(replay.body, storedResponse);
    assert.equal(actorCalls, 0, 'completed replay bypasses unavailable runner and scripted actor');
    const afterReplay = await counts();
    assert.equal(afterReplay.requests, beforeReplay.requests);
    assert.equal(afterReplay.effects, beforeReplay.effects);
    assert.equal(afterReplay.judgments, beforeReplay.judgments);

    const unavailableBefore = await counts();
    const unavailable = await request({ key: 'codebot-http-new-down-0001', message: 'new unavailable request' });
    assert.equal(unavailable.status, 503); assert.match(unavailable.body.error, /No model or tool was run/);
    assert.deepEqual({ ...(await counts()), generation: undefined }, { ...unavailableBefore, generation: undefined },
      'runner outage creates no request, effect, judgment, or completion');
    assert.equal(actorCalls, 0);

    const revokedOwnerKey = JSON.stringify(['CodeBot', String(revoked.id)]);
    const revokedRawKey = 'codebot-http-revoked-key-0001';
    const revokedKey = requestKey(revokedRawKey, revokedSession.internalSessionId);
    const revokedRun = crypto.randomUUID();
    await runtime.query(`INSERT INTO graph_runtime.owners(owner_key,generation) VALUES($1,0)`, [revokedOwnerKey]);
    await runtime.query(`INSERT INTO graph_runtime.runs(run_id,owner_key,generation,status,finished_at)
      VALUES($1,$2,0,'completed',clock_timestamp())`, [revokedRun, revokedOwnerKey]);
    await runtime.query(`INSERT INTO graph_runtime.codebot_requests(owner_key,request_key_sha256,
      request_fingerprint_sha256,user_id,platform_session_id,generation,run_id,status,response_json)
      VALUES($1,$2,$3,$4,$5,0,$6,'completed',$7::jsonb)`, [revokedOwnerKey, revokedKey,
      requestFingerprint(replayInput), revoked.id, revokedSession.internalSessionId, revokedRun, JSON.stringify(storedResponse)]);
    await identity.revokeSession(revokedSession.token, revoked.id, 'wiring qualification');
    assert.equal((await request({ session: revokedSession, key: revokedRawKey, message: replayInput.userMessage })).status, 401);
    assert.equal(actorCalls, 0, 'revoked session receives no stored response and runs no actor');

    const generationBeforeReset = (await counts()).generation;
    assert.equal((await request({ path: '/progress/reset' })).status, 503, 'reset fails before mutation while runner is down');
    assert.equal((await counts()).generation, generationBeforeReset);
    runnerReady = true;
    const readyStartup = await activation.initialize();
    assert.deepEqual({ enabled: readyStartup.enabled, ready: readyStartup.ready,
      journalReady: readyStartup.journalReady, runnerReady: readyStartup.runnerReady,
      isolation: readyStartup.isolation },
    { enabled: true, ready: true, journalReady: true, runnerReady: true, isolation: 'bwrap-codebot-v1' });
    const created = await request({ key: 'codebot-http-scripted-key-0001', message: 'neutral deterministic request' });
    assert.equal(created.status, 200); assert.equal(created.body.response, 'Deterministic HTTP wiring response.');
    assert.equal(actorCalls, 1);
    const afterCreated = await counts();
    assert.equal(afterCreated.requests, unavailableBefore.requests + 1);
    assert.equal(afterCreated.effects, 0); assert.equal(afterCreated.judgments, 0); assert.equal(afterCreated.completions, 0);
    const reset = await request({ path: '/progress/reset' });
    assert.equal(reset.status, 200); assert.equal(resetCalls, 1);
    assert.equal(Number((await counts()).generation), Number(generationBeforeReset) + 1);
    runnerReady = false;
    const stale = await request({ key: rawReplayKey, message: replayInput.userMessage });
    assert.equal(stale.status, 409); assert.match(stale.body.error, /earlier CodeBot generation/);
    assert.equal(actorCalls, 1);

    t.diagnostic(JSON.stringify({ scope: 'deterministic_http_only', actualModelCalls: 0,
      effectQualification: false, runnerIsolationAttestation: process.env.CODEBOT_WIRING_ATTESTED_ISOLATION,
      replayDuringRunnerOutage: true, newRequestDuringRunnerOutage: 503,
      revokedReplayStatus: 401, resetUnavailableStatus: 503, resetReadyStatus: 200,
      finalCounts: await counts() }));
  } finally {
    if (server) await new Promise(resolve => server.close(resolve));
    await new Promise(resolve => runner.close(resolve));
    await require('../../server/database/postgres').closePostgresPools().catch(() => {});
    await Promise.allSettled(pools.map(pool => pool.end()));
    await admin.query(`DROP DATABASE IF EXISTS ${supplyName}`).catch(() => {});
    await admin.query(`DROP DATABASE IF EXISTS ${name}`).catch(() => {});
    await admin.end(); Module._load = originalLoad;
  }
});
