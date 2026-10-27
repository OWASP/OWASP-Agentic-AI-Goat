'use strict';
// V14 original customer path. This is a separately gated, disposable native
// diagnostic, not a Fixed implementation or canonical challenge credit.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const net = require('node:net');
const { randomUUID } = require('node:crypto');
const fixture = require('../fixtures/secureshopDirectInjectionActual');

const ROOT = path.resolve(__dirname, '../..');
const TITLE = 'V14 original customer direct injection deletes exactly one foreign cart item under disposable native admission';
const SCENARIO = fixture.OWNERSHIP_EXPLANATION_SCENARIO;
const INPUT_CANDIDATE = fixture.CATALOG_PAIR_CANDIDATE;
const PREFIX = 'PG_SECURESHOP_DIRECT_';
const ENABLED = process.env.SECURESHOP_DIRECT_NATIVE === '1'
  && process.env.PG_TEST_DISPOSABLE === 'yes' && process.env.LIVE_OLLAMA_TEST === '1';

function admittedPaths(env = process.env) {
  const root = fixture.admitQualificationRunRoot(env.PG_TEST_ROOT, ROOT);
  assert.equal(env.SECURESHOP_DIRECT_EVIDENCE_PATH,
    path.join(root, 'direct-injection-evidence.json'), 'Evidence path is not the owned run file');
  const wire = path.join(root, 'direct-injection-wire.json');
  for (const file of [wire, env.SECURESHOP_DIRECT_EVIDENCE_PATH]) {
    assert.throws(() => fs.lstatSync(file), error => error?.code === 'ENOENT',
      'Native evidence files must be newly and exclusively created');
  }
  return { root, evidence: env.SECURESHOP_DIRECT_EVIDENCE_PATH, wire };
}

function disposableUrls(env = process.env) {
  const admission = fixture.admitDisposableEnvironment(env);
  return admission.urls;
}

async function freePort() {
  const server = net.createServer();
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
  const port = server.address().port;
  await new Promise(resolve => server.close(resolve));
  return port;
}

async function assertClosedLoopback(url) {
  const endpoint = new URL(url);
  assert.equal(endpoint.hostname, '127.0.0.1');
  await new Promise((resolve, reject) => {
    const socket = net.createConnection({ host: '127.0.0.1', port: Number(endpoint.port) });
    socket.setTimeout(1500, () => { socket.destroy(); reject(new Error('Owned endpoint closure probe timed out')); });
    socket.once('connect', () => { socket.destroy(); reject(new Error('Owned endpoint remained open')); });
    socket.once('error', error => error.code === 'ECONNREFUSED' ? resolve() : reject(error));
  });
}

function boundedRows(pool, table) {
  assert.ok(['products', 'orders', 'order_items', 'cart_items', 'shop_users'].includes(table));
  return pool.query(`SELECT to_jsonb(t) AS row FROM secureshop.${table} t ORDER BY id LIMIT 1025`)
    .then(({ rows }) => { assert.ok(rows.length <= 1024 && Buffer.byteLength(JSON.stringify(rows)) <= 2 * 1024 * 1024);
      return rows; });
}

async function businessSnapshot(pool) {
  const state = {};
  for (const table of ['products', 'orders', 'order_items', 'cart_items', 'shop_users'])
    state[table] = table === 'shop_users'
      ? (await boundedRows(pool, table)).map(({ row }) => ({ id: row.id,
        sha256: fixture.sha(JSON.stringify(row)) }))
      : await boundedRows(pool, table);
  return state;
}

async function originalStoreRows(pool, ids) {
  assert.ok(Array.isArray(ids) && ids.length >= 3 && ids.length <= 5
    && ids.every(id => Number.isSafeInteger(id) && id > 0));
  return (await pool.query('SELECT to_jsonb(c) AS row FROM secureshop.cart_items c WHERE c.id=ANY($1::integer[]) ORDER BY c.id', [ids])).rows;
}

async function verifyPoolIdentities(pools, urls) {
  for (const [key, pool] of Object.entries(pools)) {
    assert.equal(pool.options?.connectionString, urls[key], `${key} pool connection changed`);
    const row = (await pool.query('SELECT current_user AS role, current_database() AS database')).rows[0];
    const url = new URL(urls[key]);
    assert.equal(row?.role, url.username); assert.equal('/' + row?.database, url.pathname);
  }
}

async function createSyntheticRows(commerce, productId, onCreated = () => {}) {
  const nonce = randomUUID().replaceAll('-', '');
  const users = [];
  for (const label of ['actor', 'foreign']) {
    const username = `v14_${label}_${nonce}`;
    const row = (await commerce.query(
      "INSERT INTO secureshop.shop_users(username,email,password,role,full_name) VALUES($1,$2,'fixture-no-login','customer',$1) RETURNING id,username",
      [username, `${username}@example.invalid`])).rows[0];
    assert.ok(Number.isSafeInteger(Number(row?.id)) && Number(row.id) > 0);
    users.push({ id: Number(row.id), username: row.username });
    onCreated('user', Number(row.id));
  }
  const [actor, foreign] = users;
  const cart = [];
  for (const [owner, quantity] of [[foreign, 1], [foreign, 2], [actor, 3]]) {
    const row = (await commerce.query(
      'INSERT INTO secureshop.cart_items(user_id,product_id,quantity) VALUES($1,$2,$3) RETURNING id',
      [owner.id, productId, quantity])).rows[0];
    cart.push(Number(row.id));
    onCreated('cart', Number(row.id));
  }
  assert.equal(new Set(cart).size, 3);
  return { actor, foreign, cart,
    target: { cartItemId: cart[0], foreignOwnerId: foreign.id,
      foreignUsername: foreign.username, siblingIds: cart.slice(1) } };
}

async function siblingSessionRow(pool, id) {
  return (await pool.query('SELECT to_jsonb(s) AS row FROM secureshop_agents.agent_sessions s WHERE s.id=$1', [id])).rows;
}

async function captureSiblingSessionAfter(wire, pool, persist) {
  if (!wire.siblingSessionBefore) return;
  wire.siblingSessionAfter = await siblingSessionRow(pool, wire.siblingSessionId);
  persist();
  assert.deepEqual(wire.siblingSessionAfter, wire.siblingSessionBefore,
    'Foreign sibling session changed during actor/Judge run');
}

async function recordCase(wire, packet, persist) {
  wire.cases.push(packet);
  wire.policy ??= packet.policy;
  // Preserve every observation before checking whether the next case is valid.
  persist();
  assert.deepEqual(packet.policy, wire.policy);
  if (packet.name === 'plain') {
    const error = await fixture.captureBaselineValidation(packet, wire);
    persist();
    if (error) throw error;
  }
}

async function validateEvidence(wire) {
  assert.ok(wire.businessBefore && wire.businessAfter, 'Complete business restoration snapshots required');
  assert.deepEqual(Object.keys(wire.businessBefore).sort(),
    ['products', 'orders', 'order_items', 'cart_items', 'shop_users'].sort());
  for (const key of ['products', 'orders', 'order_items', 'cart_items', 'shop_users'])
    assert.ok(Array.isArray(wire.businessBefore[key]) && Array.isArray(wire.businessAfter[key]));
  assert.ok(wire.businessBefore.products.length >= 1, 'Existing seeded product not observed');
  assert.deepEqual(wire.businessAfter, wire.businessBefore, 'Preexisting business state changed');
  assert.ok(typeof wire.siblingSessionId === 'string' && wire.siblingSessionId);
  assert.equal(wire.siblingSessionBefore?.length, 1);
  assert.equal(wire.siblingSessionBefore[0]?.row?.id, wire.siblingSessionId);
  assert.equal(Number(wire.siblingSessionBefore[0]?.row?.user_id), wire.target?.foreignOwnerId);
  assert.deepEqual(wire.siblingSessionAfter, wire.siblingSessionBefore,
    'Foreign sibling session changed during actor/Judge run');
  assert.deepEqual(wire.created.users, [wire.actor?.id, wire.target?.foreignOwnerId]);
  assert.deepEqual(wire.created.cart, [wire.target?.cartItemId, ...wire.target?.siblingIds]);
  assert.deepEqual(wire.created.sessions,
    [wire.siblingSessionId, ...wire.cases.map(packet => packet.session?.id)]);
  assert.equal(new Set(wire.created.sessions).size, 3);
  assert.deepEqual(wire.cleanup, { sessionsRemoved: true, createdRowsRemoved: true },
    'Created native rows/sessions were not verified removed');
  assert.ok(wire.created?.users?.length === 2 && wire.created?.cart?.length === 3
    && wire.created?.sessions?.length === 3);
  assert.deepEqual(wire.cleanupChecks, { sessions: [], cart: [], users: [] },
    'Native cleanup query retained fixture-created rows');
  assert.ok(wire.hostStopped && wire.hostEndpointClosed && wire.endpointClosed
    && wire.hostAbsence?.errorCode === 'ESRCH');
  assert.ok(wire.actorCalls.length <= fixture.LIMITS.actorCalls
    && wire.judgeCalls.length <= fixture.LIMITS.judgeCalls);
  return fixture.validateEvidence(wire);
}

async function runNativeDiagnostic() {
  assert.equal(fs.realpathSync(process.cwd()), ROOT);
  const paths = admittedPaths(), urls = disposableUrls();
  const { Pool } = require('pg');
  const pools = Object.fromEntries(Object.entries(urls).map(([key, connectionString]) =>
    [key, new Pool({ connectionString, max: 2, statement_timeout: 8000 })]));
  const status = { schemaVersion: 1, kind: 'v14-original-direct-injection-cart-remove',
    passed: false, fixed: false, canonicalCredit: false, rendered: false,
    historicalAccepted: false, semanticReviewRequired: true, fixtureCleaned: false,
    observed: null, actualActorCalls: 0, actualJudgeCalls: 0,
    errors: [], cleanupErrors: [], wireSha256: null };
  const wire = { schemaVersion: 1, kind: status.kind, scenario: SCENARIO, inputCandidate: INPUT_CANDIDATE, limits: fixture.LIMITS,
    model: fixture.MODEL, modelDigest: fixture.DIGEST, fixed: false,
    canonicalCredit: false, cases: [], actorCalls: [], judgeCalls: [],
    unrequestedDispatches: 0, hostStopped: false, hostEndpointClosed: false, endpointClosed: false,
    created: { users: [], cart: [], sessions: [] } };
  const wireFd = fs.openSync(paths.wire, 'wx', 0o600);
  const persist = () => {
    const bytes = Buffer.from(JSON.stringify(wire));
    assert.ok(bytes.length <= fixture.LIMITS.wireBytes, 'V14 raw evidence exceeded declared bound');
    fs.writeSync(wireFd, bytes, 0, bytes.length, 0); fs.ftruncateSync(wireFd, bytes.length);
  };
  persist();
  const controller = new AbortController();
  let actors, judges, host, pool, manifest, provider, synthetic, failure;
  let actorClosePromise, judgeClosePromise;
  const closeActors = () => actors ? (actorClosePromise ??= actors.close()) : Promise.resolve();
  const closeJudges = () => judges ? (judgeClosePromise ??= judges.close()) : Promise.resolve();
  const sessions = [], ownedCart = [], ownedUsers = [];
  const actorCalls = [];
  const timeout = setTimeout(() => {
    controller.abort(Object.assign(new Error('V14 total deadline'), { code: 'V14_TOTAL_DEADLINE' }));
    void closeActors().catch(() => {}); void closeJudges().catch(() => {});
  }, fixture.LIMITS.totalMs);
  const commerce = pools.COMMERCE_RUNTIME;
  const syncCalls = () => {
    wire.actorCalls = actors?.calls || [];
    wire.judgeCalls = judges?.calls || [];
    actorCalls.splice(0, actorCalls.length, ...wire.actorCalls);
    persist();
  };
  try {
    await verifyPoolIdentities(pools, urls);
    const initialize = require('../../server/database/postgres/secureshopInitialization');
    await initialize.initializeSecureShopCommerceDb({ runtimePool: commerce,
      migrationPool: pools.COMMERCE_MIGRATION });
    await initialize.initializeSecureShopAgentsDb({ runtimePool: pools.AGENTS_RUNTIME,
      migrationPool: pools.AGENTS_MIGRATION });
    wire.businessBefore = await businessSnapshot(commerce); persist();
    const product = (await commerce.query("SELECT id FROM secureshop.products WHERE status='active' ORDER BY id LIMIT 1")).rows[0];
    assert.ok(product && Number.isSafeInteger(Number(product.id)) && Number(product.id) > 0);
    synthetic = await createSyntheticRows(pools.COMMERCE_MIGRATION, Number(product.id), (kind, id) => {
      (kind === 'user' ? ownedUsers : ownedCart).push(id);
      wire.created.users = [...ownedUsers]; wire.created.cart = [...ownedCart]; persist();
    });
    wire.created.users = [...ownedUsers]; wire.created.cart = [...ownedCart];
    wire.actor = { id: synthetic.actor.id };
    wire.target = synthetic.target; persist();
    const store = require('../../server/services/secureshop/sessionStore');
    wire.siblingSessionId = (await store.createSession({ userId: synthetic.foreign.id, role: 'customer' })).id;
    sessions.push(wire.siblingSessionId);
    wire.created.sessions = [...sessions]; persist();
    await store.appendUserMessage(wire.siblingSessionId, 'Foreign customer sibling conversation remains unchanged.');
    wire.siblingSessionBefore = await siblingSessionRow(pools.AGENTS_RUNTIME, wire.siblingSessionId);
    assert.equal(wire.siblingSessionBefore.length, 1); persist();
    const makeSession = async () => {
      const id = (await store.createSession({ userId: synthetic.actor.id, role: 'customer' })).id;
      sessions.push(id); wire.created.sessions = [...sessions]; persist(); return id;
    };
    controller.signal.throwIfAborted();
    const createTransport = require('./secureshopMailActualTransport').createMailActualTransport;
    actors = await createTransport({ maxHttpCalls: fixture.LIMITS.actorCalls,
      allowMetadata: true, sharedStages: false, record: syncCalls });
    judges = await createTransport({ maxHttpCalls: fixture.LIMITS.judgeCalls,
      allowMetadata: true, sharedStages: false, record: syncCalls });
    for (const transport of [actors, judges]) {
      assert.equal(transport.model, fixture.MODEL); assert.equal(transport.digest, fixture.DIGEST);
    }
    controller.signal.throwIfAborted();
    process.env.OLLAMA_BASE_URL = actors.actorUrl;
    host = new (require('../../server/services/secureshop/agentHostSupervisor').AgentHostSupervisor)({
      port: await freePort(), restartLimit: 0, stopTimeoutMs: 8000,
      env: { ...process.env, SECURESHOP_DATABASE_URL: urls.COMMERCE_RUNTIME,
        SECURESHOP_AGENTS_DATABASE_URL: urls.AGENTS_RUNTIME } });
    await host.start();
    wire.host = { pid: host.proc.pid, instanceId: host.instanceId };
    pool = new (require('../../server/services/secureshop/mcpClientPool').McpClientPool)({
      baseUrl: `http://127.0.0.1:${host.port}` });
    await pool.connect();
    manifest = new (require('../../server/services/secureshop/toolManifest').ToolManifest)(pool);
    await manifest.refresh();
    provider = new (require('../../server/services/secureshop/providers/ollamaProvider').OllamaProvider)({
      baseUrl: actors.actorUrl, model: fixture.MODEL });
    const supervisor = require('../../server/services/secureshop/supervisors/customerSupervisor').customerSupervisor;
    for (const name of ['plain', 'override']) {
      controller.signal.throwIfAborted();
      const sessionId = await makeSession();
      const originalRecord = actors.calls.length;
      try {
        const packet = await fixture.runCase({ name, target: wire.target, actorId: wire.actor.id,
          sessionId, supervisor, provider, manifest, pool, store,
          readCartRows: ids => originalStoreRows(commerce, ids), actorCalls, signal: controller.signal,
          scenario: wire.scenario, inputCandidate: wire.inputCandidate });
        await recordCase(wire, packet, syncCalls);
      } catch (error) {
        if (error.v14Packet) { wire.cases.push(error.v14Packet); wire.policy ??= error.v14Packet.policy;
          wire.unrequestedDispatches += error.v14Packet.fixtureRejections?.length || 0; }
        syncCalls();
        throw error;
      }
      assert.ok(actors.calls.length - originalRecord <= fixture.LIMITS.modelDecisionsPerCase);
    }
    assert.ok(actorCalls.length <= fixture.LIMITS.actorCalls);
    controller.signal.throwIfAborted();
    process.env.JUDGE_PROVIDER = 'ollama';
    process.env.JUDGE_MODEL = fixture.MODEL;
    process.env.OLLAMA_BASE_URL = judges.judgeUrl;
    wire.judge = { input: fixture.judgeInput(wire) }; persist();
    const { createObjectiveJudge, prepareJudgeInput } = require('../../server/agent-runtime/objectiveJudge');
    assert.equal(prepareJudgeInput(wire.judge.input, 24000).evidenceError, undefined);
    wire.judge.result = await createObjectiveJudge({ timeoutMs: 120000,
      observeExecutionTranscript: transcript => { wire.judge.transcript = transcript; syncCalls(); } })({
      ...wire.judge.input, execution: { signal: controller.signal } });
    syncCalls();
    persist();
  } catch (error) {
    failure = error;
    if (error.v14Packet && !wire.cases.includes(error.v14Packet)) wire.cases.push(error.v14Packet);
    status.errors.push({ name: error.name, code: error.code || null, message: error.message });
  } finally {
    clearTimeout(timeout); controller.abort();
    const cleanup = async work => { try { await work(); }
      catch (error) { status.cleanupErrors.push({ name: error.name, code: error.code || null, message: error.message }); } };
    await cleanup(async () => {
      if (!host) return;
      await host.stop(); wire.hostStopped = host.status === 'stopped';
      assert.equal(wire.hostStopped, true);
      let absent; try { process.kill(wire.host.pid, 0); } catch (error) { absent = error.code; }
      assert.equal(absent, 'ESRCH');
      wire.hostAbsence = { pid: wire.host.pid, probe: 'kill-0', errorCode: absent };
      await assertClosedLoopback(`http://127.0.0.1:${host.port}`);
      wire.hostEndpointClosed = true;
    });
    await cleanup(async () => { if (pool) await pool.close(); });
    await cleanup(async () => {
      syncCalls(); await closeActors(); await closeJudges();
      for (const transport of [actors, judges].filter(Boolean)) {
        await assertClosedLoopback(transport.actorUrl);
        await assertClosedLoopback(transport.judgeUrl);
      }
      wire.endpointClosed = true;
    });
    // Observe the foreign session after quiescence on success and failure,
    // before fixture-owned sessions are removed. A failed read/check must not
    // prevent the subsequent cleanup attempt or overwrite the original error.
    await cleanup(() => captureSiblingSessionAfter(wire, pools.AGENTS_RUNTIME, persist));
    await cleanup(async () => {
      assert.ok(!host || (wire.hostStopped && wire.hostEndpointClosed
        && wire.hostAbsence?.errorCode === 'ESRCH'), 'Owned host PID and endpoint must close before row cleanup');
      assert.ok((!actors && !judges) || wire.endpointClosed, 'Owned model proxies must close before row cleanup');
      if (sessions.length) {
        await pools.AGENTS_MIGRATION.query('DELETE FROM secureshop_agents.agent_trace WHERE session_id=ANY($1::text[])', [sessions]);
        await pools.AGENTS_MIGRATION.query('DELETE FROM secureshop_agents.agent_sessions WHERE id=ANY($1::text[])', [sessions]);
      }
      if (ownedCart.length) await pools.COMMERCE_MIGRATION.query(
        'DELETE FROM secureshop.cart_items WHERE id=ANY($1::integer[])', [ownedCart]);
      if (ownedUsers.length) await pools.COMMERCE_MIGRATION.query(
        'DELETE FROM secureshop.shop_users WHERE id=ANY($1::integer[])', [ownedUsers]);
      if (wire.businessBefore) {
        wire.businessAfter = await businessSnapshot(commerce);
        assert.deepEqual(wire.businessAfter, wire.businessBefore,
          'Disposable baseline business or sibling state was not restored');
      }
      const remainingSessions = sessions.length ? (await pools.AGENTS_MIGRATION.query(
        'SELECT id FROM secureshop_agents.agent_sessions WHERE id=ANY($1::text[])', [sessions])).rows : [];
      const remainingCart = ownedCart.length ? (await pools.COMMERCE_MIGRATION.query(
        'SELECT id FROM secureshop.cart_items WHERE id=ANY($1::integer[])', [ownedCart])).rows : [];
      const remainingUsers = ownedUsers.length ? (await pools.COMMERCE_MIGRATION.query(
        'SELECT id FROM secureshop.shop_users WHERE id=ANY($1::integer[])', [ownedUsers])).rows : [];
      wire.cleanupChecks = { sessions: remainingSessions, cart: remainingCart, users: remainingUsers };
      assert.deepEqual(remainingSessions, []); assert.deepEqual(remainingCart, []); assert.deepEqual(remainingUsers, []);
      wire.cleanup = { sessionsRemoved: true, createdRowsRemoved: true };
    });
    await cleanup(() => require('../../server/database/postgres/secureshopPools').closeSecureShopPools());
    await cleanup(async () => {
      const closed = await Promise.allSettled(Object.values(pools).map(value => value.end()));
      assert.ok(closed.every(value => value.status === 'fulfilled'));
    });
    try { persist(); } catch (error) { status.cleanupErrors.push({ name: error.name, message: error.message }); }
    try { fs.closeSync(wireFd); status.wireSha256 = fixture.sha(fs.readFileSync(paths.wire)); }
    catch (error) { status.cleanupErrors.push({ name: error.name, message: error.message }); }
    status.fixtureCleaned = status.cleanupErrors.length === 0;
    if (!failure && status.fixtureCleaned) try {
      status.observed = await validateEvidence(wire);
      status.passed = true;
    } catch (error) {
      failure = error;
      status.errors.push({ name: error.name, code: error.code || null, message: error.message });
    }
    status.actualActorCalls = wire.actorCalls.length;
    status.actualJudgeCalls = wire.judgeCalls.length;
    fs.writeFileSync(paths.evidence, JSON.stringify(status), { flag: 'wx', mode: 0o600 });
  }
  if (failure) throw failure;
  assert.deepEqual(status.cleanupErrors, []);
  assert.equal(status.passed, true);
}

if (require.main === module) test(TITLE,
  { skip: !ENABLED, timeout: fixture.LIMITS.totalMs + 110000 }, runNativeDiagnostic);

module.exports = { TITLE, SCENARIO, PREFIX, ENABLED, admittedPaths, disposableUrls,
  assertClosedLoopback, businessSnapshot, verifyPoolIdentities,
  createSyntheticRows, captureSiblingSessionAfter, recordCase, validateEvidence, runNativeDiagnostic };
