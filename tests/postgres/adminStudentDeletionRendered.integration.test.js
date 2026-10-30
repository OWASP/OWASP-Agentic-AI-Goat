'use strict';

// Separate, import-inert current-host student deletion fixture. Native execution
// stays closed until the complete sixteen-store oracle and launcher admission
// have been independently reviewed; these helpers never create test authority.
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs/promises');
const path = require('node:path');
const test = require('node:test');
const { readInheritedFifoGrant } = require('../fixtures/inheritedFifoGrant');
const { buildInventory, focusQ05MainPage, renderedRowAction } = require('./adminQ05RenderedScenario');
const { admitStores, STORES, BUDGET, createFixturePool, assertPoolSnapshot } =
  require('./adminStudentDeletionRenderedSupport');

const REPO = path.resolve(__dirname, '../..');
const COHORT = 'admin-student-deletion-current-host';
const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const SHA256 = /^[0-9a-f]{64}$/;
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));
const sha = value => crypto.createHash('sha256').update(value).digest('hex');

function deletionStorePlanSha256(rows) {
  assert(Array.isArray(rows) && rows.length === 16);
  return sha(Buffer.from(JSON.stringify(rows.map(({ database, schema }) => ({ database, schema }))), 'utf8'));
}

function deletionPaths(env, repo = REPO) {
  assert.equal(env.ADMIN_STUDENT_DELETION_CURRENT_HOST, '1');
  assert.equal(env.PG_TEST_DISPOSABLE, 'yes');
  const root = path.join(repo, 'tasks/qualification');
  const evidence = env.STUDENT_DELETION_EVIDENCE_PATH;
  assert.equal(typeof evidence, 'string');
  assert(path.isAbsolute(evidence));
  assert.equal(path.basename(evidence), 'student-deletion-evidence.json');
  const run = path.dirname(evidence);
  assert.equal(path.dirname(run), root);
  assert(/^run-[a-z0-9_-]+$/.test(path.basename(run)));
  const runtime = path.join(run, 'runtime');
  const temp = path.join(runtime, 'tmp');
  assert.equal(env.STUDENT_DELETION_RESOURCE_JOURNAL,
    path.join(temp, 'student-deletion-resources.json'));
  assert.equal(env.ADMIN_STUDENT_DELETION_BROWSER_ACK,
    path.join(runtime, 'browser-ack.json'));
  const buildDirectory = path.join(repo, 'client/build');
  assert.equal(env.ADMIN_STUDENT_DELETION_BUILD_DIRECTORY, buildDirectory);
  for (const key of ['ADMIN_STUDENT_DELETION_BUILD_SHA256',
    'ADMIN_STUDENT_DELETION_SNAPSHOT_SHA256', 'ADMIN_STUDENT_DELETION_STORE_PLAN_SHA256'])
    assert(SHA256.test(env[key] || ''), `${key} pin required`);
  assert.equal(env.PUPPETEER_EXECUTABLE_PATH, env.OWASP_AI_GOAT_CHROMIUM_ACTUAL_EXECUTABLE);
  assert(path.isAbsolute(env.PUPPETEER_EXECUTABLE_PATH));
  return { run, runtime, temp, evidence, buildDirectory };
}

function validateDeletionGrant(grant, { env, paths, repo = REPO,
  launcherPid = process.ppid, workerPid = process.pid }) {
  assert(grant && typeof grant === 'object' && !Array.isArray(grant));
  assert.deepEqual(Object.keys(grant).sort(), ['version', 'cohort', 'launcherPid', 'workerPid',
    'nonce', 'workspace', 'buildSha256', 'snapshotSha256', 'outerSandbox', 'chromium',
    'profile', 'storePlanSha256'].sort());
  assert.equal(grant.version, 1);
  assert.equal(grant.cohort, COHORT);
  assert.equal(grant.launcherPid, launcherPid);
  assert.equal(grant.workerPid, workerPid);
  assert(/^[0-9a-f]{12}$/.test(grant.nonce));
  assert.equal(grant.workspace, repo);
  assert.equal(grant.buildSha256, env.ADMIN_STUDENT_DELETION_BUILD_SHA256);
  assert.equal(grant.snapshotSha256, env.ADMIN_STUDENT_DELETION_SNAPSHOT_SHA256);
  assert.equal(grant.storePlanSha256, env.ADMIN_STUDENT_DELETION_STORE_PLAN_SHA256);
  assert.equal(grant.outerSandbox, 'repository-only');
  assert.equal(grant.chromium, env.OWASP_AI_GOAT_CHROMIUM_ACTUAL_EXECUTABLE);
  assert.equal(path.dirname(grant.profile), paths.temp);
  assert(/^owasp-ai-goat-student-deletion-browser-[0-9a-f]{12}$/.test(path.basename(grant.profile)));
  assert.equal(path.basename(grant.profile), `owasp-ai-goat-student-deletion-browser-${grant.nonce}`);
  return { admitted: true, nonceSha256: sha(grant.nonce), profile: grant.profile };
}

async function admitDeletionCurrentHost(env = process.env, repo = REPO) {
  const paths = deletionPaths(env, repo);
  for (const directory of [paths.run, paths.runtime, paths.temp]) {
    const info = await fs.lstat(directory);
    assert(info.isDirectory() && !info.isSymbolicLink() && info.uid === process.getuid()
      && (info.mode & 0o077) === 0, 'Student deletion runtime directories must be owned and private');
    assert.equal(await fs.realpath(directory), directory);
  }
  const stores = admitStores(env);
  assert.equal(deletionStorePlanSha256(stores), env.ADMIN_STUDENT_DELETION_STORE_PLAN_SHA256);
  const grant = await readInheritedFifoGrant(env, 'ADMIN_STUDENT_DELETION_ADMISSION_FD',
    'student deletion');
  const admitted = validateDeletionGrant(grant, { env, paths, repo });
  const initial = await buildInventory(paths.buildDirectory);
  assert.equal(initial.sha256, env.ADMIN_STUDENT_DELETION_BUILD_SHA256);
  return { ...paths, ...admitted, stores, async verifyBuild() {
    const current = await buildInventory(paths.buildDirectory);
    assert.equal(current.sha256, initial.sha256);
    assert.deepEqual(current.files, initial.files);
  }, async awaitBrowserAck(pid) {
    const deadline = Date.now() + 10000;
    while (Date.now() < deadline) {
      let info;
      try { info = await fs.lstat(env.ADMIN_STUDENT_DELETION_BROWSER_ACK); }
      catch (error) { if (error.code === 'ENOENT') { await delay(25); continue; } throw error; }
      assert(info.isFile() && !info.isSymbolicLink() && info.nlink === 1
        && (info.mode & 0o077) === 0 && info.uid === process.getuid());
      const ack = JSON.parse(await fs.readFile(env.ADMIN_STUDENT_DELETION_BROWSER_ACK, 'utf8'));
      assert.deepEqual(Object.keys(ack).sort(), ['version', 'pid', 'pgid', 'sessionId', 'uid',
        'startSec', 'startUsec', 'profile', 'executable'].sort());
      assert.equal(ack.version, 1);
      assert.equal(ack.pid, pid);
      assert(Number.isSafeInteger(ack.pgid) && ack.pgid > 0);
      assert(Number.isSafeInteger(ack.sessionId) && ack.sessionId > 0);
      assert.equal(ack.uid, process.getuid());
      assert(Number.isSafeInteger(ack.startSec) && ack.startSec > 0);
      assert(Number.isSafeInteger(ack.startUsec) && ack.startUsec >= 0);
      assert.equal(ack.profile, admitted.profile);
      assert.equal(ack.executable, env.OWASP_AI_GOAT_CHROMIUM_ACTUAL_EXECUTABLE);
      return { acknowledged: true, pid };
    }
    throw new Error('Student deletion live browser birth ACK timed out');
  } };
}

function deletionAckFact(status, body, endpoint) {
  assert(/^\/api\/admin\/students\/[1-9]\d*$/.test(endpoint));
  assert.equal(status, 200);
  assert(typeof body === 'string' || Buffer.isBuffer(body));
  assert(Buffer.byteLength(body) <= 8192);
  const result = JSON.parse(Buffer.isBuffer(body)
    ? new TextDecoder('utf-8', { fatal: true }).decode(body) : body);
  assert.equal(result?.success, true);
  assert(UUID_V4.test(result.jobId || ''), 'Only a genuine canonical deletion job may qualify');
  return { status: 200, jobId: result.jobId, serverAcknowledgedCompleted: true };
}

function createDeletionAckCapture(endpoint) {
  assert(/^\/api\/admin\/students\/[1-9]\d*$/.test(endpoint));
  const chunks = [];
  let bytes = 0, failure = null, ended = false;
  const add = (chunk, encoding) => {
    if (failure || chunk == null) return;
    if (!(typeof chunk === 'string' || Buffer.isBuffer(chunk))
      || (typeof chunk === 'string' && encoding != null
        && !['utf8', 'utf-8'].includes(String(encoding).toLowerCase()))) {
      failure = 'unsupported-chunk'; return;
    }
    const buffer = Buffer.isBuffer(chunk) ? Buffer.from(chunk) : Buffer.from(chunk, 'utf8');
    bytes += buffer.length;
    if (bytes > 8192) { failure = 'oversize'; chunks.length = 0; return; }
    if (buffer.length) chunks.push(buffer);
  };
  return { write: add, end(status, chunk, encoding, contentEncoding) {
    if (ended) return { valid: false, reason: 'duplicate-end' };
    ended = true; add(chunk, encoding);
    if (contentEncoding != null && contentEncoding !== 'identity') failure ||= 'encoded-response';
    if (failure) return { valid: false, reason: failure };
    try { return { valid: true, fact: deletionAckFact(status, Buffer.concat(chunks, bytes), endpoint) }; }
    catch { return { valid: false, reason: 'invalid-ack' }; }
  } };
}

function observeDeletionAck(res, endpoint, observe) {
  const capture = createDeletionAckCapture(endpoint);
  const write = res.write, end = res.end;
  res.write = function observedWrite(chunk, encoding) {
    capture.write(chunk, typeof encoding === 'function' ? undefined : encoding);
    return write.apply(this, arguments);
  };
  res.end = function observedEnd(chunk, encoding) {
    observe(capture.end(res.statusCode, chunk, typeof encoding === 'function' ? undefined : encoding,
      res.getHeader('content-encoding')));
    return end.apply(this, arguments);
  };
}

function deletionResponseIdentity(event, base, endpoint) {
  if (event?.request?.method !== 'DELETE' || event.request.url !== `${base}${endpoint}`) return false;
  assert.equal(event.responseStatusCode, 200);
  return true;
}

function witnessDeletionRequests(page, base, endpoint) {
  assert.equal(new URL(base).hostname, '127.0.0.1');
  assert(/^\/api\/admin\/students\/[1-9]\d*$/.test(endpoint));
  const exact = `${base}${endpoint}`;
  const selected = new Set();
  let requests = 0, failed = 0, finished = 0, unexpected = 0;
  const onRequest = request => {
    const method = request.method();
    if (!['POST', 'PUT', 'PATCH', 'DELETE'].includes(method)) return;
    if (method === 'POST' && request.url() === `${base}/api/auth/login`) return;
    if (method !== 'DELETE' || request.url() !== exact) {
      unexpected += 1;
      return;
    }
    assert(!selected.has(request), 'One browser request event per DELETE required');
    selected.add(request); requests += 1;
  };
  const onFailed = request => { if (selected.has(request)) failed += 1; };
  const onFinished = request => { if (selected.has(request)) finished += 1; };
  page.on('request', onRequest);
  page.on('requestfailed', onFailed);
  page.on('requestfinished', onFinished);
  return Object.freeze({ snapshot: () => ({ requests, failed, finished, unexpected }),
    stop() {
      page.off('request', onRequest);
      page.off('requestfailed', onFailed);
      page.off('requestfinished', onFinished);
    } });
}

function assertHeldDeletionFence({ before, after, error }) {
  assert(/^(0|[1-9]\d*)$/.test(before || ''));
  assert(/^(0|[1-9]\d*)$/.test(after || ''));
  assert(BigInt(after) > BigInt(before),
    'The canonical MCP owner generation must advance before run release');
  assert.equal(error?.name, 'AbortError');
  assert.equal(error?.message, 'Graph generation is no longer current',
    'A deadline or unrelated abort is not an MCP generation-fence proof');
  return true;
}

function assertDeletionSeedPoolKeys(runtime, migration) {
  assert.deepEqual(Object.keys(runtime).sort(), STORES.map(store => store.schema).sort());
  assert.deepEqual(Object.keys(migration).sort(), ['identity', 'ctf', 'finflow'].sort());
  return true;
}

async function releaseDeletionReadbackCapacity({ pool, readSnapshot }) {
  assert.equal(typeof pool?.end, 'function');
  assert.equal(typeof readSnapshot, 'function');
  const before = assertPoolSnapshot(readSnapshot());
  await pool.end();
  const after = assertPoolSnapshot(readSnapshot());
  assert.equal(before.reserved - after.reserved, 2,
    'Only the completed fixture XSS workshop pool may release two slots');
  assert(after.reserved + 2 <= BUDGET,
    'Both exact migration readback pools must fit without increasing the process budget');
  return Object.freeze({ reservedBefore: before.reserved,
    reservedAfter: after.reserved, plannedReadbackPeak: after.reserved + 2 });
}

async function openDeletionSeedInfrastructure(env = process.env) {
  assert.equal(env, process.env, 'Singleton deletion seed requires the admitted process environment');
  assert.equal(admitStores(env).length, 16);
  const owned = [];
  try {
    // The application singleton is the same identity pool that production
    // deletion, session validation, and the durable graph ledger will read.
    const adapter = require('../../server/services/postgresIdentityAdapter').getPostgresIdentityAdapter();
    assert.equal(typeof adapter.validateSession, 'function');
    const runtime = { identity: adapter.pool }, migration = {};
    const seedMigration = [];
    for (const store of STORES) {
      if (store.schema !== 'identity') {
        const pool = createFixturePool(env, store.runtimeVariable);
        owned.push(pool); runtime[store.schema] = pool;
      }
      if (['identity', 'ctf', 'finflow'].includes(store.schema)) {
        const pool = createFixturePool(env, store.migrationVariable);
        owned.push(pool); seedMigration.push(pool); migration[store.schema] = pool;
      }
    }
    assertDeletionSeedPoolKeys(runtime, migration);
    const ledger = require('../../server/agent-runtime/postgresRunLedger').configuredRunLedger();
    assert.equal(typeof ledger?.begin, 'function');
    assert.equal(typeof ledger.invalidate, 'function');
    let controlledEmbedCalls = 0;
    const embedder = Object.freeze({
      getRuntimeFingerprint: () => ({ fingerprint: 'a'.repeat(64) }),
      async embed() {
        controlledEmbedCalls += 1;
        return { embeddingDimension: 384, embedding: Array.from({ length: 384 }, (_, i) => i === 0 ? 1 : 0) };
      },
    });
    const expectedDatabase = new URL(env.IDENTITY_DATABASE_URL).pathname.slice(1);
    const rag = require('../../server/services/workshopRagComposition').createWorkshopRagComposition({
      pool: runtime.identity, identityAdapter: adapter, embedder,
      assertReady: pool => require('../../server/services/workshopRagReadiness')
        .assertWorkshopRagReadiness({ pool, expectedDatabase }),
    });
    await rag.initialize();
    const ragRoute = require('../../server/routes/ragInjection');
    const csrfRoute = require('../../server/routes/csrfWorkshop');
    assert.equal(ragRoute.durableRagComposition(), null, 'Fresh RAG route binding required');
    assert.equal(csrfRoute.durableRagComposition(), null, 'Fresh CSRF route binding required');
    ragRoute.configureDurableRag(rag);
    csrfRoute.configureDurableRag(rag);
    assert.equal(ragRoute.durableRagComposition(), rag);
    assert.equal(csrfRoute.durableRagComposition(), rag);
    const coordinator = require('../../server/agent-runtime/runCoordinator').createRunCoordinator({
      family: 'CTF', ledger, defaultTimeoutMs: 10000,
    });
    const poolSnapshot = assertPoolSnapshot(require('../../server/database/postgres').getPoolBudgetSnapshot());
    let migrationDrained = false, completedXssReadbackReleased = false;
    return Object.freeze({ adapter, runtime, migration, ledger, rag, coordinator, poolSnapshot,
      controlledEmbedCalls: () => controlledEmbedCalls,
      async releaseCompletedWorkshopReadbackPool() {
        assert.equal(migrationDrained, true, 'Production admission requires drained migration pools');
        assert.equal(completedXssReadbackReleased, false,
          'The fixture XSS oracle pool may retire only once after its final snapshot');
        const plan = await releaseDeletionReadbackCapacity({ pool: runtime.xss,
          readSnapshot: () => require('../../server/database/postgres').getPoolBudgetSnapshot() });
        completedXssReadbackReleased = true;
        return plan;
      },
      async closeSeedMigrationPools() {
        assert.equal(migrationDrained, false, 'Seed migration pools may be drained once');
        const results = await Promise.allSettled(seedMigration.map(pool => pool.end()));
        const errors = results.filter(row => row.status === 'rejected').map(row => row.reason);
        if (errors.length) throw new AggregateError(errors, 'Seed migration pool shutdown failed');
        migrationDrained = true;
        for (const schema of ['identity', 'ctf', 'finflow']) delete migration[schema];
        assert.equal(assertPoolSnapshot(require('../../server/database/postgres')
          .getPoolBudgetSnapshot()).allocations.some(row => row.purpose === 'migration'), false);
      },
      async withArtifactReadback(callback) {
        assert.equal(migrationDrained, true, 'Artifact readback requires drained seed pools');
        assert.equal(typeof callback, 'function');
        const temporary = [];
        const before = assertPoolSnapshot(require('../../server/database/postgres')
          .getPoolBudgetSnapshot());
        assert(before.reserved + 2 <= BUDGET,
          'Two exact migration readback pools must fit the existing process budget');
        try {
          for (const schema of ['identity', 'finflow']) {
            const store = STORES.find(row => row.schema === schema);
            temporary.push(createFixturePool(env, store.migrationVariable));
          }
          const snapshot = assertPoolSnapshot(require('../../server/database/postgres')
            .getPoolBudgetSnapshot());
          assert.equal(snapshot.allocations.filter(row => row.purpose === 'migration').length, 2);
          assert.equal(snapshot.reserved, before.reserved + 2);
          return await callback({ identity: temporary[0], finflow: temporary[1] });
        } finally {
          const results = await Promise.allSettled(temporary.map(pool => pool.end()));
          const errors = results.filter(row => row.status === 'rejected').map(row => row.reason);
          if (errors.length) throw new AggregateError(errors, 'Artifact readback pool shutdown failed');
          assert.equal(assertPoolSnapshot(require('../../server/database/postgres')
            .getPoolBudgetSnapshot()).reserved, before.reserved);
        }
      },
      async closeOwnedPools() {
        const remaining = migrationDrained ? owned.filter(pool => !seedMigration.includes(pool)) : owned;
        const results = await Promise.allSettled(remaining.map(pool => pool.end()));
        const errors = results.filter(row => row.status === 'rejected').map(row => row.reason);
        if (errors.length) throw new AggregateError(errors, 'Owned deletion seed pool shutdown failed');
      } });
  } catch (error) {
    const results = await Promise.allSettled(owned.map(pool => pool.end()));
    const failures = results.filter(row => row.status === 'rejected').map(row => row.reason);
    if (failures.length) throw new AggregateError([error, ...failures], 'Deletion seed setup and pool shutdown failed');
    throw error;
  }
}

async function seedDeletionPrincipals({ adapter, runtime, migration, nonce }) {
  assert.equal(process.env.PG_TEST_DISPOSABLE, 'yes');
  assert(/^[0-9a-f]{12}$/.test(nonce));
  assert.equal(adapter?.pool, runtime?.identity);
  assert.equal(typeof migration?.identity?.query, 'function');
  const repository = adapter.repository;
  assert.equal(typeof repository?.createUser, 'function');
  const descriptors = [
    { key: 'actor', username: `deletion-admin-${nonce}`, role: 'super_admin' },
    { key: 'target', username: `deletion-target-${nonce}`, role: 'student' },
    { key: 'sibling', username: `deletion-sibling-${nonce}`, role: 'student' },
  ];
  for (const row of descriptors) {
    const found = await runtime.identity.query('SELECT id FROM identity.users WHERE username=$1', [row.username]);
    assert.equal(found.rowCount, 0, 'Synthetic deletion principal must not preexist');
  }
  const password = `OwnedDeletion-${crypto.randomUUID()}!`;
  const hash = await require('bcryptjs').hash(password, 4);
  const result = {};
  for (const row of descriptors) {
    const email = `${row.username}@example.invalid`;
    const user = await repository.createUser({ username: row.username, email,
      passwordHash: hash, fullName: 'Controlled deletion lifecycle principal' });
    assert(Number.isSafeInteger(user.id) && user.id > 0);
    const verified = await migration.identity.query(
      'UPDATE identity.users SET email_verified=1 WHERE id=$1', [user.id]);
    assert.equal(verified.rowCount, 1);
    if (row.role === 'super_admin') {
      const promoted = await migration.identity.query(`UPDATE identity.users
        SET role='super_admin',admin_level=2 WHERE id=$1`, [user.id]);
      assert.equal(promoted.rowCount, 1);
      await repository.grantPermission({ userId: user.id, permission: 'user_management', grantedBy: user.id });
      await repository.grantPermission({ userId: user.id, permission: 'manage_progress', grantedBy: user.id });
    }
    const credential = await repository.findCredentialById(user.id);
    assert.equal(credential?.role, row.role);
    const issued = await adapter.createSession(credential, { get: () => null, ip: '127.0.0.1' });
    const current = await adapter.validateSession(issued.token);
    assert.equal(current?.user?.id, user.id);
    assert.equal(current?.session?.id, issued.internalSessionId);
    const principal = { id: user.id, sessionId: issued.internalSessionId,
      username: row.username, email };
    Object.defineProperties(principal, {
      token: { value: issued.token }, password: { value: password },
    });
    if (row.key === 'actor') {
      const alternate = await adapter.createSession(credential, { get: () => null, ip: '127.0.0.1' });
      assert.notEqual(alternate.token, issued.token);
      const alternateFound = await adapter.validateSession(alternate.token);
      assert.equal(alternateFound?.user?.id, user.id);
      assert.equal(alternateFound?.session?.id, alternate.internalSessionId);
      principal.alternateSessionId = alternate.internalSessionId;
      Object.defineProperty(principal, 'alternateToken', { value: alternate.token });
    }
    result[row.key] = Object.freeze(principal);
  }
  assert.equal(new Set(Object.values(result).map(row => row.id)).size, 3);
  return Object.freeze(result);
}

function deletionRequestFor(principal, adapter) {
  assert(Number.isSafeInteger(principal?.id) && principal.id > 0);
  assert(Number.isSafeInteger(principal.sessionId) && principal.sessionId > 0);
  assert.equal(typeof principal.token, 'string');
  assert.equal(typeof adapter?.validateSession, 'function');
  return adapter.validateSession(principal.token).then(found => {
    assert.equal(found?.user?.id, principal.id);
    assert.equal(found?.session?.id, principal.sessionId);
    return { user: found.user, identitySession: found.session,
      headers: { authorization: `Bearer ${principal.token}` } };
  });
}

async function prepareDeletionOwnedState({ infra, principals, admitted, recordStage, signal }) {
  assert.equal(typeof recordStage, 'function', 'A durable pre-effect artifact journal is mandatory');
  assert.equal(admitted?.runtime, process.env.OWASP_AI_GOAT_APP_DATA_ROOT);
  assert.equal(infra?.runtime?.identity, infra?.adapter?.pool);
  assert.equal(new Set([principals?.actor?.id, principals?.target?.id,
    principals?.sibling?.id]).size, 3);
  const ids = { targetId: principals.target.id, siblingId: principals.sibling.id };
  const seed = require('./adminStudentDeletionSeedSupport');
  const ctfSupport = require('./adminStudentDeletionCtfSupport');
  const shopSupport = require('./adminStudentDeletionSecureShopSupport');
  const artifactSupport = require('./adminStudentDeletionArtifactSupport');
  const ctf = await ctfSupport.initializeDeletionCtf({
    identityRuntime: infra.runtime.identity, identityMigration: infra.migration.identity,
    ctfRuntime: infra.runtime.ctf, ctfMigration: infra.migration.ctf,
    adapter: infra.adapter, coordinator: infra.coordinator, signal,
  });
  let artifacts;
  try {
  const targetRequest = await deletionRequestFor(principals.target, infra.adapter);
  const siblingRequest = await deletionRequestFor(principals.sibling, infra.adapter);
  const registrations = {
    target: await ctfSupport.registerDeletionCtfOwner({ runtime: ctf.runtime, req: targetRequest, signal }),
    sibling: await ctfSupport.registerDeletionCtfOwner({ runtime: ctf.runtime, req: siblingRequest, signal }),
  };
  // Both CTF registrations precede either snapshot: shared payload and
  // leaderboard comparisons must use the same global baseline.
  const ctfBefore = {
    target: await ctfSupport.readDeletionCtfOwner({ identityPool: infra.runtime.identity,
      ctfPool: infra.runtime.ctf, registration: registrations.target }),
    sibling: await ctfSupport.readDeletionCtfOwner({ identityPool: infra.runtime.identity,
      ctfPool: infra.runtime.ctf, registration: registrations.sibling }),
  };
  const workshop = await seed.seedWorkshopRows(infra.runtime, ids);
  const nonCtf = await seed.seedNonCtfServiceRows(infra.runtime, ids);
  const shop = {
    target: await shopSupport.seedSecureShopOwner({ identity: infra.runtime.identity,
      secureshop: infra.runtime.secureshop,
      secureshop_agents: infra.runtime.secureshop_agents,
      secureshop_review: infra.runtime.secureshop_review }, {
      platformOwnerId: principals.target.id, platformSessionId: principals.target.sessionId,
    }),
    sibling: await shopSupport.seedSecureShopOwner({ identity: infra.runtime.identity,
      secureshop: infra.runtime.secureshop,
      secureshop_agents: infra.runtime.secureshop_agents,
      secureshop_review: infra.runtime.secureshop_review }, {
      platformOwnerId: principals.sibling.id, platformSessionId: principals.sibling.sessionId,
    }),
  };
  const shopPools = { identity: infra.runtime.identity, secureshop: infra.runtime.secureshop,
    secureshop_agents: infra.runtime.secureshop_agents,
    secureshop_review: infra.runtime.secureshop_review };
  const shopBefore = {
    target: await shopSupport.readSecureShopOwner(shopPools, shop.target),
    sibling: await shopSupport.readSecureShopOwner(shopPools, shop.sibling),
  };
  artifacts = await artifactSupport.seedDeletionArtifacts({ scopeRoot: admitted.runtime,
    pools: { identity: { runtime: infra.runtime.identity, migration: infra.migration.identity },
      finflow: { runtime: infra.runtime.finflow, migration: infra.migration.finflow } },
    target: principals.target, sibling: principals.sibling,
    ledger: infra.ledger, ragComposition: infra.rag, recordStage, signal,
  });
  const before = { workshop: workshop.snapshot, nonCtf: nonCtf.snapshot, ctf: ctfBefore,
    shop: shopBefore, artifacts: artifacts.before,
    identity: {
      target: await require('./adminStudentDeletionRenderedSupport')
        .readIdentityDeletionState(infra.runtime.identity, principals.target.id),
      sibling: await require('./adminStudentDeletionRenderedSupport')
        .readIdentityDeletionState(infra.runtime.identity, principals.sibling.id),
    } };
  assert.equal((await seed.readCodeBotAbsence(infra.runtime.identity, principals.target.id))
    .codeBotExecutionAbsent, true);
  const coveredStores = new Set([...workshop.supportedStores,
    ...nonCtf.supportedStores, 'ctf', 'identity', 'secureshop',
    'secureshop_agents', 'secureshop_review']);
  assert.deepEqual([...coveredStores].sort(), STORES.map(row => row.schema).sort(),
    'All sixteen stores require real scoped seed paths');
  return Object.freeze({ ids, ctf, registrations, shop, artifacts, before, coveredStores,
    seedProvenance: 'controlled-preexisting-lifecycle-data-not-model-or-judge-credit' });
  } catch (error) {
    throw await preserveFailedDeletionSeedJournal({ error, artifacts, ctf });
  }
}

async function preserveFailedDeletionSeedJournal({ error, artifacts, ctf }) {
  const journal = error?.artifactJournal || artifacts?.journal || null;
  const cleanup = [];
  const emptyOwnerCleanup = error?.cleanupEmptyOwnerDirs || artifacts?.cleanupEmptyOwnerDirs;
  if (typeof emptyOwnerCleanup === 'function') {
    try { await emptyOwnerCleanup(); } catch (failure) {
      cleanup.push({ label: 'empty-owner-cleanup', error: failure });
    }
  }
  if (ctf) {
    try { await ctf.close(); } catch (failure) { cleanup.push({ label: 'ctf-close', error: failure }); }
  }
  const outgoing = cleanup.length ? new AggregateError([error, ...cleanup.map(row => row.error)],
    'Deletion seed failed and owned cleanup did not complete') : error;
  if (cleanup.length) outgoing.failureLabels = ['primary', ...cleanup.map(row => row.label)];
  if (journal) outgoing.artifactJournal = journal;
  return outgoing;
}

async function assertDeletionOwnedEffects({ infra, principals, admitted, prepared, jobId }) {
  assert(UUID_V4.test(jobId || ''));
  assert.equal(admitted?.runtime, process.env.OWASP_AI_GOAT_APP_DATA_ROOT);
  assert.equal(prepared?.coveredStores?.size, 16);
  const seed = require('./adminStudentDeletionSeedSupport');
  const ctfSupport = require('./adminStudentDeletionCtfSupport');
  const shopSupport = require('./adminStudentDeletionSecureShopSupport');
  const artifactSupport = require('./adminStudentDeletionArtifactSupport');
  const support = require('./adminStudentDeletionRenderedSupport');
  const shopPools = { identity: infra.runtime.identity, secureshop: infra.runtime.secureshop,
    secureshop_agents: infra.runtime.secureshop_agents,
    secureshop_review: infra.runtime.secureshop_review };
  const after = {
    workshop: await seed.snapshotWorkshopRows(infra.runtime, prepared.ids),
    nonCtf: await seed.snapshotNonCtfServiceRows(infra.runtime, prepared.ids),
    ctf: {
      target: await ctfSupport.readDeletionCtfOwner({ identityPool: infra.runtime.identity,
        ctfPool: infra.runtime.ctf, registration: prepared.registrations.target }),
      sibling: await ctfSupport.readDeletionCtfOwner({ identityPool: infra.runtime.identity,
        ctfPool: infra.runtime.ctf, registration: prepared.registrations.sibling }),
    },
    shop: {
      target: await shopSupport.readSecureShopOwner(shopPools, prepared.shop.target),
      sibling: await shopSupport.readSecureShopOwner(shopPools, prepared.shop.sibling),
    },
    identity: {
      target: await support.readIdentityDeletionState(infra.runtime.identity, principals.target.id),
      sibling: await support.readIdentityDeletionState(infra.runtime.identity, principals.sibling.id),
    },
  };
  // The XSS fixture pool has completed its final authoritative workshop read.
  // Production owns a distinct XSS pool for its deletion composition, so this
  // exact two-slot fixture reservation can retire before migration readback.
  await infra.releaseCompletedWorkshopReadbackPool();
  after.artifacts = await infra.withArtifactReadback(migration => artifactSupport.readDeletionArtifacts({
    pools: { identity: { migration: migration.identity },
      finflow: { migration: migration.finflow } },
    refs: prepared.artifacts.refs, scopeRoot: admitted.runtime,
  }));
  const facts = {
    identity: support.assertIdentityDeletionComplete(after.identity.target, {
      subjectId: principals.target.id, jobId,
      siblingBefore: prepared.before.identity.sibling, siblingAfter: after.identity.sibling,
    }),
    workshop: seed.assertWorkshopRowsDeleted(prepared.before.workshop, after.workshop),
    nonCtf: seed.assertNonCtfServiceRowsDeleted(prepared.before.nonCtf, after.nonCtf),
    ctf: ctfSupport.assertDeletionCtf(prepared.before.ctf.target, after.ctf.target,
      prepared.before.ctf.sibling, after.ctf.sibling, { jobId }),
    shop: shopSupport.assertSecureShopDeletion(prepared.before.shop.target, after.shop.target,
      prepared.before.shop.sibling, after.shop.sibling),
    artifacts: artifactSupport.assertDeletionArtifacts(prepared.before.artifacts, after.artifacts),
  };
  assert.equal((await seed.readCodeBotAbsence(infra.runtime.identity, principals.target.id))
    .codeBotExecutionAbsent, true);
  return Object.freeze({ facts, coveredStores: [...prepared.coveredStores].sort(),
    canonicalCredit: false, nativeVerified: false });
}

async function assertDeletionStillUnchanged({ infra, principals, admitted, prepared }) {
  assert.equal(admitted?.runtime, process.env.OWASP_AI_GOAT_APP_DATA_ROOT);
  const seed = require('./adminStudentDeletionSeedSupport');
  const ctfSupport = require('./adminStudentDeletionCtfSupport');
  const shopSupport = require('./adminStudentDeletionSecureShopSupport');
  const artifactSupport = require('./adminStudentDeletionArtifactSupport');
  const support = require('./adminStudentDeletionRenderedSupport');
  assert.deepEqual(await seed.snapshotWorkshopRows(infra.runtime, prepared.ids),
    prepared.before.workshop);
  assert.deepEqual(await seed.snapshotNonCtfServiceRows(infra.runtime, prepared.ids),
    prepared.before.nonCtf);
  for (const key of ['target', 'sibling']) {
    assert.deepEqual(await ctfSupport.readDeletionCtfOwner({ identityPool: infra.runtime.identity,
      ctfPool: infra.runtime.ctf, registration: prepared.registrations[key] }),
    prepared.before.ctf[key]);
    assert.deepEqual(await shopSupport.readSecureShopOwner({ identity: infra.runtime.identity,
      secureshop: infra.runtime.secureshop, secureshop_agents: infra.runtime.secureshop_agents,
      secureshop_review: infra.runtime.secureshop_review }, prepared.shop[key]),
    prepared.before.shop[key]);
    assert.deepEqual(await support.readIdentityDeletionState(infra.runtime.identity,
      principals[key].id), prepared.before.identity[key]);
  }
  assert.deepEqual(await infra.withArtifactReadback(migration => artifactSupport.readDeletionArtifacts({
    pools: { identity: { migration: migration.identity },
      finflow: { migration: migration.finflow } },
    refs: prepared.artifacts.refs, scopeRoot: admitted.runtime,
  })), prepared.before.artifacts);
  return true;
}

async function openDeletionArtifactJournal(admitted) {
  assert.equal(admitted?.runtime, process.env.OWASP_AI_GOAT_APP_DATA_ROOT);
  const file = path.join(admitted.run, 'student-deletion-artifact-stages.jsonl');
  const handle = await fs.open(file, 'wx', 0o600);
  const directory = await fs.open(admitted.run, 'r');
  try { await directory.sync(); } finally { await directory.close(); }
  const allowed = new Set(['version', 'phase', 'kind', 'ownerId', 'family', 'slot',
    'documentId', 'operationId', 'artifactId', 'runId', 'generation', 'backupName',
    'backupId', 'targetToken', 'intentId', 'ownerDirectory', 'filePath', 'contentSha256',
    'backupRoot', 'traversalRoot', 'ownerKey']);
  let closed = false, entries = 0;
  return Object.freeze({ file, async recordStage(entry) {
    assert.equal(closed, false);
    assert(entry && typeof entry === 'object' && !Array.isArray(entry));
    assert.equal(entry.version, 1);
    assert(Object.keys(entry).every(key => allowed.has(key)), 'Unexpected artifact journal field');
    assert(typeof entry.phase === 'string' && typeof entry.kind === 'string');
    const bounded = { ...entry };
    if (bounded.targetToken !== undefined) {
      assert(typeof bounded.targetToken === 'string' && bounded.targetToken.length > 0);
      bounded.targetTokenSha256 = sha(bounded.targetToken);
      delete bounded.targetToken;
    }
    const line = Buffer.from(`${JSON.stringify(bounded)}\n`, 'utf8');
    assert(line.length <= 4096 && entries < 256, 'Artifact journal bound exceeded');
    let offset = 0;
    while (offset < line.length) {
      const result = await handle.write(line, offset, line.length - offset, null);
      assert(result.bytesWritten > 0, 'Artifact journal write incomplete');
      offset += result.bytesWritten;
    }
    await handle.sync();
    entries += 1;
  }, count: () => entries, async close() {
    if (!closed) { closed = true; await handle.sync(); await handle.close(); }
  } });
}

async function startDeletionRenderedServer({ infra, admitted, principals, production }) {
  assert.equal(typeof production?.application?.deleteStudent, 'function');
  assert.equal(infra?.adapter?.pool, infra?.runtime?.identity);
  const express = require('express');
  const session = require('express-session');
  const http = require('node:http');
  const adapter = infra.adapter;
  const auth = require('../../server/middleware/postgresAdminAuth').createPostgresAdminAuth(adapter);
  const manager = require('../../server/middleware/postgresSessionManager').createPostgresSessionManager(adapter);
  const progress = require('../../server/database/postgres/workshopProgressRepository')
    .createWorkshopProgressRepository(infra.runtime.identity);
  const config = require('../../server/database/postgres/workshopConfigRepository')
    .createWorkshopConfigRepository(infra.runtime.identity);
  const repository = require('../../server/database/postgres/adminRepository')
    .createPostgresAdminRepository(infra.runtime.identity);
  const targetEndpoint = `/api/admin/students/${principals.target.id}`;
  const received = [];
  const acknowledgements = [];
  const app = express();
  app.disable('x-powered-by');
  app.use(express.json());
  app.use((request, response, next) => {
    if (request.method !== 'DELETE' || !/^\/api\/admin\/students\/[1-9]\d*$/.test(request.path))
      return next();
    received.push(request.path);
    if (request.path === targetEndpoint)
      observeDeletionAck(response, targetEndpoint, result => acknowledgements.push(result));
    next();
  });
  app.use(session({ secret: 'owned-student-deletion-rendered-session-secret',
    resave: false, saveUninitialized: false }));
  app.use(manager.middleware());
  const pass = (_request, _response, next) => next();
  const authRouter = require('../../server/routes/postgresAuth').createPostgresAuthRouter({
    adapter, limiters: { loginRateLimiter: pass, registerRateLimiter: pass,
      passwordResetRateLimiter: pass },
  });
  let server;
  try {
  app.use('/api/auth', authRouter);
  app.use('/api/workshop/config', require('../../server/routes/workshopConfig')
    .createWorkshopConfigRouter(config));
  const unavailable = (_request, response) => response.status(503)
    .json({ error: 'Outside bounded student deletion qualification' });
  const operational = Object.fromEntries(['providerStatus', 'switchProvider', 'configureProvider',
    'testProvider', 'testLlm', 'appLogs', 'llmLogs', 'logStats',
    'systemMonitoring'].map(key => [key, unavailable]));
  app.use('/api/admin', require('../../server/routes/postgresAdmin').createPostgresAdminRouter({
    adapter, stores: { pool: infra.runtime.identity, progress, config }, auth, repository,
    operational, resetService: { resetAll: unavailable, resetStudent: unavailable,
      resetAdministrativeStudent: unavailable, resetWorkshop: unavailable },
    deletionService: production.application,
  }));
  app.use(express.static(admitted.buildDirectory, { index: false }));
  app.get(/.*/, (_request, response) => response.sendFile('index.html',
    { root: admitted.buildDirectory }));
  server = http.createServer(app);
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  const base = `http://127.0.0.1:${server.address().port}`;
  return Object.freeze({ base, server, targetEndpoint,
    witness: () => ({ received: received.length,
      exact: received.filter(pathname => pathname === targetEndpoint).length,
      unexpected: received.filter(pathname => pathname !== targetEndpoint).length,
      validAcknowledgements: acknowledgements.filter(row => row.valid).length,
      invalidAcknowledgements: acknowledgements.filter(row => !row.valid).length,
      acknowledgedJobId: acknowledgements.find(row => row.valid)?.fact.jobId || null }),
    close: () => closeDeletionRenderedServer(server, authRouter) });
  } catch (error) {
    try { await closeDeletionRenderedServer(server, authRouter); }
    catch (cleanup) { throw new AggregateError([error, cleanup],
      'Student deletion HTTP startup and auth cleanup failed'); }
    throw error;
  }
}

async function closeDeletionRenderedServer(server, authRouter,
  closeServer = value => require('./adminQ05RenderedScenario').closeQ05OwnedServer(value)) {
  assert.equal(typeof authRouter?.close, 'function');
  const results = await Promise.allSettled([
    Promise.resolve().then(() => closeServer(server)),
    Promise.resolve().then(() => authRouter.close()),
  ]);
  const failures = results.filter(row => row.status === 'rejected').map(row => row.reason);
  if (failures.length) throw new AggregateError(failures,
    'Student deletion HTTP server or production login runtime did not close');
  return true;
}

async function openDeletionResourceJournal(admitted) {
  const file = process.env.STUDENT_DELETION_RESOURCE_JOURNAL;
  assert.equal(file, path.join(admitted.temp, 'student-deletion-resources.json'));
  const payload = { version: 1, cohort: COHORT, status: 'admitted',
    resources: { browser: null, server: null } };
  const persist = async () => {
    const temporary = `${file}.tmp-${process.pid}`;
    const handle = await fs.open(temporary, 'wx', 0o600);
    try { await handle.writeFile(`${JSON.stringify(payload)}\n`); await handle.sync(); }
    finally { await handle.close(); }
    await fs.rename(temporary, file);
    const directory = await fs.open(admitted.temp, 'r');
    try { await directory.sync(); } finally { await directory.close(); }
  };
  await persist();
  return Object.freeze({
    async reserveBrowserProfile() {
      assert.equal(payload.resources.browser, null);
      payload.resources.browser = { pid: null, profile: admitted.profile,
        executable: process.env.OWASP_AI_GOAT_CHROMIUM_ACTUAL_EXECUTABLE };
      payload.status = 'browser_profile_reserved';
      await persist();
    },
    async server(port) {
      assert(Number.isSafeInteger(port) && port > 0 && port <= 65535);
      payload.resources.server = { address: '127.0.0.1', port };
      payload.status = 'server_listening';
      await persist();
    },
    async browser(pid) {
      assert(Number.isSafeInteger(pid) && pid > 0);
      assert.deepEqual(payload.resources.browser, { pid: null, profile: admitted.profile,
        executable: process.env.OWASP_AI_GOAT_CHROMIUM_ACTUAL_EXECUTABLE });
      payload.resources.browser = { pid, profile: admitted.profile,
        executable: process.env.OWASP_AI_GOAT_CHROMIUM_ACTUAL_EXECUTABLE };
      payload.status = 'browser_launched';
      await persist();
    },
    async status(value) {
      assert(['browser_acknowledged', 'running', 'failed',
        'browser_cleanup_delegated_to_current_host_launcher'].includes(value));
      payload.status = value;
      await persist();
    },
  });
}

async function launchDeletionBrowser({ admitted, base, resources }) {
  assert.equal(typeof resources?.browser, 'function');
  assert.equal(typeof resources?.reserveBrowserProfile, 'function');
  assert.equal(new URL(base).hostname, '127.0.0.1');
  await resources.reserveBrowserProfile();
  await fs.mkdir(admitted.profile, { mode: 0o700 });
  const profile = await fs.lstat(admitted.profile);
  assert(profile.isDirectory() && !profile.isSymbolicLink()
    && profile.uid === process.getuid() && (profile.mode & 0o077) === 0);
  assert.equal(await fs.realpath(admitted.profile), admitted.profile);
  const browser = await require('puppeteer').launch({ headless: true, pipe: true,
    userDataDir: admitted.profile,
    executablePath: process.env.PUPPETEER_EXECUTABLE_PATH,
    args: [
      '--no-sandbox', '--disable-background-networking', '--disable-component-update',
      '--disable-domain-reliability', '--disable-quic',
      '--force-webrtc-ip-handling-policy=disable_non_proxied_udp',
      '--proxy-server=http://blocked.invalid:9',
      '--proxy-bypass-list=127.0.0.1;localhost;[::1]',
      '--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1, EXCLUDE localhost, EXCLUDE [::1]',
    ],
    handleSIGINT: false, handleSIGTERM: false, handleSIGHUP: false,
  });
  const pid = browser.process()?.pid;
  try {
    await resources.browser(pid); // Durable owner record precedes launcher birth ACK.
    await admitted.awaitBrowserAck(pid); // No page exists before this ACK.
    await resources.status('browser_acknowledged');
    const unexpected = [];
    const targets = require('./adminQ05RenderedScenario').q05PageTargets(target => {
      unexpected.push(target.type());
      if (target.type() === 'page') void target.page().then(page => page?.close()).catch(() => {});
      else void browser.disconnect().catch(() => {});
    });
    browser.on('targetcreated', target => targets.observe(target));
    const guardedPage = async page => {
      await page.setRequestInterception(true);
      page.on('request', request => {
        let allowed = false;
        try {
          const url = new URL(request.url());
          allowed = url.origin === base || url.protocol === 'data:';
        } catch { /* Fail closed on malformed URLs. */ }
        void (allowed ? request.continue() : request.abort('blockedbyclient'))
          .catch(() => { unexpected.push('request-disposition'); });
        if (!allowed) unexpected.push('foreign-origin');
      });
    };
    const page = await browser.newPage();
    assert(targets.mainIs(page.target()), 'Exact admitted main page required');
    await guardedPage(page);
    let auxiliary = null;
    return Object.freeze({ browser, page, pid,
      async openAuthorityTab() {
        assert(!auxiliary, 'Only one actual auxiliary tab may exist');
        targets.armAuxiliary();
        let tab;
        try {
          tab = await browser.newPage();
          assert(targets.auxiliaryIs(tab.target()));
          assert(['about:blank', ''].includes(tab.url()));
          await guardedPage(tab);
          await tab.goto(`${base}/api/auth/status`, { waitUntil: 'domcontentloaded' });
          assert.equal(new URL(tab.url()).origin, base);
          auxiliary = tab;
          return Object.freeze({ async swap(tokenA, tokenB) {
            assert.equal(auxiliary, tab);
            assert(typeof tokenA === 'string' && tokenA !== tokenB && typeof tokenB === 'string');
            await tab.evaluate(([a, b]) => {
              localStorage.setItem('token', b);
              localStorage.setItem('token', a);
            }, [tokenA, tokenB]);
          }, async close() {
            if (auxiliary === tab) {
              auxiliary = null;
              const target = tab.target();
              try { await tab.close(); } finally { targets.closeAuxiliary(target); }
            }
          } });
        } catch (error) {
          targets.disarmAuxiliary();
          if (tab) { try { await tab.close(); } finally { targets.closeAuxiliary(tab.target()); } }
          throw error;
        }
      },
      assertNoUnexpected() { assert.deepEqual(unexpected, []); },
      async disconnect() {
        if (auxiliary) {
          const target = auxiliary.target();
          try { await auxiliary.close(); } finally { targets.closeAuxiliary(target); auxiliary = null; }
        }
        await browser.disconnect();
        await resources.status('browser_cleanup_delegated_to_current_host_launcher');
      },
    });
  } catch (error) {
    await browser.disconnect().catch(() => {});
    throw error;
  }
}

async function runPhysicalDeletion({ browser, server, infra, principals, prepared, admitted,
  phase = async () => {} }) {
  const { page } = browser;
  const { base, targetEndpoint } = server;
  const requestWitness = witnessDeletionRequests(page, base, targetEndpoint);
  let loss, held, heldSettled = false;
  try {
    await phase('student-deletion-rendered-login');
    await page.goto(`${base}/workshop-login`, { waitUntil: 'networkidle0' });
    await page.type('input[placeholder="Enter your username"]', principals.actor.username);
    await page.type('input[placeholder="Enter your password"]', principals.actor.password);
    const loginWait = page.waitForResponse(response =>
      response.request().method() === 'POST'
      && new URL(response.url()).pathname === '/api/auth/login');
    await page.click('button[type="submit"]');
    const login = await loginWait;
    assert.equal(login.status(), 200);
    const mountedToken = (await login.json()).token;
    assert.equal(typeof mountedToken, 'string');
    assert.notEqual(mountedToken, principals.actor.alternateToken);
    const mounted = await infra.adapter.validateSession(mountedToken);
    assert.equal(mounted?.user?.id, principals.actor.id);
    assert(Number.isSafeInteger(mounted?.session?.id) && mounted.session.id > 0);
    await page.waitForFunction(() => location.pathname.startsWith('/admin'), { timeout: 15000 });
    await page.goto(`${base}/admin/students`, { waitUntil: 'networkidle0' });
    const actorBefore = await require('./adminStudentDeletionRenderedSupport')
      .readIdentityDeletionState(infra.runtime.identity, principals.actor.id);
    assert.equal(actorBefore.jobs.length, 0);
    assert(actorBefore.sessions.some(row => row.id === mounted.session.id && row.is_active === 1));

    await phase('student-deletion-physical-cancel');
    await physicalOpenDeleteStudent(page, principals.target.username);
    await physicalArmDeleteDialog(page);
    await physicalDeleteDialogAction(page, 'Cancel');
    assert.deepEqual(requestWitness.snapshot(), {
      requests: 0, failed: 0, finished: 0, unexpected: 0 });
    assert.deepEqual(server.witness(), { received: 0, exact: 0, unexpected: 0,
      validAcknowledgements: 0, invalidAcknowledgements: 0, acknowledgedJobId: null });
    await assertDeletionStillUnchanged({ infra, principals, admitted, prepared });

    await phase('student-deletion-dialog-storage-aba');
    await physicalOpenDeleteStudent(page, principals.target.username);
    await physicalArmDeleteDialog(page);
    await page.evaluate(() => {
      window.__studentDeletionStorageEvents = 0;
      window.addEventListener('storage', event => {
        if (event.key === 'token') window.__studentDeletionStorageEvents += 1;
      });
    });
    const stale = await page.evaluateHandle(() => {
      const headings = [...document.querySelectorAll('h2')]
        .filter(node => node.textContent.trim() === 'Delete Student');
      if (headings.length !== 1) return null;
      const controls = [...(headings[0].parentElement?.parentElement?.querySelectorAll('button') || [])]
        .filter(button => button.textContent.trim() === 'Delete Student');
      return controls.length === 1 ? controls[0] : null;
    });
    const staleButton = stale.asElement();
    assert(staleButton, 'Staged rendered confirmation must exist before cross-tab authority change');
    assert.equal(await staleButton.evaluate(button => !button.disabled
      && button.textContent.trim() === 'Delete Student'), true,
    'The original physically armed confirmation must be actionable before ABA');
    const authorityTab = await browser.openAuthorityTab();
    let eventsObserved;
    try {
      await authorityTab.swap(mountedToken, principals.actor.alternateToken);
      await require('./adminQ05RenderedScenario').focusQ05MainPage(page);
      try { await staleButton.click(); }
      catch (error) {
        const retired = await page.evaluate(() =>
          ![...document.querySelectorAll('h2')]
            .some(node => node.textContent.trim() === 'Delete Student'));
        if (!retired) throw error;
      }
      await page.waitForFunction(() => window.__studentDeletionStorageEvents >= 2,
        { timeout: 15000 });
      eventsObserved = await page.evaluate(() => window.__studentDeletionStorageEvents);
      assert.equal(eventsObserved, 2);
      await page.waitForFunction(() => ![...document.querySelectorAll('h2')]
        .some(node => node.textContent.trim() === 'Delete Student'), { timeout: 15000 });
    } finally { await stale.dispose(); await authorityTab.close(); }
    assert.deepEqual(requestWitness.snapshot(), {
      requests: 0, failed: 0, finished: 0, unexpected: 0 });
    assert.equal(server.witness().received, 0);
    await assertDeletionStillUnchanged({ infra, principals, admitted, prepared });

    await phase('student-deletion-confirmed-response-stage-loss');
    await page.goto(`${base}/admin/students`, { waitUntil: 'networkidle0' });
    await physicalOpenDeleteStudent(page, principals.target.username);
    loss = await installDeletionBrowserLoss(page, base, targetEndpoint, () => {
      const observed = server.witness();
      return observed.validAcknowledgements === 1 ? {
        status: 200, jobId: observed.acknowledgedJobId,
        serverAcknowledgedCompleted: true } : null;
    });
    held = require('./adminStudentDeletionArtifactSupport').startHeldTargetLease({
      ledger: infra.ledger, targetId: principals.target.id, timeoutMs: 30000,
    });
    const activeRun = await held.started;
    assert.equal(activeRun.ownerKey, JSON.stringify(['MCP', String(principals.target.id)]));
    await physicalDeleteDialogAction(page, 'Delete Student', {
      typeDelete: true, clickCount: 2 });
    let blockedJobId = null, advancedGeneration = null;
    const blockDeadline = Date.now() + 8000;
    while ((!blockedJobId || !advancedGeneration) && Date.now() < blockDeadline) {
      const rows = (await infra.runtime.identity.query(`SELECT job_id FROM identity.student_deletion_run_blocks
        WHERE owner_key=$1`, [activeRun.ownerKey])).rows;
      assert(rows.length <= 1);
      blockedJobId = rows[0]?.job_id || null;
      const owner = (await infra.runtime.identity.query(`SELECT generation::text AS generation
        FROM graph_runtime.owners WHERE owner_key=$1`, [activeRun.ownerKey])).rows;
      assert.equal(owner.length, 1);
      if (BigInt(owner[0].generation) > BigInt(activeRun.generation))
        advancedGeneration = owner[0].generation;
      if (!blockedJobId || !advancedGeneration) await delay(25);
    }
    assert(UUID_V4.test(blockedJobId || ''), 'Genuine deletion must fence the held target MCP run');
    assert(advancedGeneration, 'The canonical MCP generation must advance before run release');
    held.release();
    const runOutcome = await held.settled;
    heldSettled = true;
    assertHeldDeletionFence({ before: activeRun.generation, after: advancedGeneration,
      error: runOutcome.error });
    await page.waitForFunction(() => document.body.innerText.includes(
      'Deletion result could not be confirmed.'), { timeout: 15000 });
    assert.deepEqual(requestWitness.snapshot(), {
      requests: 1, failed: 1, finished: 0, unexpected: 0 });
    assert.deepEqual(loss.snapshot(), { selected: true, failed: 1, failure: false });
    const serverFact = server.witness();
    assert.deepEqual({ received: serverFact.received, exact: serverFact.exact,
      unexpected: serverFact.unexpected, validAcknowledgements: serverFact.validAcknowledgements,
      invalidAcknowledgements: serverFact.invalidAcknowledgements }, {
      received: 1, exact: 1, unexpected: 0,
      validAcknowledgements: 1, invalidAcknowledgements: 0,
    });
    assert(UUID_V4.test(serverFact.acknowledgedJobId));
    assert.equal(serverFact.acknowledgedJobId, blockedJobId);
    await delay(250);
    assert.equal(requestWitness.snapshot().requests, 1,
      'Unknown UI outcome must not automatically submit another DELETE');
    assert.equal(server.witness().received, 1);
    const effects = await assertDeletionOwnedEffects({ infra, principals, admitted,
      prepared, jobId: serverFact.acknowledgedJobId });
    const actorAfter = await require('./adminStudentDeletionRenderedSupport')
      .readIdentityDeletionState(infra.runtime.identity, principals.actor.id);
    assert.deepEqual(actorAfter, actorBefore, 'Real deletion must preserve its authorizing administrator');
    browser.assertNoUnexpected();
    await loss.close();
    loss = null;
    await page.close(); // Retire the mounted page before final request counts.
    const finalBrowser = requestWitness.snapshot();
    assert.deepEqual(finalBrowser, {
      requests: 1, failed: 1, finished: 0, unexpected: 0 });
    const finalServer = server.witness();
    assert.equal(finalServer.received, 1);
    assert.equal(finalServer.exact, 1);
    assert.equal(finalServer.unexpected, 0);
    return Object.freeze({ version: 1, targetId: principals.target.id,
      siblingId: principals.sibling.id, actorId: principals.actor.id,
      mountedActorSessionId: mounted.session.id, jobId: serverFact.acknowledgedJobId,
      cancelNoRequest: true, storageAbaEventsObserved: eventsObserved,
      storageAbaNoRequest: true, realHttp200BeforeBrowserLoss: true,
      unknownUiNoAutomaticRetry: true, browserResponseFailed: true,
      heldRunFenced: true,
      actorUnchanged: true,
      heldRunGenerations: { before: activeRun.generation, after: advancedGeneration },
      pageRetiredBeforeFinalCounts: true,
      requestCounts: { browserDelete: finalBrowser.requests, serverDelete: finalServer.received,
        unexpectedDelete: finalBrowser.unexpected + finalServer.unexpected },
      effects });
  } finally {
    if (held && !heldSettled) { held.release(); await held.settled; }
    requestWitness.stop();
    if (loss) await loss.close();
  }
}

async function installDeletionBrowserLoss(page, base, endpoint, serverValidated) {
  assert.equal(new URL(base).hostname, '127.0.0.1');
  assert(/^\/api\/admin\/students\/[1-9]\d*$/.test(endpoint));
  assert.equal(typeof serverValidated, 'function');
  const client = await page.createCDPSession();
  const tasks = new Set();
  let selected = false, failed = 0, error = null;
  const onPaused = event => {
    const chosen = !selected && event?.request?.method === 'DELETE'
      && event.request.url === `${base}${endpoint}`;
    if (chosen) selected = true;
    const task = (async () => {
      if (!chosen) return client.send('Fetch.continueRequest', { requestId: event.requestId });
      deletionResponseIdentity(event, base, endpoint);
      const deadline = Date.now() + 2000;
      let validated = serverValidated();
      while (!validated && Date.now() < deadline) {
        await delay(10); validated = serverValidated();
      }
      assert.equal(validated?.status, 200);
      assert.equal(validated?.serverAcknowledgedCompleted, true);
      assert(UUID_V4.test(validated.jobId));
      await client.send('Fetch.failRequest', { requestId: event.requestId, errorReason: 'Failed' });
      failed += 1;
    })().catch(async cause => {
      error ||= cause;
      await client.send('Fetch.continueRequest', { requestId: event.requestId }).catch(() => {});
    });
    tasks.add(task); void task.finally(() => tasks.delete(task));
  };
  client.on('Fetch.requestPaused', onPaused);
  try { await client.send('Fetch.enable', { patterns: [{ urlPattern: `${base}${endpoint}`, requestStage: 'Response' }] }); }
  catch (error) { client.off('Fetch.requestPaused', onPaused); await client.detach(); throw error; }
  return { snapshot: () => ({ selected, failed, failure: Boolean(error) }), async close() {
    try { await client.send('Fetch.disable'); await Promise.all([...tasks]); }
    finally { client.off('Fetch.requestPaused', onPaused); await client.detach(); }
    if (error) throw error;
  } };
}

async function physicalDeleteDialogAction(page, label, { typeDelete = false, clickCount = 1 } = {}) {
  assert(['Cancel', 'Delete Student'].includes(label));
  await focusQ05MainPage(page);
  if (typeDelete) {
    assert.equal(label, 'Delete Student');
    await physicalArmDeleteDialog(page);
  }
  const handle = await page.evaluateHandle(text => {
    const headings = [...document.querySelectorAll('h2')]
      .filter(node => node.textContent.trim() === 'Delete Student');
    if (headings.length !== 1) return null;
    const content = headings[0].parentElement?.parentElement;
    const controls = [...(content?.querySelectorAll('button') || [])]
      .filter(button => button.textContent.trim() === text && !button.disabled);
    return controls.length === 1 ? controls[0] : null;
  }, label);
  const control = handle.asElement();
  try {
    assert(control, `One enabled physical ${label} control required`);
    await control.click({ clickCount });
  } finally { await handle.dispose(); }
  if (label === 'Cancel') await waitForDeletionDialogGone(page);
}

async function waitForDeletionDialogGone(page) {
  const gone = await page.waitForFunction(() => ![...document.querySelectorAll('h2')]
    .some(node => node.textContent.trim() === 'Delete Student'),
  { timeout: 10000, polling: 'raf' });
  await gone.dispose();
}

async function waitForDeletionInputReady(page) {
  const present = await page.waitForFunction(() => {
    const headings = [...document.querySelectorAll('h2')]
      .filter(node => node.textContent.trim() === 'Delete Student');
    return headings.length === 1
      && !!headings[0].parentElement?.parentElement?.querySelector('#delete-confirmation');
  }, { timeout: 10000, polling: 'raf' });
  await present.dispose();
  const handle = await page.evaluateHandle(() => {
    const headings = [...document.querySelectorAll('h2')]
      .filter(node => node.textContent.trim() === 'Delete Student');
    return headings.length === 1
      ? headings[0].parentElement?.parentElement?.querySelector('#delete-confirmation') || null
      : null;
  });
  try {
    const input = handle.asElement();
    assert(input, 'One exact deletion input must exist before physical scrolling');
    await input.evaluate(element => element.scrollIntoView({ block: 'center', inline: 'center' }));
  } finally { await handle.dispose(); }
  const ready = await page.waitForFunction(async () => {
    const headings = [...document.querySelectorAll('h2')]
      .filter(node => node.textContent.trim() === 'Delete Student');
    if (headings.length !== 1) return false;
    const content = headings[0].parentElement?.parentElement;
    const input = content?.querySelector('#delete-confirmation');
    if (!input?.isConnected || input.disabled) return false;
    for (let node = input; node && node.nodeType === 1; node = node.parentElement) {
      const style = getComputedStyle(node);
      if (style.display === 'none' || style.visibility !== 'visible'
        || style.pointerEvents === 'none' || Number(style.opacity) < 0.99) return false;
    }
    const first = input.getBoundingClientRect();
    if (first.width <= 0 || first.height <= 0) return false;
    await new Promise(resolve => requestAnimationFrame(resolve));
    if (!input.isConnected) return false;
    const second = input.getBoundingClientRect();
    if (Math.abs(second.x - first.x) > 0.2 || Math.abs(second.y - first.y) > 0.2
      || Math.abs(second.width - first.width) > 0.2
      || Math.abs(second.height - first.height) > 0.2) return false;
    const x = second.left + second.width / 2;
    const y = second.top + second.height / 2;
    return x >= 0 && x < innerWidth && y >= 0 && y < innerHeight
      && document.elementFromPoint(x, y) === input;
  }, { timeout: 10000, polling: 'raf' });
  await ready.dispose();
}

async function physicalArmDeleteDialog(page) {
  await focusQ05MainPage(page);
  await waitForDeletionInputReady(page);
  const inputHandle = await page.evaluateHandle(() => {
    const headings = [...document.querySelectorAll('h2')]
      .filter(node => node.textContent.trim() === 'Delete Student');
    return headings.length === 1
      ? headings[0].parentElement?.parentElement?.querySelector('#delete-confirmation') || null
      : null;
  });
  const input = inputHandle.asElement();
  try {
    assert(input, 'The exact deletion confirmation input must be present');
    await input.click();
    await input.type('DELETE');
    assert.equal(await input.evaluate(element => element.value), 'DELETE');
  } finally { await inputHandle.dispose(); }
}

async function physicalOpenDeleteStudent(page, exactUsername) {
  assert(typeof exactUsername === 'string' && exactUsername.length > 0 && exactUsername.length <= 100);
  await focusQ05MainPage(page);
  await renderedRowAction(page, exactUsername, 'Delete');
  const dialog = await page.waitForFunction(username => {
    const headings = [...document.querySelectorAll('h2')]
      .filter(node => node.textContent.trim() === 'Delete Student');
    if (headings.length !== 1) return false;
    const content = headings[0].parentElement?.parentElement;
    const cells = [...(content?.querySelectorAll('p') || [])];
    return cells.some(node => node.textContent.includes('Username:')
      && node.textContent.includes(username));
  }, { timeout: 10000 }, exactUsername);
  await dialog.dispose();
  await waitForDeletionInputReady(page);
}

async function writeDeletionEvidence(admitted, value) {
  assert.equal(path.basename(admitted.evidence), 'student-deletion-evidence.json');
  const data = Buffer.from(`${JSON.stringify(value)}\n`, 'utf8');
  assert(data.length <= 32768, 'Bounded deletion evidence required');
  const file = `${admitted.evidence}.tmp-${process.pid}`;
  let created = false;
  try {
    const handle = await fs.open(file, 'wx', 0o600);
    created = true;
    try { await handle.writeFile(data); await handle.sync(); }
    finally { await handle.close(); }
    await fs.rename(file, admitted.evidence);
  } catch (error) {
    if (created) await fs.unlink(file).catch(cleanupError => {
      if (cleanupError.code !== 'ENOENT') throw new AggregateError([error, cleanupError],
        'Bounded deletion evidence and temporary cleanup failed');
    });
    throw error;
  }
  const directory = await fs.open(admitted.run, 'r');
  try { await directory.sync(); } finally { await directory.close(); }
}

async function cleanupDeletionManagedUploads({ prepared, principals, successful,
  root = REPO }) {
  assert.equal(typeof successful, 'boolean');
  assert(prepared?.artifacts?.refs?.target && prepared.artifacts.refs.sibling);
  const managed = path.join(root, 'server/uploads/managed');
  const ancestors = [root, path.join(root, 'server'), path.join(root, 'server/uploads'), managed];
  for (const directory of ancestors) {
    const info = await fs.lstat(directory);
    assert(info.isDirectory() && !info.isSymbolicLink() && info.uid === process.getuid());
    assert.equal(await fs.realpath(directory), directory);
  }
  const result = {};
  for (const label of ['target', 'sibling']) {
    const principal = principals[label], ref = prepared.artifacts.refs[label];
    assert.equal(ref.ownerId, principal.id);
    assert(UUID_V4.test(ref.legacyUpload.intentId || ''));
    assert(SHA256.test(ref.legacyUpload.contentSha256 || ''));
    const ownerDirectory = path.join(managed, String(principal.id));
    const intentDirectory = path.join(ownerDirectory, ref.legacyUpload.intentId);
    const filePath = path.join(intentDirectory, 'deletion-owned.txt');
    let filePresent = false;
    for (const directory of [ownerDirectory, intentDirectory]) {
      let info;
      try { info = await fs.lstat(directory); }
      catch (error) { if (error.code === 'ENOENT') break; throw error; }
      assert(info.isDirectory() && !info.isSymbolicLink() && info.uid === process.getuid());
      assert.equal(await fs.realpath(directory), directory);
    }
    try {
      const info = await fs.lstat(filePath);
      assert(info.isFile() && !info.isSymbolicLink() && info.nlink === 1
        && info.uid === process.getuid() && info.size > 0 && info.size <= 4096);
      const content = await fs.readFile(filePath);
      assert.equal(sha(content), ref.legacyUpload.contentSha256);
      filePresent = true;
    } catch (error) { if (error.code !== 'ENOENT') throw error; }
    if (successful) assert.equal(filePresent, label === 'sibling',
      'Real deletion must remove only the target managed upload before fixture cleanup');
    let intentPresent = false;
    for (const directory of [intentDirectory, ownerDirectory]) {
      let entries;
      try { entries = await fs.readdir(directory); }
      catch (error) { if (error.code === 'ENOENT') continue; throw error; }
      if (directory === intentDirectory) intentPresent = true;
      assert.deepEqual(entries.sort(), directory === intentDirectory
        ? (filePresent ? ['deletion-owned.txt'] : [])
        : (intentPresent ? [ref.legacyUpload.intentId] : []),
      'Fixture-owned upload directory must contain only its exact recorded artifact');
    }
    if (filePresent) await fs.unlink(filePath);
    for (const directory of [intentDirectory, ownerDirectory]) {
      try { await fs.rmdir(directory); }
      catch (error) { if (error.code !== 'ENOENT') throw error; }
    }
    for (const entry of [filePath, intentDirectory, ownerDirectory])
      await assert.rejects(fs.lstat(entry), { code: 'ENOENT' });
    result[label] = { ownerId: principal.id, filePath,
      observedBeforeFixtureCleanup: filePresent,
      exactFixtureArtifactsRemoved: true };
  }
  return Object.freeze(result);
}

async function cleanupPartialDeletionManagedUploads({ journal, principals, root = REPO }) {
  assert(Array.isArray(journal) && journal.length <= 256);
  assert(Number.isSafeInteger(principals?.target?.id) && Number.isSafeInteger(principals?.sibling?.id));
  const ids = new Set([principals.target.id, principals.sibling.id]);
  assert.equal(ids.size, 2);
  const reserved = journal.filter(row => row?.kind === 'legacyUpload' && row.phase === 'reserved');
  const admitted = journal.filter(row => row?.kind === 'legacyUpload' && row.phase === 'admitted');
  assert(reserved.length <= 2 && admitted.length <= 2);
  assert.equal(new Set(reserved.map(row => row.ownerId)).size, reserved.length);
  assert.equal(new Set(admitted.map(row => row.ownerId)).size, admitted.length);
  const managed = path.join(root, 'server/uploads/managed');
  for (const row of reserved) {
    assert.equal(row.version, 1);
    assert(ids.has(row.ownerId));
    assert.equal(row.ownerDirectory, path.join(managed, String(row.ownerId)));
  }
  for (const row of admitted) assert(reserved.some(item => item.ownerId === row.ownerId));
  if (!reserved.length) return Object.freeze({ reservedOwners: 0, admittedFiles: 0,
    removedFiles: 0, ownerDirsAbsent: true });
  const parents = [root, path.join(root, 'server'), path.join(root, 'server/uploads'), managed];
  for (let index = 0; index < parents.length; index += 1) {
    const directory = parents[index];
    let info;
    try { info = await fs.lstat(directory); }
    catch (error) {
      if (error.code !== 'ENOENT' || index === 0) throw error;
      assert.equal(admitted.length, 0,
        'An admitted managed upload requires its canonical ancestor to exist');
      return Object.freeze({ reservedOwners: reserved.length, admittedFiles: 0,
        removedFiles: 0, ownerDirsAbsent: true });
    }
    assert(info.isDirectory() && !info.isSymbolicLink() && info.uid === process.getuid());
    assert.equal(await fs.realpath(directory), directory);
  }
  let removedFiles = 0;
  for (const row of reserved) {
    const exact = admitted.find(item => item.ownerId === row.ownerId);
    const ownerDirectory = row.ownerDirectory;
    let intentDirectory = null;
    if (exact) {
      assert.equal(exact.version, 1);
      assert(UUID_V4.test(exact.intentId || '') && SHA256.test(exact.contentSha256 || ''));
      assert.equal(exact.ownerDirectory, ownerDirectory);
      intentDirectory = path.join(ownerDirectory, exact.intentId);
      assert.equal(exact.filePath, path.join(intentDirectory, 'deletion-owned.txt'));
    }
    for (const directory of [ownerDirectory, ...(intentDirectory ? [intentDirectory] : [])]) {
      let info;
      try { info = await fs.lstat(directory); }
      catch (error) { if (error.code === 'ENOENT') continue; throw error; }
      assert(info.isDirectory() && !info.isSymbolicLink() && info.uid === process.getuid());
      assert.equal(await fs.realpath(directory), directory);
    }
    if (exact) {
      let present = false;
      try {
        const info = await fs.lstat(exact.filePath);
        assert(info.isFile() && !info.isSymbolicLink() && info.nlink === 1
          && info.uid === process.getuid() && info.size > 0 && info.size <= 4096);
        assert.equal(sha(await fs.readFile(exact.filePath)), exact.contentSha256);
        present = true;
      } catch (error) { if (error.code !== 'ENOENT') throw error; }
      if (present) {
        assert.deepEqual(await fs.readdir(intentDirectory), ['deletion-owned.txt']);
        await fs.unlink(exact.filePath);
        removedFiles += 1;
      }
      try { await fs.rmdir(intentDirectory); }
      catch (error) { if (error.code !== 'ENOENT') throw error; }
    }
    try { await fs.rmdir(ownerDirectory); }
    catch (error) { if (error.code !== 'ENOENT') throw error; }
    await assert.rejects(fs.lstat(ownerDirectory), { code: 'ENOENT' });
  }
  return Object.freeze({ reservedOwners: reserved.length, admittedFiles: admitted.length,
    removedFiles, ownerDirsAbsent: true });
}

function boundedDeletionFailure(error, phase) {
  assert(typeof phase === 'string' && /^[a-z0-9-]{1,80}$/.test(phase));
  const nodes = [];
  const pending = [{ error, label: 'root', depth: 0 }];
  while (pending.length && nodes.length < 7) {
    const next = pending.shift();
    const current = next.error;
    const name = typeof current?.name === 'string' && /^[A-Za-z]{1,40}$/.test(current.name)
      ? current.name : 'Error';
    const code = typeof current?.code === 'string' && /^[A-Z_0-9]{1,40}$/.test(current.code)
      ? current.code : null;
    let frame = null;
    for (const line of String(current?.stack || '').split('\n').slice(0, 16)) {
      const offset = line.indexOf(`${REPO}${path.sep}`);
      if (offset < 0) continue;
      const match = line.slice(offset + REPO.length + 1).match(/^([A-Za-z0-9._/-]+):(\d{1,7}):(\d{1,7})/);
      if (!match || match[1].split('/').includes('..')
        || !/^(tests|server|db|client)\//.test(match[1])) continue;
      frame = { file: match[1], line: Number(match[2]), column: Number(match[3]) };
      break;
    }
    nodes.push({ label: next.label, name, code, frame });
    if (next.depth >= 2 || !Array.isArray(current?.errors)) continue;
    for (let index = 0; index < Math.min(current.errors.length, 4); index += 1) {
      const label = current.failureLabels?.[index];
      pending.push({ error: current.errors[index],
        label: typeof label === 'string' && /^[a-z0-9-]{1,40}$/.test(label)
          ? label : `cause-${index}`, depth: next.depth + 1 });
    }
  }
  return { phase, name: nodes[0].name, code: nodes[0].code,
    frame: nodes[0].frame, nested: nodes.slice(1) };
}

test('student deletion rendered current-host cohort performs one real scoped deletion', {
  skip: process.env.ADMIN_STUDENT_DELETION_CURRENT_HOST !== '1',
}, async t => {
  const admitted = await admitDeletionCurrentHost();
  const resources = await openDeletionResourceJournal(admitted);
  let phase = 'admitted';
  let infra, principals, artifactJournal, prepared, production, server, browser;
  let networkGuard, networkWitness;
  let uploadCleanup = null;
  let partialArtifactJournal = null;
  let primary = null, result = null;
  let initialFailureFact = null;
  const diagnostics = [];
  const advance = async value => {
    assert(/^[a-z0-9-]{1,80}$/.test(value));
    phase = value;
    t.diagnostic(`student deletion phase: ${value}`);
  };
  try {
    const postgresPort = Number(new URL(process.env.IDENTITY_DATABASE_URL).port);
    networkGuard = require('./adminStudentDeletionNetworkGuard')
      .installDeletionNetworkGuard({ postgresPort,
        chromium: process.env.OWASP_AI_GOAT_CHROMIUM_ACTUAL_EXECUTABLE });
    await advance('open-sixteen-owned-stores');
    infra = await openDeletionSeedInfrastructure();
    principals = await seedDeletionPrincipals({ adapter: infra.adapter,
      runtime: infra.runtime, migration: infra.migration,
      nonce: new URL(process.env.IDENTITY_DATABASE_URL).pathname
        .match(/deletion_([0-9a-f]{12})_identity$/)?.[1] });
    artifactJournal = await openDeletionArtifactJournal(admitted);
    await advance('seed-controlled-preexisting-lifecycles');
    prepared = await prepareDeletionOwnedState({ infra, principals, admitted,
      recordStage: artifactJournal.recordStage });
    assert.equal(prepared.coveredStores.size, 16);
    assert(artifactJournal.count() > 0, 'Artifact effects require durable pre-effect records');
    await advance('drain-seed-migration-pools');
    await infra.closeSeedMigrationPools();
    await advance('admit-production-seventeen-step-deletion');
    production = await require('./adminStudentDeletionRenderedSupport')
      .openProductionDeletionSupport();
    assert.equal(production.steps.length, 17);
    server = await startDeletionRenderedServer({ infra, admitted, principals, production });
    await resources.server(Number(new URL(server.base).port));
    await advance('admit-one-owned-browser');
    browser = await launchDeletionBrowser({ admitted, base: server.base, resources });
    await resources.status('running');
    const rendered = await runPhysicalDeletion({ browser, server, infra, principals,
      prepared, admitted, phase: advance });
    assert.equal(rendered.effects.coveredStores.length, 16);
    uploadCleanup = await cleanupDeletionManagedUploads({ prepared, principals,
      successful: true });
    result = { version: 1, cohort: COHORT,
      status: 'bounded-rendered-student-deletion-observed',
      seedProvenance: prepared.seedProvenance,
      targetId: rendered.targetId, siblingId: rendered.siblingId,
      actorId: rendered.actorId, mountedActorSessionId: rendered.mountedActorSessionId,
      jobId: rendered.jobId, cancelNoRequest: rendered.cancelNoRequest,
      storageAbaEventsObserved: rendered.storageAbaEventsObserved,
      storageAbaNoRequest: rendered.storageAbaNoRequest,
      realHttp200BeforeBrowserLoss: rendered.realHttp200BeforeBrowserLoss,
      unknownUiNoAutomaticRetry: rendered.unknownUiNoAutomaticRetry,
      browserResponseFailed: rendered.browserResponseFailed,
      heldRunFenced: rendered.heldRunFenced,
      actorUnchanged: rendered.actorUnchanged,
      heldRunGenerations: rendered.heldRunGenerations,
      pageRetiredBeforeFinalCounts: rendered.pageRetiredBeforeFinalCounts,
      requestCounts: rendered.requestCounts,
      coveredStores: rendered.effects.coveredStores,
      effects: rendered.effects.facts,
      controlledEmbeddingCalls: infra.controlledEmbedCalls(),
      artifactJournal: { path: artifactJournal.file, entryCount: artifactJournal.count() },
      managedUploads: uploadCleanup,
      canonicalCredit: false,
      excluded: ['model-grading', 'judge-credit', 'non-synthetic-users'],
    };
    assert.equal(result.controlledEmbeddingCalls > 0, true);
    await advance('rendered-facts-verified');
  } catch (error) {
    primary = error;
    partialArtifactJournal = error?.artifactJournal || null;
    initialFailureFact = boundedDeletionFailure(error, phase);
    try { await writeDeletionEvidence(admitted, { version: 1, cohort: COHORT,
      status: 'failed', failure: initialFailureFact }); }
    catch (failure) { diagnostics.push(failure); }
    try { await resources.status('failed'); }
    catch (failure) { diagnostics.push(failure); }
  } finally {
    const cleanup = diagnostics.map((error, index) => ({ name: `diagnostic-${index}`, error }));
    const close = async (name, work) => {
      try { await work(); } catch (error) { cleanup.push({ name, error }); }
    };
    if (browser) await close('browser-disconnect', () => browser.disconnect());
    if (server) await close('owned-http-server', () => server.close());
    if (production) await close('production-deletion', () => production.close());
    if (prepared?.ctf) await close('ctf-delivery', () => prepared.ctf.close());
    if (artifactJournal) await close('artifact-journal', () => artifactJournal.close());
    if (prepared && !uploadCleanup) await close('exact-managed-upload-cleanup', async () => {
      uploadCleanup = await cleanupDeletionManagedUploads({ prepared, principals,
        successful: false });
    });
    if (!prepared && partialArtifactJournal && principals) {
      await close('partial-managed-upload-cleanup', async () => {
        uploadCleanup = await cleanupPartialDeletionManagedUploads({
          journal: partialArtifactJournal, principals,
        });
      });
    }
    if (infra) await close('seed-pools', () => infra.closeOwnedPools());
    await close('postgres-pools', () => require('../../server/database/postgres').closePostgresPools());
    await close('pool-budget', () => require('./adminStudentDeletionRenderedSupport').assertPoolsDrained());
    if (networkGuard) {
      await close('network-witness', async () => { networkWitness = networkGuard.snapshot(); });
      // This isolated native worker retains the guard until process retirement.
      // Restoring it before TAP/outer cleanup would reopen an unobserved egress window.
    }
    if (cleanup.length) {
      const errors = cleanup.map(row => row.error);
      primary = primary ? new AggregateError([primary, ...errors],
        'Student deletion failed and owned cleanup did not complete')
        : new AggregateError(errors, 'Student deletion owned cleanup did not complete');
      primary.failureLabels = primary.errors.map((_, index) =>
        initialFailureFact && index === 0 ? 'primary' : cleanup[index - (initialFailureFact ? 1 : 0)]?.name || `cause-${index}`);
    }
  }
  if (primary) {
    if (initialFailureFact) {
      try { await writeDeletionEvidence(admitted, { version: 1, cohort: COHORT,
        status: 'failed', failure: initialFailureFact,
        artifactJournal: artifactJournal ? { path: artifactJournal.file,
          entryCount: artifactJournal.count() } : null,
        managedUploadCleanup: uploadCleanup,
        networkWitness: networkWitness || null }); }
      catch { /* Preserve the original failure and its earliest durable checkpoint. */ }
    }
    throw primary;
  }
  try {
    assert.equal(networkWitness?.active, true);
    assert.equal(networkWitness.intact, true);
    assert.equal(networkWitness.nonPostgresAttempts, 0);
    assert.equal(networkWitness.blockedAttempts, 0);
    assert.equal(networkWitness.chromeSpawnAttempts, 1);
    assert.equal(networkWitness.chromeSpawnsAllowed, 1);
    assert.equal(networkWitness.passwordWorkerPolicy, 'source-pinned-bcrypt-only-max-four-total');
    assert(Number.isSafeInteger(networkWitness.passwordWorkersStarted)
      && networkWitness.passwordWorkersStarted >= 1
      && networkWitness.passwordWorkersStarted <= 4);
    assert.equal(networkWitness.workerAttempts, networkWitness.passwordWorkersStarted);
    assert.equal(networkWitness.passwordWorkersExited, networkWitness.passwordWorkersStarted);
    assert.equal(networkWitness.passwordWorkersLive, 0,
      'The owned auth router must join all real bcrypt workers before final evidence');
    assert(networkWitness.postgresAttempts > 0);
    result.networkWitness = networkWitness;
    result.modelProviderAttemptsObserved = networkWitness.nonPostgresAttempts;
    result.judgeProviderAttemptsObserved = networkWitness.nonPostgresAttempts;
    await admitted.verifyBuild();
    await writeDeletionEvidence(admitted, result);
  } catch (error) {
    await writeDeletionEvidence(admitted, { version: 1, cohort: COHORT,
      status: 'failed', failure: boundedDeletionFailure(error, 'final-source-and-evidence') });
    throw error;
  }
});

module.exports = { COHORT, deletionStorePlanSha256, deletionPaths, validateDeletionGrant,
  admitDeletionCurrentHost, deletionAckFact, createDeletionAckCapture, observeDeletionAck,
  deletionResponseIdentity, installDeletionBrowserLoss, physicalDeleteDialogAction,
  physicalArmDeleteDialog, physicalOpenDeleteStudent, waitForDeletionInputReady,
  waitForDeletionDialogGone, witnessDeletionRequests,
  openDeletionSeedInfrastructure,
  seedDeletionPrincipals, deletionRequestFor, prepareDeletionOwnedState,
  assertDeletionOwnedEffects, openDeletionArtifactJournal, startDeletionRenderedServer,
  closeDeletionRenderedServer,
  openDeletionResourceJournal, launchDeletionBrowser, assertDeletionStillUnchanged,
  runPhysicalDeletion, boundedDeletionFailure, writeDeletionEvidence,
  cleanupDeletionManagedUploads, cleanupPartialDeletionManagedUploads,
  assertHeldDeletionFence, preserveFailedDeletionSeedJournal,
  assertDeletionSeedPoolKeys, releaseDeletionReadbackCapacity };
