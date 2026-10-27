'use strict';
// A separate two-store qualification. The established ten-content cohort and
// its 55 projection facts are not inputs to this destructive test.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const ROOT = path.resolve(__dirname, '../..');
const enabled = process.env.CTF_FULL_RESET_RENDERED_ISOLATED === '1';
const { assertTwoStoreEnvironment, seedFullResetPreactivation, externalFullResetSnapshot,
  launchFullResetBrowser, OWNER, SIBLING, ADMIN } = require('./support/ctfFullResetRenderedCohort');

if (enabled) {
  assert.equal(process.env.PG_TEST_DISPOSABLE, 'yes');
  assert.equal(process.env.CTF_FULL_RESET_SOURCE_ROOT, ROOT);
  const ports = new Set();
  for (const name of ['IDENTITY_DATABASE_URL', 'IDENTITY_MIGRATION_DATABASE_URL',
    'CTF_DATABASE_URL', 'CTF_MIGRATION_DATABASE_URL', 'CTF_DELIVERY_DATABASE_URL']) {
    const url = new URL(process.env[name]);
    assert.equal(url.hostname, '127.0.0.1');
    ports.add(Number(url.port));
  }
  require('./ctfStage9MainQualification').installSocketFence(ports);
  require('../fixtures/ownedBrowserCdpAllowance').install({
    browserExecutable: process.env.PUPPETEER_EXECUTABLE_PATH,
    ownedRoot: process.env.CTF_RENDERED_EVIDENCE,
    addEndpoint: endpoint => ports.add(endpoint.port),
    removeEndpoint: endpoint => ports.delete(endpoint.port) });
  global.__ctfFullResetOwnedPorts = ports;
}

const sha256 = value => crypto.createHash('sha256').update(value).digest('hex');
const one = async (pool, sql, args = []) => (await pool.query(sql, args)).rows[0];
async function boundedCloseServer(server) {
  if (!server) return;
  await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(Error('Owned Full Reset HTTP close deadline')), 5000);
    server.close(error => { clearTimeout(timer); error ? reject(error) : resolve(); });
    server.closeAllConnections();
  });
}
test('standalone current-host Full CTF Reset preserves retained and external state',
  { skip: !enabled, timeout: 180000 }, async () => {
    const inventory = assertTwoStoreEnvironment();
    const { createPool, closePostgresPools } = require('../../server/database/postgres');
    const { migrate } = require('../../db/postgres/migrate');
    const { randomUUID } = crypto;
    const pools = [];
    let application, mounted, server, browser, instructor, providerServer, finalizer;
    let primary;
    const ledger = [];
    const unexpectedApiPaths = [];
    const action = async fn => fn();
    try {
      const i = { runtime: createPool({ ...process.env, PG_POOL_MAX_WORKSHOP: '1' }, 'IDENTITY_DATABASE_URL'),
        migration: createPool({ ...process.env, PG_POOL_MAX_WORKSHOP: '1' }, 'IDENTITY_MIGRATION_DATABASE_URL') };
      const c = { runtime: createPool({ ...process.env, PG_POOL_MAX_WORKSHOP: '1' }, 'CTF_DATABASE_URL'),
        migration: createPool({ ...process.env, PG_POOL_MAX_WORKSHOP: '1' }, 'CTF_MIGRATION_DATABASE_URL') };
      pools.push(i.runtime, i.migration, c.runtime, c.migration);
      await migrate(i.migration, path.join(ROOT, 'db/postgres/identity-migrations'));
      await migrate(c.migration, path.join(ROOT, 'db/postgres/workshop-migrations/ctf'));
      assert.deepEqual(await migrate(i.migration, path.join(ROOT, 'db/postgres/identity-migrations')), []);
      assert.deepEqual(await migrate(c.migration, path.join(ROOT, 'db/postgres/workshop-migrations/ctf')), []);
      const seed = await seedFullResetPreactivation({ identity: i.migration, ctf: c.migration });
      assert.equal(seed.ownerId, OWNER); assert.equal(seed.siblingId, SIBLING);
      assert.equal(seed.adminId, ADMIN); assert.equal(seed.canonicalCredit, false);
      assert.equal(seed.modelCalls, 0); assert.equal(seed.judgeCalls, 0);
      const bootstrapOperationId = randomUUID();
      const repository = require('../../server/database/postgres/ctfAuthorityBootstrapRepository')
        .createCtfAuthorityBootstrapRepository({ identityPool: i.migration, ctfPool: c.migration });
      const prepared = await require('../../server/services/ctfAuthorityBootstrap')
        .createCtfAuthorityBootstrap({ repository }).prepare({ operationId: bootstrapOperationId });
      assert(prepared.prepared && !prepared.runtimeReady);
      const { createCtfDeliveryActivationOperator } =
        require('../../server/database/postgres/ctfDeliveryActivationOperator');
      const { createCtfDeliveryActivation } =
        require('../../server/database/postgres/ctfDeliveryActivation');
      const operator = createCtfDeliveryActivationOperator({ identityMigrationPool: i.migration,
        ctfMigrationPool: c.migration });
      const activationId = randomUUID();
      let activation = await operator.activate({ activationId, bootstrapOperationId, pageBudget: 1 });
      for (let n = 0; activation.staged && n < 16; n++)
        activation = await operator.activate({ activationId, bootstrapOperationId, pageBudget: 1 });
      assert(activation.activation && activation.trafficStarted === false);
      const { createCtfDeliveryPool } = require('../../server/database/postgres/ctfDeliveryPool');
      const delivery = await createCtfDeliveryPool({ env: process.env, activation: activation.activation });
      pools.push(delivery);
      await createCtfDeliveryActivation({ identityPool: i.runtime, ctfPool: c.runtime })
        .verify(activation.activation);
      assert.equal((await one(c.migration, 'SELECT initialized FROM ctf.projection_cursor')).initialized, true);
      assert.deepEqual((await i.migration.query(
        "SELECT kind FROM identity.ctf_adaptive_memory WHERE legacy_source=$1 ORDER BY kind",
        [`bootstrap:${bootstrapOperationId}`])).rows.map(row => row.kind), ['payload', 'technique']);
      assert.equal((await one(c.migration,
        "SELECT accepted,metadata FROM ctf.ctf_judgments WHERE run_id='controlled-historical-no-model-credit'")).accepted, 0);

      // A bounded local denial endpoint observes any attempted provider use;
      // outbound sockets elsewhere remain denied by the owned-port fence.
      const http = require('node:http');
      providerServer = http.createServer((_req, res) => {
        ledger.push({ category: 'unexpected-provider-attempt' });
        res.writeHead(503, { 'content-type': 'application/json' }); res.end('{"error":"unavailable"}');
      });
      await new Promise(resolve => providerServer.listen(0, '127.0.0.1', resolve));
      global.__ctfFullResetOwnedPorts.add(providerServer.address().port);
      const providerUrl = `http://127.0.0.1:${providerServer.address().port}`;
      for (const name of ['OLLAMA_BASE_URL', 'LMSTUDIO_BASE_URL']) process.env[name] = providerUrl;
      process.env.AI_PROVIDER = 'ollama'; process.env.JUDGE_PROVIDER = 'ollama';

      const jwtSecret = process.env.JWT_SECRET;
      assert(jwtSecret && jwtSecret.length >= 32);
      const identityRepo = require('../../server/database/postgres/identityRepository').createIdentityRepository(i.runtime);
      const adapter = require('../../server/services/postgresIdentityAdapter')
        .createPostgresIdentityAdapter({ repository: identityRepo, jwtSecret });
      const adminToken = require('jsonwebtoken').sign({ userId: ADMIN }, jwtSecret,
        { expiresIn: '1h', jwtid: randomUUID() });
      const adminSession = await one(i.migration,
        "INSERT INTO identity.user_sessions(user_id,session_token_hash,expires_at) VALUES($1,$2,clock_timestamp()+interval '1 hour') RETURNING id",
        [ADMIN, sha256(adminToken)]);
      const admin = { headers: { authorization: `Bearer ${adminToken}` },
        user: { id: ADMIN }, identitySession: { id: adminSession.id } };
      const leasePool = createPool({ ...process.env, PG_POOL_MAX_WORKSHOP: '2' }, 'IDENTITY_DATABASE_URL',
        { purpose: 'lease' }); pools.push(leasePool);
      const coordinator = require('../../server/agent-runtime/runCoordinator').createRunCoordinator({
        family: 'CTF', ledger: require('../../server/agent-runtime/postgresRunLedger')
          .createPostgresRunLedger(i.runtime, { leasePool }), defaultTimeoutMs: 10000 });
      application = require('../../server/services/ctfAuthorityApplication')
        .createCtfAuthorityApplication({ identityPool: i.runtime, ctfPool: c.runtime,
          deliveryPool: delivery, deliveryDatabaseUrl: process.env.CTF_DELIVERY_DATABASE_URL,
          activation: activation.activation, validateSession: adapter.validateSession,
          coordinator });
      await application.start();
      assert.equal((await application.runtime.readiness()).runtimeReady, true);
      const express = require('express'), web = express();
      const serverWitness = require('./support/ctfFullResetRenderedCases').createFullResetServerWitness();
      web.use(express.json({ limit: '32kb' })); web.use(serverWitness.middleware);
      web.use('/api/ctf', application.router);
      const stores = require('../../server/services/postgresPlatformStores').getPostgresPlatformStores();
      mounted = await require('../fixtures/legacyFileSsiFullAppParity').mountLegacyParityRoutes({
        app: web, adapter: require('../../server/services/postgresIdentityAdapter').getPostgresIdentityAdapter(),
        pool: i.runtime, migration: i.migration, progress: stores.progress,
        config: stores.config, identity: identityRepo });
      web.use('/api', (_req, res) => res.status(404).json({ error: 'Unmapped Full Reset API' }));
      const build = process.env.CTF_CONTENT_BUILD_DIRECTORY;
      web.use(express.static(build));
      web.get('/{*path}', (_req, res) => res.sendFile(path.join(build, 'index.html')));
      server = await new Promise(resolve => { const owned = web.listen(0, '127.0.0.1', () => resolve(owned)); });
      global.__ctfFullResetOwnedPorts.add(server.address().port);
      const origin = `http://127.0.0.1:${server.address().port}`;
      const request = async (method, route, req) => {
        const response = await fetch(origin + '/api/ctf' + route, { method,
          headers: { authorization: req.headers.authorization }, signal: AbortSignal.timeout(10000) });
        const body = await response.json();
        return { status: response.status, body };
      };
      const externalSnapshot = () => externalFullResetSnapshot({ identity: i.runtime });
      const evidence = process.env.CTF_RENDERED_EVIDENCE;
      browser = await launchFullResetBrowser();
      const context = await browser.createBrowserContext();
      instructor = await context.newPage();
      instructor.setDefaultTimeout(15000);
      await instructor.setViewport({ width: 1280, height: 900 });
      await instructor.setRequestInterception(true);
      const { contentApiAllowed, contentPointerClick } = require('./support/ctfRecoveryRenderedCases');
      instructor.on('request', req => {
        const url = new URL(req.url());
        if (['about:', 'data:', 'blob:'].includes(url.protocol)) return req.continue();
        if (url.origin !== origin) return req.abort();
        if (url.pathname.startsWith('/api/') &&
          !(contentApiAllowed(req.method(), url.pathname) ||
            (req.method() === 'POST' && url.pathname === '/api/ctf/admin/reset'))) {
          if (unexpectedApiPaths.length < 32) unexpectedApiPaths.push({ method: req.method(), path: url.pathname });
          return req.abort();
        }
        return req.continue();
      });
      await instructor.evaluateOnNewDocument(token => localStorage.setItem('token', token), mounted.adminToken);
      const click = async (page, selector, text) => {
        await action(() => page.bringToFront());
        const visible = await action(() => page.waitForFunction(({ selector, text }) =>
          [...document.querySelectorAll(selector)].filter(el =>
            el.textContent.trim() === text && el.getClientRects().length).length === 1,
        { polling: 100, timeout: 15000 }, { selector, text })); await visible.dispose();
        const handle = await action(() => page.evaluateHandle(({ selector, text }) =>
          [...document.querySelectorAll(selector)].find(el => el.textContent.trim() === text),
        { selector, text }));
        try { await contentPointerClick(page, handle, action); } finally { await handle.dispose(); }
      };
      finalizer = await require('./support/ctfFullResetRenderedCases').runFullResetRenderedFacet({
        i, c, origin, instructor, action, click, pointer: contentPointerClick,
        mounted, admin, adapter, request, serverWitness, externalSnapshot, ledger,
        receiptPath: process.env.CTF_FULL_RESET_Q05_RECEIPT,
        runtimeDirectory: process.env.CTF_FULL_RESET_RUNTIME_DIRECTORY, unexpectedApiPaths });
      await context.close();
      await browser.close(); browser = null;
      await finalizer(); finalizer = null;
      assert.equal(ledger.length, 0);
      require('./support/ctfRecoveryRenderedCases').assertContentLoadedSources(ROOT,
        inventory, Object.keys(require.cache));
    } catch (error) { primary = error; throw error; }
    finally {
      const failures = [];
      for (const close of [() => browser?.close(), () => mounted?.close(),
        () => application?.stop(), () => boundedCloseServer(server),
        () => boundedCloseServer(providerServer),
        ...pools.reverse().map(pool => () => pool.end()), () => closePostgresPools()]) {
        try { await close(); } catch (error) { failures.push(error); }
      }
      if (failures.length && !primary)
        throw new AggregateError(failures, 'Full Reset owned cleanup failed');
      if (primary && failures.length)
        throw new AggregateError([primary, ...failures], 'Full Reset primary and cleanup failed');
    }
  });

module.exports = { boundedCloseServer };
