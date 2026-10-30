'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const fs = require('node:fs/promises');
const os = require('node:os');
const { promisify } = require('node:util');
const { execFile } = require('node:child_process');
const express = require('express');
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');
const { migrate } = require('../../db/postgres/migrate');

const PREFIX = 'PG_SECURESHOP_PERSONA_ACTIVATION_';
const STORE_KEYS = ['IDENTITY', 'AGENTS', 'REVIEW', 'COMMERCE'];
const enabled = process.env.PG_TEST_DISPOSABLE === 'yes'
  && STORE_KEYS.every(store => ['MIGRATION', 'RUNTIME']
    .every(role => process.env[`${PREFIX}${store}_${role}_URL`]))
  && ['MIGRATION', 'RUNTIME'].every(role => process.env[`${PREFIX}PARTIAL_AGENTS_${role}_URL`]);
const WORKSHOP = 'secureshop_agent_security';
const OBJECTIVES = Object.freeze([
  'ss_cross_persona_effect', 'ss_acl_advisory_effect', 'ss_acl_enforced_block',
]);
const ROOT = path.join(__dirname, '../..');

function ownedUrl(name) {
  const value = new URL(process.env[name]);
  assert.ok(['127.0.0.1', 'localhost'].includes(value.hostname));
  assert.match(value.pathname, /^\/owasp_ai_goat_test_[a-z0-9_]+$/);
  return value.href;
}
async function json(response, status = 200) {
  const body = await response.json();
  assert.equal(response.status, status, JSON.stringify(body));
  return body;
}

test('candidate persona activation mounts real JWT launch and preserves catalog authority', {
  skip: !enabled,
  timeout: 90000,
}, async t => {
  const pools = {};
  for (const store of STORE_KEYS) for (const role of ['MIGRATION', 'RUNTIME']) {
    const key = `${store}_${role}`;
    pools[key] = new Pool({ connectionString: ownedUrl(`${PREFIX}${key}_URL`), max: 6 });
  }
  pools.PARTIAL_AGENTS_MIGRATION = new Pool({
    connectionString: ownedUrl(`${PREFIX}PARTIAL_AGENTS_MIGRATION_URL`), max: 3,
  });
  pools.PARTIAL_AGENTS_RUNTIME = new Pool({
    connectionString: ownedUrl(`${PREFIX}PARTIAL_AGENTS_RUNTIME_URL`), max: 3,
  });
  let server;
  let identityAdapter;
  let compositionClosed = false;
  try {
    const { initializeIdentityRepository, createIdentityRepository } = require(
      '../../server/database/postgres/identityRepository');
    const { seedWorkshopPlatform } = require('../../server/database/postgres/workshopPlatformSeed');
    const { initializeSecureShopAgentsDb } = require('../../server/database/postgres/secureshopAgentsDb');
    const { initializeSecureShopReviewDb } = require('../../server/database/postgres/secureshopReviewDb');
    const { initializeSecureShopCommerceDb } = require('../../server/database/postgres/secureshopInitialization');
    await initializeIdentityRepository(pools.IDENTITY_RUNTIME, pools.IDENTITY_MIGRATION);
    await seedWorkshopPlatform(pools.IDENTITY_MIGRATION);
    await initializeSecureShopAgentsDb({ runtimePool: pools.AGENTS_RUNTIME,
      migrationPool: pools.AGENTS_MIGRATION });
    await initializeSecureShopReviewDb(pools.REVIEW_RUNTIME, pools.REVIEW_MIGRATION);
    await initializeSecureShopCommerceDb({ runtimePool: pools.COMMERCE_RUNTIME,
      migrationPool: pools.COMMERCE_MIGRATION });

    const partialDirectory = await fs.mkdtemp(path.join(os.tmpdir(), 'owasp-ai-goat-persona-partial-'));
    t.after(() => fs.rm(partialDirectory, { recursive: true, force: true }));
    const agentsDir = path.join(ROOT, 'db/postgres/workshop-migrations/secureshop_agents');
    for (const name of (await fs.readdir(agentsDir)).filter(name => name.endsWith('.sql')
      && name < '0010_secureshop_persona_inbox.sql')) {
      await fs.copyFile(path.join(agentsDir, name), path.join(partialDirectory, name));
    }
    await migrate(pools.PARTIAL_AGENTS_MIGRATION, partialDirectory);
    const { assertPersonaInboxReadiness } = require('../../server/services/secureshopBoundReviewComposition');
    await assert.rejects(assertPersonaInboxReadiness({ identityPool: pools.IDENTITY_RUNTIME,
      agentsPool: pools.PARTIAL_AGENTS_RUNTIME }), {
      code: 'SECURESHOP_BOUND_REVIEW_UNAVAILABLE',
    });
    const partialEnvironment = { ...process.env,
      SECURESHOP_AGENTS_DATABASE_URL: ownedUrl(`${PREFIX}PARTIAL_AGENTS_RUNTIME_URL`),
      SECURESHOP_AGENTS_MIGRATION_DATABASE_URL: ownedUrl(`${PREFIX}PARTIAL_AGENTS_MIGRATION_URL`),
    };
    delete partialEnvironment.SS_PERSONA_INBOX_READY;
    const startupProbe = `
      (async()=>{
        let accepted=false;
        try {
          await require('./server/services/secureshopBoundApplication').createSecureShopBoundApplication({
            engine:'postgres',shopEnabled:true,authenticateToken(){},audit:async()=>{},
            agentRuntime:Object.freeze({provider:Object.freeze({
              async chat(){throw new Error('model');},async finalResponse(){throw new Error('model');}
            })})
          });
          accepted=true;
        } catch(error) {
          if(error?.code!=='SECURESHOP_BOUND_REVIEW_UNAVAILABLE') throw error;
        } finally {
          await Promise.allSettled([
            require('./server/services/secureshopBoundReviewComposition').closeSecureShopBoundReviewComposition(),
            require('./server/database/postgres/secureshopPools').closeSecureShopPools(),
            require('./server/database/postgres/secureshopReviewDb').closeSecureShopReviewDb(),
            require('./server/services/postgresIdentityAdapter').getPostgresIdentityAdapter().pool.end(),
          ]);
        }
        if(accepted) throw new Error('partial persona schema was accepted');
      })().catch(error=>{console.error(error?.code||error?.name||'Error');process.exitCode=1});`;
    const probe = await promisify(execFile)(process.execPath, ['-e', startupProbe], {
      cwd: ROOT, env: partialEnvironment, timeout: 30000,
    });
    assert.equal(probe.stdout, '');
    assert.equal(probe.stderr, '');

    delete process.env.SS_PERSONA_INBOX_READY;
    const { activationPolicy } = require('../../server/services/secureshopPersonaInboxActivationPolicy');
    assert.deepEqual(activationPolicy(process.env), Object.freeze({
      requested: true, postgres: true, explicitlyDisabled: false,
    }));
    const { getPostgresIdentityAdapter } = require('../../server/services/postgresIdentityAdapter');
    identityAdapter = getPostgresIdentityAdapter();
    const { authenticateToken } = require('../../server/middleware/adminAuth');
    const { createSecureShopBoundApplication } = require('../../server/services/secureshopBoundApplication');
    let modelCalls = 0;
    const bound = await createSecureShopBoundApplication({ engine: 'postgres', shopEnabled: true,
      authenticateToken, audit: row => identityAdapter.repository.recordAudit(row),
      agentRuntime: Object.freeze({ provider: Object.freeze({
        async chat() { modelCalls += 1; throw new Error('activation qualifier must not call a model'); },
        async finalResponse() { modelCalls += 1; throw new Error('activation qualifier must not call a model'); },
      }) }),
    });
    const app = express(); app.use(express.json());
    app.use('/api/auth/secureshop-launch', bound.launchRouter);
    app.use('/api/secureshop', bound.gateway);
    server = await new Promise(resolve => {
      const value = app.listen(0, '127.0.0.1', () => resolve(value));
    });
    const base = `http://127.0.0.1:${server.address().port}`;
    await json(await fetch(`${base}/api/auth/secureshop-launch`), 401);

    const passwordHash = await bcrypt.hash('OwnedPersonaActivation#2026', 4);
    const user = await createIdentityRepository(pools.IDENTITY_RUNTIME).createUser({
      username: 'owned_persona_activation', email: 'owned-persona-activation@example.invalid', passwordHash,
    });
    const platformSession = await identityAdapter.createSession({ ...user, password: passwordHash }, {
      get() { return undefined; }, ip: '127.0.0.1',
    }, { durationMs: 3600000 });
    const platformHeaders = { authorization: `Bearer ${platformSession.token}`,
      'content-type': 'application/json' };
    await json(await fetch(`${base}/api/auth/secureshop-launch`, {
      method: 'POST', headers: { ...platformHeaders, authorization: 'Bearer malformed' }, body: '{}',
    }), 401);
    const launch = await json(await fetch(`${base}/api/auth/secureshop-launch`, {
      method: 'POST', headers: platformHeaders, body: '{}',
    }), 201);
    const launchHeaders = { 'x-owasp-ai-goat-secureshop-launch': launch.bearer,
      'content-type': 'application/json' };
    const login = await json(await fetch(`${base}/api/secureshop/v2/auth/login`, {
      method: 'POST', headers: launchHeaders,
      body: JSON.stringify({ username: 'student_merchant', password: 'student123' }),
    }));
    const personaHeaders = { ...launchHeaders, authorization: `Bearer ${login.token}` };
    assert.deepEqual(await json(await fetch(
      `${base}/api/secureshop/v2/persona-inbox/readiness`, { headers: personaHeaders })), { ready: false });

    const rows = (await pools.IDENTITY_MIGRATION.query(`SELECT objective_id,label,is_enabled
      FROM workshop_platform.objectives WHERE workshop_key=$1 AND objective_id=ANY($2::text[])
      ORDER BY objective_id`, [WORKSHOP, OBJECTIVES])).rows;
    const curriculum = require('../../server/config/secureshopCurriculum');
    const candidate = require('../../docs/modernization/drafts/secureshopPersonaInboxActivationCandidate');
    const expected = new Map(curriculum.OBJECTIVES.map(row => [row.id, row]));
    assert.equal(rows.length, 3);
    for (const row of rows) {
      assert.equal(row.label, expected.get(row.objective_id).text);
      assert.equal(row.is_enabled, false);
      assert.equal(expected.get(row.objective_id).qualification, 'native-model');
      assert.equal(expected.get(row.objective_id).defaultEnabled, false);
    }
    assert.equal(curriculum.CHALLENGE.route, '/workshop/secureshop');
    assert.equal(curriculum.CHALLENGE.defaultVisible, true);
    assert.equal(curriculum.CHALLENGE.visible, 1);
    const newlyQualified = curriculum.OBJECTIVES.filter(row => candidate.QUALIFIED.includes(row.id));
    assert.deepEqual(newlyQualified.map(row => row.id), candidate.QUALIFIED);
    assert.ok(newlyQualified.every(row => row.qualification === 'native-model'));
    assert.ok(curriculum.OBJECTIVES.every(row => row.defaultEnabled === false));
    assert.ok(curriculum.PENDING_OBJECTIVE_IDS.every(id => !candidate.QUALIFIED.includes(id)));
    const exercise = (await pools.IDENTITY_MIGRATION.query(`SELECT route,is_visible
      FROM workshop_platform.exercises WHERE workshop_key=$1`, [WORKSHOP])).rows[0];
    assert.deepEqual(exercise, { route: '/workshop/secureshop', is_visible: true });
    await pools.IDENTITY_MIGRATION.query(`UPDATE workshop_platform.exercises SET is_visible=true
      WHERE workshop_key=$1`, [WORKSHOP]);
    await pools.IDENTITY_MIGRATION.query(`UPDATE workshop_platform.objectives SET is_enabled=true
      WHERE workshop_key=$1 AND objective_id=ANY($2::text[])`, [WORKSHOP, OBJECTIVES]);
    const ready = await json(await fetch(`${base}/api/secureshop/v2/persona-inbox/readiness`, {
      headers: personaHeaders,
    }));
    assert.equal(ready.ready, true);
    assert.equal(ready.capabilities.enforceAcl, true);
    assert.equal(ready.messages.length, 3);

    await pools.IDENTITY_MIGRATION.query(`UPDATE workshop_platform.objectives SET is_enabled=false
      WHERE workshop_key=$1 AND objective_id=$2`, [WORKSHOP, OBJECTIVES[1]]);
    assert.deepEqual(await json(await fetch(
      `${base}/api/secureshop/v2/persona-inbox/readiness`, { headers: personaHeaders })), { ready: false });
    await pools.IDENTITY_MIGRATION.query(`UPDATE workshop_platform.objectives SET is_enabled=true
      WHERE workshop_key=$1 AND objective_id=$2`, [WORKSHOP, OBJECTIVES[1]]);
    await pools.IDENTITY_MIGRATION.query(`UPDATE workshop_platform.exercises SET is_visible=false
      WHERE workshop_key=$1`, [WORKSHOP]);
    assert.deepEqual(await json(await fetch(
      `${base}/api/secureshop/v2/persona-inbox/readiness`, { headers: personaHeaders })), { ready: false });
    assert.equal(modelCalls, 0);

    await new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
    server = undefined;
    const { closeSecureShopBoundReviewComposition } = require('../../server/services/secureshopBoundReviewComposition');
    await closeSecureShopBoundReviewComposition(); compositionClosed = true;

    process.env.SS_PERSONA_INBOX_READY = 'false';
    assert.deepEqual(activationPolicy(process.env), Object.freeze({
      requested: false, postgres: true, explicitlyDisabled: true,
    }));
    let requested;
    const maintenanceScope = Object.freeze({
      launchId: '11111111-1111-4111-8111-111111111111',
      scenarioId: '22222222-2222-4222-8222-222222222222', generation: 1,
      platformOwnerId: 1, platformSessionId: 1,
    });
    const maintenancePersona = (req, _res, next) => {
      req.ssUser = Object.freeze({ id: 2, role: 'merchant' }); next();
    };
    const maintenanceComposition = Object.freeze({
      launchResetCoordinator: Object.freeze({ async reset() {}, async recover() {} }),
      ownerResetService: Object.freeze({ async assertReady() {}, async resetOwner() {} }),
      createStudentDeletionCleanup() {}, launches: Object.freeze({
        async resolveCapability() { return maintenanceScope; },
      }),
      personaAuth: Object.freeze({ authenticatePersona: maintenancePersona,
        async login() {}, async renew() {}, async logout() {} }),
      router: express.Router(), browserRouter: express.Router(),
      catalog: Object.freeze({ async listProducts() {}, async getProduct() {}, async listMerchantProducts() {} }),
      personaInbox: Object.freeze({ ready: false }),
    });
    const maintenance = await createSecureShopBoundApplication({ engine: 'postgres', shopEnabled: true,
      authenticateToken, audit: async () => {}, agentRuntime: Object.freeze({ provider: {} }),
      getComposition: async options => { requested = options.personaInboxFeature; return maintenanceComposition; },
    });
    assert.equal(requested, false);
    const maintenanceApp = express(); maintenanceApp.use(express.json());
    maintenanceApp.use('/api/secureshop', maintenance.gateway);
    const maintenanceServer = await new Promise(resolve => {
      const value = maintenanceApp.listen(0, '127.0.0.1', () => resolve(value));
    });
    t.after(() => new Promise(resolve => maintenanceServer.close(() => resolve())));
    const maintenanceBase = `http://127.0.0.1:${maintenanceServer.address().port}`;
    const maintenanceResponse = await fetch(`${maintenanceBase}/api/secureshop/v2/persona-inbox/readiness`, {
      headers: { 'x-owasp-ai-goat-secureshop-launch': 'a'.repeat(43) },
    });
    assert.deepEqual(await json(maintenanceResponse), { ready: false });
  } finally {
    delete process.env.SS_PERSONA_INBOX_READY;
    if (server) await new Promise(resolve => server.close(() => resolve()));
    if (!compositionClosed) {
      try { await require('../../server/services/secureshopBoundReviewComposition')
        .closeSecureShopBoundReviewComposition(); } catch {}
    }
    await Promise.allSettled([
      require('../../server/database/postgres/secureshopPools').closeSecureShopPools(),
      require('../../server/database/postgres/secureshopReviewDb').closeSecureShopReviewDb(),
      ...(identityAdapter ? [identityAdapter.pool.end()] : []),
      ...Object.values(pools).map(pool => pool.end()),
    ]);
  }
});
