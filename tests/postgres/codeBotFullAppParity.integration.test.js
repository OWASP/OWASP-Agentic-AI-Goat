'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const { randomUUID } = require('node:crypto');

test('model-free CodeBot learner, instructor, and run projection full-App parity', { skip: process.env.CODEBOT_FULL_APP_PARITY !== '1', timeout: 240000 }, async () => {
  assert.equal(process.env.PG_TEST_DISPOSABLE, 'yes'); assert.equal(fs.realpathSync(process.cwd()), fs.realpathSync(process.env.DVAIA_ISOLATED_TEST_WORKSPACE));
  const { Pool } = require('pg'); const pools = [];
  const makePool = (key, role, database) => { const url = new URL(process.env[key]); assert.equal(url.hostname, '127.0.0.1'); assert.equal(url.pathname, database); assert.equal(url.username, role); const value = new Pool({ connectionString: url.href, max: 6 }); pools.push(value); return value; };
  const identity = makePool('IDENTITY_DATABASE_URL', 'dvaia_identity_runtime', '/dvaia_test_codebot_parity_identity');
  const migration = makePool('IDENTITY_MIGRATION_DATABASE_URL', 'dvaia_identity_migration', '/dvaia_test_codebot_parity_identity');
  const lab = makePool('SUPPLY_CHAIN_WORKSHOP_DATABASE_URL', 'dvaia_supply_chain_runtime', '/dvaia_test_codebot_parity_lab');
  const labMigration = makePool('SUPPLY_CHAIN_WORKSHOP_MIGRATION_DATABASE_URL', 'dvaia_supply_chain_migration', '/dvaia_test_codebot_parity_lab');
  let server; let authRouter; let parity;
  try {
    Object.assign(process.env, { PLATFORM_DATABASE_ENGINE: 'postgres', WORKSHOP_DATABASE_ENGINE: 'postgres', AI_PROVIDER: 'mock', JUDGE_PROVIDER: 'mock', EVENT_GATE_ENABLED: 'false' });
    const identityApi = require('../../server/database/postgres/identityRepository'); await identityApi.initializeIdentityRepository(identity, migration);
    await require('../../server/database/postgres/workshopPlatformSeed').seedWorkshopPlatform(migration);
    await require('../../server/database/postgres/supplyChainWorkshopDb').createSupplyChainWorkshopDb(lab).initialize(labMigration);
    const repository = identityApi.createIdentityRepository(identity); const adapter = require('../../server/services/postgresIdentityAdapter').getPostgresIdentityAdapter();
    const password = randomUUID(); const passwordHash = await require('bcryptjs').hash(password, 4);
    const learner = await repository.createUser({ username: 'cbp-' + randomUUID().slice(0, 12), email: randomUUID() + '@example.invalid', passwordHash });
    const sibling = await repository.createUser({ username: 'cbs-' + randomUUID().slice(0, 12), email: randomUUID() + '@example.invalid', passwordHash });
    const stores = await require('../../server/services/postgresPlatformStores').getPostgresPlatformStores(); const express = require('express'); const app = express(); app.use(express.json());
    const pass = (_request, _response, next) => next(); authRouter = require('../../server/routes/postgresAuth').createPostgresAuthRouter({ adapter, limiters: { loginRateLimiter: pass, registerRateLimiter: pass, passwordResetRateLimiter: pass } }); app.use('/api/auth', authRouter);
    parity = await require('../fixtures/legacyFileSsiFullAppParity').mountLegacyParityRoutes({ app, adapter, pool: identity, migration, progress: stores.progress, config: stores.config, identity: repository });
    const admin = await identity.query("SELECT id FROM identity.users WHERE role='super_admin' ORDER BY id DESC LIMIT 1"); await repository.grantPermission({ userId: admin.rows[0].id, permission: 'view_analytics', grantedBy: admin.rows[0].id });
    const auth = require('../../server/middleware/postgresAdminAuth').createPostgresAdminAuth(adapter);
    const runReads = require('../../server/database/postgres/agentRunReadRepository').createPostgresAgentRunReadRepository(identity,
      { secureShopOwnership: { resolve: async () => { throw new Error('unexpected SecureShop ownership lookup'); } } });
    app.use('/api/agent-runs', require('../../server/routes/agentRuns').createAgentRunsRouter({ repository: runReads, authenticateToken: auth.authenticateToken }));
    app.use('/api/admin/agent-runs', require('../../server/routes/agentRuns').createAgentRunsRouter({ repository: runReads, authenticateToken: auth.authenticateToken, requirePermission: auth.requirePermission, admin: true }));
    app.use('/api/solutions', require('../../server/routes/solutions')); app.use('/api/hints', require('../../server/routes/hints')); app.use('/api/workshop/supply-chain', require('../../server/routes/supplyChainWorkshop'));
    server = app.listen(0, '127.0.0.1'); await new Promise(resolve => server.once('listening', resolve));
    const login = async owner => { const response = await fetch(`http://127.0.0.1:${server.address().port}/api/auth/login`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ username: owner.username, password }) }); assert.equal(response.status, 200); return response.json(); };
    const learnerAuth = await login(learner); const siblingAuth = await login(sibling);
    await migration.query("UPDATE workshop_platform.objectives SET is_enabled=true WHERE workshop_key='supply_chain_rce'"); await migration.query("UPDATE workshop_platform.exercises SET is_visible=(workshop_key='supply_chain_rce')");
    await migration.query("INSERT INTO workshop_platform.completions(user_id,workshop_key,objective_id) VALUES($1,'supply_chain_rce','clean_request')", [learner.id]);
    await migration.query("INSERT INTO workshop_platform.time_tracking(user_id,workshop_key,session_start,last_heartbeat,duration_seconds) VALUES($1,'supply_chain_rce',now()-interval '60 seconds',now(),60)", [learner.id]);
    await lab.query("INSERT INTO supply_chain.progress(user_id,objective_id,status,completed_at) VALUES($1,'clean_request','completed',now()) ON CONFLICT(user_id,objective_id) DO UPDATE SET status='completed',completed_at=now()", [String(learner.id)]);
    const runId = randomUUID(); const ownerKey = JSON.stringify(['CodeBot', String(learner.id)]);
    await identity.query('INSERT INTO graph_runtime.owners(owner_key,generation) VALUES($1,0)', [ownerKey]);
    await identity.query("INSERT INTO graph_runtime.runs(run_id,owner_key,generation,status,provider,model,decision_source,last_node,finished_at) VALUES($1,$2,0,'completed','controlled-projection','none','controlled-projection','respond',now())", [runId, ownerKey]);
    await identity.query("INSERT INTO graph_runtime.events(run_id,owner_key,sequence,node,event_type,metadata) VALUES($1,$2,1,'respond','node_end',$3::jsonb)", [runId, ownerKey, JSON.stringify({ decisionSource: 'controlled-projection' })]);
    const title = (await migration.query("SELECT challenge_name FROM workshop_platform.exercises WHERE workshop_key='supply_chain_rce'")).rows[0].challenge_name;
    const labelRows = (await migration.query("SELECT objective_id,label FROM workshop_platform.objectives WHERE workshop_key='supply_chain_rce' AND objective_id=ANY($1::text[])", [['tool_list', 'clean_request']])).rows;
    const labels = Object.fromEntries(labelRows.map(row => [row.objective_id, row.label]));
    assert.equal(typeof labels.tool_list, 'string'); assert.ok(labels.tool_list.length > 0); assert.equal(typeof labels.clean_request, 'string'); assert.ok(labels.clean_request.length > 0); assert.notEqual(labels.tool_list, labels.clean_request);
    const proof = await require('../fixtures/codeBotFullAppParity').qualifyCodeBotFullAppParity({ backendPort: server.address().port, token: learnerAuth.token, siblingToken: siblingAuth.token, adminToken: parity.adminToken, studentId: learner.id, title, labels, runId, runtimeRoot: path.dirname(process.env.CODEBOT_PARITY_EVIDENCE_PATH) });
    fs.writeFileSync(process.env.CODEBOT_PARITY_EVIDENCE_PATH, JSON.stringify(proof, null, 2));
  } finally {
    if (server) await new Promise(resolve => server.close(resolve)); await parity?.close?.(); await authRouter?.close?.(); await require('../../server/database/postgres').closePostgresPools(); await Promise.all(pools.map(value => value.end()));
  }
});
