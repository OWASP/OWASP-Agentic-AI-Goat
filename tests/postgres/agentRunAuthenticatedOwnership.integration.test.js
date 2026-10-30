'use strict';
// Projection fixtures only: no actor, provider, Judge, or application database.
const test = require('node:test');
const assert = require('node:assert/strict');
const { randomUUID } = require('node:crypto');
const enabled = process.env.PG_TEST_DISPOSABLE === 'yes'
  && process.env.PG_AUTHENTICATED_RUN_READS === '1';

test('durable session authentication composes with native cross-store run ownership', { skip: !enabled, timeout: 90000 }, async () => {
  const mainAdmission=process.env.PG_MAIN_BACKEND_AUTH===undefined?null:require('../fixtures/mainBackendAuthAdmission').admit(process.env);
  const keys = ['PG_READS_TEST_RUNTIME_URL', 'PG_READS_TEST_MIGRATION_URL',
    'PG_SECURESHOP_AGENTS_TEST_RUNTIME_URL', 'PG_SECURESHOP_AGENTS_TEST_MIGRATION_URL'];
  const urls = keys.map(key => {
    const url = new URL(process.env[key]);
    assert.ok(['postgres:', 'postgresql:'].includes(url.protocol));
    assert.ok(['127.0.0.1', 'localhost', '[::1]'].includes(url.hostname));
    if(mainAdmission){assert.equal(url.port,String(mainAdmission.port));assert.equal(url.hostname,'127.0.0.1');assert.ok(['/owasp_ai_goat_identity','/owasp_ai_goat_secureshop_agents'].includes(url.pathname));}
    else assert.match(url.pathname, /^\/owasp_ai_goat_test_[a-z0-9_]+$/);
    assert.ok(url.port, 'explicit disposable port required');
    assert.equal(url.search, '', 'URL connection options are forbidden');
    assert.equal(url.hash, '', 'URL fragments are forbidden');
    return url;
  });
  assert.equal(urls[0].pathname, urls[1].pathname);
  assert.equal(urls[2].pathname, urls[3].pathname);
  assert.notEqual(urls[0].pathname, urls[2].pathname);
  assert.equal(new Set(urls.map(url => url.host)).size, 1);
  assert.equal(new Set(urls.map(url => decodeURIComponent(url.username))).size, 4, 'all four roles must be distinct');
  const { createPool } = require('../../server/database/postgres');
  const pools = keys.map(key => createPool(process.env, key));
  const [pool, migration, agents, agentsMigration] = pools;
  let server;
  try {
    const identities = await Promise.all(pools.map(async (connection, index) => {
      const { rows } = await connection.query(`SELECT current_user AS role,current_database() AS database,
        rolsuper,rolcreatedb,rolcreaterole,rolbypassrls FROM pg_roles WHERE rolname=current_user`);
      assert.equal(rows.length, 1);
      const row = rows[0];
      assert.equal(row.role, decodeURIComponent(urls[index].username));
      assert.equal(row.database, decodeURIComponent(urls[index].pathname.slice(1)));
      if (index === 0 || index === 2) for (const capability of ['rolsuper', 'rolcreatedb', 'rolcreaterole', 'rolbypassrls']) {
        assert.equal(row[capability], false, `runtime must not have ${capability}`);
      }
      return row;
    }));
    assert.equal(new Set(identities.map(row => row.role)).size, 4);
    const identityApi = require('../../server/database/postgres/identityRepository');
    await identityApi.initializeIdentityRepository(pool, migration);
    await require('../../server/database/postgres/secureshopInitialization')
      .initializeSecureShopAgentsDb({ runtimePool: agents, migrationPool: agentsMigration });
    const identity = identityApi.createIdentityRepository(pool);
    const adapter = require('../../server/services/postgresIdentityAdapter').createPostgresIdentityAdapter({
      repository: identity, jwtSecret: 'owned-authenticated-runs-fixture-signing-secret',
    });
    const auth = require('../../server/middleware/postgresAdminAuth').createPostgresAdminAuth(adapter);
    const launches = require('../../server/database/postgres/secureshopLaunchRepository').createSecureShopLaunchRepository(pool);
    const { ownerKey, createPostgresAgentRunReadRepository } = require('../../server/database/postgres/agentRunReadRepository');
    async function owner(admin = false) {
      const passwordHash = await require('bcryptjs').hash(randomUUID(), 4);
      const user = await identity.createUser({ username: `run-auth-${randomUUID()}`, email: `${randomUUID()}@example.invalid`, passwordHash });
      if (admin) {
        await migration.query("UPDATE identity.users SET role='admin',admin_level=1,email_verified=1 WHERE id=$1", [user.id]);
        await identity.grantPermission({ userId: user.id, permission: 'view_analytics', grantedBy: user.id });
      }
      const session = await adapter.createSession({ ...user, password: passwordHash }, {});
      return { user, session };
    }
    async function run(key) {
      const id = randomUUID();
      await pool.query('INSERT INTO graph_runtime.owners(owner_key) VALUES($1) ON CONFLICT DO NOTHING', [key]);
      await pool.query("INSERT INTO graph_runtime.runs(run_id,owner_key,generation,status) VALUES($1,$2,0,'completed')", [id, key]);
      return id;
    }
    async function boundRun(subject) {
      const { binding } = await launches.issueOrRenew({ platformOwnerId: subject.user.id,
        platformSessionId: subject.session.internalSessionId, expiresAt: new Date(Date.now() + 3600000) });
      const id = randomUUID();
      await agents.query(`INSERT INTO secureshop_agents.agent_sessions
        (id,user_id,role,authority_mode,binding_state,platform_launch_id,platform_scenario_id,
         platform_launch_generation,original_platform_owner_id,original_platform_session_id)
        VALUES($1,1,'customer','launch_bound','pending',$2,$3,$4,$5,$6)`,
      [id, binding.launchId, binding.scenarioId, binding.generation, subject.user.id, subject.session.internalSessionId]);
      await agents.query("UPDATE secureshop_agents.agent_sessions SET binding_state='active' WHERE id=$1", [id]);
      return run(ownerKey('SecureShopBoundConversation', id));
    }
    const student = await owner(), foreign = await owner(), admin = await owner(true);
    const direct = await run(ownerKey('ARIA', String(student.user.id)));
    const ownBound = await boundRun(student), foreignBound = await boundRun(foreign);
    let outage = false;
    const ownership = require('../../server/services/secureshopConversationOwnershipResolver')
      .createSecureShopConversationOwnershipResolver({ identityPool: pool, agentsPool: {
        query: (...args) => { if (outage) throw new Error('Controlled resolver outage'); return agents.query(...args); },
      } });
    const repository = createPostgresAgentRunReadRepository(pool, { secureShopOwnership: ownership });
    const { createAgentRunsRouter } = require('../../server/routes/agentRuns');
    const app = require('express')();
    for (const isAdmin of [false, true]) app.use(isAdmin ? '/api/admin/agent-runs' : '/api/agent-runs',
      createAgentRunsRouter({ repository, authenticateToken: auth.authenticateToken,
        requirePermission: auth.requirePermission, admin: isAdmin, receiptAdapters: {}, getGraphDefinition: () => null }));
    server = await new Promise(resolve => { const value = app.listen(0, '127.0.0.1', () => resolve(value)); });
    const base = `http://127.0.0.1:${server.address().port}`;
    async function request(path, subject) {
      const response = await fetch(base + path, { signal: AbortSignal.timeout(5000),
        headers: subject ? { authorization: `Bearer ${subject.session.token}` } : {} });
      return { status: response.status, body: await response.json() };
    }
    const studentList = await request('/api/agent-runs', student);
    assert.equal(studentList.status, 200);
    assert.deepEqual(new Set(studentList.body.runs.map(row => row.runId)), new Set([direct, ownBound]));
    const adminPath = `/api/admin/agent-runs?ownerId=${student.user.id}`;
    const adminList = await request(adminPath, admin);
    assert.equal(adminList.status, 200);
    assert.deepEqual(new Set(adminList.body.runs.map(row => row.runId)), new Set([direct, ownBound]));
    assert.ok(adminList.body.runs.every(row => row.ownerId === String(student.user.id)));
    assert.equal((await request(`/api/agent-runs/${foreignBound}`, student)).status, 404);
    assert.equal((await request('/api/admin/agent-runs', student)).status, 403);
    assert.equal((await request('/api/agent-runs')).status, 401);
    const unpersisted = { session: { token: require('jsonwebtoken').sign({ userId: student.user.id },
      adapter.jwtSecret, { expiresIn: '1h', jwtid: randomUUID() }) } };
    assert.equal((await request('/api/agent-runs', unpersisted)).status, 401,
      'a valid signature without a durable session must not authorize ownership reads');
    outage = true;
    for (const [path, subject] of [['/api/agent-runs', student], [adminPath, admin], [`/api/agent-runs/${ownBound}`, student]]) {
      const result = await request(path, subject);
      assert.equal(result.status, 503);
      assert.equal(result.body.code, 'AGENT_RUN_STORE_UNAVAILABLE');
      assert.equal(result.body.runs, undefined, 'outage must never return partial ownership results');
    }
    outage = false;
    assert.equal((await request('/api/agent-runs', student)).status, 200);
    await identity.revokePermission(admin.user.id, 'view_analytics');
    assert.equal((await request(adminPath, admin)).status, 403,
      'an existing session must not retain a revoked analytics permission');
    await identity.grantPermission({ userId: admin.user.id, permission: 'view_analytics', grantedBy: admin.user.id });
    assert.equal((await request(adminPath, admin)).status, 200);
    await adapter.logout(student.session.token);
    assert.equal((await request('/api/agent-runs', student)).status, 401,
      'a signed token must stop authorizing reads after durable session revocation');
    assert.equal((await request(`/api/agent-runs/${ownBound}`, student)).status, 401);
    assert.equal((await request('/api/agent-runs', foreign)).status, 200,
      'revoking one learner session must preserve the sibling session');
  } finally {
    if (server) { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); }
    await Promise.all(pools.map(pool => pool.end()));
  }
});
