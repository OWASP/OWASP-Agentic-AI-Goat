'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { createHash, randomUUID } = require('node:crypto');
const { Pool } = require('pg');
const { migrate } = require('../../db/postgres/migrate');
const { seedSecureShop } = require('../../server/database/postgres/secureshopSeed');
const { createSecureShopBoundPersonaRepository, MAX_ACTIVE } = require(
  '../../server/database/postgres/secureshopBoundPersonaRepository');
const { createSecureShopConversationLifecycleRepository } = require(
  '../../server/database/postgres/secureshopConversationLifecycleRepository');

const PREFIX = 'PG_SECURESHOP_BOUND_PERSONA_SESSIONS_';
const stores = ['COMMERCE', 'FRESH_AGENTS', 'POPULATED_AGENTS'];
const enabled = process.env.PG_TEST_DISPOSABLE === 'yes'
  && stores.every(store => ['MIGRATION', 'RUNTIME']
    .every(role => process.env[`${PREFIX}${store}_${role}_URL`]));
const root = path.join(__dirname, '../..');
const agentsMigrations = path.join(root, 'db/postgres/workshop-migrations/secureshop_agents');
const currentMigrations = Object.freeze(fs.readdirSync(agentsMigrations)
  .filter(name => /^[0-9]{4}_.*\.sql$/.test(name)).sort());

function pool(url, max = 5) {
  return new Pool({ connectionString: url, max, statement_timeout: 15000,
    lock_timeout: 3000, application_name: 'dvaia-session-inventory-native' });
}

function scope(overrides = {}) {
  return Object.freeze({ launchId: randomUUID(), scenarioId: randomUUID(), generation: 1,
    platformOwnerId: 7101, platformSessionId: 7201, ...overrides });
}

function expires(minutes = 30) {
  return new Date(Date.now() + minutes * 60000).toISOString();
}

function copyAgentsPrefix(t, tail, prefixName) {
  const workspace = process.env.DVAIA_ISOLATED_TEST_WORKSPACE;
  assert.equal(typeof workspace, 'string');
  const directory = fs.mkdtempSync(path.join(workspace, `${prefixName}-`));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  for (const name of fs.readdirSync(agentsMigrations).sort()) {
    if (/^[0-9]{4}_/.test(name) && name <= tail) {
      fs.copyFileSync(path.join(agentsMigrations, name), path.join(directory, name));
    }
  }
  assert.equal(fs.readdirSync(directory).sort().at(-1), tail);
  return directory;
}

function copyPrefixThrough0013(t) {
  return copyAgentsPrefix(t, '0013_secureshop_conversation_purpose.sql',
    'agents-0013-prefix');
}

function copyPrefixThrough0014(t) {
  return copyAgentsPrefix(t, '0014_secureshop_bound_session_inventory.sql',
    'agents-0014-prefix');
}

function copyPrefixThrough0015(t) {
  return copyAgentsPrefix(t, '0015_secureshop_bound_password_overlay.sql',
    'agents-0015-prefix');
}

function assertDisposable(url) {
  const parsed = new URL(url);
  assert.ok(['127.0.0.1', 'localhost'].includes(parsed.hostname));
  assert.match(parsed.pathname, /^\/dvaia_test_[a-z0-9_]+$/);
}

async function waitForAdvisoryWait(observer, pid) {
  const deadline = Date.now() + 3000;
  while (Date.now() < deadline) {
    const row = (await observer.query(`SELECT wait_event_type,wait_event
      FROM pg_stat_activity WHERE pid=$1`, [pid])).rows[0];
    if (row?.wait_event_type === 'Lock' && row.wait_event === 'advisory') return;
    await new Promise(resolve => setTimeout(resolve, 10));
  }
  throw new Error('Session touch did not wait on the launch advisory lock');
}

test('fresh current-tail sessions retain exact authority, capacity and launch-first lock ordering', {
  skip: !enabled, timeout: 60000,
}, async t => {
  const urls = Object.fromEntries(stores.flatMap(store => ['MIGRATION', 'RUNTIME'].map(role => {
    const key = `${PREFIX}${store}_${role}_URL`;
    assertDisposable(process.env[key]);
    return [`${store}_${role}`, process.env[key]];
  })));
  const commerceMigration = pool(urls.COMMERCE_MIGRATION);
  const commerceRuntime = pool(urls.COMMERCE_RUNTIME);
  const migration = pool(urls.FRESH_AGENTS_MIGRATION, 6);
  const runtime = pool(urls.FRESH_AGENTS_RUNTIME, 10);
  t.after(async () => Promise.allSettled([
    runtime.end(), migration.end(), commerceRuntime.end(), commerceMigration.end(),
  ]));

  await migrate(commerceMigration,
    path.join(root, 'db/postgres/workshop-migrations/secureshop'));
  await commerceMigration.query('BEGIN');
  try {
    await seedSecureShop(commerceMigration);
    await commerceMigration.query('COMMIT');
  } catch (error) {
    await commerceMigration.query('ROLLBACK');
    throw error;
  }
  const applied = await migrate(migration, agentsMigrations);
  assert.ok(applied.includes('0014_secureshop_bound_session_inventory.sql'));
  assert.ok(applied.includes('0015_secureshop_bound_password_overlay.sql'));
  assert.ok(applied.includes('0016_secureshop_bound_api_keys.sql'));
  assert.deepEqual(applied, currentMigrations);
  assert.deepEqual(await migrate(migration, agentsMigrations), []);

  const repository = createSecureShopBoundPersonaRepository({
    commercePool: commerceRuntime, agentsPool: runtime,
  });
  const ownerScope = scope();
  const customer = await repository.findCredential('student_customer', ownerScope);
  const merchant = await repository.findCredential('student_merchant', ownerScope);
  const siblingScope = scope({ platformOwnerId: ownerScope.platformOwnerId + 1,
    platformSessionId: ownerScope.platformSessionId + 1 });
  const currentId = randomUUID();
  const otherId = randomUUID();
  const siblingId = randomUUID();
  const merchantId = randomUUID();
  await repository.createSession({ sessionId: currentId, jti: 'current-jti', scope: ownerScope,
    persona: customer, expiresAt: expires(), ip: '127.0.0.1', userAgent: 'Native Browser' });
  await repository.createSession({ sessionId: otherId, jti: 'other-jti', scope: ownerScope,
    persona: customer, expiresAt: expires(), ip: null, userAgent: null });
  await repository.createSession({ sessionId: siblingId, jti: 'sibling-jti', scope: siblingScope,
    persona: customer, expiresAt: expires() });
  await repository.createSession({ sessionId: merchantId, jti: 'merchant-jti', scope: ownerScope,
    persona: merchant, expiresAt: expires() });

  const inventory = await repository.listSessions({ scope: ownerScope,
    shopUserId: customer.id, currentSessionId: currentId });
  assert.deepEqual(new Set(inventory.map(row => row.id)), new Set([currentId, otherId]));
  assert.equal(inventory.find(row => row.id === currentId).is_current, true);
  assert.equal(inventory.find(row => row.id === currentId).ip, '127.0.0.1');
  assert.equal(inventory.find(row => row.id === currentId).user_agent, 'Native Browser');
  assert.equal(await repository.revokeOwnedSession({ scope: ownerScope,
    shopUserId: customer.id, sessionId: siblingId }), false);
  assert.equal(await repository.revokeOwnedSession({ scope: ownerScope,
    shopUserId: customer.id, sessionId: merchantId }), false);
  assert.equal(await repository.revokeOwnedSession({ scope: ownerScope,
    shopUserId: customer.id, sessionId: otherId }), true);

  const lockHolder = await runtime.connect();
  const rowLocker = await runtime.connect();
  let touchPid;
  let signalTouchConnection;
  const touchConnected = new Promise(resolve => { signalTouchConnection = resolve; });
  const observedPool = {
    query: runtime.query.bind(runtime),
    async connect() {
      const client = await runtime.connect();
      touchPid = Number((await client.query('SELECT pg_backend_pid() AS pid')).rows[0].pid);
      signalTouchConnection();
      return client;
    },
  };
  const observedRepository = createSecureShopBoundPersonaRepository({
    commercePool: commerceRuntime, agentsPool: observedPool,
  });
  try {
    await lockHolder.query('BEGIN');
    await lockHolder.query('SELECT pg_advisory_xact_lock(hashtextextended($1,0))',
      [`secureshop-conversation-admission:${ownerScope.launchId}`]);
    const touch = observedRepository.readSession({ scope: ownerScope, jti: 'current-jti' });
    const touchOutcome = touch.then(value => ({ value }), error => ({ error }));
    await touchConnected;
    await waitForAdvisoryWait(runtime, touchPid);
    await rowLocker.query('BEGIN');
    const row = await rowLocker.query(`SELECT session_id
      FROM secureshop_agents.bound_persona_sessions
      WHERE session_id=$1 FOR UPDATE NOWAIT`, [currentId]);
    assert.equal(row.rows[0].session_id, currentId);
    await rowLocker.query('ROLLBACK');
    await lockHolder.query('COMMIT');
    const settledTouch = await touchOutcome;
    if (settledTouch.error) throw settledTouch.error;
    const touched = settledTouch.value;
    assert.equal(touched.session_id, currentId);
    assert.ok(touched.last_seen_at >= touched.created_at);
  } finally {
    try { await rowLocker.query('ROLLBACK'); } catch {}
    try { await lockHolder.query('ROLLBACK'); } catch {}
    rowLocker.release();
    lockHolder.release();
  }

  assert.equal(await repository.revokeOwnedSession({ scope: ownerScope,
    shopUserId: customer.id, sessionId: currentId }), true);
  assert.equal(await repository.readSession({ scope: ownerScope, jti: 'current-jti' }), null);

  const capacityScope = scope({ platformOwnerId: 7301, platformSessionId: 7401 });
  for (let index = 0; index < MAX_ACTIVE; index += 1) {
    await repository.createSession({ sessionId: randomUUID(), jti: `capacity-${index}`,
      scope: capacityScope, persona: customer, expiresAt: expires() });
  }
  await assert.rejects(repository.createSession({ sessionId: randomUUID(), jti: 'capacity-overflow',
    scope: capacityScope, persona: customer, expiresAt: expires() }),
  { code: 'SHOP_PERSONA_CAPACITY' });

  const raceScope = scope({ platformOwnerId: 7501, platformSessionId: 7601 });
  await repository.createSession({ sessionId: randomUUID(), jti: 'retirement-race',
    scope: raceScope, persona: customer, expiresAt: expires() });
  const lifecycle = createSecureShopConversationLifecycleRepository({ pool: runtime });
  const race = await Promise.allSettled([
    repository.extendSession({ jti: 'retirement-race', scope: raceScope, expiresAt: expires(60) }),
    lifecycle.beginRetirement({ resetId: randomUUID(), binding: raceScope }),
  ]);
  assert.equal(race[1].status, 'fulfilled');
  assert.equal((await runtime.query(`SELECT count(*)::integer AS count
    FROM secureshop_agents.bound_persona_sessions WHERE platform_launch_id=$1
      AND revoked_at IS NULL`, [raceScope.launchId])).rows[0].count, 0);
  assert.equal(await repository.readSession({ scope: raceScope, jti: 'retirement-race' }), null);
  await assert.rejects(repository.createSession({ sessionId: randomUUID(), jti: 'after-retirement',
    scope: raceScope, persona: customer, expiresAt: expires() }), { code: '55000' });
});

test('populated 0013 active and revoked sessions migrate exactly once to 0014', {
  skip: !enabled, timeout: 30000,
}, async t => {
  const commerceMigration = pool(process.env[`${PREFIX}COMMERCE_MIGRATION_URL`]);
  const commerceRuntime = pool(process.env[`${PREFIX}COMMERCE_RUNTIME_URL`]);
  const migration = pool(process.env[`${PREFIX}POPULATED_AGENTS_MIGRATION_URL`]);
  const runtime = pool(process.env[`${PREFIX}POPULATED_AGENTS_RUNTIME_URL`]);
  t.after(async () => Promise.allSettled([
    runtime.end(), migration.end(), commerceRuntime.end(), commerceMigration.end(),
  ]));
  await migrate(commerceMigration,
    path.join(root, 'db/postgres/workshop-migrations/secureshop'));
  await commerceMigration.query('BEGIN');
  try {
    await seedSecureShop(commerceMigration);
    await commerceMigration.query('COMMIT');
  } catch (error) {
    await commerceMigration.query('ROLLBACK');
    throw error;
  }
  const prefix = copyPrefixThrough0013(t);
  assert.equal((await migrate(migration, prefix)).at(-1),
    '0013_secureshop_conversation_purpose.sql');
  const repository = createSecureShopBoundPersonaRepository({
    commercePool: commerceRuntime, agentsPool: runtime,
  });
  await repository.ensureTemplates();
  const customer = (await runtime.query(`SELECT shop_user_id AS id,username,email,
    password_hash AS password,role,full_name,phone
    FROM secureshop_agents.bound_persona_templates WHERE username=$1`,
  ['student_customer'])).rows[0];
  assert.equal(customer.username, 'student_customer');
  const populatedScope = scope({ platformOwnerId: 7701, platformSessionId: 7801 });
  const active = randomUUID();
  const revoked = randomUUID();
  const insert = async (sessionId, jti) => runtime.query(`INSERT INTO
    secureshop_agents.bound_persona_sessions
    (session_id,jti_sha256,platform_launch_id,platform_scenario_id,
     platform_launch_generation,original_platform_owner_id,original_platform_session_id,
     shop_user_id,username,role,email,full_name,phone,expires_at)
    VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`,
  [sessionId, createHash('sha256').update(jti).digest(), populatedScope.launchId,
    populatedScope.scenarioId, populatedScope.generation, populatedScope.platformOwnerId,
    populatedScope.platformSessionId, customer.id, customer.username, customer.role,
    customer.email, customer.full_name, customer.phone, expires()]);
  await insert(active, 'populated-active');
  await insert(revoked, 'populated-revoked');
  await runtime.query(`UPDATE secureshop_agents.bound_persona_sessions
    SET revoked_at=clock_timestamp() WHERE session_id=$1`, [revoked]);
  const before = (await runtime.query(`SELECT session_id,created_at,revoked_at
    FROM secureshop_agents.bound_persona_sessions ORDER BY session_id`)).rows;
  assert.equal(before.filter(row => row.revoked_at === null).length, 1);

  const through0014 = copyPrefixThrough0014(t);
  assert.deepEqual(await migrate(migration, through0014),
    ['0014_secureshop_bound_session_inventory.sql']);
  const after = (await runtime.query(`SELECT session_id,created_at,last_seen_at,revoked_at,ip,user_agent
    FROM secureshop_agents.bound_persona_sessions ORDER BY session_id`)).rows;
  assert.equal(after.length, 2);
  for (const row of after) {
    assert.equal(row.last_seen_at.toISOString(), row.created_at.toISOString());
    assert.equal(row.ip, null);
    assert.equal(row.user_agent, null);
  }
  assert.deepEqual(after.map(row => [row.session_id, row.revoked_at !== null]),
    before.map(row => [row.session_id, row.revoked_at !== null]));
  const through0015 = copyPrefixThrough0015(t);
  assert.deepEqual(await migrate(migration, through0015),
    ['0015_secureshop_bound_password_overlay.sql']);
  const remaining = currentMigrations.filter(name => name > '0015_secureshop_bound_password_overlay.sql');
  assert.equal(remaining[0], '0016_secureshop_bound_api_keys.sql');
  assert.deepEqual(await migrate(migration, agentsMigrations), remaining);
  assert.deepEqual(await migrate(migration, agentsMigrations), []);
  assert.equal((await repository.readSession({ scope: populatedScope,
    jti: 'populated-active' })).session_id, active);
  assert.equal(await repository.readSession({ scope: populatedScope,
    jti: 'populated-revoked' }), null);
});
