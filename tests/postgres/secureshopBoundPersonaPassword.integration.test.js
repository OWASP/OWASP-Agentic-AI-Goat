'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { createHash, randomUUID } = require('node:crypto');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const { migrate, readMigrations } = require('../../db/postgres/migrate');
const { createAgentsMigrationView } = require('../helpers/secureshopAgentsMigrationView');
const view14 = createAgentsMigrationView(14), view15 = createAgentsMigrationView(15), view16 = createAgentsMigrationView(16);
const { seedSecureShop } = require('../../server/database/postgres/secureshopSeed');
const { createSecureShopBoundPersonaRepository } = require(
  '../../server/database/postgres/secureshopBoundPersonaRepository');
const { createSecureShopBoundPersonaAuth } = require('../../server/services/secureshopBoundPersonaAuth');
const { createSecureShopConversationLifecycleRepository } = require(
  '../../server/database/postgres/secureshopConversationLifecycleRepository');

function selectFreshCohort(value = 'current-0016') {
  if (!['current-0016', 'historical-0015'].includes(value)) throw new TypeError('Closed Persona password fresh cohort required');
  return value;
}
const freshCohort = selectFreshCohort(process.env.SECURESHOP_PERSONA_PASSWORD_FRESH_COHORT);
const freshView = freshCohort === 'historical-0015' ? view15 : view16;
const PREFIX = 'PG_SECURESHOP_BOUND_PERSONA_PASSWORD_';
const stores = ['COMMERCE', 'FRESH_AGENTS', 'POPULATED_AGENTS'];
const enabled = process.env.PG_TEST_DISPOSABLE === 'yes'
  && stores.every(store => ['MIGRATION', 'RUNTIME']
    .every(role => process.env[`${PREFIX}${store}_${role}_URL`]));
const root = path.join(__dirname, '../..');
const agentsMigrations = path.join(root, 'db/postgres/workshop-migrations/secureshop_agents');
const secret = 'owned-password-overlay-secret-at-least-32-bytes';

function pool(url, max = 6) {
  return new Pool({ connectionString: url, max, statement_timeout: 15000,
    lock_timeout: 3000, application_name: 'owasp-ai-goat-password-overlay-native' });
}
function scope(overrides = {}) {
  return Object.freeze({ launchId: randomUUID(), scenarioId: randomUUID(), generation: 1,
    platformOwnerId: 8101, platformSessionId: 8201, ...overrides });
}

async function currentTailPreserves(migration, runtime, historicalFresh = false) {
  const snapshot = async () => ({
    sessions: (await runtime.query('SELECT session_id,credential_version,revoked_at FROM secureshop_agents.bound_persona_sessions ORDER BY session_id')).rows,
    credentials: (await runtime.query('SELECT to_jsonb(c) AS row FROM secureshop_agents.bound_persona_credentials c ORDER BY platform_launch_id,shop_user_id')).rows,
    receipts: (await runtime.query('SELECT to_jsonb(r) AS row FROM secureshop_agents.bound_persona_credential_cleanup_receipts r ORDER BY platform_launch_id')).rows,
  });
  const before = await snapshot();
  if (historicalFresh) {
    assert.deepEqual(await view16.migrate(migration, agentsMigrations), ['0016_secureshop_bound_api_keys.sql']);
    assert.deepEqual(await view16.migrate(migration, agentsMigrations), []);
    assert.deepEqual(await snapshot(), before);
  }
  const prior = (await migration.query('SELECT name,checksum FROM dvaia_migrations.ledger ORDER BY name')).rows;
  const full = await readMigrations(agentsMigrations);
  assert.deepEqual(await migrate(migration, agentsMigrations), full.filter(row => Number(row.name.slice(0,4)) > 16).map(row => row.name));
  assert.deepEqual(await migrate(migration, agentsMigrations), []);
  const after = (await migration.query('SELECT name,checksum FROM dvaia_migrations.ledger ORDER BY name')).rows;
  assert.deepEqual(after, full.map(({name,checksum}) => ({name,checksum})));
  assert.deepEqual(after.slice(0,prior.length), prior);
  assert.deepEqual(await snapshot(), before);
}

function expires(minutes = 30) { return new Date(Date.now() + minutes * 60000).toISOString(); }
function assertDisposable(url) {
  const parsed = new URL(url);
  assert.ok(['127.0.0.1', 'localhost'].includes(parsed.hostname));
  assert.match(parsed.pathname, /^\/owasp_ai_goat_test_[a-z0-9_]+$/);
}
async function prepareCommerce(migration) {
  await migrate(migration, path.join(root, 'db/postgres/workshop-migrations/secureshop'));
  await migration.query('BEGIN');
  try { await seedSecureShop(migration); await migration.query('COMMIT'); }
  catch (error) { await migration.query('ROLLBACK'); throw error; }
}
function launches() {
  return { async assertCurrent(value) { return { ...value,
    expiresAt: new Date(Date.now() + 60 * 60000).toISOString() }; } };
}
function jti(token) { return jwt.decode(token).jti; }

// This is a root-launched disposable PostgreSQL test. It never targets an app database.
test('fresh selected bounded cohort preserves password fencing before the separate current tail', {
  skip: !enabled, timeout: 60000,
}, async t => {
  const urls = Object.fromEntries(stores.flatMap(store => ['MIGRATION', 'RUNTIME'].map(role => {
    const key = `${PREFIX}${store}_${role}_URL`; assertDisposable(process.env[key]);
    return [`${store}_${role}`, process.env[key]];
  })));
  const commerceMigration = pool(urls.COMMERCE_MIGRATION);
  const commerceRuntime = pool(urls.COMMERCE_RUNTIME);
  const migration = pool(urls.FRESH_AGENTS_MIGRATION, 8);
  const runtime = pool(urls.FRESH_AGENTS_RUNTIME, 12);
  t.after(async () => Promise.allSettled([
    runtime.end(), migration.end(), commerceRuntime.end(), commerceMigration.end(),
  ]));
  await prepareCommerce(commerceMigration);
  const applied = await freshView.migrate(migration, agentsMigrations);
  assert.ok(applied.includes('0015_secureshop_bound_password_overlay.sql'));
  assert.equal(applied.at(-1), freshCohort === 'historical-0015'
    ? '0015_secureshop_bound_password_overlay.sql' : '0016_secureshop_bound_api_keys.sql');
  assert.deepEqual(await freshView.migrate(migration, agentsMigrations), []);

  const repository = createSecureShopBoundPersonaRepository({
    commercePool: commerceRuntime, agentsPool: runtime,
  });
  const auth = createSecureShopBoundPersonaAuth({ repository, launches: launches(), jwtSecret: secret });
  const owner = scope();
  const sibling = scope({ platformOwnerId: owner.platformOwnerId + 1,
    platformSessionId: owner.platformSessionId + 1 });
  // The first credential lookup initializes the immutable templates.
  const first = await auth.login({ scope: owner, username: 'student_customer', password: 'student123' });
  const templateBefore = (await runtime.query(`SELECT password_hash,source_sha256
    FROM secureshop_agents.bound_persona_templates WHERE username='student_customer'`)).rows[0];
  const second = await auth.login({ scope: owner, username: 'student_customer', password: 'student123' });
  const siblingLogin = await auth.login({ scope: sibling, username: 'student_customer', password: 'student123' });
  const firstRow = await repository.readSession({ scope: owner, jti: jti(first.token) });
  const secondRow = await repository.readSession({ scope: owner, jti: jti(second.token) });
  const siblingRow = await repository.readSession({ scope: sibling, jti: jti(siblingLogin.token) });
  assert.ok(firstRow && secondRow && siblingRow);

  const replacements = ['owner-password-a', 'owner-password-b'];
  const raced = await Promise.allSettled(replacements.map(newPassword => auth.changePassword({
    scope: owner, shopPersona: { id: Number(first.user.id), role: 'customer' },
    currentSessionId: firstRow.session_id, currentPassword: 'student123', newPassword,
  })));
  assert.equal(raced.filter(result => result.status === 'fulfilled').length, 1);
  assert.equal(raced.filter(result => result.status === 'rejected'
    && result.reason?.code === 'SHOP_PASSWORD_MISMATCH').length, 1);
  const loginResults = await Promise.allSettled(replacements.map(password => auth.login({
    scope: owner, username: 'student_customer', password,
  })));
  assert.equal(loginResults.filter(result => result.status === 'fulfilled').length, 1);
  const winner = replacements[loginResults.findIndex(result => result.status === 'fulfilled')];
  await assert.rejects(auth.login({ scope: owner, username: 'student_customer',
    password: 'student123' }), { code: 'SHOP_CREDENTIALS_INVALID' });

  assert.ok(await repository.readSession({ scope: owner, jti: jti(first.token) }));
  assert.equal(await repository.readSession({ scope: owner, jti: jti(second.token) }), null);
  assert.ok(await repository.readSession({ scope: sibling, jti: jti(siblingLogin.token) }));
  const overlay = (await runtime.query(`SELECT credential_version,password_hash
    FROM secureshop_agents.bound_persona_credentials WHERE platform_launch_id=$1`,
  [owner.launchId])).rows[0];
  assert.equal(Number(overlay.credential_version), 2);
  assert.equal(await bcrypt.compare(winner, overlay.password_hash), true);
  assert.equal((await runtime.query(`SELECT credential_version,revoked_at FROM
    secureshop_agents.bound_persona_sessions WHERE session_id=$1`, [firstRow.session_id])).rows[0]
    .credential_version, '2');

  const staleCredential = await repository.findCredential('student_customer', owner);
  await assert.rejects(repository.createSession({ sessionId: randomUUID(), jti: 'stale-login-race',
    scope: owner, persona: staleCredential, expiresAt: expires(), credentialVersion: 1 }),
  { code: 'SHOP_CREDENTIALS_INVALID' });

  await auth.changePassword({ scope: sibling,
    shopPersona: { id: Number(siblingLogin.user.id), role: 'customer' },
    currentSessionId: siblingRow.session_id, currentPassword: 'student123',
    newPassword: 'sibling-password' });
  const siblingHash = (await repository.findCredential('student_customer', sibling)).password;
  const lifecycle = createSecureShopConversationLifecycleRepository({ pool: runtime });
  const ownerResetId = randomUUID();
  await lifecycle.beginRetirement({ resetId: ownerResetId, binding: owner });
  await lifecycle.completeRetirement({ resetId: ownerResetId, binding: owner });
  const receipt = await repository.readCredentialCleanupReceipt(owner);
  assert.equal(receipt.deletedCredentialCount, 1);
  assert.match(receipt.receiptSha256, /^[0-9a-f]{64}$/);
  assert.equal((await runtime.query(`SELECT count(*)::integer AS count
    FROM secureshop_agents.bound_persona_credentials WHERE platform_launch_id=$1`,
  [owner.launchId])).rows[0].count, 0);
  assert.equal((await repository.findCredential('student_customer', sibling)).password, siblingHash);
  assert.equal(await repository.readSession({ scope: sibling, jti: jti(siblingLogin.token) }) !== null, true);
  assert.equal((await repository.findCredential('student_customer', owner)).password,
    templateBefore.password_hash);
  const templateAfter = (await runtime.query(`SELECT password_hash,source_sha256
    FROM secureshop_agents.bound_persona_templates WHERE username='student_customer'`)).rows[0];
  assert.equal(templateAfter.password_hash, templateBefore.password_hash);
  assert.equal(Buffer.compare(templateAfter.source_sha256, templateBefore.source_sha256), 0);
  await currentTailPreserves(migration, runtime, freshCohort === 'historical-0015');
});

test('populated 0014 sessions migrate through exact 0015 and 0016 before the current tail', {
  skip: !enabled, timeout: 30000,
}, async t => {
  const commerceMigration = pool(process.env[`${PREFIX}COMMERCE_MIGRATION_URL`]);
  const commerceRuntime = pool(process.env[`${PREFIX}COMMERCE_RUNTIME_URL`]);
  const migration = pool(process.env[`${PREFIX}POPULATED_AGENTS_MIGRATION_URL`]);
  const runtime = pool(process.env[`${PREFIX}POPULATED_AGENTS_RUNTIME_URL`]);
  t.after(async () => Promise.allSettled([
    runtime.end(), migration.end(), commerceRuntime.end(), commerceMigration.end(),
  ]));
  await prepareCommerce(commerceMigration);
  const prefix = view14.directory;
  assert.equal((await view14.migrate(migration, prefix)).at(-1),
    '0014_secureshop_bound_session_inventory.sql');
  assert.deepEqual(await view14.migrate(migration, prefix), []);
  const repository = createSecureShopBoundPersonaRepository({
    commercePool: commerceRuntime, agentsPool: runtime,
  });
  await repository.ensureTemplates();
  const customer = (await runtime.query(`SELECT shop_user_id AS id,username,email,role,full_name,phone
    FROM secureshop_agents.bound_persona_templates WHERE username='student_customer'`)).rows[0];
  const retired = scope({ platformOwnerId: 8301, platformSessionId: 8401 });
  const active = scope({ platformOwnerId: 8501, platformSessionId: 8601 });
  async function insertSession(target, sessionId, token, revoked = false) {
    await runtime.query(`INSERT INTO secureshop_agents.bound_persona_sessions
      (session_id,jti_sha256,platform_launch_id,platform_scenario_id,
       platform_launch_generation,original_platform_owner_id,original_platform_session_id,
       shop_user_id,username,role,email,full_name,phone,expires_at,ip,user_agent,last_seen_at)
      VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,NULL,NULL,clock_timestamp())`,
    [sessionId, createHash('sha256').update(token).digest(), target.launchId,target.scenarioId,
      target.generation,target.platformOwnerId,target.platformSessionId,customer.id,customer.username,
      customer.role,customer.email,customer.full_name,customer.phone,expires()]);
    if (revoked) await runtime.query(`UPDATE secureshop_agents.bound_persona_sessions
      SET revoked_at=clock_timestamp() WHERE session_id=$1`, [sessionId]);
  }
  await insertSession(retired, randomUUID(), 'retired-active');
  await insertSession(active, randomUUID(), 'preserved-active');
  await insertSession(active, randomUUID(), 'preserved-revoked', true);
  const lifecycle = createSecureShopConversationLifecycleRepository({ pool: runtime });
  const retiredResetId = randomUUID();
  await lifecycle.beginRetirement({ resetId: retiredResetId, binding: retired });
  await lifecycle.completeRetirement({ resetId: retiredResetId, binding: retired });

  const through0015 = view15.directory;
  assert.deepEqual(await view15.migrate(migration, through0015),
    ['0015_secureshop_bound_password_overlay.sql']);
  assert.deepEqual(await view15.migrate(migration, through0015), []);
  assert.deepEqual(await view16.migrate(migration, agentsMigrations),
    ['0016_secureshop_bound_api_keys.sql']);
  assert.deepEqual(await view16.migrate(migration, agentsMigrations), []);
  const rows = (await runtime.query(`SELECT credential_version,revoked_at
    FROM secureshop_agents.bound_persona_sessions WHERE platform_launch_id=$1
    ORDER BY session_id`, [active.launchId])).rows;
  assert.equal(rows.length, 2);
  assert.ok(rows.every(row => Number(row.credential_version) === 1));
  assert.equal(rows.filter(row => row.revoked_at === null).length, 1);
  const receipt = await repository.readCredentialCleanupReceipt(retired);
  assert.equal(receipt.deletedCredentialCount, 0);
  assert.match(receipt.receiptSha256, /^[0-9a-f]{64}$/);
  await assert.rejects(runtime.query(`UPDATE secureshop_agents.bound_persona_credential_cleanup_receipts
    SET deleted_credential_count=1 WHERE platform_launch_id=$1`, [retired.launchId]),
  { code: '42501' });
  await assert.rejects(migration.query(`UPDATE secureshop_agents.bound_persona_credential_cleanup_receipts
    SET deleted_credential_count=1 WHERE platform_launch_id=$1`, [retired.launchId]),
  { code: '55000' });
  await currentTailPreserves(migration, runtime);
});
