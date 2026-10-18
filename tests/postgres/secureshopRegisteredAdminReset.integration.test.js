'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const { createHash, randomBytes, randomUUID } = require('node:crypto');
const { Module, createRequire } = require('node:module');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const { migrate } = require('../../db/postgres/migrate');
const { createSecureShopStandaloneAuthRepository } = require('../../server/database/postgres/secureshopStandaloneAuthRepository');
const { createSecureShopStandaloneAuthService } = require('../../server/services/secureshopStandaloneAuth');
const { seedSecureShopStandaloneDefaults } = require('../../server/database/postgres/secureshopStandaloneSeed');
const { createRegisteredAdminResetRepository } = require('../../server/database/postgres/secureshopRegisteredAdminResetRepository');
const { createRegisteredAdminResetService } = require('../../server/services/secureshopRegisteredAdminReset');
const { createRegisteredAdminResetEnvelope } = require('../../server/services/secureshopRegisteredAdminResetEnvelope');

const prefix = 'PG_SECURESHOP_REGISTERED_RESET_';
const keys = ['IDENTITY_RUNTIME_URL', 'IDENTITY_MIGRATION_URL'];
const enabled = process.env.SECURESHOP_REGISTERED_ADMIN_RESET_NATIVE === '1'
  && process.env.PG_TEST_DISPOSABLE === 'yes' && keys.every(key => process.env[prefix + key]);
const directory = path.resolve(__dirname, '../../db/postgres/identity-migrations');
const migrationName = '0144_secureshop_registered_admin_reset.sql';

function disposableUrl(key) {
  const url = new URL(process.env[prefix + key]);
  assert.equal(url.protocol, 'postgresql:');
  assert.equal(url.hostname, '127.0.0.1');
  assert.match(url.pathname, /^\/dvaia_test_[a-z0-9_]+$/);
  assert.equal(url.password, '');
  assert.equal(url.search, '');
  assert.equal(url.hash, '');
  return url.href;
}

// Filter the migration inventory in memory; the original migration files stay intact.
function historicalMigrator(ceiling) {
  const filename = require.resolve('../../db/postgres/migrate');
  const local = createRequire(filename);
  const original = require('node:fs/promises');
  const virtual = { ...original, async readdir(target, ...args) {
    const names = await original.readdir(target, ...args);
    return path.resolve(target) === directory
      ? names.filter(name => !/^\d{4}_[a-z0-9_]+\.sql$/.test(name)
        || Number(name.slice(0, 4)) <= ceiling) : names;
  } };
  const loaded = new Module(filename, module);
  loaded.filename = filename;
  loaded.require = name => name === 'node:fs/promises' ? virtual : local(name);
  loaded._compile(require('node:fs').readFileSync(filename, 'utf8'), filename);
  return loaded.exports.migrate;
}

function resetInput(target, operationId = randomUUID()) {
  return { targetId: target.id, operationId,
    expectedCredentialVersion: target.credentialVersion,
    expectedAuthorityVersion: target.authorityVersion,
    expectedMembershipVersion: target.membershipVersion };
}

test('registered administrator reset preserves history and fences credentials across tenants',
  { skip: !enabled, timeout: 180000 }, async t => {
    assert.equal(path.resolve(process.env.DVAIA_CURRENT_MAIN_WORKSPACE || '/'), process.cwd());
    const evidencePath = process.env.SECURESHOP_REGISTERED_ADMIN_RESET_EVIDENCE_PATH || '';
    assert.ok(path.isAbsolute(evidencePath));
    assert.ok(!path.resolve(evidencePath).startsWith(`${process.cwd()}${path.sep}`));
    const migration = new Pool({ connectionString: disposableUrl('IDENTITY_MIGRATION_URL'), max: 2 });
    const runtime = new Pool({ connectionString: disposableUrl('IDENTITY_RUNTIME_URL'), max: 8 });
    t.after(() => Promise.allSettled([migration.end(), runtime.end()]));

    await historicalMigrator(143)(migration, directory);
    const sql = await fs.readFile(path.join(directory, migrationName), 'utf8');
    const preview = await migration.connect();
    try {
      await preview.query('BEGIN');
      await preview.query(sql);
      assert.equal((await preview.query(`SELECT count(*)::integer AS n
        FROM secureshop_auth.registered_admin_reset_operations`)).rows[0].n, 0);
      await preview.query('ROLLBACK');
    } catch (error) { await preview.query('ROLLBACK').catch(() => {}); throw error; }
    finally { preview.release(); }
    assert.equal((await migration.query(`SELECT to_regclass('secureshop_auth.registered_admin_reset_operations') AS relation`)).rows[0].relation, null);

    // Representative existing platform and shop rows predate the additive migration.
    const historicalName = `reset_history_${randomUUID().slice(0, 8)}`;
    const historicalPassword = await bcrypt.hash('historical platform fixture', 4);
    const historicalUser = (await migration.query(`INSERT INTO identity.users
      (username,email,password) VALUES($1,$2,$3) RETURNING id`,
    [historicalName, `${historicalName}@platform.invalid`, historicalPassword])).rows[0];
    const platformToken = randomUUID();
    const historicalSession = (await migration.query(`INSERT INTO identity.user_sessions
      (user_id,session_token_hash,expires_at) VALUES($1,$2,$3) RETURNING id`,
    [historicalUser.id, createHash('sha256').update(platformToken).digest('hex'),
      new Date(Date.now() + 3600000).toISOString()])).rows[0];
    const auth = createSecureShopStandaloneAuthService({
      repository: createSecureShopStandaloneAuthRepository({ pool: runtime }),
    });
    assert.deepEqual(await seedSecureShopStandaloneDefaults(runtime), { seeded: true });
    const admin = await auth.login({ username: 'student_admin', password: 'student123' });
    const customer = await auth.login({ username: 'student_customer', password: 'student123' });
    const customerSiblingSession = await auth.login({ username: 'student_customer', password: 'student123' });
    const merchant = await auth.login({ username: 'student_merchant', password: 'student123' });
    const adminExecution = await auth.establishTenantContext(admin.context);
    const customerExecution = await auth.establishTenantContext(customer.context);
    await auth.establishTenantContext(customerSiblingSession.context);
    await auth.establishTenantContext(merchant.context);
    const principalIds = [admin.context.principalId, customer.context.principalId, merchant.context.principalId];
    const historical = {
      user: (await migration.query(`SELECT * FROM identity.users WHERE id=$1`, [historicalUser.id])).rows,
      session: (await migration.query(`SELECT * FROM identity.user_sessions WHERE id=$1`, [historicalSession.id])).rows,
      principals: (await migration.query(`SELECT * FROM secureshop_auth.principals
        WHERE principal_id=ANY($1::uuid[]) ORDER BY principal_id`, [principalIds])).rows,
      sessions: (await migration.query(`SELECT * FROM secureshop_auth.sessions
        WHERE principal_id=ANY($1::uuid[]) ORDER BY session_id`, [principalIds])).rows,
      executions: (await migration.query(`SELECT * FROM secureshop_auth.execution_sessions
        WHERE principal_id=ANY($1::uuid[]) ORDER BY session_id`, [principalIds])).rows,
    };
    assert.deepEqual(await migrate(migration, directory), [migrationName]);
    assert.deepEqual((await migration.query(`SELECT * FROM identity.users WHERE id=$1`, [historicalUser.id])).rows, historical.user);
    assert.deepEqual((await migration.query(`SELECT * FROM identity.user_sessions WHERE id=$1`, [historicalSession.id])).rows, historical.session);
    assert.deepEqual((await migration.query(`SELECT * FROM secureshop_auth.principals
      WHERE principal_id=ANY($1::uuid[]) ORDER BY principal_id`, [principalIds])).rows, historical.principals);
    assert.deepEqual((await migration.query(`SELECT * FROM secureshop_auth.sessions
      WHERE principal_id=ANY($1::uuid[]) ORDER BY session_id`, [principalIds])).rows, historical.sessions);
    assert.deepEqual((await migration.query(`SELECT * FROM secureshop_auth.execution_sessions
      WHERE principal_id=ANY($1::uuid[]) ORDER BY session_id`, [principalIds])).rows, historical.executions);
    assert.deepEqual(await migrate(migration, directory), []);

    let clock = Date.now();
    const envelope = createRegisteredAdminResetEnvelope({
      activeKeyId: 'fixture-key', keys: new Map([['fixture-key', randomBytes(32)]]), now: () => clock,
    });
    const repository = createRegisteredAdminResetRepository({ pool: runtime, envelope, now: () => clock });
    assert.deepEqual(await repository.checkReadiness(), { ready: true });
    const reset = createRegisteredAdminResetService({ repository });
    const customerTarget = await reset.preview({ token: admin.token, targetId: customer.user.id });
    assert.equal(customerTarget.id, customer.user.id);
    assert.equal(customerTarget.resetAvailable, true);
    assert.equal(adminExecution.role, 'admin');
    assert.equal(customerExecution.role, 'customer');
    await assert.rejects(reset.preview({ token: customer.token, targetId: merchant.user.id }), { code: 'SHOP_AUTH_INVALID' });
    await assert.rejects(reset.preview({ token: merchant.token, targetId: customer.user.id }), { code: 'SHOP_AUTH_INVALID' });
    await assert.rejects(reset.preview({ token: 'A'.repeat(43), targetId: customer.user.id }), { code: 'SHOP_AUTH_INVALID' });

    const otherTenantId = randomUUID();
    const suffix = randomUUID().slice(0, 8);
    await migration.query(`INSERT INTO secureshop_auth.tenants(tenant_id,slug) VALUES($1,$2)`,
      [otherTenantId, `reset_${suffix}`]);
    await migration.query(`INSERT INTO secureshop_auth.tenant_memberships
      (tenant_id,principal_id,shop_user_id,role) VALUES($1,$2,$3,'customer')`,
    [otherTenantId, customer.context.principalId, customer.user.id]);
    await assert.rejects(reset.preview({ token: admin.token, targetId: customer.user.id }),
      { code: 'REGISTERED_RESET_FORBIDDEN' });
    await migration.query(`UPDATE secureshop_auth.tenant_memberships
      SET is_active=false,membership_version=membership_version+1
      WHERE tenant_id=$1 AND principal_id=$2`, [otherTenantId, customer.context.principalId]);
    const foreign = await auth.register({ username: `foreign_${suffix}`,
      email: `foreign_${suffix}@fixture.invalid`, password: 'foreign fixture password', role: 'customer' });
    await migration.query(`INSERT INTO secureshop_auth.tenant_memberships
      (tenant_id,principal_id,shop_user_id,role) VALUES($1,$2,$3,'customer')`,
    [otherTenantId, foreign.context.principalId, foreign.user.id]);
    await migration.query(`UPDATE secureshop_auth.tenant_memberships
      SET is_active=false,membership_version=membership_version+1
      WHERE principal_id=$1 AND tenant_id<>(SELECT tenant_id FROM secureshop_auth.tenants WHERE slug=$2)`,
    [foreign.context.principalId, `reset_${suffix}`]);
    await assert.rejects(reset.preview({ token: admin.token, targetId: foreign.user.id }),
      { code: 'REGISTERED_RESET_FORBIDDEN' });

    // A reset waiting behind an in-flight activation must see the committed
    // foreign membership. Exercise both an existing row and an inserted row.
    const deniedRace = () => repository.reset({
      tokenHash: createHash('sha256').update(admin.token).digest('hex'),
      ...resetInput(customerTarget), secret: randomBytes(32).toString('base64url'),
      passwordHash: historicalPassword,
    });
    const activation = await migration.connect();
    try {
      await activation.query('BEGIN');
      await activation.query(`UPDATE secureshop_auth.tenant_memberships
        SET is_active=true,membership_version=membership_version+1
        WHERE tenant_id=$1 AND principal_id=$2`, [otherTenantId, customer.context.principalId]);
      let settled = false;
      const blocked = deniedRace().then(() => { settled = true; return { ok: true }; },
        error => { settled = true; return { ok: false, code: error.code }; });
      await new Promise(resolve => setTimeout(resolve, 80));
      assert.equal(settled, false);
      await activation.query('COMMIT');
      assert.deepEqual(await blocked, { ok: false, code: 'REGISTERED_RESET_FORBIDDEN' });
    } catch (error) { await activation.query('ROLLBACK').catch(() => {}); throw error; }
    finally { activation.release(); }
    await migration.query(`UPDATE secureshop_auth.tenant_memberships
      SET is_active=false,membership_version=membership_version+1
      WHERE tenant_id=$1 AND principal_id=$2`, [otherTenantId, customer.context.principalId]);
    const insertedTenantId = randomUUID();
    await migration.query(`INSERT INTO secureshop_auth.tenants(tenant_id,slug) VALUES($1,$2)`,
      [insertedTenantId, `insert_${suffix}`]);
    const insertion = await migration.connect();
    try {
      await insertion.query('BEGIN');
      await insertion.query(`INSERT INTO secureshop_auth.tenant_memberships
        (tenant_id,principal_id,shop_user_id,role) VALUES($1,$2,$3,'customer')`,
      [insertedTenantId, customer.context.principalId, customer.user.id]);
      let settled = false;
      const blocked = deniedRace().then(() => { settled = true; return { ok: true }; },
        error => { settled = true; return { ok: false, code: error.code }; });
      await new Promise(resolve => setTimeout(resolve, 80));
      assert.equal(settled, false);
      await insertion.query('COMMIT');
      assert.deepEqual(await blocked, { ok: false, code: 'REGISTERED_RESET_FORBIDDEN' });
    } catch (error) { await insertion.query('ROLLBACK').catch(() => {}); throw error; }
    finally { insertion.release(); }
    await migration.query(`UPDATE secureshop_auth.tenant_memberships
      SET is_active=false,membership_version=membership_version+1
      WHERE tenant_id=$1 AND principal_id=$2`, [insertedTenantId, customer.context.principalId]);

    const before = (await migration.query(`SELECT credential_version,authority_version,password_hash
      FROM secureshop_auth.principals WHERE principal_id=$1`, [customer.context.principalId])).rows[0];
    await assert.rejects(reset.reset({ token: admin.token, ...resetInput({ ...customerTarget,
      credentialVersion: String(BigInt(customerTarget.credentialVersion) + 1n) }) }),
    { code: 'REGISTERED_RESET_REVISION_CONFLICT' });
    assert.deepEqual((await migration.query(`SELECT credential_version,authority_version,password_hash
      FROM secureshop_auth.principals WHERE principal_id=$1`, [customer.context.principalId])).rows[0], before);
    assert.equal((await migration.query(`SELECT count(*)::integer AS n
      FROM secureshop_auth.registered_admin_reset_operations`)).rows[0].n, 0);

    const input = resetInput(customerTarget);
    const completed = await reset.reset({ token: admin.token, ...input });
    assert.equal(completed.replayed, false);
    assert.equal(completed.secretAvailable, true);
    assert.equal(completed.receipt.operationId, input.operationId);
    assert.equal(completed.receipt.targetId, customer.user.id);
    assert.match(completed.receipt.receiptSha256, /^[a-f0-9]{64}$/);
    assert.equal(Object.hasOwn(completed, 'temporaryPassword'), false);
    assert.equal(JSON.stringify(completed).includes('passwordHash'), false);
    const receiptRow = (await migration.query(`SELECT * FROM secureshop_auth.registered_admin_reset_operations
      WHERE operation_id=$1`, [input.operationId])).rows[0];
    assert.equal(receiptRow.actor_principal_id, admin.context.principalId);
    assert.equal(receiptRow.actor_auth_session_id, admin.context.sessionId);
    assert.equal(receiptRow.actor_execution_session_id, adminExecution.sessionId);
    assert.equal(receiptRow.target_principal_id, customer.context.principalId);
    assert.equal(JSON.stringify(receiptRow.receipt_json).includes('passwordHash'), false);
    assert.equal((await migration.query(`SELECT envelope_json IS NOT NULL AS sealed
      FROM secureshop_auth.registered_admin_reset_recovery WHERE operation_id=$1`,
    [input.operationId])).rows[0].sealed, true);
    assert.equal(await auth.authenticate(customer.token), null);
    assert.equal(await auth.authenticate(customerSiblingSession.token), null);
    assert.equal((await migration.query(`SELECT count(*)::integer AS n
      FROM secureshop_auth.execution_sessions WHERE principal_id=$1 AND revoked_at IS NULL`,
    [customer.context.principalId])).rows[0].n, 0);
    await assert.rejects(auth.login({ username: 'student_customer', password: 'student123' }),
      { code: 'SHOP_CREDENTIALS_INVALID' });

    const read = await reset.read({ token: admin.token, targetId: customer.user.id,
      operationId: input.operationId });
    assert.deepEqual(read.receipt, completed.receipt);
    assert.equal(read.secretAvailable, true);
    const revealed = await reset.reveal({ token: admin.token, targetId: customer.user.id,
      operationId: input.operationId });
    assert.deepEqual(revealed.receipt, completed.receipt);
    assert.match(revealed.temporaryPassword, /^[A-Za-z0-9_-]{43}$/);
    const changed = await auth.login({ username: 'student_customer',
      password: revealed.temporaryPassword });
    assert.equal(changed.user.id, customer.user.id);
    const replayed = await reset.reset({ token: admin.token, ...input });
    assert.equal(replayed.replayed, true);
    assert.deepEqual(replayed.receipt, completed.receipt);
    assert.equal((await migration.query(`SELECT credential_version,authority_version
      FROM secureshop_auth.principals WHERE principal_id=$1`, [customer.context.principalId])).rows[0].credential_version,
      String(BigInt(customerTarget.credentialVersion) + 1n));
    await assert.rejects(reset.reset({ token: admin.token, ...input,
      expectedAuthorityVersion: String(BigInt(input.expectedAuthorityVersion) + 1n) }),
    { code: 'REGISTERED_RESET_CONFLICT' });
    await assert.rejects(reset.read({ token: merchant.token, targetId: customer.user.id,
      operationId: input.operationId }), { code: 'SHOP_AUTH_INVALID' });

    const acknowledged = await reset.acknowledge({ token: admin.token,
      targetId: customer.user.id, operationId: input.operationId });
    assert.deepEqual(acknowledged.receipt, completed.receipt);
    assert.equal(acknowledged.secretAvailable, false);
    assert.equal((await reset.read({ token: admin.token, targetId: customer.user.id,
      operationId: input.operationId })).secretAvailable, false);
    await assert.rejects(reset.reveal({ token: admin.token, targetId: customer.user.id,
      operationId: input.operationId }), { code: 'REGISTERED_RESET_RECOVERY_UNAVAILABLE' });
    assert.deepEqual((await migration.query(`SELECT receipt_json FROM secureshop_auth.registered_admin_reset_operations
      WHERE operation_id=$1`, [input.operationId])).rows[0].receipt_json, receiptRow.receipt_json);
    assert.equal((await migration.query(`SELECT envelope_json FROM secureshop_auth.registered_admin_reset_recovery
      WHERE operation_id=$1`, [input.operationId])).rows[0].envelope_json, null);
    await assert.rejects(runtime.query(`DELETE FROM secureshop_auth.registered_admin_reset_operations
      WHERE operation_id=$1`, [input.operationId]), { code: '42501' });
    await assert.rejects(migration.query(`UPDATE secureshop_auth.registered_admin_reset_operations
      SET receipt_json='{}'::jsonb WHERE operation_id=$1`, [input.operationId]), { code: '55000' });
    clock += 11 * 60 * 1000;
    assert.equal((await reset.read({ token: admin.token, targetId: customer.user.id,
      operationId: input.operationId })).secretAvailable, false);
    assert.equal((await auth.authenticate(admin.token)).principalId, admin.context.principalId);
    assert.equal((await auth.authenticate(merchant.token)).principalId, merchant.context.principalId);
    await fs.writeFile(evidencePath, JSON.stringify({
      passed: true,
      scope: 'Controlled disposable protected registered administrator credential reset; no browser or model qualification',
      freshMigration: true, populatedMigrationPreserved: true, secondRunNoop: true,
      protectedAdminOnly: true, tenantIsolation: true, casReplay: true,
      privateRecovery: true, sessionRevocationFenced: true, siblingPreserved: true,
    }), { mode: 0o600 });
  });
