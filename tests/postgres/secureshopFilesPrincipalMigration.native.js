'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { Module, createRequire } = require('node:module');
const { randomUUID, createHash } = require('node:crypto');
const { Pool } = require('pg');

const ROOT = path.resolve(__dirname, '../..');
const DIRECTORY = path.join(ROOT, 'db/postgres/identity-migrations');
const MIGRATION = '0151_secureshop_files_principal_admission.sql';
const enabled = process.env.PG_TEST_DISPOSABLE === 'yes'
  && Boolean(process.env.V19_ATTACHMENT_POPULATED_MIGRATION_URL);

function url(role) {
  const value = new URL(process.env[`V19_ATTACHMENT_POPULATED_${role}_URL`]);
  assert.equal(value.protocol, 'postgresql:');
  assert.equal(value.hostname, '127.0.0.1');
  assert.equal(value.username, `dvaia_identity_${role.toLowerCase()}`);
  assert.equal(value.password, ''); assert.equal(value.search, ''); assert.equal(value.hash, '');
  assert.match(value.pathname, /^\/owasp_ai_goat_test_persona_populated_[a-f0-9]{12}$/);
  return value.href;
}

function historical(ceiling) {
  const filename = require.resolve('../../db/postgres/migrate');
  const local = createRequire(filename), loaded = new Module(filename, module);
  loaded.filename = filename;
  const original = require('node:fs/promises');
  loaded.require = name => name === 'node:fs/promises' ? {
    ...original, async readdir(selected, ...args) {
      const names = await original.readdir(selected, ...args);
      return path.resolve(selected) === DIRECTORY
        ? names.filter(value => !/^\d{4}_.*\.sql$/.test(value)
          || Number(value.slice(0, 4)) <= ceiling) : names;
    },
  } : local(name);
  loaded._compile(fs.readFileSync(filename, 'utf8'), filename);
  return loaded.exports;
}

test('0151 upgrades populated files debt to immutable principal scope and is an exact no-op on replay',
  { skip: !enabled, timeout: 120000 }, async t => {
    assert.equal(fs.realpathSync(process.cwd()), fs.realpathSync(ROOT));
    const migration = new Pool({ connectionString: url('MIGRATION'), max: 2,
      statement_timeout: 20000, lock_timeout: 5000 });
    const runtime = new Pool({ connectionString: url('RUNTIME'), max: 6,
      statement_timeout: 10000, lock_timeout: 5000 });
    t.after(() => Promise.allSettled([runtime.end(), migration.end()]));
    const prior = historical(150);
    await prior.migrate(migration, DIRECTORY);
    await require('../../server/database/postgres/secureshopStandaloneSeed')
      .seedSecureShopStandaloneDefaults(migration);
    const repository = require('../../server/database/postgres/secureshopStandaloneAuthRepository')
      .createSecureShopStandaloneAuthRepository({ pool: runtime });
    const auth = require('../../server/services/secureshopStandaloneAuth')
      .createSecureShopStandaloneAuthService({ repository });
    const launches = require('../../server/database/postgres/secureshopLaunchRepository')
      .createSecureShopLaunchRepository(runtime);
    async function bootstrap(login) {
      const principal = await auth.establishTenantContext(login.context);
      const result = await launches.issueOrRenew({ platformOwnerId: principal.ownerId,
        platformSessionId: principal.sessionId, expiresAt: principal.expiresAt,
        shopPrincipal: principal });
      return require('../../server/services/secureshopConversationBinding').createLaunchScope(
        await launches.resolveCapability(result.bearer));
    }
    const first = await bootstrap(await auth.login({ username: 'student_customer', password: 'student123' }));
    const legacyShop = await launches.reserveFilesTarget({ ...first, expectedGeneration: first.generation });

    const identities = require('../../server/database/postgres/identityRepository').createIdentityRepository(runtime);
    const passwordHash = await require('bcryptjs').hash('v19-populated-platform', 4);
    const platformUser = await identities.createUser({ username: `v19-platform-${randomUUID().slice(0, 8)}`,
      email: `${randomUUID()}@example.invalid`, passwordHash });
    const expiresAt = new Date(Date.now() + 600000);
    const platformSession = await identities.createSession({ userId: platformUser.id, token: randomUUID(),
      expiresAt, expectedPasswordHash: passwordHash });
    const platform = require('../../server/services/secureshopConversationBinding').createLaunchScope(
      (await launches.issueOrRenew({ platformOwnerId: platformUser.id,
        platformSessionId: platformSession.id, expiresAt })).binding);
    const legacyPlatform = await launches.reserveFilesTarget({ ...platform,
      expectedGeneration: platform.generation });
    const oldRows = (await runtime.query(`SELECT target_id,launch_id,generation,target_kind,
      original_platform_owner_id,created_at FROM identity.secureshop_target_reservations
      WHERE target_id=ANY($1::uuid[]) ORDER BY target_id`,
    [[legacyShop.targetId, legacyPlatform.targetId]])).rows;
    const ledgerBefore = (await migration.query(
      'SELECT name,checksum FROM dvaia_migrations.ledger ORDER BY name')).rows;

    const canonical = require('../../db/postgres/migrate');
    assert.deepEqual(await canonical.migrate(migration, DIRECTORY), [MIGRATION]);
    assert.deepEqual((await runtime.query(`SELECT target_id,launch_id,generation,target_kind,
      original_platform_owner_id,created_at FROM identity.secureshop_target_reservations
      WHERE target_id=ANY($1::uuid[]) ORDER BY target_id`,
    [[legacyShop.targetId, legacyPlatform.targetId]])).rows, oldRows);
    const classified = (await runtime.query(`SELECT target_id,files_owner_slot,
      files_tenant_id::text,files_principal_id::text FROM identity.secureshop_target_reservations
      WHERE target_id=ANY($1::uuid[]) ORDER BY target_id`,
    [[legacyShop.targetId, legacyPlatform.targetId]])).rows;
    const shopRow = classified.find(value => value.target_id === legacyShop.targetId);
    const platformRow = classified.find(value => value.target_id === legacyPlatform.targetId);
    const execution = (await runtime.query(`SELECT e.tenant_id::text,e.principal_id::text
      FROM identity.secureshop_launches l
      JOIN identity.secureshop_authority_sessions s
        ON s.id=l.original_platform_session_id AND s.user_id=l.original_platform_owner_id
      JOIN secureshop_auth.execution_sessions e
        ON e.session_id=s.shop_execution_session_id AND e.session_id=s.id
      WHERE l.launch_id=$1`, [first.launchId])).rows[0];
    assert.deepEqual(shopRow, { target_id: legacyShop.targetId, files_owner_slot: 1,
      files_tenant_id: execution.tenant_id, files_principal_id: execution.principal_id });
    assert.deepEqual(platformRow, { target_id: legacyPlatform.targetId, files_owner_slot: 1,
      files_tenant_id: null, files_principal_id: null });

    const suffix = randomUUID().slice(0, 8);
    const secondLogin = await auth.register({ username: `v19_populated_b_${suffix}`,
      email: `v19_populated_b_${suffix}@example.invalid`, password: 'v19-populated-b', role: 'customer' });
    const second = await bootstrap(secondLogin);
    assert.equal(second.platformOwnerId, first.platformOwnerId);
    const secondTarget = await launches.reserveFilesTarget({ ...second,
      expectedGeneration: second.generation });
    const secondRow = (await runtime.query(`SELECT files_owner_slot,files_tenant_id::text,
      files_principal_id::text FROM identity.secureshop_target_reservations WHERE target_id=$1`,
    [secondTarget.targetId])).rows[0];
    assert.equal(secondRow.files_owner_slot, 2);
    assert.equal(secondRow.files_tenant_id, execution.tenant_id);
    assert.notEqual(secondRow.files_principal_id, execution.principal_id);

    const thirdLogin = await auth.register({ username: `v19_populated_c_${suffix}`,
      email: `v19_populated_c_${suffix}@example.invalid`, password: 'v19-populated-c', role: 'customer' });
    const third = await bootstrap(thirdLogin);
    const forgedTenant = randomUUID(), forgedPrincipal = randomUUID(), thirdTargetId = randomUUID();
    const thirdRow = (await runtime.query(`INSERT INTO identity.secureshop_target_reservations
      (target_id,launch_id,generation,target_kind,original_platform_owner_id,
       files_owner_slot,files_tenant_id,files_principal_id)
      VALUES($1,$2,$3,'files',$4,1,$5,$6)
      RETURNING files_owner_slot,files_tenant_id::text,files_principal_id::text`,
    [thirdTargetId, third.launchId, third.generation, third.platformOwnerId,
      forgedTenant, forgedPrincipal])).rows[0];
    assert.equal(thirdRow.files_owner_slot, 3);
    assert.equal(thirdRow.files_tenant_id, execution.tenant_id);
    assert.notEqual(thirdRow.files_principal_id, forgedPrincipal);

    const concurrent = await Promise.all(['d', 'e'].map(async label => {
      const username = `v19_populated_${label}_${suffix}`;
      return bootstrap(await auth.register({ username, email: `${username}@example.invalid`,
        password: `v19-populated-${label}`, role: 'customer' }));
    }));
    const concurrentRows = await Promise.all(concurrent.map(value => runtime.query(
      `INSERT INTO identity.secureshop_target_reservations
       (target_id,launch_id,generation,target_kind,original_platform_owner_id)
       VALUES($1,$2,$3,'files',$4) RETURNING files_owner_slot,files_principal_id::text`,
      [randomUUID(), value.launchId, value.generation, value.platformOwnerId])));
    assert.equal(new Set(concurrentRows.map(value => value.rows[0].files_owner_slot)).size, 2);
    assert.equal(new Set(concurrentRows.map(value => value.rows[0].files_principal_id)).size, 2);
    const concurrentAuthority = (await runtime.query(`SELECT l.launch_id,
      e.tenant_id::text AS files_tenant_id,e.principal_id::text AS files_principal_id
      FROM identity.secureshop_launches l
      JOIN identity.secureshop_authority_sessions s
        ON s.id=l.original_platform_session_id AND s.user_id=l.original_platform_owner_id
      JOIN secureshop_auth.execution_sessions e
        ON e.session_id=s.shop_execution_session_id AND e.session_id=s.id
      WHERE l.launch_id=ANY($1::uuid[]) ORDER BY l.launch_id`,
    [concurrent.map(value => value.launchId)])).rows;
    const concurrentTargets = (await runtime.query(`SELECT r.launch_id,
      r.files_tenant_id::text,r.files_principal_id::text
      FROM identity.secureshop_target_reservations r
      WHERE r.launch_id=ANY($1::uuid[]) ORDER BY r.launch_id`,
    [concurrent.map(value => value.launchId)])).rows;
    assert.deepEqual(concurrentTargets, concurrentAuthority);

    const conflictName = `v19_populated_conflict_${suffix}`;
    const conflictFirstLogin = await auth.register({ username: conflictName,
      email: `${conflictName}@example.invalid`, password: 'v19-populated-conflict', role: 'customer' });
    const conflictScopes = await Promise.all([
      bootstrap(conflictFirstLogin),
      bootstrap(await auth.login({ username: conflictName, password: 'v19-populated-conflict' })),
    ]);
    const conflicts = await Promise.allSettled(conflictScopes.map(value => runtime.query(
      `INSERT INTO identity.secureshop_target_reservations
       (target_id,launch_id,generation,target_kind,original_platform_owner_id)
       VALUES($1,$2,$3,'files',$4)`,
      [randomUUID(), value.launchId, value.generation, value.platformOwnerId])));
    assert.equal(conflicts.filter(value => value.status === 'fulfilled').length, 1);
    const conflict = conflicts.find(value => value.status === 'rejected');
    assert.equal(conflict.reason.code, '23505');

    await assert.rejects(migration.query(`DELETE FROM secureshop_auth.tenant_memberships
      WHERE tenant_id=$1 AND principal_id=$2`,
    [secondRow.files_tenant_id, secondRow.files_principal_id]), { code: '55000' });
    const filesMembership = (await migration.query(`SELECT convalidated,
      pg_get_constraintdef(oid) AS definition FROM pg_constraint
      WHERE conrelid='identity.secureshop_target_reservations'::regclass
        AND conname='secureshop_files_principal_membership'`)).rows[0];
    assert.equal(filesMembership.convalidated, true);
    assert.match(filesMembership.definition,
      /FOREIGN KEY \(files_tenant_id, files_principal_id\) REFERENCES secureshop_auth\.tenant_memberships\(tenant_id, principal_id\)/);

    const platformUser2 = await identities.createUser({ username: `v19-platform-2-${suffix}`,
      email: `${randomUUID()}@example.invalid`, passwordHash });
    const platformSession2 = await identities.createSession({ userId: platformUser2.id,
      token: randomUUID(), expiresAt, expectedPasswordHash: passwordHash });
    const platform2 = require('../../server/services/secureshopConversationBinding').createLaunchScope(
      (await launches.issueOrRenew({ platformOwnerId: platformUser2.id,
        platformSessionId: platformSession2.id, expiresAt })).binding);
    const suppliedPlatform = (await runtime.query(`INSERT INTO identity.secureshop_target_reservations
      (target_id,launch_id,generation,target_kind,original_platform_owner_id,
       files_owner_slot,files_tenant_id,files_principal_id)
      VALUES($1,$2,$3,'files',$4,7,$5,$6)
      RETURNING files_owner_slot,files_tenant_id,files_principal_id`,
    [randomUUID(), platform2.launchId, platform2.generation, platform2.platformOwnerId,
      randomUUID(), randomUUID()])).rows[0];
    assert.deepEqual(suppliedPlatform, { files_owner_slot: 1,
      files_tenant_id: null, files_principal_id: null });
    for (const kind of ['persona_inbox', 'products', 'reviews']) {
      const row = (await runtime.query(`INSERT INTO identity.secureshop_target_reservations
        (target_id,launch_id,generation,target_kind,original_platform_owner_id)
        VALUES($1,$2,$3,$4,$5)
        RETURNING target_kind,files_owner_slot,files_tenant_id,files_principal_id,
          product_owner_slot,review_owner_slot`, [randomUUID(), platform2.launchId,
        platform2.generation, kind, platform2.platformOwnerId])).rows[0];
      assert.equal(row.target_kind, kind);
      assert.equal(row.files_owner_slot, null); assert.equal(row.files_tenant_id, null);
      assert.equal(row.files_principal_id, null);
      if (kind === 'products') assert.equal(row.product_owner_slot, 1);
      if (kind === 'reviews') assert.equal(row.review_owner_slot, 1);
    }

    // Exercise the database ceiling independently from the launch ceiling. A
    // dedicated tenant owns 256 valid, principal-scoped files reservations.
    // Revoking one canonical auth session makes its launch stop consuming a
    // live-launch slot without deleting that launch's unresolved files debt;
    // a 257th launch is therefore admitted, but its files target must fail at
    // the target-reservation ceiling with every prior reservation unchanged.
    const capTenantId = randomUUID();
    const capTenant = (await migration.query(`INSERT INTO secureshop_auth.tenants(tenant_id,slug)
      VALUES($1,$2) RETURNING tenant_id::text,owner_id`,
    [capTenantId, `v19cap_${suffix}`])).rows[0];
    const capEntries = Array.from({ length: 257 }, (_, index) => {
      const ordinal = String(index + 1).padStart(3, '0');
      const token = createHash('sha256').update(`v19-cap-${suffix}-${ordinal}`).digest('base64url');
      return Object.freeze({ principalId: randomUUID(), username: `v19cap${suffix}${ordinal}`,
        email: `v19cap${suffix}${ordinal}@example.invalid`, token,
        tokenHash: createHash('sha256').update(token).digest('hex'),
        launchId: randomUUID(), scenarioId: randomUUID() });
    });
    await migration.query(`INSERT INTO secureshop_auth.principals
      (principal_id,username,email,password_hash,role)
      SELECT principal_id,username,email,$4,'customer'
      FROM unnest($1::uuid[],$2::text[],$3::text[])
        AS input(principal_id,username,email)`, [
      capEntries.map(value => value.principalId), capEntries.map(value => value.username),
      capEntries.map(value => value.email),
      '$2b$12$Lb7ZNghYLnE8hlO/ERYzFuMP/9iUqy6V3ibYldFSE73Z1A/GMiEJG',
    ]);
    await migration.query(`INSERT INTO secureshop_auth.tenant_memberships
      (tenant_id,principal_id,shop_user_id,role)
      SELECT $1,p.principal_id,p.shop_user_id,'customer'
      FROM secureshop_auth.principals p WHERE p.principal_id=ANY($2::uuid[])`,
    [capTenantId, capEntries.map(value => value.principalId)]);
    const capExpiry = new Date(Date.now() + 600000).toISOString();
    await migration.query(`INSERT INTO secureshop_auth.sessions
      (principal_id,token_hash,credential_version,authority_version,expires_at)
      SELECT principal_id,token_hash,1,1,$3::timestamptz
      FROM unnest($1::uuid[],$2::text[]) AS input(principal_id,token_hash)`, [
      capEntries.map(value => value.principalId), capEntries.map(value => value.tokenHash), capExpiry,
    ]);
    await migration.query(`INSERT INTO secureshop_auth.execution_sessions
      (auth_session_id,tenant_id,principal_id,membership_version,expires_at)
      SELECT s.session_id,$1,s.principal_id,1,s.expires_at
      FROM secureshop_auth.sessions s WHERE s.token_hash=ANY($2::text[])`,
    [capTenantId, capEntries.map(value => value.tokenHash)]);
    const firstCapEntries = capEntries.slice(0, 256);
    await runtime.query(`INSERT INTO identity.secureshop_launches
      (launch_id,platform_session_id,original_platform_session_id,original_platform_owner_id,
       handle_hash,scenario_id,expires_at)
      SELECT input.launch_id,e.session_id,e.session_id,$4,
        decode(md5(input.launch_id::text)||md5('v19-cap-'||input.launch_id::text),'hex'),
        input.scenario_id,$5::timestamptz
      FROM unnest($1::uuid[],$2::uuid[],$3::uuid[])
        AS input(launch_id,scenario_id,principal_id)
      JOIN secureshop_auth.execution_sessions e USING(principal_id)`, [
      firstCapEntries.map(value => value.launchId), firstCapEntries.map(value => value.scenarioId),
      firstCapEntries.map(value => value.principalId), capTenant.owner_id, capExpiry,
    ]);
    await runtime.query(`INSERT INTO identity.secureshop_target_reservations
      (target_id,launch_id,generation,target_kind,original_platform_owner_id)
      SELECT input.target_id,input.launch_id,1,'files',$3
      FROM unnest($1::uuid[],$2::uuid[]) AS input(target_id,launch_id)`, [
      firstCapEntries.map(() => randomUUID()), firstCapEntries.map(value => value.launchId),
      capTenant.owner_id,
    ]);
    const capBefore = (await runtime.query(`SELECT target_id,launch_id,files_owner_slot,
      files_tenant_id::text,files_principal_id::text
      FROM identity.secureshop_target_reservations
      WHERE original_platform_owner_id=$1 AND target_kind='files'
      ORDER BY files_owner_slot`, [capTenant.owner_id])).rows;
    assert.equal(capBefore.length, 256);
    assert.deepEqual(capBefore.map(value => value.files_owner_slot),
      Array.from({ length: 256 }, (_, index) => index + 1));
    assert.equal(capBefore.every(value => value.files_tenant_id === capTenant.tenant_id), true);
    assert.equal(await auth.logout(capEntries[0].token), true);
    assert.equal((await runtime.query(`SELECT identity.secureshop_launch_consumes_capacity($1) AS live`,
    [capEntries[0].launchId])).rows[0].live, false);
    const lastCap = capEntries[256];
    const lastExecution = (await runtime.query(`SELECT session_id FROM secureshop_auth.execution_sessions
      WHERE principal_id=$1`, [lastCap.principalId])).rows[0];
    await runtime.query(`INSERT INTO identity.secureshop_launches
      (launch_id,platform_session_id,original_platform_session_id,original_platform_owner_id,
       handle_hash,scenario_id,expires_at)
      VALUES($1::uuid,$2::integer,$2::integer,$3::integer,
        decode(md5(($1::uuid)::text)||md5('v19-cap-'||($1::uuid)::text),'hex'),
        $4::uuid,$5::timestamptz)`,
    [lastCap.launchId, lastExecution.session_id, capTenant.owner_id, lastCap.scenarioId, capExpiry]);
    assert.equal((await runtime.query(`SELECT count(*)::int AS count
      FROM identity.secureshop_launch_capacity WHERE original_platform_owner_id=$1`,
    [capTenant.owner_id])).rows[0].count, 256);
    await assert.rejects(runtime.query(`INSERT INTO identity.secureshop_target_reservations
      (target_id,launch_id,generation,target_kind,original_platform_owner_id)
      VALUES($1,$2,1,'files',$3)`, [randomUUID(), lastCap.launchId, capTenant.owner_id]),
    { code: '54000' });
    assert.deepEqual((await runtime.query(`SELECT target_id,launch_id,files_owner_slot,
      files_tenant_id::text,files_principal_id::text
      FROM identity.secureshop_target_reservations
      WHERE original_platform_owner_id=$1 AND target_kind='files'
      ORDER BY files_owner_slot`, [capTenant.owner_id])).rows, capBefore);

    const firstNext = await bootstrap(await auth.login({ username: 'student_customer', password: 'student123' }));
    await assert.rejects(runtime.query(`INSERT INTO identity.secureshop_target_reservations
      (target_id,launch_id,generation,target_kind,original_platform_owner_id)
      VALUES($1,$2,$3,'files',$4)`, [randomUUID(), firstNext.launchId,
      firstNext.generation, firstNext.platformOwnerId]), { code: '23505' });
    await assert.rejects(runtime.query(`INSERT INTO identity.secureshop_target_reservations
      (target_id,launch_id,generation,target_kind,original_platform_owner_id,files_owner_slot)
      VALUES($1,$2,$3,'products',$4,1)`, [randomUUID(), firstNext.launchId,
      firstNext.generation, firstNext.platformOwnerId]), { code: '23514' });

    const after = (await runtime.query(`SELECT target_id,launch_id,generation,target_kind,
      original_platform_owner_id,files_owner_slot,files_tenant_id,files_principal_id,created_at
      FROM identity.secureshop_target_reservations ORDER BY target_id`)).rows;
    const ledgerAfter = (await migration.query(
      'SELECT name,checksum FROM dvaia_migrations.ledger ORDER BY name')).rows;
    assert.deepEqual(ledgerAfter.slice(0, -1), ledgerBefore);
    assert.equal(ledgerAfter.at(-1).name, MIGRATION);
    assert.equal(ledgerAfter.at(-1).checksum, createHash('sha256')
      .update(fs.readFileSync(path.join(DIRECTORY, MIGRATION))).digest('hex'));
    assert.deepEqual(await canonical.migrate(migration, DIRECTORY), []);
    assert.deepEqual((await runtime.query(`SELECT target_id,launch_id,generation,target_kind,
      original_platform_owner_id,files_owner_slot,files_tenant_id,files_principal_id,created_at
      FROM identity.secureshop_target_reservations ORDER BY target_id`)).rows, after);
  });

test('0151 retains unclassified principal-owner debt, denies base auth without execution scope and isolates tenant admission',
  { skip: process.env.PG_TEST_DISPOSABLE !== 'yes'
      || !process.env.V19_ATTACHMENT_UNKNOWN_MIGRATION_URL, timeout: 120000 }, async t => {
    const ownedUrl = role => {
      const value = new URL(process.env[`V19_ATTACHMENT_UNKNOWN_${role}_URL`]);
      assert.equal(value.protocol, 'postgresql:'); assert.equal(value.hostname, '127.0.0.1');
      assert.equal(value.username, `dvaia_identity_${role.toLowerCase()}`);
      assert.equal(value.password, ''); assert.equal(value.search, ''); assert.equal(value.hash, '');
      assert.match(value.pathname, /^\/owasp_ai_goat_test_persona_unknown_[a-f0-9]{12}$/);
      return value.href;
    };
    const migration = new Pool({ connectionString: ownedUrl('MIGRATION'), max: 2,
      statement_timeout: 20000, lock_timeout: 5000 });
    const runtime = new Pool({ connectionString: ownedUrl('RUNTIME'), max: 4,
      statement_timeout: 10000, lock_timeout: 5000 });
    t.after(() => Promise.allSettled([runtime.end(), migration.end()]));
    await historical(150).migrate(migration, DIRECTORY);
    await require('../../server/database/postgres/secureshopStandaloneSeed')
      .seedSecureShopStandaloneDefaults(migration);
    const repository = require('../../server/database/postgres/secureshopStandaloneAuthRepository')
      .createSecureShopStandaloneAuthRepository({ pool: runtime });
    const auth = require('../../server/services/secureshopStandaloneAuth')
      .createSecureShopStandaloneAuthService({ repository });
    const launches = require('../../server/database/postgres/secureshopLaunchRepository')
      .createSecureShopLaunchRepository(runtime);
    const login = await auth.login({ username: 'student_customer', password: 'student123' });
    // Pre-0151 accepted a shop authentication session without a tenant
    // execution binding. The migration preserves that principal-owner target
    // without reclassifying it as a tenant execution partition.
    const legacyLaunch = await launches.issueOrRenew({
      platformOwnerId: login.context.ownerId, platformSessionId: login.context.sessionId,
      expiresAt: login.context.expiresAt });
    const targetId = randomUUID();
    await runtime.query(`INSERT INTO identity.secureshop_target_reservations
      (target_id,launch_id,generation,target_kind,original_platform_owner_id)
      VALUES($1,$2,$3,'files',$4)`, [targetId, legacyLaunch.binding.launchId,
      legacyLaunch.binding.generation, legacyLaunch.binding.platformOwnerId]);
    assert.deepEqual(await require('../../db/postgres/migrate').migrate(migration, DIRECTORY), [MIGRATION]);
    assert.deepEqual((await runtime.query(`SELECT files_owner_slot,files_tenant_id,files_principal_id
      FROM identity.secureshop_target_reservations WHERE target_id=$1`, [targetId])).rows[0], {
      files_owner_slot: 1, files_tenant_id: null, files_principal_id: null });
    const sameOwnerLogin = await auth.login({ username: 'student_customer', password: 'student123' });
    const sameOwnerLaunch = await launches.issueOrRenew({
      platformOwnerId: sameOwnerLogin.context.ownerId,
      platformSessionId: sameOwnerLogin.context.sessionId,
      expiresAt: sameOwnerLogin.context.expiresAt });
    const sameOwnerScope = require('../../server/services/secureshopConversationBinding')
      .createLaunchScope(sameOwnerLaunch.binding);
    assert.equal(sameOwnerScope.platformOwnerId, legacyLaunch.binding.platformOwnerId);
    await assert.rejects(launches.reserveFilesTarget({ ...sameOwnerScope,
      expectedGeneration: sameOwnerScope.generation }), { code: 'CLEANUP_REQUIRED' });
    await assert.rejects(runtime.query(`INSERT INTO identity.secureshop_target_reservations
      (target_id,launch_id,generation,target_kind,original_platform_owner_id)
      VALUES($1,$2,$3,'files',$4)`, [randomUUID(), sameOwnerScope.launchId,
      sameOwnerScope.generation, sameOwnerScope.platformOwnerId]), { code: '55000' });
    const principal = await auth.establishTenantContext(login.context);
    const current = await launches.issueOrRenew({ platformOwnerId: principal.ownerId,
      platformSessionId: principal.sessionId, expiresAt: principal.expiresAt,
      shopPrincipal: principal });
    const scope = require('../../server/services/secureshopConversationBinding')
      .createLaunchScope(current.binding);
    assert.notEqual(scope.platformOwnerId, legacyLaunch.binding.platformOwnerId);
    const tenantTarget = await launches.reserveFilesTarget({ ...scope,
      expectedGeneration: scope.generation });
    assert.equal(tenantTarget.launchId, scope.launchId);
    assert.equal(tenantTarget.kind, 'files');
    assert.deepEqual(await require('../../db/postgres/migrate').migrate(migration, DIRECTORY), []);
  });
