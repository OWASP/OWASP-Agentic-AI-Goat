'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { randomUUID, randomBytes } = require('node:crypto');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const { migrate, readMigrations } = require('../../db/postgres/migrate');
const { createXssBoundedMigrationView } = require('../helpers/xssBoundedMigrationView');
const { createIdentityRepository } = require('../../server/database/postgres/identityRepository');
const { createSecureShopLaunchRepository } = require('../../server/database/postgres/secureshopLaunchRepository');
const { createSecureShopOwnerResetRepository } = require('../../server/database/postgres/secureshopOwnerResetRepository');

const enabled = process.env.PG_TEST_DISPOSABLE === 'yes'
  && Boolean(process.env.PG_SECURESHOP_PRODUCT_ADMISSION_TEST_MIGRATION_URL);
test('native product launch admission preserves retained bindings, caps debt, and retains reset fences',
  { skip: !enabled, timeout: 180000 }, async t => {
    let pair;
    for (const suffix of ['MIGRATION', 'RUNTIME']) {
      const url = new URL(process.env[`PG_SECURESHOP_PRODUCT_ADMISSION_TEST_${suffix}_URL`]);
      assert.equal(url.protocol, 'postgresql:');
      assert.match(url.pathname, /^\/dvaia_test_[a-z0-9_]+$/);
      assert.equal(url.hostname, '127.0.0.1');
      assert.equal(url.username, `dvaia_identity_${suffix.toLowerCase()}`);
      assert.equal(url.password, ''); assert.equal(url.search, ''); assert.equal(url.hash, '');
      assert.ok(Number(url.port) > 0 && Number(url.port) <= 65535);
      const currentPair = `${url.host}${url.pathname}`;
      if (pair === undefined) pair = currentPair; else assert.equal(currentPair, pair);
    }
    const migration = new Pool({ connectionString: process.env.PG_SECURESHOP_PRODUCT_ADMISSION_TEST_MIGRATION_URL });
    const pool = new Pool({ connectionString: process.env.PG_SECURESHOP_PRODUCT_ADMISSION_TEST_RUNTIME_URL, max: 4 });
    t.after(() => Promise.all([migration.end(), pool.end()]));
    const directory = path.resolve(__dirname, '../../db/postgres/identity-migrations');
    const view = createXssBoundedMigrationView({ identity: 133 });
    assert.equal((await migration.query("SELECT to_regnamespace('identity') AS present")).rows[0].present, null);
    await view.migrate(migration, directory);
    const identity = createIdentityRepository(pool);
    const launches = createSecureShopLaunchRepository(pool);
    const hash = await bcrypt.hash('synthetic-product-admission', 4);
    const expiresAt = new Date(Date.now() + 3600000).toISOString();
    async function user(name) {
      return identity.createUser({ username: name, email: `${name}@admission.invalid`, passwordHash: hash });
    }
    async function launch(owner, historicalRaw = false) {
      // This capacity fixture needs >5 simultaneous synthetic sessions. Normal
      // login deliberately prunes to five; do not change that production policy
      // or let its pruning silently invalidate the launch authority under test.
      // The migration pool is guarded above as a fresh disposable identity DB.
      const session = (await migration.query(`INSERT INTO identity.user_sessions
        (user_id,session_token_hash,expires_at) VALUES($1,$2,$3) RETURNING id`,
      [owner.id, randomBytes(32).toString('hex'), expiresAt])).rows[0];
      const scope = { platformOwnerId: owner.id, platformSessionId: session.id };
      if (historicalRaw) {
        const launchId = randomUUID();
        await pool.query(`INSERT INTO identity.secureshop_launches
          (launch_id,platform_session_id,original_platform_session_id,original_platform_owner_id,handle_hash,scenario_id,expires_at)
          VALUES($1,$2,$2,$3,$4,$5,$6)`, [launchId, session.id, owner.id, randomBytes(32), randomUUID(), expiresAt]);
        return { ...scope, launchId, expectedGeneration: 1 };
      }
      const issued = await launches.issueOrRenew({ ...scope, expiresAt });
      return { ...scope, launchId: issued.binding.launchId, expectedGeneration: 1, binding: issued.binding, bearer: issued.bearer };
    }
    async function insertTarget(scope, kind = 'products') {
      return (await pool.query(`INSERT INTO identity.secureshop_target_reservations
        (target_id,launch_id,generation,target_kind,original_platform_owner_id)
        VALUES($1,$2,$3,$4,$5) RETURNING *`,
      [randomUUID(), scope.launchId, scope.expectedGeneration, kind, scope.platformOwnerId])).rows[0];
    }
    const alice = await user('product-admission-alice'), bob = await user('product-admission-bob');
    const a = await launch(alice), b = await launch(bob);
    const overflowOwner = await user('product-admission-historical-overflow');
    const historicalLaunches = [];
    for (let index = 0; index < 257; index++) historicalLaunches.push(await launch(overflowOwner, true));
    // Populate under the actual previous schema before applying the candidate.
    const old = await insertTarget(a), sibling = await insertTarget(b);
    const originalRows = (await pool.query(`SELECT target_id,launch_id,generation,target_kind,
      original_platform_owner_id,created_at FROM identity.secureshop_target_reservations ORDER BY target_id`)).rows;
    const baselineLedger = (await migration.query('SELECT name,checksum FROM dvaia_migrations.ledger ORDER BY name')).rows;
    assert.deepEqual(await migrate(migration, directory), ['0134_secureshop_product_launch_admission.sql']);
    assert.deepEqual((await pool.query(`SELECT target_id,launch_id,generation,target_kind,
      original_platform_owner_id,created_at FROM identity.secureshop_target_reservations ORDER BY target_id`)).rows, originalRows);
    const manifest = await readMigrations(directory);
    assert.deepEqual((await migration.query('SELECT name,checksum FROM dvaia_migrations.ledger ORDER BY name')).rows,
      manifest.map(({ name, checksum }) => ({ name, checksum })));
    assert.deepEqual(manifest.slice(0, baselineLedger.length).map(({ name, checksum }) => ({ name, checksum })), baselineLedger);
    assert.deepEqual(await migrate(migration, directory), []);
    assert.equal((await pool.query('SELECT count(*)::int AS n FROM identity.secureshop_launches WHERE original_platform_owner_id=$1', [overflowOwner.id])).rows[0].n, 257);
    assert.equal((await pool.query('SELECT count(*)::int AS n FROM identity.secureshop_launch_capacity WHERE original_platform_owner_id=$1', [overflowOwner.id])).rows[0].n, 256);

    await t.test('another session opens an independent target while old and sibling targets remain unchanged', async () => {
      const next = await launch(alice);
      const results = await Promise.all([launches.reserveProductsTarget(next), launches.reserveProductsTarget(next)]);
      assert.equal(results[0].targetId, results[1].targetId);
      assert.notEqual(results[0].targetId, old.target_id);
      assert.equal((await launches.reserveProductsTarget(a)).targetId, old.target_id);
      assert.equal((await launches.reserveProductsTarget(b)).targetId, sibling.target_id);
      assert.equal((await launches.readExistingProductsTarget(next.binding)).targetId, results[0].targetId);
      await assert.rejects(launches.reserveProductsTarget({ ...next, platformSessionId: b.platformSessionId }), { code: 'OWNER_MISMATCH' });
      await assert.rejects(launches.reserveProductsTarget({ ...next, expectedGeneration: 2 }), { code: 'LAUNCH_UNAVAILABLE' });
      await assert.rejects(insertTarget({ ...next, platformOwnerId: bob.id }), /binding is invalid/);
      await assert.rejects(insertTarget(next), { code: '23505' });
      await assert.rejects(pool.query('UPDATE identity.secureshop_target_reservations SET launch_id=$1 WHERE target_id=$2',
        [next.launchId, old.target_id]), /permission denied/);
      // Non-product debt still has its original one-per-owner rule.
      await launches.reserveFilesTarget(a);
      await assert.rejects(launches.reserveFilesTarget(next), { code: 'CLEANUP_REQUIRED' });
      await assert.rejects(insertTarget(next, 'files'), { code: '23505' });
      // Reset admission fences the selected launch, retains all cleanup debt,
      // and cannot commit without genuine cleanup checkpoints and receipts.
      const reset = await launches.beginReset({ ...next, idempotencyKey: 'product-admission-reset' });
      await assert.rejects(launches.reserveProductsTarget(next), { code: 'LAUNCH_UNAVAILABLE' });
      await assert.rejects(insertTarget(next), /binding is invalid/);
      await assert.rejects(launches.commitReset({ ...next, resetId: reset.resetId, expectedGeneration: 2 }), { code: 'CLEANUP_REQUIRED' });
      await launches.revoke({ ...next, expectedGeneration: 2, reason: 'owned-native-retirement-fence' });
      assert.equal((await pool.query('SELECT identity.secureshop_launch_is_retired($1) AS retired', [next.launchId])).rows[0].retired, false);
      assert.equal((await pool.query('SELECT identity.secureshop_launch_is_retired($1) AS retired', [randomUUID()])).rows[0].retired, false);
      assert.equal((await launches.reserveProductsTarget(a)).targetId, old.target_id);
      assert.equal((await launches.reserveProductsTarget(b)).targetId, sibling.target_id);
      const ownerReset = await createSecureShopOwnerResetRepository(pool).begin({ ownerId: alice.id });
      assert.deepEqual(new Set(ownerReset.launches.map(row => row.launchId)), new Set([a.launchId, next.launchId]));
      assert.equal((await pool.query("SELECT count(*)::int AS n FROM identity.secureshop_target_reservations WHERE original_platform_owner_id=$1 AND target_kind='products'", [alice.id])).rows[0].n, 2);
      assert.equal((await launches.reserveProductsTarget(b)).targetId, sibling.target_id);
    });

    await t.test('256 reservations allow exact reuse, reject overflow in repository and database, and isolate owners', async () => {
      let first;
      for (let index = 0; index < 255; index++) {
        const scope = historicalLaunches[index];
        const target = await launches.reserveProductsTarget(scope);
        if (!first) first = { scope, target };
      }
      const contenders = historicalLaunches.slice(255);
      const contested = await Promise.allSettled(contenders.map(scope => launches.reserveProductsTarget(scope)));
      assert.equal(contested.filter(result => result.status === 'fulfilled').length, 1);
      const loser = contested.findIndex(result => result.status === 'rejected');
      assert.equal(contested[loser].reason.code, 'PRODUCT_TARGET_CAPACITY');
      const extra = contenders[loser];
      assert.deepEqual(await launches.reserveProductsTarget(first.scope), first.target);
      await assert.rejects(launches.reserveProductsTarget(extra), { code: 'PRODUCT_TARGET_CAPACITY' });
      await assert.rejects(insertTarget(extra), { code: '54000' });
      const slots = (await pool.query(`SELECT count(*)::int AS n,count(DISTINCT product_owner_slot)::int AS slots,
        min(product_owner_slot)::int AS first,max(product_owner_slot)::int AS last
        FROM identity.secureshop_target_reservations WHERE original_platform_owner_id=$1 AND target_kind='products'`, [overflowOwner.id])).rows[0];
      assert.deepEqual(slots, { n: 256, slots: 256, first: 1, last: 256 });
      await assert.rejects(launch(overflowOwner), { code: 'LAUNCH_CAPACITY' });
      await assert.rejects(launch(overflowOwner, true), { code: '54000' });
      // Historical overflow remains intact; do not claim reset repaired it.
      await assert.rejects(createSecureShopOwnerResetRepository(pool).begin({ ownerId: overflowOwner.id }), { code: 'SECURESHOP_OWNER_RESET_CAPACITY' });
      assert.equal((await pool.query('SELECT count(*)::int AS n FROM identity.secureshop_launches WHERE original_platform_owner_id=$1', [overflowOwner.id])).rows[0].n, 257);
      assert.equal((await launches.reserveProductsTarget(b)).targetId, sibling.target_id);
    });

    await t.test('new launch cap admits 256, permits current renewal, and leaves owner reset bounded', async () => {
      const capped = await user('product-admission-new-cap');
      let first;
      for (let index = 0; index < 256; index++) {
        const scope = await launch(capped);
        if (!first) first = scope;
      }
      const target = await launches.reserveProductsTarget(first);
      await assert.rejects(launch(capped), { code: 'LAUNCH_CAPACITY' });
      await assert.rejects(launch(capped, true), { code: '54000' });
      const renewed = await launches.issueOrRenew({ ...first, expiresAt, expectedBearer: first.bearer });
      assert.equal(renewed.binding.launchId, first.launchId);
      assert.equal((await launches.reserveProductsTarget(first)).targetId, target.targetId);
      const reset = await createSecureShopOwnerResetRepository(pool).begin({ ownerId: capped.id });
      assert.equal(reset.launches.length, 256);
      await assert.rejects(pool.query('DELETE FROM identity.secureshop_launch_capacity WHERE original_platform_owner_id=$1', [capped.id]), /permission denied/);
      assert.equal((await launches.reserveProductsTarget(b)).targetId, sibling.target_id);
    });
  });
