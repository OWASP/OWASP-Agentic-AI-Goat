'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const fsp = require('node:fs/promises');
const path = require('node:path');
const { Module, createRequire } = require('node:module');
const { randomUUID } = require('node:crypto');
const { Pool } = require('pg');
const { migrate, readMigrations } = require('../../db/postgres/migrate');
const commerce = require('../../server/services/secureshopConversationalCommerceContract');
const profile = require('../../server/services/secureshopProfileUpdateContract');

const DIRECTORY = path.resolve(__dirname, '../../db/postgres/workshop-migrations/secureshop_review');
const PREFIX = 'PG_SECURESHOP_PROFILE_';
const TAIL = '0046_customer_profile_receipts.sql';
const enabled = process.env.PG_TEST_DISPOSABLE === 'yes' && ['FRESH', 'POPULATED'].every(store =>
  ['MIGRATION', 'RUNTIME'].every(role => process.env[`${PREFIX}${store}_${role}_URL`]));

// The canonical migrator reads the historical prefix from this checkout, retaining
// its ledger/checksum/transaction behavior without a copied migration directory.
function through0045() {
  const filename = require.resolve('../../db/postgres/migrate');
  const local = createRequire(filename);
  const visible = { ...fsp, async readdir(directory, ...args) {
    const names = await fsp.readdir(directory, ...args);
    return path.resolve(directory) === DIRECTORY
      ? names.filter(name => !/^\d{4}_[a-z0-9_]+\.sql$/.test(name) || name < TAIL)
      : names;
  } };
  const loaded = new Module(filename, module);
  loaded.filename = filename;
  loaded.require = name => ['node:fs/promises', 'fs/promises'].includes(name) ? visible : local(name);
  loaded._compile(fs.readFileSync(filename, 'utf8'), filename);
  return loaded.exports.migrate;
}

function ownedUrl(store, role) {
  const value = new URL(process.env[`${PREFIX}${store}_${role}_URL`]);
  assert.equal(value.protocol, 'postgresql:');
  assert.equal(value.hostname, '127.0.0.1');
  assert.equal(value.username, `dvaia_secureshop_review_${role.toLowerCase()}`);
  assert.equal(value.password, '');
  assert.equal(value.search, '');
  assert.equal(value.hash, '');
  assert.match(value.pathname, new RegExp(`^/dvaia_test_persona_${store.toLowerCase()}_[a-f0-9]{12}$`));
  return value;
}

async function rows(pool, table) {
  return (await pool.query(`SELECT to_jsonb(t) AS row FROM secureshop_review.${table} t ORDER BY to_jsonb(t)::text`)).rows;
}

test('review0046 preserves populated customer commerce and admits hash-only profile receipts', {
  skip: !enabled,
  timeout: 90000,
}, async t => {
  const urls = {};
  for (const store of ['FRESH', 'POPULATED']) for (const role of ['MIGRATION', 'RUNTIME']) {
    urls[`${store}_${role}`] = ownedUrl(store, role);
  }
  assert.equal(new Set(Object.values(urls).map(url => url.port)).size, 1);
  assert.equal(new Set(Object.values(urls).map(url => url.pathname)).size, 2);
  const pools = Object.fromEntries(Object.entries(urls).map(([key, url]) =>
    [key, new Pool({ connectionString: url.href, max: 3, statement_timeout: 15000,
      lock_timeout: 3000, application_name: 'dvaia-profile-migration-native' })]));
  t.after(async () => Promise.allSettled(Object.values(pools).map(pool => pool.end())));

  const names = (await readMigrations(DIRECTORY)).map(value => value.name);
  assert.equal(names.at(-1), TAIL);
  assert.deepEqual(await migrate(pools.FRESH_MIGRATION, DIRECTORY), names);
  assert.deepEqual(await migrate(pools.FRESH_MIGRATION, DIRECTORY), []);
  assert.deepEqual((await pools.FRESH_MIGRATION.query(
    'SELECT name FROM dvaia_migrations.ledger ORDER BY name')).rows.map(row => row.name), names);
  assert.equal((await pools.FRESH_RUNTIME.query(`SELECT has_table_privilege(current_user,
    'secureshop_review.chat_commerce_operations','INSERT') AS allowed`)).rows[0].allowed, true);

  assert.deepEqual(await through0045()(pools.POPULATED_MIGRATION, DIRECTORY), names.slice(0, -1));
  const targetId = randomUUID(), launchId = randomUUID(), scenarioId = randomUUID();
  const operationId = randomUUID(), eventId = randomUUID();
  await pools.POPULATED_MIGRATION.query(`INSERT INTO secureshop_review.product_targets
    (target_id,launch_id,scenario_id,generation,original_platform_owner_id,
     original_platform_session_id,own_merchant_id,source_count,source_sha256)
    VALUES($1,$2,$3,1,7101,7102,7103,1,$4)`,
  [targetId, launchId, scenarioId, Buffer.alloc(32, 4)]);
  await pools.POPULATED_MIGRATION.query(`INSERT INTO secureshop_review.product_target_products
    (target_id,product_id,source_retailer_id,retailer_id,source_product_sha256,
     name,description,price,images,stock_quantity,status)
    VALUES($1,7301,7103,7103,$2,'Retained lamp','Historical synthetic listing',
     9.25,'[]',3,'active')`, [targetId, Buffer.alloc(32, 5)]);
  await pools.POPULATED_MIGRATION.query(`INSERT INTO secureshop_review.product_target_profile_overlays
    (target_id,shop_user_id,email,full_name,phone) VALUES($1,7201,$2,$3,$4)`,
  [targetId, 'retained-legacy-email', '  Retained Customer  ', '5550101']);
  await pools.POPULATED_MIGRATION.query(`INSERT INTO secureshop_review.bound_audit_events
    (event_id,launch_id,scenario_id,generation,original_platform_owner_id,
     original_platform_session_id,shop_user_id,shop_role,actor,action,target,
     params_json,outcome,source_kind,source_id)
    VALUES($1,$2,$3,1,7101,7102,7201,'customer','customer','profile_update',
     '7201',$4,'completed','profile','7201')`,
  [eventId, launchId, scenarioId, '{"retained":true}']);
  await pools.POPULATED_MIGRATION.query(`INSERT INTO secureshop_review.chat_commerce_operations
    (operation_id,target_id,shop_user_id,kind,context_json,request_json,intent_sha256,
     proposal_json,proposal_sha256,result_json,result_sha256,state)
    VALUES($1,$2,7201,'address.update',$3,$4,$5,NULL,NULL,$6,$7,'completed')`,
  [operationId, targetId, '{"retained":true}', '{"address":"historical"}',
    'a'.repeat(64), '{"status":"completed"}', 'b'.repeat(64)]);
  const tables = ['product_targets', 'product_target_products',
    'product_target_profile_overlays', 'bound_audit_events',
    'chat_commerce_operations'];
  const before = Object.fromEntries(await Promise.all(tables.map(async name =>
    [name, await rows(pools.POPULATED_MIGRATION, name)])));
  const prior = (await pools.POPULATED_MIGRATION.query(
    'SELECT name,checksum FROM dvaia_migrations.ledger ORDER BY name')).rows;
  assert.deepEqual(await migrate(pools.POPULATED_MIGRATION, DIRECTORY), [TAIL]);
  assert.deepEqual(await migrate(pools.POPULATED_MIGRATION, DIRECTORY), []);
  assert.deepEqual((await pools.POPULATED_MIGRATION.query(
    'SELECT name,checksum FROM dvaia_migrations.ledger ORDER BY name')).rows.slice(0, -1), prior);
  assert.deepEqual((await pools.POPULATED_MIGRATION.query(
    'SELECT name,checksum FROM dvaia_migrations.ledger ORDER BY name')).rows,
  (await readMigrations(DIRECTORY)).map(({ name, checksum }) => ({ name, checksum })));
  for (const name of tables) assert.deepEqual(await rows(pools.POPULATED_MIGRATION, name), before[name], name);
  assert.equal(before.chat_commerce_operations.length, 1);
  const retained = (await pools.POPULATED_RUNTIME.query(`SELECT email,full_name,phone
    FROM secureshop_review.product_target_profile_overlays WHERE target_id=$1 AND shop_user_id=7201`,
  [targetId])).rows[0];
  assert.deepEqual(profile.normalizeProfileView({ fullName: retained.full_name,
    email: retained.email, phone: retained.phone }),
  { fullName: '  Retained Customer  ', email: 'retained-legacy-email', phone: '5550101' });
  assert.throws(() => profile.normalizeProfilePatch({ email: retained.email }),
    'a changed malformed legacy email remains invalid');

  const profileOperation = randomUUID();
  const intent = profile.profileIntent({ operationId: profileOperation,
    expectedSnapshotSha256: '1'.repeat(64), fields: { fullName: 'Updated customer',
      email: retained.email, phone: retained.phone } });
  const requestJson = JSON.stringify(intent);
  const savedReceipt = profile.profileReceipt({ version: 1, operationId: profileOperation,
    kind: 'profile.update', status: 'completed', result: {
      fieldsSha256: intent.fieldsSha256, profileSnapshotSha256: '2'.repeat(64) }, replayed: false });
  const resultJson = JSON.stringify(savedReceipt);
  await pools.POPULATED_RUNTIME.query(`INSERT INTO secureshop_review.chat_commerce_operations
    (operation_id,target_id,shop_user_id,kind,context_json,request_json,intent_sha256,
     proposal_json,proposal_sha256,result_json,result_sha256,state)
    VALUES($1,$2,7201,'profile.update',$3,$4,$5,NULL,NULL,$6,$7,'completed')`,
  [profileOperation, targetId, '{"scope":"owned"}', requestJson,
    commerce.digest(requestJson), resultJson, commerce.digest(resultJson)]);
  const saved = (await pools.POPULATED_RUNTIME.query(`SELECT kind,state,proposal_json,proposal_sha256
    FROM secureshop_review.chat_commerce_operations WHERE operation_id=$1`, [profileOperation])).rows[0];
  assert.deepEqual(saved, { kind: 'profile.update', state: 'completed',
    proposal_json: null, proposal_sha256: null });
  await assert.rejects(pools.POPULATED_RUNTIME.query(`UPDATE secureshop_review.chat_commerce_operations
    SET result_json=result_json WHERE operation_id=$1`, [profileOperation]),
  error => error?.code === 'P0001', 'saved profile result is immutable');
  await assert.rejects(pools.POPULATED_RUNTIME.query(`DELETE FROM secureshop_review.chat_commerce_operations
    WHERE operation_id=$1`, [profileOperation]),
  error => error?.code === '42501' || error?.code === 'P0001', 'runtime cannot delete profile result');
  await assert.rejects(pools.POPULATED_RUNTIME.query(`INSERT INTO secureshop_review.chat_commerce_operations
    (operation_id,target_id,shop_user_id,kind,context_json,request_json,intent_sha256,
     proposal_json,proposal_sha256,result_json,result_sha256,state)
    VALUES($1,$2,7201,'profile.update','{}','{}',$3,'{}',$4,'{}',$5,'completed')`,
  [randomUUID(), targetId, 'e'.repeat(64), 'f'.repeat(64), '1'.repeat(64)]),
  error => error?.code === '23514', 'profile.update cannot acquire a model proposal payload');
});
