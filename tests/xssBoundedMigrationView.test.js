'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { createXssBoundedMigrationView } = require('./helpers/xssBoundedMigrationView');
const canonical = require('../db/postgres/migrate');
function pool(role, database = 'controlled') {
  const ledger = [], statements = [];
  const p = { ledger, statements, async connect() { return p; }, release() {}, async query(sql, values) {
    statements.push(sql);
    if (sql.includes("current_setting('server_version_num')")) return { rows:[{ version:180000 }] };
    if (sql.includes('current_user AS role')) return { rows:[{ role, database }] };
    if (sql === 'SELECT name, checksum FROM dvaia_migrations.ledger ORDER BY name') return { rows:ledger.map(r => ({...r})) };
    if (sql.startsWith('INSERT INTO dvaia_migrations.ledger')) ledger.push({ name:values[0], checksum:values[1] });
    return { rows:[] };
  } };
  return p;
}
test('real migrator and identity initializer preserve each bounded prefix, transition and no-op', async () => {
  for (const [before, after] of [[69,80],[70,71],[71,76]]) {
    const view = createXssBoundedMigrationView({ identity:before });
    const all = await canonical.readMigrations(view.directories.identity);
    const expected = ceiling => all.filter(r => Number(r.name.slice(0,4)) <= ceiling);
    assert.deepEqual(await view.readMigrations(view.directories.identity), expected(before));
    const migration = pool('dvaia_identity_migration'), runtime = pool('dvaia_identity_runtime');
    await view.initializeIdentityRepository(runtime, migration);
    const prefix = structuredClone(migration.ledger);
    view.setCeiling('identity', after);
    assert.deepEqual(await view.initializeIdentityRepository(runtime, migration), expected(after).slice(prefix.length).map(r=>r.name));
    assert.deepEqual(migration.ledger.slice(0,prefix.length), prefix);
    assert.deepEqual(migration.ledger, expected(after).map(({name,checksum})=>({name,checksum})));
    assert.deepEqual(await view.initializeIdentityRepository(runtime,migration), []);
    for (const row of all.filter(r=>Number(r.name.slice(0,4))>after)) assert.ok(!migration.statements.includes(row.sql));
    assert.deepEqual(await canonical.readMigrations(view.directories.identity), all, 'global real loader remains unmodified');
  }
});
test('real XSS initializer uses private 0007→0015 view and unchanged role/database denials', async () => {
  const view = createXssBoundedMigrationView({ identity:69, xss:7 });
  const runtime=pool('dvaia_xss_runtime'), migration=pool('dvaia_xss_migration');
  await view.migrate(migration,view.directories.xss);
  const prefix=structuredClone(migration.ledger);
  view.setCeiling('xss',15);
  await view.createXssWorkshopDb(runtime).initializeXssWorkshopDb(migration);
  const expected=(await canonical.readMigrations(view.directories.xss)).filter(r=>Number(r.name.slice(0,4))<=15);
  assert.deepEqual(migration.ledger,expected.map(({name,checksum})=>({name,checksum})));
  assert.deepEqual(migration.ledger.slice(0,prefix.length),prefix);
  await view.createXssWorkshopDb(runtime).initializeXssWorkshopDb(migration);
  assert.equal(migration.ledger.length,expected.length);
  for (const [rt,mt] of [[pool('wrong'),pool('migration')],[pool('dvaia_xss_runtime'),pool('dvaia_xss_runtime')],[runtime,pool('migration','other')]]) {
    await assert.rejects(view.createXssWorkshopDb(rt).initializeXssWorkshopDb(mt), /named runtime role/);
    assert.equal(mt.ledger.length,0);
  }
});
test('identity initializer rejects wrong role, same role and different database before migration', async () => {
  const view=createXssBoundedMigrationView({identity:71});
  for(const [runtime,migration] of [[pool('wrong'),pool('migration')],[pool('dvaia_identity_runtime'),pool('dvaia_identity_runtime')],[pool('dvaia_identity_runtime'),pool('migration','other')]]) {
    await assert.rejects(view.initializeIdentityRepository(runtime,migration),/dedicated runtime role/);
    assert.equal(migration.ledger.length,0);
  }
  assert.throws(()=>view.setCeiling('identity',Infinity),TypeError);
});
