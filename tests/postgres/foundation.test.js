'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { poolConfig, withTransaction, verifyServer } = require('../../server/database/postgres');

test('configuration never silently connects to another database or weakens remote TLS', () => {
  assert.throws(() => poolConfig({}), /required/);
  assert.throws(() => poolConfig({ DATABASE_URL: 'sqlite:db' }), /PostgreSQL/);
  assert.throws(() => poolConfig({ DATABASE_URL: 'postgres://u:p@remote/db' }), /TLS/);
  assert.throws(() => poolConfig({ DATABASE_URL: 'postgres://u:p@localhost/db?sslmode=no-verify' }), /query options/);
  const config = poolConfig({ DATABASE_URL: 'postgres://u:p@remote/db', PG_TLS: 'require' });
  assert.equal(config.max, 2);
  assert.equal(config.ssl.rejectUnauthorized, true);
});

test('failed work rolls back on the checked-out client and returns original error', async () => {
  const queries = [];
  const failure = new Error('failed work');
  let releases = 0;
  const client = { query: async sql => queries.push(sql), release: error => { assert.equal(error, undefined); releases++; } };
  await assert.rejects(withTransaction({ connect: async () => client }, async () => { throw failure; }), error => error === failure);
  assert.deepEqual(queries, ['BEGIN', 'ROLLBACK']);
  assert.equal(releases, 1);
});

test('failed rollback discards the connection and preserves original error', async () => {
  const failure = new Error('commit failed');
  const rollbackFailure = new Error('connection lost');
  let discarded;
  const client = { query: async sql => { if (sql === 'COMMIT') throw failure; if (sql === 'ROLLBACK') throw rollbackFailure; }, release: error => { discarded = error; } };
  await assert.rejects(withTransaction({ connect: async () => client }, async () => 42), error => error === failure);
  assert.equal(discarded, rollbackFailure);
});

test('requires PG18 and refuses cluster administrators', async () => {
  await assert.rejects(verifyServer({ query: async () => ({ rows: [{ version: 170000 }] }) }), /18/);
  await assert.rejects(verifyServer({ query: async () => ({ rows: [{ version: 180006, rolsuper: true }] }) }), /administrative/);
  await verifyServer({ query: async () => ({ rows: [{ version: 180006, rolsuper: false }] }) });
});

test('staged workshop selectors load PostgreSQL without importing either SQLite driver', () => {
  const {execFileSync}=require('node:child_process');
  const result=execFileSync(process.execPath,['-e', `
    const sql=require('./server/database/sqlWorkshopDb');
    const nosql=require('./server/database/nosqlWorkshopDb');
    if(typeof sql.createSqlWorkshopDb!=='function'||typeof nosql.createNosqlWorkshopDb!=='function')throw new Error('Wrong store selected');
    if(Object.keys(require.cache).some(p=>/node_modules\\/(sqlite3|better-sqlite3)\\//.test(p)))throw new Error('SQLite loaded on PostgreSQL path');
  `],{cwd:require('node:path').join(__dirname,'../..'),env:{...process.env,WORKSHOP_DATABASE_ENGINE:'postgres'}});
  assert.equal(result.toString(),'');
});

test('pool registry closes idle/unopened pools idempotently and rejects new work after shutdown', () => {
  const {execFileSync}=require('node:child_process');
  execFileSync(process.execPath,['-e', `
    const assert=require('node:assert/strict');
    const {createPool,closePostgresPools}=require('./server/database/postgres');
    (async()=>{
      const pool=createPool({DATABASE_URL:'postgresql://test@127.0.0.1/dvaia_test_shutdown'});
      await Promise.all([closePostgresPools(),pool.end(),closePostgresPools()]);
      assert.throws(()=>createPool({DATABASE_URL:'postgresql://test@127.0.0.1/dvaia_test_shutdown'}),/shutting down/);
    })().catch(error=>{console.error(error);process.exitCode=1;});
  `],{cwd:require('node:path').join(__dirname,'../..')});
});
