'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { readMigrations, executionSql } = require('../db/postgres/migrate');
const { installPreInvocationMapping } = require('./fixtures/secureshopOwnedMcpRegistryUpgradeNative');
function fixture({ ledger = null, failSql } = {}) {
  const queries = []; let released = false;
  const client = { async query(sql, values) {
    queries.push({ sql, values });
    if (sql.includes('server_version_num')) return { rows: [{ version: 180000 }] };
    if (sql.includes('to_regclass')) return { rows: [{ ledger }] };
    if (sql === failSql) throw new Error('controlled SQL failure');
    return { rows: [] };
  }, release() { released = true; } };
  return { pool: { async connect() { return client; } }, queries, released: () => released };
}
test('pre-0044 bootstrap executes canonical migration bytes and ledger checksums in one transaction', async () => {
  const f = fixture(); const result = await installPreInvocationMapping(f.pool);
  const rows = (await readMigrations(result.directory)).filter(row => row.name < '0044_');
  assert.deepEqual(result.selected, rows.map(({ name, checksum }) => ({ name, checksum })));
  const inserts = f.queries.filter(q => q.sql.startsWith('INSERT INTO dvaia_migrations.ledger'));
  assert.deepEqual(inserts.map(q => q.values), rows.map(row => [row.name, row.checksum]));
  for (const row of rows) assert.equal(f.queries.filter(q => q.sql === executionSql(row)).length, 1);
  assert.equal(f.queries[0].sql, 'BEGIN'); assert.equal(f.queries.at(-1).sql, 'COMMIT');
  assert.equal(f.released(), true);
  assert(!result.selected.some(row => row.name.startsWith('0044_')));
});
test('populated database is denied before DDL and releases transaction', async () => {
  const f = fixture({ ledger: 'dvaia_migrations.ledger' });
  await assert.rejects(installPreInvocationMapping(f.pool), /Upgrade database must be empty/);
  assert(!f.queries.some(q => q.sql.startsWith('CREATE')));
  assert.equal(f.queries.at(-1).sql, 'ROLLBACK'); assert.equal(f.released(), true);
});
test('canonical SQL failure rolls back instead of leaving a partial migration ledger', async () => {
  const f = fixture({ failSql: 'CREATE SCHEMA dvaia_migrations' });
  await assert.rejects(installPreInvocationMapping(f.pool), /controlled SQL failure/);
  assert.equal(f.queries.at(-1).sql, 'ROLLBACK'); assert.equal(f.released(), true);
  assert(!f.queries.some(q => q.sql.startsWith('INSERT INTO dvaia_migrations.ledger')));
});

test('upgrade seeds canonical three persona templates and both owner sessions reference the admin template',async()=>{
 const fs=require('node:fs'),vm=require('node:vm'),crypto=require('node:crypto');
 const source=fs.readFileSync(require.resolve('./fixtures/secureshopOwnedMcpRegistryUpgradeNative'),'utf8');
 const start=source.indexOf(" const templates=",source.indexOf('async function qualifyInvocationUpgrade'));
 const end=source.indexOf('  const q={version:',start);assert(start>0&&end>start);
 const sql=fs.readFileSync('db/postgres/workshop-migrations/secureshop_agents/0008_secureshop_bound_persona_sessions.sql','utf8');assert.match(sql,/CHECK \(template_count=3\)/);
 const rows=[],sessions=[];let catalog;
 await vm.runInNewContext('(async()=>{'+source.slice(start,end)+'}})()',{assert,createHash:crypto.createHash,randomUUID:crypto.randomUUID,require:id=>{assert.equal(id,'../../db/postgres/seeds/secureshop.json');return require('../db/postgres/seeds/secureshop.json');},migration:{async query(sql,values){if(sql.includes('bound_persona_templates('))rows.push(values);else if(sql.includes('bound_persona_template_catalog(')){assert.match(sql,/VALUES\(true,1,3,\$1\)/);catalog=values[0];}else if(sql.includes('bound_persona_sessions('))sessions.push(values);else assert.fail('Unexpected SQL');}}});
 assert.equal(rows.length,3);assert.deepEqual(rows.map(x=>x[4]).sort(),['admin','customer','merchant']);assert.equal(catalog.length,32);assert.equal(sessions.length,2);
 const admin=rows.find(x=>x[4]==='admin');for(const session of sessions){assert.equal(session[5],admin[1]);assert.equal(session[6],admin[0]);assert.equal(session[7],admin[2]);}assert.notEqual(sessions[0][3],sessions[1][3]);assert.notEqual(sessions[0][0],sessions[1][0]);
});
