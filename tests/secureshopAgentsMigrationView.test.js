'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const canonical=require('../db/postgres/migrate'),fs=require('node:fs/promises');
const {createAgentsMigrationView}=require('./helpers/secureshopAgentsMigrationView');
test('private agents views execute canonical40,41,42 and full tail with exact checksums and no-op',async()=>{
 const original=fs.readdir,full=await canonical.readMigrations(createAgentsMigrationView(40).directory),ledger=[],executed=[];
 const client={release(){},async query(sql,args){
  if(sql.includes("current_setting('server_version_num')"))return {rows:[{version:180000}]};
  if(sql==='SELECT name, checksum FROM dvaia_migrations.ledger ORDER BY name')return {rows:ledger.map(r=>({...r}))};
  if(sql.startsWith('INSERT INTO dvaia_migrations.ledger'))ledger.push({name:args[0],checksum:args[1]});
  if(full.some(m=>canonical.executionSql(m)===sql))executed.push(sql);
  return {rows:[]};
 }};const pool={connect:async()=>client};let prior=0;
 for(const ceiling of [40,41,42]){
  const view=createAgentsMigrationView(ceiling),expected=full.filter(m=>Number(m.name.slice(0,4))<=ceiling);
  assert.deepEqual(await view.readMigrations(view.directory),expected);
  assert.deepEqual(await view.migrate(pool,view.directory),expected.slice(prior).map(m=>m.name));
  assert.deepEqual(ledger,expected.map(({name,checksum})=>({name,checksum})));
  assert.deepEqual(await view.migrate(pool,view.directory),[]);prior=expected.length;
 }
 assert.deepEqual(await canonical.migrate(pool,createAgentsMigrationView(42).directory),full.slice(prior).map(m=>m.name));
 assert.deepEqual(await canonical.migrate(pool,createAgentsMigrationView(42).directory),[]);
 assert.deepEqual(executed,full.map(canonical.executionSql));assert.equal(fs.readdir,original);assert.equal(require('../db/postgres/migrate'),canonical);
 ledger[0].checksum='invalid';await assert.rejects(canonical.migrate(pool,createAgentsMigrationView(42).directory),{code:'MIGRATION_HISTORY_MISMATCH'});
 assert.throws(()=>createAgentsMigrationView(0));
});

test('private agents views migrate 0037, 0042, 0043 and the remaining canonical tail as separate no-op stages',async()=>{
 const full=await canonical.readMigrations(createAgentsMigrationView(37).directory),ledger=[];
 const client={release(){},async query(sql,args){
  if(sql.includes("current_setting('server_version_num')"))return {rows:[{version:180000}]};
  if(sql==='SELECT name, checksum FROM dvaia_migrations.ledger ORDER BY name')return {rows:ledger.map(row=>({...row}))};
  if(sql.startsWith('INSERT INTO dvaia_migrations.ledger'))ledger.push({name:args[0],checksum:args[1]});
  return {rows:[]};
 }};const pool={connect:async()=>client};let prior=0;
 for(const ceiling of [37,42,43]){
  const view=createAgentsMigrationView(ceiling),expected=full.filter(m=>Number(m.name.slice(0,4))<=ceiling);
  assert.deepEqual(await view.migrate(pool,view.directory),expected.slice(prior).map(m=>m.name));
  assert.deepEqual(await view.migrate(pool,view.directory),[]);
  assert.deepEqual(ledger,expected.map(({name,checksum})=>({name,checksum})));prior=expected.length;
 }
 const tail=full.slice(prior);
 assert.deepEqual(await canonical.migrate(pool,createAgentsMigrationView(43).directory),tail.map(m=>m.name));
 assert.deepEqual(await canonical.migrate(pool,createAgentsMigrationView(43).directory),[]);
 assert.deepEqual(ledger,full.map(({name,checksum})=>({name,checksum})));
});
