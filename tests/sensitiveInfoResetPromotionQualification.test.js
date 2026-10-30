'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { EXPECTED_NAMES, PRIVATE_CONFIG_DIGEST_VARIABLE, migrationDirectory,
  assertPrivateConfigBytes, inspectStores } = require('../scripts/qualify-sensitive-info-reset-promotion');

test('promotion qualification covers the normal sixteen-store initializer manifest', () => {
  const configured = require('../db/postgres/initialize-application').requiredStoreManifest.map(row => row.schema);
  assert.deepEqual(EXPECTED_NAMES, configured);
  assert.equal(EXPECTED_NAMES.length, 16);
  for (const store of EXPECTED_NAMES) assert.ok(fs.statSync(migrationDirectory(store)).isDirectory());
  assert.match(migrationDirectory('identity'), /identity-migrations$/);
  assert.match(migrationDirectory('finflow'), /workshop-migrations[/\\]finflow$/);
});

test('installed composition preserves reviewed activation policy while lifecycle implementation evolves', () => {
  const candidate = fs.readFileSync(path.join(__dirname, '..',
    'docs/modernization/drafts/sensitiveInfoResetComposition.activated.js'),'utf8');
  const functionSource = candidate.match(/function enabled\(env = process\.env\) \{[\s\S]*?\n\}/)?.[0];
  assert.ok(functionSource, 'historical reviewed activation function remains available');
  const { activationPolicy } = require('../server/services/sensitiveInfoResetActivationPolicy');
  const historicalEnabled = require('node:vm').runInNewContext(`(${functionSource})`, {activationPolicy});
  const { enabled, FLAG } = require('../server/services/sensitiveInfoResetComposition');
  const pg = {PLATFORM_DATABASE_ENGINE:'postgres', WORKSHOP_DATABASE_ENGINE:'postgres'};
  for (const env of [{}, pg, {...pg,[FLAG]:'false'}, {...pg,[FLAG]:'true'}]) {
    assert.equal(enabled(env), historicalEnabled(env));
  }
  for (const env of [{PLATFORM_DATABASE_ENGINE:'postgres'}, {...pg,[FLAG]:'invalid'}]) {
    assert.throws(() => historicalEnabled(env), {code:'INVALID_CONFIGURATION'});
    assert.throws(() => enabled(env), {code:'INVALID_CONFIGURATION'});
  }
});

test('store inspection retains full exact ledgers and closes every injected pool', async () => {
  const closed=[];
  const ledger=[{name:'0001_fixture.sql',checksum:'fixture-checksum'}];
  const result=await inspectStores({replay:true,dependencies:{
    createPool(_env,key){return {async query(){return {rows:ledger.map(row=>({...row}))};},
      async end(){closed.push(key);}};},
    async migrate(){return [];},
    async readMigrations(){return ledger.map(row=>({...row}));},
  }});
  assert.deepEqual(Object.keys(result),EXPECTED_NAMES);
  for(const value of Object.values(result)){
    assert.deepEqual(value.ledger,ledger);assert.deepEqual(value.applied,[]);
  }
  assert.equal(closed.length,16);
  await assert.rejects(()=>inspectStores({dependencies:{
    createPool(){return {async query(){return {rows:[{name:'changed',checksum:'x'}]};},async end(){}};},
    async readMigrations(){return ledger;},async migrate(){return [];},
  }}),{code:'LEDGER_MISMATCH'});
});

test('qualification checks owned private configuration bytes without reading the working environment', t => {
  const directory=fs.mkdtempSync(path.join(require('node:os').tmpdir(),'owasp-ai-goat-promotion-config-'));
  t.after(()=>fs.rmSync(directory,{recursive:true,force:true}));
  const configPath=path.join(directory,'.env');
  const privateBytes=Buffer.from('OWNED_TEST_SELECTOR=fixture\n');
  fs.writeFileSync(configPath,privateBytes,{mode:0o600});
  const digest=crypto.createHash('sha256').update(privateBytes).digest('hex');
  const dependencies={configPath};
  assert.doesNotThrow(()=>assertPrivateConfigBytes({[PRIVATE_CONFIG_DIGEST_VARIABLE]:digest},dependencies));
  let defaultPath;
  assert.doesNotThrow(()=>assertPrivateConfigBytes({[PRIVATE_CONFIG_DIGEST_VARIABLE]:digest},{
    readFile(filename){defaultPath=filename;return privateBytes;},
  }));
  assert.equal(defaultPath,path.join(__dirname,'..','.env'));
  assert.throws(()=>assertPrivateConfigBytes({[PRIVATE_CONFIG_DIGEST_VARIABLE]:'0'.repeat(64)},dependencies),
    error=>error.code==='PRIVATE_CONFIG_CHANGED' && !error.message.includes(digest));
  fs.rmSync(configPath);
  assert.throws(()=>assertPrivateConfigBytes({[PRIVATE_CONFIG_DIGEST_VARIABLE]:digest},dependencies),
    error=>error.code==='PRIVATE_CONFIG_UNAVAILABLE' && !error.message.includes(digest));
});
