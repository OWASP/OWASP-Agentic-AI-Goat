'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { assertNativeEvidencePath } = require('./fixtures/secureshopNativeEvidencePath');

test('local evidence admission verifies exact private owned directories and socket', t => {
  const root = '/owned/repository';
  const file = `${root}/tasks/qualification/run-test/standalone-assessment.json`;
  const options = { root, dockerHost: `unix://${root}/.qualification/goat-q/docker.sock`,
    basename: 'standalone-assessment.json' };
  let flaw;
  t.mock.method(fs, 'realpathSync', value => flaw === 'ancestor-link' ? `/redirect${value}` : value);
  t.mock.method(fs, 'lstatSync', value => {
    if (value === file && flaw !== 'existing-file') throw Object.assign(new Error('absent'), { code: 'ENOENT' });
    return { uid: process.getuid() + (flaw === 'foreign-owner' ? 1 : 0),
      mode: flaw === 'public-directory' ? 0o755 : 0o700,
      isDirectory: () => !value.endsWith('docker.sock'),
      isSocket: () => flaw !== 'not-socket' && value.endsWith('docker.sock'),
      isSymbolicLink: () => flaw === 'symlink' };
  });
  assert.equal(assertNativeEvidencePath(file, options), file);
  for (flaw of ['ancestor-link', 'existing-file', 'foreign-owner', 'public-directory', 'not-socket', 'symlink']) {
    assert.throws(() => assertNativeEvidencePath(file, options), flaw);
  }
  flaw = undefined;
  for (const bad of [path.join(root, 'other.json'), file.replace('run-test', 'loose'),
    file.replace('standalone-assessment', 'different'), `${root}/tasks/../outside.json`]) {
    assert.throws(() => assertNativeEvidencePath(bad, options));
  }
  assert.throws(() => assertNativeEvidencePath(file, { ...options,
    dockerHost: `unix://${root}/.qualification/../docker.sock` }));
});

test('historical admission cannot authorize local output without owned profile', () => {
  const root = '/owned/repository';
  const options = { root, dockerHost: 'unix:///historical/docker.sock', basename: 'standalone-assessment.json' };
  assert.equal(assertNativeEvidencePath('/private/history.json', options), '/private/history.json');
  assert.throws(() => assertNativeEvidencePath(`${root}/tasks/qualification/run-test/standalone-assessment.json`, options));
});

test('actor evidence admission preserves private ownership, containment and socket denials', t => {
  const root = '/owned/repository';
  const file = `${root}/tasks/qualification/run-test/standalone-actor.json`;
  const options = { root, dockerHost: `unix://${root}/.qualification/goat-q/docker.sock`,
    basename: 'standalone-actor.json' };
  let flaw;
  t.mock.method(fs, 'realpathSync', value => flaw === 'ancestor-link' ? `/redirect${value}` : value);
  t.mock.method(fs, 'lstatSync', value => {
    if (value === file && flaw !== 'existing-file') throw Object.assign(new Error('absent'), { code: 'ENOENT' });
    return { uid: process.getuid() + (flaw === 'foreign-owner' ? 1 : 0),
      mode: flaw === 'public-directory' ? 0o755 : 0o700,
      isDirectory: () => !value.endsWith('docker.sock'),
      isSocket: () => flaw !== 'not-socket' && value.endsWith('docker.sock'),
      isSymbolicLink: () => flaw === 'symlink' };
  });
  assert.equal(assertNativeEvidencePath(file, options), file);
  for (flaw of ['ancestor-link', 'existing-file', 'foreign-owner', 'public-directory', 'not-socket', 'symlink']) {
    assert.throws(() => assertNativeEvidencePath(file, options), flaw);
  }
  flaw = undefined;
  for (const bad of [path.join(root, 'other.json'), file.replace('run-test', 'loose'),
    file.replace('standalone-actor', 'different'), `${root}/tasks/../outside.json`]) {
    assert.throws(() => assertNativeEvidencePath(bad, options));
  }
  assert.throws(() => assertNativeEvidencePath(file, { ...options,
    dockerHost: `unix://${root}/.qualification/../docker.sock` }));
});


test('actor fixture delegates evidence admission and publishes exclusively', () => {
  const source=fs.readFileSync(require.resolve('./postgres/secureshopStandaloneActor.integration.test.js'),'utf8');
  assert.ok(source.includes("basename: 'standalone-actor.json'"));
  assert.ok(source.includes("require('../fixtures/secureshopNativeEvidencePath').assertNativeEvidencePath(evidencePath"));
  assert.ok(source.includes("{ flag: 'wx', mode: 0o600 }"));
});

test('actor exact historical upgrade lists match current schema tails and preserve added row defaults', () => {
  const source=fs.readFileSync(require.resolve('./postgres/secureshopStandaloneActor.integration.test.js'),'utf8');
  const lists=[
    ["assert.deepEqual((await migrate(identityMigration,identityDirectory)),[", 'identity-migrations',137],
    ["assert.deepEqual(applied,[", 'workshop-migrations/secureshop_agents',44],
  ];
  for(const [anchor,directory,ceiling] of lists){
    const start=source.indexOf(anchor);assert(start>=0);
    const literal=source.slice(start+anchor.length,source.indexOf(']);',start));
    const names=[...literal.matchAll(/'([0-9]{4}_[a-z0-9_]+\.sql)'/g)].map(x=>x[1]);
    const current=fs.readdirSync(path.resolve(__dirname,'../db/postgres',directory))
      .filter(x=>/^[0-9]{4}_[a-z0-9_]+\.sql$/.test(x)&&Number(x.slice(0,4))>ceiling).sort();
    assert.deepEqual(names,current,'explicit fixture expectation must enumerate every actual tail');
    assert.notDeepEqual(names.slice(0,-1),current,'omitted tail cannot satisfy exact equality');
  }
  assert(source.includes('bootstrap_persona_authority_version:null,bootstrap_membership_version:null,\n      additional_session:false'));
  assert(source.includes('assert.deepEqual(await migrate(agentsMigration,agentsDirectory),[])'));
  assert(source.includes('assert.deepEqual(await migrate(identityMigration,identityDirectory),[])'));
});
