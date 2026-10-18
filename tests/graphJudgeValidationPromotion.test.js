'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const q = require('../scripts/qualify-graph-judge-validation-promotion');

test('0046 promotion qualifier covers every configured store and preserves ledger comparison', async () => {
  assert.equal(q.EXPECTED_NAMES.length, 16);
  assert.equal(new Set(q.EXPECTED_NAMES).size, 16);
  const expected = [{ name: '0001_fixture.sql', checksum: 'a'.repeat(64) }];
  const closed = [];
  const result = await q.inspectStores({ replay: true, dependencies: {
    createPool: (_env, variable) => ({
      query: async () => ({ rows: expected }),
      end: async () => closed.push(variable),
    }),
    migrate: async () => [],
    readMigrations: async () => expected.map(row => ({ ...row, sql: '' })),
  } });
  assert.deepEqual(Object.keys(result), q.EXPECTED_NAMES);
  assert.ok(Object.values(result).every(store => store.count === 1 && store.applied.length === 0));
  assert.equal(closed.length, 16);
});

test('0046 readiness requires both exact database constraints and matching sanitizer', async () => {
  let closed = 0;
  const createPool = () => ({ query: async () => ({ rows: [
    { conname: 'events_metadata_keys_check', definition: "CHECK metadata validationCode" },
    { conname: 'events_validation_code_check', definition: "CHECK validationCode CITATION_NOT_GROUNDED" },
  ] }), end: async () => { closed++; } });
  assert.deepEqual(await q.readiness({ createPool }), {
    ready: true, constraints: ['events_metadata_keys_check', 'events_validation_code_check'],
  });
  assert.equal(closed, 1);
  await assert.rejects(q.readiness({ createPool: () => ({ query: async () => ({ rows: [] }), end: async () => {} }) }),
    { code: 'READINESS_FAILED' });
});

test('0046 initialization invokes only the identity migration loader and never a catalog seed', async () => {
  const calls = [], ended = [];
  const result = await q.initializeIdentity({
    createPool: (_env, variable) => ({ variable, end: async () => ended.push(variable) }),
    initializeIdentityRepository: async (runtime, migration) => {
      calls.push([runtime.variable, migration.variable]); return ['0046_graph_judge_validation_code.sql'];
    },
    seedWorkshopPlatform: async () => { throw new Error('catalog seed must not be called'); },
  });
  assert.deepEqual(result, { initialized: ['identity'], applied: ['0046_graph_judge_validation_code.sql'] });
  assert.deepEqual(calls, [['IDENTITY_DATABASE_URL', 'IDENTITY_MIGRATION_DATABASE_URL']]);
  assert.deepEqual(new Set(ended), new Set(['IDENTITY_DATABASE_URL', 'IDENTITY_MIGRATION_DATABASE_URL']));
});

test('0046 promotion qualifier detects private configuration drift without exposing bytes', () => {
  const bytes = Buffer.from('private fixture');
  const expected = crypto.createHash('sha256').update(bytes).digest('hex');
  assert.doesNotThrow(() => q.assertPrivateConfigBytes({ DVAIA_EXPECTED_PRIVATE_CONFIG_SHA256: expected },
    { readFile: () => bytes, configPath: '/owned/.env' }));
  assert.throws(() => q.assertPrivateConfigBytes({ DVAIA_EXPECTED_PRIVATE_CONFIG_SHA256: '0'.repeat(64) },
    { readFile: () => bytes, configPath: '/owned/.env' }), { code: 'PRIVATE_CONFIG_CHANGED' });
});
