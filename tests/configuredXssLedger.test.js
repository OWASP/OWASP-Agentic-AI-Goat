'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');

test('configured XSS ledgers enable child authority and reuse the shared lease pool', () => {
  const ledgerPath = require.resolve('../server/agent-runtime/postgresRunLedger');
  const databasePath = require.resolve('../server/database/postgres');
  const identityPath = require.resolve('../server/services/postgresIdentityAdapter');
  const saved = new Map([ledgerPath, databasePath, identityPath].map(path => [path, require.cache[path]]));
  const previous = process.env.PLATFORM_DATABASE_ENGINE;
  let pools = 0;
  const pool = { query:async () => { throw new Error('Construction must not query'); } };
  try {
    process.env.PLATFORM_DATABASE_ENGINE = 'postgres';
    require.cache[databasePath] = { id:databasePath, filename:databasePath, loaded:true, exports:{
      createPool:(_env, key, options) => {
        assert.equal(key, 'IDENTITY_DATABASE_URL');
        assert.equal(options.purpose, 'lease');
        pools += 1;
        return pool;
      },
    } };
    require.cache[identityPath] = { id:identityPath, filename:identityPath, loaded:true,
      exports:{ getPostgresIdentityAdapter:() => ({ pool }) } };
    delete require.cache[ledgerPath];
    const { configuredRunLedger } = require(ledgerPath);
    assert.equal(pools, 0);
    assert.equal(configuredRunLedger({ family:'XSS' }).supportsScopedAdmission, true);
    assert.equal(configuredRunLedger({ family:'XSS' }).supportsScopedAdmission, true);
    assert.equal(configuredRunLedger({ family:'DPI' }).supportsScopedAdmission, false);
    assert.equal(pools, 1);
  } finally {
    if (previous === undefined) delete process.env.PLATFORM_DATABASE_ENGINE;
    else process.env.PLATFORM_DATABASE_ENGINE = previous;
    for (const [path, entry] of saved) {
      if (entry) require.cache[path] = entry;
      else delete require.cache[path];
    }
  }
});
