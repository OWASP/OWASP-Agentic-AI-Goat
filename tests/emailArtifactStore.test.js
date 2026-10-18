'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const Module = require('node:module');
const path = require('node:path');

const storePath = path.resolve(__dirname, '../server/services/emailArtifactStore.js');

test('configured artifact store is PostgreSQL-only, lazy, and delegates every lifecycle method', async () => {
  const previousEngine = process.env.PLATFORM_DATABASE_ENGINE;
  const originalLoad = Module._load;
  const calls = [];
  try {
    delete require.cache[storePath];
    process.env.PLATFORM_DATABASE_ENGINE = 'sqlite';
    const unavailable = require(storePath);
    await assert.rejects(async () => unavailable.assertReady(), {
      code:'EMAIL_ARTIFACT_STORAGE_NOT_READY', statusCode:503,
    });

    delete require.cache[storePath];
    process.env.PLATFORM_DATABASE_ENGINE = 'postgres';
    Module._load = function load(request, parent, isMain) {
      if (parent?.filename === storePath && request === './postgresIdentityAdapter') {
        calls.push('pool');
        return { getPostgresIdentityAdapter:() => ({ pool:{ marker:'identity' } }) };
      }
      if (parent?.filename === storePath && request === '../database/postgres/emailArtifactRepository') {
        return { createEmailArtifactRepository:pool => {
          assert.equal(pool.marker, 'identity');
          return Object.fromEntries(['createMany','resolveCurrent','retireOwner','destroyOwner','assertReady']
            .map(name => [name, async value => { calls.push([name, value]); return name; }]));
        } };
      }
      return originalLoad.call(this, request, parent, isMain);
    };
    const store = require(storePath);
    for (const name of ['createMany','resolveCurrent','retireOwner','destroyOwner','assertReady']) {
      assert.equal(await store[name]({ scope:name }), name);
    }
    assert.equal(calls.filter(value => value === 'pool').length, 1);
  } finally {
    Module._load = originalLoad;
    delete require.cache[storePath];
    if (previousEngine === undefined) delete process.env.PLATFORM_DATABASE_ENGINE;
    else process.env.PLATFORM_DATABASE_ENGINE = previousEngine;
  }
});
