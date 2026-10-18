'use strict';

const assert = require('node:assert/strict');
const Module = require('node:module');
const test = require('node:test');

test('PostgreSQL XSS store exposes private origin operations without changing the public profile DTO', async () => {
  const modulePath = require.resolve('../server/database/postgres/xssWorkshopDb');
  const originalLoad = Module._load;
  const calls = [];
  Module._load = function mockOriginRepository(request, parent, isMain) {
    if (request === './xssProfileOriginRepository' && parent?.filename === modulePath) {
      return {
        createXssProfileOriginRepository(pool) {
          calls.push({ operation: 'create', pool });
          return {
            writeModelField: async input => { calls.push({ operation: 'write', input }); return { written: true }; },
            readCurrent: async input => { calls.push({ operation: 'read', input }); return { value: input.field }; },
          };
        },
      };
    }
    return originalLoad.call(this, request, parent, isMain);
  };

  delete require.cache[modulePath];
  try {
    const queries = [];
    const pool = {
      async query(sql, params) {
        queries.push({ sql, params });
        return { rows: [{ name: 'Owner', bio: 'Raw bio', website: 'https://fixture.invalid' }] };
      },
    };
    const module = require(modulePath);
    const store = module.createXssWorkshopDb(pool);
    const write = { userKey: '17', field: 'bio', value: '<img onerror=one()>' };
    const read = { userKey: '17', platformUserId: 17, field: 'bio' };

    assert.deepEqual(await store.writeModelProfileField(write), { written: true });
    assert.deepEqual(await store.readCurrentProfileField(read), { value: 'bio' });
    assert.deepEqual(await store.getProfile('17'), {
      name: 'Owner', bio: 'Raw bio', website: 'https://fixture.invalid',
    });
    assert.deepEqual(calls, [
      { operation: 'create', pool },
      { operation: 'write', input: write },
      { operation: 'read', input: read },
    ]);
    assert.match(queries[0].sql, /^SELECT name,bio,website FROM xss\.profiles/);
    assert.deepEqual(queries[0].params, ['17']);
    assert.equal(typeof module.writeModelProfileField, 'function');
    assert.equal(typeof module.readCurrentProfileField, 'function');
  } finally {
    Module._load = originalLoad;
    delete require.cache[modulePath];
  }
});
