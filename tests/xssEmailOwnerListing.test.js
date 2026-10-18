'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { createXssWorkshopDb } = require('../server/database/postgres/xssWorkshopDb');

test('PostgreSQL XSS email listing keeps public archive rows and filters owner rows', async () => {
  const rows = [
    { id: 1, subject: 'public', sender: 'archive@example.test', received_at: '2026-01-01T00:00:00Z', user_key: null },
    { id: 2, subject: 'owner-a', sender: 'a@example.test', received_at: '2026-01-02T00:00:00Z', user_key: 'owner-a' },
    { id: 3, subject: 'owner-b', sender: 'b@example.test', received_at: '2026-01-03T00:00:00Z', user_key: 'owner-b' },
  ];
  const calls = [];
  const pool = {
    query: async (sql, params) => {
      calls.push({ sql, params });
      const owner = params[0];
      return { rows: rows.filter(row => row.user_key === null || row.user_key === owner) };
    },
  };
  const store = createXssWorkshopDb(pool);

  assert.deepEqual((await store.listEmails('owner-a')).map(row => row.subject), ['public', 'owner-a']);
  assert.deepEqual((await store.listEmails('owner-b')).map(row => row.subject), ['public', 'owner-b']);
  assert.match(calls[0].sql, /user_key IS NULL OR user_key=\$1/);
  assert.deepEqual(calls.map(call => call.params), [['owner-a'], ['owner-b']]);
  assert.throws(() => store.listEmails(), /owner is required/);
});
