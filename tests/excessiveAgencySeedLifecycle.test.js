'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { createPostgresExcessiveAgencyLabDb } = require('../server/database/postgres/excessiveAgencyLabDb');

function fixture(ownerExists) {
  const calls = [];
  const client = {
    async query(sql, params) {
      calls.push({ sql, params });
      if (sql.startsWith('INSERT INTO excessive_agency.attendees')) {
        return { rowCount: ownerExists ? 0 : 1, rows: [] };
      }
      return { rowCount: 1, rows: [] };
    },
    release() {},
  };
  return { calls, database: createPostgresExcessiveAgencyLabDb({ connect: async () => client }, 'owner-a') };
}

test('existing attendee initialization does not restore mutated teaching records', async () => {
  const { database, calls } = fixture(true);
  await database.ensureSeeded();
  assert.equal(calls.filter(call => call.sql.startsWith('INSERT')).length, 1);
  assert.equal(calls.at(-1).sql, 'COMMIT');
});

test('new attendee initialization and explicit reset both create teaching fixtures', async () => {
  for (const operation of ['initialize', 'reset']) {
    const { database, calls } = fixture(operation === 'reset');
    await (operation === 'reset' ? database.reset() : database.ensureSeeded());
    for (const table of ['users', 'notes', 'orders']) {
      assert.ok(calls.some(call => call.sql.startsWith(`INSERT INTO excessive_agency.${table}`)), `${operation}: ${table}`);
    }
    assert.equal(calls.at(-1).sql, 'COMMIT');
  }
});
