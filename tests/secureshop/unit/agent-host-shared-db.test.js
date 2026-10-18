'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');

const REPO = path.resolve(__dirname, '../../..');
const shared = require(path.join(REPO, 'agent-host/shared/db.js'));

test('retired synchronous commerce handle fails closed with the PostgreSQL-only contract', () => {
  assert.equal(
    shared.PG_ONLY_MESSAGE,
    'SecureShop uses awaited PostgreSQL repositories; synchronous database handles are unavailable'
  );
  assert.throws(() => shared.getSecureshopDb(), {
    name: 'Error',
    message: shared.PG_ONLY_MESSAGE,
  });
});

test('retired synchronous agent handle fails closed with the PostgreSQL-only contract', () => {
  assert.throws(() => shared.getAgentsDb(), {
    name: 'Error',
    message: shared.PG_ONLY_MESSAGE,
  });
});

test('legacy closeAll remains a harmless compatibility cleanup', () => {
  assert.equal(shared.closeAll(), undefined);
});
