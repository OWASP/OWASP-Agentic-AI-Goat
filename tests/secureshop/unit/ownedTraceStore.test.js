'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { agentSessionControl } = require('../../../server/routes/secureshop/_agentSessionControl.js');
const { createSecureShopCustomerRepository } = require('../../../server/database/postgres/secureshopCustomerRepository.js');
const { createSecureShopMerchantRepository } = require('../../../server/database/postgres/secureshopMerchantRepository.js');
const { createSecureShopAdminRepository } = require('../../../server/database/postgres/secureshopAdminRepository.js');

// PostgreSQL execution/owner isolation is qualified in the native
// secureshopConversationBinding and secureshopMerchant integration suites.
// This controlled suite checks query construction and authenticated forwarding.

test('control passes authenticated identity once and skips the reader on role mismatch', async () => {
  const control = agentSessionControl('merchant', {});
  const calls = [];
  const rows = await control.getLatestOwned(
    { ssUser: { id: 42, role: 'merchant' } }, 10,
    async (owner) => { calls.push(owner); return [{ session_id: 'mine' }]; },
  );
  assert.deepEqual(rows, [{ session_id: 'mine' }]);
  assert.deepEqual(calls, [{ userId: 42, role: 'merchant', limit: 10 }]);

  const denied = await control.getLatestOwned(
    { ssUser: { id: 42, role: 'customer' } }, 10,
    async () => { throw new Error('reader must not run'); },
  );
  assert.deepEqual(denied, []);
});

function recordingPool(rows = []) {
  const calls = [];
  return {
    calls,
    async query(sql, args) {
      calls.push({ sql, args });
      return { rows, fields: [] };
    },
  };
}

test('PostgreSQL latest trace adapters use one owner-scoped query before limit', async () => {
  const cases = [
    {
      pool: recordingPool([{ id: 1, session_id: 'customer' }]),
      build(pool) { return createSecureShopCustomerRepository(recordingPool(), pool); },
      read(repo) { return repo.latestTrace({ userId: 7, role: 'customer', limit: 5 }); },
      role: 'customer',
    },
    {
      pool: recordingPool([{ id: 2, session_id: 'merchant' }]),
      build(pool) { return createSecureShopMerchantRepository({ commercePool: recordingPool(), agentsPool: pool }); },
      read(repo) { return repo.latestMerchantTrace({ userId: 8, role: 'merchant', limit: 10 }); },
      role: 'merchant',
    },
    {
      pool: recordingPool([{ id: 3, session_id: 'admin' }]),
      build(pool) { return createSecureShopAdminRepository(recordingPool(), pool); },
      read(repo) { return repo.latestTrace({ userId: 9, role: 'admin', limit: 20 }); },
      role: 'admin',
    },
  ];

  for (const item of cases) {
    await item.read(item.build(item.pool));
    assert.equal(item.pool.calls.length, 1, `${item.role} query count`);
    const [{ sql, args }] = item.pool.calls;
    assert.match(sql, /INNER JOIN secureshop_agents\.agent_sessions s ON s\.id\s*=\s*t\.session_id/i);
    assert.match(sql, /WHERE s\.user_id\s*=\s*\$1 AND s\.role\s*=\s*\$2[\s\S]*ORDER BY[\s\S]*LIMIT \$3/i);
    assert.equal(args[1], item.role);
  }
});
