'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { seedSecureShopStandaloneDefaults, DEFAULTS_SHA256 } = require('../server/database/postgres/secureshopStandaloneSeed');

test('standalone seed submits only independent canonical accounts in one durable batch', async () => {
  let batch, calls = 0;
  const result = await seedSecureShopStandaloneDefaults(null, {
    repository: { seedDefaultsOnce: async input => { calls += 1; batch = input; return { seeded: true }; } },
    hashPassword: async password => { assert.equal(password, 'student123'); return 'synthetic-hash'; },
    randomUUID: () => 'new-shop-principal',
  });
  assert.deepEqual(result, { seeded: true }); assert.equal(calls, 1);
  assert.equal(batch.defaultsSha256, DEFAULTS_SHA256);
  assert.deepEqual(batch.principals.map(({ username, role }) => [username, role]), [
    ['student_customer', 'customer'], ['student_merchant', 'merchant'], ['student_admin', 'admin'],
  ]);
  assert.ok(batch.principals.every(row => row.passwordHash === 'synthetic-hash' && !('ownerId' in row)
    && !('platformUserId' in row) && !('password' in row)));
});

test('seed preserves the repository no-op decision and does not reset deleted accounts', async () => {
  const result = await seedSecureShopStandaloneDefaults(null, {
    repository: { seedDefaultsOnce: async () => ({ seeded: false }) },
    hashPassword: async () => 'synthetic-hash', randomUUID: () => 'unused',
  });
  assert.deepEqual(result, { seeded: false });
});
