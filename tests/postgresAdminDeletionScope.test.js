'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { createPostgresAdminRepository } = require('../server/database/postgres/adminRepository');
test('student deletion constrains target role in the mutation rather than a race-prone preceding read', async () => {
  let calls = 0;
  const repository = createPostgresAdminRepository({ async query(sql, values) {
    calls++;
    assert.equal(sql, "DELETE FROM identity.users WHERE id=$1 AND role='student' AND admin_level=0 RETURNING id");
    assert.deepEqual(values, [17]);
    return { rows: [] };
  } });
  assert.equal(await repository.deleteUser('17'), null);
  assert.equal(calls, 1);
  await assert.rejects(repository.deleteUser('17 OR 1=1'));
  assert.equal(calls, 1);
});
