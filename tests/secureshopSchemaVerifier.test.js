'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { EXPECTED, verifySchema } = require('../scripts/verify-secureshop-schema');

test('schema verifier reads both PostgreSQL teaching schemas without opening legacy files', async () => {
  for (const [schema, expected] of Object.entries(EXPECTED)) {
    const pool = { query: async (sql, params) => {
      assert.match(sql, /information_schema\.columns/);
      assert.match(sql, /t\.table_type='BASE TABLE'/);
      assert.doesNotMatch(sql, /INSERT|UPDATE|DELETE|CREATE|PRAGMA/);
      assert.deepEqual(params, [schema, Object.keys(expected)]);
      return { rows: Object.entries(expected).flatMap(([table, columns]) =>
        (columns.length ? columns : ['id']).map(column => ({ table_name: table, column_name: column }))) };
    } };
    assert.deepEqual(await verifySchema(pool, schema), []);
  }
});
test('missing tables and columns cannot produce a passing verification', async () => {
  const errors = await verifySchema({ query: async () => ({ rows: [
    { table_name: 'shop_users', column_name: 'id' },
  ] }) }, 'secureshop');
  assert.ok(errors.includes('secureshop.shop_users: missing column api_key'));
  assert.ok(errors.includes('secureshop: missing table products'));
  await assert.rejects(verifySchema({ query: () => assert.fail('must not query') }, 'unknown'), /Known SecureShop/);
});
test('legacy vector metadata cannot satisfy the PostgreSQL corpus generation contract', async () => {
  const errors = await verifySchema({ query: async () => ({ rows: [
    { table_name: 'vector_index_meta', column_name: 'corpus' },
    { table_name: 'vector_documents', column_name: 'id' },
  ] }) }, 'secureshop_agents');
  assert.ok(errors.includes('secureshop_agents: missing table vector_corpora'));
  assert.ok(errors.includes('secureshop_agents.vector_documents: missing column generation'));
  assert.ok(errors.includes('secureshop_agents.vector_documents: missing column embedding'));
});
