'use strict';
const test = require.main === module ? require('node:test') : () => {};
const assert = require('node:assert/strict'), { randomUUID } = require('node:crypto');
const Contract = require('../server/services/secureshopProductSearchSqlContract');
function source() {
  const sessionId = randomUUID();
  return { version: 1, search: { scope: { launchId: randomUUID(), scenarioId: randomUUID(), generation: 1,
    platformOwnerId: 1, platformSessionId: 2 }, operationId: randomUUID(), persona: { id: 3, role: 'customer' },
  personaSession: { sessionId: randomUUID(), authorityVersion: '1' }, mode: 'vuln', query: 'Training', filters: {} },
  execution: { runId: randomUUID(), ownerKey: JSON.stringify(['SecureShopBoundConversation', sessionId]),
    generation: '0', sessionId, requestId: randomUUID(), step: 1, callId: 'product-search:1' } };
}
function row(overrides = {}) { return { id: 1, name: 'Training product', description: null, price: '12.50',
  category: 'Training', image_url: null, stock_quantity: 20, retailer_id: 1, status: 'active', created_at: null, updated_at: null, ...overrides }; }
test('original eleven-column LIKE UNION text survives byte-exactly while fixed uses a literal parameter', () => {
  const input = source(); input.search.query = "' UNION SELECT 1,api_key,NULL,0,NULL,NULL,0,0,NULL,NULL,NULL FROM shop_users--";
  const query = Contract.statement(input);
  assert.match(query.text, /FROM public\.products\) SELECT id, name, description, price, category, image_url, stock_quantity, retailer_id, status, created_at, updated_at FROM products/);
  assert.ok(query.text.endsWith(`WHERE name LIKE '%${input.search.query}%' LIMIT 50`));
  assert.deepEqual(query.values, []);
  const fixed = Contract.statement({ ...input, search: { ...input.search, mode: 'fixed' } });
  assert.ok(fixed.text.endsWith('WHERE name LIKE $1 LIMIT 50'));
  assert.equal(fixed.text.includes(input.search.query), false);
  assert.deepEqual(fixed.values, [`%${input.search.query}%`]);
});
test('filters preserve original SQL rows and apply the original category/price semantics afterward', () => {
  const input = source(), raw = { rows: [row(), row({ id: 2, category: 'Other', price: '8' })], row_count: 2 };
  input.search.filters = { category: 'Training', min_price: 10, max_price: 13 };
  assert.deepEqual(Contract.publicResult(input, raw), [raw.rows[0]]);
  assert.deepEqual(Contract.filterResult(input.search.filters, raw), [raw.rows[0]]);
  assert.throws(() => Contract.filterResult({ category: 'Training', mode: 'vuln' }, raw));
  assert.equal(Contract.result(raw).row_count, 2);
  assert.equal(Contract.statement(input).text.includes('min_price'), false);
  input.search.filters = { category: '', max_price: 9 };
  assert.deepEqual(Contract.publicResult(input, raw), [raw.rows[1]]);
});
test('authority, raw arguments and result schemas are closed and snapshotted', () => {
  const input = source(), checked = Contract.request(input); input.search.filters.category = 'changed';
  assert.deepEqual(checked.search.filters, {});
  for (const mutate of [v => { v.search.mode = 'mock'; }, v => { v.search.persona.role = 'admin'; },
    v => { v.search.filters.sql = 'SELECT 1'; }, v => { v.search.query = '\0'; },
    v => { v.execution.ownerKey = 'foreign'; }, v => { v.execution.step = 9; },
    v => { v.search.personaSession.authorityVersion = 1; }, v => { v.search.scope.extra = true; }]) {
    const v = source(); mutate(v); assert.throws(() => Contract.request(v));
  }
  assert.throws(() => Contract.result({ rows: Array.from({ length: 51 }, () => row()), row_count: 51 }));
  assert.throws(() => Contract.result({ rows: [row({ extra: 1 })], row_count: 1 }));
  assert.throws(() => Contract.result({ rows: [row()], row_count: 2 }));
  assert.throws(() => Contract.result({ rows: [row({ name: 'x'.repeat(8193) })], row_count: 1 }));
  assert.throws(() => Contract.result({ rows: Array.from({ length: 50 }, () => row({ name: 'x'.repeat(4000) })), row_count: 50 }));
});
test('receipts bind request, target, original result, SQL, parameter and full execution digests', () => {
  const input = source(), target = { targetId: randomUUID(), scope: input.search.scope, sourceManifestSha256: 'a'.repeat(64) };
  const saved = Contract.buildReceipt({ target, request: input, result: { rows: [row()], row_count: 1 } });
  assert.deepEqual(Contract.receipt(saved, input), saved); assert.deepEqual(Contract.storedReceipt(saved), saved);
  for (const key of ['requestSha256', 'sqlSha256', 'valuesSha256', 'resultSha256']) assert.throws(() => Contract.receipt({ ...saved, [key]: 'b'.repeat(64) }, input));
  assert.throws(() => Contract.receipt({ ...saved, scope: { ...saved.scope, platformOwnerId: 8 } }, input));
  assert.throws(() => Contract.receipt({ ...saved, execution: { ...saved.execution, generation: '1' } }, input));
  assert.throws(() => Contract.receipt({ ...saved, kind: 'coupon-probe' }, input));
  assert.throws(() => Contract.receipt(saved, { ...input, search: { ...input.search, filters: { category: 'Other' } } }));
  const selectors = { scope: target.scope, targetId: target.targetId, operationId: input.search.operationId, requestSha256: saved.requestSha256 };
  assert.deepEqual(Contract.referenceRequest(selectors), selectors);
  assert.throws(() => Contract.referenceRequest({ ...selectors, field: 'password' }));
});
module.exports = { source, row };
