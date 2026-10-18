'use strict';
const test = require.main === module ? require('node:test') : () => {};
const assert = require('node:assert/strict'), { randomUUID } = require('node:crypto');
const C = require('../server/services/secureshopOrderStatusSqlContract');
function source() {
  const original = require('./secureshopProductSearchSqlContract.test').source();
  const { query, filters, ...lookup } = original.search;
  return { version: 1, lookup: { ...lookup, order_id: 1 }, execution: original.execution };
}
function row() { return { id: 1, customer_id: 2, total_amount: '20', status: 'paid', payment_method: null,
  payment_status: null, shipping_address: null, order_date: null }; }
test('eight-column compatibility preserves raw expression and numeric type while fixed binds a literal', () => {
  const input = source(); input.lookup.order_id = '1 AND CAST((SELECT api_key FROM shop_users WHERE id=1) AS INTEGER)=0';
  const query = C.statement(input);
  assert.ok(query.text.includes('NULL::text AS payment_method,NULL::text AS payment_status,NULL::text AS shipping_address,NULL::text AS order_date FROM public.orders'));
  assert.ok(query.text.endsWith(`WHERE id = ${input.lookup.order_id} LIMIT 1`)); assert.deepEqual(query.values, []);
  const fixed = C.statement({ ...input, lookup: { ...input.lookup, mode: 'fixed' } });
  assert.ok(fixed.text.endsWith('WHERE id = $1 LIMIT 1')); assert.deepEqual(fixed.values, [input.lookup.order_id]);
  const number = source(), string = { ...number, lookup: { ...number.lookup, order_id: '1' } };
  assert.notEqual(C.hash(C.request(number)), C.hash(C.request(string)));
  assert.equal(C.request(number).lookup.order_id, 1);
});
test('public observations preserve original rows/error and compute SQL; fixed never discloses error bytes', () => {
  const input = source(), raw = { kind: 'rows', rows: [row()], row_count: 1 };
  assert.deepEqual(C.publicResult(input, raw), { order: row(), sql: C.statement(input).text });
  assert.equal(C.publicResult(input, { kind: 'rows', rows: [], row_count: 0 }).order, null);
  const failure = { kind: 'postgres-error', sqlstate: '22P02', message: 'invalid input syntax: SYNTHETIC_KEY_private' };
  assert.equal(C.publicResult(input, failure).error, failure.message);
  const fixed = { ...input, lookup: { ...input.lookup, mode: 'fixed' } };
  assert.deepEqual(C.publicResult(fixed, failure), { error: 'Order lookup unavailable.', sql: C.statement(fixed).text });
  assert.throws(() => C.result({ ...failure, sqlstate: '42601' }));
  assert.throws(() => C.result({ ...failure, message: 'x'.repeat(8193) }));
  assert.throws(() => C.result({ ...failure, inferred: true }));
  assert.throws(() => C.result({ kind: 'rows', rows: [row(), row()], row_count: 2 }));
  assert.throws(() => C.result({ kind: 'rows', rows: [row()], row_count: 0 }));
});
test('closed receipt binds authority, raw request type, SQL/parameters and original result bytes', () => {
  const input = source(), target = { targetId: randomUUID(), scope: input.lookup.scope, sourceManifestSha256: 'a'.repeat(64) };
  const saved = C.buildReceipt({ target, request: input, result: { kind: 'postgres-error', sqlstate: '22P02', message: 'original' } });
  assert.deepEqual(C.receipt(saved, input), saved); assert.deepEqual(C.storedReceipt(saved), saved);
  for (const key of ['requestSha256', 'sqlSha256', 'valuesSha256', 'resultSha256']) assert.throws(() => C.receipt({ ...saved, [key]: 'b'.repeat(64) }, input));
  assert.throws(() => C.receipt(saved, { ...input, lookup: { ...input.lookup, order_id: '1' } }));
  assert.throws(() => C.receipt({ ...saved, scope: { ...saved.scope, platformOwnerId: 9 } }, input));
  assert.throws(() => C.request({ ...input, lookup: { ...input.lookup, sql: 'SELECT 1' } }));
  for (const order_id of [null, {}, NaN, Infinity, 1.5, '\0', 'x'.repeat(1025)]) assert.throws(() => C.request({ ...input, lookup: { ...input.lookup, order_id } }));
  const selectors = { scope: target.scope, targetId: target.targetId, operationId: input.lookup.operationId, requestSha256: saved.requestSha256 };
  assert.deepEqual(C.referenceRequest(selectors), selectors); assert.throws(() => C.referenceRequest({ ...selectors, field: 'password' }));
});
module.exports = { source, row };
