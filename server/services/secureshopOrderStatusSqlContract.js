'use strict';

const A = require('../../sidecars/analytics-sql-target/contract');
const { execution } = require('./secureshopProductSearchSqlContract');
const { isDeepStrictEqual: equal } = require('node:util');
const COLUMNS = Object.freeze(['id', 'customer_id', 'total_amount', 'status',
  'payment_method', 'payment_status', 'shipping_address', 'order_date']);
const fail = (code = 'ORDER_STATUS_SQL_INVALID') => Object.assign(Error('Owned order status unavailable'), { code });
function exact(value, keys) { try { A.exact(value, keys); } catch { throw fail(); } }
function text(value, maximum) {
  if (typeof value !== 'string' || !value.isWellFormed() || value.includes('\0') || Buffer.byteLength(value) > maximum) throw fail();
  return value;
}
function request(value) {
  exact(value, ['version', 'lookup', 'execution']); if (value.version !== 1) throw fail();
  const l = value.lookup;
  exact(l, ['scope', 'operationId', 'persona', 'personaSession', 'mode', 'order_id']);
  exact(l.persona, ['id', 'role']); exact(l.personaSession, ['sessionId', 'authorityVersion']);
  if (typeof l.operationId !== 'string' || !A.UUID.test(l.operationId)
    || !Number.isSafeInteger(l.persona.id) || l.persona.id < 1 || l.persona.role !== 'customer'
    || typeof l.personaSession.sessionId !== 'string' || !A.UUID.test(l.personaSession.sessionId)
    || typeof l.personaSession.authorityVersion !== 'string' || !/^[1-9][0-9]*$/.test(l.personaSession.authorityVersion)
    || !['vuln', 'fixed'].includes(l.mode)) throw fail();
  const orderId = typeof l.order_id === 'string' ? text(l.order_id, 1024) : l.order_id;
  if (typeof orderId !== 'string' && !Number.isSafeInteger(orderId)) throw fail();
  return Object.freeze({ version: 1, lookup: Object.freeze({ scope: A.scope(l.scope), operationId: l.operationId,
    persona: Object.freeze({ ...l.persona }), personaSession: Object.freeze({ ...l.personaSession }), mode: l.mode,
    order_id: orderId }), execution: execution(value.execution) });
}
function statement(input) {
  const l = request(input).lookup;
  const projection = 'WITH orders AS (SELECT id,customer_id,total_amount,status,NULL::text AS payment_method,NULL::text AS payment_status,NULL::text AS shipping_address,NULL::text AS order_date FROM public.orders) ';
  // The original raw order expression is the deliberate owned teaching sink.
  // Fixed mode preserves the same input as a bound value, never SQL syntax.
  return Object.freeze({ text: `${projection}SELECT ${COLUMNS.join(', ')} FROM orders WHERE id = ${l.mode === 'fixed' ? '$1' : l.order_id} LIMIT 1`,
    values: Object.freeze(l.mode === 'fixed' ? [String(l.order_id)] : []) });
}
function result(value) {
  if (value?.kind === 'postgres-error') {
    exact(value, ['kind', 'sqlstate', 'message']);
    if (value.sqlstate !== '22P02' || !text(value.message, 8192)) throw fail('ORDER_STATUS_SQL_RESULT_INVALID');
    return Object.freeze({ kind: 'postgres-error', sqlstate: '22P02', message: value.message });
  }
  exact(value, ['kind', 'rows', 'row_count']);
  if (value.kind !== 'rows' || !Array.isArray(value.rows) || Object.getPrototypeOf(value.rows) !== Array.prototype
    || Reflect.ownKeys(value.rows).length !== value.rows.length + 1 || value.rows.length > 1
    || !Number.isSafeInteger(value.row_count) || value.row_count !== value.rows.length) throw fail('ORDER_STATUS_SQL_RESULT_INVALID');
  const rows = [];
  if (value.rows.length) {
    const descriptor = Object.getOwnPropertyDescriptor(value.rows, '0');
    if (!descriptor || !Object.hasOwn(descriptor, 'value')) throw fail();
    const row = descriptor.value; exact(row, COLUMNS); const out = {};
    for (const key of COLUMNS) {
      const v = row[key];
      if (v !== null) {
        if (['id', 'customer_id'].includes(key)) { if (!Number.isSafeInteger(v)) throw fail(); }
        else if (key === 'total_amount') {
          if (!(typeof v === 'number' && Number.isFinite(v))
            && !(typeof v === 'string' && /^-?\d+(?:\.\d+)?$/.test(v) && v.length <= 128 && Number.isFinite(Number(v)))) throw fail();
        } else text(v, 8192);
      }
      out[key] = v;
    }
    rows.push(Object.freeze(out));
  }
  return Object.freeze({ kind: 'rows', rows: Object.freeze(rows), row_count: rows.length });
}
function publicResult(input, raw) {
  const source = request(input), observed = result(raw), sql = statement(source).text;
  return Object.freeze(observed.kind === 'rows' ? { order: observed.rows[0] || null, sql }
    : { error: source.lookup.mode === 'vuln' ? observed.message : 'Order lookup unavailable.', sql });
}
const RECEIPT_KEYS = ['version', 'kind', 'operationId', 'requestSha256', 'targetId', 'scope',
  'sourceManifestSha256', 'execution', 'sqlSha256', 'valuesSha256', 'resultSha256', 'result'];
function storedReceipt(value) {
  exact(value, RECEIPT_KEYS);
  if (value.version !== 1 || value.kind !== 'order-status-sql' || typeof value.operationId !== 'string' || !A.UUID.test(value.operationId)
    || !['requestSha256', 'sqlSha256', 'valuesSha256', 'resultSha256'].every(k => typeof value[k] === 'string' && A.HASH.test(value[k]))) throw fail();
  const target = A.target({ targetId: value.targetId, scope: value.scope, sourceManifestSha256: value.sourceManifestSha256 }), observed = result(value.result);
  if (A.hash(observed) !== value.resultSha256) throw fail('ORDER_STATUS_SQL_RECEIPT_INVALID');
  return Object.freeze({ ...value, ...target, execution: execution(value.execution), result: observed });
}
function receipt(value, input) {
  const source = request(input), saved = storedReceipt(value), query = statement(source);
  if (saved.operationId !== source.lookup.operationId || saved.requestSha256 !== A.hash(source)
    || !A.sameScope(saved.scope, source.lookup.scope) || !equal(saved.execution, source.execution)
    || saved.sqlSha256 !== A.hash(query.text) || saved.valuesSha256 !== A.hash(query.values)) throw fail('ORDER_STATUS_SQL_RECEIPT_INVALID');
  return saved;
}
function buildReceipt({ target, request: input, result: raw }) {
  const source = request(input), bound = A.target(target), query = statement(source), observed = result(raw);
  return receipt({ version: 1, kind: 'order-status-sql', operationId: source.lookup.operationId,
    requestSha256: A.hash(source), ...bound, execution: source.execution, sqlSha256: A.hash(query.text),
    valuesSha256: A.hash(query.values), resultSha256: A.hash(observed), result: observed }, source);
}
function readRequest(value) {
  exact(value, ['scope', 'targetId', 'operationId', 'requestSha256']);
  if (![value.targetId, value.operationId].every(v => typeof v === 'string' && A.UUID.test(v))
    || typeof value.requestSha256 !== 'string' || !A.HASH.test(value.requestSha256)) throw fail();
  return Object.freeze({ ...value, scope: A.scope(value.scope) });
}
module.exports = { COLUMNS, request, execution, statement, result, publicResult, receipt, storedReceipt,
  buildReceipt, readRequest, referenceRequest: readRequest, hash: A.hash };
