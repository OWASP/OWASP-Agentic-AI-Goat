'use strict';

const A = require('../../sidecars/analytics-sql-target/contract');
const { isDeepStrictEqual: equal } = require('node:util');
const COLUMNS = Object.freeze(['id', 'name', 'description', 'price', 'category', 'image_url',
  'stock_quantity', 'retailer_id', 'status', 'created_at', 'updated_at']);
const fail = (code = 'PRODUCT_SEARCH_SQL_INVALID') => Object.assign(Error('Owned product search unavailable'), { code });
function exact(value, keys) { try { A.exact(value, keys); } catch { throw fail(); } }
function text(value, maximum) {
  if (typeof value !== 'string' || !value.isWellFormed() || value.includes('\0')
    || Buffer.byteLength(value) > maximum) throw fail();
  return value;
}
function execution(value) {
  exact(value, ['runId', 'ownerKey', 'generation', 'sessionId', 'requestId', 'step', 'callId']);
  if (![value.runId, value.sessionId, value.requestId].every(id => typeof id === 'string' && A.UUID.test(id))
    || value.ownerKey !== JSON.stringify(['SecureShopBoundConversation', value.sessionId])
    || typeof value.generation !== 'string' || !/^(0|[1-9][0-9]*)$/.test(value.generation)
    || !Number.isSafeInteger(value.step) || value.step < 1 || value.step > 8
    || typeof value.callId !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(value.callId)) throw fail();
  return Object.freeze({ ...value });
}
function filters(value) {
  const allowed = ['category', 'min_price', 'max_price'];
  exact(value, allowed.filter(key => Object.hasOwn(value || {}, key)));
  const out = {};
  if (Object.hasOwn(value, 'category')) out.category = text(value.category, 128);
  for (const key of ['min_price', 'max_price']) if (Object.hasOwn(value, key)) {
    if (typeof value[key] !== 'number' || !Number.isFinite(value[key])) throw fail();
    out[key] = value[key];
  }
  return Object.freeze(out);
}
function request(value) {
  exact(value, ['version', 'search', 'execution']);
  if (value.version !== 1) throw fail();
  const s = value.search;
  exact(s, ['scope', 'operationId', 'persona', 'personaSession', 'mode', 'query', 'filters']);
  exact(s.persona, ['id', 'role']); exact(s.personaSession, ['sessionId', 'authorityVersion']);
  if (typeof s.operationId !== 'string' || !A.UUID.test(s.operationId)
    || !Number.isSafeInteger(s.persona.id) || s.persona.id < 1 || s.persona.role !== 'customer'
    || typeof s.personaSession.sessionId !== 'string' || !A.UUID.test(s.personaSession.sessionId)
    || typeof s.personaSession.authorityVersion !== 'string' || !/^[1-9][0-9]*$/.test(s.personaSession.authorityVersion)
    || !['vuln', 'fixed'].includes(s.mode)) throw fail();
  return Object.freeze({ version: 1, search: Object.freeze({ scope: A.scope(s.scope), operationId: s.operationId,
    persona: Object.freeze({ ...s.persona }), personaSession: Object.freeze({ ...s.personaSession }),
    mode: s.mode, query: text(s.query, 1024), filters: filters(s.filters) }), execution: execution(value.execution) });
}
function statement(value) {
  const s = request(value).search;
  // Synthetic nullable fields preserve the original eleven-column UNION shape;
  // public.products is exclusively the owned Analytics teaching database.
  const projection = 'WITH products AS (SELECT id,name,NULL::text AS description,price,category,NULL::text AS image_url,stock_quantity,retailer_id,status,NULL::text AS created_at,NULL::text AS updated_at FROM public.products) ';
  const predicate = s.mode === 'fixed' ? 'name LIKE $1' : `name LIKE '%${s.query}%'`;
  return Object.freeze({ text: `${projection}SELECT ${COLUMNS.join(', ')} FROM products WHERE ${predicate} LIMIT 50`,
    values: Object.freeze(s.mode === 'fixed' ? [`%${s.query}%`] : []) });
}
function result(value) {
  exact(value, ['rows', 'row_count']);
  if (!Array.isArray(value.rows) || Object.getPrototypeOf(value.rows) !== Array.prototype
    || Reflect.ownKeys(value.rows).length !== value.rows.length + 1 || value.rows.length > 50
    || !Number.isSafeInteger(value.row_count) || value.row_count !== value.rows.length) throw fail('PRODUCT_SEARCH_SQL_RESULT_INVALID');
  const rows = [];
  for (let i = 0; i < value.rows.length; i++) {
    const descriptor = Object.getOwnPropertyDescriptor(value.rows, String(i));
    if (!descriptor || !Object.hasOwn(descriptor, 'value')) throw fail();
    const row = descriptor.value; exact(row, COLUMNS);
    const out = {};
    for (const key of COLUMNS) {
      const v = row[key];
      if (v !== null) {
        if (['id', 'stock_quantity', 'retailer_id'].includes(key)) { if (!Number.isSafeInteger(v)) throw fail(); }
        else if (key === 'price') {
          if (!(typeof v === 'number' && Number.isFinite(v))
            && !(typeof v === 'string' && /^-?\d+(?:\.\d+)?$/.test(v) && v.length <= 128 && Number.isFinite(Number(v)))) throw fail();
        } else text(v, 8192);
      }
      out[key] = v;
    }
    rows.push(Object.freeze(out));
  }
  const checked = Object.freeze({ rows: Object.freeze(rows), row_count: rows.length });
  if (Buffer.byteLength(JSON.stringify(checked)) > 131072) throw fail('PRODUCT_SEARCH_SQL_RESULT_INVALID');
  return checked;
}
function filterResult(inputFilters, raw) {
  const selected = filters(inputFilters), original = result(raw);
  return Object.freeze(original.rows.filter(row => (!selected.category || row.category === selected.category)
    && (!Object.hasOwn(selected, 'min_price') || Number(row.price) >= selected.min_price)
    && (!Object.hasOwn(selected, 'max_price') || Number(row.price) <= selected.max_price)));
}
function publicResult(input, raw) {
  return filterResult(request(input).search.filters, raw);
}
const RECEIPT_KEYS = ['version', 'kind', 'operationId', 'requestSha256', 'targetId', 'scope',
  'sourceManifestSha256', 'execution', 'sqlSha256', 'valuesSha256', 'resultSha256', 'result'];
function storedReceipt(value) {
  exact(value, RECEIPT_KEYS);
  if (value.version !== 1 || value.kind !== 'product-search-sql' || typeof value.operationId !== 'string' || !A.UUID.test(value.operationId)
    || !['requestSha256', 'sqlSha256', 'valuesSha256', 'resultSha256'].every(k => typeof value[k] === 'string' && A.HASH.test(value[k]))) throw fail();
  const target = A.target({ targetId: value.targetId, scope: value.scope, sourceManifestSha256: value.sourceManifestSha256 });
  const checkedResult = result(value.result);
  if (A.hash(checkedResult) !== value.resultSha256) throw fail('PRODUCT_SEARCH_SQL_RECEIPT_INVALID');
  return Object.freeze({ ...value, ...target, execution: execution(value.execution), result: checkedResult });
}
function receipt(value, input) {
  const source = request(input), saved = storedReceipt(value), query = statement(source);
  if (saved.operationId !== source.search.operationId || saved.requestSha256 !== A.hash(source)
    || !A.sameScope(saved.scope, source.search.scope) || !equal(saved.execution, source.execution)
    || saved.sqlSha256 !== A.hash(query.text) || saved.valuesSha256 !== A.hash(query.values)) throw fail('PRODUCT_SEARCH_SQL_RECEIPT_INVALID');
  return saved;
}
function buildReceipt({ target, request: input, result: raw }) {
  const source = request(input), bound = A.target(target), query = statement(source), checked = result(raw);
  return receipt({ version: 1, kind: 'product-search-sql', operationId: source.search.operationId,
    requestSha256: A.hash(source), ...bound, execution: source.execution, sqlSha256: A.hash(query.text),
    valuesSha256: A.hash(query.values), resultSha256: A.hash(checked), result: checked }, source);
}
function readRequest(value) {
  exact(value, ['scope', 'targetId', 'operationId', 'requestSha256']);
  if (![value.targetId, value.operationId].every(v => typeof v === 'string' && A.UUID.test(v))
    || typeof value.requestSha256 !== 'string' || !A.HASH.test(value.requestSha256)) throw fail();
  return Object.freeze({ ...value, scope: A.scope(value.scope) });
}
module.exports = { COLUMNS, request, execution, statement, result, filterResult, publicResult, receipt, storedReceipt,
  buildReceipt, readRequest, referenceRequest: readRequest, hash: A.hash };
