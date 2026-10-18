'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { assertHistoryPrompt, assertNativeSearchRows } = require('./fixtures/sqlNoSqlFixedSessionQualification');
const marker = '...[TRUNCATED FOR MODEL CONTEXT]';
const options = { family: 'ARIA', currentRequest: 'Search exact value', recent: 'RECENT', excluded: ['OLD', 'SIBLING', 'FORGED'] };
const decision = history => `policy\nRecent history (bounded):\n${history}\nActual ordered tool observations (bounded):\n[]\nOriginal user request (JSON encoded string):\n${JSON.stringify(options.currentRequest)}\nFINAL DECISION CHECK: done`;
const response = history => `policy\nRecent conversation:\nARIA: ${history}\n\nStudent query: "${options.currentRequest}"\n\nTool executed: search_products`;
test('both model prompt types enforce actual history size and exact current request', () => {
  for (const build of [decision, response]) {
    assert.doesNotThrow(() => assertHistoryPrompt(build(`${marker} RECENT`), options));
    assert.throws(() => assertHistoryPrompt(build(`${marker} RECENT ${'x'.repeat(5000)}`), options));
    for (const bad of options.excluded) assert.throws(() => assertHistoryPrompt(build(`${marker} RECENT ${bad}`), options));
    assert.throws(() => assertHistoryPrompt(build(`${marker} RECENT`).replace(options.currentRequest, 'different request'), options));
  }
});
test('native row oracle rejects fabricated contents even with matching identities', () => {
  const aria = [{ id: 1, product_id: 'P1', name: 'real', price: 5 }];
  assert.doesNotThrow(() => assertNativeSearchRows(aria, aria, 'ARIA'));
  assert.throws(() => assertNativeSearchRows([{ ...aria[0], price: 0 }], aria, 'ARIA'));
  const nova = [{ paper_id: 'N1', title: 'real', authors: '["A"]', topics: '["T"]', cited_by: '[]', access_level: 'public' }];
  const actual = [{ ...nova[0], authors: ['A'], topics: ['T'], cited_by: [] }];
  assert.doesNotThrow(() => assertNativeSearchRows(actual, nova, 'NOVA'));
  assert.throws(() => assertNativeSearchRows([{ ...actual[0], authors: ['fabricated'] }], nova, 'NOVA'));
  assert.throws(() => assertNativeSearchRows([{ ...actual[0], access_level: 'restricted' }], nova, 'NOVA'));
});
