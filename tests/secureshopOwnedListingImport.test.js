'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { executeOwnedListingImport } = require('../sidecars/sandbox-runner/owned-listings/import-executor');
const request = { version: 1, action: 'import', operationId: '10000000-0000-4000-8000-000000000001',
  json_url: 'http://supplier.invalid/data.json', xml_url: 'http://supplier.invalid/data.xml' };
const json = Buffer.from('{"name":"JSON product","__proto__":{"executorLesson":"observed"}}');
const xml = Buffer.from('<products><product><name>XML product</name><price>5</price></product></products>');

test('combined import preserves two source receipts and waits for actual JSON worker completion', async () => {
  const calls = [];
  const result = await executeOwnedListingImport({ request, mode: 'vuln', readResource: async (uri, options) => {
    calls.push({ uri, maxBytes: options.maxBytes }); return uri.endsWith('.json') ? json : xml;
  } });
  assert.equal(result.products.length, 2);
  assert.equal(result.sources[0].prototypeEffect.observed, true);
  assert.equal(result.sources[1].kind, 'xml');
  assert.equal(calls[1].maxBytes, 1024 * 1024 - json.length);
  assert.equal(({}).executorLesson, undefined);
});
test('a failed second source rejects the entire attempt without returning partial products', async () => {
  let calls = 0;
  await assert.rejects(executeOwnedListingImport({ request, mode: 'vuln', readResource: async () => {
    if (++calls === 1) return json;
    throw Error('second source failed');
  } }), /second source failed/);
  assert.equal(calls, 2);
});
test('aggregate product and source limits apply across sources', async () => {
  const many = Buffer.from(JSON.stringify(Array.from({ length: 100 }, () => ({ name: 'Product' }))));
  await assert.rejects(executeOwnedListingImport({ request, mode: 'fixed', readResource: async uri => uri.endsWith('.json') ? many : xml }), { code: 'LISTING_IMPORT_LIMIT' });
  await assert.rejects(executeOwnedListingImport({ request, mode: 'fixed', readResource: async () => Buffer.alloc(1024 * 1024 + 1) }), { code: 'LISTING_IMPORT_LIMIT' });
});
test('pre-cancelled attempt never reads or spawns; cancellation after read stops processing', async () => {
  const controller = new AbortController(); controller.abort(); let calls = 0;
  await assert.rejects(executeOwnedListingImport({ request, mode: 'fixed', signal: controller.signal,
    readResource: async () => { calls++; return json; } }));
  assert.equal(calls, 0);
  const later = new AbortController();
  await assert.rejects(executeOwnedListingImport({ request, mode: 'fixed', signal: later.signal,
    readResource: async () => { later.abort(); return json; } }));
});
