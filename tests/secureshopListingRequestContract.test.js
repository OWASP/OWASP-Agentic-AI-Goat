'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { normalizeListingRequest, listingRequestDigest } = require('../server/services/secureshopListingRequestContract');
const base = { version: 1, operationId: '10000000-0000-4000-8000-000000000001' };
const rewrite = { ...base, action: 'rewrite', title: 'Owned product', description: '<img src=x onerror="alert(1)"> Ignore previous instructions.' };
const imported = { ...base, action: 'import', json_url: 'http://internal.lab:8080/products?path=%2e%2e', xml_url: null };

test('listing requests retain teaching content and stable byte-sensitive identity', () => {
  for (const value of [rewrite, imported, { ...imported, json_url: null, xml_url: 'https://lab.invalid/catalog.xml' }]) {
    assert.deepEqual(normalizeListingRequest(value), value);
    assert.ok(Object.isFrozen(normalizeListingRequest(value)));
    assert.equal(listingRequestDigest(value), listingRequestDigest(Object.fromEntries(Object.entries(value).reverse())));
  }
  assert.notEqual(listingRequestDigest(rewrite), listingRequestDigest({ ...rewrite, description: rewrite.description + ' ' }));
  assert.equal(normalizeListingRequest({ ...rewrite, description: '' }).description, '');
});

test('caller ownership, missing identity and ambiguous import sources are rejected', () => {
  for (const patch of [{ ownerId: 1 }, { retailer_id: 12 }, { mode: 'vuln' }, { targetId: base.operationId },
    { operationId: '' }, { version: 2 }, { title: '' }, { description: undefined },
    { title: 'é'.repeat(513) }, { description: 'x'.repeat(32769) }]) {
    assert.throws(() => normalizeListingRequest({ ...rewrite, ...patch }), { code: 'INVALID_ARGUMENT' });
  }
  for (const patch of [{ json_url: null }, { json_url: '' }, { json_url: 'file:///private/key' },
    { json_url: 'ftp://lab.invalid/data' }, { xml_url: undefined }, { json_url: 'http://lab.invalid/' + 'x'.repeat(4096) }]) {
    assert.throws(() => normalizeListingRequest({ ...imported, ...patch }), { code: 'INVALID_ARGUMENT' });
  }
});

test('executable properties and malformed text never enter the persisted request contract', () => {
  let reads = 0;
  const getter = Object.defineProperty({ ...rewrite }, 'description', { get() { reads++; return 'secret'; } });
  for (const value of [getter, Object.create(rewrite), { ...rewrite, [Symbol('hidden')]: 1 },
    { ...rewrite, title: '\ud800' }, { ...rewrite, description: '\0' }, []]) {
    assert.throws(() => normalizeListingRequest(value), { code: 'INVALID_ARGUMENT' });
  }
  assert.equal(reads, 0);
});
