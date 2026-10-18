'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { randomUUID } = require('node:crypto');
const {
  normalizeListingTemplateRequest,
  listingTemplateRequestDigest,
} = require('../server/services/secureshopListingTemplateContract');

test('template request names one saved product and never accepts source or authority from the caller', () => {
  const operationId = randomUUID();
  const request = normalizeListingTemplateRequest({ version: 1, operationId, productId: 7 });
  assert.deepEqual(request, { version: 1, operationId, productId: 7 });
  assert.equal(Object.isFrozen(request), true);
  for (const extra of [
    { templateSource: '{{ process.pid }}' },
    { targetId: randomUUID() },
    { ownerId: randomUUID() },
    { mode: 'vuln' },
    { sourceSha256: 'a'.repeat(64) },
  ]) {
    assert.throws(() => normalizeListingTemplateRequest({ ...request, ...extra }));
  }
});

test('template operation digest binds the exact saved product and operation identity', () => {
  const operationId = randomUUID();
  const first = { version: 1, operationId, productId: 7 };
  const digest = listingTemplateRequestDigest(first);
  assert.match(digest, /^[a-f0-9]{64}$/);
  assert.equal(listingTemplateRequestDigest({ ...first }), digest);
  assert.notEqual(listingTemplateRequestDigest({ ...first, productId: 8 }), digest);
  assert.notEqual(listingTemplateRequestDigest({ ...first, operationId: randomUUID() }), digest);
  for (const bad of [{ ...first, productId: 0 }, { ...first, productId: '7' },
    { ...first, operationId: 'not-a-uuid' }, { ...first, version: 2 }]) {
    assert.throws(() => normalizeListingTemplateRequest(bad));
  }
});
