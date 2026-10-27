'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const server = require('../server/services/secureshopManualListingContract');
const client = import('../client/src/pages/secureshop/pages/merchant/manualListingOperation.mjs');
const scopeKey = 'a'.repeat(64);
const listing = { name: 'Manual lamp', description: 'Merchant text', price: 12.25,
  category: 'Home', images: ['/first.png', '/second.png'], templateSource: '{{ name }}' };
function preview(kind, invalidatesGeneratedHtml = false) {
  const common = { version: 1, origin: 'manual', kind, listing, scopeKey };
  if (kind === 'create') return server.makeManualListingPreview({ ...common,
    currency: 'USD', initialStock: 0, status: 'active' });
  const before = server.manualListingView({ name: 'Old name', description: 'Old text',
    descriptionHtml: '<p>Controlled fixture HTML</p>', price: 9.5, category: null,
    templateSource: null, imageUrl: '/old.png', images: ['/old.png', '/retained.png'] });
  return server.makeManualListingPreview({ ...common, productId: 17, before,
    after: server.manualListingAfter(before, listing, invalidatesGeneratedHtml),
    catalogRevision: '42', expectedSnapshotSha256: 'b'.repeat(64), invalidatesGeneratedHtml });
}

for (const [kind, invalidates] of [['create', false], ['edit', false], ['edit', true]]) {
  test(`client decodes backend ${kind} preview (invalidation=${invalidates}) with independent immutable fields`, async () => {
    const api = await client, wire = JSON.parse(JSON.stringify(preview(kind, invalidates)));
    const decoded = await api.decodeManualPreview(wire, kind, scopeKey);
    assert.deepEqual(decoded, wire);
    assert.ok(Object.isFrozen(decoded));
    assert.ok(Object.isFrozen(decoded.listing));
    assert.ok(Object.isFrozen(decoded.listing.images));
    wire.listing.images[0] = '/mutated.png';
    assert.equal(decoded.listing.images[0], '/first.png');
    assert.throws(() => decoded.listing.images.push('/extra.png'), TypeError);
    if (kind === 'edit') {
      assert.ok(Object.isFrozen(decoded.before));
      assert.ok(Object.isFrozen(decoded.after.images));
      wire.before.images[0] = '/changed-old.png';
      assert.equal(decoded.before.images[0], '/old.png');
      assert.equal(decoded.after.descriptionHtml, invalidates ? null : decoded.before.descriptionHtml);
    }
  });
}

test('client rejects changed content, scope, kind and inconsistent edit consequences', async () => {
  const api = await client;
  for (const kind of ['create', 'edit']) {
    const original = preview(kind, true);
    await assert.rejects(api.decodeManualPreview(original, kind, 'c'.repeat(64)));
    await assert.rejects(api.decodeManualPreview(original, kind === 'create' ? 'edit' : 'create', scopeKey));
    const changed = JSON.parse(JSON.stringify(original));
    changed.listing.images.reverse();
    await assert.rejects(api.decodeManualPreview(changed, kind, scopeKey));
  }
  const changed = JSON.parse(JSON.stringify(preview('edit', true)));
  changed.after.descriptionHtml = 'Unexpected retained HTML';
  const { requestSha256, ...base } = changed;
  changed.requestSha256 = await api.manualDigest(base);
  await assert.rejects(api.decodeManualPreview(changed, 'edit', scopeKey));
});
