import { webcrypto } from 'node:crypto';
import { decodeManualPreview, decodeManualReceipt } from './manualListingOperation.mjs';

Object.defineProperty(globalThis, 'crypto', { value: webcrypto, configurable: true });
const server = require('../../../../../../server/services/secureshopManualListingContract');
const scope = 'a'.repeat(64), operationId = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const listing = { name: 'Exact merchant title', description: 'Literal <b>description</b>', price: 12.34,
  category: 'Books', images: ['https://images.test/one.png'], templateSource: '{{ title }}' };

test.each(['create', 'edit'])('decodes and deeply freezes server-generated %s preview', async kind => {
  const common = { version: 1, origin: 'manual', kind, listing, scopeKey: scope };
  const before = { name: 'Old', description: 'Before', descriptionHtml: '<p>Generated</p>', price: 10,
    category: 'Books', templateSource: null, imageUrl: null, images: [] };
  const preview = kind === 'create'
    ? server.makeManualListingPreview({ ...common, currency: 'USD', initialStock: 0, status: 'active' })
    : server.makeManualListingPreview({ ...common, productId: 7, before,
      after: server.manualListingAfter(before, listing, true), catalogRevision: '4',
      expectedSnapshotSha256: 'b'.repeat(64), invalidatesGeneratedHtml: true });
  const wire = JSON.parse(JSON.stringify(preview));
  const decoded = await decodeManualPreview(wire, kind, scope);
  expect(decoded).toEqual(preview);
  expect(Object.isFrozen(decoded)).toBe(true);
  expect(Object.isFrozen(decoded.listing)).toBe(true);
  expect(Object.isFrozen(decoded.listing.images)).toBe(true);
  if (kind === 'edit') { expect(Object.isFrozen(decoded.before)).toBe(true); expect(Object.isFrozen(decoded.after.images)).toBe(true); }
  wire.listing.images[0] = 'https://changed.test/';
  expect(decoded.listing.images).toEqual(['https://images.test/one.png']);
  const mutated = JSON.parse(JSON.stringify(preview)); mutated.listing.description = 'changed';
  await expect(decodeManualPreview(mutated, kind, scope)).rejects.toThrow();
});

test('only exact scoped completed receipt or not_found is accepted for saved operation', () => {
  const reference = { operationId, manualScopeKey: scope, requestSha256: 'c'.repeat(64), productId: 7 };
  const unknown = { origin: 'manual', kind: 'edit', operationId, status: 'not_found', scopeKey: scope };
  expect(decodeManualReceipt(unknown, 'edit', reference)).toEqual(unknown);
  const receipt = { version: 1, operationId, productId: 7, status: 'completed', scopeKey: scope,
    catalogRevision: '4', requestSha256: reference.requestSha256,
    beforeSha256: 'd'.repeat(64), afterSha256: 'e'.repeat(64), receiptSha256: 'f'.repeat(64),
    replayed: true, origin: 'manual', kind: 'edit' };
  expect(decodeManualReceipt(receipt, 'edit', reference)).toEqual(receipt);
  expect(() => decodeManualReceipt({ ...receipt, productId: 8 }, 'edit', reference)).toThrow();
  expect(() => decodeManualReceipt({ ...unknown, requestSha256: reference.requestSha256 }, 'edit', reference)).toThrow();
});
