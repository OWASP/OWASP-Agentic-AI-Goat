import { webcrypto } from 'node:crypto';
import { afterEach, beforeEach, expect, test } from '@jest/globals';
import { attachShopStorage } from '../../utils/shopStorage.mjs';
import { clearListingEditReference, decodeListingEditOperation, decodeListingEditProposal,
  decodeListingEditReference, listingEditRequestDigest, readListingEditReference,
  saveListingEditReference } from './listingEditOperation.mjs';

Object.defineProperty(globalThis, 'crypto', { value: webcrypto, configurable: true });
const id = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const scope = 'a'.repeat(64), snapshot = 'b'.repeat(64), request = 'c'.repeat(64);
const before = Object.freeze({ name: 'Practice mug', description: 'old', descriptionHtml: '<p>old</p>',
  price: 12.5, category: 'home', templateSource: null, imageUrl: null });
const patch = Object.freeze({ description: 'new' });
let release;
beforeEach(() => {
  const values = new Map();
  release = attachShopStorage({ getItem: key => values.get(key) ?? null,
    setItem: (key, value) => values.set(key, value), removeItem: key => values.delete(key), flush: async () => {} });
});
afterEach(() => release?.());
async function proposal(overrides = {}) {
  const after = { ...before, ...patch, descriptionHtml: null };
  const preview = { version: 1, productId: 7, before, after, patch, catalogRevision: '4',
    expectedSnapshotSha256: snapshot, scopeKey: scope, invalidatesGeneratedHtml: true };
  preview.requestSha256 = await listingEditRequestDigest(preview);
  return { version: 1, proposalId: id, product: { choiceId: id, name: 'Practice mug' }, preview, ...overrides };
}

test('accepts a closed preview and rejects invalid nullable patch fields', async () => {
  const value = await proposal();
  expect(await decodeListingEditProposal(value)).toEqual(value);
  const badName = JSON.parse(JSON.stringify(value)); badName.preview.patch = { name: null };
  await expect(decodeListingEditProposal(badName)).rejects.toThrow('Saved listing preview');
  const nullable = JSON.parse(JSON.stringify(value)); nullable.preview.patch = { category: null };
  nullable.preview.after = { ...before, category: null }; nullable.preview.invalidatesGeneratedHtml = false;
  nullable.preview.requestSha256 = await listingEditRequestDigest(nullable.preview);
  expect((await decodeListingEditProposal(nullable)).preview.after.category).toBeNull();
});

test('persists only opaque listing-edit identity and restores it if parent removal fails', async () => {
  const reference = { version: 1, scopeKey: scope, operationId: id, productId: 7,
    catalogRevision: '4', requestSha256: request, expectedSnapshotSha256: snapshot };
  await saveListingEditReference(reference);
  expect(readListingEditReference()).toEqual(reference);
  expect(() => decodeListingEditReference(JSON.stringify({ ...reference, before }))).toThrow();
  await clearListingEditReference(reference);
  expect(readListingEditReference()).toBeNull();
});

test('requires the complete saved receipt to bind the stored proposal', () => {
  const reference = { version: 1, scopeKey: scope, operationId: id, productId: 7,
    catalogRevision: '4', requestSha256: request, expectedSnapshotSha256: snapshot };
  expect(decodeListingEditOperation({ operationId: id, status: 'not_found', scopeKey: scope }, reference))
    .toEqual({ status: 'not_found' });
  const receipt = { version: 1, operationId: id, productId: 7, status: 'completed', scopeKey: scope,
    catalogRevision: '4', requestSha256: request, beforeSha256: snapshot, afterSha256: 'd'.repeat(64),
    receiptSha256: 'e'.repeat(64), replayed: false };
  expect(decodeListingEditOperation(receipt, reference)).toEqual(receipt);
  expect(() => decodeListingEditOperation({ ...receipt, catalogRevision: '5' }, reference)).toThrow();
  expect(() => decodeListingEditOperation({ ...receipt, beforeSha256: 'f'.repeat(64) }, reference)).toThrow();
});
