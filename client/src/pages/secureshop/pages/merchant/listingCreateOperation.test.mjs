import { webcrypto } from 'node:crypto';
const { listingCreateRequestDigest: serverListingCreateRequestDigest, listingCreateSourceDigest: serverListingCreateSourceDigest } = require('../../../../../../server/services/secureshopListingCreateContract.js');
import { afterEach, beforeEach, expect, test } from '@jest/globals';
import { attachShopStorage } from '../../utils/shopStorage.mjs';
import { clearListingCreateReference, decodeListingCreateOperation, decodeListingCreateProposal,
  decodeListingCreateReference, listingCreateRequestDigest, listingCreateSourceDigest, readListingCreateReference, saveListingCreateReference } from './listingCreateOperation.mjs';

const id = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const scope = 'a'.repeat(64), request = 'b'.repeat(64);
let release;
beforeEach(() => { Object.defineProperty(globalThis, 'crypto', { value: webcrypto, configurable: true });
  const values = new Map();
  release = attachShopStorage({ getItem: key => values.get(key) ?? null,
    setItem: (key, value) => values.set(key, value), removeItem: key => values.delete(key), flush: async () => {} });
});
afterEach(() => release?.());
const proposal = async () => { const preview = { version: 1,
  listing: { name: 'Practice mug', description: null, category: null, price: 12.5 }, currency: 'USD',
  initialStock: 0, status: 'active', scopeKey: scope }; preview.requestSha256 = await listingCreateRequestDigest(preview);
  return { version: 1, proposalId: id, preview }; };
const reference = () => ({ version: 1, scopeKey: scope, operationId: id, requestSha256: request });
const htmlSource = () => ({ version: 1, kind: 'merchant_authored_html',
  listing: { name: 'Rendered mug', description: '<img src="x" onerror="alert(1)">', category: 'home', price: 12.5, presentation: 'html' },
  authoredHtml: '<img src="x" onerror="alert(1)">',
  storedHtml: '&lt;img src=&quot;x&quot; onerror=&quot;alert(1)&quot;&gt;',
  preparation: { sessionId: id, requestId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', step: 1, callId: 'listing-create-v2',
    message: 'Create this product with <img src="x" onerror="alert(1)">.' },
  execution: { version: 1, featureId: 'listings', policyVersion: 'owned-listing-import-v1', mode: 'fixed', generation: 3,
    modeStamp: 'mode-3', scope: { launchId: '11111111-1111-4111-8111-111111111111', scenarioId: '22222222-2222-4222-8222-222222222222', generation: 3, platformOwnerId: 11, platformSessionId: 12 } } });
const htmlProposal = async () => { const source = htmlSource(); const preview = { version: 2, listing: source.listing, currency: 'USD',
  initialStock: 0, status: 'active', scopeKey: scope, source }; preview.requestSha256 = await listingCreateRequestDigest(preview);
  return { version: 1, proposalId: id, preview }; };

test('accepts the closed human-readable create draft and optional empty fields', async () => {
  const value = await proposal();
  expect(await decodeListingCreateProposal(value)).toEqual(value);
  expect(value.preview.requestSha256).toBe(serverListingCreateRequestDigest(value.preview));
  const bad = JSON.parse(JSON.stringify(value)); bad.preview.listing.name = null;
  await expect(decodeListingCreateProposal(bad)).rejects.toThrow('Saved listing draft');
  const extra = JSON.parse(JSON.stringify(value)); extra.preview.listing.imageUrl = 'not allowed';
  await expect(decodeListingCreateProposal(extra)).rejects.toThrow('Saved listing draft');
  const reordered = JSON.parse(JSON.stringify(value)); reordered.preview.listing = { price: 12.5, category: null, description: null, name: 'Practice mug' };
  expect(await decodeListingCreateProposal(reordered)).toEqual(value);
  const altered = JSON.parse(JSON.stringify(value)); altered.preview.requestSha256 = 'e'.repeat(64);
  await expect(decodeListingCreateProposal(altered)).rejects.toThrow('Saved listing draft');
});

test('persists only the opaque create identity and clears it after an acknowledged result', async () => {
  await saveListingCreateReference(reference());
  expect(readListingCreateReference()).toEqual(reference());
  expect(() => decodeListingCreateReference(JSON.stringify({ ...reference(), name: 'Practice mug' }))).toThrow();
  await clearListingCreateReference(reference());
  expect(readListingCreateReference()).toBeNull();
});

test('requires the complete saved receipt and retains typed absence as uncertainty', async () => {
  await expect(decodeListingCreateOperation({ operationId: id, status: 'not_found', scopeKey: scope }, reference()))
    .resolves.toEqual({ status: 'not_found' });
  const receipt = { version: 1, operationId: id, status: 'completed', productId: 7, scopeKey: scope,
    requestSha256: request, sourceSha256: 'c'.repeat(64), receiptSha256: 'd'.repeat(64), replayed: false };
  await expect(decodeListingCreateOperation(receipt, reference())).resolves.toEqual(receipt);
  await expect(decodeListingCreateOperation({ ...receipt, requestSha256: 'e'.repeat(64) }, reference())).rejects.toThrow();
});


test('accepts only the closed v2 authored-HTML preview with an exact source digest', async () => {
  const value = await htmlProposal(), source = value.preview.source;
  expect(await decodeListingCreateProposal(value)).toEqual(value);
  expect(value.preview.requestSha256).toBe(serverListingCreateRequestDigest(value.preview));
  expect(await listingCreateSourceDigest(source)).toBe(serverListingCreateSourceDigest(source));
  const wrongStored = JSON.parse(JSON.stringify(value)); wrongStored.preview.source.storedHtml = wrongStored.preview.source.authoredHtml;
  await expect(decodeListingCreateProposal(wrongStored)).rejects.toThrow('Saved listing draft');
  const extra = JSON.parse(JSON.stringify(value)); extra.preview.source.execution.extra = true;
  await expect(decodeListingCreateProposal(extra)).rejects.toThrow('Saved listing draft');
});

test('requires a v2 receipt to bind the complete source and its request digest', async () => {
  const proposalValue = await htmlProposal(), source = proposalValue.preview.source;
  const saved = { version: 1, scopeKey: scope, operationId: id, requestSha256: proposalValue.preview.requestSha256 };
  const receipt = { version: 2, operationId: id, status: 'completed', productId: 7, scopeKey: scope,
    requestSha256: proposalValue.preview.requestSha256, sourceSha256: 'c'.repeat(64), receiptSha256: 'd'.repeat(64), replayed: false,
    source, sourceDocumentSha256: await listingCreateSourceDigest(source) };
  await expect(decodeListingCreateOperation(receipt, saved)).resolves.toEqual(receipt);
  await expect(decodeListingCreateOperation({ ...receipt, sourceDocumentSha256: 'e'.repeat(64) }, saved)).rejects.toThrow('Saved listing create receipt');
});
