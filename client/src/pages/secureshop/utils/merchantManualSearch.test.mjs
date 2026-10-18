import { decodeMerchantManualSearch } from './merchantManualSearch.mjs';
const { webcrypto, createHash } = require('node:crypto');
const { validateManualSearchResult } = require('../../../../../server/services/secureshopBoundProductRetrieval.js');

const choiceId = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const mode = { version: 1, featureId: 'merchant_assistant',
  policyVersion: 'owned-merchant-read-and-confirmation-v1', effectiveMode: 'fixed',
  scope: { kind: 'launch_feature', id: 'merchant_assistant' } };
const hash = text => createHash('sha256').update(text).digest('hex');
const source = { sourceKind: 'manual', sourceId: 12, chunkIndex: 0,
  text: '<img src=x onerror=alert(1)> Read battery steps.', score: 0.75,
  sourceSha256: 'a'.repeat(64), filename: 'laptop.pdf',
  operationId: 'cccccccc-cccc-4ccc-8ccc-cccccccccccc', receiptSha256: 'b'.repeat(64),
  documentDigest: 'c'.repeat(64), completedAt: '2026-10-11T12:00:00.000Z',
  textBytes: 0, textSha256: '' };
source.textBytes = new TextEncoder().encode(source.text).byteLength;
source.textSha256 = hash(source.text);
const result = { product: { id: 6, name: 'Practice laptop' }, query: 'How does the battery work?',
  limit: 3, count: 1, hasMore: false,
  revision: { revisionId: 'dddddddd-dddd-4ddd-8ddd-dddddddddddd',
    runtimeFingerprint: 'd'.repeat(64), sourceSetDigest: 'e'.repeat(64) },
  status: 'complete', sources: [source] };
const wrapper = value => ({ version: 1, choiceId, productId: 6,
  modeCapability: mode, result: value });
const hops = value => [{ tool: 'merchant.manual_search', params: { choiceId },
  result: { content: [{ type: 'text', text: JSON.stringify(value) }] } }];
beforeEach(() => Object.defineProperty(globalThis.crypto, 'subtle', { configurable: true, value: webcrypto.subtle }));

test('decodes the actual closed server result and reordered JSONB fields from the protected saved hop', async () => {
  expect(validateManualSearchResult(result)).toEqual(result);
  const reverse = value => Array.isArray(value) ? value.map(reverse)
    : value && typeof value === 'object' ? Object.fromEntries(Object.entries(value).reverse()
      .map(([key, entry]) => [key, reverse(entry)])) : value;
  expect((await decodeMerchantManualSearch(wrapper(reverse(result)), mode,
    hops(result), 'end_turn')).result).toEqual(reverse(result));
});
test('honest empty and oversized metadata results decode without inventing excerpts', async () => {
  const empty = { ...result, count: 0, sources: [] };
  const oversized = { ...result, status: 'oversized', sources: [{ ...source, text: null }] };
  for (const value of [empty, oversized]) {
    expect(validateManualSearchResult(value)).toEqual(value);
    expect((await decodeMerchantManualSearch(wrapper(value), mode, hops(value), 'end_turn')).result)
      .toEqual(value);
  }
});
test('rejects tampered source, foreign product, wrong mode, nonterminal, failed hop and extra fields', async () => {
  const variants = [
    [wrapper({ ...result, sources: [{ ...source, text: source.text + ' changed' }] }), hops(result), mode, 'end_turn'],
    [{ ...wrapper(result), productId: 7 }, hops(result), mode, 'end_turn'],
    [wrapper(result), hops(result), { ...mode, policyVersion: 'wrong' }, 'end_turn'],
    [wrapper(result), hops(result), mode, 'error'],
    [wrapper(result), [{ ...hops(result)[0], error: 'denied' }], mode, 'end_turn'],
    [wrapper({ ...result, extra: true }), hops(result), mode, 'end_turn'],
  ];
  for (const [value, savedHops, savedMode, stop] of variants) {
    await expect(decodeMerchantManualSearch(value, savedMode, savedHops, stop))
      .rejects.toThrow('manual search invalid');
  }
});
