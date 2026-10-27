import { compileBridgeOperation } from './compiler.mjs';
import { matchOperationRequest } from './operations.mjs';
import { createBridgeFetch } from './fetchAdapter.mjs';

Object.assign(global, require('node:stream/web'));
global.MessagePort = require('node:worker_threads').MessagePort;
const web = require('undici');
global.Request = web.Request; global.Response = web.Response; global.Headers = web.Headers;

const requestId = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const key = 'b'.repeat(64);

test('closed GET admits only exact canonical receipt source and optional opaque key', () => {
  const path = `/api/secureshop/merchant/reviews/moderation/${requestId}`;
  expect(compileBridgeOperation('merchant.reviews.moderationReceipt', {
    params: { requestId }, query: { limit: '100' },
  })).toEqual({ path: `${path}?limit=100`, method: 'GET', responseKind: 'json' });
  expect(matchOperationRequest({ pathname: path, method: 'GET',
    query: { limit: '95', recoveryScopeKey: key } }).name).toBe('merchant.reviews.moderationReceipt');
  for (const query of [{ limit: '0' }, { limit: '101' }, { limit: '095' },
    { limit: 95 }, { limit: '95', recoveryScopeKey: 'bad' },
    { limit: '95', ownerId: '7' }, {}]) {
    expect(() => compileBridgeOperation('merchant.reviews.moderationReceipt', {
      params: { requestId }, query,
    })).toThrow();
  }
  expect(() => compileBridgeOperation('merchant.reviews.moderationReceipt', {
    params: { requestId: requestId.toUpperCase() }, query: { limit: '100' },
  })).toThrow();
  expect(() => compileBridgeOperation('merchant.reviews.moderationReceipt', {
    params: { requestId }, query: { limit: '100' }, body: {},
  })).toThrow();
});

test('scoped moderation POST preserves legacy body but rejects malformed recovery authority', async () => {
  expect(compileBridgeOperation('merchant.reviews.moderateAll', {
    body: { request_id: requestId, limit: 100 },
  }).body).toEqual({ request_id: requestId, limit: 100 });
  expect(compileBridgeOperation('merchant.reviews.moderateAll', {
    body: { request_id: requestId, limit: 100, recoveryScopeKey: key },
  }).body.recoveryScopeKey).toBe(key);
  for (const body of [{ request_id: requestId, recoveryScopeKey: key },
    { request_id: requestId, limit: 0, recoveryScopeKey: key },
    { request_id: requestId, limit: 100, recoveryScopeKey: 'bad' },
    { request_id: requestId, limit: 100, ownerId: 7 }])
    expect(() => compileBridgeOperation('merchant.reviews.moderateAll', { body })).toThrow();
  const bridge = { request: jest.fn(async () => new Response('{}', { status: 200 })) };
  const fetchImpl = createBridgeFetch({ bridge, origin: 'https://shop.test', boundReviews: true });
  await fetchImpl(`https://shop.test/api/secureshop/merchant/reviews/moderation/${requestId}?limit=100&recoveryScopeKey=${key}`);
  expect(bridge.request).toHaveBeenCalledWith('merchant.reviews.moderationReceipt', {
    params: { requestId }, query: { limit: '100', recoveryScopeKey: key },
  }, expect.any(Object));
});
