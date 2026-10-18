import { compileOperation } from '../bridge/operations.mjs';
import { createBridgeFetch } from '../bridge/fetchAdapter.mjs';
import { createBoundReviewRequests } from './boundReviewRequests.mjs';

Object.assign(global, require('node:stream/web'));
global.MessagePort = require('node:worker_threads').MessagePort;
const web = require('undici');
global.Request = web.Request;
global.Response = web.Response;
global.Headers = web.Headers;

const ids = [
  '10000000-0000-4000-8000-000000000001',
  '10000000-0000-4000-8000-000000000002',
  '10000000-0000-4000-8000-000000000003',
];

test('bound request IDs are stable only for the same kind, identity, and payload', () => {
  const bridge = { request: jest.fn() };
  const fetchImpl = createBridgeFetch({ bridge, origin: 'https://shop.invalid', boundReviews: true });
  let index = 0;
  const requests = createBoundReviewRequests({ fetchImpl, randomUUID: () => ids[index++] });
  const payload = { author_id: 7, body: 'same raw review', rating: 2 };
  expect(requests.bound).toBe(true);
  expect(requests.prepare('submission', payload, 'launch-a:customer-7').submission_id).toBe(ids[0]);
  expect(requests.prepare('submission', payload, 'launch-a:customer-7').submission_id).toBe(ids[0]);
  expect(requests.prepare('submission', { ...payload, body: 'edited review' }, 'launch-a:customer-7').submission_id).toBe(ids[1]);
  expect(requests.prepare('submission', { ...payload, body: 'edited review' }, 'launch-b:customer-7').submission_id).toBe(ids[2]);
});

test('success/invalidation rotates IDs while default-off requests retain legacy bodies', () => {
  const activeFetch = createBridgeFetch({ bridge: { request: jest.fn() },
    origin: 'https://shop.invalid', boundReviews: true });
  let index = 0;
  const active = createBoundReviewRequests({ fetchImpl: activeFetch, randomUUID: () => ids[index++] });
  const first = active.prepare('moderation', { limit: 100 }, 'merchant-9');
  active.complete('moderation');
  expect(active.prepare('moderation', { limit: 100 }, 'merchant-9').request_id).not.toBe(first.request_id);
  active.invalidate();
  expect(active.prepare('moderation', { limit: 100 }, 'merchant-9').request_id).toBe(ids[2]);

  const legacy = createBoundReviewRequests({ fetchImpl: jest.fn(), randomUUID: () => { throw new Error('unused'); } });
  expect(legacy.bound).toBe(false);
  expect(legacy.prepare('submission', { author_id: 1, body: 'legacy', rating: 5 }))
    .toEqual({ author_id: 1, body: 'legacy', rating: 5 });
  expect(legacy.prepare('moderation', { limit: 100 })).toEqual({ limit: 100 });
});

test('configured requests retain their acknowledged bridge fetch after global replacement', async () => {
  const bridge = { request: jest.fn().mockResolvedValue(new Response('{}', {
    status: 200, headers: { 'content-type': 'application/json' },
  })) };
  const bridgeFetch = createBridgeFetch({ bridge, origin: 'https://shop.invalid', boundReviews: true });
  const requests = createBoundReviewRequests({ fetchImpl: bridgeFetch, randomUUID: () => ids[0] });
  const downgrade = jest.fn();
  global.fetch = downgrade;
  await requests.fetch('/api/secureshop/products/7/reviews', {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify(requests.prepare('submission', { author_id: 1, body: 'raw', rating: 5 })),
  });
  expect(downgrade).not.toHaveBeenCalled();
  expect(bridge.request).toHaveBeenCalledWith('catalog.product.reviews.create', {
    params: { id: '7' }, query: {}, body: {
      submission_id: ids[0], author_id: 1, body: 'raw', rating: 5,
    },
  }, expect.any(Object));
});

test('closed operation registry accepts idempotency fields and rejects unknown authority', () => {
  expect(compileOperation('catalog.product.reviews.create', { params: { id: 7 }, body: {
    submission_id: ids[0], author_id: 1, body: 'raw', rating: 5,
  } }).body.submission_id).toBe(ids[0]);
  expect(compileOperation('merchant.reviews.moderateAll', { body: {
    request_id: ids[1], limit: 100,
  } }).body.request_id).toBe(ids[1]);
  expect(compileOperation('catalog.product.reviews.browserAttempt', {
    params: { productId: 7, reviewId: 41 }, body: { request_id: ids[2] },
  })).toMatchObject({ method: 'POST',
    path: '/api/secureshop/products/7/reviews/41/browser-attempt',
    body: { request_id: ids[2] } });
  expect(() => compileOperation('merchant.reviews.moderateAll', { body: {
    request_id: ids[1], limit: 100, launch: 'caller-controlled',
  } })).toThrow(/unknown key/);
});
