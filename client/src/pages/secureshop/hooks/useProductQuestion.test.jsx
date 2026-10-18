import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import { useProductQuestion } from './useProductQuestion.js';

const cap = { version: 1, featureId: 'product_assist', policyVersion: 'bounded-product-data-and-catalog-neighbors-v1',
  effectiveMode: 'fixed', scope: { kind: 'launch_feature', id: 'product_assist' } };
const sessionId = '11111111-1111-4111-8111-111111111111';
let root, node, api, sequence, previousFetch;
const response = value => ({ ok: true, headers: { get: () => 'application/json; charset=utf-8' }, json: async () => value });
function Probe({ productId = 7, ownerKey = 'owner-a' }) {
  api = useProductQuestion({ productId, ownerKey });
  return <div>{api.turns.map((turn, i) => <p key={i}>{turn.productId}: {turn.reply}</p>)}</div>;
}
beforeEach(() => {
  globalThis.IS_REACT_ACT_ENVIRONMENT = true;
  node = document.createElement('div'); document.body.append(node); root = createRoot(node);
  sequence = 0; previousFetch = global.fetch;
  Object.defineProperty(global.crypto, 'randomUUID', { configurable: true,
    value: () => `00000000-0000-4000-8000-${String(++sequence).padStart(12, '0')}` });
});
afterEach(async () => { await act(async () => root.unmount()); node.remove(); global.fetch = previousFetch; });

test('binds product, request, session, and original trusted mode to each answer', async () => {
  const seen = [];
  global.fetch = jest.fn(async (url, init) => {
    const body = JSON.parse(init.body); seen.push({ url, body });
    return response({ product_id: 7, requestId: body.requestId, sessionId,
      answer: seen.length === 1 ? '<b>First</b>' : 'Second', modeCapability: seen.length === 1 ? cap : { effectiveMode: 'fixed' } });
  });
  await act(async () => root.render(<Probe />));
  await act(async () => { expect(await api.send('Compatibility?')).toBe(true); });
  expect(api.turns[0]).toMatchObject({ productId: 7, reply: '<b>First</b>', modeCapability: cap, status: 'done' });
  await act(async () => { expect(await api.send('And warranty?')).toBe(true); });
  expect(seen.map(row => row.url)).toEqual(['/api/secureshop/products/7/question', '/api/secureshop/products/7/question']);
  expect(seen[0].body).toEqual({ message: 'Compatibility?', requestId: '00000000-0000-4000-8000-000000000001' });
  expect(seen[1].body).toEqual({ message: 'And warranty?', requestId: '00000000-0000-4000-8000-000000000002', sessionId });
  expect(api.turns[1].modeCapability).toBeNull();
});

test('rejects mismatched replies and retires an old owner or product request', async () => {
  let finish;
  global.fetch = jest.fn(() => new Promise(resolve => { finish = resolve; }));
  await act(async () => root.render(<Probe />));
  let pending;
  await act(async () => { pending = api.send('Old owner question'); });
  expect(api.status).toBe('thinking');
  await act(async () => root.render(<Probe productId={8} ownerKey="owner-b" />));
  expect(api.turns).toEqual([]);
  await act(async () => finish(response({ product_id: 7, requestId: '00000000-0000-4000-8000-000000000001', sessionId,
    answer: 'Stale answer', modeCapability: cap })));
  expect(await pending).toBe(false);
  expect(api.turns).toEqual([]);
  global.fetch = jest.fn(async () => response({ product_id: 999, requestId: 'wrong', sessionId, answer: 'Wrong owner' }));
  await act(async () => { expect(await api.send('New question')).toBe(false); });
  expect(api.error).toContain('did not match');
  expect(api.turns[0].reply).toBe('');
});
