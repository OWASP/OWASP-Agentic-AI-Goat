import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import { webcrypto } from 'node:crypto';
import { useCustomerCouponConfirmation, decodeSavedCustomerCoupon,
  decodeSavedCouponAssessment } from './useCustomerCouponConfirmation.js';
import { createCustomerCouponConfirmationStore } from '../utils/customerCouponConfirmationReference.mjs';

const sessionId = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const requestId = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const proposalId = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc';
let proposal, current, root, node, oldCrypto;
const json = value => ({ ok: true, headers: { get: () => 'application/json' }, json: async () => value });
const store = () => {
  const values = new Map();
  return createCustomerCouponConfirmationStore({ storage: {
    getItem: key => values.get(key) ?? null, setItem: (key, value) => values.set(key, value),
    removeItem: key => values.delete(key),
  }, flush: async () => {} });
};
function Harness(props) { current = useCustomerCouponConfirmation(props); return null; }
const mount = props => { node = document.createElement('div'); document.body.append(node); root = createRoot(node);
  act(() => root.render(<Harness {...props} />));
  return { rerender(next) { act(() => root.render(<Harness {...next} />)); } }; };

beforeEach(async () => {
  globalThis.IS_REACT_ACT_ENVIRONMENT = true;
  oldCrypto = globalThis.crypto;
  Object.defineProperty(globalThis, 'crypto', { configurable: true, value: webcrypto });
  const digest = [...new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode('LESSON10')))]
    .map(byte => byte.toString(16).padStart(2, '0')).join('');
  proposal = { version: 1, kind: 'cart.coupon_prepare', status: 'confirmation_required',
    proposalId, code: 'LESSON10', codeSha256: digest };
});
afterEach(async () => { if (root) await act(async () => root.unmount()); node?.remove();
  root = null; node = null;
  Object.defineProperty(globalThis, 'crypto', { configurable: true, value: oldCrypto }); });

test('single IDs-only confirmation survives lost POST response and uses exact saved GET', async () => {
  const referenceStore = store();
  const calls = [];
  const transport = jest.fn(async (path, options) => {
    calls.push({ path, method: options.method, body: options.body });
    if (path.endsWith(`/operations/${sessionId}/${requestId}`)) return json({ sessionId, requestId,
      status: 'completed', replayed: true, stopReason: 'end_turn', couponProposal: proposal });
    if (path.endsWith('/coupons/confirm') && options.method === 'POST') throw Error('lost response');
    if (path.endsWith(`/coupons/confirm/${sessionId}/${requestId}/${proposalId}`)) return json({
      status: 'completed', result: { ok: true, code: 'LESSON10', discount_percent: 10,
        subtotal: 100, applied_amount: 10 },
    });
    throw Error(`unexpected ${path}`);
  });
  const props = { shopUserId: 7, authorityKey: 'token-a', transport, referenceStore,
    sourceSessionId: sessionId, sourceRequestId: requestId, proposal };
  const view = mount(props);
  await act(async () => { expect(await current.confirm()).toBe(true); });
  expect(calls.filter(call => call.method === 'POST')).toEqual([{
    path: '/api/secureshop/agents/customer/coupons/confirm', method: 'POST',
    body: JSON.stringify({ sessionId, requestId, proposalId }),
  }]);
  expect(current.result?.ok).toBe(true);
  expect(referenceStore.read(7)).toMatchObject({ sessionId, requestId, proposalId });
  view.rerender({ ...props, authorityKey: 'token-b', proposal: null });
  await act(async () => { await Promise.resolve(); await Promise.resolve(); });
  expect(current.status).toBe('completed');
  expect(calls.filter(call => call.method === 'POST')).toHaveLength(1);
  await act(async () => { expect(await current.clearCompleted()).toBe(true); });
  expect(referenceStore.read(7)).toBeNull();
});

test('changed protected original or digest blocks confirmation before POST', async () => {
  const referenceStore = store();
  const transport = jest.fn(async path => {
    if (path.endsWith(`/operations/${sessionId}/${requestId}`)) return json({ sessionId, requestId,
      status: 'completed', replayed: true, stopReason: 'end_turn', couponProposal: {
        ...proposal, code: 'CHANGED',
      } });
    throw Error('unexpected POST');
  });
  mount({ shopUserId: 7, authorityKey: 'token', transport, referenceStore,
    sourceSessionId: sessionId, sourceRequestId: requestId, proposal });
  await act(async () => { expect(await current.confirm()).toBe(false); });
  expect(transport.mock.calls).toHaveLength(1);
  expect(referenceStore.read(7)).toBeNull();
});

test('unconfirmed saved GET leaves reference and never retries the mutation', async () => {
  const referenceStore = store();
  await referenceStore.save({ shopUserId: 7, sessionId, requestId, proposalId, startedAt: 1234 });
  const transport = jest.fn(async () => json({ status: 'unconfirmed' }));
  mount({ shopUserId: 7, authorityKey: 'token', transport, referenceStore,
    sourceSessionId: null, sourceRequestId: null, proposal: null });
  await act(async () => { await Promise.resolve(); await Promise.resolve(); });
  expect(current.reference).toMatchObject({ sessionId, requestId, proposalId });
  expect(current.status).toBe('unconfirmed');
  await act(async () => { expect(await current.check()).toBe(true); });
  expect(transport.mock.calls.every(([path, options]) => options.method === 'GET'
    && path.endsWith(`/coupons/confirm/${sessionId}/${requestId}/${proposalId}`))).toBe(true);
  expect(await current.confirm()).toBe(false);
});

test('saved result decoder rejects optimistic and oversized outcomes', () => {
  expect(decodeSavedCustomerCoupon({ status: 'unconfirmed' })).toEqual({ status: 'unconfirmed', result: null });
  expect(() => decodeSavedCustomerCoupon({ status: 'completed', result: { ok: true } })).toThrow();
  expect(() => decodeSavedCustomerCoupon({ status: 'completed', result: { ok: false,
    error: 'coupon not found', credit: true } })).toThrow();
});

test('canonical assessment reads are separate from the coupon effect and pending retry sends IDs only', async () => {
  const referenceStore = store();
  await referenceStore.save({ shopUserId: 7, sessionId, requestId, proposalId, startedAt: 1234 });
  const assessmentPath = `/api/secureshop/agents/customer/coupons/assessment/${sessionId}/${requestId}/${proposalId}`;
  const retryPath = '/api/secureshop/agents/customer/coupons/assessment-retry';
  let reads = 0;
  const transport = jest.fn(async (path, options) => {
    if (path.endsWith(`/coupons/confirm/${sessionId}/${requestId}/${proposalId}`))
      return json({ status: 'completed', result: { ok: false, error: 'coupon not found' } });
    if (path === assessmentPath) return json(++reads === 1
      ? { completed: false, status: 'unconfirmed', modelEvaluated: false }
      : { completed: false, status: 'ineligible', modelEvaluated: false });
    if (path === retryPath) {
      expect(options.method).toBe('POST');
      expect(JSON.parse(options.body)).toEqual({ sessionId, requestId, proposalId });
      return json({ completed: false, status: 'ineligible', modelEvaluated: false });
    }
    throw Error(`unexpected ${path}`);
  });
  mount({ shopUserId: 7, authorityKey: 'token', transport, referenceStore,
    sourceSessionId: null, sourceRequestId: null, proposal: null });
  await act(async () => { await Promise.resolve(); await Promise.resolve(); });
  expect(current.status).toBe('completed');
  await act(async () => { expect(await current.readAssessment()).toBe(true); });
  expect(current.assessment?.status).toBe('unconfirmed');
  await act(async () => { expect(await current.retryAssessment()).toBe(true); });
  expect(current.assessment?.status).toBe('ineligible');
  expect(await current.retryAssessment()).toBe(false);
  expect(transport.mock.calls.filter(([, options]) => options.method === 'POST')).toHaveLength(1);
  expect(transport.mock.calls.some(([path]) => path.endsWith('/coupons/confirm'))).toBe(false);
});

test('assessment decoder requires a closed canonical judgment and never infers credit from coupon result', () => {
  const evaluationId = 'dddddddd-dddd-4ddd-8ddd-dddddddddddd';
  const unavailable = { completed: false, judgment: { verdict: 'unavailable',
    evaluationId, canRetry: true }, replayed: true };
  expect(decodeSavedCouponAssessment(unavailable)).toEqual(unavailable);
  expect(() => decodeSavedCouponAssessment({ ...unavailable,
    judgment: { ...unavailable.judgment, credit: true } })).toThrow();
  expect(() => decodeSavedCouponAssessment({ completed: true,
    status: 'unconfirmed', modelEvaluated: false })).toThrow();
});
