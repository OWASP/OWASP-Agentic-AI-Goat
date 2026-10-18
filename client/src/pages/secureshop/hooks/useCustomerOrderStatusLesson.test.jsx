import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import { webcrypto } from 'node:crypto';
import { useCustomerOrderStatusLesson, decodeOrderStatusResult } from './useCustomerOrderStatusLesson.js';
import { createOrderStatusReferenceStore } from '../utils/customerOrderStatusReference.mjs';

const sessionId = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const requestId = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const base = '/api/secureshop/customer/order-status';
const json = value => ({ ok: true, headers: { get: () => 'application/json' }, json: async () => value });
const row = { id: 1, customer_id: 7, total_amount: '12.50', status: 'processing',
  payment_method: 'practice', payment_status: 'paid', shipping_address: 'Synthetic lane', order_date: null };
const completed = { status: 'completed', sessionId, requestId, text: 'Observed order lookup.',
  provider: 'ollama', model: 'llama3.1:8b', stopReason: 'end_turn', replayed: false,
  lookups: [{ order_id: '1', order: row, error: null, sql: 'SELECT * FROM orders WHERE id=$1' }] };

function memoryStore() {
  const items = new Map();
  return createOrderStatusReferenceStore({ storage: {
    getItem: key => items.get(key) ?? null,
    setItem: (key, value) => items.set(key, value),
    removeItem: key => items.delete(key),
  }, flush: async () => {} });
}

let root, node, lesson, originalCrypto;
function Harness(props) { lesson = useCustomerOrderStatusLesson(props); return null; }
async function mount(props) {
  node = document.createElement('div'); document.body.append(node); root = createRoot(node);
  await act(async () => root.render(<Harness {...props} />));
  return { rerender: async next => act(async () => root.render(<Harness {...next} />)) };
}
beforeEach(() => {
  globalThis.IS_REACT_ACT_ENVIRONMENT = true;
  originalCrypto = globalThis.crypto;
  Object.defineProperty(globalThis, 'crypto', { configurable: true,
    value: { ...webcrypto, randomUUID: () => requestId } });
});
afterEach(async () => {
  if (root) await act(async () => root.unmount());
  node?.remove(); root = null; node = null;
  Object.defineProperty(globalThis, 'crypto', { configurable: true, value: originalCrypto });
});

test('saved order request recovers by exact GET after lost response without another model POST', async () => {
  const referenceStore = memoryStore(), calls = [];
  const transport = jest.fn(async (path, options) => {
    calls.push([path, options.method]);
    if (path === `${base}/capabilities`) return json({ ready: true });
    if (path === `${base}/session`) return json({ sessionId });
    if (path === `${base}/run`) throw Error('ack lost');
    if (path === `${base}/operations/${sessionId}/${requestId}`) return json(completed);
    if (path === `${base}/assess/${sessionId}/${requestId}`) return json({ completed: false,
      status: 'unconfirmed', modelEvaluated: false });
    if (path === `${base}/assess`) return json({ completed: true,
      judgment: { evaluationId: 'cccccccc-cccc-4ccc-8ccc-cccccccccccc',
        verdict: 'pass', canRetry: false }, replayed: false });
    throw Error(`unexpected ${path}`);
  });
  const props = { shopUserId: 7, authorityKey: 'token-a', transport, referenceStore };
  const view = await mount(props);
  await act(async () => { expect(await lesson.run('owned order')).toBe(false); });
  expect(lesson.status).toBe('unconfirmed');
  expect(referenceStore.read(7)).toMatchObject({ sessionId, requestId });
  expect(calls.filter(([, method]) => method === 'POST')).toHaveLength(2);
  await view.rerender({ ...props, authorityKey: 'token-b' });
  expect(lesson.status).toBe('completed');
  expect(lesson.result.lookups[0].order.status).toBe('processing');
  expect(calls.filter(([, method]) => method === 'POST')).toHaveLength(2);
  await act(async () => { expect(await lesson.recoverAssessment()).toBe(true); });
  expect(calls.at(-1)).toEqual([`${base}/assess/${sessionId}/${requestId}`, 'GET']);
  expect(lesson.assessment.status).toBe('unconfirmed');
  await act(async () => { expect(await lesson.assess()).toBe(true); });
  expect(calls.at(-1)).toEqual([`${base}/assess`, 'POST']);
  expect(lesson.assessment.completed).toBe(true);
  await act(async () => { expect(await lesson.assess()).toBe(false); });
  expect(calls.filter(([path]) => path === `${base}/assess`)).toHaveLength(1);
});

test('authority rotation aborts a pending order response and does not render stale rows', async () => {
  const referenceStore = memoryStore();
  let resolveRun;
  const transport = jest.fn(async path => {
    if (path === `${base}/capabilities`) return json({ ready: true });
    if (path === `${base}/session`) return json({ sessionId });
    if (path === `${base}/run`) return new Promise(resolve => { resolveRun = resolve; });
    if (path === `${base}/operations/${sessionId}/${requestId}`) return json({ status: 'unconfirmed', sessionId, requestId });
    throw Error(`unexpected ${path}`);
  });
  const props = { shopUserId: 7, authorityKey: 'token-a', transport, referenceStore };
  const view = await mount(props);
  let running;
  await act(async () => { running = lesson.run('owned order'); });
  expect(referenceStore.read(7)).toMatchObject({ sessionId, requestId });
  await view.rerender({ ...props, authorityKey: 'token-b' });
  await act(async () => { resolveRun(json(completed)); await running; });
  expect(lesson.result).toBeNull();
  expect(lesson.status).toBe('unconfirmed');
  expect(transport.mock.calls.filter(([path]) => path === `${base}/run`)).toHaveLength(1);
});

test('non-2xx run body is consumed and saved request recovers only by GET', async () => {
  const referenceStore = memoryStore(), calls = [];
  const read = jest.fn().mockResolvedValueOnce({ done: false,
    value: new TextEncoder().encode('{"error":"Order status unavailable"}') })
    .mockResolvedValueOnce({ done: true });
  const cancel = jest.fn(async () => {}), parse = jest.fn();
  const transport = jest.fn(async (path, options) => {
    calls.push([path, options.method]);
    if (path === `${base}/capabilities`) return json({ ready: true });
    if (path === `${base}/session`) return json({ sessionId });
    if (path === `${base}/run`) return { ok: false,
      body: { getReader: () => ({ read, cancel }) },
      headers: { get: () => 'application/json' }, json: parse };
    if (path === `${base}/operations/${sessionId}/${requestId}`) return json({
      status: 'unconfirmed', sessionId, requestId });
    throw Error(`unexpected ${path}`);
  });
  await mount({ shopUserId: 7, authorityKey: 'token-a', transport, referenceStore });
  await act(async () => { expect(await lesson.run('owned order')).toBe(false); });
  expect(read).toHaveBeenCalledTimes(2);
  expect(cancel).toHaveBeenCalledTimes(1);
  expect(parse).not.toHaveBeenCalled();
  expect(referenceStore.read(7)).toMatchObject({ sessionId, requestId });
  expect(lesson.status).toBe('unconfirmed');
  await act(async () => { expect(await lesson.recover()).toBe(true); });
  expect(calls.at(-1)).toEqual([`${base}/operations/${sessionId}/${requestId}`, 'GET']);
  expect(calls.filter(([, method]) => method === 'POST')).toHaveLength(2);
});

test('oversized non-2xx body is cancelled without parsing or losing saved IDs', async () => {
  const referenceStore = memoryStore();
  const read = jest.fn(async () => ({ done: false, value: new Uint8Array(4097) }));
  const cancel = jest.fn(async () => {}), parse = jest.fn();
  const transport = jest.fn(async path => {
    if (path === `${base}/capabilities`) return json({ ready: true });
    if (path === `${base}/session`) return json({ sessionId });
    if (path === `${base}/run`) return { ok: false,
      body: { getReader: () => ({ read, cancel }) }, json: parse };
    throw Error(`unexpected ${path}`);
  });
  await mount({ shopUserId: 7, authorityKey: 'token-a', transport, referenceStore });
  await act(async () => { expect(await lesson.run('owned order')).toBe(false); });
  expect(read).toHaveBeenCalledTimes(1);
  expect(cancel).toHaveBeenCalledTimes(1);
  expect(parse).not.toHaveBeenCalled();
  expect(referenceStore.read(7)).toMatchObject({ sessionId, requestId });
  expect(lesson.status).toBe('unconfirmed');
});

test('closed result decoder preserves typed order observations and rejects actionable rows', () => {
  const reference = { sessionId, requestId };
  const decoded = decodeOrderStatusResult(completed, reference);
  expect(decoded.lookups[0].order).toEqual(row);
  expect(decoded.lookups[0].sql).toBe('SELECT * FROM orders WHERE id=$1');
  expect(() => decodeOrderStatusResult({ ...completed, lookups: [{ ...completed.lookups[0],
    order: { ...row, choiceId: 'browser-choice' } }] }, reference)).toThrow();
  expect(() => decodeOrderStatusResult({ ...completed, lookups: [{ ...completed.lookups[0],
    error: 'error', order: row }] }, reference)).toThrow();
  expect(() => decodeOrderStatusResult({ ...completed, sessionId: requestId }, reference)).toThrow();
});
