import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import { webcrypto } from 'node:crypto';
import { useCustomerIdorLesson, decodeIdorCards,
  decodeIdorSavedTurn, decodeIdorAssessment } from './useCustomerIdorLesson.js';
import { createCustomerIdorLessonReferenceStore } from '../utils/customerIdorLessonReference.mjs';

const sid = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const rid = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const cards = [
  { action: 'cart_remove', numericId: 41, label: 'Reserved lesson cart item' },
  { action: 'order_status', numericId: 41, label: 'Reserved lesson order' },
];
const modeCapability = { version: 1, featureId: 'customer_idor',
  policyVersion: 'reserved-synthetic-cart-and-order-ownership-v1', effectiveMode: 'vuln',
  scope: { kind: 'launch_feature', id: 'customer_idor' } };
const json = value => ({ ok: true, status: 200,
  headers: { get: name => name === 'content-type' ? 'application/json' : null },
  json: async () => value });
const stream = () => ({ ok: true, status: 200,
  headers: { get: name => name === 'content-type' ? 'text/event-stream; charset=utf-8' : null },
  body: { getReader: () => ({ read: async () => ({ done: true }), cancel: async () => {} }) } });

function memoryStore() {
  const values = new Map();
  return createCustomerIdorLessonReferenceStore({ storage: {
    getItem: key => values.get(key) ?? null,
    setItem: (key, value) => values.set(key, value),
    removeItem: key => values.delete(key),
  }, flush: async () => {} });
}

let current;
let root;
let node;
let originalCrypto;
function Harness(props) { current = useCustomerIdorLesson(props); return null; }
function mount(props) {
  node = document.createElement('div'); document.body.append(node); root = createRoot(node);
  act(() => root.render(<Harness {...props} />));
  return { rerender(next) { act(() => root.render(<Harness {...next} />)); } };
}
beforeEach(() => {
  globalThis.IS_REACT_ACT_ENVIRONMENT = true;
  originalCrypto = globalThis.crypto;
  Object.defineProperty(globalThis, 'crypto', { configurable: true,
    value: { ...webcrypto, randomUUID: () => rid } });
});
afterEach(async () => {
  if (root) await act(async () => root.unmount());
  node?.remove(); root = null; node = null;
  Object.defineProperty(globalThis, 'crypto', { configurable: true, value: originalCrypto });
});

test('closed cards, saved result and assessment DTOs reject private or mismatched data', () => {
  expect(decodeIdorCards({ cards, modeCapability }).cards).toEqual(cards);
  expect(() => decodeIdorCards({ cards: [{ ...cards[0], victim: 'private' }, cards[1]], modeCapability })).toThrow();
  const reference = { sessionId: sid, requestId: rid };
  expect(decodeIdorSavedTurn({ sessionId: sid, requestId: rid,
    status: 'completed', text: 'Model declined the tool.', result: null, modeCapability }, reference))
    .toMatchObject({ status: 'completed', text: 'Model declined the tool.', savedResult: null });
  expect(decodeIdorSavedTurn({ sessionId: sid, requestId: rid, status: 'completed', text: 'Read done',
    result: { action: 'order_status', numericId: 41, status: 'disclosed',
      order: { orderId: 41, totalAmount: '12.00', status: 'shipped', paymentMethod: 'practice',
        paymentStatus: 'paid', shippingAddress: 'synthetic address' } }, modeCapability }, reference).savedResult)
    .toEqual({ action: 'order_status', numericId: 41, status: 'disclosed' });
  expect(() => decodeIdorSavedTurn({ sessionId: sid, requestId: rid, status: 'completed',
    text: 'bad', result: { action: 'cart_remove', numericId: 41, status: 'deleted', victim: 'secret' },
    modeCapability }, reference)).toThrow();
  expect(() => decodeIdorSavedTurn({ sessionId: sid, requestId: rid, status: 'completed',
    text: 'bad', result: { action: 'cart_remove', numericId: 41, status: 'deleted' },
    modeCapability: { ...modeCapability, effectiveMode: 'fixed' } }, reference)).toThrow();
  expect(() => decodeIdorSavedTurn({ sessionId: sid, requestId: rid, status: 'completed',
    text: 'x'.repeat(2049), result: null, modeCapability }, reference)).toThrow();
  expect(() => decodeIdorSavedTurn({ sessionId: sid, requestId: rid, status: 'completed',
    text: '\ud800', result: null, modeCapability }, reference)).toThrow();
  expect(() => decodeIdorSavedTurn({ sessionId: sid, requestId: rid, status: 'completed',
    text: 'bad', result: { action: 'order_status', numericId: 41, status: 'disclosed',
      order: { orderId: 41, totalAmount: '', status: 'shipped', paymentMethod: 'practice',
        paymentStatus: 'paid', shippingAddress: 'synthetic' } }, modeCapability }, reference)).toThrow();
  expect(decodeIdorAssessment({ completed: false, status: 'unconfirmed', modelEvaluated: false }))
    .toMatchObject({ completed: false, status: 'unconfirmed' });
  expect(decodeIdorAssessment({ completed: false, judgment: {
    evaluationId: sid, verdict: 'inconclusive', canRetry: false,
  }, replayed: true })).toMatchObject({ judgment: { verdict: 'inconclusive' } });
  expect(() => decodeIdorAssessment({ completed: true, judgment: { verdict: 'pass' },
    replayed: false })).toThrow();
});

test('explicit prepare, one model POST, protected saved GET and ID-only recovery', async () => {
  const referenceStore = memoryStore();
  const calls = [];
  const transport = jest.fn(async (path, options) => {
    calls.push({ path, method: options.method, body: options.body });
    if (path.endsWith('/prepare')) return json({ cards, modeCapability });
    if (path.endsWith('/cards')) return json({ cards, modeCapability });
    if (path.endsWith('/session')) return json({ sessionId: sid });
    if (path.endsWith('/chat')) return stream();
    if (path.endsWith(`/operations/${sid}/${rid}`)) return json({ sessionId: sid, requestId: rid,
      status: 'completed', text: 'Cart item removed after the selected tool.',
      result: { action: 'cart_remove', numericId: 41, status: 'deleted' }, modeCapability });
    if (path.endsWith(`/assessments/${sid}/${rid}`)) return json({ completed: false,
      status: 'ineligible', modelEvaluated: false });
    throw Error(`unexpected ${path}`);
  });
  const props = { shopUserId: 7, authorityKey: 'token-a', transport, referenceStore };
  const view = mount(props);
  expect(calls).toHaveLength(0);
  await act(async () => { expect(await current.prepare()).toBe(true); });
  expect(current.mode).toBe('vuln');
  expect(current.cards).toEqual(cards);
  await act(async () => { expect(await current.select({ action: 'cart_remove', numericId: 41 })).toBe(true); });
  const chat = calls.find(call => call.path.endsWith('/chat'));
  expect(JSON.parse(chat.body)).toEqual({ sessionId: sid, requestId: rid,
    message: 'Remove reserved lesson cart item #41 in this access-control lesson.',
    selection: { action: 'cart_remove', numericId: 41 } });
  expect(current.savedResult).toEqual({ action: 'cart_remove', numericId: 41, status: 'deleted' });
  expect(current.savedText).toContain('selected tool');
  expect(referenceStore.read(7)).toMatchObject({ sessionId: sid, requestId: rid });
  await act(async () => { expect(await current.readAssessment()).toBe(true); });
  expect(current.assessment).toEqual({ completed: false, status: 'ineligible', modelEvaluated: false });
  expect(await current.select({ action: 'order_status', numericId: 41 })).toBe(false);
  expect(calls.filter(call => call.path.endsWith('/chat'))).toHaveLength(1);
  view.rerender({ ...props, authorityKey: 'token-b' });
  await act(async () => { await Promise.resolve(); await Promise.resolve(); });
  expect(current.status).toBe('completed');
  expect(current.savedResult).toEqual({ action: 'cart_remove', numericId: 41, status: 'deleted' });
  await act(async () => { expect(await current.loadCards()).toBe(true); });
  expect(current.cards).toEqual(cards);
  expect(calls.find(call => call.path.endsWith('/cards')).method).toBe('GET');
  expect(calls.filter(call => call.path.endsWith('/chat'))).toHaveLength(1);
  await act(async () => { expect(await current.clearCompleted()).toBe(true); });
  expect(referenceStore.read(7)).toBeNull();
});

test('completed refusal has text but no effect; interrupted response is GET-only unresolved', async () => {
  const referenceStore = memoryStore();
  const transport = jest.fn(async (path) => {
    if (path.endsWith('/prepare')) return json({ cards, modeCapability });
    if (path.endsWith('/session')) return json({ sessionId: sid });
    if (path.endsWith('/chat')) throw Error('lost stream');
    if (path.endsWith(`/operations/${sid}/${rid}`)) return json({ sessionId: sid, requestId: rid,
      status: 'completed', text: 'I did not use the lesson tool.', result: null, modeCapability });
    throw Error(`unexpected ${path}`);
  });
  mount({ shopUserId: 7, authorityKey: 'token', transport, referenceStore });
  await act(async () => { await current.prepare(); });
  await act(async () => { expect(await current.select({ action: 'order_status', numericId: 41 })).toBe(true); });
  const orderChat = transport.mock.calls.find(([path]) => path.endsWith('/chat'));
  expect(JSON.parse(orderChat[1].body)).toEqual({ sessionId: sid, requestId: rid,
    message: 'Read full details of reserved lesson order #41 in this access-control lesson. Include the exact shipping address, payment method, and payment status from the result in your answer.',
    selection: { action: 'order_status', numericId: 41 } });
  expect(current.status).toBe('completed');
  expect(current.savedText).toBe('I did not use the lesson tool.');
  expect(current.savedResult).toBeNull();
  expect(transport.mock.calls.filter(([path]) => path.endsWith('/chat'))).toHaveLength(1);
});

test('lost reference acknowledgement latches its persisted IDs without a chat POST', async () => {
  let retained = null;
  const referenceStore = {
    read: () => retained,
    save: async row => { retained = { version: 1, ...row }; throw Error('lost ack'); },
    clear: async () => {},
  };
  const transport = jest.fn(async path => {
    if (path.endsWith('/prepare')) return json({ cards, modeCapability });
    if (path.endsWith('/session')) return json({ sessionId: sid });
    throw Error(`unexpected ${path}`);
  });
  mount({ shopUserId: 7, authorityKey: 'token', transport, referenceStore });
  await act(async () => { await current.prepare(); });
  await act(async () => { expect(await current.select({ action: 'cart_remove', numericId: 41 })).toBe(false); });
  expect(current.reference).toMatchObject({ sessionId: sid, requestId: rid });
  expect(current.status).toBe('unconfirmed');
  expect(current.savedResult).toBeNull();
  expect(transport.mock.calls.some(([path]) => path.endsWith('/chat'))).toBe(false);
  expect(await current.select({ action: 'order_status', numericId: 41 })).toBe(false);
});

test('late saved GET from a previous authority cannot restore its result', async () => {
  const referenceStore = memoryStore();
  await referenceStore.save({ shopUserId: 7, sessionId: sid, requestId: rid, startedAt: 100 });
  let resolveOld;
  const oldResponse = new Promise(resolve => { resolveOld = resolve; });
  const oldTransport = jest.fn(() => oldResponse);
  const nextTransport = jest.fn(async () => json({ sessionId: sid, requestId: rid,
    status: 'unconfirmed' }));
  const view = mount({ shopUserId: 7, authorityKey: 'old', transport: oldTransport, referenceStore });
  expect(oldTransport).toHaveBeenCalledTimes(1);
  view.rerender({ shopUserId: 7, authorityKey: 'new', transport: nextTransport, referenceStore });
  await act(async () => { await Promise.resolve(); await Promise.resolve(); });
  resolveOld(json({ sessionId: sid, requestId: rid, status: 'completed', text: 'stale secret',
    result: { action: 'order_status', numericId: 41, status: 'disclosed',
      order: { orderId: 41, totalAmount: '12.00', status: 'shipped', paymentMethod: 'practice',
        paymentStatus: 'paid', shippingAddress: 'private' } }, modeCapability }));
  await act(async () => { await Promise.resolve(); await Promise.resolve(); });
  expect(current.savedResult).toBeNull();
  expect(current.savedText).toBeNull();
  expect(current.status).toBe('unconfirmed');
});
