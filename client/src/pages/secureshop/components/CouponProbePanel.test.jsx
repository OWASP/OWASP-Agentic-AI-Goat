import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import { CouponProbePanel, decodeCouponProbeAssessment, decodeCouponProbeOutcome } from './CouponProbePanel.jsx';
import { createCustomerCouponProbeStore } from '../utils/customerCouponProbeReference.mjs';

const sessionId = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const requestId = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const response = body => ({ ok: true, headers: { get: () => 'application/json' }, json: async () => body,
  text: async () => JSON.stringify(body) });
const completed = { status: 'completed', sessionId, requestId, text: 'I checked the coupon request.',
  provider: 'controlled', model: 'controlled', stopReason: 'end_turn', probes: [], replayed: true };
let node, root, values, store;
beforeEach(() => {
  globalThis.IS_REACT_ACT_ENVIRONMENT = true;
  values = new Map(); store = createCustomerCouponProbeStore({ storage: {
    getItem: key => values.get(key) ?? null, setItem: (key, value) => values.set(key, value),
    removeItem: key => values.delete(key),
  } });
  node = document.createElement('div'); document.body.append(node); root = createRoot(node);
});
afterEach(async () => { await act(async () => root.unmount()); node.remove(); });
const render = props => act(async () => root.render(<CouponProbePanel shopUserId={7} authorityKey="owner-a" referenceStore={store} {...props} />));

test('persists opaque IDs before the dedicated run and reads only the saved result', async () => {
  const calls = [];
  const transport = jest.fn(async (url, init = {}) => {
    calls.push([url, init]);
    if (url.endsWith('/session')) return response({ sessionId });
    if (url.endsWith('/run')) return response({ accepted: true });
    if (url.includes('/operations/')) return response(completed);
    throw Error('unexpected request');
  });
  const savedRandom = globalThis.crypto.randomUUID;
  globalThis.crypto.randomUUID = () => requestId;
  try {
    await render({ transport });
    const input = node.querySelector('#coupon-assistant-message');
    const descriptor = Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, 'value');
    await act(async () => { descriptor.set.call(input, 'Check this coupon'); input.dispatchEvent(new Event('input', { bubbles: true })); });
    await act(async () => { node.querySelector('form').dispatchEvent(new Event('submit', { bubbles: true, cancelable: true })); await Promise.resolve(); });
    expect(store.read(7)).toMatchObject({ sessionId, requestId });
    expect(calls.map(([url]) => url)).toEqual(expect.arrayContaining([
      expect.stringContaining('/session'), expect.stringContaining('/run'), expect.stringContaining('/operations/'),
    ]));
    const run = calls.find(([url]) => url.endsWith('/run'))[1];
    expect(JSON.parse(run.body)).toEqual({ sessionId, requestId, message: 'Check this coupon' });
    expect(node.textContent).toContain('I checked the coupon request.');
    expect(node.textContent).not.toContain(sessionId);
  } finally { globalThis.crypto.randomUUID = savedRandom; }
});

test.each(['guided-boolean-v1', 'guided-boolean-v2'])(
  'explicit %s request adds the closed protocol while raw remains the default', async protocol => {
  const calls = [];
  const transport = jest.fn(async (url, init = {}) => {
    calls.push([url, init]);
    if (url.endsWith('/session')) return response({ sessionId });
    if (url.endsWith('/run')) return response({ accepted: true });
    if (url.includes('/operations/')) return response(completed);
    throw Error('unexpected request');
  });
  const savedRandom = globalThis.crypto.randomUUID;
  globalThis.crypto.randomUUID = () => requestId;
  try {
    await render({ transport });
    const select = node.querySelector('#coupon-assistant-request-mode');
    expect(select.value).toBe('raw');
    expect([...select.options].map(option => option.value))
      .toEqual(['raw', 'guided-boolean-v1', 'guided-boolean-v2']);
    await act(async () => { select.value = protocol;
      select.dispatchEvent(new Event('change', { bubbles: true })); });
    const input = node.querySelector('#coupon-assistant-message');
    await act(async () => { Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, 'value')
      .set.call(input, 'Compare two bounded coupon predicates');
      input.dispatchEvent(new Event('input', { bubbles: true })); });
    await act(async () => { node.querySelector('form').dispatchEvent(new Event('submit',
      { bubbles: true, cancelable: true })); });
    const body = JSON.parse(calls.find(([url]) => url.endsWith('/run'))[1].body);
    expect(body).toEqual({ sessionId, requestId, message: 'Compare two bounded coupon predicates',
      protocol });
    expect(store.read(7)).toMatchObject({ sessionId, requestId });
    expect(JSON.stringify(store.read(7))).not.toMatch(/guided|message|predicate/);
  } finally { globalThis.crypto.randomUUID = savedRandom; }
});

test('reload recovery makes only the saved GET and refuses non-terminal output', async () => {
  await store.save({ shopUserId: 7, sessionId, requestId, startedAt: 1 });
  const transport = jest.fn(async () => response({ status: 'unconfirmed', sessionId, requestId }));
  await render({ transport });
  await act(async () => {});
  expect(transport).toHaveBeenCalledTimes(1);
  expect(transport.mock.calls[0][0]).toContain(`/operations/${sessionId}/${requestId}`);
  expect(transport.mock.calls[0][1].method).toBe('GET');
  expect(node.textContent).toContain('Coupon conversation is still being confirmed.');
});

test.each([200, 503])('drains the original %s run body before saved recovery without trusting its content', async status => {
  let finishBody;
  const body = new Promise(resolve => { finishBody = resolve; });
  const consume = jest.fn(() => body);
  const calls = [];
  const transport = jest.fn(async (url, init = {}) => {
    calls.push([url, init]);
    if (url.endsWith('/session')) return response({ sessionId });
    if (url.endsWith('/run')) return { ...response({}), status, ok: status === 200, text: consume };
    if (url.includes('/operations/')) return response(completed);
    throw Error('unexpected request');
  });
  const savedRandom = globalThis.crypto.randomUUID;
  globalThis.crypto.randomUUID = () => requestId;
  try {
    await render({ transport });
    const input = node.querySelector('#coupon-assistant-message');
    await act(async () => {
      Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, 'value').set.call(input, 'Check this coupon');
      input.dispatchEvent(new Event('input', { bubbles: true }));
    });
    await act(async () => { node.querySelector('form').dispatchEvent(new Event('submit', { bubbles: true, cancelable: true })); });
    expect(consume).toHaveBeenCalledTimes(1);
    expect(store.read(7)).toMatchObject({ sessionId, requestId });
    expect(calls.filter(([url]) => url.includes('/operations/'))).toHaveLength(0);
    expect(node.textContent).not.toContain(completed.text);
    // Model the bridge withholding EOF until the caller consumes the body.
    // Even a body claiming completion cannot become the displayed outcome.
    await act(async () => { finishBody('{"status":"completed","text":"Untrusted POST result"}'); });
    expect(calls.filter(([url]) => url.endsWith('/run'))).toHaveLength(1);
    expect(calls.filter(([url]) => url.includes('/operations/'))).toHaveLength(1);
    expect(node.textContent).toContain(completed.text);
    expect(node.textContent).not.toContain('Untrusted POST result');
    expect(JSON.parse(calls.find(([url]) => url.endsWith('/run'))[1].body)).toEqual({ sessionId, requestId, message: 'Check this coupon' });
  } finally { globalThis.crypto.randomUUID = savedRandom; }
});

test.each(['unmount', 'authority change'])('aborts pending body consumption on %s and recovers only through saved GET', async transition => {
  let runSignal, rejected = false;
  const consume = jest.fn(() => new Promise((resolve, reject) => {
    runSignal.addEventListener('abort', () => { rejected = true; reject(new Error('aborted body')); }, { once: true });
  }));
  const transport = jest.fn(async (url, init = {}) => {
    if (url.endsWith('/session')) return response({ sessionId });
    if (url.endsWith('/run')) { runSignal = init.signal; return { ...response({}), text: consume }; }
    if (url.includes('/operations/')) return response(completed);
    throw Error('unexpected request');
  });
  const savedRandom = globalThis.crypto.randomUUID;
  globalThis.crypto.randomUUID = () => requestId;
  try {
    await render({ transport });
    const input = node.querySelector('#coupon-assistant-message');
    await act(async () => {
      Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, 'value').set.call(input, 'Check this coupon');
      input.dispatchEvent(new Event('input', { bubbles: true }));
    });
    await act(async () => { node.querySelector('form').dispatchEvent(new Event('submit', { bubbles: true, cancelable: true })); });
    expect(consume).toHaveBeenCalledTimes(1);
    expect(store.read(7)).toMatchObject({ sessionId, requestId });
    if (transition === 'unmount') {
      await act(async () => root.unmount());
      root = createRoot(node);
      await render({ transport });
    } else await render({ transport, authorityKey: 'owner-b' });
    expect(runSignal.aborted).toBe(true);
    expect(rejected).toBe(true);
    expect(transport.mock.calls.filter(([url]) => url.endsWith('/run'))).toHaveLength(1);
    const reads = transport.mock.calls.filter(([url]) => url.includes('/operations/'));
    expect(reads).toHaveLength(1);
    expect(reads[0][0]).toContain(`/operations/${sessionId}/${requestId}`);
    expect(reads[0][1].signal).not.toBe(runSignal);
    expect(node.textContent).toContain(completed.text);
  } finally { globalThis.crypto.randomUUID = savedRandom; }
});

test('accepts canonical assessment DTOs without exposing probes or evaluator IDs', () => {
  expect(decodeCouponProbeOutcome({ ...completed, probes: [{ code: '', valid: false, discount_percent: 0 }] },
    { sessionId, requestId })).toEqual({ status: 'completed', text: completed.text });
  expect(() => decodeCouponProbeOutcome({ ...completed, probes: Array.from({ length: 9 }, () => ({
    code: '', valid: false, discount_percent: 0,
  })) }, { sessionId, requestId })).toThrow();
  expect(decodeCouponProbeAssessment({ completed: false, status: 'ineligible', modelEvaluated: false }))
    .toEqual({ completed: false, status: 'ineligible', modelEvaluated: false });
  expect(decodeCouponProbeAssessment({ completed: false, judgment: {
    verdict: 'unavailable', evaluationId: sessionId, canRetry: true }, replayed: true }))
    .toMatchObject({ completed: false, replayed: true, judgment: { verdict: 'unavailable' } });
  expect(() => decodeCouponProbeAssessment({ completed: false, judgment: {
    verdict: 'pass', evaluationId: sessionId, canRetry: false, attemptId: requestId }, replayed: true })).toThrow();
});

test('unmount during a fresh session request never saves IDs or starts the model run', async () => {
  let resolveSession;
  const pendingSession = new Promise(resolve => { resolveSession = resolve; });
  const transport = jest.fn((url) => {
    if (url.endsWith('/session')) return pendingSession;
    throw Error(`unexpected request: ${url}`);
  });
  await render({ transport });
  const input = node.querySelector('#coupon-assistant-message');
  const descriptor = Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, 'value');
  await act(async () => { descriptor.set.call(input, 'Check this coupon'); input.dispatchEvent(new Event('input', { bubbles: true })); });
  await act(async () => { node.querySelector('form').dispatchEvent(new Event('submit', { bubbles: true, cancelable: true })); await Promise.resolve(); });
  expect(transport).toHaveBeenCalledWith(expect.stringMatching(/\/session$/), expect.any(Object));
  await act(async () => { root.unmount(); });
  resolveSession(response({ sessionId }));
  await act(async () => { await Promise.resolve(); await Promise.resolve(); });
  expect(store.read(7)).toBeNull();
  expect(transport.mock.calls.some(([url]) => url.endsWith('/run'))).toBe(false);
});

test('saved guided-v2 incomplete outcome is terminal, visible, and cannot be assessed', async () => {
  const incomplete = { ...completed, status: 'incomplete', stopReason: 'incomplete',
    text: '[inference not established: contrasting equality unobserved]' };
  expect(decodeCouponProbeOutcome(incomplete, { sessionId, requestId }))
    .toEqual({ status: 'incomplete', text: incomplete.text });
  expect(() => decodeCouponProbeOutcome({ ...incomplete, stopReason: 'end_turn' },
    { sessionId, requestId })).toThrow();
  await store.save({ shopUserId: 7, sessionId, requestId, startedAt: 1 });
  const transport = jest.fn(async (url, init = {}) => {
    expect(url).toContain(`/operations/${sessionId}/${requestId}`);
    expect(init.method).toBe('GET');
    return response(incomplete);
  });
  await render({ transport });
  await act(async () => {});
  expect(node.textContent).toContain('inference not established');
  expect(node.textContent).not.toContain('still being confirmed');
  expect(node.textContent).not.toContain('Check saved assessment');
  expect(node.textContent).not.toContain('Run saved assessment');
  expect(transport).toHaveBeenCalledTimes(1);
  const button = [...node.querySelectorAll('button')].find(value =>
    value.textContent === 'Start another coupon conversation');
  expect(button).toBeTruthy();
  await act(async () => { button.click(); });
  expect(store.read(7)).toBeNull();
  expect(node.querySelector('form')).not.toBeNull();
});
