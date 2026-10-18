import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import MerchantInventoryConfirmation from './MerchantInventoryConfirmation.jsx';
import { attachShopStorage, SHOP_INVENTORY_KEY } from '../utils/shopStorage.mjs';
import { decodeInventoryReference, readInventoryReference } from '../pages/merchant/inventoryReference.mjs';

const { webcrypto, randomUUID } = require('node:crypto');
const sessionId = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const requestId = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const proposalId = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc';
const modeCapability = { version: 1, featureId: 'inventory', policyVersion: 'inventory-v1',
  effectiveMode: 'fixed', scope: { kind: 'launch_feature', id: 'inventory' } };
const chatMode = { version: 1, featureId: 'merchant_assistant', policyVersion: 'merchant-assistant-v1',
  effectiveMode: 'fixed', scope: { kind: 'launch_feature', id: 'merchant_assistant' } };
const proposal = { version: 1, proposalId,
  product: { choiceId: 'dddddddd-dddd-4ddd-8ddd-dddddddddddd', name: 'Practice laptop' },
  stockChange: { productId: 6, quantity: 5 }, message: 'Set its absolute stock to 5',
  scopeKey: 'a'.repeat(64), modeCapability };
const json = value => ({ ok: true, status: 200, json: async () => value });
const complete = () => json({ ok: true, status: 'completed', requestId: proposalId,
  answer: 'Saved stock result', operations: [{ action: 'set_stock',
    result: { productId: 6, before: 3, after: 5, applied: true } }] });

let root, node, release, values, flush;
const render = async (transport, currentProposal = proposal, authorityKey = 'merchant-persona') => act(async () => root.render(
  <MerchantInventoryConfirmation proposal={currentProposal}
    sessionId={currentProposal ? sessionId : null} requestId={currentProposal ? requestId : null}
    authorityKey={authorityKey} transport={transport} />));
const settle = () => act(async () => { await new Promise(resolve => setTimeout(resolve, 0)); });

beforeEach(() => {
  globalThis.IS_REACT_ACT_ENVIRONMENT = true;
  Object.defineProperty(globalThis.crypto, 'subtle', { configurable: true, value: webcrypto.subtle });
  Object.defineProperty(globalThis.crypto, 'randomUUID', { configurable: true, value: randomUUID });
  node = document.createElement('div'); document.body.append(node); root = createRoot(node);
  values = new Map(); flush = async () => {};
  release = attachShopStorage({ getItem: key => values.get(key) ?? null,
    setItem: (key, value) => values.set(key, value), removeItem: key => values.delete(key),
    flush: () => flush() });
});
afterEach(async () => { await act(async () => root.unmount()); release(); node.remove(); });

test('failed initial stock readiness cancels its body and keeps confirmation blocked', async () => {
  const cancel = jest.fn(async () => {});
  const transport = jest.fn(async url => {
    if (url.endsWith('/readiness')) return { ok: false, status: 503, body: { cancel } };
    throw Error(`Unexpected ${url}`);
  });
  await render(transport); await settle();
  expect(cancel).toHaveBeenCalledTimes(1);
  expect(node.textContent).toContain('Inventory readiness unavailable. Confirmation is blocked.');
  expect([...node.querySelectorAll('button')].find(button => button.textContent === 'Confirm stock change')?.disabled).toBe(true);
  expect(transport.mock.calls.some(([url]) => url.endsWith('/inventory/confirm'))).toBe(false);
});

test('failed stock preconfirm readiness cancels its body before reporting no effect', async () => {
  const cancel = jest.fn(async () => {});
  let reads = 0;
  const transport = jest.fn(async url => {
    if (url.endsWith('/readiness')) return ++reads === 1
      ? json({ ready: true, scopeKey: proposal.scopeKey, modeCapability })
      : { ok: false, status: 503, body: { cancel } };
    throw Error(`Unexpected ${url}`);
  });
  await render(transport); await settle();
  await act(async () => { [...node.querySelectorAll('button')]
    .find(button => button.textContent === 'Confirm stock change').click(); });
  await settle();
  expect(cancel).toHaveBeenCalledTimes(1);
  expect(node.textContent).toContain('Inventory readiness unavailable. No stock change was submitted.');
  expect(values.has(SHOP_INVENTORY_KEY)).toBe(false);
  expect(transport.mock.calls.some(([url]) => url.endsWith('/inventory/confirm'))).toBe(false);
});

test('named stock proposal waits for parent ACK and recovers a lost confirm response by exact GET only', async () => {
  let acknowledge, posts = 0, committed = false;
  flush = () => new Promise(resolve => { acknowledge = resolve; });
  const transport = jest.fn(async (url, options = {}) => {
    if (url.endsWith('/readiness')) return json({ ready: true, scopeKey: proposal.scopeKey, modeCapability });
    if (url.includes('/assistant/operations/')) return json({ sessionId, requestId,
      status: 'completed', replayed: true, stopReason: 'end_turn', modeCapability: chatMode,
      inventoryProposal: proposal });
    if (url.endsWith(`/inventory/operations/${proposalId}`)) return committed ? complete()
      : json({ requestId: proposalId, status: 'not_found' });
    if (url.endsWith('/inventory/confirm')) {
      posts++; expect(JSON.parse(options.body)).toEqual({ sessionId, requestId, proposalId });
      committed = true; throw Error('response lost');
    }
    throw Error(`Unexpected ${url}`);
  });
  await render(transport); await settle();
  expect(node.textContent).toContain('Practice laptop · new absolute stock quantity: 5');
  expect(node.textContent).not.toContain('Product #6');
  expect(posts).toBe(0);
  await act(async () => { node.querySelector('button').click(); await Promise.resolve(); });
  await settle();
  expect(posts).toBe(0);
  expect(decodeInventoryReference(values.get(SHOP_INVENTORY_KEY))).toMatchObject({
    version: 3, scopeKey: proposal.scopeKey, requestId: proposalId,
    access: 'write', stockChange: proposal.stockChange,
  });
  flush = async () => {}; // Later removal uses a separate acknowledged write.
  await act(async () => { acknowledge(); await new Promise(resolve => setTimeout(resolve, 0)); });
  expect(posts).toBe(1);
  expect(values.has(SHOP_INVENTORY_KEY)).toBe(false);
  expect(node.textContent).toContain('Stock change confirmed from the saved result.');
});

test('an unresolved saved stock confirmation remains GET-only after its proposal is hidden', async () => {
  let posts = 0, completed = false;
  const transport = jest.fn(async (url) => {
    if (url.endsWith('/readiness')) return json({ ready: true, scopeKey: proposal.scopeKey, modeCapability });
    if (url.includes('/assistant/operations/')) return json({ sessionId, requestId,
      status: 'completed', replayed: true, stopReason: 'end_turn', modeCapability: chatMode,
      inventoryProposal: proposal });
    if (url.endsWith(`/inventory/operations/${proposalId}`)) return completed ? complete()
      : json({ requestId: proposalId, status: posts ? 'uncertain' : 'not_found' });
    if (url.endsWith('/inventory/confirm')) { posts++; return json({ status: 'uncertain' }); }
    throw Error(`Unexpected ${url}`);
  });
  await render(transport); await settle();
  await act(async () => { node.querySelector('button').click(); });
  // WebCrypto completes asynchronously; one timer tick is not a completion signal.
  const deadline = Date.now() + 2000;
  while (posts === 0 && Date.now() < deadline) {
    await act(async () => { await new Promise(resolve => setTimeout(resolve, 10)); });
  }
  expect(posts).toBe(1);
  expect(values.has(SHOP_INVENTORY_KEY)).toBe(true);
  await render(transport, null); await settle();
  expect(node.textContent).not.toContain('Confirm stock change');
  completed = true;
  await act(async () => { [...node.querySelectorAll('button')]
    .find(button => button.textContent === 'Check saved stock change').click(); });
  await settle();
  expect(posts).toBe(1);
  expect(values.has(SHOP_INVENTORY_KEY)).toBe(false);
  expect(node.textContent).toContain('Stock change confirmed from the saved result.');
});

test('a saved stock GET survives later same-authority proposal hydration and keeps its busy lock', async () => {
  const saved = { version: 3, scopeKey: proposal.scopeKey, requestId: proposalId,
    digest: 'd'.repeat(64), access: 'write', stockChange: proposal.stockChange };
  values.set(SHOP_INVENTORY_KEY, JSON.stringify(saved));
  let resolveRead, readSignal;
  const transport = jest.fn((url, options = {}) => {
    if (url.endsWith(`/inventory/operations/${proposalId}`)) {
      readSignal = options.signal;
      return new Promise(resolve => { resolveRead = resolve; });
    }
    if (url.endsWith('/readiness')) return Promise.resolve(json({ ready: true,
      scopeKey: proposal.scopeKey, modeCapability }));
    throw Error(`Unexpected ${url}`);
  });
  await render(transport, null);
  await act(async () => { [...node.querySelectorAll('button')]
    .find(button => button.textContent === 'Check saved stock change').click(); });
  expect(readSignal.aborted).toBe(false);
  await render(transport, proposal); await settle();
  expect(readSignal.aborted).toBe(false);
  expect([...node.querySelectorAll('button')]
    .find(button => button.textContent === 'Check saved stock change').disabled).toBe(true);
  await act(async () => { resolveRead(complete()); await settle(); });
  expect(values.has(SHOP_INVENTORY_KEY)).toBe(false);
  expect(node.textContent).toContain('Stock change confirmed from the saved result.');
  expect(transport.mock.calls.some(([url]) => url.endsWith('/inventory/confirm'))).toBe(false);
});

test('a real authority change aborts a pending saved stock GET without confirming', async () => {
  values.set(SHOP_INVENTORY_KEY, JSON.stringify({ version: 3, scopeKey: proposal.scopeKey,
    requestId: proposalId, digest: 'd'.repeat(64), access: 'write', stockChange: proposal.stockChange }));
  let readSignal;
  const transport = jest.fn((url, options = {}) => {
    if (url.endsWith(`/inventory/operations/${proposalId}`)) {
      readSignal = options.signal;
      return new Promise(() => {});
    }
    throw Error(`Unexpected ${url}`);
  });
  await render(transport, null);
  await act(async () => { node.querySelector('button').click(); });
  await render(transport, null, 'other-merchant-persona');
  expect(readSignal.aborted).toBe(true);
  expect(values.has(SHOP_INVENTORY_KEY)).toBe(true);
  expect(transport.mock.calls.some(([url]) => url.endsWith('/inventory/confirm'))).toBe(false);
});

test('source replacement during stock preflight cancels confirmation before saving or POST', async () => {
  let resolvePreflight, preflightSignal, readinessReads = 0;
  const transport = jest.fn((url, options = {}) => {
    if (url.endsWith('/readiness')) {
      readinessReads += 1;
      if (readinessReads === 1) return Promise.resolve(json({ ready: true,
        scopeKey: proposal.scopeKey, modeCapability }));
      preflightSignal = options.signal;
      return new Promise(resolve => { resolvePreflight = resolve; });
    }
    throw Error(`Unexpected ${url}`);
  });
  await render(transport); await settle();
  await act(async () => { node.querySelector('button').click(); });
  expect(preflightSignal.aborted).toBe(false);
  await render(transport, null);
  expect(preflightSignal.aborted).toBe(true);
  await act(async () => { resolvePreflight(json({ ready: true,
    scopeKey: proposal.scopeKey, modeCapability })); });
  expect(values.has(SHOP_INVENTORY_KEY)).toBe(false);
  expect(transport.mock.calls.some(([url]) => url.endsWith('/inventory/confirm'))).toBe(false);
});

test('a completed saved stock result yields an actionable new proposal under the same authority', async () => {
  values.set(SHOP_INVENTORY_KEY, JSON.stringify({ version: 3, scopeKey: proposal.scopeKey,
    requestId: proposalId, digest: 'd'.repeat(64), access: 'write', stockChange: proposal.stockChange }));
  const nextProposal = { ...proposal, proposalId: 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee',
    product: { ...proposal.product, name: 'Practice tablet' } };
  const transport = jest.fn(async url => {
    if (url.endsWith(`/inventory/operations/${proposalId}`)) return complete();
    if (url.endsWith('/readiness')) return json({ ready: true,
      scopeKey: proposal.scopeKey, modeCapability });
    throw Error(`Unexpected ${url}`);
  });
  await render(transport, null);
  await act(async () => { node.querySelector('button').click(); });
  expect(node.textContent).toContain('Stock change confirmed from the saved result.');
  await render(transport, nextProposal); await settle();
  const next = [...node.querySelectorAll('button')]
    .find(button => button.textContent === 'Confirm stock change');
  expect(next).toBeDefined(); expect(next.disabled).toBe(false);
  expect(node.textContent).toContain('Practice tablet');
  expect(values.has(SHOP_INVENTORY_KEY)).toBe(false);
  expect(transport.mock.calls.some(([url]) => url.endsWith('/inventory/confirm'))).toBe(false);
});

test('changed protected source proposal blocks confirmation before parent save and POST', async () => {
  const transport = jest.fn(async url => {
    if (url.endsWith('/readiness')) return json({ ready: true, scopeKey: proposal.scopeKey, modeCapability });
    if (url.includes('/assistant/operations/')) return json({ sessionId, requestId,
      status: 'completed', replayed: true, stopReason: 'end_turn', modeCapability: chatMode,
      inventoryProposal: { ...proposal, stockChange: { productId: 6, quantity: 7 } } });
    throw Error(`Unexpected ${url}`);
  });
  await render(transport); await settle();
  await act(async () => { node.querySelector('button').click(); }); await settle();
  expect(node.textContent).toContain('Saved stock proposal changed');
  expect(values.has(SHOP_INVENTORY_KEY)).toBe(false);
  expect(transport.mock.calls.some(([url]) => url.endsWith('/inventory/confirm'))).toBe(false);
});

test('protected role GET requires the canonical merchant assistant feature before stock confirmation', async () => {
  const wrongMode = { ...chatMode, featureId: 'merchant_chat',
    scope: { kind: 'launch_feature', id: 'merchant_chat' } };
  const transport = jest.fn(async url => {
    if (url.endsWith('/readiness')) return json({ ready: true, scopeKey: proposal.scopeKey, modeCapability });
    if (url.includes('/assistant/operations/')) return json({ sessionId, requestId,
      status: 'completed', replayed: true, stopReason: 'end_turn', modeCapability: wrongMode,
      inventoryProposal: proposal });
    throw Error(`Unexpected ${url}`);
  });
  await render(transport); await settle();
  await act(async () => { node.querySelector('button').click(); }); await settle();
  expect(node.textContent).toContain('Saved stock proposal changed');
  expect(values.has(SHOP_INVENTORY_KEY)).toBe(false);
  expect(transport.mock.calls.some(([url]) => url.endsWith('/inventory/confirm'))).toBe(false);
});

test('a replaced parent inventory reference after save ACK prevents the sole confirm POST', async () => {
  flush = async () => {
    const saved = JSON.parse(values.get(SHOP_INVENTORY_KEY));
    values.set(SHOP_INVENTORY_KEY, JSON.stringify({ ...saved,
      requestId: 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee' }));
  };
  const transport = jest.fn(async url => {
    if (url.endsWith('/readiness')) return json({ ready: true, scopeKey: proposal.scopeKey, modeCapability });
    if (url.includes('/assistant/operations/')) return json({ sessionId, requestId,
      status: 'completed', replayed: true, stopReason: 'end_turn', modeCapability: chatMode,
      inventoryProposal: proposal });
    if (url.endsWith(`/inventory/operations/${proposalId}`)) return json({ requestId: proposalId,
      status: 'not_found' });
    throw Error(`Unexpected ${url}`);
  });
  await render(transport); await settle();
  await act(async () => { node.querySelector('button').click(); }); await settle();
  expect(node.textContent).toContain('Saved inventory reference changed');
  expect(transport.mock.calls.some(([url]) => url.endsWith('/inventory/confirm'))).toBe(false);
  expect(readInventoryReference().requestId).toBe('eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee');
});

test('completed stock result preserves the exact saved grading retry identity when Judge is unavailable', async () => {
  const evaluationId = 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee';
  let confirmed = false;
  const transport = jest.fn(async url => {
    if (url.endsWith('/readiness')) return json({ ready: true, scopeKey: proposal.scopeKey, modeCapability });
    if (url.includes('/assistant/operations/')) return json({ sessionId, requestId,
      status: 'completed', replayed: true, stopReason: 'end_turn', modeCapability: chatMode,
      inventoryProposal: proposal });
    if (url.endsWith(`/inventory/operations/${proposalId}`)) return confirmed
      ? json({ ok: true, status: 'completed', requestId: proposalId, answer: 'Stock saved',
        operations: [{ action: 'set_stock', result: { applied: true } }],
        grading: { status: 'evaluated', judgment: { verdict: 'unavailable', canRetry: true,
          evaluationId } } }) : json({ requestId: proposalId, status: 'not_found' });
    if (url.endsWith('/inventory/confirm')) { confirmed = true; return json({ status: 'completed' }); }
    throw Error(`Unexpected ${url}`);
  });
  await render(transport); await settle();
  await act(async () => { node.querySelector('button').click(); }); await settle();
  const saved = readInventoryReference();
  expect(saved).toMatchObject({ requestId: proposalId, evaluationId,
    retryRequestId: expect.any(String) });
  expect(saved.retryRequestId).not.toBe(saved.requestId);
  expect(node.textContent).toContain('Grading is unavailable');
  expect(node.textContent).toContain('Check saved stock change');
});
