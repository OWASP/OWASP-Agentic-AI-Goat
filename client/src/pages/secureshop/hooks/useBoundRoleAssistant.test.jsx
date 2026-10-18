import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import { useBoundRoleAssistant } from './useBoundRoleAssistant.js';
import { readRoleAssistantReference, saveRoleAssistantReference,
  clearRoleAssistantReference } from '../utils/roleAssistantReferences.mjs';
import { readRoleAssistantCompletedReference, saveRoleAssistantCompletedReference,
  clearRoleAssistantCompletedReference } from '../utils/roleAssistantCompletedReferences.mjs';
const { webcrypto, createHash } = require('node:crypto');
const { createRoleUserAdministrationProposal, projectRoleUserAdministrationProposal } =
  require('../../../../../server/services/secureshopRoleUserAdministrationProposal.js');
const { createRolePolicyProposal, projectRolePolicyProposal, policySupportedTargets } =
  require('../../../../../server/services/secureshopRolePolicyProposal.js');
const { registryServerSnapshotDigest } =
  require('../../../../../server/services/secureshopRoleMcpRegistryProposal.js');
const { createRoleSystemRestartProposal, projectRoleSystemRestartProposal } =
  require('../../../../../server/services/secureshopRoleSystemRestartProposal.js');
const { CAPABILITY: RESTART_CAPABILITY } =
  require('../../../../../server/services/secureshopSystemRestartClient.js');
const auditJobContract = require('../../../../../server/services/secureshopRoleAuditJobProposal.js');
const aclContract = require('../../../../../server/services/secureshopRoleAclProposal.js');

jest.mock('../utils/roleAssistantReferences.mjs', () => ({
  readRoleAssistantReference: jest.fn(), saveRoleAssistantReference: jest.fn(),
  clearRoleAssistantReference: jest.fn(),
}));
jest.mock('../utils/roleAssistantCompletedReferences.mjs', () => ({
  readRoleAssistantCompletedReference: jest.fn(), saveRoleAssistantCompletedReference: jest.fn(),
  clearRoleAssistantCompletedReference: jest.fn(),
  sameRoleAssistantReference: (left, right) => !!left && !!right
    && ['role', 'shopUserId', 'sessionId', 'requestId', 'startedAt']
      .every(key => left[key] === right[key]),
}));

const sid = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const choiceId = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const mode = { version: 1, featureId: 'merchant_assistant', effectiveMode: 'vuln',
  policyVersion: '1', scope: { kind: 'launch_feature', id: 'merchant_assistant' } };
const productCard = { version: 1, kind: 'merchant_product', choiceId,
  title: 'Practice laptop', detail: 'Active catalog product' };
const orderChoiceId = 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee';
const orderCard = { version: 1, kind: 'merchant_order', choiceId: orderChoiceId,
  title: 'Order #41 · Practice laptop', detail: 'paid · 2026-10-10 · Your items: USD 18.00' };
const reviewChoiceId = 'ffffffff-ffff-4fff-8fff-ffffffffffff';
const reviewCard = { version: 1, kind: 'merchant_review', choiceId: reviewChoiceId,
  title: 'Review · Practice laptop · 2 stars', detail: 'pending · Customer review' };
const reviewMode = { version: 1, featureId: 'review', policyVersion: 'product-feedback-enforced-decision-v1', effectiveMode: 'fixed',
  scope: { kind: 'launch_feature', id: 'review' } };
const reviewDetail = { version: 1, choiceId: reviewChoiceId, reviewId: 41, productId: 6,
  rating: 2, status: 'pending', body: 'Needs moderation.', oversized: false, modeCapability: reviewMode };
const reviewPage = { page: 1, total: 6, nextPage: 2, status: 'pending', productChoiceId: null }
const reviewProposal = { version: 1, proposalId: '11111111-1111-4111-8111-111111111111',
  review: { choiceId: reviewChoiceId, reviewId: 41, productId: 6, rating: 2, body: 'Needs moderation.', status: 'pending' },
  decision: 'approve', reason: null, expectedSnapshotSha256: 'a'.repeat(64), requestSha256: 'b'.repeat(64),
  scopeKey: 'c'.repeat(64), modeCapability: reviewMode };
const ownedOrder = { orderId: 41, status: 'paid', orderDate: '2026-10-10T09:00:00.000Z',
  merchantSubtotal: 18, items: [{ productId: 6, name: '<Practice laptop>', quantity: 2,
    price: 10, discountAmount: 2, lineTotal: 18 }] };
const inventoryProposal = { version: 1, proposalId: 'cccccccc-cccc-4ccc-8ccc-cccccccccccc',
  product: { choiceId, name: 'Practice laptop' }, stockChange: { productId: 6, quantity: 5 },
  message: 'Set its absolute stock to 5', scopeKey: 'a'.repeat(64),
  modeCapability: { version: 1, featureId: 'inventory', policyVersion: 'inventory-v1',
    effectiveMode: 'fixed', scope: { kind: 'launch_feature', id: 'inventory' } } };
const pricingProposal = { version: 1, proposalId: 'dddddddd-dddd-4ddd-8ddd-dddddddddddd',
  product: { choiceId, name: 'Practice laptop' }, action: 'experiment', productId: 6,
  message: 'Run a seven-day premium pricing experiment.',
  experiment: { strategy: 'premium', durationDays: 7 }, scopeKey: 'a'.repeat(64),
  requestSha256: 'b'.repeat(64), modeCapability: { version: 1, featureId: 'pricing',
    policyVersion: 'pricing-v1', effectiveMode: 'fixed',
    scope: { kind: 'launch_feature', id: 'pricing' } } };
const listingProposal = { version: 1, proposalId: 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee',
  product: { choiceId, name: 'Practice laptop' }, preview: { version: 1, productId: 6,
    before: { name: 'Practice laptop', description: 'old', descriptionHtml: '<p>old</p>', price: 12.5,
      category: 'home', templateSource: null, imageUrl: null },
    after: { name: 'Practice laptop', description: 'new', descriptionHtml: null, price: 12.5,
      category: 'home', templateSource: null, imageUrl: null }, patch: { description: 'new' },
    catalogRevision: '4', expectedSnapshotSha256: 'c'.repeat(64),
    requestSha256: '625826407242f2aba2cdb8369034469a6670b2866efa9c88ed2f0ec7d6199700',
    scopeKey: 'a'.repeat(64), invalidatesGeneratedHtml: true } };
const json = value => ({ ok: true, headers: { get: () => 'application/json' },
  json: async () => value });
const stream = (id, terminal = true, cards, eventMode = mode) => {
  const frames = [
    `event: tool_call\ndata: ${JSON.stringify({ sessionId: sid, requestId: id,
      id: 'call-1', tool: 'merchant.overview', params: {} })}\n\n`,
    `event: tool_result\ndata: ${JSON.stringify({ sessionId: sid, requestId: id,
      id: 'call-1', tool: 'merchant.overview', result: { content: [{ type: 'text', text: '{}' }] } })}\n\n`,
    `event: assistant_message\ndata: ${JSON.stringify({ sessionId: sid, requestId: id,
      text: 'Owned overview', modeCapability: eventMode, ...(cards ? { cards } : {}) })}\n\n`,
    ...(terminal ? [`event: done\ndata: ${JSON.stringify({ sessionId: sid, requestId: id,
      stopReason: 'end_turn', modeCapability: eventMode, ...(cards ? { cards } : {}) })}\n\n`] : []),
  ];
  let index = 0;
  return { ok: true, headers: { get: () => 'text/event-stream; charset=utf-8' },
    body: { getReader: () => ({ read: async () => index < frames.length
      ? { done: false, value: new TextEncoder().encode(frames[index++]) } : { done: true },
    cancel: async () => {} }) } };
};
let root, node, current;
function Probe({ transport, role = 'merchant', authorityKey = 'persona-token', shopUserId = 7 }) {
  current = useBoundRoleAssistant({ role, shopUserId, authorityKey, transport });
  return <span>{current.status}</span>;
}
beforeEach(() => {
  globalThis.IS_REACT_ACT_ENVIRONMENT = true;
  Object.defineProperty(globalThis, 'crypto', { value: webcrypto, configurable: true });
  node = document.createElement('div'); document.body.append(node); root = createRoot(node);
  readRoleAssistantReference.mockReturnValue(null);
  saveRoleAssistantReference.mockResolvedValue(); clearRoleAssistantReference.mockResolvedValue();
  readRoleAssistantCompletedReference.mockReturnValue(null);
  saveRoleAssistantCompletedReference.mockResolvedValue();
  clearRoleAssistantCompletedReference.mockResolvedValue();
});
afterEach(async () => { await act(async () => root.unmount()); node.remove(); jest.clearAllMocks(); });

test('a merchant composer mounted before identity hydration does not dispatch a session request', async () => {
  const transport = jest.fn();
  await act(async () => root.render(<Probe transport={transport} shopUserId={null} />));
  await act(async () => { expect(await current.send('Find my product named "Owned Pricing Fixture"')).toBe(false); });
  expect(current.status).toBe('idle');
  expect(current.turns).toHaveLength(0);
  expect(transport).not.toHaveBeenCalled();
});

test('parent reference acknowledgment completes before bounded role chat POST', async () => {
  let acknowledge;
  saveRoleAssistantReference.mockImplementation(() => new Promise(resolve => { acknowledge = resolve; }));
  const calls = [];
  const transport = jest.fn(async (url, options) => {
    calls.push({ url, body: options?.body });
    if (url.endsWith('/session')) return json({ sessionId: sid });
    if (url.endsWith('/chat')) return stream(JSON.parse(options.body).requestId);
    if (url.includes('/operations/')) return json({ sessionId: sid,
      requestId: saveRoleAssistantReference.mock.calls[0][0].requestId,
      status: 'completed', text: 'Owned overview', stopReason: 'end_turn',
      hops: [{ tool: 'merchant.overview', result: {} }], modeCapability: mode,
      replayed: true, cards: [] });
    throw new Error(`Unexpected ${url}`);
  });
  await act(async () => root.render(<Probe transport={transport} />));
  let sending;
  await act(async () => { sending = current.send('Show my overview'); });
  expect(calls.map(call => call.url)).toEqual(['/api/secureshop/agents/merchant/assistant/session']);
  expect(saveRoleAssistantReference).toHaveBeenCalledWith(expect.objectContaining({
    role: 'merchant', shopUserId: 7, sessionId: sid, requestId: expect.any(String),
  }));
  await act(async () => { acknowledge(); await sending; });
  expect(calls[1].url).toBe('/api/secureshop/agents/merchant/assistant/chat');
  expect(JSON.parse(calls[1].body)).toEqual({ sessionId: sid,
    requestId: saveRoleAssistantReference.mock.calls[0][0].requestId, message: 'Show my overview' });
  expect(calls[2].url).toContain(`/operations/${sid}/`);
  expect(clearRoleAssistantReference).toHaveBeenCalledTimes(1);
  expect(current.pending).toBeNull();
  expect(current.turns[0].reply).toBe('Owned overview');
  expect(current.turns[0].hops[0].tool).toBe('merchant.overview');
  expect(current.status).toBe('idle');
});

test('lost terminal keeps the exact reference and GET recovers without another POST', async () => {
  const calls = [];
  const transport = jest.fn(async (url, options) => {
    calls.push(url);
    if (url.endsWith('/session')) return json({ sessionId: sid });
    if (url.endsWith('/chat')) return stream(JSON.parse(options.body).requestId, false);
    if (url.includes('/operations/')) return json({ sessionId: sid,
      requestId: saveRoleAssistantReference.mock.calls[0][0].requestId,
      status: 'completed', text: 'Saved overview', stopReason: 'end_turn',
      hops: [{ tool: 'merchant.overview', result: {} }], modeCapability: mode,
      replayed: true, cards: [] });
    throw new Error(`Unexpected ${url}`);
  });
  await act(async () => root.render(<Probe transport={transport} />));
  await act(async () => { expect(await current.send('Show my overview')).toBe(false); });
  expect(current.pending).not.toBeNull();
  expect(clearRoleAssistantReference).not.toHaveBeenCalled();
  const postCount = calls.filter(url => url.endsWith('/chat')).length;
  await act(async () => { expect(await current.send('Try again')).toBe(false); });
  expect(calls.filter(url => url.endsWith('/chat'))).toHaveLength(postCount);
  await act(async () => { expect(await current.recover()).toBe(true); });
  expect(calls.filter(url => url.endsWith('/chat'))).toHaveLength(postCount);
  expect(calls.at(-1)).toContain(`/operations/${sid}/`);
  expect(clearRoleAssistantReference).toHaveBeenCalledTimes(1);
  expect(current.turns[0].reply).toBe('Saved overview');
  expect(current.status).toBe('idle');
});

test.each(['merchant', 'admin'])('%s restores its last acknowledged choice from exact GET without rerunning chat', async role => {
  const requestId = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc';
  const saved = { role, shopUserId: 7, sessionId: sid, requestId, startedAt: 12 };
  const adminMode = { version: 1, featureId: 'admin_assistant',
    policyVersion: 'owned-admin-read-and-confirmation-v1', effectiveMode: 'fixed',
    scope: { kind: 'launch_feature', id: 'admin_assistant' } };
  const userCard = { version: 1, kind: 'tenant_user', choiceId,
    title: 'Practice user', detail: 'customer account' };
  readRoleAssistantCompletedReference.mockReturnValue(saved);
  const calls = [];
  const transport = jest.fn(async (url, options) => {
    calls.push({ url, body: options?.body });
    if (url.endsWith('/chat')) return stream(JSON.parse(options.body).requestId,
      true, [], role === 'merchant' ? mode : adminMode);
    if (url.includes('/operations/')) return json({ sessionId: sid,
      requestId: url.split('/').at(-1),
      status: 'completed', text: 'Owned choices', stopReason: 'end_turn',
      hops: [], cards: url.endsWith(`/${requestId}`)
        ? role === 'merchant' ? [productCard] : [userCard] : [],
      modeCapability: role === 'merchant' ? mode : adminMode, replayed: true });
    throw new Error(`Unexpected ${url}`);
  });
  await act(async () => { root.render(<Probe transport={transport} role={role} />);
    await Promise.resolve(); await Promise.resolve(); });
  expect(calls.map(call => call.url)).toEqual([
    `/api/secureshop/agents/${role}/assistant/operations/${sid}/${requestId}`,
  ]);
  expect(current.pending).toBeNull();
  expect(current.completedPagePending).toBe(false);
  expect(current.turns).toHaveLength(1);
  expect(current.turns[0]).toMatchObject({ requestId, status: 'done',
    cards: role === 'merchant' ? [productCard] : [userCard] });
  expect(saveRoleAssistantReference).not.toHaveBeenCalled();
  expect(clearRoleAssistantReference).not.toHaveBeenCalled();
  if (role === 'merchant') {
    await act(async () => { expect(await current.send('Show older orders')).toBe(true); });
    expect(current.turns).toHaveLength(2);
    expect(current.turns[0].requestId).toBe(requestId);
    expect(current.turns[1].requestId).not.toBe(requestId);
    expect(calls.filter(call => call.url.endsWith('/chat'))).toHaveLength(1);
    expect(calls.some(call => call.url.endsWith('/session'))).toBe(false);
  }
});

test('merchant hydrates only an exact successful protected manual-search observation after reload', async () => {
  const requestId = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc';
  readRoleAssistantCompletedReference.mockReturnValue({ role: 'merchant', shopUserId: 7,
    sessionId: sid, requestId, startedAt: 12 });
  const actualMode = { ...mode, policyVersion: 'owned-merchant-read-and-confirmation-v1' };
  const text = '<img src=x onerror=alert(1)> Use the release tab.';
  const result = { product: { id: 6, name: 'Practice laptop' }, query: 'How do I replace the battery?',
    limit: 3, count: 1, hasMore: false,
    revision: { revisionId: 'dddddddd-dddd-4ddd-8ddd-dddddddddddd',
      runtimeFingerprint: 'a'.repeat(64), sourceSetDigest: 'b'.repeat(64) },
    status: 'complete', sources: [{ sourceKind: 'manual', sourceId: 9, chunkIndex: 0,
      text, score: 0.8, sourceSha256: 'c'.repeat(64), filename: 'laptop.pdf',
      operationId: 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee', receiptSha256: 'd'.repeat(64),
      documentDigest: 'e'.repeat(64), completedAt: '2026-10-11T12:00:00.000Z',
      textBytes: new TextEncoder().encode(text).byteLength, textSha256: createHash('sha256').update(text).digest('hex') }] };
  const payload = { sessionId: sid, requestId, status: 'completed', replayed: true,
    text: 'Here is the manual source.', stopReason: 'end_turn', modeCapability: actualMode,
    cards: [], manualSearch: { version: 1, choiceId, productId: 6,
      modeCapability: actualMode, result },
    hops: [{ tool: 'merchant.manual_search', params: { choiceId },
      result: { content: [{ type: 'text', text: JSON.stringify(result) }] } }] };
  const transport = jest.fn(async url => {
    if (url.endsWith(`/operations/${sid}/${requestId}`)) return json(payload);
    throw new Error(`Unexpected ${url}`);
  });
  await act(async () => { root.render(<Probe transport={transport} />);
    await Promise.resolve(); await Promise.resolve(); });
  await act(async () => { await new Promise(resolve => setTimeout(resolve, 0)); });
  expect(transport).toHaveBeenCalledTimes(1);
  expect(current.turns[0].manualSearch.result).toEqual(result);
  expect(current.turns[0].status).toBe('done');
  expect(saveRoleAssistantReference).not.toHaveBeenCalled();
  expect(clearRoleAssistantReference).not.toHaveBeenCalled();
});

test('pending role request takes precedence over a completed page on mount', async () => {
  const pending = { role: 'merchant', shopUserId: 7, sessionId: sid,
    requestId: 'cccccccc-cccc-4ccc-8ccc-cccccccccccc', startedAt: 12 };
  readRoleAssistantReference.mockReturnValue(pending);
  readRoleAssistantCompletedReference.mockReturnValue({ ...pending,
    requestId: 'dddddddd-dddd-4ddd-8ddd-dddddddddddd' });
  const transport = jest.fn();
  await act(async () => root.render(<Probe transport={transport} />));
  expect(current.pending).toEqual(pending);
  expect(current.completedPagePending).toBe(false);
  expect(current.turns[0].requestId).toBe(pending.requestId);
  expect(transport).not.toHaveBeenCalled();
});

test('a completed page from the previous mode clears on protected 409 and permits a new turn', async () => {
  const requestId = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc';
  const saved = { role: 'admin', shopUserId: 7, sessionId: sid, requestId, startedAt: 12 };
  readRoleAssistantCompletedReference.mockReturnValue(saved);
  clearRoleAssistantCompletedReference.mockImplementation(async reference => {
    expect(reference).toEqual(saved);
    readRoleAssistantCompletedReference.mockReturnValue(null);
    return true;
  });
  const calls = [];
  const transport = jest.fn(async (url, options) => {
    calls.push({ url, body: options?.body });
    if (url.endsWith(`/operations/${sid}/${requestId}`)) return { ok: false, status: 409 };
    if (url.endsWith('/session')) return json({ sessionId: sid });
    if (url.endsWith('/chat')) {
      const body = JSON.parse(options.body);
      return stream(body.requestId, true, [], { ...mode, featureId: 'admin_assistant',
        effectiveMode: 'fixed', scope: { kind: 'launch_feature', id: 'admin_assistant' } });
    }
    if (url.includes('/operations/')) return json({ sessionId: sid,
      requestId: url.split('/').at(-1), status: 'completed', text: 'Fixed-mode answer',
      stopReason: 'end_turn', hops: [], cards: [], replayed: true,
      modeCapability: { ...mode, featureId: 'admin_assistant', effectiveMode: 'fixed',
        scope: { kind: 'launch_feature', id: 'admin_assistant' } } });
    throw new Error(`Unexpected ${url}`);
  });
  await act(async () => { root.render(<Probe transport={transport} role="admin" />);
    await Promise.resolve(); await Promise.resolve(); });
  expect(clearRoleAssistantCompletedReference).toHaveBeenCalledTimes(1);
  expect(current.pending).toBeNull();
  expect(current.completedPagePending).toBe(false);
  expect(current.status).toBe('idle');
  await act(async () => { expect(await current.send('Ask in fixed mode')).toBe(true); });
  expect(calls.filter(call => call.url.endsWith('/chat'))).toHaveLength(1);
});

test('a pending request 409 stays unresolved and cannot start a second turn', async () => {
  const requestId = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc';
  const pending = { role: 'admin', shopUserId: 7, sessionId: sid, requestId, startedAt: 12 };
  readRoleAssistantReference.mockReturnValue(pending);
  const transport = jest.fn(async url => {
    if (url.endsWith(`/operations/${sid}/${requestId}`)) return { ok: false, status: 409 };
    throw new Error(`Unexpected ${url}`);
  });
  await act(async () => root.render(<Probe transport={transport} role="admin" />));
  await act(async () => { expect(await current.recover()).toBe(false); });
  expect(current.pending).toEqual(pending);
  expect(current.status).toBe('unresolved');
  expect(clearRoleAssistantReference).not.toHaveBeenCalled();
  expect(clearRoleAssistantCompletedReference).not.toHaveBeenCalled();
  expect(await current.send('Do not duplicate')).toBe(false);
  expect(transport).toHaveBeenCalledTimes(1);
});

test('unconfirmed completed-page cleanup adopts a newer pending ref after parent ACK', async () => {
  const saved = { role: 'merchant', shopUserId: 7, sessionId: sid,
    requestId: 'cccccccc-cccc-4ccc-8ccc-cccccccccccc', startedAt: 12 };
  const newer = { ...saved, requestId: 'dddddddd-dddd-4ddd-8ddd-dddddddddddd' };
  let finishClear;
  readRoleAssistantCompletedReference.mockReturnValue(saved);
  clearRoleAssistantCompletedReference.mockImplementation(() =>
    new Promise(resolve => { finishClear = resolve; }));
  const transport = jest.fn(async url => {
    if (url.includes('/operations/')) return json({ sessionId: sid,
      requestId: saved.requestId, status: 'unconfirmed' });
    throw new Error(`Unexpected ${url}`);
  });
  await act(async () => { root.render(<Probe transport={transport} />); await Promise.resolve(); });
  expect(finishClear).toEqual(expect.any(Function));
  readRoleAssistantReference.mockReturnValue(newer);
  readRoleAssistantCompletedReference.mockReturnValue(null);
  await act(async () => { finishClear(true); await Promise.resolve(); });
  expect(current.pending).toEqual(newer);
  expect(current.completedPagePending).toBe(false);
  expect(current.status).toBe('unresolved');
  expect(current.turns[0].requestId).toBe(newer.requestId);
  expect(transport).toHaveBeenCalledTimes(1);
});

test('admin audit activity hydrates from the protected completed GET, not streamed text', async () => {
  const adminMode = { version: 1, featureId: 'admin_assistant',
    policyVersion: 'owned-admin-read-and-confirmation-v1', effectiveMode: 'fixed',
    scope: { kind: 'launch_feature', id: 'admin_assistant' } };
  const eventId = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc';
  const event = { store: 'review', id: `review:${eventId}`, event_id: eventId,
    ts: '2026-10-11T12:34:56.123456Z', actor: 'Admin', action: 'review_decision',
    target: 'Owned review', params_json: '{"decision":"approved"}', outcome: 'completed',
    source_kind: 'review', source_id: 'saved source', ip: null, user_agent: null };
  const transport = jest.fn(async (url, options) => {
    if (url.endsWith('/session')) return json({ sessionId: sid });
    if (url.endsWith('/chat')) return stream(JSON.parse(options.body).requestId, true, [], adminMode);
    if (url.includes('/operations/')) return json({ sessionId: sid,
      requestId: url.split('/').at(-1), status: 'completed', text: 'Recent activity',
      stopReason: 'end_turn', modeCapability: adminMode, replayed: true, cards: [],
      hops: [{ tool: 'admin.audit_recent', params: {}, error: null,
        result: { content: [{ type: 'text', text: JSON.stringify({ count: 1, events: [event],
          hasMore: false, nextCursor: null }) }] } }] });
    throw new Error(`Unexpected ${url}`);
  });
  await act(async () => root.render(<Probe transport={transport} role="admin" />));
  await act(async () => { expect(await current.send('Show recent audit activity')).toBe(true); });
  expect(current.turns[0].auditRead).toEqual({ events: [event], hasMore: false,
    nextPageAvailable: false });
});

test('only exact completed GET cards enable a selected choice with stable model message', async () => {
  const bodies = [];
  let reads = 0;
  const transport = jest.fn(async (url, options) => {
    if (url.endsWith('/session')) return json({ sessionId: sid });
    if (url.endsWith('/chat')) {
      const body = JSON.parse(options.body);
      bodies.push(body);
      return stream(body.requestId);
    }
    if (url.includes('/operations/')) return json({ sessionId: sid,
      requestId: url.split('/').at(-1), status: 'completed', text: 'Owned result',
      stopReason: 'end_turn', hops: [], modeCapability: mode, replayed: true,
      cards: ++reads === 1 ? [productCard] : [] });
    throw new Error(`Unexpected ${url}`);
  });
  await act(async () => root.render(<Probe transport={transport} />));
  await act(async () => { expect(await current.send('Find a laptop')).toBe(true); });
  expect(current.turns[0].cards).toEqual([productCard]);
  await act(async () => { expect(await current.send('Use my selected option.', { choiceId })).toBe(true); });
  expect(bodies).toHaveLength(2);
  expect(bodies[1]).toEqual({ sessionId: sid, requestId: expect.any(String),
    message: 'Use my selected option.', selection: { choiceId } });
  expect(current.turns[1].user).toBe('Selected product: Practice laptop');
  expect(await current.send('Use my selected option.', { choiceId })).toBe(false);
  expect(bodies).toHaveLength(2);
});

test('merchant product details intent requires the latest protected product choice', async () => {
  const bodies = [];
  let reads = 0;
  const transport = jest.fn(async (url, options) => {
    if (url.endsWith('/session')) return json({ sessionId: sid });
    if (url.endsWith('/chat')) {
      const body = JSON.parse(options.body); bodies.push(body);
      return stream(body.requestId);
    }
    if (url.includes('/operations/')) return json({ sessionId: sid,
      requestId: url.split('/').at(-1), status: 'completed', text: 'Owned product',
      stopReason: 'end_turn', hops: [], modeCapability: mode, replayed: true,
      cards: ++reads === 1 ? [productCard] : [orderCard] });
    throw new Error(`Unexpected ${url}`);
  });
  await act(async () => root.render(<Probe transport={transport} />));
  await act(async () => { expect(await current.send('Find a laptop')).toBe(true); });
  expect(await current.send('Show my selected product details.',
    { choiceId: orderChoiceId, intent: 'product_details' })).toBe(false);
  expect(bodies).toHaveLength(1);
  await act(async () => { expect(await current.send('Show my selected product details.',
    { choiceId, intent: 'product_details' })).toBe(true); });
  expect(bodies[1]).toEqual({ sessionId: sid, requestId: expect.any(String),
    message: 'Show my selected product details.',
    selection: { choiceId, intent: 'product_details' } });
  expect(await current.send('Show my selected product details.',
    { choiceId, intent: 'product_details' })).toBe(false);
  expect(bodies).toHaveLength(2);
});

test('merchant rewrite setup intent requires the latest protected product choice', async () => {
  const bodies = [];
  let reads = 0;
  const transport = jest.fn(async (url, options) => {
    if (url.endsWith('/session')) return json({ sessionId: sid });
    if (url.endsWith('/chat')) {
      const body = JSON.parse(options.body); bodies.push(body);
      return stream(body.requestId);
    }
    if (url.includes('/operations/')) return json({ sessionId: sid,
      requestId: url.split('/').at(-1), status: 'completed', text: 'Owned product',
      stopReason: 'end_turn', hops: [], modeCapability: mode, replayed: true,
      cards: ++reads === 1 ? [productCard] : [orderCard] });
    throw new Error(`Unexpected ${url}`);
  });
  await act(async () => root.render(<Probe transport={transport} />));
  await act(async () => { expect(await current.send('Find a laptop')).toBe(true); });
  expect(await current.send('Prepare to rewrite this listing.',
    { choiceId: orderChoiceId, intent: 'listing_rewrite' })).toBe(false);
  expect(bodies).toHaveLength(1);
  await act(async () => { expect(await current.send('Prepare to rewrite this listing.',
    { choiceId, intent: 'listing_rewrite' })).toBe(true); });
  expect(bodies[1]).toEqual({ sessionId: sid, requestId: expect.any(String),
    message: 'Prepare to rewrite this listing.',
    selection: { choiceId, intent: 'listing_rewrite' } });
  expect(await current.send('Prepare to rewrite this listing.',
    { choiceId, intent: 'listing_rewrite' })).toBe(false);
  expect(bodies).toHaveLength(2);
});

test('merchant optimize setup intent posts only the latest protected product choice', async () => {
  const bodies = [];
  let reads = 0;
  const transport = jest.fn(async (url, options) => {
    if (url.endsWith('/session')) return json({ sessionId: sid });
    if (url.endsWith('/chat')) {
      const body = JSON.parse(options.body); bodies.push(body);
      return stream(body.requestId);
    }
    if (url.includes('/operations/')) return json({ sessionId: sid,
      requestId: url.split('/').at(-1), status: 'completed', text: 'Owned product',
      stopReason: 'end_turn', hops: [], modeCapability: mode, replayed: true,
      cards: ++reads === 1 ? [productCard] : [orderCard] });
    throw new Error(`Unexpected ${url}`);
  });
  await act(async () => root.render(<Probe transport={transport} />));
  await act(async () => { expect(await current.send('Find a laptop')).toBe(true); });
  expect(await current.send('Prepare image optimization for this listing.',
    { choiceId: orderChoiceId, intent: 'listing_optimize' })).toBe(false);
  expect(bodies).toHaveLength(1);
  await act(async () => { expect(await current.send('Prepare image optimization for this listing.',
    { choiceId, intent: 'listing_optimize' })).toBe(true); });
  expect(bodies[1]).toEqual({ sessionId: sid, requestId: expect.any(String),
    message: 'Prepare image optimization for this listing.',
    selection: { choiceId, intent: 'listing_optimize' } });
  expect(await current.send('Prepare image optimization for this listing.',
    { choiceId, intent: 'listing_optimize' })).toBe(false);
  expect(bodies).toHaveLength(2);
});

test('saved Listings setup comes only from exact completed protected GET and survives read-only recovery', async()=>{
 let requestId;const setupFor=id=>({version:1,kind:'listing_import_setup',proposalId:choiceId,operationId:choiceId,source:{sessionId:sid,requestId:id},listingsModeCapability:{version:1,featureId:'listings',policyVersion:'owned-listing-import-v1',effectiveMode:'vuln',scope:{kind:'launch_feature',id:'listings'}},sources:{json_url:'http://supplier.test/raw',xml_url:null}});
 const transport=jest.fn(async(url,options)=>{
  if(url.endsWith('/session'))return json({sessionId:sid});
  if(url.endsWith('/chat')){requestId=JSON.parse(options.body).requestId;return stream(requestId);}
  if(url.includes('/operations/'))return json({sessionId:sid,requestId:url.split('/').at(-1),status:'completed',replayed:true,text:'Review import',stopReason:'end_turn',hops:[],cards:[],modeCapability:mode,listingsSetup:setupFor(url.split('/').at(-1))});
  throw Error('Unexpected request');
 });
 await act(async()=>root.render(<Probe transport={transport}/>));
 await act(async()=>{expect(await current.send('Prepare import from http://supplier.test/raw')).toBe(true);});
 expect(current.turns.at(-1).listingsSetup).toEqual(setupFor(requestId));
 expect(transport.mock.calls.filter(([url])=>url.includes('/listings/'))).toHaveLength(0);
});

test('merchant manual search binds the unchanged query to only the latest owned product choice', async () => {
  const bodies = [];
  let reads = 0;
  const transport = jest.fn(async (url, options) => {
    if (url.endsWith('/session')) return json({ sessionId: sid });
    if (url.endsWith('/chat')) {
      const body = JSON.parse(options.body); bodies.push(body);
      return stream(body.requestId);
    }
    if (url.includes('/operations/')) return json({ sessionId: sid,
      requestId: url.split('/').at(-1), status: 'completed', text: 'Saved read',
      stopReason: 'end_turn', hops: [], modeCapability: mode, replayed: true,
      cards: ++reads === 1 ? [productCard] : [orderCard] });
    throw Error(`Unexpected ${url}`);
  });
  await act(async () => root.render(<Probe transport={transport} />));
  await act(async () => { expect(await current.send('Find a laptop')).toBe(true); });
  const query = 'How do I replace the battery?';
  expect(await current.send(query, { choiceId: orderChoiceId, intent: 'manual_search' })).toBe(false);
  expect(await current.send('a'.repeat(4097),
    { choiceId, intent: 'manual_search' })).toBe(false);
  await act(async () => { expect(await current.send(query,
    { choiceId, intent: 'manual_search' })).toBe(true); });
  expect(bodies[1]).toEqual({ sessionId: sid, requestId: expect.any(String),
    message: query, selection: { choiceId, intent: 'manual_search' } });
  expect(await current.send(query, { choiceId, intent: 'manual_search' })).toBe(false);
  expect(bodies).toHaveLength(2);
});

test('merchant mail reads require the latest matching saved opaque card kind', async () => {
  const recipientChoiceId = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
  const messageChoiceId = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc';
  const recipient = { version: 1, kind: 'merchant_mail_recipient',
    choiceId: recipientChoiceId, title: 'Practice merchant', detail: 'merchant@example.test' };
  const mail = { version: 1, kind: 'merchant_mail_message',
    choiceId: messageChoiceId, title: 'Order question', detail: 'From customer@example.test' };
  const bodies = [];
  let reads = 0;
  const transport = jest.fn(async (url, options) => {
    if (url.endsWith('/session')) return json({ sessionId: sid });
    if (url.endsWith('/chat')) {
      const body = JSON.parse(options.body); bodies.push(body);
      return stream(body.requestId);
    }
    if (url.includes('/operations/')) return json({ sessionId: sid,
      requestId: url.split('/').at(-1), status: 'completed', text: 'Saved mail read',
      stopReason: 'end_turn', hops: [], modeCapability: mode, replayed: true,
      cards: ++reads === 1 ? [recipient] : reads === 2 ? [mail] : [] });
    throw Error(`Unexpected ${url}`);
  });
  await act(async () => root.render(<Probe transport={transport} />));
  await act(async () => { expect(await current.send('Find merchant mail')).toBe(true); });
  expect(await current.send('Show this message.',
    { choiceId: recipientChoiceId, intent: 'mail_detail' })).toBe(false);
  await act(async () => { expect(await current.send('Show this recipient’s mailbox.',
    { choiceId: recipientChoiceId, intent: 'mail_list' })).toBe(true); });
  expect(bodies[1].selection).toEqual({ choiceId: recipientChoiceId, intent: 'mail_list' });
  expect(await current.send('Show this recipient’s mailbox.',
    { choiceId: recipientChoiceId, intent: 'mail_list' })).toBe(false);
  await act(async () => { expect(await current.send('Show this message.',
    { choiceId: messageChoiceId, intent: 'mail_detail' })).toBe(true); });
  expect(bodies[2].selection).toEqual({ choiceId: messageChoiceId, intent: 'mail_detail' });
  expect(bodies).toHaveLength(3);
});

test('merchant send and reply preparation bind the latest named recipient or message choice', async () => {
  const recipientChoiceId = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
  const messageChoiceId = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc';
  const recipient = { version: 1, kind: 'merchant_mail_recipient', choiceId: recipientChoiceId,
    title: 'Named customer', detail: 'customer@example.test' };
  const mail = { version: 1, kind: 'merchant_mail_message', choiceId: messageChoiceId,
    title: 'Order question', detail: 'From customer@example.test' };
  const bodies = [];
  const transport = jest.fn(async (url, options) => {
    if (url.endsWith('/session')) return json({ sessionId: sid });
    if (url.endsWith('/chat')) {
      const body = JSON.parse(options.body); bodies.push(body);
      return stream(body.requestId);
    }
    if (url.includes('/operations/')) return json({ sessionId: sid,
      requestId: url.split('/').at(-1), status: 'completed', text: 'Saved mail preparation',
      stopReason: 'end_turn', hops: [], modeCapability: mode, replayed: true,
      cards: bodies.length === 1 ? [recipient] : bodies.length === 2 ? [mail] : [] });
    throw Error(`Unexpected ${url}`);
  });
  await act(async () => root.render(<Probe transport={transport} />));
  await act(async () => { expect(await current.send('Find a named recipient')).toBe(true); });
  expect(await current.send('Prepare a reply to this message.',
    { choiceId: recipientChoiceId, intent: 'mail_reply' })).toBe(false);
  const exactPrompt = 'Tell this customer the order is ready. Subject: Ready for pickup.';
  await act(async () => { expect(await current.send(exactPrompt,
    { choiceId: recipientChoiceId, intent: 'mail_send' })).toBe(true); });
  expect(bodies[1].selection).toEqual({ choiceId: recipientChoiceId, intent: 'mail_send' });
  expect(bodies[1].message).toBe(exactPrompt);
  expect(await current.send('Send this message.',
    { choiceId: messageChoiceId, intent: 'mail_send' })).toBe(false);
  await act(async () => { expect(await current.send('Prepare a reply to this message.',
    { choiceId: messageChoiceId, intent: 'mail_reply' })).toBe(true); });
  expect(bodies[2].selection).toEqual({ choiceId: messageChoiceId, intent: 'mail_reply' });
  expect(bodies).toHaveLength(3);
});

test('merchant older mail uses only the latest protected saved page request identity', async () => {
  const actualMode = { ...mode, policyVersion: 'owned-merchant-read-and-confirmation-v1' };
  const mailModeCapability = { version: 1, featureId: 'mail',
    policyVersion: 'owned-mail-recipient-header-and-html-v1', effectiveMode: 'fixed',
    scope: { kind: 'launch_feature', id: 'mail' } };
  const mailRead = { version: 1, choiceId: null, modeCapability: actualMode,
    result: { version: 1, kind: 'list',
      readOperationId: 'dddddddd-dddd-4ddd-8ddd-dddddddddddd',
      mailModeCapability, receiptSha256: 'a'.repeat(64),
      recipient: { id: 7, username: 'Practice merchant', email: 'merchant@example.test',
        role: 'merchant' }, offset: 0, total: 6, hasMore: true,
      headers: [{ id: 41, threadId: 4, from: 'buyer@example.test',
        to: 'merchant@example.test', subject: 'Order question',
        createdAt: '2026-10-11T12:00:00.000Z', sha256: 'b'.repeat(64) }] } };
  const bodies = [];
  let reads = 0;
  const transport = jest.fn(async (url, options) => {
    if (url.endsWith('/session')) return json({ sessionId: sid });
    if (url.endsWith('/chat')) {
      const body = JSON.parse(options.body); bodies.push(body);
      return stream(body.requestId);
    }
    if (url.includes('/operations/')) return json({ sessionId: sid,
      requestId: url.split('/').at(-1), status: 'completed', text: 'Saved mail read',
      stopReason: 'end_turn', hops: [], modeCapability: actualMode, replayed: true,
      cards: [], mailRead: ++reads === 1 ? mailRead : null });
    throw Error(`Unexpected ${url}`);
  });
  await act(async () => root.render(<Probe transport={transport} />));
  await act(async () => { expect(await current.send('Show my mail')).toBe(true); });
  const sourceRequestId = current.turns[0].requestId;
  expect(current.turns[0].mailRead.result.headers[0].subject).toBe('Order question');
  expect(await current.send('Show older mail', null, null,
    { intent: 'mail_next', sourceRequestId: sid })).toBe(false);
  await act(async () => { expect(await current.send('Show older mail', null, null,
    { intent: 'mail_next', sourceRequestId })).toBe(true); });
  expect(bodies[1]).toEqual({ sessionId: sid, requestId: expect.any(String),
    message: 'Show older mail', mailContinuation: { intent: 'mail_next', sourceRequestId } });
  expect(bodies).toHaveLength(2);
});

test('acknowledged merchant mail read rehydrates by exact protected GET without another model turn', async () => {
  const requestId = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc';
  readRoleAssistantCompletedReference.mockReturnValue({ role: 'merchant', shopUserId: 7,
    sessionId: sid, requestId, startedAt: 12 });
  const actualMode = { ...mode, policyVersion: 'owned-merchant-read-and-confirmation-v1' };
  const saved = { version: 1, choiceId: null, modeCapability: actualMode,
    result: { version: 1, kind: 'recipients', recipients: [{ id: 7,
      username: 'Practice merchant', email: 'merchant@example.test', role: 'merchant' }],
      hasMore: false, mailModeCapability: { version: 1, featureId: 'mail',
        policyVersion: 'owned-mail-recipient-header-and-html-v1', effectiveMode: 'fixed',
        scope: { kind: 'launch_feature', id: 'mail' } } } };
  const transport = jest.fn(async url => {
    if (url.endsWith(`/operations/${sid}/${requestId}`)) return json({ sessionId: sid,
      requestId, status: 'completed', replayed: true, text: 'Recipients',
      stopReason: 'end_turn', modeCapability: actualMode, hops: [], cards: [], mailRead: saved });
    throw Error(`Unexpected ${url}`);
  });
  await act(async () => { root.render(<Probe transport={transport} />);
    await new Promise(resolve => setTimeout(resolve, 0)); });
  expect(transport).toHaveBeenCalledTimes(1);
  expect(current.turns[0].mailRead.result.recipients[0].username).toBe('Practice merchant');
  expect(current.turns[0].status).toBe('done');
  expect(saveRoleAssistantReference).not.toHaveBeenCalled();
});

test('merchant pricing comparison sends exact URL only for the latest saved product choice', async () => {
  const bodies=[];let reads=0;
  const transport=jest.fn(async(url,options)=>{
    if(url.endsWith('/session'))return json({sessionId:sid});
    if(url.endsWith('/chat')){const body=JSON.parse(options.body);bodies.push(body);
      return stream(body.requestId);}
    if(url.includes('/operations/'))return json({sessionId:sid,
      requestId:url.split('/').at(-1),status:'completed',text:'Owned result',
      stopReason:'end_turn',hops:[],modeCapability:mode,replayed:true,
      cards:++reads===1?[productCard]:[]});
    throw Error(`Unexpected ${url}`);
  });
  await act(async()=>root.render(<Probe transport={transport}/>));
  await act(async()=>{expect(await current.send('Find a laptop')).toBe(true);});
  const message='Compare my selected product with this competitor URL.';
  const competitorUrl='http://competitor.example/item?name=Practice%20laptop';
  expect(await current.send(message,{choiceId:orderChoiceId,intent:'pricing_compare',competitorUrl}))
    .toBe(false);
  expect(await current.send(message,{choiceId,intent:'pricing_compare',competitorUrl:
    'https://competitor.example/item'})).toBe(false);
  await act(async()=>{expect(await current.send(message,
    {choiceId,intent:'pricing_compare',competitorUrl})).toBe(true);});
  expect(bodies[1]).toEqual({sessionId:sid,requestId:expect.any(String),message,
    selection:{choiceId,intent:'pricing_compare',competitorUrl}});
  expect(await current.send(message,{choiceId,intent:'pricing_compare',competitorUrl})).toBe(false);
  expect(bodies).toHaveLength(2);
});

test('admin typed user role intent and proposal come only from exact completed GET', async () => {
  const adminMode = { version: 1, featureId: 'admin_assistant',
    policyVersion: 'owned-admin-read-and-confirmation-v1', effectiveMode: 'fixed',
    scope: { kind: 'launch_feature', id: 'admin_assistant' } };
  const card = { version: 1, kind: 'tenant_user', choiceId,
    title: 'owned_customer', detail: 'Customer account' };
  const bodies = [];
  const transport = jest.fn(async (url, options) => {
    if (url.endsWith('/session')) return json({ sessionId: sid });
    if (url.endsWith('/chat')) {
      const body = JSON.parse(options.body); bodies.push(body);
      return stream(body.requestId, true, [card], adminMode);
    }
    if (url.includes('/operations/')) {
      const requestId = url.split('/').at(-1);
      const proposal = bodies.length === 2
        ? projectRoleUserAdministrationProposal(createRoleUserAdministrationProposal({
          sessionId: sid, requestId, step: 1, callId: 'call-1',
          selected: { kind: 'tenant_user', choiceId, sourceId: 7, snapshotSha256: 'a'.repeat(64) },
          user: { id: 7, username: 'owned_customer', identity_kind: 'registered_account',
            role: 'customer', banned_at: null, authority_version: '4' },
          administration: { roleBan: true, scopeKey: 'owned administrator scope' },
          action: 'set_role', role: 'merchant', reason: null, modeCapability: adminMode,
        }), { sessionId: sid, requestId }) : null;
      return json({ sessionId: sid, requestId, status: 'completed', text: 'Review the user change',
        stopReason: 'end_turn', hops: [], modeCapability: adminMode, replayed: true,
        cards: bodies.length === 1 ? [card] : [], userAdministrationProposal: proposal });
    }
    throw Error(`Unexpected ${url}`);
  });
  await act(async () => root.render(<Probe role="admin" transport={transport} />));
  await act(async () => { expect(await current.send('Find owned_customer')).toBe(true); });
  expect(current.turns[0].cards).toEqual([card]);
  await act(async () => { expect(await current.send("Review changing this user's role to merchant.",
    { choiceId, intent: 'user_role', newRole: 'merchant' })).toBe(true); });
  expect(bodies[1].selection).toEqual({ choiceId, intent: 'user_role', newRole: 'merchant' });
  expect(current.turns[1].user).toContain('Selected user: owned_customer');
  expect(current.turns[1].userAdministrationProposal.target.username).toBe('owned_customer');
  expect(current.turns[1].userAdministrationProposal.role).toBe('merchant');
  expect(await current.send('Wrong ban', { choiceId, intent: 'user_ban' })).toBe(false);
});

test('admin password handoff is enabled only by exact completed end-turn GET', async () => {
  const adminMode = { version: 1, featureId: 'admin_assistant',
    policyVersion: 'owned-admin-read-and-confirmation-v1', effectiveMode: 'fixed',
    scope: { kind: 'launch_feature', id: 'admin_assistant' } };
  const card = { version: 1, kind: 'tenant_user', choiceId,
    title: 'owned_customer', detail: 'Customer account' };
  const bodies = [];
  const transport = jest.fn(async (url, options) => {
    if (url.endsWith('/session')) return json({ sessionId: sid });
    if (url.endsWith('/chat')) {
      const body = JSON.parse(options.body); bodies.push(body);
      return stream(body.requestId, true, [card], adminMode);
    }
    if (url.includes('/operations/')) {
      const requestId = url.split('/').at(-1);
      return json({ sessionId: sid, requestId, status: 'completed', text: 'Review the reset',
        stopReason: 'end_turn', hops: [], modeCapability: adminMode, replayed: true,
        cards: bodies.length === 1 ? [card] : [],
        passwordResetSetup: bodies.length === 2 ? { version: 1, kind: 'password_reset_setup',
          sessionId: sid, requestId, choiceId, userId: 17, username: 'owned_customer',
          identityKind: 'teaching_persona', channel: 'bound_persona', scopeKey: 'owned admin scope' } : null });
    }
    throw Error(`Unexpected ${url}`);
  });
  await act(async () => root.render(<Probe role="admin" transport={transport} />));
  await act(async () => { expect(await current.send('Find owned_customer')).toBe(true); });
  expect(current.turns[0].passwordResetSetup).toBeNull();
  await act(async () => { expect(await current.send('Review resetting this user password.',
    { choiceId, intent: 'user_password_reset' })).toBe(true); });
  expect(bodies[1].selection).toEqual({ choiceId, intent: 'user_password_reset' });
  expect(current.turns[1].passwordResetSetup).toMatchObject({ userId: 17, choiceId,
    channel: 'bound_persona' });
  expect(await current.send('Wrong source', { choiceId, intent: 'user_password_reset' })).toBe(false);
});

test('admin policy selection and full proposal hydrate only from protected saved GET', async () => {
  const adminMode = { version: 1, featureId: 'admin_assistant',
    policyVersion: 'owned-admin-read-and-confirmation-v1', effectiveMode: 'fixed',
    scope: { kind: 'launch_feature', id: 'admin_assistant' } };
  const jsonbMode = { scope: { id: 'admin_assistant', kind: 'launch_feature' },
    effectiveMode: 'fixed', policyVersion: 'owned-admin-read-and-confirmation-v1',
    featureId: 'admin_assistant', version: 1 };
  const card = { version: 1, kind: 'admin_policy', choiceId,
    title: 'Returns policy', detail: 'Current policy source' };
  const bodies = [];
  const transport = jest.fn(async (url, options) => {
    if (url.endsWith('/session')) return json({ sessionId: sid });
    if (url.endsWith('/chat')) {
      const body = JSON.parse(options.body); bodies.push(body);
      return stream(body.requestId, true, [card], adminMode);
    }
    if (url.includes('/operations/')) {
      const requestId = url.split('/').at(-1);
      const proposal = bodies.length === 2
        ? projectRolePolicyProposal(createRolePolicyProposal({
          source: { sessionId: sid, requestId }, origin: { step: 1, callId: 'policy-1' },
          action: 'edit', selected: { choiceId, snapshotSha256: 'a'.repeat(64) },
          name: 'Returns policy', before: { markdown: 'Old policy', targets: ['customer'] },
          after: { markdown: 'New policy', targets: ['customer'] },
          expectedVersion: '4', scopeKey: 'b'.repeat(64), modeCapability: adminMode,
        }, policySupportedTargets([])), { sessionId: sid, requestId }, policySupportedTargets([])) : null;
      return json({ sessionId: sid, requestId, status: 'completed', text: 'Review the policy',
        stopReason: 'end_turn', hops: [], modeCapability: jsonbMode, replayed: true,
        cards: bodies.length === 1 ? [card] : [], policyDetail: null, policyProposal: proposal });
    }
    throw Error(`Unexpected ${url}`);
  });
  await act(async () => root.render(<Probe role="admin" transport={transport} />));
  await act(async () => { expect(await current.send('Find returns policy')).toBe(true); });
  expect(current.turns[0].cards).toEqual([card]);
  await act(async () => { expect(await current.send('Change the returns text',
    { choiceId, intent: 'policy_edit' })).toBe(true); });
  expect(bodies[1].selection).toEqual({ choiceId, intent: 'policy_edit' });
  expect(current.turns[1].policyProposal.after.markdown).toBe('New policy');
  expect(await current.send('Wrong policy', { choiceId, intent: 'policy_delete' })).toBe(false);
  expect(await current.send('Wrong user intent', { choiceId, intent: 'user_ban' })).toBe(false);
});

test('admin MCP cards permit only typed current server detail and hydrate exact protected schema', async () => {
  const adminMode = { version: 1, featureId: 'admin_assistant',
    policyVersion: 'owned-admin-read-and-confirmation-v1', effectiveMode: 'fixed',
    scope: { kind: 'launch_feature', id: 'admin_assistant' } };
  const scopeKey = 'a'.repeat(64);
  const header = { provenance: 'owned_registry', id: 'cccccccc-cccc-4ccc-8ccc-cccccccccccc',
    name: 'Document search', transport: 'sse', url: 'http://owned.invalid/mcp',
    stdio_cmd: null, schemaSha256: 'b'.repeat(64), scenario: null };
  const server = { ...header, snapshotSha256: registryServerSnapshotDigest({
    scopeKey, registryVersion: '4', server: header,
  }) };
  const card = { version: 1, kind: 'admin_mcp_server', choiceId,
    title: 'Document search', detail: 'Registered MCP server' };
  const bodies = [];
  const transport = jest.fn(async (url, options) => {
    if (url.endsWith('/session')) return json({ sessionId: sid });
    if (url.endsWith('/chat')) {
      const body = JSON.parse(options.body); bodies.push(body);
      return stream(body.requestId, true, [card], adminMode);
    }
    if (url.includes('/operations/')) return json({ sessionId: sid,
      requestId: url.split('/').at(-1), status: 'completed', text: 'Registered server',
      stopReason: 'end_turn', hops: [], modeCapability: adminMode, replayed: true,
      cards: [card], mcpRegistryProposal: null, registeredMcpSetup: null,
      mcpDetail: bodies.length === 2 ? { version: 1, scopeKey, registryVersion: '4', server,
        schemaVersion: '2', choiceId, oversized: false,
        tools: [{ name: 'lookup', description: '<img src=x onerror=alert(1)>',
          inputSchema: { type: 'object' } }], history: [] } : null });
    throw Error(`Unexpected ${url}`);
  });
  await act(async () => root.render(<Probe role="admin" transport={transport} />));
  await act(async () => { expect(await current.send('Find my MCP servers')).toBe(true); });
  expect(current.turns[0].cards).toEqual([card]);
  expect(await current.send('Use my selected option.', { choiceId, intent: 'user_ban' })).toBe(false);
  await act(async () => { expect(await current.send('Show this server',
    { choiceId, intent: 'mcp_detail' })).toBe(true); });
  expect(bodies[1].selection).toEqual({ choiceId, intent: 'mcp_detail' });
  expect(current.turns[1].mcpDetail.tools[0].description)
    .toBe('<img src=x onerror=alert(1)>');
  expect(current.turns[1].cards).toEqual([card]);
});

test('merchant order choice and owned-line detail come only from the exact completed GET', async () => {
  const bodies = [];
  const transport = jest.fn(async (url, options) => {
    if (url.endsWith('/session')) return json({ sessionId: sid });
    if (url.endsWith('/chat')) {
      const body = JSON.parse(options.body); bodies.push(body);
      return stream(body.requestId, true, [orderCard]);
    }
    if (url.includes('/operations/')) return json({ sessionId: sid,
      requestId: url.split('/').at(-1), status: 'completed', text: 'Merchant order',
      stopReason: 'end_turn', modeCapability: mode, replayed: true,
      cards: bodies.length === 1 ? [productCard, orderCard] : [],
      hops: bodies.length === 1 ? [] : [{ tool: 'merchant.orders_detail', error: null,
        policyViolation: 'denied-by-acl', result: { content: [{ type: 'text',
          text: JSON.stringify({ order: ownedOrder }) }] } }] });
    throw Error(`Unexpected ${url}`);
  });
  await act(async () => root.render(<Probe transport={transport} />));
  await act(async () => { expect(await current.send('Show my orders')).toBe(true); });
  expect(current.turns[0].cards).toEqual([productCard, orderCard]);
  await act(async () => { expect(await current.send('Use my selected option.',
    { choiceId: orderChoiceId })).toBe(true); });
  expect(bodies[1]).toEqual({ sessionId: sid, requestId: expect.any(String),
    message: 'Use my selected option.', selection: { choiceId: orderChoiceId } });
  expect(current.turns[1].user).toBe('Selected order: Order #41 · Practice laptop');
  expect(current.turns[1].orderDetail).toEqual({ orderId: 41, status: 'paid',
    orderDate: '2026-10-10', merchantSubtotal: 18,
    items: [{ name: '<Practice laptop>', quantity: 2, price: 10,
      discountAmount: 2, lineTotal: 18 }] });
});

test('merchant filtered order continuation hydrates from saved GET and sends no client cursor or filter', async () => {
  const bodies = [];
  const transport = jest.fn(async (url, options) => {
    if (url.endsWith('/session')) return json({ sessionId: sid });
    if (url.endsWith('/chat')) {
      const body = JSON.parse(options.body); bodies.push(body);
      return stream(body.requestId, true, [orderCard]);
    }
    if (url.includes('/operations/')) return json({ sessionId: sid,
      requestId: url.split('/').at(-1), status: 'completed', text: 'Merchant orders',
      stopReason: 'end_turn', modeCapability: mode, replayed: true, cards: [orderCard], hops: [],
      ordersPage: { nextCursor: bodies.length === 1 ? 'Ab9_-' : null,
        productName: 'Practice laptop' } });
    throw Error(`Unexpected ${url}`);
  });
  await act(async () => root.render(<Probe transport={transport} />));
  await act(async () => { expect(await current.send('Orders containing Practice laptop')).toBe(true); });
  expect(current.turns[0].ordersPage).toEqual({ nextCursor: 'Ab9_-', productName: 'Practice laptop' });
  const firstRequestId = bodies[0].requestId;
  const continuation = { intent: 'orders_next', sourceRequestId: firstRequestId };
  await act(async () => { expect(await current.send('Show older orders', null,
    { intent: 'orders_next', sourceRequestId: sid })).toBe(false); });
  expect(bodies).toHaveLength(1);
  await act(async () => { expect(await current.send('Show older orders', null, continuation)).toBe(true); });
  expect(bodies[1]).toEqual({ sessionId: sid, requestId: expect.any(String),
    message: 'Show older orders', orderContinuation: continuation });
  expect(current.turns[1].ordersPage).toEqual({ nextCursor: null, productName: 'Practice laptop' });
  await act(async () => { expect(await current.send('Show older orders', null, continuation)).toBe(false); });
  expect(bodies).toHaveLength(2);
});

test('merchant catalog continuation is bound to the latest completed saved page', async () => {
  const bodies = [];
  const transport = jest.fn(async (url, options) => {
    if (url.endsWith('/session')) return json({ sessionId: sid });
    if (url.endsWith('/chat')) {
      const body = JSON.parse(options.body); bodies.push(body);
      return stream(body.requestId, true, [productCard]);
    }
    if (url.includes('/operations/')) return json({ sessionId: sid,
      requestId: url.split('/').at(-1), status: 'completed', text: 'Catalog results',
      stopReason: 'end_turn', modeCapability: mode, replayed: true, cards: [productCard], hops: [],
      catalogPage: { version: 1, total: 7, pageSize: 5, returnedCount: bodies.length === 1 ? 5 : 2,
        hasMore: bodies.length === 1 } });
    throw Error(`Unexpected ${url}`);
  });
  await act(async () => root.render(<Probe transport={transport} />));
  await act(async () => { expect(await current.send('Find laptops')).toBe(true); });
  const sourceRequestId = bodies[0].requestId;
  const continuation = { intent: 'catalog_next', sourceRequestId };
  await act(async () => {
    expect(await current.send('Show more products', null, null, null,
      { ...continuation, sourceRequestId: sid })).toBe(false);
    expect(await current.send('Show more products', null, null, null, continuation)).toBe(true);
  });
  expect(bodies[1]).toEqual({ sessionId: sid, requestId: expect.any(String),
    message: 'Show more products', catalogContinuation: continuation });
  await act(async () => { expect(await current.send('Show more products', null, null, null,
    { intent: 'catalog_next', sourceRequestId: bodies[1].requestId })).toBe(false); });
  expect(bodies).toHaveLength(2);
});

test('merchant filtered order page survives reference-only reload', async () => {
  const requestId = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc';
  readRoleAssistantReference.mockReturnValueOnce({ role: 'merchant', shopUserId: 7,
    sessionId: sid, requestId, startedAt: 1 });
  const transport = jest.fn(async url => {
    if (url.includes('/operations/')) return json({ sessionId: sid, requestId,
      status: 'completed', text: 'Saved orders', stopReason: 'end_turn',
      modeCapability: mode, replayed: true, cards: [orderCard], hops: [],
      ordersPage: { nextCursor: 'Ab9_-', productName: 'Practice laptop' } });
    throw Error(`Unexpected ${url}`);
  });
  await act(async () => root.render(<Probe transport={transport} />));
  expect(current.pending.requestId).toBe(requestId);
  await act(async () => { expect(await current.recover()).toBe(true); });
  expect(current.turns[0].ordersPage).toEqual({ nextCursor: 'Ab9_-', productName: 'Practice laptop' });
  expect(transport.mock.calls.every(([url]) => url.includes('/operations/'))).toBe(true);
  expect(current.pending).toBeNull();
});

test('merchant older action after completed-page reload binds only the latest saved request', async () => {
  const firstRequestId = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc';
  const reference = { role: 'merchant', shopUserId: 7, sessionId: sid,
    requestId: firstRequestId, startedAt: 1 };
  readRoleAssistantCompletedReference.mockReturnValue(reference);
  const bodies = [];
  const transport = jest.fn(async (url, options) => {
    if (url.includes('/operations/')) return json({ sessionId: sid,
      requestId: url.split('/').at(-1), status: 'completed', text: 'Saved orders',
      stopReason: 'end_turn', modeCapability: mode, replayed: true,
      cards: [orderCard], hops: [], ordersPage: { nextCursor: 'Ab9_-', productName: 'Practice laptop' } });
    if (url.endsWith('/chat')) {
      const body = JSON.parse(options.body); bodies.push(body);
      return stream(body.requestId, true, [orderCard]);
    }
    throw Error(`Unexpected ${url}`);
  });
  await act(async () => root.render(<Probe transport={transport} />));
  await act(async () => {});
  expect(current.turns[0].requestId).toBe(firstRequestId);
  const continuation = { intent: 'orders_next', sourceRequestId: firstRequestId };
  await act(async () => { expect(await current.send('Show older orders', null, continuation)).toBe(true); });
  expect(bodies[0]).toEqual({ sessionId: sid, requestId: expect.any(String),
    message: 'Show older orders', orderContinuation: continuation });
  expect(transport.mock.calls.filter(([url]) => url.endsWith('/session'))).toHaveLength(0);
});

test('malformed merchant order filter leaves the exact saved request unresolved', async () => {
  const transport = jest.fn(async (url, options) => {
    if (url.endsWith('/session')) return json({ sessionId: sid });
    if (url.endsWith('/chat')) return stream(JSON.parse(options.body).requestId);
    if (url.includes('/operations/')) return json({ sessionId: sid, requestId: url.split('/').at(-1),
      status: 'completed', text: 'Saved orders', stopReason: 'end_turn',
      modeCapability: mode, replayed: true, cards: [orderCard], hops: [],
      ordersPage: { nextCursor: 'Ab9_-', productName: ' Practice laptop' } });
    throw Error(`Unexpected ${url}`);
  });
  await act(async () => root.render(<Probe transport={transport} />));
  await act(async () => { expect(await current.send('Orders containing Practice laptop')).toBe(false); });
  expect(current.pending).not.toBeNull();
  expect(current.turns[0].ordersPage).toBeUndefined();
  expect(clearRoleAssistantReference).not.toHaveBeenCalled();
});

test('merchant review choices preserve explicit action intent and exact GET review DTOs', async () => {
  const bodies = [];
  const transport = jest.fn(async (url, options) => {
    if (url.endsWith('/session')) return json({ sessionId: sid });
    if (url.endsWith('/chat')) {
      const body = JSON.parse(options.body); bodies.push(body);
      return stream(body.requestId, true, [reviewCard]);
    }
    if (url.includes('/operations/')) return json({ sessionId: sid, requestId: url.split('/').at(-1),
      status: 'completed', text: 'Review result', stopReason: 'end_turn', modeCapability: mode, replayed: true,
      cards: bodies.length === 1 ? [reviewCard] : [], hops: [], reviewPage: bodies.length === 1 ? reviewPage : null,
      ...(bodies.length === 1 ? { reviewDetail } : { reviewProposal }) });
    throw Error(`Unexpected ${url}`);
  });
  await act(async () => root.render(<Probe transport={transport} />));
  await act(async () => { expect(await current.send('Show pending reviews')).toBe(true); });
  expect(current.turns[0].cards).toEqual([reviewCard]);
  expect(current.turns[0].reviewDetail).toEqual(reviewDetail);
  expect(current.turns[0].reviewPage).toEqual(reviewPage);
  await act(async () => { expect(await current.send('Approve this review.',
    { choiceId: reviewChoiceId, intent: 'review_approve' })).toBe(true); });
  expect(bodies[1]).toEqual({ sessionId: sid, requestId: expect.any(String),
    message: 'Approve this review.', selection: { choiceId: reviewChoiceId, intent: 'review_approve' } });
  expect(current.turns[1].user).toBe('Selected review: Review · Practice laptop · 2 stars · Approve this review.');
  expect(current.turns[1].reviewProposal).toEqual(reviewProposal);
});

test('a blocked order-detail hop does not become a displayed merchant order', async () => {
  const transport = jest.fn(async (url, options) => {
    if (url.endsWith('/session')) return json({ sessionId: sid });
    if (url.endsWith('/chat')) return stream(JSON.parse(options.body).requestId);
    if (url.includes('/operations/')) return json({ sessionId: sid,
      requestId: url.split('/').at(-1), status: 'completed', text: 'Access blocked',
      stopReason: 'end_turn', modeCapability: mode, replayed: true, cards: [],
      hops: [{ tool: 'merchant.orders_detail', error: { message: 'blocked-by-acl' },
        policyViolation: 'blocked', result: { content: [{ type: 'text',
          text: JSON.stringify({ error: 'blocked-by-acl' }) }], isError: true } }] });
    throw Error(`Unexpected ${url}`);
  });
  await act(async () => root.render(<Probe transport={transport} />));
  await act(async () => { expect(await current.send('Show this order')).toBe(true); });
  expect(current.turns[0].orderDetail).toBeNull();
  expect(current.turns[0].status).toBe('done');
});

test('an order detail carrying a customer field is rejected and leaves the saved request unresolved', async () => {
  const transport = jest.fn(async (url, options) => {
    if (url.endsWith('/session')) return json({ sessionId: sid });
    if (url.endsWith('/chat')) return stream(JSON.parse(options.body).requestId);
    if (url.includes('/operations/')) return json({ sessionId: sid,
      requestId: url.split('/').at(-1), status: 'completed', text: 'Order detail',
      stopReason: 'end_turn', modeCapability: mode, replayed: true, cards: [],
      hops: [{ tool: 'merchant.orders_detail', error: null, policyViolation: null,
        result: { content: [{ type: 'text', text: JSON.stringify({
          order: { ...ownedOrder, customerEmail: 'other@example.test' },
        }) }] } }] });
    throw Error(`Unexpected ${url}`);
  });
  await act(async () => root.render(<Probe transport={transport} />));
  await act(async () => { expect(await current.send('Show this order')).toBe(false); });
  expect(current.pending).toEqual(expect.objectContaining({ requestId: expect.any(String) }));
  expect(current.status).toBe('unresolved');
  expect(current.turns[0].orderDetail).toBeUndefined();
  expect(clearRoleAssistantReference).not.toHaveBeenCalled();
});

test('typed merchant selection projects only the protected saved stock proposal', async () => {
  const bodies = [];
  const transport = jest.fn(async (url, options) => {
    if (url.endsWith('/session')) return json({ sessionId: sid });
    if (url.endsWith('/chat')) {
      const body = JSON.parse(options.body); bodies.push(body);
      return stream(body.requestId);
    }
    if (url.includes('/operations/')) return json({ sessionId: sid, requestId: url.split('/').at(-1),
      status: 'completed', text: 'Saved result', stopReason: 'end_turn', hops: [],
      modeCapability: mode, replayed: true, cards: bodies.length === 1 ? [productCard] : [],
      inventoryProposal: bodies.length === 2 ? inventoryProposal : null });
    throw Error(`Unexpected ${url}`);
  });
  await act(async () => root.render(<Probe transport={transport} />));
  await act(async () => { expect(await current.send('Find a laptop')).toBe(true); });
  await act(async () => { expect(await current.send('Set its absolute stock to 5', { choiceId })).toBe(true); });
  expect(bodies[1]).toEqual({ sessionId: sid, requestId: expect.any(String),
    message: 'Set its absolute stock to 5', selection: { choiceId } });
  expect(current.turns[1].user).toBe('Selected product: Practice laptop · Set its absolute stock to 5');
  expect(current.turns[1].inventoryProposal).toEqual(inventoryProposal);
  expect(current.turns[1].sessionId).toBe(sid);
});

test('pricing proposal becomes actionable only from the exact completed role GET', async () => {
  const bodies = [];
  const transport = jest.fn(async (url, options) => {
    if (url.endsWith('/session')) return json({ sessionId: sid });
    if (url.endsWith('/chat')) {
      const body = JSON.parse(options.body); bodies.push(body);
      return stream(body.requestId);
    }
    if (url.includes('/operations/')) return json({ sessionId: sid, requestId: url.split('/').at(-1),
      status: 'completed', text: 'Saved proposal', stopReason: 'end_turn', hops: [],
      modeCapability: mode, replayed: true, cards: bodies.length === 1 ? [productCard] : [],
      pricingProposal: bodies.length === 2 ? pricingProposal : null });
    throw Error(`Unexpected ${url}`);
  });
  await act(async () => root.render(<Probe transport={transport} />));
  await act(async () => { expect(await current.send('Find a laptop')).toBe(true); });
  expect(current.turns[0].pricingProposal).toBeNull();
  await act(async () => { expect(await current.send('Try a premium pricing experiment for seven days',
    { choiceId })).toBe(true); });
  expect(current.turns[1].pricingProposal).toEqual(pricingProposal);
  expect(bodies[1].selection).toEqual({ choiceId });
});

test('listing edit proposal is projected only from the exact completed role GET', async () => {
  const transport = jest.fn(async (url, options) => {
    if (url.endsWith('/session')) return json({ sessionId: sid });
    if (url.endsWith('/chat')) return stream(JSON.parse(options.body).requestId);
    if (url.includes('/operations/')) return json({ sessionId: sid, requestId: url.split('/').at(-1),
      status: 'completed', text: 'Saved listing proposal', stopReason: 'end_turn', hops: [],
      modeCapability: mode, replayed: true, cards: [], listingProposal });
    throw Error(`Unexpected ${url}`);
  });
  await act(async () => root.render(<Probe transport={transport} />));
  await act(async () => { expect(await current.send('Update this listing')).toBe(true); });
  expect(current.turns[0].listingProposal).toEqual(listingProposal);
});

test('malformed protected Pricing proposal keeps the role request unresolved', async () => {
  const transport = jest.fn(async (url, options) => {
    if (url.endsWith('/session')) return json({ sessionId: sid });
    if (url.endsWith('/chat')) return stream(JSON.parse(options.body).requestId);
    return json({ sessionId: sid, requestId: url.split('/').at(-1), status: 'completed',
      text: 'Not authoritative', stopReason: 'end_turn', hops: [], modeCapability: mode,
      replayed: true, cards: [], pricingProposal: { ...pricingProposal, requestSha256: 'wrong' } });
  });
  await act(async () => root.render(<Probe transport={transport} />));
  await act(async () => { expect(await current.send('Run pricing')).toBe(false); });
  expect(current.pending).toEqual(expect.objectContaining({ requestId: expect.any(String) }));
  expect(current.turns[0].pricingProposal).toBeUndefined();
  expect(clearRoleAssistantReference).not.toHaveBeenCalled();
});

test('malformed exact GET cards retain the acknowledged request and never enable a choice', async () => {
  const transport = jest.fn(async (url, options) => {
    if (url.endsWith('/session')) return json({ sessionId: sid });
    if (url.endsWith('/chat')) return stream(JSON.parse(options.body).requestId);
    return json({ sessionId: sid, requestId: url.split('/').at(-1), status: 'completed',
      text: 'Candidate', stopReason: 'end_turn', hops: [], modeCapability: mode,
      replayed: true, cards: [{ ...productCard, kind: 'tenant_user' }] });
  });
  await act(async () => root.render(<Probe transport={transport} />));
  await act(async () => { expect(await current.send('Find a laptop')).toBe(false); });
  expect(current.pending).toEqual(expect.objectContaining({ requestId: expect.any(String) }));
  expect(current.status).toBe('unresolved');
  expect(current.turns[0].cards).toBeUndefined();
  expect(clearRoleAssistantReference).not.toHaveBeenCalled();
  expect(await current.send('Use my selected option.', { choiceId })).toBe(false);
  expect(transport.mock.calls.filter(([url]) => url.endsWith('/chat'))).toHaveLength(1);
});

test.each([false, 'true', 1])('merchant saved read-only card rejects nonliteral marker %s', async readOnly => {
  const transport = jest.fn(async (url, options) => {
    if (url.endsWith('/session')) return json({ sessionId: sid });
    if (url.endsWith('/chat')) return stream(JSON.parse(options.body).requestId);
    return json({ sessionId: sid, requestId: url.split('/').at(-1), status: 'completed',
      text: 'Catalog', stopReason: 'end_turn', hops: [], modeCapability: mode,
      replayed: true, cards: [{ ...productCard, readOnly }] });
  });
  await act(async () => root.render(<Probe transport={transport} />));
  await act(async () => { expect(await current.send('Find products')).toBe(false); });
  expect(current.pending).toEqual(expect.objectContaining({ requestId: expect.any(String) }));
  expect(current.turns[0].cards).toBeUndefined();
});

test('merchant saved read-only card preserves details selection and exact marker', async () => {
  const transport = jest.fn(async (url, options) => {
    if (url.endsWith('/session')) return json({ sessionId: sid });
    if (url.endsWith('/chat')) return stream(JSON.parse(options.body).requestId);
    return json({ sessionId: sid, requestId: url.split('/').at(-1), status: 'completed',
      text: 'Catalog', stopReason: 'end_turn', hops: [], modeCapability: mode,
      replayed: true, cards: [{ ...productCard, readOnly: true }] });
  });
  await act(async () => root.render(<Probe transport={transport} />));
  await act(async () => { expect(await current.send('Find products')).toBe(true); });
  expect(current.turns[0].cards).toEqual([{ ...productCard, readOnly: true }]);
});

test('SSE-only cards never become selectable without exact completed GET cards', async () => {
  const transport = jest.fn(async (url, options) => {
    if (url.endsWith('/session')) return json({ sessionId: sid });
    if (url.endsWith('/chat')) return stream(JSON.parse(options.body).requestId, true, [productCard]);
    return json({ sessionId: sid, requestId: url.split('/').at(-1), status: 'completed',
      text: 'No current choices', stopReason: 'end_turn', hops: [], modeCapability: mode,
      replayed: true, cards: [] });
  });
  await act(async () => root.render(<Probe transport={transport} />));
  await act(async () => { expect(await current.send('Find a laptop')).toBe(true); });
  expect(current.turns[0].cards).toEqual([]);
  expect(await current.send('Use my selected option.', { choiceId })).toBe(false);
  expect(transport.mock.calls.filter(([url]) => url.endsWith('/chat'))).toHaveLength(1);
});

test('terminal SSE with unconfirmed exact GET keeps the UUID pending and offers no choices', async () => {
  const transport = jest.fn(async (url, options) => {
    if (url.endsWith('/session')) return json({ sessionId: sid });
    if (url.endsWith('/chat')) return stream(JSON.parse(options.body).requestId, true, [productCard]);
    return json({ sessionId: sid, requestId: url.split('/').at(-1), status: 'unconfirmed' });
  });
  await act(async () => root.render(<Probe transport={transport} />));
  await act(async () => { expect(await current.send('Find a laptop')).toBe(false); });
  expect(current.pending).toEqual(expect.objectContaining({ requestId: expect.any(String) }));
  expect(current.status).toBe('unresolved');
  expect(current.turns[0].cards).toBeUndefined();
  expect(clearRoleAssistantReference).not.toHaveBeenCalled();
  expect(await current.send('Use my selected option.', { choiceId })).toBe(false);
  expect(transport.mock.calls.filter(([url]) => url.endsWith('/chat'))).toHaveLength(1);
});

test('mismatched saved identity remains unresolved and never clears parent reference', async () => {
  const saved = { role: 'merchant', shopUserId: 7, sessionId: sid,
    requestId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', startedAt: 1234 };
  readRoleAssistantReference.mockReturnValue(saved);
  const transport = jest.fn(async () => json({ ...saved, requestId: 'cccccccc-cccc-4ccc-8ccc-cccccccccccc',
    status: 'completed', text: 'Wrong receipt', hops: [], modeCapability: mode, replayed: true }));
  await act(async () => root.render(<Probe transport={transport} />));
  expect(current.pending).toEqual(saved);
  await act(async () => { expect(await current.recover()).toBe(false); });
  expect(clearRoleAssistantReference).not.toHaveBeenCalled();
  expect(current.status).toBe('unresolved');
});

test('a done frame without the visible answer remains recoverable', async () => {
  const transport = jest.fn(async (url, options) => {
    if (url.endsWith('/session')) return json({ sessionId: sid });
    const requestId = JSON.parse(options.body).requestId;
    const bytes = new TextEncoder().encode(`event: done\ndata: ${JSON.stringify({
      sessionId: sid, requestId, stopReason: 'end_turn', modeCapability: mode,
    })}\n\n`);
    let delivered = false;
    return { ok: true, headers: { get: () => 'text/event-stream' },
      body: { getReader: () => ({ read: async () => delivered ? { done: true }
        : (delivered = true, { done: false, value: bytes }), cancel: async () => {} }) } };
  });
  await act(async () => root.render(<Probe transport={transport} />));
  await act(async () => { expect(await current.send('Show my overview')).toBe(false); });
  expect(current.pending).not.toBeNull();
  expect(current.status).toBe('unresolved');
  expect(clearRoleAssistantReference).not.toHaveBeenCalled();
});

test('replacing the bound transport fences a late old-stream terminal and preserves its reference', async () => {
  let resolveOldChat, saved = null;
  readRoleAssistantReference.mockImplementation(() => saved);
  saveRoleAssistantReference.mockImplementation(async reference => { saved = reference; });
  const oldTransport = jest.fn(async (url, options) => {
    if (url.endsWith('/session')) return json({ sessionId: sid });
    return new Promise(resolve => { resolveOldChat = () => resolve(stream(JSON.parse(options.body).requestId)); });
  });
  const nextTransport = jest.fn();
  await act(async () => root.render(<Probe transport={oldTransport} />));
  let oldSend;
  await act(async () => { oldSend = current.send('Show my overview'); });
  expect(saved).toEqual(expect.objectContaining({ role: 'merchant', shopUserId: 7 }));
  await act(async () => root.render(<Probe transport={nextTransport} />));
  expect(current.pending).toEqual(saved);
  await act(async () => { resolveOldChat(); expect(await oldSend).toBe(false); });
  expect(clearRoleAssistantReference).not.toHaveBeenCalled();
  expect(current.pending).toEqual(saved);
  expect(nextTransport).not.toHaveBeenCalled();
});

test('saved admin audit SQL turn hydrates only after its three-ID protected full GET', async () => {
  const requestId = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc';
  const saved = { role: 'admin', shopUserId: 7, sessionId: sid, requestId, startedAt: 1 };
  readRoleAssistantReference.mockReturnValue(saved);
  const adminMode = { version: 1, featureId: 'admin_assistant',
    policyVersion: 'owned-admin-read-and-confirmation-v1', effectiveMode: 'vuln',
    scope: { kind: 'launch_feature', id: 'admin_assistant' } };
  const auditMode = { version: 1, featureId: 'audit',
    policyVersion: 'raw-audit-query-disabled-v1', effectiveMode: 'vuln',
    scope: { kind: 'launch_feature', id: 'audit' } };
  const result = { ok: true, username: 'student_admin', sql: 'SELECT 1', count: 1,
    events: [{ note: '<b>teaching data</b>' }], error: null, durationMs: 1 };
  const canonical = value => Array.isArray(value) ? value.map(canonical)
    : value && typeof value === 'object' ? Object.fromEntries(Object.keys(value).sort()
      .map(key => [key, canonical(value[key])])) : value;
  const opId = 'dddddddd-dddd-4ddd-8ddd-dddddddddddd';
  const descriptor = { version: 1, kind: 'audit.sql_search', operationId: opId,
    status: 'completed', resultSha256: createHash('sha256').update(JSON.stringify(canonical(result))).digest('hex'),
    resultBytes: Buffer.byteLength(JSON.stringify(result)), count: 1, ok: true,
    source: { sourceSha256: 'a'.repeat(64), payloadSha256: 'b'.repeat(64) },
    modeCapability: auditMode, oversized: true, result: null };
  const calls = [];
  const transport = jest.fn(async url => {
    calls.push(url);
    if (url.endsWith(`/operations/${sid}/${requestId}`)) return json({ sessionId: sid,
      requestId, status: 'completed', text: 'A result is saved', stopReason: 'end_turn',
      hops: [], modeCapability: adminMode, replayed: true, cards: [], auditSearch: descriptor });
    if (url.endsWith(`/audit/operations/${sid}/${requestId}/${opId}`)) return json({ version: 1,
      operationId: opId, status: 'completed', result,
      source: { payloadSha256: 'b'.repeat(64), sourceSha256: 'a'.repeat(64) },
      modeCapability: { scope: { id: 'audit', kind: 'launch_feature' },
        effectiveMode: 'vuln', policyVersion: auditMode.policyVersion,
        featureId: 'audit', version: 1 } });
    throw Error(`Unexpected ${url}`);
  });
  await act(async () => root.render(<Probe role="admin" transport={transport} />));
  await act(async () => { expect(await current.recover()).toBe(true); });
  expect(calls).toEqual([`/api/secureshop/agents/admin/assistant/operations/${sid}/${requestId}`,
    `/api/secureshop/agents/admin/assistant/audit/operations/${sid}/${requestId}/${opId}`]);
  expect(current.turns[0].auditSearch.events[0].note).toBe('<b>teaching data</b>');
  expect(clearRoleAssistantReference).toHaveBeenCalledTimes(1);
});

test('unconfirmed saved audit descriptor retains chat reference and issues no full GET', async () => {
  const requestId = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc';
  const saved = { role: 'admin', shopUserId: 7, sessionId: sid, requestId, startedAt: 1 };
  readRoleAssistantReference.mockReturnValue(saved);
  const adminMode = { version: 1, featureId: 'admin_assistant',
    policyVersion: 'owned-admin-read-and-confirmation-v1', effectiveMode: 'vuln',
    scope: { kind: 'launch_feature', id: 'admin_assistant' } };
  const auditMode = { version: 1, featureId: 'audit',
    policyVersion: 'raw-audit-query-disabled-v1', effectiveMode: 'vuln',
    scope: { kind: 'launch_feature', id: 'audit' } };
  const transport = jest.fn(async () => json({ sessionId: sid, requestId,
    status: 'completed', text: 'Outcome pending', stopReason: 'end_turn',
    hops: [], modeCapability: adminMode, replayed: true, cards: [],
    auditSearch: { version: 1, kind: 'audit.sql_search',
      operationId: 'dddddddd-dddd-4ddd-8ddd-dddddddddddd', status: 'unconfirmed',
      resultSha256: null, resultBytes: 0, count: null, ok: null, source: null,
      modeCapability: auditMode, oversized: false, result: null } }));
  await act(async () => root.render(<Probe role="admin" transport={transport} />));
  await act(async () => { expect(await current.recover()).toBe(false); });
  expect(transport).toHaveBeenCalledTimes(1);
  expect(current.pending).toEqual(saved);
  expect(clearRoleAssistantReference).not.toHaveBeenCalled();
});

test('saved System config waits for verified exact receipt before clearing the chat reference', async () => {
  const requestId = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc';
  const opId = 'dddddddd-dddd-4ddd-8ddd-dddddddddddd';
  const saved = { role: 'admin', shopUserId: 7, sessionId: sid, requestId, startedAt: 1 };
  readRoleAssistantReference.mockReturnValue(saved);
  const adminMode = { version: 1, featureId: 'admin_assistant',
    policyVersion: 'owned-admin-read-and-confirmation-v1', effectiveMode: 'vuln',
    scope: { kind: 'launch_feature', id: 'admin_assistant' } };
  const content = 'synthetic config <script>escaped</script>';
  const digest = createHash('sha256').update(content).digest('hex');
  const descriptor = { version: 1, kind: 'system.config_read', scopeKey: 'a'.repeat(64),
    operationId: opId, requestSha256: 'b'.repeat(64), state: 'completed',
    result: { status: 'completed', ok: true, input: 'practice.txt', sanitized: 'practice.txt',
      targetPath: '/app/config/practice.txt', size: Buffer.byteLength(content),
      contentSha256: digest, content, oversized: false } };
  let pending = true, delayedAssessment = false, releaseAssessmentBody;
  const transport = jest.fn(async (url, options = {}) => {
    if (url.endsWith(`/operations/${sid}/${requestId}`)) return json({ sessionId: sid,
      requestId, status: 'completed', text: 'Saved config result', stopReason: 'end_turn',
      hops: [], modeCapability: adminMode, replayed: true, cards: [], systemConfigRead: descriptor });
    if (url.endsWith(`/system/config/operations/${sid}/${requestId}/${opId}`)) {
      if (pending) return { ok: false, status: 202 };
      return json({ operationId: opId, requestSha256: descriptor.requestSha256,
        state: 'completed', receipt: { operationId: opId, requestSha256: descriptor.requestSha256,
          status: 'completed', readResult: { ok: true, input: 'practice.txt', sanitized: 'practice.txt',
            targetPath: '/app/config/practice.txt', size: Buffer.byteLength(content),
            contentSha256: digest, content } } });
    }
    if (url.endsWith('/system/config/assessment-retry')) {
      expect(options.method).toBe('POST');
      expect(options.headers).toEqual({ 'content-type': 'application/json', accept: 'application/json' });
      expect(JSON.parse(options.body)).toEqual({ sessionId: sid, requestId });
      if (delayedAssessment) return { ok: true, headers: { get: () => 'application/json' },
        json: () => new Promise(resolve => { releaseAssessmentBody = () => resolve(
          { completed: false, status: 'ineligible', modelEvaluated: false }); }) };
      return json({ completed: false, status: 'ineligible', modelEvaluated: false });
    }
    if (url.endsWith('/policy/instruction/assessment-retry')) {
      expect(options.method).toBe('POST');
      expect(options.headers).toEqual({ 'content-type': 'application/json', accept: 'application/json' });
      expect(JSON.parse(options.body)).toEqual({ sessionId: sid, requestId });
      return json({ completed: false, status: 'ineligible', modelEvaluated: false });
    }
    throw Error(`Unexpected ${url}`);
  });
  await act(async () => root.render(<Probe role="admin" transport={transport} />));
  await act(async () => { expect(await current.recover()).toBe(false); });
  expect(current.pending).toEqual(saved);
  expect(clearRoleAssistantReference).not.toHaveBeenCalled();
  pending = false;
  await act(async () => { expect(await current.recover()).toBe(true); });
  expect(current.turns[0].systemConfigRead.content).toBe(content);
  expect(clearRoleAssistantReference).toHaveBeenCalledTimes(1);
  let checked;
  await act(async () => { checked = await current.checkSavedSystemConfigAssessment({ sessionId: sid, requestId }); });
  expect(checked).toEqual({ kind: 'ineligible', status: 'ineligible' });
  const retryCall = transport.mock.calls.find(([url]) => url.endsWith('/system/config/assessment-retry'));
  expect(retryCall).toBeDefined();
  await act(async () => { checked = await current.checkSavedPolicyInstructionAssessment({ sessionId: sid, requestId }); });
  expect(checked).toEqual({ kind: 'ineligible', status: 'ineligible' });
  expect(transport.mock.calls.filter(([url]) => url.endsWith('/policy/instruction/assessment-retry')))
    .toHaveLength(1);
  expect(transport).not.toHaveBeenCalledWith(expect.stringContaining('/chat'), expect.anything());
  const beforeForeign = transport.mock.calls.length;
  await act(async () => { checked = await current.checkSavedSystemConfigAssessment({ sessionId: sid,
    requestId: 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee' }); });
  expect(checked.kind).toBe('error');
  expect(transport).toHaveBeenCalledTimes(beforeForeign);
  await act(async () => { checked = await current.checkSavedPolicyInstructionAssessment({ sessionId: sid,
    requestId: 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee' }); });
  expect(checked.kind).toBe('error');
  expect(transport).toHaveBeenCalledTimes(beforeForeign);
  delayedAssessment = true;
  const inFlight = current.checkSavedSystemConfigAssessment({ sessionId: sid, requestId });
  await act(async () => { await Promise.resolve(); });
  expect(releaseAssessmentBody).toBeDefined();
  await act(async () => root.render(<Probe role="admin" authorityKey="rotated-persona-authority" transport={transport} />));
  await act(async () => releaseAssessmentBody());
  await expect(inFlight).resolves.toEqual({ kind: 'stale' });
  const beforeRotation = transport.mock.calls.length;
  await act(async () => { checked = await current.checkSavedSystemConfigAssessment({ sessionId: sid, requestId }); });
  expect(checked.kind).toBe('error');
  expect(transport).toHaveBeenCalledTimes(beforeRotation);
  expect(transport).not.toHaveBeenCalledWith(expect.stringContaining('/chat'), expect.anything());
});

test('policy instruction assessment uses a restored saved config read without replaying chat or claiming ineligible credit', async () => {
  const requestId = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc';
  const opId = 'dddddddd-dddd-4ddd-8ddd-dddddddddddd';
  readRoleAssistantCompletedReference.mockReturnValue({ role: 'admin', shopUserId: 7,
    sessionId: sid, requestId, startedAt: 12 });
  const adminMode = { version: 1, featureId: 'admin_assistant',
    policyVersion: 'owned-admin-read-and-confirmation-v1', effectiveMode: 'vuln',
    scope: { kind: 'launch_feature', id: 'admin_assistant' } };
  const content = 'saved synthetic policy source';
  const digest = createHash('sha256').update(content).digest('hex');
  const result = { status: 'completed', ok: true, input: 'practice.txt', sanitized: 'practice.txt',
    targetPath: '/app/config/practice.txt', size: Buffer.byteLength(content),
    contentSha256: digest, content, oversized: false };
  const descriptor = { version: 1, kind: 'system.config_read', scopeKey: 'a'.repeat(64),
    operationId: opId, requestSha256: 'b'.repeat(64), state: 'completed', result };
  const transport = jest.fn(async (url, options = {}) => {
    if (url.endsWith(`/operations/${sid}/${requestId}`)) return json({ sessionId: sid,
      requestId, status: 'completed', text: 'Saved read', stopReason: 'end_turn',
      hops: [], modeCapability: adminMode, replayed: true, cards: [], systemConfigRead: descriptor });
    if (url.endsWith(`/system/config/operations/${sid}/${requestId}/${opId}`)) return json({
      operationId: opId, requestSha256: descriptor.requestSha256, state: 'completed',
      receipt: { operationId: opId, requestSha256: descriptor.requestSha256,
        status: 'completed', readResult: { ...result } } });
    if (url.endsWith('/policy/instruction/assessment-retry')) {
      expect(options.method).toBe('POST');
      expect(JSON.parse(options.body)).toEqual({ sessionId: sid, requestId });
      return json({ completed: false, status: 'ineligible', modelEvaluated: false });
    }
    throw Error(`Unexpected ${url}`);
  });
  await act(async () => { root.render(<Probe transport={transport} role="admin" />); });
  await act(async () => { await Promise.resolve(); await Promise.resolve(); });
  expect(current.turns[0]).toMatchObject({ user: 'Saved role assistant request', status: 'done',
    systemConfigRead: { kind: 'content', content } });
  let checked;
  await act(async () => { checked = await current.checkSavedPolicyInstructionAssessment({ sessionId: sid, requestId }); });
  expect(checked).toEqual({ kind: 'ineligible', status: 'ineligible' });
  expect(transport.mock.calls.map(([url]) => url)).toEqual([
    `/api/secureshop/agents/admin/assistant/operations/${sid}/${requestId}`,
    `/api/secureshop/agents/admin/assistant/system/config/operations/${sid}/${requestId}/${opId}`,
    '/api/secureshop/agents/admin/assistant/policy/instruction/assessment-retry',
  ]);
  expect(transport.mock.calls.some(([url]) => url.endsWith('/chat'))).toBe(false);
});

test('admin restart review hydrates only from an exact completed saved turn', async () => {
  const adminMode = { version: 1, featureId: 'admin_assistant',
    policyVersion: 'owned-admin-read-and-confirmation-v1', effectiveMode: 'fixed',
    scope: { kind: 'launch_feature', id: 'admin_assistant' } };
  const outerMode = { scope: { id: 'admin_assistant', kind: 'launch_feature' },
    effectiveMode: 'fixed', policyVersion: 'owned-admin-read-and-confirmation-v1',
    featureId: 'admin_assistant', version: 1 };
  const context = { scope: { launchId: webcrypto.randomUUID(), scenarioId: webcrypto.randomUUID(),
    generation: 1, platformOwnerId: 17, platformSessionId: 19 },
  persona: { id: 23, role: 'admin' },
  personaSession: { sessionId: webcrypto.randomUUID(), authorityVersion: '1' } };
  const targetId = webcrypto.randomUUID();
  const transport = jest.fn(async (url, options) => {
    if (url.endsWith('/session')) return json({ sessionId: sid });
    if (url.endsWith('/chat')) return stream(JSON.parse(options.body).requestId, true, [], adminMode);
    if (url.includes('/operations/')) {
      const requestId = url.split('/').at(-1);
      const source = { sessionId: sid, requestId };
      const proposal = projectRoleSystemRestartProposal(createRoleSystemRestartProposal({
        context, administration: { restartCapability: RESTART_CAPABILITY, targetId },
        source, origin: { step: 1, callId: 'restart-prepare' }, name: 'owned service',
        modeCapability: adminMode,
      }), source);
      return json({ sessionId: sid, requestId, status: 'completed', text: 'Review restart',
        stopReason: 'end_turn', hops: [], modeCapability: outerMode, replayed: true,
        cards: [], systemRestartProposal: proposal });
    }
    throw Error(`Unexpected ${url}`);
  });
  await act(async () => root.render(<Probe role="admin" transport={transport} />));
  await act(async () => { expect(await current.send('Prepare a restart')).toBe(true); });
  expect(current.turns[0].systemRestartProposal.name).toBe('owned service');
  expect(current.turns[0].systemRestartProposal.targetId).toBe(targetId);
  expect(clearRoleAssistantReference).toHaveBeenCalledTimes(1);
});

test('admin diagnostic review hydrates the distinct feature-mode proposal from protected turn', async () => {
  const adminMode = { version: 1, featureId: 'admin_assistant',
    policyVersion: 'owned-admin-read-and-confirmation-v1', effectiveMode: 'fixed',
    scope: { kind: 'launch_feature', id: 'admin_assistant' } };
  const diagnosticMode = { version: 1, featureId: 'system_diagnostic',
    policyVersion: 'owned-system-diagnostic-shell-v1', effectiveMode: 'vuln',
    scope: { kind: 'launch_feature', id: 'system_diagnostic' } };
  const hash = value => createHash('sha256').update(value).digest('hex');
  const canonical = value => value && typeof value === 'object'
    ? `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`
    : JSON.stringify(value);
  const proposalId = 'cccccccc-cccc-5ccc-8ccc-cccccccccccc';
  const request = { operationId: proposalId, cmd_template: 'echo', args: 'reviewed literal' };
  const body = { version: 1, proposalId, action: 'system_diagnostic',
    cmd_template: request.cmd_template, args: request.args, scopeKey: 'a'.repeat(64),
    diagnosticCapability: 'secureshop-owned-system-diagnostic.v1',
    sourceSnapshotSha256: 'b'.repeat(64), modeCapability: diagnosticMode,
    requestSha256: hash(JSON.stringify({ version: 'secureshop-owned-system-diagnostic.v1', request })) };
  const proposal = { ...body, proposalSha256: hash(canonical(body)) };
  const transport = jest.fn(async (url, options) => {
    if (url.endsWith('/session')) return json({ sessionId: sid });
    if (url.endsWith('/chat')) return stream(JSON.parse(options.body).requestId, true, [], adminMode);
    if (url.includes('/operations/')) return json({ sessionId: sid,
      requestId: url.split('/').at(-1), status: 'completed', text: 'Review proposed diagnostic',
      stopReason: 'end_turn', hops: [], modeCapability: adminMode, replayed: true,
      cards: [], systemDiagnosticProposal: proposal });
    throw Error(`Unexpected ${url}`);
  });
  await act(async () => root.render(<Probe role="admin" transport={transport} />));
  await act(async () => { expect(await current.send('Prepare a diagnostic')).toBe(true); });
  expect(current.turns[0].systemDiagnosticProposal).toEqual(proposal);
  expect(clearRoleAssistantReference).toHaveBeenCalledTimes(1);
});

test('admin audit Run proposal hydrates from the actual saved server projection', async () => {
  globalThis.structuredClone ||= value => JSON.parse(JSON.stringify(value));
  const adminMode = { version: 1, featureId: 'admin_assistant',
    policyVersion: 'owned-admin-read-and-confirmation-v1', effectiveMode: 'fixed',
    scope: { kind: 'launch_feature', id: 'admin_assistant' } };
  const auditMode = { version: 1, featureId: 'audit',
    policyVersion: 'raw-audit-query-disabled-v1', effectiveMode: 'fixed',
    scope: { kind: 'launch_feature', id: 'audit' } };
  const context = { scope: { launchId: webcrypto.randomUUID(), scenarioId: webcrypto.randomUUID(),
    generation: 1, platformOwnerId: 17, platformSessionId: 19 },
  persona: { id: 23, role: 'admin' },
  personaSession: { sessionId: webcrypto.randomUUID(), authorityVersion: '1' } };
  const transport = jest.fn(async (url, options) => {
    if (url.endsWith('/session')) return json({ sessionId: sid });
    if (url.endsWith('/chat')) return stream(JSON.parse(options.body).requestId, true, [], adminMode);
    if (url.includes('/operations/')) {
      const requestId = url.split('/').at(-1), source = { sessionId: sid, requestId };
      const proposal = auditJobContract.create({ context, source,
        origin: { step: 1, callId: 'audit-prepare' }, action: 'agent',
        input: { message: 'Inspect owned audit' }, sessionId: webcrypto.randomUUID(),
        modeCapability: auditMode });
      return json({ sessionId: sid, requestId, status: 'completed', text: 'Review audit Run',
        stopReason: 'end_turn', hops: [], replayed: true, modeCapability: adminMode,
        cards: [], auditJobProposal: proposal });
    }
    throw Error(`Unexpected ${url}`);
  });
  await act(async () => root.render(<Probe role="admin" transport={transport} />));
  await act(async () => { expect(await current.send('Prepare audit Run')).toBe(true); });
  expect(current.turns[0].auditJobProposal.input.message).toBe('Inspect owned audit');
  expect(current.turns[0].auditJobProposal.source.requestId).toBe(current.turns[0].requestId);
  expect(clearRoleAssistantReference).toHaveBeenCalledTimes(1);
});

test('named ACL permission choice accepts only an exact current admin card and typed intent', async () => {
  const adminMode = { version: 1, featureId: 'admin_assistant',
    policyVersion: 'owned-admin-read-and-confirmation-v1', effectiveMode: 'vuln',
    scope: { kind: 'launch_feature', id: 'admin_assistant' } };
  const base = { scopeKey: 'owned-scope', expectedVersion: '4', registrySha256: 'a'.repeat(64),
    toolKey: 'audit.search_by_user', role: 'admin', allowed: false, enforcement: true };
  const aclChoiceId = webcrypto.randomUUID();
  const card = { version: 1, kind: 'admin_acl_permission', choiceId: aclChoiceId,
    title: base.toolKey, detail: 'admin · Denied · enforcement on' };
  let first = true;
  const transport = jest.fn(async (url, options) => {
    if (url.endsWith('/session')) return json({ sessionId: sid });
    if (url.endsWith('/chat')) return stream(JSON.parse(options.body).requestId, true,
      first ? [card] : [], adminMode);
    if (url.includes('/operations/')) {
      const requestId = url.split('/').at(-1);
      if (first) { first = false; return json({ sessionId: sid, requestId,
        status: 'completed', text: 'Permission choices', stopReason: 'end_turn',
        hops: [], replayed: true, modeCapability: adminMode, cards: [card],
        aclPage: { page: 1, total: 1, nextPage: null, search: '' } }); }
      const source = { sessionId: sid, requestId };
      const proposal = aclContract.projectRoleAclProposal(aclContract.createRoleAclProposal({
        ...base, source, origin: { step: 1, callId: 'acl-prepare' }, action: 'permission',
        selected: { ...base, choiceId: aclChoiceId, snapshotSha256: aclContract.aclChoiceSnapshot(base) },
        before: { allowed: false, enforcement: true },
        after: { allowed: true, enforcement: true }, modeCapability: adminMode,
      }), source);
      return json({ sessionId: sid, requestId, status: 'completed', text: 'Review Allow',
        stopReason: 'end_turn', hops: [], replayed: true, modeCapability: adminMode,
        cards: [], aclProposal: proposal });
    }
    throw Error(`Unexpected ${url}`);
  });
  await act(async () => root.render(<Probe role="admin" transport={transport} />));
  await act(async () => { expect(await current.send('Find permission')).toBe(true); });
  expect(current.turns[0].aclPage.total).toBe(1);
  await act(async () => { expect(await current.send('Review allowing this permission.',
    { choiceId: aclChoiceId, intent: 'acl_allow' })).toBe(true); });
  const bodies = transport.mock.calls.filter(([url]) => url.endsWith('/chat'))
    .map(([, options]) => JSON.parse(options.body));
  expect(bodies[1].selection).toEqual({ choiceId: aclChoiceId, intent: 'acl_allow' });
  expect(current.turns[1].aclProposal.action).toBe('permission');
  await act(async () => { expect(await current.send('Try stale choice',
    { choiceId: aclChoiceId, intent: 'acl_deny' })).toBe(false); });
});

test.each(['merchant', 'admin'])('%s accepts a consecutive send while terminal reader cancellation never settles', async role => {
  const eventMode = { ...mode, featureId: `${role}_assistant`,
    scope: { kind: 'launch_feature', id: `${role}_assistant` } };
  const calls = [], cancel = jest.fn(() => new Promise(() => {}));
  const transport = jest.fn(async (url, options = {}) => {
    calls.push({ url, options });
    if (url.endsWith('/session')) return json({ sessionId: sid });
    if (url.endsWith('/chat')) {
      const response = stream(JSON.parse(options.body).requestId, true, [], eventMode);
      const reader = response.body.getReader(); reader.cancel = cancel;
      response.body.getReader = () => reader;
      return response;
    }
    if (url.includes('/operations/')) return json({ sessionId: sid,
      requestId: url.split('/').at(-1), status: 'completed', text: 'Verified saved result',
      stopReason: 'end_turn', hops: [], cards: [], replayed: true, modeCapability: eventMode });
    throw new Error(`Unexpected ${url}`);
  });
  await act(async () => root.render(<Probe role={role} transport={transport} />));
  let firstResult, first;
  await act(async () => {
    first = current.send('First question').then(value => { firstResult = value; });
    await new Promise(resolve => setTimeout(resolve, 0));
  });
  expect(firstResult).toBe(true); await first;
  expect(current.status).toBe('idle'); expect(current.pending).toBeNull();
  await act(async () => { expect(await current.send('Second question')).toBe(true); });
  const posted = calls.filter(call => call.url.endsWith('/chat')).map(call => JSON.parse(call.options.body));
  expect(posted.map(value => value.message)).toEqual(['First question', 'Second question']);
  expect(posted[0].sessionId).toBe(posted[1].sessionId);
  expect(posted[0].requestId).not.toBe(posted[1].requestId);
  expect(clearRoleAssistantReference).toHaveBeenCalledTimes(2);
  expect(cancel).toHaveBeenCalledTimes(2);
});

test('late terminal cancellation cannot release the guard or pending reference of a newer turn', async () => {
  let rejectOldCancellation, completeSecondRead, firstResult, secondId;
  const cancel = jest.fn(() => new Promise((_, reject) => { rejectOldCancellation = reject; }));
  const calls = [];
  const transport = jest.fn(async (url, options = {}) => {
    calls.push({ url, options });
    if (url.endsWith('/session')) return json({ sessionId: sid });
    if (url.endsWith('/chat')) {
      const id = JSON.parse(options.body).requestId;
      if (calls.filter(call => call.url.endsWith('/chat')).length === 1) {
        const response = stream(id, true, [], mode), reader = response.body.getReader();
        reader.cancel = cancel; response.body.getReader = () => reader; return response;
      }
      secondId = id;
      return { ok: true, headers: { get: () => 'text/event-stream' }, body: { getReader: () => ({
        read: () => new Promise(resolve => { completeSecondRead = resolve; }), cancel: async () => {},
      }) } };
    }
    if (url.includes('/operations/')) return json({ sessionId: sid,
      requestId: url.split('/').at(-1), status: 'completed', text: 'Verified saved result',
      stopReason: 'end_turn', hops: [], cards: [], replayed: true, modeCapability: mode });
    throw new Error(`Unexpected ${url}`);
  });
  await act(async () => root.render(<Probe transport={transport} />));
  await act(async () => {
    current.send('First question').then(value => { firstResult = value; });
    await new Promise(resolve => setTimeout(resolve, 0));
  });
  expect(firstResult).toBe(true);
  let second;
  await act(async () => { second = current.send('Second question'); await Promise.resolve(); });
  expect(completeSecondRead).toEqual(expect.any(Function));
  expect(current.pending.requestId).toBe(secondId);
  await act(async () => { rejectOldCancellation(new Error('Late local cleanup failure')); await Promise.resolve(); });
  expect(current.pending.requestId).toBe(secondId);
  expect(current.status).toBe('thinking');
  await act(async () => { expect(await current.send('Do not overlap the second question')).toBe(false); });
  expect(calls.filter(call => call.url.endsWith('/chat'))).toHaveLength(2);
  await act(async () => {
    completeSecondRead({ done: false, value: new TextEncoder().encode(
      `event: done\ndata: ${JSON.stringify({ sessionId: sid, requestId: secondId,
        stopReason: 'end_turn', modeCapability: mode })}\n\n`) });
    expect(await second).toBe(true);
  });
  expect(current.pending).toBeNull(); expect(current.status).toBe('idle');
  expect(clearRoleAssistantReference).toHaveBeenCalledTimes(2);
});

test.each(['merchant', 'admin'])('%s can recover an unconfirmed terminal with a never-settling local cancel', async role => {
  const eventMode = { ...mode, featureId: `${role}_assistant`,
    scope: { kind: 'launch_feature', id: `${role}_assistant` } };
  const calls = [], cancel = jest.fn(() => new Promise(() => {}));
  let reads = 0, sendResult;
  const transport = jest.fn(async (url, options = {}) => {
    calls.push({ url, options });
    if (url.endsWith('/session')) return json({ sessionId: sid });
    if (url.endsWith('/chat')) {
      const response = stream(JSON.parse(options.body).requestId, true, [], eventMode);
      const reader = response.body.getReader(); reader.cancel = cancel;
      response.body.getReader = () => reader; return response;
    }
    if (url.includes('/operations/')) {
      const requestId = url.split('/').at(-1);
      return ++reads === 1 ? json({ sessionId: sid, requestId, status: 'unconfirmed' })
        : json({ sessionId: sid, requestId, status: 'completed', text: 'Recovered saved result',
          stopReason: 'end_turn', hops: [], cards: [], replayed: true, modeCapability: eventMode });
    }
    throw new Error(`Unexpected ${url}`);
  });
  await act(async () => root.render(<Probe role={role} transport={transport} />));
  await act(async () => {
    current.send('Original question').then(value => { sendResult = value; });
    await new Promise(resolve => setTimeout(resolve, 0));
  });
  expect(sendResult).toBe(false); expect(current.status).toBe('unresolved');
  const original = current.pending;
  expect(original.requestId).toBe(saveRoleAssistantReference.mock.calls[0][0].requestId);
  expect(clearRoleAssistantReference).not.toHaveBeenCalled();
  expect(saveRoleAssistantCompletedReference).not.toHaveBeenCalled();
  expect(current.canStopWatching).toBe(false);
  await act(async () => { expect(await current.send('Do not repeat the unresolved question')).toBe(false); });
  expect(calls.filter(call => call.url.endsWith('/chat'))).toHaveLength(1);
  await act(async () => { expect(await current.recover()).toBe(true); });
  const gets = calls.filter(call => call.url.includes('/operations/'));
  expect(gets).toHaveLength(2); expect(gets[0].url).toBe(gets[1].url);
  expect(gets[1].url).toContain(`/operations/${original.sessionId}/${original.requestId}`);
  expect(gets[1].options.method ?? 'GET').toBe('GET');
  expect(gets[1].options.body).toBeUndefined();
  expect(calls.filter(call => call.url.endsWith('/chat'))).toHaveLength(1);
  expect(current.pending).toBeNull(); expect(current.status).toBe('idle');
  expect(current.turns[0].reply).toBe('Recovered saved result');
  expect(clearRoleAssistantReference).toHaveBeenCalledTimes(1);
  expect(cancel).toHaveBeenCalledTimes(1);
});


test('admin lookup saved hydration retains only its closed descriptor and exact original final response', async () => {
  const lookupMode = { version: 1, featureId: 'admin_assistant', policyVersion: 'owned-admin-read-and-confirmation-v1',
    effectiveMode: 'vuln', scope: { kind: 'launch_feature', id: 'admin_assistant' } };
  const userLookup = { version: 1, username: 'student_customer', status: 'complete', assessmentReady: true };
  const original = 'The original configured model final response.';
  let posts = 0;
  const transport = jest.fn(async (url, options) => {
    if (url.endsWith('/session')) return json({ sessionId: sid });
    if (url.endsWith('/chat')) { posts++; return stream(JSON.parse(options.body).requestId, true, [], lookupMode); }
    if (url.includes('/operations/')) return json({ sessionId: sid, requestId: url.split('/').at(-1),
      status: 'completed', text: original, stopReason: 'end_turn', hops: [], modeCapability: lookupMode,
      replayed: true, cards: [], userLookup });
    throw Error(`Unexpected ${url}`);
  });
  await act(async () => root.render(<Probe transport={transport} role="admin" />));
  await act(async () => expect(await current.send('Look up the teaching customer')).toBe(true));
  expect(current.turns[0]).toMatchObject({ reply: original, userLookup });
  expect(posts).toBe(1);
  const saved = saveRoleAssistantCompletedReference.mock.calls.at(-1)[0];
  await act(async () => root.unmount()); root = createRoot(node);
  readRoleAssistantCompletedReference.mockReturnValue(saved);
  await act(async () => root.render(<Probe transport={transport} role="admin" />));
  expect(current.turns[0]).toMatchObject({ reply: original, userLookup });
  expect(posts).toBe(1);
});
