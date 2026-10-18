import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import MerchantListingEditConfirmation from './MerchantListingEditConfirmation.jsx';
import { attachShopStorage, SHOP_LISTING_EDIT_KEY } from '../utils/shopStorage.mjs';
import { listingEditRequestDigest } from '../pages/merchant/listingEditOperation.mjs';

const { webcrypto } = require('node:crypto');
const sessionId = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const requestId = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const proposalId = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc';
const choiceId = 'dddddddd-dddd-4ddd-8ddd-dddddddddddd';
const scopeKey = 'a'.repeat(64), snapshot = 'b'.repeat(64);
const chatMode = { version: 1, featureId: 'merchant_assistant', effectiveMode: 'vuln',
  policyVersion: '1', scope: { kind: 'launch_feature', id: 'merchant_assistant' } };
const before = { name: 'Practice mug', description: 'old', descriptionHtml: '<p>old</p>',
  price: 12.5, category: 'home', templateSource: null, imageUrl: null };
let proposal;
const json = value => ({ ok: true, status: 200, json: async () => value });
let root, node, values, release;
const render = (transport, sourceProposal = proposal, authorityKey = 'merchant') => act(async () => root.render(
  <MerchantListingEditConfirmation proposal={sourceProposal} sessionId={sourceProposal ? sessionId : null}
    requestId={sourceProposal ? requestId : null} authorityKey={authorityKey} transport={transport} />));
const settle = () => act(async () => { await new Promise(resolve => setTimeout(resolve, 0)); });

beforeEach(async () => {
  globalThis.IS_REACT_ACT_ENVIRONMENT = true;
  Object.defineProperty(globalThis, 'crypto', { value: webcrypto, configurable: true });
  const patch = { description: 'new' }, after = { ...before, ...patch, descriptionHtml: null };
  const preview = { version: 1, productId: 7, before, after, patch, catalogRevision: '4',
    expectedSnapshotSha256: snapshot, scopeKey, invalidatesGeneratedHtml: true };
  preview.requestSha256 = await listingEditRequestDigest(preview);
  proposal = { version: 1, proposalId, product: { choiceId, name: 'Practice mug' }, preview };
  node = document.createElement('div'); document.body.append(node); root = createRoot(node); values = new Map();
  release = attachShopStorage({ getItem: key => values.get(key) ?? null,
    setItem: (key, value) => values.set(key, value), removeItem: key => values.delete(key), flush: async () => {} });
});
afterEach(async () => { await act(async () => root.unmount()); release(); node.remove(); });

function source() { return json({ sessionId, requestId, status: 'completed', replayed: true,
  stopReason: 'end_turn', modeCapability: chatMode, listingProposal: proposal }); }
function receipt() { return { version: 1, operationId: proposalId, productId: 7, status: 'completed',
  scopeKey, catalogRevision: '4', requestSha256: proposal.preview.requestSha256,
  beforeSha256: snapshot, afterSha256: 'd'.repeat(64), receiptSha256: 'e'.repeat(64), replayed: false }; }

test('shows the immutable saved before/after preview as text and recovers a lost response by exact GET only', async () => {
  let posts = 0, completed = false;
  const transport = jest.fn(async (url, options = {}) => {
    if (url.includes(`/assistant/operations/${sessionId}/${requestId}`)) return source();
    if (url.endsWith(`/listing/operations/${proposalId}`)) return json(completed ? receipt()
      : { operationId: proposalId, status: 'not_found', scopeKey });
    if (url.endsWith('/listing/confirm')) { posts++; expect(JSON.parse(options.body)).toEqual({ sessionId, requestId, proposalId }); completed = true; throw Error('lost'); }
    throw Error(`Unexpected ${url}`);
  });
  await render(transport); await settle();
  expect(node.textContent).toContain('Current listing');
  expect(node.querySelector('[data-testid="listing-current listing-name"]').textContent).toBe('Practice mug');
  expect(node.querySelector('[data-testid="listing-proposed listing-name"]').textContent).toBe('Practice mug');
  expect(node.textContent).toContain('Description');
  expect(node.textContent).not.toContain('category: home');
  expect(node.querySelector('details summary').textContent).toBe('Technical listing values');
  expect(node.textContent).toContain('<p>old</p>');
  expect(node.querySelector('p img')).toBeNull();
  await act(async () => node.querySelector('button').click()); await settle();
  expect(posts).toBe(1);
  expect(values.has(SHOP_LISTING_EDIT_KEY)).toBe(false);
  expect(node.textContent).toContain('Listing edit confirmed from the saved result.');
  expect(transport.mock.calls.filter(([url]) => url.endsWith('/listing/confirm'))).toHaveLength(1);
});

test('a changed source proposal blocks the POST before saving a reference', async () => {
  const changed = { ...proposal, preview: { ...proposal.preview, catalogRevision: '5' } };
  const transport = jest.fn(async url => {
    if (url.includes(`/assistant/operations/${sessionId}/${requestId}`)) return json({ ...await source().json(), listingProposal: changed });
    throw Error(`Unexpected ${url}`);
  });
  await render(transport); await settle();
  await act(async () => node.querySelector('button').click()); await settle();
  expect(values.has(SHOP_LISTING_EDIT_KEY)).toBe(false);
  expect(node.textContent).toContain('Saved listing proposal is invalid.');
  expect(transport.mock.calls.some(([url]) => url.endsWith('/listing/confirm'))).toBe(false);
});

test('a post-confirm absence retains the reference and makes recovery GET-only', async () => {
  let posts = 0;
  const transport = jest.fn(async (url, options = {}) => {
    if (url.includes(`/assistant/operations/${sessionId}/${requestId}`)) return source();
    if (url.endsWith(`/listing/operations/${proposalId}`)) return json({ operationId: proposalId,
      status: 'not_found', scopeKey });
    if (url.endsWith('/listing/confirm')) { posts++; expect(JSON.parse(options.body)).toEqual({ sessionId, requestId, proposalId }); return { ok: false, status: 503, json: async () => ({}) }; }
    throw Error(`Unexpected ${url}`);
  });
  await render(transport); await settle();
  await act(async () => node.querySelector('button').click()); await settle();
  expect(posts).toBe(1);
  expect(values.has(SHOP_LISTING_EDIT_KEY)).toBe(true);
  expect(node.textContent).toContain('confirmation will not be retried');
  expect(node.querySelector('button').textContent).toBe('Check saved listing edit');
  await act(async () => node.querySelector('button').click()); await settle();
  expect(posts).toBe(1);
});

test('late source hydration preserves an in-flight saved operation GET', async () => {
  values.set(SHOP_LISTING_EDIT_KEY, JSON.stringify({ version: 1, scopeKey,
    operationId: proposalId, productId: 7, catalogRevision: '4',
    requestSha256: proposal.preview.requestSha256, expectedSnapshotSha256: snapshot }));
  let finishRead, savedSignal;
  const transport = jest.fn((url, options = {}) => {
    if (url.endsWith(`/listing/operations/${proposalId}`)) {
      savedSignal = options.signal;
      return new Promise(resolve => { finishRead = resolve; });
    }
    throw Error(`Unexpected ${url}`);
  });
  await render(transport, null); await settle();
  await act(async () => node.querySelector('button').click());
  expect(finishRead).toBeDefined();
  await render(transport, proposal);
  expect(savedSignal.aborted).toBe(false);
  await act(async () => finishRead(json(receipt())));
  expect(node.textContent).toContain('Listing edit confirmed from the saved result.');
  expect(transport.mock.calls).toHaveLength(1);
  expect(values.has(SHOP_LISTING_EDIT_KEY)).toBe(false);
});

test('authority rotation aborts a saved operation GET and ignores its late result', async () => {
  values.set(SHOP_LISTING_EDIT_KEY, JSON.stringify({ version: 1, scopeKey,
    operationId: proposalId, productId: 7, catalogRevision: '4',
    requestSha256: proposal.preview.requestSha256, expectedSnapshotSha256: snapshot }));
  let finishRead, savedSignal;
  const transport = jest.fn((url, options = {}) => {
    if (url.endsWith(`/listing/operations/${proposalId}`)) {
      savedSignal = options.signal;
      return new Promise(resolve => { finishRead = resolve; });
    }
    throw Error(`Unexpected ${url}`);
  });
  await render(transport, null); await settle();
  await act(async () => node.querySelector('button').click());
  await render(transport, null, 'rotated-merchant');
  expect(savedSignal.aborted).toBe(true);
  await act(async () => finishRead(json(receipt())));
  expect(values.has(SHOP_LISTING_EDIT_KEY)).toBe(true);
  expect(node.textContent).not.toContain('Listing edit confirmed from the saved result.');
});

test('a different proposal fences an uncommitted listing edit preflight', async () => {
  let finishSource;
  const transport = jest.fn(url => {
    if (url.includes(`/assistant/operations/${sessionId}/${requestId}`))
      return new Promise(resolve => { finishSource = resolve; });
    throw Error(`Unexpected ${url}`);
  });
  await render(transport); await settle();
  await act(async () => node.querySelector('button').click());
  const replacement = { ...proposal, proposalId: 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee' };
  await render(transport, replacement);
  await act(async () => finishSource(source()));
  expect(values.has(SHOP_LISTING_EDIT_KEY)).toBe(false);
  expect(transport.mock.calls.some(([url]) => url.endsWith('/listing/confirm'))).toBe(false);
  expect(node.querySelector('button').disabled).toBe(false);
});

test('a new listing edit remains confirmable after the prior completed receipt clears', async () => {
  const secondId = 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee';
  const completed = new Set(), posts = [];
  const transport = jest.fn(async (url, options = {}) => {
    if (url.includes(`/assistant/operations/${sessionId}/${requestId}`)) return source();
    const operationId = url.split('/listing/operations/')[1];
    if (operationId) return json(completed.has(operationId)
      ? { ...receipt(), operationId } : { operationId, status: 'not_found', scopeKey });
    if (url.endsWith('/listing/confirm')) {
      const body = JSON.parse(options.body); posts.push(body.proposalId);
      completed.add(body.proposalId); return json({});
    }
    throw Error(`Unexpected ${url}`);
  });
  await render(transport); await settle();
  await act(async () => node.querySelector('button').click()); await settle();
  expect(posts).toEqual([proposalId]);
  proposal = { ...proposal, proposalId: secondId };
  await render(transport); await settle();
  expect(node.querySelector('button').textContent).toBe('Confirm listing edit');
  expect(node.querySelector('button').disabled).toBe(false);
  await act(async () => node.querySelector('button').click()); await settle();
  expect(posts).toEqual([proposalId, secondId]);
});
