import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import { webcrypto } from 'node:crypto';
import PracticeProfileUpdate from './PracticeProfileUpdate.jsx';
import { attachShopStorage, SHOP_PROFILE_KEY } from '../utils/shopStorage.mjs';
import { profileFieldsDigest, profileRequestDigest } from '../utils/profileOperation.mjs';

const id = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const sessionId = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const requestId = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc';
const scope = 'd'.repeat(64), snapshot = 'e'.repeat(64), nextSnapshot = 'f'.repeat(64);
const before = { fullName: 'Old Name', email: 'old@example.test', phone: null };
const after = { ...before, fullName: 'New Name' };
const mode = { version: 1, featureId: 'customer_chat', policyVersion: 'customer-chat-v1',
  effectiveMode: 'fixed', scope: { kind: 'launch_feature', id: 'customer_chat' } };
const json = value => ({ ok: true, status: 200, json: async () => value });
const settle = () => act(async () => { await new Promise(resolve => setTimeout(resolve, 0)); });
let node, root, values, detach;
beforeEach(() => {
  globalThis.IS_REACT_ACT_ENVIRONMENT = true;
  Object.defineProperty(globalThis, 'crypto', { configurable: true,
    value: { subtle: webcrypto.subtle, randomUUID: () => id } });
  values = new Map();
  detach = attachShopStorage({ getItem: key => values.get(key) ?? null,
    setItem: (key, value) => values.set(key, value),
    removeItem: key => values.delete(key), flush: async () => {} });
  node = document.createElement('div'); document.body.append(node); root = createRoot(node);
});
afterEach(async () => { await act(async () => root.unmount()); detach(); node.remove(); });
const click = text => act(async () => {
  const button = [...node.querySelectorAll('button')].find(item => item.textContent === text);
  if (!button) throw Error(`Missing ${text}`);
  button.click();
});

test('Account saves only after parent ACK and exact GET, then refreshes; parent stores no PII', async () => {
  let posts = 0, committed = false, confirmed = 0;
  const fieldsSha256 = await profileFieldsDigest(after);
  const requestSha256 = await profileRequestDigest(id, snapshot, after);
  const transport = jest.fn(async (url, options = {}) => {
    if (url.endsWith('/profile-form')) return json({ version: 1, fields: before,
      expectedSnapshotSha256: snapshot, scopeKey: scope });
    if (url.includes(`/operations/${id}`)) return json(committed
      ? { scopeKey: scope, operationId: id, status: 'completed', receipt: { version: 1,
        operationId: id, kind: 'profile.update', status: 'completed', replayed: true,
        result: { fieldsSha256, profileSnapshotSha256: nextSnapshot } } }
      : { scopeKey: scope, operationId: id, status: 'not_found' });
    if (url.endsWith('/commerce/profile') && options.method === 'POST') {
      posts += 1;
      expect(JSON.parse(options.body)).toEqual({ operationId: id,
        expectedSnapshotSha256: snapshot, fields: after });
      expect(JSON.parse(values.get(SHOP_PROFILE_KEY))).toEqual({ version: 1,
        operationId: id, scopeKey: scope, expectedSnapshotSha256: snapshot,
        fieldsSha256, requestSha256, sessionId: null, requestId: null });
      expect(values.get(SHOP_PROFILE_KEY)).not.toContain('New Name');
      committed = true; throw Error('response lost');
    }
    throw Error(`Unexpected ${url}`);
  });
  await act(async () => root.render(<PracticeProfileUpdate entryPoint="account" authorityKey="owner-A"
    transport={transport} onConfirmed={() => { confirmed += 1; }} />)); await settle();
  const input = node.querySelector('input[aria-label="Full name"]');
  await act(async () => { const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set;
    setter.call(input, 'New Name'); input.dispatchEvent(new Event('input', { bubbles: true })); });
  await click('Review profile');
  expect(node.querySelector('[aria-label="Profile changes to confirm"]').textContent).toContain('Old Name → New Name');
  await click('Confirm profile update');
  for (let i = 0; i < 12 && posts === 0; i += 1) await settle();
  expect(posts).toBe(1); expect(confirmed).toBe(1);
  expect(values.has(SHOP_PROFILE_KEY)).toBe(false);
  expect(node.textContent).toContain('Profile updated.');
});

test('completed chat proposal requires exact source GET and leaves unknown effect GET-only', async () => {
  const requestSha256 = await profileRequestDigest(id, snapshot, after);
  const proposal = { version: 1, proposalId: id, scopeKey: scope,
    expectedSnapshotSha256: snapshot, requestSha256, before, after, patch: { fullName: 'New Name' } };
  let posts = 0;
  const transport = jest.fn(async (url, options = {}) => {
    if (url.includes(`/operations/${id}`) && !url.includes('/agents/'))
      return json({ scopeKey: scope, operationId: id, status: 'not_found' });
    if (url.includes(`/agents/customer/operations/${sessionId}/${requestId}`))
      return json({ sessionId, requestId, status: 'completed', replayed: true,
        stopReason: 'end_turn', modeCapability: mode, profileProposal: proposal });
    if (url.endsWith('/profile/confirm') && options.method === 'POST') {
      posts += 1;
      expect(JSON.parse(options.body)).toEqual({ sessionId, requestId, proposalId: id });
      return { ok: false, status: 503 };
    }
    throw Error(`Unexpected ${url}`);
  });
  await act(async () => root.render(<PracticeProfileUpdate proposal={proposal} authorityKey="turn-A"
    sourceSessionId={sessionId} sourceRequestId={requestId} transport={transport} />));
  await click('Confirm profile update');
  for (let i = 0; i < 12 && posts === 0; i += 1) await settle();
  expect(posts).toBe(1);
  expect(values.has(SHOP_PROFILE_KEY)).toBe(true);
  expect(node.textContent).toContain('will not be retried');
  await click('Check saved profile'); await settle();
  expect(posts).toBe(1);
});

test('chat does not invent a proposal without a completed saved turn', async () => {
  await act(async () => root.render(<PracticeProfileUpdate proposal={null} authorityKey="turn-A"
    transport={jest.fn()} />));
  expect(node.querySelector('button')).toBeNull();
});

test.each([
  ['completed', 'Profile updated.', true],
  ['stale', 'No update was saved. Start a fresh review.', false],
])('a ref-only reload keeps the %s exact GET outcome visible until authority changes', async (
  outcome, expectedText, shouldRefresh,
) => {
  const fieldsSha256 = await profileFieldsDigest(after);
  const requestSha256 = await profileRequestDigest(id, snapshot, after);
  const saved = { version: 1, operationId: id, scopeKey: scope,
    expectedSnapshotSha256: snapshot, fieldsSha256, requestSha256, sessionId, requestId };
  values.set(SHOP_PROFILE_KEY, JSON.stringify(saved));
  let refreshes = 0, posts = 0;
  const transport = jest.fn(async (url, options = {}) => {
    if (url === `/api/secureshop/customer/commerce/operations/${id}`) return json({
      scopeKey: scope, operationId: id, status: 'completed', receipt: {
        version: 1, operationId: id, kind: 'profile.update', status: outcome, replayed: true,
        result: outcome === 'stale' ? { fieldsSha256 }
          : { fieldsSha256, profileSnapshotSha256: nextSnapshot },
      },
    });
    if (options.method === 'POST') posts += 1;
    throw Error(`Unexpected ${url}`);
  });
  const render = authorityKey => root.render(<PracticeProfileUpdate proposal={null}
    authorityKey={authorityKey} transport={transport}
    onConfirmed={() => { refreshes += 1; }} />);
  await act(async () => render('turn-reload'));
  expect(node.textContent).toContain('Check saved profile');
  await click('Check saved profile'); await settle();
  expect(values.has(SHOP_PROFILE_KEY)).toBe(false);
  expect(node.querySelector('[aria-label="Profile update review"]')).not.toBeNull();
  expect(node.textContent).toContain(expectedText);
  expect(node.textContent).not.toContain('Confirm profile update');
  expect(posts).toBe(0);
  expect(refreshes).toBe(shouldRefresh ? 1 : 0);
  await act(async () => render('turn-reload'));
  expect(node.textContent).toContain(expectedText);
  await act(async () => render('new-authority'));
  expect(node.querySelector('[aria-label="Profile update review"]')).toBeNull();
});

test('a replaced parent reference during exact preflight prevents the profile POST', async () => {
  let resolveRead, posts = 0;
  const pendingRead = new Promise(resolve => { resolveRead = resolve; });
  const transport = jest.fn(async (url, options = {}) => {
    if (url.endsWith('/profile-form')) return json({ version: 1, fields: before,
      expectedSnapshotSha256: snapshot, scopeKey: scope });
    if (url.includes(`/operations/${id}`)) return pendingRead;
    if (url.endsWith('/commerce/profile') && options.method === 'POST') { posts += 1; return json({}); }
    throw Error(`Unexpected ${url}`);
  });
  await act(async () => root.render(<PracticeProfileUpdate entryPoint="account" authorityKey="owner-A"
    transport={transport} />)); await settle();
  await click('Review profile');
  await click('Confirm profile update');
  await settle();
  expect(values.has(SHOP_PROFILE_KEY)).toBe(true);
  const old = JSON.parse(values.get(SHOP_PROFILE_KEY));
  values.set(SHOP_PROFILE_KEY, JSON.stringify({ ...old,
    operationId: 'ffffffff-ffff-4fff-8fff-ffffffffffff' }));
  await act(async () => resolveRead(json({ scopeKey: scope, operationId: id, status: 'not_found' })));
  await settle();
  expect(posts).toBe(0);
  expect(JSON.parse(values.get(SHOP_PROFILE_KEY)).operationId).not.toBe(id);
  expect(node.textContent).toContain('Saved profile reference changed');
});
