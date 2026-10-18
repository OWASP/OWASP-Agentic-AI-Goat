import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import AdminUserConfirmation from './AdminUserConfirmation.jsx';
import { attachShopStorage, SHOP_USER_ADMIN_KEY } from '../utils/shopStorage.mjs';
import { assertSaved } from '../pages/admin/userAdminOperation.js';
let mockStandalone = false;
jest.mock('../bridge/assessmentPanelIntent.mjs', () => ({ isStandaloneShopFrame: () => mockStandalone }));
const { webcrypto } = require('node:crypto');
const { createRoleUserAdministrationProposal, projectRoleUserAdministrationProposal } =
  require('../../../../../server/services/secureshopRoleUserAdministrationProposal.js');

const sessionId = '11111111-1111-4111-8111-111111111111';
const requestId = '22222222-2222-4222-8222-222222222222';
const choiceId = '33333333-3333-4333-8333-333333333333';
const modeCapability = { version: 1, featureId: 'admin_assistant',
  policyVersion: 'owned-admin-read-and-confirmation-v1', effectiveMode: 'fixed',
  scope: { kind: 'launch_feature', id: 'admin_assistant' } };
const proposal = projectRoleUserAdministrationProposal(createRoleUserAdministrationProposal({
  sessionId, requestId, step: 1, callId: 'call-1',
  selected: { kind: 'tenant_user', choiceId, sourceId: 7, snapshotSha256: 'a'.repeat(64) },
  user: { id: 7, username: 'owned_customer', identity_kind: 'registered_account',
    role: 'customer', banned_at: null, authority_version: '4' },
  administration: { roleBan: true, scopeKey: 'owned administrator scope' },
  action: 'set_role', role: 'merchant', reason: null, modeCapability,
}), { sessionId, requestId });
const receipt = { operationId: proposal.proposalId, targetId: 7, action: 'set_role',
  role: 'merchant', version: '5' };
const json = (value, status = 200) => ({ ok: status < 400, status, json: async () => value });
let root, node, values, flush, release;
const render = (transport, currentProposal = proposal) => act(async () => root.render(
  <AdminUserConfirmation proposal={currentProposal}
    sessionId={currentProposal ? sessionId : null} requestId={currentProposal ? requestId : null}
    shopUserId={1} authorityKey="admin-token" transport={transport} />));
const settle = () => act(async () => { await new Promise(resolve => setTimeout(resolve, 0)); });
beforeEach(() => {
  mockStandalone = false;
  globalThis.IS_REACT_ACT_ENVIRONMENT = true;
  Object.defineProperty(globalThis, 'crypto', { configurable: true, value: webcrypto });
  node = document.createElement('div'); document.body.append(node); root = createRoot(node);
  values = new Map(); flush = async () => {};
  release = attachShopStorage({ getItem: key => values.get(key) ?? null,
    setItem: (key, value) => values.set(key, value), removeItem: key => values.delete(key),
    flush: () => flush() });
});
afterEach(async () => { await act(async () => root.unmount()); release(); node.remove(); });

test('reviewed role change waits for parent ACK, then lost response recovers by one exact GET', async () => {
  let acknowledge, posts = 0, committed = false;
  flush = () => new Promise(resolve => { acknowledge = resolve; });
  const transport = jest.fn(async (url, options = {}) => {
    if (url.includes('/assistant/operations/')) return json({ sessionId, requestId,
      status: 'completed', replayed: true, stopReason: 'end_turn', modeCapability,
      userAdministrationProposal: proposal });
    if (url.endsWith('/assistant/user/confirm')) {
      posts++; expect(JSON.parse(options.body)).toEqual({ sessionId, requestId,
        proposalId: proposal.proposalId });
      committed = true; throw Error('response lost');
    }
    if (url.endsWith(`/admin/users/operations/${proposal.proposalId}`)) return committed
      ? json({ ok: true, receipt }) : json({}, 404);
    throw Error(`Unexpected ${url}`);
  });
  globalThis.fetch = transport;
  await render(transport);
  expect(node.textContent).toContain('Current role: customer');
  expect(node.textContent).toContain('New role: merchant');
  await act(async () => { node.querySelector('button').click(); await Promise.resolve(); });
  await settle();
  expect(posts).toBe(0);
  expect(assertSaved({ scopeKey: proposal.scopeKey, targetId: 7, action: 'set_role',
    role: 'merchant', operationId: proposal.proposalId, expectedVersion: '4' })).toBeTruthy();
  flush = async () => {};
  await act(async () => { acknowledge(); await new Promise(resolve => setTimeout(resolve, 0)); });
  expect(posts).toBe(1);
  expect(values.has(SHOP_USER_ADMIN_KEY)).toBe(true);
  await render(transport, null);
  const check = [...node.querySelectorAll('button')].find(button => button.textContent === 'Check saved user change');
  expect(check).toBeTruthy();
  await act(async () => check.click()); await settle();
  expect(posts).toBe(1);
  expect(values.has(SHOP_USER_ADMIN_KEY)).toBe(false);
  expect(node.textContent).toContain('User change confirmed.');
});

test('replaced parent user reference after ACK stops the confirm POST', async () => {
  flush = async () => {
    const saved = JSON.parse(values.get(SHOP_USER_ADMIN_KEY));
    values.set(SHOP_USER_ADMIN_KEY, JSON.stringify({ ...saved,
      operationId: '99999999-9999-4999-8999-999999999999' }));
  };
  const transport = jest.fn(async url => {
    if (url.includes('/assistant/operations/')) return json({ sessionId, requestId,
      status: 'completed', replayed: true, stopReason: 'end_turn', modeCapability,
      userAdministrationProposal: proposal });
    throw Error(`Unexpected ${url}`);
  });
  globalThis.fetch = transport;
  await render(transport);
  await act(async () => node.querySelector('button').click()); await settle();
  expect(node.textContent).toContain('differs from the confirmed request');
  expect(transport.mock.calls.some(([url]) => url.endsWith('/assistant/user/confirm'))).toBe(false);
  expect(values.has(SHOP_USER_ADMIN_KEY)).toBe(true);
});

test('failed parent save ACK leaves exact GET recovery visible without a confirm POST', async () => {
  flush = async () => { throw Error('parent storage unavailable'); };
  const transport = jest.fn(async url => {
    if (url.includes('/assistant/operations/')) return json({ sessionId, requestId,
      status: 'completed', replayed: true, stopReason: 'end_turn', modeCapability,
      userAdministrationProposal: proposal });
    throw Error(`Unexpected ${url}`);
  });
  globalThis.fetch = transport;
  await render(transport);
  await act(async () => node.querySelector('button').click()); await settle();
  expect(values.has(SHOP_USER_ADMIN_KEY)).toBe(true);
  expect(node.textContent).toContain('Check saved user change');
  expect(transport.mock.calls.some(([url]) => url.endsWith('/assistant/user/confirm'))).toBe(false);
});

test('changed protected turn blocks a new saved reference and mutation', async () => {
  const transport = jest.fn(async url => {
    if (url.includes('/assistant/operations/')) return json({ sessionId, requestId,
      status: 'completed', replayed: true, stopReason: 'end_turn', modeCapability,
      userAdministrationProposal: { ...proposal, role: 'admin' } });
    throw Error(`Unexpected ${url}`);
  });
  globalThis.fetch = transport;
  await render(transport);
  await act(async () => node.querySelector('button').click()); await settle();
  expect(values.has(SHOP_USER_ADMIN_KEY)).toBe(false);
  expect(transport.mock.calls.some(([url]) => url.endsWith('/assistant/user/confirm'))).toBe(false);
  expect(node.querySelector('[role="alert"]')).toBeTruthy();
});

test('double click cannot dispatch a second user confirmation', async () => {
  let posts = 0;
  const transport = jest.fn(async url => {
    if (url.includes('/assistant/operations/')) return json({ sessionId, requestId,
      status: 'completed', replayed: true, stopReason: 'end_turn', modeCapability,
      userAdministrationProposal: proposal });
    if (url.endsWith('/assistant/user/confirm')) { posts++; return json({ ok: true, replayed: false, receipt }); }
    if (url.endsWith(`/admin/users/operations/${proposal.proposalId}`)) return json({ ok: true, receipt });
    throw Error(`Unexpected ${url}`);
  });
  globalThis.fetch = transport;
  await render(transport);
  await act(async () => { const button = node.querySelector('button'); button.click(); button.click(); });
  await settle();
  expect(posts).toBe(1);
  expect(values.has(SHOP_USER_ADMIN_KEY)).toBe(false);
  expect(node.textContent).toContain('User change confirmed.');
});

test('self-change protected GET denial keeps exact ref and offers explicit parent sign-in without another POST', async () => {
  mockStandalone = true;
  const nonce = 'b'.repeat(64);
  const scopeKey = JSON.stringify(['launch', 1, 2, 3, 7, 'original-session']);
  const saved = { scopeKey, targetId: 7, action: 'set_role', role: 'merchant',
    operationId: '55555555-5555-5555-8555-555555555555', expectedVersion: '4' };
  values.set(SHOP_USER_ADMIN_KEY, JSON.stringify(saved));
  const transport = jest.fn(async url => {
    if (url.endsWith(`/admin/users/operations/${saved.operationId}`)) return json({}, 403);
    throw Error(`Unexpected ${url}`);
  });
  globalThis.fetch = transport;
  const priorHash = window.location.hash;
  window.location.hash = nonce;
  const post = jest.spyOn(window, 'postMessage').mockImplementation(() => {});
  try {
    await act(async () => root.render(<AdminUserConfirmation proposal={null} shopUserId={7}
      authorityKey="admin-token" transport={transport} />));
    const check = [...node.querySelectorAll('button')].find(button => button.textContent === 'Check saved user change');
    await act(async () => check.click()); await settle();
    expect(node.textContent).toContain('Outcome unknown. Sign in again');
    expect(values.get(SHOP_USER_ADMIN_KEY)).toBe(JSON.stringify(saved));
    expect(post).not.toHaveBeenCalled();
    const signIn = [...node.querySelectorAll('button')].find(button => button.textContent === 'Sign in again');
    expect(signIn).toBeTruthy();
    await act(async () => signIn.click());
    expect(post).toHaveBeenCalledWith({ channel: 'dvaia-secureshop-standalone-session-v1',
      type: 'auth-required', nonce }, new URL(document.baseURI).origin);
    expect(values.get(SHOP_USER_ADMIN_KEY)).toBe(JSON.stringify(saved));
    expect(transport).toHaveBeenCalledTimes(1);
  } finally { post.mockRestore(); window.location.hash = priorHash; }
});
