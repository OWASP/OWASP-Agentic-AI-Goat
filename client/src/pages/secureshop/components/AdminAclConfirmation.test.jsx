import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import AdminAclConfirmation from './AdminAclConfirmation.jsx';
import { aclProposalPending } from '../utils/roleAclProposal.mjs';
import { shopStorage, flushShopStorage, SHOP_ACL_KEY } from '../utils/shopStorage.mjs';
const { webcrypto } = require('node:crypto');
const C = require('../../../../../server/services/secureshopRoleAclProposal.js');
jest.mock('../utils/shopStorage.mjs', () => ({ ...jest.requireActual('../utils/shopStorage.mjs'), flushShopStorage: jest.fn() }));
const sessionId = '11111111-1111-4111-8111-111111111111', requestId = '22222222-2222-4222-8222-222222222222';
const mode = { version: 1, featureId: 'admin_assistant', policyVersion: 'owned-admin-read-and-confirmation-v1', effectiveMode: 'vuln', scope: { kind: 'launch_feature', id: 'admin_assistant' } };
const proposal = C.projectRoleAclProposal(C.createRoleAclProposal({ source: { sessionId, requestId }, origin: { step: 1, callId: 'prepare' }, action: 'enforcement', selected: null,
  before: { enforcement: true }, after: { enforcement: false }, expectedVersion: '4', registrySha256: 'a'.repeat(64), scopeKey: 'owned', modeCapability: mode }), { sessionId, requestId });
const saved = aclProposalPending(proposal);
const receipt = { operationId: proposal.proposalId, expectedVersion: '4', version: '5', registrySha256: proposal.registrySha256, enforcement: false, change: { kind: 'enforcement', enabled: false } };
const head = { ok: true, administration: { versionedPolicy: true, scopeKey: 'owned' }, version: '4', registrySha256: proposal.registrySha256, enforcement_enabled: true };
const source = { sessionId, requestId, status: 'completed', replayed: true, stopReason: 'end_turn', modeCapability: mode, aclProposal: proposal };
const json = value => ({ ok: true, status: 200, json: async () => value });
let node, root, transport, committed;
const render = async (p = proposal, authorityKey = 'original') => act(async () => root.render(<AdminAclConfirmation proposal={p} sessionId={sessionId} requestId={requestId} authorityKey={authorityKey} transport={transport} />));
const settle = async () => { for (let i = 0; i < 5; i++) await act(async () => { await new Promise(resolve => setTimeout(resolve, 0)); }); };
const click = async text => { await act(async () => [...node.querySelectorAll('button')].find(b => b.textContent === text).click()); await settle(); };
const posts = () => transport.mock.calls.filter(([, options]) => options?.method === 'POST');
beforeEach(() => {
  globalThis.IS_REACT_ACT_ENVIRONMENT = true;
  Object.defineProperty(globalThis.crypto, 'subtle', { configurable: true, value: webcrypto.subtle });
  localStorage.clear(); flushShopStorage.mockReset().mockResolvedValue(); committed = false;
  node = document.createElement('div'); document.body.append(node); root = createRoot(node);
  transport = jest.fn(async (url, options) => {
    if (url.endsWith('/admin/access-control')) return json(head);
    if (url.includes('/assistant/operations/')) return json(source);
    if (url.includes('/access-control/operations/')) return committed ? json({ ok: true, receipt }) : { status: 404, ok: false };
    if (url.endsWith('/assistant/acl/confirm')) { committed = true; throw Error('lost ACK'); }
    throw Error('Unexpected route');
  });
  globalThis.fetch = transport;
});
afterEach(async () => { await act(async () => root.unmount()); node.remove(); });
test('physical confirm awaits parent ACK, posts only source identity, then verifies exact GET after lost ACK', async () => {
  let acknowledge;
  flushShopStorage.mockImplementationOnce(() => new Promise(resolve => { acknowledge = resolve; }));
  await render(); await settle();
  expect(node.textContent).toContain('On → Off');
  await click('Confirm ACL change'); expect(posts()).toHaveLength(0);
  await act(async () => acknowledge()); await settle();
  expect(posts()).toHaveLength(1);
  expect(JSON.parse(posts()[0][1].body)).toEqual({ sessionId, requestId, proposalId: proposal.proposalId });
  expect(node.textContent).toContain('confirmed from the saved receipt');
  expect(shopStorage.getItem(SHOP_ACL_KEY)).toBeNull();
});
test('changed parent reference during delayed preflight prevents POST', async () => {
  let resolveRead;
  const original = transport.getMockImplementation();
  transport.mockImplementation((url, opts) => url.includes('/access-control/operations/') ? new Promise(resolve => { resolveRead = resolve; }) : original(url, opts));
  await render(); await settle(); await click('Confirm ACL change');
  const foreign = { ...saved, scopeKey: 'foreign' }; shopStorage.setItem(SHOP_ACL_KEY, JSON.stringify(foreign));
  await act(async () => resolveRead({ ok: false, status: 404 })); await settle();
  expect(posts()).toHaveLength(0); expect(JSON.parse(shopStorage.getItem(SHOP_ACL_KEY))).toEqual(foreign);
});
test('reload saved-reference recovery does one exact GET and no POST even at terminal current version', async () => {
  committed = true; shopStorage.setItem(SHOP_ACL_KEY, JSON.stringify(saved));
  const original = transport.getMockImplementation();
  transport.mockImplementation((url, opts) => url.endsWith('/admin/access-control') ? json({ ...head, version: '9223372036854775807' }) : original(url, opts));
  await render(null); await settle(); await click('Check saved ACL change');
  expect(posts()).toHaveLength(0); expect(node.textContent).toContain('Saved policy version 5');
  expect(shopStorage.getItem(SHOP_ACL_KEY)).toBeNull();
});
test('foreign pending slot and substituted completed source each deny dispatch without clearing', async () => {
  shopStorage.setItem(SHOP_ACL_KEY, JSON.stringify({ ...saved, scopeKey: 'foreign' }));
  await render(); await settle(); await click('Confirm ACL change'); expect(posts()).toHaveLength(0);
  expect(JSON.parse(shopStorage.getItem(SHOP_ACL_KEY)).scopeKey).toBe('foreign');
  localStorage.clear(); const original = transport.getMockImplementation();
  transport.mockImplementation((url, opts) => url.includes('/assistant/operations/') ? json({ ...source, requestId: sessionId }) : original(url, opts));
  await render(proposal, 'renewed'); await settle(); await click('Confirm ACL change');
  expect(posts()).toHaveLength(0); expect(shopStorage.getItem(SHOP_ACL_KEY)).toBeNull();
});
test('an existing not-found operation remains unknown and recovery never resends it', async () => {
  shopStorage.setItem(SHOP_ACL_KEY, JSON.stringify(saved));
  await render(null); await settle(); await click('Check saved ACL change'); await click('Check saved ACL change');
  expect(posts()).toHaveLength(0); expect(node.textContent).toContain('unconfirmed');
  expect(JSON.parse(shopStorage.getItem(SHOP_ACL_KEY))).toEqual(saved);
});
test('authority renewal while source GET is pending denies late publication and POST', async () => {
  let completeSource; const original = transport.getMockImplementation();
  transport.mockImplementation((url, opts) => url.includes('/assistant/operations/') ? new Promise(resolve => { completeSource = resolve; }) : original(url, opts));
  await render(); await settle(); await click('Confirm ACL change');
  await render(null, 'new-authority'); await settle();
  await act(async () => completeSource(json(source))); await settle();
  expect(posts()).toHaveLength(0); expect(shopStorage.getItem(SHOP_ACL_KEY)).toBeNull();
});
test('failed parent save acknowledgement retains unknown reference and submits nothing', async () => {
  flushShopStorage.mockRejectedValueOnce(Error('Parent save acknowledgement failed'));
  await render(); await settle(); await click('Confirm ACL change');
  expect(posts()).toHaveLength(0);
  expect(JSON.parse(shopStorage.getItem(SHOP_ACL_KEY))).toEqual(saved);
  expect(node.textContent).toContain('Parent save acknowledgement failed');
  await click('Check saved ACL change'); expect(posts()).toHaveLength(0);
});
test('failed terminal clear acknowledgement keeps verified receipt visible and never resubmits', async () => {
  flushShopStorage.mockResolvedValueOnce().mockRejectedValueOnce(Error('Parent clear acknowledgement failed'));
  await render(); await settle(); await click('Confirm ACL change');
  expect(posts()).toHaveLength(1);
  expect(node.textContent).toContain('Saved policy version 5');
  expect(node.textContent).toContain('Parent clear acknowledgement failed');
  expect(JSON.parse(shopStorage.getItem(SHOP_ACL_KEY))).toEqual(saved);
  const reads = transport.mock.calls.filter(([url]) => url.includes('/access-control/operations/')).length;
  await click('Check saved ACL change');
  expect(transport.mock.calls.filter(([url]) => url.includes('/access-control/operations/'))).toHaveLength(reads + 1);
  expect(shopStorage.getItem(SHOP_ACL_KEY)).toBeNull();
  expect(posts()).toHaveLength(1);
});
