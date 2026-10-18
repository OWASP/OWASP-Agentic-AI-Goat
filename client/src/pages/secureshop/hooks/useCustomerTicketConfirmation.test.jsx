import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import { webcrypto } from 'node:crypto';
import { useCustomerTicketConfirmation, decodeSavedCustomerTicket } from './useCustomerTicketConfirmation.js';
import { createCustomerTicketConfirmationStore } from '../utils/customerTicketConfirmationReference.mjs';

const sessionId = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const requestId = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const proposalId = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc';
let proposal, result, current, root, node, oldCrypto;
const json = value => ({ ok: true, headers: { get: () => 'application/json' }, json: async () => value });
const digest = async value => [...new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value)))]
  .map(byte => byte.toString(16).padStart(2, '0')).join('');
const store = () => { const values = new Map(); return createCustomerTicketConfirmationStore({
  storage: { getItem: key => values.get(key) ?? null,
    setItem: (key, value) => values.set(key, value), removeItem: key => values.delete(key) },
  flush: async () => {},
}); };
function Harness(props) { current = useCustomerTicketConfirmation(props); return null; }
const mount = props => { node = document.createElement('div'); document.body.append(node); root = createRoot(node);
  act(() => root.render(<Harness {...props} />));
  return { rerender(next) { act(() => root.render(<Harness {...next} />)); } }; };

beforeEach(async () => {
  globalThis.IS_REACT_ACT_ENVIRONMENT = true; oldCrypto = globalThis.crypto;
  Object.defineProperty(globalThis, 'crypto', { configurable: true, value: webcrypto });
  proposal = { version: 1, kind: 'support.ticket_prepare', status: 'confirmation_required',
    proposalId, subject: 'Delivery question', body: '<b>Raw customer text</b>',
    subjectSha256: await digest('Delivery question'), bodySha256: await digest('<b>Raw customer text</b>') };
  result = { version: 1, kind: 'support_ticket', ticketId: '42',
    operationId: proposalId, requestId, runId: 'dddddddd-dddd-4ddd-8ddd-dddddddddddd',
    proposalId, status: 'open', subjectSha256: proposal.subjectSha256,
    bodySha256: proposal.bodySha256, receiptSha256: 'c'.repeat(64) };
});
afterEach(async () => { if (root) await act(async () => root.unmount()); node?.remove();
  root = null; node = null;
  Object.defineProperty(globalThis, 'crypto', { configurable: true, value: oldCrypto }); });

test('original saved proposal authorizes one IDs-only POST; lost ACK resolves through GET', async () => {
  const referenceStore = store(), calls = [];
  const transport = jest.fn(async (path, options) => {
    calls.push({ path, method: options.method, body: options.body });
    if (path.endsWith(`/operations/${sessionId}/${requestId}`)) return json({ sessionId, requestId,
      status: 'completed', replayed: true, stopReason: 'end_turn', ticketProposal: proposal });
    if (path.endsWith('/tickets/confirm') && options.method === 'POST') throw Error('lost response');
    if (path.endsWith(`/tickets/confirm/${sessionId}/${requestId}/${proposalId}`))
      return json({ status: 'completed', result });
    throw Error(`unexpected ${path}`);
  });
  const props = { shopUserId: 7, authorityKey: 'token-a', transport, referenceStore,
    sourceSessionId: sessionId, sourceRequestId: requestId, proposal };
  const view = mount(props);
  await act(async () => { expect(await current.confirm()).toBe(true); });
  expect(calls.filter(call => call.method === 'POST')).toEqual([{
    path: '/api/secureshop/agents/customer/tickets/confirm', method: 'POST',
    body: JSON.stringify({ sessionId, requestId, proposalId }),
  }]);
  expect(current.result).toEqual(result);
  expect(referenceStore.read(7)).toMatchObject({ sessionId, requestId, proposalId });
  view.rerender({ ...props, authorityKey: 'token-b', proposal: null });
  await act(async () => { await Promise.resolve(); await Promise.resolve(); });
  expect(current.status).toBe('completed');
  expect(calls.filter(call => call.method === 'POST')).toHaveLength(1);
});

test('changed protected original or digest denies ticket creation before POST', async () => {
  const referenceStore = store();
  const transport = jest.fn(async path => {
    if (path.endsWith(`/operations/${sessionId}/${requestId}`)) return json({ sessionId, requestId,
      status: 'completed', replayed: true, stopReason: 'end_turn',
      ticketProposal: { ...proposal, body: 'Changed' } });
    throw Error('unexpected POST');
  });
  mount({ shopUserId: 7, authorityKey: 'token', transport, referenceStore,
    sourceSessionId: sessionId, sourceRequestId: requestId, proposal });
  await act(async () => { expect(await current.confirm()).toBe(false); });
  expect(transport.mock.calls).toHaveLength(1);
  expect(referenceStore.read(7)).toBeNull();
});

test('unconfirmed saved GET retains IDs-only reference and never repeats mutation', async () => {
  const referenceStore = store();
  await referenceStore.save({ shopUserId: 7, sessionId, requestId, proposalId, startedAt: 1234 });
  const transport = jest.fn(async () => json({ status: 'unconfirmed' }));
  mount({ shopUserId: 7, authorityKey: 'token', transport, referenceStore,
    sourceSessionId: null, sourceRequestId: null, proposal: null });
  await act(async () => { await Promise.resolve(); await Promise.resolve(); });
  expect(current.status).toBe('unconfirmed');
  await act(async () => { expect(await current.check()).toBe(true); });
  expect(transport.mock.calls.every(([path, options]) => options.method === 'GET'
    && path.endsWith(`/tickets/confirm/${sessionId}/${requestId}/${proposalId}`))).toBe(true);
  expect(await current.confirm()).toBe(false);
});

test('closed saved result binds original IDs and cannot claim optimistic completion', () => {
  const reference = { sessionId, requestId, proposalId };
  expect(decodeSavedCustomerTicket({ status: 'completed', result }, reference)).toEqual({ status: 'completed', result });
  expect(() => decodeSavedCustomerTicket({ status: 'completed', result: { ...result, requestId: sessionId } }, reference)).toThrow();
  expect(() => decodeSavedCustomerTicket({ status: 'completed', result: { ...result, credit: true } }, reference)).toThrow();
});
