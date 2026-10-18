import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import { webcrypto } from 'node:crypto';
import { AdminTicketsView } from './Tickets.jsx';
import { SHOP_ADMIN_TICKET_ASSESSMENT_KEY } from '../../utils/shopStorage.mjs';

jest.mock('../../components/PageTransition.jsx', () => ({ children }) => children);
const id = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const modeCapability = { version: 1, featureId: 'support_tickets', policyVersion: 'owned-ticket-render-v1',
  effectiveMode: 'fixed', scope: { kind: 'launch_feature', id: 'support_tickets' } };
const reply = value => ({ ok: true, status: 200, headers: { get: () => 'application/json' }, json: async () => value });
const list = { version: 1, tickets: [{ ticketId: '42', subject: 'Help', status: 'open',
  createdAt: '2026-10-12T12:00:00.000Z' }], nextCursor: null };
const digest = async value => [...new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value)))]
  .map(byte => byte.toString(16).padStart(2, '0')).join('');
let root, node, originalCrypto, detail;
beforeEach(async () => {
  globalThis.IS_REACT_ACT_ENVIRONMENT = true;
  originalCrypto = globalThis.crypto;
  Object.defineProperty(globalThis, 'crypto', { configurable: true, value: webcrypto });
  localStorage.removeItem(SHOP_ADMIN_TICKET_ASSESSMENT_KEY);
  node = document.createElement('div'); document.body.append(node); root = createRoot(node);
  detail = { version: 1, ticketId: '42', operationId: id, proposalId: id,
    subject: 'Help', body: 'Plain ticket body', status: 'open',
    createdAt: '2026-10-12T12:00:00.000Z', subjectSha256: await digest('Help'),
    bodySha256: await digest('Plain ticket body'), receiptSha256: 'c'.repeat(64), modeCapability };
});
afterEach(async () => { await act(async () => root.unmount()); node.remove();
  localStorage.removeItem(SHOP_ADMIN_TICKET_ASSESSMENT_KEY);
  Object.defineProperty(globalThis, 'crypto', { configurable: true, value: originalCrypto }); });
const render = transport => act(async () => root.render(<AdminTicketsView
  transport={transport} authorityKey="admin-a" shopUserId={7} />));
const settle = () => act(async () => { await new Promise(resolve => setTimeout(resolve, 15)); });
const click = async label => { const button = [...node.querySelectorAll('button')].find(item =>
  item.textContent === label || item.getAttribute('aria-label')?.startsWith(label));
  expect(button).toBeTruthy(); await act(async () => button.click()); await settle(); };

test('one physical Check ticket writes IDs before POST; lost ACK and reload use only saved GET', async () => {
  let outcome = { completed: false, status: 'unconfirmed', modelEvaluated: false };
  const transport = jest.fn(async (path, options) => {
    if (path.endsWith('/42/assessment') && options.method === 'POST') {
      const ref = JSON.parse(localStorage.getItem(SHOP_ADMIN_TICKET_ASSESSMENT_KEY));
      expect(Object.keys(ref).sort()).toEqual(['requestId', 'shopUserId', 'startedAt', 'ticketId', 'version']);
      expect(JSON.parse(options.body)).toEqual({ requestId: ref.requestId });
      throw Error('lost acknowledgment');
    }
    if (path.includes('/assessment/')) return reply(outcome);
    return reply(path.endsWith('/42') ? detail : list);
  });
  await render(transport); await settle(); await click('Read ticket'); await click('Check ticket');
  expect(node.textContent).toContain('Assessment not confirmed');
  expect(JSON.parse(localStorage.getItem(SHOP_ADMIN_TICKET_ASSESSMENT_KEY)).ticketId).toBe('42');
  const posts = () => transport.mock.calls.filter(([path, options]) =>
    path.endsWith('/42/assessment') && options.method === 'POST');
  expect(posts()).toHaveLength(1);
  await act(async () => root.unmount()); root = createRoot(node);
  outcome = { completed: true, judgment: { verdict: 'pass', evaluationId: id,
    canRetry: false }, replayed: true };
  await render(transport); await settle();
  expect(node.textContent).toContain('Objective completed.');
  expect(transport.mock.calls.filter(([path, options]) => path.includes('/assessment/')
    && options.method === 'GET').length).toBeGreaterThanOrEqual(2);
  expect(posts()).toHaveLength(1);
});

test('assessment 401 removes selected body and prior administrator list', async () => {
  let deny = false;
  const transport = jest.fn(async (path, options) => {
    if (path.endsWith('/42/assessment') && options.method === 'POST') { deny = true; return reply({}); }
    if (path.includes('/assessment/') && deny) return { ok: false, status: 401 };
    return reply(path.endsWith('/42') ? detail : list);
  });
  await render(transport); await settle(); await click('Read ticket'); await click('Check ticket');
  expect(node.textContent).toContain('Administrator ticket access is unavailable');
  expect(node.querySelector('button[aria-label^="Read ticket"]')).toBeNull();
  expect(node.querySelector('[data-testid="ticket-fixed-body"]')).toBeNull();
});
