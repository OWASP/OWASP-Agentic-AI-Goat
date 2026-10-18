import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import { webcrypto } from 'node:crypto';
import { AdminTicketsView } from './Tickets.jsx';

jest.mock('../../components/PageTransition.jsx', () => ({ children }) => children);

const subject = '<script>subject()</script>';
const body = '<img src=x onerror=alert(1)>\nTicket body';
const createdAt = '2026-10-12T12:00:00.000Z';
const capability = mode => ({ version: 1, featureId: 'support_tickets',
  policyVersion: 'owned-ticket-render-v1', effectiveMode: mode,
  scope: { kind: 'launch_feature', id: 'support_tickets' } });
const digest = async value => [...new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value)))]
  .map(byte => byte.toString(16).padStart(2, '0')).join('');
const response = value => ({ ok: true, headers: { get: () => 'application/json' }, json: async () => value });
const list = { version: 1, tickets: [{ ticketId: '42', subject, status: 'open', createdAt }], nextCursor: null };
let root, node, originalCrypto, detail;
beforeEach(async () => {
  globalThis.IS_REACT_ACT_ENVIRONMENT = true; originalCrypto = globalThis.crypto;
  Object.defineProperty(globalThis, 'crypto', { configurable: true, value: webcrypto });
  node = document.createElement('div'); document.body.append(node); root = createRoot(node);
  detail = { version: 1, ticketId: '42', operationId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
    proposalId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', subject, body, status: 'open', createdAt,
    subjectSha256: await digest(subject), bodySha256: await digest(body), receiptSha256: 'c'.repeat(64),
    modeCapability: capability('vuln') };
});
afterEach(async () => { await act(async () => root.unmount()); node.remove();
  Object.defineProperty(globalThis, 'crypto', { configurable: true, value: originalCrypto }); });
const render = async transport => act(async () => root.render(<AdminTicketsView
  transport={transport} authorityKey="admin-a" />));
const settle = () => act(async () => { await new Promise(resolve => setTimeout(resolve, 10)); });
const select = async () => { await act(async () => node.querySelector('button[aria-label^="Read ticket"]').click());
  await settle(); };

test('list subject is escaped; only trusted vulnerable detail renders raw ticket body', async () => {
  const transport = jest.fn(async path => response(path.endsWith('/42') ? detail : list));
  await render(transport);
  expect(node.textContent).toContain(subject);
  expect(node.querySelector('script')).toBeNull();
  await select();
  expect(node.querySelector('[data-testid="ticket-vulnerable-body"] img')).not.toBeNull();
  expect(node.querySelector('[data-testid="ticket-fixed-body"]')).toBeNull();
  await act(async () => window.dispatchEvent(new Event('blur')));
  expect(node.querySelector('[data-testid="ticket-vulnerable-body"]')).toBeNull();
});

test('fixed detail displays literal text and rejects tampered digest without an HTML sink', async () => {
  let current = { ...detail, modeCapability: capability('fixed') };
  const transport = jest.fn(async path => response(path.endsWith('/42') ? current : list));
  await render(transport);
  await select();
  expect(node.querySelector('[data-testid="ticket-fixed-body"]')?.textContent).toBe(body);
  expect(node.querySelector('[data-testid="ticket-fixed-body"] img')).toBeNull();
  current = { ...detail, body: 'tampered' };
  await act(async () => [...node.querySelectorAll('button')].find(button =>
    button.textContent === 'Refresh ticket detail').click());
  await settle();
  expect(node.textContent).toContain('could not be verified');
  expect(node.querySelector('[data-testid="ticket-vulnerable-body"]')).toBeNull();
});

test('401 detail clears admin list and detail rather than retaining stale data', async () => {
  let deny = false;
  const transport = jest.fn(async path => path.endsWith('/42') && deny
    ? { ok: false, status: 401 } : response(path.endsWith('/42') ? detail : list));
  await render(transport);
  await select();
  expect(node.querySelector('[data-testid="ticket-vulnerable-body"]')).not.toBeNull();
  deny = true;
  await act(async () => [...node.querySelectorAll('button')].find(button =>
    button.textContent === 'Refresh ticket detail').click());
  await settle();
  expect(node.textContent).toContain('Administrator ticket access is unavailable');
  expect(node.querySelector('[data-testid="ticket-vulnerable-body"]')).toBeNull();
  expect(node.querySelector('button[aria-label^="Read ticket"]')).toBeNull();
});
