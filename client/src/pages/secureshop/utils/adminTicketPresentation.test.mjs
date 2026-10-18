import { webcrypto } from 'node:crypto';
import { decodeAdminTicketList, decodeAdminTicketDetail, decodeTicketModeCapability,
  verifyAdminTicketDetail } from './adminTicketPresentation.mjs';

const capability = { version: 1, featureId: 'support_tickets',
  policyVersion: 'owned-ticket-render-v1', effectiveMode: 'vuln',
  scope: { kind: 'launch_feature', id: 'support_tickets' } };
const detail = { version: 1, ticketId: '42',
  operationId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
  proposalId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
  subject: 'Help', body: '<img src=x onerror=alert(1)>', status: 'open',
  createdAt: '2026-10-12T12:00:00.000Z', subjectSha256: 'a'.repeat(64),
  bodySha256: 'b'.repeat(64), receiptSha256: 'c'.repeat(64), modeCapability: capability };

test('closed admin list provides bounded escaped-summary data', () => {
  const list = { version: 1, tickets: [{ ticketId: '42', subject: '<script>bad()</script>',
    status: 'open', createdAt: detail.createdAt }], nextCursor: null };
  expect(decodeAdminTicketList(list)).toEqual(list);
  expect(() => decodeAdminTicketList({ ...list, tickets: [...list.tickets, { ...list.tickets[0], body: 'secret' }] })).toThrow();
  expect(() => decodeAdminTicketList({ ...list, nextCursor: 'x'.repeat(1025) })).toThrow();
});

test('detail requires current canonical mode projection and no extra fields', () => {
  expect(decodeAdminTicketDetail(detail)).toEqual(detail);
  expect(() => decodeTicketModeCapability({ ...capability, policyVersion: 'owned-ticket-html-render-v1' })).toThrow();
  expect(() => decodeAdminTicketDetail({ ...detail, source: {} })).toThrow();
  expect(() => decodeAdminTicketDetail({ ...detail, operationId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb' })).toThrow();
});

test('detail digest verification rejects altered HTML before display', async () => {
  Object.defineProperty(globalThis.crypto, 'subtle', { configurable: true, value: webcrypto.subtle });
  const digest = async value => [...new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value)))]
    .map(byte => byte.toString(16).padStart(2, '0')).join('');
  const valid = { ...detail, subjectSha256: await digest(detail.subject),
    bodySha256: await digest(detail.body) };
  await expect(verifyAdminTicketDetail(valid)).resolves.toEqual(valid);
  await expect(verifyAdminTicketDetail({ ...valid, body: 'altered' })).rejects.toThrow();
});
