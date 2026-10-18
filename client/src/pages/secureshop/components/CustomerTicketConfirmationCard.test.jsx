import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import CustomerTicketConfirmationCard, { decodeCustomerTicketProposal,
  decodeSavedTicketResult } from './CustomerTicketConfirmationCard.jsx';

const proposal = { version: 1, kind: 'support.ticket_prepare', status: 'confirmation_required',
  proposalId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', subject: 'Delivery question',
  body: '<img src=x onerror=alert(1)>\nPlease help', subjectSha256: 'a'.repeat(64),
  bodySha256: 'b'.repeat(64) };
const result = { version: 1, kind: 'support_ticket', ticketId: '42',
  operationId: proposal.proposalId, requestId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
  runId: 'cccccccc-cccc-4ccc-8ccc-cccccccccccc', proposalId: proposal.proposalId,
  status: 'open', subjectSha256: proposal.subjectSha256, bodySha256: proposal.bodySha256,
  receiptSha256: 'c'.repeat(64) };
let root, node;
beforeEach(() => { globalThis.IS_REACT_ACT_ENVIRONMENT = true;
  node = document.createElement('div'); document.body.append(node); root = createRoot(node); });
afterEach(async () => { await act(async () => root.unmount()); node.remove(); });
const render = async props => act(async () => root.render(<CustomerTicketConfirmationCard {...props} />));

test('shows exact subject and body as escaped text and one trusted confirmation action', async () => {
  const onConfirm = jest.fn();
  await render({ proposal, onConfirm });
  expect(node.textContent).toContain(proposal.subject);
  expect(node.textContent).toContain(proposal.body);
  expect(node.querySelector('img')).toBeNull();
  await act(async () => node.querySelector('button').click());
  expect(onConfirm).toHaveBeenCalledWith();
});

test('saved reference offers readback but never repeats ticket creation', async () => {
  const onConfirm = jest.fn(), onCheck = jest.fn();
  const reference = { proposalId: proposal.proposalId };
  await render({ proposal, reference, status: 'unconfirmed', onConfirm, onCheck });
  expect(node.textContent).toContain('confirmation will not be sent again');
  await act(async () => node.querySelector('button').click());
  expect(onCheck).toHaveBeenCalledWith();
  expect(onConfirm).not.toHaveBeenCalled();
  await render({ proposal, reference, status: 'completed', result, onConfirm, onCheck });
  expect(node.textContent).toContain('Ticket #42 is open');
  expect(node.textContent).not.toContain('Open support ticket');
});

test('malformed proposal and result cannot appear as trusted ticket state', async () => {
  expect(() => decodeCustomerTicketProposal({ ...proposal, origin: {} })).toThrow();
  expect(() => decodeCustomerTicketProposal({ ...proposal, body: '\ud800' })).toThrow();
  expect(() => decodeSavedTicketResult({ ...result, body: proposal.body })).toThrow();
  await render({ proposal: { ...proposal, origin: {} } });
  expect(node.textContent).toBe('');
  await render({ proposal, reference: { proposalId: proposal.proposalId },
    status: 'completed', result: { ...result, status: 'closed' } });
  expect(node.textContent).not.toContain('Ticket #42 is open');
});
