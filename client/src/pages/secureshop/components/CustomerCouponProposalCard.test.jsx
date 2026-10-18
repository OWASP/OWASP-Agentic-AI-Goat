import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import CustomerCouponProposalCard, { decodeCustomerCouponProposal,
  decodeSavedCouponResult } from './CustomerCouponProposalCard.jsx';

const proposal = { version: 1, kind: 'cart.coupon_prepare', status: 'confirmation_required',
  proposalId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', code: 'LESSON10', codeSha256: 'a'.repeat(64) };
let root, node;
beforeEach(() => { globalThis.IS_REACT_ACT_ENVIRONMENT = true;
  node = document.createElement('div'); document.body.append(node); root = createRoot(node); });
afterEach(async () => { await act(async () => root.unmount()); node.remove(); });
const render = async props => act(async () => root.render(<CustomerCouponProposalCard {...props} />));

test('coupon proposal displays literal code and submits no browser code or operation ID', async () => {
  const onConfirm = jest.fn();
  await render({ proposal, onConfirm });
  expect(node.textContent).toContain('LESSON10');
  expect(node.textContent).toContain('Your cart is unchanged');
  await act(async () => node.querySelector('button').click());
  expect(onConfirm).toHaveBeenCalledWith();
});

test('saved reference exposes check only and never repeats confirmation', async () => {
  const onConfirm = jest.fn(), onCheck = jest.fn();
  await render({ proposal, reference: { sessionId: 's', requestId: 'r', proposalId: proposal.proposalId },
    status: 'unconfirmed', onConfirm, onCheck });
  expect(node.textContent).toContain('Coupon outcome is unconfirmed');
  expect(node.textContent).not.toContain('Confirm coupon');
  await act(async () => node.querySelector('button').click());
  expect(onCheck).toHaveBeenCalledWith();
  expect(onConfirm).not.toHaveBeenCalled();
});

test('closed proposal shape rejects hidden data and renders control bytes as text', async () => {
  expect(() => decodeCustomerCouponProposal({ ...proposal, operationId: proposal.proposalId })).toThrow();
  expect(() => decodeCustomerCouponProposal({ ...proposal, code: '\ud800' })).toThrow();
  await render({ proposal: { ...proposal, code: '<img src=x onerror=alert(1)>' }, onConfirm: jest.fn() });
  expect(node.querySelector('img')).toBeNull();
  expect(node.textContent).toContain('<img src=x onerror=alert(1)>');
});

test('only a closed saved response can display coupon application', async () => {
  const reference = { sessionId: 's', requestId: 'r', proposalId: proposal.proposalId };
  await render({ proposal, status: 'completed', result: { ok: true, code: 'LESSON10',
    discount_percent: 10, subtotal: 100, applied_amount: 10 } });
  expect(node.textContent).not.toContain('Coupon applied');
  await render({ proposal, reference, status: 'completed', result: { ok: true, code: 'LESSON10',
    discount_percent: 10, subtotal: 100, applied_amount: 10 } });
  expect(node.textContent).toContain('Coupon applied');
  await render({ proposal, reference, status: 'completed', result: { ok: true, code: 'LESSON10',
    discount_percent: 10, subtotal: 100, applied_amount: 10, injected: true } });
  expect(node.textContent).not.toContain('Coupon applied');
  expect(() => decodeSavedCouponResult({ ok: true, code: 'LESSON10' })).toThrow();
});

test('completed coupon cannot be cleared into another confirmation of the same proposal', async () => {
  const reference = { sessionId: 's', requestId: 'r', proposalId: proposal.proposalId };
  const result = { ok: false, error: 'coupon not found' };
  const onClear = jest.fn();
  await render({ proposal, reference, status: 'completed', result, onClear });
  expect(node.textContent).not.toContain('Review newer coupon');
  await render({ proposal: null, reference, status: 'completed', result,
    nextProposalAvailable: true, onClear });
  await act(async () => [...node.querySelectorAll('button')].find(button =>
    button.textContent === 'Review newer coupon').click());
  expect(onClear).toHaveBeenCalledTimes(1);
});

test('coupon application and objective assessment remain separate saved outcomes', async () => {
  const reference = { sessionId: 's', requestId: 'r', proposalId: proposal.proposalId };
  const result = { ok: true, code: 'LESSON10', discount_percent: 10,
    subtotal: 100, applied_amount: 10 };
  const onReadAssessment = jest.fn(), onRetryAssessment = jest.fn();
  await render({ proposal, reference, status: 'completed', result, onReadAssessment, onRetryAssessment });
  expect(node.textContent).toContain('Coupon applied');
  expect(node.textContent).not.toContain('Objective completed');
  await act(async () => [...node.querySelectorAll('button')].find(button =>
    button.textContent === 'Check saved assessment').click());
  expect(onReadAssessment).toHaveBeenCalledWith();
  await render({ proposal, reference, status: 'completed', result,
    assessment: { completed: false, status: 'unconfirmed', modelEvaluated: false },
    onReadAssessment, onRetryAssessment });
  await act(async () => [...node.querySelectorAll('button')].find(button =>
    button.textContent === 'Check objective').click());
  expect(onRetryAssessment).toHaveBeenCalledWith();
  await render({ proposal, reference, status: 'completed', result,
    assessment: { completed: false, status: 'ineligible', modelEvaluated: false }, onReadAssessment });
  expect(node.textContent).toContain('not eligible for objective credit');
  expect(node.textContent).not.toContain('Objective completed');
});
