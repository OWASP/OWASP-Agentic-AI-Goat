import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import SecureShopStandaloneExternalMail from './SecureShopStandaloneExternalMail.jsx';

const principalId = '11111111-1111-4111-8111-111111111111';
const operationId = '22222222-2222-4222-8222-222222222222';
const scopeKey = 'a'.repeat(64), requestSha256 = 'b'.repeat(64);
const preview = { sender: 'shop@gmail.com', recipient: 'person@sharklasers.com',
  subject: 'SecureShop synthetic delivery test',
  text: `This is a manually requested SecureShop synthetic delivery test.\nNo shop, inbox, account or private document content is included.\nTest operation: ${operationId}\n` };
const prepared = { version: 1, operationId, scopeKey, requestSha256, state: 'prepared',
  preview, expiresAt: new Date(Date.now() + 600000).toISOString(), smtp: null };
const ready = { version: 1, available: true, scopeKey, sender: preview.sender,
  templateVersion: 'synthetic-test-v1', limits: { ownerPerHour: 3, senderPerHour: 20 } };
const key = `dvaia:secureshop:external-mail:v1:${principalId}`;

let root, container, originalUuid;
const flush = async () => { await act(async () => { await Promise.resolve(); await Promise.resolve(); }); };
const button = label => [...container.querySelectorAll('button')].find(item => item.textContent === label);
const deferred = () => { let resolve; const promise = new Promise(done => { resolve = done; }); return { promise, resolve }; };
const reactHandler = (element, name) => element[Object.keys(element).find(key => key.startsWith('__reactProps$'))][name];

beforeEach(() => {
  global.IS_REACT_ACT_ENVIRONMENT = true;
  sessionStorage.clear();
  originalUuid = Object.getOwnPropertyDescriptor(global.crypto, 'randomUUID');
  Object.defineProperty(global.crypto, 'randomUUID', { configurable: true, value: () => operationId });
  container = document.createElement('div'); document.body.appendChild(container);
  root = createRoot(container);
});
afterEach(async () => {
  await act(async () => root.unmount()); container.remove(); sessionStorage.clear();
  if (originalUuid) Object.defineProperty(global.crypto, 'randomUUID', originalUuid);
  else delete global.crypto.randomUUID;
});

function controller(overrides = {}) {
  return { getExternalMailReadiness: jest.fn().mockResolvedValue(ready),
    getExternalMailOperation: jest.fn().mockResolvedValue(prepared),
    prepareExternalMail: jest.fn().mockResolvedValue(prepared),
    confirmExternalMail: jest.fn().mockResolvedValue({ ...prepared, state: 'smtp_accepted',
      smtp: { smtpAccepted: true, deliveryConfirmed: false, messageId: 'accepted',
        acceptedRecipient: preview.recipient } }),
    cancelExternalMail: jest.fn().mockResolvedValue({ ...prepared, state: 'cancelled' }), ...overrides };
}
async function mount(control, open = true) {
  await act(async () => root.render(<SecureShopStandaloneExternalMail
    controller={control} user={{ principalId, role: 'merchant' }} open={open} onClose={jest.fn()} />));
  await flush();
}

test('blank recipient and Cancel-before-review never dispatch; prepare yields immutable server review', async () => {
  const control = controller(); await mount(control);
  expect(container.querySelector('input').value).toBe('');
  expect(button('Review synthetic message').disabled).toBe(true);
  expect(control.prepareExternalMail).not.toHaveBeenCalled();
  await act(async () => { const input = container.querySelector('input');
    const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set;
    setter.call(input, preview.recipient); input.dispatchEvent(new Event('input', { bubbles: true })); });
  await act(async () => button('Review synthetic message').click()); await flush();
  expect(control.prepareExternalMail).toHaveBeenCalledTimes(1);
  expect(container.textContent).toContain(preview.text);
  expect(sessionStorage.getItem(key)).toContain('"phase":"prepared"');
  await act(async () => button('Cancel prepared send').click()); await flush();
  expect(control.cancelExternalMail).toHaveBeenCalledTimes(1);
  expect(control.confirmExternalMail).not.toHaveBeenCalled();
});

test('lost prepare acknowledgement restores exact prepared review, while lost confirm never resends', async () => {
  sessionStorage.setItem(key, JSON.stringify({ version: 1, principalId, operationId,
    scopeKey, phase: 'prepare_submitted' }));
  const control = controller(); await mount(control);
  expect(button('Confirm external send')).toBeTruthy();
  expect(sessionStorage.getItem(key)).toContain('"phase":"prepared"');
  control.confirmExternalMail.mockRejectedValueOnce(new Error('response lost'));
  await act(async () => button('Confirm external send').click()); await flush();
  expect(control.confirmExternalMail).toHaveBeenCalledTimes(1);
  expect(button('Confirm external send')).toBeFalsy();
  expect(button('Cancel prepared send')).toBeFalsy();
  await act(async () => button('Check saved status').click()); await flush();
  expect(control.getExternalMailOperation).toHaveBeenCalledTimes(2);
  expect(control.confirmExternalMail).toHaveBeenCalledTimes(1);
  expect(sessionStorage.getItem(key)).toContain('"phase":"confirm_submitted"');
});

test('synchronous claim blocks duplicate confirm and old completion cannot replace newer status', async () => {
  sessionStorage.setItem(key, JSON.stringify({ version: 1, principalId, operationId,
    scopeKey, phase: 'prepared' }));
  const parked = deferred();
  const control = controller({ confirmExternalMail: jest.fn(() => parked.promise) });
  await mount(control);
  const oldConfirm = button('Confirm external send');
  await act(async () => { oldConfirm.click(); oldConfirm.click(); });
  expect(control.confirmExternalMail).toHaveBeenCalledTimes(1);
  expect(sessionStorage.getItem(key)).toContain('"phase":"confirm_submitted"');
  await act(async () => parked.resolve({ ...prepared, state: 'smtp_accepted', smtp: {
    smtpAccepted: true, deliveryConfirmed: false, messageId: 'accepted', acceptedRecipient: preview.recipient } }));
  expect(container.textContent).toContain('does not prove mailbox delivery');
});

test('saved operation from earlier scope stays GET-only in current merchant practice', async () => {
  sessionStorage.setItem(key, JSON.stringify({ version: 1, principalId, operationId,
    scopeKey, phase: 'prepared' }));
  const control = controller({ getExternalMailReadiness: jest.fn().mockResolvedValue({ ...ready, scopeKey: 'c'.repeat(64) }) });
  await mount(control);
  expect(control.getExternalMailOperation).toHaveBeenCalledWith(operationId, scopeKey, expect.anything());
  expect(button('Confirm external send')).toBeFalsy();
  expect(button('Cancel prepared send')).toBeFalsy();
  expect(container.textContent).toContain('read-only here');
});

test('past-dated prepared preview cannot confirm, but original scope still permits explicit cancel', async () => {
  sessionStorage.setItem(key, JSON.stringify({ version: 1, principalId, operationId,
    scopeKey, phase: 'prepared' }));
  const expiredPreview = { ...prepared, expiresAt: new Date(Date.now() - 60000).toISOString() };
  const control = controller({ getExternalMailOperation: jest.fn().mockResolvedValue(expiredPreview) });
  await mount(control);
  expect(button('Confirm external send')).toBeFalsy();
  expect(button('Cancel prepared send')).toBeTruthy();
  await act(async () => button('Cancel prepared send').click()); await flush();
  expect(control.cancelExternalMail).toHaveBeenCalledTimes(1);
  expect(control.confirmExternalMail).not.toHaveBeenCalled();
});

test('fresh server expired status alone retires old-scope draft; dispatching and unknown remain blocked', async () => {
  sessionStorage.setItem(key, JSON.stringify({ version: 1, principalId, operationId,
    scopeKey, phase: 'confirm_submitted' }));
  const oldReady = { ...ready, scopeKey: 'c'.repeat(64) };
  const control = controller({ getExternalMailReadiness: jest.fn().mockResolvedValue(oldReady),
    getExternalMailOperation: jest.fn().mockResolvedValueOnce({ ...prepared, state: 'dispatching' })
      .mockResolvedValueOnce({ ...prepared, state: 'unknown' })
      .mockResolvedValueOnce({ ...prepared, state: 'expired', expiresAt: new Date(Date.now() - 60000).toISOString() }) });
  await mount(control);
  expect(button('Dismiss result')).toBeFalsy();
  expect(button('Confirm external send')).toBeFalsy();
  await act(async () => button('Check saved status').click()); await flush();
  expect(button('Dismiss result')).toBeFalsy();
  expect(sessionStorage.getItem(key)).toContain('"phase":"confirm_submitted"');
  await act(async () => button('Check saved status').click()); await flush();
  expect(button('Dismiss result')).toBeTruthy();
  expect(container.textContent).toContain('service confirms');
  await act(async () => button('Dismiss result').click()); await flush();
  expect(sessionStorage.getItem(key)).toBeNull();
  expect(control.confirmExternalMail).not.toHaveBeenCalled();
  expect(control.cancelExternalMail).not.toHaveBeenCalled();
  await mount(control, false);
  await mount(control, true);
  expect(container.querySelector('input').value).toBe('');
  expect(button('Review synthetic message')).toBeTruthy();
  expect(control.prepareExternalMail).not.toHaveBeenCalled();
});

test('retained Prepare and recipient callbacks cannot carry a closed draft into a reopened panel', async () => {
  const control = controller(); await mount(control);
  const input = container.querySelector('input');
  const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set;
  await act(async () => { setter.call(input, preview.recipient);
    input.dispatchEvent(new Event('input', { bubbles: true })); });
  const oldPrepare = reactHandler(button('Review synthetic message'), 'onClick');
  const oldField = reactHandler(container.querySelector('input'), 'onChange');
  await mount(control, false);
  await mount(control, true);
  await act(async () => {
    oldField({ target: { value: 'other@sharklasers.com' } });
    oldPrepare();
  });
  expect(container.querySelector('input').value).toBe('');
  expect(control.prepareExternalMail).not.toHaveBeenCalled();
  expect(sessionStorage.getItem(key)).toBeNull();
});
