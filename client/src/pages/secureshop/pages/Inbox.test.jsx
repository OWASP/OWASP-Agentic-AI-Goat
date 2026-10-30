import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import Inbox from './Inbox';
let mockAuth;
const toast = { success: jest.fn(), error: jest.fn(), info: jest.fn() };
jest.mock('../context/AuthContext', () => ({ useAuth: () => mockAuth }));
jest.mock('../context/ToastContext.jsx', () => ({ useToast: () => toast }));
jest.mock('../components/PersonaInboxLab.jsx', () => () => null);
jest.mock('../components/Dialog.jsx', () => ({ open, children }) => open ? <div>{children}</div> : null);
jest.mock('framer-motion', () => {
  const React = require('react');
  const element = tag => React.forwardRef(({ initial, animate, exit, transition, whileHover, whileTap, ...props }, ref) => React.createElement(tag, { ...props, ref }));
  return { motion: { div: element('div'), button: element('button'), span: element('span') },
    AnimatePresence: ({ children }) => children, useReducedMotion: () => true };
});
const mail = { id: 5, thread_id: 3, subject: 'Original message', from_addr: 'sender@lab', body_html: '<b data-testid="raw">raw teaching HTML</b>', created_at: '2026-09-26' };
const response = (body, ok = true) => ({ ok, json: async () => body });
let root, container;
const render = async () => { await act(async () => root.render(<Inbox />)); };
const click = async text => { const button = [...container.querySelectorAll('button')].find(x => x.textContent.includes(text)); await act(async () => button.click()); };
beforeEach(() => {
  jest.clearAllMocks(); global.IS_REACT_ACT_ENVIRONMENT = true;
  mockAuth = { user: { id: 1, role: 'customer' }, token: 'old' };
  global.fetch = jest.fn().mockResolvedValue(response({ ok: true, emails: [mail] }));
  container = document.createElement('div'); document.body.appendChild(container); root = createRoot(container);
});
afterEach(async () => { await act(async () => root.unmount()); container.remove(); });
async function select() { await act(async () => [...container.querySelectorAll('div')].find(x => x.textContent === mail.subject).click()); }
test('HTTP errors remain load errors and retry can establish empty inbox', async () => {
  fetch.mockResolvedValueOnce(response({ error: 'Bound OWASP AI SecureShop operation unavailable' }, false));
  await render(); expect(container.textContent).toContain('Unable to load inbox'); expect(container.textContent).not.toContain('No mail yet');
  fetch.mockResolvedValueOnce(response({ ok: true, emails: [] })); await click('Retry'); expect(container.textContent).toContain('No mail yet');
});
test.each([
  [false, { ok: true, sent_email_id: 9 }], [true, { ok: false, error: 'no latest email' }], [true, { ok: true, queued: true }],
])('auto reply never claims success without HTTP and persisted evidence %s %j', async (ok, body) => {
  await render(); await select(); fetch.mockResolvedValueOnce(response(body, ok)); await click('Auto-reply');
  expect(toast.success).not.toHaveBeenCalled(); expect(toast.error).toHaveBeenCalled();
});
test('saved auto reply reports lab persistence; raw HTML and local hiding remain', async () => {
  await render(); await select(); expect(container.querySelector('[data-testid="raw"]').tagName).toBe('B');
  fetch.mockResolvedValueOnce(response({ ok: true, sent_email_id: 8 })); await click('Auto-reply');
  expect(toast.success).toHaveBeenCalledWith('Auto-reply saved to lab mail');
  await click('Hide locally'); expect(toast.info.mock.calls[0][0]).toContain('Hidden locally'); expect(container.textContent).not.toContain(mail.subject);
});
test('declined auto reply remains visible for its thread without claiming a send or policy cause', async () => {
  const other = { ...mail, id: 6, thread_id: 4, subject: 'Other message', created_at: '2026-09-27' };
  fetch.mockResolvedValueOnce(response({ ok: true, emails: [mail, other] }));
  await render(); await select();
  const requestId = 'bd09fc30-8539-4a7a-874f-c71644c264e8';
  fetch.mockResolvedValueOnce(response({ ok: true, status: 'declined', requestId, threadId: 3, terminalNoSend: true }));
  await click('Auto-reply');
  expect(container.textContent).toContain('Auto-reply finished without a confirmed saved reply.');
  expect(container.textContent).toContain(`Request ${requestId}`);
  expect(toast.success).not.toHaveBeenCalled();
  expect(container.textContent).not.toContain('policy blocked');
  await act(async () => [...container.querySelectorAll('div')].find(node => node.textContent === other.subject).click());
  expect(container.textContent).not.toContain(`Request ${requestId}`);
  await select();
  expect(container.textContent).toContain(`Request ${requestId}`);
});
test('bare declined response does not become a customer result', async () => {
  await render(); await select();
  fetch.mockResolvedValueOnce(response({ ok: true, status: 'declined', requestId: 'bd09fc30-8539-4a7a-874f-c71644c264e8' }));
  await click('Auto-reply');
  expect(toast.error).toHaveBeenCalled();
  expect(container.textContent).not.toContain('Request bd09fc30-8539-4a7a-874f-c71644c264e8');
});
test('credential rotation aborts stale inbox and clears selection', async () => {
  let resolve; fetch.mockImplementationOnce(() => new Promise(done => { resolve = done; })); await render();
  const signal = fetch.mock.calls[0][1].signal;
  mockAuth = { ...mockAuth, token: 'new' }; fetch.mockResolvedValueOnce(response({ ok: true, emails: [] })); await render();
  expect(signal.aborted).toBe(true);
  await act(async () => resolve(response({ ok: true, emails: [mail] })));
  expect(container.textContent).not.toContain(mail.subject); expect(container.textContent).toContain('No mail yet');
});
test('credential rotation suppresses late auto reply toast and clears selected content', async () => {
  await render(); await select(); let resolve;
  fetch.mockImplementationOnce(() => new Promise(done => { resolve = done; })); await click('Auto-reply');
  mockAuth = { ...mockAuth, token: 'new' }; await render();
  await act(async () => resolve(response({ ok: true, sent_email_id: 8 })));
  expect(toast.success).not.toHaveBeenCalled(); expect(container.querySelector('[data-testid="raw"]')).toBeNull();
});
test.each([[false, { ok: true, email_id: 5 }], [true, { ok: true, queued: true }], [true, { ok: true, email_id: 5 }]])('compose validates persisted response %s %j', async (ok, body) => {
  await render(); await select(); await click('Reply');
  fetch.mockResolvedValueOnce(response(body, ok));
  await act(async () => container.querySelector('form').dispatchEvent(new Event('submit', { bubbles: true, cancelable: true })));
  if (ok && body.email_id) expect(toast.success).toHaveBeenCalledWith('Message saved to lab mail for sender@lab');
  else { expect(toast.success).not.toHaveBeenCalled(); expect(toast.error).toHaveBeenCalled(); expect(container.querySelector('form')).not.toBeNull(); }
});
test('compose actions wrap within the narrow dialog so Send stays reachable', async () => {
  await render(); await click('Compose');
  const send = [...container.querySelectorAll('button')].find(value => value.textContent === 'Send');
  expect(send).toBeTruthy();
  expect(send.parentElement.style.flexWrap).toBe('wrap');
});
test('closing compose cancels its result without claiming failed or successful delivery', async () => {
  await render(); await select(); await click('Reply'); let resolve;
  fetch.mockImplementationOnce(() => new Promise(done => { resolve = done; }));
  await act(async () => container.querySelector('form').dispatchEvent(new Event('submit', { bubbles: true, cancelable: true })));
  const signal = fetch.mock.calls[1][1].signal; await click('Cancel'); expect(signal.aborted).toBe(true);
  await act(async () => resolve(response({ ok: true, email_id: 8 })));
  expect(toast.success).not.toHaveBeenCalled(); expect(toast.error).not.toHaveBeenCalled();
});
test('owner change discards selected raw message and open compose draft', async () => {
  await render(); await select(); await click('Reply');
  mockAuth = { user: { id: 2, role: 'customer' }, token: 'new-owner' };
  fetch.mockResolvedValueOnce(response({ ok: true, emails: [] })); await render();
  expect(container.querySelector('form')).toBeNull(); expect(container.querySelector('[data-testid="raw"]')).toBeNull();
  expect(fetch.mock.calls.at(-1)[0]).toBe('/api/secureshop/email/inbox/2');
});
