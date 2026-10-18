import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import Inbox from './Inbox';
let mockAuth;
jest.mock('../../context/AuthContext.jsx', () => ({ useAuth: () => mockAuth }));
jest.mock('../../components/PersonaInboxLab.jsx', () => () => null);
jest.mock('framer-motion', () => {
  const React = require('react');
  const element = tag => ({ initial, animate, exit, transition, ...props }) => React.createElement(tag, props);
  return { motion: { div: element('div'), button: element('button'), section: element('section') }, AnimatePresence: ({ children }) => children, useReducedMotion: () => true };
});
const mail = { id: 5, thread_id: 3, subject: 'Original message', from_addr: 'sender@lab', body_html: '<b data-testid="raw">raw teaching HTML</b>', created_at: '2026-09-26' };
const response = (body, ok = true) => ({ ok, json: async () => body });
let root, container;
const render = async () => { await act(async () => root.render(<Inbox />)); };
const click = async text => { const button = [...container.querySelectorAll('button')].find(x => x.textContent.trim() === text); await act(async () => button.click()); };
async function change(input, value) { await act(async () => { Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set.call(input, value); input.dispatchEvent(new Event('input', { bubbles: true })); }); }
beforeEach(() => {
  global.IS_REACT_ACT_ENVIRONMENT = true; mockAuth = { user: { id: 1, role: 'merchant' }, token: 'old' };
  global.fetch = jest.fn().mockResolvedValue(response({ ok: true, emails: [mail] }));
  container = document.createElement('div'); document.body.appendChild(container); root = createRoot(container);
});
afterEach(async () => { await act(async () => root.unmount()); container.remove(); });

test('visible teaching-message action performs one saved POST then its authoritative GET', async () => {
  const scopeKey = 'a'.repeat(64);
  let requestId = null;
  const inline = (body, status) => ({ ok: status >= 200 && status < 300, status, json: async () => body });
  fetch.mockImplementation((url, options = {}) => {
    if (url.endsWith('/readiness')) return Promise.resolve(inline({ ready: true, scopeKey }, 200));
    if (url.includes('/inbox/')) return Promise.resolve(response({ ok: true, emails: [mail] }));
    if (url.endsWith('/inline/teaching-message') && options.method === 'POST') {
      requestId = JSON.parse(options.body).requestId;
      return Promise.resolve(inline({ ok: true, status: 'unconfirmed', requestId }, 202));
    }
    if (requestId && url.endsWith(`/inline/teaching-message/${requestId}`)) return Promise.resolve(inline({
      ok: true, status: 'saved', requestId, messageId: 17, threadId: 9, replayed: false,
    }, 200));
    throw new Error(`Unexpected request ${url}`);
  });
  await render();
  await act(async () => { await Promise.resolve(); await Promise.resolve(); });
  await click('Save teaching message');
  expect(container.textContent).toContain('Teaching message saved to this mailbox.');
  const post = fetch.mock.calls.filter(([url, options]) => url.endsWith('/inline/teaching-message')
    && options?.method === 'POST');
  expect(post).toHaveLength(1);
  expect(JSON.parse(post[0][1].body)).toEqual({ requestId });
  expect(fetch.mock.calls.filter(([url]) => requestId && url.endsWith(`/inline/teaching-message/${requestId}`))).toHaveLength(1);
});

test('bound unavailable is an error, reload can establish empty inbox', async () => {
  fetch.mockResolvedValueOnce(response({ error: 'Bound SecureShop operation unavailable' }, false)); await render();
  expect(container.textContent).toContain('Unable to load inbox'); expect(container.textContent).not.toContain('Inbox empty');
  fetch.mockResolvedValueOnce(response({ ok: true, emails: [] })); await click('Reload'); expect(container.textContent).toContain('Inbox empty');
});
test.each([[false, { ok: true, sent_email_id: 8 }], [true, { ok: false }], [true, { ok: true, queued: true }]])('reply rejects unconfirmed save %s %j', async (ok, body) => {
  await render(); fetch.mockResolvedValueOnce(response(body, ok)); await click('Auto-reply');
  expect(container.querySelector('[role="status"]').textContent).toContain('Auto-reply not confirmed');
});
test('bound saved reply shows receipt evidence and selects the saved message when browsed', async () => {
  await render(); expect(container.querySelector('[data-testid="raw"]').tagName).toBe('B');
  const saved = { ...mail, id: 8, from_addr: 'merchant@lab', to_addr: 'sender@lab',
    body_html: '<p data-testid="saved-reply">Saved reply body</p>', created_at: '2026-09-27' };
  fetch.mockResolvedValueOnce(response({ ok: true, status: 'saved',
    requestId: 'bd09fc30-8539-4a7a-874f-c71644c264e8',
    sendOperationId: '9b97e4a7-c3e2-4dab-96fa-d414bf929945', replayed: false,
    sent_email_id: 8, thread_id: 3, assessmentStatus: 'pending',
    savedReply: { recipientId: 1, to: 'sender@lab', subject: 'Re: Original message',
      body_markdown: 'Saved reply body' } }));
  fetch.mockResolvedValueOnce(response({ ok: true, emails: [mail, saved] }));
  await click('Auto-reply');
  expect(container.textContent).toContain('Auto-reply saved to lab mail');
  expect(container.textContent).toContain('Lab reply saved as message #8 in thread #3.');
  expect(container.textContent).toContain('Assessment pending.');
  expect(container.textContent).toContain('Saved recipient: sender@lab');
  expect(container.textContent).toContain('Subject: Re: Original message');
  expect(container.textContent).not.toContain('Lab reply saved for:');
  expect(container.textContent).not.toContain('LLM01 fired');
  expect(container.querySelector('[data-testid="saved-reply"]')).not.toBeNull();
  const messageOne = [...container.querySelectorAll('[role="group"][aria-label="Messages in thread"] button')]
    .find(button => button.textContent.includes('Message 1'));
  expect(messageOne).toBeTruthy();
  await act(async () => messageOne.click());
  expect(container.querySelector('[data-testid="raw"]')).not.toBeNull();
  expect(container.querySelector('[data-testid="saved-reply"]')).toBeNull();
});

test('declined auto-reply keeps a cautious request-bound result for its thread', async () => {
  const other = { ...mail, id: 6, thread_id: 4, subject: 'Second thread', created_at: '2026-09-27' };
  fetch.mockResolvedValueOnce(response({ ok: true, emails: [mail, other] }));
  await render();
  await act(async () => [...container.querySelectorAll('button')].find(button => button.textContent.includes(mail.subject)).click());
  const requestId = 'bd09fc30-8539-4a7a-874f-c71644c264e8';
  fetch.mockResolvedValueOnce(response({ ok: true, status: 'declined', requestId, threadId: 3, terminalNoSend: true }));
  await click('Auto-reply');
  expect(container.textContent).toContain('Auto-reply finished without a confirmed saved reply.');
  expect(container.textContent).toContain(`Request ${requestId}`);
  expect(container.textContent).not.toContain('Lab reply saved as message');
  expect(container.textContent).not.toContain('The assistant declined');
  await act(async () => [...container.querySelectorAll('button')].find(button => button.textContent.includes(other.subject)).click());
  expect(container.textContent).not.toContain(`Request ${requestId}`);
  await act(async () => [...container.querySelectorAll('button')].find(button => button.textContent.includes(mail.subject)).click());
  expect(container.textContent).toContain(`Request ${requestId}`);
  let resolve;
  fetch.mockImplementationOnce(() => new Promise(done => { resolve = done; }));
  await click('Auto-reply');
  expect(container.textContent).not.toContain(`Request ${requestId}`);
  await act(async () => resolve(response({ ok: true, status: 'declined', requestId: 'f3f43be8-d1b2-4379-b2cc-e15c0ad98765', threadId: 3, terminalNoSend: true })));
  expect(container.textContent).toContain('Request f3f43be8-d1b2-4379-b2cc-e15c0ad98765');
});
test('bare declined response is treated as unresolved, not a verified no-send result', async () => {
  await render();
  fetch.mockResolvedValueOnce(response({ ok: true, status: 'declined', requestId: 'bd09fc30-8539-4a7a-874f-c71644c264e8' }));
  await click('Auto-reply');
  expect(container.querySelector('[role="status"]').textContent).toContain('Auto-reply not confirmed');
  expect(container.textContent).not.toContain('Request bd09fc30-8539-4a7a-874f-c71644c264e8');
});

test('outgoing saved reply absent from recipient-only inbox still shows a truthful receipt', async () => {
  await render();
  fetch.mockResolvedValueOnce(response({ ok: true, status: 'saved',
    sent_email_id: 8, thread_id: 3, assessmentStatus: 'pending',
    savedReply: { recipientId: 4, to: 'customer@lab', subject: 'Re: Original message',
      body_markdown: 'The saved outbound response.' } }));
  fetch.mockResolvedValueOnce(response({ ok: true, emails: [mail] }));
  await click('Auto-reply');
  expect(container.textContent).toContain('Lab reply saved as message #8 in thread #3.');
  expect(container.textContent).toContain('Saved recipient: customer@lab');
  expect(container.textContent).toContain('The saved outbound response.');
  expect(container.querySelector('[data-testid="raw"]')).not.toBeNull();
  expect(container.querySelector('[data-testid="saved-reply"]')).toBeNull();
});
test('IDOR selector remains while stale mailbox load is aborted', async () => {
  let resolve; fetch.mockImplementationOnce(() => new Promise(done => { resolve = done; })); await render();
  const signal = fetch.mock.calls[0][1].signal; fetch.mockResolvedValueOnce(response({ ok: true, emails: [] }));
  await change(container.querySelector('[data-testid="inbox-userid"]'), '99'); expect(fetch.mock.calls.at(-1)[0]).toContain('/99'); expect(signal.aborted).toBe(true);
  await act(async () => resolve(response({ ok: true, emails: [mail] })));
  expect(container.textContent).not.toContain(mail.subject); expect(container.textContent).toContain('Inbox empty');
});
test('IDOR selector change invalidates pending reply and retained selection', async () => {
  await render(); let resolve; fetch.mockImplementationOnce(() => new Promise(done => { resolve = done; })); await click('Auto-reply');
  fetch.mockResolvedValueOnce(response({ ok: true, emails: [] })); await change(container.querySelector('[data-testid="inbox-userid"]'), '77');
  await act(async () => resolve(response({ ok: true, sent_email_id: 8 })));
  expect(container.querySelector('[role="status"]')).toBeNull(); expect(container.querySelector('[data-testid="raw"]')).toBeNull();
});
async function compose() { await click('Compose'); const fields = container.querySelectorAll('[role="dialog"] input'); await change(fields[0], 'other@lab'); await change(fields[2], 'Subject'); }
test.each([[false, { ok: true, email_id: 8 }], [true, { ok: true }], [true, { ok: true, email_id: 8 }]])('compose requires persistence %s %j', async (ok, body) => {
  await render(); await compose(); fetch.mockResolvedValueOnce(response(body, ok)); await click('Send');
  expect(container.querySelector('[role="status"]').textContent).toContain(ok && body.email_id ? 'Message saved to lab mail' : 'Send not confirmed');
});
test('closing compose suppresses late response', async () => {
  await render(); await compose(); let resolve; fetch.mockImplementationOnce(() => new Promise(done => { resolve = done; })); await click('Send'); await click('Cancel');
  await act(async () => resolve(response({ ok: true, email_id: 8 }))); expect(container.querySelector('[role="status"]')).toBeNull();
});
test('token rotation clears draft and old selection', async () => {
  await render(); await compose(); mockAuth = { ...mockAuth, token: 'new' }; fetch.mockResolvedValueOnce(response({ ok: true, emails: [] })); await render();
  expect(container.querySelector('[role="dialog"]')).toBeNull(); expect(container.querySelector('[data-testid="raw"]')).toBeNull();
});
test('incremental mailbox typing retains the input and focus; blank sends no fallback request', async () => {
  await render();
  const input = container.querySelector('[data-testid="inbox-userid"]'); input.focus();
  const before = fetch.mock.calls.length;
  await change(input, '');
  expect(input.value).toBe(''); expect(document.activeElement).toBe(input);
  expect(container.querySelector('[data-testid="inbox-userid"]')).toBe(input);
  expect(fetch.mock.calls).toHaveLength(before);
  expect([...container.querySelectorAll('button')].some(b => b.textContent.includes('Reload'))).toBe(false);
  for (const value of ['9', '99', '991']) {
    await change(input, value);
    expect(container.querySelector('[data-testid="inbox-userid"]')).toBe(input);
    expect(document.activeElement).toBe(input); expect(input.value).toBe(value);
    expect(fetch.mock.calls.at(-1)[0]).toContain(`/inbox/${value}`);
  }
  const validCalls = fetch.mock.calls.length;
  for (const value of ['0', '-1', '2147483648', '1.5']) await change(input, value);
  expect(fetch.mock.calls).toHaveLength(validCalls);
});
test('blank edit tears down reply controls and rejects late saved response before reselecting same mailbox', async () => {
  await render(); let resolve;
  fetch.mockImplementationOnce((url, options) => new Promise(done => { resolve = done; }));
  await click('Auto-reply'); const signal = fetch.mock.calls.at(-1)[1].signal;
  const input = container.querySelector('[data-testid="inbox-userid"]'); input.focus();
  await change(input, ''); expect(signal.aborted).toBe(true);
  expect(container.querySelector('[data-testid="raw"]')).toBeNull();
  await act(async () => resolve(response({ ok: true, sent_email_id: 8 })));
  expect(container.textContent).not.toContain('Auto-reply saved');
  expect(container.textContent).not.toContain('Check pending mail');
  fetch.mockResolvedValueOnce(response({ ok: true, emails: [] })); await change(input, '1');
  expect(document.activeElement).toBe(input); expect(container.textContent).toContain('Inbox empty');
  expect(container.textContent).not.toContain('Lab reply saved for:');
});
