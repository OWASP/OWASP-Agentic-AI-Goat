import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import Inbox from './Inbox';

const mockToast = { success: jest.fn(), error: jest.fn(), info: jest.fn() };
const mockMail = {};
jest.mock('../context/AuthContext', () => ({ useAuth: () => ({ user: { id: 1, role: 'customer' }, token: 'shop-token' }) }));
jest.mock('../context/ToastContext.jsx', () => ({ useToast: () => mockToast }));
jest.mock('../components/PersonaInboxLab.jsx', () => () => null);
jest.mock('./MailAssessment', () => () => null);
jest.mock('./MailCapabilityStatus', () => () => null);
jest.mock('../components/MailMessageBody.jsx', () => () => null);
jest.mock('framer-motion', () => {
  const React = require('react');
  const element = tag => React.forwardRef(({ initial, animate, exit, transition, whileHover, whileTap, ...props }, ref) => React.createElement(tag, { ...props, ref }));
  return { motion: { div: element('div'), button: element('button'), span: element('span') },
    AnimatePresence: ({ children }) => children, useReducedMotion: () => true };
});
jest.mock('./mailRequests', () => ({
  useMailCommands: () => mockMail,
  useRequests: () => () => { const controller = new AbortController(); return { signal: controller.signal, finish() {} }; },
  readResponse: async response => { const value = await response.json(); if (!response.ok || value.ok !== true) throw Error(value.error || 'Unavailable'); return value; },
  persistedId: value => Number.isSafeInteger(value) && value > 0,
}));

const receipt = body => ({ ok: true, json: async () => body });
const reference = { action: 'autoReply', requestId: '11111111-1111-4111-8111-111111111111', digest: 'a'.repeat(64) };
const message = { id: 9, thread_id: 5, subject: 'Original thread', from_addr: 'customer@lab',
  body_html: '<p>Message</p>', created_at: '2026-09-26T00:00:00.000Z' };
let root, node;
beforeEach(() => {
  global.IS_REACT_ACT_ENVIRONMENT = true;
  jest.clearAllMocks();
  Object.assign(mockMail, {
    pending: { ...reference }, unresolved: [], unresolvedOutcomes: {}, assessment: null, headerAssessment: null, browserAssessment: null,
    modelCapabilities: null, read: jest.fn(async () => receipt({ ok: true, emails: [message] })),
    recover: jest.fn(async () => receipt({ ok: true, status: 'unconfirmed', requestId: reference.requestId, canRetrySameId: false })),
    keepUnresolved: jest.fn(async threadId => { mockMail.pending = null; mockMail.unresolved = [{ ...reference, threadId }]; return { ok: true }; }),
    checkUnresolved: jest.fn(async () => {
      mockMail.unresolvedOutcomes = { [reference.requestId]: 'saved' };
      return receipt({ ok: true, status: 'saved', requestId: reference.requestId, sent_email_id: 7 });
    }),
  });
  global.fetch = jest.fn();
  node = document.createElement('div'); document.body.appendChild(node); root = createRoot(node);
});
afterEach(async () => { await act(async () => root.unmount()); node.remove(); });
const click = async text => {
  const button = [...node.querySelectorAll('button')].find(value => value.textContent.includes(text));
  expect(button).toBeTruthy();
  await act(async () => button.click());
};

test('historical uncertain reply needs explicit keep action, remains visible, and blocks same-thread replay', async () => {
  await act(async () => root.render(<Inbox />));
  expect(node.textContent).not.toContain('Keep unresolved and start a different message');
  await click('Check pending mail');
  expect(mockMail.recover).toHaveBeenCalledTimes(1);
  expect(mockMail.keepUnresolved).not.toHaveBeenCalled();
  expect(node.textContent).toContain('may have sent');
  await act(async () => [...node.querySelectorAll('div')].find(value => value.textContent === message.subject).click());
  await click('Keep unresolved and start a different message');
  expect(mockMail.keepUnresolved).toHaveBeenCalledWith(5, expect.any(AbortSignal));
  expect(node.textContent).toContain('Thread #5: Earlier auto-reply is unresolved');
  const autoReply = [...node.querySelectorAll('button')].find(value => value.textContent.includes('Auto-reply (LLM01'));
  expect(autoReply.disabled).toBe(true);
  await click('Check saved status');
  expect(node.textContent).toContain('Saved reply confirmed');
  expect(node.textContent).toContain('Earlier auto-reply saved. Its recovery record is retained.');
  expect(autoReply.disabled).toBe(false);
  expect(mockMail.unresolved).toHaveLength(1);
});
