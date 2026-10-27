import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import Account from './Account';

let mockLogout = jest.fn();
let mockToken = 'bound-persona-token';
const toast = { success: jest.fn(), error: jest.fn() };

jest.mock('framer-motion', () => ({
  motion: { section: ({ children, initial, animate, transition, ...props }) => (
    <section {...props}>{children}</section>
  ) },
}));
jest.mock('../context/AuthContext', () => ({
  useAuth: () => ({ user: { id: 7, username: 'student_customer', role: 'customer' },
    logout: mockLogout }),
}));
jest.mock('../context/ToastContext.jsx', () => ({ useToast: () => toast }));
jest.mock('../components/Button.jsx', () => ({ children, icon, loading, ...props }) => (
  <button {...props}>{icon}{children}</button>
));
jest.mock('../components/Card.jsx', () => ({ children }) => <div>{children}</div>);
jest.mock('../components/Dialog.jsx', () => ({ open, title, children, footer, onClose }) => open
  ? <div role="dialog" aria-label={title}><button onClick={onClose}>Close dialog</button>{children}{footer}</div> : null);
jest.mock('../components/Input.jsx', () => props => <input {...props} />);
jest.mock('../components/Badge.jsx', () => ({ children }) => <span>{children}</span>);
jest.mock('../components/UploadZone.jsx', () => () => null);
jest.mock('../utils/shopStorage.mjs', () => ({
  shopStorage: { getItem: () => mockToken },
}));

let container;
let root;

function response(body, status = 200) {
  return { ok: status >= 200 && status < 300, status,
    json: jest.fn().mockResolvedValue(body) };
}

function deferred() {
  let resolve;
  const promise = new Promise(value => { resolve = value; });
  return { promise, resolve };
}

async function settle() {
  await act(async () => {
    await Promise.resolve();
    await Promise.resolve();
    await Promise.resolve();
  });
}

async function openSessions() {
  const tab = [...container.querySelectorAll('[role="tab"]')]
    .find(element => element.textContent.includes('Sessions'));
  await act(async () => tab.click());
  await settle();
}

beforeEach(async () => {
  jest.clearAllMocks();
  mockLogout = jest.fn().mockResolvedValue();
  mockToken = 'bound-persona-token';
  global.IS_REACT_ACT_ENVIRONMENT = true;
  container = document.createElement('div');
  document.body.appendChild(container);
  root = createRoot(container);
  await act(async () => root.render(<Account />));
});

afterEach(async () => {
  await act(async () => root.unmount());
  container.remove();
});

test('non-auth inventory failures render the server error instead of a false empty state', async () => {
  global.fetch = jest.fn().mockResolvedValue(response({ error: 'inventory unavailable' }, 503));
  await openSessions();
  expect(container.querySelector('[role="alert"]')?.textContent)
    .toContain('Unable to load sessions: inventory unavailable');
  expect(container.textContent).not.toContain('No active sessions found');
  expect(mockLogout).not.toHaveBeenCalled();
});

test.each([401, 403])('inventory status %s clears the authenticated identity', async status => {
  global.fetch = jest.fn().mockResolvedValue(response({ error: 'invalid identity' }, status));
  await openSessions();
  expect(mockLogout).toHaveBeenCalledTimes(1);
});

test('revoking the current row clears auth without reloading with the revoked bearer', async () => {
  global.fetch = jest.fn()
    .mockResolvedValueOnce(response({ sessions: [{ id: 'current', user_agent: 'Browser',
      ip: '127.0.0.1', created_at: '2026-09-18T00:00:00Z',
      last_seen_at: '2026-09-18T00:01:00Z', is_current: true }] }))
    .mockResolvedValueOnce(response({ ok: true }));
  await openSessions();
  const revoke = [...container.querySelectorAll('button')]
    .find(element => element.textContent.includes('Revoke'));
  await act(async () => revoke.click());
  expect(global.fetch).toHaveBeenCalledTimes(1);
  expect(container.querySelector('[role="dialog"]')?.textContent).toContain('will sign you out');
  await act(async () => [...container.querySelectorAll('[role="dialog"] button')]
    .find(element => element.textContent.includes('Confirm revoke')).click());
  await settle();
  expect(mockLogout).toHaveBeenCalledTimes(1);
  expect(global.fetch).toHaveBeenCalledTimes(2);
});

test('revoking a sibling session reloads inventory and retains current auth', async () => {
  global.fetch = jest.fn()
    .mockResolvedValueOnce(response({ sessions: [{ id: 'other', user_agent: 'Old Browser',
      ip: null, created_at: '2026-09-18T00:00:00Z',
      last_seen_at: '2026-09-18T00:01:00Z', is_current: false }] }))
    .mockResolvedValueOnce(response({ ok: true }))
    .mockResolvedValueOnce(response({ sessions: [] }));
  await openSessions();
  const revoke = [...container.querySelectorAll('button')]
    .find(element => element.textContent.includes('Revoke'));
  await act(async () => revoke.click());
  expect(container.querySelector('[role="dialog"]')?.textContent).toContain('Your current session will remain signed in');
  await act(async () => [...container.querySelectorAll('[role="dialog"] button')]
    .find(element => element.textContent.includes('Confirm revoke')).click());
  await settle();
  expect(mockLogout).not.toHaveBeenCalled();
  expect(global.fetch).toHaveBeenCalledTimes(3);
  expect(container.textContent).toContain('No active sessions found');
});

test('Cancel makes no revoke request and double Confirm still targets exactly one selected session', async () => {
  const pending = deferred();
  global.fetch = jest.fn().mockResolvedValueOnce(response({ sessions: [{ id: 'other',
    user_agent: 'Old Browser', ip: '192.0.2.2', is_current: false }] }))
    .mockReturnValueOnce(pending.promise).mockResolvedValueOnce(response({ sessions: [] }));
  await openSessions();
  const revoke = [...container.querySelectorAll('button')].find(button => button.textContent === 'Revoke');
  await act(async () => revoke.click());
  expect(container.querySelector('[role="dialog"]')?.textContent).toContain('Old Browser (192.0.2.2), session other');
  await act(async () => [...container.querySelectorAll('[role="dialog"] button')]
    .find(button => button.textContent === 'Cancel').click());
  expect(global.fetch).toHaveBeenCalledTimes(1);
  await act(async () => revoke.click());
  const confirm = [...container.querySelectorAll('[role="dialog"] button')]
    .find(button => button.textContent === 'Confirm revoke');
  await act(async () => { confirm.click(); confirm.click(); });
  expect(global.fetch).toHaveBeenCalledTimes(2);
  expect(global.fetch).toHaveBeenNthCalledWith(2,
    '/api/secureshop/v2/auth/users/me/sessions/other/revoke',
    { method: 'POST', headers: { Authorization: 'Bearer bound-persona-token' } });
  await act(async () => pending.resolve(response({ ok: true })));
  await settle();
  expect(global.fetch).toHaveBeenCalledTimes(3);
});

test('staged revoke cannot use stale rows after bearer A→B→A or transport replacement', async () => {
  const otherRead = deferred();
  const original = jest.fn().mockResolvedValueOnce(response({ sessions: [{ id: 'other',
    user_agent: 'Old Browser', is_current: false }] }))
    .mockReturnValueOnce(otherRead.promise)
    .mockResolvedValue(response({ sessions: [{ id: 'other', user_agent: 'Old Browser', is_current: false }] }));
  global.fetch = original;
  await openSessions();
  const revoke = [...container.querySelectorAll('button')].find(button => button.textContent === 'Revoke');
  await act(async () => revoke.click());
  mockToken = 'other-token';
  await act(async () => root.render(<Account />));
  expect(container.textContent).not.toContain('Old Browser');
  mockToken = 'bound-persona-token';
  await act(async () => root.render(<Account />));
  expect(container.querySelector('[role="dialog"]')).toBeNull();
  await act(async () => revoke.click());
  expect(container.querySelector('[role="dialog"]')).toBeNull();
  const replacement = jest.fn().mockResolvedValue(response({ sessions: [] }));
  global.fetch = replacement;
  await act(async () => root.render(<Account />));
  expect(container.textContent).not.toContain('Old Browser');
  expect(original.mock.calls.filter(call => call[1]?.method === 'POST')).toHaveLength(0);
  expect(replacement.mock.calls.filter(call => call[1]?.method === 'POST')).toHaveLength(0);
});

test('unknown revoke outcome blocks another POST until an explicit successful sessions refresh', async () => {
  const session = { id: 'other', user_agent: 'Old Browser', is_current: false };
  global.fetch = jest.fn().mockResolvedValueOnce(response({ sessions: [session] }))
    .mockRejectedValueOnce(new Error('lost response'))
    .mockResolvedValueOnce(response({ sessions: [session] }));
  await openSessions();
  const revoke = [...container.querySelectorAll('button')].find(button => button.textContent === 'Revoke');
  await act(async () => revoke.click());
  await act(async () => [...container.querySelectorAll('[role="dialog"] button')]
    .find(button => button.textContent === 'Confirm revoke').click());
  await settle();
  expect(container.textContent).toContain('Session change is unresolved');
  await act(async () => revoke.click());
  expect(global.fetch.mock.calls.filter(call => call[1]?.method === 'POST')).toHaveLength(1);
  await act(async () => [...container.querySelectorAll('button')]
    .find(button => button.textContent === 'Refresh').click());
  await settle();
  expect(container.textContent).not.toContain('Session change is unresolved');
});

test('a delayed inventory 401 from an old auth generation cannot log out the replacement', async () => {
  const oldLogout = mockLogout;
  const pending = deferred();
  global.fetch = jest.fn()
    .mockReturnValueOnce(pending.promise)
    .mockResolvedValueOnce(response({ sessions: [] }));
  await openSessions();
  const replacementLogout = jest.fn().mockResolvedValue();
  mockLogout = replacementLogout;
  await act(async () => root.render(<Account />));
  await settle();
  await act(async () => pending.resolve(response({ error: 'old identity' }, 401)));
  await settle();
  expect(oldLogout).not.toHaveBeenCalled();
  expect(replacementLogout).not.toHaveBeenCalled();
});

test('a delayed revoke from an old auth generation cannot toast, reload or log out the replacement', async () => {
  const oldLogout = mockLogout;
  const pending = deferred();
  global.fetch = jest.fn()
    .mockResolvedValueOnce(response({ sessions: [{ id: 'current', user_agent: 'Browser',
      ip: null, created_at: '2026-09-18T00:00:00Z',
      last_seen_at: '2026-09-18T00:01:00Z', is_current: true }] }))
    .mockReturnValueOnce(pending.promise)
    .mockResolvedValueOnce(response({ sessions: [] }));
  await openSessions();
  const revoke = [...container.querySelectorAll('button')]
    .find(element => element.textContent.includes('Revoke'));
  await act(async () => revoke.click());
  await act(async () => [...container.querySelectorAll('[role="dialog"] button')]
    .find(element => element.textContent.includes('Confirm revoke')).click());
  const replacementLogout = jest.fn().mockResolvedValue();
  mockLogout = replacementLogout;
  await act(async () => root.render(<Account />));
  await settle();
  await act(async () => pending.resolve(response({ ok: true })));
  await settle();
  expect(oldLogout).not.toHaveBeenCalled();
  expect(replacementLogout).not.toHaveBeenCalled();
  expect(toast.success).not.toHaveBeenCalled();
  expect(global.fetch).toHaveBeenCalledTimes(3);
});

test('a delayed inventory 401 cannot clear a token persisted before the auth callback rerenders', async () => {
  const pending = deferred();
  global.fetch = jest.fn().mockReturnValueOnce(pending.promise);
  await openSessions();
  mockToken = 'replacement-persona-token';
  await act(async () => pending.resolve(response({ error: 'old identity' }, 401)));
  await settle();
  expect(mockLogout).not.toHaveBeenCalled();
  expect(container.textContent).not.toContain('Unable to load sessions');
});

test('a delayed current-session revoke cannot clear or toast after storage switches tokens', async () => {
  const pending = deferred();
  global.fetch = jest.fn()
    .mockResolvedValueOnce(response({ sessions: [{ id: 'current', user_agent: 'Browser',
      ip: null, created_at: '2026-09-18T00:00:00Z',
      last_seen_at: '2026-09-18T00:01:00Z', is_current: true }] }))
    .mockReturnValueOnce(pending.promise);
  await openSessions();
  const revoke = [...container.querySelectorAll('button')]
    .find(element => element.textContent.includes('Revoke'));
  await act(async () => revoke.click());
  await act(async () => [...container.querySelectorAll('[role="dialog"] button')]
    .find(element => element.textContent.includes('Confirm revoke')).click());
  mockToken = 'replacement-persona-token';
  await act(async () => pending.resolve(response({ ok: true })));
  await settle();
  expect(mockLogout).not.toHaveBeenCalled();
  expect(toast.success).not.toHaveBeenCalled();
  expect(global.fetch).toHaveBeenCalledTimes(2);
});
