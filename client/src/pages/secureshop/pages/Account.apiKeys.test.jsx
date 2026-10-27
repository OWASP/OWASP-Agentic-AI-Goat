import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import Account from './Account';

let mockToken = 'bound-persona-token';
let mockAuthToken = 'bound-persona-token';
let mockUser = { id: 7, username: 'student_customer', role: 'customer' };
let mockBridgeMetadata = null;
jest.mock('../bridge/fetchAdapter.mjs', () => ({ getBridgeFetchMetadata: () => mockBridgeMetadata }));
const toast = { success: jest.fn(), error: jest.fn() };

jest.mock('framer-motion', () => ({
  motion: { section: ({ children, initial, animate, transition, ...props }) => (
    <section {...props}>{children}</section>
  ) },
}));
jest.mock('../context/AuthContext', () => ({
  useAuth: () => ({ user: mockUser, token: mockAuthToken,
    logout: jest.fn() }),
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
let clipboardDescriptor;
let execCommandDescriptor;
const key1 = `sk_ss_live_${'1'.repeat(32)}`;
const key2 = `sk_ss_live_${'2'.repeat(32)}`;

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
async function openApiKeys() {
  const tab = [...container.querySelectorAll('[role="tab"]')]
    .find(element => element.textContent.includes('API Keys'));
  await act(async () => tab.click());
  await settle();
}

beforeEach(async () => {
  jest.clearAllMocks();
  clipboardDescriptor = Object.getOwnPropertyDescriptor(global.navigator, 'clipboard');
  execCommandDescriptor = Object.getOwnPropertyDescriptor(document, 'execCommand');
  mockBridgeMetadata = null;
  mockToken = 'bound-persona-token';
  mockAuthToken = mockToken;
  mockUser = { id: 7, username: 'student_customer', role: 'customer' };
  global.IS_REACT_ACT_ENVIRONMENT = true;
  container = document.createElement('div');
  document.body.appendChild(container);
  root = createRoot(container);
  await act(async () => root.render(<Account />));
});
afterEach(async () => {
  await act(async () => root.unmount());
  container.remove();
  if (clipboardDescriptor) Object.defineProperty(global.navigator, 'clipboard', clipboardDescriptor);
  else delete global.navigator.clipboard;
  if (execCommandDescriptor) Object.defineProperty(document, 'execCommand', execCommandDescriptor);
  else delete document.execCommand;
  window.getSelection()?.removeAllRanges();
});

test('API key copy reports only an actual clipboard write', async () => {
  const writeText = jest.fn().mockResolvedValue(undefined);
  Object.defineProperty(global.navigator, 'clipboard', { configurable: true, value: { writeText } });
  global.fetch = jest.fn().mockResolvedValue(response({ api_key: key1,
    created_at: '2026-09-18T00:00:00.000Z', version: 1 }));
  await openApiKeys();
  const copy = [...container.querySelectorAll('button')].find(element => element.textContent.includes('Copy'));
  await act(async () => copy.click());
  await settle();
  expect(writeText).toHaveBeenCalledWith(key1);
  expect(toast.success).toHaveBeenCalledWith('API key copied to clipboard');

  jest.clearAllMocks();
  Object.defineProperty(global.navigator, 'clipboard', { configurable: true,
    value: { writeText: jest.fn().mockRejectedValue(new DOMException('Denied', 'NotAllowedError')) } });
  await act(async () => copy.click());
  await settle();
  expect(toast.error).toHaveBeenCalledWith('Clipboard access was denied; API key was not copied');
  expect(toast.success).not.toHaveBeenCalled();
});

test('API key copy reports unavailable clipboard without claiming success', async () => {
  Object.defineProperty(global.navigator, 'clipboard', { configurable: true, value: undefined });
  global.fetch = jest.fn().mockResolvedValue(response({ api_key: key1,
    created_at: '2026-09-18T00:00:00.000Z', version: 1 }));
  await openApiKeys();
  const copy = [...container.querySelectorAll('button')].find(element => element.textContent.includes('Copy'));
  await act(async () => copy.click());
  expect(toast.error).toHaveBeenCalledWith('Clipboard unavailable; API key was not copied');
  expect(toast.success).not.toHaveBeenCalled();
});

test('API key tab preserves the live-key UI and rotates through exact bound routes', async () => {
  global.fetch = jest.fn()
    .mockResolvedValueOnce(response({ api_key: key1,
      created_at: '2026-09-18T00:00:00.000Z', version: 1 }))
    .mockResolvedValueOnce(response({ ok: true, api_key: key2,
      created_at: '2026-09-18T00:00:00.000Z', version: 2 }));
  await openApiKeys();
  expect(container.textContent).toContain('Live API key');
  expect(container.textContent).toContain('keys are stored in plaintext in the DB');
  expect(global.fetch).toHaveBeenNthCalledWith(1,
    '/api/secureshop/v2/auth/users/me/api-keys',
    { headers: { Authorization: 'Bearer bound-persona-token' } });
  const rotate = [...container.querySelectorAll('button')]
    .find(element => element.textContent.includes('Rotate key'));
  await act(async () => rotate.click());
  expect(global.fetch).toHaveBeenCalledTimes(1);
  expect(container.querySelector('[role="dialog"]')?.textContent).toContain('current API key will stop working');
  const confirm = [...container.querySelectorAll('[role="dialog"] button')]
    .find(element => element.textContent.includes('Confirm rotation'));
  await act(async () => confirm.click());
  await settle();
  expect(global.fetch).toHaveBeenNthCalledWith(2,
    '/api/secureshop/v2/auth/users/me/api-keys/rotate',
    { method: 'POST', headers: { Authorization: 'Bearer bound-persona-token' } });
  expect(container.querySelector('input')?.value).toBe(key2);
  expect(toast.success).toHaveBeenCalledWith('New API key generated');
});

test('Cancel makes no key mutation, while a double Confirm issues only one rotation', async () => {
  const pending = deferred();
  global.fetch = jest.fn().mockResolvedValueOnce(response({ api_key: key1 }))
    .mockReturnValueOnce(pending.promise);
  await openApiKeys();
  const rotate = [...container.querySelectorAll('button')].find(button => button.textContent.includes('Rotate key'));
  await act(async () => rotate.click());
  expect(global.fetch).toHaveBeenCalledTimes(1);
  await act(async () => [...container.querySelectorAll('[role="dialog"] button')]
    .find(button => button.textContent.includes('Cancel')).click());
  expect(global.fetch).toHaveBeenCalledTimes(1);
  await act(async () => rotate.click());
  const confirm = [...container.querySelectorAll('[role="dialog"] button')]
    .find(button => button.textContent.includes('Confirm rotation'));
  await act(async () => { confirm.click(); confirm.click(); });
  expect(global.fetch).toHaveBeenCalledTimes(2);
  await act(async () => pending.resolve(response({ ok: true, api_key: key2 })));
  expect(container.querySelector('input')?.value).toBe(key2);
});

test('a staged key rotation is invalidated by bearer A→B→A and transport replacement', async () => {
  const original = jest.fn().mockResolvedValue(response({ api_key: key1 }));
  global.fetch = original;
  await openApiKeys();
  const rotate = [...container.querySelectorAll('button')].find(button => button.textContent.includes('Rotate key'));
  await act(async () => rotate.click());
  expect(container.querySelector('[role="dialog"]')).not.toBeNull();
  mockToken = 'other-token'; mockAuthToken = mockToken;
  await act(async () => root.render(<Account />));
  mockToken = 'bound-persona-token'; mockAuthToken = mockToken;
  await act(async () => root.render(<Account />));
  expect(container.querySelector('[role="dialog"]')).toBeNull();
  expect(original.mock.calls.filter(call => call[1]?.method === 'POST')).toHaveLength(0);
  await act(async () => rotate.click());
  const replacement = jest.fn().mockResolvedValue(response({ api_key: key2 }));
  global.fetch = replacement;
  await act(async () => root.render(<Account />));
  expect(container.querySelector('[role="dialog"]')).toBeNull();
  expect(original.mock.calls.filter(call => call[1]?.method === 'POST')).toHaveLength(0);
  expect(replacement.mock.calls.filter(call => call[1]?.method === 'POST')).toHaveLength(0);
});

test('unknown key rotation cannot become Generate until an explicit successful GET readback', async () => {
  global.fetch = jest.fn().mockResolvedValueOnce(response({ api_key: key1 }))
    .mockRejectedValueOnce(new Error('lost response'))
    .mockResolvedValueOnce(response({ api_key: key2 }));
  await openApiKeys();
  await act(async () => [...container.querySelectorAll('button')]
    .find(button => button.textContent.includes('Rotate key')).click());
  await act(async () => [...container.querySelectorAll('[role="dialog"] button')]
    .find(button => button.textContent === 'Confirm rotation').click());
  await settle();
  expect(container.textContent).toContain('Key state is unresolved');
  expect(container.textContent).toContain('The current API key is unknown');
  expect(container.textContent).not.toContain('You do not have an API key yet');
  const unavailable = [...container.querySelectorAll('button')]
    .find(button => button.textContent.includes('Key change unavailable'));
  expect(unavailable.disabled).toBe(true);
  await act(async () => unavailable.click());
  expect(global.fetch.mock.calls.filter(call => call[1]?.method === 'POST')).toHaveLength(1);
  await act(async () => [...container.querySelectorAll('button')]
    .find(button => button.textContent === 'Refresh key').click());
  await settle();
  expect(container.textContent).not.toContain('Key state is unresolved');
  expect(container.querySelector('input')?.value).toContain(key2.slice(0, 12));
});

test('a missing key requires explicit generation confirmation and Cancel sends no POST', async () => {
  global.fetch = jest.fn().mockResolvedValueOnce(response({ api_key: null }))
    .mockResolvedValueOnce(response({ ok: true, api_key: key1 }));
  await openApiKeys();
  const generate = [...container.querySelectorAll('button')]
    .find(button => button.textContent.includes('Generate key'));
  await act(async () => generate.click());
  expect(container.querySelector('[role="dialog"]')?.textContent).toContain('A new API key will be created');
  await act(async () => [...container.querySelectorAll('[role="dialog"] button')]
    .find(button => button.textContent === 'Cancel').click());
  expect(global.fetch).toHaveBeenCalledTimes(1);
  await act(async () => generate.click());
  await act(async () => [...container.querySelectorAll('[role="dialog"] button')]
    .find(button => button.textContent === 'Confirm generation').click());
  expect(global.fetch.mock.calls.filter(call => call[1]?.method === 'POST')).toHaveLength(1);
});

test('late API-key GET from the prior auth identity cannot replace the new identity key', async () => {
  const oldGet = deferred();
  global.fetch = jest.fn().mockReturnValueOnce(oldGet.promise)
    .mockResolvedValueOnce(response({ api_key: key2 }));
  await openApiKeys();
  mockToken = 'replacement-persona-token';
  mockAuthToken = mockToken;
  mockUser = { id: 8, username: 'replacement', role: 'customer' };
  await act(async () => root.render(<Account />));
  await settle();
  expect(global.fetch).toHaveBeenCalledTimes(2);
  await act(async () => oldGet.resolve(response({ api_key: key1 })));
  await settle();
  expect(container.textContent).toContain('replacement');
  expect(container.querySelector('input')?.value).toContain(key2.slice(0, 12));
  expect(container.querySelector('input')?.value).not.toContain(key1.slice(0, 12));
});

test('late API-key GET from a replaced transport cannot repopulate the tab', async () => {
  const oldGet = deferred();
  const original = jest.fn().mockReturnValueOnce(oldGet.promise);
  global.fetch = original;
  await openApiKeys();
  const replacement = jest.fn().mockResolvedValue(response({ api_key: key2 }));
  global.fetch = replacement;
  await act(async () => root.render(<Account />));
  await settle();
  expect(replacement).toHaveBeenCalledTimes(1);
  await act(async () => oldGet.resolve(response({ api_key: key1 })));
  await settle();
  expect(container.querySelector('input')?.value).toContain(key2.slice(0, 12));
  expect(container.querySelector('input')?.value).not.toContain(key1.slice(0, 12));
});

test('late rotate after auth and transport replacement cannot reveal or toast an old key', async () => {
  const oldRotate = deferred();
  const original = jest.fn().mockResolvedValueOnce(response({ api_key: key1 }))
    .mockReturnValueOnce(oldRotate.promise);
  global.fetch = original;
  await openApiKeys();
  const rotate = [...container.querySelectorAll('button')]
    .find(element => element.textContent.includes('Rotate key'));
  await act(async () => rotate.click());
  const confirm = [...container.querySelectorAll('[role="dialog"] button')]
    .find(element => element.textContent.includes('Confirm rotation'));
  await act(async () => confirm.click());
  const replacement = jest.fn().mockResolvedValue(response({ api_key: key2 }));
  global.fetch = replacement;
  mockToken = 'replacement-persona-token';
  mockAuthToken = mockToken;
  mockUser = { id: 8, username: 'replacement', role: 'customer' };
  await act(async () => root.render(<Account />));
  await settle();
  await act(async () => oldRotate.resolve(response({ ok: true, api_key: key1 })));
  await settle();
  expect(replacement).toHaveBeenCalledTimes(1);
  expect(container.querySelector('input')?.value).not.toBe(key1);
  expect(toast.success).not.toHaveBeenCalledWith('New API key generated');
});


test('bound Copy synchronously selects the exact key and restores focus and input selection', async () => {
  mockBridgeMetadata = { boundReviews: true, standalone: true };
  const writeText = jest.fn();
  Object.defineProperty(navigator, 'clipboard', { configurable: true, value: { writeText } });
  global.fetch = jest.fn().mockResolvedValue(response({ api_key: key1 }));
  await openApiKeys();
  const input = container.querySelector('input');
  input.focus(); input.setSelectionRange(2, 7, 'backward');
  let inClick = false;
  const command = jest.fn(name => {
    expect(inClick).toBe(true);
    expect(name).toBe('copy');
    const selected = document.activeElement;
    expect(selected.tagName).toBe('TEXTAREA');
    expect(selected.readOnly).toBe(true);
    expect(selected.value).toBe(key1);
    expect(selected.selectionStart).toBe(0);
    expect(selected.selectionEnd).toBe(key1.length);
    return true;
  });
  Object.defineProperty(document, 'execCommand', { configurable: true, value: command });
  const copy = [...container.querySelectorAll('button')].find(element => element.textContent.includes('Copy'));
  await act(async () => { inClick = true; copy.click(); inClick = false; });
  expect(command).toHaveBeenCalledTimes(1);
  expect(writeText).not.toHaveBeenCalled();
  expect(document.querySelector('textarea')).toBeNull();
  expect(document.activeElement).toBe(input);
  expect([input.selectionStart, input.selectionEnd, input.selectionDirection]).toEqual([2, 7, 'backward']);
  expect(input.value).not.toBe(key1); // Masked UI remains masked.
  expect(toast.success).toHaveBeenCalledWith('API key copied to clipboard');
});

test.each(['false', 'throw', 'unavailable'])('bound Copy %s is honest and never retries through async clipboard', async outcome => {
  mockBridgeMetadata = { boundReviews: true, standalone: true };
  const writeText = jest.fn().mockResolvedValue(undefined);
  Object.defineProperty(navigator, 'clipboard', { configurable: true, value: { writeText } });
  global.fetch = jest.fn().mockResolvedValue(response({ api_key: key1 }));
  await openApiKeys();
  const copy = [...container.querySelectorAll('button')].find(element => element.textContent.includes('Copy'));
  copy.focus();
  const text = container.querySelector('h3').firstChild, range = document.createRange();
  range.setStart(text, 0); range.setEnd(text, 4);
  window.getSelection().removeAllRanges(); window.getSelection().addRange(range);
  const command = outcome === 'unavailable' ? undefined : jest.fn(() => {
    if (outcome === 'throw') throw new DOMException('Denied', 'NotAllowedError');
    return false;
  });
  Object.defineProperty(document, 'execCommand', { configurable: true, value: command });
  await act(async () => copy.click());
  expect(toast.success).not.toHaveBeenCalled();
  expect(toast.error).toHaveBeenCalledWith(outcome === 'unavailable'
    ? 'Clipboard unavailable; API key was not copied' : 'Clipboard access was denied; API key was not copied');
  expect(writeText).not.toHaveBeenCalled();
  expect(document.querySelector('textarea')).toBeNull();
  expect(document.activeElement).toBe(copy);
  expect(window.getSelection().toString()).toBe('Live');
});
