/* eslint-disable testing-library/no-unnecessary-act -- React DOM createRoot is used directly. */
import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import axios from 'axios';
import { toast } from 'react-toastify';
import CTFAdminPanel from './CTFAdminPanel';
import { AuthProvider, useAuth } from '../../context/AuthContext';

jest.mock('axios', () => ({ get: jest.fn(), post: jest.fn(), put: jest.fn(), delete: jest.fn(),
  defaults: { headers: { common: {} } }, interceptors: { response: { use: jest.fn(), eject: jest.fn() } } }));
jest.mock('react-toastify', () => ({ toast: { error: jest.fn(), success: jest.fn() } }));

async function flush() {
  await act(async () => {
    await Promise.resolve();
    await Promise.resolve();
    await Promise.resolve();
  });
}

function button(root, text) {
  return [...root.querySelectorAll('button')].find(node => node.textContent.includes(text));
}

beforeEach(() => {
  global.IS_REACT_ACT_ENVIRONMENT = true;
  localStorage.clear();
  localStorage.setItem('token', 'admin-token');
  axios.get.mockResolvedValue({ data: { analytics: {} } });
});

afterEach(() => {
  localStorage.clear();
  jest.restoreAllMocks();
});

test('blocklist clear reserves its destructive action before React rerenders', async () => {
  let finish;
  axios.post.mockImplementation(() => new Promise(resolve => { finish = resolve; }));
  const nativeConfirm = jest.spyOn(window, 'confirm');
  const node = document.createElement('div'); document.body.appendChild(node);
  const root = createRoot(node);
  try {
    await act(async () => root.render(<CTFAdminPanel />)); await flush();
    await act(async () => button(node, 'Danger Zone').click()); await flush();
    const clear = button(node, 'Clear Technique Blocklist');
    act(() => { clear.click(); clear.click(); });
    expect(document.querySelectorAll('[role="dialog"]')).toHaveLength(1);
    const confirm = button(document, 'Clear Blocklist');
    act(() => { confirm.click(); confirm.click(); });
    expect(axios.post).toHaveBeenCalledTimes(1);
    expect(nativeConfirm).not.toHaveBeenCalled();
    expect(axios.post).toHaveBeenCalledWith('/api/ctf/admin/blocklists/technique/clear', {}, expect.objectContaining({ headers: { Authorization: 'Bearer admin-token' } }));
    await act(async () => finish({ status: 200, data: { message: 'Technique blocklist cleared' } }));
    await flush();
  } finally { await act(async () => root.unmount()); node.remove(); }
});

test('blocklist clear Cancel sends nothing and an A→B→A change inside confirmation cannot dispatch', async () => {
  const nativeConfirm = jest.spyOn(window, 'confirm');
  const node = document.createElement('div'); document.body.appendChild(node);
  const root = createRoot(node);
  try {
    await act(async () => root.render(<CTFAdminPanel />)); await flush();
    await act(async () => button(node, 'Danger Zone').click()); await flush();
    await act(async () => button(node, 'Clear Technique Blocklist').click()); await flush();
    expect(document.querySelector('[role="dialog"]')?.textContent).toContain('cannot be undone');
    await act(async () => button(document, 'Cancel').click()); await flush();
    expect(axios.post).not.toHaveBeenCalled();
    await act(async () => button(node, 'Clear Technique Blocklist').click()); await flush();
    const staleConfirm = button(document, 'Clear Blocklist');
    await act(async () => {
      localStorage.setItem('token', 'other-admin-token');
      window.dispatchEvent(new StorageEvent('storage', { key: 'token', storageArea: localStorage }));
      localStorage.setItem('token', 'admin-token');
      window.dispatchEvent(new StorageEvent('storage', { key: 'token', storageArea: localStorage }));
      staleConfirm.click();
    });
    expect(document.querySelector('[role="dialog"]')).toBeNull();
    expect(axios.post).not.toHaveBeenCalled();
    expect(nativeConfirm).not.toHaveBeenCalled();
  } finally { await act(async () => root.unmount()); node.remove(); }
});

test('blocklist and full reset cannot stage overlapping destructive confirmations', async () => {
  const node = document.createElement('div'); document.body.appendChild(node);
  const root = createRoot(node);
  try {
    await act(async () => root.render(<CTFAdminPanel />)); await flush();
    await act(async () => button(node, 'Danger Zone').click()); await flush();
    const input = node.querySelector('input[placeholder="RESET_CTF_CONFIRM"]');
    await act(async () => {
      Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set.call(input, 'RESET_CTF_CONFIRM');
      input.dispatchEvent(new Event('input', { bubbles: true }));
    });
    const blocklist = button(node, 'Clear Technique Blocklist');
    const reset = button(node, 'Full CTF Reset');
    act(() => { blocklist.click(); reset.click(); });
    expect(document.querySelectorAll('[role="dialog"]')).toHaveLength(1);
    expect(document.querySelector('[role="alertdialog"]')).toBeNull();
    expect(reset.disabled).toBe(true);
    await act(async () => button(document, 'Cancel').click()); await flush();
    expect(reset.disabled).toBe(false);
    act(() => { reset.click(); blocklist.click(); });
    expect(document.querySelector('[role="dialog"]')).toBeNull();
    expect(document.querySelectorAll('[role="alertdialog"]')).toHaveLength(1);
    expect(blocklist.disabled).toBe(true);
    await act(async () => button(document, 'Cancel').click()); await flush();
    expect(blocklist.disabled).toBe(false);
    expect(axios.post).not.toHaveBeenCalled();
    await act(async () => blocklist.click()); await flush();
    await act(async () => button(document, 'Clear Blocklist').click()); await flush();
    expect(axios.post).toHaveBeenCalledTimes(1);
    expect(axios.post.mock.calls[0][0]).toBe('/api/ctf/admin/blocklists/technique/clear');
  } finally { await act(async () => root.unmount()); node.remove(); }
});

test('blocklist clear pending response after a cross-tab A→B→A cycle has no stale success', async () => {
  let finish;
  axios.post.mockImplementation(() => new Promise(resolve => { finish = resolve; }));
  const node = document.createElement('div'); document.body.appendChild(node);
  const root = createRoot(node);
  try {
    await act(async () => root.render(<CTFAdminPanel />)); await flush();
    await act(async () => button(node, 'Danger Zone').click()); await flush();
    await act(async () => button(node, 'Clear Payload Blocklist').click()); await flush();
    await act(async () => button(document, 'Clear Blocklist').click()); await flush();
    expect(axios.post).toHaveBeenCalledTimes(1);
    await act(async () => {
      localStorage.setItem('token', 'other-admin-token');
      window.dispatchEvent(new StorageEvent('storage', { key: 'token', storageArea: localStorage }));
      localStorage.setItem('token', 'admin-token');
      window.dispatchEvent(new StorageEvent('storage', { key: 'token', storageArea: localStorage }));
    });
    await act(async () => finish({ status: 200, data: { message: 'Payload blocklist cleared' } })); await flush();
    expect(toast.success).not.toHaveBeenCalled();
    expect(axios.post).toHaveBeenCalledTimes(1);
  } finally { await act(async () => root.unmount()); node.remove(); }
});

test('blocklist clear pending response after a same-token auth revision change has no stale error', async () => {
  let auth;
  let failClear;
  function Probe() { auth = useAuth(); return null; }
  axios.get.mockImplementation(url => url === '/api/auth/status'
    ? Promise.resolve({ data: { authenticated: true, user: { id: 1, username: 'admin', security_level: 2 } } })
    : Promise.resolve({ data: { analytics: {} } }));
  axios.post.mockImplementation((url) => url === '/api/auth/login'
    ? Promise.resolve({ data: { token: 'admin-token', user: { id: 1, username: 'admin', security_level: 2 } } })
    : new Promise((resolve, reject) => { failClear = reject; }));
  const node = document.createElement('div'); document.body.appendChild(node);
  const root = createRoot(node);
  try {
    await act(async () => root.render(<AuthProvider><Probe /><CTFAdminPanel /></AuthProvider>)); await flush();
    await act(async () => button(node, 'Danger Zone').click()); await flush();
    await act(async () => button(node, 'Clear Technique Blocklist').click()); await flush();
    await act(async () => button(document, 'Clear Blocklist').click()); await flush();
    expect(axios.post.mock.calls.filter(([url]) => url.includes('/blocklists/'))).toHaveLength(1);
    await act(async () => auth.login('admin', 'ignored')); await flush();
    expect(localStorage.getItem('token')).toBe('admin-token');
    await act(async () => failClear({ response: { status: 403, data: { error: 'Prior admin rejected' } } })); await flush();
    expect(toast.error).not.toHaveBeenCalled();
    expect(toast.success).not.toHaveBeenCalled();
  } finally { await act(async () => root.unmount()); node.remove(); }
});

test('blocklist clear parked recovery cannot check status after storage authority retirement', async () => {
  const operationId = '10000000-0000-0000-0000-000000000001';
  axios.post.mockResolvedValue({ status: 202, data: { pending: true, operationId } });
  axios.get.mockImplementation(url => url === `/api/ctf/operations/${operationId}`
    ? Promise.reject(new Error('Current status temporarily unavailable'))
    : Promise.resolve({ data: { analytics: {} } }));
  const node = document.createElement('div'); document.body.appendChild(node);
  const root = createRoot(node);
  try {
    await act(async () => root.render(<CTFAdminPanel />)); await flush();
    await act(async () => button(node, 'Danger Zone').click()); await flush();
    await act(async () => button(node, 'Clear Payload Blocklist').click()); await flush();
    await act(async () => button(document, 'Clear Blocklist').click()); await flush();
    const check = button(node, 'Check status');
    expect(check).toBeTruthy();
    const reads = axios.get.mock.calls.filter(([url]) => url === `/api/ctf/operations/${operationId}`).length;
    act(() => {
      localStorage.setItem('token', 'other-admin-token');
      window.dispatchEvent(new StorageEvent('storage', { key: 'token', storageArea: localStorage }));
      localStorage.setItem('token', 'admin-token');
      window.dispatchEvent(new StorageEvent('storage', { key: 'token', storageArea: localStorage }));
      check.click();
    });
    await flush();
    expect(axios.get.mock.calls.filter(([url]) => url === `/api/ctf/operations/${operationId}`)).toHaveLength(reads);
    expect(axios.post.mock.calls.filter(([url]) => url.includes('/blocklists/'))).toHaveLength(1);
    expect(toast.success).not.toHaveBeenCalled();
  } finally { await act(async () => root.unmount()); node.remove(); }
});

test('full reset retains typed confirmation and sends one request from the accessible dialog', async () => {
  let finish;
  axios.post.mockImplementation(() => new Promise(resolve => { finish = resolve; }));
  const confirm = jest.spyOn(window, 'confirm').mockReturnValue(true);
  const node = document.createElement('div'); document.body.appendChild(node);
  const root = createRoot(node);
  try {
    await act(async () => root.render(<CTFAdminPanel />)); await flush();
    await act(async () => button(node, 'Danger Zone').click()); await flush();
    const input = node.querySelector('input[placeholder="RESET_CTF_CONFIRM"]');
    await act(async () => {
      Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set.call(input, 'RESET_CTF_CONFIRM');
      input.dispatchEvent(new Event('input', { bubbles: true }));
    });
    const reset = button(node, 'Full CTF Reset');
    expect(reset.disabled).toBe(false);
    await act(async () => reset.click()); await flush();
    const dialog = document.querySelector('[role="alertdialog"]');
    expect(dialog).not.toBeNull();
    expect(dialog.textContent).toContain('This deletes all CTF participants');
    const dialogConfirm = button(document, 'Confirm reset');
    act(() => { dialogConfirm.click(); dialogConfirm.click(); });
    expect(axios.post).toHaveBeenCalledTimes(1);
    expect(axios.post).toHaveBeenCalledWith('/api/ctf/admin/reset', { confirm: 'RESET_CTF_CONFIRM' }, expect.objectContaining({ headers: { Authorization: 'Bearer admin-token' } }));
    expect(confirm).not.toHaveBeenCalled();
    await act(async () => finish({ status: 200, data: { message: 'CTF reset successfully' } }));
    await flush();
  } finally { await act(async () => root.unmount()); node.remove(); }
});

test('full reset staged under another admin token cannot be confirmed, but can be restaged', async () => {
  const node = document.createElement('div'); document.body.appendChild(node);
  const root = createRoot(node);
  try {
    await act(async () => root.render(<CTFAdminPanel />)); await flush();
    await act(async () => button(node, 'Danger Zone').click()); await flush();
    const input = node.querySelector('input[placeholder="RESET_CTF_CONFIRM"]');
    await act(async () => {
      Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set.call(input, 'RESET_CTF_CONFIRM');
      input.dispatchEvent(new Event('input', { bubbles: true }));
    });
    await act(async () => button(node, 'Full CTF Reset').click()); await flush();
    expect(document.querySelector('[role="alertdialog"]')).not.toBeNull();
    localStorage.setItem('token', 'other-admin-token');
    await act(async () => button(document, 'Confirm reset').click()); await flush();
    expect(axios.post).not.toHaveBeenCalled();
    await act(async () => button(node, 'Full CTF Reset').click()); await flush();
    await act(async () => button(document, 'Confirm reset').click()); await flush();
    expect(axios.post).toHaveBeenCalledTimes(1);
    expect(axios.post).toHaveBeenCalledWith('/api/ctf/admin/reset', { confirm: 'RESET_CTF_CONFIRM' }, expect.objectContaining({ headers: { Authorization: 'Bearer other-admin-token' } }));
  } finally { await act(async () => root.unmount()); node.remove(); }
});

test('full reset rejects a token A→B→A cycle observed by the auth provider', async () => {
  let auth;
  function Probe() { auth = useAuth(); return null; }
  axios.get.mockImplementation(url => url === '/api/auth/status'
    ? Promise.resolve({ data: { authenticated: true, user: { id: 1, username: 'admin', security_level: 2 } } })
    : Promise.resolve({ data: { analytics: {} } }));
  axios.post.mockImplementation((url, body) => url === '/api/auth/login'
    ? Promise.resolve({ data: { token: body.username === 'other' ? 'other-admin-token' : 'admin-token', user: { id: 1, username: 'admin', security_level: 2 } } })
    : Promise.resolve({ status: 200, data: { message: 'CTF reset successfully' } }));
  const node = document.createElement('div'); document.body.appendChild(node);
  const root = createRoot(node);
  try {
    await act(async () => root.render(<AuthProvider><Probe /><CTFAdminPanel /></AuthProvider>)); await flush();
    await act(async () => button(node, 'Danger Zone').click()); await flush();
    const input = node.querySelector('input[placeholder="RESET_CTF_CONFIRM"]');
    await act(async () => {
      Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set.call(input, 'RESET_CTF_CONFIRM');
      input.dispatchEvent(new Event('input', { bubbles: true }));
    });
    await act(async () => button(node, 'Full CTF Reset').click()); await flush();
    await act(async () => auth.login('other', 'ignored')); await flush();
    await act(async () => auth.login('admin', 'ignored')); await flush();
    expect(localStorage.getItem('token')).toBe('admin-token');
    await act(async () => button(document, 'Confirm reset').click()); await flush();
    expect(axios.post.mock.calls.filter(([url]) => url === '/api/ctf/admin/reset')).toHaveLength(0);
  } finally { await act(async () => root.unmount()); node.remove(); }
});

test('late full-reset success after an A→B→A login cycle does not show stale success', async () => {
  let auth;
  let finishReset;
  function Probe() { auth = useAuth(); return null; }
  axios.get.mockImplementation(url => url === '/api/auth/status'
    ? Promise.resolve({ data: { authenticated: true, user: { id: 1, username: 'admin', security_level: 2 } } })
    : Promise.resolve({ data: { analytics: {} } }));
  axios.post.mockImplementation((url, body) => {
    if (url === '/api/auth/login') return Promise.resolve({ data: { token: body.username === 'other' ? 'other-admin-token' : 'admin-token', user: { id: 1, username: 'admin', security_level: 2 } } });
    if (url === '/api/ctf/admin/reset') return new Promise(resolve => { finishReset = resolve; });
    return Promise.resolve({});
  });
  const node = document.createElement('div'); document.body.appendChild(node);
  const root = createRoot(node);
  try {
    await act(async () => root.render(<AuthProvider><Probe /><CTFAdminPanel /></AuthProvider>)); await flush();
    await act(async () => button(node, 'Danger Zone').click()); await flush();
    const input = node.querySelector('input[placeholder="RESET_CTF_CONFIRM"]');
    await act(async () => {
      Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set.call(input, 'RESET_CTF_CONFIRM');
      input.dispatchEvent(new Event('input', { bubbles: true }));
    });
    await act(async () => button(node, 'Full CTF Reset').click()); await flush();
    await act(async () => button(document, 'Confirm reset').click()); await flush();
    expect(axios.post.mock.calls.filter(([url]) => url === '/api/ctf/admin/reset')).toHaveLength(1);
    await act(async () => auth.login('other', 'ignored')); await flush();
    await act(async () => auth.login('admin', 'ignored')); await flush();
    await act(async () => finishReset({ status: 200, data: { message: 'CTF reset successfully' } })); await flush();
    expect(toast.success).not.toHaveBeenCalled();
    expect(axios.post.mock.calls.filter(([url]) => url === '/api/ctf/admin/reset')).toHaveLength(1);
  } finally { await act(async () => root.unmount()); node.remove(); }
});

test('full reset staged dialog is retired by a cross-tab A→B→A cycle before React rerenders', async () => {
  const node = document.createElement('div'); document.body.appendChild(node);
  const root = createRoot(node);
  try {
    await act(async () => root.render(<CTFAdminPanel />)); await flush();
    await act(async () => button(node, 'Danger Zone').click()); await flush();
    const input = node.querySelector('input[placeholder="RESET_CTF_CONFIRM"]');
    await act(async () => {
      Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set.call(input, 'RESET_CTF_CONFIRM');
      input.dispatchEvent(new Event('input', { bubbles: true }));
    });
    await act(async () => button(node, 'Full CTF Reset').click()); await flush();
    const staleConfirm = button(document, 'Confirm reset');
    act(() => {
      localStorage.setItem('token', 'other-admin-token');
      window.dispatchEvent(new StorageEvent('storage', { key: 'token', storageArea: localStorage }));
      localStorage.setItem('token', 'admin-token');
      window.dispatchEvent(new StorageEvent('storage', { key: 'token', storageArea: localStorage }));
      staleConfirm.click();
    });
    await flush();
    expect(axios.post).not.toHaveBeenCalled();
    expect(document.querySelector('[role="alertdialog"]')).toBeNull();
    await act(async () => button(node, 'Full CTF Reset').click()); await flush();
    const cancelledConfirm = button(document, 'Confirm reset');
    act(() => { button(document, 'Cancel').click(); cancelledConfirm.click(); });
    await flush();
    expect(axios.post).not.toHaveBeenCalled();
    await act(async () => button(node, 'Full CTF Reset').click()); await flush();
    await act(async () => button(document, 'Confirm reset').click()); await flush();
    expect(axios.post).toHaveBeenCalledTimes(1);
  } finally { await act(async () => root.unmount()); node.remove(); }
});

test('participant reset confirmation reserves its owner before React rerenders', async () => {
  let finish;
  axios.get.mockImplementation((url) => {
    if (url === '/api/ctf/leaderboard') return Promise.resolve({ data: { leaderboard: [{ participant_id: 71, username: 'learner-one' }] } });
    if (url === '/api/ctf/admin/participants') return Promise.resolve({ data: { participants: [{ id: 71, user_id: 44, username: 'learner-one' }] } });
    return Promise.resolve({ data: { analytics: {} } });
  });
  axios.post.mockImplementation(() => new Promise(resolve => { finish = resolve; }));
  const node = document.createElement('div'); document.body.appendChild(node);
  const root = createRoot(node);
  try {
    await act(async () => root.render(<CTFAdminPanel />)); await flush();
    await act(async () => button(node, 'Leaderboard').click()); await flush();
    await act(async () => [...node.querySelectorAll('button')].find(item => item.textContent.trim() === 'Reset').click());
    const dialog = node.querySelector('[role="dialog"]');
    expect(dialog.textContent).toContain('Shared winning-payload fingerprints remain active for everyone.');
    const confirm = button(dialog, 'Reset Progress');
    act(() => { confirm.click(); confirm.click(); });
    expect(axios.post).toHaveBeenCalledTimes(1);
    expect(axios.post).toHaveBeenCalledWith('/api/ctf/admin/participants/44/reset', {}, expect.objectContaining({ headers: { Authorization: 'Bearer admin-token' } }));
    await act(async () => finish({ status: 200, data: { message: 'Participant reset' } }));
    await flush();
  } finally { await act(async () => root.unmount()); node.remove(); }
});

test('Ban reason prompt stages a cancellable consequence review before any POST', async () => {
  axios.get.mockImplementation(url => {
    if (url === '/api/ctf/leaderboard') return Promise.resolve({ data: { leaderboard: [{ participant_id: 71, username: 'learner-one' }] } });
    if (url === '/api/ctf/admin/participants') return Promise.resolve({ data: { participants: [{ id: 71, user_id: 44, username: 'learner-one', is_banned: false }] } });
    return Promise.resolve({ data: { analytics: {} } });
  });
  const prompt = jest.spyOn(window, 'prompt').mockReturnValue('controlled reason');
  const node = document.createElement('div'); document.body.appendChild(node);
  const root = createRoot(node);
  try {
    await act(async () => root.render(<CTFAdminPanel />)); await flush();
    await act(async () => button(node, 'Leaderboard').click()); await flush();
    await act(async () => button(node, 'Ban').click()); await flush();
    expect(prompt).toHaveBeenCalledTimes(1);
    expect(axios.post).not.toHaveBeenCalled();
    const dialog = node.querySelector('[role="dialog"]');
    expect(dialog?.textContent).toContain('learner-one');
    await act(async () => button(dialog, 'Cancel').click()); await flush();
    expect(axios.post).not.toHaveBeenCalled();
  } finally { await act(async () => root.unmount()); node.remove(); }
});

test('Unban requires a cancellable consequence review after authoritative roster readback', async () => {
  axios.get.mockImplementation(url => {
    if (url === '/api/ctf/leaderboard') return Promise.resolve({ data: { leaderboard: [{ participant_id: 71, username: 'learner-one' }] } });
    if (url === '/api/ctf/admin/participants') return Promise.resolve({ data: { participants: [{ id: 71, user_id: 44, username: 'learner-one', is_banned: true }] } });
    return Promise.resolve({ data: { analytics: {} } });
  });
  const node = document.createElement('div'); document.body.appendChild(node);
  const root = createRoot(node);
  try {
    await act(async () => root.render(<CTFAdminPanel />)); await flush();
    await act(async () => button(node, 'Leaderboard').click()); await flush();
    expect(button(node, 'Unban')).toBeTruthy();
    await act(async () => button(node, 'Unban').click()); await flush();
    expect(axios.post).not.toHaveBeenCalled();
    const dialog = node.querySelector('[role="dialog"]');
    expect(dialog?.textContent).toContain('learner-one');
    await act(async () => button(dialog, 'Cancel').click()); await flush();
    expect(axios.post).not.toHaveBeenCalled();
  } finally { await act(async () => root.unmount()); node.remove(); }
});

test.each([
  ['Ban', false, 'Confirm Ban', 'ban', { reason: 'controlled reason' }],
  ['Unban', true, 'Confirm Unban', 'unban', {}],
])('%s confirmation claims once, binds the original bearer and target, and retires its dialog', async (action, banned, confirmLabel, route, body) => {
  let finish;
  axios.get.mockImplementation(url => {
    if (url === '/api/ctf/leaderboard') return Promise.resolve({ data: { leaderboard: [{ participant_id: 71, username: 'learner-one' }] } });
    if (url === '/api/ctf/admin/participants') return Promise.resolve({ data: { participants: [{ id: 71, user_id: 44, username: 'learner-one', is_banned: banned }] } });
    return Promise.resolve({ data: { analytics: {} } });
  });
  axios.post.mockImplementation(() => new Promise(resolve => { finish = resolve; }));
  jest.spyOn(window, 'prompt').mockReturnValue('controlled reason');
  const node = document.createElement('div'); document.body.appendChild(node);
  const root = createRoot(node);
  try {
    await act(async () => root.render(<CTFAdminPanel />)); await flush();
    await act(async () => button(node, 'Leaderboard').click()); await flush();
    await act(async () => button(node, action).click()); await flush();
    const confirm = button(node.querySelector('[role="dialog"]'), confirmLabel);
    act(() => { confirm.click(); confirm.click(); });
    expect(axios.post).toHaveBeenCalledTimes(1);
    expect(axios.post).toHaveBeenCalledWith(`/api/ctf/admin/participants/44/${route}`, body,
      expect.objectContaining({ headers: { Authorization: 'Bearer admin-token' } }));
    expect(node.querySelector('[role="dialog"]')).toBeNull();
    await act(async () => finish({ status: 200, data: { message: 'Done' } })); await flush();
    expect(toast.success).toHaveBeenCalledTimes(1);
  } finally { await act(async () => root.unmount()); node.remove(); }
});

test('Ban rejects a prompt-time storage A→B→A cycle and a cancelled retained Confirm', async () => {
  axios.get.mockImplementation(url => {
    if (url === '/api/ctf/leaderboard') return Promise.resolve({ data: { leaderboard: [{ participant_id: 71, username: 'learner-one' }] } });
    if (url === '/api/ctf/admin/participants') return Promise.resolve({ data: { participants: [{ id: 71, user_id: 44, is_banned: false }] } });
    return Promise.resolve({ data: { analytics: {} } });
  });
  const prompt = jest.spyOn(window, 'prompt').mockImplementation(() => {
    localStorage.setItem('token', 'other-admin-token');
    window.dispatchEvent(new StorageEvent('storage', { key: 'token', storageArea: localStorage }));
    localStorage.setItem('token', 'admin-token');
    window.dispatchEvent(new StorageEvent('storage', { key: 'token', storageArea: localStorage }));
    return 'controlled reason';
  });
  const node = document.createElement('div'); document.body.appendChild(node);
  const root = createRoot(node);
  try {
    await act(async () => root.render(<CTFAdminPanel />)); await flush();
    await act(async () => button(node, 'Leaderboard').click()); await flush();
    await act(async () => button(node, 'Ban').click()); await flush();
    expect(axios.post).not.toHaveBeenCalled();
    expect(node.querySelector('[role="dialog"]')).toBeNull();
    prompt.mockReturnValue('controlled reason');
    await act(async () => button(node, 'Ban').click()); await flush();
    const dialog = node.querySelector('[role="dialog"]');
    const staleConfirm = button(dialog, 'Confirm Ban');
    act(() => { button(dialog, 'Cancel').click(); staleConfirm.click(); });
    await flush();
    expect(axios.post).not.toHaveBeenCalled();
  } finally { await act(async () => root.unmount()); node.remove(); }
});

test('Unban pending response after storage A→B→A cannot show stale success or change the current roster', async () => {
  let finish;
  axios.get.mockImplementation(url => {
    if (url === '/api/ctf/leaderboard') return Promise.resolve({ data: { leaderboard: [{ participant_id: 71, username: 'learner-one' }] } });
    if (url === '/api/ctf/admin/participants') return Promise.resolve({ data: { participants: [{ id: 71, user_id: 44, is_banned: true }] } });
    return Promise.resolve({ data: { analytics: {} } });
  });
  axios.post.mockImplementation(() => new Promise(resolve => { finish = resolve; }));
  const node = document.createElement('div'); document.body.appendChild(node);
  const root = createRoot(node);
  try {
    await act(async () => root.render(<CTFAdminPanel />)); await flush();
    await act(async () => button(node, 'Leaderboard').click()); await flush();
    await act(async () => button(node, 'Unban').click()); await flush();
    await act(async () => button(node.querySelector('[role="dialog"]'), 'Confirm Unban').click()); await flush();
    act(() => {
      localStorage.setItem('token', 'other-admin-token');
      window.dispatchEvent(new StorageEvent('storage', { key: 'token', storageArea: localStorage }));
      localStorage.setItem('token', 'admin-token');
      window.dispatchEvent(new StorageEvent('storage', { key: 'token', storageArea: localStorage }));
    });
    await flush();
    await act(async () => finish({ status: 200, data: { message: 'Unbanned' } })); await flush();
    expect(toast.success).not.toHaveBeenCalled();
    expect(button(node, 'Unban')).toBeTruthy();
    expect(axios.post).toHaveBeenCalledTimes(1);
  } finally { await act(async () => root.unmount()); node.remove(); }
});

test('same-token auth revision retires a staged Ban before its retained Confirm can post', async () => {
  let auth;
  function Probe() { auth = useAuth(); return null; }
  axios.get.mockImplementation(url => url === '/api/auth/status'
    ? Promise.resolve({ data: { authenticated: true, user: { id: 1, username: 'admin', security_level: 2 } } })
    : url === '/api/ctf/leaderboard'
      ? Promise.resolve({ data: { leaderboard: [{ participant_id: 71, username: 'learner-one' }] } })
      : url === '/api/ctf/admin/participants'
        ? Promise.resolve({ data: { participants: [{ id: 71, user_id: 44, is_banned: false }] } })
        : Promise.resolve({ data: { analytics: {} } }));
  axios.post.mockImplementation(url => url === '/api/auth/login'
    ? Promise.resolve({ data: { token: 'admin-token', user: { id: 1, username: 'admin', security_level: 2 } } })
    : Promise.resolve({ status: 200, data: { message: 'Banned' } }));
  jest.spyOn(window, 'prompt').mockReturnValue('controlled reason');
  const node = document.createElement('div'); document.body.appendChild(node);
  const root = createRoot(node);
  try {
    await act(async () => root.render(<AuthProvider><Probe /><CTFAdminPanel /></AuthProvider>)); await flush();
    await act(async () => button(node, 'Leaderboard').click()); await flush();
    await act(async () => button(node, 'Ban').click()); await flush();
    const retained = button(node.querySelector('[role="dialog"]'), 'Confirm Ban');
    await act(async () => auth.login('admin', 'ignored')); await flush();
    await act(async () => retained.click()); await flush();
    expect(axios.post.mock.calls.filter(([url]) => url.endsWith('/ban'))).toHaveLength(0);
  } finally { await act(async () => root.unmount()); node.remove(); }
});

test('old admin roster response cannot overwrite newer authority ban readback', async () => {
  let releaseOldLeaderboard;
  let releaseOldParticipants;
  axios.get.mockImplementation((url, config) => {
    if (url === '/api/ctf/leaderboard') return config?.headers?.Authorization === 'Bearer admin-token'
      ? new Promise(resolve => { releaseOldLeaderboard = resolve; })
      : Promise.resolve({ data: { leaderboard: [{ participant_id: 71, username: 'learner-one' }] } });
    if (url === '/api/ctf/admin/participants') return config?.headers?.Authorization === 'Bearer admin-token'
      ? new Promise(resolve => { releaseOldParticipants = resolve; })
      : Promise.resolve({ data: { participants: [{ id: 71, user_id: 44, is_banned: true }] } });
    return Promise.resolve({ data: { analytics: {} } });
  });
  const node = document.createElement('div'); document.body.appendChild(node);
  const root = createRoot(node);
  try {
    await act(async () => root.render(<CTFAdminPanel />)); await flush();
    await act(async () => button(node, 'Leaderboard').click()); await flush();
    act(() => {
      localStorage.setItem('token', 'other-admin-token');
      window.dispatchEvent(new StorageEvent('storage', { key: 'token', storageArea: localStorage }));
    });
    await flush();
    expect(button(node, 'Unban')).toBeTruthy();
    await act(async () => {
      releaseOldLeaderboard({ data: { leaderboard: [{ participant_id: 71, username: 'learner-one' }] } });
      releaseOldParticipants({ data: { participants: [{ id: 71, user_id: 44, is_banned: false }] } });
    });
    await flush();
    expect(button(node, 'Unban')).toBeTruthy();
    expect(button(node, 'Ban')).toBeFalsy();
  } finally { await act(async () => root.unmount()); node.remove(); }
});

test.each(['resolve', 'reject'])('late roster %s after unmount cannot publish state or errors', async outcome => {
  let settleLeaderboard;
  let settleParticipants;
  const signals = [];
  axios.get.mockImplementation((url, config) => {
    if (url === '/api/ctf/leaderboard') {
      signals.push(config.signal);
      return new Promise((resolve, reject) => { settleLeaderboard = outcome === 'resolve' ? resolve : reject; });
    }
    if (url === '/api/ctf/admin/participants') {
      signals.push(config.signal);
      return new Promise((resolve, reject) => { settleParticipants = outcome === 'resolve' ? resolve : reject; });
    }
    return Promise.resolve({ data: { analytics: {} } });
  });
  const node = document.createElement('div'); document.body.appendChild(node);
  const root = createRoot(node);
  await act(async () => root.render(<CTFAdminPanel />)); await flush();
  await act(async () => button(node, 'Leaderboard').click()); await flush();
  await act(async () => root.unmount()); node.remove();
  expect(signals).toHaveLength(2);
  expect(signals.every(signal => signal.aborted)).toBe(true);
  await act(async () => {
    if (outcome === 'resolve') {
      settleLeaderboard({ data: { leaderboard: [{ participant_id: 71 }] } });
      settleParticipants({ data: { participants: [{ id: 71, user_id: 44, is_banned: true }] } });
    } else {
      settleLeaderboard(new Error('old network failure'));
      settleParticipants(new Error('old network failure'));
    }
  });
  await flush();
  expect(toast.error).not.toHaveBeenCalled();
  expect(toast.success).not.toHaveBeenCalled();
});

test('a rejected roster GET retires its still-pending sibling request', async () => {
  let participantSignal;
  axios.get.mockImplementation((url, config) => {
    if (url === '/api/ctf/leaderboard') return Promise.reject(new Error('roster unavailable'));
    if (url === '/api/ctf/admin/participants') {
      participantSignal = config.signal;
      return new Promise(() => {});
    }
    return Promise.resolve({ data: { analytics: {} } });
  });
  const node = document.createElement('div'); document.body.appendChild(node);
  const root = createRoot(node);
  try {
    await act(async () => root.render(<CTFAdminPanel />)); await flush();
    await act(async () => button(node, 'Leaderboard').click()); await flush();
    expect(participantSignal).toBeDefined();
    expect(participantSignal.aborted).toBe(true);
    expect(toast.error).toHaveBeenCalledTimes(1);
  } finally { await act(async () => root.unmount()); node.remove(); }
});

test('same-token auth revision starts a replacement roster read while the previous read is pending', async () => {
  let auth;
  let oldLeaderboard;
  let oldParticipants;
  let rosterReads = 0;
  function Probe() { auth = useAuth(); return null; }
  axios.get.mockImplementation(url => {
    if (url === '/api/auth/status') return Promise.resolve({ data: { authenticated: true, user: { id: 1, username: 'admin', security_level: 2 } } });
    if (url === '/api/ctf/leaderboard') {
      rosterReads += 1;
      return rosterReads === 1 ? new Promise(resolve => { oldLeaderboard = resolve; })
        : Promise.resolve({ data: { leaderboard: [{ participant_id: 71, username: 'learner-one' }] } });
    }
    if (url === '/api/ctf/admin/participants') return rosterReads === 1
      ? new Promise(resolve => { oldParticipants = resolve; })
      : Promise.resolve({ data: { participants: [{ id: 71, user_id: 44, is_banned: true }] } });
    return Promise.resolve({ data: { analytics: {} } });
  });
  axios.post.mockImplementation(url => url === '/api/auth/login'
    ? Promise.resolve({ data: { token: 'admin-token', user: { id: 1, username: 'admin', security_level: 2 } } })
    : Promise.resolve({ status: 200, data: { message: 'Done' } }));
  const node = document.createElement('div'); document.body.appendChild(node);
  const root = createRoot(node);
  try {
    await act(async () => root.render(<AuthProvider><Probe /><CTFAdminPanel /></AuthProvider>)); await flush();
    await act(async () => button(node, 'Leaderboard').click()); await flush();
    expect(rosterReads).toBe(1);
    await act(async () => auth.login('admin', 'ignored')); await flush();
    expect(rosterReads).toBe(2);
    expect(button(node, 'Unban')).toBeTruthy();
    await act(async () => {
      oldLeaderboard({ data: { leaderboard: [{ participant_id: 71, username: 'learner-one' }] } });
      oldParticipants({ data: { participants: [{ id: 71, user_id: 44, is_banned: false }] } });
    });
    expect(button(node, 'Unban')).toBeTruthy();
  } finally { await act(async () => root.unmount()); node.remove(); }
});

test('parked Ban recovery cannot check status after a storage A→B→A authority retirement', async () => {
  const operationId = '10000000-0000-0000-0000-000000000001';
  axios.get.mockImplementation(url => {
    if (url === '/api/ctf/leaderboard') return Promise.resolve({ data: { leaderboard: [{ participant_id: 71, username: 'learner-one' }] } });
    if (url === '/api/ctf/admin/participants') return Promise.resolve({ data: { participants: [{ id: 71, user_id: 44, is_banned: false }] } });
    if (url === `/api/ctf/operations/${operationId}`) return Promise.reject(new Error('Current status unavailable'));
    return Promise.resolve({ data: { analytics: {} } });
  });
  axios.post.mockResolvedValue({ status: 202, data: { pending: true, operationId } });
  jest.spyOn(window, 'prompt').mockReturnValue('controlled reason');
  const node = document.createElement('div'); document.body.appendChild(node);
  const root = createRoot(node);
  try {
    await act(async () => root.render(<CTFAdminPanel />)); await flush();
    await act(async () => button(node, 'Leaderboard').click()); await flush();
    await act(async () => button(node, 'Ban').click()); await flush();
    await act(async () => button(node.querySelector('[role="dialog"]'), 'Confirm Ban').click()); await flush();
    const check = button(node, 'Check status');
    expect(check).toBeTruthy();
    const before = axios.get.mock.calls.filter(([url]) => url === `/api/ctf/operations/${operationId}`).length;
    act(() => {
      localStorage.setItem('token', 'other-admin-token');
      window.dispatchEvent(new StorageEvent('storage', { key: 'token', storageArea: localStorage }));
      localStorage.setItem('token', 'admin-token');
      window.dispatchEvent(new StorageEvent('storage', { key: 'token', storageArea: localStorage }));
      check.click();
    });
    await flush();
    expect(axios.get.mock.calls.filter(([url]) => url === `/api/ctf/operations/${operationId}`)).toHaveLength(before);
    expect(axios.post).toHaveBeenCalledTimes(1);
  } finally { await act(async () => root.unmount()); node.remove(); }
});

test('participant reset retires its confirmation before a recoverable result is parked', async () => {
  const operationId = '10000000-0000-0000-0000-000000000001';
  let operationReads = 0;
  axios.get.mockImplementation((url) => {
    if (url === '/api/ctf/leaderboard') return Promise.resolve({ data: { leaderboard: [{ participant_id: 71, username: 'learner-one' }] } });
    if (url === '/api/ctf/admin/participants') return Promise.resolve({ data: { participants: [{ id: 71, user_id: 44, username: 'learner-one' }] } });
    if (url === `/api/ctf/operations/${operationId}`) {
      operationReads += 1;
      return operationReads === 1
        ? Promise.reject(new Error('Current status temporarily unavailable'))
        : Promise.resolve({ status: 200, data: { pending: false } });
    }
    return Promise.resolve({ data: { analytics: {} } });
  });
  axios.post.mockResolvedValue({ status: 202, data: { pending: true, operationId } });
  const node = document.createElement('div'); document.body.appendChild(node);
  const root = createRoot(node);
  try {
    await act(async () => root.render(<CTFAdminPanel />)); await flush();
    await act(async () => button(node, 'Leaderboard').click()); await flush();
    await act(async () => [...node.querySelectorAll('button')].find(item => item.textContent.trim() === 'Reset').click()); await flush();
    await act(async () => button(node.querySelector('[role="dialog"]'), 'Reset Progress').click()); await flush();
    expect(axios.post).toHaveBeenCalledTimes(1);
    expect(axios.post).toHaveBeenCalledWith('/api/ctf/admin/participants/44/reset', {}, expect.objectContaining({ headers: { Authorization: 'Bearer admin-token' } }));
    expect(node.querySelector('[role="dialog"]')).toBeNull();
    const reset = [...node.querySelectorAll('button')].find(item => item.textContent.trim() === 'Reset');
    expect(reset.disabled).toBe(true);
    act(() => reset.click());
    expect(axios.post).toHaveBeenCalledTimes(1);
    const check = button(node, 'Check status');
    expect(check).toBeTruthy();
    await act(async () => check.click()); await flush();
    expect(axios.get.mock.calls.filter(([url]) => url === `/api/ctf/operations/${operationId}`)).toHaveLength(2);
    expect(axios.post).toHaveBeenCalledTimes(1);
  } finally { await act(async () => root.unmount()); node.remove(); }
});

test.each([
  ['Reset', 'Reset Progress', '/api/ctf/admin/participants/44/reset'],
  ['Remove', 'Remove from CTF', '/api/ctf/admin/participants/44/remove'],
])('%s participant confirmation rejects a changed admin and permits a fresh review', async (action, confirmLabel, endpoint) => {
  axios.get.mockImplementation(url => {
    if (url === '/api/ctf/leaderboard') return Promise.resolve({ data: { leaderboard: [{ participant_id: 71, username: 'learner-one' }] } });
    if (url === '/api/ctf/admin/participants') return Promise.resolve({ data: { participants: [{ id: 71, user_id: 44, username: 'learner-one' }] } });
    return Promise.resolve({ data: { analytics: {} } });
  });
  axios.post.mockResolvedValue({ status: 200, data: { message: 'Done' } });
  const node = document.createElement('div'); document.body.appendChild(node);
  const root = createRoot(node);
  try {
    await act(async () => root.render(<CTFAdminPanel />)); await flush();
    await act(async () => button(node, 'Leaderboard').click()); await flush();
    const actionButton = () => [...node.querySelectorAll('button')].find(item => item.textContent.trim() === action);
    await act(async () => actionButton().click()); await flush();
    const dialog = node.querySelector('[role="dialog"]');
    expect(dialog.textContent).toContain('learner-one');
    const cancelledConfirm = button(dialog, confirmLabel);
    act(() => { button(dialog, 'Cancel').click(); cancelledConfirm.click(); });
    await flush();
    expect(axios.post).not.toHaveBeenCalled();
    await act(async () => actionButton().click()); await flush();
    const restagedDialog = node.querySelector('[role="dialog"]');
    localStorage.setItem('token', 'other-admin-token');
    await act(async () => button(restagedDialog, confirmLabel).click()); await flush();
    expect(axios.post).not.toHaveBeenCalled();
    await act(async () => actionButton().click()); await flush();
    await act(async () => button(node.querySelector('[role="dialog"]'), confirmLabel).click()); await flush();
    expect(axios.post).toHaveBeenCalledTimes(1);
    expect(axios.post).toHaveBeenCalledWith(endpoint, {}, expect.objectContaining({ headers: { Authorization: 'Bearer other-admin-token' } }));
  } finally { await act(async () => root.unmount()); node.remove(); }
});
