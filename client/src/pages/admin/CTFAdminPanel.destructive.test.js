/* eslint-disable testing-library/no-unnecessary-act -- React DOM createRoot is used directly. */
import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import axios from 'axios';
import CTFAdminPanel from './CTFAdminPanel';

jest.mock('axios', () => ({ get: jest.fn(), post: jest.fn(), put: jest.fn(), delete: jest.fn() }));
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
  const confirm = jest.spyOn(window, 'confirm').mockReturnValue(true);
  const node = document.createElement('div'); document.body.appendChild(node);
  const root = createRoot(node);
  try {
    await act(async () => root.render(<CTFAdminPanel />)); await flush();
    await act(async () => button(node, 'Danger Zone').click()); await flush();
    const clear = button(node, 'Clear Technique Blocklist');
    act(() => { clear.click(); clear.click(); });
    expect(confirm).toHaveBeenCalledTimes(1);
    expect(axios.post).toHaveBeenCalledTimes(1);
    expect(axios.post).toHaveBeenCalledWith('/api/ctf/admin/blocklists/technique/clear', {}, expect.objectContaining({ headers: { Authorization: 'Bearer admin-token' } }));
    await act(async () => finish({ status: 200, data: { message: 'Technique blocklist cleared' } }));
    await flush();
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
