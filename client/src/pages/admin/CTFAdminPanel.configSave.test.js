/* eslint-disable testing-library/no-unnecessary-act -- This suite exercises retained DOM callbacks with createRoot. */
import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import axios from 'axios';
import { toast } from 'react-toastify';
import CTFAdminPanel from './CTFAdminPanel';
import { AuthProvider, useAuth } from '../../context/AuthContext';

jest.mock('axios', () => ({ get: jest.fn(), post: jest.fn(), put: jest.fn(), delete: jest.fn(),
  defaults: { headers: { common: {} } }, interceptors: { response: { use: jest.fn(), eject: jest.fn() } } }));
jest.mock('react-toastify', () => ({ toast: { error: jest.fn(), success: jest.fn() } }));

const keys = [
  'ctf_enabled', 'ctf_visible_to_students', 'student_leaderboard_visible',
  'public_leaderboard_visible', 'ctf_registration_open', 'ctf_max_participants',
  'ctf_time_limit', 'leaderboard_update_interval', 'ctf_nav_visible',
  'ctf_show_technique_feedback', 'ctf_show_attempt_counter',
  'ctf_hint_gating_attempts', 'ctf_hint_cost_1', 'ctf_hint_cost_2', 'ctf_hint_cost_3',
];
const booleanKeys = new Set(keys.filter(key => ![
  'ctf_max_participants', 'ctf_time_limit', 'leaderboard_update_interval',
  'ctf_hint_gating_attempts', 'ctf_hint_cost_1', 'ctf_hint_cost_2', 'ctf_hint_cost_3',
].includes(key)));
const initialConfig = () => Object.fromEntries(keys.map(key => [key, booleanKeys.has(key) ? 'true' : '12']));
async function flush() { await act(async () => { await Promise.resolve(); await Promise.resolve(); await Promise.resolve(); }); }
const button = (root, text) => [...root.querySelectorAll('button')].find(el => el.textContent.includes(text));
async function mount(config) {
  const node = document.createElement('div'); document.body.appendChild(node);
  const root = createRoot(node);
  let current = { ...config };
  axios.get.mockImplementation(url => Promise.resolve({ status: 200,
    data: url === '/api/ctf/config' ? { config: { ...current } } : { analytics: {} } }));
  await act(async () => root.render(<CTFAdminPanel />)); await flush();
  await act(async () => button(node, 'Config').click()); await flush();
  return { node, root, setCurrent: value => { current = value; },
    close: async () => { await act(async () => root.unmount()); node.remove(); } };
}
function rowFor(node, key) {
  const label = [...node.querySelectorAll('div')].find(el => el.textContent === key && el.parentElement?.parentElement?.querySelector('button'));
  expect(label).toBeTruthy();
  return label.parentElement.parentElement;
}
function edit(row, key, value) {
  if (booleanKeys.has(key)) {
    row.querySelector('[role="switch"]').click();
  } else {
    const input = row.querySelector('input');
    Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set.call(input, value);
    input.dispatchEvent(new Event('input', { bubbles: true }));
    button(row, 'Save').click();
  }
}
beforeEach(() => {
  global.IS_REACT_ACT_ENVIRONMENT = true;
  jest.clearAllMocks(); localStorage.clear(); localStorage.setItem('token', 'admin-A');
});
afterEach(() => localStorage.clear());

test.each(keys)('%s stages Cancel with zero POST and confirms one captured value after readback', async key => {
  const config = initialConfig();
  const env = await mount(config);
  const next = booleanKeys.has(key) ? 'false' : '157';
  try {
    await act(async () => edit(rowFor(env.node, key), key, next)); await flush();
    expect(document.querySelector('[role="dialog"]')?.textContent).toContain(key);
    expect(axios.post).not.toHaveBeenCalled();
    await act(async () => button(document.querySelector('[role="dialog"]'), 'Cancel').click()); await flush();
    expect(axios.post).not.toHaveBeenCalled();
    await act(async () => edit(rowFor(env.node, key), key, next)); await flush();
    env.setCurrent({ ...config, [key]: next });
    axios.post.mockResolvedValue({ status: 200, data: { success: true } });
    const confirm = button(document.querySelector('[role="dialog"]'), 'Confirm Config Save');
    await act(async () => { confirm.click(); confirm.click(); }); await flush();
    expect(axios.post).toHaveBeenCalledTimes(1);
    expect(axios.post).toHaveBeenCalledWith('/api/ctf/admin/config', { key, value: next },
      expect.objectContaining({ headers: { Authorization: 'Bearer admin-A' } }));
    expect(toast.success).toHaveBeenCalledTimes(1);
  } finally { await env.close(); }
});

test('cross-tab A→B→A retires retained confirmation with zero POST', async () => {
  const env = await mount(initialConfig());
  try {
    await act(async () => edit(rowFor(env.node, 'ctf_enabled'), 'ctf_enabled', 'false')); await flush();
    const stale = button(document.querySelector('[role="dialog"]'), 'Confirm Config Save');
    await act(async () => {
      localStorage.setItem('token', 'admin-B');
      window.dispatchEvent(new StorageEvent('storage', { key: 'token', storageArea: localStorage }));
      localStorage.setItem('token', 'admin-A');
      window.dispatchEvent(new StorageEvent('storage', { key: 'token', storageArea: localStorage }));
      stale.click();
    }); await flush();
    expect(axios.post).not.toHaveBeenCalled();
    expect(document.querySelector('[role="dialog"]')).toBeNull();
  } finally { await env.close(); }
});

test('late response after authority retirement cannot produce success or stale config', async () => {
  const env = await mount(initialConfig());
  let complete;
  axios.post.mockImplementation(() => new Promise(resolve => { complete = resolve; }));
  try {
    await act(async () => edit(rowFor(env.node, 'ctf_enabled'), 'ctf_enabled', 'false')); await flush();
    await act(async () => button(document.querySelector('[role="dialog"]'), 'Confirm Config Save').click()); await flush();
    expect(axios.post).toHaveBeenCalledTimes(1);
    await act(async () => {
      localStorage.setItem('token', 'admin-B');
      window.dispatchEvent(new StorageEvent('storage', { key: 'token', storageArea: localStorage }));
      localStorage.setItem('token', 'admin-A');
      window.dispatchEvent(new StorageEvent('storage', { key: 'token', storageArea: localStorage }));
      complete({ status: 200, data: { success: true } });
    }); await flush();
    expect(toast.success).not.toHaveBeenCalled();
    expect(axios.post).toHaveBeenCalledTimes(1);
  } finally { await env.close(); }
});

test('completed POST with failed readback never claims saved value or retries POST', async () => {
  const env = await mount(initialConfig());
  try {
    await act(async () => edit(rowFor(env.node, 'ctf_enabled'), 'ctf_enabled', 'false')); await flush();
    axios.post.mockResolvedValue({ status: 200, data: { success: true } });
    await act(async () => button(document.querySelector('[role="dialog"]'), 'Confirm Config Save').click()); await flush();
    expect(axios.post).toHaveBeenCalledTimes(1);
    expect(toast.success).not.toHaveBeenCalled();
    expect(toast.error).toHaveBeenCalledWith(expect.stringContaining('may have applied'));
  } finally { await env.close(); }
});

test('same-token login revision retires staged confirmation and refreshes from current authority', async () => {
  let auth;
  function Probe() { auth = useAuth(); return null; }
  const config = initialConfig();
  axios.get.mockImplementation(url => Promise.resolve({ status: 200, data: url === '/api/auth/status'
    ? { authenticated: true, user: { id: 1, username: 'admin', security_level: 2 } }
    : url === '/api/ctf/config' ? { config } : { analytics: {} } }));
  axios.post.mockImplementation(url => url === '/api/auth/login'
    ? Promise.resolve({ data: { token: 'admin-A', user: { id: 1, username: 'admin', security_level: 2 } } })
    : Promise.resolve({ status: 200, data: { success: true } }));
  const node = document.createElement('div'); document.body.appendChild(node);
  const root = createRoot(node);
  try {
    await act(async () => root.render(<AuthProvider><Probe /><CTFAdminPanel /></AuthProvider>)); await flush();
    await act(async () => button(node, 'Config').click()); await flush();
    await act(async () => edit(rowFor(node, 'ctf_enabled'), 'ctf_enabled', 'false')); await flush();
    const retained = button(document.querySelector('[role="dialog"]'), 'Confirm Config Save');
    await act(async () => auth.login('admin', 'ignored')); await flush();
    await act(async () => retained.click()); await flush();
    expect(localStorage.getItem('token')).toBe('admin-A');
    expect(axios.post.mock.calls.filter(([url]) => url === '/api/ctf/admin/config')).toHaveLength(0);
    expect(document.querySelector('[role="dialog"]')).toBeNull();
    expect(axios.get.mock.calls.filter(([url]) => url === '/api/ctf/config').length).toBeGreaterThan(1);
  } finally { await act(async () => root.unmount()); node.remove(); }
});

test('unmount aborts a pending config read and cannot show a late error', async () => {
  const env = await mount(initialConfig());
  let rejectRead;
  axios.get.mockImplementationOnce(() => new Promise((_, reject) => { rejectRead = reject; }));
  await act(async () => button(env.node, 'Refresh').click()); await flush();
  await env.close();
  await act(async () => rejectRead({ response: { status: 403, data: { error: 'Stale administrator' } } }));
  expect(toast.error).not.toHaveBeenCalled();
});
