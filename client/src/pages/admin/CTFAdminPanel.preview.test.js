/* eslint-disable testing-library/no-unnecessary-act -- Retained DOM callbacks are intentional here. */
import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import axios from 'axios';
import { toast } from 'react-toastify';
import CTFAdminPanel from './CTFAdminPanel';
import { AuthProvider, useAuth } from '../../context/AuthContext';

jest.mock('axios', () => ({ get: jest.fn(), post: jest.fn(), put: jest.fn(), delete: jest.fn(),
  defaults: { headers: { common: {} } }, interceptors: { response: { use: jest.fn(), eject: jest.fn() } } }));
jest.mock('react-toastify', () => ({ toast: { error: jest.fn(), success: jest.fn() } }));

const stage = Object.freeze({ id: 3, stage_number: 3, stage_name: 'Owned preview stage',
  hints: '[]', defense_style: '[]', feedback_mode: 'full', adaptive_mode: 'none', is_active: 1 });
const previewResult = Object.freeze({ classification: { tag: 'direct_extraction', confidence: 0.8 },
  defenseBlocked: false, wouldSucceed: false, previewTrace: [], rawResponse: 'safe',
  processedResponse: 'safe', secretCriteria: 'SECRET' });
const button = (root, text) => [...root.querySelectorAll('button')].find(node => node.textContent.includes(text));
async function flush() { await act(async () => { await Promise.resolve(); await Promise.resolve(); await Promise.resolve(); }); }
async function mount(withAuth = false) {
  let auth;
  function Probe() { auth = useAuth(); return null; }
  axios.get.mockImplementation(url => Promise.resolve({ status: 200, data: url === '/api/auth/status'
    ? { authenticated: true, user: { id: 1, username: 'admin', security_level: 2 } }
    : url === '/api/ctf/admin/stages' ? { stages: [stage] } : { analytics: {} } }));
  const node = document.createElement('div'); document.body.appendChild(node);
  const root = createRoot(node);
  await act(async () => root.render(withAuth
    ? <AuthProvider><Probe /><CTFAdminPanel /></AuthProvider> : <CTFAdminPanel />)); await flush();
  await act(async () => button(node, 'Levels').click()); await flush();
  await act(async () => [...node.querySelectorAll('td')].find(el => el.textContent === stage.stage_name).click()); await flush();
  await act(async () => button(node, 'Preview').click()); await flush();
  expect(node.querySelector('[role="dialog"]')?.textContent).toContain(stage.stage_name);
  return { node, root, getAuth: () => auth,
    close: async () => { await act(async () => root.unmount()); node.remove(); } };
}
function typePayload(node, value) {
  const input = node.querySelector('[role="dialog"] textarea');
  Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, 'value').set.call(input, value);
  input.dispatchEvent(new Event('input', { bubbles: true }));
}
beforeEach(() => {
  global.IS_REACT_ACT_ENVIRONMENT = true;
  jest.clearAllMocks(); localStorage.clear(); localStorage.setItem('token', 'admin-A');
});
afterEach(() => localStorage.clear());

test('opening and closing Preview, including blank Run, sends no POST', async () => {
  const env = await mount();
  try {
    await act(async () => button(env.node, 'Run Preview').click()); await flush();
    expect(axios.post).not.toHaveBeenCalled();
    expect(toast.error).toHaveBeenCalledWith('Enter a payload to preview');
    await act(async () => env.node.querySelector('[aria-label="Close"]').click()); await flush();
    expect(axios.post).not.toHaveBeenCalled();
  } finally { await env.close(); }
});

test('storage A→B→A retires an armed modal before retained Run can dispatch', async () => {
  const env = await mount();
  try {
    await act(async () => typePayload(env.node, 'ordinary payload')); await flush();
    const stale = button(env.node, 'Run Preview');
    await act(async () => {
      localStorage.setItem('token', 'admin-B');
      window.dispatchEvent(new StorageEvent('storage', { key: 'token', storageArea: localStorage }));
      localStorage.setItem('token', 'admin-A');
      window.dispatchEvent(new StorageEvent('storage', { key: 'token', storageArea: localStorage }));
      stale.click();
    }); await flush();
    expect(axios.post).not.toHaveBeenCalled();
    expect(env.node.querySelector('[role="dialog"]')).toBeNull();
  } finally { await env.close(); }
});

test('same-token auth revision retires the original modal and cannot dispatch', async () => {
  const env = await mount(true);
  axios.post.mockImplementation(url => url === '/api/auth/login'
    ? Promise.resolve({ data: { token: 'admin-A', user: { id: 1, username: 'admin', security_level: 2 } } })
    : Promise.resolve({ status: 200, data: previewResult }));
  try {
    await act(async () => typePayload(env.node, 'ordinary payload')); await flush();
    const stale = button(env.node, 'Run Preview');
    await act(async () => env.getAuth().login('admin', 'ignored')); await flush();
    await act(async () => stale.click()); await flush();
    expect(axios.post.mock.calls.filter(([url]) => url.includes('/preview'))).toHaveLength(0);
    expect(env.node.querySelector('[role="dialog"]')).toBeNull();
  } finally { await env.close(); }
});

test('rapid Run clicks send one frozen payload with the captured bearer and show only a complete 200', async () => {
  let complete;
  axios.post.mockImplementation(() => new Promise(resolve => { complete = resolve; }));
  const env = await mount();
  try {
    await act(async () => typePayload(env.node, 'ordinary payload')); await flush();
    const run = button(env.node, 'Run Preview');
    await act(async () => { run.click(); run.click(); }); await flush();
    expect(axios.post).toHaveBeenCalledTimes(1);
    expect(axios.post).toHaveBeenCalledWith('/api/ctf/admin/stages/3/preview',
      { payload: 'ordinary payload' }, expect.objectContaining({ headers: { Authorization: 'Bearer admin-A' },
        signal: expect.any(AbortSignal) }));
    await act(async () => { typePayload(env.node, 'changed after dispatch'); run.click(); }); await flush();
    expect(axios.post.mock.calls[0][1]).toEqual({ payload: 'ordinary payload' });
    expect(axios.post).toHaveBeenCalledTimes(1);
    await act(async () => complete({ status: 200, data: previewResult })); await flush();
    expect(env.node.querySelector('[role="dialog"]')?.textContent).toContain('safe');
    expect(axios.post).toHaveBeenCalledTimes(1);
  } finally { await env.close(); }
});

test('post-dispatch authority retirement aborts transport and suppresses late output without claiming zero provider use', async () => {
  let complete;
  axios.post.mockImplementation(() => new Promise(resolve => { complete = resolve; }));
  const env = await mount();
  try {
    await act(async () => typePayload(env.node, 'ordinary payload')); await flush();
    await act(async () => button(env.node, 'Run Preview').click()); await flush();
    const signal = axios.post.mock.calls[0][2].signal;
    await act(async () => {
      localStorage.setItem('token', 'admin-B');
      window.dispatchEvent(new StorageEvent('storage', { key: 'token', storageArea: localStorage }));
      localStorage.setItem('token', 'admin-A');
      window.dispatchEvent(new StorageEvent('storage', { key: 'token', storageArea: localStorage }));
    }); await flush();
    expect(signal.aborted).toBe(true);
    await act(async () => complete({ status: 200, data: previewResult })); await flush();
    expect(env.node.querySelector('[role="dialog"]')).toBeNull();
    expect(toast.success).not.toHaveBeenCalled();
    expect(axios.post).toHaveBeenCalledTimes(1);
  } finally { await env.close(); }
});

test('Close aborts pending transport and suppresses late error', async () => {
  let reject;
  axios.post.mockImplementation(() => new Promise((_, fail) => { reject = fail; }));
  const env = await mount();
  try {
    await act(async () => typePayload(env.node, 'ordinary payload')); await flush();
    await act(async () => button(env.node, 'Run Preview').click()); await flush();
    const signal = axios.post.mock.calls[0][2].signal;
    const staleRun = button(env.node, 'Running…');
    await act(async () => { env.node.querySelector('[aria-label="Close"]').click(); staleRun.click(); }); await flush();
    expect(signal.aborted).toBe(true);
    await act(async () => reject({ response: { status: 403, data: { error: 'stale' } } })); await flush();
    expect(toast.error).not.toHaveBeenCalled();
    expect(axios.post).toHaveBeenCalledTimes(1);
  } finally { await env.close(); }
});

test('unmount aborts pending transport and suppresses late output', async () => {
  let complete;
  axios.post.mockImplementation(() => new Promise(resolve => { complete = resolve; }));
  const env = await mount();
  await act(async () => typePayload(env.node, 'ordinary payload')); await flush();
  await act(async () => button(env.node, 'Run Preview').click()); await flush();
  const signal = axios.post.mock.calls[0][2].signal;
  await env.close();
  expect(signal.aborted).toBe(true);
  await act(async () => complete({ status: 200, data: previewResult })); await flush();
  expect(toast.success).not.toHaveBeenCalled();
  expect(toast.error).not.toHaveBeenCalled();
  expect(axios.post).toHaveBeenCalledTimes(1);
});

test('incomplete 200 response is not published or retried', async () => {
  axios.post.mockResolvedValue({ status: 200, data: { classification: { tag: 'other', confidence: 1 } } });
  const env = await mount();
  try {
    await act(async () => typePayload(env.node, 'ordinary payload')); await flush();
    await act(async () => button(env.node, 'Run Preview').click()); await flush();
    expect(toast.error).toHaveBeenCalledWith('Preview failed or did not complete');
    expect(env.node.querySelector('[role="dialog"]')?.textContent).not.toContain('Classification');
    expect(axios.post).toHaveBeenCalledTimes(1);
  } finally { await env.close(); }
});
