/* eslint-disable testing-library/no-unnecessary-act -- React DOM createRoot is used directly. */
import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import axios from 'axios';
import { toast } from 'react-toastify';
import CTFAdminPanel from './CTFAdminPanel';

jest.mock('axios', () => ({ get: jest.fn(), post: jest.fn(), put: jest.fn(), delete: jest.fn() }));
jest.mock('react-toastify', () => ({ toast: { error: jest.fn(), success: jest.fn() } }));

const stage = { id: 41, stage_number: 11, stage_name: 'Owned extra stage',
  hints: '[]', defense_style: '[]', is_active: 1 };
async function flush() { await act(async () => { await Promise.resolve(); await Promise.resolve(); await Promise.resolve(); }); }
const button = (root, text) => [...root.querySelectorAll('button')]
  .find(item => item.textContent.trim() === text);

async function mount() {
  const node = document.createElement('div'); document.body.appendChild(node);
  const root = createRoot(node);
  await act(async () => root.render(<CTFAdminPanel />)); await flush();
  await act(async () => [...node.querySelectorAll('button')].find(item => item.textContent.includes('Levels')).click());
  await flush();
  await act(async () => [...node.querySelectorAll('td')].find(item => item.textContent === stage.stage_name).click());
  return { node, root, close: async () => { await act(async () => root.unmount()); node.remove(); } };
}

beforeEach(() => {
  global.IS_REACT_ACT_ENVIRONMENT = true;
  jest.clearAllMocks(); localStorage.clear(); localStorage.setItem('token', 'mounted-admin');
  axios.get.mockImplementation(url => Promise.resolve({ data: url.endsWith('/stages')
    ? { stages: [stage] } : { analytics: {} } }));
});
afterEach(() => localStorage.clear());

test('stage deletion requires explicit review, Cancel sends zero DELETE, and double Confirm sends one captured request', async () => {
  let settle;
  axios.delete.mockImplementation(() => new Promise(resolve => { settle = resolve; }));
  const nativeConfirm = jest.spyOn(window, 'confirm');
  const mounted = await mount();
  try {
    await act(async () => button(mounted.node, 'Delete').click());
    expect(axios.delete).not.toHaveBeenCalled();
    expect(mounted.node.querySelector('[role="dialog"]')?.textContent).toContain('cannot be undone');
    await act(async () => button(mounted.node, 'Cancel').click());
    expect(axios.delete).not.toHaveBeenCalled();
    await act(async () => button(mounted.node, 'Delete').click());
    const confirm = button(mounted.node, 'Confirm Delete');
    await act(async () => { confirm.click(); confirm.click(); });
    expect(axios.delete).toHaveBeenCalledTimes(1);
    expect(axios.delete).toHaveBeenCalledWith('/api/ctf/admin/stages/41',
      expect.objectContaining({ headers: { Authorization: 'Bearer mounted-admin' } }));
    expect(toast.success).not.toHaveBeenCalled();
    await act(async () => settle({ status: 200, data: { message: 'Stage deleted' } })); await flush();
    expect(toast.success).toHaveBeenCalledWith('Stage deleted');
    expect(nativeConfirm).not.toHaveBeenCalled();
  } finally { nativeConfirm.mockRestore(); await mounted.close(); }
});

test('retained Confirm after an A→B→A authority change sends no DELETE', async () => {
  const mounted = await mount();
  try {
    await act(async () => button(mounted.node, 'Delete').click());
    const staleConfirm = button(mounted.node, 'Confirm Delete');
    await act(async () => {
      localStorage.setItem('token', 'other-admin');
      window.dispatchEvent(new StorageEvent('storage', { key: 'token', storageArea: localStorage }));
      localStorage.setItem('token', 'mounted-admin');
      window.dispatchEvent(new StorageEvent('storage', { key: 'token', storageArea: localStorage }));
      staleConfirm.click();
    });
    await flush();
    expect(axios.delete).not.toHaveBeenCalled();
    expect(mounted.node.querySelector('[role="dialog"]')).toBeNull();
  } finally { await mounted.close(); }
});

test('late completion after unmount cannot show deletion success or trigger another request', async () => {
  let settle;
  axios.delete.mockImplementation(() => new Promise(resolve => { settle = resolve; }));
  const mounted = await mount();
  await act(async () => button(mounted.node, 'Delete').click());
  await act(async () => button(mounted.node, 'Confirm Delete').click());
  expect(axios.delete).toHaveBeenCalledTimes(1);
  await mounted.close();
  await act(async () => settle({ status: 200, data: { message: 'Stage deleted' } })); await flush();
  expect(toast.success).not.toHaveBeenCalled();
  expect(axios.delete).toHaveBeenCalledTimes(1);
});

test('A→B→A while DELETE is pending suppresses stale success and never sends a second DELETE', async () => {
  let settle;
  axios.delete.mockImplementation(() => new Promise(resolve => { settle = resolve; }));
  const mounted = await mount();
  try {
    await act(async () => button(mounted.node, 'Delete').click());
    await act(async () => button(mounted.node, 'Confirm Delete').click());
    expect(axios.delete).toHaveBeenCalledTimes(1);
    await act(async () => {
      localStorage.setItem('token', 'other-admin');
      window.dispatchEvent(new StorageEvent('storage', { key: 'token', storageArea: localStorage }));
      localStorage.setItem('token', 'mounted-admin');
      window.dispatchEvent(new StorageEvent('storage', { key: 'token', storageArea: localStorage }));
    });
    await act(async () => settle({ status: 200, data: { message: 'Stage deleted' } }));
    await flush();
    expect(toast.success).not.toHaveBeenCalled();
    expect(axios.delete).toHaveBeenCalledTimes(1);
  } finally { await mounted.close(); }
});

test('response loss remains unresolved and never automatically resubmits DELETE', async () => {
  axios.delete.mockRejectedValue(new Error('owned transport response lost'));
  const mounted = await mount();
  try {
    await act(async () => button(mounted.node, 'Delete').click());
    await act(async () => button(mounted.node, 'Confirm Delete').click());
    await flush();
    expect(axios.delete).toHaveBeenCalledTimes(1);
    expect(toast.success).not.toHaveBeenCalled();
    expect(toast.error).not.toHaveBeenCalled();
    expect(mounted.node.textContent).toContain('Outcome unknown');
    expect(axios.get.mock.calls.filter(([url]) => url.startsWith('/api/ctf/operations/'))).toHaveLength(0);
  } finally { await mounted.close(); }
});
