/* eslint-disable testing-library/no-unnecessary-act -- Exact React callbacks are retained for lifecycle regressions. */
import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import axios from 'axios';
import { toast } from 'react-toastify';
import CTFAdminPanel from './CTFAdminPanel';

jest.mock('axios', () => ({ get: jest.fn(), post: jest.fn(), put: jest.fn(), delete: jest.fn() }));
jest.mock('react-toastify', () => ({ toast: { error: jest.fn(), success: jest.fn() } }));

const stage = (id, name) => ({ id, stage_number: id, stage_name: name,
  stage_description: `Description ${id}`, system_prompt: `POLICY_${id}`,
  success_criteria: `CRITERIA_${id}`, hints: '["First hint"]', defense_style: '[]',
  adaptive_mode: 'none', level_score: 100, feedback_mode: 'reason', is_active: 1 });
const stages = [stage(12, 'Advanced level'), stage(13, 'Sibling level')];
const button = (node, label) => [...node.querySelectorAll('button')].find(item => item.textContent.trim() === label);
const reactClick = node => node[Object.keys(node).find(key => key.startsWith('__reactProps$'))].onClick;
const stageGets = () => axios.get.mock.calls.filter(([url]) => url === '/api/ctf/admin/stages');
const operationGets = id => axios.get.mock.calls.filter(([url]) => url === `/api/ctf/operations/${id}`);
async function flush() { await act(async () => { await Promise.resolve(); await Promise.resolve(); await Promise.resolve(); }); }
const swap = () => {
  localStorage.setItem('token', 'other-admin-token');
  window.dispatchEvent(new StorageEvent('storage', { key: 'token', storageArea: localStorage }));
  localStorage.setItem('token', 'admin-token');
  window.dispatchEvent(new StorageEvent('storage', { key: 'token', storageArea: localStorage }));
};

beforeEach(() => {
  global.IS_REACT_ACT_ENVIRONMENT = true;
  localStorage.clear(); localStorage.setItem('token', 'admin-token');
  axios.get.mockImplementation(url => Promise.resolve({ status: 200,
    data: url === '/api/ctf/admin/stages' ? { stages } : { analytics: {} } }));
  axios.put.mockResolvedValue({ status: 200, data: { message: 'Stage updated' } });
});
afterEach(() => { localStorage.clear(); jest.restoreAllMocks(); });

async function mountEditor() {
  const node = document.createElement('div'); document.body.appendChild(node);
  const root = createRoot(node);
  await act(async () => root.render(<CTFAdminPanel />)); await flush();
  await act(async () => button(node, 'Levels').click()); await flush();
  const row = [...node.querySelectorAll('tr')].find(item => item.textContent.includes('Advanced level'));
  await act(async () => row.click()); await flush();
  return { node, root, row, close: async () => { await act(async () => root.unmount()); node.remove(); } };
}

test('Advanced Save reviews all consequential fields; Cancel sends zero PUTs', async () => {
  const mounted = await mountEditor();
  try {
    await act(async () => button(mounted.node, 'Save').click()); await flush();
    expect(axios.put).not.toHaveBeenCalled();
    const dialog = mounted.node.querySelector('[role="dialog"]');
    expect(dialog?.textContent).toContain('Advanced level');
    expect(dialog?.textContent).toContain('guardian');
    expect(dialog?.textContent).toContain('scoring');
    await act(async () => button(dialog, 'Cancel').click()); await flush();
    expect(axios.put).not.toHaveBeenCalled();
  } finally { await mounted.close(); }
});

test('Advance Save captures nine fields and original bearer, then synchronously claims one PUT', async () => {
  let finish;
  axios.put.mockImplementation(() => new Promise(resolve => { finish = resolve; }));
  const mounted = await mountEditor();
  try {
    await act(async () => button(mounted.node, 'Save').click()); await flush();
    const confirm = button(mounted.node.querySelector('[role="dialog"]'), 'Confirm Advanced Save');
    act(() => { confirm.click(); confirm.click(); });
    expect(axios.put).toHaveBeenCalledTimes(1);
    expect(axios.put).toHaveBeenCalledWith('/api/ctf/admin/stages/12', {
      stage_name: 'Advanced level', stage_description: 'Description 12',
      system_prompt: 'POLICY_12', success_criteria: 'CRITERIA_12',
      hints: '["First hint"]', defense_style: '[]', adaptive_mode: 'none',
      level_score: 100, feedback_mode: 'reason',
    }, expect.objectContaining({ headers: { Authorization: 'Bearer admin-token' } }));
    expect(mounted.node.querySelector('[role="dialog"]')).toBeNull();
    await act(async () => finish({ status: 200, data: { message: 'Stage updated' } })); await flush();
    expect(stageGets().length).toBeGreaterThanOrEqual(2);
    expect(toast.success).toHaveBeenCalledTimes(1);
  } finally { await mounted.close(); }
});

test('A→B→A retires retained Advanced Save Confirm before any PUT', async () => {
  const mounted = await mountEditor();
  try {
    await act(async () => button(mounted.node, 'Save').click()); await flush();
    const retained = reactClick(button(mounted.node.querySelector('[role="dialog"]'), 'Confirm Advanced Save'));
    act(() => { swap(); retained(); }); await flush();
    expect(axios.put).not.toHaveBeenCalled();
    expect(toast.success).not.toHaveBeenCalled();
  } finally { await mounted.close(); }
});

test('closed or refreshed editor retires retained Advanced Save callback', async () => {
  const mounted = await mountEditor();
  try {
    const staleSave = reactClick(button(mounted.node, 'Save'));
    await act(async () => mounted.row.click()); await flush();
    await act(async () => mounted.row.click()); await flush();
    act(() => staleSave()); await flush();
    expect(mounted.node.querySelector('[role="dialog"]')).toBeNull();
    await act(async () => button(mounted.node, 'Refresh').click()); await flush();
    act(() => staleSave()); await flush();
    expect(mounted.node.querySelector('[role="dialog"]')).toBeNull();
    expect(axios.put).not.toHaveBeenCalled();
    await act(async () => button(mounted.node, 'Save').click()); await flush();
    expect(mounted.node.querySelector('[role="dialog"]')).toBeTruthy();
  } finally { await mounted.close(); }
});

test('late Advanced Save completion after authority retirement cannot publish stale UI or retry', async () => {
  let finish;
  axios.put.mockImplementation(() => new Promise(resolve => { finish = resolve; }));
  const mounted = await mountEditor();
  try {
    await act(async () => button(mounted.node, 'Save').click()); await flush();
    await act(async () => button(mounted.node.querySelector('[role="dialog"]'), 'Confirm Advanced Save').click()); await flush();
    act(() => swap()); await flush();
    const getsAfterAuthorityRefresh = stageGets().length;
    await act(async () => finish({ status: 200, data: { message: 'Stage updated' } })); await flush();
    expect(axios.put).toHaveBeenCalledTimes(1);
    expect(stageGets()).toHaveLength(getsAfterAuthorityRefresh);
    expect(toast.success).not.toHaveBeenCalled();
    expect(toast.error).not.toHaveBeenCalled();
  } finally { await mounted.close(); }
});

test('lost Advanced Save ACK parks unknown outcome; operation check cannot cross ABA', async () => {
  const operationId = '10000000-0000-4000-8000-000000000001';
  axios.put.mockResolvedValue({ status: 202, data: { pending: true, operationId } });
  axios.get.mockImplementation(url => {
    if (url === `/api/ctf/operations/${operationId}`) return Promise.reject(new Error('Current status unavailable'));
    return Promise.resolve({ status: 200, data: url === '/api/ctf/admin/stages' ? { stages } : { analytics: {} } });
  });
  const mounted = await mountEditor();
  try {
    await act(async () => button(mounted.node, 'Save').click()); await flush();
    await act(async () => button(mounted.node.querySelector('[role="dialog"]'), 'Confirm Advanced Save').click()); await flush();
    expect(axios.put).toHaveBeenCalledTimes(1);
    const check = button(mounted.node, 'Check status');
    expect(check).toBeTruthy();
    const before = operationGets(operationId).length;
    act(() => { swap(); check.click(); }); await flush();
    expect(operationGets(operationId)).toHaveLength(before);
    expect(axios.put).toHaveBeenCalledTimes(1);
  } finally { await mounted.close(); }
});
