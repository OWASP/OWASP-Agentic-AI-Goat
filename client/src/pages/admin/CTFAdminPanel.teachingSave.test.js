/* eslint-disable testing-library/no-unnecessary-act -- React DOM createRoot is used directly. */
import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import axios from 'axios';
import { toast } from 'react-toastify';
import CTFAdminPanel from './CTFAdminPanel';

jest.mock('axios', () => ({ get: jest.fn(), post: jest.fn(), put: jest.fn(), delete: jest.fn() }));
jest.mock('react-toastify', () => ({ toast: { error: jest.fn(), success: jest.fn() } }));

const stage = (id, name) => ({ id, stage_number: id, stage_name: name,
  stage_description: `Description ${id}`, hints: '["First hint"]', teaching_objective: `Objective ${id}`,
  solution_content: `Instructor solution ${id}`, system_prompt: `POLICY_${id}`, success_criteria: `SECRET_${id}`,
  defense_style: '[]', adaptive_mode: 'none', level_score: 100, feedback_mode: 'reason' });
const stages = [stage(12, 'Teaching level'), stage(13, 'Sibling level')];
const button = (node, label) => [...node.querySelectorAll('button')].find(item => item.textContent.trim() === label);
const reactClick = node => node[Object.keys(node).find(key => key.startsWith('__reactProps$'))].onClick;
async function flush() { await act(async () => { await Promise.resolve(); await Promise.resolve(); await Promise.resolve(); }); }

beforeEach(() => {
  global.IS_REACT_ACT_ENVIRONMENT = true;
  localStorage.clear(); localStorage.setItem('token', 'admin-token');
  axios.get.mockImplementation(url => Promise.resolve({ data: url.endsWith('/stages') ? { stages } : { analytics: {} } }));
  axios.put.mockResolvedValue({ status: 200, data: { message: 'Teaching content updated' } });
});
afterEach(() => { localStorage.clear(); jest.restoreAllMocks(); });

async function mountEditor() {
  const node = document.createElement('div'); document.body.appendChild(node);
  const root = createRoot(node);
  await act(async () => root.render(<CTFAdminPanel />)); await flush();
  await act(async () => button(node, 'Levels').click()); await flush();
  const row = [...node.querySelectorAll('tr')].find(item => item.textContent.includes('Teaching level'));
  await act(async () => row.click()); await flush();
  return { node, root, row, close: async () => { await act(async () => root.unmount()); node.remove(); } };
}

test('Teaching Save stages immutable review; Cancel never sends a PUT', async () => {
  const mounted = await mountEditor();
  try {
    await act(async () => button(mounted.node, 'Save teaching content').click()); await flush();
    expect(axios.put).not.toHaveBeenCalled();
    const dialog = mounted.node.querySelector('[role="dialog"]');
    expect(dialog?.textContent).toContain('Teaching level');
    expect(dialog?.textContent).toContain('hints');
    await act(async () => button(dialog, 'Cancel').click()); await flush();
    expect(axios.put).not.toHaveBeenCalled();
  } finally { await mounted.close(); }
});

test('retained Save from a closed editor cannot stage an earlier draft under a reopened editor', async () => {
  const mounted = await mountEditor();
  try {
    const staleSave = reactClick(button(mounted.node, 'Save teaching content'));
    await act(async () => mounted.row.click()); await flush();
    await act(async () => mounted.row.click()); await flush();
    act(() => staleSave()); await flush();
    expect(mounted.node.querySelector('[role="dialog"]')).toBeNull();
    expect(axios.put).not.toHaveBeenCalled();
  } finally { await mounted.close(); }
});

test('Refresh retires an old editor Save callback while leaving the refreshed editor usable', async () => {
  const mounted = await mountEditor();
  try {
    const staleSave = reactClick(button(mounted.node, 'Save teaching content'));
    await act(async () => button(mounted.node, 'Refresh').click()); await flush();
    expect(button(mounted.node, 'Save teaching content')).toBeTruthy();
    act(() => staleSave()); await flush();
    expect(mounted.node.querySelector('[role="dialog"]')).toBeNull();
    expect(axios.put).not.toHaveBeenCalled();
    await act(async () => button(mounted.node, 'Save teaching content').click()); await flush();
    expect(mounted.node.querySelector('[role="dialog"]')).toBeTruthy();
  } finally { await mounted.close(); }
});

test('Teaching Save review rejects a cross-tab A→B→A authority cycle and retained Confirm', async () => {
  const mounted = await mountEditor();
  try {
    await act(async () => button(mounted.node, 'Save teaching content').click()); await flush();
    const retained = reactClick(button(mounted.node.querySelector('[role="dialog"]'), 'Confirm Teaching Save'));
    act(() => {
      localStorage.setItem('token', 'other-admin-token');
      window.dispatchEvent(new StorageEvent('storage', { key: 'token', storageArea: localStorage }));
      localStorage.setItem('token', 'admin-token');
      window.dispatchEvent(new StorageEvent('storage', { key: 'token', storageArea: localStorage }));
      retained();
    });
    await flush();
    expect(axios.put).not.toHaveBeenCalled();
    expect(toast.success).not.toHaveBeenCalled();
  } finally { await mounted.close(); }
});

test('Teaching Save Confirm synchronously claims one exact five-field PUT with the original bearer', async () => {
  let finish;
  axios.put.mockImplementation(() => new Promise(resolve => { finish = resolve; }));
  const mounted = await mountEditor();
  try {
    await act(async () => button(mounted.node, 'Save teaching content').click()); await flush();
    const confirm = button(mounted.node.querySelector('[role="dialog"]'), 'Confirm Teaching Save');
    act(() => { confirm.click(); confirm.click(); });
    expect(axios.put).toHaveBeenCalledTimes(1);
    expect(axios.put).toHaveBeenCalledWith('/api/ctf/admin/stages/12/content', {
      stage_name: 'Teaching level', stage_description: 'Description 12', hints: '["First hint"]',
      teaching_objective: 'Objective 12', solution_content: 'Instructor solution 12',
    }, expect.objectContaining({ headers: { Authorization: 'Bearer admin-token' } }));
    expect(mounted.node.querySelector('[role="dialog"]')).toBeNull();
    await act(async () => finish({ status: 200, data: { message: 'Teaching content updated' } })); await flush();
    expect(toast.success).toHaveBeenCalledTimes(1);
  } finally { await mounted.close(); }
});

test('late Teaching Save response after storage ABA cannot publish stale success or retry', async () => {
  let finish;
  axios.put.mockImplementation(() => new Promise(resolve => { finish = resolve; }));
  const mounted = await mountEditor();
  try {
    await act(async () => button(mounted.node, 'Save teaching content').click()); await flush();
    await act(async () => button(mounted.node.querySelector('[role="dialog"]'), 'Confirm Teaching Save').click()); await flush();
    act(() => {
      localStorage.setItem('token', 'other-admin-token');
      window.dispatchEvent(new StorageEvent('storage', { key: 'token', storageArea: localStorage }));
      localStorage.setItem('token', 'admin-token');
      window.dispatchEvent(new StorageEvent('storage', { key: 'token', storageArea: localStorage }));
    });
    await flush();
    await act(async () => finish({ status: 200, data: { message: 'Teaching content updated' } })); await flush();
    expect(toast.success).not.toHaveBeenCalled();
    expect(axios.put).toHaveBeenCalledTimes(1);
  } finally { await mounted.close(); }
});

test('parked Teaching Save recovery cannot Check status after storage ABA', async () => {
  const operationId = '10000000-0000-0000-0000-000000000001';
  axios.put.mockResolvedValue({ status: 202, data: { pending: true, operationId } });
  axios.get.mockImplementation(url => {
    if (url === `/api/ctf/operations/${operationId}`) return Promise.reject(new Error('Current status unavailable'));
    return Promise.resolve({ data: url.endsWith('/stages') ? { stages } : { analytics: {} } });
  });
  const mounted = await mountEditor();
  try {
    await act(async () => button(mounted.node, 'Save teaching content').click()); await flush();
    await act(async () => button(mounted.node.querySelector('[role="dialog"]'), 'Confirm Teaching Save').click()); await flush();
    const check = button(mounted.node, 'Check status');
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
    expect(axios.put).toHaveBeenCalledTimes(1);
  } finally { await mounted.close(); }
});

test('old row handler cannot open its editor after storage authority retirement', async () => {
  const mounted = await mountEditor();
  try {
    const staleOpen = reactClick(mounted.row);
    act(() => {
      localStorage.setItem('token', 'other-admin-token');
      window.dispatchEvent(new StorageEvent('storage', { key: 'token', storageArea: localStorage }));
      localStorage.setItem('token', 'admin-token');
      window.dispatchEvent(new StorageEvent('storage', { key: 'token', storageArea: localStorage }));
      staleOpen();
    });
    await flush();
    expect(button(mounted.node, 'Save teaching content')).toBeFalsy();
    expect(axios.put).not.toHaveBeenCalled();
  } finally { await mounted.close(); }
});

test('older stage GET cannot replace the current administrator roster after a token change', async () => {
  let releaseOld;
  axios.get.mockImplementation((url, config) => {
    if (url !== '/api/ctf/admin/stages') return Promise.resolve({ data: { analytics: {} } });
    return config?.headers?.Authorization === 'Bearer admin-token'
      ? new Promise(resolve => { releaseOld = resolve; })
      : Promise.resolve({ data: { stages: [stage(13, 'Current admin stage')] } });
  });
  const node = document.createElement('div'); document.body.appendChild(node);
  const root = createRoot(node);
  try {
    await act(async () => root.render(<CTFAdminPanel />)); await flush();
    await act(async () => button(node, 'Levels').click()); await flush();
    act(() => {
      localStorage.setItem('token', 'other-admin-token');
      window.dispatchEvent(new StorageEvent('storage', { key: 'token', storageArea: localStorage }));
    });
    await flush();
    expect(node.textContent).toContain('Current admin stage');
    await act(async () => releaseOld({ data: { stages: [stage(12, 'Old admin stage')] } })); await flush();
    expect(node.textContent).toContain('Current admin stage');
    expect(node.textContent).not.toContain('Old admin stage');
  } finally { await act(async () => root.unmount()); node.remove(); }
});
