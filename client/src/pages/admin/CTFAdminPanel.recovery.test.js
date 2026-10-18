import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import axios from 'axios';
import { toast } from 'react-toastify';
import CTFAdminPanel from './CTFAdminPanel';
jest.mock('axios', () => ({ get: jest.fn(), post: jest.fn(), put: jest.fn(), delete: jest.fn() }));
jest.mock('react-toastify', () => ({ toast: { error: jest.fn(), success: jest.fn() } }));
async function flush() { await act(async () => { await Promise.resolve(); await Promise.resolve(); }); }
test('config202 retains current display and suppresses success toast until current projection', async () => {
 global.IS_REACT_ACT_ENVIRONMENT = true; localStorage.setItem('token', 'admin');
 axios.get.mockImplementation(url => Promise.resolve({ data: url.endsWith('/analytics') ? { analytics: {} } : { config: { ctf_enabled: 'true' } } }));
 const node = document.createElement('div'); document.body.appendChild(node); const root = createRoot(node);
 act(() => root.render(<CTFAdminPanel />)); await flush();
 const configTab = [...node.querySelectorAll('button')].find(x => x.textContent.includes('Config'));
 act(() => configTab.click()); await flush();
 const toggle = node.querySelector('button[role="switch"]');
 expect(toggle).not.toBeNull();
 let finish; axios.post.mockResolvedValue({ status: 202, data: { operationId: '11111111-1111-4111-8111-111111111111' } });
 axios.get.mockImplementationOnce(() => new Promise(resolve => { finish = resolve; }));
 act(() => toggle.click()); await flush();
 expect(toast.success).not.toHaveBeenCalled(); expect(toggle.getAttribute('aria-checked')).toBe('true');
 await act(async () => finish({ status: 200, data: { success: true } })); await flush();
 expect(toast.success).toHaveBeenCalledTimes(1); expect(axios.post).toHaveBeenCalledTimes(1);
 act(() => root.unmount()); node.remove(); localStorage.clear();
});

test('stage editor displays persisted full feedback and can restore and save it after editing', async () => {
 global.IS_REACT_ACT_ENVIRONMENT = true;
 jest.clearAllMocks(); localStorage.setItem('token', 'admin');
 const stage = { id: 1, stage_number: 1, stage_name: 'Open guardian', feedback_mode: 'full', hints: '[]', defense_style: '[]', is_active: 1 };
 axios.get.mockImplementation(url => Promise.resolve({ data: url.endsWith('/stages') ? { stages: [stage] } : { analytics: {} } }));
 axios.put.mockResolvedValue({ status: 200, data: { success: true } });
 const node = document.createElement('div'); document.body.appendChild(node); const root = createRoot(node);
 try {
  act(() => root.render(<CTFAdminPanel />)); await flush();
  act(() => [...node.querySelectorAll('button')].find(x => x.textContent.includes('Levels')).click()); await flush();
  act(() => [...node.querySelectorAll('td')].find(x => x.textContent === 'Open guardian').click());
  const select = [...node.querySelectorAll('label')].find(x => x.textContent === 'Feedback Mode').parentElement.querySelector('select');
  expect(select.value).toBe('full');
  act(() => { select.value = 'silent'; select.dispatchEvent(new Event('change', { bubbles: true })); });
  expect(select.value).toBe('silent');
  act(() => { select.value = 'full'; select.dispatchEvent(new Event('change', { bubbles: true })); });
  expect(select.value).toBe('full');
  act(() => [...node.querySelectorAll('button')].find(x => x.textContent.trim() === 'Save').click()); await flush();
  expect(axios.put).toHaveBeenCalledTimes(1);
  expect(axios.put.mock.calls[0][0]).toBe('/api/ctf/admin/stages/1');
  expect(axios.put.mock.calls[0][1]).toEqual(expect.objectContaining({ feedback_mode: 'full', stage_name: 'Open guardian', hints: '[]', defense_style: '[]' }));
  expect(toast.success).toHaveBeenCalledWith('Stage saved');
 } finally { act(() => root.unmount()); node.remove(); localStorage.clear(); }
});
