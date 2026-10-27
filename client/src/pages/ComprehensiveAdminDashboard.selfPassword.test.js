import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import { MemoryRouter, useLocation, useNavigate } from 'react-router-dom';
import axios from 'axios';
import { toast } from 'react-toastify';
import ComprehensiveAdminDashboard from './ComprehensiveAdminDashboard';

jest.mock('axios', () => ({ get: jest.fn(), post: jest.fn(), put: jest.fn(), delete: jest.fn() }));
let mockUser, mockAuthRevision;
const mockLogout = jest.fn();
jest.mock('../context/AuthContext', () => ({ useAuth: () => ({ user: mockUser, logout: mockLogout,
  getAuthRevision: () => mockAuthRevision }) }));
jest.mock('../context/WorkshopConfigContext', () => ({ useWorkshopConfig: () => ({ registerReconciler: () => () => {} }) }));
jest.mock('react-toastify', () => ({ toast: { error: jest.fn(), success: jest.fn() } }));
jest.mock('./admin/CTFAdminPanel', () => () => null);
jest.mock('../components/admin/AIProviderManagement', () => () => null);
jest.mock('../components/admin/StudentWorkshopView', () => () => null);
jest.mock('../components/admin/ServerLogs', () => () => null);
jest.mock('./admin/ProgressAnalyticsPanel', () => () => null);
jest.mock('../components/admin/PromptInjectionHintEditorModal', () => () => null);
jest.mock('../components/observability/AgentRunInspector', () => () => null);

let root, node;
let navigateInTest;
const ack = { status: 200, data: { success: true, sessionsRevoked: 1 } };
async function flush() { await act(async () => { await Promise.resolve(); await Promise.resolve(); await Promise.resolve(); }); }
function PathProbe() { const location = useLocation(); navigateInTest = useNavigate(); return <span data-testid="path">{location.pathname}</span>; }
async function mount() { node = document.createElement('div'); document.body.appendChild(node); root = createRoot(node);
  await act(async () => root.render(<MemoryRouter initialEntries={['/admin/settings']}><ComprehensiveAdminDashboard /><PathProbe /></MemoryRouter>)); await flush(); }
function button(label) { const found = [...node.querySelectorAll('button')].find(item => item.textContent.trim() === label); expect(found).toBeTruthy(); return found; }
function handler(element, name) { const props = element[Object.keys(element).find(key => key.startsWith('__reactProps$'))]; expect(typeof props?.[name]).toBe('function'); return props[name]; }
async function click(label) { await act(async () => button(label).click()); await flush(); }
function form() { return [...node.querySelectorAll('form')].filter(item => [...item.querySelectorAll('button')].some(button => button.textContent.trim() === 'Change Password')).at(-1); }
async function change(index, value) { const input = form().querySelectorAll('input[type="password"]')[index];
  await act(async () => handler(input, 'onChange')({ target: { value } })); await flush(); }
async function fill() { await change(0, 'current-password'); await change(1, 'new-password-123'); await change(2, 'new-password-123'); }
async function open() { await mount(); await click('Change Password'); expect(form()).toBeTruthy(); }
function deferred() { let resolve, reject; const promise = new Promise((done, fail) => { resolve = done; reject = fail; }); return { promise, resolve, reject }; }

beforeEach(() => { global.IS_REACT_ACT_ENVIRONMENT = true;
  mockUser = { id: 1, username: 'admin-a', isAdmin: true, adminLevel: 2, permissions: ['user_management'] };
  mockAuthRevision = 0; localStorage.setItem('token', 'admin-a'); mockLogout.mockResolvedValue({ success: true });
  axios.get.mockImplementation(() => Promise.resolve({ data: { success: true, challenges: [] } }));
  axios.post.mockResolvedValue(ack);
  jest.spyOn(console, 'error').mockImplementation(() => {}); jest.spyOn(console, 'warn').mockImplementation(() => {});
  jest.spyOn(console, 'log').mockImplementation(() => {});
});
afterEach(() => { if (root) { act(() => root.unmount()); root = null; } document.body.replaceChildren(); localStorage.clear();
  jest.restoreAllMocks(); jest.clearAllMocks(); });

test('A staged self-password cannot POST under equally authorized B', async () => {
  await open(); await fill(); const submit = handler(form(), 'onSubmit');
  mockUser = { ...mockUser, id: 2, username: 'admin-b' }; mockAuthRevision += 1; localStorage.setItem('token', 'admin-b');
  await act(async () => root.render(<MemoryRouter initialEntries={['/admin/settings']}><ComprehensiveAdminDashboard /><PathProbe /></MemoryRouter>)); await flush();
  await act(async () => submit({ preventDefault() {} }));
  expect(axios.post.mock.calls.some(([url]) => url === '/api/admin/account/change-password')).toBe(false);
});
test('same-render double self-password submit sends only one POST', async () => {
  const request = deferred(); axios.post.mockReturnValue(request.promise); await open(); await fill();
  const submit = handler(form(), 'onSubmit'); act(() => { void submit({ preventDefault() {} }); void submit({ preventDefault() {} }); });
  expect(axios.post.mock.calls.filter(([url]) => url === '/api/admin/account/change-password')).toHaveLength(1);
  await act(async () => request.resolve(ack)); await flush();
});
test('Cancel and restage clear all three password fields', async () => {
  await open(); await fill(); await click('Cancel'); await click('Change Password');
  expect([...form().querySelectorAll('input[type="password"]')].map(input => input.value)).toEqual(['', '', '']);
});
test('strict 200 acknowledgement with zero revoked sessions signs out and navigates immediately', async () => {
  const logoutResult = deferred(); mockLogout.mockReturnValueOnce(logoutResult.promise);
  axios.post.mockResolvedValueOnce({ status: 200, data: { success: true, sessionsRevoked: 0 } });
  await open(); await fill(); toast.success.mockClear();
  await act(async () => form().dispatchEvent(new Event('submit', { bubbles: true, cancelable: true }))); await flush();
  expect(axios.post).toHaveBeenCalledWith('/api/admin/account/change-password',
    { currentPassword: 'current-password', newPassword: 'new-password-123', confirmPassword: 'new-password-123' },
    { headers: { Authorization: 'Bearer admin-a' } });
  expect(mockLogout).toHaveBeenCalledTimes(1);
  expect(node.querySelector('[data-testid="path"]').textContent).toBe('/workshop-login');
  expect(toast.success).toHaveBeenCalledWith('Password changed. Your sessions were revoked; sign in again.');
  await act(async () => logoutResult.resolve({ success: true })); await flush();
});
test.each(['resolve', 'reject'])('old pending logout %s cannot redirect a newer administrator session', async ending => {
  const logoutResult = deferred(); mockLogout.mockReturnValueOnce(logoutResult.promise);
  await open(); await fill();
  await act(async () => form().dispatchEvent(new Event('submit', { bubbles: true, cancelable: true }))); await flush();
  expect(node.querySelector('[data-testid="path"]').textContent).toBe('/workshop-login');
  mockUser = { ...mockUser, id: 2, username: 'admin-b' }; mockAuthRevision += 1; localStorage.setItem('token', 'admin-b');
  await act(async () => navigateInTest('/admin/settings')); await flush();
  expect(node.querySelector('[data-testid="path"]').textContent).toBe('/admin/settings');
  await act(async () => ending === 'resolve'
    ? logoutResult.resolve({ success: true }) : logoutResult.reject(new Error('old logout failed'))); await flush();
  expect(node.querySelector('[data-testid="path"]').textContent).toBe('/admin/settings');
  expect(mockLogout).toHaveBeenCalledTimes(1);
});
test.each([
  ['missing revoked count', { status: 200, data: { success: true } }],
  ['boolean revoked count', { status: 200, data: { success: true, sessionsRevoked: true } }],
  ['negative revoked count', { status: 200, data: { success: true, sessionsRevoked: -1 } }],
  ['missing success', { status: 200, data: { sessionsRevoked: 1 } }],
])('%s ACK stays unknown without logout or replay', async (_label, response) => {
  axios.post.mockResolvedValueOnce(response); await open(); await fill(); toast.success.mockClear();
  const retainedSubmit = handler(form(), 'onSubmit');
  await act(async () => form().dispatchEvent(new Event('submit', { bubbles: true, cancelable: true }))); await flush();
  expect(form().textContent).toContain('outcome could not be confirmed');
  expect([...form().querySelectorAll('input[type="password"]')].map(input => input.value)).toEqual(['', '', '']);
  expect(mockLogout).not.toHaveBeenCalled(); expect(toast.success).not.toHaveBeenCalled();
  await act(async () => retainedSubmit({ preventDefault() {} }));
  expect(axios.post.mock.calls.filter(([url]) => url === '/api/admin/account/change-password')).toHaveLength(1);
});
test('lost response with secret-bearing Axios config is never logged or retried', async () => {
  const lost = new Error('lost'); lost.config = { data: JSON.stringify({ currentPassword: 'current-password' }) };
  axios.post.mockRejectedValueOnce(lost); await open(); await fill(); toast.success.mockClear();
  await act(async () => form().dispatchEvent(new Event('submit', { bubbles: true, cancelable: true }))); await flush();
  expect(form().textContent).toContain('outcome could not be confirmed');
  expect(console.error).not.toHaveBeenCalled(); expect(mockLogout).not.toHaveBeenCalled();
  expect(axios.post.mock.calls.filter(([url]) => url === '/api/admin/account/change-password')).toHaveLength(1);
});
test('late A acknowledgement after B sign-in cannot logout or navigate B', async () => {
  const request = deferred(); axios.post.mockReturnValue(request.promise); await open(); await fill();
  const submit = handler(form(), 'onSubmit'); act(() => { void submit({ preventDefault() {} }); });
  mockUser = { ...mockUser, id: 2, username: 'admin-b' }; mockAuthRevision += 1; localStorage.setItem('token', 'admin-b');
  await act(async () => root.render(<MemoryRouter initialEntries={['/admin/settings']}><ComprehensiveAdminDashboard /><PathProbe /></MemoryRouter>)); await flush();
  toast.success.mockClear();
  await act(async () => request.resolve(ack)); await flush();
  expect(mockLogout).not.toHaveBeenCalled(); expect(toast.success).not.toHaveBeenCalled();
  expect(node.querySelector('[data-testid="path"]').textContent).toBe('/admin/settings');
});
test('pending request clears all secrets and ignores retained close and duplicate submit', async () => {
  const request = deferred(); axios.post.mockReturnValue(request.promise); await open(); await fill();
  const submit = handler(form(), 'onSubmit'); const cancel = handler(form().querySelector('button[type="button"]'), 'onClick');
  act(() => { void submit({ preventDefault() {} }); cancel(); void submit({ preventDefault() {} }); });
  expect([...form().querySelectorAll('input[type="password"]')].map(input => input.value)).toEqual(['', '', '']);
  expect(axios.post.mock.calls.filter(([url]) => url === '/api/admin/account/change-password')).toHaveLength(1);
  await act(async () => request.resolve(ack)); await flush(); expect(mockLogout).toHaveBeenCalledTimes(1);
});
test('retained old field and Cancel callbacks cannot affect a new self-password stage', async () => {
  await open(); const oldField = handler(form().querySelector('input[type="password"]'), 'onChange');
  const oldCancel = handler(form().querySelector('button[type="button"]'), 'onClick');
  await click('Cancel'); await click('Change Password');
  await change(0, 'replacement-current');
  await act(async () => { oldField({ target: { value: 'old-current' } }); oldCancel(); });
  expect(form().querySelector('input[type="password"]').value).toBe('replacement-current');
});
test('same-token auth revision retires retained self-password form', async () => {
  await open(); await fill(); const submit = handler(form(), 'onSubmit'); mockAuthRevision += 1;
  await act(async () => root.render(<MemoryRouter initialEntries={['/admin/settings']}><ComprehensiveAdminDashboard /><PathProbe /></MemoryRouter>)); await flush();
  await act(async () => submit({ preventDefault() {} }));
  expect(axios.post.mock.calls.some(([url]) => url === '/api/admin/account/change-password')).toBe(false);
  await click('Change Password');
  expect([...form().querySelectorAll('input[type="password"]')].map(input => input.value)).toEqual(['', '', '']);
});
test('cross-tab token storage ABA retires retained self-password form', async () => {
  await open(); await fill(); const submit = handler(form(), 'onSubmit');
  await act(async () => window.dispatchEvent(new StorageEvent('storage', {
    key: 'token', oldValue: 'other', newValue: 'admin-a', storageArea: localStorage,
  }))); await flush();
  await act(async () => submit({ preventDefault() {} }));
  expect(axios.post.mock.calls.some(([url]) => url === '/api/admin/account/change-password')).toBe(false);
  await click('Change Password');
  expect([...form().querySelectorAll('input[type="password"]')].map(input => input.value)).toEqual(['', '', '']);
});
test('unmount denies retained self-password submit', async () => {
  await open(); await fill(); const submit = handler(form(), 'onSubmit');
  await act(async () => root.unmount()); root = null;
  await act(async () => submit({ preventDefault() {} }));
  expect(axios.post.mock.calls.some(([url]) => url === '/api/admin/account/change-password')).toBe(false);
});
test.each(['X', 'backdrop'])('%s dismissal clears secrets and retires retained submit', async method => {
  await open(); await fill(); const current = form(), submit = handler(current, 'onSubmit');
  const close = method === 'X'
    ? handler(node.querySelector('button[aria-label="Close own password change"]'), 'onClick')
    : handler(current.parentElement.parentElement.parentElement, 'onClick');
  await act(async () => close()); await flush();
  await act(async () => submit({ preventDefault() {} }));
  expect(axios.post.mock.calls.some(([url]) => url === '/api/admin/account/change-password')).toBe(false);
  await click('Change Password');
  expect([...form().querySelectorAll('input[type="password"]')].map(input => input.value)).toEqual(['', '', '']);
});
test('leaving Settings retires staged password and prevents old submit', async () => {
  await open(); await fill(); const submit = handler(form(), 'onSubmit');
  const nav = label => [...node.querySelectorAll('div')].find(item => item.textContent.trim() === label
    && typeof item[Object.keys(item).find(key => key.startsWith('__reactProps$'))]?.onClick === 'function');
  expect(nav('Dashboard')).toBeTruthy();
  await act(async () => nav('Dashboard').click()); await flush();
  await act(async () => submit({ preventDefault() {} }));
  expect(axios.post.mock.calls.some(([url]) => url === '/api/admin/account/change-password')).toBe(false);
});
