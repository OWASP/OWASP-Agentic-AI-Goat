import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import { MemoryRouter } from 'react-router-dom';
import axios from 'axios';
import { toast } from 'react-toastify';
import ComprehensiveAdminDashboard from './ComprehensiveAdminDashboard';

jest.mock('axios', () => ({ get: jest.fn(), post: jest.fn(), put: jest.fn(), delete: jest.fn() }));
let mockUser, mockAuthRevision;
jest.mock('../context/AuthContext', () => ({ useAuth: () => ({ user: mockUser, logout: jest.fn(), getAuthRevision: () => mockAuthRevision }) }));
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
const student = { id: 19, username: 'learner', email: 'learner@example.test', is_active: 1 };
async function flush() { await act(async () => { await Promise.resolve(); await Promise.resolve(); await Promise.resolve(); }); }
async function mount() {
  node = document.createElement('div'); document.body.appendChild(node); root = createRoot(node);
  await act(async () => root.render(<MemoryRouter initialEntries={['/admin/students']}><ComprehensiveAdminDashboard /></MemoryRouter>));
  await flush();
}
function button(label) { const found = [...node.querySelectorAll('button')].find(item => item.textContent.trim() === label); expect(found).toBeTruthy(); return found; }
function reactHandler(element, name) { const props = element[Object.keys(element).find(key => key.startsWith('__reactProps$'))]; expect(typeof props?.[name]).toBe('function'); return props[name]; }
async function click(label) { await act(async () => button(label).click()); await flush(); }
function dialogForm() { return [...node.querySelectorAll('form')].filter(form => form.querySelector('input[placeholder="Enter new password (min 8 characters)"]')).at(-1); }
async function change(placeholder, value) { const input = dialogForm().querySelector(`input[placeholder="${placeholder}"]`); await act(async () => reactHandler(input, 'onChange')({ target: { value } })); await flush(); }
async function fill() { await change('Enter new password (min 8 characters)', 'new-password-123'); await change('Confirm new password', 'new-password-123'); }
async function open() { await mount(); await click('Password'); expect(dialogForm()).toBeTruthy(); }
function deferred() { let resolve; const promise = new Promise(done => { resolve = done; }); return { promise, resolve }; }

beforeEach(() => {
  global.IS_REACT_ACT_ENVIRONMENT = true;
  mockUser = { id: 1, username: 'admin-a', isAdmin: true, adminLevel: 2, permissions: ['user_management', 'manage_progress'] };
  mockAuthRevision = 0; localStorage.setItem('token', 'admin-a');
  axios.get.mockImplementation(url => url === '/api/admin/students'
    ? Promise.resolve({ data: { success: true, students: [student] } })
    : Promise.resolve({ data: { success: true, challenges: [] } }));
  axios.post.mockResolvedValue({ status: 200, data: { success: true, sessionsRevoked: 1 } });
  jest.spyOn(console, 'error').mockImplementation(() => {});
  jest.spyOn(console, 'warn').mockImplementation(() => {});
  jest.spyOn(console, 'log').mockImplementation(() => {});
});
afterEach(() => { if (root) { act(() => root.unmount()); root = null; } document.body.replaceChildren(); localStorage.clear(); jest.restoreAllMocks(); jest.clearAllMocks(); });

test('A staged password cannot be submitted under equally authorized B', async () => {
  await open(); await fill(); const submit = reactHandler(dialogForm(), 'onSubmit');
  mockUser = { ...mockUser, id: 2, username: 'admin-b' }; mockAuthRevision += 1; localStorage.setItem('token', 'admin-b');
  await act(async () => root.render(<MemoryRouter initialEntries={['/admin/students']}><ComprehensiveAdminDashboard /></MemoryRouter>)); await flush();
  await act(async () => submit({ preventDefault() {} }));
  expect(axios.post).not.toHaveBeenCalled();
});
test('same-render double password submit sends only one POST', async () => {
  const request = deferred(); axios.post.mockReturnValue(request.promise);
  await open(); await fill(); const submit = reactHandler(dialogForm(), 'onSubmit');
  act(() => { void submit({ preventDefault() {} }); void submit({ preventDefault() {} }); });
  expect(axios.post).toHaveBeenCalledTimes(1);
  await act(async () => request.resolve({ status: 200, data: { success: true, sessionsRevoked: 1 } })); await flush();
});
test('Cancel and restage clear plaintext and reject old field callbacks', async () => {
  await open(); await fill();
  const oldPassword = reactHandler(dialogForm().querySelector('input[placeholder="Enter new password (min 8 characters)"]'), 'onChange');
  await click('Cancel'); await click('Password');
  expect(dialogForm().querySelector('input[placeholder="Enter new password (min 8 characters)"]').value).toBe('');
  await act(async () => oldPassword({ target: { value: 'stale-plaintext' } }));
  expect(dialogForm().querySelector('input[placeholder="Enter new password (min 8 characters)"]').value).toBe('');
});
test('acknowledged zero revoked sessions is a valid success and uses staged bearer', async () => {
  axios.post.mockResolvedValueOnce({ status: 200, data: { success: true, sessionsRevoked: 0 } });
  await open(); await fill(); toast.success.mockClear();
  await act(async () => dialogForm().dispatchEvent(new Event('submit', { bubbles: true, cancelable: true }))); await flush();
  expect(axios.post).toHaveBeenCalledWith('/api/admin/students/19/change-password',
    { newPassword: 'new-password-123', confirmPassword: 'new-password-123' },
    { headers: { Authorization: 'Bearer admin-a' } });
  expect(toast.success).toHaveBeenCalledTimes(1);
  await click('Password');
  expect(dialogForm().querySelector('input[placeholder="Enter new password (min 8 characters)"]').value).toBe('');
});
test.each([
  ['missing count', { status: 200, data: { success: true } }],
  ['boolean count', { status: 200, data: { success: true, sessionsRevoked: true } }],
  ['negative count', { status: 200, data: { success: true, sessionsRevoked: -1 } }],
  ['missing success', { status: 200, data: { sessionsRevoked: 1 } }],
])('malformed password ACK with %s remains uncertain without retry', async (_label, response) => {
  axios.post.mockResolvedValueOnce(response);
  await open(); await fill(); toast.success.mockClear();
  await act(async () => dialogForm().dispatchEvent(new Event('submit', { bubbles: true, cancelable: true }))); await flush();
  expect(toast.success).not.toHaveBeenCalled();
  expect(dialogForm().textContent).toContain('outcome could not be confirmed');
  expect(dialogForm().querySelector('input[placeholder="Enter new password (min 8 characters)"]').value).toBe('');
  expect(axios.post).toHaveBeenCalledTimes(1);
  await act(async () => dialogForm().querySelector('button[type="button"]').click()); await flush();
  expect(axios.post).toHaveBeenCalledTimes(1);
  await click('Password');
  expect(dialogForm().querySelector('input[placeholder="Enter new password (min 8 characters)"]').value).toBe('');
});
test('lost response remains uncertain and never logs plaintext or retries', async () => {
  const lost = new Error('lost response'); lost.config = { data: JSON.stringify({ newPassword: 'new-password-123' }) };
  axios.post.mockRejectedValueOnce(lost);
  await open(); await fill(); toast.success.mockClear();
  await act(async () => dialogForm().dispatchEvent(new Event('submit', { bubbles: true, cancelable: true }))); await flush();
  expect(dialogForm().textContent).toContain('outcome could not be confirmed');
  expect(dialogForm().querySelector('input[placeholder="Confirm new password"]').value).toBe('');
  expect(toast.success).not.toHaveBeenCalled(); expect(console.error).not.toHaveBeenCalled();
  expect(axios.post).toHaveBeenCalledTimes(1);
});
test('late A ACK after B sign-in cannot show success', async () => {
  const request = deferred(); axios.post.mockReturnValue(request.promise);
  await open(); await fill();
  await act(async () => { void reactHandler(dialogForm(), 'onSubmit')({ preventDefault() {} }); });
  mockUser = { ...mockUser, id: 2, username: 'admin-b' }; mockAuthRevision += 1; localStorage.setItem('token', 'admin-b');
  await act(async () => root.render(<MemoryRouter initialEntries={['/admin/students']}><ComprehensiveAdminDashboard /></MemoryRouter>)); await flush();
  toast.success.mockClear();
  await act(async () => request.resolve({ status: 200, data: { success: true, sessionsRevoked: 1 } })); await flush();
  expect(toast.success).not.toHaveBeenCalled(); expect(axios.post).toHaveBeenCalledTimes(1);
});
test('storage ABA retires stage and retained submit without changing token string', async () => {
  await open(); await fill(); const submit = reactHandler(dialogForm(), 'onSubmit');
  await act(async () => window.dispatchEvent(new StorageEvent('storage', {
    key: 'token', oldValue: 'other', newValue: 'admin-a', storageArea: localStorage,
  })));
  await flush();
  await act(async () => submit({ preventDefault() {} }));
  expect(axios.post).not.toHaveBeenCalled();
  await click('Password');
  expect(dialogForm().querySelector('input[placeholder="Enter new password (min 8 characters)"]').value).toBe('');
});
test('auth revision ABA retires a retained submit even with the same actor and token', async () => {
  await open(); await fill(); const submit = reactHandler(dialogForm(), 'onSubmit');
  mockAuthRevision += 1;
  await act(async () => root.render(<MemoryRouter initialEntries={['/admin/students']}><ComprehensiveAdminDashboard /></MemoryRouter>)); await flush();
  await act(async () => submit({ preventDefault() {} }));
  expect(axios.post).not.toHaveBeenCalled();
  await click('Password');
  expect(dialogForm().querySelector('input[placeholder="Enter new password (min 8 characters)"]').value).toBe('');
});
test('retained old Cancel cannot dismiss a replacement password stage', async () => {
  await open(); const oldCancel = reactHandler(dialogForm().querySelector('button[type="button"]'), 'onClick');
  await click('Cancel'); await click('Password');
  await change('Enter new password (min 8 characters)', 'replacement-password');
  await act(async () => oldCancel());
  expect(dialogForm().querySelector('input[placeholder="Enter new password (min 8 characters)"]').value).toBe('replacement-password');
});
test('pending request clears visible secrets and cannot be dismissed or resubmitted', async () => {
  const request = deferred(); axios.post.mockReturnValue(request.promise);
  await open(); await fill(); const submit = reactHandler(dialogForm(), 'onSubmit');
  const cancel = reactHandler(dialogForm().querySelector('button[type="button"]'), 'onClick');
  const closeX = reactHandler(node.querySelector('button[aria-label="Close student password change"]'), 'onClick');
  await act(async () => { void submit({ preventDefault() {} }); });
  expect(dialogForm().querySelector('input[placeholder="Enter new password (min 8 characters)"]').value).toBe('');
  expect(dialogForm().querySelector('input[placeholder="Confirm new password"]').value).toBe('');
  await act(async () => { cancel(); closeX(); }); await flush();
  expect(dialogForm().querySelector('button[type="button"]').disabled).toBe(true);
  toast.success.mockClear();
  await act(async () => { void submit({ preventDefault() {} }); });
  expect(axios.post).toHaveBeenCalledTimes(1);
  await act(async () => request.resolve({ status: 200, data: { success: true, sessionsRevoked: 1 } })); await flush();
  expect(toast.success).toHaveBeenCalledTimes(1);
});
test('retained submit after unmount cannot issue a password rotation', async () => {
  await open(); await fill(); const submit = reactHandler(dialogForm(), 'onSubmit');
  await act(async () => root.unmount()); root = null;
  await act(async () => submit({ preventDefault() {} }));
  expect(axios.post).not.toHaveBeenCalled();
});
test('permission retirement blocks a staged password submit', async () => {
  await open(); await fill(); const submit = reactHandler(dialogForm(), 'onSubmit');
  mockUser = { ...mockUser, permissions: ['manage_progress'] };
  await act(async () => root.render(<MemoryRouter initialEntries={['/admin/students']}><ComprehensiveAdminDashboard /></MemoryRouter>)); await flush();
  await act(async () => submit({ preventDefault() {} }));
  expect(axios.post).not.toHaveBeenCalled();
});
test('navigation retires staged password and its retained submit', async () => {
  await open(); await fill(); const submit = reactHandler(dialogForm(), 'onSubmit');
  const nav = label => [...node.querySelectorAll('div')].find(item => item.textContent.trim() === label
    && typeof item[Object.keys(item).find(key => key.startsWith('__reactProps$'))]?.onClick === 'function');
  expect(nav('Settings')).toBeTruthy();
  await act(async () => nav('Settings').click()); await flush();
  await act(async () => submit({ preventDefault() {} }));
  expect(axios.post).not.toHaveBeenCalled();
  expect(nav('Students')).toBeTruthy();
  await act(async () => nav('Students').click()); await flush();
  await click('Password');
  expect(dialogForm().querySelector('input[placeholder="Enter new password (min 8 characters)"]').value).toBe('');
});
test.each(['close button', 'backdrop'])('%s retires stage and clears plaintext', async method => {
  await open(); await fill(); const form = dialogForm(), submit = reactHandler(form, 'onSubmit');
  const close = method === 'close button'
    ? reactHandler(node.querySelector('button[aria-label="Close student password change"]'), 'onClick')
    : reactHandler(form.parentElement.parentElement.parentElement, 'onClick');
  await act(async () => close()); await flush();
  await act(async () => submit({ preventDefault() {} }));
  expect(axios.post).not.toHaveBeenCalled();
  await click('Password');
  expect(dialogForm().querySelector('input[placeholder="Enter new password (min 8 characters)"]').value).toBe('');
});
