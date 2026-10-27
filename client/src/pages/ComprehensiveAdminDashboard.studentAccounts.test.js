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
const student = { id: 19, username: 'learner', email: 'learner@example.test', role: 'student', admin_level: 0,
  full_name: 'Learner', phone: '', department: '', is_active: 1, email_verified: 1 };
const createAck = { status: 201, data: { success: true, user: { id: 31, username: 'new-learner',
  email: 'new@example.test', role: 'student', admin_level: 0, full_name: '', is_active: 1 } } };
const editAck = { status: 200, data: { success: true, changes: 1, user: { ...student, username: 'updated-learner' } } };
async function flush() { await act(async () => { await Promise.resolve(); await Promise.resolve(); await Promise.resolve(); }); }
async function mount() { node = document.createElement('div'); document.body.appendChild(node); root = createRoot(node);
  await act(async () => root.render(<MemoryRouter initialEntries={['/admin/students']}><ComprehensiveAdminDashboard /></MemoryRouter>)); await flush(); }
function button(label) { const found = [...node.querySelectorAll('button')].find(item => item.textContent.trim() === label); expect(found).toBeTruthy(); return found; }
function handler(element, name) { const props = element[Object.keys(element).find(key => key.startsWith('__reactProps$'))]; expect(typeof props?.[name]).toBe('function'); return props[name]; }
async function click(label) { await act(async () => button(label).click()); await flush(); }
function form(label) { return [...node.querySelectorAll('form')].filter(item => [...item.querySelectorAll('button')].some(button => button.textContent.trim() === label)).at(-1); }
async function change(input, value, checked) { await act(async () => handler(input, 'onChange')({ target: checked === undefined ? { value } : { value, checked } })); await flush(); }
async function openCreate() { await mount(); await click('Create New Student'); expect(form('Create Student')).toBeTruthy(); }
async function fillCreate() { const current = form('Create Student'); await change(current.querySelector('input[placeholder="Enter username"]'), 'new-learner');
  await change(form('Create Student').querySelector('input[placeholder="Enter email"]'), 'new@example.test');
  await change(form('Create Student').querySelector('input[placeholder="Enter password"]'), 'new-password-123');
  await change(form('Create Student').querySelector('input[placeholder="Confirm password"]'), 'new-password-123'); }
async function openEdit() { await mount(); await click('Edit'); expect(form('Update Student')).toBeTruthy(); }
async function fillEdit() { await change(form('Update Student').querySelector('input[type="text"]'), 'updated-learner'); }
function deferred() { let resolve; const promise = new Promise(done => { resolve = done; }); return { promise, resolve }; }
async function rerenderB() { mockUser = { ...mockUser, id: 2, username: 'admin-b' }; mockAuthRevision += 1; localStorage.setItem('token', 'admin-b');
  await act(async () => root.render(<MemoryRouter initialEntries={['/admin/students']}><ComprehensiveAdminDashboard /></MemoryRouter>)); await flush(); }

beforeEach(() => { global.IS_REACT_ACT_ENVIRONMENT = true;
  mockUser = { id: 1, username: 'admin-a', isAdmin: true, adminLevel: 2, permissions: ['user_management', 'manage_progress'] };
  mockAuthRevision = 0; localStorage.setItem('token', 'admin-a');
  axios.get.mockImplementation(url => url === '/api/admin/students'
    ? Promise.resolve({ data: { success: true, students: [student] } })
    : Promise.resolve({ data: { success: true, challenges: [] } }));
  axios.post.mockResolvedValue(createAck); axios.put.mockResolvedValue(editAck);
  jest.spyOn(console, 'error').mockImplementation(() => {}); jest.spyOn(console, 'warn').mockImplementation(() => {});
  jest.spyOn(console, 'log').mockImplementation(() => {});
});
afterEach(() => { if (root) { act(() => root.unmount()); root = null; } document.body.replaceChildren(); localStorage.clear();
  jest.restoreAllMocks(); jest.clearAllMocks(); });

test('A staged Create cannot POST its password under B', async () => {
  await openCreate(); await fillCreate(); const submit = handler(form('Create Student'), 'onSubmit'); await rerenderB();
  await act(async () => submit({ preventDefault() {} })); expect(axios.post).not.toHaveBeenCalled();
});
test('same-render double Create sends one POST', async () => {
  const request = deferred(); axios.post.mockReturnValue(request.promise); await openCreate(); await fillCreate();
  const submit = handler(form('Create Student'), 'onSubmit'); act(() => { void submit({ preventDefault() {} }); void submit({ preventDefault() {} }); });
  expect(axios.post).toHaveBeenCalledTimes(1); await act(async () => request.resolve(createAck)); await flush();
});
test('Create Cancel and restage clear plaintext and reject old password callback', async () => {
  await openCreate(); await fillCreate(); const oldPassword = handler(form('Create Student').querySelector('input[placeholder="Enter password"]'), 'onChange');
  await click('Cancel'); await click('Create New Student');
  expect(form('Create Student').querySelector('input[placeholder="Enter password"]').value).toBe('');
  await act(async () => oldPassword({ target: { value: 'stale-plaintext' } }));
  expect(form('Create Student').querySelector('input[placeholder="Enter password"]').value).toBe('');
});
test('A staged Edit cannot PUT under B', async () => {
  await openEdit(); await fillEdit(); const submit = handler(form('Update Student'), 'onSubmit'); await rerenderB();
  await act(async () => submit({ preventDefault() {} })); expect(axios.put).not.toHaveBeenCalled();
});
test('same-render double Edit sends one PUT', async () => {
  const request = deferred(); axios.put.mockReturnValue(request.promise); await openEdit(); await fillEdit();
  const submit = handler(form('Update Student'), 'onSubmit'); act(() => { void submit({ preventDefault() {} }); void submit({ preventDefault() {} }); });
  expect(axios.put).toHaveBeenCalledTimes(1); await act(async () => request.resolve(editAck)); await flush();
});
test('server-shaped Create 201 succeeds once and clears submitted secret', async () => {
  await openCreate(); await fillCreate(); toast.success.mockClear();
  await act(async () => form('Create Student').dispatchEvent(new Event('submit', { bubbles: true, cancelable: true }))); await flush();
  expect(axios.post).toHaveBeenCalledWith('/api/admin/students',
    { username: 'new-learner', email: 'new@example.test', password: 'new-password-123', full_name: '', role: 'student' },
    { headers: { Authorization: 'Bearer admin-a' } });
  expect(toast.success).toHaveBeenCalledWith('Student created successfully');
  await click('Create New Student');
  expect(form('Create Student').querySelector('input[placeholder="Enter password"]').value).toBe('');
});
test('server-shaped Edit 200 acknowledges exact target and fields', async () => {
  await openEdit(); await fillEdit(); toast.success.mockClear();
  await act(async () => form('Update Student').dispatchEvent(new Event('submit', { bubbles: true, cancelable: true }))); await flush();
  expect(axios.put.mock.calls[0][0]).toBe('/api/admin/students/19');
  expect(axios.put.mock.calls[0][1]).toEqual(expect.objectContaining({ username: 'updated-learner', role: 'student' }));
  expect(toast.success).toHaveBeenCalledWith('Student updated successfully');
});
test('deactivating a student preserves the 0 flag and explains session revocation', async () => {
  axios.put.mockResolvedValueOnce({ status: 200, data: { success: true, changes: 1,
    user: { ...student, is_active: 0 } } });
  await openEdit(); const checkbox = form('Update Student').querySelector('#is_active');
  await change(checkbox, undefined, false);
  expect(form('Update Student').textContent).toContain('revokes active sessions');
  await act(async () => form('Update Student').dispatchEvent(new Event('submit', { bubbles: true, cancelable: true }))); await flush();
  expect(axios.put.mock.calls[0][1].is_active).toBe(false);
  expect(toast.success).toHaveBeenCalledWith('Student updated successfully');
});
test.each([
  ['missing created ID', { ...createAck, data: { ...createAck.data, user: { ...createAck.data.user, id: null } } }],
  ['admin role', { ...createAck, data: { ...createAck.data, user: { ...createAck.data.user, role: 'admin' } } }],
  ['wrong full name', { ...createAck, data: { ...createAck.data, user: { ...createAck.data.user, full_name: null } } }],
])('Create %s ACK stays unknown without retry or plaintext', async (_label, response) => {
  axios.post.mockResolvedValueOnce(response); await openCreate(); await fillCreate(); toast.success.mockClear();
  await act(async () => form('Create Student').dispatchEvent(new Event('submit', { bubbles: true, cancelable: true }))); await flush();
  expect(toast.success).not.toHaveBeenCalled(); expect(form('Create Student').textContent).toContain('could not be confirmed');
  expect(form('Create Student').querySelector('input[placeholder="Enter password"]').value).toBe('');
  expect(axios.post).toHaveBeenCalledTimes(1);
});
test('lost Create response cannot be inferred from username or replayed, and error is not logged', async () => {
  const lost = new Error('lost'); lost.config = { data: JSON.stringify({ password: 'new-password-123' }) };
  axios.post.mockRejectedValueOnce(lost); await openCreate(); await fillCreate(); toast.success.mockClear();
  await act(async () => form('Create Student').dispatchEvent(new Event('submit', { bubbles: true, cancelable: true }))); await flush();
  expect(form('Create Student').textContent).toContain('No account ID was acknowledged');
  expect(toast.success).not.toHaveBeenCalled(); expect(console.error).not.toHaveBeenCalled();
  expect(axios.post).toHaveBeenCalledTimes(1);
});
test.each([
  ['wrong target', { ...editAck, data: { ...editAck.data, user: { ...editAck.data.user, id: 20 } } }],
  ['wrong active flag', { ...editAck, data: { ...editAck.data, user: { ...editAck.data.user, is_active: 0 } } }],
  ['missing changes', { ...editAck, data: { ...editAck.data, changes: undefined } }],
])('Edit %s ACK stays unknown without retry', async (_label, response) => {
  axios.put.mockResolvedValueOnce(response); await openEdit(); await fillEdit(); toast.success.mockClear();
  await act(async () => form('Update Student').dispatchEvent(new Event('submit', { bubbles: true, cancelable: true }))); await flush();
  expect(toast.success).not.toHaveBeenCalled(); expect(form('Update Student').textContent).toContain('could not be confirmed');
  expect(axios.put).toHaveBeenCalledTimes(1);
});
test('late A Create ACK after B sign-in cannot toast or refresh B roster', async () => {
  const request = deferred(); axios.post.mockReturnValue(request.promise); await openCreate(); await fillCreate();
  const submit = handler(form('Create Student'), 'onSubmit'); act(() => { void submit({ preventDefault() {} }); });
  await rerenderB(); toast.success.mockClear(); axios.get.mockClear();
  await act(async () => request.resolve(createAck)); await flush();
  expect(toast.success).not.toHaveBeenCalled(); expect(axios.post).toHaveBeenCalledTimes(1);
  expect(axios.get.mock.calls.some(([url]) => url === '/api/admin/students')).toBe(false);
});
test('late A Edit ACK after B sign-in cannot toast or refresh B roster', async () => {
  const request = deferred(); axios.put.mockReturnValue(request.promise); await openEdit(); await fillEdit();
  const submit = handler(form('Update Student'), 'onSubmit'); act(() => { void submit({ preventDefault() {} }); });
  await rerenderB(); toast.success.mockClear(); axios.get.mockClear();
  await act(async () => request.resolve(editAck)); await flush();
  expect(toast.success).not.toHaveBeenCalled(); expect(axios.put).toHaveBeenCalledTimes(1);
  expect(axios.get.mock.calls.some(([url]) => url === '/api/admin/students')).toBe(false);
});
test('retained old Edit field and Cancel callbacks cannot alter a new edit of the same target', async () => {
  await openEdit(); const first = form('Update Student');
  const oldField = handler(first.querySelector('input[type="text"]'), 'onChange');
  const oldCancel = handler([...first.querySelectorAll('button')].find(item => item.textContent.trim() === 'Cancel'), 'onClick');
  await click('Cancel'); await click('Edit'); await fillEdit();
  await act(async () => { oldField({ target: { value: 'stale-name' } }); oldCancel(); });
  expect(form('Update Student').querySelector('input[type="text"]').value).toBe('updated-learner');
});
test.each(['Create Student', 'Update Student'])('%s stage is retired by same-token auth revision', async label => {
  if (label === 'Create Student') { await openCreate(); await fillCreate(); } else { await openEdit(); await fillEdit(); }
  const submit = handler(form(label), 'onSubmit'); mockAuthRevision += 1;
  await act(async () => root.render(<MemoryRouter initialEntries={['/admin/students']}><ComprehensiveAdminDashboard /></MemoryRouter>)); await flush();
  await act(async () => submit({ preventDefault() {} }));
  expect(axios.post).not.toHaveBeenCalled(); expect(axios.put).not.toHaveBeenCalled();
});
test.each(['Create Student', 'Update Student'])('%s stage is retired by token storage ABA event', async label => {
  if (label === 'Create Student') { await openCreate(); await fillCreate(); } else { await openEdit(); await fillEdit(); }
  const submit = handler(form(label), 'onSubmit');
  await act(async () => window.dispatchEvent(new StorageEvent('storage', {
    key: 'token', oldValue: 'other', newValue: 'admin-a', storageArea: localStorage,
  }))); await flush();
  await act(async () => submit({ preventDefault() {} }));
  expect(axios.post).not.toHaveBeenCalled(); expect(axios.put).not.toHaveBeenCalled();
});
test.each(['Create Student', 'Update Student'])('%s retained submit is denied after unmount', async label => {
  if (label === 'Create Student') { await openCreate(); await fillCreate(); } else { await openEdit(); await fillEdit(); }
  const submit = handler(form(label), 'onSubmit'); await act(async () => root.unmount()); root = null;
  await act(async () => submit({ preventDefault() {} }));
  expect(axios.post).not.toHaveBeenCalled(); expect(axios.put).not.toHaveBeenCalled();
});
test.each(['Create Student', 'Update Student'])('%s Cancel/X/backdrop retire retained submit', async label => {
  for (const method of ['Cancel', 'X', 'backdrop']) {
    if (root) { act(() => root.unmount()); root = null; document.body.replaceChildren(); }
    if (label === 'Create Student') { await openCreate(); await fillCreate(); } else { await openEdit(); await fillEdit(); }
    const current = form(label), submit = handler(current, 'onSubmit');
    const close = method === 'Cancel'
      ? handler([...current.querySelectorAll('button')].find(item => item.textContent.trim() === 'Cancel'), 'onClick')
      : method === 'X'
        ? handler(node.querySelector(`button[aria-label="Close student ${label === 'Create Student' ? 'creation' : 'edit'}"]`), 'onClick')
        : handler(current.parentElement.parentElement.parentElement, 'onClick');
    await act(async () => close()); await flush();
    await act(async () => submit({ preventDefault() {} }));
    expect(axios.post).not.toHaveBeenCalled(); expect(axios.put).not.toHaveBeenCalled();
  }
});
test.each(['Create Student', 'Update Student'])('%s navigation retires retained submit', async label => {
  if (label === 'Create Student') { await openCreate(); await fillCreate(); } else { await openEdit(); await fillEdit(); }
  const submit = handler(form(label), 'onSubmit');
  const nav = target => [...node.querySelectorAll('div')].find(item => item.textContent.trim() === target
    && typeof item[Object.keys(item).find(key => key.startsWith('__reactProps$'))]?.onClick === 'function');
  expect(nav('Settings')).toBeTruthy(); await act(async () => nav('Settings').click()); await flush();
  await act(async () => submit({ preventDefault() {} }));
  expect(axios.post).not.toHaveBeenCalled(); expect(axios.put).not.toHaveBeenCalled();
});
test('pending Create blocks retained Edit and password buttons until completion', async () => {
  const request = deferred(); axios.post.mockReturnValue(request.promise); await mount();
  const edit = handler(button('Edit'), 'onClick'); const password = handler(button('Password'), 'onClick');
  await click('Create New Student'); await fillCreate(); const submit = handler(form('Create Student'), 'onSubmit');
  act(() => { void submit({ preventDefault() {} }); edit(); password(); });
  expect(axios.post).toHaveBeenCalledTimes(1);
  expect(form('Create Student').querySelector('input[placeholder="Enter password"]').value).toBe('');
  expect(form('Update Student')).toBeFalsy();
  await act(async () => request.resolve(createAck)); await flush();
});
test('post-Create roster refresh cannot publish old rows after authority replacement', async () => {
  await openCreate(); await fillCreate(); const oldRead = deferred();
  const normal = axios.get.getMockImplementation();
  axios.get.mockImplementation((url, config) => url === '/api/admin/students'
    && config?.headers?.Authorization === 'Bearer admin-a' ? oldRead.promise : normal(url, config));
  await act(async () => form('Create Student').dispatchEvent(new Event('submit', { bubbles: true, cancelable: true })));
  await flush(); expect(toast.success).toHaveBeenCalledWith('Student created successfully');
  await rerenderB();
  await act(async () => oldRead.resolve({ data: { success: true, students: [{ ...student, username: 'stale-a-roster' }] } })); await flush();
  expect(node.textContent).not.toContain('stale-a-roster');
});
