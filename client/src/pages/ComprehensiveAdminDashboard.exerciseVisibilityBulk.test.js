import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import { MemoryRouter } from 'react-router-dom';
import axios from 'axios';
import { toast } from 'react-toastify';
import ComprehensiveAdminDashboard from './ComprehensiveAdminDashboard';

jest.mock('axios', () => ({ get: jest.fn(), post: jest.fn(), patch: jest.fn(), put: jest.fn(), delete: jest.fn() }));
let mockUser, mockAuthRevision;
jest.mock('../context/AuthContext', () => ({ useAuth: () => ({ user: mockUser, logout: jest.fn(), getAuthRevision: () => mockAuthRevision }) }));
const mockContentSnapshot = { exercises: { example: { showHints: true, showSolutions: true } } };
jest.mock('../context/WorkshopConfigContext', () => ({ useWorkshopConfig: () => ({
  registerReconciler: () => () => {}, refreshAfterMutation: jest.fn(() => Promise.resolve(mockContentSnapshot)), retireSnapshotReads: jest.fn(),
}) }));
jest.mock('react-toastify', () => ({ toast: { error: jest.fn(), success: jest.fn() } }));
jest.mock('./admin/CTFAdminPanel', () => () => null);
jest.mock('../components/admin/AIProviderManagement', () => () => null);
jest.mock('../components/admin/StudentWorkshopView', () => () => null);
jest.mock('../components/admin/ServerLogs', () => () => null);
jest.mock('./admin/ProgressAnalyticsPanel', () => () => null);
jest.mock('../components/admin/PromptInjectionHintEditorModal', () => () => null);
jest.mock('../components/observability/AgentRunInspector', () => () => null);

let root, node;
const challenge = { id: 'example', key: 'example', workshopKey: 'example', name: 'Example', enabled: false };
const enabledAck = { status: 200, data: { success: true, enabled: true, changed: true, affectedCount: 1,
  revision: '2', exercises: { example: { workshopKey: 'example', isVisible: true,
    showHints: false, showSolutions: false, objectives: {} } } } };
async function flush() { await act(async () => { await Promise.resolve(); await Promise.resolve(); await Promise.resolve(); }); }
async function mount() {
  node = document.createElement('div'); document.body.appendChild(node); root = createRoot(node);
  await act(async () => root.render(<MemoryRouter initialEntries={['/admin/exercises']}><ComprehensiveAdminDashboard /></MemoryRouter>));
  await flush();
}
function button(label) { const found = [...node.querySelectorAll('button')].find(item => item.textContent.trim() === label); expect(found).toBeTruthy(); return found; }
function reactHandler(element) { const props = element[Object.keys(element).find(key => key.startsWith('__reactProps$'))]; expect(typeof props?.onClick).toBe('function'); return props.onClick; }
function dialog() { return node.querySelector('[role="dialog"][aria-label="Confirm all exercise visibility change"]'); }
function contentDialog() { return node.querySelector('[role="dialog"][aria-label="Confirm all hint and solution visibility change"]'); }
async function click(label) { await act(async () => button(label).click()); await flush(); }
function deferred() { let resolve; const promise = new Promise(done => { resolve = done; }); return { promise, resolve }; }

beforeEach(() => {
  global.IS_REACT_ACT_ENVIRONMENT = true;
  mockUser = { id: 1, username: 'admin-a', isAdmin: true, adminLevel: 2, permissions: ['challenge_management'] };
  mockAuthRevision = 0; localStorage.setItem('token', 'admin-a');
  axios.get.mockImplementation(url => Promise.resolve({ data: url === '/api/admin/challenges'
    ? { success: true, challenges: [challenge] } : { success: true } }));
  axios.post.mockResolvedValue(enabledAck);
  axios.patch.mockResolvedValue({ status: 200, data: { success: true, changed: true, revision: '3',
    exercises: { example: { isVisible: false, showHints: true, showSolutions: true } } } });
  jest.spyOn(console, 'error').mockImplementation(() => {});
  jest.spyOn(console, 'warn').mockImplementation(() => {});
  jest.spyOn(console, 'log').mockImplementation(() => {});
});
afterEach(() => { if (root) { act(() => root.unmount()); root = null; } document.body.replaceChildren(); localStorage.clear(); jest.restoreAllMocks(); jest.clearAllMocks(); });

test('Enable All stages full-catalog consequence and Cancel sends no POST', async () => {
  await mount(); await click('Enable All');
  expect(axios.post).not.toHaveBeenCalled();
  expect(dialog()).not.toBeNull();
  expect(dialog().textContent).toMatch(/all catalog-active exercises/i);
  expect(dialog().textContent).toMatch(/filtered/i);
  expect(dialog().textContent).toMatch(/progress/i);
  await click('Cancel');
  expect(axios.post).not.toHaveBeenCalled();
});
test('global hint and solution controls stage and confirm the database-backed bulk endpoint', async () => {
  await mount(); await click('Enable All Hints & Solutions');
  expect(axios.patch).not.toHaveBeenCalled();
  expect(contentDialog()).not.toBeNull();
  await click('Confirm Enable All');
  expect(axios.patch).toHaveBeenCalledWith('/api/admin/exercises/content-visibility', { enabled: true }, expect.objectContaining({
    headers: { Authorization: 'Bearer admin-a' }, timeout: 10000,
  }));
  expect(toast.success).toHaveBeenCalledWith('All available hints and solutions enabled.');
});
test('a retained Enable All handler from A cannot dispatch under equally authorized B', async () => {
  await mount(); const retained = reactHandler(button('Enable All'));
  mockUser = { ...mockUser, id: 2, username: 'admin-b' }; mockAuthRevision += 1; localStorage.setItem('token', 'admin-b');
  await act(async () => root.render(<MemoryRouter initialEntries={['/admin/exercises']}><ComprehensiveAdminDashboard /></MemoryRouter>)); await flush();
  await act(async () => retained()); await flush();
  expect(axios.post).not.toHaveBeenCalled();
});
test('same-render double Enable All activation does not duplicate POST', async () => {
  const request = deferred(); axios.post.mockReturnValue(request.promise);
  await mount(); const stage = reactHandler(button('Enable All'));
  act(() => { void stage(); void stage(); });
  expect(axios.post).not.toHaveBeenCalled();
  expect(dialog()).not.toBeNull();
  const confirm = reactHandler(button('Confirm Enable All'));
  act(() => { void confirm(); void confirm(); });
  expect(axios.post).toHaveBeenCalledTimes(1);
  await act(async () => request.resolve(enabledAck)); await flush();
  expect(axios.post).toHaveBeenCalledTimes(1);
});
test('staged A confirmation retires before B can use it, including revision-only change', async () => {
  await mount(); await click('Disable All');
  const retained = reactHandler(button('Confirm Disable All'));
  mockUser = { ...mockUser, id: 2, username: 'admin-b' }; mockAuthRevision += 1; localStorage.setItem('token', 'admin-b');
  await act(async () => root.render(<MemoryRouter initialEntries={['/admin/exercises']}><ComprehensiveAdminDashboard /></MemoryRouter>)); await flush();
  expect(dialog()).toBeNull();
  await act(async () => retained());
  expect(axios.post).not.toHaveBeenCalled();
  await click('Enable All');
  const revisionRetained = reactHandler(button('Confirm Enable All'));
  mockAuthRevision += 1;
  await act(async () => root.render(<MemoryRouter initialEntries={['/admin/exercises']}><ComprehensiveAdminDashboard /></MemoryRouter>)); await flush();
  expect(dialog()).toBeNull();
  await act(async () => revisionRetained());
  expect(axios.post).not.toHaveBeenCalled();
});
test('storage ABA and cancel/restage retire old confirm and close handlers', async () => {
  await mount(); await click('Enable All');
  const oldConfirm = reactHandler(button('Confirm Enable All'));
  const oldCancel = reactHandler(button('Cancel'));
  await click('Cancel'); await click('Disable All');
  await act(async () => { oldCancel(); oldConfirm(); });
  expect(dialog().textContent).toContain('Disable all exercises');
  expect(axios.post).not.toHaveBeenCalled();
  const retained = reactHandler(button('Confirm Disable All'));
  await act(async () => window.dispatchEvent(new StorageEvent('storage', { key: 'token', storageArea: localStorage,
    oldValue: 'admin-a', newValue: 'admin-b' }))); await flush();
  await act(async () => new Promise(resolve => setTimeout(resolve, 400)));
  expect(dialog()).toBeNull();
  await act(async () => retained());
  expect(axios.post).not.toHaveBeenCalled();
});
test('Disable All sends captured boolean and acknowledges a valid no-op snapshot', async () => {
  const disabledAck = { status: 200, data: { success: true, enabled: false, changed: false,
    affectedCount: 0, revision: '2', exercises: { example: { workshopKey: 'example', isVisible: false,
      showHints: false, showSolutions: false, objectives: {} } } } };
  axios.post.mockResolvedValueOnce(disabledAck);
  await mount(); await click('Disable All'); toast.success.mockClear(); await click('Confirm Disable All');
  expect(axios.post).toHaveBeenCalledWith('/api/admin/challenges/bulk-toggle', { enabled: false },
    { headers: { Authorization: 'Bearer admin-a' } });
  expect(dialog()).toBeNull();
  expect(toast.success).toHaveBeenCalledTimes(1);
});
test('an acknowledged bulk snapshot updates the cards before the later roster refresh returns', async () => {
  await mount(); await click('Enable All'); await click('Confirm Enable All');
  const card = node.querySelector('[data-exercise-key="example"]');
  expect(card?.textContent).toContain('VISIBLE');
});
test('wrong-target or malformed acknowledgement remains uncertain and cannot replay', async () => {
  axios.post.mockResolvedValueOnce({ ...enabledAck, data: { ...enabledAck.data, enabled: false } });
  await mount(); await click('Enable All'); toast.success.mockClear();
  const retained = reactHandler(button('Confirm Enable All'));
  await click('Confirm Enable All');
  expect(toast.success).not.toHaveBeenCalled();
  expect(dialog().textContent).toMatch(/outcome could not be confirmed/i);
  await act(async () => retained());
  expect(axios.post).toHaveBeenCalledTimes(1);
  await click('Close');
  expect(dialog()).toBeNull();
});
test('late acknowledgement after authority retirement cannot toast or refresh under B', async () => {
  const request = deferred(); axios.post.mockReturnValue(request.promise);
  await mount(); await click('Enable All'); await click('Confirm Enable All');
  expect(axios.post).toHaveBeenCalledTimes(1);
  mockUser = { ...mockUser, id: 2, username: 'admin-b' }; mockAuthRevision += 1; localStorage.setItem('token', 'admin-b');
  await act(async () => root.render(<MemoryRouter initialEntries={['/admin/exercises']}><ComprehensiveAdminDashboard /></MemoryRouter>)); await flush();
  toast.success.mockClear(); axios.get.mockClear();
  await act(async () => request.resolve(enabledAck)); await flush();
  expect(dialog()).toBeNull();
  expect(toast.success).not.toHaveBeenCalled();
  expect(axios.get).not.toHaveBeenCalled();
});
test('an acknowledged A refresh cannot install a delayed A roster after B takes over', async () => {
  await mount();
  const delayed = deferred();
  let challengeReads = 0;
  axios.get.mockImplementation(url => {
    if (url === '/api/admin/challenges') return ++challengeReads === 1 ? delayed.promise
      : Promise.resolve({ data: { success: true, challenges: [{ ...challenge, name: 'B EXERCISE' }] } });
    return Promise.resolve({ data: { success: true } });
  });
  await click('Enable All'); await click('Confirm Enable All');
  expect(axios.get).toHaveBeenCalledWith('/api/admin/challenges', expect.anything());
  mockUser = { ...mockUser, id: 2, username: 'admin-b' }; mockAuthRevision += 1; localStorage.setItem('token', 'admin-b');
  await act(async () => root.render(<MemoryRouter initialEntries={['/admin/exercises']}><ComprehensiveAdminDashboard /></MemoryRouter>)); await flush();
  await act(async () => delayed.resolve({ data: { success: true,
    challenges: [{ ...challenge, name: 'STALE A EXERCISE' }] } })); await flush();
  expect(node.textContent).toContain('B EXERCISE');
  expect(node.textContent).not.toContain('STALE A EXERCISE');
});
test('an impossible changed-count snapshot is unknown, not an acknowledged success', async () => {
  axios.post.mockResolvedValueOnce({ ...enabledAck, data: { ...enabledAck.data, exercises: {} } });
  await mount(); await click('Enable All'); toast.success.mockClear(); await click('Confirm Enable All');
  expect(dialog().textContent).toMatch(/outcome could not be confirmed/i);
  expect(toast.success).not.toHaveBeenCalled();
  expect(axios.post).toHaveBeenCalledTimes(1);
});
test('permission loss and unmount retire retained confirmation without dispatch', async () => {
  await mount(); await click('Enable All');
  const retained = reactHandler(button('Confirm Enable All'));
  mockUser = { ...mockUser, permissions: [] };
  await act(async () => root.render(<MemoryRouter initialEntries={['/admin/exercises']}><ComprehensiveAdminDashboard /></MemoryRouter>)); await flush();
  await act(async () => retained());
  expect(axios.post).not.toHaveBeenCalled();
  await act(async () => root.unmount()); root = null;
  await act(async () => retained());
  expect(axios.post).not.toHaveBeenCalled();
});
test('leaving Exercises retires a staged confirmation before a retained Confirm fires', async () => {
  await mount(); await click('Enable All');
  const retained = reactHandler(button('Confirm Enable All'));
  const settings = [...node.querySelectorAll('span')].find(item => item.textContent.trim() === 'Settings');
  expect(settings).toBeTruthy();
  await act(async () => settings.parentElement.click()); await flush();
  await act(async () => retained());
  expect(axios.post).not.toHaveBeenCalled();
});
