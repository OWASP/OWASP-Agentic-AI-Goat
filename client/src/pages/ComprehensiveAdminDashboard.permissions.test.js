import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import { MemoryRouter } from 'react-router-dom';
import axios from 'axios';
import { toast } from 'react-toastify';
import ComprehensiveAdminDashboard from './ComprehensiveAdminDashboard';

jest.mock('axios', () => ({ get: jest.fn(), post: jest.fn(), put: jest.fn(), delete: jest.fn() }));
let mockUser;
let mockAuthRevision;
jest.mock('../context/AuthContext', () => ({ useAuth: () => ({ user: mockUser, logout: jest.fn(),
  getAuthRevision: () => mockAuthRevision }) }));
jest.mock('../context/WorkshopConfigContext', () => ({ useWorkshopConfig: () => ({ registerReconciler: () => () => {} }) }));
jest.mock('react-toastify', () => ({ toast: { error: jest.fn(), success: jest.fn() } }));
jest.mock('./admin/CTFAdminPanel', () => () => null);
jest.mock('../components/admin/AIProviderManagement', () => () => null);
jest.mock('../components/admin/StudentWorkshopView', () => () => null);
jest.mock('../components/admin/ServerLogs', () => () => null);
jest.mock('./admin/ProgressAnalyticsPanel', () => () => <div>PROGRESS_ANALYTICS_MOUNTED</div>);
jest.mock('../components/admin/PromptInjectionHintEditorModal', () => () => null);
jest.mock('../components/observability/AgentRunInspector', () => () => <div>AGENT_INSPECTOR_MOUNTED</div>);

const flush = async () => act(async () => { await Promise.resolve(); await Promise.resolve(); await Promise.resolve(); });
function genericGet(url) {
  if (url === '/api/admin/challenges') return Promise.resolve({ data: { success: true, challenges: [] } });
  if (url === '/api/admin/students') return Promise.resolve({ data: { success: true, students: [] } });
  return Promise.resolve({ data: {} });
}
function deferred() {
  let resolve;
  const promise = new Promise(value => { resolve = value; });
  return { promise, resolve };
}
async function mount(path) {
  const node = document.createElement('div'); document.body.appendChild(node);
  const root = createRoot(node);
  await act(async () => { root.render(<MemoryRouter initialEntries={[path]}><ComprehensiveAdminDashboard /></MemoryRouter>); });
  await flush();
  return { node, root };
}

beforeEach(() => {
  global.IS_REACT_ACT_ENVIRONMENT = true;
  mockUser = { id: 1, username: 'admin', isAdmin: true, adminLevel: 2, permissions: [] };
  mockAuthRevision = 0;
  localStorage.setItem('token', 'fixture');
  axios.get.mockImplementation(genericGet);
  axios.post.mockResolvedValue({ data: { success: true } });
  axios.delete.mockResolvedValue({ data: { success: true, jobId: '6b58bc44-f15b-4b12-972b-cfcad0c37c1a' } });
  jest.spyOn(console, 'error').mockImplementation(() => {});
  jest.spyOn(console, 'warn').mockImplementation(() => {});
  jest.spyOn(console, 'log').mockImplementation(() => {});
});
afterEach(() => { jest.restoreAllMocks(); jest.clearAllMocks(); document.body.replaceChildren(); localStorage.clear(); });

test('Agent Runs navigation and direct content fail closed without current analytics permission', async () => {
  const denied = await mount('/admin/agent-runs');
  expect(denied.node.textContent).toContain('Permission denied: Agent Runs requires analytics access.');
  expect(denied.node.textContent).not.toContain('AGENT_INSPECTOR_MOUNTED');
  act(() => denied.root.unmount());
  mockUser = { ...mockUser, permissions: ['view_analytics'] };
  const allowed = await mount('/admin/agent-runs');
  expect(allowed.node.textContent).toContain('AGENT_INSPECTOR_MOUNTED');
  expect(allowed.node.textContent).not.toContain('Permission denied: Agent Runs requires analytics access.');
  act(() => allowed.root.unmount());
});

test('student data surfaces stay hidden and do not request progress data without manage_progress', async () => {
  mockUser = { ...mockUser, permissions: ['user_management'] };
  const dashboard = await mount('/admin/dashboard');
  expect(dashboard.node.textContent).not.toContain('Student View');
  expect(dashboard.node.textContent).toContain('Total Exercises');
  expect(axios.get.mock.calls.some(([url]) => url === '/api/admin/students')).toBe(false);
  act(() => dashboard.root.unmount());

  const students = await mount('/admin/students');
  expect(students.node.textContent).toContain('Permission denied: Students requires progress management access.');
  expect(axios.get.mock.calls.some(([url]) => url === '/api/admin/students')).toBe(false);
  act(() => students.root.unmount());

  const workshopView = await mount('/admin/student-workshop-view?studentId=19');
  expect(workshopView.node.textContent).toContain('Permission denied: Student View requires progress management access.');
  expect(axios.get.mock.calls.some(([url]) => url.includes('/api/admin/student-workshop-view/'))).toBe(false);
  act(() => workshopView.root.unmount());
});

test('progress analytics fails closed without manage_progress and mounts with the grant', async () => {
  const denied = await mount('/admin/progress-analytics');
  expect(denied.node.textContent).toContain('Permission denied: Student Progress requires progress management access.');
  expect(denied.node.textContent).not.toContain('PROGRESS_ANALYTICS_MOUNTED');
  expect([...denied.node.querySelectorAll('span')].some(node => node.textContent === 'Student Progress')).toBe(false);
  expect(axios.get.mock.calls.some(([url]) => url === '/api/admin/analytics/progress')).toBe(false);
  act(() => denied.root.unmount());

  mockUser = { ...mockUser, permissions: ['manage_progress'] };
  const allowed = await mount('/admin/progress-analytics');
  expect(allowed.node.textContent).toContain('PROGRESS_ANALYTICS_MOUNTED');
  expect([...allowed.node.querySelectorAll('span')].some(node => node.textContent === 'Student Progress')).toBe(true);
  act(() => allowed.root.unmount());
});

test('Active Users card does not navigate to Activity without user-management permission', async () => {
  const view = await mount('/admin/dashboard');
  const activeUsersLabel = [...view.node.querySelectorAll('p')]
    .find(node => node.textContent === 'Active Users');
  expect(activeUsersLabel).toBeDefined();
  axios.get.mockClear();
  await act(async () => { activeUsersLabel.parentElement.parentElement.click(); });
  await flush();
  expect(axios.get.mock.calls.some(([url]) => url === '/api/admin/activity-stats')).toBe(false);
  expect(axios.get.mock.calls.some(([url]) => url.startsWith('/api/admin/activity-logs'))).toBe(false);
  act(() => view.root.unmount());
});

test('permission loss fences an in-flight student response while retaining allowed challenge stats', async () => {
  mockUser = { ...mockUser, permissions: ['manage_progress'] };
  const pending = deferred();
  axios.get.mockImplementation(url => {
    if (url === '/api/admin/students') return pending.promise;
    if (url === '/api/admin/challenges') return Promise.resolve({ data: { success: true, challenges: [] } });
    return Promise.resolve({ data: {} });
  });
  const view = await mount('/admin/dashboard');
  mockUser = { ...mockUser, permissions: [] };
  await act(async () => {
    view.root.render(<MemoryRouter initialEntries={['/admin/dashboard']}><ComprehensiveAdminDashboard /></MemoryRouter>);
  });
  pending.resolve({ data: { success: true, students: [{ id: 91, username: 'stale-student' }] } });
  await flush();
  expect(view.node.textContent).not.toContain('stale-student');
  expect(view.node.textContent).toContain('Total Exercises');
  expect(view.node.textContent).not.toContain('Total Students0');
  act(() => view.root.unmount());
});

test('permission loss refresh cleanup prevents the old timer from requesting students', async () => {
  jest.useFakeTimers();
  try {
    mockUser = { ...mockUser, permissions: ['manage_progress'] };
    const view = await mount('/admin/dashboard');
    mockUser = { ...mockUser, permissions: [] };
    await act(async () => {
      view.root.render(<MemoryRouter initialEntries={['/admin/dashboard']}><ComprehensiveAdminDashboard /></MemoryRouter>);
    });
    axios.get.mockClear();
    await act(async () => { jest.advanceTimersByTime(30000); });
    await flush();
    expect(axios.get.mock.calls.some(([url]) => url === '/api/admin/students')).toBe(false);
    act(() => view.root.unmount());
  } finally {
    jest.useRealTimers();
  }
});

test('objective panel renders persisted label and visibility toggle does not change solution or hint gates', async () => {
  mockUser = { ...mockUser, permissions: ['challenge_management', 'manage_progress'] };
  axios.get.mockImplementation((url) => {
    if (url === '/api/admin/challenges') return Promise.resolve({ data: { success: true, challenges: [{
      id: 'direct_prompt_injection', workshopKey: 'direct_prompt_injection', key: 'dpi_alias',
      name: 'DPI', category: 'AI', difficulty: 'Medium', enabled: true, showSolutions: true, showHints: true,
    }] } });
    if (url === '/api/admin/students') return Promise.resolve({ data: { success: true, students: [] } });
    if (url === '/api/admin/workshops/direct_prompt_injection/objectives') return Promise.resolve({ data: { objectives: [{
      workshopKey: 'direct_prompt_injection', objective_id: 'jailbreak', label: 'Instructor-edited label',
      is_enabled: true, hint_enabled: false, solutions_enabled: true,
    }] } });
    if (url === '/api/admin/workshops/direct_prompt_injection/hints') return Promise.resolve({ data: { hints: { jailbreak: false } } });
    if (url === '/api/admin/pi-workshop/solutions') return Promise.resolve({ data: { challenges: [{ challengeId: 'jailbreak', solutionsEnabled: true }] } });
    return Promise.resolve({ data: {} });
  });
  const view = await mount('/admin/exercises');
  const manage = [...view.node.querySelectorAll('button')].find(button => button.textContent.includes('Manage Objectives'));
  expect(manage).toBeDefined();
  await act(async () => { manage.click(); }); await flush();
  expect(view.node.textContent).toContain('Instructor-edited label');
  const label = [...view.node.querySelectorAll('div')].find(element => element.textContent === 'Instructor-edited label');
  const row = label.parentElement.parentElement;
  await act(async () => { row.children[1].firstElementChild.click(); }); await flush();
  const mutations = axios.post.mock.calls.filter(([url]) => url.includes('/objectives/') || url.includes('/solutions/') || url.includes('/hints/'));
  expect(mutations).toEqual([[
    '/api/admin/workshops/direct_prompt_injection/objectives/jailbreak/toggle',
    { enabled: false },
    { headers: { Authorization: 'Bearer fixture' } },
  ]]);
  act(() => view.root.unmount());
});

test('database card provides additive migration guidance without password prompt or initializer POST', async () => {
  const prompt = jest.spyOn(window, 'prompt').mockImplementation(() => { throw Error('Obsolete prompt called'); });
  const view = await mount('/admin/settings');
  try {
    expect(view.node.textContent).toContain('PostgreSQL Schema Migrations');
    expect(view.node.textContent).toContain('npm run db:initialize-all');
    expect(view.node.textContent).toContain('preserves existing data');
    expect(view.node.textContent).not.toContain('Abh1nav@');
    expect(view.node.textContent).not.toContain('All 10 databases');
    const button = [...view.node.querySelectorAll('button')].find(node => node.textContent.includes('Use migration command'));
    expect(button.disabled).toBe(true);
    await act(async () => button.click()); await flush();
    expect(prompt).not.toHaveBeenCalled();
    expect(axios.post.mock.calls.some(([url]) => url.includes('/database/initialize') || url.includes('/database/initilize'))).toBe(false);
  } finally { act(() => view.root.unmount()); }
});

const managedStudent = {
  id: 19, username: 'managed-student', email: 'managed@example.invalid', role: 'student',
  admin_level: 0, completed_challenges: 0, total_challenges: 1,
};

function studentGet(url) {
  if (url === '/api/admin/students') {
    return Promise.resolve({ data: { success: true, students: [managedStudent] } });
  }
  if (url === '/api/admin/challenges') return Promise.resolve({ data: { success: true, challenges: [] } });
  return Promise.resolve({ data: {} });
}

function rowDeleteButton(node) {
  const row = [...node.querySelectorAll('tbody tr')]
    .find(candidate => candidate.querySelector('td')?.textContent.trim() === managedStudent.username);
  return [...(row?.querySelectorAll('button') || [])]
    .find(button => button.textContent.trim() === 'Delete');
}

test('level-one administrators cannot open student deletion even with user-management permission', async () => {
  mockUser = { ...mockUser, adminLevel: 1, permissions: ['user_management', 'manage_progress'] };
  axios.get.mockImplementation(studentGet);
  const view = await mount('/admin/students');
  const remove = rowDeleteButton(view.node);
  expect(remove).toBeDefined();
  expect(remove.disabled).toBe(true);
  expect(remove.title).toBe('Student deletion requires administrator level 2.');
  await act(async () => { remove.click(); });
  expect(view.node.textContent).not.toContain('Type DELETE to confirm deletion');
  expect(axios.delete).not.toHaveBeenCalled();
  act(() => view.root.unmount());
});

test('level-two administrators cannot open student deletion without user-management permission', async () => {
  mockUser = { ...mockUser, adminLevel: 2, permissions: ['manage_progress'] };
  axios.get.mockImplementation(studentGet);
  const view = await mount('/admin/students');
  const remove = rowDeleteButton(view.node);
  expect(remove).toBeDefined();
  expect(remove.disabled).toBe(true);
  expect(remove.title).toBe('Student deletion requires user management permission.');
  await act(async () => { remove.click(); });
  expect(view.node.textContent).not.toContain('Type DELETE to confirm deletion');
  expect(axios.delete).not.toHaveBeenCalled();
  act(() => view.root.unmount());
});

test('administrator creation is visible only to level two with user-management permission and submits selected grants', async () => {
  mockUser = { ...mockUser, adminLevel: 1, permissions: ['user_management'] };
  let view = await mount('/admin/settings');
  await act(async () => { [...view.node.querySelectorAll('button')].find(button => button.textContent.includes('Manage Users')).click(); });
  await flush();
  expect(view.node.textContent).toContain('Administrators');
  expect(view.node.textContent).not.toContain('Add administrator');
  act(() => view.root.unmount());

  mockUser = { ...mockUser, adminLevel: 2, permissions: ['user_management'] };
  axios.post.mockResolvedValue({ status: 201, data: { success: true, user: { id: 31,
    username: 'new-instructor', email: 'new@example.test', full_name: null, admin_level: 2,
    role: 'admin', is_active: 1 },
    permissions: ['challenge_management', 'view_analytics', 'manage_progress'] } });
  view = await mount('/admin/settings');
  await act(async () => { [...view.node.querySelectorAll('button')].find(button => button.textContent.includes('Manage Users')).click(); });
  await flush();
  await act(async () => { [...view.node.querySelectorAll('button')].find(button => button.textContent.trim() === 'Add administrator').click(); });
  const setValue = async (selector, value) => {
    await act(async () => {
      const input = view.node.querySelector(selector);
      Object.getOwnPropertyDescriptor(Object.getPrototypeOf(input), 'value').set.call(input, value);
      input.dispatchEvent(new Event('input', { bubbles: true }));
      input.dispatchEvent(new Event('change', { bubbles: true }));
    });
  };
  await setValue('#new-admin-username', 'new-instructor');
  await setValue('#new-admin-email', 'new@example.test');
  await setValue('#new-admin-password', 'test-password');
  await setValue('#new-admin-confirm-password', 'test-password');
  await act(async () => { view.node.querySelector('#new-admin-level').value = '2'; view.node.querySelector('#new-admin-level').dispatchEvent(new Event('change', { bubbles: true })); });
  await act(async () => { view.node.querySelector('#new-admin-username').closest('form').dispatchEvent(new Event('submit', { bubbles: true, cancelable: true })); });
  await flush();
  expect(axios.post).toHaveBeenCalledWith('/api/admin/administrators', expect.objectContaining({
    username: 'new-instructor', email: 'new@example.test', password: 'test-password',
    adminLevel: 2, permissions: ['challenge_management', 'view_analytics', 'manage_progress']
  }), expect.any(Object));
  act(() => view.root.unmount());
});

test('administrator edit and deactivation use the protected account endpoints', async () => {
  mockUser = { ...mockUser, permissions: ['user_management'] };
  const account = { id: 17, username: 'instructor', email: 'instructor@example.test', full_name: 'Instructor One',
    role: 'admin', admin_level: 1, permissions: ['challenge_management'], is_active: 1 };
  axios.get.mockImplementation(url => url.startsWith('/api/admin/users?')
    ? Promise.resolve({ data: { users: [account] } }) : genericGet(url));
  axios.put.mockResolvedValue({ data: { success: true, user: { id: 17, username: 'instructor',
    email: 'instructor@example.test', full_name: 'Instructor Two', admin_level: 1, is_active: 1 },
    permissions: ['challenge_management'] } });
  axios.delete.mockResolvedValue({ data: { success: true, user: { id: 17, is_active: 0 } } });
  const view = await mount('/admin/settings');
  await act(async () => { [...view.node.querySelectorAll('button')].find(button => button.textContent.includes('Manage Users')).click(); });
  await flush();
  expect(axios.get).toHaveBeenCalledWith('/api/admin/users?role=administrators&includeInactive=true&limit=200', expect.any(Object));
  await act(async () => { [...view.node.querySelectorAll('button')].find(button => button.textContent.trim() === 'Edit').click(); });
  expect(view.node.querySelector('#edit-admin-name').value).toBe('Instructor One');
  const dialog = view.node.querySelector('[aria-labelledby="user-management-title"][role="dialog"]');
  expect(dialog.getAttribute('aria-modal')).toBe('true');
  expect(dialog.querySelector('button[aria-label="Close user management"]')).not.toBeNull();
  const editForm = view.node.querySelector('#edit-admin-name').closest('form');
  expect(editForm.compareDocumentPosition(dialog.querySelector('table')) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
  await act(async () => {
    const input = view.node.querySelector('#edit-admin-name');
    Object.getOwnPropertyDescriptor(Object.getPrototypeOf(input), 'value').set.call(input, 'Instructor Two');
    input.dispatchEvent(new Event('input', { bubbles: true }));
    input.dispatchEvent(new Event('change', { bubbles: true }));
  });
  await act(async () => { view.node.querySelector('#edit-admin-name').closest('form').dispatchEvent(new Event('submit', { bubbles: true, cancelable: true })); });
  await flush();
  expect(axios.put).toHaveBeenCalledWith('/api/admin/administrators/17', {
    username: 'instructor', email: 'instructor@example.test', fullName: 'Instructor Two',
    adminLevel: 1, permissions: ['challenge_management'], isActive: true
  }, expect.any(Object));
  await act(async () => { [...view.node.querySelectorAll('button')].find(button => button.textContent.trim() === 'Deactivate').click(); });
  expect(view.node.textContent).toContain('audit and learner evidence are retained');
  expect(axios.delete).not.toHaveBeenCalled();
  await act(async () => { [...view.node.querySelectorAll('button')].find(button => button.textContent.trim() === 'Confirm deactivation').click(); });
  await flush();
  expect(axios.delete).toHaveBeenCalledWith('/api/admin/administrators/17', expect.any(Object));
  act(() => view.root.unmount());
});

test('inactive administrators remain editable for reactivation', async () => {
  mockUser = { ...mockUser, permissions: ['user_management'] };
  const account = { id: 18, username: 'former-admin', email: 'former@example.test', full_name: 'Former Admin',
    role: 'admin', admin_level: 1, permissions: ['view_analytics'], is_active: 0 };
  axios.get.mockImplementation(url => url.startsWith('/api/admin/users?')
    ? Promise.resolve({ data: { users: [account] } }) : genericGet(url));
  axios.put.mockResolvedValue({ data: { success: true, user: { id: 18, username: 'former-admin',
    email: 'former@example.test', full_name: 'Former Admin', admin_level: 1, is_active: 1 },
    permissions: ['view_analytics'] } });
  const view = await mount('/admin/settings');
  await act(async () => { [...view.node.querySelectorAll('button')].find(button => button.textContent.includes('Manage Users')).click(); });
  await flush();
  expect(view.node.textContent).toContain('Inactive');
  expect([...view.node.querySelectorAll('button')].some(button => button.textContent.trim() === 'Deactivate')).toBe(false);
  await act(async () => { [...view.node.querySelectorAll('button')].find(button => button.textContent.trim() === 'Edit').click(); });
  expect(view.node.querySelector('#edit-admin-active').checked).toBe(false);
  await act(async () => { view.node.querySelector('#edit-admin-active').click(); });
  await act(async () => { view.node.querySelector('#edit-admin-active').closest('form').dispatchEvent(new Event('submit', { bubbles: true, cancelable: true })); });
  await flush();
  expect(axios.put).toHaveBeenCalledWith('/api/admin/administrators/18', expect.objectContaining({ isActive: true }), expect.any(Object));
  act(() => view.root.unmount());
});

test('last capable administrator rejection is explained and the account remains visible', async () => {
  mockUser = { ...mockUser, permissions: ['user_management'] };
  axios.get.mockImplementation(url => url.startsWith('/api/admin/users?')
    ? Promise.resolve({ data: { users: [{ id: 17, username: 'only-admin', email: 'only@example.test',
      admin_level: 2, permissions: ['user_management'], is_active: 1 }] } }) : genericGet(url));
  axios.delete.mockRejectedValue({ response: { data: { code: 'LAST_ADMIN', error: 'At least one active administrator with user management authority is required' } } });
  const view = await mount('/admin/settings');
  await act(async () => { [...view.node.querySelectorAll('button')].find(button => button.textContent.includes('Manage Users')).click(); });
  await flush();
  await act(async () => { [...view.node.querySelectorAll('button')].find(button => button.textContent.trim() === 'Deactivate').click(); });
  await act(async () => { [...view.node.querySelectorAll('button')].find(button => button.textContent.trim() === 'Confirm deactivation').click(); });
  await flush();
  expect(toast.error).toHaveBeenCalledWith('At least one active level 2 administrator with user management permission must remain.');
  expect(view.node.textContent).toContain('only-admin');
  expect(view.node.textContent).toContain('Deactivate only-admin?');
  act(() => view.root.unmount());
});

test('user management separates administrator and student lists and lays out administrator fields', async () => {
  mockUser = { ...mockUser, permissions: ['user_management', 'manage_progress'] };
  axios.get.mockImplementation(url => {
    if (url.startsWith('/api/admin/users?')) return Promise.resolve({ data: { users: [] } });
    if (url === '/api/admin/students') return Promise.resolve({ data: { students: [{ id: 20, username: 'learner',
      email: 'learner@example.test', role: 'student', is_active: 1 }] } });
    return genericGet(url);
  });
  const view = await mount('/admin/settings');
  await act(async () => { [...view.node.querySelectorAll('button')].find(button => button.textContent.includes('Manage Users')).click(); });
  await flush();
  expect(view.node.textContent).toContain('No administrators found.');
  expect(view.node.textContent).not.toContain('learner@example.test');
  await act(async () => { [...view.node.querySelectorAll('[role="tab"]')].find(tab => tab.textContent === 'Students').click(); });
  await flush();
  expect(view.node.textContent).toContain('learner@example.test');
  expect(view.node.textContent).not.toContain('No administrators found.');
  expect(view.node.textContent).toContain('Manage students');
  expect(view.node.querySelector('[role="tabpanel"]').getAttribute('aria-labelledby')).toBe('user-management-students-tab');
  await act(async () => { view.node.querySelector('#user-management-students-tab').dispatchEvent(new KeyboardEvent('keydown', { key: 'ArrowLeft', bubbles: true })); });
  await flush();
  expect(view.node.querySelector('#user-management-administrators-tab').getAttribute('aria-selected')).toBe('true');
  await act(async () => { [...view.node.querySelectorAll('button')].find(button => button.textContent.trim() === 'Add administrator').click(); });
  const username = view.node.querySelector('#new-admin-username');
  expect(username.previousElementSibling.textContent).toBe('Username');
  expect(getComputedStyle(username.parentElement.parentElement).display).toBe('grid');
  expect(getComputedStyle(username).width).toBe('100%');
  act(() => view.root.unmount());
});

test('administrator loading errors remain visible with a retry action', async () => {
  mockUser = { ...mockUser, permissions: ['user_management'] };
  axios.get.mockImplementation(url => url.startsWith('/api/admin/users?')
    ? Promise.reject({ response: { data: { error: 'Administrator directory unavailable' } } })
    : genericGet(url));
  const view = await mount('/admin/settings');
  await act(async () => { [...view.node.querySelectorAll('button')].find(button => button.textContent.includes('Manage Users')).click(); });
  await flush();
  expect(view.node.querySelector('[role="alert"]').textContent).toContain('Administrator directory unavailable');
  expect(view.node.textContent).not.toContain('No administrators found.');
  expect([...view.node.querySelectorAll('button')].some(button => button.textContent.trim() === 'Retry')).toBe(true);
  act(() => view.root.unmount());
});

test('level-one user managers cannot edit or deactivate administrators', async () => {
  mockUser = { ...mockUser, adminLevel: 1, permissions: ['user_management'] };
  axios.get.mockImplementation(url => url.startsWith('/api/admin/users?')
    ? Promise.resolve({ data: { users: [{ id: 17, username: 'instructor', email: 'i@example.test', admin_level: 1, is_active: 1 }] } })
    : genericGet(url));
  const view = await mount('/admin/settings');
  await act(async () => { [...view.node.querySelectorAll('button')].find(button => button.textContent.includes('Manage Users')).click(); });
  await flush();
  expect(view.node.textContent).toContain('instructor');
  expect([...view.node.querySelectorAll('button')].some(button => button.textContent.trim() === 'Edit')).toBe(false);
  expect([...view.node.querySelectorAll('button')].some(button => button.textContent.trim() === 'Deactivate')).toBe(false);
  act(() => view.root.unmount());
});

test('level-two permission enables deletion but live revocation disables an already-open confirmation', async () => {
  mockUser = { ...mockUser, adminLevel: 2, permissions: ['user_management', 'manage_progress'] };
  axios.get.mockImplementation(studentGet);
  const view = await mount('/admin/students');
  const remove = rowDeleteButton(view.node);
  expect(remove.disabled).toBe(false);
  expect(remove.title).toBe('Delete student');
  await act(async () => { remove.click(); });
  expect(view.node.textContent).toContain('Type DELETE to confirm deletion');

  mockUser = { ...mockUser, permissions: [] };
  await act(async () => {
    view.root.render(<MemoryRouter initialEntries={['/admin/students']}><ComprehensiveAdminDashboard /></MemoryRouter>);
  });
  await flush();
  let confirm = [...view.node.querySelectorAll('button')]
    .find(button => button.textContent.trim() === 'Delete Student');
  expect(confirm).toBeDefined();
  expect(confirm.disabled).toBe(true);
  expect(confirm.title).toBe('Student deletion requires user management permission.');
  expect(axios.delete).not.toHaveBeenCalled();

  mockUser = { ...mockUser, permissions: ['user_management'] };
  await act(async () => {
    view.root.render(<MemoryRouter initialEntries={['/admin/students']}><ComprehensiveAdminDashboard /></MemoryRouter>);
  });
  await flush();
  const input = view.node.querySelector('#delete-confirmation');
  input.value = 'DELETE';
  confirm = [...view.node.querySelectorAll('button')]
    .find(button => button.textContent.trim() === 'Delete Student');
  expect(confirm.disabled).toBe(false);
  await act(async () => { confirm.click(); });
  await flush();
  expect(axios.delete).toHaveBeenCalledWith('/api/admin/students/19', {
    headers: { Authorization: 'Bearer fixture' },
  });
  act(() => view.root.unmount());
});

test('student deletion staged under one authorized session cannot be confirmed after another authorized session replaces it', async () => {
  mockUser = { ...mockUser, id: 1, adminLevel: 2, permissions: ['user_management', 'manage_progress'] };
  axios.get.mockImplementation(studentGet);
  const view = await mount('/admin/students');
  await act(async () => { rowDeleteButton(view.node).click(); });
  expect(view.node.textContent).toContain('Type DELETE to confirm deletion');

  localStorage.setItem('token', 'replacement-session');
  mockUser = { ...mockUser, id: 2, username: 'other-admin' };
  await act(async () => {
    view.root.render(<MemoryRouter initialEntries={['/admin/students']}><ComprehensiveAdminDashboard /></MemoryRouter>);
  });
  await flush();
  const input = view.node.querySelector('#delete-confirmation');
  if (input) input.value = 'DELETE';
  const confirm = [...view.node.querySelectorAll('button')]
    .find(button => button.textContent.trim() === 'Delete Student');
  if (confirm) await act(async () => { confirm.click(); });
  await flush();
  expect(axios.delete).not.toHaveBeenCalled();
  act(() => view.root.unmount());
});

test('student deletion rejects a same-token A→B→A auth revision and permits only a fresh stage', async () => {
  mockUser = { ...mockUser, adminLevel: 2, permissions: ['user_management', 'manage_progress'] };
  axios.get.mockImplementation(studentGet);
  const view = await mount('/admin/students');
  await act(async () => { rowDeleteButton(view.node).click(); });
  mockAuthRevision += 2; // AuthProvider advances on logout and login, even if the token value returns.
  const input = view.node.querySelector('#delete-confirmation');
  input.value = 'DELETE';
  await act(async () => {
    [...view.node.querySelectorAll('button')].find(button => button.textContent.trim() === 'Delete Student').click();
  });
  expect(axios.delete).not.toHaveBeenCalled();

  await act(async () => { rowDeleteButton(view.node).click(); });
  view.node.querySelector('#delete-confirmation').value = 'DELETE';
  await act(async () => {
    [...view.node.querySelectorAll('button')].find(button => button.textContent.trim() === 'Delete Student').click();
  });
  await flush();
  expect(axios.delete).toHaveBeenCalledTimes(1);
  expect(axios.delete).toHaveBeenCalledWith('/api/admin/students/19', {
    headers: { Authorization: 'Bearer fixture' },
  });
  act(() => view.root.unmount());
});

test('cancel consumes student deletion intent before a retained confirm and a new review is required', async () => {
  mockUser = { ...mockUser, adminLevel: 2, permissions: ['user_management', 'manage_progress'] };
  axios.get.mockImplementation(studentGet);
  const view = await mount('/admin/students');
  await act(async () => { rowDeleteButton(view.node).click(); });
  view.node.querySelector('#delete-confirmation').value = 'DELETE';
  const confirm = [...view.node.querySelectorAll('button')]
    .find(button => button.textContent.trim() === 'Delete Student');
  const reactPropsKey = Object.keys(confirm).find(key => key.startsWith('__reactProps$'));
  const staleOnClick = confirm[reactPropsKey].onClick;
  const cancel = [...view.node.querySelectorAll('button')]
    .find(button => button.textContent.trim() === 'Cancel');
  act(() => { cancel.click(); confirm.click(); });
  expect(axios.delete).not.toHaveBeenCalled();
  await act(async () => { rowDeleteButton(view.node).click(); });
  view.node.querySelector('#delete-confirmation').value = 'DELETE';
  act(() => { staleOnClick({ currentTarget: confirm }); });
  expect(axios.delete).not.toHaveBeenCalled();
  await act(async () => {
    [...view.node.querySelectorAll('button')].find(button => button.textContent.trim() === 'Delete Student').click();
  });
  await flush();
  expect(axios.delete).toHaveBeenCalledTimes(1);
  act(() => view.root.unmount());
});

test('double confirmation sends one deletion and an uncertain failure closes consumed intent', async () => {
  mockUser = { ...mockUser, adminLevel: 2, permissions: ['user_management', 'manage_progress'] };
  axios.get.mockImplementation(studentGet);
  const pending = deferred();
  axios.delete.mockImplementation(() => pending.promise);
  const view = await mount('/admin/students');
  await act(async () => { rowDeleteButton(view.node).click(); });
  view.node.querySelector('#delete-confirmation').value = 'DELETE';
  const confirm = [...view.node.querySelectorAll('button')]
    .find(button => button.textContent.trim() === 'Delete Student');
  act(() => { confirm.click(); confirm.click(); });
  expect(axios.delete).toHaveBeenCalledTimes(1);
  await act(async () => { pending.resolve(Promise.reject(new Error('connection lost'))); });
  await flush();
  expect(toast.error).toHaveBeenCalledWith(expect.stringContaining('could not be confirmed'));
  expect(axios.delete).toHaveBeenCalledTimes(1);
  act(() => view.root.unmount());
});

test('cross-tab token cycle retires staged student deletion before React rerenders', async () => {
  mockUser = { ...mockUser, adminLevel: 2, permissions: ['user_management', 'manage_progress'] };
  axios.get.mockImplementation(studentGet);
  const view = await mount('/admin/students');
  await act(async () => { rowDeleteButton(view.node).click(); });
  view.node.querySelector('#delete-confirmation').value = 'DELETE';
  const confirm = [...view.node.querySelectorAll('button')]
    .find(button => button.textContent.trim() === 'Delete Student');
  await act(async () => {
    window.dispatchEvent(new StorageEvent('storage', { key: 'token', storageArea: localStorage,
      oldValue: 'fixture', newValue: 'replacement-session' }));
    confirm.click();
  });
  expect(axios.delete).not.toHaveBeenCalled();
  act(() => view.root.unmount());
});

test('student deletion refresh never applies an old result after an A→B→A auth cycle during the GET', async () => {
  mockUser = { ...mockUser, adminLevel: 2, permissions: ['user_management', 'manage_progress'] };
  const pendingRefresh = deferred();
  let holdRefresh = false;
  let held = false;
  axios.get.mockImplementation(url => {
    if (url === '/api/admin/students' && holdRefresh && !held) {
      held = true;
      return pendingRefresh.promise;
    }
    return studentGet(url);
  });
  const view = await mount('/admin/students');
  await act(async () => { rowDeleteButton(view.node).click(); });
  view.node.querySelector('#delete-confirmation').value = 'DELETE';
  holdRefresh = true;
  const originalConfirm = [...view.node.querySelectorAll('button')]
    .find(button => button.textContent.trim() === 'Delete Student');
  const originalPropsKey = Object.keys(originalConfirm).find(key => key.startsWith('__reactProps$'));
  const oldConfirmHandler = originalConfirm[originalPropsKey].onClick;
  await act(async () => {
    originalConfirm.click();
    await Promise.resolve();
  });
  expect(axios.delete).toHaveBeenCalledTimes(1);
  expect(held).toBe(true);
  mockAuthRevision += 2;
  await act(async () => pendingRefresh.resolve({ data: { success: true, students: [
    { ...managedStudent, id: 77, username: 'stale-refresh-student' },
  ] } }));
  await flush();
  expect(view.node.textContent).not.toContain('stale-refresh-student');
  expect(toast.success).not.toHaveBeenCalledWith('Student deleted successfully');
  await act(async () => { rowDeleteButton(view.node).click(); });
  view.node.querySelector('#delete-confirmation').value = 'DELETE';
  act(() => { oldConfirmHandler({ currentTarget: originalConfirm }); });
  expect(axios.delete).toHaveBeenCalledTimes(1);
  await act(async () => {
    [...view.node.querySelectorAll('button')].find(button => button.textContent.trim() === 'Delete Student').click();
  });
  await flush();
  expect(axios.delete).toHaveBeenCalledTimes(2);
  act(() => view.root.unmount());
});
