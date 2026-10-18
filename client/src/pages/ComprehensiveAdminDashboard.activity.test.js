import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import { MemoryRouter } from 'react-router-dom';
import axios from 'axios';
import { toast } from 'react-toastify';
import ComprehensiveAdminDashboard from './ComprehensiveAdminDashboard';

jest.mock('axios', () => ({ get: jest.fn(), post: jest.fn(), put: jest.fn() }));
let mockUser;
jest.mock('../context/AuthContext', () => ({ useAuth: () => ({ user: mockUser, logout: jest.fn() }) }));
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
async function flush() { await act(async () => { await Promise.resolve(); await Promise.resolve(); }); }
function renderDashboard() {
  root.render(<MemoryRouter initialEntries={['/admin/activity']}><ComprehensiveAdminDashboard /></MemoryRouter>);
}
function mount() {
  node = document.createElement('div'); document.body.appendChild(node); root = createRoot(node);
  act(() => renderDashboard());
}
function response(url, failed = false) {
  if (url.startsWith('/api/admin/activity-')) {
    if (failed) return Promise.reject(new Error('owned API unavailable'));
    if (url.includes('activity-stats')) return Promise.resolve({ data: { stats: { successful_logins: 7 } } });
    return Promise.resolve({ data: { logs: [{ id: 42, username: 'real-audit-user', action_type: 'login_success', action_description: 'Actual persisted action', timestamp: '2026-09-13T00:00:00.000Z', success: 1 }], pagination: { pages: 1, total: 1 } } });
  }
  return Promise.resolve({ data: { success: true, students: [], challenges: [], solutions: [], objectives: [], users: [], pagination: {} } });
}
beforeEach(() => {
  global.IS_REACT_ACT_ENVIRONMENT = true;
  mockUser = { id: 1, username: 'instructor', isAdmin: true, adminLevel: 2, permissions: ['user_management'] };
  jest.spyOn(console, 'error').mockImplementation(() => {});
  axios.get.mockReset();
  toast.error.mockClear();
});
afterEach(() => { if (root) act(() => root.unmount()); node?.remove(); root = null; node = null; jest.useRealTimers(); jest.restoreAllMocks(); });

test('activity cards include attendees beyond the first 100-user API page', async () => {
  const users = Array.from({ length: 201 }, (_, i) => ({ id: i + 1,
    username: `workshop-attendee-${i + 1}`, recent_activity_count: i, role: 'student' }));
  axios.get.mockImplementation((url, config) => {
    if (url === '/api/admin/users') {
      const page = config?.params?.page || 1;
      return Promise.resolve({ data: { success: true, users: users.slice((page - 1) * 100, page * 100), pagination: { pages: 3 } } });
    }
    return response(url);
  });
  mount(); await flush(); await flush();
  expect(node.textContent).toContain('workshop-attendee-201');
  expect(node.textContent).toContain('workshop-attendee-101');
  expect(axios.get.mock.calls.some(([url, config]) => url === '/api/admin/users' && config.params.page === 3)).toBe(true);
});

test('failed activity APIs show an error without fabricated audit events or empty-success text', async () => {
  axios.get.mockImplementation(url => response(url, true)); mount(); await flush();
  expect(node.querySelector('[role="alert"]').textContent).toContain('Unable to load activity logs');
  expect(node.textContent).not.toContain('student_user'); expect(node.textContent).not.toContain('john_doe');
  expect(node.textContent).not.toContain('Completed SQL Injection Challenge'); expect(node.textContent).not.toContain('No recent activity found');
});

test('refresh uses the numeric page and clears stale audit rows when the API fails', async () => {
  axios.get.mockImplementation(url => response(url)); mount(); await flush(); expect(node.textContent).toContain('real-audit-user');
  axios.get.mockImplementation(url => response(url, true));
  const refresh = [...node.querySelectorAll('button')].find(button => button.textContent.trim() === 'Refresh'); expect(refresh).toBeDefined();
  act(() => refresh.click()); await flush();
  const urls = axios.get.mock.calls.map(([url]) => url).filter(url => url.includes('activity-logs'));
  expect(urls.every(url => /&page=1$/.test(url))).toBe(true);
  expect(node.textContent).not.toContain('real-audit-user'); expect(node.querySelector('[role="alert"]').textContent).toContain('Unable to load activity logs');
});

test.each([undefined, 503])('failed active-user refresh %s keeps the prior roster and labels it as stale', async status => {
  let failRoster = false;
  axios.get.mockImplementation(url => {
    if (url === '/api/admin/users') {
      if (failRoster) return Promise.reject(Object.assign(new Error('roster unavailable'), { response: { status } }));
      return Promise.resolve({ data: { success: true, users: [{ id: 7, username: 'retained-active-learner', recent_activity_count: 3 }], pagination: { pages: 1 } } });
    }
    return response(url);
  });
  mount(); await flush(); await flush();
  expect(node.textContent).toContain('retained-active-learner');

  failRoster = true;
  const heading = [...node.querySelectorAll('h3')].find(element => element.textContent.includes('Active Users & Their Activity'));
  const refresh = heading.parentElement.querySelector('button');
  await act(async () => { refresh.click(); await Promise.resolve(); });
  await flush();

  expect(node.textContent).toContain('retained-active-learner');
  expect(node.textContent).toContain('Unable to refresh active users. Showing previously loaded data.');
  expect(toast.error).toHaveBeenCalledWith('Failed to load active users data');
});

test('active-user roster follows user-management delegation and revocation', async () => {
  jest.useFakeTimers();
  mockUser = { ...mockUser, permissions: [] };
  axios.get.mockImplementation(url => {
    if (url === '/api/admin/users') {
      return Promise.resolve({ data: { success: true, users: [{ id: 8, username: 'delegated-roster-user', recent_activity_count: 1 }], pagination: { pages: 1 } } });
    }
    return response(url);
  });
  mount(); await flush();
  expect(node.textContent).toContain('Successful Logins');
  expect(node.textContent).toContain('User activity details require user management permission.');
  expect(axios.get.mock.calls.filter(([url]) => url === '/api/admin/users')).toHaveLength(0);

  mockUser = { ...mockUser, permissions: ['user_management'] };
  await act(async () => { renderDashboard(); await Promise.resolve(); });
  await flush();
  expect(node.textContent).toContain('delegated-roster-user');
  expect(axios.get.mock.calls.filter(([url]) => url === '/api/admin/users')).toHaveLength(1);

  mockUser = { ...mockUser, permissions: [] };
  await act(async () => { renderDashboard(); await Promise.resolve(); });
  await flush();
  expect(node.textContent).toContain('User activity details require user management permission.');
  expect(node.textContent).not.toContain('delegated-roster-user');
  expect(axios.get.mock.calls.filter(([url]) => url === '/api/admin/users')).toHaveLength(1);

  act(() => jest.advanceTimersByTime(30000)); await flush();
  expect(axios.get.mock.calls.filter(([url]) => url === '/api/admin/users')).toHaveLength(1);
});

test.each([undefined, 503])('initial active-user failure %s shows unavailable state instead of empty success', async status => {
  axios.get.mockImplementation(url => url === '/api/admin/users'
    ? Promise.reject(Object.assign(new Error('roster unavailable'), { response: { status } }))
    : response(url));
  mount(); await flush(); await flush();
  expect(node.textContent).toContain('Active user data is unavailable. Refresh to try again.');
  expect(node.textContent).not.toContain('No active users found');
});


test('polling keeps the selected page and ignores an older failed activity request', async () => {
  jest.useFakeTimers();
  let rejectOld;
  const oldRequest = new Promise((_resolve, reject) => { rejectOld = reject; });
  let holdNextPage = true;
  axios.get.mockImplementation(async url => {
    if (url.includes('activity-logs') && url.endsWith('page=2') && holdNextPage) {
      holdNextPage = false;
      return oldRequest;
    }
    const result = await response(url);
    if (url.includes('activity-logs')) result.data.pagination = { pages: 3, total: 201 };
    return result;
  });
  mount(); await flush();
  const next = [...node.querySelectorAll('button')].find(button => button.textContent.includes('Next'));
  act(() => next.click()); await flush();
  act(() => jest.advanceTimersByTime(30000)); await flush();
  const urls = axios.get.mock.calls.map(([url]) => url).filter(url => url.includes('activity-logs'));
  expect(urls.at(-1)).toMatch(/&page=2$/);
  expect(node.textContent).toContain('real-audit-user');
  await act(async () => { rejectOld(new Error('older request failed')); await Promise.resolve(); });
  await flush();
  expect(node.textContent).toContain('real-audit-user');
  expect(node.querySelector('[role="alert"]')).toBeNull();
});

test.each(['failure', 'success'])('a superseded active-user %s cannot replace current data or raise a false error toast', async outcome => {
  jest.useFakeTimers();
  let rejectOld, resolveOld, first = true;
  const old = new Promise((resolve, reject) => { resolveOld = resolve; rejectOld = reject; });
  axios.get.mockImplementation(url => {
    if (url === '/api/admin/users') {
      if (first) { first = false; return old; }
      return Promise.resolve({ data: { success: true, users: [{ id: 3, username: 'current-active-learner', recent_activity_count: 4 }] } });
    }
    return response(url);
  });
  mount(); await flush();
  act(() => jest.advanceTimersByTime(30000)); await flush();
  expect(node.textContent).toContain('current-active-learner');
  await act(async () => {
    if (outcome === 'failure') rejectOld(new Error('superseded request'));
    else resolveOld({ data: { success: true, users: [{ id: 4, username: 'obsolete-active-learner' }] } });
    await Promise.resolve();
  });
  await flush();
  expect(node.textContent).toContain('current-active-learner');
  expect(node.textContent).not.toContain('obsolete-active-learner');
  expect(toast.error).not.toHaveBeenCalledWith('Failed to load active users data');
});

test.each([401, 403])('active-user access denial %s clears previously loaded private roster', async status => {
  let failRoster = false;
  axios.get.mockImplementation(url => {
    if (url === '/api/admin/users') {
      if (failRoster) return Promise.reject(Object.assign(new Error('roster denied'), { response: { status } }));
      return Promise.resolve({ data: { success: true, users: [{ id: 7, username: 'retained-active-learner', recent_activity_count: 3 }], pagination: { pages: 1 } } });
    }
    return response(url);
  });
  mount(); await flush(); await flush();
  expect(node.textContent).toContain('retained-active-learner');

  failRoster = true;
  const heading = [...node.querySelectorAll('h3')].find(element => element.textContent.includes('Active Users & Their Activity'));
  const refresh = heading.parentElement.querySelector('button');
  await act(async () => { refresh.click(); await Promise.resolve(); });
  await flush();

  expect(node.textContent).not.toContain('retained-active-learner');
  expect(node.textContent).toContain('Active user data is no longer accessible.');
  expect(toast.error).toHaveBeenCalledWith('Failed to load active users data');
});
