import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import { MemoryRouter } from 'react-router-dom';
import axios from 'axios';
import ComprehensiveAdminDashboard from './ComprehensiveAdminDashboard';

jest.mock('axios', () => ({ get: jest.fn(), post: jest.fn(), put: jest.fn(), delete: jest.fn() }));
jest.mock('../context/AuthContext', () => ({ useAuth: () => ({
  user: { id: 1, username: 'admin', isAdmin: true, adminLevel: 2,
    permissions: ['manage_progress', 'user_management'] },
  logout: jest.fn(),
}) }));
jest.mock('../context/WorkshopConfigContext', () => ({ useWorkshopConfig: () => ({ registerReconciler: () => () => {} }) }));
jest.mock('react-toastify', () => ({ toast: { error: jest.fn(), success: jest.fn() } }));
jest.mock('./admin/CTFAdminPanel', () => () => null);
jest.mock('../components/admin/AIProviderManagement', () => () => null);
jest.mock('../components/admin/StudentWorkshopView', () => () => null);
jest.mock('../components/admin/ServerLogs', () => () => null);
jest.mock('./admin/ProgressAnalyticsPanel', () => () => null);
jest.mock('../components/admin/PromptInjectionHintEditorModal', () => () => null);
jest.mock('../components/observability/AgentRunInspector', () => () => null);

const student = {
  id: 17, username: 'details-student', email: 'details@example.invalid', full_name: 'Details Student',
  role: 'student', admin_level: 0, created_at: '2026-09-01T00:00:00Z', last_login: null,
  completed_challenges: 0, total_challenges: 1,
};
const detail = {
  success: true,
  student,
  progress: [{ id: 'mcp_workshop', challenge_name: 'MCP Workshop', status: 'in_progress',
    score: null, challenge_max_score: null, difficulty_level: 'Advanced', category: 'Agentic' }],
  stats: { totalChallenges: 1, completedChallenges: 0, inProgressChallenges: 1,
    totalTimeSpent: 75, totalObjectivesCompleted: 1, totalScore: null, averageScore: null,
    pointsAvailable: false },
  workshopObjectives: { mcp_workshop: [{ workshop_key: 'mcp_workshop',
    objective_id: 'mcp_indirect_injection', objective_label: 'Indirect prompt injection',
    objective_category: null, completed: true, completed_at: null }] },
  pointsAvailable: false,
};

const flush = async () => act(async () => {
  await Promise.resolve(); await Promise.resolve(); await Promise.resolve();
});

async function mount() {
  const node = document.createElement('div'); document.body.appendChild(node);
  const root = createRoot(node);
  await act(async () => {
    root.render(<MemoryRouter initialEntries={['/admin/students']}><ComprehensiveAdminDashboard /></MemoryRouter>);
  });
  await flush();
  return { node, root };
}

beforeEach(() => {
  global.IS_REACT_ACT_ENVIRONMENT = true;
  localStorage.setItem('token', 'fixture');
  axios.get.mockImplementation(url => {
    if (url === '/api/admin/students') return Promise.resolve({ data: { success: true, students: [student] } });
    if (url === '/api/admin/challenges') return Promise.resolve({ data: { success: true, challenges: [] } });
    if (url === '/api/admin/students/17/progress') return Promise.resolve({ data: detail });
    return Promise.resolve({ data: {} });
  });
  axios.post.mockResolvedValue({ data: { success: true } });
  jest.spyOn(console, 'error').mockImplementation(() => {});
  jest.spyOn(console, 'warn').mockImplementation(() => {});
  jest.spyOn(console, 'log').mockImplementation(() => {});
});

afterEach(() => {
  jest.restoreAllMocks(); jest.clearAllMocks(); document.body.replaceChildren(); localStorage.clear();
});

test('PostgreSQL student details render canonical workshop progress and unknown scores without fabricating zero', async () => {
  const view = await mount();
  const details = [...view.node.querySelectorAll('button')].find(button => button.textContent.trim() === 'Details');
  expect(details).toBeDefined();
  await act(async () => { details.click(); });
  await flush();
  expect(axios.get).toHaveBeenCalledWith('/api/admin/students/17/progress', {
    headers: { Authorization: 'Bearer fixture' },
  });
  expect(view.node.textContent).toContain('Student Details');
  expect(view.node.textContent).toContain('details-student');
  expect(view.node.textContent).toContain('Mcp Workshop');
  expect(view.node.textContent).toContain('1/1 objectives');
  expect(view.node.textContent).toContain('Indirect prompt injection');
  expect(view.node.textContent).toContain('Score: —');
  const reset = [...view.node.querySelectorAll('button')].find(button => button.textContent.trim() === 'Reset');
  expect(reset).toBeDefined();
  act(() => view.root.unmount());
});

test('student deletion modal accurately describes anonymization, content removal, and retained records', async () => {
  const view = await mount();
  const remove = [...view.node.querySelectorAll('button')].find(button => button.textContent.trim() === 'Delete');
  expect(remove).toBeDefined();
  await act(async () => { remove.click(); });
  expect(view.node.textContent).toContain('deactivates and anonymizes the account');
  expect(view.node.textContent).toContain('removes workshop content');
  expect(view.node.textContent).toContain('retains redacted assessment and audit records');
  expect(view.node.textContent).not.toContain('all associated data');
  act(() => view.root.unmount());
});

test('create student submits typed full name, only offers student role, and clears successful form on reopen', async () => {
  const view = await mount();
  axios.post.mockResolvedValueOnce({ status: 201, data: { success: true, user: {
    id: 18, username: 'owned-student', email: 'owned@example.invalid', full_name: 'Owned Étudiant',
    role: 'student', admin_level: 0, is_active: 1,
  } } });
  const open = () => [...view.node.querySelectorAll('button')].find(b => b.textContent.trim() === 'Create New Student');
  const type = async (placeholder, value) => {
    const input = view.node.querySelector(`input[placeholder="${placeholder}"]`);
    await act(async () => {
      Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set.call(input, value);
      input.dispatchEvent(new Event('input', { bubbles: true }));
    });
  };
  try {
    await act(async () => open().click());
    await type('Enter username', 'owned-student'); await type('Enter email', 'owned@example.invalid');
    await type('Enter password', 'Owned-test-password-123'); await type('Confirm password', 'Owned-test-password-123');
    await type('Enter full name', 'Owned Étudiant');
    const form = view.node.querySelector('input[placeholder="Enter full name"]').closest('form');
    await act(async () => form.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true })));
    await flush();
    expect(axios.post).toHaveBeenCalledWith('/api/admin/students', {
      username: 'owned-student', email: 'owned@example.invalid', password: 'Owned-test-password-123', full_name: 'Owned Étudiant', role: 'student',
    }, { headers: { Authorization: 'Bearer fixture' } });
    await act(async () => open().click());
    const reopened = view.node.querySelector('input[placeholder="Enter full name"]');
    expect(reopened.value).toBe('');
    const roles = [...reopened.closest('form').querySelectorAll('select option')].map(o => o.value);
    expect(roles).toEqual(['student']);
    expect(view.node.querySelector('input[placeholder="Enter username"]').value).toBe('');
  } finally { act(() => view.root.unmount()); }
});

test('student edit retains its existing full name and only offers student role', async () => {
  const view = await mount();
  try {
    const edit = [...view.node.querySelectorAll('button')].find(b => b.textContent.trim() === 'Edit');
    await act(async () => edit.click());
    expect(view.node.textContent).toContain('Edit Student');
    const input = [...view.node.querySelectorAll('input')].find(node => node.value === student.full_name);
    expect(input).toBeDefined();
    const form = input.closest('form');
    expect([...form.querySelectorAll('select option')].map(option => option.value)).toEqual(['student']);
  } finally { act(() => view.root.unmount()); }
});
