import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import axios from 'axios';
import WorkshopDashboard from '../pages/WorkshopDashboard';
import StudentWorkshopView from '../components/admin/StudentWorkshopView';

jest.mock('axios', () => ({ get: jest.fn(), post: jest.fn() }));
jest.mock('../context/AuthContext', () => ({ useAuth: () => ({ user: { id: 1 } }) }));
jest.mock('../context/WorkshopConfigContext', () => ({
  useWorkshopConfig: () => ({
    revision: 1,
    snapshot: { revision: 1, exercises: {} },
    registerReconciler: () => () => {},
  }),
}));
jest.mock('react-router-dom', () => ({
  Link: ({ children }) => <a href="/">{children}</a>,
  useNavigate: () => jest.fn(),
  useLocation: () => ({ pathname: '/admin/student-workshop-view', search: '' }),
}));
jest.mock('react-toastify', () => ({
  toast: { success: jest.fn(), error: jest.fn(), info: jest.fn() },
}));

const challenge = {
  id: 'direct_prompt_injection',
  workshopKey: 'direct_prompt_injection',
  title: 'Direct Prompt Injection',
  name: 'Direct Prompt Injection',
  description: 'DPI',
  difficulty: 'Beginner',
  category: 'ai',
  route: '/vulnerabilities/direct-prompt-injection',
  status: 'in_progress',
  objectiveCount: 8,
  completedObjectiveCount: 2,
  timeSpentSeconds: 59,
  objectives: [],
};

async function flush() {
  await act(async () => {
    await Promise.resolve();
    await Promise.resolve();
    await new Promise((resolve) => setTimeout(resolve, 0));
  });
}

beforeEach(() => {
  global.IS_REACT_ACT_ENVIRONMENT = true;
  jest.spyOn(console, 'log').mockImplementation(() => {});
  axios.get.mockReset();
  axios.post.mockReset();
});

afterEach(() => {
  console.log.mockRestore();
});

test('student Dashboard renders canonical sub-minute time with the shared formatter', async () => {
  axios.get.mockImplementation((url) => {
    if (url === '/api/workshop/challenges') {
      return Promise.resolve({ data: { success: true, challenges: [challenge] } });
    }
    if (url === '/api/workshop/time/summary') {
      return Promise.resolve({ data: { summary: {} } });
    }
    return Promise.reject(new Error(`unexpected URL ${url}`));
  });
  const node = document.createElement('div');
  const root = createRoot(node);
  act(() => root.render(<WorkshopDashboard />));
  await flush();

  expect(node.textContent).toContain('59s');
  act(() => root.unmount());
});

test('Admin Student Workshop View renders the same canonical sub-minute time', async () => {
  axios.get.mockImplementation((url) => {
    if (url === '/api/admin/students') {
      return Promise.resolve({ data: { success: true, students: [{ id: 1, username: 'student', email: 'student@example.com' }] } });
    }
    if (url === '/api/admin/student-workshop-view/1') {
      return Promise.resolve({ data: {
        success: true,
        overview: {
          completedChallenges: 0,
          totalChallenges: 1,
          totalSystemChallenges: 1,
          totalPoints: 0,
          streak: 0,
          completionPercentage: 0,
        },
        challenges: [challenge],
      } });
    }
    return Promise.reject(new Error(`unexpected URL ${url}`));
  });
  const node = document.createElement('div');
  const root = createRoot(node);
  act(() => root.render(<StudentWorkshopView />));
  await flush();
  await flush();

  expect(node.textContent).toContain('59s');
  act(() => root.unmount());
});
