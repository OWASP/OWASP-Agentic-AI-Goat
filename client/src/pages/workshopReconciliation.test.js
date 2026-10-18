import React, { act } from 'react';
import { createHash } from 'crypto';
import { TextEncoder } from 'util';
Object.defineProperty(global.crypto, 'subtle', { value: { digest: async (_algorithm, bytes) => createHash('sha256').update(bytes).digest() }, configurable: true });
global.TextEncoder = TextEncoder;
import { createRoot } from 'react-dom/client';
import { MemoryRouter } from 'react-router-dom';
import axios from 'axios';
import { toast } from 'react-toastify';
import WorkshopDashboard from './WorkshopDashboard';
import WorkshopChallenges from './WorkshopChallenges';
import StudentWorkshopView from '../components/admin/StudentWorkshopView';

let mockReconcilers = [];
const mockRegisterReconciler = jest.fn((callback) => {
  mockReconcilers.push(callback);
  return () => {
    mockReconcilers = mockReconcilers.filter((candidate) => candidate !== callback);
  };
});

function deferred() {
  let resolve;
  let reject;
  const promise = new Promise((resolvePromise, rejectPromise) => {
    resolve = resolvePromise;
    reject = rejectPromise;
  });
  return { promise, resolve, reject };
}

jest.mock('axios', () => ({ get: jest.fn(), post: jest.fn() }));
jest.mock('../context/AuthContext', () => ({
  useAuth: () => ({ user: { id: 7, username: 'student' } }),
}));
jest.mock('../context/WorkshopConfigContext', () => ({
  useWorkshopConfig: () => ({
    snapshot: { exercises: {} },
    revision: 1,
    registerReconciler: mockRegisterReconciler,
  }),
}));
jest.mock('../components/HintPanel', () => () => null);
jest.mock('../components/SolutionPanel', () => () => null);
jest.mock('react-toastify', () => ({
  toast: { error: jest.fn(), success: jest.fn() },
}));

async function flush() {
  await act(async () => {
    await Promise.resolve();
    await Promise.resolve();
    await Promise.resolve();
  });
}

function render(Component, initialEntry = '/') {
  const node = document.createElement('div');
  const root = createRoot(node);
  act(() => root.render(
    <MemoryRouter initialEntries={[initialEntry]}>
      <Component />
    </MemoryRouter>
  ));
  return { node, root };
}

beforeEach(() => {
  global.IS_REACT_ACT_ENVIRONMENT = true;
  localStorage.setItem('token', 'admin-token');
  sessionStorage.clear();
  mockReconcilers = [];
  mockRegisterReconciler.mockClear();
  axios.get.mockReset();
  axios.post.mockReset();
  toast.error.mockReset();
  jest.spyOn(console, 'error').mockImplementation(() => {});
});

afterEach(() => {
  jest.restoreAllMocks();
});

test('WorkshopDashboard keeps last-good exercises when background reconciliation fails', async () => {
  axios.get.mockImplementation((url) => {
    if (url.includes('/time/summary')) return Promise.resolve({ data: { summary: {} } });
    return Promise.resolve({
      data: {
        challenges: [{
          id: 'direct_prompt_injection', title: 'Retained dashboard exercise',
          status: 'unlocked', objectiveCount: 1, completedObjectiveCount: 0,
          timeSpentSeconds: 0, route: '/workshop/prompt-injection',
        }],
      },
    });
  });
  const view = render(WorkshopDashboard);
  await flush();
  expect(view.node.textContent).toContain('Retained dashboard exercise');

  axios.get.mockImplementation((url) => (
    url.includes('/time/summary')
      ? Promise.resolve({ data: { summary: {} } })
      : Promise.reject(new Error('dashboard offline'))
  ));
  const reconcile = mockRegisterReconciler.mock.calls.at(-1)[0];
  await expect(reconcile()).rejects.toThrow('dashboard offline');
  expect(view.node.textContent).toContain('Retained dashboard exercise');
  act(() => view.root.unmount());
});

test('WorkshopDashboard renders a locked action without a route link when no objectives are enabled', async () => {
  axios.get.mockImplementation((url) => {
    if (url.includes('/time/summary')) return Promise.resolve({ data: { summary: {} } });
    return Promise.resolve({
      data: {
        challenges: [{
          id: 'direct_prompt_injection', title: 'Locked dashboard exercise',
          status: 'locked', objectiveCount: 0, completedObjectiveCount: 0,
          timeSpentSeconds: 0, route: '/workshop/prompt-injection',
        }],
      },
    });
  });
  const view = render(WorkshopDashboard);
  await flush();
  expect(view.node.textContent).toContain('Locked');
  expect(view.node.querySelector('a[href="/workshop/prompt-injection"]')).toBeNull();
  act(() => view.root.unmount());
});

test('WorkshopDashboard presents one next exercise and links to the complete Exercise Library', async () => {
  axios.get.mockImplementation((url) => {
    if (url.includes('/time/summary')) return Promise.resolve({ data: { summary: {} } });
    return Promise.resolve({
      data: {
        challenges: [
          {
            id: 'locked_exercise', title: 'Locked exercise', status: 'locked',
            objectiveCount: 1, completedObjectiveCount: 0, timeSpentSeconds: 0,
            route: '/workshop/locked',
          },
          {
            id: 'direct_prompt_injection', title: 'Continue this exercise', status: 'in_progress',
            objectiveCount: 2, completedObjectiveCount: 1, timeSpentSeconds: 0,
            route: '/workshop/prompt-injection',
          },
          {
            id: 'indirect_prompt_injection', title: 'Library-only exercise', status: 'unlocked',
            objectiveCount: 1, completedObjectiveCount: 0, timeSpentSeconds: 0,
            route: '/workshop/rag-injection',
          },
        ],
      },
    });
  });
  const view = render(WorkshopDashboard);
  await flush();
  expect(view.node.textContent).toContain('Student Dashboard');
  expect(view.node.textContent).toContain('3 instructor-visible exercises are in your library: 2 ready to open, 1 locked');
  expect(view.node.textContent).toContain('Visible Exercises');
  expect(view.node.querySelector('[data-testid="dashboard-continue-learning"]')?.textContent).toContain('Continue this exercise');
  expect(view.node.textContent).not.toContain('Locked exercise');
  expect(view.node.textContent).not.toContain('Library-only exercise');
  expect(view.node.querySelector('a[href="/workshop/challenges"]')?.textContent).toContain('Browse Exercise Library');
  act(() => view.root.unmount());
});

test('Exercise Library distinguishes visible cards from exercises ready to open', async () => {
  axios.get.mockResolvedValue({ data: { challenges: [
    { id: 'secureshop_agent_security', workshopKey: 'secureshop_agent_security', title: 'SecureShop',
      description: 'Pending objectives', difficulty: 'Advanced', status: 'locked', objectives: [], route: '/workshop/secureshop' },
    { id: 'direct_prompt_injection', workshopKey: 'direct_prompt_injection', title: 'Prompt Injection',
      description: 'Available objective', difficulty: 'Beginner', status: 'unlocked',
      objectives: [{ id: 'interact', completed: false }], route: '/workshop/prompt-injection' },
  ] } });
  const view = render(WorkshopChallenges);
  await flush();
  expect(view.node.textContent).toContain('2 instructor-visible exercises: 1 ready to open, 1 locked');
  expect(view.node.textContent).toContain('Exercise Library (2 visible)');
  expect(view.node.querySelector('a[href="/workshop/secureshop"]')).toBeNull();
  act(() => view.root.unmount());
});

test('WorkshopChallenges keeps last-good cards when background reconciliation fails', async () => {
  axios.get.mockResolvedValue({
    data: {
      challenges: [{
        id: 'direct_prompt_injection', workshopKey: 'direct_prompt_injection',
        title: 'Retained challenge card', description: 'Current canonical card',
        difficulty: 'Beginner', status: 'unlocked', objectives: [],
        route: '/workshop/prompt-injection',
      }],
    },
  });
  const view = render(WorkshopChallenges);
  await flush();
  expect(view.node.textContent).toContain('Retained challenge card');

  axios.get.mockRejectedValue(new Error('challenges offline'));
  const reconcile = mockRegisterReconciler.mock.calls.at(-1)[0];
  await expect(reconcile()).rejects.toThrow('challenges offline');
  expect(view.node.textContent).toContain('Retained challenge card');
  act(() => view.root.unmount());
});

test.each([undefined, 503])('StudentWorkshopView background failure %s retains data without loading state or toast', async (status) => {
  axios.get.mockImplementation((url) => {
    if (url === '/api/admin/students') {
      return Promise.resolve({ data: { success: true, students: [{ id: 3, username: 'learner' }] } });
    }
    if (url.includes('/student-workshop-view/3')) {
      return Promise.resolve({
        data: {
          success: true,
          overview: {
            completedChallenges: 1, totalChallenges: 2, totalPoints: 42,
            streak: 1, completionPercentage: 50, totalSystemChallenges: 2,
          },
          challenges: [],
        },
      });
    }
    return Promise.resolve({ data: { success: true, progress: [], achievements: [], totalScore: 0 } });
  });
  const view = render(StudentWorkshopView, '/admin/student-workshop-view');
  await flush();
  await flush();
  expect(view.node.textContent).toContain('42');
  toast.error.mockClear();

  axios.get.mockRejectedValue(Object.assign(new Error('student view offline'), { response: { status } }));
  const reconcile = mockRegisterReconciler.mock.calls.at(-1)[0];
  await expect(reconcile()).rejects.toThrow('student view offline');
  expect(view.node.textContent).toContain('42');
  expect(view.node.textContent).not.toContain('Loading');
  expect(toast.error).not.toHaveBeenCalled();
  act(() => view.root.unmount());
});

test('StudentWorkshopView renders Sensitive Info objectives from the canonical admin projection only', async () => {
  axios.get.mockImplementation((url) => {
    if (url === '/api/admin/students') {
      return Promise.resolve({ data: { success: true, students: [{ id: 3, username: 'learner' }] } });
    }
    if (url === '/api/admin/student-workshop-view/3') {
      return Promise.resolve({
        data: {
          success: true,
          overview: {
            completedChallenges: 0, totalChallenges: 1, totalPoints: null,
            pointsAvailable: false, streak: 0, completionPercentage: 0,
            totalSystemChallenges: 1,
          },
          challenges: [{
            id: 'sensitive_info_disclosure',
            workshopKey: 'sensitive_info_disclosure',
            name: 'Sensitive Information Disclosure',
            status: 'in_progress', difficulty: 'Advanced', description: 'FinFlow',
            objectiveCount: 18, completedObjectiveCount: 1, timeSpentSeconds: 5,
            route: '/workshop/sensitive-info',
            objectives: [
              { id: 'tool_enum', label: 'Tool Enumeration — list all tools', completed: true, completedAt: '2026-09-13T00:00:00.000Z' },
              { id: 'llm_identify', label: 'LLM Model Identification', completed: false, completedAt: null },
            ],
          }],
        },
      });
    }
    return Promise.reject(new Error(`unexpected URL ${url}`));
  });

  const view = render(StudentWorkshopView, '/admin/student-workshop-view');
  await flush();
  await flush();

  expect(axios.get).toHaveBeenCalledTimes(2);
  expect(view.node.textContent).toContain('1 / 18 objectives completed');
  expect(view.node.textContent).toContain('Tool Enumeration — list all tools');
  expect(view.node.textContent).toContain('LLM Model Identification');
  expect(view.node.textContent).toContain('COMPLETED');
  expect(view.node.textContent).toContain('NOT COMPLETED');
  expect(view.node.textContent).not.toMatch(/Score:|Achievements:|LOCKED/);
  act(() => view.root.unmount());
});

test('StudentWorkshopView reports canonical Sensitive Info absence without inventing not-started progress', async () => {
  axios.get.mockImplementation((url) => {
    if (url === '/api/admin/students') {
      return Promise.resolve({ data: { success: true, students: [{ id: 3, username: 'learner' }] } });
    }
    if (url === '/api/admin/student-workshop-view/3') {
      return Promise.resolve({
        data: {
          success: true,
          overview: { completedChallenges: 0, totalChallenges: 0, totalPoints: null, streak: 0, completionPercentage: 0, totalSystemChallenges: 0 },
          challenges: [],
        },
      });
    }
    return Promise.reject(new Error(`unexpected URL ${url}`));
  });

  const view = render(StudentWorkshopView, '/admin/student-workshop-view');
  await flush();
  await flush();

  expect(view.node.textContent).toContain('Sensitive Info progress is unavailable for learner in the current admin projection.');
  expect(view.node.textContent).not.toContain('has not started');
  expect(axios.get).toHaveBeenCalledTimes(2);
  act(() => view.root.unmount());
});

test('StudentWorkshopView serializes background success behind foreground loading ownership', async () => {
  const initialWorkshop = deferred();
  const backgroundWorkshop = deferred();
  let workshopCalls = 0;
  axios.get.mockImplementation((url) => {
    if (url === '/api/admin/students') {
      return Promise.resolve({ data: { success: true, students: [{ id: 3, username: 'learner' }] } });
    }
    if (url.includes('/student-workshop-view/3')) {
      workshopCalls += 1;
      return workshopCalls === 1 ? initialWorkshop.promise : backgroundWorkshop.promise;
    }
    return Promise.reject(new Error(`unexpected URL ${url}`));
  });
  const view = render(StudentWorkshopView, '/admin/student-workshop-view');
  await flush();
  const reconcile = mockRegisterReconciler.mock.calls.at(-1)[0];
  const reconciliation = reconcile();
  expect(workshopCalls).toBe(1);

  await act(async () => {
    initialWorkshop.resolve({
      data: {
        success: true,
        overview: {
          completedChallenges: 1, totalChallenges: 2, totalPoints: 11,
          streak: 1, completionPercentage: 50, totalSystemChallenges: 2,
        },
        challenges: [],
      },
    });
  });
  await flush();
  expect(workshopCalls).toBe(2);

  await act(async () => {
    backgroundWorkshop.resolve({
      data: {
        success: true,
        overview: {
          completedChallenges: 2, totalChallenges: 2, totalPoints: 99,
          streak: 2, completionPercentage: 100, totalSystemChallenges: 2,
        },
        challenges: [],
      },
    });
    await reconciliation;
  });
  expect(view.node.textContent).toContain('99');
  expect(view.node.textContent).not.toContain('11');
  act(() => view.root.unmount());
});

test('StudentWorkshopView drops a waiting reconciliation after student selection changes', async () => {
  const initialStudentAWorkshop = deferred();
  let studentAWorkshopCalls = 0;

  axios.get.mockImplementation((url) => {
    if (url === '/api/admin/students') {
      return Promise.resolve({
        data: {
          success: true,
          students: [
            { id: 3, username: 'student-a', email: 'a@example.com' },
            { id: 4, username: 'student-b', email: 'b@example.com' },
          ],
        },
      });
    }
    if (url.includes('/student-workshop-view/3')) {
      studentAWorkshopCalls += 1;
      if (studentAWorkshopCalls === 1) return initialStudentAWorkshop.promise;
      return Promise.resolve({
        data: {
          success: true,
          overview: {
            completedChallenges: 9, totalChallenges: 9, totalPoints: 999,
            streak: 9, completionPercentage: 100, totalSystemChallenges: 9,
          },
          challenges: [],
        },
      });
    }
    if (url.includes('/student-workshop-view/4')) {
      return Promise.resolve({
        data: {
          success: true,
          overview: {
            completedChallenges: 2, totalChallenges: 2, totalPoints: 200,
            streak: 2, completionPercentage: 100, totalSystemChallenges: 2,
          },
          challenges: [],
        },
      });
    }
    return Promise.reject(new Error(`unexpected URL ${url}`));
  });

  const view = render(StudentWorkshopView, '/admin/student-workshop-view');
  await flush();
  const staleReconcile = mockRegisterReconciler.mock.calls.at(-1)[0]();

  const selector = view.node.querySelector('select');
  await act(async () => {
    selector.value = '4';
    selector.dispatchEvent(new Event('change', { bubbles: true }));
  });
  await flush();
  expect(view.node.textContent).toContain('200');

  await act(async () => {
    initialStudentAWorkshop.resolve({
      data: {
        success: true,
        overview: {
          completedChallenges: 1, totalChallenges: 2, totalPoints: 100,
          streak: 1, completionPercentage: 50, totalSystemChallenges: 2,
        },
        challenges: [],
      },
    });
    await staleReconcile;
  });

  expect(studentAWorkshopCalls).toBe(1);
  expect(view.node.textContent).toContain('200');
  expect(view.node.textContent).not.toContain('999');
  expect(toast.error).not.toHaveBeenCalled();
  act(() => view.root.unmount());
});

test('StudentWorkshopView clears student A data and shows an inline error when student B fails', async () => {
  axios.get.mockImplementation((url) => {
    if (url === '/api/admin/students') {
      return Promise.resolve({ data: { success: true, students: [
        { id: 3, username: 'student-a', email: 'a@example.com' },
        { id: 4, username: 'student-b', email: 'b@example.com' },
      ] } });
    }
    if (url.includes('/student-workshop-view/3')) {
      return Promise.resolve({ data: {
        success: true,
        overview: { completedChallenges: 1, totalChallenges: 1, totalPoints: null,
          streak: 1, completionPercentage: 100, totalSystemChallenges: 1 },
        challenges: [{ id: 'student-a-only', workshopKey: 'student_a_only', name: 'Student A private progress',
          description: 'Belongs to student A', difficulty: 'Beginner', status: 'completed',
          objectiveCount: 1, completedObjectiveCount: 1, timeSpentSeconds: 1, objectives: [] }],
      } });
    }
    if (url.includes('/student-workshop-view/4')) {
      return Promise.reject({ response: { data: { error: 'Student workshop view is temporarily unavailable' } } });
    }
    return Promise.reject(new Error(`unexpected URL ${url}`));
  });

  const view = render(StudentWorkshopView, '/admin/student-workshop-view');
  await flush();
  await flush();
  expect(view.node.textContent).toContain('Student A private progress');

  const selector = view.node.querySelector('select');
  await act(async () => {
    selector.value = '4';
    selector.dispatchEvent(new Event('change', { bubbles: true }));
  });
  await flush();

  expect(selector.value).toBe('4');
  expect(view.node.textContent).not.toContain('Student A private progress');
  expect(view.node.querySelector('[role="alert"]').textContent)
    .toContain('Student workshop view is temporarily unavailable');
  expect(toast.error).toHaveBeenCalledWith('Failed to load student workshop data');
  act(() => view.root.unmount());
});

test('StudentWorkshopView releases foreground loading before a serialized background failure', async () => {
  const initialWorkshop = deferred();
  let workshopCalls = 0;
  axios.get.mockImplementation((url) => {
    if (url === '/api/admin/students') {
      return Promise.resolve({ data: { success: true, students: [{ id: 3, username: 'learner' }] } });
    }
    if (url.includes('/student-workshop-view/3')) {
      workshopCalls += 1;
      return workshopCalls === 1 ? initialWorkshop.promise : Promise.reject(new Error('baseline offline'));
    }
    return Promise.reject(new Error(`unexpected URL ${url}`));
  });
  const view = render(StudentWorkshopView, '/admin/student-workshop-view');
  await flush();
  const reconcile = mockRegisterReconciler.mock.calls.at(-1)[0];
  const reconciliation = reconcile();
  const rejectedReconciliation = expect(reconciliation).rejects.toThrow('baseline offline');

  await act(async () => {
    initialWorkshop.resolve({
      data: {
        success: true,
        overview: {
          completedChallenges: 1, totalChallenges: 2, totalPoints: 37,
          streak: 1, completionPercentage: 50, totalSystemChallenges: 2,
        },
        challenges: [],
      },
    });
  });
  await rejectedReconciliation;
  await flush();
  expect(view.node.textContent).toContain('37');
  expect(toast.error).not.toHaveBeenCalled();
  act(() => view.root.unmount());
});

test('StudentWorkshopView does not start a waiting background request after unmount', async () => {
  const initialWorkshop = deferred();
  axios.get.mockImplementation((url) => {
    if (url === '/api/admin/students') {
      return Promise.resolve({ data: { success: true, students: [{ id: 3, username: 'learner' }] } });
    }
    if (url.includes('/student-workshop-view/3')) return initialWorkshop.promise;
    return Promise.reject(new Error(`unexpected URL ${url}`));
  });
  const view = render(StudentWorkshopView, '/admin/student-workshop-view');
  await flush();
  const reconcile = mockRegisterReconciler.mock.calls.at(-1)[0];
  const reconciliation = reconcile();
  expect(axios.get).toHaveBeenCalledTimes(2);
  act(() => view.root.unmount());

  await act(async () => {
    initialWorkshop.resolve({ data: { success: false } });
    await reconciliation;
  });
  expect(axios.get).toHaveBeenCalledTimes(2);
  expect(toast.error).not.toHaveBeenCalled();
});

test('StudentWorkshopView resets Sensitive Info through the canonical admin endpoint and refreshes the selected student', async () => {
  localStorage.setItem('token', 'admin-token');
  jest.spyOn(window, 'confirm').mockReturnValue(true);
  let workshopFetches = 0;
  axios.get.mockImplementation((url) => {
    if (url === '/api/admin/students') {
      return Promise.resolve({ data: { success: true, students: [{ id: 3, username: 'learner' }] } });
    }
    if (url.includes('/student-workshop-view/3')) {
      workshopFetches += 1;
      return Promise.resolve({
        data: {
          success: true,
          overview: {
            completedChallenges: workshopFetches === 1 ? 1 : 0, totalChallenges: 2,
            totalPoints: workshopFetches === 1 ? 42 : 0, streak: 1,
            completionPercentage: workshopFetches === 1 ? 50 : 0, totalSystemChallenges: 2,
          },
          challenges: [],
        },
      });
    }
    return Promise.reject(new Error(`unexpected URL ${url}`));
  });
  axios.post.mockResolvedValue({ data: { success: true } });

  const view = render(StudentWorkshopView, '/admin/student-workshop-view');
  await flush();
  await flush();
  const resetButton = [...view.node.querySelectorAll('button')]
    .find((button) => button.textContent.includes('Reset Progress'));
  await act(async () => {
    resetButton.dispatchEvent(new MouseEvent('click', { bubbles: true }));
  });
  await flush();

  expect(axios.post).toHaveBeenCalledWith(
    '/api/admin/students/3/workshops/sensitive_info_disclosure/reset',
    {},
    { headers: { Authorization: 'Bearer admin-token', 'x-reset-operation-id': expect.any(String) } }
  );
  expect(workshopFetches).toBe(2);
  expect(toast.success).toHaveBeenCalledWith('Sensitive Info progress reset for learner');
  act(() => view.root.unmount());
});

test('StudentWorkshopView reports a rejected Sensitive Info reset without a false success or refresh', async () => {
  jest.spyOn(window, 'confirm').mockReturnValue(true);
  let workshopFetches = 0;
  axios.get.mockImplementation((url) => {
    if (url === '/api/admin/students') {
      return Promise.resolve({ data: { success: true, students: [{ id: 3, username: 'learner' }] } });
    }
    if (url.includes('/student-workshop-view/3')) {
      workshopFetches += 1;
      return Promise.resolve({
        data: {
          success: true,
          overview: { completedChallenges: 1, totalChallenges: 2, totalPoints: 42, streak: 1, completionPercentage: 50, totalSystemChallenges: 2 },
          challenges: [],
        },
      });
    }
    return Promise.resolve({ data: { success: true, progress: [], achievements: [], totalScore: 0 } });
  });
  axios.post.mockResolvedValue({ data: { success: false, error: 'Reset was rejected' } });

  const view = render(StudentWorkshopView, '/admin/student-workshop-view');
  await flush();
  await flush();
  const resetButton = [...view.node.querySelectorAll('button')]
    .find((button) => button.textContent.includes('Reset Progress'));
  await act(async () => {
    resetButton.dispatchEvent(new MouseEvent('click', { bubbles: true }));
  });
  await flush();

  expect(workshopFetches).toBe(1);
  expect(toast.success).not.toHaveBeenCalled();
  expect(toast.error).toHaveBeenCalledWith('Reset completion is uncertain. Retry this same student to recover the original request.');
  act(() => view.root.unmount());
});

test('StudentWorkshopView drops a completed Sensitive Info reset after the selected student changes', async () => {
  jest.spyOn(window, 'confirm').mockReturnValue(true);
  const reset = deferred();
  let studentAWorkshopFetches = 0;
  axios.get.mockImplementation((url) => {
    if (url === '/api/admin/students') {
      return Promise.resolve({
        data: {
          success: true,
          students: [
            { id: 3, username: 'student-a' },
            { id: 4, username: 'student-b' },
          ],
        },
      });
    }
    if (url.includes('/student-workshop-view/3')) {
      studentAWorkshopFetches += 1;
      return Promise.resolve({
        data: {
          success: true,
          overview: { completedChallenges: 1, totalChallenges: 2, totalPoints: 30, streak: 1, completionPercentage: 50, totalSystemChallenges: 2 },
          challenges: [],
        },
      });
    }
    if (url.includes('/student-workshop-view/4')) {
      return Promise.resolve({
        data: {
          success: true,
          overview: { completedChallenges: 2, totalChallenges: 2, totalPoints: 40, streak: 2, completionPercentage: 100, totalSystemChallenges: 2 },
          challenges: [],
        },
      });
    }
    return Promise.resolve({ data: { success: true, progress: [], achievements: [], totalScore: 0 } });
  });
  axios.post.mockReturnValue(reset.promise);

  const view = render(StudentWorkshopView, '/admin/student-workshop-view');
  await flush();
  await flush();
  const resetButton = [...view.node.querySelectorAll('button')]
    .find((button) => button.textContent.includes('Reset Progress'));
  act(() => {
    resetButton.dispatchEvent(new MouseEvent('click', { bubbles: true }));
  });
  const selector = view.node.querySelector('select');
  await act(async () => {
    selector.value = '4';
    selector.dispatchEvent(new Event('change', { bubbles: true }));
  });
  await flush();

  await act(async () => {
    reset.resolve({ data: { success: true } });
  });
  await flush();

  expect(studentAWorkshopFetches).toBe(1);
  expect(view.node.textContent).toContain('40');
  expect(toast.success).not.toHaveBeenCalled();
  act(() => view.root.unmount());
});

test('StudentWorkshopView drops a rejected Sensitive Info reset after the selected student changes', async () => {
  jest.spyOn(window, 'confirm').mockReturnValue(true);
  const reset = deferred();
  axios.get.mockImplementation((url) => {
    if (url === '/api/admin/students') {
      return Promise.resolve({
        data: {
          success: true,
          students: [
            { id: 3, username: 'student-a' },
            { id: 4, username: 'student-b' },
          ],
        },
      });
    }
    if (url.includes('/student-workshop-view/3')) {
      return Promise.resolve({
        data: {
          success: true,
          overview: { completedChallenges: 1, totalChallenges: 2, totalPoints: 30, streak: 1, completionPercentage: 50, totalSystemChallenges: 2 },
          challenges: [],
        },
      });
    }
    if (url.includes('/student-workshop-view/4')) {
      return Promise.resolve({
        data: {
          success: true,
          overview: { completedChallenges: 2, totalChallenges: 2, totalPoints: 40, streak: 2, completionPercentage: 100, totalSystemChallenges: 2 },
          challenges: [],
        },
      });
    }
    return Promise.resolve({ data: { success: true, progress: [], achievements: [], totalScore: 0 } });
  });
  axios.post.mockReturnValue(reset.promise);

  const view = render(StudentWorkshopView, '/admin/student-workshop-view');
  await flush();
  await flush();
  const resetButton = [...view.node.querySelectorAll('button')]
    .find((button) => button.textContent.includes('Reset Progress'));
  act(() => {
    resetButton.dispatchEvent(new MouseEvent('click', { bubbles: true }));
  });
  const selector = view.node.querySelector('select');
  await act(async () => {
    selector.value = '4';
    selector.dispatchEvent(new Event('change', { bubbles: true }));
  });
  await flush();

  await act(async () => {
    reset.resolve({ data: { success: false, error: 'Reset was rejected' } });
  });
  await flush();

  expect(view.node.textContent).toContain('40');
  expect(toast.error).not.toHaveBeenCalled();
  expect(toast.success).not.toHaveBeenCalled();
  act(() => view.root.unmount());
});

test('StudentWorkshopView ignores a rejected Sensitive Info reset after unmount', async () => {
  jest.spyOn(window, 'confirm').mockReturnValue(true);
  const reset = deferred();
  axios.get.mockImplementation((url) => {
    if (url === '/api/admin/students') {
      return Promise.resolve({ data: { success: true, students: [{ id: 3, username: 'learner' }] } });
    }
    if (url.includes('/student-workshop-view/3')) {
      return Promise.resolve({
        data: {
          success: true,
          overview: { completedChallenges: 1, totalChallenges: 2, totalPoints: 42, streak: 1, completionPercentage: 50, totalSystemChallenges: 2 },
          challenges: [],
        },
      });
    }
    return Promise.resolve({ data: { success: true, progress: [], achievements: [], totalScore: 0 } });
  });
  axios.post.mockReturnValue(reset.promise);

  const view = render(StudentWorkshopView, '/admin/student-workshop-view');
  await flush();
  await flush();
  const resetButton = [...view.node.querySelectorAll('button')]
    .find((button) => button.textContent.includes('Reset Progress'));
  act(() => {
    resetButton.dispatchEvent(new MouseEvent('click', { bubbles: true }));
  });
  await flush();
  expect(axios.post).toHaveBeenCalledTimes(1);
  act(() => view.root.unmount());
  jest.spyOn(console, 'error').mockClear();

  await act(async () => {
    reset.reject(new Error('reset request failed'));
  });
  await flush();

  expect(toast.error).not.toHaveBeenCalled();
  expect(console.error).not.toHaveBeenCalled();
});

test('StudentWorkshopView drops an older reset success after A-to-B-to-A while a newer A reset is pending', async () => {
  jest.spyOn(window, 'confirm').mockReturnValue(true);
  const olderReset = deferred();
  const newerReset = deferred();
  let studentAWorkshopFetches = 0;
  axios.get.mockImplementation((url) => {
    if (url === '/api/admin/students') {
      return Promise.resolve({
        data: { success: true, students: [{ id: 3, username: 'student-a' }, { id: 4, username: 'student-b' }] },
      });
    }
    if (url.includes('/student-workshop-view/3')) {
      studentAWorkshopFetches += 1;
      return Promise.resolve({
        data: {
          success: true,
          overview: { completedChallenges: 1, totalChallenges: 2, totalPoints: 30, streak: 1, completionPercentage: 50, totalSystemChallenges: 2 },
          challenges: [],
        },
      });
    }
    if (url.includes('/student-workshop-view/4')) {
      return Promise.resolve({
        data: {
          success: true,
          overview: { completedChallenges: 2, totalChallenges: 2, totalPoints: 40, streak: 2, completionPercentage: 100, totalSystemChallenges: 2 },
          challenges: [],
        },
      });
    }
    return Promise.resolve({ data: { success: true, progress: [], achievements: [], totalScore: 0 } });
  });
  axios.post.mockImplementationOnce(() => olderReset.promise).mockImplementationOnce(() => newerReset.promise);

  const view = render(StudentWorkshopView, '/admin/student-workshop-view');
  await flush();
  await flush();
  let resetButton = [...view.node.querySelectorAll('button')]
    .find((button) => button.textContent.includes('Reset Progress'));
  act(() => resetButton.dispatchEvent(new MouseEvent('click', { bubbles: true })));
  await flush();
  const selector = view.node.querySelector('select');
  await act(async () => {
    selector.value = '4';
    selector.dispatchEvent(new Event('change', { bubbles: true }));
  });
  await flush();
  await act(async () => {
    selector.value = '3';
    selector.dispatchEvent(new Event('change', { bubbles: true }));
  });
  await flush();
  resetButton = [...view.node.querySelectorAll('button')]
    .find((button) => button.textContent.includes('Reset Progress'));
  act(() => resetButton.dispatchEvent(new MouseEvent('click', { bubbles: true })));
  await flush();

  await act(async () => {
    olderReset.resolve({ data: { success: true } });
  });
  await flush();

  expect(studentAWorkshopFetches).toBe(2);
  expect(resetButton.disabled).toBe(true);
  expect(toast.success).not.toHaveBeenCalled();

  await act(async () => {
    newerReset.resolve({ data: { success: true } });
  });
  await flush();

  expect(studentAWorkshopFetches).toBe(3);
  expect(toast.success).toHaveBeenCalledTimes(1);
  act(() => view.root.unmount());
});

test('StudentWorkshopView drops an older reset failure after A-to-B-to-A while a newer A reset is pending', async () => {
  jest.spyOn(window, 'confirm').mockReturnValue(true);
  const olderReset = deferred();
  const newerReset = deferred();
  axios.get.mockImplementation((url) => {
    if (url === '/api/admin/students') {
      return Promise.resolve({
        data: { success: true, students: [{ id: 3, username: 'student-a' }, { id: 4, username: 'student-b' }] },
      });
    }
    if (url.includes('/student-workshop-view/3')) {
      return Promise.resolve({
        data: {
          success: true,
          overview: { completedChallenges: 1, totalChallenges: 2, totalPoints: 30, streak: 1, completionPercentage: 50, totalSystemChallenges: 2 },
          challenges: [],
        },
      });
    }
    if (url.includes('/student-workshop-view/4')) {
      return Promise.resolve({
        data: {
          success: true,
          overview: { completedChallenges: 2, totalChallenges: 2, totalPoints: 40, streak: 2, completionPercentage: 100, totalSystemChallenges: 2 },
          challenges: [],
        },
      });
    }
    return Promise.resolve({ data: { success: true, progress: [], achievements: [], totalScore: 0 } });
  });
  axios.post.mockImplementationOnce(() => olderReset.promise).mockImplementationOnce(() => newerReset.promise);

  const view = render(StudentWorkshopView, '/admin/student-workshop-view');
  await flush();
  await flush();
  let resetButton = [...view.node.querySelectorAll('button')]
    .find((button) => button.textContent.includes('Reset Progress'));
  act(() => resetButton.dispatchEvent(new MouseEvent('click', { bubbles: true })));
  await flush();
  const selector = view.node.querySelector('select');
  await act(async () => {
    selector.value = '4';
    selector.dispatchEvent(new Event('change', { bubbles: true }));
  });
  await flush();
  await act(async () => {
    selector.value = '3';
    selector.dispatchEvent(new Event('change', { bubbles: true }));
  });
  await flush();
  resetButton = [...view.node.querySelectorAll('button')]
    .find((button) => button.textContent.includes('Reset Progress'));
  act(() => resetButton.dispatchEvent(new MouseEvent('click', { bubbles: true })));
  await flush();

  await act(async () => {
    olderReset.resolve({ data: { success: false, error: 'Older reset rejected' } });
  });
  await flush();

  expect(resetButton.disabled).toBe(true);
  expect(toast.error).not.toHaveBeenCalled();
  expect(toast.success).not.toHaveBeenCalled();

  await act(async () => {
    newerReset.resolve({ data: { success: true } });
  });
  await flush();

  expect(toast.success).toHaveBeenCalledTimes(1);
  expect(toast.error).not.toHaveBeenCalled();
  act(() => view.root.unmount());
});

test('StudentWorkshopView background waiter follows replacement foreground across A-B-A selection', async () => {
  const firstA = deferred(), nextA = deferred(), onlyB = deferred(), backgroundA = deferred();
  let aCalls = 0;
  axios.get.mockImplementation(url => {
    if (url === '/api/admin/students') return Promise.resolve({ data: { success: true,
      students: [{ id: 3, username: 'learner-a' }, { id: 4, username: 'learner-b' }] } });
    if (url.endsWith('/student-workshop-view/3')) return [firstA, nextA, backgroundA][aCalls++].promise;
    if (url.endsWith('/student-workshop-view/4')) return onlyB.promise;
    throw Error('Unexpected URL '+url);
  });
  const data = points => ({ data: { success: true, overview: { completedChallenges: 0,
    totalChallenges: 1, totalPoints: points, streak: 0, completionPercentage: 0, totalSystemChallenges: 1 }, challenges: [] } });
  const view = render(StudentWorkshopView, '/admin/student-workshop-view'); await flush();
  const reconcile = mockRegisterReconciler.mock.calls.at(-1)[0];
  const pending = reconcile();
  const select = view.node.querySelector('select');
  await act(async () => { select.value = '4'; select.dispatchEvent(new Event('change', { bubbles: true })); });
  await flush();
  await act(async () => { select.value = '3'; select.dispatchEvent(new Event('change', { bubbles: true })); });
  await flush(); expect(aCalls).toBe(2);
  await act(async () => { firstA.resolve(data(1)); }); await flush();
  // The older A waiter must follow the newer A foreground, not supersede it.
  expect(aCalls).toBe(2);
  await act(async () => { nextA.resolve(data(22)); onlyB.resolve(data(4)); }); await flush();
  expect(aCalls).toBe(3);
  await act(async () => { backgroundA.resolve(data(33)); await pending; }); await flush();
  expect([...view.node.querySelectorAll('button')].find(button => button.textContent.includes('Refresh')).disabled).toBe(false);
  expect(view.node.textContent).toContain('33');
  act(() => view.root.unmount());
});

test.each([401, 403, 404])('StudentWorkshopView clears retained student detail on current background access denial %s', async (status) => {
  axios.get.mockImplementation((url) => {
    if (url === '/api/admin/students') {
      return Promise.resolve({ data: { success: true, students: [{ id: 3, username: 'learner' }] } });
    }
    if (url.includes('/student-workshop-view/3')) {
      return Promise.resolve({
        data: {
          success: true,
          overview: {
            completedChallenges: 1, totalChallenges: 2, totalPoints: 42,
            streak: 1, completionPercentage: 50, totalSystemChallenges: 2,
          },
          challenges: [],
        },
      });
    }
    return Promise.resolve({ data: { success: true, progress: [], achievements: [], totalScore: 0 } });
  });
  const view = render(StudentWorkshopView, '/admin/student-workshop-view');
  await flush();
  await flush();
  expect(view.node.textContent).toContain('42');
  toast.error.mockClear();

  axios.get.mockRejectedValue(Object.assign(new Error('access denied'), { response: { status } }));
  const reconcile = mockRegisterReconciler.mock.calls.at(-1)[0];
  await act(async () => { await expect(reconcile()).rejects.toThrow('access denied'); });
  expect(view.node.textContent).not.toContain('42');
  expect(view.node.textContent).toContain('no longer accessible');
  expect(view.node.querySelector('button[title="Erase all Sensitive Info workshop progress for this student"]')).toBeNull();
  expect(view.node.textContent).not.toContain('Loading');
  expect(toast.error).not.toHaveBeenCalled();
  axios.get.mockResolvedValue({ data: { success: true, overview: { totalPoints: 87, completedChallenges: 0, totalChallenges: 2, streak: 0, completionPercentage: 0, totalSystemChallenges: 2 }, challenges: [] } });
  act(() => [...view.node.querySelectorAll('button')].find(button => button.textContent.trim() === 'Refresh').click());
  await flush();
  expect(view.node.textContent).toContain('87');
  expect(view.node.textContent).not.toContain('no longer accessible');
  act(() => view.root.unmount());
});

test('StudentWorkshopView stale background denial cannot erase a newer foreground readback', async () => {
  const denied = deferred(); let calls = 0;
  const data = points => ({ data: { success: true, overview: { completedChallenges: 1, totalChallenges: 2, totalPoints: points, streak: 1, completionPercentage: 50, totalSystemChallenges: 2 }, challenges: [] } });
  axios.get.mockImplementation(url => {
    if (url === '/api/admin/students') return Promise.resolve({ data: { success: true, students: [{ id: 3, username: 'learner' }] } });
    if (url.includes('/student-workshop-view/3')) return ++calls === 2 ? denied.promise : Promise.resolve(data(calls === 1 ? 42 : 99));
    return Promise.resolve({ data: {} });
  });
  const view = render(StudentWorkshopView, '/admin/student-workshop-view');
  await flush(); await flush();
  const pending = mockRegisterReconciler.mock.calls.at(-1)[0]();
  const observed = pending.catch(error => error);
  await flush();
  act(() => [...view.node.querySelectorAll('button')].find(button => button.textContent.trim() === 'Refresh').click());
  await flush(); expect(view.node.textContent).toContain('99');
  await act(async () => { denied.reject(Object.assign(new Error('old denial'), { response: { status: 403 } })); await observed; });
  expect(view.node.textContent).toContain('99');
  expect(view.node.textContent).not.toContain('no longer accessible');
  act(() => view.root.unmount());
});

test('StudentWorkshopView old learner denial preserves the selected sibling', async () => {
  const denied = deferred(); let reads = 0;
  const data = totalPoints => ({ data: { success: true, overview: { totalPoints, completedChallenges: 0, totalChallenges: 2, streak: 0, completionPercentage: 0, totalSystemChallenges: 2 }, challenges: [] } });
  axios.get.mockImplementation(url => {
    if (url === '/api/admin/students') return Promise.resolve({ data: { success: true, students: [{ id: 3, username: 'learnerA' }, { id: 4, username: 'learnerB' }] } });
    if (url.endsWith('/student-workshop-view/3')) return ++reads === 1 ? Promise.resolve(data(42)) : denied.promise;
    if (url.endsWith('/student-workshop-view/4')) return Promise.resolve(data(91));
    return Promise.resolve({ data: {} });
  });
  const view = render(StudentWorkshopView, '/admin/student-workshop-view'); await flush(); await flush();
  const pending = mockRegisterReconciler.mock.calls.at(-1)[0]().catch(error => error); await flush();
  const select = view.node.querySelector('select');
  act(() => { select.value = '4'; select.dispatchEvent(new Event('change', { bubbles: true })); }); await flush();
  await act(async () => { denied.reject(Object.assign(new Error('old learner deleted'), { response: { status: 404 } })); await pending; });
  expect(view.node.textContent).toContain('91'); expect(view.node.textContent).not.toContain('no longer accessible');
  act(() => view.root.unmount());
});

test('student bootstrap failure after unmount is silent', async () => {
  const list = deferred(); axios.get.mockReturnValue(list.promise);
  const view = render(StudentWorkshopView);
  act(() => view.root.unmount());
  await act(async () => list.reject(new Error('late list failure')));
  expect(toast.error).not.toHaveBeenCalled();
});

test('StrictMode retired student bootstrap cannot replace a newer manual selection', async () => {
  const old = deferred(); let lists = 0;
  const students = [{id:3,username:'Alice'},{id:4,username:'Bob'}];
  axios.get.mockImplementation(url => url === '/api/admin/students'
    ? ++lists === 1 ? old.promise : Promise.resolve({data:{success:true,students}})
    : Promise.resolve({data:{success:true,overview:{},challenges:[]}}));
  const node = document.createElement('div'); const root = createRoot(node);
  const view = {node, root};
  act(() => root.render(<React.StrictMode><MemoryRouter><StudentWorkshopView/></MemoryRouter></React.StrictMode>));
  await flush();
  expect(lists).toBe(2);
  const select = view.node.querySelector('select');
  act(() => {select.value='4';select.dispatchEvent(new Event('change',{bubbles:true}));});
  expect(select.value).toBe('4');
  await flush();
  await act(async () => old.resolve({data:{success:true,students}}));
  expect(select.value).toBe('4');
  act(() => view.root.unmount());
});

test('student bootstrap preserves router query selection when list arrives later', async () => {
  const list = deferred();
  axios.get.mockImplementation(url => url === '/api/admin/students' ? list.promise
    : Promise.resolve({data:{success:true,overview:{},challenges:[]}}));
  const view = render(StudentWorkshopView, '/admin/student-workshop-view?studentId=4');
  await flush();
  await act(async () => list.resolve({data:{success:true,students:[{id:3,username:'Alice'},{id:4,username:'Bob'}]}}));
  expect(view.node.querySelector('select').value).toBe('4');
  act(() => view.root.unmount());
});
