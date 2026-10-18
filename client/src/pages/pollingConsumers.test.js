import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import axios from 'axios';
import UserActivity from './UserActivity';
import ProgressAnalyticsPanel from './admin/ProgressAnalyticsPanel';
import { toast } from 'react-toastify';

let mockPollingCallbacks = [];

jest.mock('axios', () => ({ get: jest.fn() }));
jest.mock('../context/AuthContext', () => ({
  useAuth: () => ({ user: { id: 7, lastLogin: null, last_login: null } }),
}));
jest.mock('../hooks/useChangePolling', () => ({
  __esModule: true,
  default: (callback) => {
    mockPollingCallbacks.push(callback);
  },
}));
jest.mock('react-toastify', () => ({
  toast: { error: jest.fn(), success: jest.fn() },
}));
jest.mock('react-router-dom', () => ({
  ...jest.requireActual('react-router-dom'),
  useNavigate: () => jest.fn(),
}));

function deferred() {
  let resolve;
  let reject;
  const promise = new Promise((resolvePromise, rejectPromise) => {
    resolve = resolvePromise;
    reject = rejectPromise;
  });
  return { promise, resolve, reject };
}

async function flush() {
  await act(async () => {
    await Promise.resolve();
    await Promise.resolve();
    await Promise.resolve();
  });
}

function render(Component) {
  const node = document.createElement('div');
  const root = createRoot(node);
  act(() => root.render(<Component />));
  return { node, root };
}

beforeEach(() => {
  global.IS_REACT_ACT_ENVIRONMENT = true;
  mockPollingCallbacks = [];
  axios.get.mockReset();
  toast.error.mockReset();
});

test('UserActivity serializes baseline reconciliation after initial load and newest data wins', async () => {
  const initialActivity = deferred();
  const initialProgress = deferred();
  const backgroundActivity = deferred();
  const backgroundProgress = deferred();
  axios.get
    .mockImplementationOnce(() => initialActivity.promise)
    .mockImplementationOnce(() => initialProgress.promise)
    .mockImplementationOnce(() => backgroundActivity.promise)
    .mockImplementationOnce(() => backgroundProgress.promise);

  const view = render(UserActivity);
  const poll = mockPollingCallbacks.at(-1)();
  expect(axios.get).toHaveBeenCalledTimes(2);

  await act(async () => {
    initialActivity.resolve({ data: { activity: [{ id: 1, title: 'Old activity' }] } });
    initialProgress.resolve({ data: { challenges: [] } });
  });
  await flush();
  expect(axios.get).toHaveBeenCalledTimes(4);

  await act(async () => {
    backgroundActivity.resolve({ data: { activity: [{ id: 2, title: 'Current activity' }] } });
    backgroundProgress.resolve({
      data: { challenges: [{ status: 'completed', completedObjectiveCount: 3 }] },
    });
    await poll;
  });
  expect(view.node.textContent).toContain('Current activity');
  expect(view.node.textContent).not.toContain('Old activity');
  expect(view.node.textContent).toContain('Objectives Done');
  act(() => view.root.unmount());
});

test('ProgressAnalyticsPanel serializes initial and background requests and suppresses background errors', async () => {
  const initial = deferred();
  const background = deferred();
  axios.get
    .mockImplementationOnce(() => initial.promise)
    .mockImplementationOnce(() => background.promise);

  const view = render(ProgressAnalyticsPanel);
  const poll = mockPollingCallbacks.at(-1)();
  expect(axios.get).toHaveBeenCalledTimes(1);

  await act(async () => initial.resolve({
    data: {
      overview: { totalObjectiveCompletions: 1 },
      progressOverTime: [], studentProgress: [], challengeStats: [], topPerformers: [],
    },
  }));
  await flush();
  expect(axios.get).toHaveBeenCalledTimes(2);

  const rejectedPoll = expect(poll).rejects.toThrow('poll offline');
  await act(async () => background.reject(new Error('poll offline')));
  await rejectedPoll;
  expect(view.node.textContent).toContain('Objective Completions');
  expect(view.node.textContent).toContain('1');
  expect(toast.error).not.toHaveBeenCalled();
  act(() => view.root.unmount());
});

test('ProgressAnalyticsPanel retires student data when a background refresh loses access', async () => {
  axios.get.mockResolvedValueOnce({ data: {
    overview: { totalObjectiveCompletions: 1 }, progressOverTime: [],
    studentProgress: [{ username: 'Learner A' }], challengeStats: [], topPerformers: [],
  }}).mockRejectedValueOnce({ response: { status: 403, data: { error: 'Forbidden' } } });
  const view = render(ProgressAnalyticsPanel);
  await flush();
  expect(view.node.textContent).toContain('Learner A');
  await act(async () => {
    await expect(mockPollingCallbacks.at(-1)()).rejects.toMatchObject({ response: { status: 403 } });
  });
  expect(view.node.textContent).toContain('No Analytics Data');
  expect(view.node.textContent).not.toContain('Learner A');
  expect(view.node.textContent).not.toContain('Export CSV');
  act(() => view.root.unmount());
});

test('late standalone consumer responses do not write after unmount', async () => {
  const activity = deferred();
  const progress = deferred();
  axios.get
    .mockImplementationOnce(() => activity.promise)
    .mockImplementationOnce(() => progress.promise);
  const view = render(UserActivity);
  act(() => view.root.unmount());

  await act(async () => {
    activity.resolve({ data: { activity: [{ id: 1, title: 'Late activity' }] } });
    progress.resolve({ data: { challenges: [] } });
  });
  await flush();

  expect(view.node.textContent).toBe('');
  expect(toast.error).not.toHaveBeenCalled();
});

test('UserActivity aborts a timed-out background reconciliation and ignores its late data', async () => {
  const initialActivity = deferred();
  const initialProgress = deferred();
  const lateActivity = deferred();
  const lateProgress = deferred();
  axios.get
    .mockImplementationOnce(() => initialActivity.promise)
    .mockImplementationOnce(() => initialProgress.promise)
    .mockImplementationOnce(() => lateActivity.promise)
    .mockImplementationOnce(() => lateProgress.promise);

  const view = render(UserActivity);
  await act(async () => {
    initialActivity.resolve({ data: { activity: [{ id: 1, title: 'Retained activity' }] } });
    initialProgress.resolve({ data: { challenges: [] } });
  });
  await flush();
  const controller = new AbortController();
  const poll = mockPollingCallbacks.at(-1)(null, null, { signal: controller.signal });
  expect(axios.get.mock.calls.at(-1)[1].signal).toBe(controller.signal);

  controller.abort();
  await act(async () => {
    lateActivity.resolve({ data: { activity: [{ id: 2, title: 'Late activity' }] } });
    lateProgress.resolve({ data: { challenges: [] } });
    await poll;
  });
  expect(view.node.textContent).toContain('Retained activity');
  expect(view.node.textContent).not.toContain('Late activity');
  act(() => view.root.unmount());
});

test('ProgressAnalyticsPanel aborts a timed-out background reconciliation and ignores its late data', async () => {
  const initial = deferred();
  const late = deferred();
  axios.get.mockImplementationOnce(() => initial.promise).mockImplementationOnce(() => late.promise);
  const view = render(ProgressAnalyticsPanel);
  await act(async () => initial.resolve({
    data: { overview: { totalObjectiveCompletions: 1 }, progressOverTime: [], studentProgress: [], challengeStats: [], topPerformers: [] },
  }));
  await flush();
  const controller = new AbortController();
  const poll = mockPollingCallbacks.at(-1)(null, null, { signal: controller.signal });
  expect(axios.get.mock.calls.at(-1)[1].signal).toBe(controller.signal);

  controller.abort();
  await act(async () => {
    late.resolve({
      data: { overview: { totalObjectiveCompletions: 99 }, progressOverTime: [], studentProgress: [], challengeStats: [], topPerformers: [] },
    });
    await poll;
  });
  expect(view.node.textContent).toContain('1');
  expect(view.node.textContent).not.toContain('99');
  act(() => view.root.unmount());
});
