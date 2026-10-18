import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import { MemoryRouter } from 'react-router-dom';
import axios from 'axios';
import CTFLeaderboard from './CTFLeaderboard';

jest.mock('axios', () => ({ get: jest.fn() }));

function deferred() {
  let resolve;
  let reject;
  const promise = new Promise((resolvePromise, rejectPromise) => {
    resolve = resolvePromise;
    reject = rejectPromise;
  });
  return { promise, resolve, reject };
}

function createScheduler() {
  const tasks = [];
  return {
    tasks,
    setTimeout(callback, delay) {
      const task = { callback, delay, cancelled: false };
      tasks.push(task);
      return task;
    },
    clearTimeout(task) {
      if (task) task.cancelled = true;
    },
    active() {
      return tasks.filter((task) => !task.cancelled);
    },
    startNext() {
      const index = tasks.findIndex((task) => !task.cancelled);
      if (index < 0) throw new Error('Expected a scheduled leaderboard poll');
      const [task] = tasks.splice(index, 1);
      return { task, promise: task.callback() };
    },
    async runNext() {
      let started;
      await act(async () => {
        started = this.startNext();
        await started.promise;
      });
      await flush();
      return started.task;
    },
  };
}

function createVisibility(initial = 'visible') {
  let state = initial;
  const listeners = new Set();
  return {
    get state() {
      return state;
    },
    subscribe(listener) {
      listeners.add(listener);
      return () => listeners.delete(listener);
    },
    async set(next) {
      state = next;
      listeners.forEach((listener) => listener(next));
      await flush();
    },
  };
}

const row = (username, score = 100) => ({
  participant_id: username,
  username,
  team_name: null,
  total_stages_completed: 1,
  total_completion_time: 1000,
  total_attempts: 1,
  success_rate: 100,
  total_score: score,
  rank_position: 1,
});

const ok = (...rows) => Promise.resolve({ data: { leaderboard: rows } });
const forbidden = () => Promise.reject({ response: { status: 403 } });

async function flush() {
  await act(async () => {
    await Promise.resolve();
    await Promise.resolve();
    await Promise.resolve();
  });
}

function renderLeaderboard({ scheduler, visibility } = {}) {
  const node = document.createElement('div');
  document.body.appendChild(node);
  const root = createRoot(node);
  act(() => {
    root.render(
      <MemoryRouter future={{ v7_startTransition: true, v7_relativeSplatPath: true }}>
        <CTFLeaderboard
          pollerOptions={{ scheduler, visibility, random: () => 0 }}
        />
      </MemoryRouter>,
    );
  });
  return { node, root };
}

beforeEach(() => {
  global.IS_REACT_ACT_ENVIRONMENT = true;
  axios.get.mockReset();
  localStorage.clear();
});

afterEach(() => {
  document.body.innerHTML = '';
});

test('visible polling stays within 15 seconds and silently recovers after transient failure', async () => {
  const scheduler = createScheduler();
  const visibility = createVisibility();
  axios.get
    .mockImplementationOnce(() => ok(row('Alice')))
    .mockRejectedValueOnce(new Error('network offline'))
    .mockImplementationOnce(() => ok(row('Bob', 200)));

  const view = renderLeaderboard({ scheduler, visibility });
  await flush();

  expect(view.node.textContent).toContain('Alice');
  expect(view.node.textContent).toContain('Auto-refresh · 15s');
  expect(scheduler.active()).toHaveLength(1);
  expect(scheduler.active()[0].delay).toBeGreaterThanOrEqual(12000);
  expect(scheduler.active()[0].delay).toBeLessThanOrEqual(15000);

  await scheduler.runNext();
  expect(view.node.textContent).toContain('Alice');
  expect(view.node.textContent).not.toContain('Failed to load leaderboard data.');
  expect(scheduler.active()[0].delay).toBeLessThanOrEqual(15000);

  await scheduler.runNext();
  expect(view.node.textContent).toContain('Bob');
  expect(view.node.textContent).not.toContain('Alice');
  expect(view.node.textContent).not.toContain('Failed to load leaderboard data.');
  act(() => view.root.unmount());
});

test('canonical 403 hides stale rows and manual refresh uses same canonical endpoint', async () => {
  const scheduler = createScheduler();
  const visibility = createVisibility();
  axios.get
    .mockImplementationOnce(() => ok(row('Alice')))
    .mockImplementationOnce(forbidden)
    .mockImplementationOnce(() => ok(row('Carol', 300)));

  const view = renderLeaderboard({ scheduler, visibility });
  await flush();
  await scheduler.runNext();

  expect(view.node.textContent).toContain('Leaderboard is not available at this time.');
  expect(view.node.textContent).not.toContain('Alice');

  const refresh = [...view.node.querySelectorAll('button')]
    .find((button) => button.textContent.includes('Refresh'));
  await act(async () => refresh.click());
  await flush();

  expect(view.node.textContent).toContain('Carol');
  expect(view.node.textContent).not.toContain('Leaderboard is not available at this time.');
  expect(axios.get.mock.calls.every(([url]) => url === '/api/ctf/leaderboard')).toBe(true);
  expect(axios.get.mock.calls.every(([, options]) => options.timeout === 10000)).toBe(true);
  act(() => view.root.unmount());
});

test('hidden tabs pause polling and becoming visible reconciles immediately', async () => {
  const scheduler = createScheduler();
  const visibility = createVisibility();
  axios.get
    .mockImplementationOnce(() => ok(row('Alice')))
    .mockImplementationOnce(() => ok(row('Bob')));

  const view = renderLeaderboard({ scheduler, visibility });
  await flush();
  expect(axios.get).toHaveBeenCalledTimes(1);

  await visibility.set('hidden');
  expect(scheduler.active()).toHaveLength(0);
  await visibility.set('visible');

  expect(axios.get).toHaveBeenCalledTimes(2);
  expect(view.node.textContent).toContain('Bob');
  act(() => view.root.unmount());
});

test('newer manual result wins over older background response', async () => {
  const scheduler = createScheduler();
  const visibility = createVisibility();
  const staleBackground = deferred();
  axios.get
    .mockImplementationOnce(() => ok(row('Alice')))
    .mockImplementationOnce(() => staleBackground.promise)
    .mockImplementationOnce(() => ok(row('Carol', 300)));

  const view = renderLeaderboard({ scheduler, visibility });
  await flush();
  const background = scheduler.startNext().promise;
  await flush();

  const refresh = [...view.node.querySelectorAll('button')]
    .find((button) => button.textContent.includes('Refresh'));
  await act(async () => refresh.click());
  await flush();
  expect(view.node.textContent).toContain('Carol');

  await act(async () => staleBackground.resolve({ data: { leaderboard: [row('Bob')] } }));
  await background;
  await flush();
  expect(view.node.textContent).toContain('Carol');
  expect(view.node.textContent).not.toContain('Bob');
  act(() => view.root.unmount());
});

test('unmount aborts active polling and prevents late writes or timers', async () => {
  const scheduler = createScheduler();
  const visibility = createVisibility();
  const late = deferred();
  let backgroundSignal;
  axios.get
    .mockImplementationOnce(() => ok(row('Alice')))
    .mockImplementationOnce((url, options) => {
      backgroundSignal = options.signal;
      return late.promise;
    });

  const view = renderLeaderboard({ scheduler, visibility });
  await flush();
  const background = scheduler.startNext().promise;
  await flush();
  act(() => view.root.unmount());

  expect(backgroundSignal.aborted).toBe(true);
  await act(async () => late.resolve({ data: { leaderboard: [row('Late')] } }));
  await background;
  await flush();
  expect(view.node.textContent).toBe('');
  expect(scheduler.active()).toHaveLength(0);
});
