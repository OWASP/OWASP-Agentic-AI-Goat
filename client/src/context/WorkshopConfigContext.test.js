import React, { act, useEffect } from 'react';
import { createRoot } from 'react-dom/client';
import { MemoryRouter } from 'react-router-dom';
import axios from 'axios';
import {
  WorkshopConfigProvider,
  buildWorkshopConfigUrls,
  useWorkshopConfig,
} from './WorkshopConfigContext';
import WorkshopChallenges from '../pages/WorkshopChallenges';

jest.mock('axios', () => ({
  get: jest.fn(),
  defaults: {},
}));
jest.mock('../components/HintPanel', () => () => <button type="button">Hint control</button>);
jest.mock('../components/SolutionPanel', () => () => <button type="button">Solution control</button>);

const snapshot = (revision, exercises = {}) => ({ revision, exercises });
const appChanges = (workshops = {}) => ({
  revisions: { global: {}, workshops, user: {} },
});

const flush = async () => {
  await act(async () => {
    await Promise.resolve();
    await Promise.resolve();
    await Promise.resolve();
    await Promise.resolve();
    await Promise.resolve();
    await Promise.resolve();
  });
};

const deferred = () => {
  let resolve;
  let reject;
  const promise = new Promise((resolvePromise, rejectPromise) => {
    resolve = resolvePromise;
    reject = rejectPromise;
  });
  return { promise, resolve, reject };
};

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
    async runNext() {
      const index = tasks.findIndex((task) => !task.cancelled);
      if (index < 0) throw new Error('Expected scheduled poll');
      const [task] = tasks.splice(index, 1);
      await act(async () => task.callback());
      await flush();
      return task;
    },
    active() {
      return tasks.filter((task) => !task.cancelled);
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

function renderProvider({ token = 'token', scheduler, visibility, reconciler, pollerOptions = {}, ...props } = {}) {
  let latest;
  function Probe() {
    latest = useWorkshopConfig();
    useEffect(() => (
      reconciler ? latest.registerReconciler(reconciler) : undefined
    ), [latest.registerReconciler]);
    return null;
  }

  const node = document.createElement('div');
  const root = createRoot(node);
  const render = (nextToken = token) => act(() => {
    root.render(
      <WorkshopConfigProvider
        token={nextToken}
        pollerOptions={{ scheduler, visibility, random: () => 0, ...pollerOptions }}
        {...props}
      >
        <Probe />
      </WorkshopConfigProvider>
    );
  });
  render(token);
  return { getLatest: () => latest, render, root };
}

function renderChallengesProvider({ token = 'token', scheduler, visibility } = {}) {
  const node = document.createElement('div');
  const root = createRoot(node);
  act(() => {
    root.render(
      <MemoryRouter>
        <WorkshopConfigProvider
          token={token}
          pollerOptions={{ scheduler, visibility, random: () => 0 }}
        >
          <WorkshopChallenges />
        </WorkshopConfigProvider>
      </MemoryRouter>
    );
  });
  return { node, root };
}

beforeEach(() => {
  global.IS_REACT_ACT_ENVIRONMENT = true;
  axios.get.mockReset();
  Object.defineProperty(document, 'visibilityState', { configurable: true, value: 'visible' });
});

afterEach(() => {
  jest.restoreAllMocks();
});

test('initial mount loads the authoritative snapshot', async () => {
  const scheduler = createScheduler();
  const visibility = createVisibility();
  axios.get.mockImplementation((url) => Promise.resolve({
    data: url.endsWith('/changes/revisions')
      ? appChanges()
      : url.endsWith('/revision')
        ? { revision: 4 }
        : snapshot(4, { direct_prompt_injection: {} }),
  }));

  const view = renderProvider({ scheduler, visibility });
  await flush();

  expect(view.getLatest().revision).toBe(4);
  expect(view.getLatest().snapshot).toEqual(snapshot(4, { direct_prompt_injection: {} }));
  expect(view.getLatest().error).toBeNull();
  act(() => view.root.unmount());
});

test('foreground snapshot refresh keeps its request free of the polling deadline', async () => {
  const scheduler = createScheduler();
  const visibility = createVisibility();
  let snapshotCall = 0;
  axios.get.mockImplementation((url) => {
    if (url.endsWith('/changes/revisions')) return Promise.resolve({ data: appChanges() });
    if (url.endsWith('/revision')) return Promise.resolve({ data: { revision: 1 } });
    snapshotCall += 1;
    return Promise.resolve({ data: snapshot(snapshotCall, { [`revision_${snapshotCall}`]: {} }) });
  });
  const view = renderProvider({ scheduler, visibility });
  await flush();
  axios.get.mockClear();

  await view.getLatest().refresh(2);
  const [, config] = axios.get.mock.calls.find(([url]) => url.endsWith('/snapshot'));
  expect(config.timeout).toBeUndefined();
  expect(view.getLatest().revision).toBe(2);
  act(() => view.root.unmount());
});

test('one newer polled revision causes exactly one canonical snapshot refetch', async () => {
  const scheduler = createScheduler();
  const visibility = createVisibility();
  let revision = 1;
  let appRevision = 1;
  axios.get.mockImplementation((url) => Promise.resolve({
    data: url.endsWith('/changes/revisions')
      ? appChanges({ xss_workshop: { visibility: appRevision } })
      : url.endsWith('/revision')
        ? { revision }
        : snapshot(revision, { [`revision_${revision}`]: {} }),
  }));
  const view = renderProvider({ scheduler, visibility });
  await flush();
  axios.get.mockClear();

  revision = 2;
  appRevision = 2;
  await scheduler.runNext();

  expect(axios.get.mock.calls.filter(([url]) => url.endsWith('/revision'))).toHaveLength(1);
  expect(axios.get.mock.calls.filter(([url]) => url.endsWith('/snapshot'))).toHaveLength(1);
  expect(view.getLatest().revision).toBe(2);
  act(() => view.root.unmount());
});

test('student progress revision refreshes mounted consumers while config snapshot is unavailable', async () => {
  const scheduler = createScheduler();
  const visibility = createVisibility();
  const reconciler = jest.fn(async () => {});
  let progressRevision = 1;
  let timeRevision = 1;
  let snapshotCalls = 0;
  axios.get.mockImplementation((url) => {
    if (url.endsWith('/changes/revisions')) return Promise.resolve({
      data: { revisions: { global: {}, workshops: {}, user: {
        workshop_progress: progressRevision, workshop_time: timeRevision,
      } } },
    });
    if (url.endsWith('/revision')) return Promise.resolve({ data: { revision: 4 } });
    snapshotCalls += 1;
    if (snapshotCalls > 2) return Promise.reject(new Error('config snapshot offline'));
    return Promise.resolve({ data: snapshot(4, { direct_prompt_injection: {} }) });
  });
  const view = renderProvider({ scheduler, visibility, reconciler });
  await flush();
  expect(snapshotCalls).toBe(2);
  reconciler.mockClear();

  progressRevision = 2;
  await scheduler.runNext();

  expect(snapshotCalls).toBe(2);
  expect(reconciler).toHaveBeenCalledTimes(1);
  timeRevision = 2;
  await scheduler.runNext();
  expect(snapshotCalls).toBe(2);
  expect(reconciler).toHaveBeenCalledTimes(2);
  expect(view.getLatest().revision).toBe(4);
  act(() => view.root.unmount());
});

test('permitted admin aggregate revision refreshes mounted student views without a config read', async () => {
  const scheduler = createScheduler();
  const visibility = createVisibility();
  const reconciler = jest.fn(async () => {});
  let adminProgress = 'first';
  let snapshotCalls = 0;
  axios.get.mockImplementation((url) => {
    if (url.endsWith('/changes/revisions')) return Promise.resolve({
      data: { revisions: { global: {}, workshops: {}, user: {}, adminProgress } },
    });
    if (url.endsWith('/revision')) return Promise.resolve({ data: { revision: 4 } });
    snapshotCalls += 1;
    return Promise.resolve({ data: snapshot(4, {}) });
  });
  const view = renderProvider({ scheduler, visibility, reconciler });
  await flush();
  reconciler.mockClear();
  const baselineSnapshotCalls = snapshotCalls;

  adminProgress = 'second';
  await scheduler.runNext();

  expect(reconciler).toHaveBeenCalledTimes(1);
  expect(snapshotCalls).toBe(baselineSnapshotCalls);
  act(() => view.root.unmount());
});

test('same or older polled revisions do not refetch the snapshot', async () => {
  const scheduler = createScheduler();
  const visibility = createVisibility();
  let revision = 3;
  axios.get.mockImplementation((url) => Promise.resolve({
    data: url.endsWith('/changes/revisions')
      ? appChanges()
      : url.endsWith('/revision')
        ? { revision }
        : snapshot(3, { retained: {} }),
  }));
  const view = renderProvider({ scheduler, visibility });
  await flush();
  axios.get.mockClear();

  await scheduler.runNext();
  revision = 2;
  await scheduler.runNext();

  expect(axios.get.mock.calls.filter(([url]) => url.endsWith('/snapshot'))).toHaveLength(0);
  expect(view.getLatest().revision).toBe(3);
  act(() => view.root.unmount());
});

test('first app-change baseline refreshes config after an initial snapshot race', async () => {
  const scheduler = createScheduler();
  const visibility = createVisibility();
  const configBaseline = deferred();
  const appBaseline = deferred();
  let hintVisible = false;
  let snapshotAttempts = 0;
  axios.get.mockImplementation((url) => {
    if (url.endsWith('/changes/revisions')) return appBaseline.promise;
    if (url.endsWith('/revision')) return configBaseline.promise;
    snapshotAttempts += 1;
    return Promise.resolve({
      data: snapshot(4, {
        xss_workshop: { objectives: { reflected: { hintVisible } } },
      }),
    });
  });
  const view = renderProvider({ scheduler, visibility });
  await flush();
  expect(view.getLatest().snapshot.exercises.xss_workshop.objectives.reflected.hintVisible).toBe(false);

  hintVisible = true;
  await act(async () => {
    configBaseline.resolve({ data: { revision: 4 } });
    appBaseline.resolve({ data: appChanges({ xss_workshop: { visibility: 2 } }) });
  });
  await flush();

  expect(snapshotAttempts).toBe(2);
  expect(view.getLatest().snapshot.exercises.xss_workshop.objectives.reflected.hintVisible).toBe(true);
  act(() => view.root.unmount());
});

test('failed first app-change baseline refresh retries before accepting baseline', async () => {
  const scheduler = createScheduler();
  const visibility = createVisibility();
  let snapshotAttempts = 0;
  axios.get.mockImplementation((url) => {
    if (url.endsWith('/changes/revisions')) {
      return Promise.resolve({ data: appChanges({ xss_workshop: { visibility: 2 } }) });
    }
    if (url.endsWith('/revision')) return Promise.resolve({ data: { revision: 4 } });
    snapshotAttempts += 1;
    if (snapshotAttempts === 2) return Promise.reject(new Error('baseline config offline'));
    return Promise.resolve({
      data: snapshot(4, {
        xss_workshop: { objectives: { reflected: { hintVisible: snapshotAttempts > 2 } } },
      }),
    });
  });
  const view = renderProvider({ scheduler, visibility });
  await flush();

  expect(snapshotAttempts).toBe(2);
  expect(view.getLatest().snapshot.exercises.xss_workshop.objectives.reflected.hintVisible).toBe(false);
  expect(view.getLatest().error).toBeNull();

  await scheduler.runNext();
  expect(snapshotAttempts).toBe(3);
  expect(view.getLatest().snapshot.exercises.xss_workshop.objectives.reflected.hintVisible).toBe(true);
  act(() => view.root.unmount());
});

test('a timed-out canonical reconciliation aborts its snapshot, keeps last-good state, and retries', async () => {
  const scheduler = createScheduler();
  const visibility = createVisibility();
  const timedOutSnapshot = deferred();
  let snapshotCalls = 0;
  let timedOutSignal;
  axios.get.mockImplementation((url, config = {}) => {
    if (url.endsWith('/changes/revisions')) return Promise.resolve({ data: appChanges() });
    if (url.endsWith('/revision')) return Promise.resolve({ data: { revision: 2 } });
    snapshotCalls += 1;
    if (snapshotCalls === 1) return Promise.resolve({ data: snapshot(1, { retained: {} }) });
    if (snapshotCalls === 2) {
      timedOutSignal = config.signal;
      return timedOutSnapshot.promise;
    }
    return Promise.resolve({ data: snapshot(2, { recovered: {} }) });
  });

  const view = renderProvider({
    scheduler,
    visibility,
    pollerOptions: { reconciliationTimeoutMs: 100, reconciliationScheduler: scheduler },
  });
  await flush();
  expect(view.getLatest().snapshot).toEqual(snapshot(1, { retained: {} }));
  const deadline = scheduler.tasks.find((task) => task.delay === 100 && !task.cancelled);
  expect(deadline).toBeDefined();

  await act(async () => deadline.callback());
  await flush();
  expect(timedOutSignal.aborted).toBe(true);
  expect(view.getLatest().snapshot).toEqual(snapshot(1, { retained: {} }));
  expect(view.getLatest().error).toBeNull();
  expect(view.getLatest().stale).toBe(false);

  await act(async () => timedOutSnapshot.resolve({ data: snapshot(2, { stale: {} }) }));
  await flush();
  expect(view.getLatest().snapshot).toEqual(snapshot(1, { retained: {} }));

  await scheduler.runNext();
  expect(view.getLatest().snapshot).toEqual(snapshot(2, { recovered: {} }));
  act(() => view.root.unmount());
});

test('legacy app change refreshes canonical snapshot when workshop config revision is unchanged', async () => {
  const scheduler = createScheduler();
  const visibility = createVisibility();
  let appRevision = 1;
  let hintVisible = false;
  axios.get.mockImplementation((url) => {
    if (url.endsWith('/changes/revisions')) {
      return Promise.resolve({ data: { revisions: { global: {}, workshops: { xss_workshop: { visibility: appRevision } }, user: {} } } });
    }
    if (url.endsWith('/revision')) return Promise.resolve({ data: { revision: 4 } });
    return Promise.resolve({
      data: snapshot(4, {
        xss_workshop: { objectives: { reflected: { hintVisible } } },
      }),
    });
  });
  const view = renderProvider({ scheduler, visibility });
  await flush();
  axios.get.mockClear();

  appRevision = 2;
  hintVisible = true;
  await scheduler.runNext();

  expect(axios.get.mock.calls.filter(([url]) => url.endsWith('/changes/revisions'))).toHaveLength(1);
  expect(axios.get.mock.calls.find(([url]) => url.endsWith('/changes/revisions'))[1]).toEqual(expect.objectContaining({
    headers: { Authorization: 'Bearer token' },
    params: { workshops: '*' },
  }));
  expect(axios.get.mock.calls.filter(([url]) => url.endsWith('/snapshot'))).toHaveLength(1);
  expect(view.getLatest().snapshot.exercises.xss_workshop.objectives.reflected.hintVisible).toBe(true);
  act(() => view.root.unmount());
});

test('failed legacy app-change refresh keeps last-good snapshot and retries same signal', async () => {
  const scheduler = createScheduler();
  const visibility = createVisibility();
  let appRevision = 1;
  let snapshotAttempts = 0;
  axios.get.mockImplementation((url) => {
    if (url.endsWith('/changes/revisions')) {
      return Promise.resolve({ data: { revisions: { global: {}, workshops: { supply_chain: { hints: appRevision } }, user: {} } } });
    }
    if (url.endsWith('/revision')) return Promise.resolve({ data: { revision: 9 } });
    snapshotAttempts += 1;
    if (snapshotAttempts === 3) return Promise.reject(new Error('canonical snapshot offline'));
    return Promise.resolve({
      data: snapshot(9, {
        supply_chain: { objectives: { package_confusion: { hintVisible: snapshotAttempts > 3 } } },
      }),
    });
  });
  const view = renderProvider({ scheduler, visibility });
  await flush();

  appRevision = 2;
  await scheduler.runNext();
  expect(view.getLatest().snapshot.exercises.supply_chain.objectives.package_confusion.hintVisible).toBe(false);
  expect(view.getLatest().error).toBeNull();
  expect(view.getLatest().stale).toBe(false);

  await scheduler.runNext();
  expect(snapshotAttempts).toBe(4);
  expect(view.getLatest().snapshot.exercises.supply_chain.objectives.package_confusion.hintVisible).toBe(true);
  act(() => view.root.unmount());
});

test('WorkshopChallenges shows legacy hint control after app-change reconciliation', async () => {
  const scheduler = createScheduler();
  const visibility = createVisibility();
  let appRevision = 1;
  let hintVisible = false;
  axios.get.mockImplementation((url) => {
    if (url === '/api/workshop/challenges') {
      return Promise.resolve({
        data: {
          challenges: [{
            id: 'xss_workshop',
            workshopKey: 'xss_workshop',
            title: 'XSS Workshop',
            description: 'Legacy visibility owner',
            difficulty: 'Beginner',
            status: 'unlocked',
            route: '/workshop/xss',
            objectives: [{ id: 'reflected', text: 'Reflected XSS', completed: false }],
          }],
        },
      });
    }
    if (url.endsWith('/changes/revisions')) {
      return Promise.resolve({ data: { revisions: { global: {}, workshops: { xss_workshop: { visibility: appRevision } }, user: {} } } });
    }
    if (url.endsWith('/revision')) return Promise.resolve({ data: { revision: 6 } });
    return Promise.resolve({
      data: snapshot(6, {
        xss_workshop: { objectives: { reflected: { hintVisible, solutionVisible: false } } },
      }),
    });
  });
  const view = renderChallengesProvider({ scheduler, visibility });
  await flush();
  expect(view.node.textContent).not.toContain('Hint control');

  appRevision = 2;
  hintVisible = true;
  await scheduler.runNext();

  expect(view.node.textContent).toContain('Hint control');
  act(() => view.root.unmount());
});

test('late lower snapshot cannot overwrite a newer announced high-water revision', async () => {
  const scheduler = createScheduler();
  const visibility = createVisibility();
  const revisionEight = deferred();
  const revisionNine = deferred();
  let revision = 7;
  let snapshotCalls = 0;
  axios.get.mockImplementation((url) => {
    if (url.endsWith('/changes/revisions')) return Promise.resolve({ data: appChanges() });
    if (url.endsWith('/revision')) return Promise.resolve({ data: { revision } });
    snapshotCalls += 1;
    if (snapshotCalls <= 2) return Promise.resolve({ data: snapshot(7, { retained: {} }) });
    if (snapshotCalls === 3) return revisionEight.promise;
    return revisionNine.promise;
  });
  const view = renderProvider({ scheduler, visibility });
  await flush();

  revision = 8;
  const scheduledIndex = scheduler.tasks.findIndex((task) => !task.cancelled);
  const [scheduledPoll] = scheduler.tasks.splice(scheduledIndex, 1);
  const poll = scheduledPoll.callback();
  await flush();
  const manual = view.getLatest().refresh(9);
  await act(async () => revisionEight.resolve({ data: snapshot(8, { stale: {} }) }));
  await flush();

  expect(view.getLatest().revision).toBe(7);
  expect(view.getLatest().snapshot.exercises).toEqual({ retained: {} });

  await act(async () => revisionNine.resolve({ data: snapshot(9, { current: {} }) }));
  await Promise.all([poll, manual]);
  await flush();
  expect(view.getLatest().revision).toBe(9);
  expect(view.getLatest().snapshot.exercises).toEqual({ current: {} });
  act(() => view.root.unmount());
});

test('failed background snapshot keeps last-good state silent and retries the same revision', async () => {
  const scheduler = createScheduler();
  const visibility = createVisibility();
  let revision = 7;
  let snapshotCalls = 0;
  axios.get.mockImplementation((url) => {
    if (url.endsWith('/changes/revisions')) return Promise.resolve({ data: appChanges() });
    if (url.endsWith('/revision')) return Promise.resolve({ data: { revision } });
    snapshotCalls += 1;
    if (snapshotCalls <= 2) return Promise.resolve({ data: snapshot(7, { retained: {} }) });
    if (snapshotCalls === 3) return Promise.reject(new Error('snapshot offline'));
    return Promise.resolve({ data: snapshot(8, { recovered: {} }) });
  });
  const view = renderProvider({ scheduler, visibility });
  await flush();

  revision = 8;
  await scheduler.runNext();
  expect(view.getLatest().snapshot).toEqual(snapshot(7, { retained: {} }));
  expect(view.getLatest().error).toBeNull();
  expect(view.getLatest().stale).toBe(false);

  await scheduler.runNext();
  expect(view.getLatest().snapshot).toEqual(snapshot(8, { recovered: {} }));
  expect(snapshotCalls).toBe(4);
  act(() => view.root.unmount());
});

test('background app-change revision failure is silent and a later poll recovers', async () => {
  const scheduler = createScheduler();
  const visibility = createVisibility();
  let revision = 1;
  let failAppChanges = false;
  axios.get.mockImplementation((url) => {
    if (url.endsWith('/changes/revisions')) {
      if (failAppChanges) return Promise.reject(new Error('app changes offline'));
      return Promise.resolve({ data: appChanges() });
    }
    if (url.endsWith('/revision')) {
      return Promise.resolve({ data: { revision } });
    }
    return Promise.resolve({ data: snapshot(revision, { [`revision_${revision}`]: {} }) });
  });
  const view = renderProvider({ scheduler, visibility });
  await flush();

  failAppChanges = true;
  await scheduler.runNext();
  expect(view.getLatest().snapshot).toEqual(snapshot(1, { revision_1: {} }));
  expect(view.getLatest().error).toBeNull();

  failAppChanges = false;
  revision = 2;
  await scheduler.runNext();
  expect(view.getLatest().revision).toBe(2);
  expect(view.getLatest().error).toBeNull();
  act(() => view.root.unmount());
});

test('same app-change signal retries when a mounted consumer canonical reconciliation fails', async () => {
  const scheduler = createScheduler();
  const visibility = createVisibility();
  let appRevision = 1;
  let consumerAttempts = 0;
  let failNextConsumerRefresh = false;
  const reconciler = jest.fn(async () => {
    consumerAttempts += 1;
    if (failNextConsumerRefresh) {
      failNextConsumerRefresh = false;
      throw new Error('dashboard refresh offline');
    }
  });
  axios.get.mockImplementation((url) => Promise.resolve({
    data: url.endsWith('/changes/revisions')
      ? appChanges({ xss_workshop: { visibility: appRevision } })
      : url.endsWith('/revision')
        ? { revision: 1 }
        : snapshot(1),
  }));
  const view = renderProvider({ scheduler, visibility, reconciler });
  await flush();
  const baselineAttempts = consumerAttempts;

  appRevision = 2;
  failNextConsumerRefresh = true;
  await scheduler.runNext();
  expect(view.getLatest().revision).toBe(1);
  expect(consumerAttempts).toBe(baselineAttempts + 1);

  await scheduler.runNext();
  expect(consumerAttempts).toBe(baselineAttempts + 2);
  act(() => view.root.unmount());
});

test('token replacement ignores late old-token snapshot and revision results', async () => {
  const scheduler = createScheduler();
  const visibility = createVisibility();
  const oldSnapshot = deferred();
  const oldRevision = deferred();
  axios.get.mockImplementation((url, config) => {
    const authorization = config.headers.Authorization;
    if (authorization === 'Bearer old-token') {
      return url.endsWith('/revision') ? oldRevision.promise : oldSnapshot.promise;
    }
    return Promise.resolve({
      data: url.endsWith('/changes/revisions')
        ? appChanges()
        : url.endsWith('/revision')
          ? { revision: 5 }
          : snapshot(5, { current: {} }),
    });
  });
  const view = renderProvider({ token: 'old-token', scheduler, visibility });
  view.render('new-token');
  await flush();

  await act(async () => {
    oldSnapshot.resolve({ data: snapshot(99, { stale: {} }) });
    oldRevision.resolve({ data: { revision: 99 } });
  });
  await flush();

  expect(view.getLatest().revision).toBe(5);
  expect(view.getLatest().snapshot.exercises).toEqual({ current: {} });
  act(() => view.root.unmount());
});

test('unmount cancels scheduled checks and late revision cannot start a snapshot', async () => {
  const scheduler = createScheduler();
  const visibility = createVisibility();
  const pendingRevision = deferred();
  let initialRevisionRead = true;
  axios.get.mockImplementation((url) => {
    if (url.endsWith('/changes/revisions')) return Promise.resolve({ data: appChanges() });
    if (url.endsWith('/revision')) {
      if (initialRevisionRead) {
        initialRevisionRead = false;
        return Promise.resolve({ data: { revision: 1 } });
      }
      return pendingRevision.promise;
    }
    return Promise.resolve({ data: snapshot(1) });
  });
  const view = renderProvider({ scheduler, visibility });
  await flush();
  const scheduled = scheduler.runNext();
  await flush();
  const callsBeforeUnmount = axios.get.mock.calls.length;
  act(() => view.root.unmount());
  await act(async () => pendingRevision.resolve({ data: { revision: 2 } }));
  await scheduled;

  expect(axios.get).toHaveBeenCalledTimes(callsBeforeUnmount);
  expect(scheduler.active()).toHaveLength(0);
});

test('hidden tab suppresses revision polling and visibility return checks immediately', async () => {
  const scheduler = createScheduler();
  const visibility = createVisibility('hidden');
  axios.get.mockImplementation((url) => Promise.resolve({
    data: url.endsWith('/changes/revisions')
      ? appChanges()
      : url.endsWith('/revision')
        ? { revision: 1 }
        : snapshot(1),
  }));
  const view = renderProvider({ scheduler, visibility });
  await flush();

  expect(axios.get.mock.calls.filter(([url]) => url.endsWith('/revision'))).toHaveLength(0);
  expect(scheduler.active()).toHaveLength(0);

  await visibility.set('visible');
  expect(axios.get.mock.calls.filter(([url]) => url.endsWith('/revision'))).toHaveLength(1);
  expect(scheduler.active()).toHaveLength(1);
  act(() => view.root.unmount());
});

test('manual remount reaches same canonical state as polling reconciliation', async () => {
  const scheduler = createScheduler();
  const visibility = createVisibility();
  let revision = 1;
  axios.get.mockImplementation((url) => Promise.resolve({
    data: url.endsWith('/changes/revisions')
      ? appChanges()
      : url.endsWith('/revision')
        ? { revision }
        : snapshot(revision, { [`revision_${revision}`]: {} }),
  }));
  const first = renderProvider({ scheduler, visibility });
  await flush();
  revision = 2;
  await scheduler.runNext();
  const polledState = first.getLatest().snapshot;
  act(() => first.root.unmount());

  const second = renderProvider({ scheduler: createScheduler(), visibility: createVisibility() });
  await flush();
  expect(second.getLatest().snapshot).toEqual(polledState);
  act(() => second.root.unmount());
});

test('URL derivation supports deployed API base paths without socket URLs', () => {
  expect(buildWorkshopConfigUrls({
    apiBaseUrl: 'https://example.test/training/api/',
    locationOrigin: 'http://localhost:3000',
  })).toEqual({
    snapshotUrl: 'https://example.test/training/api/workshop/config/snapshot',
    revisionUrl: 'https://example.test/training/api/workshop/config/revision',
    appChangesRevisionUrl: 'https://example.test/training/api/changes/revisions',
  });

  expect(buildWorkshopConfigUrls({
    apiBaseUrl: '',
    locationOrigin: 'http://localhost:3000',
  })).toEqual({
    snapshotUrl: '/api/workshop/config/snapshot',
    revisionUrl: '/api/workshop/config/revision',
    appChangesRevisionUrl: '/api/changes/revisions',
  });
});


test('mutation readback supersedes older in-flight snapshot while polling is hidden', async () => {
  const old=deferred(), fresh=deferred();let reads=0;
  axios.get.mockImplementation(url=>{
    if(url.includes('/snapshot'))return ++reads===1?old.promise:fresh.promise;
    throw new Error('Hidden poll must not run');
  });
  const view=renderProvider({scheduler:createScheduler(),visibility:createVisibility('hidden')});
  await flush();const oldSignal=axios.get.mock.calls[0][1].signal;let result;
  await act(async()=>{result=view.getLatest().refreshAfterMutation();});
  expect(oldSignal.aborted).toBe(true);expect(reads).toBe(2);
  const next=snapshot(2,{sql_injection_workshop:{showHints:false,showSolutions:true}});
  await act(async()=>fresh.resolve({data:next}));expect(await result).toEqual(next);
  await act(async()=>old.resolve({data:snapshot(1,{sql_injection_workshop:{showHints:true}})}));await flush();
  expect(view.getLatest().snapshot).toEqual(next);act(()=>view.root.unmount());
});
test('mutation readback abort settles without late publication; token replacement fences response', async () => {
  for(const retire of ['abort','token']){
    const held=deferred();let reads=0;
    axios.get.mockImplementation((_url,config)=>config.headers.Authorization==='Bearer new-token'?Promise.resolve({data:snapshot(3,{newSession:true})}):++reads===1?Promise.resolve({data:snapshot(1,{})}):held.promise);
    const view=renderProvider({scheduler:createScheduler(),visibility:createVisibility('hidden')});await flush();
    const controller=new AbortController();let result;await act(async()=>{result=view.getLatest().refreshAfterMutation({signal:controller.signal});});
    const passed=axios.get.mock.calls.at(-1)[1].signal;
    if(retire==='abort'){await act(async()=>controller.abort());expect(await result).toBeNull();}else {view.render('new-token');await flush();}
    expect(passed.aborted).toBe(true);
    await act(async()=>held.resolve({data:snapshot(2,{oldPrivate:true})}));await result;await flush();
    if(retire==='abort')expect(view.getLatest().snapshot).toEqual(snapshot(1,{}));
    else expect(view.getLatest().snapshot).toEqual(snapshot(3,{newSession:true}));
    act(()=>view.root.unmount());axios.get.mockClear();
  }
});

test('mutation readback deadline aborts a noncooperative request and rejects its late publication', async () => {
  jest.useFakeTimers();const held=deferred();let reads=0;let view;
  try {
    axios.get.mockImplementation(()=>++reads===1?Promise.resolve({data:snapshot(1,{})}):held.promise);
    view=renderProvider({scheduler:createScheduler(),visibility:createVisibility('hidden')});await flush();
    let result;await act(async()=>{result=view.getLatest().refreshAfterMutation();});const signal=axios.get.mock.calls.at(-1)[1].signal;
    await act(async()=>jest.advanceTimersByTime(10000));expect(await result).toBeNull();expect(signal.aborted).toBe(true);
    await act(async()=>held.resolve({data:snapshot(2,{late:true})}));await flush();expect(view.getLatest().snapshot).toEqual(snapshot(1,{}));
  } finally {if(view)act(()=>view.root.unmount());jest.useRealTimers();}
});

test('retired read cannot advance freshness barrier even with a same-revision noncooperative result', async () => {
 const old=deferred();let reads=0;
 axios.get.mockImplementation(()=>++reads===1?old.promise:Promise.resolve({data:snapshot(1,{fresh:true})}));
 const view=renderProvider({scheduler:createScheduler(),visibility:createVisibility('hidden')});await flush();
 const signal=axios.get.mock.calls[0][1].signal;const barrier=view.getLatest().retireSnapshotReads();
 expect(barrier).toBeGreaterThan(0);expect(signal.aborted).toBe(true);
 await act(async()=>old.resolve({data:snapshot(1,{stale:true})}));await flush();
 expect(view.getLatest().snapshotReadSequence).toBeLessThanOrEqual(barrier);expect(view.getLatest().snapshot).toBeNull();
 await act(async()=>view.getLatest().refresh());await flush();
 expect(view.getLatest().snapshotReadSequence).toBeGreaterThan(barrier);expect(view.getLatest().snapshot).toEqual(snapshot(1,{fresh:true}));
 act(()=>view.root.unmount());
});
