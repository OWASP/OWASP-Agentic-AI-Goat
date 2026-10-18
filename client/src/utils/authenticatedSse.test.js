import { connectAuthenticatedSse } from './authenticatedSse.mjs';

const bytes = value => new TextEncoder().encode(value);
const flush = async () => {
  for (let index = 0; index < 12; index += 1) await Promise.resolve();
};

function response(reader) {
  return {
    ok: true,
    headers: { get: name => name.toLowerCase() === 'content-type' ? 'text/event-stream; charset=utf-8' : null },
    body: { getReader: () => reader },
  };
}

function scheduler() {
  const tasks = [];
  return {
    tasks,
    setTimeout(callback, delay) {
      const task = { callback, delay, cancelled: false };
      tasks.push(task);
      return task;
    },
    clearTimeout(task) { task.cancelled = true; },
  };
}

test('sends bearer authentication and parses split SSE frames', async () => {
  const reads = [
    { value: bytes('event: csrf_'), done: false },
    { value: bytes('forged\r\ndata: {"phase":'), done: false },
    { value: bytes('"request"}\r\n\r\nevent: note\ndata: first\ndata: second\n\n'), done: false },
    { done: true },
  ];
  const reader = { read: jest.fn(() => Promise.resolve(reads.shift())), cancel: jest.fn(() => Promise.resolve()) };
  const fetchImpl = jest.fn(() => Promise.resolve(response(reader)));
  const events = [];
  const opened = jest.fn();
  const errors = [];
  const clock = scheduler();
  const stream = connectAuthenticatedSse({
    url: '/api/workshop/csrf/events', getToken: () => 'owned-token', fetchImpl,
    scheduler: clock, onOpen: opened, onError: error => errors.push(error), onEvent: event => events.push(event),
    retryMs: 25,
  });
  await flush();

  expect(fetchImpl).toHaveBeenCalledWith('/api/workshop/csrf/events', expect.objectContaining({
    method: 'GET', credentials: 'omit', cache: 'no-store', redirect: 'error',
    headers: { Accept: 'text/event-stream', Authorization: 'Bearer owned-token' },
  }));
  expect(opened).toHaveBeenCalledTimes(1);
  expect(events).toEqual([
    { type: 'csrf_forged', data: '{"phase":"request"}', lastEventId: '' },
    { type: 'note', data: 'first\nsecond', lastEventId: '' },
  ]);
  expect(errors).toHaveLength(1);
  expect(clock.tasks).toHaveLength(1);
  stream.close();
  expect(clock.tasks[0].cancelled).toBe(true);
});

test.each([
  '//evil.example/events',
  '/\\evil.example/events',
  '/api/workshop/csrf/events?token=secret',
  '/api/workshop/csrf/events#other',
  'https://evil.example/events',
])('rejects credential-bearing unsafe stream destination %s before fetch', url => {
  const fetchImpl = jest.fn();
  expect(() => connectAuthenticatedSse({
    url, getToken: () => 'owned-token', fetchImpl, retryMs: 20,
  })).toThrow('Invalid authenticated SSE configuration');
  expect(fetchImpl).not.toHaveBeenCalled();
});

test('reconnects with the current token after an ended stream', async () => {
  const clock = scheduler();
  let token = 'first-token';
  const first = { read: jest.fn(() => Promise.resolve({ done: true })), cancel: jest.fn(() => Promise.resolve()) };
  let finishSecond;
  const second = {
    read: jest.fn(() => new Promise(resolve => { finishSecond = resolve; })),
    cancel: jest.fn(() => { finishSecond?.({ done: true }); return Promise.resolve(); }),
  };
  const fetchImpl = jest.fn()
    .mockResolvedValueOnce(response(first))
    .mockResolvedValueOnce(response(second));
  const stream = connectAuthenticatedSse({
    url: '/api/workshop/csrf/events', getToken: () => token, fetchImpl,
    scheduler: clock, retryMs: 50,
  });
  await flush();
  expect(clock.tasks).toHaveLength(1);
  token = 'rotated-token';
  clock.tasks[0].callback();
  await flush();
  expect(fetchImpl.mock.calls[1][1].headers.Authorization).toBe('Bearer rotated-token');
  stream.close();
  await flush();
  expect(fetchImpl).toHaveBeenCalledTimes(2);
});

test('close aborts a pending connection and suppresses stale callbacks and reconnects', async () => {
  let resolveFetch;
  const pending = new Promise(resolve => { resolveFetch = resolve; });
  const reader = { read: jest.fn(), cancel: jest.fn(() => Promise.resolve()) };
  const fetchImpl = jest.fn(() => pending);
  const clock = scheduler();
  const opened = jest.fn();
  const errored = jest.fn();
  const received = jest.fn();
  const stream = connectAuthenticatedSse({
    url: '/api/workshop/csrf/events', getToken: () => 'owned-token', fetchImpl,
    scheduler: clock, retryMs: 50, onOpen: opened, onError: errored, onEvent: received,
  });
  const signal = fetchImpl.mock.calls[0][1].signal;
  stream.close();
  expect(signal.aborted).toBe(true);
  resolveFetch(response(reader));
  await flush();
  expect(opened).not.toHaveBeenCalled();
  expect(errored).not.toHaveBeenCalled();
  expect(received).not.toHaveBeenCalled();
  expect(clock.tasks).toHaveLength(0);
});

test('backs off repeated connection failures within the configured bound', async () => {
  const clock = scheduler();
  const fetchImpl = jest.fn(() => Promise.reject(new Error('offline')));
  const stream = connectAuthenticatedSse({
    url: '/api/workshop/csrf/events', getToken: () => 'owned-token', fetchImpl,
    scheduler: clock, retryMs: 20,
  });
  await flush();
  expect(clock.tasks[0].delay).toBe(20);
  clock.tasks[0].callback();
  await flush();
  expect(clock.tasks[1].delay).toBe(40);
  clock.tasks[1].callback();
  await flush();
  expect(clock.tasks[2].delay).toBe(80);
  stream.close();
});


test('default retry and cancellation timers retain the browser global receiver', async () => {
  const originalSet = globalThis.setTimeout;
  const originalClear = globalThis.clearTimeout;
  const tasks = [];
  const cancelled = [];
  let stream;
  try {
    globalThis.setTimeout = function (callback, delay) {
      expect(this).toBe(globalThis);
      const task = { callback, delay };
      tasks.push(task);
      return task;
    };
    globalThis.clearTimeout = function (task) {
      expect(this).toBe(globalThis);
      cancelled.push(task);
    };
    const errors = [];
    stream = connectAuthenticatedSse({
      url: '/api/workshop/csrf/events', getToken: () => '',
      fetchImpl: jest.fn(), onError: error => errors.push(error), retryMs: 25,
    });
    await flush();
    expect(errors).toHaveLength(1);
    expect(tasks.map(task => task.delay)).toEqual([25]);
    tasks[0].callback();
    await flush();
    expect(errors).toHaveLength(2);
    expect(tasks.map(task => task.delay)).toEqual([25, 50]);
    stream.close();
    expect(cancelled).toEqual([tasks[1]]);
  } finally {
    stream?.close();
    globalThis.setTimeout = originalSet;
    globalThis.clearTimeout = originalClear;
  }
});
