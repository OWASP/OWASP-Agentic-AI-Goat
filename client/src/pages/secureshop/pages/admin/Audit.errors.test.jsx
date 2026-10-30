import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import Audit from './Audit.jsx';

jest.mock('../../components/PageTransition.jsx', () => ({ children }) => <div>{children}</div>);
jest.mock('framer-motion', () => ({
  AnimatePresence: ({ children }) => children,
  motion: new Proxy({}, { get: (_, tag) => ({ children, initial, animate, exit, transition, ...props }) =>
    React.createElement(tag, props, children) }),
}));

const event = (id, actor = 'admin') => ({
  id,
  actor,
  action: 'ban',
  target: `user:${id}`,
  params_json: '{}',
  ip: '127.0.0.1',
  user_agent: 'test',
  ts: '2026-09-19T10:00:00Z',
});
const list = (...events) => ({ ok: true, count: events.length, events });
const response = (body, status = 200) => ({
  ok: status >= 200 && status < 300,
  status,
  json: async () => body,
});
const readyCapabilities = { ok: true, capabilities: {
  manualSearch: { ready: true }, agentSearch: { ready: true }, summary: { ready: true },
} };
function installReadyCapabilities() {
  const next = global.fetch;
  global.fetch = jest.fn((url, options) => String(url).endsWith('/capabilities')
    ? Promise.resolve(response(readyCapabilities)) : next(url, options));
}
const deferred = () => {
  let resolve;
  const promise = new Promise(done => { resolve = done; });
  return { promise, resolve };
};

let container;
let root;

beforeEach(() => {
  global.IS_REACT_ACT_ENVIRONMENT = true;
  container = document.createElement('div');
  document.body.appendChild(container);
  root = createRoot(container);
});

afterEach(async () => {
  if (root) await act(async () => root.unmount());
  container.remove();
  jest.useRealTimers();
});

async function mount() {
  installReadyCapabilities();
  await act(async () => root.render(<Audit />));
  await flush();
}

async function flush() {
  await act(async () => {
    await Promise.resolve();
    await Promise.resolve();
  });
}

function button(label) {
  const match = [...container.querySelectorAll('button')].find(node => node.textContent === label);
  expect(match).toBeTruthy();
  return match;
}

async function enter(input, value) {
  const setValue = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set;
  await act(async () => {
    setValue.call(input, value);
    input.dispatchEvent(new Event('input', { bubbles: true }));
  });
}

test.each([
  ['HTTP failure', response({ error: 'database unavailable' }, 503), 'HTTP 503'],
  ['error envelope', response({ ok: false, error: 'audit read failed' }), 'audit read failed'],
  ['malformed success', response({ ok: true, events: 'not-an-array' }), 'Invalid response'],
  ['malformed count', response({ ok: true, count: -1, events: [] }), 'Invalid response'],
])('%s is shown as unavailable rather than an empty successful audit', async (_name, reply, message) => {
  global.fetch = jest.fn(async () => reply);
  await mount();

  expect(container.querySelector('[role="alert"]')?.textContent).toContain(`audit events unavailable · ${message}`);
  expect(container.textContent).not.toContain('no events match');
  expect(container.textContent).not.toContain('database unavailable');
});

test('a failed refresh retains prior rows and marks them stale', async () => {
  global.fetch = jest.fn()
    .mockResolvedValueOnce(response(list(event(1, 'retained-admin'))))
    .mockResolvedValueOnce(response({ error: 'down' }, 503));
  await mount();
  expect(container.textContent).toContain('retained-admin');

  await act(async () => button('refresh now').click());
  await flush();

  expect(container.textContent).toContain('retained-admin');
  expect(container.querySelector('[role="alert"]')?.textContent).toContain('stale data · HTTP 503');
  expect(container.textContent).toContain('1 events');
});

test('CSV export names its current-page scope in the visible and accessible button label', async () => {
  global.fetch = jest.fn(async () => response(list(event(1))));
  await mount();

  const exportButton = button('Export current page');
  expect(exportButton.disabled).toBe(false);
  expect(exportButton.getAttribute('aria-label')).toBeNull();
  expect(exportButton.textContent).toBe('Export current page');
  await act(async () => exportButton.click());
  expect(container.querySelector('[role="alert"]')?.textContent).toContain('CSV export is available in standalone OWASP AI SecureShop');
});

test('unavailable audit capabilities disable dependent controls without attempting mutations', async () => {
  global.fetch = jest.fn(async url => String(url).endsWith('/capabilities')
    ? response({ ok: true, capabilities: {
      manualSearch: { ready: false, reason: 'Owned audit search is unavailable' },
      agentSearch: { ready: false, reason: 'Owned audit agent is unavailable' },
      summary: { ready: false, reason: 'Audit summary is unavailable' },
    } }) : response(list()));
  await act(async () => root.render(<Audit />));
  await flush();
  await enter(container.querySelector('[aria-label="Search by user"]'), 'alice');
  expect(button('Search').disabled).toBe(true);
  expect(button('Ask audit agent').disabled).toBe(true);
  expect(button('Summarize anomalies').disabled).toBe(true);
  expect(container.textContent).toContain('Owned audit search is unavailable');
  expect(container.textContent).toContain('Owned audit agent is unavailable');
  expect(container.textContent).toContain('Audit summary is unavailable');
  expect(global.fetch.mock.calls.every(([url]) => !String(url).includes('search-by-user'))).toBe(true);
});

test('failed capability read leaves audit actions disabled with an explicit retry', async () => {
  global.fetch = jest.fn(async url => String(url).endsWith('/capabilities')
    ? response({ error: 'readiness unavailable' }, 503) : response(list()));
  await act(async () => root.render(<Audit />));
  await flush();
  expect(button('Summarize anomalies').disabled).toBe(true);
  expect(container.textContent).toContain('Audit actions are unavailable');
  expect(button('Retry readiness')).toBeTruthy();
});

test('a superseded filter response is aborted and cannot replace current rows', async () => {
  jest.useFakeTimers();
  const oldRequest = deferred();
  const requests = [];
  global.fetch = jest.fn((url, options = {}) => {
    requests.push({ url, signal: options.signal });
    if (url.includes('actor=old')) return oldRequest.promise;
    if (url.includes('actor=new')) return Promise.resolve(response(list(event(3, 'new-result'))));
    return Promise.resolve(response(list(event(1, 'initial-result'))));
  });
  await mount();

  const actor = container.querySelector('[aria-label="actor"]');
  await enter(actor, 'old');
  await act(async () => jest.advanceTimersByTime(250));
  await flush();
  const oldCall = requests.find(request => request.url.includes('actor=old'));
  expect(oldCall).toBeTruthy();

  await enter(actor, 'new');
  await act(async () => jest.advanceTimersByTime(250));
  await flush();
  expect(oldCall.signal.aborted).toBe(true);
  expect(container.textContent).toContain('new-result');

  oldRequest.resolve(response(list(event(2, 'old-result'))));
  await flush();
  expect(container.textContent).toContain('new-result');
  expect(container.textContent).not.toContain('old-result');
});

test('polling skips a still-pending read and allows that read to finish', async () => {
  jest.useFakeTimers();
  const pending = deferred();
  global.fetch = jest.fn(() => pending.promise);
  installReadyCapabilities();
  await act(async () => root.render(<Audit />));
  expect(global.fetch).toHaveBeenCalledTimes(2);

  await act(async () => jest.advanceTimersByTime(5000));
  expect(global.fetch).toHaveBeenCalledTimes(2);

  pending.resolve(response(list(event(7, 'eventual-result'))));
  await flush();
  expect(container.textContent).toContain('eventual-result');
});

test('search reports failures inline and preserves the raw SQLi teaching input', async () => {
  global.fetch = jest.fn((url, options = {}) => {
    if (url.includes('search-by-user')) return Promise.resolve(response({
      ok: false,
      error: 'query failed',
      sql: "SELECT * FROM audit_events WHERE actor LIKE '%alice' OR 1=1--%'",
      count: 0,
      events: [],
    }));
    return Promise.resolve(response(list()));
  });
  await mount();

  const search = container.querySelector('[aria-label="Search by user"]');
  await enter(search, "alice' OR 1=1--");
  await act(async () => container.querySelector('form').dispatchEvent(new Event('submit', { bubbles: true, cancelable: true })));
  await flush();

  const write = global.fetch.mock.calls.find(([url]) => url.includes('search-by-user'));
  expect(JSON.parse(write[1].body)).toEqual({ username: "alice' OR 1=1--", operationId: expect.stringMatching(/^[a-f0-9-]{36}$/) });
  expect(container.querySelector('[role="alert"]')?.textContent).toContain('search failed · query failed');
  expect(container.textContent).toContain("SELECT * FROM audit_events WHERE actor LIKE");
});

test('summary reports failures, restores its button, and preserves the unbounded request', async () => {
  global.fetch = jest.fn((url, options = {}) => {
    if (url.includes('bound-session')) return Promise.resolve(response({ ok: true, sessionId: '10000000-0000-4000-8000-000000000001' }));
    if (url.includes('bound-summary')) return Promise.resolve(response({ error: 'model unavailable' }, 503));
    return Promise.resolve(response(list()));
  });
  await mount();

  await act(async () => button('Summarize anomalies').click());
  await flush();

  const write = global.fetch.mock.calls.find(([url]) => url.includes('bound-summary'));
  expect(JSON.parse(write[1].body)).toMatchObject({ limit: 5000, session_id: '10000000-0000-4000-8000-000000000001' });
  expect(container.querySelector('[role="alert"]')?.textContent).toContain('summary failed · HTTP 503');
  expect(button('Summarize anomalies').disabled).toBe(false);
});

test('unmount aborts list, search, and summary requests without applying late responses', async () => {
  const pending = [];
  global.fetch = jest.fn((url, options = {}) => {
    const request = deferred();
    pending.push({ ...request, url, signal: options.signal });
    return request.promise;
  });
  installReadyCapabilities();
  await act(async () => root.render(<Audit />));

  const search = container.querySelector('[aria-label="Search by user"]');
  await enter(search, 'alice');
  await act(async () => {
    container.querySelector('form').dispatchEvent(new Event('submit', { bubbles: true, cancelable: true }));
    button('Summarize anomalies').click();
  });
  expect(pending).toHaveLength(3);

  await act(async () => root.unmount());
  root = null;
  expect(pending.every(request => request.signal.aborted)).toBe(true);

  pending.forEach(request => request.resolve(response(
    request.url.includes('search-by-user')
      ? { ok: true, sql: 'stale', events: [] }
      : request.url.includes('summarize-anomalies')
        ? { ok: true, prompt: 'stale', log_text: '', row_count: 0 }
        : list(event(99, 'stale')),
  )));
  await flush();
});

test('older pages use continuation and pause polling until latest events is selected', async () => {
  jest.useFakeTimers();
  global.fetch = jest.fn(async url => response(url.includes('cursor=')
    ? { ...list(event('older')), hasMore: false, nextCursor: null }
    : { ...list(event('latest')), hasMore: true, nextCursor: 'owned-cursor' }));
  await mount();
  await act(async () => button('older events').click());
  await flush();
  expect(fetch.mock.calls.at(-1)[0]).toContain('cursor=owned-cursor');
  expect(container.textContent).toContain('historical page');
  const calls = fetch.mock.calls.length;
  await act(async () => jest.advanceTimersByTime(10000));
  expect(fetch).toHaveBeenCalledTimes(calls);
  await act(async () => button('latest events').click());
  await flush();
  expect(fetch.mock.calls.at(-1)[0]).not.toContain('cursor=');
  expect(container.textContent).not.toContain('historical page');
});

test('limit changes restart historical pagination at the latest page', async () => {
  global.fetch = jest.fn(async () => response({ ...list(event('row')), hasMore: true, nextCursor: 'owned-cursor' }));
  await mount();
  await act(async () => button('older events').click());
  await flush();
  await enter(container.querySelector('input[type="number"]'), '50');
  await flush();
  expect(fetch.mock.calls.at(-1)[0]).toContain('limit=50');
  expect(fetch.mock.calls.at(-1)[0]).not.toContain('cursor=');
});

test('uncertain search retries preserve operation identity and changed input starts a new operation', async () => {
  global.fetch = jest.fn(async url => url.includes('search-by-user')
    ? response({ error: 'Owned query acknowledgement unavailable' }, 503) : response(list()));
  await mount();
  const input = container.querySelector('[aria-label="Search by user"]');
  const submit = async () => {
    await act(async () => container.querySelector('form').dispatchEvent(new Event('submit', { bubbles: true, cancelable: true })));
    await flush();
  };
  await enter(input, "alice' OR 1=1--");await submit();await submit();
  await enter(input, 'bob');await submit();
  const writes = global.fetch.mock.calls.filter(([url]) => url.includes('search-by-user')).map(([, opts]) => JSON.parse(opts.body));
  expect(writes).toHaveLength(3);
  expect(writes[1]).toEqual(writes[0]);
  expect(writes[2].operationId).not.toEqual(writes[0].operationId);
});

test('audit agent uses its bound session, preserves uncertain turn identity and displays model provenance', async () => {
  const sessionId='30000000-0000-4000-8000-000000000099';let turns=0;
  global.fetch=jest.fn(async url=>{
    if(url.endsWith('/agent-session'))return response({ok:true,sessionId});
    if(url.endsWith('/agent-search'))return ++turns===1?response({error:'uncertain'},503):response({replayed:true,result:{text:'Observed owned result',provider:'ollama',model:'llama3.1:8b',query:null,assessment:{judgment:{verdict:'fail'}}}});
    return response(list());
  });
  await mount();await enter(container.querySelector('[aria-label="Search by user"]'),'admin');
  await act(async()=>button('Ask audit agent').click());await flush();
  await act(async()=>button('Ask audit agent').click());await flush();
  const calls=global.fetch.mock.calls.filter(([url])=>url.endsWith('/agent-search')).map(([,opts])=>JSON.parse(opts.body));
  expect(calls).toHaveLength(2);expect(calls[1]).toEqual(calls[0]);expect(Object.keys(calls[0]).sort()).toEqual(['message','requestId','sessionId']);expect(calls[0].sessionId).toBe(sessionId);
  expect(container.textContent).toContain('Observed owned result');expect(container.textContent).toContain('Judge: fail');
  expect(global.fetch.mock.calls.filter(([url])=>url.endsWith('/agent-session'))).toHaveLength(1);
});
