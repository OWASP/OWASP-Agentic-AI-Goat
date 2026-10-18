import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import { MemoryRouter } from 'react-router-dom';
import Overview from './Overview.jsx';

jest.mock('../../components/PageTransition.jsx', () => ({ children }) => <div>{children}</div>);
jest.mock('framer-motion', () => ({
  AnimatePresence: ({ children }) => children,
  motion: new Proxy({}, { get: (_, tag) => ({ children, initial, animate, exit, transition, ...props }) =>
    React.createElement(tag, props, children) }),
}));

const response = (body, status = 200) => ({ ok: status >= 200 && status < 300, status, json: async () => body });
const bodies = {
  '/api/secureshop/admin/overview/kpis': { total_users: 12, admin_count: 2, banned_count: 1, total_products: 30, total_orders: 9, total_revenue: 123.45, active_sessions: 4 },
  '/api/secureshop/admin/agent-host/health': { status: 'ONLINE', port: 8082, agents: 17 },
  '/api/secureshop/admin/mcp/servers': { servers: [{ id: 1, name: 'catalog' }] },
  '/api/secureshop/admin/mcp/schema-history': { history: [{ name: 'catalog', schema_hash: 'one', ts: '2026-09-19T10:00:00Z' }] },
  '/api/secureshop/admin/provider-state': { providers: [{ role: 'admin', active_provider: 'openai' }] },
  '/api/secureshop/admin/db-sizes': { files: [{ path: '/owned/secureshop', size_mb: 2 }] },
  '/api/secureshop/admin/audit?limit=200': { events: [{ id: 1, action: 'ban', actor: 'admin', target: 'user:4', ts: '2026-09-19T10:00:00Z' }] },
  '/api/secureshop/agents/admin/trace/latest?limit=5': { rows: [{ id: 1, session_role: 'admin', session_id: 'abcdefghijk', actor: 'admin', kind: 'tool', ts: '2026-09-19T10:00:00Z' }] },
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
  await act(async () => root.render(<MemoryRouter><Overview /></MemoryRouter>));
  await flush();
}

async function flush() {
  await act(async () => {
    await Promise.resolve();
    await Promise.resolve();
  });
}

test('failed reads show unavailable state without fabricated healthy or empty claims', async () => {
  global.fetch = jest.fn(async () => response({ error: 'private upstream detail' }, 503));
  await mount();

  expect(container.querySelector('[role="alert"]').textContent).toContain('incomplete refresh');
  expect(container.textContent).toContain('MCP Registry');
  expect(container.textContent).toContain('UNAVAILABLE');
  expect(container.textContent).not.toContain('no provider state yet');
  expect(container.textContent).not.toContain('no security-relevant events yet');
  expect(container.textContent).not.toContain('last complete update');
  expect(container.textContent).not.toContain('private upstream detail');
});

test('partial polling failure retains prior provider data as stale and does not advance the complete timestamp', async () => {
  jest.useFakeTimers();
  jest.setSystemTime(new Date('2026-09-19T12:00:00'));
  let cycle = 0;
  global.fetch = jest.fn(async url => {
    const currentCycle = Math.floor(cycle++ / 8);
    if (currentCycle > 0 && url === '/api/secureshop/admin/provider-state') return response({ error: 'down' }, 503);
    return response(bodies[url]);
  });
  await mount();
  expect(container.textContent).toContain('last complete update 12:00:00');

  await act(async () => {
    jest.advanceTimersByTime(5000);
    await Promise.resolve();
    await Promise.resolve();
  });
  await flush();

  expect(container.textContent).toContain('openai');
  expect(container.textContent).toContain('stale data · HTTP 503');
  expect(container.textContent).toContain('last complete update 12:00:00');
  expect(container.textContent).not.toContain('last complete update 12:00:05');
});

test('a complete polling recovery clears errors and records a complete refresh', async () => {
  jest.useFakeTimers();
  jest.setSystemTime(new Date('2026-09-19T13:00:00'));
  let providerAvailable = false;
  global.fetch = jest.fn(async url => {
    if (url === '/api/secureshop/admin/provider-state' && !providerAvailable) return response({ error: 'down' }, 503);
    const body = url === '/api/secureshop/admin/provider-state'
      ? { providers: [{ role: 'admin', active_provider: 'anthropic' }] }
      : bodies[url];
    return response(body);
  });
  await mount();
  expect(container.querySelector('[role="alert"]')).not.toBeNull();
  expect(container.textContent).not.toContain('last complete update');

  providerAvailable = true;
  await act(async () => {
    jest.advanceTimersByTime(5000);
    await Promise.resolve();
    await Promise.resolve();
  });
  await flush();

  expect(container.querySelector('[role="alert"]')).toBeNull();
  expect(container.textContent).toContain('anthropic');
  expect(container.textContent).toContain('last complete update 13:00:05');
});

test('pending polling cannot overlap and is aborted on unmount', async () => {
  jest.useFakeTimers();
  const pending = [];
  global.fetch = jest.fn((url, options) => new Promise(resolve => pending.push({ resolve, signal: options.signal, url })));
  await act(async () => root.render(<MemoryRouter><Overview /></MemoryRouter>));
  expect(global.fetch).toHaveBeenCalledTimes(8);

  await act(async () => jest.advanceTimersByTime(10000));
  expect(global.fetch).toHaveBeenCalledTimes(8);

  await act(async () => root.unmount());
  root = null;
  expect(pending.every(request => request.signal.aborted)).toBe(true);
  pending.forEach(request => request.resolve(response(bodies[request.url])));
  await flush();
  jest.advanceTimersByTime(10000);
  expect(global.fetch).toHaveBeenCalledTimes(8);
});

test.each([null, [], { ok: false }])('malformed successful response %p cannot mark a refresh complete', async body => {
  global.fetch = jest.fn(async url => response(url.endsWith('/provider-state') ? body : bodies[url]));
  await mount();
  expect(container.querySelector('[role="alert"]')?.textContent).toContain('incomplete refresh');
  expect(container.textContent).not.toContain('last complete update');
  expect(container.textContent).not.toContain('no provider state yet');
});

test('bound logical sizes and service readiness do not imply disk usage or tested inference',async()=>{
 global.fetch=jest.fn(async url=>response(url.endsWith('/agent-host/health')?{status:'SERVICE_READY',runtime:'in-process LangGraph',model_execution:'not_tested',providers:[{provider:'ollama',availability:'model_missing'}]}:url.endsWith('/db-sizes')?{basis:'selected_launch_json_row_bytes',files:[{path:'Product source rows',size_mb:0.1}]}:url.endsWith('/mcp/servers')?{basis:'persisted_launch_discovery',servers:[]}:bodies[url]));
 await mount();expect(container.textContent).toContain('Scoped service checks only; model execution not tested.');expect(container.textContent).toContain('model_missing');expect(container.textContent).toContain('Selected launch data');expect(container.textContent).toContain('not physical disk usage');expect(container.textContent).toContain('network health is not measured');expect(container.textContent).not.toContain('ONLINE');
});


test('hung read times out while successful sections publish, then recovers without a late overwrite', async () => {
  jest.useFakeTimers();
  let late;
  let firstSignal;
  let providerCalls = 0;
  global.fetch = jest.fn((url, options) => {
    if (url.endsWith('/provider-state')) {
      if (++providerCalls === 1) {
        firstSignal = options.signal;
        return new Promise(resolve => { late = resolve; });
      }
      return Promise.resolve(response({ providers: [{ role: 'admin', active_provider: 'recovered-provider' }] }));
    }
    return Promise.resolve(response(bodies[url]));
  });
  await mount();
  await act(async () => jest.advanceTimersByTime(10000));
  await flush();
  expect(firstSignal.aborted).toBe(true);
  expect(container.textContent).toContain('Request timed out');
  expect(container.textContent).toContain('123.45');
  expect(container.textContent).not.toContain('last complete update');
  await act(async () => jest.advanceTimersByTime(5000));
  await flush();
  expect(container.textContent).toContain('recovered-provider');
  expect(container.querySelector('[role="alert"]')).toBeNull();
  await act(async () => late(response({ providers: [{ role: 'admin', active_provider: 'obsolete-provider' }] })));
  await flush();
  expect(container.textContent).not.toContain('obsolete-provider');
  expect(container.textContent).toContain('recovered-provider');
});

test('hung response body retains prior data as stale and timeout timers are removed on unmount', async () => {
  jest.useFakeTimers();
  const timers = jest.spyOn(global, 'setTimeout');
  const clears = jest.spyOn(global, 'clearTimeout');
  let providerCalls = 0;
  global.fetch = jest.fn(async url => {
    if (url.endsWith('/provider-state') && ++providerCalls > 1) return { ok: true, json: () => new Promise(() => {}) };
    return response(bodies[url]);
  });
  await mount();
  await act(async () => jest.advanceTimersByTime(5000));
  await flush();
  await act(async () => jest.advanceTimersByTime(10000));
  await flush();
  expect(container.textContent).toContain('openai');
  expect(container.textContent).toContain('stale data · Request timed out');
  await act(async () => root.unmount()); root = null;
  const requestTimers = timers.mock.calls.flatMap((args, i) => args[1] === 10000 ? [timers.mock.results[i].value] : []);
  expect(requestTimers.length).toBeGreaterThan(0);
  requestTimers.forEach(timer => expect(clears).toHaveBeenCalledWith(timer));
  timers.mockRestore(); clears.mockRestore();
});
