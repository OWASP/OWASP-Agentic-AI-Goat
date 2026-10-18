import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import AdminAudit from './Audit';
let mockStandalone = false;
const mockOpenAssessments = jest.fn();
jest.mock('../../bridge/assessmentPanelIntent.mjs', () => ({
  isStandaloneShopFrame: () => mockStandalone,
  openStandaloneAssessments: (...args) => mockOpenAssessments(...args),
}));

jest.mock('framer-motion', () => {
  const ReactModule = require('react');
  const element = tag => ReactModule.forwardRef(function MotionElement(
    { initial, animate, exit, transition, ...props }, ref,
  ) { return ReactModule.createElement(tag, { ...props, ref }); });
  return { motion: { section: element('section'), div: element('div') },
    AnimatePresence: ({ children }) => <>{children}</> };
});
jest.mock('../../components/PageTransition.jsx', () => ({ children }) => <>{children}</>);

const sessionId = '10000000-0000-4000-8000-000000000001';
const requestId = '20000000-0000-4000-8000-000000000002';
const runId = '30000000-0000-4000-8000-000000000003';

function response(body, status = 200) {
  return { ok: status >= 200 && status < 300, status,
    json: jest.fn().mockResolvedValue(body) };
}
let auditCapabilities;
function renderAudit(props = {}) {
  if (!global.fetch.__readyCapabilities) {
    const next = global.fetch;
    const wrapper = jest.fn((url, options) => String(url).endsWith('/capabilities')
      ? Promise.resolve(response({ ok: true, capabilities: auditCapabilities })) : next(url, options));
    wrapper.__readyCapabilities = true;
    global.fetch = wrapper;
  }
  root.render(<AdminAudit {...props} />);
}

async function settle() {
  await act(async () => { await Promise.resolve(); await Promise.resolve(); await Promise.resolve(); });
}

let root;
let container;

beforeEach(() => {
  global.IS_REACT_ACT_ENVIRONMENT = true;
  mockStandalone = false;
  mockOpenAssessments.mockClear();
  global.crypto = { randomUUID: () => requestId };
  auditCapabilities = {
    manualSearch: { ready: true }, agentSearch: { ready: true }, summary: { ready: true },
    unbounded: { ready: false }, timingAgent: { ready: false },
  };
  container = document.createElement('div');
  document.body.appendChild(container);
  root = createRoot(container);
});

afterEach(async () => {
  await act(async () => root.unmount());
  container.remove();
});

test('admits one bound audit session and retries an uncertain response with the same request identity', async () => {
  const calls = [];
  global.fetch = jest.fn((url, options = {}) => {
    calls.push([String(url), options]);
    if (String(url).includes('/admin/audit?')) return Promise.resolve(response({ events: [], count: 0, hasMore: false, nextCursor: null }));
    if (String(url).endsWith('/bound-session')) return Promise.resolve(response({ ok: true, sessionId }));
    if (String(url).endsWith('/bound-summary') && calls.filter(([u]) => u.endsWith('/bound-summary')).length === 1) return Promise.reject(new Error('Connection lost'));
    if (String(url).endsWith('/bound-summary')) return Promise.resolve(response({
      runId, summary: 'Observed one anomaly in the retained audit rows.', provider: 'ollama', model: 'llama3.1:8b',
      requestedCount: 5000, rowCount: 1, objectiveCredit: false, replayed: false,
      assessment: { judgment: { verdict: 'inconclusive' }, completed: false },
    }));
    throw new Error(`unexpected URL ${url}`);
  });

  await act(async () => renderAudit());
  await settle();
  const button = container.querySelector('button[aria-label="Summarize anomalies"]');
  await act(async () => button.click());
  await settle();
  expect(container.textContent).toContain('Connection lost');
  await act(async () => button.click());
  await settle();

  const sessions = calls.filter(([url]) => url.endsWith('/bound-session'));
  const summaries = calls.filter(([url]) => url.endsWith('/bound-summary'));
  expect(sessions).toHaveLength(1);
  expect(summaries).toHaveLength(2);
  const firstBody = JSON.parse(summaries[0][1].body);
  expect(firstBody).toMatchObject({ session_id: sessionId, limit: 5000 });
  expect(firstBody.request_id).toMatch(/^[0-9a-f-]{36}$/i);
  expect(JSON.parse(summaries[1][1].body)).toEqual(firstBody);
  expect(container.textContent).toContain('Judge: inconclusive');
});

test('fixed projection rejection retries the direct summary at its authoritative 100-row bound', async () => {
  const calls = [];
  global.fetch = jest.fn((url, options = {}) => {
    calls.push([String(url), options]);
    if (String(url).includes('/admin/audit?')) return Promise.resolve(response({ events: [], count: 0, hasMore: false, nextCursor: null }));
    if (String(url).endsWith('/bound-session')) return Promise.resolve(response({ ok: true, sessionId }));
    if (String(url).endsWith('/bound-summary')) {
      const body = JSON.parse(options.body);
      if (body.limit === 5000) return Promise.resolve(response({ error: 'Fixed audit summaries accept at most 100 events' }, 400));
      return Promise.resolve(response({
        runId, summary: 'Fixed projection summary.', provider: 'ollama', model: 'llama3.1:8b',
        requestedCount: 100, rowCount: 1, objectiveCredit: false, replayed: false,
        assessment: { judgment: { verdict: 'fail' }, completed: false },
      }));
    }
    throw new Error(`unexpected URL ${url}`);
  });

  await act(async () => renderAudit());
  await settle();
  await act(async () => container.querySelector('button[aria-label="Summarize anomalies"]').click());
  await settle();

  const summaries = calls.filter(([url]) => url.endsWith('/bound-summary'));
  expect(summaries).toHaveLength(2);
  expect(JSON.parse(summaries[0][1].body).limit).toBe(5000);
  expect(JSON.parse(summaries[1][1].body).limit).toBe(100);
  expect(JSON.parse(summaries[1][1].body).request_id).not.toBe(JSON.parse(summaries[0][1].body).request_id);
  expect(container.textContent).toContain('Fixed projection summary.');
});

test('lost fixed-limit acknowledgement retries the same 100-row request without a new vulnerable request', async () => {
  const calls = [];
  let fixedAttempts = 0;
  global.fetch = jest.fn((url, options = {}) => {
    calls.push([String(url), options]);
    if (String(url).includes('/admin/audit?')) return Promise.resolve(response({ events: [], count: 0, hasMore: false, nextCursor: null }));
    if (String(url).endsWith('/bound-session')) return Promise.resolve(response({ ok: true, sessionId }));
    if (String(url).endsWith('/bound-summary')) {
      const body = JSON.parse(options.body);
      if (body.limit === 5000) return Promise.resolve(response({ error: 'Fixed audit summaries accept at most 100 events' }, 400));
      fixedAttempts += 1;
      if (fixedAttempts === 1) return Promise.reject(new Error('Connection lost after fixed request'));
      return Promise.resolve(response({
        runId, summary: 'Recovered fixed projection summary.', provider: 'ollama', model: 'llama3.1:8b',
        requestedCount: 100, rowCount: 1, objectiveCredit: false, replayed: false,
        assessment: { judgment: { verdict: 'fail' }, completed: false },
      }));
    }
    throw new Error(`unexpected URL ${url}`);
  });

  await act(async () => renderAudit());
  await settle();
  const button = container.querySelector('button[aria-label="Summarize anomalies"]');
  await act(async () => button.click());
  await settle();
  await act(async () => button.click());
  await settle();

  const summaries = calls.filter(([url]) => url.endsWith('/bound-summary'));
  expect(summaries).toHaveLength(3);
  expect(JSON.parse(summaries[0][1].body).limit).toBe(5000);
  expect(JSON.parse(summaries[1][1].body).limit).toBe(100);
  expect(JSON.parse(summaries[2][1].body)).toEqual(JSON.parse(summaries[1][1].body));
  expect(container.textContent).toContain('Recovered fixed projection summary.');
});

test('scope changes discard the durable session and request identities', async () => {
  const calls = [];
  global.fetch = jest.fn((url, options = {}) => {
    calls.push([String(url), options]);
    if (String(url).includes('/admin/audit?')) return Promise.resolve(response({ events: [], count: 0, hasMore: false, nextCursor: null }));
    if (String(url).endsWith('/bound-session')) return Promise.resolve(response({ ok: true, sessionId }));
    if (String(url).endsWith('/bound-summary')) return Promise.resolve(response({
      runId, summary: 'Summary', provider: 'ollama', model: 'model', requestedCount: 5000,
      rowCount: 0, objectiveCredit: false, replayed: false,
      assessment: { completed: false, judgment: { verdict: 'fail' } },
    }));
    throw new Error(`unexpected URL ${url}`);
  });
  await act(async () => renderAudit({ scopeKey: 'launch-a' }));
  await settle();
  await act(async () => container.querySelector('button[aria-label="Summarize anomalies"]').click());
  await settle();
  await act(async () => renderAudit({ scopeKey: 'launch-b' }));
  await settle();
  await act(async () => container.querySelector('button[aria-label="Summarize anomalies"]').click());
  await settle();
  expect(calls.filter(([url]) => url.endsWith('/bound-session'))).toHaveLength(2);
});

test('a completed summary allows a fresh observation on the next click', async () => {
  const requests = [];
  global.fetch = jest.fn(async (url, options = {}) => {
    if (String(url).includes('/admin/audit?')) return response({ events: [], count: 0 });
    if (String(url).endsWith('/bound-session')) return response({ ok: true, sessionId });
    requests.push(JSON.parse(options.body));
    return response({ runId, summary: `Observation ${requests.length}`, provider: 'ollama', model: 'llama3.1:8b',
      requestedCount: 5000, rowCount: 1, objectiveCredit: false, replayed: false,
      assessment: { completed: false, judgment: { verdict: 'fail' } } });
  });
  await act(async () => renderAudit());
  await settle();
  for (let i = 0; i < 2; i++) {
    await act(async () => container.querySelector('[aria-label="Summarize anomalies"]').click());
    await settle();
  }
  expect(requests).toHaveLength(2);
  expect(requests[1].session_id).toBe(requests[0].session_id);
  expect(requests[1].request_id).not.toBe(requests[0].request_id);
  expect(container.textContent).toContain('Observation 2');
});

test('late session admission after scope rotation cannot submit a summary', async () => {
  let resolveSession;
  global.fetch = jest.fn(async url => {
    if (String(url).includes('/admin/audit?')) return response({ events: [], count: 0 });
    if (String(url).endsWith('/bound-session')) return new Promise(resolve => { resolveSession = resolve; });
    throw new Error('Old scope must not submit a summary');
  });
  await act(async () => renderAudit({ scopeKey: 'old' }));
  await settle();
  await act(async () => container.querySelector('[aria-label="Summarize anomalies"]').click());
  await act(async () => renderAudit({ scopeKey: 'new' }));
  await act(async () => resolveSession(response({ ok: true, sessionId })));
  await settle();
  expect(fetch.mock.calls.some(([url]) => String(url).endsWith('/bound-summary'))).toBe(false);
});


test.each(['unavailable', 'fail', 'pass'])(
  'saved Audit %s shows recovery guidance only when grading is unavailable', async verdict => {
    global.fetch = jest.fn(async url => {
      if (String(url).includes('/admin/audit?')) return response({ events: [], count: 0 });
      if (String(url).endsWith('/bound-session')) return response({ ok: true, sessionId });
      if (String(url).endsWith('/bound-summary')) return response({
        runId, summary: 'Saved owned Audit summary.', provider: 'ollama', model: 'llama3.3:70b',
        requestedCount: 5000, rowCount: 1, objectiveCredit: verdict === 'pass', replayed: false,
        assessment: { completed: verdict === 'pass', judgment: { verdict, canRetry: verdict === 'unavailable' } },
      });
      throw new Error(`unexpected URL ${url}`);
    });
    await act(async () => renderAudit());
    await settle();
    await act(async () => container.querySelector('[aria-label="Summarize anomalies"]').click());
    await settle();
    expect(container.textContent).toContain('Saved owned Audit summary.');
    if (verdict === 'unavailable') {
      const status = container.querySelector('[role="status"]');
      expect(status.textContent).toContain('Open Agent Runs in the workshop navigation, then Recent evaluations.');
      expect(status.textContent).toContain('Retry evaluation for this saved Audit run if available');
      expect(status.textContent).toContain('without creating a new summary');
      expect(status.textContent).toContain(runId);
      expect(global.fetch.mock.calls.filter(([url]) => String(url).endsWith('/bound-summary'))).toHaveLength(1);
      expect(container.querySelector('a')).toBeNull();
    } else {
      expect(container.textContent).not.toContain('Open Agent Runs');
    }
  },
);

test('standalone Audit unavailable grading opens shop recovery without workshop navigation or a new summary', async () => {
  mockStandalone = true;
  const evaluationId = '7f078c35-0bda-4bb4-9c9f-819807aa2668';
  global.fetch = jest.fn(async url => {
    if (String(url).includes('/admin/audit?')) return response({ events: [], count: 0 });
    if (String(url).endsWith('/bound-session')) return response({ ok: true, sessionId });
    if (String(url).endsWith('/bound-summary')) return response({ runId, summary: 'Saved owned Audit summary.',
      provider: 'ollama', model: 'configured', requestedCount: 5000, rowCount: 1,
      objectiveCredit: false, replayed: false,
      assessment: { completed: false, judgment: { verdict: 'unavailable', evaluationId } } });
    throw new Error(`unexpected URL ${url}`);
  });
  await act(async () => renderAudit());
  await settle();
  await act(async () => container.querySelector('[aria-label="Summarize anomalies"]').click());
  await settle();
  expect(container.textContent).not.toContain('workshop navigation');
  const open = [...container.querySelectorAll('button')].find(button => button.textContent === 'Open saved assessments');
  await act(async () => open.click());
  expect(mockOpenAssessments).toHaveBeenCalledWith(evaluationId);
  expect(global.fetch.mock.calls.filter(([url]) => String(url).endsWith('/bound-summary'))).toHaveLength(1);
});


test('unbounded audit observation keeps a separate saved request and exposes only its closed projection', async () => {
  auditCapabilities = { ...auditCapabilities, unbounded: { ready: true } };
  const calls = [];
  const modeCapability = { version: 1, featureId: 'audit_summary', policyVersion: 'capped-audit-metadata-v1',
    effectiveMode: 'vuln', scope: { kind: 'launch_feature', id: 'audit_summary' } };
  global.fetch = jest.fn((url, options = {}) => {
    calls.push([String(url), options]);
    if (String(url).includes('/admin/audit?')) return Promise.resolve(response({ events: [], count: 0, hasMore: false, nextCursor: null }));
    if (String(url).endsWith('/unbounded-session')) return Promise.resolve(response({ ok: true, sessionId }));
    if (String(url).endsWith('/unbounded-summary')) return Promise.resolve(response({
      runId, summary: 'Observed bounded teaching rows.', provider: 'ollama', model: 'llama3.1:8b',
      requestedCount: 5000, rowCount: 2, objectiveCredit: false, replayed: false,
      assessment: { completed: false, judgment: { verdict: 'fail' } }, modeCapability,
    }));
    throw new Error(`unexpected URL ${url}`);
  });
  await act(async () => renderAudit()); await settle();
  await act(async () => container.querySelector('[aria-label="Observe unbounded audit summary"]').click()); await settle();
  const request = calls.find(([url]) => url.endsWith('/unbounded-summary'));
  expect(JSON.parse(request[1].body)).toEqual({ session_id: sessionId,
    request_id: expect.stringMatching(/^[0-9a-f-]{36}$/i), limit: 5000 });
  expect(container.querySelector('[aria-label="Unbounded audit observation"]').textContent)
    .toContain('Observed bounded teaching rows.');
  expect(container.textContent).not.toContain('Objective completion recorded');
});

test('timing audit uses its own human message and closed server-selected run result', async () => {
  auditCapabilities = { ...auditCapabilities, timingAgent: { ready: true } };
  const calls = [];
  global.fetch = jest.fn((url, options = {}) => {
    calls.push([String(url), options]);
    if (String(url).includes('/admin/audit?')) return Promise.resolve(response({ events: [], count: 0, hasMore: false, nextCursor: null }));
    if (String(url).endsWith('/timing-session')) return Promise.resolve(response({ ok: true, sessionId }));
    if (String(url).endsWith('/timing-run')) return Promise.resolve(response({ result: {
      text: 'The owned timing target was observed.', query: { blocked: true, reason: 'fixed policy' },
      provider: 'ollama', model: 'llama3.1:8b', assessment: { completed: false },
    }, replayed: false }));
    throw new Error(`unexpected URL ${url}`);
  });
  await act(async () => renderAudit()); await settle();
  const input = container.querySelector('[aria-label="Timing audit request"]');
  await act(async () => {
    Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, 'value').set.call(input, 'Inspect timing without changing it.');
    input.dispatchEvent(new Event('input', { bubbles: true }));
  });
  const ask = [...container.querySelectorAll('button')].find(button => button.textContent === 'Ask timing audit agent');
  await act(async () => ask.click()); await settle();
  const request = calls.find(([url]) => url.endsWith('/timing-run'));
  expect(JSON.parse(request[1].body)).toEqual({ sessionId,
    requestId: expect.stringMatching(/^[0-9a-f-]{36}$/i), message: 'Inspect timing without changing it.' });
  const result = container.querySelector('[aria-label="Timing audit agent result"]');
  expect(result.textContent).toContain('The owned timing target was observed.');
  expect(result.textContent).not.toContain('fixed policy');
  expect(result.textContent).not.toContain('Objective completion recorded');
});

test('unbounded observation retains its exact saved request after an uncertain response', async () => {
  auditCapabilities = { ...auditCapabilities, unbounded: { ready: true } };
  const requests = [];
  const modeCapability = { version: 1, featureId: 'audit_summary', policyVersion: 'capped-audit-metadata-v1',
    effectiveMode: 'vuln', scope: { kind: 'launch_feature', id: 'audit_summary' } };
  global.fetch = jest.fn((url, options = {}) => {
    if (String(url).includes('/admin/audit?')) return Promise.resolve(response({ events: [], count: 0, hasMore: false, nextCursor: null }));
    if (String(url).endsWith('/unbounded-session')) return Promise.resolve(response({ ok: true, sessionId }));
    if (String(url).endsWith('/unbounded-summary')) {
      requests.push(JSON.parse(options.body));
      if (requests.length === 1) return Promise.reject(new Error('Connection lost'));
      return Promise.resolve(response({ runId, summary: 'Recovered observation.', provider: 'ollama', model: 'llama3.1:8b',
        requestedCount: 5000, rowCount: 1, objectiveCredit: false, replayed: true,
        assessment: { completed: false, judgment: { verdict: 'unavailable' } }, modeCapability }));
    }
    throw new Error(`unexpected URL ${url}`);
  });
  await act(async () => renderAudit()); await settle();
  const observe = () => container.querySelector('[aria-label="Observe unbounded audit summary"]');
  await act(async () => observe().click()); await settle();
  await act(async () => observe().click()); await settle();
  expect(requests).toHaveLength(2);
  expect(requests[1]).toEqual(requests[0]);
  expect(container.textContent).toContain('Recovered observation.');
});

test('scope rotation aborts timing session admission before a timing run can dispatch', async () => {
  auditCapabilities = { ...auditCapabilities, timingAgent: { ready: true } };
  let resolveSession;
  global.fetch = jest.fn(url => {
    if (String(url).includes('/admin/audit?')) return Promise.resolve(response({ events: [], count: 0, hasMore: false, nextCursor: null }));
    if (String(url).endsWith('/timing-session')) return new Promise(resolve => { resolveSession = resolve; });
    throw new Error('Old scope must not start a timing run');
  });
  await act(async () => renderAudit({ scopeKey: 'old' })); await settle();
  const input = container.querySelector('[aria-label="Timing audit request"]');
  await act(async () => {
    Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, 'value').set.call(input, 'Inspect timing.');
    input.dispatchEvent(new Event('input', { bubbles: true }));
  });
  const ask = () => [...container.querySelectorAll('button')].find(button => button.textContent === 'Ask timing audit agent');
  await act(async () => ask().click());
  await act(async () => renderAudit({ scopeKey: 'new' }));
  await act(async () => resolveSession(response({ ok: true, sessionId })));
  await settle();
  expect(fetch.mock.calls.some(([url]) => String(url).endsWith('/timing-run'))).toBe(false);
});
