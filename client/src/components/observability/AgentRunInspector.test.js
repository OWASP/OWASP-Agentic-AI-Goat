import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import axios from 'axios';
import AgentRunInspector from './AgentRunInspector';

jest.mock('axios');

const run = { runId: 'run-1', family: 'ARIA', status: 'completed', generation: 2, lastNode: 'respond',
  startedAt: '2026-09-10T00:00:00.000Z', finishedAt: '2026-09-10T00:00:00.125Z' };
const flush = async () => act(async () => { await Promise.resolve(); await Promise.resolve(); await Promise.resolve(); });

beforeEach(() => {
  global.IS_REACT_ACT_ENVIRONMENT = true;
  axios.get.mockImplementation(url => Promise.resolve(url.endsWith('/run-1') ? { data: { run, graph: {
    nodes: ['decide', 'tool', 'judge'], edges: [{ source: 'decide', target: 'tool', condition: 'tool selected' }],
  }, events: [
    { seq: 1, node: 'decide', type: 'decision', createdAt: '2026-09-10T00:00:00.010Z', data: {
      decisionSource: 'model', tool: 'search_orders', provider: 'ollama', model: 'llama3.1:8b', tokens: 18,
      durationMs: 42, rationale: '<script>hidden thought</script>', prompt: 'secret prompt',
    } },
    { seq: 2, node: 'tool', type: 'tool', createdAt: '2026-09-10T00:00:00.060Z', data: { tool: 'search_orders', attempt: 1 } },
    { seq: 3, node: 'judge', type: 'decision', createdAt: '2026-09-10T00:00:00.100Z', data: { verdict: 'achieved', evidenceSummary: 'Verified tool outcome.' } },
    { seq: 4, node: 'decision/respond_repair', type: 'decision', createdAt: '2026-09-10T00:00:00.110Z', data: { provider: 'ollama', model: 'llama3.1:8b', attempt: 1 } },
    { seq: 5, node: 'judge_validate', type: 'invalid', data: { errorCode: 'INVALID_JUDGE_OUTPUT', validationCode: 'CITATION_NOT_GROUNDED', rawResponse: 'private invalid response' } },
  ] } } : { data: { runs: [run], families: [
    'ARIA', 'NOVA', 'CTF', 'LegacySensitiveInfo', 'SensitiveLookup', 'SecureShopBoundConversation',
  ] } }));
});
afterEach(() => { jest.clearAllMocks(); document.body.replaceChildren(); });

test('refresh reloads the selected completed run details even when the list is unchanged', async () => {
  let detailReads = 0;
  axios.get.mockImplementation(url => {
    if (url === '/api/admin/agent-runs') return Promise.resolve({ data: { runs: [run] } });
    detailReads += 1;
    return Promise.resolve({ data: { run, events: [{ seq: 1, type: 'decision',
      node: detailReads === 1 ? 'initial_judge' : 'refreshed_judge', data: { verdict: 'pass' } }] } });
  });
  const node = document.createElement('div'); document.body.appendChild(node); const root = createRoot(node);
  try {
    await act(async () => { root.render(<AgentRunInspector admin />); }); await flush();
    expect(node.textContent).toContain('initial_judge');
    act(() => Array.from(node.querySelectorAll('button')).find(button => button.textContent.includes('Refresh')).click());
    await flush();
    expect(node.textContent).toContain('refreshed_judge');
    expect(node.textContent).not.toContain('initial_judge');
    expect(detailReads).toBe(2);
  } finally { act(() => root.unmount()); }
});

test('retains the same-run receipt while a failed judgment refresh leaves detail reload pending', async () => {
  let judgmentsFail = false, detailReads = 0, resolveRefreshedDetail;
  const initialDetail = { run, events: [{ seq: 1, type: 'decision', node: 'retained_timeline' }], judgments: [{
    evaluationId: 'retained-evaluation', objectiveId: 'sql_1', verdict: 'inconclusive', disposition: 'not_pass',
    explanation: 'Retained receipt explanation.',
  }] };
  axios.get.mockImplementation(url => {
    if (url === '/api/agent-runs/judgments') return judgmentsFail
      ? Promise.reject({ response: { status: 503, data: { error: 'private diagnostic' } } })
      : Promise.resolve({ data: { judgments: [{ evaluationId: 'retained-evaluation', objectiveId: 'sql_1', verdict: 'inconclusive' }] } });
    if (url === '/api/agent-runs') return Promise.resolve({ data: { runs: [run] } });
    detailReads += 1;
    if (detailReads === 1) return Promise.resolve({ data: initialDetail });
    return new Promise(resolve => { resolveRefreshedDetail = resolve; });
  });
  const node = document.createElement('div'); document.body.appendChild(node); const root = createRoot(node);
  try {
    await act(async () => root.render(<AgentRunInspector />)); await flush();
    expect(node.textContent).toContain('Retained receipt explanation.');
    expect(node.textContent).toContain('retained_timeline');
    judgmentsFail = true;
    await act(async () => [...node.querySelectorAll('button')].find(button => button.textContent.includes('Refresh')).click());
    await flush();
    expect(detailReads).toBe(2);
    expect(node.querySelector('[role="alert"]').textContent).toContain('Previously loaded results may be out of date');
    expect(node.textContent).toContain('Retained receipt explanation.');
    expect(node.textContent).toContain('retained_timeline');
    expect(node.textContent).not.toContain('Loading timeline…');
    expect(node.textContent).not.toContain('private diagnostic');
    await act(async () => resolveRefreshedDetail({ data: { ...initialDetail,
      events: [{ seq: 2, type: 'decision', node: 'refreshed_timeline' }] } }));
    await flush();
    expect(node.textContent).toContain('refreshed_timeline');
    expect(node.textContent).not.toContain('retained_timeline');
  } finally { act(() => root.unmount()); }
});

test.each([401, 403, 404])('clears retained detail after a %s response during refresh', async status => {
  let detailReads = 0;
  axios.get.mockImplementation(url => {
    if (url === '/api/agent-runs/judgments') return Promise.resolve({ data: { judgments: [] } });
    if (url === '/api/agent-runs') return Promise.resolve({ data: { runs: [run] } });
    detailReads += 1;
    return detailReads === 1
      ? Promise.resolve({ data: { run, events: [{ seq: 1, type: 'decision', node: 'private_old_timeline' }],
        judgments: [{ evaluationId: 'private-old', objectiveId: 'sql_1', verdict: 'pass', disposition: 'awarded',
          explanation: 'Previously authorized receipt.' }] } })
      : Promise.reject({ response: { status, data: { error: 'Run detail access denied' } } });
  });
  const node = document.createElement('div'); document.body.appendChild(node); const root = createRoot(node);
  try {
    await act(async () => root.render(<AgentRunInspector />)); await flush();
    expect(node.textContent).toContain('Previously authorized receipt.');
    await act(async () => [...node.querySelectorAll('button')].find(button => button.textContent.includes('Refresh')).click());
    await flush();
    expect(node.querySelector('[role="alert"]').textContent).toContain('Run detail access denied');
    expect(node.textContent).not.toContain('Previously authorized receipt.');
    expect(node.textContent).not.toContain('private_old_timeline');
    expect(node.textContent).not.toContain('Loading timeline…');
    expect(node.querySelector('[aria-label="Authoritative Judge receipts"]')).toBeNull();
  } finally { act(() => root.unmount()); }
});

test('never renders retained detail under a different endpoint scope', async () => {
  let resolveOtherDetail;
  axios.get.mockImplementation(url => {
    if (url === '/api/admin/agent-runs') return Promise.resolve({ data: { runs: [run] } });
    if (url === '/api/admin/agent-runs/run-1') return Promise.resolve({ data: { run, events: [], judgments: [{
      evaluationId: 'admin-only', objectiveId: 'sql_1', verdict: 'pass', disposition: 'awarded',
      explanation: 'Administrator-only receipt.',
    }] } });
    if (url === '/api/scoped-runs') return Promise.resolve({ data: { runs: [run] } });
    if (url === '/api/scoped-runs/run-1') return new Promise(resolve => { resolveOtherDetail = resolve; });
    throw new Error(`Unexpected URL ${url}`);
  });
  const node = document.createElement('div'); document.body.appendChild(node); const root = createRoot(node);
  try {
    await act(async () => root.render(<AgentRunInspector admin endpoint="/api/admin/agent-runs" />)); await flush();
    expect(node.textContent).toContain('Administrator-only receipt.');
    await act(async () => root.render(<AgentRunInspector admin endpoint="/api/scoped-runs" />)); await flush();
    expect(resolveOtherDetail).toEqual(expect.any(Function));
    expect(node.textContent).not.toContain('Administrator-only receipt.');
    expect(node.querySelector('[aria-label="Authoritative Judge receipts"]')).toBeNull();
    expect(node.textContent).toContain('Loading timeline…');
    await act(async () => resolveOtherDetail({ data: { run, events: [], judgments: [] } }));
  } finally { act(() => root.unmount()); }
});

test('shows owner-safe run metadata and graph events without rationale or prompt content', async () => {
  const node = document.createElement('div'); document.body.appendChild(node); const root = createRoot(node);
  await act(async () => { root.render(<AgentRunInspector />); }); await flush();
  expect(node.textContent).toContain('ARIA · respond'); expect(node.textContent).toContain('tool: search_orders');
  expect(node.textContent).toContain('decision: model'); expect(node.textContent).toContain('provider: ollama');
  expect(node.textContent).toContain('model: llama3.1:8b'); expect(node.textContent).not.toContain('hidden thought');
  expect(node.textContent).toContain('Edge · decide → tool · tool selected'); expect(node.textContent).toContain('judge: achieved');
  expect(node.textContent).toContain('evidence: Verified tool outcome.');
  expect(node.textContent).toContain('Response assistance1 bounded model repair used');
  expect(node.textContent).toContain('assistance: bounded model repair');
  expect(node.textContent).toContain('Judge citation did not match the source evidence');
  expect(node.textContent).not.toContain('private invalid response');
  expect(node.textContent).not.toContain('secret prompt'); act(() => root.unmount());
});

test('uses family allowlist filter and refreshes the list', async () => {
  const node = document.createElement('div'); document.body.appendChild(node); const root = createRoot(node);
  await act(async () => { root.render(<AgentRunInspector admin />); }); await flush();
  const select = node.querySelector('select');
  expect(select.querySelector('option[value="CTF"]')).not.toBeNull();
  expect(select.querySelector('option[value="LegacySensitiveInfo"]')).not.toBeNull();
  expect(select.querySelector('option[value="SensitiveLookup"]')).not.toBeNull();
  expect(select.querySelector('option[value="SecureShopBoundConversation"]')).not.toBeNull();
  act(() => { const setter = Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype, 'value').set; setter.call(select, 'NOVA'); select.dispatchEvent(new Event('change', { bubbles: true })); });
  await flush(); expect(axios.get).toHaveBeenCalledWith('/api/admin/agent-runs', expect.objectContaining({ params: { family: 'NOVA', limit: 25 }, signal: expect.any(AbortSignal) }));
  act(() => root.unmount());
});

test('renders canonical receipt state and exercise context without grading content', async () => {
  axios.get.mockImplementation(url => {
    if (url === '/api/agent-runs/judgments') return Promise.resolve({ data: { judgments: [] } });
    if (url === '/api/agent-runs') return Promise.resolve({ data: { runs: [run] } });
    return Promise.resolve({ data: { run, graph: null, events: [], judgments: [
      { evaluationId: 'eval-canonical', runId: run.runId, workshopKey: 'sql_injection_workshop', objectiveId: 'sql_1', family: 'ARIA', scenario: 'product_search', rubricVersion: 'sql-v1', evidenceDigest: 'a'.repeat(64), verdict: 'pass', disposition: 'awarded', explanation: 'The observed product result proves the objective.', criteria: [{ id: 'observed_result', satisfied: true, evidenceRefs: ['tool_result'], citations: [{ evidenceId: 'tool_result', quote: 'Synthetic visible cited evidence.' }] }], evaluatedAt: '2026-09-10T00:00:01.000Z' },
      { evaluationId: 'eval-pending', runId: run.runId, workshopKey: 'sql_injection_workshop', objectiveId: 'sql_2', family: 'ARIA', scenario: 'product_search', rubricVersion: 'sql-v1', evidenceDigest: 'b'.repeat(64), verdict: null, disposition: 'pending' },
    ] } });
  });
  const node = document.createElement('div'); document.body.appendChild(node); const root = createRoot(node);
  await act(async () => { root.render(<AgentRunInspector />); }); await flush();
  expect(node.textContent).toContain('Authoritative Judge receipts');
  expect(node.textContent).toContain('ARIA · sql_1 · awarded');
  expect(node.textContent).toContain('Scenario: product_search');
  expect(node.textContent).toContain('Evaluation explanation: The observed product result proves the objective.');
  expect(node.textContent).toContain('Criterion observed_result: satisfied · Evidence: tool_result');
  expect(node.textContent).toContain('Citation tool_result: “Synthetic visible cited evidence.”');
  expect(node.textContent).toContain('ARIA · sql_2 · pending');
  expect(node.textContent).not.toContain('result_json');
  act(() => root.unmount());
});

test('labels separate receipt sources and makes partial availability visible', async () => {
  axios.get.mockImplementation(url => url === '/api/agent-runs'
    ? Promise.resolve({ data: { runs: [{ ...run, family: 'CTF' }] } })
    : Promise.resolve({ data: { run: { ...run, family: 'CTF' }, graph: null, events: [], judgments: [],
      receiptSources: [{ source: 'canonical', status: 'available', count: 0 }, { source: 'CTF', status: 'unavailable', code: 'FAMILY_RECEIPT_UNAVAILABLE' }] } }));
  const node = document.createElement('div'); document.body.appendChild(node); const root = createRoot(node);
  await act(async () => { root.render(<AgentRunInspector />); }); await flush();
  expect(node.textContent).toContain('A Judge receipt source is temporarily unavailable.');
  act(() => root.unmount());
});

test('refreshes linked receipts when terminal polling observes completion', async () => {
  jest.useFakeTimers();
  let detailCalls = 0, finishFinalDetail, finalSignal;
  const running = { ...run, status: 'running' };
  axios.get.mockImplementation((url, options) => {
    if (url === '/api/agent-runs/judgments') return Promise.resolve({ data: { judgments: [] } });
    if (url === '/api/agent-runs') return Promise.resolve({ data: { runs: [running] } });
    if (url.endsWith('/events')) return Promise.resolve({ data: { run: { ...running, status: 'completed' }, events: [] } });
    detailCalls += 1;
    if (detailCalls > 1) {
      finalSignal = options.signal;
      return new Promise(resolve => { finishFinalDetail = resolve; });
    }
    return Promise.resolve({ data: { run: { ...running, status: detailCalls > 1 ? 'completed' : 'running' }, events: [],
      judgments: detailCalls > 1 ? [{ receiptId: 'ctf:receipt', source: 'ctf', family: 'CTF', objectiveId: 'stage_1', verdict: 'pass', disposition: 'accepted' }] : [] } });
  });
  const node = document.createElement('div'); document.body.appendChild(node); const root = createRoot(node);
  await act(async () => { root.render(<AgentRunInspector />); }); await flush();
  await act(async () => { jest.advanceTimersByTime(4000); await Promise.resolve(); await Promise.resolve(); });
  expect(detailCalls).toBeGreaterThanOrEqual(2);
  await flush();
  expect(finalSignal.aborted).toBe(false);
  const pendingDetailCalls = detailCalls;
  await act(async () => { jest.advanceTimersByTime(12000); }); await flush();
  expect(detailCalls).toBe(pendingDetailCalls);
  expect(axios.get.mock.calls.filter(([url]) => url.endsWith('/events'))).toHaveLength(1);
  await act(async () => finishFinalDetail({ data: { run, events: [], judgments: [
    { receiptId: 'ctf:receipt', source: 'ctf', family: 'CTF', objectiveId: 'stage_1', verdict: 'pass', disposition: 'accepted' },
  ] } })); await flush();
  expect(node.textContent).toContain('Receipt source: ctf');
  act(() => root.unmount()); jest.useRealTimers();
});

test('slow live-event reads never overlap and polling resumes after settlement', async () => {
  jest.useFakeTimers();
  const running = { ...run, status: 'running' };
  let finishEvents;
  axios.get.mockImplementation(url => {
    if (url === '/api/agent-runs/judgments') return Promise.resolve({ data: { judgments: [] } });
    if (url === '/api/agent-runs') return Promise.resolve({ data: { runs: [running] } });
    if (url.endsWith('/events')) return new Promise(resolve => { finishEvents = resolve; });
    return Promise.resolve({ data: { run: running, events: [] } });
  });
  const node = document.createElement('div'); document.body.appendChild(node); const root = createRoot(node);
  try {
    await act(async () => root.render(<AgentRunInspector />)); await flush();
    await act(async () => jest.advanceTimersByTime(16000)); await flush();
    expect(axios.get.mock.calls.filter(([url]) => url.endsWith('/events'))).toHaveLength(1);
    await act(async () => finishEvents({ data: { run: running, events: [] } })); await flush();
    await act(async () => jest.advanceTimersByTime(4000)); await flush();
    expect(axios.get.mock.calls.filter(([url]) => url.endsWith('/events'))).toHaveLength(2);
  } finally { act(() => root.unmount()); jest.useRealTimers(); }
});

test('shows polling failures without discarding the last timeline and clears them after recovery', async () => {
  jest.useFakeTimers();
  const running = { ...run, status: 'running' };
  let available = false;
  axios.get.mockImplementation(url => {
    if (url.endsWith('/judgments')) return Promise.resolve({ data: { judgments: [] } });
    if (url === '/api/agent-runs') return Promise.resolve({ data: { runs: [running] } });
    if (url.endsWith('/events')) return available
      ? Promise.resolve({ data: { run: running, events: [] } })
      : Promise.reject(new Error('private connection details'));
    return Promise.resolve({ data: { run: running, events: [{ seq: 1, node: 'observed_tool', type: 'tool', data: {} }] } });
  });
  const node = document.createElement('div'); document.body.appendChild(node); const root = createRoot(node);
  try {
    await act(async () => root.render(<AgentRunInspector />)); await flush();
    await act(async () => jest.advanceTimersByTime(4000)); await flush();
    expect(node.querySelector('[role="alert"]')?.textContent).toContain('Live updates are temporarily unavailable');
    expect(node.textContent).toContain('observed_tool');
    expect(node.textContent).not.toContain('private connection details');
    available = true;
    await act(async () => jest.advanceTimersByTime(4000)); await flush();
    expect(node.querySelector('[role="alert"]')).toBeNull();
    expect(node.textContent).toContain('observed_tool');
  } finally { act(() => root.unmount()); jest.useRealTimers(); }
});

test.each([401, 403, 404])('clears retained detail when terminal polling receives a %s full-run response', async status => {
  jest.useFakeTimers();
  const running = { ...run, status: 'running' };
  let detailReads = 0;
  axios.get.mockImplementation(url => {
    if (url === '/api/agent-runs/judgments') return Promise.resolve({ data: { judgments: [] } });
    if (url === '/api/agent-runs') return Promise.resolve({ data: { runs: [running] } });
    if (url.endsWith('/events')) return Promise.resolve({ data: { run: { ...running, status: 'completed' }, events: [] } });
    detailReads += 1;
    return detailReads === 1
      ? Promise.resolve({ data: { run: running, events: [{ seq: 1, node: 'private_polled_event', type: 'decision' }],
        judgments: [{ evaluationId: 'private-polled', objectiveId: 'sql_1', verdict: 'pass', disposition: 'awarded',
          explanation: 'Private polled receipt.' }] } })
      : Promise.reject({ response: { status, data: { error: 'Polled run access denied' } } });
  });
  const node = document.createElement('div'); document.body.appendChild(node); const root = createRoot(node);
  try {
    await act(async () => root.render(<AgentRunInspector />)); await flush();
    expect(node.textContent).toContain('Private polled receipt.');
    await act(async () => { jest.advanceTimersByTime(4000); await Promise.resolve(); await Promise.resolve(); });
    await flush();
    expect(node.querySelector('[role="alert"]').textContent).toContain('Polled run access denied');
    expect(node.textContent).not.toContain('Private polled receipt.');
    expect(node.textContent).not.toContain('private_polled_event');
    expect(node.textContent).not.toContain('Loading timeline…');
    expect(node.querySelector('[aria-label="Authoritative Judge receipts"]')).toBeNull();
  } finally { act(() => root.unmount()); jest.useRealTimers(); }
});

test('renders API failures as escaped status text', async () => {
  axios.get.mockRejectedValueOnce({ response: { data: { error: '<b>Run store unavailable</b>' } } });
  const node = document.createElement('div'); document.body.appendChild(node); const root = createRoot(node);
  await act(async () => { root.render(<AgentRunInspector />); }); await flush();
  expect(node.querySelector('[role="alert"]').textContent).toBe('<b>Run store unavailable</b>');
  expect(node.querySelector('b')).toBeNull(); act(() => root.unmount());
});

test('discovers owner recovery metadata on mount and retries by evaluation ID only', async () => {
  const recovery = {
    evaluationId: 'eval-123', runId: 'run-1', family: 'XSS', objectiveId: 'xss_r2',
    verdict: 'unavailable', errorCode: 'JUDGE_QUEUE_FULL', createdAt: '2026-09-10T00:00:00.000Z', canRetry: true,
    rawPayload: 'never render this student payload', evidence: { secret: 'never render evidence' },
  };
  axios.get.mockImplementation(url => {
    if (url === '/api/agent-runs/judgments') return Promise.resolve({ data: { judgments: [recovery] } });
    if (url === '/api/agent-runs') return Promise.resolve({ data: { runs: [run] } });
    return Promise.resolve({ data: { run: { ...run, runId: url.endsWith('retry-run') ? 'retry-run' : 'run-1' }, events: [] } });
  });
  axios.post.mockResolvedValue({ data: {
    judgment: { verdict: 'pass', evaluationId: 'eval-child', canRetry: false },
    completed: true, retryRunId: 'retry-run',
  } });
  const node = document.createElement('div'); document.body.appendChild(node); const root = createRoot(node);
  await act(async () => { root.render(<AgentRunInspector />); }); await flush();

  expect(axios.get).toHaveBeenCalledWith('/api/agent-runs/judgments', { signal: expect.any(AbortSignal) });
  expect(node.textContent).toContain('XSS · xss_r2');
  expect(node.textContent).toContain('Verdict: unavailable');
  expect(node.textContent).toContain('The evaluation queue is full.');
  expect(node.textContent).not.toContain('never render this student payload');
  expect(node.textContent).not.toContain('never render evidence');
  await act(async () => node.querySelector('[data-testid="judge-retry-eval-123"]').click());
  await flush();
  expect(axios.post).toHaveBeenCalledWith('/api/agent-runs/judgments/eval-123/retry', {}, { signal: expect.any(AbortSignal) });
  expect(JSON.stringify(axios.post.mock.calls[0])).not.toMatch(/rawPayload|evidence|objectiveId|userId/);
  expect(axios.get).toHaveBeenCalledWith('/api/agent-runs/retry-run', { signal: expect.any(AbortSignal) });
  act(() => root.unmount());
});

test('hides recovery UI when the durable grade store is unavailable', async () => {
  axios.get.mockImplementation(url => url === '/api/agent-runs/judgments'
    ? Promise.reject({ response: { data: { code: 'GRADE_STORE_NOT_READY' } } })
    : Promise.resolve({ data: { runs: [run] } }));
  const node = document.createElement('div'); document.body.appendChild(node); const root = createRoot(node);
  await act(async () => { root.render(<AgentRunInspector />); }); await flush();
  expect(node.querySelector('[aria-label="Recent evaluation recovery"]')).toBeNull();
  expect(node.textContent).not.toContain('Grade recovery store unavailable');
  act(() => root.unmount());
});

test.each([undefined, 503])('retains prior recovery evaluations for transient failure %s and clears alert on retry', async status => {
  let failed = false;
  axios.get.mockImplementation(url => {
    if (url === '/api/agent-runs/judgments') return failed
      ? Promise.reject({ response: { status, data: { error: 'private provider diagnostic' } } })
      : Promise.resolve({ data: { judgments: [{ evaluationId: 'saved', family: 'XSS',
        objectiveId: 'saved-objective', verdict: 'pass', canRetry: false }] } });
    return Promise.resolve({ data: { runs: [] } });
  });
  const node = document.createElement('div'); const root = createRoot(node);
  await act(async () => root.render(<AgentRunInspector />)); await flush();
  expect(node.textContent).toContain('saved-objective');
  failed = true;
  await act(async () => [...node.querySelectorAll('button')].find(button => button.textContent.includes('Refresh')).click());
  await flush();
  expect(node.querySelector('[role="alert"]').textContent).toContain('Previously loaded results may be out of date');
  expect(node.textContent).toContain('saved-objective');
  expect(node.textContent).not.toContain('private provider diagnostic');
  failed = false;
  await act(async () => [...node.querySelectorAll('button')].find(button => button.textContent.includes('Refresh')).click());
  await flush();
  expect(node.querySelector('[role="alert"]')).toBeNull();
  act(() => root.unmount());
});

test('ignores an older recovery failure after a newer refresh succeeds', async () => {
  let rejectOld;
  let reads = 0;
  axios.get.mockImplementation(url => {
    if (url === '/api/agent-runs/judgments') {
      reads += 1;
      if (reads === 1) return new Promise((_resolve, reject) => { rejectOld = reject; });
      return Promise.resolve({ data: { judgments: [{ evaluationId: 'new', family: 'XSS',
        objectiveId: 'new-objective', verdict: 'pass', canRetry: false }] } });
    }
    return Promise.resolve({ data: { runs: [] } });
  });
  const node = document.createElement('div'); const root = createRoot(node);
  await act(async () => root.render(<AgentRunInspector />)); await flush();
  await act(async () => [...node.querySelectorAll('button')].find(button => button.textContent.includes('Refresh')).click());
  await flush();
  await act(async () => rejectOld(new Error('old failed request'))); await flush();
  expect(node.querySelector('[role="alert"]')).toBeNull();
  expect(node.textContent).toContain('new-objective');
  act(() => root.unmount());
});

test('aborts recovery discovery and suppresses a late response after unmount', async () => {
  let resolveJudgments;
  let discoverySignal;
  axios.get.mockImplementation((url, options = {}) => {
    if (url === '/api/agent-runs/judgments') {
      discoverySignal = options.signal;
      return new Promise(resolve => { resolveJudgments = resolve; });
    }
    return Promise.resolve({ data: { runs: [run] } });
  });
  const node = document.createElement('div'); document.body.appendChild(node); const root = createRoot(node);
  await act(async () => { root.render(<AgentRunInspector />); }); await flush();
  act(() => root.unmount());
  expect(discoverySignal.aborted).toBe(true);
  await act(async () => resolveJudgments({ data: { judgments: [{
    evaluationId: 'late-evaluation', family: 'MCP', objectiveId: 'mcp_1', verdict: 'unavailable', canRetry: true,
  }] } }));
  expect(node.textContent).toBe('');
});

test.each(['success', 'failure'])('keeps the newest filter when an older request completes with %s', async outcome => {
  let resolveOlder, rejectOlder;
  const older = new Promise((resolve, reject) => { resolveOlder = resolve; rejectOlder = reject; });
  const latest = { ...run, runId: 'latest-run', family: 'NOVA' };
  axios.get.mockImplementation((url, options) => {
    if (url === '/api/admin/agent-runs') {
      if (options.params.family === 'ARIA') return older;
      return Promise.resolve({ data: { runs: options.params.family === 'NOVA' ? [latest] : [run], families: ['ARIA', 'NOVA'] } });
    }
    return Promise.resolve({ data: { run: url.endsWith('/latest-run') ? latest : run, events: [] } });
  });
  const node = document.createElement('div'); document.body.appendChild(node); const root = createRoot(node);
  try {
    await act(async () => { root.render(<AgentRunInspector admin />); }); await flush();
    const select = node.querySelector('select');
    const choose = value => act(() => {
      Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype, 'value').set.call(select, value);
      select.dispatchEvent(new Event('change', { bubbles: true }));
    });
    choose('ARIA'); await flush(); choose('NOVA'); await flush();
    expect(node.textContent).toContain('latest-run');
    await act(async () => {
      if (outcome === 'success') resolveOlder({ data: { runs: [run], families: ['ARIA'] } });
      else rejectOlder({ response: { data: { error: 'Stale request failure' } } });
    }); await flush();
    expect(node.textContent).toContain('latest-run');
    expect(node.textContent).not.toContain('Stale request failure');
    expect(select.value).toBe('NOVA');
  } finally { act(() => root.unmount()); }
});

test('loads later timeline pages for a completed run so final Judge events remain visible', async () => {
  axios.get.mockImplementation(url => {
    if (url === '/api/admin/agent-runs') return Promise.resolve({ data: { runs: [run] } });
    if (url.endsWith('/events')) return Promise.resolve({ data: { run, nextCursor: null,
      events: [{ seq: 101, node: 'final_objective_judge', type: 'decision', data: { verdict: 'pass' } }] } });
    return Promise.resolve({ data: { run, nextCursor: 100,
      events: Array.from({ length: 100 }, (_, index) => ({ seq: index + 1, node: `step_${index + 1}`, type: 'decision' })) } });
  });
  const node = document.createElement('div'); document.body.appendChild(node); const root = createRoot(node);
  try {
    await act(async () => { root.render(<AgentRunInspector admin />); }); await flush();
    expect(node.textContent).toContain('final_objective_judge');
    expect(node.textContent).toContain('judge: pass');
    expect(axios.get).toHaveBeenCalledWith('/api/admin/agent-runs/run-1/events', expect.objectContaining({ params: { after: 100, limit: 100 } }));
  } finally { act(() => root.unmount()); }
});

test('keeps the run list usable after a detail failure and recovers on another selection', async () => {
  const healthy = { ...run, runId: 'healthy-run', family: 'NOVA' };
  axios.get.mockImplementation(url => {
    if (url === '/api/admin/agent-runs') return Promise.resolve({ data: { runs: [run, healthy] } });
    if (url.endsWith('/run-1')) return Promise.reject({ response: { data: { error: 'This run is temporarily unavailable' } } });
    return Promise.resolve({ data: { run: healthy, events: [], judgments: [] } });
  });
  const node = document.createElement('div'); document.body.appendChild(node); const root = createRoot(node);
  try {
    await act(async () => { root.render(<AgentRunInspector admin />); }); await flush();
    expect(node.textContent).toContain('This run is temporarily unavailable');
    const healthyButton = Array.from(node.querySelectorAll('[aria-label="Agent runs"] button')).find(button => button.textContent.includes('NOVA'));
    expect(healthyButton).toBeDefined();
    act(() => healthyButton.click()); await flush();
    expect(node.textContent).toContain('healthy-run');
    expect(node.textContent).not.toContain('This run is temporarily unavailable');
  } finally { act(() => root.unmount()); }
});

const protectedOperation = { operationId:'operation-1', operation:'rotate_secret', origin:'controlled', originalEffectStatus:'uncertain',canReconcile:true,creditGranted:false };
function protectedFixture(operation=protectedOperation){axios.get.mockImplementation(url=>Promise.resolve({data:url.endsWith('/run-1')?{run:{...run,status:'failed'},events:[],protectedOperations:[operation]}:url.endsWith('/judgments')?{judgments:[]}:{runs:[{...run,status:'failed'}]}}));}
test.each([false,true])('protected readback respects administrator observer boundary (%s)',async admin=>{
 protectedFixture(); const node=document.createElement('div');document.body.appendChild(node);const root=createRoot(node);
 try{await act(async()=>root.render(<AgentRunInspector admin={admin}/>));await flush();
 expect(node.textContent).toContain('Original effect: uncertain');expect(node.textContent).toContain('does not rerun the tool');
 const button=Array.from(node.querySelectorAll('button')).find(b=>b.textContent==='Check receipt');expect(Boolean(button)).toBe(!admin);
 if(!admin){axios.post.mockResolvedValue({data:{...protectedOperation,outcome:'completed'}});await act(async()=>button.click());await flush();expect(axios.post).toHaveBeenCalledWith('/api/workshop/mcp/protected-operations/reconcile',{operationId:'operation-1'},expect.objectContaining({signal:expect.any(AbortSignal)}));expect(node.textContent).toContain('failed');}
 }finally{act(()=>root.unmount());}
});
test('unavailable protected readback retains original uncertainty and never claims recovery',async()=>{
 protectedFixture();axios.post.mockRejectedValue({response:{status:404}});const node=document.createElement('div');document.body.appendChild(node);const root=createRoot(node);
 try{await act(async()=>root.render(<AgentRunInspector/>));await flush();await act(async()=>Array.from(node.querySelectorAll('button')).find(b=>b.textContent==='Check receipt').click());await flush();expect(node.textContent).toContain('unavailable in the current session');expect(node.textContent).toContain('Receipt: not checked');expect(node.textContent).toContain('Original effect: uncertain');}finally{act(()=>root.unmount());}
});
test('protected readback is single-flight and aborts when inspector unmounts',async()=>{
 protectedFixture();let resolve;axios.post.mockImplementation(()=>new Promise(r=>{resolve=r;}));const node=document.createElement('div');document.body.appendChild(node);const root=createRoot(node);
 await act(async()=>root.render(<AgentRunInspector/>));await flush();const button=Array.from(node.querySelectorAll('button')).find(b=>b.textContent==='Check receipt');act(()=>{button.click();button.click();});expect(axios.post).toHaveBeenCalledTimes(1);const signal=axios.post.mock.calls[0][2].signal;act(()=>root.unmount());expect(signal.aborted).toBe(true);await act(async()=>resolve({data:{...protectedOperation,outcome:'completed'}}));
});
test('protected readback rejects malformed success metadata',async()=>{
 protectedFixture();axios.post.mockResolvedValue({data:{...protectedOperation,outcome:'completed',creditGranted:true}});const node=document.createElement('div');document.body.appendChild(node);const root=createRoot(node);
 try{await act(async()=>root.render(<AgentRunInspector/>));await flush();await act(async()=>Array.from(node.querySelectorAll('button')).find(b=>b.textContent==='Check receipt').click());await flush();expect(node.textContent).toContain('Receipt readback is unavailable');expect(node.textContent).toContain('Receipt: not checked');}finally{act(()=>root.unmount());}
});

test.each([
  ['completed stages', {comparisonVersion:'source-only-obligation-verified-v4',comparisonStages:[
    {stage:'source',attempts:1,provider:'ollama',model:'llama3.1:8b',completed:true},
    {stage:'effect',attempts:2,provider:'ollama',model:'llama3.1:8b',completed:true},
    {stage:'support',attempts:1,provider:'ollama',model:'llama3.1:8b',completed:true},
  ]}],
  ['incomplete support', {comparisonVersion:'source-only-obligation-verified-v4',comparisonStages:[
    {stage:'source',attempts:1,provider:'ollama',model:'llama3.1:8b',completed:true},
    {stage:'effect',attempts:1,provider:'ollama',model:'llama3.1:8b',completed:true},
    {stage:'support',attempts:2,provider:null,model:null,completed:false},
  ]}],
  ['legacy receipt', {}],
])('renders honest comparison details for %s without changing receipt outcome', async (label, metadata) => {
  axios.get.mockImplementation(url => Promise.resolve({data:url.endsWith('/run-1') ? {
    run,events:[],judgments:[{evaluationId:'comparison-eval',objectiveId:'rag_query_injection',
      verdict:'unavailable',disposition:'not_pass',...metadata,
      rawReasoning:'PRIVATE_REASONING_NOT_DISPLAYED',sourceObligations:[{requirementQuote:'PRIVATE_OBLIGATION_NOT_DISPLAYED'}]}],
  } : {runs:[run]}}));
  const node=document.createElement('div');document.body.appendChild(node);const root=createRoot(node);
  try {
    await act(async()=>root.render(<AgentRunInspector admin />));await flush();
    const receipts=node.querySelector('[aria-label="Authoritative Judge receipts"]');
    expect(receipts.textContent).toContain('Verdict: unavailable · Disposition: not_pass');
    expect(receipts.textContent).not.toContain('PRIVATE_');
    if(label==='legacy receipt') {
      expect(receipts.textContent).not.toContain('Comparison version:');
      expect(receipts.textContent).not.toContain('Judge stage:');
    } else {
      expect(receipts.textContent).toContain('Comparison version: source-only-obligation-verified-v4');
      expect(receipts.textContent).toContain('Judge stage: Source classification · 1 attempt · ollama · llama3.1:8b · Completed');
      expect(receipts.textContent).toContain('Judge stage: Response effect');
      expect(receipts.textContent).toContain(label==='incomplete support'
        ? 'Judge stage: Independent support · 2 attempts · Provider unavailable · Model unavailable · Incomplete'
        : 'Judge stage: Independent support · 1 attempt · ollama · llama3.1:8b · Completed');
    }
  } finally { await act(async()=>root.unmount()); }
});


test.each([
  ['completed', 'Completed'], ['failed', 'Failed'], ['running', 'Running'],
  ['queued', 'Starting'], ['cancelled', 'Cancelled'], ['unknown', 'No node recorded'],
])('missing last node uses honest %s run label', async (status, label) => {
  const currentRun = { ...run, lastNode: null, status };
  axios.get.mockImplementation(url => Promise.resolve({ data: url.endsWith('/run-1')
    ? { run: currentRun, events: [] } : { runs: [currentRun] } }));
  const node = document.createElement('div'); document.body.appendChild(node);
  const root = createRoot(node);
  try {
    await act(async () => root.render(<AgentRunInspector admin />)); await flush();
    const row = node.querySelector('[data-run-id="run-1"]');
    expect(row.querySelector('strong').textContent).toBe(`ARIA · ${label}`);
    expect(row.textContent).toContain(status);
    expect(node.textContent).toContain('Last node—');
  } finally { act(() => root.unmount()); }
});


test.each([401, 403, 404])('clears prior recovery receipts and retry actions after access denial %s', async status => {
  let denied = false;
  axios.get.mockImplementation(url => url === '/api/agent-runs/judgments'
    ? denied ? Promise.reject({ response: { status, data: { error: 'private denial' } } })
      : Promise.resolve({ data: { judgments: [{ evaluationId: 'prior-evaluation', family: 'XSS',
          objectiveId: 'prior-private-objective', verdict: 'unavailable', canRetry: true }] } })
    : Promise.resolve({ data: { runs: [] } }));
  const node = document.createElement('div'); const root = createRoot(node);
  await act(async () => root.render(<AgentRunInspector />)); await flush();
  expect(node.textContent).toContain('prior-private-objective');
  expect(node.querySelector('[aria-label="Recent evaluation recovery"]')).not.toBeNull();
  denied = true;
  await act(async () => [...node.querySelectorAll('button')].find(button => button.textContent.includes('Refresh')).click());
  await flush();
  expect(node.textContent).not.toContain('prior-private-objective');
  expect(node.querySelector('[aria-label="Recent evaluation recovery"]')).toBeNull();
  expect(node.textContent).toContain('Recent evaluations are no longer accessible');
  expect(node.textContent).not.toContain('private denial');
  expect(axios.post).not.toHaveBeenCalled();
  act(() => root.unmount());
});


test('explains unqualified grading without hiding the raw pass verdict or awarding completion', async () => {
  const judgment = { evaluationId: 'unqualified', objectiveId: 'diagnostic-objective',
    verdict: 'pass', disposition: 'grading_unqualified', canRetry: false };
  axios.get.mockImplementation(url => Promise.resolve({ data: url.endsWith('/judgments')
    ? { judgments: [judgment] } : url.endsWith('/run-1')
      ? { run, events: [], judgments: [judgment] } : { runs: [run] } }));
  const node = document.createElement('div'); const root = createRoot(node);
  await act(async () => root.render(<AgentRunInspector />)); await flush();
  expect(node.textContent.match(/Grading pending qualification; no completion awarded/g)).toHaveLength(2);
  expect(node.textContent).toContain('Verdict: pass · State: grading_unqualified');
  expect(node.textContent).toContain('Verdict: pass · Disposition: grading_unqualified');
  expect(axios.post).not.toHaveBeenCalled();
  act(() => root.unmount());
});

test.each([401, 403, 404])('does not restore a late initial detail after live polling denies access %s', async status => {
  jest.useFakeTimers();
  const running = { ...run, status: 'running' };
  let finishDetail;
  axios.get.mockImplementation(url => {
    if (url.endsWith('/judgments')) return Promise.resolve({ data: { judgments: [] } });
    if (url === '/api/agent-runs') return Promise.resolve({ data: { runs: [running] } });
    if (url.endsWith('/events')) return Promise.reject({ response: { status, data: { error: 'Run access denied' } } });
    return new Promise(resolve => { finishDetail = resolve; });
  });
  const node = document.createElement('div'); document.body.appendChild(node); const root = createRoot(node);
  try {
    await act(async () => root.render(<AgentRunInspector />)); await flush();
    await act(async () => jest.advanceTimersByTime(4000)); await flush();
    expect(node.textContent).toContain('Run access denied');
    await act(async () => finishDetail({ data: { run: running,
      events: [{ seq: 1, node: 'private_late_event', type: 'decision' }],
      judgments: [{ evaluationId: 'late-private', objectiveId: 'sql_1', verdict: 'pass', disposition: 'awarded', explanation: 'Private late receipt.' }] } }));
    await flush();
    expect(node.textContent).not.toContain('private_late_event');
    expect(node.textContent).not.toContain('Private late receipt.');
    expect(node.querySelector('[aria-label="Authoritative Judge receipts"]')).toBeNull();
  } finally { act(() => root.unmount()); jest.useRealTimers(); }
});

test.each([401, 403, 404])('does not restore a late terminal polling receipt after detail refresh denies access %s', async status => {
  jest.useFakeTimers();
  const running = { ...run, status: 'running' };
  let finishTerminal, reads = 0;
  axios.get.mockImplementation(url => {
    if (url.endsWith('/judgments')) return Promise.resolve({ data: { judgments: [] } });
    if (url === '/api/agent-runs') return Promise.resolve({ data: { runs: [running] } });
    if (url.endsWith('/events')) return Promise.resolve({ data: { run, events: [] } });
    reads += 1;
    if (reads === 1) return Promise.resolve({ data: { run: running, events: [] } });
    if (reads === 2) return new Promise(resolve => { finishTerminal = resolve; });
    return Promise.reject({ response: { status, data: { error: 'Refresh access denied' } } });
  });
  const node = document.createElement('div'); document.body.appendChild(node); const root = createRoot(node);
  try {
    await act(async () => root.render(<AgentRunInspector />)); await flush();
    await act(async () => jest.advanceTimersByTime(4000)); await flush();
    expect(reads).toBe(2);
    await act(async () => [...node.querySelectorAll('button')].find(button => button.textContent.includes('Refresh')).click()); await flush();
    expect(node.textContent).toContain('Refresh access denied');
    await act(async () => finishTerminal({ data: { run, events: [], judgments: [{
      evaluationId: 'late-terminal', objectiveId: 'sql_1', verdict: 'pass', disposition: 'awarded', explanation: 'Private terminal receipt.' }] } }));
    await flush();
    expect(node.textContent).not.toContain('Private terminal receipt.');
    expect(node.querySelector('[aria-label="Authoritative Judge receipts"]')).toBeNull();
  } finally { act(() => root.unmount()); jest.useRealTimers(); }
});

test('fresh authorized refresh restores detail without accepting an older denied-epoch response', async () => {
  jest.useFakeTimers();
  const running = { ...run, status: 'running' };
  let finishOldDetail, reads = 0;
  axios.get.mockImplementation(url => {
    if (url.endsWith('/judgments')) return Promise.resolve({ data: { judgments: [] } });
    if (url === '/api/agent-runs') return Promise.resolve({ data: { runs: [running] } });
    if (url.endsWith('/events')) return Promise.reject({ response: { status: 403, data: { error: 'Access denied' } } });
    reads += 1;
    if (reads === 1) return new Promise(resolve => { finishOldDetail = resolve; });
    return Promise.resolve({ data: { run: running, events: [{ seq: 2, node: 'fresh_authorized_event', type: 'decision' }] } });
  });
  const node = document.createElement('div'); document.body.appendChild(node); const root = createRoot(node);
  try {
    await act(async () => root.render(<AgentRunInspector />)); await flush();
    await act(async () => jest.advanceTimersByTime(4000)); await flush();
    expect(node.textContent).toContain('Access denied');
    await act(async () => [...node.querySelectorAll('button')].find(button => button.textContent.includes('Refresh')).click()); await flush();
    expect(node.textContent).toContain('fresh_authorized_event');
    expect(node.textContent).not.toContain('Access denied');
    await act(async () => finishOldDetail({ data: { run: running, events: [{ seq: 1, node: 'obsolete_private_event', type: 'decision' }] } })); await flush();
    expect(node.textContent).toContain('fresh_authorized_event');
    expect(node.textContent).not.toContain('obsolete_private_event');
  } finally { act(() => root.unmount()); jest.useRealTimers(); }
});

test('DPI conditional registration is separate from actual timeline and receipt availability', async () => {
 const dpiRun={...run,family:'DPI'};
 axios.get.mockImplementation(url=>Promise.resolve(url.endsWith('/run-1')?{data:{run:dpiRun,events:[{seq:1,node:'actor_model',type:'node_end'}],judgments:[],receiptSources:[{status:'unavailable'}],graph:{scope:'registered-current',nodes:[{id:'model'}],edges:[{source:'detect',target:'__end__',conditional:true},{source:'detect',target:'publication',conditional:true,condition:'grade needed'}],subgraphs:[{id:'decoder',parentNode:'model',activation:'Obfuscation objective only (conditional)',nodes:[{id:'decode_payload'}],edges:[]}]}}}:{data:{runs:[dpiRun]}}));
 const node=document.createElement('div');document.body.appendChild(node);const root=createRoot(node);
 try {await act(async()=>{root.render(<AgentRunInspector admin/>);});await flush();
  expect(node.textContent).toContain('not a historical execution record');
  expect(node.textContent).toContain('detect → __end__ · conditional');expect(node.textContent).toContain('detect → publication · grade needed');
  const child=node.querySelector('[aria-label="Conditional registered subgraph"]');expect(child.textContent).toContain('decode_payload');expect(child.textContent).toContain('Registration does not establish execution');
  expect(node.textContent).toContain('temporarily unavailable');expect(node.textContent).toContain('actor_model');
  expect(node.textContent.match(/decode_payload/g)).toHaveLength(1);
 } finally {act(()=>root.unmount());}
});

test('semantic comparison stage names describe actual task-only verification and response assessment', async () => {
  axios.get.mockImplementation(url => Promise.resolve({data:url.endsWith('/run-1') ? {
    run,events:[],judgments:[{evaluationId:'semantic-eval',objectiveId:'rag_injected_doc',verdict:'unavailable',disposition:'not_pass',comparisonVersion:'rag-semantic-decomposition-v4',comparisonStages:['source','effect','support'].map(stage=>({stage,attempts:1,provider:'controlled',model:'fixture',completed:true}))}],
  } : {runs:[run]}}));
  const node=document.createElement('div');document.body.appendChild(node);const root=createRoot(node);
  try {await act(async()=>root.render(<AgentRunInspector admin/>));await flush();const text=node.querySelector('[aria-label="Authoritative Judge receipts"]').textContent;expect(text).toContain('Judge stage: Source inventory');expect(text).toContain('Judge stage: Source coverage and task relation');expect(text).toContain('Judge stage: Response assessment');expect(text).not.toContain('Independent support');expect(text).toContain('Verdict: unavailable');}finally{await act(async()=>root.unmount());node.remove();}
});

test('saved mail shows server observations separately from unchanged model rationale', async () => {
  axios.get.mockImplementation(url => Promise.resolve({data: url.endsWith('/run-1') ? {run,events:[],judgments:[{
    evaluationId:'mail-evaluation',family:'SecureShop',objectiveId:'ss_mail_stored_browser_execution',verdict:'fail',disposition:'not_pass',
    explanation:'The message was not mounted.',serverObservation:{version:'saved-mail-browser-observation-v1',componentMounted:true,browserEffectCompleted:true,attributedExecution:false,targetEffectObserved:false,provenanceDigest:'a'.repeat(64)}
  }]} : {runs:[run]}}));
  const node=document.createElement('div');document.body.appendChild(node);const root=createRoot(node);
  try {await act(async()=>{root.render(<AgentRunInspector admin />);});await flush();
    expect(node.textContent).toContain('Inbox component mounted: yes');
    expect(node.textContent).toContain('Attributed execution: no');
    expect(node.textContent).toContain('Target effect observed: no');
    expect(node.textContent).toContain('Model rationale (may contain errors): The message was not mounted.');
    expect(node.textContent).toContain('Verdict: fail');
  } finally {act(()=>root.unmount());}
});

test('successful retry keeps its run refresh alive when recovery capability becomes false', async () => {
  let judgmentReads=0,listReads=0,resolveRuns,refreshSignal;
  const recovery={evaluationId:'eval-refresh',runId:'run-1',family:'XSS',objectiveId:'xss_r2',verdict:'unavailable',canRetry:true};
  axios.get.mockImplementation((url,options)=>{
    if(url==='/api/agent-runs/judgments')return Promise.resolve({data:{judgments:[{...recovery,canRetry:++judgmentReads===1}]}});
    if(url==='/api/agent-runs'){
      if(++listReads===1)return Promise.resolve({data:{runs:[run]}});
      refreshSignal=options.signal;return new Promise(resolve=>{resolveRuns=resolve;});
    }
    return Promise.resolve({data:{run:{...run,runId:url.endsWith('retry-run')?'retry-run':'run-1'},events:[]}});
  });
  axios.post.mockResolvedValue({data:{completed:false,judgment:{verdict:'inconclusive'},retryRunId:'retry-run'}});
  const node=document.createElement('div');document.body.appendChild(node);const root=createRoot(node);
  try {
    await act(async()=>root.render(<AgentRunInspector/>));await flush();
    await act(async()=>node.querySelector('[data-testid="judge-retry-eval-refresh"]').click());await flush();
    expect(node.querySelector('[data-testid="judge-retry-eval-refresh"]')).toBeNull();
    expect(refreshSignal.aborted).toBe(false);
    await act(async()=>resolveRuns({data:{runs:[run,{...run,runId:'retry-run'}]}}));await flush();
    expect(axios.get).toHaveBeenCalledWith('/api/agent-runs/retry-run',{signal:expect.any(AbortSignal)});
    expect(axios.post).toHaveBeenCalledTimes(1);
  } finally {act(()=>root.unmount());}
});

test.each([
  ['unavailable', 'JUDGE_STORAGE_SCHEMA', true],
  ['unavailable', 'PRIVATE_UNKNOWN_CODE', false],
  ['pass', 'JUDGE_STORAGE_SCHEMA', false],
])('admin receipt maps only known unavailable diagnostics (%s/%s)', async (verdict, errorCode, visible) => {
  axios.get.mockImplementation(url => Promise.resolve({ data: url.endsWith('/run-1')
    ? { run, events: [], judgments: [{ evaluationId: 'diagnostic-receipt', objectiveId: 'sql_1', verdict, disposition: verdict === 'pass' ? 'awarded' : 'not_pass', errorCode }] }
    : { runs: [run] } }));
  const node = document.createElement('div'); document.body.appendChild(node); const root = createRoot(node);
  try {
    await act(async () => root.render(<AgentRunInspector admin />)); await flush();
    const receipt = node.querySelector('[aria-label="Authoritative Judge receipts"]');
    expect(receipt.textContent).toContain(`Verdict: ${verdict}`);
    expect(receipt.textContent.includes('Evaluation storage needs updating. Check the application database migrations.')).toBe(visible);
    expect(node.querySelector('[aria-label="Recent evaluation recovery"]')).toBeNull();
    expect(receipt.textContent).not.toContain('PRIVATE_UNKNOWN_CODE');
    expect(node.querySelector('[data-testid="judge-retry-diagnostic-receipt"]')).toBeNull();
  } finally { act(() => root.unmount()); }
});

test.each([
 ['  The judge returned invalid results; please retry.  ', false],
 ['The response-effect verification returned invalid results; no completion was awarded.', true],
])('admin invalid-output receipt retains only meaningful explanation (%s)', async (explanation, retain) => {
 axios.get.mockImplementation(url => Promise.resolve({data:url.endsWith('/run-1')
  ? {run,events:[],judgments:[{evaluationId:'invalid-output',objectiveId:'sql_1',verdict:'unavailable',disposition:'not_pass',errorCode:'INVALID_JUDGE_OUTPUT',explanation,canRetry:false}]}
  : {runs:[run]}}));
 const node=document.createElement('div');document.body.appendChild(node);const root=createRoot(node);
 try {
  await act(async()=>root.render(<AgentRunInspector admin/>));await flush();
  const receipt=node.querySelector('[aria-label="Authoritative Judge receipts"]');
  expect(receipt.textContent).toContain('The Judge response failed validation. No completion was awarded.');
  expect(receipt.textContent.includes(explanation.trim())).toBe(retain);
  expect(receipt.textContent).not.toContain('please retry.');
  expect(receipt.textContent).toContain('Verdict: unavailable · Disposition: not_pass');
  expect(node.querySelector('[data-testid="judge-retry-invalid-output"]')).toBeNull();
 }finally{act(()=>root.unmount());}
});
