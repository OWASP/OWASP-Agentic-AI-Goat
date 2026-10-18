jest.mock('../../context/AuthContext', () => ({ useAuth: () => ({ user: { id: 1 } }) }));
import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import axios from 'axios';
import { toast } from 'react-toastify';
import SensitiveInfoWorkshop from './SensitiveInfoWorkshop';

let pollReconciler;
let retryResult;
jest.mock('../../components/workshop/JudgeRetryButton', () => (props) => {
  retryResult = props.onResult;
  return null;
});

globalThis.IS_REACT_ACT_ENVIRONMENT = true;

jest.mock('axios', () => ({ get: jest.fn(), post: jest.fn() }));
jest.mock('react-toastify', () => ({ toast: { warn: jest.fn(), info: jest.fn(), error: jest.fn(), success: jest.fn() } }));
jest.mock('../../components/VulnerabilityTemplate', () => ({ children }) => <div>{children}</div>);
jest.mock('../../hooks/useWorkshopHeartbeat', () => () => {});
jest.mock('../../hooks/useChangePolling', () => (reconcile) => { pollReconciler = reconcile; });
jest.mock('../../context/WorkshopConfigContext', () => ({
  useWorkshopConfig: () => ({
    revision: 1,
    snapshot: {
      exercises: {
        sensitive_info_disclosure: {
          isVisible: true,
          objectives: Object.fromEntries([
            'tool_enum', 'llm_identify', 'tool_version', 'traversal_secrets',
            'traversal_passwd', 'traversal_llm', 'ssrf_oob', 'ssrf_internal',
            'ssrf_ollama', 'error_leak', 'admin_enum', 'admin_backup',
            'admin_dl_backup', 'admin_read_logs', 'admin_llm_logs',
            'admin_modify_logs', 'admin_secrets', 'admin_dirlist',
          ].map(id => [id, { isVisible: true,
            ...(id === 'tool_enum' ? { label: 'Instructor tool discovery' } : {}) }])),
        },
      },
    },
  }),
}));

const flush = async () => {
  await act(async () => {
    await Promise.resolve();
    await Promise.resolve();
  });
};

test('canonical fixed mode creates the first message and later polling preserves that transcript', async () => {
  const consoleErrors = jest.spyOn(console, 'error');
  let canonicalMode = 'fixed';
  axios.get.mockImplementation((url) => {
    if (url.endsWith('/mode')) return Promise.resolve({ data: { mode: canonicalMode } });
    if (url.includes('/progress/')) return Promise.resolve({ data: { progress: [] } });
    if (url.includes('/solutions/')) return Promise.resolve({ data: { objectives: {} } });
    if (url.endsWith('/llm-status')) return Promise.resolve({ data: { available: false } });
    return Promise.resolve({ data: {} });
  });
  axios.post.mockResolvedValue({ data: { success: true } });

  const node = document.createElement('div');
  const root = createRoot(node);
  await act(async () => { root.render(<SensitiveInfoWorkshop />); });
  await flush();

  expect(node.textContent).toContain('ARIA (FinFlow Banking AI) is ready — 🟢 Fixed Mode');
  expect(node.textContent).not.toContain('ARIA (FinFlow Banking AI) is ready — 🔴 Vulnerable Mode');
  expect(node.textContent).toContain('Instructor tool discovery');

  canonicalMode = 'vulnerable';
  await act(async () => {
    await pollReconciler({}, {}, {});
  });
  await flush();

  expect(node.textContent).toContain('ARIA (FinFlow Banking AI) is ready — 🟢 Fixed Mode');
  expect(node.textContent).not.toContain('ARIA (FinFlow Banking AI) is ready — 🔴 Vulnerable Mode');

  act(() => root.unmount());
  const errors = consoleErrors.mock.calls;
  consoleErrors.mockRestore();
  expect(errors).toEqual([]);
});

async function renderWithLlmStatus(status) {
  axios.get.mockImplementation((url) => {
    if (url.endsWith('/mode')) return Promise.resolve({ data: { mode: 'vulnerable' } });
    if (url.includes('/progress/')) return Promise.resolve({ data: { progress: [] } });
    if (url.includes('/solutions/')) return Promise.resolve({ data: { objectives: {} } });
    if (url.endsWith('/llm-status')) return Promise.resolve({ data: status });
    return Promise.resolve({ data: {} });
  });
  axios.post.mockResolvedValue({ data: { success: true } });
  const node = document.createElement('div');
  const root = createRoot(node);
  await act(async () => { root.render(<SensitiveInfoWorkshop />); });
  await flush();
  return { node, root };
}

test('local reachability status does not claim model generation readiness', async () => {
  axios.get.mockReset();
  const { node, root } = await renderWithLlmStatus({
    available: true, configured: true, checkKind: 'reachability', provider: 'ollama',
    model: 'llama3.1:8b', message: 'Ollama reachable; model presence checked.',
  });
  expect(node.textContent).toContain('AI server reachable');
  expect(node.textContent).toContain('Generation not verified. Ollama reachable; model presence checked.');
  expect(node.textContent).not.toContain('AI ready');
  act(() => root.unmount());
});

test('configured cloud status remains neutral until connection is tested', async () => {
  axios.get.mockReset();
  const { node, root } = await renderWithLlmStatus({
    available: null, configured: true, checkKind: 'configuration_only', provider: 'openai',
    model: 'configured-model', message: 'Provider configured; connection not tested.',
  });
  expect(node.textContent).toContain('AI configured — connection not tested');
  expect(node.textContent).toContain('Provider configured; connection not tested.');
  expect(node.textContent).not.toContain('AI ready');
  expect(node.textContent).not.toContain('AI unavailable');
  act(() => root.unmount());
});

test('reachable LMStudio status does not claim selected model verification', async () => {
  axios.get.mockReset();
  const { node, root } = await renderWithLlmStatus({
    available: null, configured: true, checkKind: 'reachability', provider: 'lmstudio',
    model: 'local-model', message: 'LM Studio reachable; selected model not verified.',
  });
  expect(node.textContent).toContain('AI server reachable — model not verified');
  expect(node.textContent).toContain('LM Studio reachable; selected model not verified.');
  expect(node.textContent).not.toContain('AI ready');
  expect(node.textContent).not.toContain('connection not tested');
  act(() => root.unmount());
});

test('unavailable status remains an explicit unavailable state', async () => {
  axios.get.mockReset();
  const { node, root } = await renderWithLlmStatus({
    available: false, configured: true, checkKind: 'reachability', provider: 'ollama',
    model: 'llama3.1:8b', message: 'AI provider is not reachable.',
  });
  expect(node.textContent).toContain('AI unavailable');
  expect(node.textContent).toContain('AI provider is not reachable.');
  expect(node.textContent).not.toContain('AI server reachable');
  act(() => root.unmount());
});


test.each([false, true])('Judge retry progress refresh respects conversation reset=%s', async reset => {
  const { node, root } = await renderWithLlmStatus({ available: false });
  let resolveProgress;
  const pendingProgress = new Promise(resolve => { resolveProgress = resolve; });
  axios.get.mockImplementation(url => {
    if (url.includes('/progress/')) return pendingProgress;
    return Promise.resolve({ data: {} });
  });
  toast.success.mockClear();
  const controller = new AbortController();
  let pending;
  try {
    await act(async () => {
      pending = retryResult({ completed: true, judgments: [] }, { signal: controller.signal });
      await Promise.resolve();
    });
    if (reset) {
      const button = [...node.querySelectorAll('button')].find(item => item.textContent.trim() === 'Reset conversation');
      expect(button).toBeDefined();
      await act(async () => button.click());
    }
    await act(async () => {
      resolveProgress({ data: { progress: [{ id: 'tool_enum', completed: true }] } });
      await pending;
    });
    expect(node.textContent).toContain(`${reset ? 0 : 1} / 18`);
    if (reset) expect(toast.success).not.toHaveBeenCalledWith('Objective evaluation passed.');
    else expect(toast.success).toHaveBeenCalledWith('Objective evaluation passed.');
  } finally {
    resolveProgress({ data: { progress: [] } });
    await act(async () => { await pending; root.unmount(); });
  }
});


test.each(['reset', 'aborted'])('retired Judge callback ignores %s before feedback or progress requests', async retirement => {
  const { node, root } = await renderWithLlmStatus({ available: false });
  const oldCallback = retryResult;
  const controller = new AbortController();
  try {
    if (retirement === 'reset') {
      await act(async () => [...node.querySelectorAll('button')].find(item => item.textContent.trim() === 'Reset conversation').click());
    } else controller.abort();
    axios.get.mockClear();
    toast.success.mockClear();
    const before = node.textContent;
    await act(async () => oldCallback({ completed: true, judgments: [{ objectiveId: 'tool_enum', verdict: 'pass' }] }, { signal: controller.signal }));
    expect(axios.get).not.toHaveBeenCalled();
    expect(node.textContent).toBe(before);
    expect(toast.success).not.toHaveBeenCalled();
  } finally { act(() => root.unmount()); }
});


test.each([false, true])('Judge retry progress 503 warns only for current reset=%s', async reset => {
  const { node, root } = await renderWithLlmStatus({ available: false });
  let rejectProgress;
  const progress = new Promise((_resolve, reject) => { rejectProgress = reject; });
  axios.get.mockImplementation(url => url.includes('/progress/') ? progress : Promise.resolve({ data: {} }));
  toast.warn.mockClear(); toast.success.mockClear();
  let pending;
  try {
    expect(node.textContent).toContain('0 / 18');
    await act(async () => { pending = retryResult({ completed: true, judgments: [] }, { signal: new AbortController().signal }); await Promise.resolve(); });
    if (reset) await act(async () => [...node.querySelectorAll('button')].find(item => item.textContent.trim() === 'Reset conversation').click());
    await act(async () => { rejectProgress(Object.assign(new Error('Progress unavailable'), { response: { status: 503 } })); await pending; });
    expect(node.textContent).toContain('0 / 18');
    if (reset) {
      expect(toast.warn).not.toHaveBeenCalled();
      expect(toast.success).not.toHaveBeenCalledWith('Objective evaluation passed.');
    } else {
      expect(toast.warn).toHaveBeenCalledWith('Evaluation received, but progress could not be refreshed. Refresh progress to see the latest counts.');
      expect(toast.success).not.toHaveBeenCalledWith('Objective evaluation passed.');
    }
  } finally { act(() => root.unmount()); }
});
