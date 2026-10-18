jest.mock('../../context/AuthContext', () => ({ useAuth: () => ({ user: { id: 1 } }) }));
import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import axios from 'axios';
import SensitiveInfoWorkshop from './SensitiveInfoWorkshop';

let pollReconciler;
let mockConfiguredLabel = 'Internal App SSRF';
let mockConfiguredDescription = '';
let mockHintVisible = false;
globalThis.IS_REACT_ACT_ENVIRONMENT = true;

jest.mock('axios', () => ({ get: jest.fn(), post: jest.fn() }));
jest.mock('react-toastify', () => ({ toast: { info: jest.fn(), error: jest.fn(), success: jest.fn() } }));
jest.mock('../../components/VulnerabilityTemplate', () => ({ children }) => <div>{children}</div>);
jest.mock('../../hooks/useWorkshopHeartbeat', () => () => {});
jest.mock('../../hooks/useChangePolling', () => (reconcile) => { pollReconciler = reconcile; });
jest.mock('../../context/WorkshopConfigContext', () => ({
  useWorkshopConfig: () => ({ revision: 1, snapshot: { exercises: {
    sensitive_info_disclosure: { isVisible: true, objectives: {
      ssrf_internal: { isVisible: true, label: mockConfiguredLabel, description: mockConfiguredDescription,
        hintVisible: mockHintVisible },
    } },
  } } }),
}));

const response = (visible, url) => ({ data: {
  success: true,
  progress: [{ id: 'ssrf_internal', label: 'Internal App SSRF',
    desc: visible ? 'Current canonical target description' : 'Hidden canonical target description', completed: false }],
  solutionStatus: { ssrf_internal: visible },
  ssrfExamples: visible && url ? { ssrf_internal: { url } } : {},
} });
const deferred = () => {
  let resolve;
  const promise = new Promise(done => { resolve = done; });
  return { promise, resolve };
};
const flush = () => act(async () => { await Promise.resolve(); await Promise.resolve(); });

test.each([false, true])('shared solution preserves examples and the independent hint gate (%s)', async hintVisible => {
  mockHintVisible = hintVisible;
  axios.get.mockImplementation(url => {
    if (url.includes('/progress/')) return Promise.resolve(response(true));
    if (url.endsWith('/mode')) return Promise.resolve({ data: { mode: 'vulnerable' } });
    if (url.endsWith('/llm-status')) return Promise.resolve({ data: { available: false } });
    if (url.endsWith('/ssrf_internal')) return Promise.resolve({ data: { solution: {
      title: 'Instructor SSRF solution', difficulty: 'Medium', hints: ['Scoped hint'],
      examples: [{ prompt: 'first SSRF payload', explanation: 'First reason' },
        { prompt: 'second SSRF payload', explanation: 'Second reason' }],
      approach: 'Walk through the owned target', tips: ['Watch the target URL'],
    } } });
    return Promise.resolve({ data: {} });
  });
  axios.post.mockResolvedValue({ data: { success: true } });
  const node = document.createElement('div');
  const root = createRoot(node);
  try {
    await act(async () => { root.render(<SensitiveInfoWorkshop />); });
    await flush();
    const ssrfTab = [...node.querySelectorAll('button')]
      .find(button => button.textContent.trim().startsWith('SSRF'));
    await act(async () => { ssrfTab.click(); });
    await act(async () => { node.querySelector('[data-testid="solution-button-ssrf_internal"]').click(); });
    await flush();
    const modal = document.querySelector('[data-testid="objective-help-modal"]');
    expect(modal?.dataset.helpKind).toBe('solution');
    expect(modal.textContent).toContain('Instructor SSRF solution');
    expect(modal.textContent).toContain('Difficulty: Medium');
    expect(modal.textContent).toContain('Walk through the owned target');
    expect(modal.textContent).toContain('Watch the target URL');
    expect(modal.textContent.includes('Scoped hint')).toBe(hintVisible);
    expect(modal.querySelectorAll('[data-testid="solution-example"]')).toHaveLength(2);
    await act(async () => { modal.querySelectorAll('[data-testid="solution-example"] button')[1].click(); });
    expect(node.querySelector('textarea').value).toBe('second SSRF payload');
    expect(document.querySelector('[data-testid="objective-help-modal"]')).toBeNull();
  } finally {
    act(() => root.unmount());
    mockHintVisible = false;
  }
});

test('saved objective copy takes precedence over progress copy; an empty description preserves the dynamic fallback', async () => {
  mockConfiguredLabel = 'Instructor SSRF label';
  mockConfiguredDescription = 'Instructor SSRF description';
  axios.get.mockImplementation(url => {
    if (url.includes('/progress/')) return Promise.resolve(response(false));
    if (url.endsWith('/mode')) return Promise.resolve({ data: { mode: 'vulnerable' } });
    if (url.endsWith('/llm-status')) return Promise.resolve({ data: { available: false } });
    return Promise.resolve({ data: {} });
  });
  axios.post.mockResolvedValue({ data: { success: true } });

  const node = document.createElement('div');
  const root = createRoot(node);
  try {
    await act(async () => { root.render(<SensitiveInfoWorkshop />); });
    await flush();
    const ssrfTab = [...node.querySelectorAll('button')]
      .find(button => button.textContent.trim().startsWith('SSRF'));
    await act(async () => { ssrfTab.click(); });
    expect(node.querySelector('.obj-name')?.textContent).toBe('Instructor SSRF label');
    expect(node.querySelector('.obj-desc')?.textContent).toBe('Instructor SSRF description');

    mockConfiguredDescription = '  ';
    await act(async () => { root.render(<SensitiveInfoWorkshop />); });
    expect(node.querySelector('.obj-desc')?.textContent).toBe('Hidden canonical target description');
  } finally {
    act(() => root.unmount());
    mockConfiguredLabel = 'Internal App SSRF';
    mockConfiguredDescription = '';
  }
});

test('mounted workshop follows hide-show-hide and rejects a delayed stale presentation', async () => {
  const progressResponses = [Promise.resolve(response(false))];
  axios.get.mockImplementation(url => {
    if (url.includes('/progress/')) return progressResponses.shift();
    if (url.endsWith('/mode')) return Promise.resolve({ data: { mode: 'vulnerable' } });
    if (url.endsWith('/llm-status')) return Promise.resolve({ data: { available: false } });
    return Promise.resolve({ data: {} });
  });
  axios.post.mockResolvedValue({ data: { success: true } });

  const node = document.createElement('div');
  const root = createRoot(node);
  await act(async () => { root.render(<SensitiveInfoWorkshop />); });
  await flush();
  const ssrfTab = [...node.querySelectorAll('button')].find(button => button.textContent.trim().startsWith('SSRF'));
  expect(ssrfTab).toBeTruthy();
  act(() => ssrfTab.dispatchEvent(new MouseEvent('click', { bubbles: true })));
  expect(node.textContent).not.toContain('https://internal.example/ready');

  progressResponses.push(Promise.resolve(response(true, 'https://internal.example/ready')));
  await act(async () => { await pollReconciler({}, {}, {}); });
  expect(node.textContent).toContain('Check my credit score using https://internal.example/ready');
  expect(node.querySelector('textarea').placeholder).toContain('https://internal.example/ready');

  progressResponses.push(Promise.resolve(response(false)));
  await act(async () => { await pollReconciler({}, {}, {}); });
  expect(node.textContent).not.toContain('https://internal.example/ready');
  expect(node.querySelector('textarea').placeholder).not.toContain('https://internal.example/ready');

  const stale = deferred();
  progressResponses.push(stale.promise, Promise.resolve(response(false)));
  let stalePoll;
  act(() => { stalePoll = pollReconciler({}, {}, {}); });
  await flush();
  await act(async () => { await pollReconciler({}, {}, {}); });
  stale.resolve(response(true, 'https://stale.example/ready'));
  await act(async () => { await expect(stalePoll).rejects.toMatchObject({ code: 'STALE_RECONCILIATION' }); });
  expect(node.textContent).not.toContain('https://stale.example/ready');
  expect(node.textContent).toContain('Hidden canonical target description');

  // Removing the last canonical objective must not announce an achievement.
  progressResponses.push(Promise.resolve({ data: { success: true, progress: [], solutionStatus: {}, ssrfExamples: {} } }));
  await act(async () => { await pollReconciler({}, {}, {}); });
  expect(node.textContent).not.toContain('All objectives for this tab complete!');
  expect(node.textContent).not.toContain('All exercise objectives complete!');

  act(() => root.unmount());
});
