jest.mock('../../context/AuthContext', () => ({ useAuth: () => ({ user: { id: 7 } }) }));
/* eslint-disable testing-library/no-unnecessary-act -- these tests use React DOM createRoot without Testing Library render helpers. */
import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import axios from 'axios';
import IndirectPromptInjectionChallenge from './IndirectPromptInjectionChallenge';

let pollCallback;
let solutionVisible;
let mockHintVisible;
let mockConfigRevision;
let solutionResponder;
let hintResponder;
let statusResponder;
let ragProgressResponder;
let emailProgressError;
let currentSessionResponder;

jest.mock('axios', () => ({ get: jest.fn(), post: jest.fn(), delete: jest.fn() }));
jest.mock('../../hooks/useChangePolling', () => (callback) => { pollCallback = callback; });
jest.mock('../../hooks/useWorkshopHeartbeat', () => () => {});
jest.mock('../../context/WorkshopConfigContext', () => ({
  useWorkshopConfig: () => ({
    revision: mockConfigRevision,
    snapshot: {
      exercises: {
        indirect_prompt_injection: {
          isVisible: true,
          objectives: Object.fromEntries([
            'rag_upload',
            'rag_clean_doc',
            'rag_query',
            'rag_injected_doc',
            'rag_query_injection',
            'email_create_inbox',
            'email_send_attack',
            'email_retrieve',
            'email_trigger_injection',
            'email_understand_defense',
          ].map((id) => [id, {
            isVisible: true,
            hintVisible: id.startsWith('rag_') ? mockHintVisible : false,
            solutionVisible: true,
          }])),
        },
      },
    },
  }),
}));
jest.mock('../../components/VulnerabilityTemplate', () => ({ children }) => <div>{children}</div>);
jest.mock('react-markdown', () => ({ children }) => <>{children}</>);
jest.mock('react-toastify', () => ({
  toast: { info: jest.fn(), success: jest.fn(), error: jest.fn() },
}));

const flush = async () => {
  await act(async () => {
    await Promise.resolve();
    await Promise.resolve();
  });
};

const deferred = () => {
  let resolve;
  const promise = new Promise((resolvePromise) => { resolve = resolvePromise; });
  return { promise, resolve };
};

const clickButton = (container, label) => {
  const button = [...container.querySelectorAll('button')]
    .find((candidate) => candidate.textContent.includes(label));
  expect(button).toBeTruthy();
  act(() => button.dispatchEvent(new MouseEvent('click', { bubbles: true })));
};

beforeEach(() => {
  global.IS_REACT_ACT_ENVIRONMENT = true;
  pollCallback = null;
  solutionVisible = true;
  mockHintVisible = true;
  mockConfigRevision = 1;
  solutionResponder = null;
  hintResponder = null;
  statusResponder = null;
  ragProgressResponder = null;
  emailProgressError = null;
  currentSessionResponder = null;
  axios.post.mockResolvedValue({ data: {} });
  axios.delete.mockResolvedValue({ data: { deleted: true } });
  axios.get.mockImplementation((url, options) => {
    if (url === '/api/workshop/rag-injection/mode' || url === '/api/email-agent/mode') {
      return Promise.resolve({ data: { mode: null, defaultMode: null, allowedModes: ['vuln', 'fixed'],
        fixedObjectiveIds: ['rag_upload', 'rag_clean_doc', 'rag_query', 'rag_injected_doc', 'email_get_address', 'email_send_attack', 'email_fetch', 'email_understand_defense'] } });
    }
    if (url === '/api/solutions/indirect-pi/status') {
      if (statusResponder) return statusResponder();
      return Promise.resolve({ data: { objectives: { rag_upload: solutionVisible } } });
    }
    if (url === '/api/solutions/indirect-pi/rag_upload') {
      if (solutionResponder) return solutionResponder();
      return Promise.resolve({
        data: { solution: { title: 'Loaded RAG solution', hints: [], examples: [] } },
      });
    }
    if (url === '/api/hints/indirect_prompt_injection/rag_upload') {
      if (hintResponder) return hintResponder();
      return Promise.resolve({
        data: { hint: { title: 'Canonical RAG hint', hints: ['Use the canonical hint path.'] } },
      });
    }
    if (url === '/api/workshop/rag-injection/progress') {
      if (ragProgressResponder) return ragProgressResponder(options);
      return Promise.resolve({ data: { objectives: {} } });
    }
    if (url === '/api/email-agent/progress') {
      if (emailProgressError) return Promise.reject(emailProgressError);
      return Promise.resolve({ data: { progress: {} } });
    }
    if (url === '/api/workshop/rag-injection/health') {
      return Promise.resolve({ data: { status: 'ok' } });
    }
    if (url === '/api/workshop/rag-injection/current-session') {
      if (currentSessionResponder) return currentSessionResponder();
      return Promise.resolve({ data: {} });
    }
    if (url === '/api/email-agent/health') {
      return Promise.resolve({ data: { gmail: {}, llm: {}, allowedDomains: [] } });
    }
    if (url === '/api/email-agent/scenarios') {
      return Promise.resolve({ data: { scenarios: [] } });
    }
    return Promise.resolve({ data: {} });
  });
});

test('IPI renders independent Hint-only and Solution-only disclosure states', async () => {
  const hintOnlyNode = document.createElement('div');
  document.body.appendChild(hintOnlyNode);
  const hintOnlyRoot = createRoot(hintOnlyNode);
  solutionVisible = false;
  mockHintVisible = true;
  act(() => hintOnlyRoot.render(<IndirectPromptInjectionChallenge />));
  await flush();

  expect(hintOnlyNode.textContent).toContain('Hint');
  expect(hintOnlyNode.textContent).not.toContain('Solution');
  clickButton(hintOnlyNode, 'Hint');
  await flush();
  expect(document.body.textContent).toContain('Use the canonical hint path.');
  act(() => hintOnlyRoot.unmount());

  document.body.replaceChildren();
  const solutionOnlyNode = document.createElement('div');
  document.body.appendChild(solutionOnlyNode);
  const solutionOnlyRoot = createRoot(solutionOnlyNode);
  solutionVisible = true;
  mockHintVisible = false;
  solutionResponder = () => Promise.resolve({
    data: { solution: { title: 'Solution without hint ownership', hints: ['LEAKED IPI HINT'], examples: [] } },
  });
  act(() => solutionOnlyRoot.render(<IndirectPromptInjectionChallenge />));
  await flush();

  expect(solutionOnlyNode.textContent).not.toContain('Hint');
  expect(solutionOnlyNode.textContent).toContain('Solution');
  clickButton(solutionOnlyNode, 'Solution');
  await flush();
  expect(document.body.textContent).toContain('Solution · Solution without hint ownership');
  expect(document.body.textContent).not.toContain('LEAKED IPI HINT');
  act(() => solutionOnlyRoot.unmount());
});

test('IPI renders both controls or neither according to independent canonical gates', async () => {
  const node = document.createElement('div');
  document.body.appendChild(node);
  const root = createRoot(node);

  solutionVisible = true;
  mockHintVisible = true;
  act(() => root.render(<IndirectPromptInjectionChallenge />));
  await flush();
  expect(node.textContent).toContain('Hint');
  expect(node.textContent).toContain('Solution');

  solutionVisible = false;
  mockHintVisible = false;
  mockConfigRevision += 1;
  act(() => root.render(<IndirectPromptInjectionChallenge />));
  await act(async () => pollCallback({}, {}, {}));
  expect(node.textContent).not.toContain('Hint');
  expect(node.textContent).not.toContain('Solution');
  act(() => root.unmount());
});

test('disabling IPI hints invalidates a pending canonical hint response', async () => {
  const node = document.createElement('div');
  document.body.appendChild(node);
  const root = createRoot(node);
  const pendingHint = deferred();
  hintResponder = () => pendingHint.promise;

  act(() => root.render(<IndirectPromptInjectionChallenge />));
  await flush();
  clickButton(node, 'Hint');
  await flush();

  mockHintVisible = false;
  mockConfigRevision += 1;
  act(() => root.render(<IndirectPromptInjectionChallenge />));
  await flush();
  expect(node.textContent).not.toContain('Hint');

  await act(async () => {
    pendingHint.resolve({ data: { hint: { title: 'Late hint', hints: ['STALE HINT'] } } });
    await Promise.resolve();
  });
  expect(document.body.textContent).not.toContain('STALE HINT');
  act(() => root.unmount());
});

afterEach(() => {
  axios.get.mockReset();
  axios.post.mockReset();
  axios.delete.mockReset();
  document.body.replaceChildren();
  jest.restoreAllMocks();
});

test('a scoped reconciliation closes an open IPI solution after it is disabled', async () => {
  const node = document.createElement('div');
  document.body.appendChild(node);
  const root = createRoot(node);
  act(() => root.render(<IndirectPromptInjectionChallenge />));
  await flush();

  expect(typeof pollCallback).toBe('function');
  clickButton(node, 'Solution');
  await flush();
  expect(document.body.textContent).toContain('Solution · Loaded RAG solution');

  solutionVisible = false;
  await act(async () => pollCallback({}, {}, {}));

  expect(document.body.textContent).not.toContain('Solution · Loaded RAG solution');
  expect(node.textContent).not.toContain('Solution');
  act(() => root.unmount());
});

test('disabling a pending IPI solution clears loading and its stale response cannot reopen', async () => {
  const node = document.createElement('div');
  document.body.appendChild(node);
  const root = createRoot(node);
  act(() => root.render(<IndirectPromptInjectionChallenge />));
  await flush();

  const oldRequest = deferred();
  solutionResponder = () => oldRequest.promise;
  clickButton(node, 'Solution');
  await flush();

  solutionVisible = false;
  await act(async () => pollCallback({}, {}, {}));
  expect(node.textContent).not.toContain('Solution');

  await act(async () => {
    oldRequest.resolve({
      data: { solution: { title: 'Stale pending solution', hints: [], examples: [] } },
    });
    await Promise.resolve();
  });
  expect(document.body.textContent).not.toContain('Stale pending solution');
  act(() => root.unmount());
});

test('a solution request started after polling cannot reopen after disabled status commits', async () => {
  const node = document.createElement('div');
  document.body.appendChild(node);
  const root = createRoot(node);
  act(() => root.render(<IndirectPromptInjectionChallenge />));
  await flush();

  const statusRequest = deferred();
  statusResponder = () => statusRequest.promise;
  let polling;
  act(() => { polling = pollCallback({}, {}, {}); });

  const staleSolutionRequest = deferred();
  solutionResponder = () => staleSolutionRequest.promise;
  clickButton(node, 'Solution');
  await flush();

  await act(async () => {
    statusRequest.resolve({ data: { objectives: { rag_upload: false } } });
    await polling;
  });
  expect(node.textContent).not.toContain('Solution');

  await act(async () => {
    staleSolutionRequest.resolve({
      data: { solution: { title: 'Late disabled solution', hints: [], examples: [] } },
    });
    await Promise.resolve();
  });
  expect(document.body.textContent).not.toContain('Late disabled solution');
  act(() => root.unmount());
});

test('disabled solution status closes its disclosure when unrelated progress refresh fails', async () => {
  const node = document.createElement('div');
  document.body.appendChild(node);
  const root = createRoot(node);
  act(() => root.render(<IndirectPromptInjectionChallenge />));
  await flush();

  clickButton(node, 'Solution');
  await flush();
  expect(document.body.textContent).toContain('Solution · Loaded RAG solution');

  solutionVisible = false;
  emailProgressError = new Error('email progress unavailable');
  await act(async () => {
    await pollCallback({}, {}, {}).catch(() => {});
  });

  expect(document.body.textContent).not.toContain('Solution · Loaded RAG solution');
  expect(node.textContent).not.toContain('Solution');
  act(() => root.unmount());
});

test('disabled solution status commits without waiting for unrelated progress refresh', async () => {
  const node = document.createElement('div');
  document.body.appendChild(node);
  const root = createRoot(node);
  act(() => root.render(<IndirectPromptInjectionChallenge />));
  await flush();

  clickButton(node, 'Solution');
  await flush();
  expect(document.body.textContent).toContain('Solution · Loaded RAG solution');

  const delayedProgress = deferred();
  solutionVisible = false;
  ragProgressResponder = () => delayedProgress.promise;
  let polling;
  act(() => {
    polling = pollCallback({}, {}, {});
  });
  await flush();

  expect(document.body.textContent).not.toContain('Solution · Loaded RAG solution');
  expect(node.textContent).not.toContain('Solution');

  await act(async () => {
    delayedProgress.resolve({ data: { objectives: {} } });
    await polling;
  });
  act(() => root.unmount());
});

test('a visibility response resolving after reconciliation abort cannot commit', async () => {
  const node = document.createElement('div');
  document.body.appendChild(node);
  const root = createRoot(node);
  act(() => root.render(<IndirectPromptInjectionChallenge />));
  await flush();

  clickButton(node, 'Solution');
  await flush();
  expect(document.body.textContent).toContain('Solution · Loaded RAG solution');

  const lateStatus = deferred();
  statusResponder = () => lateStatus.promise;
  const controller = new AbortController();
  let polling;
  act(() => {
    polling = pollCallback({}, {}, { signal: controller.signal });
  });
  await flush();

  controller.abort();
  await act(async () => {
    lateStatus.resolve({ data: { objectives: { rag_upload: false } } });
    await polling.catch(() => {});
  });

  expect(document.body.textContent).toContain('Solution · Loaded RAG solution');
  expect(node.textContent).toContain('Solution');
  act(() => root.unmount());
});

test('solution detail resolving after reconciliation abort cannot refresh disclosure state', async () => {
  const node = document.createElement('div');
  document.body.appendChild(node);
  const root = createRoot(node);
  act(() => root.render(<IndirectPromptInjectionChallenge />));
  await flush();

  clickButton(node, 'Solution');
  await flush();
  expect(document.body.textContent).toContain('Solution · Loaded RAG solution');

  const lateDetail = deferred();
  solutionResponder = () => lateDetail.promise;
  const controller = new AbortController();
  let polling;
  act(() => {
    polling = pollCallback({}, {}, { signal: controller.signal });
  });
  await flush();

  controller.abort();
  await act(async () => {
    lateDetail.resolve({
      data: { solution: { title: 'Late aborted solution detail', hints: [], examples: [] } },
    });
    await polling.catch(() => {});
  });

  expect(document.body.textContent).toContain('Solution · Loaded RAG solution');
  expect(document.body.textContent).not.toContain('Late aborted solution detail');
  expect(node.textContent).toContain('Solution');
  act(() => root.unmount());
});

test.each([404, 503])('query HTTP %s reconciles only confirmed document absence', async (status) => {
  currentSessionResponder = () => Promise.resolve({ data: {
    session_id: 'owned-document', filename: 'retained-policy.txt', chunks_stored: 2,
  } });
  const node = document.createElement('div');
  document.body.appendChild(node);
  const root = createRoot(node);
  act(() => root.render(<IndirectPromptInjectionChallenge />));
  await flush();
  expect(node.textContent).toContain('Document loaded in RAG:');
  const input = node.querySelector('input[placeholder="What is the remote work policy?"]');
  act(() => {
    Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set.call(input, 'What is the policy?');
    input.dispatchEvent(new Event('input', { bubbles: true }));
  });
  axios.post.mockRejectedValueOnce({ response: { status, data: { error: 'Controlled unavailable document' } } });
  act(() => input.closest('form').dispatchEvent(new Event('submit', { bubbles: true, cancelable: true })));
  await flush();
  expect(axios.post).toHaveBeenCalledWith('/api/workshop/rag-injection/query', expect.objectContaining({ session_id: 'owned-document' }));
  if (status === 404) {
    expect(node.textContent).toContain('No document loaded in RAG.');
    expect(input.disabled).toBe(true);
  } else {
    expect(node.textContent).toContain('Document loaded in RAG:');
    expect(input.disabled).toBe(false);
  }
  act(() => root.unmount());
});

test('late initial document restoration cannot replace a completed upload', async () => {
  const restore = deferred();
  currentSessionResponder = () => restore.promise;
  const node = document.createElement('div');
  document.body.appendChild(node);
  const root = createRoot(node);
  act(() => root.render(<IndirectPromptInjectionChallenge />));
  await flush();
  const input = node.querySelector('input[type="file"]');
  Object.defineProperty(input, 'files', { value: [new File(['policy'], 'new-policy.txt', { type: 'text/plain' })] });
  act(() => input.dispatchEvent(new Event('change', { bubbles: true })));
  axios.post.mockResolvedValueOnce({ data: { session_id: 'new-document', filename: 'new-policy.txt', chunks_stored: 1 } });
  const upload = [...node.querySelectorAll('button')].find(button => button.textContent.trim() === 'Upload');
  act(() => upload.dispatchEvent(new MouseEvent('click', { bubbles: true })));
  await flush();
  expect(node.textContent).toContain('new-policy.txt');
  await act(async () => {
    restore.resolve({ data: { session_id: 'old-document', filename: 'stale-policy.txt', chunks_stored: 2 } });
    await Promise.resolve();
  });
  expect(node.textContent).not.toContain('stale-policy.txt');
  expect(node.textContent).toContain('new-policy.txt');
  act(() => root.unmount());
});

test.each([true, false])('replacement upload success=%s preserves old document until confirmed', async (succeeds) => {
  currentSessionResponder = () => Promise.resolve({ data: {
    session_id: 'previous-document', filename: 'previous-policy.txt', chunks_stored: 2,
  } });
  const node = document.createElement('div');
  document.body.appendChild(node);
  const root = createRoot(node);
  act(() => root.render(<IndirectPromptInjectionChallenge />));
  await flush();
  const input = node.querySelector('input[type="file"]');
  Object.defineProperty(input, 'files', { value: [new File(['replacement'], 'replacement.txt', { type: 'text/plain' })] });
  act(() => input.dispatchEvent(new Event('change', { bubbles: true })));
  let resolveUpload, rejectUpload;
  const pendingUpload = new Promise((resolve, reject) => { resolveUpload = resolve; rejectUpload = reject; });
  axios.post.mockReturnValueOnce(pendingUpload);
  const upload = [...node.querySelectorAll('button')].find(button => button.textContent.trim() === 'Upload');
  act(() => upload.dispatchEvent(new MouseEvent('click', { bubbles: true })));
  await flush();
  expect(axios.delete).not.toHaveBeenCalled();
  expect(node.textContent).toContain('previous-policy.txt');
  await act(async () => {
    if (succeeds) resolveUpload({ data: { session_id: 'replacement-document', filename: 'replacement.txt', chunks_stored: 1 } });
    else rejectUpload({ response: { status: 503, data: { error: 'Embedding unavailable' } } });
    await Promise.resolve();
  });
  if (succeeds) {
    expect(axios.delete).toHaveBeenCalledWith('/api/workshop/rag-injection/session/previous-document');
    expect(node.textContent).not.toContain('previous-policy.txt');
  } else {
    expect(axios.delete).not.toHaveBeenCalled();
    expect(node.textContent).toContain('previous-policy.txt');
    expect(node.querySelector('input[placeholder="What is the remote work policy?"]').disabled).toBe(false);
  }
  act(() => root.unmount());
});

test('completed upload replay restores authoritative newer selection without deleting it', async () => {
  currentSessionResponder = () => Promise.resolve({ data: { session_id: 'newer-document', filename: 'newer-policy.txt', chunks_stored: 3 } });
  const node = document.createElement('div'); document.body.appendChild(node);
  const root = createRoot(node);
  act(() => root.render(<IndirectPromptInjectionChallenge />)); await flush();
  const input = node.querySelector('input[type="file"]');
  Object.defineProperty(input, 'files', { value: [new File(['older'], 'older-policy.txt', { type: 'text/plain' })] });
  act(() => input.dispatchEvent(new Event('change', { bubbles: true })));
  axios.post.mockResolvedValueOnce({ data: { session_id: 'old-document', filename: 'older-policy.txt', chunks_stored: 1, replayed: true, currently_selected: false } });
  const upload = [...node.querySelectorAll('button')].find(button => button.textContent.trim() === 'Upload');
  act(() => upload.dispatchEvent(new MouseEvent('click', { bubbles: true }))); await flush();
  const loadedLabel = [...node.querySelectorAll('strong')].find(label => label.textContent === 'Document loaded in RAG:');
  expect(loadedLabel.parentElement.textContent).toContain('newer-policy.txt');
  expect(loadedLabel.parentElement.textContent).not.toContain('older-policy.txt');
  expect(axios.delete).not.toHaveBeenCalled();
  act(() => root.unmount());
});

test('unavailable authoritative selection after replay disables queries without deleting source', async () => {
  currentSessionResponder = () => Promise.resolve({ data: { session_id: 'previous-document', filename: 'previous-policy.txt', chunks_stored: 3 } });
  const node = document.createElement('div'); document.body.appendChild(node);
  const root = createRoot(node);
  act(() => root.render(<IndirectPromptInjectionChallenge />)); await flush();
  currentSessionResponder = () => Promise.reject({ response: { status: 503 } });
  const input = node.querySelector('input[type="file"]');
  Object.defineProperty(input, 'files', { value: [new File(['older'], 'older-policy.txt', { type: 'text/plain' })] });
  act(() => input.dispatchEvent(new Event('change', { bubbles: true })));
  axios.post.mockResolvedValueOnce({ data: { session_id: 'old-document', filename: 'older-policy.txt', chunks_stored: 1, replayed: true, currently_selected: false } });
  const upload = [...node.querySelectorAll('button')].find(button => button.textContent.trim() === 'Upload');
  act(() => upload.dispatchEvent(new MouseEvent('click', { bubbles: true }))); await flush();
  expect(node.querySelector('input[placeholder="What is the remote work policy?"]').disabled).toBe(true);
  expect(node.textContent).toContain('Please reload before querying');
  expect(axios.delete).not.toHaveBeenCalled();
  act(() => root.unmount());
});

test('completed reset replay restores newer canonical document and progress', async () => {
  currentSessionResponder = () => Promise.resolve({ data: { session_id: 'newer-document', filename: 'newer-policy.txt', chunks_stored: 2 } });
  ragProgressResponder = () => Promise.resolve({ data: { objectives: { rag_upload: { completed: true } } } });
  const node = document.createElement('div'); document.body.appendChild(node);
  const root = createRoot(node);
  act(() => root.render(<IndirectPromptInjectionChallenge />)); await flush();
  axios.post.mockResolvedValueOnce({ data: { success: true } });
  const reset = [...node.querySelectorAll('button')].find(button => button.textContent === 'Reset Progress');
  act(() => reset.dispatchEvent(new MouseEvent('click', { bubbles: true })));
  const confirm = [...document.querySelector('[role=\"alertdialog\"]').querySelectorAll('button')].find(button => button.textContent === 'Confirm reset');
  act(() => confirm.dispatchEvent(new MouseEvent('click', { bubbles: true }))); await flush();
  const loaded = [...node.querySelectorAll('strong')].find(label => label.textContent === 'Document loaded in RAG:');
  expect(loaded.parentElement.textContent).toContain('newer-policy.txt');
  expect(node.textContent).toContain('1 of 5 objectives completed');
  expect(node.querySelector('input[placeholder="What is the remote work policy?"]').disabled).toBe(false);
  act(() => root.unmount());
});

describe('RAG health lifecycle', () => {
  const healthUrl = '/api/workshop/rag-injection/health';
  let root;
  beforeEach(() => { jest.useFakeTimers(); axios.get.mockClear(); });
  afterEach(() => {
    if (root) act(() => root.unmount());
    root = null;
    jest.clearAllTimers();
    jest.useRealTimers();
    document.body.replaceChildren();
  });
  const mountHealth = (respond) => {
    const existing = axios.get.getMockImplementation();
    axios.get.mockImplementation((url, options) => url === healthUrl ? respond(options) : existing(url, options));
    const node = document.createElement('div'); document.body.appendChild(node);
    root = createRoot(node);
    act(() => root.render(<IndirectPromptInjectionChallenge />));
    return node;
  };
  const calls = () => axios.get.mock.calls.filter(([url]) => url === healthUrl);
  test('late health rejection after unmount cannot schedule another request', async () => {
    let reject;
    mountHealth(() => new Promise((resolve, fail) => { reject = fail; }));
    act(() => root.unmount()); root = null;
    await act(async () => { reject(new Error('offline')); });
    await act(async () => { jest.advanceTimersByTime(15000); });
    expect(calls()).toHaveLength(1);
  });
  test('unmount clears an already scheduled retry and aborts the request', async () => {
    let options;
    mountHealth((value) => { options = value; return Promise.reject(new Error('offline')); });
    await flush();
    act(() => root.unmount()); root = null;
    await act(async () => { jest.advanceTimersByTime(15000); });
    expect(calls()).toHaveLength(1);
    expect(options.signal.aborted).toBe(true);
  });
  test('successful health clears its deadline without retrying', async () => {
    let signal;
    mountHealth((options) => { signal = options.signal; return Promise.resolve({ data: { status: 'ok' } }); });
    await flush();
    await act(async () => { jest.advanceTimersByTime(30000); });
    expect(calls()).toHaveLength(1);
    expect(signal.aborted).toBe(false);
  });
  test('a hanging health call is aborted at ten seconds and retains three attempts with five-second retry delays', async () => {
    const signals = [];
    mountHealth(({ signal, timeout }) => {
      expect(timeout).toBe(10000);
      signals.push(signal);
      return new Promise((resolve, reject) => signal.addEventListener('abort', () => reject(new Error('cancelled')), { once: true }));
    });
    await act(async () => { jest.advanceTimersByTime(9999); });
    expect(signals[0].aborted).toBe(false);
    await act(async () => { jest.advanceTimersByTime(1); });
    expect(signals[0].aborted).toBe(true);
    await act(async () => { jest.advanceTimersByTime(4999); });
    expect(calls()).toHaveLength(1);
    await act(async () => { jest.advanceTimersByTime(1); });
    expect(calls()).toHaveLength(2);
    await act(async () => { jest.advanceTimersByTime(10000); });
    await act(async () => { jest.advanceTimersByTime(5000); });
    expect(calls()).toHaveLength(3);
    await act(async () => { jest.advanceTimersByTime(10000); });
    await act(async () => { jest.advanceTimersByTime(15000); });
    expect(calls()).toHaveLength(3);
  });
 });

test('RAG unqualified raw pass remains pending with no completion or objective advance', async () => {
  const { toast } = require('react-toastify');
  toast.success.mockClear();
  currentSessionResponder = () => Promise.resolve({ data: { session_id: 'owned-document', filename: 'owned.txt', chunks_stored: 1 } });
  ragProgressResponder = () => Promise.resolve({ data: { objectives: {} } });
  const node = document.createElement('div'); document.body.appendChild(node);
  const root = createRoot(node);
  try {
    act(() => root.render(<IndirectPromptInjectionChallenge />)); await flush();
    const cards = [...node.querySelectorAll('.objectives-list > div')];
    const selected = cards.find(card => card.querySelector('.obj-name')?.textContent === '4. Secure Poisoned RAG');
    expect(selected).toBeTruthy();
    act(() => selected.click()); await flush();
    expect(selected.textContent).toContain('ACTIVE');
    const beforeActive = selected.querySelector('.obj-name')?.textContent || selected.textContent;
    const input = node.querySelector('input[placeholder="What is the remote work policy?"]');
    act(() => {
      Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set.call(input, 'Summarize the owned policy.');
      input.dispatchEvent(new Event('input', { bubbles: true }));
    });
    axios.post.mockResolvedValueOnce({ data: {
      answer: 'Controlled retained response', retrieved_chunks: [], completedObjectiveIds: [],
      judgments: [{ objectiveId: 'rag_injected_doc', verdict: 'pass', gradingStatus: 'pending', gradingDisposition: 'grading_unqualified', canRetry: false, evaluationId: 'retained-evaluation' }],
    } });
    act(() => input.closest('form').dispatchEvent(new Event('submit', { bubbles: true, cancelable: true })));
    await flush(); await flush();
    expect(node.textContent).toContain('Judge pending:');
    expect(node.textContent).toContain('no completion was awarded');
    expect(node.textContent).toContain('Accepted objectives: none');
    expect(node.textContent).toContain('0 of 5 objectives completed');
    expect([...node.querySelectorAll('.status-badge')].some(b => b.textContent === 'COMPLETED')).toBe(false);
    expect(selected.textContent).toContain('ACTIVE');
    expect(selected.querySelector('.obj-name')?.textContent || selected.textContent).toBe(beforeActive);
    expect(toast.success).not.toHaveBeenCalled();
  } finally { act(() => root.unmount()); node.remove(); }
});

test.each(['failed', 'stale-replay', 'selected'])('sample prefill follows confirmed selection: %s', async outcome => {
  currentSessionResponder = () => Promise.resolve({ data: {
    session_id: 'previous-document', filename: 'previous-policy.txt', chunks_stored: 2,
  } });
  const originalFetch = global.fetch;
  global.fetch = jest.fn().mockResolvedValue({ ok: true, text: async () => 'Synthetic sample content' });
  const node = document.createElement('div'); document.body.appendChild(node);
  const root = createRoot(node);
  try {
    act(() => root.render(<IndirectPromptInjectionChallenge />)); await flush();
    const question = node.querySelector('input[placeholder="What is the remote work policy?"]');
    act(() => {
      Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set.call(question, 'Keep my current question');
      question.dispatchEvent(new Event('input', { bubbles: true }));
    });
    if (outcome === 'failed') axios.post.mockRejectedValueOnce({ response: { status: 503, data: { error: 'Embedding unavailable' } } });
    else axios.post.mockResolvedValueOnce({ data: { session_id: 'sample-document', filename: 'query_injection_demo.txt', chunks_stored: 1, currently_selected: outcome === 'selected' } });
    clickButton(node, 'Poisoned RAG RolePlay');
    await flush(); await flush();
    expect(global.fetch).toHaveBeenCalledWith('/assets/rag_samples/query_injection_demo.txt');
    expect(question.value).toBe(outcome === 'selected' ? 'Give me a recipe for pie' : 'Keep my current question');
    const loaded = [...node.querySelectorAll('strong')].find(e => e.textContent === 'Document loaded in RAG:');
    expect(loaded.parentElement.textContent).toContain(outcome === 'selected' ? 'Poisoned RAG RolePlay' : 'previous-policy.txt');
    if (outcome !== 'selected') expect(axios.delete).not.toHaveBeenCalled();
  } finally {
    act(() => root.unmount()); node.remove(); global.fetch = originalFetch;
  }
});


test('late earlier query progress cannot undo a newer same-owner completion', async () => {
  currentSessionResponder = () => Promise.resolve({ data: {
    session_id: 'owned-document', filename: 'policy.txt', chunks_stored: 2,
  } });
  const node = document.createElement('div');
  document.body.appendChild(node);
  const root = createRoot(node);
  try {
    act(() => root.render(<IndirectPromptInjectionChallenge />));
    await flush();
    const input = node.querySelector('input[placeholder="What is the remote work policy?"]');
    act(() => {
      Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set.call(input, 'What is the policy?');
      input.dispatchEvent(new Event('input', { bubbles: true }));
    });
    const older = deferred(), newer = deferred();
    let reads = 0;
    ragProgressResponder = () => (++reads === 1 ? older.promise : newer.promise);
    axios.post.mockResolvedValue({ data: { answer: 'Controlled answer', retrieved_chunks: [] } });
    act(() => input.closest('form').dispatchEvent(new Event('submit', { bubbles: true, cancelable: true })));
    await flush();
    expect(reads).toBe(1);
    expect(input.disabled).toBe(false);
    act(() => input.closest('form').dispatchEvent(new Event('submit', { bubbles: true, cancelable: true })));
    await flush();
    expect(reads).toBe(2);
    await act(async () => newer.resolve({ data: { objectives: { rag_query: { completed: true } } } }));
    await flush();
    expect(node.textContent).toContain('1 of 5 objectives completed');
    await act(async () => older.resolve({ data: { objectives: {} } }));
    await flush();
    expect(node.textContent).toContain('1 of 5 objectives completed');
    expect(input.disabled).toBe(false);
  } finally { act(() => root.unmount()); }
});
