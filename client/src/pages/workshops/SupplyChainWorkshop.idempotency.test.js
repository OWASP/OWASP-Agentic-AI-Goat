import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import axios from 'axios';
import { toast } from 'react-toastify';
import SupplyChainWorkshop from './SupplyChainWorkshop';

globalThis.IS_REACT_ACT_ENVIRONMENT = true;

jest.mock('axios', () => ({ get: jest.fn(), post: jest.fn() }));
let mockRetryResult;
jest.mock('../../components/workshop/JudgeRetryButton', () => (props) => {
  mockRetryResult = props.onResult;
  return null;
});
jest.mock('react-toastify', () => ({ toast: { info: jest.fn(), error: jest.fn(), success: jest.fn() } }));
jest.mock('../../components/VulnerabilityTemplate', () => ({ children }) => <div>{children}</div>);
jest.mock('../../components/HintPanel', () => () => null);
jest.mock('../../hooks/useWorkshopHeartbeat', () => () => {});
let mockPoll;
jest.mock('../../hooks/useChangePolling', () => callback => { mockPoll = callback; });
jest.mock('../../context/WorkshopConfigContext', () => ({
  useWorkshopConfig: () => ({
    snapshot: {
      exercises: {
        supply_chain_rce: {
          isVisible: true,
          objectives: {
            tool_list: { isVisible: true }, pkg_discover: { isVisible: true }, clean_request: { isVisible: true },
            rce_env: { isVisible: true }, rce_ssh: { isVisible: true }, rce_cmd: { isVisible: true },
          },
        },
      },
    },
  }),
}));

const roots = [];

function deferred() {
  let resolve;
  let reject;
  const promise = new Promise((resolvePromise, rejectPromise) => {
    resolve = resolvePromise;
    reject = rejectPromise;
  });
  return { promise, resolve, reject };
}

async function flush() {
  await act(async () => {
    await Promise.resolve();
    await Promise.resolve();
    await Promise.resolve();
  });
}

async function renderWorkshop() {
  const node = document.createElement('div');
  document.body.appendChild(node);
  const root = createRoot(node);
  roots.push({ root, node });
  await act(async () => { root.render(<SupplyChainWorkshop />); });
  await flush();
  return node;
}

async function confirmOpenReset() {
  const dialog = document.querySelector('[role="alertdialog"]');
  expect(dialog).not.toBeNull();
  const confirm = [...dialog.querySelectorAll('button')].find(button => button.textContent.trim() === 'Confirm reset');
  await act(async () => { confirm.click(); });
}

test('cancelled durable reset does not mutate progress or send a reset request', async () => {
  const node = await renderWorkshop();
  const trigger = [...node.querySelectorAll('button')].find(button => button.textContent.trim() === 'Reset Progress');
  trigger.focus();
  await act(async () => { trigger.click(); });
  const dialog = document.querySelector('[role="alertdialog"]');
  expect(dialog.textContent).toContain('CodeBot conversation and objective progress');
  await act(async () => { [...dialog.querySelectorAll('button')].find(button => button.textContent.trim() === 'Cancel').click(); });
  expect(document.querySelector('[role="alertdialog"]')).toBeNull();
  expect(document.activeElement).toBe(trigger);
  expect(axios.post.mock.calls.some(([url]) => url.endsWith('/progress/reset'))).toBe(false);
});

test('double confirmation admits only one durable reset while the transport is pending', async () => {
  const node = await renderWorkshop();
  const pending = deferred();
  axios.post.mockImplementation(url => url.endsWith('/progress/reset') ? pending.promise : Promise.resolve({ data: {} }));
  const trigger = [...node.querySelectorAll('button')].find(button => button.textContent.trim() === 'Reset Progress');
  await act(async () => { trigger.click(); });
  const dialog = document.querySelector('[role="alertdialog"]');
  const confirm = [...dialog.querySelectorAll('button')].find(button => button.textContent.trim() === 'Confirm reset');
  act(() => { confirm.click(); confirm.click(); });
  expect(axios.post.mock.calls.filter(([url]) => url.endsWith('/progress/reset'))).toHaveLength(1);
  expect(dialog.textContent).toContain('Resetting…');
  await act(async () => { pending.resolve({ data: { success: true } }); });
  expect(document.querySelector('[role="alertdialog"]')).toBeNull();
});

function setTextareaValue(textarea, value) {
  const setter = Object.getOwnPropertyDescriptor(window.HTMLTextAreaElement.prototype, 'value').set;
  setter.call(textarea, value);
  textarea.dispatchEvent(new Event('input', { bubbles: true }));
}

async function submit(node, value) {
  const textarea = node.querySelector('textarea');
  await act(async () => { setTextareaValue(textarea, value); });
  await act(async () => {
    textarea.closest('form').dispatchEvent(new Event('submit', { bubbles: true, cancelable: true }));
  });
}

function chatCalls() {
  return axios.post.mock.calls.filter(([url]) => url === '/api/workshop/supply-chain/chat');
}

beforeEach(() => {
  mockRetryResult = undefined;
  axios.get.mockReset();
  axios.post.mockReset();
  toast.info.mockReset();
  toast.error.mockReset();
  toast.success.mockReset();
  axios.get.mockImplementation((url) => {
    if (url.endsWith('/mode')) return Promise.resolve({ data: { mode: 'vulnerable' } });
    if (url.endsWith('/llm-status')) return Promise.resolve({ data: { available: false } });
    if (url.endsWith('/status')) return Promise.resolve({ data: { objectives: {} } });
    if (url.endsWith('/progress/current')) return Promise.resolve({ data: { progress: [] } });
    return Promise.resolve({ data: {} });
  });
  axios.post.mockImplementation((url) => {
    if (url.endsWith('/init')) return Promise.resolve({ data: { progress: [] } });
    if (url.endsWith('/progress/reset')) return Promise.resolve({ data: { success: true } });
    return Promise.resolve({ data: { response: 'received', newlyCompletedObjectives: [] } });
  });
});

afterEach(() => {
  while (roots.length) {
    const { root, node } = roots.pop();
    act(() => root.unmount());
    node.remove();
  }
});

test('sends a UUID idempotency header and does not reuse it after a completed attempt', async () => {
  const node = await renderWorkshop();

  await submit(node, 'inspect first manifest');
  await flush();
  await submit(node, 'inspect first manifest');
  await flush();

  const [first, second] = chatCalls();
  expect(first[1]).toEqual({ userMessage: 'inspect first manifest', conversationHistory: [] });
  expect(first[2].headers['Idempotency-Key']).toMatch(/^[0-9a-f-]{36}$/i);
  expect(second[2].headers['Idempotency-Key']).not.toBe(first[2].headers['Idempotency-Key']);
  expect(second[1].conversationHistory).toEqual([
    { role: 'user', content: 'inspect first manifest' },
    { role: 'assistant', content: 'received' },
  ]);
});

test('shared mode control maps vulnerable to the persisted Supply Chain mode values', async () => {
  axios.post.mockImplementation((url, body) => url.endsWith('/mode')
    ? Promise.resolve({ data: { mode: body.mode } })
    : Promise.resolve({ data: { success: true } }));
  const node = await renderWorkshop();
  const control = node.querySelector('[data-workshop-mode-control]');
  expect(control.getAttribute('data-workshop-mode')).toBe('vuln');
  await act(async () => [...control.querySelectorAll('button')].find(button => button.textContent.trim() === 'Fixed').click());
  await flush();
  expect(axios.post).toHaveBeenCalledWith('/api/workshop/supply-chain/mode', { mode: 'fixed' });
  expect(control.getAttribute('data-workshop-mode')).toBe('fixed');
  await act(async () => [...control.querySelectorAll('button')].find(button => button.textContent.trim() === 'Vulnerable').click());
  await flush();
  expect(axios.post).toHaveBeenCalledWith('/api/workshop/supply-chain/mode', { mode: 'vulnerable' });
});

test('uses cryptographic random bytes to create a UUIDv4 when randomUUID is unavailable', async () => {
  const randomUuidDescriptor = Object.getOwnPropertyDescriptor(globalThis.crypto, 'randomUUID');
  Object.defineProperty(globalThis.crypto, 'randomUUID', { configurable: true, value: undefined });
  const randomBytes = jest.spyOn(globalThis.crypto, 'getRandomValues').mockImplementation((bytes) => {
    bytes.set([0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
    return bytes;
  });
  try {
    const node = await renderWorkshop();
    await submit(node, 'exercise fallback key generation');
    await flush();

    expect(chatCalls()[0][2].headers['Idempotency-Key']).toBe('00112233-4455-4677-8899-aabbccddeeff');
    expect(randomBytes).toHaveBeenCalledWith(expect.any(Uint8Array));
  } finally {
    randomBytes.mockRestore();
    if (randomUuidDescriptor) Object.defineProperty(globalThis.crypto, 'randomUUID', randomUuidDescriptor);
    else delete globalThis.crypto.randomUUID;
  }
});

test('reuses the exact body, history, and key after an uncertain proxy 502 failure', async () => {
  const node = await renderWorkshop();
  let chatAttempt = 0;
  axios.post.mockImplementation((url) => {
    if (url.endsWith('/init')) return Promise.resolve({ data: { progress: [] } });
    if (url.endsWith('/chat')) {
      chatAttempt += 1;
      return chatAttempt === 2
        ? Promise.reject(Object.assign(new Error('proxy failure'), {
          response: { status: 502, data: { error: 'upstream unavailable' } },
        }))
        : Promise.resolve({ data: { response: chatAttempt === 1 ? 'context established' : 'replayed once', newlyCompletedObjectives: [] } });
    }
    return Promise.resolve({ data: { success: true } });
  });

  await submit(node, 'establish context');
  await flush();
  await submit(node, 'retry this exact request');
  await flush();
  expect(node.querySelector('textarea').value).toBe('retry this exact request');
  await submit(node, 'retry this exact request');
  await flush();

  const [, first, second] = chatCalls();
  expect(first[1]).toEqual({
    userMessage: 'retry this exact request',
    conversationHistory: [
      { role: 'user', content: 'establish context' },
      { role: 'assistant', content: 'context established' },
    ],
  });
  expect(second[1]).toEqual(first[1]);
  expect(second[2].headers['Idempotency-Key']).toBe(first[2].headers['Idempotency-Key']);
  expect(node.querySelectorAll('.user')).toHaveLength(2);
});

test('a failed reset restores the retry snapshot without changing its idempotency key', async () => {
  const node = await renderWorkshop();
  let chatAttempt = 0;
  axios.post.mockImplementation((url) => {
    if (url.endsWith('/init')) return Promise.resolve({ data: { progress: [] } });
    if (url.endsWith('/chat')) {
      chatAttempt += 1;
      return chatAttempt === 1
        ? Promise.reject(Object.assign(new Error('network down'), { code: 'ERR_NETWORK' }))
        : Promise.resolve({ data: { response: 'replayed after failed reset', newlyCompletedObjectives: [] } });
    }
    if (url.endsWith('/progress/reset')) return Promise.reject(new Error('reset unavailable'));
    return Promise.resolve({ data: {} });
  });

  await submit(node, 'preserve this request');
  await flush();
  const firstKey = chatCalls()[0][2].headers['Idempotency-Key'];
  const reset = [...node.querySelectorAll('button')].find(button => button.textContent.includes('Reset Progress'));
  await act(async () => { reset.dispatchEvent(new MouseEvent('click', { bubbles: true })); });
  await confirmOpenReset();
  await flush();
  expect(toast.error).toHaveBeenCalledWith('Reset could not be confirmed. Please try again.');
  expect(node.querySelector('textarea').value).toBe('preserve this request');
  await submit(node, 'preserve this request');
  await flush();

  expect(chatCalls()[1][2].headers['Idempotency-Key']).toBe(firstKey);
});

test('admits only one synchronous submission while the first transport is pending', async () => {
  const node = await renderWorkshop();
  const chat = deferred();
  axios.post.mockImplementation((url) => {
    if (url.endsWith('/init')) return Promise.resolve({ data: { progress: [] } });
    if (url.endsWith('/chat')) return chat.promise;
    return Promise.resolve({ data: {} });
  });

  const textarea = node.querySelector('textarea');
  await act(async () => { setTextareaValue(textarea, 'one turn only'); });
  await act(async () => {
    const form = textarea.closest('form');
    form.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true }));
    form.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true }));
  });

  expect(chatCalls()).toHaveLength(1);
  await act(async () => { chat.resolve({ data: { response: 'done', newlyCompletedObjectives: [] } }); });
});

test('reset invalidates an in-flight attempt so its late response cannot restore messages or progress', async () => {
  const node = await renderWorkshop();
  const chat = deferred();
  axios.post.mockImplementation((url) => {
    if (url.endsWith('/init')) return Promise.resolve({ data: { progress: [] } });
    if (url.endsWith('/chat')) return chat.promise;
    if (url.endsWith('/progress/reset')) return Promise.resolve({ data: { success: true } });
    return Promise.resolve({ data: {} });
  });

  await submit(node, 'request that will finish late');
  const reset = [...node.querySelectorAll('button')].find(button => button.textContent.includes('Reset Progress'));
  await act(async () => { reset.dispatchEvent(new MouseEvent('click', { bubbles: true })); });
  await confirmOpenReset();
  await flush();
  await act(async () => { chat.resolve({ data: { response: 'late reply', newlyCompletedObjectives: ['tool_list'] } }); });
  await flush();

  expect(node.textContent).toContain('Progress reset.');
  expect(node.textContent).not.toContain('late reply');
  expect(node.textContent).toContain('0 of 6 objectives completed');
});

test('an unmounted reset cannot apply its late completion', async () => {
  const node = await renderWorkshop();
  const resetRequest = deferred();
  axios.post.mockImplementation((url) => {
    if (url.endsWith('/init')) return Promise.resolve({ data: { progress: [] } });
    if (url.endsWith('/progress/reset')) return resetRequest.promise;
    return Promise.resolve({ data: {} });
  });

  const reset = [...node.querySelectorAll('button')].find(button => button.textContent.includes('Reset Progress'));
  await act(async () => { reset.dispatchEvent(new MouseEvent('click', { bubbles: true })); });
  await confirmOpenReset();
  const mounted = roots.pop();
  act(() => mounted.root.unmount());
  mounted.node.remove();
  await act(async () => { resetRequest.resolve({ data: { success: true } }); });
  await flush();

  expect(toast.info).not.toHaveBeenCalledWith('Progress reset.');
});

test('a current Judge retry refreshes progress and reports visible success', async () => {
  const node = await renderWorkshop();
  expect(mockRetryResult).toEqual(expect.any(Function));
  const signal = new AbortController().signal;

  await act(async () => {
    await mockRetryResult({
      completed: true,
      judgments: [{ verdict: 'fail', explanation: 'Controlled retry feedback.' }],
    }, { signal });
  });
  await flush();

  expect(node.textContent).toContain('Judge fail: Controlled retry feedback.');
  expect(toast.success).toHaveBeenCalledWith('Objective evaluation passed.');
  expect(axios.get).toHaveBeenCalledWith('/api/workshop/supply-chain/progress/current', { signal });
});

test('a Judge retry progress response cannot commit success after reset', async () => {
  const node = await renderWorkshop();
  const progress = deferred();
  const prior = axios.get.getMockImplementation();
  axios.get.mockImplementation(url => url.endsWith('/progress/current') ? progress.promise : prior(url));
  const retry = mockRetryResult;
  const signal = new AbortController().signal;

  let retryPromise;
  await act(async () => {
    retryPromise = retry({ completed: true, judgments: [] }, { signal });
    await Promise.resolve();
  });
  const reset = [...node.querySelectorAll('button')].find(button => button.textContent.includes('Reset Progress'));
  await act(async () => { reset.click(); });
  await confirmOpenReset();
  await flush();
  await act(async () => { progress.resolve({ data: { progress: [{ objective_id: 'tool_list', status: 'completed' }] } }); });
  await retryPromise;
  await flush();

  expect(node.textContent).toContain('Progress reset.');
  expect(node.textContent).toContain('0 of 6 objectives completed');
  expect(toast.success).not.toHaveBeenCalledWith('Objective evaluation passed.');
});

test('a retained Judge callback after reset or pre-abort cannot add stale feedback', async () => {
  const node = await renderWorkshop();
  const retry = mockRetryResult;
  const reset = [...node.querySelectorAll('button')].find(button => button.textContent.includes('Reset Progress'));
  await act(async () => { reset.click(); });
  await confirmOpenReset();
  await flush();

  const aborted = new AbortController();
  aborted.abort();
  await act(async () => {
    await retry({ completed: true, judgments: [{ verdict: 'fail', explanation: 'stale retained feedback' }] }, { signal: aborted.signal });
  });
  await flush();

  expect(node.textContent).toContain('Progress reset.');
  expect(node.textContent).not.toContain('stale retained feedback');
  expect(toast.error).not.toHaveBeenCalled();
});


test('idle reset rejection preserves history and progress, reports failure, and permits successful retry', async () => {
  const node = await renderWorkshop();
  axios.post.mockImplementation((url) => url.endsWith('/chat')
    ? Promise.resolve({ data: { response: 'retained answer', newlyCompletedObjectives: ['tool_list'] } })
    : Promise.resolve({ data: {} }));
  await submit(node, 'retained request');
  await flush();
  expect(node.textContent).toContain('1 of 6 objectives completed');
  const before = node.textContent;
  let resets = 0;
  axios.post.mockImplementation((url) => {
    if (url.endsWith('/progress/reset')) return ++resets === 1
      ? Promise.reject(new Error('private endpoint detail'))
      : Promise.resolve({ data: { success: true } });
    return Promise.resolve({ data: {} });
  });
  const reset = [...node.querySelectorAll('button')].find(button => button.textContent.includes('Reset Progress'));
  await act(async () => { reset.click(); });
  await confirmOpenReset();
  await flush();
  expect(node.textContent).toBe(before);
  expect(toast.error).toHaveBeenCalledTimes(1);
  expect(toast.error).toHaveBeenCalledWith('Reset could not be confirmed. Please try again.');
  expect(document.querySelector('[role="alertdialog"]')?.textContent).toContain('Retry this reset.');
  expect(toast.info).not.toHaveBeenCalledWith('Progress reset.');
  await confirmOpenReset();
  await flush();
  expect(resets).toBe(2);
  expect(node.textContent).toContain('0 of 6 objectives completed');
  expect(node.textContent).not.toContain('retained answer');
  expect(toast.info).toHaveBeenCalledWith('Progress reset.');
});

test('an old unmounted reset rejection does not notify or disturb a newly mounted workshop', async () => {
  const node = await renderWorkshop();
  const pending = deferred();
  axios.post.mockImplementation(url => url.endsWith('/progress/reset') ? pending.promise : Promise.resolve({ data: {} }));
  const reset = [...node.querySelectorAll('button')].find(button => button.textContent.includes('Reset Progress'));
  await act(async () => { reset.click(); });
  await confirmOpenReset();
  const mounted = roots.pop();
  act(() => mounted.root.unmount());
  mounted.node.remove();
  const current = await renderWorkshop();
  const before = current.textContent;
  await act(async () => { pending.reject(new Error('late reset failure')); });
  await flush();
  expect(toast.error).not.toHaveBeenCalled();
  expect(current.textContent).toBe(before);
});

function enableSolutionRequests(handler) {
  const prior = axios.get.getMockImplementation();
  axios.get.mockImplementation(url => {
    if (url === '/api/solutions/supply-chain/status') return Promise.resolve({ data: { objectives: { tool_list: true } } });
    if (url === '/api/solutions/supply-chain/tool_list') return handler();
    return prior(url);
  });
}
async function clickSolution(node) {
  const button = [...node.querySelectorAll('button')].find(x => x.textContent.trim() === 'Solution');
  expect(button).toBeTruthy();
  await act(async () => { button.click(); });
}
test('retired solution rejection after unmount cannot toast', async () => {
  const pending = deferred(); enableSolutionRequests(() => pending.promise);
  const node = await renderWorkshop(); await clickSolution(node);
  const mounted = roots.pop(); act(() => mounted.root.unmount()); mounted.node.remove();
  await act(async () => { pending.reject(Error('late request failure')); }); await flush();
  expect(toast.error).not.toHaveBeenCalled();
});
test('superseded solution rejection cannot toast while current rejection still does', async () => {
  const old = deferred(), current = deferred(); let calls = 0;
  enableSolutionRequests(() => ++calls === 1 ? old.promise : current.promise);
  const node = await renderWorkshop(); await clickSolution(node); await clickSolution(node);
  await act(async () => { old.reject(Error('old failure')); }); await flush();
  expect(toast.error).not.toHaveBeenCalled();
  await act(async () => { current.reject(Error('current failure')); }); await flush();
  expect(toast.error).toHaveBeenCalledWith('Solution not available for this objective.');
});
test('closing an existing solution retires a pending replacement failure', async () => {
  const pending = deferred(); let calls = 0;
  enableSolutionRequests(() => ++calls === 1 ? Promise.resolve({ data: { solution: { title: 'Owned solution', description: 'Teaching content' } } }) : pending.promise);
  const node = await renderWorkshop(); await clickSolution(node); await flush();
  expect(document.body.textContent).toContain('Owned solution');
  await clickSolution(node);
  const close = [...document.body.querySelectorAll('button')].find(x => x.textContent === 'Close');
  await act(async () => { close.click(); });
  await act(async () => { pending.reject(Error('closed failure')); }); await flush();
  expect(toast.error).not.toHaveBeenCalled();
  expect(document.body.textContent).not.toContain('Owned solution');
});
test('objective styling booleans stay off the DOM without React prop warnings', async () => {
  const error = jest.spyOn(console, 'error');
  try {
    const node = await renderWorkshop();
    expect([...node.querySelectorAll('*')].some(element => ['active', 'completed', '$active', '$completed'].some(name => element.hasAttribute(name)))).toBe(false);
    expect(error.mock.calls.filter(args => args.some(x => typeof x === 'string' && x.includes('non-boolean attribute')))).toEqual([]);
  } finally { error.mockRestore(); }
});


test.each([false, true])('superseded Judge refresh preserves newer committed progress, reject=%s', async reject => {
  const node = await renderWorkshop();
  const pending = deferred(), originalGet = axios.get.getMockImplementation(); let hold = true;
  axios.get.mockImplementation((url, options) => url.endsWith('/progress/current')
    ? (hold ? (hold = false, pending.promise) : Promise.resolve({data:{progress:[{objective_id:'tool_list', status:'completed'}]}}))
    : originalGet(url, options));
  let retry;
  await act(async () => { retry = mockRetryResult({completed:true, judgments:[]}, {signal:new AbortController().signal}); await Promise.resolve(); });
  await act(async () => mockPoll(null, null, {signal:new AbortController().signal}));
  expect(node.querySelector('.progress-text').textContent).toBe('1 of 6 objectives completed');
  toast.error.mockClear();
  await act(async () => {
    if (reject) pending.reject(new Error('Obsolete GET failed'));
    else pending.resolve({data:{progress:[]}});
    await retry;
  });
  expect(node.querySelector('.progress-text').textContent).toBe('1 of 6 objectives completed');
  expect(toast.error).not.toHaveBeenCalled();
});

test('current Judge refresh transport failure still reports failure without success', async () => {
  await renderWorkshop();
  const originalGet = axios.get.getMockImplementation();
  axios.get.mockImplementation((url, options) => url.endsWith('/progress/current')
    ? Promise.reject(Object.assign(new Error('Unavailable'), {response:{status:503}})) : originalGet(url, options));
  await act(async () => mockRetryResult({completed:true, judgments:[]}, {signal:new AbortController().signal}));
  expect(toast.error).toHaveBeenCalledWith('Evaluation finished, but progress could not be refreshed.');
  expect(toast.success).not.toHaveBeenCalled();
});
