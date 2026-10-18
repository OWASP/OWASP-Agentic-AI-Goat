/* eslint-disable testing-library/no-unnecessary-act -- real React root exercises async workshop configuration. */
import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import { MemoryRouter } from 'react-router-dom';
import axios from 'axios';
import { toast } from 'react-toastify';
import { WorkshopConfigProvider } from '../../context/WorkshopConfigContext';
import CSRFWorkshop from './CSRFWorkshop';
import { connectAuthenticatedSse } from '../../utils/authenticatedSse.mjs';
let mockRetryResult;
jest.mock('../../components/workshop/JudgeRetryButton', () => {
  const Actual = jest.requireActual('../../components/workshop/JudgeRetryButton').default;
  return props => { mockRetryResult = props.onResult; return <Actual {...props} />; };
});

let mockUser = { id: 7 };
jest.mock('../../context/AuthContext', () => ({ useAuth: () => ({user:mockUser}) }));
jest.mock('axios', () => ({
  get: jest.fn(), post: jest.fn(),
  defaults: {},
  interceptors: { response: { use: jest.fn(() => 1), eject: jest.fn() } },
}));
jest.mock('../../hooks/useChangePolling', () => () => {});
jest.mock('../../hooks/useWorkshopHeartbeat', () => () => {});
jest.mock('../../utils/authenticatedSse.mjs', () => ({
  connectAuthenticatedSse: jest.fn(() => ({ close: jest.fn() })),
}));
jest.mock('../../components/VulnerabilityTemplate', () => ({ children }) => <div>{children}</div>);
jest.mock('react-toastify', () => ({
  toast: { info: jest.fn(), success: jest.fn(), error: jest.fn(), warning: jest.fn() },
}));

const IDS = [
  'csrf_g1', 'csrf_g2', 'csrf_g3', 'csrf_p1', 'csrf_p2', 'csrf_p3',
  'csrf_x1', 'csrf_x2', 'csrf_x3', 'csrf_i1', 'csrf_i2', 'csrf_i3',
];
let revision;
let visibility;

const victim = tab => ({
  tab, victim: `Victim ${tab}`, profile: { email: `${tab}@example.test`, phone: '555' },
  security: { password: 'training', mfaEnabled: true },
  account: { balance: 1000, role: 'customer', payees: [] }, baseline: { balance: 1000 },
  defenses: { csrfToken: false, sameSite: 'Lax' }, attackLog: [], agentChatEnabled: false,
});

const snapshot = () => ({
  revision,
  exercises: { csrf_workshop: {
    isVisible: true,
    objectives: Object.fromEntries(IDS.map(id => [id, {
      isVisible: visibility[id], hintVisible: visibility[id], solutionVisible: visibility[id],
    }])),
  } },
});

function scheduler() {
  const tasks = [];
  return {
    setTimeout(callback, delay) {
      const task = { callback, delay, cancelled: false };
      tasks.push(task);
      return task;
    },
    clearTimeout(task) { if (task) task.cancelled = true; },
    async runNext() {
      const index = tasks.findIndex(task => !task.cancelled);
      expect(index).toBeGreaterThanOrEqual(0);
      const [task] = tasks.splice(index, 1);
      await act(async () => task.callback());
      await flush();
    },
  };
}

function deferred() {
  let resolve;
  let reject;
  const promise = new Promise((res, rej) => { resolve = res; reject = rej; });
  return { promise, resolve, reject };
}

async function flush() {
  await act(async () => {
    await Promise.resolve();
    await Promise.resolve();
    await Promise.resolve();
    await Promise.resolve();
  });
}

function installGetResponses() {
  axios.get.mockImplementation(url => {
    if (url === '/api/workshop/config/snapshot') return Promise.resolve({ data: snapshot() });
    if (url === '/api/workshop/config/revision') return Promise.resolve({ data: { revision } });
    if (url === '/api/changes/revisions') return Promise.resolve({ data: { revisions: { global: {}, workshops: {}, user: {} } } });
    if (url === '/api/workshop/csrf/progress') return Promise.resolve({ data: { objectives: {} } });
    if (url === '/api/solutions/csrf-workshop/status') {
      return Promise.resolve({ data: { objectives: Object.fromEntries(IDS.map(id => [id, {
        hint: visibility[id], solution: visibility[id],
      }])) } });
    }
    if (url.startsWith('/api/workshop/csrf/victim-state?tab=')) {
      const tab = new URL(url, 'http://fixture').searchParams.get('tab');
      return Promise.resolve({ data: { success: true, state: victim(tab), surface: {} } });
    }
    if (url.startsWith('/api/workshop/csrf/payload/')) {
      const id = url.split('/')[5];
      return Promise.resolve({ data: { html: `SKELETON_${id}`, filename: `${id}.html` } });
    }
    if (url === '/api/workshop/csrf/llm-status') return Promise.resolve({ data: { available: true } });
    if (url === '/api/workshop/csrf/email/payloads') return Promise.resolve({ data: { payloads: [] } });
    if (url === '/api/workshop/csrf/email/inbox-address') return Promise.resolve({ data: {} });
    if (url === '/api/email-agent/health') return Promise.resolve({ data: { gmail: {}, llm: {} } });
    if (url === '/api/workshop/csrf/rag/payloads') return Promise.resolve({ data: { payloads: [] } });
    if (url === '/api/workshop/csrf/rag/state') return Promise.resolve({ data: { cleanTopics: [] } });
    return Promise.resolve({ data: {} });
  });
}

function renderWorkshop({ strict = false } = {}) {
  const pollScheduler = scheduler();
  const node = document.createElement('div');
  document.body.appendChild(node);
  const root = createRoot(node);
  const workshop = () => (
    <MemoryRouter initialEntries={['/vulnerabilities/csrf-via-ai?scenario=post&objective=csrf_p1']}>
      <WorkshopConfigProvider token="token" pollerOptions={{
        scheduler: pollScheduler,
        visibility: { state: 'visible', subscribe: () => () => {} },
        random: () => 0,
      }}>
        <CSRFWorkshop />
      </WorkshopConfigProvider>
    </MemoryRouter>
  );
  act(() => root.render(strict ? <React.StrictMode>{workshop()}</React.StrictMode> : workshop()));
  return { node, root, scheduler: pollScheduler, rerender: () => root.render(workshop()) };
}

function button(node, text) {
  return [...node.querySelectorAll('button')].find(candidate => candidate.textContent.includes(text));
}

async function beginConfirmedReset(view) {
  await act(async () => button(view.node, 'Reset tab').click());
  const dialog = document.querySelector('[role="alertdialog"]');
  expect(dialog).not.toBeNull();
  await act(async () => button(dialog, 'Confirm reset').click());
  await flush();
}

function editPayload(node, html) {
  const editor = node.querySelector('.b-editor');
  const valueSetter = Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, 'value').set;
  act(() => {
    valueSetter.call(editor, html);
    editor.dispatchEvent(new Event('input', { bubbles: true }));
  });
}

function successfulAttempt(projectionPending = []) {
  return {
    tab: 'post', objectiveId: 'csrf_p1', graded: true, newlyCompleted: ['csrf_p1'], judgments: [],
    projectionPending, victimState: victim('post'), payloadDigest: 'a'.repeat(64),
    browser: {
      method: 'POST', resourceType: 'document', responseStatus: 200,
      responseObserved: true, boundary: 'synthetic-same-site-cross-origin',
    },
  };
}

beforeEach(() => {
  sessionStorage.clear();
  global.IS_REACT_ACT_ENVIRONMENT = true;
  global.requestAnimationFrame = callback => callback();
  global.EventSource = class { addEventListener() {} close() {} };
  mockUser = { id: 7 };
  localStorage.setItem('token', 'fixture-token');
  revision = 1;
  visibility = Object.fromEntries(IDS.map(id => [id, true]));
  axios.get.mockReset();
  axios.post.mockReset();
  toast.info.mockReset(); toast.success.mockReset(); toast.error.mockReset(); toast.warning.mockReset();
  installGetResponses();
});

afterEach(() => {
  document.body.replaceChildren();
  localStorage.clear();
});

test('submits the exact editor HTML once, blocks duplicate clicks, and never renders a raw iframe', async () => {
  const browserAttempt = deferred();
  axios.post.mockImplementation(url => {
    if (url === '/api/workshop/csrf/browser-attempt') return browserAttempt.promise;
    return Promise.resolve({ data: { success: true } });
  });
  const view = renderWorkshop();
  await flush();

  const rawHtml = '  <!doctype html>\n<form>Δ &amp; exact bytes</form>\n  ';
  editPayload(view.node, rawHtml);
  const execute = button(view.node, 'Execute observed payload');
  act(() => { execute.click(); execute.click(); });

  const calls = axios.post.mock.calls.filter(([url]) => url === '/api/workshop/csrf/browser-attempt');
  expect(calls).toEqual([['/api/workshop/csrf/browser-attempt', {
    tab: 'post', objectiveId: 'csrf_p1', html: rawHtml,
  }]]);
  expect(button(view.node, 'Executing…').disabled).toBe(true);
  expect(view.node.querySelector('iframe')).toBeNull();
  expect(axios.get).toHaveBeenCalledWith('/api/workshop/csrf/payload/csrf_p1/skeleton');

  axios.get.mockClear();
  await act(async () => browserAttempt.resolve({ data: successfulAttempt(['csrf_p1']) }));
  await flush();
  expect(toast.success).toHaveBeenCalledWith('Objective complete: 1. Forge POST via auto-submit <form>', { autoClose: 2500 });
  expect(button(view.node, 'Execute observed payload').disabled).toBe(false);
  expect(view.node.textContent).toContain('Downloads and new-tab previews are ungraded');
  expect(view.node.textContent).toContain('.invalid');
  expect(axios.get.mock.calls.some(([url]) => url === '/api/workshop/csrf/progress'
    || url.startsWith('/api/workshop/csrf/victim-state?tab='))).toBe(false);
  act(() => view.root.unmount());
});

test('StrictMode replay restores the mounted guard so a completed attempt leaves Execute enabled', async () => {
  axios.post.mockImplementation(url => url === '/api/workshop/csrf/browser-attempt'
    ? Promise.resolve({ data: successfulAttempt() })
    : Promise.resolve({ data: { success: true } }));
  const view = renderWorkshop({ strict: true });
  await flush();
  editPayload(view.node, '<form>strict replay</form>');

  await act(async () => button(view.node, 'Execute observed payload').click());
  await flush();

  expect(button(view.node, 'Executing…')).toBeUndefined();
  expect(button(view.node, 'Execute observed payload').disabled).toBe(false);
  expect(axios.post.mock.calls.filter(([url]) => url === '/api/workshop/csrf/browser-attempt')).toHaveLength(1);
  act(() => view.root.unmount());
});

test('a failed managed-browser request reports the error and grants no client-side credit', async () => {
  axios.post.mockRejectedValue({ response: { data: { error: 'Managed browser unavailable' } } });
  const view = renderWorkshop();
  await flush();
  editPayload(view.node, '<form>failed</form>');

  await act(async () => button(view.node, 'Execute observed payload').click());
  await flush();
  expect(toast.error).toHaveBeenCalledWith('Managed browser unavailable');
  expect(toast.success.mock.calls.some(([message]) => String(message).startsWith('Objective complete:'))).toBe(false);
  expect(view.node.textContent).toContain('Error: Managed browser unavailable');
  expect(button(view.node, 'Execute observed payload').disabled).toBe(false);
  act(() => view.root.unmount());
});

test('a browser failure reconciles a persisted victim effect without retrying or granting credit', async () => {
  const defaultGet = axios.get.getMockImplementation();
  let exposePersistedState = false;
  axios.get.mockImplementation(url => {
    if (exposePersistedState && url === '/api/workshop/csrf/victim-state?tab=post') {
      const changed = victim('post');
      changed.account.balance = 750;
      return Promise.resolve({ data: { success: true, state: changed, surface: {} } });
    }
    if (exposePersistedState && url === '/api/workshop/csrf/progress') {
      return Promise.resolve({ data: { objectives: { csrf_p1: { completed: false } } } });
    }
    return defaultGet(url);
  });
  axios.post.mockImplementation(url => {
    if (url === '/api/workshop/csrf/browser-attempt') {
      exposePersistedState = true;
      return Promise.reject({ response: { status: 504, data: { error: 'Browser response observation timed out' } } });
    }
    return Promise.resolve({ data: { success: true } });
  });
  const view = renderWorkshop();
  await flush();
  editPayload(view.node, '<form>effect persisted before timeout</form>');

  await act(async () => button(view.node, 'Execute observed payload').click());
  await flush();
  expect(toast.error).toHaveBeenCalledWith('Browser response observation timed out');
  expect(toast.success.mock.calls.some(([message]) => String(message).startsWith('Objective complete:'))).toBe(false);
  expect(view.node.textContent).toContain('$750');
  expect(axios.post.mock.calls.filter(([url]) => url === '/api/workshop/csrf/browser-attempt')).toHaveLength(1);
  act(() => view.root.unmount());
});

test('reset invalidates a late browser-attempt response so it cannot restore credit', async () => {
  const browserAttempt = deferred();
  axios.post.mockImplementation(url => {
    if (url === '/api/workshop/csrf/browser-attempt') return browserAttempt.promise;
    if (url === '/api/workshop/csrf/progress/reset-tab') return Promise.resolve({ data: { success: true } });
    return Promise.resolve({ data: { success: true } });
  });
  const view = renderWorkshop();
  await flush();
  editPayload(view.node, '<form>late</form>');
  act(() => button(view.node, 'Execute observed payload').click());
  await beginConfirmedReset(view);

  await act(async () => browserAttempt.resolve({ data: successfulAttempt() }));
  await flush();
  expect(toast.success.mock.calls.some(([message]) => String(message).startsWith('Objective complete:'))).toBe(false);
  expect(view.node.textContent).not.toContain('Managed browser observed POST');
  act(() => view.root.unmount());
});

test('hiding the selected objective while its request is pending suppresses the late result', async () => {
  const browserAttempt = deferred();
  axios.post.mockImplementation(url => url === '/api/workshop/csrf/browser-attempt'
    ? browserAttempt.promise
    : Promise.resolve({ data: { success: true } }));
  const view = renderWorkshop();
  await flush();
  editPayload(view.node, '<form>hidden while pending</form>');
  act(() => button(view.node, 'Execute observed payload').click());

  visibility.csrf_p1 = false;
  revision = 2;
  await view.scheduler.runNext();
  expect(view.node.textContent).not.toContain('Forge POST via auto-submit');
  expect(view.node.querySelector('.b-editor').value).toBe('SKELETON_csrf_p2');

  await act(async () => browserAttempt.resolve({ data: successfulAttempt() }));
  await flush();
  expect(toast.success.mock.calls.some(([message]) => String(message).startsWith('Objective complete:'))).toBe(false);
  expect(view.node.textContent).not.toContain('Managed browser observed POST');
  act(() => view.root.unmount());
});

test('switching tabs while a request is pending suppresses its late result', async () => {
  const browserAttempt = deferred();
  axios.post.mockImplementation(url => url === '/api/workshop/csrf/browser-attempt'
    ? browserAttempt.promise
    : Promise.resolve({ data: { success: true } }));
  const view = renderWorkshop();
  await flush();
  editPayload(view.node, '<form>old tab</form>');
  act(() => button(view.node, 'Execute observed payload').click());
  act(() => button(view.node, 'GET CSRF').click());
  await flush();
  expect(view.node.textContent).toContain('GET CSRF — Objectives');

  await act(async () => browserAttempt.resolve({ data: successfulAttempt() }));
  await flush();
  expect(toast.success.mock.calls.some(([message]) => String(message).startsWith('Objective complete:'))).toBe(false);
  expect(view.node.textContent).not.toContain('Managed browser observed POST');
  act(() => view.root.unmount());
});

test('rejects a browser response for a different objective without granting credit', async () => {
  const browserAttempt = deferred();
  axios.post.mockImplementation(url => url === '/api/workshop/csrf/browser-attempt'
    ? browserAttempt.promise
    : Promise.resolve({ data: { success: true } }));
  const view = renderWorkshop();
  await flush();
  editPayload(view.node, '<form>mismatch</form>');
  act(() => button(view.node, 'Execute observed payload').click());

  await act(async () => browserAttempt.resolve({
    data: { ...successfulAttempt(), objectiveId: 'csrf_p2', newlyCompleted: ['csrf_p2'] },
  }));
  await flush();
  expect(toast.error).toHaveBeenCalledWith('Browser attempt response did not match the submitted objective.');
  expect(toast.success.mock.calls.some(([message]) => String(message).startsWith('Objective complete:'))).toBe(false);
  expect(view.node.textContent).not.toContain('Managed browser observed POST');
  act(() => view.root.unmount());
});

test.each(['current', 'reset-pending', 'reset-before', 'aborted', 'unmounted', 'token-change'])(
  'Judge retry respects %s response ownership', async mode => {
    mockRetryResult = undefined;
    const attempt = { ...successfulAttempt(), newlyCompleted: [], judgments: [{
      objectiveId: 'csrf_p1', verdict: 'unavailable', evaluationId: 'csrf-retry', canRetry: true,
    }] };
    axios.post.mockImplementation(url => Promise.resolve({ data: url.endsWith('/browser-attempt') ? attempt : { success: true } }));
    const view = renderWorkshop(); await flush();
    editPayload(view.node, '<form>retry lifecycle</form>');
    act(() => button(view.node, 'Execute observed payload').click()); await flush();
    const callback = mockRetryResult;
    expect(callback).toEqual(expect.any(Function));
    const pending = deferred(); const original = axios.get.getMockImplementation();
    let hold = true;
    axios.get.mockImplementation((url, ...args) => url === '/api/workshop/csrf/progress' && hold
      ? (hold = false, pending.promise) : original(url, ...args));
    const reset = async () => beginConfirmedReset(view);
    if (mode === 'reset-before') { hold = false; await reset(); }
    const controller = new AbortController();
    if (mode === 'aborted') controller.abort();
    if (mode === 'unmounted') act(() => view.root.unmount());
    if (mode === 'token-change') localStorage.setItem('token', 'replacement-token');
    axios.get.mockClear(); toast.success.mockClear(); toast.info.mockClear();
    let work;
    act(() => { work = callback({ completed: true, judgment: {
      objectiveId: 'csrf_p1', verdict: 'fail', explanation: 'Retry lifecycle feedback',
    } }, { signal: controller.signal }); });
    if (mode === 'reset-pending') await reset();
    await act(async () => { pending.resolve({ data: { objectives: { csrf_p1: { completed: true } } } }); await work; });
    if (mode === 'current') {
      expect(view.node.textContent).toContain('Retry lifecycle feedback');
      expect(view.node.textContent).toContain('This tab: 1/3');
      expect(toast.success).toHaveBeenCalledWith('Objective evaluation passed.');
      expect(axios.get).toHaveBeenCalledWith('/api/workshop/csrf/progress', { signal: controller.signal });
    } else {
      expect(view.node.textContent).not.toContain('Retry lifecycle feedback');
      expect(toast.success).not.toHaveBeenCalledWith('Objective evaluation passed.');
      if (mode !== 'unmounted') expect(view.node.textContent).toContain('This tab: 0/3');
      if (mode !== 'reset-pending') { expect(axios.get).not.toHaveBeenCalled(); expect(toast.info).not.toHaveBeenCalled(); }
    }
    if (mode !== 'unmounted') act(() => view.root.unmount());
  },
);


test.each(['current','reset','unmount'])('retry refresh failure is visible only while current: %s',async mode=>{
  const attempt={...successfulAttempt(),newlyCompleted:[],judgments:[{objectiveId:'csrf_p1',verdict:'unavailable',evaluationId:'csrf-refresh',canRetry:true}]};
  axios.post.mockImplementation(url=>Promise.resolve({data:url.endsWith('/browser-attempt')?attempt:{success:true}}));
  const view=renderWorkshop();await flush();editPayload(view.node,'<form>refresh</form>');act(()=>button(view.node,'Execute observed payload').click());await flush();
  const pending=deferred(),prior=axios.get.getMockImplementation();let hold=true;
  axios.get.mockImplementation((url,...args)=>url==='/api/workshop/csrf/progress'&&hold?(hold=false,pending.promise):prior(url,...args));
  let work;act(()=>{work=mockRetryResult({completed:true,judgments:[]},{signal:new AbortController().signal});});
  if(mode==='reset') await beginConfirmedReset(view);
  if(mode==='unmount')act(()=>view.root.unmount());
  toast.warning.mockClear();toast.success.mockClear();
  await act(async()=>{pending.reject(new Error('503'));await work;});
  expect(toast.success).not.toHaveBeenCalledWith('Objective evaluation passed.');
  if(mode==='current')expect(toast.warning).toHaveBeenCalledWith('Evaluation finished, but progress could not be refreshed.');
  else expect(toast.warning).not.toHaveBeenCalled();
  if(mode!=='unmount'){expect(view.node.textContent).toContain('This tab: 0/3');act(()=>view.root.unmount());}
});

test('owner replacement retires pending reset, reloads progress, and does not resurrect A callbacks', async () => {
  const pending = deferred(); axios.post.mockImplementation(url => url.endsWith('/reset-tab') ? pending.promise : Promise.resolve({data:successfulAttempt()}));
  const view = renderWorkshop(); await flush();
  act(()=>button(view.node,'Reset tab').click());
  act(()=>button(document.body,'Confirm reset').click()); await flush();
  const original=axios.get.getMockImplementation();
  axios.get.mockImplementation((url,...args)=>url.endsWith('/csrf/progress')?Promise.resolve({data:{objectives:{csrf_p2:{completed:true}}}}):original(url,...args));
  localStorage.setItem('token','owner-b'); mockUser={id:8};act(()=>view.rerender());await flush();
  expect(view.node.textContent).toContain('This tab: 1/3');
  localStorage.setItem('token','fixture-token');mockUser={id:7};act(()=>view.rerender());await flush();
  editPayload(view.node,'<form>NEW_OWNER_PAYLOAD</form>'); toast.success.mockClear();
  await act(async()=>pending.resolve({data:{success:true}}));await flush();
  expect(view.node.querySelector('.b-editor').value).toContain('NEW_OWNER_PAYLOAD');expect(view.node.textContent).toContain('This tab: 1/3');expect(toast.success).not.toHaveBeenCalled();
  act(()=>button(view.node,'Execute observed payload').click());await flush();
  expect(axios.post.mock.calls.some(([url,body])=>url.endsWith('/browser-attempt')&&body.html.includes('NEW_OWNER_PAYLOAD'))).toBe(true);
  act(()=>view.root.unmount());
});
test('pending attempt after immediate token replacement cannot publish; new owner attempt remains usable',async()=>{
 const pending=deferred();axios.post.mockReturnValueOnce(pending.promise);const view=renderWorkshop();await flush();editPayload(view.node,'<form>old</form>');act(()=>button(view.node,'Execute observed payload').click());await flush();
 localStorage.setItem('token','owner-b');await act(async()=>pending.resolve({data:successfulAttempt()}));await flush();expect(view.node.textContent).toContain('This tab: 0/3');
 mockUser={id:8};act(()=>view.rerender());await flush();axios.post.mockResolvedValue({data:successfulAttempt()});editPayload(view.node,'<form>new</form>');act(()=>button(view.node,'Execute observed payload').click());await flush();expect(axios.post.mock.calls.length).toBe(2);act(()=>view.root.unmount());
});


test('SSE token supplier fails closed when browser storage becomes unavailable', async () => {
  const view = renderWorkshop(); await flush();
  const options = connectAuthenticatedSse.mock.calls.at(-1)[0];
  expect(options.getToken()).toBe('fixture-token');
  const storage = jest.spyOn(Storage.prototype, 'getItem').mockImplementation(() => { throw new DOMException('Storage blocked', 'SecurityError'); });
  try {
    expect(() => options.getToken()).not.toThrow();
    expect(options.getToken()).toBeUndefined();
    const before = view.node.textContent;
    await act(async () => options.onEvent({ type: 'csrf_forged', data: JSON.stringify({ tab: 'post', phase: 'reply', agentReply: 'STALE_STORAGE_REPLY', objectivesHit: ['csrf_p1'] }) }));
    expect(view.node.textContent).toBe(before);
    expect(view.node.textContent).not.toContain('STALE_STORAGE_REPLY');
  } finally { storage.mockRestore(); act(() => view.root.unmount()); }
});


test('late authenticated 401 cannot redirect replacement owner; current request retains redirect', async () => {
  const view = renderWorkshop(); await flush();
  const oldHandler = axios.interceptors.response.use.mock.calls.at(-1)[1];
  const error = { response: { status: 401 }, config: { url: '/api/workshop/csrf/progress', headers: { Authorization: 'Bearer fixture-token' } } };
  const navigation = jest.spyOn(console, 'error').mockImplementation(() => {});
  try {
    localStorage.setItem('token', 'owner-b'); mockUser = { id: 8 };
    await expect(oldHandler(error)).rejects.toBe(error);
    expect(navigation).not.toHaveBeenCalled();
    act(() => view.rerender()); await flush();
    const handler = axios.interceptors.response.use.mock.calls.at(-1)[1];
    await expect(handler(error)).rejects.toBe(error);
    expect(navigation).not.toHaveBeenCalled();
    const currentError = { ...error, config: { ...error.config, headers: { get: name => name === 'Authorization' ? 'Bearer owner-b' : undefined } } };
    await expect(handler(currentError)).rejects.toBe(currentError);
    // JSDOM reports its unimplemented navigation when the real assign is invoked.
    expect(navigation.mock.calls.some(args => args.some(value => String(value).includes('navigation')))).toBe(true);
  } finally { navigation.mockRestore(); act(() => view.root.unmount()); }
});
