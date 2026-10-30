/* eslint-disable testing-library/no-unnecessary-act -- real React root exercises async configuration. */
import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import { MemoryRouter } from 'react-router-dom';
import axios from 'axios';
import { WorkshopConfigProvider } from '../../context/WorkshopConfigContext';
import CSRFWorkshop from './CSRFWorkshop';
import { workshopTokens } from '../../components/workshop/experience.mjs';

jest.mock('../../context/AuthContext', () => ({ useAuth: () => ({user:{id:7}}) }));
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
let labels;
let descriptions;

const victim = tab => ({
  tab, victim: `Victim ${tab}`, profile: { email: `${tab}@example.test`, phone: '555' },
  security: { password: 'training', mfaEnabled: true },
  account: { balance: 1000, role: 'customer', payees: [] }, baseline: { balance: 1000 },
  defenses: { csrfToken: false, sameSite: 'None' }, attackLog: [], agentChatEnabled: false,
});

function snapshot() {
  return { revision, exercises: { csrf_workshop: {
    isVisible: true,
    objectives: Object.fromEntries(IDS.map(id => [id, {
      label: labels[id], description: descriptions[id], isVisible: visibility[id], hintVisible: visibility[id], solutionVisible: visibility[id],
    }])),
  } } };
}

function scheduler() {
  const tasks = [];
  return {
    setTimeout(callback, delay) { const task = { callback, delay, cancelled: false }; tasks.push(task); return task; },
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

async function flush() {
  await act(async () => {
    await Promise.resolve(); await Promise.resolve(); await Promise.resolve();
    await Promise.resolve(); await Promise.resolve();
  });
}

function installResponses() {
  axios.post.mockResolvedValue({ data: { success: true } });
  axios.get.mockImplementation(url => {
    if (url === '/api/workshop/config/snapshot') return Promise.resolve({ data: snapshot() });
    if (url === '/api/workshop/config/revision') return Promise.resolve({ data: { revision } });
    if (url === '/api/changes/revisions') return Promise.resolve({ data: { revisions: { global: {}, workshops: {}, user: {} } } });
    if (url === '/api/workshop/csrf/progress') return Promise.resolve({ data: { objectives: {} } });
    if (url === '/api/workshop/csrf/mode') return Promise.resolve({ data: { mode: null, effectiveMode: 'vuln', fixedObjectiveIds: ['csrf_x3'] } });
    if (url === '/api/solutions/csrf-workshop/status') {
      return Promise.resolve({ data: { objectives: Object.fromEntries(IDS.map(id => [id,
        { hint: visibility[id], solution: visibility[id] }])) } });
    }
    if (url.startsWith('/api/workshop/csrf/victim-state?tab=')) {
      const tab = new URL(url, 'http://fixture').searchParams.get('tab');
      return Promise.resolve({ data: { success: true, state: victim(tab), surface: {} } });
    }
    if (url.startsWith('/api/workshop/csrf/payload/')) {
      const id = url.split('/')[5];
      return Promise.resolve({ data: { html: `SKELETON_${id}` } });
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

function renderWorkshop(initialUrl = '/vulnerabilities/csrf-via-ai?scenario=post&objective=csrf_p1') {
  const pollScheduler = scheduler();
  const node = document.createElement('div');
  document.body.appendChild(node);
  const root = createRoot(node);
  act(() => root.render(
    <MemoryRouter initialEntries={[initialUrl]}>
      <WorkshopConfigProvider token="token" pollerOptions={{
        scheduler: pollScheduler,
        visibility: { state: 'visible', subscribe: () => () => {} },
        random: () => 0,
      }}>
        <CSRFWorkshop />
      </WorkshopConfigProvider>
    </MemoryRouter>,
  ));
  return { node, root, scheduler: pollScheduler };
}

beforeEach(() => {
  sessionStorage.clear();
  global.IS_REACT_ACT_ENVIRONMENT = true;
  global.requestAnimationFrame = callback => callback();
  global.EventSource = class {
    addEventListener() {}
    close() {}
  };
  localStorage.setItem('token', 'fixture-token');
  revision = 1;
  labels = {};
  descriptions = {};
  visibility = Object.fromEntries(IDS.map(id => [id, true]));
  axios.get.mockReset(); axios.post.mockReset();
  installResponses();
});

afterEach(() => {
  document.body.replaceChildren();
  localStorage.clear();
});

test('briefing query renders the visible POST tab and loads the csrf_p1 skeleton', async () => {
  const view = renderWorkshop();
  await flush();
  expect(view.node.textContent).toContain('POST CSRF — Objectives');
  expect(view.node.textContent).toContain('Forge POST via auto-submit');
  expect(view.node.querySelector('.b-editor').value).toBe('SKELETON_csrf_p1');
  expect(axios.get.mock.calls.some(([url]) => url.startsWith('/api/workshop/csrf/payload/csrf_p1/skeleton'))).toBe(true);
  act(() => view.root.unmount());
});

test('CSRF scenario, chat, objective and action chrome use the shared workshop baseline', async () => {
  const view = renderWorkshop();
  await flush();
  const selected = view.node.querySelector('[data-scenario-tab="post"]');
  const intro = [...view.node.querySelectorAll('h3')].find(node => node.textContent.includes('CSRF-via-AI Attack Console')).parentElement;
  const chatHeader = [...view.node.querySelectorAll('h3')].find(node => node.textContent.includes('Victim Chat')).parentElement;
  const objective = view.node.querySelector('.obj-content').parentElement;
  const execute = [...view.node.querySelectorAll('button')].find(node => node.textContent.includes('Execute observed payload'));
  expect(selected.getAttribute('aria-selected')).toBe('true');
  expect(getComputedStyle(selected).borderBottomColor).toBe('rgb(102, 126, 234)');
  expect(getComputedStyle(intro).borderTopColor).toBe('rgb(102, 126, 234)');
  expect(getComputedStyle(chatHeader).backgroundImage).toContain(workshopTokens.brand);
  expect(getComputedStyle(objective).borderTopColor).toBe('rgb(102, 126, 234)');
  expect(getComputedStyle(execute).minHeight).toBe('44px');
  await act(async () => view.node.querySelector('[data-scenario-tab="get"]').click());
  await flush();
  expect(view.node.querySelector('[data-scenario-tab="get"]').getAttribute('aria-selected')).toBe('true');
  expect(view.node.textContent).toContain('GET CSRF — Objectives');
  act(() => view.root.unmount());
});

test('defense toggle is legible in both protected and unprotected states', async () => {
  const originalPost = axios.post.getMockImplementation();
  axios.post.mockImplementation((url, body, options) => url === '/api/workshop/csrf/defense-toggle'
    ? Promise.resolve({ data: { victimState: { ...victim('post'), defenses: { csrfToken: body.enabled, sameSite: 'None' } } } })
    : originalPost(url, body, options));
  const view = renderWorkshop();
  await flush();
  const toggle = view.node.querySelector('button.def');
  expect(toggle.textContent).toContain('CSRF OFF');
  expect(getComputedStyle(toggle).backgroundColor).toBe('rgb(255, 241, 242)');
  expect(getComputedStyle(toggle).color).toBe('rgb(159, 18, 57)');
  expect(getComputedStyle(toggle).minHeight).toBe('44px');
  await act(async () => toggle.click());
  await flush();
  expect(toggle.textContent).toContain('CSRF ON');
  expect(getComputedStyle(toggle).backgroundColor).toBe('rgb(240, 253, 244)');
  expect(getComputedStyle(toggle).color).toBe('rgb(22, 101, 52)');
  act(() => view.root.unmount());
});

test('canonical objective copy and independently gated hint and solution use focused shared dialogs', async () => {
  labels.csrf_p1 = 'Instructor POST objective';
  descriptions.csrf_p1 = 'Instructor-authored POST guidance';
  const originalGet = axios.get.getMockImplementation();
  axios.get.mockImplementation((url, options) => {
    if (url === '/api/hints/csrf_workshop/csrf_p1') return Promise.resolve({ data: { hint: { title: 'Instructor hint', hints: ['First hint', 'Second hint'] } } });
    if (url === '/api/solutions/csrf-workshop/objective/csrf_p1') return Promise.resolve({ data: { solution: {
      title: 'Instructor solution', example: '<form>owned skeleton</form>', explanation: 'Instructor explanation',
      hasPayload: true, solutionUrl: '/api/workshop/csrf/payload/csrf_p1/solution',
    } } });
    return originalGet(url, options);
  });
  const view = renderWorkshop();
  await flush();
  expect(view.node.textContent).toContain('Instructor POST objective');
  expect(view.node.textContent).toContain('Instructor-authored POST guidance');
  const card = [...view.node.querySelectorAll('.obj-content')].find(node => node.textContent.includes('Instructor POST objective'));
  const hintButton = [...card.querySelectorAll('button')].find(button => button.textContent.trim() === 'Hint');
  const solutionButton = [...card.querySelectorAll('button')].find(button => button.textContent.trim() === 'Solution');
  expect(hintButton).toBeTruthy(); expect(solutionButton).toBeTruthy();
  await act(async () => hintButton.click()); await flush();
  let dialog = document.querySelector('[data-testid="objective-help-modal"]');
  expect(dialog.dataset.helpKind).toBe('hint');
  expect(dialog.textContent).toContain('First hint');
  expect(dialog.textContent).not.toContain('Second hint');
  expect(document.activeElement.getAttribute('aria-label')).toBe('Close hint');
  await act(async () => dialog.querySelector('button[aria-label="Close hint"]').click());
  await act(async () => solutionButton.click()); await flush();
  dialog = document.querySelector('[data-testid="objective-help-modal"]');
  expect(dialog.dataset.helpKind).toBe('solution');
  expect(dialog.textContent).toContain('Instructor solution');
  expect(dialog.textContent).toContain('Instructor explanation');
  expect(dialog.textContent).toContain('owned skeleton');
  expect(dialog.textContent).toContain('Download skeleton (ungraded)');
  expect(dialog.textContent).toContain('Show working HTML payload');
  act(() => view.root.unmount());
});

test('a canonical visibility revision closes the open solution and removes its gated payload actions', async () => {
  const originalGet = axios.get.getMockImplementation();
  axios.get.mockImplementation((url, options) => url === '/api/solutions/csrf-workshop/objective/csrf_p1'
    ? Promise.resolve({ data: { solution: { title: 'Private instructor payload', example: '<form>private</form>', hasPayload: true } } })
    : originalGet(url, options));
  const view = renderWorkshop(); await flush();
  const button = [...view.node.querySelectorAll('button')].find(element => element.textContent.trim() === 'Solution');
  await act(async () => button.click()); await flush();
  expect(document.querySelector('[data-testid="objective-help-modal"]')?.textContent).toContain('Private instructor payload');
  visibility.csrf_p1 = false;
  revision = 2;
  await view.scheduler.runNext();
  expect(document.querySelector('[data-testid="objective-help-modal"]')).toBeNull();
  expect(document.body.textContent).not.toContain('Private instructor payload');
  act(() => view.root.unmount());
});

test('canonical CSRF workshop mode remains available across tabs and posts only the selected choice', async () => {
  axios.post.mockImplementation((url, body) => url === '/api/workshop/csrf/mode'
    ? Promise.resolve({ data: { mode: body.mode, effectiveMode: body.mode, fixedObjectiveIds: IDS } })
    : Promise.resolve({ data: { success: true } }));
  const view = renderWorkshop();
  await flush();
  let control = view.node.querySelector('[data-workshop-mode-control]');
  expect(control).toBeTruthy();
  expect(control.textContent).toContain('CSRF workshop');
  expect(control.getAttribute('data-workshop-mode')).toBe('vuln');
  await act(async () => [...control.querySelectorAll('button')].find(button => button.textContent.trim() === 'Fixed').click());
  await flush();
  expect(axios.post).toHaveBeenCalledWith('/api/workshop/csrf/mode', { mode: 'fixed' });
  expect(view.node.querySelector('[data-workshop-mode-control]').getAttribute('data-workshop-mode')).toBe('fixed');
  for (const tab of ['get', 'xss', 'indirect']) {
    await act(async () => view.node.querySelector(`[data-scenario-tab="${tab}"]`).click());
    await flush();
    control = view.node.querySelector('[data-workshop-mode-control]');
    expect(control).toBeTruthy();
    expect(control.textContent).toContain('CSRF workshop');
    expect(control.getAttribute('data-workshop-mode')).toBe('fixed');
  }
  await act(async () => [...control.querySelectorAll('button')].find(button => button.textContent.trim() === 'Vulnerable').click());
  await flush();
  expect(axios.post).toHaveBeenCalledWith('/api/workshop/csrf/mode', { mode: 'vuln' });
  expect(view.node.querySelector('[data-workshop-mode-control]').getAttribute('data-workshop-mode')).toBe('vuln');
  act(() => view.root.unmount());
});

test('manual Clear remains authoritative across a configuration refresh', async () => {
  const view = renderWorkshop();
  await flush();
  expect(view.node.querySelector('.b-editor').value).toBe('SKELETON_csrf_p1');
  const clear = [...view.node.querySelectorAll('button')]
    .find(candidate => candidate.textContent.trim() === 'Clear');
  act(() => clear.click());
  expect(view.node.querySelector('.b-editor').value).toBe('');

  axios.get.mockClear();
  revision = 2;
  await view.scheduler.runNext();
  expect(view.node.querySelector('.b-editor').value).toBe('');
  expect(axios.get.mock.calls.some(([url]) => url.startsWith('/api/workshop/csrf/payload/'))).toBe(false);
  act(() => view.root.unmount());
});

test('learner editing while initial hydration is pending wins over the late skeleton', async () => {
  let resolveSkeleton;
  const skeleton = new Promise(resolve => { resolveSkeleton = resolve; });
  const normalGet = axios.get.getMockImplementation();
  axios.get.mockImplementation(url => url === '/api/workshop/csrf/payload/csrf_p1/skeleton'
    ? skeleton
    : normalGet(url));
  const view = renderWorkshop();
  await flush();
  const editor = view.node.querySelector('.b-editor');
  const setter = Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, 'value').set;
  act(() => {
    setter.call(editor, 'LEARNER_AUTHORED_PAYLOAD');
    editor.dispatchEvent(new Event('input', { bubbles: true }));
  });

  await act(async () => resolveSkeleton({ data: { html: 'LATE_SKELETON' } }));
  await flush();
  expect(view.node.querySelector('.b-editor').value).toBe('LEARNER_AUTHORED_PAYLOAD');
  act(() => view.root.unmount());
});

test('hidden csrf_p1 is never loaded, and a later config change clears a selected p1 skeleton', async () => {
  visibility.csrf_p1 = false;
  let view = renderWorkshop();
  await flush();
  expect(view.node.textContent).toContain('POST CSRF — Objectives');
  expect(view.node.textContent).not.toContain('Forge POST via auto-submit');
  expect(axios.get.mock.calls.some(([url]) => url.startsWith('/api/workshop/csrf/payload/csrf_p1/skeleton'))).toBe(false);
  expect(view.node.querySelector('.b-editor').value).toBe('SKELETON_csrf_p2');
  act(() => view.root.unmount());

  axios.get.mockClear();
  visibility.csrf_p1 = true;
  view = renderWorkshop();
  await flush();
  expect(view.node.querySelector('.b-editor').value).toBe('SKELETON_csrf_p1');
  visibility.csrf_p1 = false;
  revision = 2;
  await view.scheduler.runNext();
  expect(view.node.textContent).not.toContain('Forge POST via auto-submit');
  expect(view.node.querySelector('.b-editor').value).toBe('SKELETON_csrf_p2');
  act(() => view.root.unmount());
});

test('a late skeleton for a newly hidden objective cannot replace its visible successor', async () => {
  let resolveP1;
  const p1 = new Promise(resolve => { resolveP1 = resolve; });
  const normalGet = axios.get.getMockImplementation();
  axios.get.mockImplementation(url => url === '/api/workshop/csrf/payload/csrf_p1/skeleton'
    ? p1
    : normalGet(url));
  const view = renderWorkshop();
  await flush();

  visibility.csrf_p1 = false;
  revision = 2;
  await view.scheduler.runNext();
  expect(view.node.querySelector('.b-editor').value).toBe('SKELETON_csrf_p2');

  await act(async () => resolveP1({ data: { html: 'STALE_P1' } }));
  await flush();
  expect(view.node.querySelector('.b-editor').value).toBe('SKELETON_csrf_p2');
  act(() => view.root.unmount());
});

async function clickReset(view, label) {
  const prior = document.querySelector('[role="alertdialog"]');
  if (prior) await act(async () => [...prior.querySelectorAll('button')].find(element => element.textContent.trim() === 'Cancel').click());
  const button = [...view.node.querySelectorAll('button')].find(element => element.textContent.trim() === label);
  expect(button).toBeTruthy();
  await act(async () => button.click());
  const dialog = document.querySelector('[role="alertdialog"]');
  expect(dialog).not.toBeNull();
  await act(async () => [...dialog.querySelectorAll('button')].find(element => element.textContent.trim() === 'Confirm reset').click());
  await flush();
}

test('cancelled scoped reset sends no request and restores the trigger', async () => {
  const view = renderWorkshop(); await flush();
  const trigger = [...view.node.querySelectorAll('button')].find(element => element.textContent.trim() === 'Reset tab');
  trigger.focus();
  await act(async () => trigger.click());
  const dialog = document.querySelector('[role="alertdialog"]');
  expect(dialog.textContent).toContain('POST CSRF');
  expect(document.activeElement.textContent).toBe('Confirm reset');
  await act(async () => [...dialog.querySelectorAll('button')].find(element => element.textContent.trim() === 'Cancel').click());
  expect(document.querySelector('[role="alertdialog"]')).toBeNull();
  expect(document.activeElement).toBe(trigger);
  expect(axios.post.mock.calls.some(([url]) => url.endsWith('/progress/reset-tab'))).toBe(false);
  act(() => view.root.unmount());
});

test('double confirmation keeps one CSRF operation id while the reset is pending', async () => {
  const view = renderWorkshop(); await flush();
  let resolveReset;
  const pending = new Promise(resolve => { resolveReset = resolve; });
  const originalPost = axios.post.getMockImplementation();
  axios.post.mockImplementation((url, ...args) => url.endsWith('/progress/reset-tab') ? pending : originalPost(url, ...args));
  const trigger = [...view.node.querySelectorAll('button')].find(element => element.textContent.trim() === 'Reset tab');
  await act(async () => trigger.click());
  const dialog = document.querySelector('[role="alertdialog"]');
  const confirm = [...dialog.querySelectorAll('button')].find(element => element.textContent.trim() === 'Confirm reset');
  act(() => { confirm.click(); confirm.click(); });
  const calls = axios.post.mock.calls.filter(([url]) => url.endsWith('/progress/reset-tab'));
  expect(calls).toHaveLength(1);
  expect(calls[0][2].headers['x-reset-operation-id']).toMatch(/^[0-9a-f-]{36}$/i);
  expect(dialog.textContent).toContain('Resetting…');
  await act(async () => resolveReset({ data: { success: true } })); await flush();
  expect(document.querySelector('[role="alertdialog"]')).toBeNull();
  act(() => view.root.unmount());
});

test('failed scoped reset survives remount, rejects competing full reset and retries original operation', async () => {
  axios.post.mockRejectedValueOnce(new Error('partial reset'));
  let view = renderWorkshop(); await flush();
  await clickReset(view, 'Reset tab');
  const first = axios.post.mock.calls.find(([url]) => url.endsWith('/progress/reset-tab'));
  const operationId = first[2].headers['x-reset-operation-id'];
  expect(document.querySelector('[role="alertdialog"]')?.textContent).toContain('Retry this same scope.');
  expect(JSON.parse(sessionStorage.getItem('owasp-ai-goat:csrf-reset:7'))).toEqual({scope:'tab:post',operationId});
  act(() => view.root.unmount()); view = renderWorkshop(); await flush();
  const calls = axios.post.mock.calls.length;
  await clickReset(view, 'Reset all');
  expect(axios.post.mock.calls).toHaveLength(calls);
  await clickReset(view, 'Reset tab');
  expect(axios.post.mock.calls.at(-1)[2].headers['x-reset-operation-id']).toBe(operationId);
  expect(sessionStorage.getItem('owasp-ai-goat:csrf-reset:7')).toBeNull();
  act(() => view.root.unmount());
});

test('successful mutation with failed refresh retains operation, completed replay refreshes new canonical progress', async () => {
  const view = renderWorkshop(); await flush();
  const normalGet = axios.get.getMockImplementation(); let failed = false;
  axios.get.mockImplementation(url => {
    if (url === '/api/workshop/csrf/progress' && !failed) { failed = true; return Promise.reject(new Error('refresh unavailable')); }
    return normalGet(url);
  });
  await clickReset(view, 'Reset tab');
  const operationId = JSON.parse(sessionStorage.getItem('owasp-ai-goat:csrf-reset:7')).operationId;
  axios.get.mockImplementation(url => url === '/api/workshop/csrf/progress'
    ? Promise.resolve({data:{objectives:{csrf_p1:{completed:true}}}}) : normalGet(url));
  await clickReset(view, 'Reset tab');
  expect(axios.post.mock.calls.at(-1)[2].headers['x-reset-operation-id']).toBe(operationId);
  expect(sessionStorage.getItem('owasp-ai-goat:csrf-reset:7')).toBeNull();
  expect(view.node.textContent).toContain('1/3');
  act(() => view.root.unmount());
});

test('poison reset clears busy after refresh and preserves pending poison scope over a competing tab reset', async () => {
  const url = '/vulnerabilities/csrf-via-ai?scenario=indirect&objective=csrf_i1';
  axios.post.mockRejectedValueOnce(new Error('lost reset response'));
  let view = renderWorkshop(url); await flush();
  await clickReset(view, 'Reset RAG (clean)');
  const operationId = JSON.parse(sessionStorage.getItem('owasp-ai-goat:csrf-reset:7')).operationId;
  expect([...view.node.querySelectorAll('button')].find(button => button.textContent.trim() === 'Reset RAG (clean)').disabled).toBe(false);
  act(() => view.root.unmount()); view = renderWorkshop(url); await flush();
  const count = axios.post.mock.calls.length; await clickReset(view, 'Reset tab');
  expect(axios.post.mock.calls).toHaveLength(count);
  await clickReset(view, 'Reset RAG (clean)');
  expect(axios.post.mock.calls.at(-1)[2].headers['x-reset-operation-id']).toBe(operationId);
  expect(sessionStorage.getItem('owasp-ai-goat:csrf-reset:7')).toBeNull();
  expect([...view.node.querySelectorAll('button')].find(button => button.textContent.trim() === 'Reset RAG (clean)').disabled).toBe(false);
  act(() => view.root.unmount());
});


test('content controls wait for explicit objective permissions and keep hints independent', async () => {
  let resolveStatus;
  const pendingStatus = new Promise(resolve => { resolveStatus = resolve; });
  const normalGet = axios.get.getMockImplementation();
  axios.get.mockImplementation(url => url === '/api/solutions/csrf-workshop/status'
    ? pendingStatus : normalGet(url));
  const view = renderWorkshop();
  const controls = label => [...view.node.querySelectorAll('button')]
    .filter(button => button.textContent.trim() === label);
  try {
    await flush();
    expect(view.node.textContent).toContain('POST CSRF — Objectives');
    expect(controls('Hint')).toHaveLength(0);
    expect(controls('Solution')).toHaveLength(0);
    await act(async () => resolveStatus({ data: { objectives: {
      csrf_p1: { hint: true, solution: false },
      csrf_p2: { hint: 'true', solution: 1 },
    } } }));
    await flush();
    expect(controls('Hint')).toHaveLength(1);
    expect(controls('Solution')).toHaveLength(0);
  } finally { act(() => view.root.unmount()); }
});

test('unavailable content visibility does not expose teaching content controls', async () => {
  const normalGet = axios.get.getMockImplementation();
  axios.get.mockImplementation(url => url === '/api/solutions/csrf-workshop/status'
    ? Promise.reject(new Error('Controlled unavailable status')) : normalGet(url));
  const view = renderWorkshop();
  try {
    await flush();
    expect(view.node.textContent).toContain('POST CSRF — Objectives');
    const controls = [...view.node.querySelectorAll('button')]
      .filter(button => ['Hint', 'Solution'].includes(button.textContent.trim()));
    expect(controls).toHaveLength(0);
  } finally { act(() => view.root.unmount()); }
});

test('canonical scenario buttons select all four objective groups without query navigation', async () => {
  const view = renderWorkshop('/vulnerabilities/csrf-via-ai');
  try {
    await flush();
    for (const [scenario, title] of [
      ['get', '1. Recon the target'],
      ['post', '1. Forge POST via auto-submit <form>'],
      ['xss', '1. Recon the victim inbox'],
      ['indirect', '1. Poison the RAG (XSS payload)'],
    ]) {
      const button = view.node.querySelector(`[data-scenario-tab="${scenario}"]`);
      expect(button).not.toBeNull();
      await act(async () => button.click());
      await flush();
      expect(button.getAttribute('aria-selected')).toBe('true');
      expect(view.node.querySelectorAll('.obj-content')).toHaveLength(3);
      expect(view.node.querySelector('.obj-name').textContent.trim()).toBe(title);
    }
  } finally { act(() => view.root.unmount()); }
});

test('canonical instructor labels refresh while blank and invalid labels retain familiar fallback',async()=>{labels.csrf_p1='Instructor POST objective';labels.csrf_p2=' ';labels.csrf_p3=42;const view=renderWorkshop();await flush();expect(view.node.querySelectorAll('.obj-name')[0].textContent).toBe('Instructor POST objective');expect(view.node.querySelectorAll('.obj-name')[1].textContent).toContain('Forge POST via fetch');expect(view.node.querySelectorAll('.obj-name')[2].textContent).toContain('Defense blocks');labels.csrf_p1='Revised instructor objective';revision=2;await view.scheduler.runNext();expect(view.node.querySelectorAll('.obj-name')[0].textContent).toBe('Revised instructor objective');act(()=>view.root.unmount());});
test('cached foreign email never replaces authenticated assigned inbox and external editing stays available',async()=>{localStorage.setItem('owasp_ai_goat_email_agent_temp_email','foreign@example.invalid');const normal=axios.get.getMockImplementation();axios.get.mockImplementation(url=>url==='/api/workshop/csrf/email/inbox-address'?Promise.resolve({data:{address:'csrf-7@owasp-ai-goat.invalid'}}):normal(url));const view=renderWorkshop('/vulnerabilities/csrf?tab=xss&objective=csrf_x1');await flush();expect(axios.get).toHaveBeenCalledWith('/api/workshop/csrf/email/inbox-address');const input=view.node.querySelector('input[type="email"]');expect(input.value).toBe('csrf-7@owasp-ai-goat.invalid');expect(input.readOnly).toBe(false);act(()=>view.root.unmount());});
test.each(['failed','empty'])('canonical inbox %s never falls back to cached foreign address; manual editing remains usable',async outcome=>{localStorage.setItem('owasp_ai_goat_email_agent_temp_email','foreign@example.invalid');const normal=axios.get.getMockImplementation();axios.get.mockImplementation(url=>url==='/api/workshop/csrf/email/inbox-address'?(outcome==='failed'?Promise.reject(Error('Unavailable')):Promise.resolve({data:{address:''}})):normal(url));const view=renderWorkshop('/vulnerabilities/csrf?tab=xss&objective=csrf_x1');await flush();const input=view.node.querySelector('input[type="email"]');expect(input.value).toBe('');act(()=>{Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value').set.call(input,'instructor-allowed@example.invalid');input.dispatchEvent(new Event('input',{bubbles:true}));});expect(input.value).toBe('instructor-allowed@example.invalid');expect(localStorage.getItem('owasp_ai_goat_email_agent_temp_email')).toBe('instructor-allowed@example.invalid');act(()=>view.root.unmount());});
