import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import { flushSync } from 'react-dom';
import fs from 'fs';
import path from 'path';
import axios from 'axios';
import { toast } from 'react-toastify';
import SQLWorkshop from './SQLWorkshop';
import NoSQLWorkshop from './NoSQLWorkshop';

let mockRetryResult;
jest.mock('../../components/workshop/JudgeRetryButton', () => props => {
  mockRetryResult = props.onResult;
  return null;
});
let mockUser = { id: 7, username: 'student_7' };
let mockProgressRequest;
let mockConfigRevision;
let mockObjectiveVisibilityByExercise;
const mockPollers = [];
const mountedRoots = [];

globalThis.IS_REACT_ACT_ENVIRONMENT = true;

jest.mock('axios', () => ({ get: jest.fn(), post: jest.fn() }));
jest.mock('react-toastify', () => ({
  toast: { info: jest.fn(), error: jest.fn(), success: jest.fn() },
}));
jest.mock('../../context/AuthContext', () => ({
  useAuth: () => ({ user: mockUser }),
}));
jest.mock('../../context/WorkshopConfigContext', () => ({
  useWorkshopConfig: () => ({
    revision: mockConfigRevision,
    snapshot: {
      exercises: Object.fromEntries(Object.entries(mockObjectiveVisibilityByExercise).map(
        ([exerciseId, objectives]) => [exerciseId, { isVisible: true, objectives }],
      )),
    },
  }),
}));
jest.mock('../../components/VulnerabilityTemplate', () => ({ children }) => <div>{children}</div>);
jest.mock('../../hooks/useWorkshopHeartbeat', () => () => {});
jest.mock('../../hooks/useChangePolling', () => (reconcile) => { mockPollers.push(reconcile); });

const LABS = [
  {
    name: 'SQL',
    Component: SQLWorkshop,
    baseKey: 'sqli_workshop_completed',
    objectiveId: 'sqli_1',
    objectiveIds: Array.from({ length: 10 }, (_, index) => `sqli_${index + 1}`),
    exerciseId: 'sql_injection_workshop',
    objectiveName: 'Trigger SQL Syntax Error',
    chatChip: 'List my orders',
    resetTitle: 'Reset chat, cart & progress',
    sourceFile: 'SQLWorkshop.js',
  },
  {
    name: 'NoSQL',
    Component: NoSQLWorkshop,
    baseKey: 'nosqli_workshop_completed',
    objectiveId: 'nosqli_1',
    objectiveIds: Array.from({ length: 10 }, (_, index) => `nosqli_${index + 1}`),
    exerciseId: 'nosql_injection_workshop',
    objectiveName: 'Trigger NoSQL Error',
    chatChip: 'Show trending topics',
    resetTitle: 'Reset chat, reading list & progress',
    sourceFile: 'NoSQLWorkshop.js',
  },
];

const scopedKey = (baseKey, userId) => `${baseKey}:user:${userId}`;

async function flush() {
  await act(async () => {
    await Promise.resolve();
    await Promise.resolve();
    await Promise.resolve();
  });
}

async function renderLab(Component) {
  const node = document.createElement('div');
  document.body.appendChild(node);
  const root = createRoot(node);
  mountedRoots.push({ root, node });
  await act(async () => { root.render(<Component />); });
  await flush();
  return { root, node };
}

function completedProgress(objectiveId) {
  return { data: { objectives: { [objectiveId]: { completed: true } } } };
}

function deferred() {
  let resolve;
  let reject;
  const promise = new Promise((resolvePromise, rejectPromise) => {
    resolve = resolvePromise;
    reject = rejectPromise;
  });
  return { promise, resolve, reject };
}

function findButton(node, text) {
  const label = text === 'View Solution' ? 'Solution' : text;
  return [...node.querySelectorAll('button')].find(button => button.textContent.includes(label));
}

async function confirmDestructiveReset(node, label) {
  await act(async () => { findButton(node, label).click(); });
  const dialog = document.querySelector('[role="alertdialog"]');
  expect(dialog).not.toBeNull();
  const confirm = [...dialog.querySelectorAll('button')].find(button => button.textContent === 'Confirm reset');
  expect(confirm).toBeDefined();
  act(() => confirm.click());
  await flush();
}

function setTextareaValue(textarea, value) {
  const valueSetter = Object.getOwnPropertyDescriptor(
    window.HTMLTextAreaElement.prototype,
    'value',
  ).set;
  valueSetter.call(textarea, value);
  textarea.dispatchEvent(new Event('input', { bubbles: true }));
}

beforeEach(() => {
  mockUser = { id: 7, username: 'student_7' };
  mockConfigRevision = 1;
  mockObjectiveVisibilityByExercise = Object.fromEntries(LABS.map(lab => [
    lab.exerciseId,
    Object.fromEntries(lab.objectiveIds.map(id => [id, { isVisible: true }])),
  ]));
  mockPollers.length = 0;
  localStorage.clear();
  axios.get.mockReset();
  axios.post.mockReset();
  axios.post.mockResolvedValue({ data: { success: true } });
  mockProgressRequest = () => Promise.reject(Object.assign(new Error('offline'), { code: 'ERR_NETWORK' }));
  axios.get.mockImplementation((url) => {
    if (url.endsWith('/progress')) return mockProgressRequest(url);
    if (url.endsWith('/mode')) return Promise.resolve({ data: { mode: 'fixed' } });
    if (url.endsWith('/llm-status')) return Promise.resolve({ data: { available: false } });
    if (url.endsWith('/status')) return Promise.resolve({ data: { objectives: {} } });
    return Promise.resolve({ data: {} });
  });
});

afterEach(() => {
  while (mountedRoots.length) {
    const { root, node } = mountedRoots.pop();
    act(() => root.unmount());
    node.remove();
  }
  jest.restoreAllMocks();
});

describe.each(LABS)('$name progress cache isolation', (lab) => {
  test('destructive reset requires confirmation, fences duplicate confirms, and permits retry after failure', async () => {
    const activeKey = scopedKey(lab.baseKey, 7);
    localStorage.setItem(activeKey, JSON.stringify([lab.objectiveId]));
    const firstReset = deferred();
    let attempts = 0;
    axios.post.mockImplementation(url => {
      if (url.endsWith('/reset')) {
        attempts += 1;
        return attempts === 1 ? firstReset.promise : Promise.resolve({ data: { success: true } });
      }
      return Promise.resolve({ data: { success: true } });
    });
    const { node } = await renderLab(lab.Component);

    await act(async () => { findButton(node, lab.resetTitle).click(); });
    let dialog = document.querySelector('[role="alertdialog"]');
    expect(dialog.textContent).toContain(lab.resetTitle);
    expect(attempts).toBe(0);
    expect(localStorage.getItem(activeKey)).not.toBeNull();

    await act(async () => { [...dialog.querySelectorAll('button')].find(button => button.textContent === 'Cancel').click(); });
    expect(attempts).toBe(0);
    await act(async () => { findButton(node, lab.resetTitle).click(); });
    dialog = document.querySelector('[role="alertdialog"]');
    const confirm = [...dialog.querySelectorAll('button')].find(button => button.textContent === 'Confirm reset');
    act(() => { confirm.click(); confirm.click(); });
    expect(attempts).toBe(1);
    expect(localStorage.getItem(activeKey)).not.toBeNull();
    expect(dialog.querySelector('button:not(:disabled)')).toBeNull();

    await act(async () => { firstReset.reject(new Error('controlled reset failure')); });
    expect(dialog.textContent).toContain('controlled reset failure');
    expect(localStorage.getItem(activeKey)).not.toBeNull();
    await act(async () => { [...dialog.querySelectorAll('button')].find(button => button.textContent === 'Confirm reset').click(); });
    expect(attempts).toBe(2);
    expect(localStorage.getItem(activeKey)).toBeNull();
    expect(document.querySelector('[role="alertdialog"]')).toBeNull();
  });

  test.each([false, true])('shared solution keeps all examples and honors the independent hint gate (%s)', async (hintVisible) => {
    axios.get.mockImplementation((url) => {
      if (url.endsWith('/progress')) return Promise.resolve({ data: { objectives: {} } });
      if (url.endsWith('/mode')) return Promise.resolve({ data: { mode: 'fixed' } });
      if (url.endsWith('/llm-status')) return Promise.resolve({ data: { available: false } });
      if (url.startsWith('/api/hints/') && url.endsWith('/status')) {
        return Promise.resolve({ data: { objectives: { [lab.objectiveId]: hintVisible } } });
      }
      if (url.endsWith('/status')) return Promise.resolve({ data: { objectives: { [lab.objectiveId]: true } } });
      if (url.endsWith(`/${lab.objectiveId}`)) return Promise.resolve({ data: { solution: {
        title: 'Instructor solution', hints: ['Authorized progressive hint'],
        examples: ['first payload', { prompt: 'second payload', note: 'Second explanation' }],
        approach: 'Instructor approach', tips: ['Instructor tip'],
      } } });
      return Promise.resolve({ data: {} });
    });
    const { node } = await renderLab(lab.Component);
    await act(async () => { findButton(node, 'View Solution').click(); });
    await flush();
    let modal = document.querySelector('[data-testid="objective-help-modal"]');
    expect(modal?.dataset.helpKind).toBe('solution');
    expect(modal.textContent).toContain('Instructor solution');
    expect(modal.textContent).toContain('Instructor approach');
    expect(modal.textContent).toContain('Instructor tip');
    expect(modal.textContent.includes('Authorized progressive hint')).toBe(hintVisible);
    expect([...modal.querySelectorAll('[data-testid="solution-example"]')]).toHaveLength(2);
    expect(modal.textContent).toContain('Second explanation');

    await act(async () => { modal.querySelector('[data-testid="solution-example"] button').click(); });
    expect(node.querySelector('textarea').value).toBe('first payload');
    expect(document.querySelector('[data-testid="objective-help-modal"]')).toBeNull();

    await act(async () => { findButton(node, 'View Solution').click(); });
    await flush();
    modal = document.querySelector('[data-testid="objective-help-modal"]');
    await act(async () => { modal.querySelectorAll('[data-testid="solution-example"] button')[1].click(); });
    expect(node.querySelector('textarea').value).toBe('second payload');
  });

  test('instructor metadata replaces the objective copy and an empty description keeps authored copy', async () => {
    const configured = mockObjectiveVisibilityByExercise[lab.exerciseId][lab.objectiveId];
    configured.label = 'Instructor objective';
    configured.description = 'Instructor context for this objective';

    const { root, node } = await renderLab(lab.Component);
    const objectiveCopy = () => [...node.querySelectorAll('.obj-content')]
      .find(element => element.querySelector('.obj-name')?.textContent === 'Instructor objective');
    expect(objectiveCopy()?.querySelector('.obj-technique')?.textContent)
      .toBe('Instructor context for this objective');
    expect(node.textContent).toContain('0 of 10 objectives completed');

    configured.description = '  ';
    mockConfigRevision = 2;
    await act(async () => { root.render(<lab.Component />); });
    expect(objectiveCopy()?.querySelector('.obj-technique')?.textContent).toBe('Error-Based');
  });

  test('an admin-hidden objective neither renders nor counts after refresh', async () => {
    mockObjectiveVisibilityByExercise[lab.exerciseId][lab.objectiveId].isVisible = false;
    mockProgressRequest = () => Promise.resolve(completedProgress(lab.objectiveId));

    const { node } = await renderLab(lab.Component);

    expect(node.textContent).not.toContain(lab.objectiveName);
    expect(node.textContent).toContain('0 of 9 objectives completed');
  });

  test('a revised snapshot hides an objective and closes its open solution', async () => {
    axios.get.mockImplementation((url) => {
      if (url.endsWith('/progress')) return Promise.resolve({ data: { objectives: {} } });
      if (url.endsWith('/mode')) return Promise.resolve({ data: { mode: 'fixed' } });
      if (url.endsWith('/llm-status')) return Promise.resolve({ data: { available: false } });
      if (url.endsWith('/status')) return Promise.resolve({ data: { objectives: { [lab.objectiveId]: true } } });
      if (url.endsWith(`/${lab.objectiveId}`)) {
        return Promise.resolve({ data: { solution: { title: 'Current objective solution', hints: [], examples: [] } } });
      }
      return Promise.resolve({ data: {} });
    });
    const { root, node } = await renderLab(lab.Component);
    const viewSolution = findButton(node, 'View Solution');
    await act(async () => { viewSolution.dispatchEvent(new MouseEvent('click', { bubbles: true })); });
    await flush();
    expect(document.body.textContent).toContain('Current objective solution');

    mockObjectiveVisibilityByExercise[lab.exerciseId][lab.objectiveId].isVisible = false;
    mockConfigRevision = 2;
    await act(async () => { root.render(<lab.Component />); });
    await flush();

    expect(node.textContent).not.toContain(lab.objectiveName);
    expect(document.body.textContent).not.toContain('Current objective solution');
  });

  test('an all-hidden snapshot renders neutral zero progress', async () => {
    for (const objective of Object.values(mockObjectiveVisibilityByExercise[lab.exerciseId])) {
      objective.isVisible = false;
    }

    const { node } = await renderLab(lab.Component);

    expect(node.textContent).toContain('0 of 0 objectives completed');
    expect(node.textContent).not.toContain('All objectives completed!');
    expect(node.innerHTML).not.toContain('NaN');
  });

  test('failure fallback ignores another user and the legacy global key', async () => {
    localStorage.setItem(scopedKey(lab.baseKey, 7), JSON.stringify([lab.objectiveId]));
    localStorage.setItem(lab.baseKey, JSON.stringify([lab.objectiveId]));
    mockUser = { id: 8, username: 'student_8' };

    const { node } = await renderLab(lab.Component);

    expect(node.textContent).toContain('0 of 10 objectives completed');
  });

  test('failure fallback restores only the authenticated user scoped cache', async () => {
    localStorage.setItem(scopedKey(lab.baseKey, 7), JSON.stringify([lab.objectiveId]));

    const { node } = await renderLab(lab.Component);

    expect(node.textContent).toContain('1 of 10 objectives completed');
  });

  test('successful empty server progress clears state and overwrites the active cache', async () => {
    const activeKey = scopedKey(lab.baseKey, 7);
    localStorage.setItem(activeKey, JSON.stringify([lab.objectiveId]));
    mockProgressRequest = () => Promise.resolve({ data: { objectives: {} } });

    const { node } = await renderLab(lab.Component);

    expect(node.textContent).toContain('0 of 10 objectives completed');
    expect(localStorage.getItem(activeKey)).toBe('[]');
  });

  test('an authenticated identity switch clears prior state when the new fallback is absent', async () => {
    mockProgressRequest = () => Promise.resolve(completedProgress(lab.objectiveId));
    const { root, node } = await renderLab(lab.Component);
    expect(node.textContent).toContain('1 of 10 objectives completed');

    mockUser = { id: 8, username: 'student_8' };
    mockProgressRequest = () => Promise.reject(Object.assign(new Error('offline'), { code: 'ERR_NETWORK' }));
    await act(async () => { root.render(<lab.Component />); });
    await flush();

    expect(node.textContent).toContain('0 of 10 objectives completed');
  });

  test('the first render for a new identity never exposes the prior identity completion state', async () => {
    mockProgressRequest = () => Promise.resolve(completedProgress(lab.objectiveId));
    const { root, node } = await renderLab(lab.Component);

    mockUser = { id: 8, username: 'student_8' };
    mockProgressRequest = () => Promise.reject(Object.assign(new Error('offline'), { code: 'ERR_NETWORK' }));
    globalThis.IS_REACT_ACT_ENVIRONMENT = false;
    try {
      flushSync(() => { root.render(<lab.Component />); });
    } finally {
      globalThis.IS_REACT_ACT_ENVIRONMENT = true;
    }

    expect(node.textContent).toContain('0 of 10 objectives completed');

    await flush();
  });

  test('a stale mount progress response cannot update the new identity state or cache', async () => {
    const oldProgress = deferred();
    mockProgressRequest = () => oldProgress.promise;
    const { root, node } = await renderLab(lab.Component);

    mockUser = { id: 8, username: 'student_8' };
    mockProgressRequest = () => Promise.reject(Object.assign(new Error('offline'), { code: 'ERR_NETWORK' }));
    await act(async () => { root.render(<lab.Component />); });
    await flush();

    await act(async () => { oldProgress.resolve(completedProgress(lab.objectiveId)); });
    await flush();

    expect(node.textContent).toContain('0 of 10 objectives completed');
    expect(localStorage.getItem(scopedKey(lab.baseKey, 8))).toBeNull();
  });

  test('a stale poll response cannot replace the new identity fallback or cache', async () => {
    const { root, node } = await renderLab(lab.Component);
    const oldPollProgress = deferred();
    mockProgressRequest = () => oldPollProgress.promise;
    const poll = mockPollers[mockPollers.length - 1];
    let pollPromise;
    await act(async () => { pollPromise = poll(); });

    const newIdentityKey = scopedKey(lab.baseKey, 8);
    localStorage.setItem(newIdentityKey, JSON.stringify([lab.objectiveId]));
    mockUser = { id: 8, username: 'student_8' };
    mockProgressRequest = () => Promise.reject(Object.assign(new Error('offline'), { code: 'ERR_NETWORK' }));
    await act(async () => { root.render(<lab.Component />); });
    await flush();
    expect(node.textContent).toContain('1 of 10 objectives completed');

    await act(async () => {
      oldPollProgress.resolve({ data: { objectives: {} } });
      await pollPromise.catch(() => {});
    });
    await flush();

    expect(node.textContent).toContain('1 of 10 objectives completed');
    expect(localStorage.getItem(newIdentityKey)).toBe(JSON.stringify([lab.objectiveId]));
  });

  test('a stale reset completion cannot clear the new identity fallback state', async () => {
    const oldReset = deferred();
    axios.post.mockImplementation((url) => (
      url.endsWith('/reset') ? oldReset.promise : Promise.resolve({ data: { success: true } })
    ));
    const { root, node } = await renderLab(lab.Component);
    const reset = findButton(node, lab.resetTitle);
    await confirmDestructiveReset(node, lab.resetTitle);

    const newIdentityKey = scopedKey(lab.baseKey, 8);
    localStorage.setItem(newIdentityKey, JSON.stringify([lab.objectiveId]));
    mockUser = { id: 8, username: 'student_8' };
    await act(async () => { root.render(<lab.Component />); });
    await flush();
    expect(node.textContent).toContain('1 of 10 objectives completed');

    await act(async () => { oldReset.resolve({ data: { success: true } }); });
    await flush();

    expect(node.textContent).toContain('1 of 10 objectives completed');
    expect(localStorage.getItem(newIdentityKey)).toBe(JSON.stringify([lab.objectiveId]));
  });

  test('a stale chat completion cannot update or synchronize progress for the new identity', async () => {
    const oldChat = deferred();
    axios.post.mockImplementation((url) => (
      url.endsWith('/chat') ? oldChat.promise : Promise.resolve({ data: { success: true } })
    ));
    const { root, node } = await renderLab(lab.Component);
    const chatChip = findButton(node, lab.chatChip);
    expect(chatChip).toBeDefined();
    await act(async () => { chatChip.dispatchEvent(new MouseEvent('click', { bubbles: true })); });

    mockUser = { id: 8, username: 'student_8' };
    await act(async () => { root.render(<lab.Component />); });
    await flush();

    await act(async () => {
      oldChat.resolve({
        data: { success: true, response: 'done', completedObjectives: [lab.objectiveId] },
      });
    });
    await flush();

    expect(node.textContent).toContain('0 of 10 objectives completed');
    expect(localStorage.getItem(scopedKey(lab.baseKey, 8))).toBeNull();
    expect(axios.post.mock.calls.filter(([url]) => url.endsWith('/progress/complete'))).toHaveLength(0);
  });

  test('a rejected old-identity chat cannot add an error or mutate loading after a switch', async () => {
    const oldChat = deferred();
    axios.post.mockImplementation((url) => (
      url.endsWith('/chat') ? oldChat.promise : Promise.resolve({ data: { success: true } })
    ));
    const { root, node } = await renderLab(lab.Component);
    const chatChip = findButton(node, lab.chatChip);
    await act(async () => { chatChip.dispatchEvent(new MouseEvent('click', { bubbles: true })); });

    mockUser = { id: 8, username: 'student_8' };
    await act(async () => { root.render(<lab.Component />); });
    await flush();
    const loadingBeforeRejection = node.querySelector('textarea').disabled;

    await act(async () => { oldChat.reject(new Error('old identity offline')); });
    await flush();

    expect(node.textContent).not.toContain('Connection error. Please try again.');
    expect(node.querySelector('textarea').disabled).toBe(loadingBeforeRejection);
  });

  test('a completed chat and draft are absent on the new identity first render', async () => {
    axios.post.mockImplementation((url) => {
      if (url.endsWith('/chat')) {
        return Promise.resolve({
          data: {
            success: true,
            response: mockUser.id === 7
              ? 'Attendee A private response'
              : 'Attendee B first response',
            completedObjectives: [],
          },
        });
      }
      return Promise.resolve({ data: { success: true } });
    });
    const { root, node } = await renderLab(lab.Component);
    const textarea = node.querySelector('textarea');
    await act(async () => {
      setTextareaValue(textarea, 'Attendee A private prompt');
    });
    await act(async () => {
      textarea.dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter', bubbles: true }));
    });
    await flush();
    expect(node.textContent).toContain('Attendee A private prompt');
    expect(node.textContent).toContain('Attendee A private response');

    await act(async () => {
      setTextareaValue(node.querySelector('textarea'), 'Attendee A unfinished draft');
    });
    expect(node.querySelector('textarea').value).toBe('Attendee A unfinished draft');

    mockUser = { id: 8, username: 'student_8' };
    globalThis.IS_REACT_ACT_ENVIRONMENT = false;
    try {
      flushSync(() => { root.render(<lab.Component />); });
    } finally {
      globalThis.IS_REACT_ACT_ENVIRONMENT = true;
    }

    expect(node.textContent).not.toContain('Attendee A private prompt');
    expect(node.textContent).not.toContain('Attendee A private response');
    expect(node.querySelector('textarea').value).toBe('');

    await flush();

    await act(async () => {
      setTextareaValue(node.querySelector('textarea'), 'Attendee B first prompt');
    });
    await act(async () => {
      node.querySelector('textarea').dispatchEvent(
        new KeyboardEvent('keydown', { key: 'Enter', bubbles: true }),
      );
    });
    await flush();

    expect([...node.querySelectorAll('[data-message-id]')].map(message => ({
      id: message.getAttribute('data-message-id'),
      text: message.textContent,
    }))).toEqual([
      expect.objectContaining({ id: '1', text: expect.stringContaining('Attendee B first prompt') }),
      expect.objectContaining({ id: '2', text: expect.stringContaining('Attendee B first response') }),
    ]);
  });

  test('a cache write failure cannot turn successful server progress into fallback', async () => {
    mockProgressRequest = () => Promise.resolve(completedProgress(lab.objectiveId));
    const getItem = jest.spyOn(Storage.prototype, 'getItem');
    jest.spyOn(Storage.prototype, 'setItem').mockImplementation(() => {
      throw new DOMException('Storage quota unavailable', 'QuotaExceededError');
    });

    const { node } = await renderLab(lab.Component);

    expect(node.textContent).toContain('1 of 10 objectives completed');
    // Session identity reads are allowed; successful progress must never read fallback cache.
    expect(getItem.mock.calls.every(([key]) => key === 'token')).toBe(true);

    mockProgressRequest = () => Promise.resolve({ data: { objectives: {} } });
    const poll = mockPollers[mockPollers.length - 1];
    await act(async () => { await poll(); });
    expect(node.textContent).toContain('0 of 10 objectives completed');
  });

  test('cache write failure cannot interrupt a completion already persisted by the chat endpoint', async () => {
    jest.spyOn(Storage.prototype, 'setItem').mockImplementation(() => {
      throw new DOMException('Storage quota unavailable', 'QuotaExceededError');
    });
    axios.post.mockImplementation((url) => {
      if (url.endsWith('/chat')) {
        return Promise.resolve({
          data: { success: true, response: 'done', completedObjectives: [lab.objectiveId] },
        });
      }
      return Promise.resolve({ data: { success: true } });
    });
    const { node } = await renderLab(lab.Component);

    const chatChip = findButton(node, lab.chatChip);
    await act(async () => { chatChip.dispatchEvent(new MouseEvent('click', { bubbles: true })); });
    await flush();

    expect(node.textContent).toContain('1 of 10 objectives completed');
    expect(axios.post.mock.calls.filter(([url]) => url.endsWith('/progress/complete'))).toHaveLength(0);
  });

  test('an unavailable judgment is escaped, shown as feedback, and does not grant credit', async () => {
    axios.post.mockImplementation((url) => {
      if (url.endsWith('/chat')) {
        return Promise.resolve({
          data: {
            success: true,
            response: 'The tool request was processed.',
            completedObjectives: [],
            judgments: [{
              objectiveId: lab.objectiveId,
              verdict: 'unavailable',
              explanation: '<img src=x onerror="window.__judgeInjected=true"> Please retry.',
            }],
          },
        });
      }
      return Promise.resolve({ data: { success: true } });
    });
    const { node } = await renderLab(lab.Component);

    const chatChip = findButton(node, lab.chatChip);
    await act(async () => { chatChip.dispatchEvent(new MouseEvent('click', { bubbles: true })); });
    await flush();

    expect(node.textContent).toContain(`${lab.objectiveName}: evaluation unavailable.`);
    expect(node.textContent).toContain('<img src=x onerror="window.__judgeInjected=true">');
    expect(node.querySelector('[role="alert"]')).not.toBeNull();
    expect(node.querySelector('img[src="x"]')).toBeNull();
    expect(node.textContent).toContain('0 of 10 objectives completed');
    expect(axios.post.mock.calls.filter(([url]) => url.endsWith('/progress/complete'))).toHaveLength(0);
  });

  test('rapid A to B to A rendering cannot rematch an earlier A generation', async () => {
    mockProgressRequest = () => Promise.resolve(completedProgress(lab.objectiveId));
    const { root, node } = await renderLab(lab.Component);
    expect(node.textContent).toContain('1 of 10 objectives completed');

    axios.get.mockImplementation(() => new Promise(() => {}));
    globalThis.IS_REACT_ACT_ENVIRONMENT = false;
    try {
      mockUser = { id: 8, username: 'student_8' };
      flushSync(() => { root.render(<lab.Component />); });
      expect(node.textContent).toContain('0 of 10 objectives completed');

      mockUser = { id: 7, username: 'student_7' };
      flushSync(() => { root.render(<lab.Component />); });
      expect(node.textContent).toContain('0 of 10 objectives completed');
    } finally {
      globalThis.IS_REACT_ACT_ENVIRONMENT = true;
    }
  });

  test('fallback filters duplicate, unknown, and non-string objective identifiers', async () => {
    localStorage.setItem(scopedKey(lab.baseKey, 7), JSON.stringify([
      lab.objectiveId,
      lab.objectiveId,
      'unknown_objective',
      null,
      { id: lab.objectiveId },
    ]));

    const { node } = await renderLab(lab.Component);

    expect(node.textContent).toContain('1 of 10 objectives completed');
  });

  test('a deferred old-identity solution cannot open after an identity switch', async () => {
    const oldSolution = deferred();
    axios.get.mockImplementation((url) => {
      if (url.endsWith('/progress')) return mockProgressRequest(url);
      if (url.endsWith('/mode')) return Promise.resolve({ data: { mode: 'fixed' } });
      if (url.endsWith('/llm-status')) return Promise.resolve({ data: { available: false } });
      if (url.endsWith('/status')) {
        return Promise.resolve({ data: { objectives: { [lab.objectiveId]: true } } });
      }
      if (url.endsWith(`/${lab.objectiveId}`)) return oldSolution.promise;
      return Promise.resolve({ data: {} });
    });
    const { root, node } = await renderLab(lab.Component);
    const viewSolution = findButton(node, 'View Solution');
    expect(viewSolution).toBeDefined();

    await act(async () => {
      viewSolution.dispatchEvent(new MouseEvent('click', { bubbles: true }));
    });
    mockUser = { id: 8, username: 'student_8' };
    await act(async () => { root.render(<lab.Component />); });
    await flush();

    await act(async () => {
      oldSolution.resolve({
        data: { solution: { title: 'Old identity solution', hints: [], examples: [] } },
      });
    });
    await flush();

    expect(document.body.textContent).not.toContain('Old identity solution');
  });

  test('an already-open solution closes on an identity switch', async () => {
    axios.get.mockImplementation((url) => {
      if (url.endsWith('/progress')) return mockProgressRequest(url);
      if (url.endsWith('/mode')) return Promise.resolve({ data: { mode: 'fixed' } });
      if (url.endsWith('/llm-status')) return Promise.resolve({ data: { available: false } });
      if (url.endsWith('/status')) {
        return Promise.resolve({ data: { objectives: { [lab.objectiveId]: true } } });
      }
      if (url.endsWith(`/${lab.objectiveId}`)) {
        return Promise.resolve({
          data: { solution: { title: 'User A solution', hints: [], examples: [] } },
        });
      }
      return Promise.resolve({ data: {} });
    });
    const { root, node } = await renderLab(lab.Component);
    const viewSolution = findButton(node, 'View Solution');
    expect(viewSolution).toBeDefined();
    await act(async () => {
      viewSolution.dispatchEvent(new MouseEvent('click', { bubbles: true }));
    });
    await flush();
    expect(document.body.textContent).toContain('User A solution');

    mockUser = { id: 8, username: 'student_8' };
    await act(async () => { root.render(<lab.Component />); });

    expect(document.body.textContent).not.toContain('User A solution');
  });

  test('reset removes only the active user cache', async () => {
    const activeKey = scopedKey(lab.baseKey, 7);
    const otherKey = scopedKey(lab.baseKey, 8);
    localStorage.setItem(activeKey, JSON.stringify([lab.objectiveId]));
    localStorage.setItem(otherKey, JSON.stringify([lab.objectiveId]));
    localStorage.setItem(lab.baseKey, JSON.stringify([lab.objectiveId]));
    const { node } = await renderLab(lab.Component);

    const reset = findButton(node, lab.resetTitle);
    expect(reset).not.toBeNull();
    await confirmDestructiveReset(node, lab.resetTitle);
    await flush();

    expect(localStorage.getItem(activeKey)).toBeNull();
    expect(localStorage.getItem(otherKey)).toBe(JSON.stringify([lab.objectiveId]));
    expect(localStorage.getItem(lab.baseKey)).toBe(JSON.stringify([lab.objectiveId]));
  });

  test('every cache read, write, and removal uses the derived scoped key', () => {
    const source = fs.readFileSync(path.join(__dirname, lab.sourceFile), 'utf8');
    expect(source).not.toMatch(/localStorage\.(?:getItem|setItem|removeItem)\(LS_KEY_COMPLETED/);
    // Mount, polling, accepted chat results, and Judge retry reconciliation all
    // write through the same owner-scoped cache key.
    expect(source.match(/writeCompletedCache\(completedCacheKey/g)).toHaveLength(4);
    expect(source.match(/localStorage\.setItem\(cacheKey/g)).toHaveLength(1);
    expect(source.match(/localStorage\.getItem\(completedCacheKey/g)).toHaveLength(1);
    expect(source.match(/removeCompletedCache\(completedCacheKey/g)).toHaveLength(1);
    expect(source.match(/localStorage\.removeItem\(cacheKey/g)).toHaveLength(1);
  });
});

describe.each(LABS)('$name canonical independent hints', lab => {
  function configure({ hint = true, solution = false, content } = {}) {
    axios.get.mockImplementation(url => {
      if (url.startsWith('/api/hints/') && url.endsWith('/status')) return Promise.resolve({ data: { objectives: { [lab.objectiveId]: hint } } });
      if (url.startsWith('/api/hints/')) return content || Promise.resolve({ data: { hint: { title: 'Canonical hint', hints: ['Owned independent hint'] } } });
      if (url.includes('/solutions/') && url.endsWith('/status')) return Promise.resolve({ data: { objectives: { [lab.objectiveId]: solution } } });
      if (url.endsWith('/progress')) return Promise.resolve({ data: { objectives: {} } });
      if (url.endsWith('/mode')) return Promise.resolve({ data: { mode: 'fixed' } });
      return Promise.resolve({ data: {} });
    });
  }
  test('effective master/objective hint gates vary independently of solution gates', async () => {
    configure(); const { node } = await renderLab(lab.Component);
    for (const [hint, solution] of [[true,false],[false,true],[false,false],[true,true]]) {
      configure({ hint, solution });
      await act(async () => { await mockPollers.at(-1)(); });
      expect(Boolean(findButton(node, 'Hint'))).toBe(hint);
      expect(Boolean(findButton(node, 'View Solution'))).toBe(solution);
    }
    await act(async () => { findButton(node,'Hint').click(); }); await flush();
    expect(document.body.textContent).toContain('Owned independent hint');
    expect(axios.get).toHaveBeenCalledWith(`/api/hints/${lab.exerciseId}/${lab.objectiveId}`);
    configure({hint:false,solution:true});
    await act(async () => { await mockPollers.at(-1)(); });
    expect(document.body.textContent).not.toContain('Owned independent hint');
  });
  test.each(['reset','session','hidden'])('late hint response cannot reopen after %s', async boundary => {
    const pending=deferred(); configure({content:pending.promise});
    const {root,node}=await renderLab(lab.Component);
    await act(async()=>{findButton(node,'Hint').click();});
    if(boundary==='reset') await confirmDestructiveReset(node, lab.resetTitle);
    if(boundary==='session'){localStorage.setItem('token','replacement-session');await act(async()=>{root.render(<lab.Component/>);});}
    if(boundary==='hidden'){mockObjectiveVisibilityByExercise[lab.exerciseId][lab.objectiveId].isVisible=false;mockConfigRevision++;await act(async()=>{root.render(<lab.Component/>);});}
    await act(async()=>pending.resolve({data:{hint:{title:'Late private hint',hints:['Must not appear']}}}));await flush();
    expect(document.body.textContent).not.toContain('Late private hint');
    expect(document.body.textContent).not.toContain('Must not appear');
  });
});

describe('NOVA pending chat reset lifecycle', () => {
  async function send(node) {
    act(() => setTextareaValue(node.querySelector('textarea'), 'Controlled research request'));
    act(() => node.querySelector('textarea').dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter', bubbles: true, cancelable: true })));
    await flush();
  }
  test('late completion cannot restore reset transcript or progress cache', async () => {
    const { node } = await renderLab(NoSQLWorkshop);
    const pending = deferred(); axios.post.mockReturnValueOnce(pending.promise); await send(node);
    await confirmDestructiveReset(node, 'Reset chat, reading list & progress');
    pending.resolve({ data: { success: true, response: 'Obsolete completed response', completedObjectives: ['nosqli_1'] } }); await flush();
    expect(node.textContent).not.toContain('Obsolete completed response');
    expect(localStorage.getItem(scopedKey('nosqli_workshop_completed', 7))).toBeNull();
  });
  test('failed reset preserves prior transcript/progress but retires pending chat', async () => {
    const { node } = await renderLab(NoSQLWorkshop);
    axios.post.mockResolvedValueOnce({ data: { success: true, response: 'Prior current response', completedObjectives: ['nosqli_1'] } }); await send(node);
    const priorCache = localStorage.getItem(scopedKey('nosqli_workshop_completed', 7));
    const pending = deferred(); axios.post.mockReturnValueOnce(pending.promise); await send(node);
    axios.post.mockRejectedValueOnce(new Error('controlled failure'));
    await confirmDestructiveReset(node, 'Reset chat, reading list & progress');
    pending.reject(new Error('obsolete chat error')); await flush();
    expect(node.textContent).toContain('Prior current response');
    expect(node.textContent).not.toContain('Connection error. Please try again.');
    expect(localStorage.getItem(scopedKey('nosqli_workshop_completed', 7))).toBe(priorCache);
    expect(toast.error).toHaveBeenCalledWith('Failed to reset');
    axios.post.mockResolvedValueOnce({ data: { success: true, response: 'New current response' } }); await send(node);
    expect(node.textContent).toContain('New current response');
  });
  test('unmount suppresses late completion cache, events and notices', async () => {
    const { node, root } = await renderLab(NoSQLWorkshop);
    const pending = deferred(); axios.post.mockReturnValueOnce(pending.promise); await send(node);
    const call = axios.post.mock.calls.find(([url]) => url.endsWith('/chat'));
    act(() => root.unmount()); mountedRoots.pop(); node.remove();
    expect(call[2].signal.aborted).toBe(true);
    toast.success.mockClear(); const events = jest.spyOn(window, 'dispatchEvent');
    pending.resolve({ data: { success: true, response: 'Late', completedObjectives: ['nosqli_1'] } }); await flush();
    expect(localStorage.getItem(scopedKey('nosqli_workshop_completed', 7))).toBeNull();
    expect(toast.success).not.toHaveBeenCalled();
    expect(events.mock.calls.filter(([event]) => event.type === 'objectiveCompleted')).toHaveLength(0);
  });
  test('StrictMode still admits current chat after reset', async () => {
    const StrictNOVA = () => <React.StrictMode><NoSQLWorkshop /></React.StrictMode>;
    const { node } = await renderLab(StrictNOVA);
    await confirmDestructiveReset(node, 'Reset chat, reading list & progress');
    axios.post.mockResolvedValueOnce({ data: { success: true, response: 'Fresh response', completedObjectives: ['nosqli_1'] } }); await send(node);
    expect(node.textContent).toContain('Fresh response');
    expect(JSON.parse(localStorage.getItem(scopedKey('nosqli_workshop_completed', 7)))).toContain('nosqli_1');
  });

});

test('ARIA late chat completion cannot restore reset transcript or progress cache', async () => {
  const { node } = await renderLab(SQLWorkshop);
  const pending = deferred(); axios.post.mockReturnValueOnce(pending.promise);
  act(() => setTextareaValue(node.querySelector('textarea'), 'Controlled order request'));
  act(() => node.querySelector('textarea').dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter', bubbles: true, cancelable: true })));
  await flush();
  await confirmDestructiveReset(node, 'Reset chat, cart & progress');
  pending.resolve({ data: { success: true, response: 'Obsolete ARIA completed response', completedObjectives: ['sqli_1'] } }); await flush();
  expect(node.textContent).not.toContain('Obsolete ARIA completed response');
  expect(localStorage.getItem(scopedKey('sqli_workshop_completed', 7))).toBeNull();
});

describe('ARIA pending chat reset lifecycle', () => {
  async function send(node) {
    act(() => setTextareaValue(node.querySelector('textarea'), 'Controlled research request'));
    act(() => node.querySelector('textarea').dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter', bubbles: true, cancelable: true })));
    await flush();
  }
  test('late completion cannot restore reset transcript or progress cache', async () => {
    const { node } = await renderLab(SQLWorkshop);
    const pending = deferred(); axios.post.mockReturnValueOnce(pending.promise); await send(node);
    await confirmDestructiveReset(node, 'Reset chat, cart & progress');
    pending.resolve({ data: { success: true, response: 'Obsolete completed response', completedObjectives: ['sqli_1'] } }); await flush();
    expect(node.textContent).not.toContain('Obsolete completed response');
    expect(localStorage.getItem(scopedKey('sqli_workshop_completed', 7))).toBeNull();
  });
  test('failed reset preserves prior transcript/progress but retires pending chat', async () => {
    const { node } = await renderLab(SQLWorkshop);
    axios.post.mockResolvedValueOnce({ data: { success: true, response: 'Prior current response', completedObjectives: ['sqli_1'] } }); await send(node);
    const priorCache = localStorage.getItem(scopedKey('sqli_workshop_completed', 7));
    const pending = deferred(); axios.post.mockReturnValueOnce(pending.promise); await send(node);
    axios.post.mockRejectedValueOnce(new Error('controlled failure'));
    await confirmDestructiveReset(node, 'Reset chat, cart & progress');
    pending.reject(new Error('obsolete chat error')); await flush();
    expect(node.textContent).toContain('Prior current response');
    expect(node.textContent).not.toContain('Connection error. Please try again.');
    expect(localStorage.getItem(scopedKey('sqli_workshop_completed', 7))).toBe(priorCache);
    expect(toast.error).toHaveBeenCalledWith('Failed to reset');
    axios.post.mockResolvedValueOnce({ data: { success: true, response: 'New current response' } }); await send(node);
    expect(node.textContent).toContain('New current response');
  });
  test('unmount suppresses late completion cache, events and notices', async () => {
    const { node, root } = await renderLab(SQLWorkshop);
    const pending = deferred(); axios.post.mockReturnValueOnce(pending.promise); await send(node);
    const call = axios.post.mock.calls.find(([url]) => url.endsWith('/chat'));
    act(() => root.unmount()); mountedRoots.pop(); node.remove();
    expect(call[2].signal.aborted).toBe(true);
    toast.success.mockClear(); const events = jest.spyOn(window, 'dispatchEvent');
    pending.resolve({ data: { success: true, response: 'Late', completedObjectives: ['sqli_1'] } }); await flush();
    expect(localStorage.getItem(scopedKey('sqli_workshop_completed', 7))).toBeNull();
    expect(toast.success).not.toHaveBeenCalled();
    expect(events.mock.calls.filter(([event]) => event.type === 'objectiveCompleted')).toHaveLength(0);
  });
  test('StrictMode still admits current chat after reset', async () => {
    const StrictNOVA = () => <React.StrictMode><SQLWorkshop /></React.StrictMode>;
    const { node } = await renderLab(StrictNOVA);
    await confirmDestructiveReset(node, 'Reset chat, cart & progress');
    axios.post.mockResolvedValueOnce({ data: { success: true, response: 'Fresh response', completedObjectives: ['sqli_1'] } }); await send(node);
    expect(node.textContent).toContain('Fresh response');
    expect(JSON.parse(localStorage.getItem(scopedKey('sqli_workshop_completed', 7)))).toContain('sqli_1');
  });

});


describe.each(LABS)('$name saved conversation continuity', lab => {
  const composed = '**Model explanation:**\n\nObserved query result.\n\n**Tool result — search (server-rendered):**\n\n| Value |\n| --- |\n| Exact owned value 123 |\n\n<script>window.__historyExecuted = true</script>';
  function historyResponse() { return { data: { success: true, history: [
    { message_type: 'user', message: 'Prior owned request' },
    { message_type: 'assistant', message: composed },
  ] } }; }
  function useHistory(promise) {
    const prior = axios.get.getMockImplementation();
    axios.get.mockImplementation((url, ...args) => url.includes('/history/') ? promise : prior(url, ...args));
  }
  test('reload passes persisted Markdown and full tool values to the existing renderer', async () => {
    useHistory(Promise.resolve(historyResponse()));
    const { node } = await renderLab(lab.Component);
    expect(node.textContent).toContain('Prior owned request');
    expect(node.textContent).toContain('Model explanation:');
    expect(node.textContent).toContain('Exact owned value 123');
    expect(node.querySelector('script')).toBeNull();
    expect(window.__historyExecuted).toBeUndefined();
  });
  test('late saved history cannot cross an authenticated identity change', async () => {
    const pending = deferred();
    const prior = axios.get.getMockImplementation();
    axios.get.mockImplementation((url, ...args) => url.includes('/history/7') ? pending.promise
      : url.includes('/history/') ? Promise.resolve({ data: { success: true, history: [] } }) : prior(url, ...args));
    const { root, node } = await renderLab(lab.Component);
    mockUser = { id: 8, username: 'student_8' };
    await act(async () => { root.render(<lab.Component />); }); await flush();
    await act(async () => { pending.resolve(historyResponse()); }); await flush();
    expect(node.textContent).not.toContain('Prior owned request');
  });
  test('late saved history cannot overwrite a newly sent conversation', async () => {
    const pending = deferred(); useHistory(pending.promise);
    axios.post.mockResolvedValue({ data: { success: true, response: 'Current live reply' } });
    const { node } = await renderLab(lab.Component);
    await act(async () => { findButton(node, lab.chatChip).click(); }); await flush();
    await act(async () => { pending.resolve(historyResponse()); }); await flush();
    expect(node.textContent).toContain('Current live reply');
    expect(node.textContent).not.toContain('Prior owned request');
  });
  test('late saved history cannot restore a cleared conversation', async () => {
    const pending = deferred(); useHistory(pending.promise);
    const { node } = await renderLab(lab.Component);
    const reset = findButton(node, lab.resetTitle);
    await confirmDestructiveReset(node, lab.resetTitle);
    await act(async () => { pending.resolve(historyResponse()); }); await flush();
    expect(node.textContent).not.toContain('Prior owned request');
  });
});


describe.each(LABS)('$name Judge retry lifecycle', lab => {
  test.each(['valid', 'reset', 'identity'])('deferred progress is fenced for %s', async change => {
    const { root, node } = await renderLab(lab.Component);
    axios.post.mockResolvedValue({ data: { success: true, response: 'Current controlled response' } });
    await act(async () => findButton(node, lab.chatChip).click());
    await flush();
    const pending = deferred();
    mockProgressRequest = () => pending.promise;
    toast.success.mockClear();
    let retry;
    await act(async () => {
      retry = mockRetryResult({ completed: true, judgments: [] }, { signal: new AbortController().signal });
      await Promise.resolve();
    });
    if (change === 'reset') {
      await confirmDestructiveReset(node, lab.resetTitle);
    } else if (change === 'identity') {
      mockUser = { id: 8, username: 'student_8' };
      mockProgressRequest = () => Promise.resolve({ data: { objectives: {} } });
      await act(async () => root.render(<lab.Component />));
    }
    await act(async () => { pending.resolve(completedProgress(lab.objectiveId)); await retry; });
    if (change === 'valid') {
      expect(JSON.parse(localStorage.getItem(scopedKey(lab.baseKey, 7)))).toContain(lab.objectiveId);
      expect(toast.success).toHaveBeenCalledWith('Objective evaluation passed.');
    } else {
      expect(localStorage.getItem(scopedKey(lab.baseKey, 7))).toBeNull();
      expect(JSON.parse(localStorage.getItem(scopedKey(lab.baseKey, 8)) || '[]')).not.toContain(lab.objectiveId);
      expect(toast.success).not.toHaveBeenCalledWith('Objective evaluation passed.');
    }
  });
  test.each(['reset', 'identity', 'aborted'])('retained callback rejects %s before writes', async change => {
    const { root, node } = await renderLab(lab.Component);
    axios.post.mockResolvedValue({ data: { success: true, response: 'Current controlled response' } });
    await act(async () => findButton(node, lab.chatChip).click());
    await flush();
    const callback = mockRetryResult;
    const controller = new AbortController();
    if (change === 'reset') await confirmDestructiveReset(node, lab.resetTitle);
    else if (change === 'identity') {
      mockUser = { id: 8, username: 'student_8' };
      await act(async () => root.render(<lab.Component />));
    } else controller.abort();
    await flush();
    axios.get.mockClear(); toast.success.mockClear();
    const before = node.textContent;
    await act(async () => callback({ completed: true, judgments: [{ objectiveId: lab.objectiveId, verdict: 'pass' }] }, { signal: controller.signal }));
    expect(axios.get).not.toHaveBeenCalled();
    expect(node.textContent).toBe(before);
    expect(toast.success).not.toHaveBeenCalled();
  });
});
