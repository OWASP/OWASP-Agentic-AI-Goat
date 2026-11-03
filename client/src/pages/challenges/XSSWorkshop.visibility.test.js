jest.mock('../../context/AuthContext', () => ({ useAuth: () => ({ user: { id: 1 } }) }));
/* eslint-disable testing-library/no-unnecessary-act -- real React root exercises provider polling. */
import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import axios from 'axios';
import { toast } from 'react-toastify';
import { WorkshopConfigProvider } from '../../context/WorkshopConfigContext';
import XSSWorkshop from './XSSWorkshop';

const originalClipboardDescriptor = Object.getOwnPropertyDescriptor(navigator, 'clipboard');

jest.mock('axios', () => ({ get: jest.fn(), post: jest.fn(), defaults: {} }));
let mockReconcileSummary;
let mockRetryResult;
jest.mock('../../components/workshop/JudgeRetryButton', () => props => { mockRetryResult = props.onResult; return null; });
jest.mock('../../hooks/useChangePolling', () => callback => { mockReconcileSummary = callback; });
jest.mock('./XssEmailBuilder', () => ({ onProgressChange }) => <button onClick={() => onProgressChange([{ objective_id: 'xss_email_level_1', completed: true }])}>Builder workspace</button>);
jest.mock('../../hooks/useWorkshopHeartbeat', () => () => {});
jest.mock('../../components/VulnerabilityTemplate', () => ({ children, challengeId }) => (
  <div data-challenge-id={challengeId}>{children}</div>
));
jest.mock('../../components/HintPanel', () => ({ objectiveId }) => <div>Hint {objectiveId}</div>);
jest.mock('react-toastify', () => ({
  toast: { info: jest.fn(), success: jest.fn(), error: jest.fn(), warning: jest.fn() },
}));

const OBJECTIVE_IDS = [
  'xss_r1', 'xss_r2', 'xss_r3',
  'xss_s1', 'xss_s2', 'xss_s3',
  'xss_g1', 'xss_g2', 'xss_g3',
  'xss_e1', 'xss_e2', 'xss_e3',
];

let configRevision;
let objectiveVisibility;
let mainVisible;
let builderVisible;

const flush = async () => {
  await act(async () => {
    await Promise.resolve();
    await Promise.resolve();
    await Promise.resolve();
    await Promise.resolve();
    await Promise.resolve();
  });
};

const change = (element, value) => act(() => {
  const setter = Object.getOwnPropertyDescriptor(Object.getPrototypeOf(element), 'value').set;
  setter.call(element, value);
  element.dispatchEvent(new Event('input', { bubbles: true }));
});

const confirmReset = async () => {
  const dialog = document.querySelector('[role="alertdialog"]');
  expect(dialog).toBeTruthy();
  await act(async () => [...dialog.querySelectorAll('button')]
    .find(button => button.textContent === 'Confirm reset').click());
  await flush();
};

function createScheduler() {
  const tasks = [];
  return {
    setTimeout(callback, delay) {
      const task = { callback, delay, cancelled: false };
      tasks.push(task);
      return task;
    },
    clearTimeout(task) {
      if (task) task.cancelled = true;
    },
    async runNext() {
      const index = tasks.findIndex((task) => !task.cancelled);
      expect(index).toBeGreaterThanOrEqual(0);
      const [task] = tasks.splice(index, 1);
      await act(async () => task.callback());
      await flush();
    },
  };
}

function setAllObjectives(visible) {
  objectiveVisibility = Object.fromEntries(OBJECTIVE_IDS.map((id) => [id, {
    isVisible: visible,
    hintVisible: visible,
    solutionVisible: visible,
  }]));
}

function snapshot() {
  return {
    revision: configRevision,
    exercises: {
      xss_workshop: { isVisible: mainVisible, objectives: objectiveVisibility },
      xss_email_builder: { isVisible: builderVisible, objectives: Object.fromEntries([1, 2, 3, 4].map(level => [`xss_email_level_${level}`, { isVisible: builderVisible }])) },
    },
  };
}

function installResponses() {
  axios.post.mockResolvedValue({ data: {} });
  axios.get.mockImplementation((url) => {
    if (url === '/api/workshop/config/snapshot') return Promise.resolve({ data: snapshot() });
    if (url === '/api/workshop/config/revision') return Promise.resolve({ data: { revision: configRevision } });
    if (url === '/api/changes/revisions') {
      return Promise.resolve({ data: { revisions: { global: {}, workshops: {}, user: {} } } });
    }
    if (url === '/api/workshop/xss/progress') {
      return Promise.resolve({ data: { completedObjectives: Object.fromEntries(OBJECTIVE_IDS.map((id) => [id, true])) } });
    }
    if (url === '/api/solutions/xss-workshop/status') {
      return Promise.resolve({ data: { objectives: Object.fromEntries(OBJECTIVE_IDS.map((id) => [id, true])) } });
    }
    if (url === '/api/hints/reflected_xss_llm/status') {
      return Promise.resolve({ data: { objectives: Object.fromEntries(OBJECTIVE_IDS.map((id) => [id, true])) } });
    }
    if (url.startsWith('/api/solutions/xss-workshop/objective/')) {
      return Promise.resolve({ data: { solution: { title: 'Current XSS solution', hint: 'Current hint' } } });
    }
    if (url === '/api/workshop/xss/mode') return Promise.resolve({ data: { mode: 'vuln', effectiveMode: 'vuln', scope: { kind: 'workshop', id: 'xss_workshop' } } });
    if (url === '/api/workshop/xss/llm-status') return Promise.resolve({ data: { available: true } });
    if (url === '/api/workshop/xss/emails/sharklaser-email') return Promise.resolve({ data: {
      email: 'xss-42@owasp-ai-goat.invalid', mode: 'local', provider: 'mailpit', editable: false,
      sender: 'attacker@owasp-ai-goat.invalid',
    } });
    return Promise.resolve({ data: {} });
  });
}

function renderWorkshop(strict = false) {
  const scheduler = createScheduler();
  const node = document.createElement('div');
  document.body.appendChild(node);
  const root = createRoot(node);
  act(() => {
    root.render(
      <WorkshopConfigProvider
        token="token"
        pollerOptions={{
          scheduler,
          visibility: { state: 'visible', subscribe: () => () => {} },
          random: () => 0,
        }}
      >
        {strict ? <React.StrictMode><XSSWorkshop /></React.StrictMode> : <XSSWorkshop />}
      </WorkshopConfigProvider>,
    );
  });
  return { node, root, scheduler };
}

beforeEach(() => {
  global.IS_REACT_ACT_ENVIRONMENT = true;
  global.requestAnimationFrame = (callback) => callback();
  configRevision = 1;
  mainVisible = true;
  builderVisible = false;
  window.history.replaceState({}, '', '/');
  setAllObjectives(true);
  axios.get.mockReset();
  axios.post.mockReset();
  installResponses();
});

afterEach(() => {
  document.body.replaceChildren();
  if (originalClipboardDescriptor) Object.defineProperty(navigator, 'clipboard', originalClipboardDescriptor);
  else delete navigator.clipboard;
  jest.restoreAllMocks();
});

test('an admin-hidden XSS objective neither renders nor counts after refresh', async () => {
  objectiveVisibility.xss_r2.isVisible = false;
  const view = renderWorkshop();
  await flush();

  expect(view.node.textContent).not.toContain('Inject an HTML tag');
  expect(view.node.querySelector('.progress-text').textContent).toContain('11 of 11 objectives completed');
  act(() => view.root.unmount());
});

test('instructor objective label and description override authored fallback', async () => {
  objectiveVisibility.xss_r1.label = 'Instructor reflected label';
  objectiveVisibility.xss_r1.description = 'Instructor reflected guidance';
  const view = renderWorkshop(); await flush();
  expect(view.node.textContent).toContain('Instructor reflected label');
  expect(view.node.textContent).toContain('Instructor reflected guidance');
  expect(view.node.textContent).not.toContain('Send a normal message to see how the assistant responds.');
  act(() => view.root.unmount());
});

test('builder-only visibility uses the combined XSS template while hiding main objectives', async () => {
  mainVisible = false;
  builderVisible = true;
  setAllObjectives(false);
  const view = renderWorkshop();
  await flush();

  expect(view.node.querySelector('[data-challenge-id]')?.getAttribute('data-challenge-id')).toBe('reflected_xss_llm');
  expect(view.node.textContent).toContain('About the XSS workshop');
  expect(view.node.textContent).toContain('Builder workspace');
  expect(view.node.textContent).not.toContain('Interact with the assistant');
  expect(view.node.textContent).not.toContain('XSS in AI Powered Chat System');
  act(() => view.root.unmount());
});

test('a polled snapshot hides an objective and closes its open solution', async () => {
  const view = renderWorkshop();
  await flush();

  const objective = [...view.node.querySelectorAll('.obj-name')]
    .find((candidate) => candidate.textContent === 'Interact with the assistant');
  const solutionButton = objective.parentElement.querySelector('[data-testid="solution-button-xss_r1"]');
  act(() => solutionButton.dispatchEvent(new MouseEvent('click', { bubbles: true })));
  await flush();
  expect(document.querySelector('[data-testid="objective-help-modal"]')).toBeTruthy();
  expect(document.body.textContent).toContain('Solution · Interact with the assistant');
  expect(document.body.textContent).toContain('Current hint');

  objectiveVisibility.xss_r1.isVisible = false;
  configRevision = 2;
  await view.scheduler.runNext();

  expect(view.node.textContent).not.toContain('Interact with the assistant');
  expect(document.querySelector('[data-testid="objective-help-modal"]')).toBeNull();
  act(() => view.root.unmount());
});

test('XSS solution retains authored payload actions without exposing independently disabled hints', async () => {
  objectiveVisibility.xss_r1.hintVisible = false;
  const originalGet = axios.get.getMockImplementation();
  axios.get.mockImplementation(url => {
    if (url === '/api/hints/reflected_xss_llm/status') {
      return Promise.resolve({ data: { objectives: { xss_r1: false } } });
    }
    if (url === '/api/solutions/xss-workshop/objective/xss_r1') {
      return Promise.resolve({ data: { solution: {
        title: 'Current XSS solution', hint: 'GATED XSS HINT',
        example: '<b>first</b>|||<b>second</b>', explanation: 'Authored explanation',
      } } });
    }
    return originalGet(url);
  });
  const clipboard = { writeText: jest.fn().mockResolvedValue() };
  Object.defineProperty(navigator, 'clipboard', { configurable: true, value: clipboard });
  const view = renderWorkshop(); await flush();
  act(() => view.node.querySelector('[data-testid="solution-button-xss_r1"]').click()); await flush();
  const modal = document.querySelector('[data-testid="objective-help-modal"]');
  expect(modal.textContent).toContain('Authored explanation');
  expect(modal.textContent).toContain('<b>first</b>');
  expect(modal.textContent).toContain('<b>second</b>');
  expect(modal.textContent).not.toContain('GATED XSS HINT');
  act(() => modal.querySelectorAll('[data-testid="solution-example"] button')[1].click());
  expect(clipboard.writeText).toHaveBeenCalledWith('<b>second</b>');
  expect(view.node.querySelector('textarea').value).toBe('<b>second</b>');
  expect(document.querySelector('[data-testid="objective-help-modal"]')).toBeNull();
  act(() => view.root.unmount());
});

test('an all-hidden snapshot renders neutral zero progress without false completion', async () => {
  const view = renderWorkshop();
  await flush();

  setAllObjectives(false);
  configRevision = 2;
  await view.scheduler.runNext();

  expect(view.node.querySelector('.progress-text').textContent).toContain('0 of 0 objectives completed');
  expect(view.node.textContent).not.toContain('All objectives completed!');
  expect(view.node.innerHTML).not.toContain('NaN');
  act(() => view.root.unmount());
});

test('scenario navigation preserves each XSS transcript and does not reset sibling artifacts', async () => {
  const view = renderWorkshop();
  await flush();
  const input = view.node.querySelector('textarea');
  change(input, 'reflected scenario evidence');
  await act(async () => {
    input.closest('form').dispatchEvent(new Event('submit', { bubbles: true, cancelable: true }));
    await Promise.resolve();
  });
  await flush();
  expect(view.node.textContent).toContain('reflected scenario evidence');

  const storedTab = view.node.querySelector('[data-scenario-tab="stored_user"]');
  await act(async () => {
    storedTab.dispatchEvent(new MouseEvent('click', { bubbles: true }));
    await Promise.resolve();
  });
  expect(view.node.textContent).not.toContain('reflected scenario evidence');
  expect(axios.post.mock.calls.some(([url]) => url === '/api/workshop/xss/profile/reset')).toBe(false);

  const reflectedTab = view.node.querySelector('[data-scenario-tab="reflected"]');
  await act(async () => {
    reflectedTab.dispatchEvent(new MouseEvent('click', { bubbles: true }));
    await Promise.resolve();
  });
  expect(view.node.textContent).toContain('reflected scenario evidence');
  act(() => view.root.unmount());
});

test('local email panel uses the server-owned private inbox and reports only SMTP acceptance', async () => {
  localStorage.setItem('owasp_ai_goat_email_agent_temp_email', 'stale-public@sharklasers.com');
  const view = renderWorkshop();
  await flush();
  expect(view.node.textContent).toContain('unsanitized HTML with executable event-handler attributes can run');
  expect(view.node.textContent).toContain('Script elements inserted through innerHTML remain inert');
  expect(view.node.textContent).toContain('a passing Judge verdict records completion');
  expect(view.node.textContent).toContain('isolated qualification browser');
  const emailTab = view.node.querySelector('[data-scenario-tab="email"]');
  await act(async () => {
    emailTab.dispatchEvent(new MouseEvent('click', { bubbles: true }));
    await Promise.resolve();
  });

  expect(view.node.textContent).toContain('Send from attacker@owasp-ai-goat.invalid to Your Workshop Inbox');
  expect(view.node.textContent).toContain('Your workshop inbox (To)');
  expect(view.node.textContent).toContain('through the configured workshop mail transport');
  expect(view.node.textContent).toContain('Summarize my latest exercise attack email');
  expect(view.node.textContent).not.toContain('Summarize the email from indirectpromptinjection@gmail.com');
  expect(view.node.textContent).toContain('Private local inbox assigned to your signed-in workshop account');
  expect(view.node.textContent).not.toContain('Open SharkLasers.com');
  expect(view.node.textContent).not.toContain('base SharkLasers address');
  expect(view.node.textContent).not.toContain('Send Your Malicious Email to indirectpromptinjection@gmail.com');
  const recipient = view.node.querySelector('input[type="email"]');
  expect(recipient.value).toBe('xss-42@owasp-ai-goat.invalid');
  expect(recipient.readOnly).toBe(true);
  await act(async () => {
    [...view.node.querySelectorAll('button')].find(candidate => candidate.textContent === 'Send Email').click();
    await Promise.resolve();
  });
  await flush();
  expect(axios.post.mock.calls.some(([url, body]) => url === '/api/workshop/xss/emails/send-attack'
    && body.fromEmail === 'xss-42@owasp-ai-goat.invalid')).toBe(true);
  expect(view.node.textContent).toContain('Local SMTP accepted the message. Ask the AI to check your workshop inbox.');
  act(() => view.root.unmount());
});

test('external email mode retains editable address and external delivery guidance', async () => {
  const baseGet = axios.get.getMockImplementation();
  axios.get.mockImplementation((url, options) => url === '/api/workshop/xss/emails/sharklaser-email'
    ? Promise.resolve({ data: { email: 'owner@sharklasers.com', mode: 'external', provider: 'gmail',
      editable: true, sender: 'indirectpromptinjection@gmail.com' } })
    : baseGet(url, options));
  const view = renderWorkshop();
  await flush();
  const emailTab = view.node.querySelector('[data-scenario-tab="email"]');
  await act(async () => {
    emailTab.dispatchEvent(new MouseEvent('click', { bubbles: true }));
    await Promise.resolve();
  });
  await flush();
  const recipient = view.node.querySelector('input[type="email"]');
  expect(recipient.readOnly).toBe(false);
  expect(view.node.textContent).toContain('Send from indirectpromptinjection@gmail.com to Your Workshop Inbox');
  expect(view.node.textContent).toContain('Open SharkLasers.com');
  expect(view.node.textContent).toContain('base SharkLasers address');
  change(recipient, 'edited-owner@sharklasers.com');
  const reflectedTab = view.node.querySelector('[data-scenario-tab="reflected"]');
  await act(async () => {
    reflectedTab.dispatchEvent(new MouseEvent('click', { bubbles: true }));
    await Promise.resolve();
    emailTab.dispatchEvent(new MouseEvent('click', { bubbles: true }));
    await Promise.resolve();
  });
  await flush();
  expect(view.node.querySelector('input[type="email"]').value).toBe('edited-owner@sharklasers.com');
  await act(async () => {
    [...view.node.querySelectorAll('button')].find(candidate => candidate.textContent === 'Send Email').click();
    await Promise.resolve();
  });
  await flush();
  expect(axios.post.mock.calls.some(([url, body]) => url === '/api/workshop/xss/emails/send-attack'
    && body.fromEmail === 'edited-owner@sharklasers.com')).toBe(true);
  expect(view.node.textContent).toContain('SMTP accepted. Wait for it to reach your inbox');
  act(() => view.root.unmount());
});

test('email send failure renders the bounded server message', async () => {
  axios.post.mockImplementation(url => url === '/api/workshop/xss/emails/send-attack'
    ? Promise.reject({ response: { data: { error: 'Workshop SMTP is temporarily unavailable.' } } })
    : Promise.resolve({ data: {} }));
  const view = renderWorkshop();
  await flush();
  const emailTab = view.node.querySelector('[data-scenario-tab="email"]');
  await act(async () => {
    emailTab.dispatchEvent(new MouseEvent('click', { bubbles: true }));
    await Promise.resolve();
  });
  await flush();
  await act(async () => {
    [...view.node.querySelectorAll('button')].find(candidate => candidate.textContent === 'Send Email').click();
    await Promise.resolve();
  });
  await flush();
  expect(view.node.textContent).toContain('Workshop SMTP is temporarily unavailable.');
  act(() => view.root.unmount());
});

test('judge failures render as plain feedback and never call the retired completion endpoint', async () => {
  axios.post.mockImplementation((url) => {
    if (url === '/api/workshop/xss/chat') return Promise.resolve({ data: {
      response: '<div>Formatting response</div>',
      xssDetected: false,
      completedObjectiveId: null,
      judgments: [{ objectiveId: 'xss_r1', verdict: 'unavailable',
        explanation: '<img src=x onerror=alert(1)> evaluator offline' }],
    } });
    return Promise.resolve({ data: {} });
  });
  const view = renderWorkshop();
  await flush();
  const input = view.node.querySelector('textarea');
  change(input, 'format this');
  await act(async () => {
    input.closest('form').dispatchEvent(new Event('submit', { bubbles: true, cancelable: true }));
    await Promise.resolve();
  });
  await flush();
  expect(view.node.textContent).toContain('Judge unavailable: <img src=x onerror=alert(1)> evaluator offline');
  expect([...view.node.querySelectorAll('.message-text')].some(element => element.querySelector('img') &&
    element.textContent.includes('evaluator offline'))).toBe(false);
  expect(axios.post.mock.calls.some(([url]) => url === '/api/workshop/xss/progress/complete')).toBe(false);
  act(() => view.root.unmount());
});

test.each([false, true])('progress reset permits a fresh email and rejects stale send UI (late=%s)', async late => {
  let finishSend;
  axios.post.mockImplementation(url => {
    if (url === '/api/workshop/xss/emails/send-attack') {
      if (late) return new Promise(resolve => { finishSend = resolve; });
      return Promise.resolve({ data: { completedObjectiveId: 'xss_e2' } });
    }
    return Promise.resolve({ data: {} });
  });
  const view = renderWorkshop();
  await flush();
  await act(async () => view.node.querySelector('[data-scenario-tab="email"]').click());
  await flush();
  const buttons = () => [...view.node.querySelectorAll('button')];
  await act(async () => buttons().find(button => button.textContent === 'Send Email').click());
  await flush();
  await act(async () => buttons().find(button => button.textContent.trim() === 'Reset Chat Progress').click());
  await confirmReset();
  await flush();
  if (late) {
    await act(async () => finishSend({ data: { completedObjectiveId: 'xss_e2', judgments: [{ verdict: 'pass', explanation: 'stale-send-feedback' }] } }));
    await flush();
  }
  const send = buttons().find(button => button.textContent === 'Send Email');
  expect(send).toBeDefined();
  expect(send.disabled).toBe(false);
  expect(view.node.textContent).not.toContain('stale-send-feedback');
  expect(view.node.textContent).not.toContain('Local SMTP accepted the message.');
  act(() => view.root.unmount());
});

test('XSS tab reset confirms its captured scope and cancellation makes no mutation', async () => {
  const view = renderWorkshop(); await flush();
  const resetTab = () => [...view.node.querySelectorAll('button')]
    .find(button => button.textContent.trim() === 'Reset Above Objectives');
  act(() => resetTab().click());
  expect(document.querySelector('[role="alertdialog"]').textContent).toContain('Reflected XSS objectives');
  expect(axios.post.mock.calls.some(([url]) => url === '/api/workshop/xss/progress/reset-tab')).toBe(false);
  act(() => [...document.querySelector('[role="alertdialog"]').querySelectorAll('button')]
    .find(button => button.textContent === 'Cancel').click());
  expect(document.querySelector('[role="alertdialog"]')).toBeNull();

  act(() => resetTab().click());
  await confirmReset();
  expect(axios.post).toHaveBeenCalledWith('/api/workshop/xss/progress/reset-tab', { exerciseId: 'reflected' });
  expect(view.node.querySelector('.progress-text').textContent).toContain('9 of 12 objectives completed');
  expect(document.querySelector('[role="alertdialog"]')).toBeNull();
  act(() => view.root.unmount());
});

test('XSS all-progress confirmation holds pending state and permits retry after an error', async () => {
  let rejectReset;
  axios.post.mockImplementation(url => url === '/api/workshop/xss/progress/reset'
    ? new Promise((_resolve, reject) => { rejectReset = reject; }) : Promise.resolve({ data: {} }));
  const view = renderWorkshop(); await flush();
  act(() => [...view.node.querySelectorAll('button')]
    .find(button => button.textContent.trim() === 'Reset Chat Progress').click());
  expect(axios.post.mock.calls.some(([url]) => url === '/api/workshop/xss/progress/reset')).toBe(false);
  await confirmReset();
  let dialog = document.querySelector('[role="alertdialog"]');
  expect(dialog.textContent).toContain('Resetting…');
  expect([...dialog.querySelectorAll('button')].every(button => button.disabled)).toBe(true);
  expect([...view.node.querySelectorAll('button')].find(button => button.textContent.trim() === 'Resetting…').disabled).toBe(true);
  await act(async () => rejectReset({ response: { data: { error: 'Reset unavailable' } } }));
  await flush();
  dialog = document.querySelector('[role="alertdialog"]');
  expect(dialog.textContent).toContain('Reset unavailable');
  expect(view.node.querySelector('.progress-text').textContent).toContain('12 of 12 objectives completed');

  axios.post.mockImplementation(() => Promise.resolve({ data: { success: true } }));
  await confirmReset();
  expect(document.querySelector('[role="alertdialog"]')).toBeNull();
  expect(view.node.querySelector('.progress-text').textContent).toContain('0 of 12 objectives completed');
  act(() => view.root.unmount());
});

test('a late chat response cannot repopulate messages or completion after progress reset', async () => {
  let finishChat;
  const originalGet = axios.get.getMockImplementation();
  axios.get.mockImplementation(url => url === '/api/workshop/xss/progress'
    ? Promise.resolve({ data: { completedObjectives: {} } }) : originalGet(url));
  axios.post.mockImplementation(url => url === '/api/workshop/xss/chat'
    ? new Promise(resolve => { finishChat = resolve; }) : Promise.resolve({ data: {} }));
  const view = renderWorkshop();
  await flush();
  const input = view.node.querySelector('textarea');
  change(input, 'old request');
  await act(async () => input.closest('form').dispatchEvent(new Event('submit', { bubbles: true, cancelable: true })));
  await flush();
  await act(async () => [...view.node.querySelectorAll('button')].find(button => button.textContent.trim() === 'Reset Chat Progress').click());
  await confirmReset();
  await flush();
  await act(async () => finishChat({ data: { response: 'stale chat response', completedObjectiveId: 'xss_r1', xssDetected: true } }));
  await flush();
  expect(view.node.textContent).not.toContain('stale chat response');
  expect(view.node.querySelector('.progress-text').textContent).toContain('0 of 12 objectives completed');
  expect(view.node.querySelector('textarea').disabled).toBe(false);
  act(() => view.root.unmount());
});

test('clearing one conversation fences its delayed response without clearing progress or sibling transcripts', async () => {
  let finishChat;
  let chatCount = 0;
  const originalGet = axios.get.getMockImplementation();
  axios.get.mockImplementation(url => url === '/api/workshop/xss/progress'
    ? Promise.resolve({ data: { completedObjectives: Object.fromEntries(
      OBJECTIVE_IDS.map(id => [id, id !== 'xss_r1']),
    ) } }) : originalGet(url));
  axios.post.mockImplementation(url => {
    if (url !== '/api/workshop/xss/chat') return Promise.resolve({ data: {} });
    chatCount += 1;
    if (chatCount === 1) return Promise.resolve({ data: { response: 'retained sibling response' } });
    return new Promise(resolve => { finishChat = resolve; });
  });
  const view = renderWorkshop();
  await flush();
  expect(view.node.querySelector('.progress-text').textContent).toContain('11 of 12 objectives completed');
  await act(async () => view.node.querySelector('[data-scenario-tab="email"]').click());
  await flush();
  const siblingInput = view.node.querySelector('textarea');
  change(siblingInput, 'retained sibling request');
  await act(async () => siblingInput.closest('form').dispatchEvent(new Event('submit', { bubbles: true, cancelable: true })));
  await flush();
  expect(view.node.textContent).toContain('retained sibling response');

  await act(async () => view.node.querySelector('[data-scenario-tab="reflected"]').click());
  await flush();
  const input = view.node.querySelector('textarea');
  change(input, 'discard this delayed request');
  await act(async () => input.closest('form').dispatchEvent(new Event('submit', { bubbles: true, cancelable: true })));
  await flush();
  await act(async () => [...view.node.querySelectorAll('button')]
    .find(button => button.textContent.includes('Reset conversation')).click());
  await flush();
  expect(view.node.textContent).not.toContain('discard this delayed request');
  expect(view.node.querySelector('textarea').disabled).toBe(false);

  await act(async () => finishChat({ data: {
    response: 'discard this delayed response', completedObjectiveId: 'xss_r1', xssDetected: true,
  } }));
  await flush();
  expect(view.node.textContent).not.toContain('discard this delayed response');
  expect(view.node.querySelector('.progress-text').textContent).toContain('12 of 12 objectives completed');
  expect(axios.post.mock.calls.some(([url]) => url.includes('/reset'))).toBe(false);
  await act(async () => view.node.querySelector('[data-scenario-tab="email"]').click());
  await flush();
  expect(view.node.textContent).toContain('retained sibling request');
  expect(view.node.textContent).toContain('retained sibling response');
  act(() => view.root.unmount());
});

test('late email metadata cannot undo a newer scenario selection', async () => {
  const originalGet = axios.get.getMockImplementation();
  let finishMetadata;
  axios.get.mockImplementation(url => url === '/api/workshop/xss/emails/sharklaser-email'
    ? new Promise(resolve => { finishMetadata = resolve; }) : originalGet(url));
  const view = renderWorkshop();
  await flush();
  act(() => view.node.querySelector('[data-scenario-tab="email"]').click());
  act(() => view.node.querySelector('[data-scenario-tab="reflected"]').click());
  await act(async () => finishMetadata({ data: {
    mode: 'local', provider: 'mailpit', email: 'xss-1@owasp-ai-goat.invalid', editable: false,
  } }));
  await flush();
  expect(view.node.querySelector('input[type="email"]')).toBeNull();
  act(() => view.root.unmount());
});

test('late chat stays in its originating scenario conversation', async () => {
  let finishChat;
  axios.post.mockImplementation(url => url === '/api/workshop/xss/chat'
    ? new Promise(resolve => { finishChat = resolve; }) : Promise.resolve({ data: {} }));
  const view = renderWorkshop();
  await flush();
  const input = view.node.querySelector('textarea');
  change(input, 'reflected-only-question');
  act(() => input.closest('form').dispatchEvent(new Event('submit', { bubbles: true, cancelable: true })));
  await act(async () => view.node.querySelector('[data-scenario-tab="email"]').click());
  await flush();
  await act(async () => finishChat({ data: { response: 'reflected-only-answer' } }));
  await flush();
  expect(view.node.textContent).not.toContain('reflected-only-answer');
  act(() => view.node.querySelector('[data-scenario-tab="reflected"]').click());
  await flush();
  expect(view.node.textContent).toContain('reflected-only-answer');
  expect(view.node.textContent).toContain('reflected-only-question');
  act(() => view.root.unmount());
});

test('late email Judge feedback belongs only to the email conversation', async () => {
  let finishSend;
  axios.post.mockImplementation(url => url === '/api/workshop/xss/emails/send-attack'
    ? new Promise(resolve => { finishSend = resolve; }) : Promise.resolve({ data: {} }));
  const view = renderWorkshop();
  await flush();
  await act(async () => view.node.querySelector('[data-scenario-tab="email"]').click());
  await flush();
  act(() => [...view.node.querySelectorAll('button')].find(button => button.textContent === 'Send Email').click());
  act(() => view.node.querySelector('[data-scenario-tab="reflected"]').click());
  await act(async () => finishSend({ data: { judgments: [{ verdict: 'unavailable', explanation: 'email-only-judge-feedback' }] } }));
  await flush();
  expect(view.node.textContent).not.toContain('email-only-judge-feedback');
  await act(async () => view.node.querySelector('[data-scenario-tab="email"]').click());
  await flush();
  expect(view.node.textContent).toContain('email-only-judge-feedback');
  act(() => view.root.unmount());
});

test.each(['chat', 'email'])('late %s completion after unmount cannot emit completion', async kind => {
  let finish;
  const originalGet = axios.get.getMockImplementation();
  axios.get.mockImplementation(url => url === '/api/workshop/xss/progress' ? Promise.resolve({ data: { completedObjectives: {} } }) : originalGet(url));
  const endpoint = kind === 'chat' ? '/api/workshop/xss/chat' : '/api/workshop/xss/emails/send-attack';
  axios.post.mockImplementation(url => url === endpoint ? new Promise(resolve => { finish = resolve; }) : Promise.resolve({ data: {} }));
  const view = renderWorkshop(); await flush();
  if (kind === 'email') {
    await act(async () => view.node.querySelector('[data-scenario-tab="email"]').click()); await flush();
    act(() => [...view.node.querySelectorAll('button')].find(button => button.textContent === 'Send Email').click());
  } else {
    const input = view.node.querySelector('textarea'); change(input, 'Pending chat');
    act(() => input.closest('form').dispatchEvent(new Event('submit', { bubbles: true, cancelable: true })));
  }
  await flush(); act(() => view.root.unmount());
  expect(axios.post.mock.calls.find(([url]) => url === endpoint)[2].signal.aborted).toBe(true);
  const events = jest.spyOn(window, 'dispatchEvent');
  try {
    await act(async () => finish({ data: { response: 'Late response', completedObjectiveId: kind === 'chat' ? 'xss_r1' : 'xss_e2' } }));
    await flush();
    expect(events.mock.calls.filter(([event]) => event.type === 'objectiveCompleted')).toHaveLength(0);
  } finally { events.mockRestore(); }
});

 test('StrictMode permits current chat completion after cleanup replay', async () => {
  const originalGet = axios.get.getMockImplementation();
  axios.get.mockImplementation(url => url === '/api/workshop/xss/progress' ? Promise.resolve({ data: { completedObjectives: {} } }) : originalGet(url));
  axios.post.mockResolvedValue({ data: { response: 'Current response', completedObjectiveId: 'xss_r1' } });
  const view = renderWorkshop(true); await flush();
  const input = view.node.querySelector('textarea'); change(input, 'Current request');
  await act(async () => input.closest('form').dispatchEvent(new Event('submit', { bubbles: true, cancelable: true }))); await flush();
  expect(view.node.textContent).toContain('Current response');
  expect(view.node.querySelector('.progress-text').textContent).toContain('1 of 12 objectives completed');
  act(() => view.root.unmount());
 });

test('stored cards use canonical instructor labels and refresh them without changing identity, gates or DONE', async () => {
  objectiveVisibility.xss_s1.label = 'Instructor profile exercise';
  objectiveVisibility.xss_s2.label = '   ';
  objectiveVisibility.xss_s3.label = 42;
  const view = renderWorkshop();
  await flush();
  act(() => view.node.querySelector('[data-scenario-tab="stored_user"]').click());
  await flush();
  let names = [...view.node.querySelectorAll('.obj-name')].map(x => x.textContent);
  expect(names).toContain('Instructor profile exercise');
  expect(names).not.toContain('View your profile');
  const card = [...view.node.querySelectorAll('.obj-name')].find(x => x.textContent === 'Instructor profile exercise').closest('.obj-content').parentElement;
  expect(card.querySelector('.status-badge').textContent).toBe('DONE');
  expect(card.textContent).toContain('Hint xss_s1');
  expect(card.querySelector('[data-testid="solution-button-xss_s1"]')).toBeTruthy();
  objectiveVisibility.xss_s1.label = 'Revised instructor exercise';
  configRevision = 2;
  await view.scheduler.runNext();
  await flush();
  names = [...view.node.querySelectorAll('.obj-name')].map(x => x.textContent);
  expect(names).toContain('Revised instructor exercise');
  expect(names).not.toContain('Instructor profile exercise');
  expect(names).toContain('Save XSS payload in a profile field');
  expect(names).toContain('Trigger stored XSS');
  act(() => view.root.unmount());
});


test('query-selected scenario displays its current chat response', async () => {
  window.history.replaceState({}, '', '/?tab=stored_user');
  axios.post.mockResolvedValue({ data: { response: 'query scenario response' } });
  const view = renderWorkshop(); await flush();
  const input = view.node.querySelector('textarea'); change(input, 'query scenario question');
  await act(async () => input.closest('form').dispatchEvent(new Event('submit', { bubbles: true, cancelable: true })));
  await flush();
  expect(axios.post.mock.calls.find(([url]) => url === '/api/workshop/xss/chat')[1].exerciseId).toBe('stored_user');
  expect(view.node.textContent).toContain('query scenario response');
  act(() => view.root.unmount());
});

test('catalog removal switches presentation without copying the hidden scenario transcript', async () => {
  axios.post.mockResolvedValue({ data: { response: 'hidden scenario response' } });
  const view = renderWorkshop(); await flush();
  act(() => view.node.querySelector('[data-scenario-tab="email"]').click()); await flush();
  const input = view.node.querySelector('textarea'); change(input, 'hidden scenario question');
  await act(async () => input.closest('form').dispatchEvent(new Event('submit', { bubbles: true, cancelable: true })));
  await flush();
  for (const id of ['xss_e1', 'xss_e2', 'xss_e3']) objectiveVisibility[id].isVisible = false;
  configRevision += 1; await view.scheduler.runNext(); await flush();
  expect(view.node.textContent).not.toContain('hidden scenario question');
  expect(view.node.textContent).not.toContain('hidden scenario response');
  axios.post.mockResolvedValue({ data: { response: 'visible scenario response' } });
  const nextInput = view.node.querySelector('textarea'); change(nextInput, 'visible scenario question');
  await act(async () => nextInput.closest('form').dispatchEvent(new Event('submit', { bubbles: true, cancelable: true })));
  await flush();
  expect(axios.post.mock.calls.filter(([url]) => url === '/api/workshop/xss/chat').at(-1)[1].exerciseId).toBe('stored_llm');
  expect(view.node.textContent).toContain('visible scenario response');
  act(() => view.root.unmount());
});

test('summary revisions received on builder remain current when returning to summary', async () => {
  builderVisible = true;
  const view = renderWorkshop(); await flush();
  act(() => view.node.querySelector('[data-scenario-tab="email_builder"]').click()); await flush();
  expect(view.node.textContent).toContain('Builder workspace');
  expect(view.node.textContent).toContain('About the XSS workshop');
  expect(view.node.textContent).not.toContain('XSS in AI Powered Chat System');
  act(() => view.node.querySelector('[data-scenario-tab="reflected"]').click()); await flush();
  expect(view.node.textContent).toContain('About the XSS workshop');
  act(() => view.node.querySelector('[data-scenario-tab="email_builder"]').click()); await flush();
  act(() => [...view.node.querySelectorAll('button')].find(button => button.textContent === 'Builder workspace').click());
  const originalGet = axios.get.getMockImplementation();
  axios.get.mockImplementation(url => url === '/api/workshop/xss/progress'
    ? Promise.resolve({ data: { completedObjectives: {} } })
    : url === '/api/solutions/xss-workshop/status' || url === '/api/hints/reflected_xss_llm/status'
      ? Promise.resolve({ data: { objectives: {} } }) : originalGet(url));
  await act(async () => mockReconcileSummary({}, {}, {})); await flush();
  act(() => view.node.querySelector('[data-scenario-tab="reflected"]').click()); await flush();
  expect(view.node.querySelector('.progress-text').textContent).toContain('1 of 16 objectives completed');
  expect(view.node.textContent).not.toContain('View Solution');
  expect(view.node.textContent).not.toContain('Hint xss_r1');
  act(() => view.root.unmount());
});


test.each(['current', 'during-reset', 'after-reset', 'aborted'])('Judge retry respects XSS conversation lifetime: %s', async timing => {
  const defaultGet = axios.get.getMockImplementation();
  axios.get.mockImplementation((url, ...args) => url === '/api/workshop/xss/progress'
    ? Promise.resolve({ data: { completedObjectives: {} } }) : defaultGet(url, ...args));
  const view = renderWorkshop();
  await flush();
  const input = view.node.querySelector('textarea');
  change(input, 'retry fixture');
  act(() => input.closest('form').dispatchEvent(new Event('submit', { bubbles: true, cancelable: true })));
  await flush();
  const callback = mockRetryResult;
  expect(callback).toEqual(expect.any(Function));
  const controller = new AbortController();
  let resolveProgress;
  const progress = new Promise(resolve => { resolveProgress = resolve; });
  axios.get.mockImplementation(() => progress);
  axios.get.mockClear();
  toast.success.mockClear();
  const reset = () => [...view.node.querySelectorAll('button')].find(button => button.textContent.trim() === 'Reset conversation').click();
  let pending;
  try {
    if (timing === 'after-reset') await act(async () => reset());
    if (timing === 'aborted') controller.abort();
    await act(async () => {
      pending = callback({ completed: true, judgment: { verdict: 'inconclusive', explanation: 'retry lifetime feedback' } }, { signal: controller.signal });
      await Promise.resolve();
    });
    if (timing === 'during-reset') await act(async () => reset());
    await act(async () => {
      resolveProgress({ data: { completedObjectives: { xss_r1: true } } });
      await pending;
    });
    expect(view.node.textContent).toContain(`${timing === 'current' ? 1 : 0} of 12 objectives completed`);
    if (timing === 'current') {
      expect(toast.success).toHaveBeenCalledWith('Objective evaluation passed.');
      expect(view.node.textContent).toContain('retry lifetime feedback');
    } else {
      expect(toast.success).not.toHaveBeenCalledWith('Objective evaluation passed.');
      expect(view.node.textContent).not.toContain('retry lifetime feedback');
      if (timing !== 'during-reset') expect(axios.get).not.toHaveBeenCalled();
    }
  } finally {
    resolveProgress({ data: {} });
    await act(async () => { await pending; view.root.unmount(); });
  }
});


test.each([
  ['stored_user', true, null], ['stored_llm', true, null], ['stored_user', false, null],
  ['reflected', true, null], ['email', true, null], ['stored_user', true, 'stored_llm'],
])('profile reset fences only stored presentation: pending %s, success=%s', async (scenario, resetSucceeds, resetScenario) => {
  let finishChat;
  const objective = { stored_user: 'xss_s1', stored_llm: 'xss_g1', reflected: 'xss_r1', email: 'xss_e1' }[scenario];
  const originalGet = axios.get.getMockImplementation();
  axios.get.mockImplementation(url => url === '/api/workshop/xss/progress'
    ? Promise.resolve({ data: { completedObjectives: Object.fromEntries(OBJECTIVE_IDS.map(id => [id, id !== objective])) } })
    : originalGet(url));
  axios.post.mockImplementation(url => {
    if (url === '/api/workshop/xss/chat') return new Promise(resolve => { finishChat = resolve; });
    if (url === '/api/workshop/xss/profile/reset' && !resetSucceeds) return Promise.reject(new Error('reset unavailable'));
    return Promise.resolve({ data: { success: true } });
  });
  const view = renderWorkshop(); await flush();
  await act(async () => view.node.querySelector(`[data-scenario-tab="${scenario}"]`).click()); await flush();
  const input = view.node.querySelector('textarea'); change(input, 'retained pre-reset request');
  await act(async () => input.closest('form').dispatchEvent(new Event('submit', { bubbles: true, cancelable: true })));
  if (!scenario.startsWith('stored_') || resetScenario) {
    await act(async () => view.node.querySelector(`[data-scenario-tab="${resetScenario || 'stored_user'}"]`).click()); await flush();
  }
  await act(async () => [...view.node.querySelectorAll('button')].find(button => button.textContent.trim() === 'Reset Profile').click());
  expect(axios.post.mock.calls.some(([url]) => url === '/api/workshop/xss/profile/reset')).toBe(false);
  expect(document.querySelector('[role="alertdialog"]')?.textContent).toContain('Earned XSS objective progress is preserved.');
  await confirmReset();
  await flush(); toast.error.mockClear();
  if (!scenario.startsWith('stored_') || resetScenario) {
    await act(async () => view.node.querySelector(`[data-scenario-tab="${scenario}"]`).click()); await flush();
  }
  await act(async () => finishChat({ data: { response: 'late profile effect response', xssDetected: true, completedObjectiveId: objective } }));
  await flush();
  expect(view.node.textContent).toContain('retained pre-reset request');
  expect(view.node.querySelector('.progress-text').textContent).toContain('12 of 12 objectives completed');
  if (resetSucceeds && scenario.startsWith('stored_')) {
    expect(view.node.textContent).not.toContain('late profile effect response');
    expect(view.node.textContent).not.toContain('The injected script ran in the browser.');
    expect(toast.error).not.toHaveBeenCalledWith('⚡ XSS Executed!', { autoClose: 3000 });
  } else {
    expect(view.node.textContent).toContain('late profile effect response');
    expect(toast.error).toHaveBeenCalledWith('⚡ XSS Executed!', { autoClose: 3000 });
  }
  expect(view.node.querySelector('textarea').disabled).toBe(false);
  act(() => view.root.unmount());
});

test('profile reset confirmation can be cancelled without clearing earned progress', async () => {
  const view = renderWorkshop(); await flush();
  await act(async () => view.node.querySelector('[data-scenario-tab="stored_user"]').click());
  await flush();
  await act(async () => [...view.node.querySelectorAll('button')]
    .find(button => button.textContent.trim() === 'Reset Profile').click());
  const dialog = document.querySelector('[role="alertdialog"]');
  expect(dialog.textContent).toContain('Earned XSS objective progress is preserved.');
  await act(async () => [...dialog.querySelectorAll('button')]
    .find(button => button.textContent === 'Cancel').click());
  expect(document.querySelector('[role="alertdialog"]')).toBeNull();
  expect(axios.post.mock.calls.some(([url]) => url === '/api/workshop/xss/profile/reset')).toBe(false);
  expect(view.node.querySelector('.progress-text').textContent).toContain('12 of 12 objectives completed');
  act(() => view.root.unmount());
});

test('profile reset blocks duplicate confirms and keeps a failed reset open for retry', async () => {
  let rejectFirst;
  let resetRequests = 0;
  axios.post.mockImplementation(url => {
    if (url === '/api/workshop/xss/profile/reset') {
      resetRequests += 1;
      if (resetRequests === 1) return new Promise((_, reject) => { rejectFirst = reject; });
    }
    return Promise.resolve({ data: { success: true } });
  });
  const view = renderWorkshop(); await flush();
  await act(async () => view.node.querySelector('[data-scenario-tab="stored_llm"]').click());
  await flush();
  await act(async () => [...view.node.querySelectorAll('button')]
    .find(button => button.textContent.trim() === 'Reset Profile').click());
  const confirm = [...document.querySelector('[role="alertdialog"]').querySelectorAll('button')]
    .find(button => button.textContent === 'Confirm reset');
  await act(async () => { confirm.click(); confirm.click(); });
  expect(resetRequests).toBe(1);
  expect(document.querySelector('[role="alertdialog"]').textContent).toContain('Resetting…');
  await act(async () => rejectFirst(new Error('reset unavailable')));
  await flush();
  expect(document.querySelector('[role="alertdialog"]').textContent).toContain('Failed to reset profile.');
  await confirmReset();
  expect(resetRequests).toBe(2);
  expect(document.querySelector('[role="alertdialog"]')).toBeNull();
  expect(view.node.querySelector('.progress-text').textContent).toContain('12 of 12 objectives completed');
  act(() => view.root.unmount());
});

test('chat-wide reset preserves builder completion and states its scope', async () => {
  builderVisible = true;
  const view = renderWorkshop(); await flush();
  act(() => view.node.querySelector('[data-scenario-tab="email_builder"]').click()); await flush();
  act(() => [...view.node.querySelectorAll('button')].find(button => button.textContent === 'Builder workspace').click());
  act(() => view.node.querySelector('[data-scenario-tab="reflected"]').click()); await flush();
  act(() => [...view.node.querySelectorAll('button')].find(button => button.textContent.trim() === 'Reset Chat Progress').click());
  expect(document.body.textContent).toContain('Email Template Builder progress is preserved');
  await confirmReset(); await flush();
  expect(view.node.querySelector('.progress-text').textContent).toContain('1 of 16 objectives completed');
  expect(axios.post).toHaveBeenCalledWith('/api/workshop/xss/progress/reset');
  expect(axios.post.mock.calls.some(([url]) => url === '/api/xss-email/challenge/reset')).toBe(false);
  act(() => view.root.unmount());
});

test('scenario navigation preserves independent drafts without sending a message', async () => {
  const view = renderWorkshop(); await flush();
  change(view.node.querySelector('textarea'), 'unsent reflected draft');
  await act(async () => view.node.querySelector('[data-scenario-tab="stored_user"]').click());
  await flush();
  expect(view.node.querySelector('textarea').value).toBe('');
  change(view.node.querySelector('textarea'), 'unsent profile draft');
  await act(async () => view.node.querySelector('[data-scenario-tab="reflected"]').click());
  await flush();
  expect(view.node.querySelector('textarea').value).toBe('unsent reflected draft');
  await act(async () => view.node.querySelector('[data-scenario-tab="stored_user"]').click());
  await flush();
  expect(view.node.querySelector('textarea').value).toBe('unsent profile draft');
  expect(axios.post).not.toHaveBeenCalled();
  act(() => view.root.unmount());
});

test('composer distinguishes Enter from Shift+Enter and IME composition', async () => {
  const view = renderWorkshop(); await flush();
  const input = view.node.querySelector('textarea');
  expect(input.getAttribute('aria-label')).toBe('Message the XSS assistant');
  change(input, 'compose this');
  for (const options of [{ shiftKey: true }, { isComposing: true }, { keyCode: 229 }]) {
    await act(async () => input.dispatchEvent(new KeyboardEvent('keydown', {
      key: 'Enter', bubbles: true, cancelable: true, ...options,
    })));
  }
  expect(axios.post).not.toHaveBeenCalled();
  expect(input.value).toBe('compose this');
  await act(async () => input.dispatchEvent(new KeyboardEvent('keydown', {
    key: 'Enter', bubbles: true, cancelable: true,
  })));
  expect(axios.post.mock.calls.filter(([url]) => url === '/api/workshop/xss/chat')).toHaveLength(1);
  act(() => view.root.unmount());
});

test('server tool activity stays inert and returns to its originating scenario', async () => {
  const view = renderWorkshop(); await flush();
  await act(async () => view.node.querySelector('[data-scenario-tab="stored_user"]').click());
  await flush();
  let finish;
  axios.post.mockImplementation(() => new Promise(resolve => { finish = resolve; }));
  const input = view.node.querySelector('textarea'); change(input, 'show my profile');
  await act(async () => input.closest('form').dispatchEvent(new Event('submit', { bubbles: true, cancelable: true })));
  await act(async () => view.node.querySelector('[data-scenario-tab="reflected"]').click());
  await act(async () => finish({ data: { response: 'Profile loaded.', toolActivity: [{
    id: 'xss-tool-0', name: 'getProfile', arguments: {},
    result: { profile: { bio: '<img id="activity-only-payload" src=x onerror=alert(1)>' } },
    timestamp: '2026-11-01T12:00:00.000Z', status: 'success', controlled: true,
  }] } }));
  await flush();
  const activityTab = () => [...view.node.querySelectorAll('[role="tab"]')]
    .find(button => button.textContent.startsWith('Tool Activity'));
  await act(async () => activityTab().click());
  expect(view.node.querySelector('[aria-label="0 recorded tool calls"]')).toBeTruthy();
  expect(view.node.textContent).not.toContain('activity-only-payload');
  await act(async () => view.node.querySelector('[data-scenario-tab="stored_user"]').click());
  await flush();
  change(view.node.querySelector('textarea'), 'retained activity draft');
  await act(async () => activityTab().click());
  expect(view.node.querySelector('[aria-label="1 recorded tool calls"]')).toBeTruthy();
  expect(view.node.textContent).toContain('Controlled/mock execution');
  expect(JSON.parse(view.node.querySelector('[aria-label="getProfile result"]').textContent).profile.bio)
    .toBe('<img id="activity-only-payload" src=x onerror=alert(1)>');
  expect(view.node.querySelector('#activity-only-payload')).toBeNull();
  await act(async () => [...view.node.querySelectorAll('[role="tab"]')]
    .find(button => button.textContent === 'Chat').click());
  expect(view.node.querySelector('textarea').value).toBe('retained activity draft');
  await act(async () => [...view.node.querySelectorAll('button')]
    .find(button => button.textContent.trim() === 'Reset conversation').click());
  expect(view.node.querySelector('[aria-label="0 recorded tool calls"]')).toBeTruthy();
  expect(view.node.textContent).not.toContain('activity-only-payload');
  act(() => view.root.unmount());
});
