import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import axios from 'axios';
import MCPWorkshop from './MCPWorkshop';
import useChangePolling from '../../hooks/useChangePolling';

let mockMcpUser = { id: 1 };
jest.mock('../../context/AuthContext', () => ({useAuth:()=>({user:mockMcpUser})}));
jest.mock('axios', () => ({ get: jest.fn(), post: jest.fn() }));
jest.mock('../../hooks/useChangePolling', () => jest.fn());
jest.mock('../../hooks/useWorkshopHeartbeat', () => jest.fn());
jest.mock('../../components/VulnerabilityTemplate', () => ({ children }) => <div>{children}</div>);
let mockJudgeRetryResult;
jest.mock('../../components/workshop/JudgeRetryButton', () => ({ onResult }) => {
  mockJudgeRetryResult = onResult;
  return null;
});
let mockWorkshopSnapshot;
jest.mock('../../context/WorkshopConfigContext', () => ({
  useWorkshopConfig: () => ({
    revision: 1,
    snapshot: mockWorkshopSnapshot,
  }),
}));

const objectiveIds = [
  'mcp_recon', 'mcp_cmd_injection', 'mcp_ssrf', 'mcp_tool_poisoning',
  'mcp_indirect_injection', 'mcp_confused_deputy', 'mcp_broken_authz',
  'mcp_secret_exposure', 'mcp_supply_chain', 'mcp_audit_gap', 'mcp_shadow_server',
];

const workshopSnapshot = (hiddenIds = []) => ({
  exercises: {
    mcp_workshop: {
      isVisible: true,
      objectives: Object.fromEntries(objectiveIds.map(id => [id, {
        isVisible: !hiddenIds.includes(id),
        label: id === 'mcp_recon' ? 'Instructor MCP discovery' : undefined,
      }])),
    },
  },
});

let root;
let node;
let pollCallback;
let solutionVersion;
let hintVersion;
let solutionResponder;
let progressPayload;
const previousActEnvironment = global.IS_REACT_ACT_ENVIRONMENT;

beforeAll(() => {
  global.IS_REACT_ACT_ENVIRONMENT = true;
});

afterAll(() => {
  global.IS_REACT_ACT_ENVIRONMENT = previousActEnvironment;
});

const deferred = () => {
  let resolve; let reject;
  const promise = new Promise((resolvePromise, rejectPromise) => { resolve = resolvePromise; reject = rejectPromise; });
  return { promise, resolve, reject };
};

const flush = async () => {
  await act(async () => {
    await Promise.resolve();
    await Promise.resolve();
  });
};

const clickButton = (label) => {
  const button = [...document.querySelectorAll('button')]
    .find((candidate) => candidate.textContent.includes(label));
  expect(button).toBeTruthy();
  act(() => button.dispatchEvent(new MouseEvent('click', { bubbles: true })));
};
const clickHelp = (kind) => {
  const button = node.querySelector(`[data-testid="${kind}-button-mcp_recon"]`);
  expect(button).toBeTruthy();
  act(() => button.dispatchEvent(new MouseEvent('click', { bubbles: true })));
};
const confirmReset = async () => {
  const dialog = document.querySelector('[role="alertdialog"]');
  expect(dialog).toBeTruthy();
  const button = [...dialog.querySelectorAll('button')]
    .find(candidate => candidate.textContent === 'Confirm reset');
  expect(button).toBeTruthy();
  act(() => button.dispatchEvent(new MouseEvent('click', { bubbles: true })));
  await flush();
};

const mountWorkshop = async () => {
  node = document.createElement('div');
  document.body.appendChild(node);
  root = createRoot(node);
  act(() => root.render(<MCPWorkshop />));
  await flush();
};

const remountWorkshop = async () => {
  act(() => root.unmount());
  node.remove();
  await mountWorkshop();
};

const exposeJudgeRetryHandler = async () => {
  axios.post.mockResolvedValueOnce({ data: {
    response: 'retry setup',
    judgments: [{ objectiveId: 'mcp_recon', verdict: 'unavailable', canRetry: true, evaluationId: 'eval-retry' }],
  } });
  clickButton('MCP Assistant');
  const input = node.querySelector('textarea');
  act(() => {
    Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, 'value').set.call(input, 'retry setup');
    input.dispatchEvent(new Event('input', { bubbles: true }));
  });
  act(() => input.closest('form').dispatchEvent(new Event('submit', { bubbles: true, cancelable: true })));
  await flush();
  expect(mockJudgeRetryResult).toEqual(expect.any(Function));
};

beforeEach(async () => {
  mockMcpUser = { id: 1 };
  solutionVersion = 'Original solution';
  hintVersion = 'Original hint';
  solutionResponder = null;
  mockJudgeRetryResult = null;
  mockWorkshopSnapshot = workshopSnapshot();
  progressPayload = { completed: [] };
  useChangePolling.mockImplementation((callback) => { pollCallback = callback; });
  axios.post.mockReset();
  axios.post.mockResolvedValue({ data: { success: true } });
  axios.get.mockImplementation((url) => {
    if (url === '/api/solutions/mcp-workshop/status') {
      return Promise.resolve({ data: { objectives: { mcp_recon: true } } });
    }
    if (url === '/api/hints/mcp_workshop/status') {
      return Promise.resolve({ data: { objectives: { mcp_recon: true } } });
    }
    if (url === '/api/workshop/mcp/progress') return Promise.resolve({ data: progressPayload });
    if (url === '/api/workshop/mcp/mode') return Promise.resolve({ data: {
      success: true, version: 1, mode: null, effectiveMode: 'vuln', defaultMode: null,
      allowedModes: ['vuln', 'fixed'], selectableModes: ['vuln', 'fixed'], fixedSupported: true,
      scope: { kind: 'chat', id: 'mcp_assistant' }, supportedObjectiveIds: objectiveIds, reason: null,
    } });
    if (url === '/api/workshop/mcp/exfil') return Promise.resolve({ data: {} });
    if (url === '/api/workshop/mcp/llm-status') return Promise.resolve({ data: { available: true } });
    if (url === '/api/workshop/mcp/tools') return Promise.resolve({ data: { tools: [] } });
    if (url === '/api/workshop/mcp/infra') return Promise.resolve({ data: {} });
    if (url === '/api/workshop/mcp/activity') return Promise.resolve({ data: { activity: [] } });
    if (url === '/api/solutions/mcp-workshop/mcp_recon') {
      if (solutionResponder) return solutionResponder();
      return Promise.resolve({ data: { solution: { title: solutionVersion, examples: [] } } });
    }
    if (url === '/api/hints/mcp_workshop/mcp_recon') {
      return Promise.resolve({ data: { hint: { title: hintVersion, hints: [hintVersion] } } });
    }
    return Promise.resolve({ data: {} });
  });

  // eslint-disable-next-line testing-library/no-render-in-setup -- this shared mount keeps the race scenarios identical.
  await mountWorkshop();
});

afterEach(() => {
  act(() => root.unmount());
  node.remove();
  document.querySelectorAll('[role="dialog"]').forEach((dialog) => dialog.remove());
  axios.get.mockReset();
  axios.post.mockReset();
  useChangePolling.mockReset();
});

test('open MCP solution and hint both refresh after a scoped revision', async () => {
  expect(node.textContent).toContain('Instructor MCP discovery');
  clickHelp('solution');
  clickHelp('hint');
  await flush();
  expect(document.body.textContent).toContain('Original solution');
  expect(document.body.textContent).toContain('Original hint');

  solutionVersion = 'Edited solution';
  hintVersion = 'Edited hint';
  await act(async () => pollCallback({}, {}, {}));

  expect(document.body.textContent).toContain('Edited solution');
  expect(document.body.textContent).toContain('Edited hint');
  expect(document.body.textContent).not.toContain('Original solution');
  expect(document.body.textContent).not.toContain('Original hint');
});

test('MCP solution uses shared help and filters embedded hints by their independent gate', async () => {
  let hintAllowed = false;
  const originalGet = axios.get.getMockImplementation();
  axios.get.mockImplementation(url => {
    if (url === '/api/hints/mcp_workshop/status') {
      return Promise.resolve({ data: { objectives: { mcp_recon: hintAllowed } } });
    }
    if (url === '/api/solutions/mcp-workshop/mcp_recon') {
      return Promise.resolve({ data: { solution: {
        title: 'MCP authored solution', difficulty: 'Easy', hints: ['GATED MCP HINT'],
        examples: [{ prompt: 'What tools do you have?', explanation: 'Read the tool list' }],
        approach: 'Ask for capabilities', tips: ['Compare the response with the tools'],
      } } });
    }
    return originalGet(url);
  });
  await act(async () => pollCallback({}, {}, {}));
  clickHelp('solution'); await flush();
  let modal = document.querySelector('[data-help-kind="solution"]');
  expect(modal).toBeTruthy();
  expect(modal.textContent).toContain('Difficulty: Easy');
  expect(modal.textContent).toContain('Ask for capabilities');
  expect(modal.textContent).toContain('Read the tool list');
  expect(modal.textContent).toContain('Compare the response with the tools');
  expect(modal.textContent).not.toContain('GATED MCP HINT');

  hintAllowed = true;
  await act(async () => pollCallback({}, {}, {}));
  modal = document.querySelector('[data-help-kind="solution"]');
  expect(modal.textContent).toContain('GATED MCP HINT');
  act(() => modal.querySelector('[data-testid="solution-example"] button').click());
  expect(node.querySelector('textarea').value).toBe('What tools do you have?');
  expect(document.querySelector('[data-help-kind="solution"]')).toBeNull();
});

test('MCP Assistant mode changes only after canonical confirmation and chat sends no client mode', async () => {
  const pendingMode = deferred();
  axios.post.mockImplementation((url) => url === '/api/workshop/mcp/mode'
    ? pendingMode.promise : Promise.resolve({ data: { response: 'Read-only practice response' } }));
  const control = node.querySelector('[data-workshop-mode-control]');
  expect(control).toBeTruthy();
  const fixed = [...control.querySelectorAll('button')].find(button => button.textContent === 'Fixed');
  act(() => fixed.dispatchEvent(new MouseEvent('click', { bubbles: true })));
  expect(axios.post).toHaveBeenCalledWith('/api/workshop/mcp/mode', { mode: 'fixed' }, expect.any(Object));
  expect(fixed.disabled).toBe(true);
  expect(node.querySelector('form textarea').disabled).toBe(true);
  await act(async () => {
    pendingMode.resolve({ data: { success: true, version: 1, mode: 'fixed', effectiveMode: 'fixed',
      defaultMode: null, allowedModes: ['vuln', 'fixed'], selectableModes: ['vuln', 'fixed'],
      fixedSupported: true, scope: { kind: 'chat', id: 'mcp_assistant' },
      supportedObjectiveIds: objectiveIds, reason: null } });
    await Promise.resolve();
  });
  expect(node.querySelector('[data-workshop-mode-control]').getAttribute('data-workshop-mode')).toBe('fixed');
  expect(node.textContent).toContain('Previous chat and tool activity are hidden');
  const input = node.querySelector('form textarea');
  act(() => {
    Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, 'value').set.call(input, 'check system status');
    input.dispatchEvent(new Event('input', { bubbles: true }));
  });
  act(() => input.closest('form').dispatchEvent(new Event('submit', { bubbles: true, cancelable: true })));
  await flush();
  const chatCall = axios.post.mock.calls.find(([url]) => url === '/api/workshop/mcp/chat');
  expect(chatCall).toBeTruthy();
  expect(chatCall[1]).toMatchObject({ message: 'check system status' });
  expect(chatCall[1]).not.toHaveProperty('mode');
});

test('hidden recon uses the visible objective total in the completed state', async () => {
  mockWorkshopSnapshot = workshopSnapshot(['mcp_recon']);
  progressPayload = { completed: objectiveIds.filter(id => id !== 'mcp_recon') };
  await remountWorkshop();

  expect(node.textContent).toContain('Objectives (10/10)');
  expect(node.textContent).toContain('10 of 10 techniques completed');
  expect(node.textContent).toContain('All 10 techniques complete — nice work!');
  expect(node.textContent).not.toContain('All 11 techniques complete');
  expect(node.textContent).not.toContain('Instructor MCP discovery');
});

test('normal qualified profile clears recon pending while retaining unqualified pending state', async () => {
  const qualifiedObjectives = new Set([
    'mcp_cmd_injection', 'mcp_confused_deputy', 'mcp_broken_authz',
    'mcp_secret_exposure', 'mcp_audit_gap', 'mcp_recon',
  ]);
  progressPayload = {
    completed: [],
    runtimeQualification: {
      mode: 'qualified_subset',
      objectives: objectiveIds.map(objectiveId => ({
        objectiveId,
        qualified: qualifiedObjectives.has(objectiveId),
      })),
    },
  };
  await remountWorkshop();

  const cards = [...node.querySelectorAll('.obj-name')].reduce((byName, name) => {
    byName[name.textContent] = name.parentElement.parentElement;
    return byName;
  }, {});
  expect(cards['Instructor MCP discovery'].querySelector('.status-badge').textContent).not.toBe('RUNTIME PENDING');
  expect(cards['Instructor MCP discovery'].textContent).not.toContain('RUNTIME PENDING');
  expect(cards['Command Injection'].querySelector('.status-badge').textContent).not.toBe('RUNTIME PENDING');
  expect(cards['SSRF via fetch_url'].querySelector('.status-badge').textContent).toBe('RUNTIME PENDING');
  expect(cards['SSRF via fetch_url'].textContent).toContain('This objective is visible, but its owner-isolated runtime and Judge path are not qualified yet.');
});

test('disabled owned runtime marks every visible objective as runtime pending', async () => {
  progressPayload = {
    completed: [],
    runtimeQualification: {
      mode: 'qualified_subset', version: 'mcp-owned-runtime-unavailable',
      objectives: objectiveIds.map(objectiveId => ({ objectiveId, qualified: false })),
    },
  };
  await remountWorkshop();

  const cards = [...node.querySelectorAll('.obj-name')].reduce((byName, name) => {
    byName[name.textContent] = name.parentElement.parentElement;
    return byName;
  }, {});
  expect(Object.keys(cards)).toHaveLength(objectiveIds.length);
  Object.values(cards).forEach((card) => {
    expect(card.querySelector('.status-badge').textContent).toBe('RUNTIME PENDING');
    expect(card.querySelector('.status-badge').textContent).not.toBe('TODO');
  });
});

test.each([
  ['SHADOW_REGISTRATION_REQUIRES_REREGISTRATION', 'then register the server again.'],
  ['HTTP_LEGACY_RECEIPT_RESET_REQUIRED', 'then retry the exercise.'],
])(
  'legacy MCP error %s points to the existing full workshop reset', async (code, nextStep) => {
    axios.post.mockRejectedValueOnce({ response: { data: { error: code } } });
    clickButton('MCP Assistant');
    const input = node.querySelector('textarea');
    act(() => {
      Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, 'value').set.call(input, 'Use the imported tool');
      input.dispatchEvent(new Event('input', { bubbles: true }));
    });
    act(() => input.closest('form').dispatchEvent(new Event('submit', { bubbles: true, cancelable: true })));
    await flush();
    expect(node.textContent).toContain(`Use Reset on this MCP workshop page, ${nextStep}`);
    expect(node.textContent).toContain('Reset clears all MCP workshop progress.');
    expect(axios.post.mock.calls.some(([url]) => url === '/api/workshop/mcp/progress/reset')).toBe(false);
  }
);

test('poll content beats an older pending request and a later manual close wins', async () => {
  const oldRequest = deferred();
  solutionResponder = () => oldRequest.promise;
  clickHelp('solution');

  solutionResponder = null;
  solutionVersion = 'Edited while pending';
  await act(async () => pollCallback({}, {}, {}));
  expect(document.body.textContent).toContain('Edited while pending');

  await act(async () => {
    oldRequest.resolve({ data: { solution: { title: 'Stale manual result', examples: [] } } });
    await Promise.resolve();
  });
  expect(document.body.textContent).not.toContain('Stale manual result');

  const latePoll = deferred();
  solutionResponder = () => latePoll.promise;
  let pollPromise;
  act(() => { pollPromise = pollCallback({}, {}, {}); });
  await flush();
  clickButton('Close');
  let rejection;
  await act(async () => {
    latePoll.resolve({ data: { solution: { title: 'Must stay closed', examples: [] } } });
    try { await pollPromise; } catch (error) { rejection = error; }
  });
  expect(rejection).toMatchObject({ code: 'STALE_RECONCILIATION' });
  expect(document.body.textContent).not.toContain('Must stay closed');
});

test('unavailable judge feedback is escaped and candidate hits do not grant optimistic credit', async () => {
  axios.post.mockResolvedValue({ data: {
    success: true,
    response: 'Catalog inspected.',
    objectivesHit: ['mcp_recon'],
    objectiveCandidates: ['mcp_recon'],
    completedObjectives: [],
    judgments: [{
      objectiveId: 'mcp_recon',
      verdict: 'unavailable',
      explanation: '<img src=x onerror="window.__mcpJudgeInjected=true"> Please retry.',
    }],
  } });
  clickButton('MCP Assistant');
  const textarea = node.querySelector('textarea');
  const setter = Object.getOwnPropertyDescriptor(window.HTMLTextAreaElement.prototype, 'value').set;
  act(() => {
    setter.call(textarea, 'What tools do you have?');
    textarea.dispatchEvent(new Event('input', { bubbles: true }));
  });
  await act(async () => {
    textarea.closest('form').dispatchEvent(new Event('submit', { bubbles: true, cancelable: true }));
  });
  await flush();

  expect(node.textContent).toContain('Instructor MCP discovery: evaluation unavailable.');
  expect(node.textContent).toContain('<img src=x onerror="window.__mcpJudgeInjected=true">');
  expect(node.querySelector('[role="alert"]')).not.toBeNull();
  expect(node.querySelector('img[src="x"]')).toBeNull();
  expect(node.querySelector('.objective-complete')).toBeNull();
});

test('reset fences old chat responses without clearing a newer pending request', async () => {
  const old = deferred();
  const fresh = deferred();
  let calls = 0;
  axios.post.mockImplementation(() => (++calls === 1 ? old.promise : fresh.promise));
  const send = async (message) => {
    const input = node.querySelector('textarea');
    act(() => {
      Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, 'value').set.call(input, message);
      input.dispatchEvent(new Event('input', { bubbles: true }));
    });
    act(() => input.closest('form').dispatchEvent(new Event('submit', { bubbles: true, cancelable: true })));
    await flush();
  };
  await send('old request');
  const signal = axios.post.mock.calls[0][2].signal;
  clickButton('Reset conversation');
  expect(signal.aborted).toBe(true);
  await send('new request');
  await act(async () => old.resolve({ data: { response: 'STALE RESPONSE', completedObjectives: ['mcp_recon'] } }));
  expect(node.textContent).not.toContain('STALE RESPONSE');
  expect(node.textContent).toContain('Thinking…');
  await act(async () => fresh.resolve({ data: { response: 'CURRENT RESPONSE' } }));
  expect(node.textContent).toContain('CURRENT RESPONSE');
  expect(node.textContent).not.toContain('Thinking…');
});

test('conversation clear cannot release a pending full reset or admit another chat', async () => {
  const reset = deferred();
  axios.post.mockImplementation((url) => url.endsWith('/progress/reset')
    ? reset.promise : Promise.resolve({ data: { response: 'NEW CHAT' } }));
  {
    const resetButton = [...node.querySelectorAll('button')].find(button => button.textContent.trim() === 'Reset');
    expect(resetButton).toBeTruthy();
    act(() => resetButton.dispatchEvent(new MouseEvent('click', { bubbles: true })));
    expect(axios.post).not.toHaveBeenCalledWith('/api/workshop/mcp/progress/reset');
    await confirmReset();
    clickButton('Reset conversation');
    act(() => resetButton.dispatchEvent(new MouseEvent('click', { bubbles: true })));
    const input = node.querySelector('textarea');
    act(() => {
      Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, 'value').set.call(input, 'new chat');
      input.dispatchEvent(new Event('input', { bubbles: true }));
    });
    act(() => input.closest('form').dispatchEvent(new Event('submit', { bubbles: true, cancelable: true })));
    expect(axios.post.mock.calls.map(([url]) => url)).toEqual(['/api/workshop/mcp/progress/reset']);
    expect(node.textContent).toContain('Thinking…');
    await act(async () => reset.resolve({ data: { success: true } }));
    act(() => input.closest('form').dispatchEvent(new Event('submit', { bubbles: true, cancelable: true })));
    await flush();
    expect(node.textContent).toContain('NEW CHAT');
  }
});

test('MCP reset can be cancelled before any durable mutation', async () => {
  const resetButton = [...node.querySelectorAll('button')]
    .find(button => button.textContent.trim() === 'Reset');
  act(() => resetButton.click());
  const dialog = document.querySelector('[role="alertdialog"]');
  expect(dialog.textContent).toContain('Reset all MCP workshop progress?');
  expect(axios.post.mock.calls.some(([url]) => url === '/api/workshop/mcp/progress/reset')).toBe(false);
  act(() => [...dialog.querySelectorAll('button')]
    .find(button => button.textContent === 'Cancel').click());
  expect(document.querySelector('[role="alertdialog"]')).toBeNull();
  expect(axios.post.mock.calls.some(([url]) => url === '/api/workshop/mcp/progress/reset')).toBe(false);
});

test('incomplete reset refreshes authoritative progress even though the request failed', async () => {
  axios.post.mockRejectedValue({ response: { data: { code: 'RESET_INCOMPLETE' } } });
  const prior = axios.get.mock.calls.filter(([url]) => url === '/api/workshop/mcp/progress').length;
  {
    const button = [...node.querySelectorAll('button')].find(candidate => candidate.textContent.trim() === 'Reset');
    act(() => button.dispatchEvent(new MouseEvent('click', { bubbles: true })));
    await confirmReset();
    expect(axios.get.mock.calls.filter(([url]) => url === '/api/workshop/mcp/progress').length).toBeGreaterThan(prior);
    expect(node.textContent).not.toContain('Thinking…');
    expect(document.querySelector('[role="alertdialog"]').textContent).toContain('Reset cleanup is incomplete');
  }
});

test.each(['resolve', 'reject'])('reset fences Inspector %s while a newer chat remains pending', async outcome => {
  const old = deferred(); const fresh = deferred();
  axios.post.mockImplementation(url => url.endsWith('/jsonrpc') ? old.promise : url.endsWith('/chat') ? fresh.promise : Promise.resolve({ data: {} }));
  {
    clickButton('Raw MCP Inspector');
    act(() => [...node.querySelectorAll('button')].find(b => b.textContent.trim() === 'Send').click()); await flush();
    act(() => [...node.querySelectorAll('button')].find(b => b.textContent.trim() === 'Reset').click()); await confirmReset();
    clickButton('MCP Assistant');
    const input = node.querySelector('textarea');
    act(() => { Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, 'value').set.call(input, 'New chat'); input.dispatchEvent(new Event('input', { bubbles: true })); });
    act(() => input.closest('form').dispatchEvent(new Event('submit', { bubbles: true, cancelable: true }))); await flush();
    if (outcome === 'resolve') old.resolve({ data: { result: 'STALE INSPECTOR' } }); else old.reject(new Error('STALE INSPECTOR'));
    await flush();
    expect(node.textContent).toContain('Thinking…');
    clickButton('Raw MCP Inspector'); expect(node.textContent).not.toContain('STALE INSPECTOR');
    clickButton('MCP Assistant'); fresh.resolve({ data: { response: 'CURRENT CHAT' } }); await flush();
    expect(node.textContent).toContain('CURRENT CHAT');
  }
});

test('unmount aborts Inspector and suppresses its late failure notice', async () => {
  const pending = deferred(); axios.post.mockReturnValueOnce(pending.promise);
  clickButton('Raw MCP Inspector');
  act(() => [...node.querySelectorAll('button')].find(b => b.textContent.trim() === 'Send').click()); await flush();
  const signal = axios.post.mock.calls[0][2].signal;
  await remountWorkshop(); expect(signal.aborted).toBe(true);
  const { toast } = require('react-toastify'); const notice = jest.spyOn(toast, 'error').mockImplementation(() => {});
  pending.reject(new Error('OLD INSPECTOR FAILURE')); await flush();
  expect(notice).not.toHaveBeenCalled(); notice.mockRestore();
  clickButton('Raw MCP Inspector'); expect(node.textContent).not.toContain('OLD INSPECTOR FAILURE');
  axios.post.mockResolvedValueOnce({ data: { result: 'CURRENT INSPECTOR' } });
  act(() => [...node.querySelectorAll('button')].find(b => b.textContent.trim() === 'Send').click()); await flush();
  expect(node.textContent).toContain('CURRENT INSPECTOR');
});

test('Judge retry keeps current feedback and refreshes authoritative state', async () => {
  await exposeJudgeRetryHandler();
  const prior = axios.get.getMockImplementation();
  axios.get.mockImplementation(url => url === '/api/workshop/mcp/exfil'
    ? Promise.resolve({ data: { state: { auditEnabled: false } } }) : prior(url));
  const { toast } = require('react-toastify');
  const success = jest.spyOn(toast, 'success').mockImplementation(() => {});
  try {
    const controller = new AbortController();
    await act(async () => mockJudgeRetryResult({
      completed: true,
      judgments: [{ objectiveId: 'mcp_recon', verdict: 'fail', explanation: 'retry feedback' }],
    }, { signal: controller.signal }));
    expect(node.textContent).toContain('retry feedback');
    expect(node.textContent).toContain('Target logging DISABLED');
    expect(success).toHaveBeenCalledWith('Objective evaluation passed.');
  } finally { success.mockRestore(); }
});

test('Judge retry cannot restore an exfil capture after full reset', async () => {
  await exposeJudgeRetryHandler();
  const pendingExfil = deferred();
  const pendingProgress = deferred();
  let exfilCalls = 0;
  let progressCalls = 0;
  const prior = axios.get.getMockImplementation();
  axios.get.mockImplementation(url => {
    if (url === '/api/workshop/mcp/exfil') {
      exfilCalls += 1;
      return exfilCalls === 1 ? Promise.resolve({ data: { state: { auditEnabled: false } } }) : exfilCalls === 2 ? pendingExfil.promise : Promise.resolve({ data: {} });
    }
    if (url === '/api/workshop/mcp/progress') {
      progressCalls += 1;
      return progressCalls === 2 ? pendingProgress.promise : Promise.resolve({ data: { completed: progressCalls === 1 ? ['mcp_recon'] : [] } });
    }
    return prior(url);
  });
  {
    const retry = mockJudgeRetryResult({ completed: false, judgments: [], completedObjectives: ['mcp_recon'] }, { signal: new AbortController().signal });
    await flush();
    expect(node.textContent).toContain('Target logging DISABLED');
    expect(node.textContent).toContain('Objectives (1/11)');
    await retry;
    const retainedRetry = mockJudgeRetryResult;
    let staleRetry;
    act(() => { staleRetry = retainedRetry({ completed: true, judgments: [] }, { signal: new AbortController().signal }); });
    await flush();
    expect(exfilCalls).toBe(2);
    expect(progressCalls).toBe(2);
    act(() => [...node.querySelectorAll('button')].find(button => button.textContent.trim() === 'Reset').click());
    await confirmReset();
    await act(async () => {
      pendingExfil.resolve({ data: { state: { auditEnabled: false } } });
      pendingProgress.resolve({ data: { completed: ['mcp_recon'] } });
      await staleRetry;
    });
    expect(node.textContent).not.toContain('Target logging DISABLED');
    expect(node.textContent).toContain('Objectives (0/11)');
  }
});

test('Judge retry suppresses retained callbacks after abort, unmount, and token change', async () => {
  const oldToken = localStorage.getItem('token');
  localStorage.setItem('token', 'mcp-retry-token-before');
  try {
    await remountWorkshop();
    await exposeJudgeRetryHandler();
    const controller = new AbortController();
    controller.abort();
    await act(async () => mockJudgeRetryResult({
      completed: false,
      judgments: [{ objectiveId: 'mcp_recon', verdict: 'fail', explanation: 'ABORTED_FEEDBACK' }],
    }, { signal: controller.signal }));
    expect(node.textContent).not.toContain('ABORTED_FEEDBACK');

    localStorage.setItem('token', 'mcp-retry-token-after');
    await act(async () => mockJudgeRetryResult({
      completed: false,
      judgments: [{ objectiveId: 'mcp_recon', verdict: 'fail', explanation: 'TOKEN_CHANGED_FEEDBACK' }],
    }, { signal: new AbortController().signal }));
    expect(node.textContent).not.toContain('TOKEN_CHANGED_FEEDBACK');

    localStorage.setItem('token', 'mcp-retry-token-before');
    const retainedAfterOwnerChange = mockJudgeRetryResult;
    mockMcpUser = { id: 2 };
    act(() => root.render(<MCPWorkshop />));
    await flush();
    const retryCallsBeforeOwnerCallback = axios.get.mock.calls.filter(([url]) => (
      url === '/api/workshop/mcp/progress' || url === '/api/workshop/mcp/exfil'
    )).length;
    await act(async () => retainedAfterOwnerChange({
      completed: false,
      judgments: [{ objectiveId: 'mcp_recon', verdict: 'fail', explanation: 'OWNER_CHANGED_FEEDBACK' }],
    }, { signal: new AbortController().signal }));
    expect(node.textContent).not.toContain('OWNER_CHANGED_FEEDBACK');
    expect(axios.get.mock.calls.filter(([url]) => (
      url === '/api/workshop/mcp/progress' || url === '/api/workshop/mcp/exfil'
    )).length).toBe(retryCallsBeforeOwnerCallback);

    localStorage.setItem('token', 'mcp-retry-token-before');
    const retained = mockJudgeRetryResult;
    const conversationCalls = axios.get.mock.calls.filter(([url]) => (
      url === '/api/workshop/mcp/progress' || url === '/api/workshop/mcp/exfil'
    )).length;
    clickButton('Reset conversation');
    await act(async () => retained({
      completed: false,
      judgments: [{ objectiveId: 'mcp_recon', verdict: 'fail', explanation: 'CONVERSATION_RESET_FEEDBACK' }],
    }, { signal: new AbortController().signal }));
    expect(node.textContent).not.toContain('CONVERSATION_RESET_FEEDBACK');
    expect(axios.get.mock.calls.filter(([url]) => (
      url === '/api/workshop/mcp/progress' || url === '/api/workshop/mcp/exfil'
    )).length).toBe(conversationCalls);

    await exposeJudgeRetryHandler();
    const pending = deferred();
    axios.get.mockImplementation(url => url === '/api/workshop/mcp/exfil' ? pending.promise : (
      url === '/api/workshop/mcp/progress' ? Promise.resolve({ data: { completed: [] } }) : Promise.resolve({ data: {} })
    ));
    const abortController = new AbortController();
    const aborting = mockJudgeRetryResult({ completed: false, judgments: [] }, { signal: abortController.signal });
    await flush();
    abortController.abort();
    await act(async () => pending.resolve({ data: { state: { auditEnabled: false } } }));
    await aborting;
    expect(node.textContent).not.toContain('Target logging DISABLED');

    act(() => root.unmount());
    await act(async () => retained({
      completed: false,
      judgments: [{ objectiveId: 'mcp_recon', verdict: 'fail', explanation: 'UNMOUNTED_FEEDBACK' }],
    }, { signal: new AbortController().signal }));
    expect(node.textContent).not.toContain('UNMOUNTED_FEEDBACK');
  } finally {
    if (oldToken === null) localStorage.removeItem('token'); else localStorage.setItem('token', oldToken);
  }
});


test('audit lesson and observed disabled-log panel distinguish target telemetry from retained platform evidence', async () => {
  expect(node.textContent).toContain('Target-Private Audit Logging');
  expect(node.textContent).toContain('Disable target-private logging or clear its entries; platform history remains.');
  expect(node.textContent).toContain('The platform retains the logging-control action and immutable run evidence.');
  const priorGet = axios.get.getMockImplementation();
  axios.get.mockImplementation(url => url === '/api/workshop/mcp/exfil'
    ? Promise.resolve({ data: { state: { auditEnabled: false } } }) : priorGet(url));
  await remountWorkshop();
  expect(node.textContent).toContain('Target logging DISABLED');
  expect(node.textContent).toContain('The platform retains the logging-control action, earlier activity and immutable run evidence.');
  expect(node.textContent).not.toContain('action itself left no record');
  expect(node.textContent).not.toContain('so your actions go unrecorded');
  expect(node.textContent).not.toContain('with no authorization and no record');
});

test.each(['current', 'reset', 'token'])('initial capture read respects %s lifecycle', async mode => {
  const pending = deferred(), prior = axios.get.getMockImplementation();
  axios.get.mockImplementation((url, ...args) => url === '/api/workshop/mcp/exfil' ? pending.promise : prior(url, ...args));
  await remountWorkshop();
  const oldToken = localStorage.getItem('token');
  try {
    if (mode === 'reset') {
      axios.post.mockResolvedValueOnce({ data: { success: true } });
      act(() => [...node.querySelectorAll('button')].find(b => b.textContent.trim() === 'Reset').click());
      await confirmReset();
    }
    if (mode === 'token') localStorage.setItem('token', 'new-owner-token');
    await act(async () => pending.resolve({ data: {
      state: { auditEnabled: false }, deliveredMail: [{ to: 'owned@example.test', subject: 'OLD_CAPTURE_SUBJECT', snippet: 'Controlled retained mail' }],
    } }));
    await flush();
    if (mode === 'current') {
      expect(node.textContent).toContain('Target logging DISABLED');
      expect(node.textContent).toContain('OLD_CAPTURE_SUBJECT');
    } else {
      expect(node.textContent).not.toContain('Target logging DISABLED');
      expect(node.textContent).not.toContain('OLD_CAPTURE_SUBJECT');
    }
  } finally { if (oldToken === null) localStorage.removeItem('token'); else localStorage.setItem('token', oldToken); }
});

test.each(['mount', 'poll'])('%s progress cannot publish after owner changes', async origin => {
  const pending = deferred(), prior = axios.get.getMockImplementation();
  axios.get.mockImplementation((url, ...args) => url === '/api/workshop/mcp/progress' ? pending.promise : prior(url, ...args));
  let work;
  if (origin === 'mount') await remountWorkshop();
  else act(() => { work = pollCallback(); });
  mockMcpUser = { id: 2 };
  axios.get.mockImplementation(prior); // Replacement owner's fresh request must not reuse A's deferred response.
  act(() => root.render(<MCPWorkshop />));
  await act(async () => { pending.resolve({ data: { completed: [...objectiveIds] } }); await work; });
  await flush();
  expect(node.textContent).toContain('0 of 11 techniques completed');
  expect(node.textContent).not.toContain('All 11 techniques complete');
});


test.each([['progress','current'],['exfil','current'],['progress','reset'],['exfil','unmount']])('retry %s failure after %s',async(loader,lifetime)=>{
  await exposeJudgeRetryHandler();const pending=deferred(),prior=axios.get.getMockImplementation();let hold=true;
  axios.get.mockImplementation((url,...args)=>url===`/api/workshop/mcp/${loader}`&&hold?(hold=false,pending.promise):prior(url,...args));
  const {toast}=require('react-toastify');const warning=jest.spyOn(toast,'warning').mockImplementation(()=>{}),success=jest.spyOn(toast,'success').mockImplementation(()=>{});
  try{
    let work;act(()=>{work=mockJudgeRetryResult({completed:true,judgments:[]},{signal:new AbortController().signal});});await flush();
    if(lifetime==='reset'){act(()=>[...node.querySelectorAll('button')].find(b=>b.textContent.trim()==='Reset').click());await confirmReset();}
    if(lifetime==='unmount')act(()=>root.unmount());
    warning.mockClear();success.mockClear();
    await act(async()=>{pending.reject(new Error('503'));await work;});
    expect(success).not.toHaveBeenCalledWith('Objective evaluation passed.');
    if(lifetime==='current')expect(warning).toHaveBeenCalledWith('Evaluation finished, but progress or captured effects could not be refreshed.');
    else expect(warning).not.toHaveBeenCalled();
  }finally{warning.mockRestore();success.mockRestore();}
});

const sendSessionChat = async text => {
  clickButton('MCP Assistant');
  const input = node.querySelector('textarea');
  act(() => { Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, 'value').set.call(input, text); input.dispatchEvent(new Event('input', { bubbles: true })); });
  act(() => input.closest('form').dispatchEvent(new Event('submit', { bubbles: true, cancelable: true })));
  await flush();
};
const replaceSession = async (token, id) => {
  localStorage.setItem('token', token); mockMcpUser = { id };
  act(() => root.render(<MCPWorkshop />)); await flush();
};
test('owner replacement rejects old chat immediately and loads current progress/history', async () => {
  const oldToken = localStorage.getItem('token'), pending = deferred();
  try {
    axios.post.mockReturnValueOnce(pending.promise); await sendSessionChat('OLD_CHAT_PENDING');
    localStorage.setItem('token', 'session-b');
    await act(async () => pending.resolve({ data: { response: 'OLD_PRIVATE_RESPONSE', completedObjectives: ['mcp_recon'] } }));
    expect(node.textContent).not.toContain('OLD_PRIVATE_RESPONSE');
    progressPayload = { completed: ['mcp_ssrf'] }; await replaceSession('session-b', 2);
    expect(node.textContent).not.toContain('OLD_CHAT_PENDING'); expect(node.textContent).toContain('1 of 11');
    axios.post.mockResolvedValueOnce({ data: { response: 'CURRENT_OWNER_RESPONSE' } }); await sendSessionChat('CURRENT_OWNER_QUESTION');
    expect(node.textContent).toContain('CURRENT_OWNER_RESPONSE');
  } finally { if (oldToken === null) localStorage.removeItem('token'); else localStorage.setItem('token', oldToken); }
});
test('old reset cannot erase B transcript or unlock its pending request; A-B-A never resurrects reset', async () => {
  const oldToken = localStorage.getItem('token'), reset = deferred(), chat = deferred();
  try {
    axios.post.mockReturnValueOnce(reset.promise); act(() => [...node.querySelectorAll('button')].find(b => b.textContent.trim() === 'Reset').click()); await confirmReset();
    progressPayload = { completed: ['mcp_ssrf'] }; await replaceSession('session-b', 2);
    axios.post.mockReturnValueOnce(chat.promise); await sendSessionChat('B_PENDING_QUESTION');
    await act(async () => reset.resolve({ data: { success: true } }));
    expect(node.textContent).toContain('B_PENDING_QUESTION'); expect(node.querySelector('textarea').disabled).toBe(true);
    await act(async () => chat.resolve({ data: { response: 'B_FINAL_ANSWER' } })); expect(node.textContent).toContain('B_FINAL_ANSWER');
    await replaceSession('session-a',1); const staleReset = deferred(); axios.post.mockReturnValueOnce(staleReset.promise); act(() => [...node.querySelectorAll('button')].find(b => b.textContent.trim() === 'Reset').click()); await confirmReset();
    await replaceSession('session-b',2); await replaceSession('session-a',1);
    axios.post.mockResolvedValueOnce({data:{response:'NEW_A_ANSWER'}}); await sendSessionChat('NEW_A_QUESTION');
    await act(async()=>staleReset.resolve({data:{success:true}})); expect(node.textContent).toContain('NEW_A_QUESTION');
  } finally { if(oldToken===null)localStorage.removeItem('token');else localStorage.setItem('token',oldToken); }
});
test('storage becoming unavailable fails closed for pending chat and new mutations', async () => {
  const pending = deferred(); axios.post.mockReturnValueOnce(pending.promise); await sendSessionChat('PENDING_STORAGE_CHAT');
  const storage = jest.spyOn(Storage.prototype, 'getItem').mockImplementation(() => { throw new DOMException('Storage blocked', 'SecurityError'); });
  try {
    await act(async () => pending.resolve({ data: { response: 'UNTRUSTED_AFTER_STORAGE_FAILURE' } }));
    expect(node.textContent).not.toContain('UNTRUSTED_AFTER_STORAGE_FAILURE');
    const posts = axios.post.mock.calls.length;
    act(() => [...node.querySelectorAll('button')].find(b => b.textContent.trim() === 'Reset').click());
    await flush(); expect(axios.post.mock.calls.length).toBe(posts);
  } finally { storage.mockRestore(); }
});
