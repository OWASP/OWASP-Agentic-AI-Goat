jest.mock('../context/AuthContext', () => { const user = { id: 1 }; return { useAuth: () => ({ user }) }; });
import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import { MemoryRouter, useNavigate } from 'react-router-dom';
import axios from 'axios';
import CTFChallenge, { projectCtfLessonState } from './CTFChallenge';

jest.mock('axios', () => ({ get: jest.fn(), post: jest.fn() }));

const stage = {
  id: 5,
  stage_number: 5,
  stage_name: 'Feedback fixture',
  stage_description: 'Controlled grading feedback stage',
  difficulty: 'hard',
  ai_guardian_name: 'Fixture Guardian',
  level_score: 400,
  adaptive_mode: 'none',
};

async function flush() {
  await act(async () => {
    await Promise.resolve();
    await Promise.resolve();
    await Promise.resolve();
  });
}

async function renderStartedChallenge({ attemptsSoFar = 1, challengeStage = stage, hintsAvailable = false, startResponse } = {}) {
  axios.post.mockResolvedValueOnce(startResponse || {
    data: {
      stage: challengeStage,
      alreadyStarted: true,
      attemptsSoFar,
      hintsAvailable,
      hintsUsed: 0,
      hintPenaltyTotal: 0,
      purchasedHints: [],
    },
  });
  axios.get.mockResolvedValueOnce({
    data: {
      config: {
        ctf_show_attempt_counter: 'true',
        ctf_hint_gating_attempts: '3',
        ctf_hint_cost_1: '15',
      },
    },
  });

  const node = document.createElement('div');
  document.body.appendChild(node);
  const root = createRoot(node);
  let navigate;
  function NavigationCapture() {
    navigate = useNavigate();
    return null;
  }
  act(() => {
    root.render(
      <MemoryRouter
        initialEntries={[{ pathname: '/ctf/challenge', state: { stage: challengeStage } }]}
        future={{ v7_startTransition: true, v7_relativeSplatPath: true }}
      >
        <NavigationCapture />
        <CTFChallenge />
      </MemoryRouter>,
    );
  });
  await flush();
  return { node, root, navigateToStage: nextStage => navigate('/ctf/challenge', { state: { stage: nextStage } }) };
}

async function submitAttempt(node, payload = 'controlled learner prompt') {
  const textarea = node.querySelector('textarea');
  await act(async () => {
    Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, 'value').set.call(textarea, payload);
    textarea.dispatchEvent(new Event('input', { bubbles: true }));
  });
  await act(async () => {
    textarea.closest('form').dispatchEvent(new Event('submit', { bubbles: true, cancelable: true }));
  });
  await flush();
}

beforeEach(() => {
  global.IS_REACT_ACT_ENVIRONMENT = true;
  Element.prototype.scrollIntoView = jest.fn();
  localStorage.clear();
  localStorage.setItem('token', 'owner-token');
  axios.get.mockReset();
  axios.post.mockReset();
});

afterEach(() => {
  document.body.innerHTML = '';
  jest.restoreAllMocks();
});

test.each([
  ['unavailable', 'Grading is temporarily unavailable. Your response was saved, but no completion credit was awarded.'],
  ['inconclusive', 'The Judge could not verify completion from this response. No completion credit was awarded.'],
])('shows the learner-visible response and %s no-credit message from an actual submission', async (verdict, message) => {
  const { node, root } = await renderStartedChallenge();
  axios.post.mockResolvedValueOnce({
    data: {
      success: false,
      judgment: { verdict },
      aiResponse: 'VISIBLE_FIXTURE_VALUE',
      attemptNumber: 2,
      hintsAvailable: false,
      hintsUsed: 0,
      hintPenaltyTotal: 0,
      message,
    },
  });

  await submitAttempt(node);

  expect(axios.post).toHaveBeenNthCalledWith(
    2,
    '/api/ctf/stage/5/attempt',
    expect.objectContaining({ payload: 'controlled learner prompt' }),
    expect.objectContaining({ headers: { Authorization: 'Bearer owner-token' }, signal: expect.any(AbortSignal) }),
  );
  expect(node.textContent).toContain('VISIBLE_FIXTURE_VALUE');
  expect(node.textContent).toContain(message);
  expect(node.textContent).toContain('2Attempts Made');

  act(() => root.unmount());
});

test('reconciles a counted 503 attempt and unlocks hints from the known gate without claiming it was uncounted', async () => {
  jest.spyOn(console, 'error').mockImplementation(() => {});
  const { node, root } = await renderStartedChallenge({ attemptsSoFar: 2 });
  axios.post.mockRejectedValueOnce({
    response: {
      status: 503,
      data: {
        error: 'AI system temporarily unavailable. Please try again.',
        attemptNumber: 3,
        judgment: { verdict: 'unavailable' },
      },
    },
  });

  await submitAttempt(node);

  expect(node.textContent).toContain('Attempt 3 was recorded, but no completion credit was awarded.');
  expect(node.textContent).not.toContain('not counted');
  expect(node.textContent).toContain('3Attempts Made');
  expect(node.textContent).toContain('Unlock Hint 1');
  expect(node.textContent).not.toContain('Hints unlock after 3 attempts.');

  act(() => root.unmount());
});

test('renders only the exact categorical lesson-state contract in the existing stage information area', async () => {
  const adaptiveStage = { ...stage, id: 8, stage_number: 8, adaptive_mode: 'technique' };
  const { node, root } = await renderStartedChallenge({ challengeStage: adaptiveStage });
  axios.post.mockResolvedValueOnce({ data: {
    success: false, blocked: true, reason: 'This approach has been blocked.', attemptNumber: 2,
    lessonState: {
      input_guard_observed: false,
      reviewer_observed: false,
      category_consumed: false,
      category_reuse_blocked: true,
      shared_similarity_blocked: false,
    },
  } });
  await submitAttempt(node);
  expect(node.textContent).toContain('Technique reuse blockedObserved');
  expect(node.textContent).not.toContain('Output reviewer observed');
  expect(node.textContent).not.toContain('PRIVATE');
  act(() => root.unmount());
});

test('rejects malformed, extra-key and non-boolean lesson projections', () => {
  const valid = {
    input_guard_observed: true, reviewer_observed: false, category_consumed: false,
    category_reuse_blocked: false, shared_similarity_blocked: false,
  };
  expect(projectCtfLessonState(valid)).toEqual(valid);
  expect(projectCtfLessonState({ ...valid, rawModel: 'PRIVATE' })).toBeNull();
  expect(projectCtfLessonState({ ...valid, reviewer_observed: 'true' })).toBeNull();
  expect(projectCtfLessonState(null)).toBeNull();
});

test('uses the fixed-practice endpoint with an isolated, unscored transcript', async () => {
  const { node, root } = await renderStartedChallenge({ attemptsSoFar: 1 });
  const fixed = [...node.querySelectorAll('button')].find((button) => button.textContent === 'Fixed practice');
  await act(async () => fixed.click());
  expect(node.textContent).toContain('Fixed practice — unscored.');
  expect(node.textContent).not.toContain('Hints unlock after');

  axios.post.mockResolvedValueOnce({ data: {
    response: 'The fixed guardian declined the request.', mode: 'fixed', practice: true,
    unscored: true, scoringEligible: false, protectedContextIncluded: false, serverSecretProvided: false,
  } });
  await submitAttempt(node, 'fixed lane prompt');

  expect(axios.post).toHaveBeenLastCalledWith(
    '/api/ctf/stage/5/practice',
    expect.objectContaining({ payload: 'fixed lane prompt', sessionToken: expect.any(String) }),
    expect.objectContaining({ headers: { Authorization: 'Bearer owner-token' }, signal: expect.any(AbortSignal) }),
  );
  expect(axios.post.mock.calls.filter(([url]) => url.endsWith('/attempt'))).toHaveLength(0);
  expect(node.textContent).toContain('The fixed guardian declined the request.');
  expect(node.textContent).toContain('protected context withheld, server secret withheld, and scoring disabled');
  expect(node.textContent).not.toContain('Attempts Made');

  const vulnerable = [...node.querySelectorAll('button')].find((button) => button.textContent === 'Vulnerable challenge');
  await act(async () => vulnerable.click());
  expect(node.textContent).not.toContain('The fixed guardian declined the request.');
  expect(node.textContent).toContain('Hello! I am Fixture Guardian');
  expect(node.textContent).toContain('1Attempts Made');
  act(() => root.unmount());
});

test('does not publish a stale fixed-practice response after the authenticated session changes', async () => {
  const { node, root } = await renderStartedChallenge();
  const fixed = [...node.querySelectorAll('button')].find((button) => button.textContent === 'Fixed practice');
  await act(async () => fixed.click());
  let resolvePractice;
  axios.post.mockImplementationOnce(() => new Promise((resolve) => { resolvePractice = resolve; }));
  await submitAttempt(node, 'private fixed prompt');
  localStorage.setItem('token', 'replacement-owner-token');
  await act(async () => {
    resolvePractice({ data: {
      response: 'STALE_FIXED_REPLY', mode: 'fixed', practice: true,
      unscored: true, scoringEligible: false, protectedContextIncluded: false, serverSecretProvided: false,
    } });
    await Promise.resolve();
  });
  expect(node.textContent).not.toContain('STALE_FIXED_REPLY');
  expect(node.textContent).not.toContain('Fixed response confirmed');
  expect(axios.post.mock.calls.filter(([url]) => url.endsWith('/attempt'))).toHaveLength(0);
  act(() => root.unmount());
});

test('holds the selected fixed lane while its request is in flight', async () => {
  const { node, root } = await renderStartedChallenge();
  const fixed = [...node.querySelectorAll('button')].find((button) => button.textContent === 'Fixed practice');
  await act(async () => fixed.click());
  let resolvePractice;
  axios.post.mockImplementationOnce(() => new Promise((resolve) => { resolvePractice = resolve; }));
  await submitAttempt(node, 'fixed prompt in flight');
  const vulnerable = [...node.querySelectorAll('button')].find((button) => button.textContent === 'Vulnerable challenge');
  expect(vulnerable.disabled).toBe(true);
  await act(async () => vulnerable.click());
  await act(async () => {
    resolvePractice({ data: {
      response: 'FIXED_LANE_REPLY', mode: 'fixed', practice: true,
      unscored: true, scoringEligible: false, protectedContextIncluded: false, serverSecretProvided: false,
    } });
    await Promise.resolve();
  });
  expect(node.textContent).toContain('FIXED_LANE_REPLY');
  expect(node.textContent).not.toContain('Hello! I am Fixture Guardian');
  act(() => root.unmount());
});

test('a success arriving after unmount cannot schedule a redirect', async () => {
  const { node, root } = await renderStartedChallenge();
  let resolveAttempt;
  axios.post.mockImplementationOnce(() => new Promise(resolve => { resolveAttempt = resolve; }));
  await submitAttempt(node);
  act(() => root.unmount());
  const timer = jest.spyOn(global, 'setTimeout');
  await act(async () => {
    resolveAttempt({ data: { success: true, attemptNumber: 2, message: 'STALE_SUCCESS' } });
    await Promise.resolve();
  });
  expect(timer.mock.calls.filter(([, delay]) => delay === 3000)).toHaveLength(0);
});

test('a previous stage reply cannot change the newly opened stage', async () => {
  const { node, root, navigateToStage } = await renderStartedChallenge();
  let resolveAttempt;
  axios.post.mockImplementationOnce(() => new Promise(resolve => { resolveAttempt = resolve; }));
  await submitAttempt(node);
  const nextStage = { ...stage, id: 6, stage_number: 6, stage_name: 'Replacement stage' };
  axios.post.mockResolvedValueOnce({ data: { stage: nextStage, attemptsSoFar: 0 } });
  axios.get.mockResolvedValueOnce({ data: { config: {} } });
  await act(async () => navigateToStage(nextStage));
  await flush();
  const timer = jest.spyOn(global, 'setTimeout');
  await act(async () => {
    resolveAttempt({ data: { success: true, aiResponse: 'STALE_STAGE', attemptNumber: 99 } });
    await Promise.resolve();
  });
  expect(node.textContent).toContain('Replacement stage');
  expect(node.textContent).not.toContain('STALE_STAGE');
  expect(timer.mock.calls.filter(([, delay]) => delay === 3000)).toHaveLength(0);
  act(() => root.unmount());
});

test.each(['success', 'unavailable'])('ignores a stale owner %s reply before an auth rerender', async outcome => {
  const { node, root } = await renderStartedChallenge();
  let resolveAttempt, rejectAttempt;
  axios.post.mockImplementationOnce(() => new Promise((resolve, reject) => {
    resolveAttempt = resolve; rejectAttempt = reject;
  }));
  await submitAttempt(node);
  // A token-observing render now starts replacement initialization; keep it pending.
  axios.post.mockImplementationOnce(() => new Promise(() => {}));
  localStorage.setItem('token', 'replacement-owner-token');
  const timer = jest.spyOn(global, 'setTimeout');
  await act(async () => {
    if (outcome === 'success') resolveAttempt({ data: { success: true, aiResponse: 'STALE_OWNER', attemptNumber: 99 } });
    else rejectAttempt({ response: { status: 503, data: { error: 'STALE_OWNER', attemptNumber: 99 } } });
    await Promise.resolve();
  });
  expect(node.textContent).not.toContain('STALE_OWNER');
  expect(timer.mock.calls.filter(([, delay]) => delay === 3000)).toHaveLength(0);
  act(() => root.unmount());
});


test.each(['resolve', 'reject'])('ignores a stale hint purchase after authentication changes (%s)', async outcome => {
  const alert = jest.spyOn(window, 'alert').mockImplementation(() => {});
  const { node, root } = await renderStartedChallenge({ attemptsSoFar: 3, hintsAvailable: true });
  let resolveHint, rejectHint;
  axios.post.mockImplementationOnce(() => new Promise((resolve, reject) => {
    resolveHint = resolve;
    rejectHint = reject;
  }));
  const clickButton = async text => {
    const button = [...node.querySelectorAll('button')].find(candidate => candidate.textContent.trim().startsWith(text));
    expect(button).toBeDefined();
    await act(async () => button.click());
  };
  await clickButton('Unlock Hint 1');
  await clickButton('Unlock (-15 pts)');
  localStorage.setItem('token', 'replacement-owner-token');
  await act(async () => {
    if (outcome === 'resolve') resolveHint({ data: { hint: 'STALE_PRIVATE_HINT', hintsUsed: 1, totalPenalty: 15 } });
    else rejectHint({ response: { data: { error: 'STALE_PRIVATE_ERROR' } } });
  });
  await flush();
  expect(node.textContent).not.toContain('STALE_PRIVATE_HINT');
  expect(alert).not.toHaveBeenCalled();
  act(() => root.unmount());
});


test.each(['resolve', 'reject'])('ignores initialization after authentication changes (%s)', async outcome => {
  jest.spyOn(console, 'error').mockImplementation(() => {});
  let resolveStart, rejectStart;
  const startResponse = new Promise((resolve, reject) => { resolveStart = resolve; rejectStart = reject; });
  const { node, root } = await renderStartedChallenge({ startResponse });
  localStorage.setItem('token', 'replacement-owner-token');
  await act(async () => {
    if (outcome === 'resolve') resolveStart({ data: {
      stage: { ...stage, ai_guardian_name: 'STALE_PRIVATE_GUARDIAN' },
      hintsAvailable: true, hintsUsed: 1, hintPenaltyTotal: 15,
      purchasedHints: ['STALE_PRIVATE_HINT'], attemptsSoFar: 99,
    } });
    else rejectStart({ response: { data: { error: 'STALE_PRIVATE_ERROR' } } });
  });
  await flush();
  expect(node.textContent).not.toContain('STALE_PRIVATE');
  expect(node.textContent).not.toContain('99Attempts Made');
  act(() => root.unmount());
});


test('failed replacement-stage initialization cannot retain the previous stage hints or counters', async () => {
  jest.spyOn(console, 'error').mockImplementation(() => {});
  const { node, root, navigateToStage } = await renderStartedChallenge({ startResponse: {
    data: { stage, attemptsSoFar: 19, hintsAvailable: true, hintsUsed: 1,
      hintPenaltyTotal: 15, purchasedHints: ['PREVIOUS_STAGE_HINT'] },
  } });
  expect(node.textContent).toContain('PREVIOUS_STAGE_HINT');
  const nextStage = { ...stage, id: 6, stage_number: 6, stage_name: 'Replacement stage' };
  axios.post.mockRejectedValueOnce({ response: { data: { error: 'CURRENT_INIT_ERROR' } } });
  axios.get.mockResolvedValueOnce({ data: { config: {} } });
  await act(async () => navigateToStage(nextStage));
  await flush();
  expect(node.textContent).toContain('CURRENT_INIT_ERROR');
  expect(node.textContent).not.toContain('PREVIOUS_STAGE_HINT');
  expect(node.textContent).not.toContain('19Attempts Made');
  expect(node.textContent).not.toContain('Unlock Hint 2');
  act(() => root.unmount());
});

test('pending attempt publishes only after historical recovery and current publication; no duplicate prompt', async () => {
  const { node, root } = await renderStartedChallenge();
  const admissionId = '11111111-1111-4111-8111-111111111111';
  const decisionId = '22222222-2222-4222-8222-222222222222';
  let publish;
  axios.post.mockResolvedValueOnce({ status: 202, data: { pending: true, admissionId } });
  axios.get.mockResolvedValueOnce({ status: 200, data: { state: 'historical_receipt', admissionId, decisionId, currentCompletion: false } })
    .mockImplementationOnce(() => new Promise(resolve => { publish = resolve; }));
  await submitAttempt(node, 'retained pending prompt');
  expect(node.textContent).toContain('retained pending prompt');
  expect(node.textContent).not.toContain('Challenge Completed!');
  await act(async () => { publish({ status: 200, data: { success: false, aiResponse: 'Current authorized response', attemptNumber: 2 } }); });
  await flush();
  expect(node.textContent).toContain('Current authorized response');
  expect(axios.post.mock.calls.filter(([url]) => url.endsWith('/attempt'))).toHaveLength(1);
  act(() => root.unmount());
});

test('unsupported predefense pending displays recovery-needed and preserves prompt without replay', async () => {
  const { node, root } = await renderStartedChallenge();
  axios.post.mockResolvedValueOnce({ status: 202, data: { pending: true, operationId: '11111111-1111-4111-8111-111111111111', admissionId: null, decisionId: null } });
  await submitAttempt(node, 'uncertain original prompt');
  expect(node.textContent).toContain('no supported result reference');
  expect(node.textContent).toContain('uncertain original prompt');
  expect(node.textContent).not.toContain('Check status');
  expect(axios.post.mock.calls.filter(([url]) => url.endsWith('/attempt'))).toHaveLength(1);
  act(() => root.unmount());
});

test('lost initial response is unknown and never automatically resubmitted', async () => {
  const { node, root } = await renderStartedChallenge();
  axios.post.mockRejectedValueOnce(new Error('connection lost'));
  await submitAttempt(node, 'original uncertain prompt');
  expect(node.textContent).toContain('Outcome unknown');
  expect(node.textContent).toContain('original uncertain prompt');
  expect(axios.post.mock.calls.filter(([url]) => url.endsWith('/attempt'))).toHaveLength(1);
  act(() => root.unmount());
});

test('navigation aborts current-publication HTTP and late success cannot render', async () => {
  const { node, root, navigateToStage } = await renderStartedChallenge();
  const decisionId = '22222222-2222-4222-8222-222222222222';
  let publish, publicationSignal;
  axios.post.mockResolvedValueOnce({ status: 202, data: { decisionId } });
  axios.get.mockImplementationOnce((url, options) => { publicationSignal = options.signal; return new Promise(resolve => { publish = resolve; }); });
  await submitAttempt(node);
  axios.post.mockResolvedValueOnce({ data: { stage: { ...stage, id: 6 }, purchasedHints: [] } });
  axios.get.mockResolvedValueOnce({ data: { config: {} } });
  await act(async () => navigateToStage({ ...stage, id: 6 })); await flush();
  expect(publicationSignal.aborted).toBe(true);
  await act(async () => publish({ status: 200, data: { success: true, message: 'stale secret success' } }));
  await flush(); expect(node.textContent).not.toContain('stale secret success');
  act(() => root.unmount());
});

test.each([401,403,423])('terminal%s retires hints and submission context without retrying original attempt',async status=>{
 const {node,root}=await renderStartedChallenge({hintsAvailable:true,startResponse:{data:{stage,alreadyStarted:true,attemptsSoFar:2,hintsAvailable:true,hintsUsed:1,purchasedHints:['PRIVATE_HINT_SENTINEL']}}});
 expect(node.textContent).toContain('PRIVATE_HINT_SENTINEL');
 axios.post.mockRejectedValueOnce({response:{status,data:{error:'denied'}}});
 await submitAttempt(node,'PRIVATE_CHAT_SENTINEL');await flush();
 expect(node.textContent).not.toContain('PRIVATE_HINT_SENTINEL');expect(node.textContent).not.toContain('PRIVATE_CHAT_SENTINEL');expect(node.textContent).not.toContain('Challenge Completed!');
 if(status===401){expect(node.querySelector('textarea')).toBeNull();expect(node.textContent).toContain('Sign in');}
 else{expect(node.querySelector('textarea').disabled).toBe(true);expect(node.textContent).toContain('Return to dashboard');}
 expect(axios.post.mock.calls.filter(([url])=>url.endsWith('/attempt'))).toHaveLength(1);
 const denialButton=[...node.querySelectorAll('button')].find(button=>button.textContent===(status===401?'Sign in':'Return to dashboard'));
 expect(denialButton.style.borderRadius).toBe('10px');expect(denialButton.style.padding).toBe('0.65rem 1.1rem');
 expect(denialButton.style.fontFamily).toBe('inherit');expect(denialButton.style.fontWeight).toBe('600');
 if(status===401)expect(denialButton.closest('[role="status"]').style.fontFamily).toContain('sans-serif');
 expect(localStorage.getItem('token')).toBe('owner-token'); // Feature denial is not a global logout.
 act(()=>root.unmount());node.remove();
});

test('late hint recovery cannot restore private content after an attempt denies current context',async()=>{
 const {node,root}=await renderStartedChallenge({attemptsSoFar:3,hintsAvailable:true});let late;
 axios.post.mockImplementationOnce(()=>new Promise(resolve=>{late=resolve;}));
 act(()=>[...node.querySelectorAll('button')].find(button=>button.textContent.includes('Unlock Hint 1')).click());await flush();
 await act(async()=>[...node.querySelectorAll('button')].find(button=>button.textContent.includes('Unlock (-')).click());
 axios.post.mockRejectedValueOnce({response:{status:403,data:{error:'stale context'}}});await submitAttempt(node);await flush();
 await act(async()=>late({status:200,data:{hint:'LATE_PRIVATE_HINT',hintsUsed:1,totalPenalty:15}}));await flush();
 expect(node.textContent).not.toContain('LATE_PRIVATE_HINT');expect(node.querySelector('textarea').disabled).toBe(true);expect(node.textContent).not.toContain('Challenge Completed!');
 expect(axios.post.mock.calls.filter(([url])=>url.endsWith('/hint'))).toHaveLength(1);act(()=>root.unmount());node.remove();
});

test('acknowledges ordered stage start before reading current config; no overlapping read or mutation retry', async () => {
  let acknowledge;
  axios.post.mockImplementationOnce(() => new Promise(resolve => { acknowledge = resolve; }));
  axios.get.mockImplementation(() => Promise.resolve({ data: { config: {} } }));
  const node = document.createElement('div'); document.body.appendChild(node);
  const root = createRoot(node);
  act(() => root.render(<MemoryRouter initialEntries={[{ pathname: '/ctf/challenge', state: { stage } }]}><CTFChallenge /></MemoryRouter>));
  await flush();
  expect(axios.post).toHaveBeenCalledTimes(1);
  expect(axios.get).not.toHaveBeenCalled();
  expect(node.textContent).toContain('Initializing challenge');
  await act(async () => acknowledge({ status: 200, data: { stage } })); await flush();
  expect(axios.get).toHaveBeenCalledTimes(1);
  expect(axios.get).toHaveBeenCalledWith('/api/ctf/config', expect.any(Object));
  expect(node.querySelector('textarea').disabled).toBe(false);
  expect(axios.post).toHaveBeenCalledTimes(1);
  act(() => root.unmount());
});

test('late stage acknowledgement after unmount cannot start a config read', async () => {
  let acknowledge;
  axios.post.mockImplementationOnce(() => new Promise(resolve => { acknowledge = resolve; }));
  const node = document.createElement('div'); document.body.appendChild(node);
  const root = createRoot(node);
  act(() => root.render(<MemoryRouter initialEntries={[{ pathname: '/ctf/challenge', state: { stage } }]}><CTFChallenge /></MemoryRouter>));
  await flush();act(() => root.unmount());
  await act(async () => acknowledge({ status: 200, data: { stage } }));await flush();
  expect(axios.get).not.toHaveBeenCalled();
  expect(axios.post).toHaveBeenCalledTimes(1);
});

test.each([401, 403, 423])('configuration auth denial %s never retries start or config', async status => {
  axios.post.mockResolvedValueOnce({ status: 200, data: { stage } });
  axios.get.mockRejectedValue({ response: { status, data: { error: 'denied config' } } });
  const node=document.createElement('div');document.body.appendChild(node);const root=createRoot(node);
  act(()=>root.render(<MemoryRouter initialEntries={[{pathname:'/ctf/challenge',state:{stage}}]}><CTFChallenge /></MemoryRouter>));
  await flush();expect(axios.post).toHaveBeenCalledTimes(1);expect(axios.get).toHaveBeenCalledTimes(1);
  expect(node.querySelector('textarea')?.disabled ?? true).toBe(true);act(()=>root.unmount());
});

test('transient config503 retries reads with fixed bound but never replays acknowledged start', async () => {
  jest.useFakeTimers();
  axios.post.mockResolvedValueOnce({status:200,data:{stage}});
  axios.get.mockRejectedValueOnce({response:{status:503,data:{error:'current read pending'}}}).mockResolvedValueOnce({data:{config:{}}});
  const node=document.createElement('div');document.body.appendChild(node);const root=createRoot(node);
  try{
    act(()=>root.render(<MemoryRouter initialEntries={[{pathname:'/ctf/challenge',state:{stage}}]}><CTFChallenge /></MemoryRouter>));
    await flush();expect(axios.get).toHaveBeenCalledTimes(1);
    await act(async()=>jest.advanceTimersByTime(100));await flush();
    expect(axios.get).toHaveBeenCalledTimes(2);expect(axios.post).toHaveBeenCalledTimes(1);
    expect(node.querySelector('textarea').disabled).toBe(false);
  }finally{act(()=>root.unmount());jest.useRealTimers();}
});

test('config503 exhaustion preserves error after exactly three reads and one start', async () => {
  jest.useFakeTimers();axios.post.mockResolvedValue({status:200,data:{stage}});
  axios.get.mockRejectedValue({response:{status:503,data:{error:'CONFIG_STILL_PENDING'}}});
  const node=document.createElement('div');document.body.appendChild(node);const root=createRoot(node);
  try{
    act(()=>root.render(<MemoryRouter initialEntries={[{pathname:'/ctf/challenge',state:{stage}}]}><CTFChallenge /></MemoryRouter>));await flush();
    await act(async()=>jest.advanceTimersByTime(100));await flush();
    await act(async()=>jest.advanceTimersByTime(200));await flush();
    expect(axios.get).toHaveBeenCalledTimes(3);expect(axios.post).toHaveBeenCalledTimes(1);
    expect(node.textContent).toContain('CONFIG_STILL_PENDING');expect(node.querySelector('textarea').disabled).toBe(true);
  }finally{act(()=>root.unmount());jest.useRealTimers();}
});

test('changed session during config backoff suppresses later reads and publication', async () => {
  jest.useFakeTimers();axios.post.mockResolvedValueOnce({status:200,data:{stage}});
  axios.get.mockRejectedValue({response:{status:503}});
  const node=document.createElement('div');document.body.appendChild(node);const root=createRoot(node);
  try{
    act(()=>root.render(<MemoryRouter initialEntries={[{pathname:'/ctf/challenge',state:{stage}}]}><CTFChallenge /></MemoryRouter>));await flush();
    localStorage.setItem('token','different-session');await act(async()=>jest.advanceTimersByTime(300));await flush();
    expect(axios.get).toHaveBeenCalledTimes(1);expect(axios.post).toHaveBeenCalledTimes(1);
    expect(node.querySelector('textarea')?.disabled??true).toBe(true);
  }finally{act(()=>root.unmount());jest.useRealTimers();}
});

test('configuration deadline aborts underlying read and ignores noncooperative late success', async () => {
  jest.useFakeTimers();axios.post.mockResolvedValueOnce({status:200,data:{stage}});
  let complete,signal;axios.get.mockImplementation((_url,options)=>{signal=options.signal;return new Promise(resolve=>{complete=resolve;});});
  const node=document.createElement('div');document.body.appendChild(node);const root=createRoot(node);
  try{
    act(()=>root.render(<MemoryRouter initialEntries={[{pathname:'/ctf/challenge',state:{stage}}]}><CTFChallenge /></MemoryRouter>));await flush();
    await act(async()=>jest.advanceTimersByTime(3000));await flush();expect(signal.aborted).toBe(true);
    expect(node.querySelector('textarea').disabled).toBe(true);
    await act(async()=>complete({data:{config:{}}}));await flush();expect(node.querySelector('textarea').disabled).toBe(true);
    expect(axios.get).toHaveBeenCalledTimes(1);expect(axios.post).toHaveBeenCalledTimes(1);
  }finally{act(()=>root.unmount());jest.useRealTimers();}
});

test('unmount aborts config and clears retry deadline without sending another read', async () => {
  jest.useFakeTimers();const scheduled=jest.spyOn(global,'setTimeout'),cleared=jest.spyOn(global,'clearTimeout');axios.post.mockResolvedValueOnce({status:200,data:{stage}});
  let signal;axios.get.mockImplementation((_url,options)=>{signal=options.signal;return new Promise(()=>{});});
  const node=document.createElement('div');document.body.appendChild(node);const root=createRoot(node);
  try{
    act(()=>root.render(<MemoryRouter initialEntries={[{pathname:'/ctf/challenge',state:{stage}}]}><CTFChallenge /></MemoryRouter>));await flush();
    act(()=>root.unmount());await flush();expect(signal.aborted).toBe(true);
    for(const delay of [3000])expect(scheduled.mock.calls.filter(args=>args[1]===delay)).toHaveLength(1);for(const [index,args] of scheduled.mock.calls.entries())if([100,3000].includes(args[1]))expect(cleared).toHaveBeenCalledWith(scheduled.mock.results[index].value);expect(axios.get).toHaveBeenCalledTimes(1);
  // React act queues microtasks counted by Jest; drain those separately.
    jest.runAllTicks();expect(jest.getTimerCount()).toBe(0);
  }finally{scheduled.mockRestore();cleared.mockRestore();jest.useRealTimers();}
});

test('unmount during config503 backoff cancels all timers and prevents further reads', async () => {
  jest.useFakeTimers();const scheduled=jest.spyOn(global,'setTimeout'),cleared=jest.spyOn(global,'clearTimeout');axios.post.mockResolvedValueOnce({status:200,data:{stage}});
  let signal;axios.get.mockImplementation((_url,options)=>{signal=options.signal;return Promise.reject({response:{status:503}});});
  const node=document.createElement('div');document.body.appendChild(node);const root=createRoot(node);
  try{
    act(()=>root.render(<MemoryRouter initialEntries={[{pathname:'/ctf/challenge',state:{stage}}]}><CTFChallenge /></MemoryRouter>));await flush();
    expect(axios.get).toHaveBeenCalledTimes(1);act(()=>root.unmount());await flush();
    expect(signal.aborted).toBe(true);for(const delay of [100, 3000])expect(scheduled.mock.calls.filter(args=>args[1]===delay)).toHaveLength(1);for(const [index,args] of scheduled.mock.calls.entries())if([100,3000].includes(args[1]))expect(cleared).toHaveBeenCalledWith(scheduled.mock.results[index].value);
    await act(async()=>jest.advanceTimersByTime(3000));await flush();
    expect(axios.get).toHaveBeenCalledTimes(1);expect(axios.post).toHaveBeenCalledTimes(1);
  // React act queues microtasks counted by Jest; drain those separately.
    jest.runAllTicks();expect(jest.getTimerCount()).toBe(0);
  }finally{scheduled.mockRestore();cleared.mockRestore();jest.useRealTimers();}
});
