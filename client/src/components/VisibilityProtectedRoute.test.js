/* eslint-disable testing-library/no-unnecessary-act -- these tests use React DOM createRoot directly. */
import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import axios from 'axios';
import VisibilityProtectedRoute from './VisibilityProtectedRoute';

jest.mock('axios', () => ({ get: jest.fn() }));
jest.mock('react-router-dom', () => ({
  Navigate: ({ to, replace }) => (
    <div data-testid="visibility-redirect" data-to={to} data-replace={String(replace)} />
  ),
}));
jest.mock('./VulnerabilityTemplate', () => {
  const React = require('react');
  return {
    __esModule: true,
    ConfirmedVisibilityContext: React.createContext(null),
    default: ({ challengeId, loading, visibilityManagedExternally }) => (
      <div
        data-testid="visibility-loading"
        data-challenge-id={challengeId}
        data-loading={String(loading)}
        data-visibility-managed-externally={String(visibilityManagedExternally)}
      />
    ),
  };
});

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

let node;
let root;

function renderRoute(challengeId, childLabel = `child:${challengeId}`, alternateChallengeId) {
  act(() => {
    root.render(
      <VisibilityProtectedRoute challengeId={challengeId} alternateChallengeId={alternateChallengeId}>
        <div data-testid="protected-child">{childLabel}</div>
      </VisibilityProtectedRoute>
    );
  });
}

beforeEach(() => {
  global.IS_REACT_ACT_ENVIRONMENT = true;
  axios.get.mockReset();
  jest.spyOn(console, 'error').mockImplementation(() => {});
  node = document.createElement('div');
  document.body.appendChild(node);
  root = createRoot(node);
});

afterEach(() => {
  act(() => root.unmount());
  node.remove();
  jest.restoreAllMocks();
});

test('keeps the existing VulnerabilityTemplate loading state while visibility is unresolved', () => {
  axios.get.mockReturnValue(new Promise(() => {}));
  renderRoute('direct_prompt_injection');

  const loading = node.querySelector('[data-testid="visibility-loading"]');
  expect(loading).toBeTruthy();
  expect(loading.dataset.challengeId).toBe('direct_prompt_injection');
  expect(loading.dataset.loading).toBe('true');
  expect(loading.dataset.visibilityManagedExternally).toBe('true');
  expect(node.querySelector('[data-testid="protected-child"]')).toBeNull();
  expect(node.querySelector('[data-testid="visibility-redirect"]')).toBeNull();
});

test('renders children only after a valid authoritative response confirms visibility', async () => {
  axios.get.mockResolvedValue({
    data: { success: true, challenges: [{ id: 'direct_prompt_injection' }] },
  });
  renderRoute('direct_prompt_injection');
  await flush();

  expect(node.querySelector('[data-testid="protected-child"]')?.textContent).toBe('child:direct_prompt_injection');
  expect(node.querySelector('[data-testid="visibility-redirect"]')).toBeNull();
});

test.each([
  ['main only', 'reflected_xss_llm'],
  ['builder only', 'xss_email_builder'],
])('admits the XSS page when %s is visible', async (_label, visibleId) => {
  axios.get.mockResolvedValue({ data: { success: true, challenges: [{ id: visibleId }] } });
  renderRoute('reflected_xss_llm', 'XSS page', 'xss_email_builder');
  await flush();

  expect(node.querySelector('[data-testid="protected-child"]')?.textContent).toBe('XSS page');
  expect(node.querySelector('[data-testid="visibility-redirect"]')).toBeNull();
});

test('denies the shared XSS page when both catalog exercises are hidden', async () => {
  axios.get.mockResolvedValue({ data: { success: true, challenges: [] } });
  renderRoute('reflected_xss_llm', 'XSS page', 'xss_email_builder');
  await flush();

  expect(node.querySelector('[data-testid="visibility-redirect"]')).toBeTruthy();
  expect(node.querySelector('[data-testid="protected-child"]')).toBeNull();
});

test('redirects with replacement only after a valid list confirms the challenge is hidden', async () => {
  axios.get.mockResolvedValue({
    data: { success: true, challenges: [{ id: 'another_challenge' }] },
  });
  renderRoute('direct_prompt_injection');
  await flush();

  const redirect = node.querySelector('[data-testid="visibility-redirect"]');
  expect(redirect).toBeTruthy();
  expect(redirect.dataset.to).toBe('/workshop/challenges');
  expect(redirect.dataset.replace).toBe('true');
  expect(node.querySelector('[data-testid="protected-child"]')).toBeNull();
});

test('request failure renders an in-place retry and never redirects', async () => {
  axios.get.mockRejectedValue(new Error('visibility unavailable'));
  renderRoute('direct_prompt_injection');
  await flush();

  expect(node.querySelector('[role="alert"]')?.textContent).toMatch(/unable to verify exercise availability/i);
  expect(node.querySelector('button')?.textContent).toMatch(/retry/i);
  expect(node.querySelector('[data-testid="visibility-redirect"]')).toBeNull();
  expect(node.querySelector('[data-testid="protected-child"]')).toBeNull();
});

test.each([
  ['null body', null],
  ['missing success marker', { challenges: [] }],
  ['unsuccessful body', { success: false, challenges: [] }],
  ['missing challenge list', { success: true }],
  ['non-array challenge list', { success: true, challenges: {} }],
  ['malformed challenge entry', { success: true, challenges: [{}] }],
])('treats a %s as an error rather than confirmed hidden', async (_label, data) => {
  axios.get.mockResolvedValue({ data });
  renderRoute('direct_prompt_injection');
  await flush();

  expect(node.querySelector('[role="alert"]')).toBeTruthy();
  expect(node.querySelector('[data-testid="visibility-redirect"]')).toBeNull();
  expect(node.querySelector('[data-testid="protected-child"]')).toBeNull();
});

test('retry returns to loading and can recover to visible content', async () => {
  const retryRequest = deferred();
  axios.get
    .mockRejectedValueOnce(new Error('temporary visibility failure'))
    .mockReturnValueOnce(retryRequest.promise);
  renderRoute('direct_prompt_injection');
  await flush();

  act(() => node.querySelector('button').click());
  expect(node.querySelector('[data-testid="visibility-loading"]')).toBeTruthy();
  expect(node.querySelector('[role="alert"]')).toBeNull();

  retryRequest.resolve({
    data: { success: true, challenges: [{ id: 'direct_prompt_injection' }] },
  });
  await flush();

  expect(axios.get).toHaveBeenCalledTimes(2);
  expect(node.querySelector('[data-testid="protected-child"]')).toBeTruthy();
  expect(node.querySelector('[data-testid="visibility-redirect"]')).toBeNull();
});

test('a late response for an old challengeId cannot replace the current decision', async () => {
  const oldRequest = deferred();
  const currentRequest = deferred();
  axios.get
    .mockReturnValueOnce(oldRequest.promise)
    .mockReturnValueOnce(currentRequest.promise);

  renderRoute('challenge_a', 'child A');
  renderRoute('challenge_b', 'child B');
  expect(node.querySelector('[data-testid="visibility-loading"]')?.dataset.challengeId).toBe('challenge_b');
  expect(node.querySelector('[data-testid="protected-child"]')).toBeNull();

  currentRequest.resolve({
    data: { success: true, challenges: [{ id: 'challenge_b' }] },
  });
  await flush();
  expect(node.querySelector('[data-testid="protected-child"]')?.textContent).toBe('child B');

  oldRequest.resolve({ data: { success: true, challenges: [] } });
  await flush();
  expect(node.querySelector('[data-testid="protected-child"]')?.textContent).toBe('child B');
  expect(node.querySelector('[data-testid="visibility-redirect"]')).toBeNull();
});

test('a late response for an old alternate challenge cannot authorize the current pair', async () => {
  const oldRequest = deferred();
  const currentRequest = deferred();
  axios.get.mockReturnValueOnce(oldRequest.promise).mockReturnValueOnce(currentRequest.promise);

  renderRoute('main', 'old pair', 'old_alternate');
  renderRoute('main', 'current pair', 'current_alternate');
  expect(node.querySelector('[data-testid="visibility-loading"]')).toBeTruthy();

  currentRequest.resolve({ data: { success: true, challenges: [] } });
  await flush();
  expect(node.querySelector('[data-testid="visibility-redirect"]')).toBeTruthy();

  oldRequest.resolve({ data: { success: true, challenges: [{ id: 'old_alternate' }] } });
  await flush();
  expect(node.querySelector('[data-testid="visibility-redirect"]')).toBeTruthy();
  expect(node.querySelector('[data-testid="protected-child"]')).toBeNull();
});

test('changing challengeId aborts the superseded request and starts a fresh signaled request', () => {
  axios.get.mockReturnValue(new Promise(() => {}));

  renderRoute('challenge_a');
  const firstSignal = axios.get.mock.calls[0][1]?.signal;
  expect(firstSignal).toBeInstanceOf(AbortSignal);
  expect(firstSignal.aborted).toBe(false);

  renderRoute('challenge_b');
  const secondSignal = axios.get.mock.calls[1][1]?.signal;
  expect(firstSignal.aborted).toBe(true);
  expect(secondSignal).toBeInstanceOf(AbortSignal);
  expect(secondSignal).not.toBe(firstSignal);
  expect(secondSignal.aborted).toBe(false);
});

test('retry aborts the prior request ownership before starting a fresh signaled request', async () => {
  axios.get
    .mockRejectedValueOnce(new Error('temporary visibility failure'))
    .mockReturnValueOnce(new Promise(() => {}));

  renderRoute('direct_prompt_injection');
  await flush();
  const firstSignal = axios.get.mock.calls[0][1]?.signal;
  expect(firstSignal).toBeInstanceOf(AbortSignal);

  act(() => node.querySelector('button').click());
  const secondSignal = axios.get.mock.calls[1][1]?.signal;
  expect(firstSignal.aborted).toBe(true);
  expect(secondSignal).toBeInstanceOf(AbortSignal);
  expect(secondSignal).not.toBe(firstSignal);
  expect(secondSignal.aborted).toBe(false);
});

test.each([true,false])('standalone app admission uses its exact endpoint and retains visible=%s decision',async visible=>{
 axios.get.mockResolvedValue({data:{success:true,challenges:visible?[{id:'secureshop_agent_security'}]:[]}});
 act(()=>root.render(<VisibilityProtectedRoute challengeId="secureshop_agent_security" visibilityEndpoint="/api/workshop/applications/secureshop"><div data-testid="protected-child">Shop app</div></VisibilityProtectedRoute>));
 await flush();expect(axios.get).toHaveBeenCalledWith('/api/workshop/applications/secureshop',expect.any(Object));
 expect(Boolean(node.querySelector('[data-testid="protected-child"]'))).toBe(visible);expect(Boolean(node.querySelector('[data-testid="visibility-redirect"]'))).toBe(!visible);
});
