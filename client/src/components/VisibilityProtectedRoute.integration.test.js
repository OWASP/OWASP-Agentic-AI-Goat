/* eslint-disable testing-library/no-unnecessary-act -- these tests use React DOM createRoot directly. */
import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import axios from 'axios';
import VisibilityProtectedRoute from './VisibilityProtectedRoute';
import VulnerabilityTemplate from './VulnerabilityTemplate';

const mockNavigate = jest.fn();
jest.mock('axios', () => ({ get: jest.fn() }));
jest.mock('react-router-dom', () => ({
  Navigate: ({ to }) => <div data-testid="visibility-redirect" data-to={to} />,
  useNavigate: () => mockNavigate,
  useParams: () => ({}),
}));

function deferred() {
  let resolve;
  const promise = new Promise((resolvePromise) => {
    resolve = resolvePromise;
  });
  return { promise, resolve };
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

beforeEach(() => {
  global.IS_REACT_ACT_ENVIRONMENT = true;
  axios.get.mockReset();
  mockNavigate.mockReset();
  jest.spyOn(console, 'error').mockImplementation(() => {});
  node = document.createElement('div');
  document.body.appendChild(node);
  root = createRoot(node);
});

afterEach(() => {
  act(() => root.unmount());
  node.remove();
  jest.useRealTimers();
  jest.restoreAllMocks();
});

test('the outer loading guard owns the only visibility request and never exposes inner access denied', async () => {
  const outerRequest = deferred();
  axios.get.mockImplementation((_url, options) => (
    options?.signal
      ? outerRequest.promise
      : Promise.resolve({ data: { challenges: [] } })
  ));

  act(() => {
    root.render(
      <VisibilityProtectedRoute challengeId="direct_prompt_injection">
        <div>protected exercise</div>
      </VisibilityProtectedRoute>
    );
  });
  await flush();

  expect(axios.get).toHaveBeenCalledTimes(1);
  expect(node.textContent).toContain('Loading exercise...');
  expect(node.textContent).not.toContain('Exercise Not Available');
  expect(node.querySelector('[data-testid="visibility-redirect"]')).toBeNull();
});

test('outer confirmation hydrates a nested VulnerabilityTemplate without an immediate duplicate check', async () => {
  axios.get
    .mockResolvedValueOnce({
      data: {
        success: true,
        challenges: [{ id: 'direct_prompt_injection', showHints: true }],
      },
    })
    .mockRejectedValueOnce(new Error('an inner visibility request must not run'));

  act(() => {
    root.render(
      <VisibilityProtectedRoute challengeId="direct_prompt_injection">
        <VulnerabilityTemplate challengeId="direct_prompt_injection">
          <div data-testid="protected-exercise">protected exercise</div>
        </VulnerabilityTemplate>
      </VisibilityProtectedRoute>
    );
  });
  await flush();

  expect(axios.get).toHaveBeenCalledTimes(1);
  expect(node.querySelector('[data-testid="protected-exercise"]')).toBeTruthy();
  expect(node.textContent).not.toContain('Exercise Not Available');
});

test('builder-only visibility hydrates its nested template through the shared XSS route', async () => {
  axios.get.mockResolvedValueOnce({
    data: { success: true, challenges: [{ id: 'xss_email_builder', showHints: true }] },
  }).mockRejectedValueOnce(new Error('nested builder visibility must not refetch'));

  act(() => {
    root.render(
      <VisibilityProtectedRoute challengeId="reflected_xss_llm" alternateChallengeId="xss_email_builder">
        <VulnerabilityTemplate challengeId="xss_email_builder">
          <div data-testid="protected-exercise">builder exercise</div>
        </VulnerabilityTemplate>
      </VisibilityProtectedRoute>
    );
  });
  await flush();

  expect(axios.get).toHaveBeenCalledTimes(1);
  expect(node.querySelector('[data-testid="protected-exercise"]')?.textContent).toBe('builder exercise');
  expect(node.querySelector('[data-testid="visibility-redirect"]')).toBeNull();
});

test('managed template keeps confirmed content through a silent error and blocks on a later hidden response', async () => {
  jest.useFakeTimers();
  axios.get
    .mockResolvedValueOnce({
      data: {
        success: true,
        challenges: [{ id: 'direct_prompt_injection', showHints: false }],
      },
    })
    .mockRejectedValueOnce(new Error('temporary background failure'))
    .mockResolvedValueOnce({ data: { success: true, challenges: [] } });

  act(() => {
    root.render(
      <VisibilityProtectedRoute challengeId="direct_prompt_injection">
        <VulnerabilityTemplate challengeId="direct_prompt_injection">
          <div data-testid="protected-exercise">protected exercise</div>
        </VulnerabilityTemplate>
      </VisibilityProtectedRoute>
    );
  });
  await flush();
  expect(node.querySelector('[data-testid="protected-exercise"]')).toBeTruthy();

  await act(async () => {
    jest.advanceTimersByTime(30000);
    await Promise.resolve();
    await Promise.resolve();
  });
  expect(axios.get).toHaveBeenCalledTimes(2);
  expect(node.querySelector('[data-testid="protected-exercise"]')).toBeTruthy();
  expect(node.textContent).not.toContain('Exercise Not Available');

  await act(async () => {
    jest.advanceTimersByTime(30000);
    await Promise.resolve();
    await Promise.resolve();
  });
  expect(axios.get).toHaveBeenCalledTimes(3);
  expect(node.querySelector('[data-testid="protected-exercise"]')).toBeNull();
  expect(node.textContent).toContain('Exercise Not Available');
});

test('an older background visibility response cannot restore content after a newer hidden confirmation', async () => {
  jest.useFakeTimers();
  const olderIntervalRequest = deferred();
  const newerObjectiveRequest = deferred();
  axios.get
    .mockResolvedValueOnce({
      data: {
        success: true,
        challenges: [{ id: 'direct_prompt_injection', showHints: false }],
      },
    })
    .mockReturnValueOnce(olderIntervalRequest.promise)
    .mockReturnValueOnce(newerObjectiveRequest.promise);

  act(() => {
    root.render(
      <VisibilityProtectedRoute challengeId="direct_prompt_injection">
        <VulnerabilityTemplate challengeId="direct_prompt_injection">
          <div data-testid="protected-exercise">protected exercise</div>
        </VulnerabilityTemplate>
      </VisibilityProtectedRoute>
    );
  });
  await flush();

  await act(async () => {
    jest.advanceTimersByTime(30000);
    await Promise.resolve();
  });
  const olderSignal = axios.get.mock.calls[1][1]?.signal;
  expect(olderSignal).toBeInstanceOf(AbortSignal);
  expect(olderSignal.aborted).toBe(false);

  act(() => window.dispatchEvent(new Event('objectiveCompleted')));
  expect(axios.get).toHaveBeenCalledTimes(3);
  expect(olderSignal.aborted).toBe(true);
  expect(axios.get.mock.calls[2][1]?.signal).toBeInstanceOf(AbortSignal);

  newerObjectiveRequest.resolve({ data: { success: true, challenges: [] } });
  await flush();
  expect(node.querySelector('[data-testid="protected-exercise"]')).toBeNull();
  expect(node.textContent).toContain('Exercise Not Available');

  olderIntervalRequest.resolve({
    data: {
      success: true,
      challenges: [{ id: 'direct_prompt_injection', showHints: false }],
    },
  });
  await flush();

  expect(node.querySelector('[data-testid="protected-exercise"]')).toBeNull();
  expect(node.textContent).toContain('Exercise Not Available');
});

test('retry remounts the exact loading presentation without adding an inner visibility request', async () => {
  const retryRequest = deferred();
  let outerAttempts = 0;
  axios.get.mockImplementation((_url, options) => {
    if (!options?.signal) return Promise.resolve({ data: { challenges: [] } });
    outerAttempts += 1;
    return outerAttempts === 1
      ? Promise.reject(new Error('temporary visibility failure'))
      : retryRequest.promise;
  });

  act(() => {
    root.render(
      <VisibilityProtectedRoute challengeId="direct_prompt_injection">
        <div>protected exercise</div>
      </VisibilityProtectedRoute>
    );
  });
  await flush();
  expect(node.querySelector('[role="alert"]')).toBeTruthy();
  expect(axios.get).toHaveBeenCalledTimes(1);

  act(() => node.querySelector('button').click());
  await flush();

  expect(axios.get).toHaveBeenCalledTimes(2);
  expect(node.textContent).toContain('Loading exercise...');
  expect(node.textContent).not.toContain('Exercise Not Available');
});

test('VulnerabilityTemplate keeps its standalone visibility loading and denied behavior', async () => {
  const request = deferred();
  axios.get.mockReturnValue(request.promise);

  act(() => {
    root.render(
      <VulnerabilityTemplate challengeId="direct_prompt_injection">
        <div>template child</div>
      </VulnerabilityTemplate>
    );
  });
  expect(axios.get).toHaveBeenCalledTimes(1);
  expect(node.textContent).toContain('Loading exercise...');

  request.resolve({ data: { challenges: [] } });
  await flush();
  expect(node.textContent).toContain('Exercise Not Available');
  expect(node.textContent).not.toContain('template child');
});

test('exercise template back and denied fallback use the canonical student dashboard', async () => {
  axios.get.mockResolvedValue({ data: { challenges: [] } });
  act(() => root.render(<VulnerabilityTemplate challengeId="direct_prompt_injection"><div>Unavailable child</div></VulnerabilityTemplate>));
  await flush();
  const back = [...node.querySelectorAll('button')].find(button => button.textContent.includes('Back to Dashboard'));
  act(() => back.click());
  expect(mockNavigate).toHaveBeenLastCalledWith('/workshop/challenges');
  const fallback = [...node.querySelectorAll('button')].find(button => button.textContent.includes('Return to Dashboard'));
  act(() => fallback.click());
  expect(mockNavigate).toHaveBeenLastCalledWith('/workshop/challenges');
});
