import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import SecureShopStandaloneAssessmentsControl from './SecureShopStandaloneAssessmentsControl.jsx';

const evaluationId = '7f078c35-0bda-4bb4-9c9f-819807aa2668';
const createdAt = '2026-10-09T12:00:00.000Z';
const row = { evaluationId, objectiveId: 'ss_inventory_cross_merchant_stock', verdict: 'unavailable',
  disposition: 'not_pass', createdAt, evaluatedAt: null, canRetry: true, childEvaluationId: null };

function deferred() {
  let resolve;
  const promise = new Promise(yes => { resolve = yes; });
  return { promise, resolve };
}

function harness(client) {
  global.IS_REACT_ACT_ENVIRONMENT = true;
  const container = document.createElement('div'); document.body.appendChild(container);
  const root = createRoot(container);
  return { container, render: async () => act(async () => root.render(
    <SecureShopStandaloneAssessmentsControl client={client} />)),
  close: async () => { await act(async () => root.unmount()); container.remove(); } };
}

test('retry appears only for server canRetry and posts saved evaluation without replaying shop action', async () => {
  const retry = deferred();
  const client = { getAssessments: jest.fn().mockResolvedValueOnce([row, { ...row,
    evaluationId: '9f078c35-0bda-4bb4-9c9f-819807aa2668', canRetry: false }])
    .mockResolvedValueOnce([{ ...row, canRetry: false,
      childEvaluationId: '9f078c35-0bda-4bb4-9c9f-819807aa2668' }]),
  retryAssessment: jest.fn().mockReturnValue(retry.promise) };
  const h = harness(client);
  try {
    await h.render();
    const buttons = [...h.container.querySelectorAll('button')].filter(button => button.textContent === 'Retry evaluation');
    expect(buttons).toHaveLength(1);
    await act(async () => buttons[0].click());
    expect(client.retryAssessment).toHaveBeenCalledWith(evaluationId, expect.any(AbortSignal));
    expect(h.container.textContent).toContain('Retrying…');
    await act(async () => retry.resolve({ evaluationId, childEvaluationId: '9f078c35-0bda-4bb4-9c9f-819807aa2668',
      verdict: 'pass', disposition: 'awarded', completed: true, replayed: false }));
    expect(client.getAssessments).toHaveBeenCalledTimes(2);
    expect(h.container.textContent).toContain('Saved evaluation completed');
    expect(h.container.textContent).not.toContain('Retry evaluation');
  } finally { await h.close(); }
});

test('uncertain retry never claims completion and reloads authoritative list', async () => {
  const client = { getAssessments: jest.fn().mockResolvedValueOnce([row]).mockResolvedValueOnce([row]),
    retryAssessment: jest.fn().mockRejectedValue(new Error('Shop service unavailable')) };
  const h = harness(client);
  try {
    await h.render();
    await act(async () => h.container.querySelector('button').click());
    expect(client.getAssessments).toHaveBeenCalledTimes(2);
    expect(h.container.querySelector('[role="alert"]')?.textContent).toContain('could not be confirmed');
    expect(h.container.textContent).not.toContain('Saved evaluation completed');
  } finally { await h.close(); }
});

test('same-turn duplicate retry and refresh admit one POST until reconciliation finishes', async () => {
  const pending = deferred();
  const client = { getAssessments: jest.fn().mockResolvedValueOnce([row])
    .mockResolvedValueOnce([{ ...row, canRetry: false }]),
  retryAssessment: jest.fn().mockReturnValue(pending.promise) };
  const h = harness(client);
  try {
    await h.render();
    const retryButton = [...h.container.querySelectorAll('button')]
      .find(button => button.textContent === 'Retry evaluation');
    const refreshButton = [...h.container.querySelectorAll('button')]
      .find(button => button.textContent === 'Refresh assessments');
    await act(async () => { retryButton.click(); retryButton.click(); refreshButton.click(); });
    expect(client.retryAssessment).toHaveBeenCalledTimes(1);
    expect(client.getAssessments).toHaveBeenCalledTimes(1);
    await act(async () => pending.resolve({ evaluationId,
      childEvaluationId: '9f078c35-0bda-4bb4-9c9f-819807aa2668', verdict: 'pass',
      disposition: 'awarded', completed: true, replayed: false }));
    expect(client.getAssessments).toHaveBeenCalledTimes(2);
  } finally { await h.close(); }
});
