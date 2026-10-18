import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import SecureShopStandaloneProgressControl from './SecureShopStandaloneProgressControl.jsx';

const ownerId = '4a792aa0-026b-4e76-9520-17ee0252c9aa';
const learnerId = '7f078c35-0bda-4bb4-9c9f-819807aa2668';
const progress = (principalId, role = 'customer') => ({ principalId, shopUserId: principalId === ownerId ? 7 : 8,
  username: principalId === ownerId ? 'shop_admin' : 'student_customer', role, generation: 2,
  objectives: [{ objectiveId: 'ss_inventory_cross_merchant_stock', label: 'Owned stock authorization', completed: true },
    { objectiveId: 'ss_customer_checkout', label: 'Customer checkout', completed: false }],
  totalObjectives: 2, completedObjectives: 1 });

function deferred() {
  let resolve;
  const promise = new Promise(done => { resolve = done; });
  return { promise, resolve };
}

function harness(client, user) {
  global.IS_REACT_ACT_ENVIRONMENT = true;
  const container = document.createElement('div'); document.body.appendChild(container);
  const root = createRoot(container);
  return { container, render: async nextUser => act(async () => root.render(
    <SecureShopStandaloneProgressControl client={client} user={nextUser || user} />)),
  close: async () => { await act(async () => root.unmount()); container.remove(); } };
}

test('learner sees only their completed and open objective summary; no admin reads', async () => {
  const client = { getProgress: jest.fn().mockResolvedValue(progress(learnerId)),
    getAdminProgressLearners: jest.fn(), getAdminProgress: jest.fn() };
  const h = harness(client, { principalId: learnerId, role: 'customer' });
  try {
    await h.render();
    expect(h.container.textContent).toContain('1 of 2 objectives completed');
    expect(h.container.textContent).toContain('Owned stock authorization');
    expect(h.container.textContent).toContain('Customer checkout');
    expect(h.container.textContent).not.toContain('Learners in this shop');
    expect(client.getAdminProgressLearners).not.toHaveBeenCalled();
    expect(client.getAdminProgress).not.toHaveBeenCalled();
    expect(h.container.textContent).not.toMatch(/packet|retry|evaluationId/i);
  } finally { await h.close(); }
});

test('admin pages same-tenant list and opens only a selected protected learner detail', async () => {
  const admin = progress(ownerId, 'admin'), learner = progress(learnerId);
  const client = { getProgress: jest.fn().mockResolvedValue(admin),
    getAdminProgressLearners: jest.fn().mockResolvedValueOnce({ learners: [learner], nextCursor: 8 })
      .mockResolvedValueOnce({ learners: [], nextCursor: null }),
    getAdminProgress: jest.fn().mockResolvedValue(learner) };
  const h = harness(client, { principalId: ownerId, role: 'admin' });
  try {
    await h.render();
    expect(client.getAdminProgressLearners).toHaveBeenCalledWith({ limit: 25, cursor: null }, expect.any(AbortSignal));
    expect(client.getAdminProgress).not.toHaveBeenCalled();
    await act(async () => [...h.container.querySelectorAll('button')]
      .find(button => button.textContent.startsWith('student_customer ·')).click());
    expect(client.getAdminProgress).toHaveBeenCalledWith(learnerId, expect.any(AbortSignal));
    expect(h.container.querySelector('[aria-label="student_customer objectives"]')?.textContent)
      .toContain('Owned stock authorization');
    await act(async () => [...h.container.querySelectorAll('button')]
      .find(button => button.textContent === 'More learners').click());
    expect(client.getAdminProgressLearners).toHaveBeenLastCalledWith({ limit: 25, cursor: 8 }, expect.any(AbortSignal));
  } finally { await h.close(); }
});

test('foreign self projection and stale detail are never displayed after authority changes', async () => {
  const oldDetail = deferred();
  const client = { getProgress: jest.fn().mockResolvedValueOnce(progress(learnerId))
    .mockResolvedValueOnce(progress(ownerId, 'admin')),
  getAdminProgressLearners: jest.fn().mockResolvedValue({ learners: [progress(learnerId)], nextCursor: null }),
  getAdminProgress: jest.fn().mockReturnValue(oldDetail.promise) };
  const h = harness(client, { principalId: ownerId, role: 'admin' });
  try {
    await h.render();
    expect(h.container.querySelector('[aria-label="Your progress"]')).toBeNull();
    expect(h.container.querySelector('[role="alert"]')?.textContent).toContain('could not be loaded');
    await act(async () => [...h.container.querySelectorAll('button')]
      .find(button => button.textContent.startsWith('student_customer ·')).click());
    const staleSignal = client.getAdminProgress.mock.calls[0][1];
    await h.close();
    expect(staleSignal.aborted).toBe(true);
    await act(async () => oldDetail.resolve(progress(learnerId)));
  } finally { if (h.container.isConnected) await h.close(); }
});

test('administrator denial clears previously displayed learner and detail rows', async () => {
  const admin = progress(ownerId, 'admin'), learner = progress(learnerId);
  const denied = Object.assign(new Error('denied'), { status: 403 });
  const client = { getProgress: jest.fn().mockResolvedValue(admin),
    getAdminProgressLearners: jest.fn().mockResolvedValueOnce({ learners: [learner], nextCursor: 8 })
      .mockRejectedValueOnce(denied),
    getAdminProgress: jest.fn().mockResolvedValue(learner) };
  const h = harness(client, { principalId: ownerId, role: 'admin' });
  try {
    await h.render();
    await act(async () => [...h.container.querySelectorAll('button')]
      .find(button => button.textContent.startsWith('student_customer ·')).click());
    expect(h.container.querySelector('[aria-label="student_customer objectives"]')).not.toBeNull();
    await act(async () => [...h.container.querySelectorAll('button')]
      .find(button => button.textContent === 'More learners').click());
    expect(h.container.querySelector('[aria-label="student_customer objectives"]')).toBeNull();
    expect(h.container.textContent).not.toContain('student_customer ·');
    expect([...h.container.querySelectorAll('[role="alert"]')].some(alert =>
      alert.textContent.includes('Shop administrator access is required.'))).toBe(true);
  } finally { await h.close(); }
});

test('401 detail denial aborts an in-flight learner page so it cannot repopulate the view', async () => {
  const admin = progress(ownerId, 'admin'), learner = progress(learnerId);
  const delayedPage = deferred();
  const denied = Object.assign(new Error('expired'), { status: 401 });
  const client = { getProgress: jest.fn().mockResolvedValue(admin),
    getAdminProgressLearners: jest.fn().mockResolvedValueOnce({ learners: [learner], nextCursor: 8 })
      .mockReturnValueOnce(delayedPage.promise),
    getAdminProgress: jest.fn().mockRejectedValue(denied) };
  const h = harness(client, { principalId: ownerId, role: 'admin' });
  try {
    await h.render();
    await act(async () => [...h.container.querySelectorAll('button')]
      .find(button => button.textContent === 'More learners').click());
    const pageSignal = client.getAdminProgressLearners.mock.calls[1][1];
    await act(async () => [...h.container.querySelectorAll('button')]
      .find(button => button.textContent.startsWith('student_customer ·')).click());
    expect(pageSignal.aborted).toBe(true);
    await act(async () => delayedPage.resolve({ learners: [learner], nextCursor: null }));
    expect(h.container.textContent).not.toContain('student_customer ·');
    expect(h.container.querySelector('[aria-label="student_customer objectives"]')).toBeNull();
    expect(h.container.querySelector('[aria-label="Your progress"]')).toBeNull();
    expect(h.container.textContent).toContain('Sign in again to view learner progress.');
  } finally { await h.close(); }
});

test('401 self read aborts a concurrent admin list before it can reveal learner rows', async () => {
  const delayedList = deferred();
  const denied = Object.assign(new Error('expired'), { status: 401 });
  const client = { getProgress: jest.fn().mockRejectedValue(denied),
    getAdminProgressLearners: jest.fn().mockReturnValue(delayedList.promise),
    getAdminProgress: jest.fn() };
  const h = harness(client, { principalId: ownerId, role: 'admin' });
  try {
    await h.render();
    const listSignal = client.getAdminProgressLearners.mock.calls[0][1];
    expect(listSignal.aborted).toBe(true);
    await act(async () => delayedList.resolve({ learners: [progress(learnerId)], nextCursor: null }));
    expect(h.container.textContent).not.toContain('student_customer');
    expect(h.container.textContent).toContain('Sign in again to view learner progress.');
  } finally { await h.close(); }
});

test.each(['page', 'detail'])('401 during administrator %s read clears all cached progress', async point => {
  const admin = progress(ownerId, 'admin'), learner = progress(learnerId);
  const denied = Object.assign(new Error('expired'), { status: 401 });
  const client = { getProgress: jest.fn().mockResolvedValue(admin),
    getAdminProgressLearners: jest.fn().mockResolvedValueOnce({ learners: [learner], nextCursor: 8 })
      .mockImplementationOnce(() => Promise.reject(denied)),
    getAdminProgress: jest.fn().mockImplementation(() => point === 'detail'
      ? Promise.reject(denied) : Promise.resolve(learner)) };
  const h = harness(client, { principalId: ownerId, role: 'admin' });
  try {
    await h.render();
    await act(async () => [...h.container.querySelectorAll('button')]
      .find(button => button.textContent.startsWith('student_customer ·')).click());
    if (point === 'page') {
      expect(h.container.querySelector('[aria-label="student_customer objectives"]')).not.toBeNull();
      await act(async () => [...h.container.querySelectorAll('button')]
        .find(button => button.textContent === 'More learners').click());
    }
    expect(h.container.querySelector('[aria-label="student_customer objectives"]')).toBeNull();
    expect(h.container.querySelector('[aria-label="Your progress"]')).toBeNull();
    expect(h.container.textContent).not.toContain('student_customer ·');
    expect(h.container.textContent).toContain('Sign in again to view learner progress.');
  } finally { await h.close(); }
});
