import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import SecureShopStandaloneObjectivesControl from './SecureShopStandaloneObjectivesControl.jsx';

const ready = { objectiveId: 'ss_inventory_cross_merchant_stock', label: 'Owned stock authorization',
  enabled: false, qualification: 'native-model', revision: '3' };
const pending = { objectiveId: 'ss_pricing_false_grounding', label: 'Pricing grounding',
  enabled: false, qualification: 'pending', revision: '1' };

function deferred() {
  let resolve; let reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}

function harness(client) {
  global.IS_REACT_ACT_ENVIRONMENT = true;
  const container = document.createElement('div'); document.body.appendChild(container);
  const root = createRoot(container);
  return { container, render: async () => act(async () => root.render(
    <SecureShopStandaloneObjectivesControl client={client} />)),
  close: async () => { await act(async () => root.unmount()); container.remove(); } };
}

test('pending qualification cannot be enabled and qualified change waits for confirmed CAS response', async () => {
  const initial = deferred();
  const saved = deferred();
  const client = { getAssessmentObjectives: jest.fn().mockReturnValue(initial.promise),
    setAssessmentObjective: jest.fn().mockReturnValue(saved.promise) };
  const h = harness(client);
  try {
    await h.render();
    expect(h.container.textContent).toContain('Loading objectives');
    await act(async () => initial.resolve([ready, pending]));
    const enable = h.container.querySelector(`[aria-label="Enable ${ready.label}"]`);
    const pendingButton = h.container.querySelector(`[aria-label="Enable ${pending.label}"]`);
    expect(enable.disabled).toBe(false);
    expect(pendingButton.disabled).toBe(true);
    expect(h.container.textContent).toContain('Pending qualification — cannot enable yet');
    await act(async () => enable.click());
    expect(client.setAssessmentObjective).toHaveBeenCalledWith(ready.objectiveId, true, '3', expect.any(AbortSignal));
    expect(enable.getAttribute('aria-pressed')).toBe('false');
    await act(async () => saved.resolve({ objectiveId: ready.objectiveId, enabled: true,
      qualification: 'native-model', revision: '4' }));
    expect(h.container.querySelector(`[aria-label="Disable ${ready.label}"]`)?.getAttribute('aria-pressed')).toBe('true');
    expect(h.container.textContent).toContain('revision 4');
  } finally { await h.close(); }
});

test('409 conflict reloads server settings and never presents requested state as confirmed', async () => {
  const conflict = Object.assign(new Error('Stale objective'), { status: 409 });
  const client = { getAssessmentObjectives: jest.fn().mockResolvedValueOnce([ready, pending])
    .mockResolvedValueOnce([{ ...ready, revision: '4' }, pending]),
  setAssessmentObjective: jest.fn().mockRejectedValue(conflict) };
  const h = harness(client);
  try {
    await h.render();
    await act(async () => h.container.querySelector(`[aria-label="Enable ${ready.label}"]`).click());
    expect(client.getAssessmentObjectives).toHaveBeenCalledTimes(2);
    expect(h.container.querySelector(`[aria-label="Enable ${ready.label}"]`)?.getAttribute('aria-pressed')).toBe('false');
    expect(h.container.textContent).toContain('revision 4');
    expect(h.container.querySelector('[role="alert"]')?.textContent).toContain('Current settings reloaded');
  } finally { await h.close(); }
});

test('denied objective read has no controls and offers explicit retry', async () => {
  const denied = Object.assign(new Error('Forbidden'), { status: 403 });
  const client = { getAssessmentObjectives: jest.fn().mockRejectedValueOnce(denied)
    .mockResolvedValueOnce([ready]), setAssessmentObjective: jest.fn() };
  const h = harness(client);
  try {
    await h.render();
    expect(h.container.querySelector('[role="alert"]')?.textContent).toContain('Shop administrator access is required');
    expect(h.container.querySelector('[aria-pressed]')).toBeNull();
    await act(async () => h.container.querySelector('button').click());
    expect(h.container.querySelector(`[aria-label="Enable ${ready.label}"]`)).toBeTruthy();
  } finally { await h.close(); }
});
