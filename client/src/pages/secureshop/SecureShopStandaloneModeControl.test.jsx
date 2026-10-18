import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import SecureShopStandaloneModeControl from './SecureShopStandaloneModeControl.jsx';

function deferred() {
  let resolve; let reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}

function harness(client, onModeChanged = jest.fn()) {
  global.IS_REACT_ACT_ENVIRONMENT = true;
  const container = document.createElement('div'); document.body.appendChild(container);
  const root = createRoot(container);
  const render = (nextClient = client) => act(async () => root.render(
    <SecureShopStandaloneModeControl client={nextClient} onModeChanged={onModeChanged} />));
  return { container, onModeChanged, render,
    close: async () => { await act(async () => root.unmount()); container.remove(); } };
}

test('shows only the server mode and updates after confirmed revisioned response', async () => {
  const initial = deferred();
  const saved = deferred();
  const client = { getMode: jest.fn().mockReturnValue(initial.promise),
    setMode: jest.fn().mockReturnValue(saved.promise) };
  const h = harness(client);
  try {
    await h.render();
    expect(h.container.textContent).toContain('Loading mode');
    expect(h.container.querySelector('button')).toBeNull();
    await act(async () => initial.resolve({ mode: 'vuln', revision: '3' }));
    expect(h.container.textContent).toContain('Current: Vulnerable');
    const fixed = [...h.container.querySelectorAll('button')].find(button => button.textContent === 'Fixed');
    await act(async () => fixed.click());
    expect(client.setMode).toHaveBeenCalledWith('fixed', '3', expect.any(AbortSignal));
    expect(h.container.textContent).toContain('Current: Vulnerable');
    expect(fixed.disabled).toBe(true);
    await act(async () => saved.resolve({ mode: 'fixed', revision: '4' }));
    expect(h.container.textContent).toContain('Current: Fixed');
    expect(h.container.textContent).toContain('revision 4');
    expect(h.onModeChanged).toHaveBeenCalledTimes(1);
    expect(h.onModeChanged).toHaveBeenCalledWith({ mode: 'fixed', revision: '4' });
  } finally { await h.close(); }
});

test('does not publish a late mode change after the client authority is replaced', async () => {
  const saved = deferred();
  const first = { getMode: jest.fn().mockResolvedValue({ mode: 'vuln', revision: '3' }),
    setMode: jest.fn().mockReturnValue(saved.promise) };
  const second = { getMode: jest.fn().mockResolvedValue({ mode: 'fixed', revision: '4' }),
    setMode: jest.fn() };
  const h = harness(first);
  try {
    await h.render();
    const fixed = [...h.container.querySelectorAll('button')].find(button => button.textContent === 'Fixed');
    await act(async () => fixed.click());
    await h.render(second);
    await act(async () => saved.resolve({ mode: 'fixed', revision: '4' }));
    expect(h.onModeChanged).not.toHaveBeenCalled();
    expect(h.container.textContent).toContain('Current: Fixed');
  } finally { await h.close(); }
});

test('409 conflict reloads current server mode without pretending the requested mode succeeded', async () => {
  const conflict = Object.assign(new Error('Conflict'), { status: 409 });
  const client = { getMode: jest.fn().mockResolvedValueOnce({ mode: 'vuln', revision: '3' })
    .mockResolvedValueOnce({ mode: 'vuln', revision: '4' }),
  setMode: jest.fn().mockRejectedValue(conflict) };
  const h = harness(client);
  try {
    await h.render();
    const fixed = [...h.container.querySelectorAll('button')].find(button => button.textContent === 'Fixed');
    await act(async () => fixed.click());
    expect(client.getMode).toHaveBeenCalledTimes(2);
    expect(h.container.textContent).toContain('Current: Vulnerable');
    expect(h.container.textContent).toContain('revision 4');
    expect(h.container.querySelector('[role="alert"]')?.textContent).toContain('Mode changed in another session');
    expect(h.onModeChanged).toHaveBeenCalledTimes(1);
    expect(h.onModeChanged).toHaveBeenCalledWith({ mode: 'vuln', revision: '4' });
  } finally { await h.close(); }
});

test('uncertain write refreshes authority only when readback proves a new effective revision', async () => {
  const failure = Object.assign(new Error('Connection closed'), { status: 503 });
  const client = { getMode: jest.fn().mockResolvedValueOnce({ mode: 'vuln', revision: '3' })
    .mockResolvedValueOnce({ mode: 'vuln', revision: '3' }),
  setMode: jest.fn().mockRejectedValue(failure) };
  const h = harness(client);
  try {
    await h.render();
    const fixed = [...h.container.querySelectorAll('button')].find(button => button.textContent === 'Fixed');
    await act(async () => fixed.click());
    expect(h.onModeChanged).not.toHaveBeenCalled();
    expect(h.container.textContent).toContain('Current: Vulnerable');
    expect(h.container.textContent).toContain('revision 3');
  } finally { await h.close(); }
});

test('load failure exposes retry and no fabricated mode selection', async () => {
  const client = { getMode: jest.fn().mockRejectedValueOnce(new Error('Mode service unavailable'))
    .mockResolvedValueOnce({ mode: 'fixed', revision: '7' }), setMode: jest.fn() };
  const h = harness(client);
  try {
    await h.render();
    expect(h.container.querySelector('[role="alert"]')?.textContent).toContain('Mode service unavailable');
    expect(h.container.textContent).not.toContain('Current:');
    const retry = [...h.container.querySelectorAll('button')].find(button => button.textContent === 'Retry mode');
    await act(async () => retry.click());
    expect(h.container.textContent).toContain('Current: Fixed');
  } finally { await h.close(); }
});
