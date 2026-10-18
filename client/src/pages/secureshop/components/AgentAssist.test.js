import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import AgentAssist from './AgentAssist.jsx';
import { useAgentStream } from '../hooks/useAgentStream.js';

jest.mock('../hooks/useAgentStream.js', () => ({ useAgentStream: jest.fn() }));
jest.mock('../context/AuthContext.jsx', () => ({ useAuth: () => ({ user: { id: 42 } }) }));
globalThis.IS_REACT_ACT_ENVIRONMENT = true;

let root;
let container;
let state;
beforeEach(() => {
  container = document.createElement('div');
  document.body.appendChild(container);
  root = createRoot(container);
  state = { turns: [], status: 'idle', error: null, send: jest.fn().mockResolvedValue(), createSession: jest.fn().mockResolvedValue('session') };
  useAgentStream.mockImplementation(() => state);
});
afterEach(async () => {
  await act(async () => root.unmount());
  container.remove();
});
async function render() {
  await act(async () => root.render(<AgentAssist role="merchant" prompt="Check this product" />));
}

test('uses shared stream with current persona and submits the unchanged message', async () => {
  await render();
  expect(useAgentStream).toHaveBeenCalledWith({ role: 'merchant', defaultUserId: 42 });
  await act(async () => container.querySelector('form').dispatchEvent(new Event('submit', { bubbles: true, cancelable: true })));
  expect(state.send).toHaveBeenCalledWith('Check this product');
  expect(state.createSession).toHaveBeenCalledTimes(1);
});

test('does not send a prompt when one-shot session creation fails', async () => {
  state.createSession.mockRejectedValue(new Error('session denied'));
  await render();
  await act(async () => container.querySelector('form').dispatchEvent(new Event('submit', { bubbles: true, cancelable: true })));
  expect(state.send).not.toHaveBeenCalled();
});

test('shows real stream errors instead of a fabricated no-response answer', async () => {
  state.error = 'Agent request failed (403)';
  state.status = 'error';
  state.turns = [{ reply: 'Partial answer' }];
  await render();
  expect(container.textContent).toContain('Agent request failed (403)');
  expect(container.textContent).not.toContain('no assistant response');
  expect(container.textContent).not.toContain('Partial answer');
});

test('preserves loading control and renders the completed assistant text', async () => {
  state.status = 'thinking';
  state.turns = [{ reply: 'Partial answer' }];
  await render();
  expect(container.querySelector('button[type="submit"]').disabled).toBe(true);
  expect(container.textContent).not.toContain('Partial answer');
  state.status = 'idle';
  state.turns = [{ reply: '<b>Actual answer</b>', status: 'done' }];
  await render();
  expect(container.textContent).toContain('<b>Actual answer</b>');
  expect(container.querySelector('b')).toBeNull();
});

test('shows only trusted feature mode for a completed one-shot chat', async () => {
  state.turns = [{ reply: 'Owned result', modeCapability: { version: 1, featureId: 'analytics',
    policyVersion: 'postgres-restricted-capability-v1', effectiveMode: 'fixed',
    scope: { kind: 'launch_feature', id: 'analytics' } } }];
  await render();
  expect(container.textContent).toContain('analytics effect policy · fixed');
  state.turns = [{ reply: 'Legacy result', modeCapability: { effectiveMode: 'fixed' } }];
  await render();
  expect(container.textContent).not.toContain('effect policy');
});
