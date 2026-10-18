import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import { MemoryRouter } from 'react-router-dom';
import AgentLane from './AgentLane.jsx';
import { useBoundRoleAssistant } from '../hooks/useBoundRoleAssistant.js';

jest.mock('../bridge/fetchAdapter.mjs', () => ({ getBridgeFetchMetadata: () => ({ boundReviews: true }) }));
jest.mock('../context/AuthContext.jsx', () => ({ useAuth: () => ({ user: { id: 7 }, token: 'admin-token' }) }));
jest.mock('../hooks/useBoundRoleAssistant.js', () => ({ useBoundRoleAssistant: jest.fn() }));

let node;
let root;
beforeEach(() => {
  globalThis.IS_REACT_ACT_ENVIRONMENT = true;
  node = document.createElement('div');
  document.body.append(node);
  root = createRoot(node);
  useBoundRoleAssistant.mockReturnValue({ turns: [], pending: null, status: 'idle', error: null,
    send: jest.fn().mockResolvedValue(true), recover: jest.fn().mockResolvedValue(true) });
});
afterEach(async () => { await act(async () => root.unmount()); node.remove(); jest.clearAllMocks(); });

test('bound admin lane keeps the role composer outside its scrolling body', async () => {
  await act(async () => root.render(<MemoryRouter><AgentLane role="admin" /></MemoryRouter>));
  const body = node.querySelector('.ss-lane__body');
  const slot = node.querySelector('[data-testid="admin-role-composer-slot"]');
  expect(slot).not.toBeNull();
  expect(body.querySelector('form')).toBeNull();
  expect(slot.querySelector('form')).not.toBeNull();
  expect(slot.querySelector('#lane-admin-assistant-admin-lane')).not.toBeNull();
});
