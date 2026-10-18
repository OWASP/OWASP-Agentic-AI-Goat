import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import AgentLane from './AgentLane.jsx';

jest.mock('../bridge/fetchAdapter.mjs', () => ({ getBridgeFetchMetadata: () => undefined }));
jest.mock('../context/AuthContext.jsx', () => ({ useAuth: () => ({ user: { id: 1 } }) }));
jest.mock('../hooks/useAgentStream.js', () => ({ useAgentStream: () => ({
  turns: [], status: 'idle', send: jest.fn(), error: null,
}) }));

let node;
let root;
beforeEach(() => {
  globalThis.IS_REACT_ACT_ENVIRONMENT = true;
  node = document.createElement('div');
  root = createRoot(node);
});
afterEach(async () => { await act(async () => root.unmount()); });

test.each([
  ['customer', 'Message to customer supervisor', 'recommend a laptop for coding'],
  ['merchant', 'Message to merchant supervisor', 'review a product listing'],
  ['admin', 'Message to admin supervisor', 'explain a recent audit event'],
])('%s agent lane has an accurate role label and starter', async (role, label, starter) => {
  await act(async () => root.render(<AgentLane role={role} />));
  expect(node.querySelector('input[aria-label]').getAttribute('aria-label')).toBe(label);
  expect(node.textContent).toContain(starter);
});
