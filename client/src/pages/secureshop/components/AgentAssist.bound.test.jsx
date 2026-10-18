import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import AgentAssist from './AgentAssist.jsx';
import { useProductQuestion } from '../hooks/useProductQuestion.js';
import { useAgentStream } from '../hooks/useAgentStream.js';

jest.mock('../bridge/fetchAdapter.mjs', () => ({ getBridgeFetchMetadata: () => ({ boundReviews: true }) }));
jest.mock('../context/AuthContext.jsx', () => ({ useAuth: () => ({ user: { id: 4, role: 'customer' }, token: 'shop-token' }) }));
jest.mock('../hooks/useProductQuestion.js', () => ({ useProductQuestion: jest.fn() }));
jest.mock('../hooks/useAgentStream.js', () => ({ useAgentStream: jest.fn() }));

let node, root, question;
beforeEach(() => {
  globalThis.IS_REACT_ACT_ENVIRONMENT = true;
  node = document.createElement('div'); document.body.append(node); root = createRoot(node);
  question = { turns: [], status: 'idle', error: null, validProduct: true, send: jest.fn().mockResolvedValue(true) };
  useProductQuestion.mockReturnValue(question);
});
afterEach(async () => { await act(async () => root.unmount()); node.remove(); });

test('bound product assist asks about the selected product and renders replies as text', async () => {
  await act(async () => root.render(<AgentAssist productId={11} prompt="Does it fit?" />));
  expect(useProductQuestion).toHaveBeenCalledWith(expect.objectContaining({ productId: 11 }));
  await act(async () => node.querySelector('form').dispatchEvent(new Event('submit', { bubbles: true, cancelable: true })));
  expect(question.send).toHaveBeenCalledWith('Does it fit?');
  expect(useAgentStream).not.toHaveBeenCalled();
  question.turns = [{ reply: '<img src=x onerror=alert(1)>', modeCapability: { version: 1, featureId: 'product_assist',
    policyVersion: 'bounded-product-data-and-catalog-neighbors-v1', effectiveMode: 'fixed',
    scope: { kind: 'launch_feature', id: 'product_assist' } } }];
  await act(async () => root.render(<AgentAssist productId={11} prompt="Does it fit?" />));
  expect(node.textContent).toContain('<img src=x onerror=alert(1)>');
  expect(node.querySelector('img')).toBeNull();
  expect(node.textContent).toContain('product_assist effect policy · fixed');
  await act(async () => root.render(<AgentAssist productId={12} prompt="New product" />));
  expect(node.querySelector('input').value).toBe('New product');
});
