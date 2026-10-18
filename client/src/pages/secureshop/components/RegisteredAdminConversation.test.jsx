import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import RegisteredAdminConversation from './RegisteredAdminConversation.jsx';
import { useRegisteredAdminStream } from '../hooks/useRegisteredAdminStream.js';

jest.mock('../hooks/useRegisteredAdminStream.js', () => ({ useRegisteredAdminStream: jest.fn() }));
jest.mock('../bridge/assessmentPanelIntent.mjs', () => ({
  isStandaloneShopFrame: () => false, openStandaloneAssessments: jest.fn(),
}));

const sessionId = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const requestId = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
let root, node, stream;
beforeEach(() => {
  globalThis.IS_REACT_ACT_ENVIRONMENT = true;
  node = document.createElement('div'); document.body.append(node); root = createRoot(node);
  stream = { turns: [{ sessionId, requestId, shopUserId: 7, user: 'Saved registered-tools request',
    reply: 'Saved result', hops: [], status: 'done', stopReason: 'end_turn' }],
  pending: null, completedPage: { sessionId, requestId }, status: 'idle', error: null,
  send: jest.fn(), recover: jest.fn(), recoverCompleted: jest.fn(),
  readAssessment: jest.fn().mockResolvedValue({ kind: 'unconfirmed' }),
  retryAssessment: jest.fn().mockResolvedValue({ kind: 'ineligible' }),
  readDescriptionAssessment: jest.fn().mockResolvedValue({ kind: 'unconfirmed' }),
  submitDescriptionAssessment: jest.fn().mockResolvedValue({ kind: 'ineligible' }) };
  useRegisteredAdminStream.mockReturnValue(stream);
});
afterEach(async () => { await act(async () => root.unmount()); node.remove(); jest.clearAllMocks(); });
const render = () => act(async () => root.render(<RegisteredAdminConversation shopUserId={7}
  authorityKey="parent-credential" visible />));
const button = text => [...node.querySelectorAll('button')].find(item => item.textContent.trim() === text);

test('saved registered result checks assessment, offers explicit retry, and never claims credit when ineligible', async () => {
  await render();
  expect(node.querySelector('[aria-label="Saved registered-tools assessment"]')).not.toBeNull();
  await act(async () => button('Check saved assessment').click());
  expect(stream.readAssessment).toHaveBeenCalledWith({ sessionId, requestId });
  expect(node.textContent).toContain('Assessment not confirmed');
  await act(async () => button('Retry saved assessment').click());
  expect(stream.retryAssessment).toHaveBeenCalledWith({ sessionId, requestId });
  expect(node.textContent).toContain('not eligible for objective credit');
  expect(node.textContent).not.toContain('Objective completed.');
});

test('description assessment uses separate saved turn controls and never replays registered tools', async () => {
  await render();
  expect(node.querySelector('[aria-label="Saved registered-description assessment"]')).not.toBeNull();
  await act(async () => button('Check saved description assessment').click());
  expect(stream.readDescriptionAssessment).toHaveBeenCalledWith({ sessionId, requestId });
  expect(node.textContent).toContain('Description assessment is unconfirmed');
  await act(async () => button('Assess description adoption').click());
  expect(stream.submitDescriptionAssessment).toHaveBeenCalledWith({ sessionId, requestId });
  expect(button('Assess description adoption')).toBeUndefined();
  expect(stream.send).not.toHaveBeenCalled();
  expect(node.textContent).toContain('not eligible for description-adoption credit');
});

test('unavailable completed-page hydration offers exact GET recovery without an assessment claim', async () => {
  stream.turns = []; stream.completedPage = { sessionId, requestId };
  await render();
  expect(node.querySelector('[aria-label="Saved registered-tools page"]')).not.toBeNull();
  expect(node.querySelector('[aria-label="Saved registered-tools assessment"]')).toBeNull();
  await act(async () => button('Check saved registered-tools page').click());
  expect(stream.recoverCompleted).toHaveBeenCalledTimes(1);
});
