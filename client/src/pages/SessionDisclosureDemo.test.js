import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import axios from 'axios';
import SessionDisclosureDemo from './SessionDisclosureDemo';
jest.mock('axios', () => ({ get: jest.fn(), post: jest.fn() }));
jest.mock('../components/WorkshopNavbar', () => () => null);
let node, root;
const packet = generation => ({ data: { scope: 'isolated synthetic lab session', session: { sessionId: 'lab-only', role: 'learner', generation }, cookies: { dvaia_lab_session: `lab-cookie-${generation}`, platform_token: 'MUST_NOT_RENDER' }, platformToken: 'MUST_NOT_RENDER' } });
const click = async text => { await act(async () => { [...node.querySelectorAll('button')].find(b => b.textContent === text).click(); }); };
beforeEach(() => { global.IS_REACT_ACT_ENVIRONMENT = true; axios.get.mockReset(); axios.post.mockReset(); node = document.createElement('div'); root = createRoot(node); act(() => root.render(<SessionDisclosureDemo />)); });
afterEach(() => act(() => root.unmount()));
test('inspect renders only the explicitly isolated credential projection', async () => {
  axios.get.mockResolvedValue(packet(0));
  expect(axios.get).not.toHaveBeenCalled();
  await click('Inspect lab session');
  expect(node.textContent).toContain('lab-cookie-0');
  expect(node.textContent).not.toContain('MUST_NOT_RENDER');
  expect(node.textContent).toContain('ungraded');
});
test('reset rotates through the server before fetching the replacement and removes old display', async () => {
  axios.get.mockResolvedValueOnce(packet(0)).mockResolvedValueOnce(packet(1));
  axios.post.mockResolvedValue({ data: { success: true, generation: 1 } });
  await click('Inspect lab session');
  await click('Reset lab session');
  expect(axios.post).toHaveBeenCalledWith('/api/vulnerabilities/session/reset', {}, expect.objectContaining({ signal: expect.any(AbortSignal) }));
  expect(node.textContent).toContain('lab-cookie-1');
  expect(node.textContent).not.toContain('lab-cookie-0');
});
test('failed reset clears stale display and does not fetch a claimed replacement', async () => {
  axios.get.mockResolvedValue(packet(0));
  await click('Inspect lab session');
  axios.post.mockRejectedValue(new Error('unavailable'));
  await click('Reset lab session');
  expect(axios.get).toHaveBeenCalledTimes(1);
  expect(node.textContent).not.toContain('lab-cookie-0');
  expect(node.textContent).toContain('could not be loaded');
});
test('rejects projections outside the isolated lab scope', async () => {
  axios.get.mockResolvedValue({ data: { scope: 'platform', session: {}, cookies: { dvaia_lab_session: 'MUST_NOT_RENDER' } } });
  await click('Inspect lab session');
  expect(node.textContent).not.toContain('MUST_NOT_RENDER');
  expect(node.textContent).toContain('could not be loaded');
});
test('unmount aborts an in-flight request', async () => {
  axios.get.mockImplementation(() => new Promise(() => {}));
  await click('Inspect lab session');
  const signal = axios.get.mock.calls[0][1].signal;
  act(() => root.unmount());
  expect(signal.aborted).toBe(true);
  root = createRoot(node);
});

test('does not report reset success when the refreshed generation disagrees', async () => {
  axios.post.mockResolvedValue({ data: { success: true, generation: 2 } });
  axios.get.mockResolvedValue(packet(1));
  await click('Reset lab session');
  expect(node.textContent).not.toContain('lab-cookie-1');
  expect(node.textContent).not.toContain('credential rotated');
  expect(node.textContent).toContain('could not be loaded');
});
