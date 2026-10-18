import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import axios from 'axios';
import { toast } from 'react-toastify';
import SensitiveInfoWorkshop from './SensitiveInfoWorkshop';
let mockUser = { id: 1 };
let mockRetry;
let mockPoll;
jest.mock('../../context/AuthContext', () => ({ useAuth: () => ({ user: mockUser }) }));
jest.mock('axios', () => ({ get: jest.fn(), post: jest.fn() }));
jest.mock('react-toastify', () => ({ toast: { warn: jest.fn(), info: jest.fn(), error: jest.fn(), success: jest.fn() } }));
jest.mock('../../components/workshop/JudgeRetryButton', () => props => { mockRetry = props.onResult; return null; });
jest.mock('../../components/VulnerabilityTemplate', () => ({ children }) => <div>{children}</div>);
jest.mock('../../hooks/useWorkshopHeartbeat', () => () => {});
jest.mock('../../hooks/useChangePolling', () => fn => { mockPoll = fn; });
jest.mock('../../context/WorkshopConfigContext', () => ({ useWorkshopConfig: () => ({ revision: 1, snapshot: { exercises: { sensitive_info_disclosure: { isVisible: true, objectives: { tool_enum: { isVisible: true }, llm_identify: { isVisible: true } } } } } }) }));
globalThis.IS_REACT_ACT_ENVIRONMENT = true;
const deferred = () => { let resolve; const promise = new Promise(r => { resolve = r; }); return { promise, resolve }; };
let root, node;
const render = async () => { await act(async () => { root.render(<SensitiveInfoWorkshop />); }); };
const click = async label => { const b = [...node.querySelectorAll('button'), ...document.querySelectorAll('[role="alertdialog"] button')].find(x => x.textContent.trim() === label); expect(b).toBeDefined(); await act(async () => b.click()); };
const send = async text => {
 const input = node.querySelector('textarea');
 await act(async () => { Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, 'value').set.call(input, text); input.dispatchEvent(new Event('input', { bubbles: true })); });
 await act(async () => { input.dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter', bubbles: true })); });
};
beforeEach(async () => {
 jest.clearAllMocks(); mockUser = { id: 1 }; localStorage.setItem('token', 'owner-a');
 axios.get.mockImplementation(url => Promise.resolve({ data: url.endsWith('/mode') ? { mode: 'vulnerable' } : url.includes('/progress/') ? { progress: localStorage.getItem('token') === 'owner-b' ? [{ id: 'llm_identify', completed: true }] : [] } : { available: false } }));
 axios.post.mockImplementation(url => Promise.resolve({ data: url.endsWith('/chat') ? { response: 'current answer', judgments: [{ verdict: 'unavailable', evaluationId: 'eval-a', canRetry: true }] } : { success: true } }));
 node = document.createElement('div'); root = createRoot(node); await render();
});
afterEach(async () => { await act(async () => root.unmount()); localStorage.clear(); });
const replace = async () => { localStorage.setItem('token', 'owner-b'); mockUser = { id: 2 }; await render(); };
test('account replacement clears populated transcript and reloads progress; current chat has no previous history', async () => {
 await send('old private question'); expect(node.textContent).toContain('old private question');
 await replace(); expect(node.textContent).not.toContain('old private question'); expect(node.textContent).toContain('1 / 2');
 await send('new question'); expect(node.textContent).toContain('current answer');
 const posts = axios.post.mock.calls.filter(([url]) => url.endsWith('/chat')); expect(posts.at(-1)[1].conversationHistory).toEqual([]);
});
test('pending old reset cannot erase replacement transcript/progress or toast', async () => {
 const pending = deferred(); const base = axios.post.getMockImplementation(); axios.post.mockImplementation((url,...args) => url.endsWith('/progress/reset') ? pending.promise : base(url,...args));
 await click('Reset objective progress'); await click('Confirm reset'); await replace(); await send('new owner question'); toast.success.mockClear();
 await act(async () => pending.resolve({ data: { success: true } }));
 expect(node.textContent).toContain('new owner question'); expect(node.textContent).toContain('1 / 2'); expect(toast.success).not.toHaveBeenCalledWith('Progress reset');
});
test('progress reset waits for confirmation and rejects duplicate confirms while pending', async () => {
 await send('Existing conversation');
 const pending = deferred(); const base = axios.post.getMockImplementation();
 axios.post.mockImplementation((url,...args) => url.endsWith('/progress/reset') ? pending.promise : base(url,...args));
 await click('Reset objective progress');
 expect(axios.post.mock.calls.filter(([url]) => url.endsWith('/progress/reset'))).toHaveLength(0);
 expect(node.textContent).toContain('Existing conversation');
 const dialog = document.querySelector('[role="alertdialog"]');
 expect(dialog.textContent).toContain('Reset objective progress?');
 const confirm = [...dialog.querySelectorAll('button')].find(button => button.textContent === 'Confirm reset');
 act(() => { confirm.click(); confirm.click(); });
 expect(axios.post.mock.calls.filter(([url]) => url.endsWith('/progress/reset'))).toHaveLength(1);
 expect(node.textContent).toContain('Existing conversation');
 expect(confirm.disabled).toBe(true);
 await act(async () => pending.resolve({ data: { success: true } }));
 expect(node.textContent).not.toContain('Existing conversation');
 expect(document.querySelector('[role="alertdialog"]')).toBeNull();
});
test('old retry progress and retained callback cannot publish after token replacement, including before rerender', async () => {
 await send('seed retry'); const callback = mockRetry; const pending = deferred(); const base = axios.get.getMockImplementation(); let held = true;
 axios.get.mockImplementation((url,...args) => held && url.includes('/progress/') ? pending.promise : base(url,...args));
 let work; await act(async () => { work = callback({ completed: true, judgments: [] }); });
 localStorage.setItem('token', 'owner-b'); const calls = axios.get.mock.calls.length;
 await act(async () => callback({ completed: true, judgments: [] })); expect(axios.get.mock.calls.length).toBe(calls);
 held = false; await replace(); toast.success.mockClear();
 await act(async () => { pending.resolve({ data: { progress: [{ id: 'tool_enum', completed: true }, { id: 'llm_identify', completed: true }] } }); await work; });
 expect(node.textContent).toContain('1 / 2'); expect(toast.success).not.toHaveBeenCalledWith('Objective evaluation passed.');
});
test('same user token renewal retires old polling data and remains usable', async () => {
 const pending = deferred(); const base = axios.get.getMockImplementation(); let held = true;
 axios.get.mockImplementation((url,...args) => held && url.includes('/progress/') ? pending.promise : base(url,...args));
 let work; await act(async () => { work = mockPoll(null,null,{}); });
 localStorage.setItem('token', 'owner-b'); held = false; await render();
 await act(async () => { pending.resolve({ data: { progress: [{ id: 'tool_enum', completed: true }, { id: 'llm_identify', completed: true }] } }); await work; });
 expect(node.textContent).toContain('1 / 2'); await send('renewed session'); expect(node.textContent).toContain('current answer');
});
test('identity replacement with unchanged token retires pending retry and reloads session', async () => {
 await send('old identity'); const callback = mockRetry; const before = axios.get.mock.calls.length;
 mockUser = { id: 2 }; await render();
 expect(node.textContent).not.toContain('old identity'); expect(axios.get.mock.calls.length).toBeGreaterThan(before);
 const after = axios.get.mock.calls.length; await act(async () => callback({ completed: true, judgments: [] }));
 expect(axios.get.mock.calls.length).toBe(after); await send('replacement identity'); expect(node.textContent).toContain('current answer');
});
test('late chat response is rejected immediately when token changes before rerender', async () => {
 const pending = deferred(); const base = axios.post.getMockImplementation();
 axios.post.mockImplementation((url,...args) => url.endsWith('/chat') ? pending.promise : base(url,...args));
 await send('pending old question'); localStorage.setItem('token', 'owner-b');
 await act(async () => pending.resolve({ data: { response: 'old private answer', newlyCompletedObjectives: ['tool_enum'] } }));
 expect(node.textContent).not.toContain('old private answer'); expect(toast.success).not.toHaveBeenCalled();
 axios.post.mockImplementation(base); await render(); await send('new live question'); expect(node.textContent).toContain('current answer');
});
test('replacement owner can poll while old mode mutation remains pending', async () => {
 const pending = deferred(); const base = axios.post.getMockImplementation();
 axios.post.mockImplementation((url,...args) => url.endsWith('/mode') ? pending.promise : base(url,...args));
 const toggle = [...node.querySelectorAll('[data-workshop-mode-control] button')].find(x => x.textContent.trim() === 'Fixed');
 expect(toggle).toBeDefined(); await act(async () => toggle.click());
 expect(axios.post.mock.calls.some(([url]) => url.endsWith('/mode'))).toBe(true);
 await replace();
 await act(async () => { await mockPoll(null,null,{}); });
 expect(node.textContent).toContain('1 / 2'); toast.info.mockClear();
 await act(async () => pending.resolve({ data: { mode: 'fixed' } }));
 expect(toast.info).not.toHaveBeenCalled(); await send('new owner still usable'); expect(node.textContent).toContain('current answer');
});
