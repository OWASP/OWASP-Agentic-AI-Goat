import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import { MemoryRouter, useNavigate, useLocation } from 'react-router-dom';
import axios from 'axios';
import CTFChallenge from './CTFChallenge';
import { SessionProvider } from '../context/AuthContext';
jest.mock('axios', () => ({ get: jest.fn(), post: jest.fn() }));
jest.mock('../context/AuthContext', () => {
  const React = require('react');
  const Context = React.createContext(null);
  return { useAuth: () => React.useContext(Context), SessionProvider: Context.Provider };
});
const stage = { id: 5, stage_number: 5, stage_name: 'Session stage', ai_guardian_name: 'Guardian', level_score: 100 };
const started = (hint, attempts = 1) => ({ data: { stage, purchasedHints: [hint], hintsAvailable: true, hintsUsed: 1, hintPenaltyTotal: 10, attemptsSoFar: attempts } });
const deferred = () => { let resolve; const promise = new Promise(r => { resolve = r; }); return { promise, resolve }; };
let node, root, navigate, currentPath;
let mockAuthRevision;
async function flush() { await act(async () => { for (let i = 0; i < 12; i++) await Promise.resolve(); }); }
function Nav() { navigate = useNavigate(); currentPath = useLocation().pathname; return null; }
function render(user) { act(() => root.render(<SessionProvider value={{ user, getAuthRevision: () => mockAuthRevision }}><MemoryRouter initialEntries={[{ pathname: '/ctf/challenge', state: { stage } }]}><Nav /><CTFChallenge /></MemoryRouter></SessionProvider>)); }
async function submit(text) {
  await act(async () => { const el = node.querySelector('textarea'); Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, 'value').set.call(el, text); el.dispatchEvent(new Event('input', { bubbles: true })); });
  await act(async () => node.querySelector('form').dispatchEvent(new Event('submit', { bubbles: true, cancelable: true })));
  await flush();
}
beforeEach(() => {
  global.IS_REACT_ACT_ENVIRONMENT = true; Element.prototype.scrollIntoView = jest.fn();
  mockAuthRevision = 0;
  localStorage.setItem('token', 'owner-a'); axios.post.mockReset(); axios.get.mockReset();
  axios.get.mockResolvedValue({ data: { config: { ctf_show_attempt_counter: 'true', ctf_hint_cost_2: '10' } } });
  node = document.createElement('div'); document.body.appendChild(node); root = createRoot(node);
});
afterEach(() => { act(() => root.unmount()); node.remove(); localStorage.clear(); });
test('same-tab owner replacement clears prior hints and transcript, starts new owner and rotates client session', async () => {
  axios.post.mockResolvedValueOnce(started('private hint A')).mockResolvedValueOnce({ data: { aiResponse: 'private answer A', attemptNumber: 2 } });
  render({ id: 1 }); await flush(); await submit('old prompt');
  const firstSession = axios.post.mock.calls.find(x => x[0].endsWith('/attempt'))[1].sessionToken;
  expect(node.textContent).toContain('private hint A'); expect(node.textContent).toContain('private answer A');
  const next = deferred(); axios.post.mockReturnValueOnce(next.promise);
  localStorage.setItem('token', 'owner-b'); render({ id: 2 }); await flush();
  expect(node.textContent).not.toContain('private hint A'); expect(node.textContent).not.toContain('private answer A');
  expect(node.querySelector('textarea')?.disabled ?? true).toBe(true);
  next.resolve(started('private hint B', 7)); await flush();
  expect(node.textContent).toContain('private hint B'); expect(node.querySelector('textarea').disabled).toBe(false);
  axios.post.mockResolvedValueOnce({ data: { aiResponse: 'new owner answer', attemptNumber: 8 } }); await submit('new prompt');
  const attempts = axios.post.mock.calls.filter(x => x[0].endsWith('/attempt'));
  expect(attempts[1][2].headers.Authorization).toBe('Bearer owner-b'); expect(attempts[1][1].sessionToken).not.toBe(firstSession);
  expect(node.textContent).toContain('new owner answer');
});
test('token replacement before rerender suppresses stale dispatch and late old attempt', async () => {
  const old = deferred(); axios.post.mockResolvedValueOnce(started('hint A')).mockReturnValueOnce(old.promise);
  render({ id: 1 }); await flush(); await submit('held prompt');
  const next = deferred(); axios.post.mockReturnValueOnce(next.promise);
  localStorage.setItem('token', 'owner-b'); old.resolve({ data: { aiResponse: 'late old answer', success: true, message: 'old completion' } }); await flush();
  expect(node.textContent).not.toContain('late old answer'); expect(node.textContent).not.toContain('old completion');
  expect(node.querySelector('form')).toBeNull();
  expect(axios.post.mock.calls.filter(c => c[0].endsWith('/attempt'))).toHaveLength(1);
  render({ id: 1 }); next.resolve(started('hint B')); await flush(); expect(node.querySelector('textarea').disabled).toBe(false);
});
test('same-stage route replacement retires old pending attempt and starts a fresh route lifetime', async () => {
  const old = deferred(); axios.post.mockResolvedValueOnce(started('old route hint')).mockReturnValueOnce(old.promise);
  render({ id: 1 }); await flush(); await submit('old route prompt');
  axios.post.mockResolvedValueOnce(started('new route hint'));
  await act(async () => navigate('/ctf/challenge', { state: { stage: { ...stage } } })); await flush();
  old.resolve({ data: { aiResponse: 'old route late response', success: true } }); await flush();
  expect(node.textContent).toContain('new route hint'); expect(node.textContent).not.toContain('old route late response'); expect(node.querySelector('textarea').disabled).toBe(false);
});

test('pending hint from prior owner cannot populate new owner purchased hints', async () => {
  const hint = deferred(); axios.post.mockResolvedValueOnce(started('owner A purchased hint')).mockReturnValueOnce(hint.promise);
  render({ id: 1 }); await flush();
  act(() => [...node.querySelectorAll('button')].find(b => b.textContent.includes('Unlock Hint 2')).click());
  await flush();
  act(() => [...node.querySelectorAll('button')].find(b => b.textContent.includes('Unlock (-')).click()); await flush();
  expect(axios.post.mock.calls.filter(c => c[0].endsWith('/hint'))).toHaveLength(1);
  axios.post.mockResolvedValueOnce(started('owner B purchased hint')); localStorage.setItem('token', 'owner-b'); render({ id: 2 }); await flush();
  hint.resolve({ data: { hint: 'late private hint A', hintsUsed: 2, totalPenalty: 30 } }); await flush();
  expect(node.textContent).toContain('owner B purchased hint'); expect(node.textContent).not.toContain('late private hint A');
  expect(node.textContent).not.toContain('owner A purchased hint'); expect(node.querySelector('textarea').disabled).toBe(false);
});

test('same user object with new token restarts while profile-only refresh preserves lesson', async () => {
  const user = { id: 1 }; axios.post.mockResolvedValueOnce(started('same user first session'));
  render(user); await flush(); render({ id: 1, name: 'updated profile' }); await flush();
  expect(axios.post.mock.calls.filter(c => c[0].endsWith('/start'))).toHaveLength(1);
  axios.post.mockResolvedValueOnce(started('same user renewed session'));
  localStorage.setItem('token', 'renewed-token'); render(user); await flush();
  expect(axios.post.mock.calls.filter(c => c[0].endsWith('/start'))).toHaveLength(2);
  expect(node.textContent).not.toContain('same user first session'); expect(node.textContent).toContain('same user renewed session');
});

test('ready old render cannot dispatch a payload with replacement token', async () => {
  axios.post.mockResolvedValueOnce(started('old ready session')); render({ id: 1 }); await flush();
  await act(async () => { const el = node.querySelector('textarea'); Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, 'value').set.call(el, 'typed under old owner'); el.dispatchEvent(new Event('input', { bubbles: true })); });
  localStorage.setItem('token', 'replacement-without-render');
  act(() => node.querySelector('form').dispatchEvent(new Event('submit', { bubbles: true, cancelable: true })));
  expect(axios.post.mock.calls.filter(c => c[0].endsWith('/attempt'))).toHaveLength(0);
});

test('completed-stage start returns to dashboard without config reads or attempts', async () => {
  axios.post.mockResolvedValueOnce({ data: { alreadyCompleted: true, message: 'Stage already completed' } });
  render({ id: 1 }); await flush();
  expect(currentPath).toBe('/ctf'); expect(axios.get).not.toHaveBeenCalled();
  expect(axios.post.mock.calls.filter(c => c[0].endsWith('/attempt'))).toHaveLength(0);
});
test('old owner completed-stage response cannot redirect replacement session', async () => {
  const old = deferred(); axios.post.mockReturnValueOnce(old.promise);
  render({ id: 1 }); await flush();
  axios.post.mockResolvedValueOnce(started('replacement active stage'));
  localStorage.setItem('token', 'owner-b'); render({ id: 2 }); await flush();
  old.resolve({ data: { alreadyCompleted: true } }); await flush();
  expect(currentPath).toBe('/ctf/challenge'); expect(node.textContent).toContain('replacement active stage');
  expect(node.querySelector('textarea').disabled).toBe(false);
});
test('same-token auth revision starts a new CTF session and discards the old attempt response',async()=>{
 const old=deferred();axios.post.mockResolvedValueOnce(started('old session hint')).mockReturnValueOnce(old.promise);
 render({id:1});await flush();await submit('old prompt');
 const oldSession=axios.post.mock.calls.find(call=>call[0].endsWith('/attempt'))[1].sessionToken;
 axios.post.mockResolvedValueOnce(started('renewed session hint'));
 mockAuthRevision+=1;render({id:1});await flush();
 expect(axios.post.mock.calls.filter(call=>call[0].endsWith('/start'))).toHaveLength(2);
 old.resolve({data:{aiResponse:'late old answer',success:true,message:'old completion'}});await flush();
 expect(node.textContent).toContain('renewed session hint');
 expect(node.textContent).not.toContain('late old answer');
 expect(node.textContent).not.toContain('old session hint');
 axios.post.mockResolvedValueOnce({data:{aiResponse:'renewed answer',attemptNumber:2}});
 await submit('new prompt');
 const attempts=axios.post.mock.calls.filter(call=>call[0].endsWith('/attempt'));
 expect(attempts[1][1].sessionToken).not.toBe(oldSession);
});
test('ready challenge cannot submit through retained form after auth revision changes',async()=>{
 axios.post.mockResolvedValueOnce(started('ready session hint'));render({id:1});await flush();
 await act(async()=>{const el=node.querySelector('textarea');Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype,'value').set.call(el,'typed before revision');el.dispatchEvent(new Event('input',{bubbles:true}));});
 mockAuthRevision+=1;
 await act(async()=>node.querySelector('form').dispatchEvent(new Event('submit',{bubbles:true,cancelable:true})));
 await flush();
 expect(axios.post.mock.calls.filter(call=>call[0].endsWith('/attempt'))).toHaveLength(0);
});
