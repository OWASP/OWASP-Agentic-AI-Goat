import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import axios from 'axios';
import useCtfRecovery from './useCtfRecovery';
import CtfRecoveryNotice from '../components/CtfRecoveryNotice';
jest.mock('axios', () => ({ get: jest.fn(), post: jest.fn(), delete: jest.fn() }));
const operationId = '11111111-1111-4111-8111-111111111111';
let node, root, api;
function Harness({ scope = 1 }) { api = useCtfRecovery(scope); return <CtfRecoveryNotice notices={api.notices} />; }
async function flush() { await act(async () => { await Promise.resolve(); await Promise.resolve(); }); }
beforeEach(() => {
 global.IS_REACT_ACT_ENVIRONMENT = true; jest.useFakeTimers(); localStorage.setItem('token', 'original');
 for (const mock of Object.values(axios)) mock.mockReset();
 node = document.createElement('div'); document.body.appendChild(node); root = createRoot(node);
 act(() => root.render(<Harness />));
});
afterEach(() => { act(() => root.unmount()); node.remove(); jest.restoreAllMocks(); jest.useRealTimers(); localStorage.clear(); });
const send = (method = 'post', url = '/api/ctf/register') => api.request(method, url, {}, { headers: { Authorization: 'Bearer original' } });
test('initial deadline aborts HTTP, retains unknown state until explicit dismissal, never retries', async () => {
 let late; axios.post.mockImplementation(() => new Promise(resolve => { late = resolve; }));
 let result; await act(async () => { result = send(); result.catch(() => {}); });
 await act(async () => jest.advanceTimersByTimeAsync(180000));
 expect(axios.post.mock.calls[0][2].signal.aborted).toBe(true);
 expect(node.textContent).toContain('Outcome unknown'); expect(node.textContent).not.toContain('Check status');
 await act(async () => late({ status: 200, data: { success: true } }));
 expect(node.textContent).toContain('Outcome unknown'); expect(axios.post).toHaveBeenCalledTimes(1);
 await act(async () => node.querySelector('button').click());
 await expect(result).rejects.toMatchObject({ code: 'CTF_RECOVERY_CANCELLED' });
});
test('same pending delete shares original promise including parked recovery', async () => {
 axios.delete.mockResolvedValue({ status: 202, data: { operationId } });
 axios.get.mockRejectedValue({ response: { status: 503 } });
 let first, duplicate;
 await act(async () => { first = send('delete', '/api/ctf/admin/stages/1'); first.catch(() => {}); duplicate = send('delete', '/api/ctf/admin/stages/1'); });
 await flush(); expect(duplicate).toBe(first); expect(axios.delete).toHaveBeenCalledTimes(1);
 expect(send('delete', '/api/ctf/admin/stages/1')).toBe(first); expect(node.textContent).toContain('Check status');
 axios.get.mockResolvedValue({ status: 200, data: { success: true } });
 await act(async () => [...node.querySelectorAll('button')].find(x => x.textContent === 'Check status').click());
 await expect(first).resolves.toMatchObject({ data: { success: true } }); expect(axios.delete).toHaveBeenCalledTimes(1);
});
test.each(['session', 'navigation'])('%s invalidates pending HTTP and late response', async kind => {
 const timers = jest.spyOn(global, 'setTimeout'), clearTimer = jest.spyOn(global, 'clearTimeout');
 const intervals = jest.spyOn(global, 'setInterval'), clearWatch = jest.spyOn(global, 'clearInterval');
 let late; axios.post.mockImplementation(() => new Promise(resolve => { late = resolve; }));
 let pending; await act(async () => { pending = send(); pending.catch(() => {}); });
 if (kind === 'session') { localStorage.setItem('token', 'other'); await act(async () => jest.advanceTimersByTimeAsync(200)); }
 else { act(() => root.render(<Harness scope={2} />)); }
 await expect(pending).rejects.toMatchObject({ code: 'CTF_RECOVERY_CANCELLED' });
 expect(axios.post.mock.calls[0][2].signal.aborted).toBe(true);
 await flush();
 const deadlineIndex = timers.mock.calls.findIndex(args => args[1] === 180000);
 const watcherIndex = intervals.mock.calls.findIndex(args => args[1] === 200);
 expect(deadlineIndex).toBeGreaterThanOrEqual(0); expect(watcherIndex).toBeGreaterThanOrEqual(0);
 expect(clearTimer).toHaveBeenCalledWith(timers.mock.results[deadlineIndex].value);
 expect(clearWatch).toHaveBeenCalledWith(intervals.mock.results[watcherIndex].value);
 await act(async () => late({ status: 200, data: { success: true } }));
 expect(node.textContent).toBe(''); expect(axios.post).toHaveBeenCalledTimes(1);
});
test('global reset cancels older parked recovery before its own original POST', async () => {
 axios.post.mockResolvedValueOnce({ status: 202, data: { operationId } }).mockResolvedValueOnce({ status: 200, data: { success: true } });
 axios.get.mockRejectedValue({ response: { status: 503 } });
 let prior, reset; await act(async () => { prior = send(); prior.catch(() => {}); }); await flush();
 await act(async () => { reset = send('post', '/api/ctf/admin/reset'); });
 await expect(prior).rejects.toMatchObject({ code: 'CTF_RECOVERY_CANCELLED' });
 await expect(reset).resolves.toMatchObject({ data: { success: true } }); expect(node.textContent).toBe('');
});

test('repeated global reset shares pending result and never cancels itself', async () => {
 axios.post.mockResolvedValue({ status: 202, data: { operationId } }); axios.get.mockRejectedValue({ response: { status: 503 } });
 let first; await act(async () => { first = send('post', '/api/ctf/admin/reset'); first.catch(() => {}); }); await flush();
 expect(send('post', '/api/ctf/admin/reset')).toBe(first);
 expect(axios.post).toHaveBeenCalledTimes(1); expect(node.textContent).toContain('Check status');
});

test('initial attempt202 only reads; explicit Check status resumes deterministic work once', async () => {
 const admissionId='22222222-2222-4222-8222-222222222222',blockedOperationId='33333333-3333-4333-8333-333333333333';
 const read=state=>({status:200,data:{version:1,state,runId:operationId,admissionId,blockedOperationId,decisionId:null,currentCompletion:false}});
 axios.post.mockResolvedValueOnce({status:202,data:{runId:operationId}}).mockResolvedValueOnce({status:202,data:{state:'recovery_pending'}});
 axios.get.mockResolvedValue(read('outcome_stored'));
 let pending;await act(async()=>{pending=send('post','/api/ctf/stage/1/attempt');pending.catch(()=>{});});await flush();
 expect(axios.post).toHaveBeenCalledTimes(1);expect(node.textContent).toContain('Check status');
 axios.get.mockReset().mockResolvedValueOnce(read('outcome_stored')).mockResolvedValueOnce(read('blocked_publishable')).mockResolvedValueOnce({status:200,data:{blocked:true,success:false,reason:'Input blocked',attemptNumber:1}});
 await act(async()=>[...node.querySelectorAll('button')].find(x=>x.textContent==='Check status').click());
 await expect(pending).resolves.toMatchObject({data:{blocked:true}});expect(axios.post).toHaveBeenCalledTimes(2);
 expect(axios.post.mock.calls.map(x=>x[0])).toEqual(['/api/ctf/stage/1/attempt',`/api/ctf/predefense/${operationId}/resume`]);
});
