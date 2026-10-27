import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import { MemoryRouter, Routes, Route, useLocation } from 'react-router-dom';
import CTFChallenge from './CTFChallenge';
import axios from 'axios';
import CTFDashboard from './CTFDashboard';
jest.mock('axios', () => ({ get: jest.fn(), post: jest.fn() }));
let mockUser = { id: 7, username: 'Learner' };
let mockAuthRevision = 0;
jest.mock('../context/AuthContext', () => ({ useAuth: () => ({ user: mockUser, getAuthRevision: () => mockAuthRevision }) }));
const operationId = '11111111-1111-4111-8111-111111111111';
async function flush() { await act(async () => { await Promise.resolve(); await Promise.resolve(); }); }
let node, root;
beforeEach(async () => {
 mockUser = { id: 7, username: 'Learner' };
 mockAuthRevision = 0;
 global.IS_REACT_ACT_ENVIRONMENT = true; localStorage.setItem('token', 'owner'); axios.get.mockReset(); axios.post.mockReset();
 axios.get.mockImplementation(url => Promise.resolve({ data: url.endsWith('/config') ? { config: { ctf_registration_open: 'true' } } : url.endsWith('/stages') ? { stages: [] } : { registered: false } }));
 node = document.createElement('div'); document.body.appendChild(node); root = createRoot(node);
 act(() => root.render(<MemoryRouter><CTFDashboard /></MemoryRouter>)); await flush();
});
afterEach(() => { act(() => root.unmount()); node.remove(); localStorage.clear(); });
test('registration202 does not refresh or report registered until current operation200', async () => {
 let finish; axios.post.mockResolvedValue({ status: 202, data: { operationId } });
 axios.get.mockImplementationOnce(() => new Promise(resolve => { finish = resolve; }));
 await act(async () => node.querySelector('form').dispatchEvent(new Event('submit', { bubbles: true, cancelable: true })));
 await flush(); expect(node.textContent).toContain('Registering'); expect(axios.get).toHaveBeenCalledTimes(4);
 await act(async () => finish({ status: 200, data: { success: true } })); await flush();
 expect(axios.get).toHaveBeenCalledTimes(7); expect(axios.post).toHaveBeenCalledTimes(1);
});
test('lost registration response keeps entered name and unknown notice, no refresh or retry', async () => {
 axios.post.mockRejectedValue(new Error('lost'));
 await act(async () => node.querySelector('form').dispatchEvent(new Event('submit', { bubbles: true, cancelable: true })));
 await flush(); expect(node.textContent).toContain('Outcome unknown'); expect(node.querySelector('#displayName').value).toBe('Learner');
 expect(axios.get).toHaveBeenCalledTimes(3); expect(axios.post).toHaveBeenCalledTimes(1);
});


test('dashboard navigation leaves the single authenticated start and config read to challenge initialization', async () => {
 act(() => root.unmount()); root = createRoot(node); Element.prototype.scrollIntoView = jest.fn();
 const stage = { id: 1, stage_number: 1, stage_order: 1, stage_name: 'Owned navigation', stage_description: 'Current description', difficulty: 'easy', level_score: 100, ai_guardian_name: 'Guardian' };
 let finishStart; const events=[];
 axios.get.mockImplementation(url => {events.push(url);return Promise.resolve({data:url.endsWith('/config')?{config:{ctf_hint_gating_attempts:'4',ctf_registration_open:'true'}}:url.endsWith('/stages')?{stages:[stage]}:{registered:true,participant:{id:7},progress:[],leaderboardEntry:{}}});});
 axios.post.mockImplementation(url=>{events.push(url);return new Promise(resolve=>{finishStart=resolve;});});
 function Location(){return <output data-location>{useLocation().pathname}</output>;}
 act(()=>root.render(<MemoryRouter initialEntries={['/ctf']}><Location/><Routes><Route path="/ctf" element={<CTFDashboard/>}/><Route path="/ctf/challenge" element={<CTFChallenge/>}/></Routes></MemoryRouter>));await flush();
 const card=[...node.querySelectorAll('h3')].find(e=>e.textContent==='Owned navigation').closest('[role="button"]');
 await act(async()=>card.dispatchEvent(new MouseEvent('click',{bubbles:true})));await flush();
 expect(node.querySelector('[data-location]').textContent).toBe('/ctf/challenge');expect(axios.post).toHaveBeenCalledTimes(1);
 const startIndex=events.indexOf('/api/ctf/stage/1/start');expect(events.slice(startIndex+1)).not.toContain('/api/ctf/config');
 await act(async()=>finishStart({status:200,data:{stage,hintsAvailable:false,hintsUsed:0,attemptsSoFar:3,purchasedHints:[]}}));await flush();
 expect(events.slice(startIndex+1)).toContain('/api/ctf/config');expect(node.textContent).toContain('Hints unlock after 4 attempts.');expect(axios.post).toHaveBeenCalledTimes(1);
});

function replaceOwner(token, user) {
 localStorage.setItem('token', token); mockUser = user;
 act(() => root.render(<MemoryRouter><CTFDashboard /></MemoryRouter>));
}
test('same-user token replacement reloads and delayed former status cannot publish', async () => {
 let oldStatus;
 axios.get.mockImplementation((url, options) => {
  if (url.endsWith('/status') && options.headers.Authorization === 'Bearer pending-owner') return new Promise(resolve => { oldStatus = resolve; });
  return Promise.resolve({data:url.endsWith('/config')?{config:{ctf_registration_open:'true'}}:url.endsWith('/stages')?{stages:[]}:{registered:false}});
 });
 replaceOwner('pending-owner', {id:7,username:'Old name'}); await flush();
 replaceOwner('new-owner', {id:7,username:'New name'}); await flush();
 expect(node.querySelector('#displayName').value).toBe('New name');
 await act(async()=>oldStatus({data:{registered:true,participant:{id:7},progress:[]}})); await flush();
 expect(node.querySelector('#displayName').value).toBe('New name');
 expect(axios.get.mock.calls.filter(([url, options])=>url.endsWith('/status')&&options.headers.Authorization==='Bearer new-owner')).toHaveLength(1);
});
test('replacement during registration refresh rejects old error and preserves new owner input', async () => {
 let rejectOld;
 axios.post.mockResolvedValue({status:200,data:{success:true}});
 axios.get.mockImplementation((url, options)=>{
  if(url.endsWith('/status')&&options.headers.Authorization==='Bearer owner')return new Promise((resolve,reject)=>{rejectOld=reject;});
  return Promise.resolve({data:url.endsWith('/config')?{config:{ctf_registration_open:'true'}}:url.endsWith('/stages')?{stages:[]}:{registered:false}});
 });
 await act(async()=>node.querySelector('form').dispatchEvent(new Event('submit',{bubbles:true,cancelable:true})));await flush();
 replaceOwner('second',{id:8,username:'Second learner'});await flush();
 await act(async()=>rejectOld({response:{status:503,data:{error:'OLD OWNER ERROR'}}}));await flush();
 expect(node.textContent).not.toContain('OLD OWNER ERROR');expect(node.textContent).not.toContain('Registering');
 expect(node.querySelector('#displayName').value).toBe('Second learner');expect(axios.post).toHaveBeenCalledTimes(1);
});
test('unmounted pending owner load does not publish or issue a replacement read', async()=>{
 const finishes=[];axios.get.mockImplementation(()=>new Promise(resolve=>{finishes.push(resolve);}));
 replaceOwner('pending',{id:8,username:'Pending'});await flush();const calls=axios.get.mock.calls.length;
 act(()=>root.unmount());root=createRoot(node);
 await act(async()=>finishes.forEach(finish=>finish({data:{registered:true}})));await flush();
 expect(node.textContent).toBe('');expect(axios.get).toHaveBeenCalledTimes(calls);
});

test('live token fences old load before rerender and replacement owner can register normally', async()=>{
 let oldStatus;let registered=false;
 axios.get.mockImplementation((url, options)=>{
  if(url.endsWith('/status')&&options.headers.Authorization==='Bearer delayed')return new Promise(resolve=>{oldStatus=resolve;});
  return Promise.resolve({data:url.endsWith('/config')?{config:{ctf_registration_open:'true'}}:url.endsWith('/stages')?{stages:[]}:{registered,participant:registered?{id:9}:undefined}});
 });
 replaceOwner('delayed',{id:7,username:'Old'});await flush();
 localStorage.setItem('token','replacement');
 await act(async()=>oldStatus({data:{registered:true,participant:{id:7}}}));await flush();
 // No AuthContext rerender yet: the former result must not end the loading view.
 expect(node.querySelector('form')).toBeNull();
 expect(node.textContent).toMatch(/loading/i);
 replaceOwner('replacement',{id:9,username:'Replacement'});await flush();
 expect(node.querySelector('#displayName').value).toBe('Replacement');
 axios.post.mockImplementation((url,body,options)=>{
  expect(url).toBe('/api/ctf/register');expect(options.headers.Authorization).toBe('Bearer replacement');
  expect(body.displayName).toBe('Replacement');registered=true;
  return Promise.resolve({status:200,data:{success:true}});
 });
 await act(async()=>node.querySelector('form').dispatchEvent(new Event('submit',{bubbles:true,cancelable:true})));await flush();
 expect(axios.post).toHaveBeenCalledTimes(1);expect(node.querySelector('form')).toBeNull();
 expect(node.textContent).not.toMatch(/loading|registering/i);
 expect(axios.get.mock.calls.filter(([url,options])=>url.endsWith('/status')&&options.headers.Authorization==='Bearer replacement')).toHaveLength(2);
});
test('same-token auth revision retires a pending status read and loads the renewed session',async()=>{
 let finishOldStatus;let statusCalls=0;
 axios.get.mockImplementation(url=>{
  if(url.endsWith('/status')){
   statusCalls+=1;
   return statusCalls===1?new Promise(resolve=>{finishOldStatus=resolve;}):Promise.resolve({data:{registered:false}});
  }
  return Promise.resolve({data:url.endsWith('/config')?{config:{ctf_registration_open:'true'}}:{stages:[]}});
 });
 replaceOwner('same-token',{id:7,username:'Learner'});await flush();
 mockAuthRevision+=1;
 replaceOwner('same-token',{id:7,username:'Learner'});await flush();
 expect(statusCalls).toBe(2);
 await act(async()=>finishOldStatus({data:{registered:true,participant:{id:7}}}));await flush();
 expect(node.querySelector('form')).not.toBeNull();
});
test('ready dashboard cannot register through a retained handler after auth revision changes',async()=>{
 expect(node.querySelector('form')).not.toBeNull();
 mockAuthRevision+=1;
 await act(async()=>node.querySelector('form').dispatchEvent(new Event('submit',{bubbles:true,cancelable:true})));
 await flush();
 expect(axios.post).not.toHaveBeenCalled();
});
