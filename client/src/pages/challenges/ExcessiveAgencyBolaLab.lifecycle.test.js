import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import axios from 'axios';
import { toast } from 'react-toastify';
import Page from './ExcessiveAgencyBolaLab';
jest.mock('../../context/WorkshopConfigContext',()=>({useWorkshopConfig:()=>({snapshot:{exercises:{excessive_agency:{isVisible:true,objectives:{objective_1:{isVisible:true}}}}},revision:'1'})}));
let mockPoll;
jest.mock('../../hooks/useChangePolling',()=>callback=>{mockPoll=callback;});
jest.mock('../../hooks/useWorkshopHeartbeat',()=>()=>{});
jest.mock('../../components/VulnerabilityTemplate',()=>({children})=>children);
jest.mock('axios',()=>({get:jest.fn(),post:jest.fn()}));
jest.mock('react-toastify',()=>({toast:{warn:jest.fn(),success:jest.fn(),error:jest.fn(),info:jest.fn()}}));
const deferred=()=>{let resolve,reject;const promise=new Promise((a,b)=>{resolve=a;reject=b;});return{promise,resolve,reject};};
let mockRetryResult;
jest.mock('../../components/workshop/JudgeRetryButton', () => props => { mockRetryResult = props.onResult; return null; });
let root,node;
const flush=async()=>act(async()=>{await Promise.resolve();await Promise.resolve();});
const click=async title=>{const label={'Reset Conversation':'Reset conversation','Reset Lab':'Reset lab progress'}[title];const button=label?[...node.querySelectorAll('button')].find(item=>item.textContent.trim()===label):node.querySelector(`[title="${title}"]`);await act(async()=>button.click());await flush();if(title==='Reset Lab'){const confirm=[...document.querySelectorAll('button')].find(item=>item.textContent.trim()==='Confirm reset');await act(async()=>confirm.click());await flush();}};
const login=async name=>{await act(async()=>[...node.querySelectorAll('button')].find(b=>b.textContent.includes(`Login as ${name}`)).click());await flush();};
const submit=async text=>{const input=node.querySelector('textarea');await act(async()=>{Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype,'value').set.call(input,text);input.dispatchEvent(new Event('input',{bubbles:true}));});await act(async()=>input.closest('form').requestSubmit());await flush();};
const reply=text=>({data:{response:text,toolExecutions:[{id:'one',tool:'deleteNote',success:true,result:{success:true}}],progress:{objectives:{objective_1:true}}}});
beforeEach(async()=>{global.IS_REACT_ACT_ENVIRONMENT=true;localStorage.setItem('token','platform-before');axios.get.mockReset();axios.post.mockReset();Object.values(toast).forEach(f=>f.mockClear());axios.get.mockResolvedValue({data:{mode:'vuln',objectives:{},progress:{objectives:{}},message:'Current welcome'}});axios.post.mockImplementation((url,body)=>Promise.resolve(url.endsWith('/auth/login')?{data:{user:{username:body.username},sessionToken:body.username+'-token'}}:{data:{success:true}}));node=document.createElement('div');document.body.append(node);root=createRoot(node);await act(async()=>root.render(<Page/>));await login('Alice');});
afterEach(()=>{if(root)act(()=>root.unmount());node.remove();});
test.each(['Reset Conversation','Reset Lab'])('late pre-%s chat cannot restore cleared response or tools',async title=>{const pending=deferred();axios.post.mockImplementation(url=>url.endsWith('/chat')?pending.promise:Promise.resolve({data:{success:true}}));await submit('old request');await click(title);await act(async()=>pending.resolve(reply('obsolete answer')));expect(node.textContent).not.toContain('obsolete answer');expect(node.querySelector('textarea').disabled).toBe(false);});
test('progress reset requires confirmation before it dispatches', async () => {
  const button = [...node.querySelectorAll('button')].find(item => item.textContent.trim() === 'Reset lab progress');
  await act(async () => button.click()); await flush();
  expect(axios.post.mock.calls.some(([url]) => url.endsWith('/progress/reset'))).toBe(false);
  expect(document.querySelector('[role="alertdialog"]')?.textContent).toContain('Reset Excessive Agency progress?');
  const cancel = [...document.querySelectorAll('button')].find(item => item.textContent.trim() === 'Cancel');
  await act(async () => cancel.click()); await flush();
  expect(axios.post.mock.calls.some(([url]) => url.endsWith('/progress/reset'))).toBe(false);
});
test('failed reset preserves settled history and later chat remains usable',async()=>{axios.post.mockResolvedValueOnce(reply('retained answer'));await submit('prior request');axios.post.mockRejectedValueOnce(new Error('reset rejected'));await click('Reset Lab');expect(node.textContent).toContain('retained answer');expect(toast.error).toHaveBeenCalledWith('Failed to reset progress');expect(document.querySelector('[role="alertdialog"]')?.textContent).toContain('Failed to reset progress. Try again.');axios.post.mockResolvedValueOnce(reply('fresh answer'));await submit('new request');expect(node.textContent).toContain('fresh answer');});
test('logout and new login fence old chat response and error',async()=>{const old=deferred();axios.post.mockImplementation((url,body)=>url.endsWith('/chat')?old.promise:Promise.resolve(url.endsWith('/auth/login')?{data:{user:{username:body.username},sessionToken:body.username+'-token'}}:{data:{success:true}}));await submit('Alice request');await click('Logout');await login('Bob');await act(async()=>old.resolve(reply('Alice stale answer')));expect(node.textContent).not.toContain('Alice stale answer');expect(node.querySelector('textarea').disabled).toBe(false);});
test('unmounted pending reset failure emits no stale toast',async()=>{const pending=deferred();axios.post.mockReturnValueOnce(pending.promise);await click('Reset Lab');act(()=>root.unmount());root=null;await act(async()=>pending.reject(new Error('late failure')));expect(toast.error).not.toHaveBeenCalled();});

test('retired chat rejection cannot clear a newer chat loading state or display an error', async () => {
  const old = deferred(), current = deferred();
  axios.post.mockReturnValueOnce(old.promise);
  await submit('old request');
  const oldSignal = axios.post.mock.calls.at(-1)[2].signal;
  await click('Reset Conversation');
  expect(oldSignal.aborted).toBe(true);
  axios.post.mockReturnValueOnce(current.promise);
  await submit('new request');
  await act(async () => old.reject(new Error('old failure')));
  expect(node.querySelector('textarea').disabled).toBe(true);
  expect(toast.error).not.toHaveBeenCalled();
  await act(async () => current.resolve(reply('new answer')));
  expect(node.textContent).toContain('new answer');
  expect(node.querySelector('textarea').disabled).toBe(false);
});
test('old reset welcome cannot overwrite a new identity welcome', async () => {
  const welcome = deferred();
  axios.get.mockReturnValueOnce(welcome.promise);
  await click('Reset Conversation');
  await click('Logout');
  await login('Bob');
  await act(async () => welcome.resolve({data:{message:'Old Alice welcome'}}));
  expect(node.textContent).not.toContain('Old Alice welcome');
  expect(node.textContent).toContain('logged in as bob');
});
test('unmounted chat response and tool effects are ignored', async () => {
  const pending = deferred();
  axios.post.mockReturnValueOnce(pending.promise);
  await submit('pending');
  const signal = axios.post.mock.calls.at(-1)[2].signal;
  act(() => root.unmount()); root = null;
  expect(signal.aborted).toBe(true);
  await act(async () => pending.resolve(reply('late answer')));
  expect(toast.error).not.toHaveBeenCalled();
  expect(node.textContent).toBe('');
});


test.each(['current', 'during-reset', 'after-reset', 'aborted', 'persona', 'unmount'])('Judge retry lifecycle %s', async timing => {
  axios.post.mockResolvedValueOnce(reply('Current response'));
  await submit('current request');
  const callback = mockRetryResult;
  expect(callback).toEqual(expect.any(Function));
  const pendingProgress = deferred();
  const originalGet = axios.get.getMockImplementation();
  let hold = true;
  axios.get.mockImplementation((url, options) => url.endsWith('/progress') && hold
    ? (hold = false, pendingProgress.promise) : originalGet(url, options));
  const controller = new AbortController();
  let pending;
  try {
    if (timing === 'after-reset') await click('Reset Conversation');
    if (timing === 'persona') { hold = false; await click('Logout'); await login('Bob'); }
    if (timing === 'aborted') controller.abort();
    if (timing === 'unmount') { act(() => root.unmount()); root = null; }
    axios.get.mockClear(); toast.success.mockClear();
    await act(async () => { pending = callback({ completed: true, judgment: { verdict: 'unavailable', objectiveId: 'objective_1', explanation: 'Retry lifecycle feedback' } }, { signal: controller.signal }); await Promise.resolve(); });
    if (timing === 'during-reset') await click('Reset Conversation');
    await act(async () => { pendingProgress.resolve({ data: { progress: { objectives: { 1: true } } } }); await pending; });
    if (timing === 'current') {
      expect(toast.success).toHaveBeenCalledWith('Objective evaluation passed.');
      expect(node.textContent).toContain('Retry lifecycle feedback');
      expect(node.querySelector('.progress-text').textContent).toBe('1 of 1 objectives completed');
    }
    else {
      expect(toast.success).not.toHaveBeenCalledWith('Objective evaluation passed.');
      expect(node.textContent).not.toContain('Retry lifecycle feedback');
      if (timing !== 'unmount') expect(node.querySelector('.progress-text').textContent).toBe('0 of 1 objectives completed');
      if (timing !== 'during-reset') expect(axios.get).not.toHaveBeenCalled();
    }
  } finally { pendingProgress.resolve({ data: {} }); await act(async () => { await pending; }); }
});


test.each(['Reset Conversation', 'Reset Lab'])('%s retains unique welcome and subsequent message keys', async title => {
  const errors = jest.spyOn(console, 'error');
  try {
    await click(title);
    axios.post.mockResolvedValueOnce({ data: { response: 'First unique response' } });
    await submit('First unique request');
    axios.post.mockResolvedValueOnce({ data: { response: 'Second unique response' } });
    await submit('Second unique request');
    const texts = [...node.querySelectorAll('.message-text')].map(element => element.textContent);
    for (const expected of ['Current welcome', 'First unique request', 'First unique response', 'Second unique request', 'Second unique response']) {
      expect(texts.filter(text => text === expected)).toHaveLength(1);
    }
    expect(errors.mock.calls.filter(args => args.some(value => typeof value === 'string' && value.includes('same key')))).toEqual([]);
  } finally { errors.mockRestore(); }
});


test('same-tab platform replacement suppresses old chat and permits new teaching login', async () => {
  const old = deferred();
  axios.post.mockReturnValueOnce(old.promise);
  await submit('old platform request');
  const signal = axios.post.mock.calls.at(-1)[2].signal;
  localStorage.setItem('token', 'platform-after');
  // Live credential comparison protects the interval before React commits the new identity.
  await act(async () => old.resolve(reply('OLD PLATFORM SECRET')));
  expect(node.textContent).not.toContain('OLD PLATFORM SECRET');
  await act(async () => root.render(<Page/>));
  expect(signal.aborted).toBe(true);
  await login('Bob');
  axios.post.mockResolvedValueOnce(reply('CURRENT PLATFORM ANSWER'));
  await submit('new platform request');
  expect(node.textContent).toContain('CURRENT PLATFORM ANSWER');
  expect(node.querySelector('textarea').disabled).toBe(false);
});

test('platform replacement fences held Judge progress and retained retry callback', async () => {
  axios.post.mockResolvedValueOnce(reply('Current response'));
  await submit('current request');
  const callback = mockRetryResult, pendingProgress = deferred();
  axios.get.mockReturnValueOnce(pendingProgress.promise);
  let pending;
  await act(async () => { pending = callback({ completed:true }, {}); await Promise.resolve(); });
  localStorage.setItem('token', 'platform-after');
  await act(async () => root.render(<Page/>));
  await login('Bob');
  await act(async () => { pendingProgress.resolve({data:{progress:{objectives:{1:true}}}}); await pending; });
  axios.get.mockClear(); toast.success.mockClear();
  await act(async () => callback({ completed:true, judgment:{verdict:'unavailable',objectiveId:'objective_1',explanation:'OLD RETRY'} }, {}));
  expect(axios.get).not.toHaveBeenCalled();
  expect(toast.success).not.toHaveBeenCalled();
  expect(node.textContent).not.toContain('OLD RETRY');
  expect(node.querySelector('.progress-text').textContent).toBe('0 of 1 objectives completed');
});


test.each([false,true])('Judge retry progress 503 warns only for current owner, reset=%s',async reset=>{
  axios.post.mockResolvedValueOnce(reply('Settled response'));await submit('current request');
  const callback=mockRetryResult,progress=deferred(),originalGet=axios.get.getMockImplementation();let hold=true;
  axios.get.mockImplementation((url,options)=>url.endsWith('/progress')&&hold?(hold=false,progress.promise):originalGet(url,options));
  const before=node.querySelector('.progress-text').textContent;
  let pending;const errors=jest.spyOn(console,'error').mockImplementation(()=>{});
  try{
    await act(async()=>{pending=callback({completed:true,judgments:[]},{signal:new AbortController().signal});await Promise.resolve();});
    if(reset)await click('Reset Conversation');
    const expected=reset?node.querySelector('.progress-text').textContent:before;
    toast.success.mockClear();toast.warn.mockClear();
    await act(async()=>{progress.reject(Object.assign(new Error('Progress unavailable'),{response:{status:503}}));await pending;});
    expect(node.querySelector('.progress-text').textContent).toBe(expected);
    expect(toast.success).not.toHaveBeenCalledWith('Objective evaluation passed.');
    if(reset)expect(toast.warn).not.toHaveBeenCalled();
    else expect(toast.warn).toHaveBeenCalledWith('Evaluation received, but progress could not be refreshed. Refresh progress to see the latest counts.');
  }finally{errors.mockRestore();}
});

 test('retired mode request cannot block replacement persona polling', async () => {
  const pending=deferred();
  axios.post.mockReturnValueOnce(pending.promise);
  await act(async()=>[...node.querySelectorAll('[data-workshop-mode-control] button')].find(b=>b.textContent==='Fixed').click());
  await click('Logout'); await login('Bob');
  axios.get.mockClear();
  axios.get.mockResolvedValue({data:{mode:'vuln',objectives:{},progress:{objectives:{1:true}}}});
  await act(async()=>mockPoll(null,null,{signal:new AbortController().signal}));
  expect(axios.get).toHaveBeenCalledWith(expect.stringMatching(/\/progress$/),expect.objectContaining({headers:{'x-lab-session':'bob-token'}}));
  expect(node.querySelector('.progress-text').textContent).toBe('1 of 1 objectives completed');
  toast.info.mockClear();
  await act(async()=>pending.resolve({data:{mode:'fixed'}}));
  expect(toast.info).not.toHaveBeenCalled();
  expect(node.textContent).not.toContain('Lab mode changed to: FIXED');
  expect(node.querySelector('textarea').disabled).toBe(false);
});


test.each([false, true])('superseded Judge refresh retains newer poll progress without a failure warning, reject=%s', async reject => {
  axios.post.mockResolvedValueOnce(reply('Settled response')); await submit('current request');
  const progress = deferred(), originalGet = axios.get.getMockImplementation(); let hold = true;
  axios.get.mockImplementation((url, options) => url.endsWith('/progress')
    ? (hold ? (hold = false, progress.promise) : Promise.resolve({data:{progress:{objectives:{1:true}}}}))
    : originalGet(url, options));
  let pending;
  await act(async () => { pending = mockRetryResult({completed:true, judgments:[]}, {signal:new AbortController().signal}); await Promise.resolve(); });
  await act(async () => mockPoll(null, null, {signal:new AbortController().signal}));
  expect(node.querySelector('.progress-text').textContent).toBe('1 of 1 objectives completed');
  toast.warn.mockClear(); toast.success.mockClear();
  await act(async () => {
    if (reject) progress.reject(Object.assign(new Error('Obsolete progress GET failed'), {response:{status:503}}));
    else progress.resolve({data:{progress:{objectives:{}}}});
    await pending;
  });
  expect(node.querySelector('.progress-text').textContent).toBe('1 of 1 objectives completed');
  expect(toast.warn).not.toHaveBeenCalled();
  expect(toast.success).toHaveBeenCalledWith('Objective evaluation passed.');
});
