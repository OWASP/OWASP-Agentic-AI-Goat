import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import axios from 'axios';
import { toast } from 'react-toastify';
import XSSWorkshop from './XSSWorkshop';
let mockUser = { id: 1 }, mockRetry, mockPoll, mockChatMode = 'vuln';
jest.mock('../../context/AuthContext', () => ({ useAuth: () => ({ user: mockUser }) }));
jest.mock('axios', () => ({ get: jest.fn(), post: jest.fn() }));
jest.mock('react-toastify', () => ({ toast: { info: jest.fn(), success: jest.fn(), error: jest.fn(), warning: jest.fn() } }));
jest.mock('../../components/VulnerabilityTemplate', () => ({ children }) => <div>{children}</div>);
jest.mock('../../components/HintPanel', () => () => null);
jest.mock('./XssEmailBuilder', () => () => null);
jest.mock('../../components/workshop/JudgeRetryButton', () => props => { mockRetry = props.onResult; return null; });
jest.mock('../../hooks/useWorkshopHeartbeat', () => () => {});
jest.mock('../../hooks/useChangePolling', () => callback => { mockPoll = callback; });
jest.mock('../../context/WorkshopConfigContext', () => ({ useWorkshopConfig: () => ({ revision: 1, snapshot: { exercises: { xss_workshop: { isVisible: true, objectives: { xss_r1: { isVisible: true }, xss_r2: { isVisible: true } } } } } }) }));
globalThis.IS_REACT_ACT_ENVIRONMENT = true;
let root, node;
const deferred = () => { let resolve; const promise = new Promise(r => { resolve = r; }); return { resolve, promise }; };
const render = async () => { await act(async () => root.render(<XSSWorkshop />)); };
const replace = async () => { localStorage.setItem('token','owner-b'); mockUser = { id: 2 }; await render(); };
const send = async text => {
 const input = node.querySelector('textarea'); expect(input).not.toBeNull();
 await act(async () => { Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype,'value').set.call(input,text); input.dispatchEvent(new Event('input',{bubbles:true})); });
 await act(async () => input.closest('form').dispatchEvent(new Event('submit',{bubbles:true,cancelable:true})));
};
beforeEach(async () => {
 jest.clearAllMocks(); localStorage.setItem('token','owner-a'); mockUser = { id: 1 }; mockChatMode = 'vuln';
 axios.get.mockImplementation(url => Promise.resolve({data: url === '/api/workshop/xss/mode'
   ? {mode:mockChatMode,effectiveMode:mockChatMode,scope:{kind:'workshop',id:'xss_workshop'}}
   : url.endsWith('/progress') ? {completedObjectives: localStorage.getItem('token') === 'owner-b' ? {xss_r2:true} : {}} : {available:true,objectives:{}}}));
 axios.post.mockResolvedValue({data:{response:'current answer',judgments:[{verdict:'unavailable',evaluationId:'eval-a',canRetry:true}]}});
 node=document.createElement('div');root=createRoot(node);await render();
});
afterEach(async () => { await act(async () => root.unmount()); localStorage.clear(); });
test.each(['Reset Chat Progress','Reset Above Objectives'])('pending %s cannot clear replacement transcript or progress',async label => {
 await send('old owner question');const pending=deferred();const base=axios.post.getMockImplementation();axios.post.mockImplementation((url,...args)=>url.includes('/progress/reset')?pending.promise:base(url,...args));
 await act(async()=>[...node.querySelectorAll('button')].find(b=>b.textContent.trim()===label).click());
 const dialog=document.querySelector('[role="alertdialog"]');expect(dialog).toBeTruthy();
 await act(async()=>[...dialog.querySelectorAll('button')].find(b=>b.textContent==='Confirm reset').click());
 expect(axios.post.mock.calls.some(([url])=>url.includes('/progress/reset'))).toBe(true);
 await replace();expect(node.textContent).not.toContain('old owner question');await send('new owner question');toast.success.mockClear();
 await act(async()=>pending.resolve({data:{success:true}}));expect(node.textContent).toContain('new owner question');expect(node.textContent).toContain('1 of 2 objectives');expect(toast.success).not.toHaveBeenCalled();
});
test('late chat after token change before rerender is suppressed and new owner can send',async()=>{
 const pending=deferred();axios.post.mockReturnValue(pending.promise);await send('old pending');localStorage.setItem('token','owner-b');
 await act(async()=>pending.resolve({data:{response:'private old answer',completedObjectiveId:'xss_r1'}}));expect(node.textContent).not.toContain('private old answer');
 axios.post.mockResolvedValue({data:{response:'current answer'}});await replace();await send('new owner');expect(node.textContent).toContain('current answer');expect(node.textContent).toContain('1 of 2 objectives');
});
test.each(['retry','poll'])('old %s progress cannot overwrite new owner and retained callback cannot dispatch',async kind=>{
 await send('seed retry');const oldRetry=mockRetry;const pending=deferred();const base=axios.get.getMockImplementation();let hold=true;
 axios.get.mockImplementation((url,...args)=>hold&&url.endsWith('/progress')?pending.promise:base(url,...args));
 let work;await act(async()=>{work=kind==='retry'?oldRetry({completed:true,judgments:[]}):mockPoll(null,null,{});});
 localStorage.setItem('token','owner-b');const calls=axios.get.mock.calls.length;await act(async()=>oldRetry({completed:true,judgments:[]}));expect(axios.get.mock.calls.length).toBe(calls);
 hold=false;await replace();toast.success.mockClear();await act(async()=>{pending.resolve({data:{completedObjectives:{xss_r1:true,xss_r2:true}}});await work;});
 expect(node.textContent).toContain('1 of 2 objectives');expect(toast.success).not.toHaveBeenCalled();await send('new usable');expect(node.textContent).toContain('current answer');
});

test('fixed chat uses inert response text while vulnerable mode retains the intentional HTML sink',async()=>{
 const original=axios.post.getMockImplementation();
 axios.post.mockImplementation((url,body)=>url.endsWith('/mode')
   ? Promise.resolve({data:{mode:body.mode,effectiveMode:body.mode,scope:{kind:'workshop',id:'xss_workshop'}}})
   : url.endsWith('/chat')
     ? Promise.resolve({data: mockChatMode === 'fixed'
       ? {mode:'fixed',response:'&lt;img id="fixed-payload"&gt;',responseText:'<img id="fixed-payload">',xssDetected:false}
       : {mode:'vuln',response:'<b id="vulnerable-payload">rendered</b>',xssDetected:false}})
     : original(url,body));
 const fixed=[...node.querySelectorAll('[data-workshop-mode-control] button')].find(button=>button.textContent.trim()==='Fixed');
 await act(async()=>fixed.click());mockChatMode='fixed';
 expect(node.querySelector('[data-workshop-mode-control]').getAttribute('data-workshop-mode')).toBe('fixed');
 await send('test fixed');
 expect(node.textContent).toContain('<img id="fixed-payload">');
 expect(node.querySelector('#fixed-payload')).toBeNull();
 const vulnerable=[...node.querySelectorAll('[data-workshop-mode-control] button')].find(button=>button.textContent.trim()==='Vulnerable');
 await act(async()=>vulnerable.click());mockChatMode='vuln';
 await send('test vulnerable');
 expect(node.querySelector('#vulnerable-payload')).not.toBeNull();
 expect(node.textContent).toContain('test fixed');
});

test('a mode switch suppresses a late vulnerable chat response without clearing prior messages',async()=>{
 let finishOld;let chatCalls=0;
 axios.post.mockImplementation((url,body)=>url.endsWith('/mode')
   ? Promise.resolve({data:{mode:body.mode,effectiveMode:body.mode,scope:{kind:'workshop',id:'xss_workshop'}}})
   : url.endsWith('/chat') && ++chatCalls===1
     ? new Promise(resolve=>{finishOld=resolve;})
     : Promise.resolve({data:{mode:'fixed',responseText:'<strong>safe</strong>',response:'&lt;strong&gt;safe&lt;/strong&gt;'}}));
 await send('old user prompt');
 await act(async()=>[...node.querySelectorAll('[data-workshop-mode-control] button')].find(button=>button.textContent.trim()==='Fixed').click());
 mockChatMode='fixed';
 await act(async()=>finishOld({data:{mode:'vuln',response:'<img id="late-vuln">'}}));
 expect(node.querySelector('#late-vuln')).toBeNull();
 expect(node.textContent).toContain('old user prompt');
 await send('new fixed prompt');
 expect(node.textContent).toContain('<strong>safe</strong>');
 expect(node.querySelector('.message-text strong')).toBeNull();
});

test('owner replacement clears private drafts and tool activity', async () => {
 axios.post.mockResolvedValue({data:{response:'Owned profile',toolActivity:[{
   id:'xss-tool-0',name:'getProfile',arguments:{},result:{profile:{bio:'owner-a-private-tool-output'}},
   status:'success',timestamp:'2026-11-01T12:00:00.000Z',controlled:true,
 }]}});
 await send('show my profile');
 expect(node.textContent).toContain('owner-a-private-tool-output');
 const input=node.querySelector('textarea');
 await act(async()=>{Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype,'value').set.call(input,'owner-a-private-draft');input.dispatchEvent(new Event('input',{bubbles:true}));});
 await replace();
 expect(node.textContent).not.toContain('owner-a-private-tool-output');
 expect(node.querySelector('textarea').value).toBe('');
 expect(node.querySelector('[aria-label="0 recorded tool calls"]')).toBeTruthy();
});

test('unknown mode blocks submission until authoritative mode resolves', async () => {
 const pending=deferred();
 const base=axios.get.getMockImplementation();
 axios.get.mockImplementation((url,...args)=>url==='/api/workshop/xss/mode'?pending.promise:base(url,...args));
 await replace();
 expect(node.querySelector('textarea').disabled).toBe(true);
 expect(node.querySelector('[aria-label="Send message"]').disabled).toBe(true);
 await send('not admitted while mode is unknown');
 expect(axios.post).not.toHaveBeenCalled();
 await act(async()=>pending.resolve({data:{mode:'vuln',effectiveMode:'vuln',scope:{kind:'workshop',id:'xss_workshop'}}}));
 expect(node.querySelector('textarea').disabled).toBe(false);
 await send('admitted after readiness');
 expect(axios.post.mock.calls.filter(([url])=>url==='/api/workshop/xss/chat')).toHaveLength(1);
});
