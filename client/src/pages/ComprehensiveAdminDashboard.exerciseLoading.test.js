import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import { MemoryRouter, useNavigate } from 'react-router-dom';
let navigate;
function Navigation(){navigate=useNavigate();return null;}
import axios from 'axios';
import ComprehensiveAdminDashboard from './ComprehensiveAdminDashboard';

jest.mock('axios', () => ({ get: jest.fn(), post: jest.fn(), put: jest.fn(), patch: jest.fn(), delete: jest.fn() }));
let mockUser, mockReconcile, mockSnapshot, mockReadSequence = 1;
const mockRefresh = jest.fn();
const mockRegister = callback => { mockReconcile = callback; return () => {}; };
jest.mock('../context/AuthContext', () => ({ useAuth: () => ({ user: mockUser, logout: jest.fn() }) }));
jest.mock('../context/WorkshopConfigContext', () => ({ useWorkshopConfig: () => ({ registerReconciler: mockRegister, snapshot: mockSnapshot, snapshotReadSequence: mockReadSequence, retireSnapshotReads: () => mockReadSequence, refreshAfterMutation: mockRefresh }) }));
jest.mock('react-toastify', () => ({ toast: { error: jest.fn(), success: jest.fn() } }));
jest.mock('./admin/CTFAdminPanel', () => () => null);
jest.mock('../components/admin/AIProviderManagement', () => () => null);
jest.mock('../components/admin/StudentWorkshopView', () => () => null);
jest.mock('../components/admin/ServerLogs', () => () => null);
jest.mock('./admin/ProgressAnalyticsPanel', () => () => <div>PROGRESS_ANALYTICS_MOUNTED</div>);
jest.mock('../components/admin/PromptInjectionHintEditorModal', () => () => null);
jest.mock('../components/observability/AgentRunInspector', () => () => <div>AGENT_INSPECTOR_MOUNTED</div>);

const flush=async()=>act(async()=>{await Promise.resolve();await Promise.resolve();await Promise.resolve();});
const families=['sql_injection_workshop','nosql_injection_workshop'];
const catalog=families.map((key,i)=>({id:key,key,workshopKey:key,name:i?'NOVA':'ARIA',enabled:true,showHints:true,showSolutions:true,completions:0}));
function response(url){
 if(url==='/api/admin/challenges')return {data:{success:true,challenges:catalog}};
 if(url.endsWith('/objectives'))return {data:{objectives:[{objective_id:url.includes('nosql')?'nosqli_1':'sqli_1',label:url.includes('nosql')?'NOVA current':'ARIA current',is_enabled:true,hint_enabled:true,has_hint_content:true}]}};
 if(url.endsWith('/hints'))return {data:{hints:{[url.includes('nosql')?'nosqli_1':'sqli_1']:true}}};
 if(url.includes('injection-workshop/solutions'))return {data:{objectives:[{objective_id:url.includes('nosql')?'nosqli_1':'sqli_1',solutions_enabled:true}]}};
 return {data:{}};
}
let root,node;
beforeEach(()=>{mockReadSequence=1;global.IS_REACT_ACT_ENVIRONMENT=true;mockSnapshot=undefined;mockRefresh.mockImplementation(async()=>mockSnapshot);mockUser={id:1,isAdmin:true,adminLevel:2,permissions:['challenge_management','manage_progress','user_management']};localStorage.setItem('token','owned');axios.get.mockImplementation(url=>Promise.resolve(response(url)));jest.spyOn(console,'error').mockImplementation(()=>{});jest.spyOn(console,'warn').mockImplementation(()=>{});jest.spyOn(console,'log').mockImplementation(()=>{});node=document.createElement('div');document.body.appendChild(node);root=createRoot(node);});
afterEach(()=>{act(()=>root.unmount());node.remove();localStorage.clear();jest.restoreAllMocks();jest.clearAllMocks();});
async function render(path='/admin/exercises'){await act(async()=>root.render(<MemoryRouter initialEntries={[path]}><Navigation/><ComprehensiveAdminDashboard/></MemoryRouter>));await flush();}
async function open(index){const buttons=[...node.querySelectorAll('button')].filter(b=>b.textContent.includes('Manage Objectives'));await act(async()=>buttons[index].click());await flush();}
function xssFixture({mixed = false} = {}) {
 const parent={id:'reflected_xss_llm',key:'reflected_xss_llm',name:'XSS in AI Powered Chat System',enabled:true,showHints:true,showSolutions:true,completions:9,displayCompletions:11};
 const builder={id:'xss_email_builder',key:'xss_email_builder',name:'XSS Email Template Builder',enabled:!mixed,showHints:true,showSolutions:true,completions:8,displayCompletions:11};
 const objectives = (builder) => Array.from({length:8},(_,i)=>({objective_id:builder?`xss_email_level_${i+1}`:`xss_${i+1}`,label:builder?`Builder objective ${i+1}`:`Chat objective ${i+1}`,is_enabled:true,hint_enabled:true,has_hint_content:true}));
 mockSnapshot={revision:1,exercises:Object.fromEntries(['xss_workshop','xss_email_builder'].map(key=>[key,{isVisible:key==='xss_workshop'||!mixed,showHints:true,showSolutions:true,objectives:Object.fromEntries(objectives(key==='xss_email_builder').map(obj=>[obj.objective_id,{isVisible:true,raw:{objectiveEnabled:true}}]))}]))};
 axios.get.mockImplementation(url=>Promise.resolve(url==='/api/admin/challenges'?{data:{success:true,challenges:[builder,parent]}}:
  url==='/api/admin/solutions'?{data:{solutions:[{id:'builder-solution',objective_id:'xss_email_level_1',challengeKey:'xss_email_builder',title:'Builder solution',description:'Stored profile lesson',explanation:'Preserve the exact profile source.',isPublic:true}]}}:
  url==='/api/admin/xss-workshop/objective-solutions'?{data:{objectives:[]}}:
  url.endsWith('/objectives')?{data:{objectives:objectives(url.includes('xss_email_builder'))}}:
  url.endsWith('/hints')?{data:{hints:{}}}:response(url)));
}
test('one XSS card and one flat objective window include both families and deduplicated completions',async()=>{
 xssFixture();await render();
 const card=node.querySelector('[data-exercise-key="reflected_xss_llm"]');
 expect(node.querySelectorAll('[data-exercise-key]')).toHaveLength(1);
 expect(card.textContent).toContain('16 of 16 objectives');
 expect(card.textContent).not.toContain('Chat scenarios');
 expect(card.textContent).not.toContain('Email Template Builder');
 expect(card.textContent).not.toContain('Controls apply to');
 expect(card.textContent).toContain('11');
 expect(card.querySelectorAll('[role="switch"]')).toHaveLength(3);
 expect([...card.querySelectorAll('button')].filter(b=>b.textContent.includes('Manage Objectives'))).toHaveLength(1);
 await open(0);
 expect(node.querySelectorAll('[data-objective-id]')).toHaveLength(16);
 expect(node.textContent).toContain('Chat objective 8');expect(node.textContent).toContain('Builder objective 8');
 const preview=node.querySelector('[data-objective-id="xss_email_level_1"] button[title="Preview Solution"]');
 expect(preview).not.toBeNull();await act(async()=>preview.click());
 expect(node.textContent).toContain('Stored profile lesson');expect(node.textContent).toContain('Preserve the exact profile source.');
});
test('builder row visibility retains its canonical family within the combined window',async()=>{
 xssFixture();axios.post.mockResolvedValue({data:{exercise:{objectives:{xss_email_level_1:{raw:{objectiveEnabled:false}}}}}});
 await render();await open(0);
 await act(async()=>node.querySelector('[data-objective-id="xss_email_level_1"] [data-control="visible"]').click());await flush();
 expect(axios.post).toHaveBeenCalledWith('/api/admin/workshops/xss_email_builder/objectives/xss_email_level_1/toggle',{enabled:false},expect.any(Object));
 expect(node.querySelectorAll('[data-objective-id]')).toHaveLength(16);
 expect(node.textContent).toContain('Chat objective 8');
});
test('editing a builder objective saves to its own family and keeps the combined window open',async()=>{
 xssFixture();const read=axios.get.getMockImplementation();
 axios.get.mockImplementation(url=>url==='/api/admin/exercises/xss_email_builder/objectives/xss_email_level_1'
  ?Promise.resolve({data:{objective:{objectiveId:'xss_email_level_1',label:'Builder objective 1',description:'',category:'AI'}}}):read(url));
 axios.put.mockResolvedValue({data:{success:true}});
 await render();await open(0);
 await act(async()=>node.querySelector('[data-objective-id="xss_email_level_1"] button[title="Edit Objective"]').click());await flush();
 const dialog=node.querySelector('[role="dialog"][aria-label="Edit objective xss_email_level_1"]');
 expect(dialog).not.toBeNull();
 const title=dialog.querySelector('input');
 await act(async()=>{Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value').set.call(title,'Instructor builder title');title.dispatchEvent(new Event('input',{bubbles:true}));});
 await act(async()=>[...dialog.querySelectorAll('button')].find(button=>button.textContent==='Save Changes').click());await flush();
 expect(axios.put).toHaveBeenCalledWith('/api/admin/exercises/xss_email_builder/objectives/xss_email_level_1',{label:'Instructor builder title'},expect.any(Object));
 expect(node.querySelectorAll('[data-objective-id]')).toHaveLength(16);
 expect(node.textContent).toContain('Chat objective 8');
 expect(axios.post).not.toHaveBeenCalled();
});
test.each(['active','hints','solutions'])('XSS %s switch applies one atomic mutation and confirms both canonical families',async dimension=>{
 xssFixture();
 axios.post.mockImplementation(async()=>{
  const field=dimension==='active'?'isVisible':dimension==='hints'?'showHints':'showSolutions';
  mockSnapshot={...mockSnapshot,revision:2,exercises:Object.fromEntries(Object.entries(mockSnapshot.exercises).map(([key,value])=>[key,{...value,[field]:false}]))};
  return {data:{success:true}};
 });
 await render();
 const card=()=>node.querySelector('[data-exercise-key="reflected_xss_llm"]');
 await act(async()=>card().querySelector(`[data-control="${dimension}"]`).click());await flush();
 expect(axios.post).toHaveBeenCalledTimes(1);
 expect(axios.post).toHaveBeenCalledWith('/api/admin/exercises/reflected_xss_llm/group-controls',{dimension,enabled:false},expect.any(Object));
 expect(mockRefresh).toHaveBeenCalled();
 expect(card().querySelector(`[data-control="${dimension}"]`).getAttribute('aria-checked')).toBe('false');
});
test('mixed XSS visibility is explicit and enabling it targets both families',async()=>{
 xssFixture({mixed:true});axios.post.mockResolvedValue({data:{success:true}});await render();
 const card=node.querySelector('[data-exercise-key="reflected_xss_llm"]');
 expect(card.textContent).toContain('PARTLY VISIBLE');
 expect(card.querySelector('[data-control="active"]').getAttribute('aria-checked')).toBe('mixed');
 await act(async()=>card.querySelector('[data-control="active"]').click());await flush();
 expect(axios.post).toHaveBeenCalledWith('/api/admin/exercises/reflected_xss_llm/group-controls',{dimension:'active',enabled:true},expect.any(Object));
});
test('XSS master readback cannot confirm only the chat family',async()=>{
 xssFixture();axios.post.mockImplementation(async()=>{
  mockSnapshot={...mockSnapshot,revision:2,exercises:{...mockSnapshot.exercises,xss_workshop:{...mockSnapshot.exercises.xss_workshop,showHints:false}}};
  return {data:{success:true}};
 });await render();
 await act(async()=>node.querySelector('[data-exercise-key="reflected_xss_llm"] [data-control="hints"]').click());await flush();
 expect(require('react-toastify').toast.error).toHaveBeenCalled();
 expect(require('react-toastify').toast.success).not.toHaveBeenCalled();
 const control=node.querySelector('[data-exercise-key="reflected_xss_llm"] [data-control="hints"]');
 expect(control.disabled || control.getAttribute('aria-disabled')==='true').toBe(true);
});
test('mounted objective and new solution editors persist teaching content without enabling gates',async()=>{
 const key='sql_injection_workshop',id='sqli_1';
 mockSnapshot={revision:1,exercises:{[key]:{isVisible:true,showHints:false,showSolutions:false,objectives:{[id]:{
  label:'ARIA current',description:'',hintVisible:false,solutionVisible:false,hasSolutionContent:false,
  raw:{objectiveEnabled:true,hintEnabled:false,solutionEnabled:false},
 }}}}};
 axios.get.mockImplementation(url=>Promise.resolve(
  url===`/api/admin/exercises/${key}/objectives/${id}`?{data:{objective:{objectiveId:id,label:'ARIA current',description:'',category:'AI'}}}:
  url===`/api/admin/exercises/${key}/objectives/${id}/solution`?{data:{solution:{objectiveId:id,authored:false}}}:
  url==='/api/admin/sql-injection-workshop/solutions'?{data:{objectives:[]}}:response(url)));
 axios.put.mockResolvedValue({data:{success:true}});
 await render();await open(0);
 const row=()=>node.querySelector(`[data-objective-id="${id}"]`);
 expect(row().textContent).toContain('Student view: hint hidden · solution hidden');
 await act(async()=>row().querySelector('button[title="Edit Objective"]').click());await flush();
 const objectiveDialog=node.querySelector('[role="dialog"][aria-label="Edit objective sqli_1"]');
 const title=objectiveDialog.querySelector('input');
 await act(async()=>{Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value').set.call(title,'Instructor title');title.dispatchEvent(new Event('input',{bubbles:true}));});
 await act(async()=>[...objectiveDialog.querySelectorAll('button')].find(button=>button.textContent==='Save Changes').click());await flush();
 expect(axios.put).toHaveBeenCalledWith(`/api/admin/exercises/${key}/objectives/${id}`,{label:'Instructor title'},expect.any(Object));
 await act(async()=>row().querySelector('button[title="Edit Solution"]').click());await flush();
 const solutionDialog=node.querySelector('[role="dialog"][aria-label="Edit solution for sqli_1"]');
 const solutionTitle=solutionDialog.querySelector('input');
 const description=solutionDialog.querySelector('textarea');
 await act(async()=>{Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value').set.call(solutionTitle,'Instructor solution');solutionTitle.dispatchEvent(new Event('input',{bubbles:true}));});
 await act(async()=>{Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype,'value').set.call(description,'Explain the synthetic SQL lesson');description.dispatchEvent(new Event('input',{bubbles:true}));});
 await act(async()=>[...solutionDialog.querySelectorAll('button')].find(button=>button.textContent==='Save Changes').click());await flush();
 expect(axios.put).toHaveBeenCalledWith(`/api/admin/exercises/${key}/objectives/${id}/solution`,
  {title:'Instructor solution',description:'Explain the synthetic SQL lesson'},expect.any(Object));
 expect(axios.post).not.toHaveBeenCalled();
 expect(row().textContent).toContain('Student view: hint hidden · solution hidden');
 mockSnapshot={revision:2,exercises:{[key]:{...mockSnapshot.exercises[key],objectives:{[id]:{...mockSnapshot.exercises[key].objectives[id],hasSolutionContent:true}}}}};
 await render();
 axios.patch.mockResolvedValue({data:{exercise:{objectives:{[id]:{raw:{solutionEnabled:true}}}}}});
 await act(async()=>row().children[3].firstElementChild.click());await flush();
 expect(axios.patch).toHaveBeenCalledWith(`/api/admin/exercises/${key}/objectives/${id}/solution`,
  {enabled:true},expect.any(Object));
});
test('actual mounted exercise page reads one catalog; baseline,80 gates,66 restoration and54 other mutation revisions refresh only selected family',async()=>{
 await render();expect(axios.get.mock.calls.map(([url])=>url)).toEqual(['/api/admin/challenges']);
 await act(async()=>{await mockReconcile(1);});expect(axios.get.mock.calls.length).toBe(2);
 await open(0);expect(node.textContent).toContain('ARIA current');expect(axios.get.mock.calls.length).toBe(6);
 for(let revision=2;revision<202;revision++)await act(async()=>{await mockReconcile(revision);});
 expect(axios.get.mock.calls.length).toBe(6+200*4);
 expect(axios.get.mock.calls.every(([url])=>url==='/api/admin/challenges'||url.includes('/sql_injection_workshop/')||url==='/api/admin/sql-injection-workshop/solutions')).toBe(true);
 await open(1);expect(node.textContent).toContain('NOVA current');expect(node.textContent).not.toContain('ARIA current');
 expect(axios.get.mock.calls.slice(-4).map(([url])=>url)).toEqual(['/api/admin/challenges','/api/admin/workshops/nosql_injection_workshop/objectives','/api/admin/workshops/nosql_injection_workshop/hints','/api/admin/nosql-injection-workshop/solutions']);
});
test('new revision and modal selection retire delayed old family data',async()=>{
 await render();let release;const held=new Promise(resolve=>{release=resolve;});let hold=true;
 axios.get.mockImplementation(url=>url.includes('/sql_injection_workshop/objectives')&&hold?held:Promise.resolve(response(url)));
 await open(0);expect(node.textContent).not.toContain('ARIA current');
 hold=false;await act(async()=>{await mockReconcile(2);});expect(node.textContent).toContain('ARIA current');
 await open(1);expect(node.textContent).toContain('NOVA current');
 await act(async()=>release({data:{objectives:[{objective_id:'sqli_1',label:'STALE PRIVATE',is_enabled:true}]}}));await flush();
 expect(node.textContent).not.toContain('STALE PRIVATE');expect(node.textContent).toContain('NOVA current');
});
test('same-user token replacement rejects a late content response and reloads fresh authority',async()=>{
 await render();let release;const held=new Promise(resolve=>{release=resolve;});axios.get.mockImplementation(url=>url.endsWith('/objectives')?held:Promise.resolve(response(url)));
 await open(0);localStorage.setItem('token','replacement');await render();
 await act(async()=>release({data:{objectives:[{objective_id:'sqli_1',label:'OLD TOKEN PRIVATE'}]}}));await flush();
 expect(node.textContent).not.toContain('OLD TOKEN PRIVATE');expect(node.querySelector('[data-objective-id]')).toBeNull();
 expect(axios.get.mock.calls.at(-1)[1].headers.Authorization).toBe('Bearer replacement');
});
test('closing a modal rejects a late refresh and subsequent revisions load catalog only',async()=>{
 await render();await open(0);let release;const held=new Promise(resolve=>{release=resolve;});axios.get.mockImplementation(url=>url.endsWith('/objectives')?held:Promise.resolve(response(url)));
 let pending;await act(async()=>{pending=mockReconcile(2);});
 const title=[...node.querySelectorAll('h3')].find(e=>e.textContent.includes('Objectives —'));
 await act(async()=>title.parentElement.querySelector('button').click());
 await act(async()=>release({data:{objectives:[{objective_id:'sqli_1',label:'CLOSED PRIVATE'}]}}));await pending;await flush();
 expect(node.textContent).not.toContain('CLOSED PRIVATE');expect(node.querySelector('[data-objective-id]')).toBeNull();
 const count=axios.get.mock.calls.length;await act(async()=>{await mockReconcile(3);});expect(axios.get.mock.calls.length-count).toBe(1);
});
test('failed active-family read exposes error without installing incomplete controls',async()=>{
 const {toast}=require('react-toastify');await render();axios.get.mockImplementation(url=>url.endsWith('/hints')?Promise.reject(Error('unavailable')):Promise.resolve(response(url)));
 await open(0);expect(node.querySelector('[data-objective-id]')).toBeNull();expect(toast.error).toHaveBeenCalledWith('Unable to load current exercise controls.');
});
test('delayed inactive-panel preload cannot publish after entering Exercises or contaminate reopened content',async()=>{
 let release;const held=new Promise(resolve=>{release=resolve;});let hold=true;
 axios.get.mockImplementation(url=>url==='/api/admin/sql-injection-workshop/solutions'&&hold?held:Promise.resolve(response(url)));
 await render('/admin/dashboard');await act(async()=>navigate('/admin/exercises'));await flush();
 hold=false;await act(async()=>release({data:{objectives:[{objective_id:'sqli_1',title:'OLD PRELOAD PRIVATE',solutions_enabled:true}]}}));await flush();
 await open(0);expect(node.textContent).toContain('ARIA current');expect(node.textContent).not.toContain('OLD PRELOAD PRIVATE');
 expect(axios.get.mock.calls.filter(([url])=>url==='/api/admin/sql-injection-workshop/solutions').length).toBe(2);
});
test('403 after loaded content retires modal and requires a fresh content read before reopening',async()=>{
 await render();await open(0);expect(node.textContent).toContain('ARIA current');
 axios.get.mockImplementation(url=>url.endsWith('/objectives')?Promise.reject(Object.assign(Error('denied'),{response:{status:403}})):Promise.resolve(response(url)));
 await act(async()=>{await expect(mockReconcile(4)).rejects.toThrow('denied');});expect(node.querySelector('[data-objective-id]')).toBeNull();
 axios.get.mockImplementation(url=>Promise.resolve(response(url)));const count=axios.get.mock.calls.length;
 await open(0);expect(axios.get.mock.calls.length-count).toBe(4);expect(node.textContent).toContain('ARIA current');
});
test('divergent canonical gates override stale catalog and one master write waits for readback',async()=>{
 const key='sql_injection_workshop';
 mockSnapshot={revision:1,exercises:{[key]:{isVisible:true,showHints:false,showSolutions:true,objectives:{}}}};
 await render();
 const control=dimension=>node.querySelector(`[data-exercise-key="${key}"] [data-control="${dimension}"]`);
 const on=dimension=>getComputedStyle(control(dimension)).backgroundColor==='rgb(72, 187, 120)';
 expect(on('hints')).toBe(false);expect(on('solutions')).toBe(true);
 for(const [dimension,enabled]of [
  ['hints',true],
  ['solutions',false],
 ]){
  const before={hints:on('hints'),solutions:on('solutions')};
  let release;mockRefresh.mockImplementation(()=>new Promise(resolve=>{release=resolve;}));
  axios.post.mockClear();axios.post.mockResolvedValue({data:{success:true}});
  await act(async()=>control(dimension).click());await flush();
  const field=dimension==='hints'?'showHints':'showSolutions';
  expect(axios.post.mock.calls).toEqual([
   [`/api/admin/challenges/${dimension}/toggle`,{challengeKey:key,[field]:enabled},{headers:{Authorization:'Bearer owned'},signal:expect.any(AbortSignal),timeout:10000}],
  ]);
  expect(on('hints')).toBe(before.hints);expect(on('solutions')).toBe(before.solutions);
  expect(control('hints').getAttribute('aria-disabled')).toBe('true');
  expect(control('solutions').getAttribute('aria-disabled')).toBe('true');
  mockSnapshot={revision:mockSnapshot.revision+1,exercises:{[key]:{...mockSnapshot.exercises[key],[field]:enabled}}};
  await act(async()=>release(mockSnapshot));await flush();
  expect(on(dimension)).toBe(enabled);
  const other=dimension==='hints'?'solutions':'hints';expect(on(other)).toBe(before[other]);
 }
});
test('committed master response reconciles an open objective panel with one write per control',async()=>{
 const key='sql_injection_workshop';
 mockSnapshot={revision:1,exercises:{[key]:{isVisible:true,showHints:true,showSolutions:true,objectives:{}}}};
 await render();await open(0);
 const row=()=>node.querySelector('[data-objective-id="sqli_1"]');
 const enabled=column=>getComputedStyle(row().children[column].firstElementChild).backgroundColor==='rgb(72, 187, 120)';
 const master=dimension=>node.querySelector(`[data-exercise-key="${key}"] [data-control="${dimension}"]`);
 expect(enabled(2)).toBe(true);expect(enabled(3)).toBe(true);
 for(const [dimension,field,column]of [['solutions','showSolutions',3],['hints','showHints',2]]){
  axios.post.mockClear();
  axios.post.mockResolvedValue({data:{success:true,exercise:{objectives:{sqli_1:{raw:{solutionEnabled:false,hintEnabled:false}}}}}});
  mockRefresh.mockResolvedValue({revision:2,exercises:{[key]:{...mockSnapshot.exercises[key],[field]:false}}});
  await act(async()=>master(dimension).click());await flush();
  expect(axios.post).toHaveBeenCalledTimes(1);
  expect(axios.post.mock.calls[0][0]).toBe(`/api/admin/challenges/${dimension}/toggle`);
  expect(enabled(column)).toBe(false);
  mockSnapshot={revision:2,exercises:{[key]:{...mockSnapshot.exercises[key],[field]:false}}};
  await render();
 }
});
test('consecutive canonical master off/on toggles work with polling paused; both switches wait for readback',async()=>{
 for(const key of families)for(const dimension of ['hints','solutions']){
  mockSnapshot={revision:1,exercises:{[key]:{isVisible:true,showHints:true,showSolutions:true,objectives:{}}}};
  await render();const control=d=>node.querySelector('[data-exercise-key="'+key+'"] [data-control="'+d+'"]');
  for(const enabled of [false,true]){
   let release;mockRefresh.mockImplementation(()=>new Promise(resolve=>{release=resolve;}));axios.post.mockResolvedValue({data:{success:true}});axios.post.mockClear();
   await act(async()=>control(dimension).click());await flush();
   expect(control('hints').getAttribute('aria-disabled')).toBe('true');expect(control('solutions').getAttribute('aria-disabled')).toBe('true');
   const expectedField=dimension==='hints'?'showHints':'showSolutions';
   expect(axios.post.mock.calls[0][1]).toEqual({challengeKey:key,[expectedField]:enabled});
   await act(async()=>control(dimension==='hints'?'solutions':'hints').click());expect(axios.post).toHaveBeenCalledTimes(1);
   mockSnapshot={revision:mockSnapshot.revision+1,exercises:{[key]:{...mockSnapshot.exercises[key],[expectedField]:enabled}}};
   await act(async()=>release(mockSnapshot));await flush();
   expect(control(dimension).getAttribute('aria-disabled')).toBe('false');
   expect(getComputedStyle(control(dimension)).backgroundColor==='rgb(72, 187, 120)').toBe(enabled);
  }
 }
});
test('consecutive canonical Active OFF/ON derives next value from rendered snapshot when catalog remains stale',async()=>{
 const key='sql_injection_workshop';
 mockSnapshot={revision:1,exercises:{[key]:{isVisible:true,showHints:true,showSolutions:true,objectives:{}}}};
 await render();const control=()=>node.querySelector(`[data-exercise-key="${key}"] [data-control="active"]`);
 for(const enabled of [false,true]){
  let release;mockRefresh.mockImplementation(()=>new Promise(resolve=>{release=resolve;}));
  axios.post.mockResolvedValue({data:{success:true}});axios.post.mockClear();
  await act(async()=>control().click());await flush();
  expect(axios.post.mock.calls).toEqual([['/api/admin/challenges/toggle',{challengeKey:key,enabled},
   {headers:{Authorization:'Bearer owned'},signal:expect.any(AbortSignal),timeout:10000}]]);
  expect(control().getAttribute('aria-disabled')).toBe('true');
  mockSnapshot={revision:mockSnapshot.revision+1,exercises:{[key]:{...mockSnapshot.exercises[key],isVisible:enabled}}};
  await act(async()=>release(mockSnapshot));await flush();
  expect(control().getAttribute('aria-disabled')).toBe('false');
  expect(getComputedStyle(control()).backgroundColor==='rgb(72, 187, 120)').toBe(enabled);
 }
});
test('failed canonical readback never reports success or retries mutation',async()=>{
 const {toast}=require('react-toastify');mockSnapshot={revision:1,exercises:{sql_injection_workshop:{isVisible:true,showHints:true,showSolutions:true}}};mockRefresh.mockResolvedValue(null);axios.post.mockResolvedValue({data:{success:true}});
 await render();await act(async()=>node.querySelector('[data-exercise-key="sql_injection_workshop"] [data-control="hints"]').click());await flush();
 expect(axios.post).toHaveBeenCalledTimes(1);expect(toast.success).not.toHaveBeenCalled();expect(toast.error).toHaveBeenCalledWith('Unable to confirm current exercise controls. Reload before trying again.');
 expect(node.querySelector('[data-exercise-key="sql_injection_workshop"] [data-control="hints"]').getAttribute('aria-disabled')).toBe('true');
 await act(async()=>node.querySelector('[data-exercise-key="sql_injection_workshop"] [data-control="hints"]').click());expect(axios.post).toHaveBeenCalledTimes(1);
 mockReadSequence++;mockSnapshot={revision:2,exercises:{sql_injection_workshop:{isVisible:true,showHints:false,showSolutions:true}}};await render();expect(node.querySelector('[data-exercise-key="sql_injection_workshop"] [data-control="hints"]').getAttribute('aria-disabled')).toBe('false');expect(axios.post).toHaveBeenCalledTimes(1);
});
test('active visibility waits for canonical readback and stays stale after an unconfirmed write',async()=>{
 const key='sql_injection_workshop',control=()=>node.querySelector(`[data-exercise-key="${key}"] [data-control="active"]`);
 mockSnapshot={revision:1,exercises:{[key]:{isVisible:true,showHints:true,showSolutions:true}}};
 let release;mockRefresh.mockImplementation(()=>new Promise(resolve=>{release=resolve;}));axios.post.mockResolvedValue({data:{success:true}});
 await render();await act(async()=>control().click());await flush();
 expect(axios.post.mock.calls).toEqual([['/api/admin/challenges/toggle',{challengeKey:key,enabled:false},{headers:{Authorization:'Bearer owned'},signal:expect.any(AbortSignal),timeout:10000}]]);
 expect(control().getAttribute('aria-disabled')).toBe('true');
 expect(getComputedStyle(control()).backgroundColor).toBe('rgb(72, 187, 120)');
 await act(async()=>release(mockSnapshot));await flush();
 expect(control().getAttribute('aria-disabled')).toBe('true');
 expect(getComputedStyle(control()).backgroundColor).toBe('rgb(72, 187, 120)');
 expect(require('react-toastify').toast.success).not.toHaveBeenCalled();
 mockReadSequence++;mockSnapshot={revision:2,exercises:{[key]:{isVisible:false,showHints:true,showSolutions:true}}};await render();
 expect(control().getAttribute('aria-disabled')).toBe('false');
 expect(getComputedStyle(control()).backgroundColor).toBe('rgb(203, 213, 224)');
});
test('session retirement aborts pending master mutation and prevents cascade or success',async()=>{
 const {toast}=require('react-toastify');let release;axios.post.mockImplementation(()=>new Promise(resolve=>{release=resolve;}));
 mockSnapshot={revision:1,exercises:{sql_injection_workshop:{isVisible:true,showHints:true,showSolutions:true}}};await render();
 await act(async()=>node.querySelector('[data-exercise-key="sql_injection_workshop"] [data-control="hints"]').click());const signal=axios.post.mock.calls[0][2].signal;
 localStorage.setItem('token','replacement');await render();expect(signal.aborted).toBe(true);
 await act(async()=>release({data:{success:true}}));await flush();expect(axios.post).toHaveBeenCalledTimes(1);expect(mockRefresh).not.toHaveBeenCalled();expect(toast.success).not.toHaveBeenCalled();
});
test('stored hint toggle remains ON when master, objective or absent content makes effective hints OFF',async()=>{
 for(const condition of ['master-off','objective-disabled','missing-content']){
  mockSnapshot={revision:1,exercises:{sql_injection_workshop:{isVisible:true,showHints:condition!=='master-off',showSolutions:true,objectives:{sqli_1:{hintVisible:false}}}}};
  axios.get.mockImplementation(url=>{const r=response(url);if(url.endsWith('/objectives'))r.data.objectives[0]={...r.data.objectives[0],hint_enabled:true,is_enabled:condition!=='objective-disabled',has_hint_content:condition!=='missing-content'};if(url.endsWith('/hints'))r.data.hints={sqli_1:false};return Promise.resolve(r);});
  await render();await open(0);const row=node.querySelector('[data-objective-id="sqli_1"]');expect(getComputedStyle(row.children[2].firstElementChild).backgroundColor).toBe('rgb(72, 187, 120)');
 }
});
test('objective and hint controls render committed gates and ignore incomplete mutation replies',async()=>{
 await render();await open(0);
 const row=()=>node.querySelector('[data-objective-id="sqli_1"]');
 const enabled=column=>getComputedStyle(row().children[column].firstElementChild).backgroundColor==='rgb(72, 187, 120)';
 const click=async column=>{await act(async()=>row().children[column].firstElementChild.click());await flush();};
 expect(enabled(1)).toBe(true);expect(enabled(2)).toBe(true);
 axios.post.mockResolvedValueOnce({data:{success:true,exercise:{objectives:{sqli_1:{raw:{hintEnabled:false}}}}}});
 await click(2);expect(enabled(2)).toBe(false);expect(enabled(1)).toBe(true);
 axios.post.mockResolvedValueOnce({data:{success:true,exercise:{objectives:{sqli_1:{raw:{objectiveEnabled:false}}}}}});
 await click(1);expect(enabled(1)).toBe(false);expect(enabled(2)).toBe(false);
 axios.post.mockResolvedValueOnce({data:{success:true}});
 await click(1);expect(enabled(1)).toBe(false);
 expect(require('react-toastify').toast.error).toHaveBeenCalledWith('Failed to update objective visibility');
});
test('same-panel round trip rejects the first private preload even with identical credentials',async()=>{
 const staleRows=[{id:'old-private'}];let staleCommits=0,release,first=true;
 const originalUseState=React.useState;
 jest.spyOn(React,'useState').mockImplementation(initial=>{const [value,set]=originalUseState(initial);return[value,next=>{if(next===staleRows)staleCommits++;return set(next);}];});
 const held=new Promise(resolve=>{release=resolve;});
 axios.get.mockImplementation(url=>{if(url==='/api/admin/solutions'){if(first){first=false;return held;}return Promise.resolve({data:{solutions:[]}});}return Promise.resolve(response(url));});
 await render('/admin/dashboard');await act(async()=>navigate('/admin/exercises'));await flush();await act(async()=>navigate('/admin/dashboard'));await flush();
 await act(async()=>release({data:{solutions:staleRows}}));await flush();
 expect(axios.get.mock.calls.filter(([url])=>url==='/api/admin/solutions').length).toBe(2);expect(staleCommits).toBe(0);
});

test('leaving and returning to Exercises retires acknowledged mutation readback without success or replay',async()=>{
 const {toast}=require('react-toastify');let release;
 mockSnapshot={revision:1,exercises:{sql_injection_workshop:{isVisible:true,showHints:true,showSolutions:true}}};
 axios.post.mockResolvedValue({data:{success:true}});mockRefresh.mockImplementation(()=>new Promise(resolve=>{release=resolve;}));
 await render();await act(async()=>node.querySelector('[data-exercise-key="sql_injection_workshop"] [data-control="hints"]').click());await flush();
 const signal=mockRefresh.mock.calls[0][0].signal;expect(axios.post).toHaveBeenCalledTimes(1);
 await act(async()=>navigate('/admin/dashboard'));await flush();await act(async()=>navigate('/admin/exercises'));await flush();expect(signal.aborted).toBe(true);
 await act(async()=>release({revision:2,exercises:{sql_injection_workshop:{showHints:false}}}));await flush();
 expect(toast.success.mock.calls.some(([message])=>message.startsWith('Challenge '))).toBe(false);expect(axios.post).toHaveBeenCalledTimes(1);
});

test('noncooperative mutation deadline leaves controls stale and never replays or publishes late success',async()=>{
 jest.useFakeTimers();const {toast}=require('react-toastify');let release;
 try {
  mockSnapshot={revision:1,exercises:{sql_injection_workshop:{isVisible:true,showHints:true,showSolutions:true}}};axios.post.mockImplementation(()=>new Promise(resolve=>{release=resolve;}));
  await render();const control=()=>node.querySelector('[data-exercise-key="sql_injection_workshop"] [data-control="hints"]');
  await act(async()=>control().click());const signal=axios.post.mock.calls[0][2].signal;
  await act(async()=>jest.advanceTimersByTime(20000));await flush();expect(signal.aborted).toBe(true);expect(control().getAttribute('aria-disabled')).toBe('true');
  expect(toast.error).toHaveBeenCalledWith('Unable to confirm current exercise controls. Reload before trying again.');
  await act(async()=>release({data:{success:true}}));await flush();expect(axios.post).toHaveBeenCalledTimes(1);expect(mockRefresh).not.toHaveBeenCalled();expect(toast.success).not.toHaveBeenCalled();
 } finally {jest.useRealTimers();}
});

 test('failed POST cannot unlock from an old same-revision snapshot or same-session view roundtrip',async()=>{
 mockSnapshot={revision:1,exercises:{sql_injection_workshop:{isVisible:true,showHints:true,showSolutions:true}}};
 axios.post.mockRejectedValue(new Error('lost acknowledgement'));await render();
 const control=()=>node.querySelector('[data-exercise-key="sql_injection_workshop"] [data-control="hints"]');
 await act(async()=>control().click());await flush();
 mockSnapshot=JSON.parse(JSON.stringify(mockSnapshot));await render();expect(control().getAttribute('aria-disabled')).toBe('true');
 await act(async()=>navigate('/admin/dashboard'));await flush();await act(async()=>navigate('/admin/exercises'));await flush();expect(control().getAttribute('aria-disabled')).toBe('true');
 mockReadSequence++;await render();expect(control().getAttribute('aria-disabled')).toBe('true');
 mockSnapshot={revision:2,exercises:{sql_injection_workshop:{isVisible:true,showHints:false,showSolutions:true}}};await render();
 expect(control().getAttribute('aria-disabled')).toBe('false');expect(axios.post).toHaveBeenCalledTimes(1);
 });

test('standalone SecureShop never exposes platform objective bulk controls',async()=>{
 const key='secureshop_agent_security';
 axios.get.mockImplementation(url=>Promise.resolve(url==='/api/admin/challenges'
   ?{data:{success:true,challenges:[],applications:[{id:key,key,workshopKey:key,name:'OWASP AI SecureShop',enabled:true}]}}
   :{data:{}}));
 await render();
 const card=node.querySelector(`[data-application-key="${key}"]`);
 expect(card.querySelector('a').getAttribute('href')).toBe('/secureshop');
 expect(card.textContent).toContain('Shop settings → Assessment objectives');
 expect(card.querySelector('button')).toBeNull();
 expect(node.textContent).not.toContain('Enable Available Objectives');
 expect(node.textContent).not.toContain('Disable All Objectives');
 expect(axios.post).not.toHaveBeenCalled();
});

test('objective bulk controls are absent without challenge management permission',async()=>{
 mockUser={...mockUser,permissions:['manage_progress']};await render();await open(0);
 expect(node.textContent).not.toContain('Enable Available Objectives');expect(node.textContent).not.toContain('Disable All Objectives');expect(axios.post).not.toHaveBeenCalled();
});
