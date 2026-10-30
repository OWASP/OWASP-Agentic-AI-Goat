import React, {act} from 'react';
import {createRoot} from 'react-dom/client';
import axios from 'axios';
import WorkshopChallenges from './WorkshopChallenges';

jest.mock('axios',()=>({get:jest.fn()}));
jest.mock('react-router-dom',()=>({Link:({children,...props})=><a {...props}>{children}</a>,useNavigate:()=>jest.fn()}));
let mockReconcile;
let mockExercises = {};
jest.mock('../context/WorkshopConfigContext',()=>({useWorkshopConfig:()=>({snapshot:{exercises:mockExercises},revision:1,registerReconciler:callback=>{mockReconcile=callback;return()=>{};}})}));
jest.mock('../components/HintPanel',()=>({workshopKey,objectiveId})=><button data-help-source={workshopKey}>{objectiveId} hint</button>);
jest.mock('../components/SolutionPanel',()=>({solutionEndpoint})=><button data-solution-source={solutionEndpoint}>Solution</button>);
const challenge={id:'direct_prompt_injection',workshopKey:'direct_prompt_injection',title:'Direct Prompt Injection',description:'Controlled exercise',difficulty:'Beginner',status:'unlocked',route:'/vulnerabilities/direct-prompt-injection',objectives:[{id:'jailbreak',label:'Controlled objective',completed:false}]};
const deferred=()=>{let resolve,reject;const promise=new Promise((yes,no)=>{resolve=yes;reject=no;});return{promise,resolve,reject};};
const flush=async()=>act(async()=>{await Promise.resolve();await Promise.resolve();});
let node,root;
beforeEach(()=>{global.IS_REACT_ACT_ENVIRONMENT=true;axios.get.mockReset();mockReconcile=null;mockExercises={};jest.spyOn(console,'error').mockImplementation(()=>{});node=document.createElement('div');document.body.appendChild(node);root=createRoot(node);});
afterEach(()=>{act(()=>root.unmount());node.remove();console.error.mockRestore();});
const mount=async()=>{await act(async()=>root.render(<WorkshopChallenges/>));};
const emptyCopy="Your instructor hasn't enabled any exercises yet";
test('pending initial response shows loading and never claims enabled exercises are absent',async()=>{
 const request=deferred();axios.get.mockReturnValue(request.promise);await mount();expect(node.querySelector('[role="status"]').textContent).toBe('Loading exercises…');expect(node.textContent).not.toContain('No Exercises Available');expect(node.textContent).not.toContain(emptyCopy);expect(node.textContent).not.toContain('Waiting for your instructor');
 await act(async()=>request.resolve({data:{challenges:[challenge]}}));await flush();expect(node.textContent).toContain('Direct Prompt Injection');expect(node.querySelector('[role="status"]')).toBeNull();expect(node.textContent).not.toContain(emptyCopy);
});
test('initial failure renders an explicit retry error and successful retry shows canonical exercises',async()=>{
 axios.get.mockRejectedValueOnce(Error('controlled network failure'));await mount();await flush();expect(node.querySelector('[role="alert"]').textContent).toContain('Unable to load exercises');expect(node.textContent).not.toContain(emptyCopy);expect(node.textContent).not.toContain('No Exercises Available');
 axios.get.mockResolvedValueOnce({data:{challenges:[challenge]}});await act(async()=>node.querySelector('button').click());await flush();expect(node.textContent).toContain('Direct Prompt Injection');expect(node.querySelector('[role="alert"]')).toBeNull();
});
test('successful empty response alone renders the instructor availability empty state',async()=>{
 axios.get.mockResolvedValue({data:{challenges:[]}});await mount();await flush();expect(node.textContent).toContain('No Exercises Available');expect(node.textContent).toContain(emptyCopy);expect(node.querySelector('[role="alert"]')).toBeNull();expect(node.querySelector('[role="status"]')).toBeNull();
});
test('student dashboard shows the full canonical exercise library and compact progress summary',async()=>{
 const ready={...challenge,status:'in_progress',objectiveCount:2,completedObjectiveCount:1,timeSpentSeconds:125,objectives:[{id:'one',text:'First objective',completed:true},{id:'two',text:'Second objective',completed:false}]};
 const locked={...challenge,id:'secure_shop',title:'OWASP AI SecureShop',status:'locked',objectiveCount:0,completedObjectiveCount:0,timeSpentSeconds:0,objectives:[]};
 axios.get.mockResolvedValue({data:{challenges:[ready,locked]}});await mount();await flush();
 expect(node.querySelector('h1').textContent).toContain('Student Dashboard');
 expect(node.textContent).toContain('Exercise Library (2 visible)');
 expect(node.textContent).toContain('2 instructor-visible exercises: 1 ready to open, 1 locked');
 expect(node.textContent).toContain('1/2');
 expect(node.textContent).toContain('2m');
 expect(node.querySelector('[role="progressbar"]').getAttribute('aria-valuenow')).toBe('50');
 expect(node.textContent).toContain('Direct Prompt Injection');
 expect(node.textContent).toContain('OWASP AI SecureShop');
 expect(node.textContent).not.toContain('Back to Student Dashboard');
 const start=[...node.querySelectorAll('button')].find(button=>button.textContent.includes('Continue Exercise'));
 expect(getComputedStyle(start).minHeight).toBe('44px');
 expect(getComputedStyle(node.querySelector('h1').parentElement).backgroundColor).toBe('rgba(255, 255, 255, 0.95)');
});
test('background refresh retains existing cards while pending and on failure',async()=>{
 axios.get.mockResolvedValueOnce({data:{challenges:[challenge]}});await mount();await flush();const request=deferred();axios.get.mockReturnValueOnce(request.promise);let result;await act(async()=>{result=mockReconcile(2).catch(error=>error);});expect(node.textContent).toContain('Direct Prompt Injection');expect(node.querySelector('[role="status"]').textContent).toBe('Refreshing exercises…');expect(node.textContent).not.toContain(emptyCopy);
 const failure=Error('controlled refresh failure');await act(async()=>request.reject(failure));expect(await result).toBe(failure);await flush();expect(node.textContent).toContain('Direct Prompt Injection');expect(node.querySelector('[role="alert"]').textContent).toContain('Unable to load exercises');expect(node.querySelector('[role="status"]')).toBeNull();expect(node.textContent).not.toContain(emptyCopy);
});
test('superseded request failure cannot replace the latest pending load with a false empty or error state',async()=>{
 const first=deferred(),latest=deferred();axios.get.mockReturnValueOnce(first.promise).mockReturnValueOnce(latest.promise);await mount();let refresh;await act(async()=>{refresh=mockReconcile(2);});await act(async()=>first.reject(Error('superseded failure')));await flush();expect(node.querySelector('[role="status"]').textContent).toBe('Loading exercises…');expect(node.querySelector('[role="alert"]')).toBeNull();expect(node.textContent).not.toContain(emptyCopy);
 await act(async()=>latest.resolve({data:{challenges:[challenge]}}));await refresh;await flush();expect(node.textContent).toContain('Direct Prompt Injection');expect(node.querySelector('[role="status"]')).toBeNull();expect(node.querySelector('[role="alert"]')).toBeNull();
});

test('combined XSS card preserves builder help source and independent configuration gates',async()=>{
 mockExercises={xss_workshop:{objectives:{}},xss_email_builder:{objectives:{xss_email_level_1:{hintVisible:true,solutionVisible:false}}}};
 axios.get.mockResolvedValue({data:{challenges:[{...challenge,id:'reflected_xss_llm',workshopKey:'xss_workshop',title:'XSS in AI Powered Chat System',objectives:[{id:'xss_email_level_1',text:'Template objective',completed:true,sourceWorkshopKey:'xss_email_builder',sourceChallengeKey:'xss_email_builder',solutionEndpoint:'/api/solutions/xss_email_builder/xss_email_level_1'}]}]}});
 await mount();await flush();
 expect(node.querySelector('[data-help-source]').getAttribute('data-help-source')).toBe('xss_email_builder');
 expect(node.querySelector('[data-solution-source]')).toBeNull();
 expect(node.textContent).toContain('Exercise Library (1 visible)');
 expect(node.textContent).not.toContain('XSS Email Template Builder');
});
