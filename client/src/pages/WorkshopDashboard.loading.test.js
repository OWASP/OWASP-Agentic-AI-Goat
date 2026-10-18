import React, {act} from 'react';
import {createRoot} from 'react-dom/client';
import axios from 'axios';
import WorkshopDashboard from './WorkshopDashboard';

jest.mock('axios',()=>({get:jest.fn()}));
jest.mock('react-router-dom',()=>({Link:({children,...props})=><a {...props}>{children}</a>}));
jest.mock('../context/AuthContext',()=>({useAuth:()=>({user:{id:7,username:'student'}})}));
let mockReconcile;
jest.mock('../context/WorkshopConfigContext',()=>({useWorkshopConfig:()=>({registerReconciler:callback=>{mockReconcile=callback;return()=>{};}})}));
const challenge={id:'direct_prompt_injection',workshopKey:'direct_prompt_injection',title:'Direct Prompt Injection',description:'Controlled exercise',difficulty:'Beginner',status:'in_progress',route:'/vulnerabilities/direct-prompt-injection',objectiveCount:8,completedObjectiveCount:2,timeSpentSeconds:59,objectives:[]};
const deferred=()=>{let resolve,reject;const promise=new Promise((yes,no)=>{resolve=yes;reject=no;});return{promise,resolve,reject};};
const flush=async()=>act(async()=>{await Promise.resolve();await Promise.resolve();});
let node,root;
beforeEach(()=>{global.IS_REACT_ACT_ENVIRONMENT=true;axios.get.mockReset();mockReconcile=null;jest.spyOn(console,'error').mockImplementation(()=>{});jest.spyOn(console,'log').mockImplementation(()=>{});node=document.createElement('div');document.body.appendChild(node);root=createRoot(node);});
afterEach(()=>{act(()=>root.unmount());node.remove();console.error.mockRestore();console.log.mockRestore();});
const requests=callback=>axios.get.mockImplementation(url=>url==='/api/workshop/time/summary'?Promise.resolve({data:{summary:{}}}):callback());
const mount=async()=>{await act(async()=>root.render(<WorkshopDashboard/>));};
const emptyCopy="Your instructor hasn't enabled any exercises yet";
test('pending initial response shows loading without claiming instructor-disabled exercises',async()=>{
 const request=deferred();requests(()=>request.promise);await mount();expect(node.querySelector('[role="status"]').textContent).toBe('Loading your dashboard…');expect(node.textContent).not.toContain(emptyCopy);expect(node.textContent).not.toContain('Waiting for your instructor');
 await act(async()=>request.resolve({data:{challenges:[challenge]}}));await flush();expect(node.textContent).toContain('Direct Prompt Injection');expect(node.textContent).toContain('59s');expect(node.textContent).toContain('2 / 8');expect(node.querySelector('[role="status"]')).toBeNull();
});
test('initial failure renders a retry error and successful retry restores canonical exercises',async()=>{
 requests(()=>Promise.reject(Error('controlled request failure')));await mount();await flush();expect(node.querySelector('[role="alert"]').textContent).toContain('Unable to load your dashboard');expect(node.textContent).not.toContain(emptyCopy);expect(node.textContent).not.toContain('Waiting for your instructor');
 requests(()=>Promise.resolve({data:{challenges:[challenge]}}));await act(async()=>node.querySelector('button').click());await flush();expect(node.textContent).toContain('Direct Prompt Injection');expect(node.querySelector('[role="alert"]')).toBeNull();
});
test('successful empty response alone shows the instructor availability empty state',async()=>{
 requests(()=>Promise.resolve({data:{challenges:[]}}));await mount();await flush();expect(node.textContent).toContain(emptyCopy);expect(node.querySelector('[role="alert"]')).toBeNull();expect(node.querySelector('[role="status"]')).toBeNull();
});
test('background refresh preserves cards and counts while pending and after failure',async()=>{
 requests(()=>Promise.resolve({data:{challenges:[challenge]}}));await mount();await flush();const request=deferred();requests(()=>request.promise);let result;await act(async()=>{result=mockReconcile(2).catch(error=>error);});expect(node.textContent).toContain('Direct Prompt Injection');expect(node.textContent).toContain('2 / 8');expect(node.textContent).toContain('59s');expect(node.querySelector('[role="status"]').textContent).toBe('Refreshing dashboard…');
 const failure=Error('controlled refresh failure');await act(async()=>request.reject(failure));expect(await result).toBe(failure);await flush();expect(node.querySelector('[role="alert"]').textContent).toContain('Unable to load your dashboard');expect(node.querySelector('[role="status"]')).toBeNull();expect(node.textContent).toContain('Direct Prompt Injection');expect(node.textContent).toContain('2 / 8');expect(node.textContent).toContain('59s');expect(node.textContent).not.toContain(emptyCopy);expect(node.textContent).not.toContain('Waiting for your instructor');
});
