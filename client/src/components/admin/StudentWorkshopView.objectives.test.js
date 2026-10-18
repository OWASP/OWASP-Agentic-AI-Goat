import React, {act} from 'react';
import {createRoot} from 'react-dom/client';
import {MemoryRouter} from 'react-router-dom';
import axios from 'axios';
import StudentWorkshopView from './StudentWorkshopView';
jest.mock('axios',()=>({get:jest.fn()}));
jest.mock('../../context/WorkshopConfigContext',()=>({useWorkshopConfig:()=>({registerReconciler:()=>()=>{}})}));
jest.mock('react-toastify',()=>({toast:{error:jest.fn(),success:jest.fn()}}));
test('each exercise exposes collapsed canonical objectives and independent gates without contents or mutations',async()=>{
 global.IS_REACT_ACT_ENVIRONMENT=true;localStorage.setItem('token','controlled-component-token');
 const exercise={id:'shop',workshopKey:'secureshop_agent_security',name:'Instructor catalog label',description:'Owned component fixture',status:'in_progress',difficulty:'Intermediate',completedObjectiveCount:1,objectiveCount:2,timeSpentSeconds:45,route:'/fixture',objectives:[{id:'saved_mail',label:'Instructor-edited mail label',completed:true,hintVisible:true,solutionVisible:false,hints:'DO NOT RENDER HINT',solution:'DO NOT RENDER SOLUTION'},{id:'other',text:'Canonical fallback label',completed:false,hintVisible:false,solutionVisible:true}]};
 axios.get.mockImplementation(url=>Promise.resolve({data:url==='/api/admin/students'?{success:true,students:[{id:7,username:'fixture'}]}:{success:true,overview:{},challenges:[exercise,{...exercise,id:'empty',name:'Empty exercise',objectives:[],objectiveCount:0,completedObjectiveCount:0}]}}));
 const node=document.createElement('div');document.body.appendChild(node);const root=createRoot(node);
 try{await act(async()=>{root.render(<MemoryRouter initialEntries={['/admin/student-workshop-view?studentId=7']}><StudentWorkshopView/></MemoryRouter>);});await act(async()=>{await Promise.resolve();await Promise.resolve();});
 const details=node.querySelector('details[aria-label="Objective progress: Instructor catalog label"]');expect(details).not.toBeNull();expect(details.open).toBe(false);expect(details.querySelector('summary').textContent).toBe('Objective progress');details.open=true;
 const done=details.querySelector('[data-objective-id="saved_mail"]'),pending=details.querySelector('[data-objective-id="other"]');
 expect(done.querySelector('.level-name').textContent).toBe('Instructor-edited mail label');expect(done.querySelector('.level-badge').textContent).toBe('Completed');expect(done.textContent).toContain('Objective ID: saved_mail');expect(done.textContent).toContain('Hints: Available');expect(done.textContent).toContain('Solutions: Unavailable');
 expect(pending.querySelector('.level-name').textContent).toBe('Canonical fallback label');expect(pending.querySelector('.level-badge').textContent).toBe('Not completed');expect(pending.textContent).toContain('Hints: Unavailable');expect(pending.textContent).toContain('Solutions: Available');
 expect(node.textContent).not.toContain('DO NOT RENDER');expect(node.querySelector('details[aria-label="Objective progress: Empty exercise"]').textContent).toContain('No objectives are currently available.');expect(axios.get.mock.calls.every(([url])=>url.startsWith('/api/admin/'))).toBe(true);
 }finally{act(()=>root.unmount());node.remove();localStorage.clear();}
});
