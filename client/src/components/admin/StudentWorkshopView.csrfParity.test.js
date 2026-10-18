import React, {act} from 'react';
import {createRoot} from 'react-dom/client';
import {MemoryRouter} from 'react-router-dom';
import axios from 'axios';
import StudentWorkshopView from './StudentWorkshopView';
const {csrfAdminCardHasProgress}=require('../../../../tests/fixtures/csrfAdminCard');
jest.mock('axios',()=>({get:jest.fn()}));
jest.mock('../../context/WorkshopConfigContext',()=>({useWorkshopConfig:()=>({registerReconciler:()=>()=>{}})}));
jest.mock('react-toastify',()=>({toast:{error:jest.fn(),success:jest.fn()}}));
test('browser parity predicate reads count/time from actual CSRF card, never its header or another card',async()=>{
 global.IS_REACT_ACT_ENVIRONMENT=true;localStorage.setItem('token','controlled-component-token');
 const exercise=(name,completed,total,seconds)=>({id:name,name,description:'Controlled component fixture',status:'in_progress',difficulty:'Intermediate',completedObjectiveCount:completed,objectiveCount:total,timeSpentSeconds:seconds,objectives:[],route:'/fixture'});
 axios.get.mockImplementation(url=>Promise.resolve({data:url==='/api/admin/students'?{success:true,students:[{id:7,username:'fixture'}]}:{success:true,overview:{},challenges:[exercise('Unrelated',1,12,60),exercise('CSRF via AI Prompt Injection',1,12,45)]}}));
 const node=document.createElement('div');document.body.appendChild(node);const root=createRoot(node);
 try{
  await act(async()=>{root.render(<MemoryRouter initialEntries={['/admin/student-workshop-view?studentId=7']}><StudentWorkshopView/></MemoryRouter>);});
  await act(async()=>{await Promise.resolve();await Promise.resolve();});
  expect(csrfAdminCardHasProgress({completed:1,total:12})).toBe(true);
  const title=[...node.querySelectorAll('.title')].find(e=>e.textContent.includes('CSRF'));
  expect(title.parentElement.parentElement.textContent).not.toContain('1/12 objectives');
  const card=title.closest('.header').parentElement;card.querySelector('strong').textContent='0';
  expect(csrfAdminCardHasProgress({completed:1,total:12})).toBe(false);expect(csrfAdminCardHasProgress({completed:0,total:12})).toBe(true);
  card.querySelector('strong').textContent='1';const time=[...card.querySelectorAll('span')].find(e=>e.textContent.trim()==='45s');time.textContent='0s';expect(csrfAdminCardHasProgress({completed:1,total:12})).toBe(false);
 }finally{act(()=>root.unmount());node.remove();localStorage.clear();}
});
