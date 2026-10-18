import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import { MemoryRouter } from 'react-router-dom';
import axios from 'axios';
import ComprehensiveAdminDashboard from './ComprehensiveAdminDashboard';

jest.mock('axios', () => ({ get: jest.fn(), post: jest.fn(), put: jest.fn(), patch: jest.fn(), delete: jest.fn() }));
jest.mock('../context/AuthContext', () => ({ useAuth: () => ({
  user: { id: 1, username: 'admin', isAdmin: true, adminLevel: 2,
    permissions: ['manage_progress', 'challenge_management', 'user_management'] },
  logout: jest.fn(),
}) }));
jest.mock('../context/WorkshopConfigContext', () => ({ useWorkshopConfig: () => ({ registerReconciler: () => () => {}, refreshAfterMutation: async () => ({ exercises: {} }) }) }));
jest.mock('react-toastify', () => ({ toast: { error: jest.fn(), success: jest.fn() } }));
jest.mock('./admin/CTFAdminPanel', () => () => null);
jest.mock('../components/admin/AIProviderManagement', () => () => null);
jest.mock('../components/admin/StudentWorkshopView', () => () => null);
jest.mock('../components/admin/ServerLogs', () => () => null);
jest.mock('./admin/ProgressAnalyticsPanel', () => () => null);
jest.mock('../components/observability/AgentRunInspector', () => () => null);

const {toast}=require('react-toastify');
test('MCP authored editors use mapped content URLs without changing independent gates and refresh preview',async()=>{
 global.IS_REACT_ACT_ENVIRONMENT=true;localStorage.setItem('token','controlled');
 const solution={title:'Owned solution',difficulty:'Easy',approach:'Owned approach',examples:[{prompt:'P',explanation:'E'}],tips:['T'],extra:{keep:true}};
 const hint={title:'Owned hint',hints:['First'],extra:'retain'};
 axios.get.mockImplementation(url=>Promise.resolve({data:url==='/api/admin/challenges'?{success:true,challenges:[{id:'mcp_server_rce',key:'mcp_server_rce',workshopKey:'mcp_workshop',name:'MCP',enabled:true}]}:url.endsWith('/objectives')?{objectives:[{objective_id:'mcp_audit_gap',label:'Target audit',is_enabled:true,hint_enabled:false,has_hint_content:true}]}:url.endsWith('/hints')?{hints:{mcp_audit_gap:false}}:url.endsWith('/hint')?{hint}:url.endsWith('/preview/mcp_audit_gap')?{solution}:url==='/api/admin/mcp-workshop/solutions'?{objectives:[{objective_id:'mcp_audit_gap',solutions_enabled:true,title:solution.title}]}:{}}));axios.put.mockImplementation((url,body)=>{const allowed=url.endsWith('/hint')?['title','hints']:['title','difficulty','approach','examples','tips'];if(Object.keys(body).some(key=>!allowed.includes(key)))return Promise.reject(new Error('Invalid content patch'));return Promise.resolve({data:{success:true}});});
 const node=document.createElement('div');document.body.appendChild(node);const root=createRoot(node);const flush=()=>act(async()=>{await Promise.resolve();await Promise.resolve();await Promise.resolve();});
 try{await act(async()=>root.render(<MemoryRouter initialEntries={['/admin/exercises']}><ComprehensiveAdminDashboard/></MemoryRouter>));await flush();await act(async()=>[...node.querySelectorAll('button')].find(x=>x.textContent.includes('Manage Objectives')).click());await flush();await act(async()=>node.querySelector('button[title="Edit Hint"]').click());await flush();await act(async()=>[...node.querySelectorAll('[role="dialog"] button')].find(x=>x.textContent==='Save Changes').click());await flush();expect(axios.put).toHaveBeenCalledWith('/api/admin/exercises/mcp_workshop/objectives/mcp_audit_gap/hint',{title:hint.title,hints:hint.hints},expect.any(Object));await act(async()=>node.querySelector('button[title="Edit Solution"]').click());await flush();await act(async()=>{const input=node.querySelector('[aria-label="Edit MCP solution — mcp_audit_gap"] input');Object.getOwnPropertyDescriptor(Object.getPrototypeOf(input),'value').set.call(input,'Changed title');input.dispatchEvent(new Event('input',{bubbles:true}));});await act(async()=>[...node.querySelectorAll('[aria-label="Edit MCP solution — mcp_audit_gap"] button')].find(x=>x.textContent==='Save Changes').click());await flush();expect(axios.put).toHaveBeenCalledWith('/api/admin/exercises/mcp_workshop/objectives/mcp_audit_gap/solution',{title:'Changed title'},expect.any(Object));expect(axios.post).not.toHaveBeenCalled();expect(toast.error).not.toHaveBeenCalled();expect(axios.get.mock.calls.filter(([u])=>u.endsWith('/preview/mcp_audit_gap')).length).toBe(2);}
 finally{await act(async()=>root.unmount());node.remove();localStorage.clear();}
});

test('a missing hint can be authored in the admin editor without changing visibility',async()=>{
 global.IS_REACT_ACT_ENVIRONMENT=true;localStorage.setItem('token','controlled');
 axios.get.mockImplementation(url=>Promise.resolve({data:url==='/api/admin/challenges'
  ?{success:true,challenges:[{id:'mcp_server_rce',key:'mcp_server_rce',workshopKey:'mcp_workshop',name:'MCP',enabled:true}]}
  :url.endsWith('/objectives')?{objectives:[{objective_id:'mcp_audit_gap',label:'Target audit',is_enabled:true,hint_enabled:false,has_hint_content:false}]}
  :url.endsWith('/hints')?{hints:{mcp_audit_gap:false}}
  :url.endsWith('/hint')?{hint:{objectiveId:'mcp_audit_gap',authored:false}}
  :url==='/api/admin/mcp-workshop/solutions'?{objectives:[]}:{} }));
 axios.put.mockResolvedValue({data:{success:true}});
 const node=document.createElement('div');document.body.appendChild(node);const root=createRoot(node);
 const flush=()=>act(async()=>{await Promise.resolve();await Promise.resolve();await Promise.resolve();});
 try{
  await act(async()=>root.render(<MemoryRouter initialEntries={['/admin/exercises']}><ComprehensiveAdminDashboard/></MemoryRouter>));await flush();
  await act(async()=>[...node.querySelectorAll('button')].find(button=>button.textContent.includes('Manage Objectives')).click());await flush();
  await act(async()=>node.querySelector('button[title="Edit Hint"]').click());await flush();
  const title=node.querySelector('#prompt-injection-hint-title'),hint=node.querySelector('#prompt-injection-hint-0');
  await act(async()=>{Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value').set.call(title,'Instructor hint');title.dispatchEvent(new Event('input',{bubbles:true}));});
  await act(async()=>{Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype,'value').set.call(hint,'Inspect the owned tool trace');hint.dispatchEvent(new Event('input',{bubbles:true}));});
  await act(async()=>[...node.querySelectorAll('[role="dialog"] button')].find(button=>button.textContent==='Save Changes').click());await flush();
  expect(axios.put).toHaveBeenCalledWith('/api/admin/exercises/mcp_workshop/objectives/mcp_audit_gap/hint',
   {title:'Instructor hint',hints:['Inspect the owned tool trace']},expect.any(Object));
  expect(axios.post).not.toHaveBeenCalled();expect(axios.patch).not.toHaveBeenCalled();expect(toast.error).not.toHaveBeenCalled();
 }finally{await act(async()=>root.unmount());node.remove();localStorage.clear();}
});
