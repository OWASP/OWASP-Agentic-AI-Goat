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
jest.mock('../context/WorkshopConfigContext', () => ({ useWorkshopConfig: () => ({ registerReconciler: () => () => {} }) }));
jest.mock('react-toastify', () => ({ toast: { error: jest.fn(), success: jest.fn() } }));
jest.mock('./admin/CTFAdminPanel', () => () => null);
jest.mock('../components/admin/AIProviderManagement', () => () => null);
jest.mock('../components/admin/StudentWorkshopView', () => () => null);
jest.mock('../components/admin/ServerLogs', () => () => null);
jest.mock('./admin/ProgressAnalyticsPanel', () => () => null);
jest.mock('../components/observability/AgentRunInspector', () => () => null);

test('generic SSI editor hydrates and preserves explanation across typed title and description saves',async()=>{
 global.IS_REACT_ACT_ENVIRONMENT=true;localStorage.setItem('token','controlled');
 const solution={id:'legacy_sensitive_file_ssi:path_traversal',objective_id:'path_traversal',challengeKey:'legacy_sensitive_file_ssi',title:'Original title',description:'Original description',explanation:'Original nonempty approach',steps:[],tags:[],references:[],prerequisites:[],isPublic:true};
 axios.get.mockImplementation(url=>Promise.resolve({data:url==='/api/admin/challenges'?{success:true,challenges:[{id:'legacy_sensitive_file_ssi',key:'legacy_sensitive_file_ssi',workshopKey:'legacy_sensitive_file_ssi',name:'File and SSI Security',enabled:true}]}:url.endsWith('/objectives')?{objectives:[{objective_id:'path_traversal',label:'Read a protected teaching file through path traversal',is_enabled:true,hint_enabled:false}]}:url.endsWith('/hints')?{hints:{path_traversal:false}}:url==='/api/admin/solutions'?{solutions:[solution]}:{}}));axios.put.mockResolvedValue({data:{success:true}});
 const node=document.createElement('div');document.body.appendChild(node);const root=createRoot(node);const flush=()=>act(async()=>{await Promise.resolve();await Promise.resolve();});
 try{await act(async()=>root.render(<MemoryRouter initialEntries={['/admin/exercises']}><ComprehensiveAdminDashboard/></MemoryRouter>));await flush();await act(async()=>[...node.querySelectorAll('button')].find(x=>x.textContent.includes('Manage Objectives')).click());await flush();await act(async()=>node.querySelector('button[title="Edit Solution"]').click());await flush();
 const field=label=>[...node.querySelectorAll('label')].find(x=>x.textContent.trim()===label).parentElement.querySelector('input,textarea');expect(field('Explanation').value).toBe(solution.explanation);
 for(const [label,value]of [['Solution Title *','Owned title'],['Description','Owned description']]){await act(async()=>{const input=field(label);input.focus();input.select();Object.getOwnPropertyDescriptor(Object.getPrototypeOf(input),'value').set.call(input,'');input.dispatchEvent(new Event('input',{bubbles:true}));});await act(async()=>{const input=field(label);Object.getOwnPropertyDescriptor(Object.getPrototypeOf(input),'value').set.call(input,value);input.dispatchEvent(new Event('input',{bubbles:true}));});expect(field('Explanation').value).toBe(solution.explanation);}
 await act(async()=>node.querySelector('form').dispatchEvent(new Event('submit',{bubbles:true,cancelable:true})));expect(axios.put).toHaveBeenCalledWith('/api/admin/solutions/'+solution.id,expect.objectContaining({solution_title:'Owned title',solution_description:'Owned description',explanation:solution.explanation}));
 }finally{await act(async()=>root.unmount());node.remove();localStorage.clear();}
});
