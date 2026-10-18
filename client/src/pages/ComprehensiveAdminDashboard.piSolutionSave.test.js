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
jest.mock('../components/admin/PromptInjectionHintEditorModal', () => () => null);
jest.mock('../components/observability/AgentRunInspector', () => () => null);

const {toast}=require('react-toastify');
test('DPI solution editor sends only content fields; objective identity stays in URL',async()=>{
 global.IS_REACT_ACT_ENVIRONMENT=true;localStorage.setItem('token','controlled');
 const solution={title:'Owned solution',difficulty:'Easy',approach:'Owned approach',examples:[{prompt:'Owned prompt',explanation:'Owned explanation'}],tips:['A tip']};
 axios.get.mockImplementation(url=>Promise.resolve({data:url==='/api/admin/challenges'?{success:true,challenges:[{id:'direct_prompt_injection',key:'direct_prompt_injection',workshopKey:'direct_prompt_injection',name:'CodeBot',enabled:true}]}:url.endsWith('/objectives')?{success:true,objectives:[{objective_id:'system_prompt',label:'Tool list',is_enabled:true}]}:url.endsWith('/hints')?{hints:{system_prompt:true}}:url.endsWith('/preview/system_prompt')?{solution}:url==='/api/admin/pi-workshop/solutions'?{success:true,challenges:[{challengeId:'system_prompt',solutionsEnabled:true}]}:{}}));
 const allowed=new Set(['title','difficulty','approach','hints','examples','tips']);
 axios.post.mockImplementation((url,body)=>Object.keys(body).some(k=>!allowed.has(k))?Promise.reject({response:{status:400,data:{error:'Invalid content patch'}}}):Promise.resolve({data:{success:true}}));
 const node=document.createElement('div');document.body.appendChild(node);const root=createRoot(node);const flush=()=>act(async()=>{await Promise.resolve();await Promise.resolve();await Promise.resolve();});
 try{await act(async()=>root.render(<MemoryRouter initialEntries={['/admin/exercises']}><ComprehensiveAdminDashboard/></MemoryRouter>));await flush();await act(async()=>[...node.querySelectorAll('button')].find(x=>x.textContent.includes('Manage Objectives')).click());await flush();await act(async()=>node.querySelector('button[title="Edit Solution"]').click());await flush();await act(async()=>[...node.querySelectorAll('button')].find(x=>x.textContent.trim()==='Save Changes').click());await flush();expect(axios.post).toHaveBeenCalledWith('/api/admin/pi-workshop/solutions/system_prompt',solution,expect.any(Object));expect(toast.success).toHaveBeenCalledWith('Solution updated successfully');expect(toast.error).not.toHaveBeenCalled();}
 finally{await act(async()=>root.unmount());node.remove();localStorage.clear();}
});
