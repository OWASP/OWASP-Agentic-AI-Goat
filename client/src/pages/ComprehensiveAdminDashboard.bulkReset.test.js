import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import { MemoryRouter } from 'react-router-dom';
import axios from 'axios';
import { toast } from 'react-toastify';
import ComprehensiveAdminDashboard from './ComprehensiveAdminDashboard';

jest.mock('axios', () => ({ get: jest.fn(), post: jest.fn(), put: jest.fn(), delete: jest.fn() }));
let mockUser;
let mockAuthRevision;
jest.mock('../context/AuthContext', () => ({ useAuth: () => ({ user: mockUser, logout: jest.fn(),
  getAuthRevision: () => mockAuthRevision }) }));
jest.mock('../context/WorkshopConfigContext', () => ({ useWorkshopConfig: () => ({ registerReconciler: () => () => {} }) }));
jest.mock('react-toastify', () => ({ toast: { error: jest.fn(), success: jest.fn() } }));
jest.mock('./admin/CTFAdminPanel', () => () => null);
jest.mock('../components/admin/AIProviderManagement', () => () => null);
jest.mock('../components/admin/StudentWorkshopView', () => () => null);
jest.mock('../components/admin/ServerLogs', () => () => null);
jest.mock('./admin/ProgressAnalyticsPanel', () => () => <div>PROGRESS_ANALYTICS_MOUNTED</div>);
jest.mock('../components/admin/PromptInjectionHintEditorModal', () => () => null);
jest.mock('../components/observability/AgentRunInspector', () => () => <div>AGENT_INSPECTOR_MOUNTED</div>);

const flush = async () => act(async () => { await Promise.resolve(); await Promise.resolve(); await Promise.resolve(); });
function genericGet(url) {
  if (url === '/api/admin/challenges') return Promise.resolve({data:{success:true,challenges:[{id:'csrf_prompt_injection',workshopKey:'csrf_workshop',name:'CSRF',category:'AI',difficulty:'Medium',enabled:true,completions:0}]}});
  if (url === '/api/admin/workshops/reset-operations') return Promise.resolve({data:{success:true,operations:[]}});
  if (url === '/api/admin/students') return Promise.resolve({ data: { success: true, students: [] } });
  return Promise.resolve({ data: {} });
}
function deferred() {
  let resolve;
  const promise = new Promise(value => { resolve = value; });
  return { promise, resolve };
}
async function mount(path) {
  const node = document.createElement('div'); document.body.appendChild(node);
  const root = createRoot(node);
  await act(async () => { root.render(<MemoryRouter initialEntries={[path]}><ComprehensiveAdminDashboard /></MemoryRouter>); });
  await flush();
  return { node, root };
}

beforeEach(() => {
  global.IS_REACT_ACT_ENVIRONMENT = true;
  mockUser = { id: 1, username: 'admin', isAdmin: true, adminLevel: 2, permissions: ['manage_progress', 'manage_challenges'] };
  mockAuthRevision = 0;
  sessionStorage.clear();
  localStorage.setItem('token', 'fixture');
  axios.get.mockImplementation(genericGet);
  axios.post.mockResolvedValue({ data: { success: true } });
  axios.delete.mockResolvedValue({ data: { success: true, jobId: '6b58bc44-f15b-4b12-972b-cfcad0c37c1a' } });
  jest.spyOn(console, 'error').mockImplementation(() => {});
  jest.spyOn(console, 'warn').mockImplementation(() => {});
  jest.spyOn(console, 'log').mockImplementation(() => {});
});
afterEach(() => { jest.restoreAllMocks(); jest.clearAllMocks(); document.body.replaceChildren(); localStorage.clear(); });


async function click(view,label){const button=[...document.querySelectorAll('button')].find(el=>el.textContent.trim()===label);expect(button).toBeTruthy();await act(async()=>button.click());await flush();}
function resetConfirmHandler(view){const button=[...view.node.querySelectorAll('button')].find(el=>el.textContent.trim()==='Reset Progress');expect(button).toBeTruthy();const props=button[Object.keys(button).find(key=>key.startsWith('__reactProps$'))];expect(typeof props?.onClick).toBe('function');return props.onClick;}
async function confirm(view){await click(view,'Reset');await click(view,'Reset Progress');}
const key='dvaia:admin-reset:1:workshop:csrf_workshop';
test('mounted workshop reset retains operation across lost success and remount, then confirms exact original operation',async()=>{
 axios.post.mockRejectedValueOnce(new Error('lost response'));
 let view=await mount('/admin/challenges');await confirm(view);
 const saved=sessionStorage.getItem(key);expect(saved).toMatch(/^[a-f0-9-]{36}$/);
 expect(axios.post.mock.calls[0][0]).toBe('/api/admin/workshops/csrf_workshop/reset-all-students');
 expect(axios.post.mock.calls[0][2].headers).toEqual({Authorization:'Bearer fixture','x-reset-operation-id':saved});
 act(()=>view.root.unmount());view=await mount('/admin/challenges');await confirm(view);
 expect(axios.post.mock.calls.at(-1)[2].headers['x-reset-operation-id']).toBe(saved);expect(sessionStorage.getItem(key)).toBeNull();
 act(()=>view.root.unmount());
});
test('mounted reset cannot mutate after administrator token changes during discovery',async()=>{
 const pending=deferred(),normal=axios.get.getMockImplementation();axios.get.mockImplementation(url=>url==='/api/admin/workshops/reset-operations'?pending.promise:normal(url));
 const view=await mount('/admin/challenges');await confirm(view);localStorage.setItem('token','replacement');
 await act(async()=>pending.resolve({data:{success:true,operations:[]}}));await flush();expect(axios.post).not.toHaveBeenCalled();act(()=>view.root.unmount());
});
test('workshop bulk reset staged by one administrator cannot be confirmed by another administrator',async()=>{
 const view=await mount('/admin/challenges');
 await click(view,'Reset');
 expect(view.node.textContent).toContain('Reset ALL student progress for');
 expect(axios.post).not.toHaveBeenCalled();
 const retainedConfirm=resetConfirmHandler(view);

 mockUser={id:2,username:'other-admin',isAdmin:true,adminLevel:2,permissions:['manage_progress','manage_challenges']};
 localStorage.setItem('token','other-admin-token');
 await act(async()=>view.root.render(<MemoryRouter initialEntries={['/admin/challenges']}><ComprehensiveAdminDashboard /></MemoryRouter>));
 await flush();
 expect(view.node.textContent).not.toContain('Reset ALL student progress for');

 await act(async()=>retainedConfirm());
 await flush();
 expect(axios.post).not.toHaveBeenCalled();
 act(()=>view.root.unmount());
});
test('workshop bulk reset rejects an ABA session revision after the token is restored',async()=>{
 const view=await mount('/admin/challenges');await click(view,'Reset');
 const retainedConfirm=resetConfirmHandler(view);
 localStorage.setItem('token','temporary-session');
 localStorage.setItem('token','fixture');
 mockAuthRevision+=1;
 await act(async()=>view.root.render(<MemoryRouter initialEntries={['/admin/challenges']}><ComprehensiveAdminDashboard /></MemoryRouter>));
 await flush();
 expect(view.node.textContent).not.toContain('Reset ALL student progress for');
 await act(async()=>retainedConfirm());await flush();
 expect(axios.post).not.toHaveBeenCalled();
 act(()=>view.root.unmount());
});
test('cross-tab token storage event retires a staged reset even when the token string matches',async()=>{
 const view=await mount('/admin/challenges');await click(view,'Reset');
 const retainedConfirm=resetConfirmHandler(view);
 await act(async()=>window.dispatchEvent(new StorageEvent('storage',{
  key:'token',oldValue:'other-session',newValue:'fixture',storageArea:localStorage,
 })));
 await flush();
 expect(view.node.textContent).not.toContain('Reset ALL student progress for');
 await act(async()=>retainedConfirm());await flush();
 expect(axios.get.mock.calls.some(([url])=>url==='/api/admin/workshops/reset-operations')).toBe(false);
 expect(axios.post).not.toHaveBeenCalled();
 act(()=>view.root.unmount());
});
test('canceled workshop reset cannot confirm a later staging through its retained handler',async()=>{
 const view=await mount('/admin/challenges');await click(view,'Reset');
 const oldConfirm=resetConfirmHandler(view);
 await click(view,'Cancel');await click(view,'Reset');
 await act(async()=>oldConfirm());await flush();
 expect(axios.post).not.toHaveBeenCalled();
 expect(view.node.textContent).toContain('Reset ALL student progress for');
 await click(view,'Reset Progress');
 expect(axios.post).toHaveBeenCalledTimes(1);
 act(()=>view.root.unmount());
});
test('double confirmation issues one workshop reset request',async()=>{
 const view=await mount('/admin/challenges');await click(view,'Reset');
 const confirmOnce=resetConfirmHandler(view);
 await act(async()=>{confirmOnce();confirmOnce();});await flush();
 expect(axios.post).toHaveBeenCalledTimes(1);
 act(()=>view.root.unmount());
});
test('mounted password-confirmed all reset resumes server-discovered original operation',async()=>{
 const id='11111111-1111-4111-8111-111111111111',normal=axios.get.getMockImplementation();
 axios.get.mockImplementation(url=>url==='/api/admin/workshops/reset-operations'?Promise.resolve({data:{success:true,operations:[{operationId:id,requestKind:'all'}]}}):normal(url));
 jest.spyOn(window,'prompt').mockReturnValue('controlled-password');const view=await mount('/admin/settings');await click(view,'Reset Challenge Data');
 expect(axios.post).toHaveBeenCalledWith('/api/admin/database/reset',{resetType:'challenges',confirmPassword:'controlled-password'},{headers:{Authorization:'Bearer fixture','x-reset-operation-id':id}});
 expect(sessionStorage.getItem('dvaia:admin-reset:1:all')).toBeNull();act(()=>view.root.unmount());
});
test('workshop reset requires progress permission and refreshes authoritative completion totals',async()=>{
 mockUser={...mockUser,permissions:['manage_challenges']};let view=await mount('/admin/challenges');expect([...view.node.querySelectorAll('button')].some(button=>button.textContent.trim()==='Reset')).toBe(false);act(()=>view.root.unmount());
 mockUser={...mockUser,permissions:['manage_progress']};const normal=axios.get.getMockImplementation();let count=3;
 axios.get.mockImplementation(async url=>{const result=await normal(url);if(url==='/api/admin/challenges')result.data.challenges[0].completions=count;return result;});
 view=await mount('/admin/challenges');expect(view.node.textContent).toContain('✓ 3');axios.post.mockImplementation(async()=>{count=0;return{data:{success:true}};});await confirm(view);expect(view.node.textContent).toContain('✓ 0');act(()=>view.root.unmount());
});
test('refresh failure retains original operation and retry shows newer canonical state without a new destructive ID',async()=>{
 const normal=axios.get.getMockImplementation();let fail=false;
 axios.post.mockImplementation(async()=>{fail=true;return{data:{success:true}};});
 axios.get.mockImplementation(url=>url==='/api/admin/challenges'&&fail?Promise.reject(new Error('refresh failure')):normal(url));
 const view=await mount('/admin/challenges');await confirm(view);const id=sessionStorage.getItem(key);expect(id).toMatch(/^[a-f0-9-]{36}$/);
 axios.post.mockResolvedValue({data:{success:true}});axios.get.mockImplementation(async url=>{const result=await normal(url);if(url==='/api/admin/challenges')result.data.challenges[0].completions=2;return result;});
 await confirm(view);expect(axios.post.mock.calls.at(-1)[2].headers['x-reset-operation-id']).toBe(id);expect(view.node.textContent).toContain('✓ 2');expect(sessionStorage.getItem(key)).toBeNull();act(()=>view.root.unmount());
});
test('authority changes during count refresh prevent stale dashboard commit and retain original recovery',async()=>{
 const normal=axios.get.getMockImplementation(),pending=deferred();let refreshing=false;
 axios.post.mockImplementation(async()=>{refreshing=true;return{data:{success:true}};});
 axios.get.mockImplementation((url,config)=>url==='/api/admin/challenges'&&refreshing&&config?.headers?.Authorization!=='Bearer changed'?pending.promise:normal(url));
 const view=await mount('/admin/challenges');await confirm(view);const id=sessionStorage.getItem(key);localStorage.setItem('token','changed');await act(async()=>pending.resolve({data:{success:true,challenges:[{id:'foreign',name:'SHOULD_NOT_RENDER',completions:99}]}}));await flush();expect(view.node.textContent).not.toContain('SHOULD_NOT_RENDER');expect(sessionStorage.getItem(key)).toBe(id);act(()=>view.root.unmount());
});
test('revision change during count refresh retains recovery without stale counts or success',async()=>{
 const normal=axios.get.getMockImplementation(),pending=deferred();let refreshing=false;
 axios.post.mockImplementation(async()=>{refreshing=true;return{data:{success:true}};});
 axios.get.mockImplementation((url,config)=>url==='/api/admin/challenges'&&refreshing?pending.promise:normal(url));
 const view=await mount('/admin/challenges');await confirm(view);
 const id=sessionStorage.getItem(key);expect(id).toMatch(/^[a-f0-9-]{36}$/);
 mockAuthRevision+=1;
 await act(async()=>pending.resolve({data:{success:true,challenges:[{id:'foreign',name:'SHOULD_NOT_RENDER',completions:99}]}}));
 await flush();
 expect(view.node.textContent).not.toContain('SHOULD_NOT_RENDER');
 expect(sessionStorage.getItem(key)).toBe(id);
 expect(toast.success).not.toHaveBeenCalled();
 act(()=>view.root.unmount());
});
