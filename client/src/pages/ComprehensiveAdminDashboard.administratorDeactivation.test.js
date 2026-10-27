import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import { MemoryRouter } from 'react-router-dom';
import axios from 'axios';
import { toast } from 'react-toastify';
import ComprehensiveAdminDashboard from './ComprehensiveAdminDashboard';

jest.mock('axios', () => ({ get: jest.fn(), post: jest.fn(), put: jest.fn(), delete: jest.fn() }));
let mockUser, mockAuthRevision, mockLogout, accounts;
jest.mock('../context/AuthContext', () => ({ useAuth: () => ({ user: mockUser, logout: mockLogout,
  getAuthRevision: () => mockAuthRevision }) }));
jest.mock('../context/WorkshopConfigContext', () => ({ useWorkshopConfig: () => ({ registerReconciler: () => () => {} }) }));
jest.mock('react-toastify', () => ({ toast: { error: jest.fn(), success: jest.fn() } }));
jest.mock('./admin/CTFAdminPanel', () => () => null);
jest.mock('../components/admin/AIProviderManagement', () => () => null);
jest.mock('../components/admin/StudentWorkshopView', () => () => null);
jest.mock('../components/admin/ServerLogs', () => () => null);
jest.mock('./admin/ProgressAnalyticsPanel', () => () => null);
jest.mock('../components/admin/PromptInjectionHintEditorModal', () => () => null);
jest.mock('../components/observability/AgentRunInspector', () => () => null);

const target={id:17,username:'instructor',email:'instructor@example.test',admin_level:1,
  permissions:['challenge_management'],is_active:1};
let node,root;
async function flush(){await act(async()=>{await Promise.resolve();await Promise.resolve();await Promise.resolve();});}
async function mount(){node=document.createElement('div');document.body.appendChild(node);root=createRoot(node);
 await act(async()=>root.render(<MemoryRouter initialEntries={['/admin/settings']}><ComprehensiveAdminDashboard /></MemoryRouter>));await flush();}
async function click(label){const button=[...node.querySelectorAll('button')].find(item=>item.textContent.trim()===label);
 expect(button).toBeTruthy();await act(async()=>button.click());await flush();return button;}
function dialog(){return node.querySelector('[role="dialog"][aria-label="Deactivate administrator"]');}
function handler(element){const props=element[Object.keys(element).find(key=>key.startsWith('__reactProps$'))];
 expect(typeof props?.onClick).toBe('function');return props.onClick;}
function deferred(){let resolve,reject;const promise=new Promise((ok,no)=>{resolve=ok;reject=no;});return {promise,resolve,reject};}
async function stage(){await mount();await click('Manage Users');await click('Deactivate');expect(dialog()).not.toBeNull();}
function confirmHandler(){return handler([...dialog().querySelectorAll('button')].find(button=>button.textContent.trim()==='Confirm deactivation'));}

beforeEach(()=>{
 global.IS_REACT_ACT_ENVIRONMENT=true;
 mockUser={id:1,username:'admin-a',isAdmin:true,adminLevel:2,permissions:['user_management']};
 mockAuthRevision=0;mockLogout=jest.fn();accounts=[target];localStorage.setItem('token','admin-a');
 axios.get.mockImplementation(url=>url.startsWith('/api/admin/users?')
  ? Promise.resolve({data:{success:true,users:accounts}})
  : Promise.resolve({data:{success:true,challenges:[]}}));
 axios.delete.mockResolvedValue({data:{success:true,user:{id:17,is_active:0}}});
 jest.spyOn(console,'error').mockImplementation(()=>{});
 jest.spyOn(console,'warn').mockImplementation(()=>{});
 jest.spyOn(console,'log').mockImplementation(()=>{});
});
afterEach(()=>{if(root){act(()=>root.unmount());root=null;}document.body.replaceChildren();localStorage.clear();
 jest.restoreAllMocks();jest.clearAllMocks();});

test('deactivation confirmation staged by A cannot dispatch under B',async()=>{
 await stage();const retained=handler([...dialog().querySelectorAll('button')].find(button=>button.textContent.trim()==='Confirm deactivation'));
 mockUser={...mockUser,id:2,username:'admin-b'};mockAuthRevision+=1;localStorage.setItem('token','admin-b');
 await act(async()=>root.render(<MemoryRouter initialEntries={['/admin/settings']}><ComprehensiveAdminDashboard /></MemoryRouter>));await flush();
 await act(async()=>retained());await flush();
 expect(axios.delete).not.toHaveBeenCalled();
});
test('two same-render confirms dispatch one deactivation',async()=>{
 const request=deferred();axios.delete.mockReturnValue(request.promise);
 await stage();const confirm=handler([...dialog().querySelectorAll('button')].find(button=>button.textContent.trim()==='Confirm deactivation'));
 act(()=>{void confirm();void confirm();});
 expect(axios.delete).toHaveBeenCalledTimes(1);
 await act(async()=>request.resolve({data:{success:true,user:{id:17,is_active:0}}}));await flush();
});
test('lost deactivation acknowledgement reads exact target and reports observed state without success',async()=>{
 axios.delete.mockRejectedValueOnce(new Error('connection lost'));
 axios.get.mockImplementation(url=>url==='/api/admin/users/17'
  ? Promise.resolve({data:{success:true,user:{id:17,is_active:0}}})
  : url.startsWith('/api/admin/users?')
    ? Promise.resolve({data:{success:true,users:accounts}})
    : Promise.resolve({data:{success:true}}));
 await stage();toast.success.mockClear();await click('Confirm deactivation');
 expect(axios.get).toHaveBeenCalledWith('/api/admin/users/17',expect.anything());
 expect(dialog().textContent).toMatch(/currently inactive.*does not prove/i);
 expect(toast.success).not.toHaveBeenCalled();
 expect(axios.delete).toHaveBeenCalledTimes(1);
});
test('failed B administrator roster read cannot reveal A rows',async()=>{
 axios.get.mockImplementation((url,config)=>url.startsWith('/api/admin/users?')
  ? (config.headers.Authorization==='Bearer admin-a'
    ? Promise.resolve({data:{success:true,users:[target]}})
    : Promise.reject(new Error('B roster unavailable')))
  : Promise.resolve({data:{success:true}}));
 await mount();await click('Manage Users');
 expect(node.textContent).toContain('instructor@example.test');
 mockUser={...mockUser,id:2,username:'admin-b'};mockAuthRevision+=1;localStorage.setItem('token','admin-b');
 await act(async()=>root.render(<MemoryRouter initialEntries={['/admin/settings']}><ComprehensiveAdminDashboard /></MemoryRouter>));await flush();
 expect(axios.get.mock.calls.filter(([url])=>url.startsWith('/api/admin/users?'))).toHaveLength(2);
 expect(node.textContent).not.toContain('instructor@example.test');
});
test('old canceled or outer-closed confirmation cannot act on a new staging',async()=>{
 await stage();const oldConfirm=confirmHandler();
 const oldCancel=handler([...dialog().querySelectorAll('button')].find(button=>button.textContent.trim()==='Cancel'));
 await click('Cancel');await click('Deactivate');
 await act(async()=>{oldCancel();void oldConfirm();});
 expect(dialog()).not.toBeNull();expect(axios.delete).not.toHaveBeenCalled();
 const secondConfirm=confirmHandler();
 await act(async()=>node.querySelector('button[aria-label="Close user management"]').click());
 await act(async()=>secondConfirm());
 expect(axios.delete).not.toHaveBeenCalled();
});
test('late deactivation response from A cannot toast or sign out B',async()=>{
 const request=deferred();axios.delete.mockReturnValue(request.promise);
 accounts=[{...target,id:1,username:'admin-a',admin_level:2,permissions:['user_management']}];
 await stage();toast.success.mockClear();await click('Confirm deactivation');
 mockUser={...mockUser,id:2,username:'admin-b'};mockAuthRevision+=1;localStorage.setItem('token','admin-b');
 await act(async()=>root.render(<MemoryRouter initialEntries={['/admin/settings']}><ComprehensiveAdminDashboard /></MemoryRouter>));await flush();
 toast.success.mockClear();
 await act(async()=>request.resolve({data:{success:true,user:{id:1,is_active:0}}}));await flush();
 expect(toast.success).not.toHaveBeenCalled();expect(mockLogout).not.toHaveBeenCalled();
});
test('acknowledged self-deactivation begins local sign-out once',async()=>{
 accounts=[{...target,id:1,username:'admin-a',admin_level:2,permissions:['user_management']}];
 axios.delete.mockResolvedValueOnce({data:{success:true,user:{id:1,is_active:0}}});
 await stage();toast.success.mockClear();await click('Confirm deactivation');
 expect(toast.success).toHaveBeenCalledWith('Administrator deactivated');
 expect(mockLogout).toHaveBeenCalledTimes(1);
 expect(axios.delete).toHaveBeenCalledTimes(1);
});
test('malformed success acknowledgement is reconciled, never treated as confirmed',async()=>{
 axios.delete.mockResolvedValueOnce({data:{success:true,user:{id:99,is_active:0}}});
 axios.get.mockImplementation(url=>url==='/api/admin/users/17'
  ? Promise.resolve({data:{success:true,user:{id:17,is_active:1}}})
  : url.startsWith('/api/admin/users?')
    ? Promise.resolve({data:{success:true,users:accounts}})
    : Promise.resolve({data:{success:true}}));
 await stage();toast.success.mockClear();await click('Confirm deactivation');
 expect(toast.success).not.toHaveBeenCalled();
 expect(dialog().textContent).toMatch(/currently active.*does not prove/i);
 expect(mockLogout).not.toHaveBeenCalled();
});
test.each([
 ['missing state',{id:17}],['wrong state type',{id:17,is_active:'0'}],['wrong target',{id:18,is_active:0}],
])('uncertain readback with %s cannot claim observed state',async(_label,user)=>{
 axios.delete.mockRejectedValueOnce(new Error('connection lost'));
 axios.get.mockImplementation(url=>url==='/api/admin/users/17'
  ? Promise.resolve({data:{success:true,user}})
  : url.startsWith('/api/admin/users?')
    ? Promise.resolve({data:{success:true,users:accounts}})
    : Promise.resolve({data:{success:true}}));
 await stage();await click('Confirm deactivation');
 expect(dialog().textContent).toContain('Current account status could not be read.');
 expect(dialog().textContent).not.toMatch(/currently (active|inactive)/i);
});
test('last-capable-administrator rejection stays visible without retry',async()=>{
 axios.delete.mockRejectedValueOnce({response:{status:409,data:{code:'LAST_ADMIN',error:'last admin'}}});
 await stage();toast.success.mockClear();await click('Confirm deactivation');
 expect(toast.error).toHaveBeenCalledWith('At least one active level 2 administrator with user management permission must remain.');
 expect(dialog().textContent).toContain('The server rejected deactivation');
 expect(axios.delete).toHaveBeenCalledTimes(1);expect(toast.success).not.toHaveBeenCalled();
});
test('administrator roster Retry captures current bearer rather than click event',async()=>{
 let attempts=0;
 axios.get.mockImplementation((url,config)=>{
  if(url.startsWith('/api/admin/users?')){
   attempts+=1;
   if(attempts===1)return Promise.reject(new Error('temporary outage'));
   expect(config.headers.Authorization).toBe('Bearer admin-a');
   return Promise.resolve({data:{success:true,users:[target]}});
  }
  return Promise.resolve({data:{success:true}});
 });
 await mount();await click('Manage Users');
 expect(node.textContent).toContain('Failed to load administrators');
 await click('Retry');
 expect(attempts).toBe(2);expect(node.textContent).toContain('instructor@example.test');
});
test('same-token revision ABA retires a staged deactivation',async()=>{
 await stage();const retained=confirmHandler();
 mockAuthRevision+=1;
 await act(async()=>root.render(<MemoryRouter initialEntries={['/admin/settings']}><ComprehensiveAdminDashboard /></MemoryRouter>));await flush();
 expect(dialog()).toBeNull();
 await act(async()=>retained());
 expect(axios.delete).not.toHaveBeenCalled();
});
test('cross-tab storage ABA retires a staged deactivation',async()=>{
 await stage();const retained=confirmHandler();
 await act(async()=>window.dispatchEvent(new StorageEvent('storage',{
  key:'token',oldValue:'admin-b',newValue:'admin-a',storageArea:localStorage,
 })));
 expect(dialog()).toBeNull();
 await act(async()=>retained());
 expect(axios.delete).not.toHaveBeenCalled();
});
test('late A administrator roster cannot overwrite B roster',async()=>{
 const first=deferred(),second=deferred();
 axios.get.mockImplementation((url,config)=>url.startsWith('/api/admin/users?')
  ? (config.headers.Authorization==='Bearer admin-a'?first.promise:second.promise)
  : Promise.resolve({data:{success:true}}));
 await mount();await click('Manage Users');
 mockUser={...mockUser,id:2,username:'admin-b'};mockAuthRevision+=1;localStorage.setItem('token','admin-b');
 await act(async()=>root.render(<MemoryRouter initialEntries={['/admin/settings']}><ComprehensiveAdminDashboard /></MemoryRouter>));await flush();
 await act(async()=>first.resolve({data:{success:true,users:[target]}}));await flush();
 expect(node.textContent).not.toContain('instructor@example.test');
 await act(async()=>second.resolve({data:{success:true,users:[{...target,id:18,username:'instructor-b',email:'b@example.test'}]}}));await flush();
 expect(node.textContent).toContain('b@example.test');
 expect(node.textContent).not.toContain('instructor@example.test');
});
test('older same-session roster read cannot restore active row after confirmed deactivation',async()=>{
 const oldRead=deferred();let rosterReads=0;
 axios.get.mockImplementation(url=>{
  if(url.startsWith('/api/admin/users?')){
   rosterReads+=1;
   if(rosterReads===1)return Promise.reject(new Error('temporary outage'));
   if(rosterReads===2)return Promise.resolve({data:{success:true,users:[target]}});
   if(rosterReads===3)return oldRead.promise;
   return Promise.resolve({data:{success:true,users:[{...target,is_active:0}]}});
  }
  return Promise.resolve({data:{success:true}});
 });
 await mount();await click('Manage Users');
 const retry=handler([...node.querySelectorAll('button')].find(button=>button.textContent.trim()==='Retry'));
 await click('Retry');await click('Deactivate');
 await act(async()=>{void retry();});
 expect(rosterReads).toBe(3);
 await click('Confirm deactivation');
 expect(rosterReads).toBe(4);
 expect(node.textContent).toContain('Inactive');
 await act(async()=>oldRead.resolve({data:{success:true,users:[target]}}));await flush();
 const row=[...node.querySelectorAll('tr')].find(item=>item.textContent.includes('instructor@example.test'));
 expect(row).toBeTruthy();expect(row.textContent).toContain('Inactive');
 expect([...row.querySelectorAll('button')].some(button=>button.textContent.trim()==='Deactivate')).toBe(false);
});
