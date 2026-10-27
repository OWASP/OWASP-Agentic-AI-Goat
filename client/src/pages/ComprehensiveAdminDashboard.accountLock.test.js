import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import { MemoryRouter } from 'react-router-dom';
import axios from 'axios';
import { toast } from 'react-toastify';
import ComprehensiveAdminDashboard from './ComprehensiveAdminDashboard';

jest.mock('axios', () => ({ get: jest.fn(), post: jest.fn(), put: jest.fn(), delete: jest.fn() }));
let mockUser, mockAuthRevision, lockedUsers;
jest.mock('../context/AuthContext', () => ({ useAuth: () => ({ user: mockUser, logout: jest.fn(), getAuthRevision: () => mockAuthRevision }) }));
jest.mock('../context/WorkshopConfigContext', () => ({ useWorkshopConfig: () => ({ registerReconciler: () => () => {} }) }));
jest.mock('react-toastify', () => ({ toast: { error: jest.fn(), success: jest.fn() } }));
jest.mock('./admin/CTFAdminPanel', () => () => null);
jest.mock('../components/admin/AIProviderManagement', () => () => null);
jest.mock('../components/admin/StudentWorkshopView', () => () => null);
jest.mock('../components/admin/ServerLogs', () => () => null);
jest.mock('./admin/ProgressAnalyticsPanel', () => () => null);
jest.mock('../components/admin/PromptInjectionHintEditorModal', () => () => null);
jest.mock('../components/observability/AgentRunInspector', () => () => null);

const student = { id: 19, username: 'learner19', email: 'learner19@example.test', role: 'student', is_active: true };
const lockedStudent = { ...student, lock_type: 'admin', login_attempts: 2, isCurrentlyLocked: true, remainingMinutes: 1000 };
let root, node;
async function flush(){await act(async()=>{await Promise.resolve();await Promise.resolve();await Promise.resolve();});}
async function mount(path){node=document.createElement('div');document.body.appendChild(node);root=createRoot(node);await act(async()=>root.render(<MemoryRouter initialEntries={[path]}><ComprehensiveAdminDashboard /></MemoryRouter>));await flush();}
async function click(label){const buttons=[...node.querySelectorAll('button')];const button=buttons.find(item=>item.textContent.trim()===label);if(!button)throw new Error(`Missing ${label}; visible buttons: ${buttons.map(item=>item.textContent.trim()).join(', ')}`);await act(async()=>button.click());await flush();return button;}
function dialog(){return node.querySelector('[role="dialog"][aria-label="Confirm account access change"]');}
function handler(element,name='onClick'){const props=element[Object.keys(element).find(key=>key.startsWith('__reactProps$'))];expect(typeof props?.[name]).toBe('function');return props[name];}
function deferred(){let resolve,reject;const promise=new Promise((ok,no)=>{resolve=ok;reject=no;});return {promise,resolve,reject};}
function confirmButton(action){return [...dialog().querySelectorAll('button')].find(button=>button.textContent.trim()===`Confirm ${action}`);}
async function openLock(){await mount('/admin/settings');await click('Manage Users');await click('Students');await click('Lock');}
async function openUnlock(){await mount('/admin/locked-users');await click('Unlock');}

beforeEach(()=>{
 global.IS_REACT_ACT_ENVIRONMENT=true;
 mockUser={id:1,username:'admin',isAdmin:true,adminLevel:2,permissions:['user_management','manage_progress']};
 mockAuthRevision=0;lockedUsers=[lockedStudent];localStorage.setItem('token','admin-a');
 axios.get.mockImplementation(url=>{
  if(url==='/api/admin/students')return Promise.resolve({data:{success:true,students:[student]}});
  if(url==='/api/admin/users/locked')return Promise.resolve({data:{success:true,lockedUsers}});
  if(url.startsWith('/api/admin/users?'))return Promise.resolve({data:{success:true,users:[]}});
  if(url==='/api/admin/challenges')return Promise.resolve({data:{success:true,challenges:[]}});
  return Promise.resolve({data:{}});
 });
 axios.post.mockResolvedValue({data:{success:true,message:'Account changed successfully'}});
 jest.spyOn(console,'error').mockImplementation(()=>{});
 jest.spyOn(console,'warn').mockImplementation(()=>{});
 jest.spyOn(console,'log').mockImplementation(()=>{});
});
afterEach(()=>{if(root){act(()=>root.unmount());root=null;}document.body.replaceChildren();localStorage.clear();jest.restoreAllMocks();jest.clearAllMocks();});

test('Lock stages a consequence dialog without changing account access',async()=>{
 await openLock();
 expect(axios.post).not.toHaveBeenCalled();
 expect(dialog()).not.toBeNull();
 expect(dialog().textContent).toContain('learner19');
 expect(dialog().textContent).toMatch(/revoke.*session/i);
 await click('Cancel');
 expect(axios.post).not.toHaveBeenCalled();
});
test('Unlock stages a consequence dialog without changing account access',async()=>{
 await openUnlock();
 expect(axios.post).not.toHaveBeenCalled();
 expect(dialog()).not.toBeNull();
 expect(dialog().textContent).toContain('learner19');
 expect(dialog().textContent).toMatch(/failed.*attempt/i);
 await click('Cancel');
 expect(axios.post).not.toHaveBeenCalled();
});
test('Lock confirmation staged by one administrator cannot run under another session',async()=>{
 await openLock();
 const retainedConfirm=handler(confirmButton('Lock'));
 mockUser={...mockUser,id:2,username:'other-admin'};mockAuthRevision+=1;localStorage.setItem('token','admin-b');
 await act(async()=>root.render(<MemoryRouter initialEntries={['/admin/settings']}><ComprehensiveAdminDashboard /></MemoryRouter>));await flush();
 expect(dialog()).toBeNull();
 await act(async()=>retainedConfirm());await flush();
 expect(axios.post).not.toHaveBeenCalled();
});
test('same-render repeated confirmation sends only one lock request',async()=>{
 const request=deferred();axios.post.mockReturnValue(request.promise);
 await openLock();toast.success.mockClear();const confirm=handler(confirmButton('Lock'));
 act(()=>{void confirm();void confirm();});
 expect(axios.post).toHaveBeenCalledTimes(1);
 expect(dialog().textContent).toContain('Changing account access');
 await act(async()=>request.resolve({data:{success:true}}));await flush();
 expect(axios.post).toHaveBeenCalledTimes(1);
 expect(toast.success).toHaveBeenCalledTimes(1);
});
test('lost acknowledgement uses exact target readback and never claims the request committed',async()=>{
 axios.post.mockRejectedValueOnce(new Error('connection lost'));
 axios.get.mockImplementation(url=>{
  if(url==='/api/admin/users/19')return Promise.resolve({data:{success:true,user:{id:19,account_locked_until:'2099-12-31T23:59:59Z',login_attempts:2}}});
  if(url==='/api/admin/users/locked')return Promise.resolve({data:{success:true,lockedUsers}});
  return Promise.resolve({data:{success:true,students:[student],users:[]}});
 });
 await openLock();toast.success.mockClear();await click('Confirm Lock');
 expect(axios.get).toHaveBeenCalledWith('/api/admin/users/19',expect.anything());
 expect(dialog().textContent).toMatch(/currently locked.*does not prove this request made the change/i);
 expect(toast.success).not.toHaveBeenCalled();
 expect(axios.post).toHaveBeenCalledTimes(1);
 await click('Close');
 expect(dialog()).toBeNull();
});
test('revision-only retirement blocks retained confirmation',async()=>{
 await openUnlock();const retained=handler(confirmButton('Unlock'));
 mockAuthRevision+=1;
 await act(async()=>root.render(<MemoryRouter initialEntries={['/admin/locked-users']}><ComprehensiveAdminDashboard /></MemoryRouter>));await flush();
 expect(dialog()).toBeNull();
 await act(async()=>retained());
 expect(axios.post).not.toHaveBeenCalled();
});
test('a storage ABA event retires a staged confirmation even when the token returns',async()=>{
 await openUnlock();const retained=handler(confirmButton('Unlock'));
 act(()=>window.dispatchEvent(new StorageEvent('storage',{key:'token',storageArea:localStorage,oldValue:'admin-a',newValue:'admin-b'})));
 expect(dialog()).toBeNull();
 await act(async()=>retained());
 expect(axios.post).not.toHaveBeenCalled();
});
test('an acknowledged lock remains acknowledged if a later read loses session access',async()=>{
 await openLock();toast.success.mockClear();
 axios.get.mockImplementation(url=>url==='/api/admin/users/locked'
  ? Promise.reject(Object.assign(new Error('revoked'),{response:{status:401}}))
  : Promise.resolve({data:{success:true}}));
 await click('Confirm Lock');
 expect(toast.success).toHaveBeenCalledWith('learner19 locked');
 expect(dialog()).toBeNull();
 expect(axios.post).toHaveBeenCalledTimes(1);
});
test('a late POST acknowledgement cannot report success after authority revision changes',async()=>{
 const request=deferred();axios.post.mockReturnValue(request.promise);
 await openUnlock();toast.success.mockClear();await click('Confirm Unlock');
 expect(axios.post).toHaveBeenCalledTimes(1);
 mockAuthRevision+=1;
 await act(async()=>root.render(<MemoryRouter initialEntries={['/admin/locked-users']}><ComprehensiveAdminDashboard /></MemoryRouter>));await flush();
 expect(dialog()).toBeNull();
 await act(async()=>request.resolve({data:{success:true}}));await flush();
 expect(toast.success).not.toHaveBeenCalled();
 expect(axios.get.mock.calls.some(([url])=>url==='/api/admin/users/19')).toBe(false);
});
test('an old canceled dialog cannot confirm or cancel a newly staged action',async()=>{
 await openUnlock();const oldConfirm=handler(confirmButton('Unlock'));
 const oldCancel=handler([...dialog().querySelectorAll('button')].find(button=>button.textContent.trim()==='Cancel'));
 await click('Cancel');await click('Unlock');
 await act(async()=>{oldCancel();void oldConfirm();});
 expect(dialog()).not.toBeNull();
 expect(axios.post).not.toHaveBeenCalled();
 await click('Confirm Unlock');
 expect(axios.post).toHaveBeenCalledTimes(1);
});
test.each([[403,'Administrator session required'],[409,'LAST_ADMIN']])('server rejection %i stays a rejection with no success or retry',async(status,message)=>{
 axios.post.mockRejectedValueOnce({response:{status,data:{error:message}}});
 await openUnlock();toast.success.mockClear();await click('Confirm Unlock');
 expect(dialog().textContent).toContain(`The server rejected this account change: ${message}`);
 expect(toast.success).not.toHaveBeenCalled();
 expect(axios.post).toHaveBeenCalledTimes(1);
 expect(axios.get.mock.calls.some(([url])=>url==='/api/admin/users/19')).toBe(false);
});
test('locked-users visibility alone does not permit Unlock',async()=>{
 mockUser={...mockUser,permissions:[]};
 await mount('/admin/locked-users');
 const unlock=[...node.querySelectorAll('button')].find(button=>button.textContent.trim()==='Unlock');
 expect(unlock).toBeTruthy();expect(unlock.disabled).toBe(true);
 await act(async()=>handler(unlock)());
 expect(axios.post).not.toHaveBeenCalled();
});
test.each(['late success','late failure'])('%s from administrator A cannot replace B roster or clear B loading',async(outcome)=>{
 const first=deferred(),second=deferred();
 axios.get.mockImplementation((url,config)=>url==='/api/admin/users/locked'
  ? (config.headers.Authorization==='Bearer admin-a'?first.promise:second.promise)
  : Promise.resolve({data:{success:true}}));
 await mount('/admin/locked-users');
 expect(axios.get.mock.calls.filter(([url])=>url==='/api/admin/users/locked')).toHaveLength(1);
 mockUser={...mockUser,id:2,username:'admin-b'};mockAuthRevision+=1;localStorage.setItem('token','admin-b');
 await act(async()=>root.render(<MemoryRouter initialEntries={['/admin/locked-users']}><ComprehensiveAdminDashboard /></MemoryRouter>));await flush();
 expect(axios.get.mock.calls.filter(([url])=>url==='/api/admin/users/locked')).toHaveLength(2);
 toast.error.mockClear();
 await act(async()=>outcome==='late success'
  ? first.resolve({data:{success:true,lockedUsers:[lockedStudent]}})
  : first.reject(new Error('old administrator read failed')));await flush();
 expect(node.textContent).not.toContain('learner19');
 expect(node.textContent).toContain('Loading locked users');
 expect(toast.error).not.toHaveBeenCalled();
 await act(async()=>second.resolve({data:{success:true,lockedUsers:[{...lockedStudent,id:27,username:'learner27',email:'learner27@example.test'}]}}));await flush();
 expect(node.textContent).toContain('learner27');
 expect(node.textContent).not.toContain('learner19');
});
test('failed B roster read does not reveal A roster after authority changes',async()=>{
 axios.get.mockImplementation((url,config)=>url==='/api/admin/users/locked'
  ? (config.headers.Authorization==='Bearer admin-a'
    ? Promise.resolve({data:{success:true,lockedUsers:[lockedStudent]}})
    : Promise.reject(new Error('B roster unavailable')))
  : Promise.resolve({data:{success:true}}));
 await mount('/admin/locked-users');
 expect(node.textContent).toContain('learner19');
 mockUser={...mockUser,id:2,username:'admin-b'};mockAuthRevision+=1;localStorage.setItem('token','admin-b');
 await act(async()=>root.render(<MemoryRouter initialEntries={['/admin/locked-users']}><ComprehensiveAdminDashboard /></MemoryRouter>));await flush();
 expect(toast.error).toHaveBeenCalledWith(expect.stringContaining('B roster unavailable'));
 expect(node.textContent).not.toContain('learner19');
});
test.each([
 ['malformed lock timestamp',{id:19,account_locked_until:'not-a-date'}],
 ['missing lock timestamp',{id:19}],
 ['wrong timestamp type',{id:19,account_locked_until:0}],
 ['mismatched target',{id:20,account_locked_until:null}],
])('unknown outcome with %s never claims an observed lock state',async(_label,account)=>{
 axios.post.mockRejectedValueOnce(new Error('connection lost'));
 axios.get.mockImplementation(url=>url==='/api/admin/users/19'
  ? Promise.resolve({data:{success:true,user:account}})
  : Promise.resolve({data:{success:true,lockedUsers,students:[student]}}));
 await openLock();await click('Confirm Lock');
 expect(dialog().textContent).toContain('Current account status could not be read.');
 expect(dialog().textContent).not.toMatch(/currently (locked|unlocked)/i);
 expect(axios.post).toHaveBeenCalledTimes(1);
});
test('older same-session roster read cannot resurrect a row after confirmed Unlock refresh',async()=>{
 const oldRead=deferred();let rosterReads=0;
 axios.get.mockImplementation(url=>{
  if(url==='/api/admin/users/locked'){
   rosterReads+=1;
   if(rosterReads===1)return Promise.resolve({data:{success:true,lockedUsers:[lockedStudent]}});
   if(rosterReads===2)return oldRead.promise;
   return Promise.resolve({data:{success:true,lockedUsers:[]}});
  }
  return Promise.resolve({data:{}});
 });
 await mount('/admin/locked-users');
 const unlock=[...node.querySelectorAll('button')].find(button=>button.textContent.trim()==='Unlock');
 const retainedUnlock=handler(unlock);
 const refresh=node.querySelector('button[title="Refresh locked users list"]');
 await act(async()=>refresh.click());
 expect(rosterReads).toBe(2);
 await act(async()=>retainedUnlock());await click('Confirm Unlock');
 expect(rosterReads).toBe(3);
 expect(node.textContent).not.toContain('learner19');
 await act(async()=>oldRead.resolve({data:{success:true,lockedUsers:[lockedStudent]}}));await flush();
 expect(node.textContent).not.toContain('learner19');
 expect(axios.post).toHaveBeenCalledTimes(1);
});
