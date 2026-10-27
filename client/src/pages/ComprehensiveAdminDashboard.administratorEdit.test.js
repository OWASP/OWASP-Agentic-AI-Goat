import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import { MemoryRouter } from 'react-router-dom';
import axios from 'axios';
import { toast } from 'react-toastify';
import ComprehensiveAdminDashboard from './ComprehensiveAdminDashboard';

jest.mock('axios',()=>({get:jest.fn(),post:jest.fn(),put:jest.fn(),delete:jest.fn()}));
let mockUser,mockAuthRevision,mockLogout,accounts;
jest.mock('../context/AuthContext',()=>({useAuth:()=>({user:mockUser,logout:mockLogout,getAuthRevision:()=>mockAuthRevision})}));
jest.mock('../context/WorkshopConfigContext',()=>({useWorkshopConfig:()=>({registerReconciler:()=>()=>{}})}));
jest.mock('react-toastify',()=>({toast:{error:jest.fn(),success:jest.fn()}}));
jest.mock('./admin/CTFAdminPanel',()=>()=>null);
jest.mock('../components/admin/AIProviderManagement',()=>()=>null);
jest.mock('../components/admin/StudentWorkshopView',()=>()=>null);
jest.mock('../components/admin/ServerLogs',()=>()=>null);
jest.mock('./admin/ProgressAnalyticsPanel',()=>()=>null);
jest.mock('../components/admin/PromptInjectionHintEditorModal',()=>()=>null);
jest.mock('../components/observability/AgentRunInspector',()=>()=>null);

const target={id:17,username:'instructor',email:'instructor@example.test',full_name:'Instructor One',
 admin_level:1,permissions:['challenge_management'],is_active:1};
const ack=account=>({data:{success:true,user:{id:account.id,username:account.username,email:account.email,
 full_name:account.full_name,admin_level:account.admin_level,is_active:account.is_active},permissions:account.permissions}});
let root,node;
async function flush(){await act(async()=>{await Promise.resolve();await Promise.resolve();await Promise.resolve();});}
async function mount(){node=document.createElement('div');document.body.appendChild(node);root=createRoot(node);
 await act(async()=>root.render(<MemoryRouter initialEntries={['/admin/settings']}><ComprehensiveAdminDashboard /></MemoryRouter>));await flush();}
async function click(label){const button=[...node.querySelectorAll('button')].find(item=>item.textContent.trim()===label);
 expect(button).toBeTruthy();await act(async()=>button.click());await flush();return button;}
function editForm(){return node.querySelector('#edit-admin-username')?.closest('form');}
function handler(element,name){const props=element[Object.keys(element).find(key=>key.startsWith('__reactProps$'))];
 expect(typeof props?.[name]).toBe('function');return props[name];}
function deferred(){let resolve,reject;const promise=new Promise((ok,no)=>{resolve=ok;reject=no;});return {promise,resolve,reject};}
async function stage(){await mount();await click('Manage Users');await click('Edit');expect(editForm()).toBeTruthy();}
async function submit(){await act(async()=>editForm().dispatchEvent(new Event('submit',{bubbles:true,cancelable:true})));await flush();}

beforeEach(()=>{
 global.IS_REACT_ACT_ENVIRONMENT=true;
 mockUser={id:1,username:'admin-a',isAdmin:true,adminLevel:2,permissions:['user_management']};
 mockAuthRevision=0;mockLogout=jest.fn();accounts=[target];localStorage.setItem('token','admin-a');
 axios.get.mockImplementation(url=>url.startsWith('/api/admin/users?')
  ? Promise.resolve({data:{success:true,users:accounts}})
  : Promise.resolve({data:{success:true,challenges:[]}}));
 axios.put.mockResolvedValue(ack(target));
 jest.spyOn(console,'error').mockImplementation(()=>{});
 jest.spyOn(console,'warn').mockImplementation(()=>{});
 jest.spyOn(console,'log').mockImplementation(()=>{});
});
afterEach(()=>{if(root){act(()=>root.unmount());root=null;}document.body.replaceChildren();localStorage.clear();
 jest.restoreAllMocks();jest.clearAllMocks();});

test('Edit form staged by A cannot submit under B',async()=>{
 await stage();const retained=handler(editForm(),'onSubmit');
 mockUser={...mockUser,id:2,username:'admin-b'};mockAuthRevision+=1;localStorage.setItem('token','admin-b');
 await act(async()=>root.render(<MemoryRouter initialEntries={['/admin/settings']}><ComprehensiveAdminDashboard /></MemoryRouter>));await flush();
 await act(async()=>retained({preventDefault(){}}));
 expect(axios.put).not.toHaveBeenCalled();
});
test('two same-render Save submissions issue one administrator update',async()=>{
 const request=deferred();axios.put.mockReturnValue(request.promise);
 await stage();const retained=handler(editForm(),'onSubmit');
 act(()=>{void retained({preventDefault(){}});void retained({preventDefault(){}});});
 expect(axios.put).toHaveBeenCalledTimes(1);
 await act(async()=>request.resolve(ack(target)));await flush();
});
test('late self-Edit acknowledgement cannot log out a replacement admin',async()=>{
 const request=deferred();axios.put.mockReturnValue(request.promise);
 accounts=[{...target,id:1,username:'admin-a',admin_level:2,permissions:['user_management']}];
 await stage();await submit();
 mockUser={...mockUser,id:2,username:'admin-b'};mockAuthRevision+=1;localStorage.setItem('token','admin-b');
 await act(async()=>root.render(<MemoryRouter initialEntries={['/admin/settings']}><ComprehensiveAdminDashboard /></MemoryRouter>));await flush();
 toast.success.mockClear();
 await act(async()=>request.resolve(ack(accounts[0])));await flush();
 expect(mockLogout).not.toHaveBeenCalled();expect(toast.success).not.toHaveBeenCalled();
});
test('canceled Edit callback cannot submit or close a newly staged Edit',async()=>{
 await stage();const oldSubmit=handler(editForm(),'onSubmit');
 const oldCancel=handler([...editForm().querySelectorAll('button')].find(button=>button.textContent.trim()==='Cancel'),'onClick');
 await click('Cancel');await click('Edit');
 await act(async()=>{oldCancel();void oldSubmit({preventDefault(){}});});
 expect(editForm()).toBeTruthy();expect(axios.put).not.toHaveBeenCalled();
});
test('lost Edit acknowledgement reads exact target and reports only current state',async()=>{
 axios.put.mockRejectedValueOnce(new Error('connection lost'));
 axios.get.mockImplementation(url=>url==='/api/admin/users/17'
  ? Promise.resolve({data:{success:true,user:{id:17,username:'instructor',is_active:1}}})
  : url.startsWith('/api/admin/users?')
    ? Promise.resolve({data:{success:true,users:accounts}})
    : Promise.resolve({data:{success:true}}));
 await stage();toast.success.mockClear();await submit();
 expect(axios.get).toHaveBeenCalledWith('/api/admin/users/17',expect.anything());
 expect(editForm().textContent).toMatch(/currently active.*does not prove/i);
 expect(editForm().textContent).toContain('Permission changes could not be confirmed.');
 expect(toast.success).not.toHaveBeenCalled();expect(axios.put).toHaveBeenCalledTimes(1);
});
test.each([
 ['opposite active state',account=>({...ack(account),data:{...ack(account).data,user:{...ack(account).data.user,is_active:0}}})],
 ['wrong permission set',account=>({...ack(account),data:{...ack(account).data,permissions:['view_analytics']}})],
])('malformed Edit ACK with %s cannot claim success',async(_label,makeResponse)=>{
 axios.put.mockResolvedValueOnce(makeResponse(target));
 axios.get.mockImplementation(url=>url==='/api/admin/users/17'
  ? Promise.resolve({data:{success:true,user:{id:17,username:'instructor',is_active:1}}})
  : url.startsWith('/api/admin/users?')
    ? Promise.resolve({data:{success:true,users:accounts}})
    : Promise.resolve({data:{success:true}}));
 await stage();toast.success.mockClear();await submit();
 expect(toast.success).not.toHaveBeenCalled();expect(mockLogout).not.toHaveBeenCalled();
 expect(editForm().textContent).toContain('The update outcome could not be confirmed.');
});
test('acknowledged self-Edit signs out only the submitting session',async()=>{
 accounts=[{...target,id:1,username:'admin-a',admin_level:2,permissions:['user_management']}];
 axios.put.mockResolvedValueOnce(ack(accounts[0]));
 await stage();toast.success.mockClear();await submit();
 expect(mockLogout).toHaveBeenCalledTimes(1);
 expect(toast.success).toHaveBeenCalledWith('Administrator updated');
});
test('LAST_ADMIN edit rejection remains visible without automatic retry',async()=>{
 axios.put.mockRejectedValueOnce({response:{status:409,data:{code:'LAST_ADMIN'}}});
 await stage();toast.success.mockClear();await submit();
 expect(toast.error).toHaveBeenCalledWith('At least one active level 2 administrator with user management permission must remain.');
 expect(editForm().textContent).toContain('The server rejected this update');
 expect(axios.put).toHaveBeenCalledTimes(1);expect(toast.success).not.toHaveBeenCalled();
});
test('pending Edit ref blocks retained Deactivate in the same render',async()=>{
 const request=deferred();axios.put.mockReturnValue(request.promise);
 await mount();await click('Manage Users');
 const deactivate=handler([...node.querySelectorAll('button')].find(button=>button.textContent.trim()==='Deactivate'),'onClick');
 await click('Edit');
 const editSubmit=handler(editForm(),'onSubmit');
 act(()=>{void editSubmit({preventDefault(){}});deactivate();});
 expect(axios.put).toHaveBeenCalledTimes(1);expect(axios.delete).not.toHaveBeenCalled();
 await act(async()=>request.resolve(ack(target)));await flush();
});
test('cross-tab storage ABA retires a staged Edit callback',async()=>{
 await stage();const retained=handler(editForm(),'onSubmit');
 await act(async()=>window.dispatchEvent(new StorageEvent('storage',{
  key:'token',oldValue:'admin-b',newValue:'admin-a',storageArea:localStorage,
 })));
 expect(editForm()).toBeFalsy();
 await act(async()=>retained({preventDefault(){}}));
 expect(axios.put).not.toHaveBeenCalled();
});
test('pending Deactivate ref blocks retained Edit in the same render',async()=>{
 const request=deferred();axios.delete.mockReturnValue(request.promise);
 await mount();await click('Manage Users');
 const edit=handler([...node.querySelectorAll('button')].find(button=>button.textContent.trim()==='Edit'),'onClick');
 await click('Deactivate');
 const confirm=handler([...node.querySelectorAll('button')].find(button=>button.textContent.trim()==='Confirm deactivation'),'onClick');
 act(()=>{void confirm();edit();});
 expect(axios.delete).toHaveBeenCalledTimes(1);expect(editForm()).toBeFalsy();
 await act(async()=>request.resolve({data:{success:true,user:{id:17,is_active:0}}}));await flush();
});
test('retained old Edit email handler cannot poison a new same-target draft',async()=>{
 await stage();const oldChange=handler(editForm().querySelector('#edit-admin-email'),'onChange');
 await click('Cancel');await click('Edit');
 await act(async()=>oldChange({target:{value:'old-session@example.test'}}));
 expect(editForm().querySelector('#edit-admin-email').value).toBe('instructor@example.test');
 await submit();
 expect(axios.put.mock.calls[0][1].email).toBe('instructor@example.test');
});
test('retained old Edit permission handler cannot add a grant to a new draft',async()=>{
 await stage();const oldChange=handler(editForm().querySelector('input[value="view_analytics"]'),'onChange');
 await click('Cancel');await click('Edit');
 await act(async()=>oldChange({target:{checked:true}}));
 expect(editForm().querySelector('input[value="view_analytics"]').checked).toBe(false);
 await submit();
 expect(axios.put.mock.calls[0][1].permissions).toEqual(['challenge_management']);
});
test('old A field handler cannot alter B draft for the same target',async()=>{
 await stage();const oldChange=handler(editForm().querySelector('#edit-admin-email'),'onChange');
 mockUser={...mockUser,id:2,username:'admin-b'};mockAuthRevision+=1;localStorage.setItem('token','admin-b');
 await act(async()=>root.render(<MemoryRouter initialEntries={['/admin/settings']}><ComprehensiveAdminDashboard /></MemoryRouter>));await flush();
 await click('Edit');
 await act(async()=>oldChange({target:{value:'old-admin@example.test'}}));
 expect(editForm().querySelector('#edit-admin-email').value).toBe('instructor@example.test');
 await submit();
 expect(axios.put.mock.calls[0][1].email).toBe('instructor@example.test');
 expect(axios.put.mock.calls[0][2].headers.Authorization).toBe('Bearer admin-b');
});
