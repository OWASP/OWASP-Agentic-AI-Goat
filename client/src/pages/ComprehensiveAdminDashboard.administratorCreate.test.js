import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import { MemoryRouter } from 'react-router-dom';
import axios from 'axios';
import { toast } from 'react-toastify';
import ComprehensiveAdminDashboard from './ComprehensiveAdminDashboard';

jest.mock('axios',()=>({get:jest.fn(),post:jest.fn(),put:jest.fn(),delete:jest.fn()}));
let mockUser,mockAuthRevision;
jest.mock('../context/AuthContext',()=>({useAuth:()=>({user:mockUser,logout:jest.fn(),getAuthRevision:()=>mockAuthRevision})}));
jest.mock('../context/WorkshopConfigContext',()=>({useWorkshopConfig:()=>({registerReconciler:()=>()=>{}})}));
jest.mock('react-toastify',()=>({toast:{error:jest.fn(),success:jest.fn()}}));
jest.mock('./admin/CTFAdminPanel',()=>()=>null);
jest.mock('../components/admin/AIProviderManagement',()=>()=>null);
jest.mock('../components/admin/StudentWorkshopView',()=>()=>null);
jest.mock('../components/admin/ServerLogs',()=>()=>null);
jest.mock('./admin/ProgressAnalyticsPanel',()=>()=>null);
jest.mock('../components/admin/PromptInjectionHintEditorModal',()=>()=>null);
jest.mock('../components/observability/AgentRunInspector',()=>()=>null);

let root,node;
async function flush(){await act(async()=>{await Promise.resolve();await Promise.resolve();await Promise.resolve();});}
async function mount(){node=document.createElement('div');document.body.appendChild(node);root=createRoot(node);
 await act(async()=>root.render(<MemoryRouter initialEntries={['/admin/settings']}><ComprehensiveAdminDashboard /></MemoryRouter>));await flush();}
async function click(label){const button=[...node.querySelectorAll('button')].find(item=>item.textContent.trim()===label);
 expect(button).toBeTruthy();await act(async()=>button.click());await flush();return button;}
function form(){return node.querySelector('#new-admin-username')?.closest('form');}
function handler(element,name){const props=element[Object.keys(element).find(key=>key.startsWith('__reactProps$'))];
 expect(typeof props?.[name]).toBe('function');return props[name];}
function deferred(){let resolve,reject;const promise=new Promise((ok,no)=>{resolve=ok;reject=no;});return {promise,resolve,reject};}
async function change(selector,value,checked){const input=form().querySelector(selector);const onChange=handler(input,'onChange');
 await act(async()=>onChange({target:checked===undefined?{value}:{value,checked}}));await flush();}
async function stage(){await mount();await click('Manage Users');await click('Add administrator');expect(form()).toBeTruthy();}
async function fill(){await change('#new-admin-username','new-instructor');await change('#new-admin-email','new@example.test');
 await change('#new-admin-password','test-password');await change('#new-admin-confirm-password','test-password');}
async function submit(){await act(async()=>form().dispatchEvent(new Event('submit',{bubbles:true,cancelable:true})));await flush();}
const createAck={status:201,data:{success:true,user:{id:31,username:'new-instructor',email:'new@example.test',
 full_name:null,admin_level:1,role:'admin',is_active:1},permissions:['challenge_management','view_analytics','manage_progress']}};

beforeEach(()=>{
 global.IS_REACT_ACT_ENVIRONMENT=true;
 mockUser={id:1,username:'admin-a',isAdmin:true,adminLevel:2,permissions:['user_management']};
 mockAuthRevision=0;localStorage.setItem('token','admin-a');
 axios.get.mockImplementation(url=>url.startsWith('/api/admin/users?')
  ? Promise.resolve({data:{success:true,users:[]}})
  : Promise.resolve({data:{success:true,challenges:[]}}));
 axios.post.mockResolvedValue(createAck);
 jest.spyOn(console,'error').mockImplementation(()=>{});
 jest.spyOn(console,'warn').mockImplementation(()=>{});
 jest.spyOn(console,'log').mockImplementation(()=>{});
});
afterEach(()=>{if(root){act(()=>root.unmount());root=null;}document.body.replaceChildren();localStorage.clear();
 jest.restoreAllMocks();jest.clearAllMocks();});

test('Create form staged by A cannot POST passwords under B',async()=>{
 await stage();await fill();const retained=handler(form(),'onSubmit');
 mockUser={...mockUser,id:2,username:'admin-b'};mockAuthRevision+=1;localStorage.setItem('token','admin-b');
 await act(async()=>root.render(<MemoryRouter initialEntries={['/admin/settings']}><ComprehensiveAdminDashboard /></MemoryRouter>));await flush();
 await act(async()=>retained({preventDefault(){}}));
 expect(axios.post).not.toHaveBeenCalled();
});
test('retained Create submit cannot POST after unmount',async()=>{
 await stage();await fill();const retained=handler(form(),'onSubmit');
 await act(async()=>root.unmount());root=null;
 await act(async()=>retained({preventDefault(){}}));
 expect(axios.post).not.toHaveBeenCalled();
});
test('actual 201 acknowledgement closes Create and refreshes the roster',async()=>{
 await stage();await fill();
 await change('#new-admin-username','  new-instructor  ');
 await change('#new-admin-email','  new@example.test  ');
 toast.success.mockClear();axios.get.mockClear();
 await submit();
 expect(form()).toBeFalsy();
 expect(toast.success).toHaveBeenCalledWith('Administrator created successfully');
 expect(axios.post).toHaveBeenCalledTimes(1);
 expect(axios.post.mock.calls[0][1]).toEqual(expect.objectContaining({
   username:'  new-instructor  ',email:'  new@example.test  ',
 }));
 expect(axios.get.mock.calls.some(([url])=>url.startsWith('/api/admin/users?'))).toBe(true);
 await click('Add administrator');
 expect(form().querySelector('#new-admin-password').value).toBe('');
});
test('409 duplicate username is not proof a Create request committed and never retries',async()=>{
 axios.post.mockRejectedValueOnce({response:{status:409}});
 await stage();await fill();toast.success.mockClear();await submit();
 expect(form().textContent).toContain('The creation outcome could not be confirmed.');
 expect(form().querySelector('#new-admin-password').value).toBe('');
 expect(toast.success).not.toHaveBeenCalled();
 expect(axios.post).toHaveBeenCalledTimes(1);
});
test('pending Create retired by storage change clears passwords and suppresses late ACK',async()=>{
 const request=deferred();axios.post.mockReturnValue(request.promise);
 await stage();await fill();await submit();
 await act(async()=>window.dispatchEvent(new StorageEvent('storage',{
   key:'token',oldValue:'admin-a',newValue:'admin-b',storageArea:localStorage,
 })));
 expect(form()).toBeFalsy();toast.success.mockClear();
 await act(async()=>request.resolve(createAck));await flush();
 expect(toast.success).not.toHaveBeenCalled();
 await click('Add administrator');
 expect(form().querySelector('#new-admin-password').value).toBe('');
 expect(axios.post).toHaveBeenCalledTimes(1);
});
test('storage token ABA retires Create stage and clears sensitive draft',async()=>{
 await stage();await fill();const retained=handler(form(),'onSubmit');
 await act(async()=>window.dispatchEvent(new StorageEvent('storage',{
   key:'token',oldValue:'admin-a',newValue:'admin-b',storageArea:localStorage,
 })));
 expect(form()).toBeFalsy();
 await act(async()=>retained({preventDefault(){}}));
 expect(axios.post).not.toHaveBeenCalled();
 await click('Add administrator');
 expect(form().querySelector('#new-admin-password').value).toBe('');
});
test('same-render double Create submits only one POST',async()=>{
 const request=deferred();axios.post.mockReturnValue(request.promise);
 await stage();await fill();const retained=handler(form(),'onSubmit');
 act(()=>{void retained({preventDefault(){}});void retained({preventDefault(){}});});
 expect(axios.post).toHaveBeenCalledTimes(1);
 await act(async()=>request.resolve(createAck));await flush();
});
test('cancel and restage clear password and ignore old password/grant callbacks',async()=>{
 await stage();await fill();
 const oldPassword=handler(form().querySelector('#new-admin-password'),'onChange');
 const oldGrant=handler(form().querySelector('input[value="system_config"]'),'onChange');
 await click('Cancel administrator creation');await click('Add administrator');
 expect(form().querySelector('#new-admin-password').value).toBe('');
 await act(async()=>{oldPassword({target:{value:'old-secret-password'}});oldGrant({target:{checked:true}});});
 expect(form().querySelector('#new-admin-password').value).toBe('');
 expect(form().querySelector('input[value="system_config"]').checked).toBe(false);
});
test('lost Create acknowledgement stays unknown, clears passwords, and never retries',async()=>{
 axios.post.mockRejectedValueOnce(new Error('connection lost'));
 await stage();await fill();toast.success.mockClear();await submit();
 expect(form().textContent).toContain('The creation outcome could not be confirmed.');
 expect(form().textContent).toContain('No account ID was acknowledged.');
 expect(form().querySelector('#new-admin-password').value).toBe('');
 expect(form().querySelector('#new-admin-confirm-password').value).toBe('');
 expect(toast.success).not.toHaveBeenCalled();expect(axios.post).toHaveBeenCalledTimes(1);
 await click('Close');expect(form()).toBeFalsy();expect(axios.post).toHaveBeenCalledTimes(1);
});
test.each([
 ['wrong grants',{...createAck,data:{...createAck.data,permissions:['view_analytics']}}],
 ['no created ID',{...createAck,data:{...createAck.data,user:{...createAck.data.user,id:null}}}],
 ['coercible nonnumeric ID',{...createAck,data:{...createAck.data,user:{...createAck.data.user,id:true}}}],
 ['non-201 status',{...createAck,status:200}],
])('malformed Create ACK with %s cannot claim creation',async(_label,response)=>{
 axios.post.mockResolvedValueOnce(response);
 await stage();await fill();toast.success.mockClear();await submit();
 expect(toast.success).not.toHaveBeenCalled();
 expect(form().textContent).toContain('The creation outcome could not be confirmed.');
 expect(form().querySelector('#new-admin-password').value).toBe('');
});
test('late A Create acknowledgement cannot toast or show success under B',async()=>{
 const request=deferred();axios.post.mockReturnValue(request.promise);
 await stage();await fill();await submit();
 mockUser={...mockUser,id:2,username:'admin-b'};mockAuthRevision+=1;localStorage.setItem('token','admin-b');
 await act(async()=>root.render(<MemoryRouter initialEntries={['/admin/settings']}><ComprehensiveAdminDashboard /></MemoryRouter>));await flush();
 expect(form()).toBeFalsy();toast.success.mockClear();
 await act(async()=>request.resolve(createAck));await flush();
 expect(toast.success).not.toHaveBeenCalled();expect(axios.post).toHaveBeenCalledTimes(1);
});
test('outer modal close clears sensitive Create draft',async()=>{
 await stage();await fill();
 await act(async()=>node.querySelector('button[aria-label="Close user management"]').click());
 await click('Manage Users');await click('Add administrator');
 expect(form().querySelector('#new-admin-password').value).toBe('');
 expect(form().querySelector('#new-admin-confirm-password').value).toBe('');
});
test('old A password handler cannot alter B Create draft after authority replacement',async()=>{
 await stage();const oldPassword=handler(form().querySelector('#new-admin-password'),'onChange');
 mockUser={...mockUser,id:2,username:'admin-b'};mockAuthRevision+=1;localStorage.setItem('token','admin-b');
 await act(async()=>root.render(<MemoryRouter initialEntries={['/admin/settings']}><ComprehensiveAdminDashboard /></MemoryRouter>));await flush();
 await click('Add administrator');
 await act(async()=>oldPassword({target:{value:'old-a-secret'}}));
 expect(form().querySelector('#new-admin-password').value).toBe('');
});
test('pending Create blocks retained Edit and Deactivate controls',async()=>{
 const account={id:17,username:'instructor',email:'instructor@example.test',full_name:'Instructor',
  admin_level:1,is_active:1,permissions:['challenge_management']};
 axios.get.mockImplementation(url=>url.startsWith('/api/admin/users?')
  ? Promise.resolve({data:{success:true,users:[account]}})
  : Promise.resolve({data:{success:true}}));
 const request=deferred();axios.post.mockReturnValue(request.promise);
 await mount();await click('Manage Users');
 const edit=handler([...node.querySelectorAll('button')].find(button=>button.textContent.trim()==='Edit'),'onClick');
 const deactivate=handler([...node.querySelectorAll('button')].find(button=>button.textContent.trim()==='Deactivate'),'onClick');
 await click('Add administrator');await fill();
 const create=handler(form(),'onSubmit');
 act(()=>{void create({preventDefault(){}});edit();deactivate();});
 expect(form()).toBeTruthy();expect(axios.post).toHaveBeenCalledTimes(1);
 expect(axios.put).not.toHaveBeenCalled();expect(axios.delete).not.toHaveBeenCalled();
 await act(async()=>request.resolve(createAck));await flush();
});
