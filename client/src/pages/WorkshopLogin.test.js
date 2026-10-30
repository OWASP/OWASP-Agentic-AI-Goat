/* eslint-disable testing-library/no-unnecessary-act */
import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import WorkshopLogin from './WorkshopLogin';
import { toast } from 'react-toastify';
const mockNavigate=jest.fn();
const mockLogin=jest.fn(async()=>({success:false})),mockRegister=jest.fn(async()=>({success:false}));
jest.mock('react-router-dom',()=>({useNavigate:()=>mockNavigate,useLocation:()=>({}),Link:({children})=><span>{children}</span>}));
jest.mock('../context/AuthContext',()=>({useAuth:()=>({login:mockLogin,register:mockRegister})}));
jest.mock('axios',()=>({get:()=>new Promise(()=>{})}));
jest.mock('react-toastify',()=>({toast:{success:jest.fn(),error:jest.fn()}}));
const props=node=>node[Object.keys(node).find(key=>key.startsWith('__reactProps$'))];
// Directly batch real rendered callbacks; this controls a schedule, not browser provenance.
test.each([['login',false],['login',true],['register',false],['register',true]])('%s batched fields preserve values through submit (reverse=%s)',async(mode,reverse)=>{
 global.IS_REACT_ACT_ENVIRONMENT=true;mockLogin.mockClear();mockRegister.mockClear();
 const host=document.createElement('div');document.body.append(host);const root=createRoot(host);
 try{
  await act(async()=>root.render(<WorkshopLogin/>));
  if(mode==='register')await act(async()=>props([...host.querySelectorAll('button')].find(x=>x.textContent==='Register')).onClick());
  const values=mode==='login'?['owned-student','synthetic-password']:['owned-student','owned@example.test','synthetic-password','synthetic-password'];
  const inputs=[...host.querySelectorAll('form input')];const updates=inputs.map((node,i)=>({node,value:values[i],change:props(node).onChange}));
  await act(async()=>{for(const x of reverse?[...updates].reverse():updates)x.change({target:{value:x.value}});});
  for(const x of updates)expect(x.node.value).toBe(x.value);
  await act(async()=>props(host.querySelector('form')).onSubmit({preventDefault(){}}));
  if(mode==='login')expect(mockLogin).toHaveBeenCalledWith(...values);
  else expect(mockRegister).toHaveBeenCalledWith({username:values[0],email:values[1],password:values[2]});
 }finally{await act(async()=>root.unmount());host.remove();}
});

const authorityCases=[['student',1,'/workshop/challenges'],['student',2,'/workshop/challenges'],['admin',0,'/workshop/challenges'],['admin',1,'/admin/dashboard'],['super_admin',0,'/workshop/challenges'],['super_admin',2,'/admin/dashboard']];
test.each(authorityCases)('login redirect %s/%s preserves canonical destination',async(role,adminLevel,destination)=>{
 global.IS_REACT_ACT_ENVIRONMENT=true;mockNavigate.mockClear();mockLogin.mockResolvedValueOnce({success:true,user:{id:7,role,adminLevel,isAdmin:true}});
 const host=document.createElement('div');document.body.append(host);const root=createRoot(host);
 try{await act(async()=>root.render(<WorkshopLogin/>));const inputs=[...host.querySelectorAll('form input')];await act(async()=>{props(inputs[0]).onChange({target:{value:'synthetic'}});props(inputs[1]).onChange({target:{value:'controlled'}});});await act(async()=>props(host.querySelector('form')).onSubmit({preventDefault(){}}));if(destination==='/workshop/challenges')expect(mockNavigate).toHaveBeenCalledWith(destination,{replace:true});else expect(mockNavigate).toHaveBeenCalledWith(destination);}finally{await act(async()=>root.unmount());host.remove();}
});


test.each([['student', 0], ['admin', 2]])('OWASP AI SecureShop login keeps the app destination for %s', async (role, adminLevel) => {
 global.IS_REACT_ACT_ENVIRONMENT=true;
 mockNavigate.mockClear();
 mockLogin.mockResolvedValueOnce({success:true,user:{id:7,role,adminLevel}});
 const host=document.createElement('div');document.body.append(host);const root=createRoot(host);
 try {
  await act(async()=>root.render(<WorkshopLogin application="secureshop"/>));
  expect(host.textContent).toContain('OWASP AI SecureShop Access');
  expect(host.textContent).toContain('Shop practice accounts are used inside the shop.');
  expect(host.querySelector('button[type="submit"]').textContent).toBe('Enter OWASP AI SecureShop');
  const inputs=[...host.querySelectorAll('form input')];
  await act(async()=>{props(inputs[0]).onChange({target:{value:'synthetic'}});props(inputs[1]).onChange({target:{value:'controlled'}});});
  await act(async()=>props(host.querySelector('form')).onSubmit({preventDefault(){}}));
  expect(mockLogin).toHaveBeenCalledWith('synthetic','controlled');
  expect(mockNavigate).toHaveBeenCalledWith('/secureshop',{replace:true});
 } finally {await act(async()=>root.unmount());host.remove();}
});


test('failed OWASP AI SecureShop sign-in keeps the user at login and reports the server error', async () => {
 global.IS_REACT_ACT_ENVIRONMENT=true;
 mockNavigate.mockClear();mockLogin.mockResolvedValueOnce({success:false,error:'Invalid credentials'});
 const host=document.createElement('div');document.body.append(host);const root=createRoot(host);
 try {
  await act(async()=>root.render(<WorkshopLogin application="secureshop"/>));
  await act(async()=>props(host.querySelector('form')).onSubmit({preventDefault(){}}));
  expect(mockNavigate).not.toHaveBeenCalled();
  expect(toast.error).toHaveBeenCalledWith('Invalid credentials');
  expect(host.querySelector('button[type="submit"]').disabled).toBe(false);
 } finally {await act(async()=>root.unmount());host.remove();}
});
