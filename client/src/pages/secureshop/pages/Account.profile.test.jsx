import React, { act, useState } from 'react';
import { createRoot } from 'react-dom/client';
import { MemoryRouter } from 'react-router-dom';
import { AuthProvider, useAuth } from '../context/AuthContext';
import Account from './Account';
import Checkout from './Checkout';
const toast={success:jest.fn(),error:jest.fn()};
let savedToken='one',auth;
jest.mock('../utils/shopStorage.mjs',()=>({shopStorage:{getItem:()=>savedToken,setItem:(_k,v)=>{savedToken=v;},removeItem:()=>{savedToken=null;}},flushShopStorage:async()=>{},disconnectShopStorage:()=>{}}));
jest.mock('../../../utils/secureShopFetch.mjs',()=>({createSecureShopFetch:({fetchImpl})=>fetchImpl}));
jest.mock('../context/ToastContext.jsx',()=>({useToast:()=>toast}));
jest.mock('../context/CartContext.jsx',()=>({useCart:()=>({items:[{id:1,name:'Item',quantity:1,price:1}],subtotal:1,total:1,discount:0,clear:jest.fn(),reload:jest.fn()})}));
jest.mock('../bridge/fetchAdapter.mjs',()=>({getBridgeFetchMetadata:()=>null}));
jest.mock('../components/UploadZone.jsx',()=>()=>null);
jest.mock('../components/Input.jsx',()=>({label,helper,...props})=><input aria-label={label} {...props}/>);
jest.mock('framer-motion',()=>({motion:new Proxy({},{get:(_,tag)=>({children,initial,animate,exit,transition,layout,...props})=>React.createElement(tag,props,children)}),AnimatePresence:({children})=>children,useReducedMotion:()=>true}));
let root,node,fetchMock;const initial={id:7,username:'merchant',role:'merchant',full_name:'Old Name',email:'old@example.test',phone:'111'};
const response=x=>({ok:true,json:async()=>x});
function Screen(){auth=useAuth();const [checkout,setCheckout]=useState(false);return <><button onClick={()=>setCheckout(true)}>Go checkout</button><output>{auth.user?.full_name}</output>{checkout?<Checkout/>:<Account/>}</>;}
beforeEach(async()=>{global.IS_REACT_ACT_ENVIRONMENT=true;savedToken='one';jest.clearAllMocks();fetchMock=jest.fn(async()=>response({user:initial}));global.fetch=fetchMock;node=document.createElement('div');document.body.append(node);root=createRoot(node);await act(async()=>root.render(<MemoryRouter><AuthProvider><Screen/></AuthProvider></MemoryRouter>));});
afterEach(async()=>{await act(async()=>root.unmount());node.remove();});
function click(text){return act(async()=>[...node.querySelectorAll('button')].find(x=>x.textContent.includes(text)).click());}
test('saved canonical profile survives tab remount and pre-fills real Checkout',async()=>{const updated={...initial,full_name:'Saved Name',email:'saved@example.test',phone:'222'};fetchMock.mockResolvedValueOnce(response({ok:true,user:updated}));await act(async()=>node.querySelector('form').dispatchEvent(new Event('submit',{bubbles:true,cancelable:true})));expect(toast.success).toHaveBeenCalledWith('Profile saved');await click('Security');await click('Profile');expect(node.querySelector('[aria-label="Full name"]').value).toBe('Saved Name');expect(node.querySelector('[aria-label="Email"]').value).toBe('saved@example.test');await click('Go checkout');expect(node.querySelector('[aria-label="Full name"]').value).toBe('Saved Name');expect(node.querySelector('output').textContent).toBe('Saved Name');});
test('late old-persona save cannot replace newer identity or publish success',async()=>{let resolve;fetchMock.mockImplementationOnce(()=>new Promise(r=>{resolve=r;}));await act(async()=>node.querySelector('form').dispatchEvent(new Event('submit',{bubbles:true,cancelable:true})));const other={...initial,id:8,full_name:'Other Persona'};fetchMock.mockResolvedValueOnce(response({token:'two',user:other})).mockResolvedValue(response({user:other}));await act(async()=>auth.login('other','password'));await act(async()=>resolve(response({ok:true,user:{...initial,full_name:'Stale'}})));expect(auth.user.id).toBe(8);expect(auth.user.full_name).toBe('Other Persona');expect(toast.success).not.toHaveBeenCalled();expect(toast.error).not.toHaveBeenCalled();});
test('wrong-owner response is rejected without changing profile or authority',async()=>{fetchMock.mockResolvedValueOnce(response({ok:true,user:{...initial,id:99,role:'admin',full_name:'Foreign'}}));await act(async()=>node.querySelector('form').dispatchEvent(new Event('submit',{bubbles:true,cancelable:true})));expect(auth.user).toEqual(initial);expect(toast.error).toHaveBeenCalledWith('Save failed: Invalid profile response');expect(toast.success).not.toHaveBeenCalled();});

test('customer Account mounts trusted profile review instead of legacy PUT form', async () => {
  const customer = { ...initial, role: 'customer', username: 'customer' };
  fetchMock.mockImplementation(async url => {
    if (url.endsWith('/login')) return response({ token: 'customer-token', user: customer });
    if (url.endsWith('/profile-form')) return response({ version: 1,
      fields: { fullName: customer.full_name, email: customer.email, phone: customer.phone },
      expectedSnapshotSha256: 'a'.repeat(64), scopeKey: 'b'.repeat(64) });
    return response({ user: customer });
  });
  await act(async () => { await auth.login('customer', 'password'); });
  expect(node.querySelector('[aria-label="Profile update review"]')).not.toBeNull();
  expect(node.textContent).toContain('Review profile');
  expect(node.textContent).not.toContain('Save changes');
  expect(fetchMock.mock.calls.filter(([url, options]) => url.endsWith('/users/me')
    && options?.method === 'PUT')).toHaveLength(0);
});

test('protected profile refresh publishes only current-owner display fields', async () => {
  const updated = { ...initial, full_name: 'Receipt-backed Name' };
  fetchMock.mockResolvedValueOnce(response({ ok: true, user: updated }));
  await act(async () => { await auth.refreshProfile(); });
  expect(auth.user).toEqual(updated);
  expect(node.querySelector('output').textContent).toBe('Receipt-backed Name');
  expect(fetchMock).toHaveBeenCalledWith('/api/secureshop/v2/auth/users/me',
    expect.objectContaining({ method: 'GET' }));
  fetchMock.mockResolvedValueOnce(response({ ok: true, user: { ...updated, id: 99, role: 'admin' } }));
  await act(async () => { await expect(auth.refreshProfile()).rejects.toThrow('Current profile is unavailable'); });
  expect(auth.user).toEqual(updated);
});
