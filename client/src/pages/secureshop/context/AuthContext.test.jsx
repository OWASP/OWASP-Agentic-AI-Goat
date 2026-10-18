import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import { AuthProvider, useAuth } from './AuthContext';
import { shopStorage, flushShopStorage, disconnectShopStorage } from '../utils/shopStorage.mjs';

jest.mock('../utils/shopStorage.mjs',()=>({shopStorage:{getItem:jest.fn(),setItem:jest.fn(),removeItem:jest.fn()},flushShopStorage:jest.fn(),disconnectShopStorage:jest.fn()}));
jest.mock('../../../utils/secureShopFetch.mjs',()=>({createSecureShopFetch:({fetchImpl})=>fetchImpl}));
const user={id:7,username:'student_customer',role:'customer'};
function deferred(){let resolve,reject;const promise=new Promise((a,b)=>{resolve=a;reject=b;});return {promise,resolve,reject};}
let root,container,auth;
const previousActEnvironment=global.IS_REACT_ACT_ENVIRONMENT;
beforeAll(()=>{global.IS_REACT_ACT_ENVIRONMENT=true;});
afterAll(()=>{global.IS_REACT_ACT_ENVIRONMENT=previousActEnvironment;});
function Probe(){auth=useAuth();return <span>{auth.isAuthed?'signed-in':'signed-out'}</span>;}
beforeEach(async()=>{
 jest.resetAllMocks();shopStorage.getItem.mockReturnValue(null);flushShopStorage.mockResolvedValue();
 global.fetch=jest.fn(async()=>({ok:true,json:async()=>({token:'learner-shop-token',user})}));
 container=document.createElement('div');document.body.append(container);root=createRoot(container);
 await act(async()=>root.render(<AuthProvider><Probe/></AuthProvider>));
});
afterEach(async()=>{await act(async()=>root.unmount());container.remove();});

for(const action of ['login','register'])test(`${action} waits for storage acknowledgement before publishing identity or resolving`,async()=>{
 const saved=deferred();flushShopStorage.mockReturnValueOnce(saved.promise);let pending,settled=false;
 await act(async()=>{pending=action==='login'?auth.login('student','password'):auth.register({username:'student',password:'password'});pending.then(()=>{settled=true;});});
 expect(flushShopStorage).toHaveBeenCalledTimes(1);expect(settled).toBe(false);expect(auth.isAuthed).toBe(false);
 await act(async()=>{saved.resolve();await pending;});expect(settled).toBe(true);expect(auth.isAuthed).toBe(true);
});

for(const action of ['logout','switchRole'])test(`${action} waits for acknowledged token removal`,async()=>{
 await act(async()=>auth.login('student','password'));
 const saved=deferred();flushShopStorage.mockReturnValueOnce(saved.promise);let pending,settled=false;
 await act(async()=>{pending=action==='logout'?auth.logout():auth.switchRole('merchant');pending.then(()=>{settled=true;});});
 expect(shopStorage.removeItem).toHaveBeenCalledWith('secureshop_v2_token');expect(settled).toBe(false);expect(auth.isAuthed).toBe(true);
 await act(async()=>{saved.resolve();await pending;});expect(settled).toBe(true);expect(auth.isAuthed).toBe(false);
});

for(const action of ['login','register','logout','switchRole'])test(`${action} fails closed when state acknowledgement fails`,async()=>{
 if(['logout','switchRole'].includes(action))await act(async()=>auth.login('student','password'));
 flushShopStorage.mockRejectedValueOnce(new Error('private storage details'));
 await act(async()=>{
  const pending=action==='login'?auth.login('student','password'):action==='register'?auth.register({username:'student'}):action==='logout'?auth.logout():auth.switchRole('merchant');
  await expect(pending).rejects.toThrow('Shop session could not be saved');
 });
 expect(disconnectShopStorage).toHaveBeenCalled();expect(auth.isAuthed).toBe(false);expect(auth.error).not.toContain('private storage');expect(auth.error).toContain('Reload');
});

test('a logout queued during login persistence runs after it and remains the final identity',async()=>{
 const saved=deferred();flushShopStorage.mockReturnValueOnce(saved.promise);let login,logout;
 await act(async()=>{login=auth.login('student','password');});
 await act(async()=>{logout=auth.logout();});
 expect(shopStorage.removeItem).not.toHaveBeenCalled();
 await act(async()=>{saved.resolve();await Promise.all([login,logout]);});
 expect(auth.isAuthed).toBe(false);expect(shopStorage.removeItem).toHaveBeenCalledTimes(1);
});

test('an old whoami failure cannot erase a token being acknowledged by a newer login',async()=>{
 await act(async()=>root.unmount());
 shopStorage.getItem.mockReturnValue('old-token');const old=deferred();
 global.fetch=jest.fn().mockReturnValueOnce(old.promise).mockResolvedValue({ok:true,json:async()=>({token:'new-token',user})});
 root=createRoot(container);await act(async()=>root.render(<AuthProvider><Probe/></AuthProvider>));
 const saved=deferred();flushShopStorage.mockReturnValueOnce(saved.promise);let login;
 await act(async()=>{login=auth.login('student','password');});
 await act(async()=>{old.resolve({ok:false,status:401,json:async()=>({})});});
 expect(shopStorage.removeItem).not.toHaveBeenCalled();
 await act(async()=>{saved.resolve();await login;});expect(auth.token).toBe('new-token');expect(auth.isAuthed).toBe(true);
});

test('a failed save disconnects the actual storage binding so the fetch decorator cannot reuse its JWT',async()=>{
 const real=jest.requireActual('../utils/shopStorage.mjs');let value=null,closed=false;
 const release=real.attachShopStorage({getItem:()=>value,setItem:(key,next)=>{value=next;},removeItem:()=>{value=null;},flush:async()=>{throw Error('quota');},close:()=>{closed=true;}});
 shopStorage.setItem.mockImplementation(real.shopStorage.setItem);shopStorage.removeItem.mockImplementation(real.shopStorage.removeItem);
 flushShopStorage.mockImplementation(real.flushShopStorage);disconnectShopStorage.mockImplementation(real.disconnectShopStorage);
 try {
  await act(async()=>{await expect(auth.login('student','password')).rejects.toThrow('could not be saved');});
  expect(value).toBe('learner-shop-token');expect(closed).toBe(true);
  expect(()=>real.shopStorage.getItem('secureshop_v2_token')).toThrow('disconnected');expect(auth.isAuthed).toBe(false);
 }finally{release();}
});

test('temporary whoami failure preserves the stored token instead of silently deleting it',async()=>{
 await act(async()=>root.unmount());shopStorage.getItem.mockReturnValue('existing-token');
 global.fetch=jest.fn(async()=>({ok:false,status:503,json:async()=>({})}));
 root=createRoot(container);await act(async()=>root.render(<AuthProvider><Probe/></AuthProvider>));
 expect(shopStorage.removeItem).not.toHaveBeenCalled();expect(auth.token).toBe('existing-token');expect(auth.loading).toBe(false);expect(auth.error).toContain('Unable to verify');
});

test('transient whoami 503 after accepted login retains its acknowledged shop identity',async()=>{
 let stored=null;
 shopStorage.getItem.mockImplementation(()=>stored);
 shopStorage.setItem.mockImplementation((_key,value)=>{stored=value;});
 global.fetch=jest.fn(url=>url.endsWith('/login')
  ? Promise.resolve({ok:true,json:async()=>({token:'accepted-token',user})})
  : Promise.resolve({ok:false,status:503,json:async()=>({error:'not ready'})}));
 await act(async()=>{await auth.login('student_customer','student123');});
 await act(async()=>{await Promise.resolve();await Promise.resolve();});
 expect(auth.token).toBe('accepted-token');
 expect(auth.isAuthed).toBe(true);
 expect(auth.error).toContain('Unable to verify');
 expect(shopStorage.removeItem).not.toHaveBeenCalled();
});

test('invalid-token hydration acknowledges removal before publishing signed-out state',async()=>{
 await act(async()=>root.unmount());shopStorage.getItem.mockReturnValue('invalid-token');const saved=deferred();flushShopStorage.mockReturnValueOnce(saved.promise);
 global.fetch=jest.fn(async()=>({ok:false,status:401,json:async()=>({})}));
 root=createRoot(container);await act(async()=>root.render(<AuthProvider><Probe/></AuthProvider>));
 expect(auth.token).toBe('invalid-token');expect(shopStorage.removeItem).toHaveBeenCalled();
 await act(async()=>saved.resolve());expect(auth.token).toBe(null);expect(auth.loading).toBe(false);
});

test('nested auth decoration restores the exact preceding fetch function for frame teardown',async()=>{
 const preceding=window.fetch;const child=document.createElement('div');const nested=createRoot(child);
 await act(async()=>nested.render(<AuthProvider><span/></AuthProvider>));expect(window.fetch).not.toBe(preceding);
 await act(async()=>nested.unmount());expect(window.fetch).toBe(preceding);
});

test('acknowledged bridge fetch retains its identity through provider mount and teardown',async()=>{
 const {createBridgeFetch,getBridgeFetchMetadata}=await import('../bridge/fetchAdapter.mjs');
 const original=window.fetch;
 const bridgeFetch=createBridgeFetch({bridge:{request:jest.fn(async()=>new Response('{}'))},origin:window.location.origin,boundReviews:true});
 window.fetch=bridgeFetch;
 const child=document.createElement('div');const nested=createRoot(child);
 try {
  await act(async()=>nested.render(<AuthProvider><span/></AuthProvider>));
  expect(window.fetch).toBe(bridgeFetch);
  expect(getBridgeFetchMetadata(window.fetch).boundReviews).toBe(true);
  await act(async()=>nested.unmount());
  expect(window.fetch).toBe(bridgeFetch);
 } finally {window.fetch=original;}
});

test('persona renewal is single-scope, and logout aborts a late refresh before it can republish identity',async()=>{
 jest.useFakeTimers();jest.setSystemTime(new Date('2026-09-13T20:00:00.000Z'));
 let stored=null;shopStorage.getItem.mockImplementation(()=>stored);
 shopStorage.setItem.mockImplementation((_key,value)=>{stored=value;});
 shopStorage.removeItem.mockImplementation(()=>{stored=null;});
 const pending=deferred();let renewalSignal;
 global.fetch=jest.fn((url,init={})=>{
  if(url.endsWith('/login'))return Promise.resolve({ok:true,json:async()=>({token:'persona-one',user,
   expiresAt:'2026-09-13T20:30:00.000Z'})});
  if(url.endsWith('/renew')){renewalSignal=init.signal;return pending.promise;}
  if(url.endsWith('/logout'))return Promise.resolve({ok:true,json:async()=>({ok:true})});
  return Promise.resolve({ok:true,json:async()=>({user,expiresAt:'2026-09-13T20:30:00.000Z'})});
 });
 try{
  await act(async()=>auth.login('student','password'));
  await act(async()=>{jest.advanceTimersByTime(25*60*1000);await Promise.resolve();});
  expect(global.fetch).toHaveBeenCalledWith(expect.stringMatching(/\/renew$/),expect.objectContaining({method:'PATCH',
   headers:{Authorization:'Bearer persona-one'}}));
  let logout;await act(async()=>{logout=auth.logout();await Promise.resolve();});
  expect(renewalSignal.aborted).toBe(true);
  await act(async()=>{pending.resolve({ok:true,json:async()=>({token:'late-persona',user,
   expiresAt:'2026-09-13T21:00:00.000Z'})});await logout;});
  expect(stored).toBe(null);expect(auth.isAuthed).toBe(false);
  expect(shopStorage.setItem).not.toHaveBeenCalledWith('secureshop_v2_token','late-persona');
 }finally{jest.useRealTimers();}
});
