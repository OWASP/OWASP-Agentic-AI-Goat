import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import axios from 'axios';
import { AuthProvider, useAuth } from './AuthContext';
jest.mock('axios', () => ({ get: jest.fn(), post: jest.fn(), defaults: { headers: { common: {} } }, interceptors: { response: { use: jest.fn(), eject: jest.fn() } } }));
let current, root, container;
function Probe() { current = useAuth(); return null; }
beforeEach(() => { global.IS_REACT_ACT_ENVIRONMENT = true; localStorage.setItem('token', 'retained-session'); container = document.createElement('div'); root = createRoot(container); axios.get.mockReset(); axios.post.mockReset(); });
afterEach(async () => { await act(async () => root.unmount()); localStorage.clear(); });
test('service outage preserves token and exposes retry instead of declaring unauthenticated', async () => {
  axios.get.mockRejectedValueOnce({ response: { status: 502 } });
  await act(async () => root.render(<AuthProvider><Probe /></AuthProvider>));
  expect(current.user).toBe(null);
  expect(current.authError).toMatch(/retry/);
  expect(localStorage.getItem('token')).toBe('retained-session');
  axios.get.mockResolvedValueOnce({ data: { authenticated: true, user: { id: 42 } } });
  await act(async () => current.checkAuthStatus());
  expect(current.authError).toBe(null);
  expect(current.user.id).toBe(42);
});
test('authoritative status rejection clears even an unexpired token', async () => {
  const token = 'a.' + btoa(JSON.stringify({ exp: Math.floor(Date.now()/1000)+3600 })) + '.c';
  localStorage.setItem('token', token);
  axios.get.mockRejectedValueOnce({ response: { status: 401 } });
  await act(async () => root.render(<AuthProvider><Probe /></AuthProvider>));
  expect(localStorage.getItem('token')).toBe(null);
  expect(current.authError).toBe(null);
  expect(current.loading).toBe(false);
});

function deferred() { let resolve, reject; const promise = new Promise((a,b) => { resolve=a; reject=b; }); return { promise, resolve, reject }; }
test('late status response cannot restore a logged-out user', async () => {
  const pending = deferred(); axios.get.mockReturnValueOnce(pending.promise);
  await act(async () => root.render(<AuthProvider><Probe /></AuthProvider>));
  axios.post.mockResolvedValueOnce({});
  await act(async () => current.logout());
  await act(async () => pending.resolve({ data: { authenticated: true, user: { id: 42 } } }));
  expect(current.user).toBe(null); expect(localStorage.getItem('token')).toBe(null);
  expect(axios.post).toHaveBeenCalledWith('/api/auth/logout', null, expect.objectContaining({ headers: { Authorization: 'Bearer retained-session' } }));
});
test('late rejected status cannot erase a new login', async () => {
  const pending = deferred(); axios.get.mockReturnValueOnce(pending.promise);
  await act(async () => root.render(<AuthProvider><Probe /></AuthProvider>));
  axios.post.mockResolvedValueOnce({ data: { token: 'new-session', user: { id: 77 } } });
  await act(async () => current.login('user', 'password'));
  await act(async () => pending.reject({ response: { status: 401 } }));
  expect(current.user.id).toBe(77); expect(localStorage.getItem('token')).toBe('new-session');
});
test('late logout completion cannot erase a subsequent login', async () => {
  axios.get.mockResolvedValueOnce({ data: { authenticated: true, user: { id: 42 } } });
  await act(async () => root.render(<AuthProvider><Probe /></AuthProvider>));
  const pending = deferred(); axios.post.mockReturnValueOnce(pending.promise);
  let logout; await act(async () => { logout = current.logout(); });
  axios.post.mockResolvedValueOnce({ data: { token: 'next-session', user: { id: 77 } } });
  await act(async () => current.login('user', 'password'));
  await act(async () => { pending.resolve({}); await logout; });
  expect(current.user.id).toBe(77); expect(localStorage.getItem('token')).toBe('next-session');
});

test('logout in another tab retires the displayed user immediately', async () => {
  axios.get.mockResolvedValueOnce({ data: { authenticated: true, user: { id: 42 } } });
  await act(async () => root.render(<AuthProvider><Probe /></AuthProvider>));
  await act(async () => { localStorage.removeItem('token'); window.dispatchEvent(new StorageEvent('storage', { key: 'token', storageArea: localStorage })); });
  expect(current.user).toBe(null); expect(current.loading).toBe(false);
  expect(axios.defaults.headers.common.Authorization).toBeUndefined();
});
test('replacement session in another tab hides prior user until revalidated', async () => {
  axios.get.mockResolvedValueOnce({ data: { authenticated: true, user: { id: 42 } } });
  await act(async () => root.render(<AuthProvider><Probe /></AuthProvider>));
  const pending=deferred(); axios.get.mockReturnValueOnce(pending.promise);
  await act(async () => { localStorage.setItem('token', 'replacement-session'); window.dispatchEvent(new StorageEvent('storage', { key: 'token', storageArea: localStorage })); });
  expect(current.user).toBe(null); expect(current.loading).toBe(true);
  expect(axios.defaults.headers.common.Authorization).toBe('Bearer replacement-session');
  await act(async () => pending.resolve({ data: { authenticated: true, user: { id: 77 } } }));
  expect(current.user.id).toBe(77); expect(current.loading).toBe(false);
});

const adminMatrix=[['student',1,false],['student',2,false],['admin',0,false],['admin',1,true],['super_admin',0,false],['super_admin',2,true]];
test.each(adminMatrix)('status/login presentation follows role AND level for %s/%s',async(role,adminLevel,expected)=>{
 const raw={id:42,role,adminLevel,isAdmin:!expected,workshop_admin:1};
 axios.get.mockResolvedValueOnce({data:{authenticated:true,user:raw}});
 await act(async()=>root.render(<AuthProvider><Probe/></AuthProvider>));
 expect(current.user.isAdmin).toBe(expected);expect(current.user.isWorkshopAdmin).toBe(expected);
 axios.post.mockResolvedValueOnce({data:{token:'next-session',user:raw}});let result;
 await act(async()=>{result=await current.login('synthetic','controlled');});
 expect(result.user.isAdmin).toBe(expected);expect(current.user.isAdmin).toBe(expected);
 expect(current.user.adminLevel).toBe(adminLevel);expect(current.user.role).toBe(role);
 await act(async()=>current.updateUser({role:'student',isAdmin:true,isWorkshopAdmin:true}));
 expect(current.user.isAdmin).toBe(false);expect(current.user.isWorkshopAdmin).toBe(false);
});
