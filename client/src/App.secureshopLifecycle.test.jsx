import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import App from './App';
import axios from 'axios';
let mockUser=null;
let mockSuspendStandalone = false;
const mockPendingStandalone = new Promise(() => {});
jest.mock('axios',()=>({get:jest.fn(),post:jest.fn()}));

const mockLifecycle = { mounts: 0, unmounts: 0 };
let platformMounts = 0;

jest.mock('./pages/secureshop/SecureShopApp', () => {
  const ReactModule = require('react');
  function SecureShopProbe() {
    ReactModule.useEffect(() => {
      mockLifecycle.mounts += 1;
      return () => { mockLifecycle.unmounts += 1; };
    }, []);
    return ReactModule.createElement('div', { 'data-testid': 'secure-shop-probe' });
  }
  return { __esModule: true, default: SecureShopProbe };
});
jest.mock('./pages/secureshop/SecureShopWorkshop', () => ({ __esModule: true,
  default: () => <div data-testid="bound-shop-workshop">Bound workshop</div> }));
jest.mock('./pages/secureshop/SecureShopStandalone', () => ({ __esModule: true,
  default: () => {
    if (mockSuspendStandalone) throw mockPendingStandalone;
    return <div data-testid="standalone-shop">SecureShop</div>;
  } }));

jest.mock('./context/AuthContext', () => ({
  AuthProvider: ({ children }) => { platformMounts += 1; return children; },
  useAuth: () => ({ user: mockUser, loading: false }),
}));
jest.mock('./context/WorkshopConfigContext', () => ({ WorkshopConfigProvider: ({ children }) => children }));
jest.mock('./components/ErrorBoundary', () => ({ __esModule: true, default: ({ children }) => children }));
jest.mock('./components/VisibilityProtectedRoute', () => ({ __esModule: true, default: ({ children }) => children }));
jest.mock('./components/WorkshopNavbar', () => ({ __esModule: true, default: () => null }));
jest.mock('./pages/LandingPage', () => ({ __esModule: true, default: () => <div>Workshop landing</div> }));
jest.mock('./pages/secureshop/SecureShopAccess', () => ({ __esModule: true, default: () => <div data-testid="login-entry">secureshop</div> }));
jest.mock('./pages/secureshop/SecureShopGuestLanding', () => ({ __esModule: true, default: () => <div data-testid="shop-public-landing">Storefront</div> }));
jest.mock('./pages/WorkshopLogin', () => ({ __esModule: true, default: ({ application }) => <div data-testid="login-entry">{application || 'workshop'}</div> }));
jest.mock('./pages/WorkshopSignup', () => ({ __esModule: true, default: () => null }));
jest.mock('react-toastify', () => ({ ToastContainer: () => null }));

async function navigate(path) {
  await act(async () => {
    window.history.pushState({}, '', path);
    window.dispatchEvent(new PopStateEvent('popstate'));
    await Promise.resolve();
  });
}

test('SecureShop routes stay outside platform auth and historical workshop links redirect to the app', async () => {
  global.IS_REACT_ACT_ENVIRONMENT = true;
  mockLifecycle.mounts = 0;
  mockLifecycle.unmounts = 0;
  platformMounts = 0;
  mockUser = { id: 7, username: 'Learner' };
  window.history.replaceState({}, '', '/secureshop/catalog');
  const container = document.createElement('div');
  const root = createRoot(container);

  await act(async () => { root.render(<App />); });
  expect(container.querySelector('[data-testid="standalone-shop"]')).not.toBeNull();
  expect(platformMounts).toBe(0);
  expect(mockLifecycle).toEqual({ mounts: 0, unmounts: 0 });

  await navigate('/secureshop/cart');
  expect(container.querySelector('[data-testid="standalone-shop"]')).not.toBeNull();
  await navigate('/secureshop/v2/catalog');
  expect(container.querySelector('[data-testid="standalone-shop"]')).not.toBeNull();
  expect(mockLifecycle).toEqual({ mounts: 0, unmounts: 0 });
  await navigate('/workshop/secureshop');
  expect(window.location.pathname).toBe('/secureshop');
  expect(container.querySelector('[data-testid="standalone-shop"]')).not.toBeNull();

  await act(async () => root.unmount());
  mockUser = null;
});


test('real App CTF navigation does not remount and resubmit a pending challenge start',async()=>{
 global.IS_REACT_ACT_ENVIRONMENT=true;Element.prototype.scrollIntoView=jest.fn();mockUser={id:7,username:'Learner'};localStorage.setItem('token','owner');
 const stage={id:1,stage_number:1,stage_order:1,stage_name:'Single start',stage_description:'Owned stage',difficulty:'easy',ai_guardian_name:'Guardian'};
 axios.get.mockImplementation(url=>Promise.resolve({data:url.endsWith('/config')?{config:{ctf_hint_gating_attempts:'4'}}:url.endsWith('/stages')?{stages:[stage]}:{registered:true,participant:{id:7},progress:[],leaderboardEntry:{}}}));
 let finish;axios.post.mockImplementation(()=>new Promise(resolve=>{finish=resolve;}));
 window.history.replaceState({},'','/ctf');const host=document.createElement('div');document.body.append(host);const root=createRoot(host);
 const flush=()=>act(async()=>{await Promise.resolve();await Promise.resolve();});
 try{
  await act(async()=>root.render(<App/>));await flush();
  const card=[...host.querySelectorAll('h3')].find(e=>e.textContent==='Single start').closest('[role="button"]');await act(async()=>card.dispatchEvent(new MouseEvent('click',{bubbles:true})));await flush();
  expect(window.location.pathname).toBe('/ctf/challenge');expect(axios.post).toHaveBeenCalledTimes(1);const signal=axios.post.mock.calls[0][2].signal;expect(signal.aborted).toBe(false);
  await act(async()=>root.render(<App/>));await flush();expect(axios.post).toHaveBeenCalledTimes(1);expect(signal.aborted).toBe(false);
  await act(async()=>finish({status:200,data:{stage,hintsAvailable:false,attemptsSoFar:3}}));await flush();expect(host.textContent).toContain('Hints unlock after 4 attempts.');
  const back=[...host.querySelectorAll('button')].find(e=>e.textContent.trim()==='Back to Dashboard');await act(async()=>back.dispatchEvent(new MouseEvent('click',{bubbles:true})));await flush();expect(window.location.pathname).toBe('/ctf');expect(axios.post).toHaveBeenCalledTimes(1);
 }finally{await act(async()=>root.unmount());host.remove();localStorage.clear();mockUser=null;}
});


test.each(['/secureshop/catalog', '/secureshop/product/1'])('%s enters standalone SecureShop without workshop identity', async (path) => {
  global.IS_REACT_ACT_ENVIRONMENT = true;
  mockUser = null;
  window.history.replaceState({}, '', path);
  const host = document.createElement('div');
  const root = createRoot(host);
  try {
    await act(async () => root.render(<App />));
    expect(window.location.pathname).toBe(path);
    expect(host.querySelector('[data-testid="standalone-shop"]')).not.toBeNull();
    expect(host.querySelector('[data-testid="bound-shop-workshop"]')).toBeNull();
  } finally { await act(async () => root.unmount()); }
});

test('SecureShop lazy loading shows the shop spinner with accessible status', async () => {
  global.IS_REACT_ACT_ENVIRONMENT = true;
  mockSuspendStandalone = true;
  window.history.replaceState({}, '', '/secureshop/catalog');
  const host = document.createElement('div');
  const root = createRoot(host);
  try {
    await act(async () => root.render(<App />));
    const spinner = host.querySelector('.ss-spinner');
    expect(spinner).not.toBeNull();
    expect(spinner.getAttribute('aria-hidden')).toBe('true');
    expect(spinner.style.animation).toBe('spin 800ms linear infinite');
    expect(host.querySelector('p[role="status"]').textContent).toContain('Opening SecureShop');
    expect(host.textContent).not.toContain('Loading Workshop');
  } finally {
    await act(async () => root.unmount());
    mockSuspendStandalone = false;
  }
});

test('SecureShop sign-in does not use the workshop account even if one exists', async () => {
  global.IS_REACT_ACT_ENVIRONMENT = true;
  mockUser = { id: 7, username: 'Learner' };
  window.history.replaceState({}, '', '/secureshop/login');
  const host = document.createElement('div');
  const root = createRoot(host);
  try {
    await act(async () => root.render(<App />));
    expect(window.location.pathname).toBe('/secureshop/login');
    expect(host.querySelector('[data-testid="standalone-shop"]')).not.toBeNull();
  } finally { await act(async () => root.unmount()); mockUser = null; }
});

test.each([['login', ''], ['register', ''], ['login', '/'], ['register', '/']])('legacy v2 %s%s bookmark canonicalizes without platform auth', async (page, slash) => {
  global.IS_REACT_ACT_ENVIRONMENT = true;
  platformMounts = 0;
  window.history.replaceState({}, '', `/secureshop/v2/${page}${slash}?next=%2Fsecureshop%2Fcart`);
  const host = document.createElement('div');
  const root = createRoot(host);
  try {
    await act(async () => root.render(<App />));
    expect(window.location.pathname).toBe(`/secureshop/${page}`);
    expect(window.location.search).toBe('?next=%2Fsecureshop%2Fcart');
    expect(host.querySelector('[data-testid="standalone-shop"]')).not.toBeNull();
    expect(platformMounts).toBe(0);
  } finally { await act(async () => root.unmount()); }
});

 test.each(['/secureshop','/workshop/secureshop'])('guest %s sees the storefront rather than a workshop login', async path => {
 global.IS_REACT_ACT_ENVIRONMENT=true;mockUser=null;window.history.replaceState({},'',path);
 const host=document.createElement('div'),root=createRoot(host);
 try {await act(async()=>root.render(<App/>));expect(window.location.pathname).toBe('/secureshop');expect(host.querySelector('[data-testid="standalone-shop"]')).not.toBeNull();expect(host.querySelector('[data-testid="login-entry"]')).toBeNull();}
 finally {await act(async()=>root.unmount());}
 });
