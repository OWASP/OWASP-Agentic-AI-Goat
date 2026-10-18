import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import App from './App';

let mockUser;

jest.mock('./pages/secureshop/SecureShopApp',()=>({__esModule:true,default:()=>null}));
jest.mock('./context/AuthContext', () => ({
  AuthProvider: ({ children }) => children,
  useAuth: () => ({ user: mockUser, loading: false }),
}));
jest.mock('./context/WorkshopConfigContext', () => ({ WorkshopConfigProvider: ({ children }) => children }));
jest.mock('./components/ErrorBoundary', () => ({ __esModule: true, default: ({ children }) => children }));
jest.mock('./components/VisibilityProtectedRoute', () => ({ __esModule: true, default: ({ children }) => children }));
jest.mock('./components/WorkshopNavbar', () => ({ __esModule: true, default: () => null }));
jest.mock('./pages/LandingPage', () => ({ __esModule: true, default: () => <div>Workshop landing</div> }));
jest.mock('./pages/WorkshopLogin', () => ({ __esModule: true, default: () => <div>Controlled login view</div> }));
jest.mock('./pages/WorkshopSignup', () => ({ __esModule: true, default: () => null }));
jest.mock('react-toastify', () => ({ ToastContainer: () => null }));


jest.mock('./pages/ComprehensiveAdminDashboard',()=>({__esModule:true,default:()=> <div>Controlled admin view</div>}));
jest.mock('./pages/WorkshopChallenges',()=>({__esModule:true,default:()=> <div>Controlled learner view</div>}));
const matrix=[['student',0,false],['student',1,false],['student',2,false],['admin',0,false],['admin',1,true],['admin',2,true],['super_admin',0,false],['super_admin',1,true],['super_admin',2,true]];
test.each(matrix)('actual platform route gate %s/%s does not trust contradictory flags',async(role,adminLevel,allowed)=>{
 global.IS_REACT_ACT_ENVIRONMENT=true;mockUser={id:7,role,adminLevel,isAdmin:!allowed};window.history.replaceState({},'', '/admin');
 const host=document.createElement('div');document.body.append(host);const root=createRoot(host);
 try{await act(async()=>{root.render(<App/>);await Promise.resolve();});expect(window.location.pathname).toBe(allowed?'/admin/dashboard':'/workshop/challenges');expect(host.textContent).toContain(allowed?'Controlled admin view':'Controlled learner view');}finally{await act(async()=>root.unmount());host.remove();}
});

const learnerDestinations=['/','/workshop-dashboard','/workshop/progress'];
test.each(learnerDestinations)('signed-in route %s replaces history with the canonical student library',async destination=>{
 global.IS_REACT_ACT_ENVIRONMENT=true;mockUser={id:7,role:'student',adminLevel:0};window.history.replaceState({},'',destination);
 const replace=jest.spyOn(window.history,'replaceState'),push=jest.spyOn(window.history,'pushState');
 const host=document.createElement('div');document.body.append(host);const root=createRoot(host);
 try{await act(async()=>{root.render(<App/>);await Promise.resolve();});
  expect(window.location.pathname).toBe('/workshop/challenges');expect(host.textContent).toContain('Controlled learner view');
  expect(replace.mock.calls.some(args=>args[2]==='/workshop/challenges')).toBe(true);expect(push).not.toHaveBeenCalled();
 }finally{await act(async()=>root.unmount());host.remove();replace.mockRestore();push.mockRestore();}
});
test.each(['/workshop-dashboard','/workshop/progress','/workshop/challenges'])('unauthenticated route %s stays behind the student login guard',async destination=>{
 global.IS_REACT_ACT_ENVIRONMENT=true;mockUser=null;window.history.replaceState({},'',destination);
 const host=document.createElement('div');document.body.append(host);const root=createRoot(host);
 try{await act(async()=>{root.render(<App/>);await Promise.resolve();});expect(window.location.pathname).toBe('/workshop/login');expect(host.textContent).toContain('Controlled login view');expect(host.textContent).not.toContain('Controlled learner view');}
 finally{await act(async()=>root.unmount());host.remove();}
});
test('unauthenticated root retains its public landing page',async()=>{
 global.IS_REACT_ACT_ENVIRONMENT=true;mockUser=null;window.history.replaceState({},'','/');
 const host=document.createElement('div');document.body.append(host);const root=createRoot(host);
 try{await act(async()=>{root.render(<App/>);await Promise.resolve();});expect(window.location.pathname).toBe('/');expect(host.textContent).toContain('Workshop landing');}
 finally{await act(async()=>root.unmount());host.remove();}
});
