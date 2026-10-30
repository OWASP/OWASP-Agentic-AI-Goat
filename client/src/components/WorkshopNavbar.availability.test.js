import React, {act} from 'react';
import {createRoot} from 'react-dom/client';
import {MemoryRouter} from 'react-router-dom';
import axios from 'axios';
import WorkshopNavbar from './WorkshopNavbar';

jest.mock('axios',()=>({get:jest.fn()}));
let mockUser={id:7,username:'student',role:'student'};
jest.mock('../context/AuthContext',()=>({useAuth:()=>({user:mockUser,logout:jest.fn()})}));
const flush=async()=>act(async()=>{await Promise.resolve();await Promise.resolve();});

test('visible locked exercises remain discoverable without a navigable route, including refresh',async()=>{
 global.IS_REACT_ACT_ENVIRONMENT=true;
 jest.useFakeTimers();
 const locked={id:'locked_exercise',title:'Locked Exercise',route:'/workshop/locked',status:'locked'};
 const app={id:'secureshop_agent_security',title:'OWASP AI SecureShop Agent Security',route:'/workshop/secureshop',status:'unlocked'};
 const open={id:'legacy_sensitive_file_ssi',title:'File and SSI Security',route:'/workshop/file-ssi',status:'unlocked'};
 const ctf={id:'ctf_prompt_injection_challenge',title:'Separate CTF',route:'/ctf',status:'unlocked'};
 axios.get.mockImplementation(url=>Promise.resolve({data:url==='/api/workshop/challenges'?{challenges:[locked,open,ctf,app]}:{config:{ctf_enabled:'false'}}}));
 const node=document.createElement('div');document.body.appendChild(node);const root=createRoot(node);
 try{await act(async()=>root.render(<MemoryRouter initialEntries={['/workshop/challenges']}><WorkshopNavbar/></MemoryRouter>));await flush();
  const toggle=[...node.querySelectorAll('button')].find(button=>button.textContent.includes('Exercises'));
  expect(toggle.textContent).toContain('(2)');await act(async()=>toggle.click());
  const unavailable=node.querySelector('button[title="Locked Exercise: no enabled objectives"]');
  expect(unavailable).toBeTruthy();expect(unavailable.disabled).toBe(true);expect(unavailable.textContent).toContain('Locked');
  expect(node.querySelector('a[href="/workshop/secureshop"]')).toBeNull();expect(node.textContent).not.toContain('OWASP AI SecureShop Agent Security');expect(node.querySelector('a[href="/secureshop"]')).not.toBeNull();
  expect(node.querySelector('a[href="/workshop/file-ssi"]')).toBeTruthy();expect(node.textContent).not.toContain('Separate CTF');
  await act(async()=>jest.advanceTimersByTime(60000));await flush();
  expect(node.querySelector('button[title="Locked Exercise: no enabled objectives"]').disabled).toBe(true);
  expect(node.querySelector('a[href="/workshop/file-ssi"]')).toBeTruthy();
 }finally{act(()=>root.unmount());node.remove();jest.useRealTimers();jest.clearAllMocks();}
});

async function renderNavigation(path='/workshop/challenges') {
 global.IS_REACT_ACT_ENVIRONMENT=true;
 const node=document.createElement('div');document.body.appendChild(node);const root=createRoot(node);
 await act(async()=>root.render(<MemoryRouter initialEntries={[path]}><WorkshopNavbar/></MemoryRouter>));await flush();
 return{node,async close(){await act(async()=>root.unmount());node.remove();}};
}

test('canonical dashboard is the only active top-level link and Exercises keeps distinct quick links',async()=>{
 mockUser={id:7,username:'student',role:'student'};
 axios.get.mockImplementation(url=>Promise.resolve({data:url==='/api/workshop/challenges'?{challenges:[{id:'file_ssi',title:'File and SSI Security',route:'/workshop/file-ssi',status:'unlocked'}]}:{config:{ctf_enabled:'false'}}}));
 const h=await renderNavigation();
 try{
  const dashboard=[...h.node.querySelectorAll('a')].find(a=>a.textContent.includes('Student Dashboard'));
  expect(dashboard.getAttribute('href')).toBe('/workshop/challenges');expect(dashboard.getAttribute('aria-current')).toBe('page');
  expect([...h.node.querySelectorAll('a.active')].map(a=>a.textContent.trim())).toEqual(['Student Dashboard']);
  const logo=[...h.node.querySelectorAll('a')].find(a=>a.textContent.includes('OWASP Agentic AI GOAT'));expect(logo.getAttribute('href')).toBe('/workshop/challenges');
  const exercises=h.node.querySelector('button[aria-label="Exercises menu"]');expect(exercises.textContent).toContain('Exercises (1)');expect(exercises.getAttribute('aria-expanded')).toBe('false');await act(async()=>exercises.click());expect(exercises.getAttribute('aria-expanded')).toBe('true');
  expect(h.node.querySelector('a[href="/workshop/file-ssi"]')).not.toBeNull();expect(h.node.textContent).not.toContain('Exercise Library');expect(h.node.querySelector('a[href="/workshop-dashboard"]')).toBeNull();
 }finally{await h.close();}
});

test('empty exercise list keeps a menu without a duplicate dashboard navigation link',async()=>{
 mockUser={id:7,username:'student',role:'student'};axios.get.mockResolvedValue({data:{challenges:[],config:{ctf_enabled:'false'}}});const h=await renderNavigation();
 try{expect(h.node.querySelector('button[aria-label="Exercises menu"]').textContent).toContain('Exercises (0)');expect(h.node.querySelectorAll('a.active')).toHaveLength(1);expect(h.node.textContent).not.toContain('Exercise Library');}finally{await h.close();}
});

test('guest home and canonical admin return authority remain unchanged',async()=>{
 mockUser=null;const guest=await renderNavigation('/');try{expect([...guest.node.querySelectorAll('a')].find(a=>a.textContent.includes('OWASP Agentic AI GOAT')).getAttribute('href')).toBe('/');expect(guest.node.textContent).toContain('Workshop Home');expect(guest.node.textContent).not.toContain('Student Dashboard');}finally{await guest.close();}
 sessionStorage.setItem('adminReturnPath','/admin/dashboard');axios.get.mockResolvedValue({data:{challenges:[],config:{ctf_enabled:'false'}}});
 for(const [user,allowed] of [[{role:'student',adminLevel:2},false],[{role:'admin',adminLevel:0},false],[{role:'admin',adminLevel:2},true]]){mockUser={id:7,username:'controlled',...user};const h=await renderNavigation('/workshop/file-ssi');try{expect(h.node.textContent.includes('Back to Admin')).toBe(allowed);expect(h.node.querySelectorAll('a.active')).toHaveLength(0);}finally{await h.close();}}
 sessionStorage.removeItem('adminReturnPath');mockUser={id:7,username:'student',role:'student'};
});
