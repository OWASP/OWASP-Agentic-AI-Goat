import { toolExecutionsFromResponse, appendToolExecutions } from './ExcessiveAgencyBolaLab';
jest.mock('../../context/WorkshopConfigContext',()=>({useWorkshopConfig:()=>({snapshot:{exercises:{}},revision:'1'})}));
jest.mock('../../hooks/useChangePolling',()=>()=>{});jest.mock('../../hooks/useWorkshopHeartbeat',()=>()=>{});jest.mock('../../components/VulnerabilityTemplate',()=>({children})=>children);jest.mock('axios',()=>({get:jest.fn(),post:jest.fn()}));jest.mock('react-toastify',()=>({toast:{success:jest.fn(),error:jest.fn(),info:jest.fn()}}));
test('uses ordered array, assigns response-local ids once, and preserves failures',()=>{
 const multiple=[{id:'observation-1',sequence:1,tool:'listNotes',success:true},{id:'observation-2',sequence:2,tool:'deleteNote',success:false,result:{error:'Access denied'}}];expect(toolExecutionsFromResponse({toolExecutions:multiple,toolExecution:multiple[1]})).toBe(multiple);const once=appendToolExecutions([],multiple,17);expect(once.map(v=>v.id)).toEqual(['response-17:observation-1','response-17:observation-2']);expect(once[1].success).toBe(false);expect(appendToolExecutions(once,multiple,17)).toEqual(once);
});
test('empty new array is authoritative and legacy final execution remains compatible',()=>{
 const legacy={tool:'listNotes',args:{userId:'alice'},success:true};expect(toolExecutionsFromResponse({toolExecutions:[],toolExecution:legacy})).toEqual([]);expect(toolExecutionsFromResponse({toolExecution:legacy})).toEqual([legacy]);expect(toolExecutionsFromResponse({})).toEqual([]);expect(appendToolExecutions([{id:'prior'}],[],18)).toEqual([{id:'prior'}]);
});

test('mounted activity renders all observations and conversation reset clears them',async()=>{
 global.IS_REACT_ACT_ENVIRONMENT=true;
 const React=require('react');const {act}=React;const {createRoot}=require('react-dom/client');const axios=require('axios');const Page=require('./ExcessiveAgencyBolaLab').default;
 const multiple=[{id:'observation-1',sequence:1,tool:'listNotes',args:{userId:'bob'},success:true,result:{success:true}},{id:'observation-2',sequence:2,tool:'deleteNote',args:{noteId:'note-bob-1'},success:false,result:{success:false,error:'Access denied'}}];
 axios.get.mockResolvedValue({data:{mode:'vuln',objectives:{},progress:{objectives:{}},message:'Welcome'}});axios.post.mockImplementation(url=>{
  if(url.endsWith('/auth/login'))return Promise.resolve({data:{user:{username:'alice'},sessionToken:'owned'}});
  if(url.endsWith('/chat'))return Promise.resolve({data:{response:'done',toolExecutions:multiple,toolExecution:multiple[1],judgments:[],progress:{objectives:{}}}});
  if(url.endsWith('/conversation/reset'))return Promise.resolve({data:{success:true}});
  return Promise.resolve({data:{}});
 });
 const container=document.createElement('div');document.body.append(container);const root=createRoot(container);
 try{
  await act(async()=>root.render(<Page/>));await act(async()=>[...container.querySelectorAll('button')].find(button=>button.textContent.includes('Login as Alice')).click());
  const input=container.querySelector('textarea');await act(async()=>{const setter=Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype,'value').set;setter.call(input,'do both');input.dispatchEvent(new Event('input',{bubbles:true}));});await act(async()=>input.closest('form').requestSubmit());
  await act(async()=>[...container.querySelectorAll('*')].find(node=>node.textContent.trim().startsWith('Tool Activity')&&getComputedStyle(node).cursor==='pointer').click());
  expect([...container.querySelectorAll('.tool-name')].map(node=>node.textContent)).toEqual(['deleteNote()','listNotes()']);expect(container.textContent).toContain('Access denied');
  await act(async()=>[...container.querySelectorAll('button')].find(node=>node.textContent.trim()==='Reset conversation').click());await act(async()=>[...container.querySelectorAll('*')].find(node=>node.textContent.trim().startsWith('Tool Activity')&&getComputedStyle(node).cursor==='pointer').click());expect(container.textContent).toContain('No tool executions yet');
 }finally{act(()=>root.unmount());container.remove();}
});
