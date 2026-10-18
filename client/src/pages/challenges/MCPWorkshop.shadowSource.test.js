import React,{act} from 'react';
import {createRoot} from 'react-dom/client';
import axios from 'axios';
import {ShadowSourceEditor} from './MCPWorkshop';
jest.mock('axios',()=>({get:jest.fn(),post:jest.fn()}));
let node,root;const sha='a'.repeat(64);const flush=async()=>{await act(async()=>{await Promise.resolve();});};
const button=text=>[...node.querySelectorAll('button')].find(x=>x.textContent===text);
const click=async text=>{await act(async()=>button(text).click());};
const render=async props=>{await act(async()=>root.render(<ShadowSourceEditor ownerId={7} {...props}/>));};
beforeEach(()=>{global.IS_REACT_ACT_ENVIRONMENT=true;localStorage.setItem('token','owned-token');sessionStorage.clear();axios.post.mockReset();node=document.createElement('div');document.body.appendChild(node);root=createRoot(node);});
afterEach(async()=>{await act(async()=>root.unmount());node.remove();localStorage.clear();sessionStorage.clear();});
test('exact BOM text is retained for retry after lost response and reread cannot reselect an older replay',async()=>{
 const text='\ufeffActual synthetic mirror';let writes=0;axios.post.mockImplementation(async url=>{if(url.endsWith('/read'))return{data:{text:writes>1?'Newer source':text,sha256:sha}};writes++;if(writes===1)throw Error('lost reply');return{data:{success:true}};});
 await render();await click('Load mirror policy');await click('Save mirror policy');const first=axios.post.mock.calls.find(c=>c[0].endsWith('/write'))[1];expect(first.text).toBe(text);expect(node.querySelector('textarea').disabled).toBe(true);
 await act(async()=>root.unmount());root=createRoot(node);await render();await click('Retry policy save');
 const requests=axios.post.mock.calls.filter(c=>c[0].endsWith('/write'));expect(requests[1][1]).toEqual(first);expect(node.querySelector('textarea').value).toBe('Newer source');expect(sessionStorage.getItem('dvaia:mcp-shadow-source:7')).toBeNull();
});
test('failed authoritative refresh retains operation ID even after successful mutation',async()=>{
 let reads=0;axios.post.mockImplementation(async url=>{if(url.endsWith('/read')){if(++reads===2)throw Error('unavailable');return{data:{text:'Policy',sha256:sha}};}return{data:{success:true}};});
 await render();await click('Load mirror policy');await click('Save mirror policy');await click('Retry policy save');const writes=axios.post.mock.calls.filter(c=>c[0].endsWith('/write'));expect(writes[1][1]).toEqual(writes[0][1]);
});
test('owner and token changes fence stale source responses and successful reset clears pending operation',async()=>{
 let resolve;axios.post.mockImplementation(()=>new Promise(r=>{resolve=r;}));await render();await click('Load mirror policy');localStorage.setItem('token','new-token');await render({ownerId:8});await act(async()=>resolve({data:{text:'Stale owner source',sha256:sha}}));expect(node.textContent).not.toContain('Mirror policy loaded');expect(node.querySelector('textarea').value).toBe('');
 sessionStorage.setItem('dvaia:mcp-shadow-source:8',JSON.stringify({operationId:'11111111-1111-4111-8111-111111111111',expectedSha256:sha,text:'pending'}));await render({ownerId:8,resetting:true});await render({ownerId:8,resetVersion:1});expect(sessionStorage.getItem('dvaia:mcp-shadow-source:8')).toBeNull();expect(node.querySelector('textarea').value).toBe('');
});
test('reset and unmount abort pending read without restoring obsolete source',async()=>{
 let resolve;axios.post.mockImplementation(()=>new Promise(r=>{resolve=r;}));await render();await click('Load mirror policy');const signal=axios.post.mock.calls[0][2].signal;await render({resetting:true});expect(signal.aborted).toBe(true);await act(async()=>resolve({data:{text:'obsolete',sha256:sha}}));expect(node.querySelector('textarea').value).toBe('');await flush();
});
test('terminal CAS conflict permits loading current policy without workshop reset',async()=>{
 axios.post.mockImplementation(async url=>{if(url.endsWith('/read'))return{data:{text:'Current policy',sha256:sha}};throw{response:{status:409,data:{error:'SHADOW_SOURCE_CONFLICT'}}};});
 await render();await click('Load mirror policy');await click('Save mirror policy');expect(button('Load mirror policy').disabled).toBe(false);expect(sessionStorage.getItem('dvaia:mcp-shadow-source:7')).toBeNull();expect(node.textContent).toContain('nothing was written');await click('Load mirror policy');expect(node.querySelector('textarea').disabled).toBe(false);
});
test('actor change deletes prior private pending payload and blocked storage does not crash reset',async()=>{
 sessionStorage.setItem('dvaia:mcp-shadow-source:7',JSON.stringify({operationId:'11111111-1111-4111-8111-111111111111',expectedSha256:sha,text:'private pending'}));await render();await render({ownerId:8});expect(sessionStorage.getItem('dvaia:mcp-shadow-source:7')).toBeNull();
 const remove=jest.spyOn(Storage.prototype,'removeItem').mockImplementation(()=>{throw Error('blocked');});try{await render({ownerId:8,resetVersion:1});expect(node.textContent).toContain('Load your isolated mirror policy');}finally{remove.mockRestore();}
});
test('actions remain disabled until the current owner hydration effect commits',async()=>{
 const observed=[];
 function BeforePassiveEffects({ownerId}) {
  React.useLayoutEffect(()=>{const load=button('Load mirror policy');observed.push(load.disabled);load.click();},[ownerId]);
  return <ShadowSourceEditor ownerId={ownerId}/>;
 }
 await act(async()=>root.render(<BeforePassiveEffects ownerId={7}/>));
 expect(observed).toEqual([true]);expect(axios.post).not.toHaveBeenCalled();expect(button('Load mirror policy').disabled).toBe(false);
 await act(async()=>root.render(<BeforePassiveEffects ownerId={8}/>));
 expect(observed).toEqual([true,true]);expect(axios.post).not.toHaveBeenCalled();expect(button('Load mirror policy').disabled).toBe(false);
});
