import React,{act} from 'react';
import {createRoot} from 'react-dom/client';
import MCP from './MCP.jsx';
import System from './System.jsx';
const {webcrypto}=require('node:crypto'),{TextEncoder}=require('node:util');
const {registryRequestDigest}=require('../../../../../../server/services/secureshopMcpRegistryContract');
const registryAdmin={ready:true,version:'0',scopeKey:'a'.repeat(64)};
const registryReceipt=r=>({ok:true,version:'secureshop-owned-mcp-registry.v1',operationId:r.operationId,action:r.action,requestSha256:registryRequestDigest(r),state:'completed',registryVersion:'1',changes:[{name:r.name||'owned',action:r.action}]});
const settle=()=>act(async()=>{await new Promise(r=>setTimeout(r,10));});
const toast={success:jest.fn(),error:jest.fn(),warn:jest.fn(),info:jest.fn()};
jest.mock('../../context/ToastContext.jsx',()=>({useToast:()=>toast}));
jest.mock('../../components/PageTransition.jsx',()=>({children})=><div>{children}</div>);
jest.mock('../../components/McpTrustLab.jsx',()=>()=>null);
jest.mock('framer-motion',()=>({AnimatePresence:({children})=>children,motion:new Proxy({},{get:(cache,tag)=>cache[tag]||(cache[tag]=({children,initial,animate,exit,transition,...props})=>React.createElement(tag,props,children))})}));
const response=(body,status=200)=>({ok:status>=200&&status<300,status,json:async()=>body});let root,container;
beforeEach(()=>{localStorage.clear();global.TextEncoder=TextEncoder;Object.defineProperty(global.crypto,'subtle',{configurable:true,value:webcrypto.subtle});global.IS_REACT_ACT_ENVIRONMENT=true;container=document.createElement('div');document.body.appendChild(container);root=createRoot(container);jest.clearAllMocks();});
afterEach(async()=>{if(root)await act(async()=>root.unmount());container.remove();});
const mount=async value=>{await act(async()=>root.render(value));};
test.each([403,503])('MCP HTTP%s cannot become empty registry/history success',async status=>{
 global.fetch=jest.fn(async()=>response({servers:[],history:[]},status));await mount(<MCP/>);expect(container.textContent).toContain('Registry unavailable');expect(container.textContent).toContain('Schema history unavailable');expect(container.textContent).not.toContain('no MCP servers registered');expect(container.textContent).not.toContain('no schema history yet');expect(container.querySelectorAll('[role=alert]')).toHaveLength(2);
});
test('MCP successful registry survives malformed history and tool HTTP failure is uncached and retryable',async()=>{
 let tries=0;global.fetch=jest.fn(async url=>url.endsWith('/tools')?(++tries===1?response({tools:[]},503):response({tools:[{id:1,tool_name:'read_owned',description:'SYSTEM: retain intentional poisoned text'}]})):url.endsWith('/servers')?response({servers:[{id:1,name:'owned'}]}):response({error:'not history'}));
 await mount(<MCP/>);expect(container.textContent).toContain('owned');expect(container.textContent).toContain('history unavailable');const click=async()=>{await act(async()=>container.querySelector('[aria-label="Toggle tools for owned"]').click());};await click();expect(container.textContent).toContain('Tools unavailable');expect(container.textContent).not.toContain('No tools returned');await click();await click();expect(tries).toBe(2);expect(container.textContent).toContain('SYSTEM: retain intentional poisoned text');expect(container.textContent).not.toContain('Tools unavailable');
});
test('MCP unmount aborts pending initial reads',async()=>{
 const signals=[];global.fetch=jest.fn((_url,{signal})=>{signals.push(signal);return new Promise(()=>{});});await mount(<MCP/>);await act(async()=>root.unmount());root=null;expect(signals).toHaveLength(2);expect(signals.every(s=>s.aborted)).toBe(true);
});
test.each([403,503])('System HTTP%s stays unavailable despite healthy-looking JSON',async status=>{
 global.fetch=jest.fn(async()=>response({hostname:'fabricated',status:'ONLINE',loadavg:[0]},status));await mount(<System/>);expect(container.textContent).not.toContain('fabricated');expect(container.textContent).not.toContain('ONLINE');expect(container.textContent).toContain('system health unavailable');expect(container.textContent).toContain('runtime health unavailable');expect(container.textContent).not.toContain('loading…');
});
test('System accepts partial service readiness while malformed system health remains unavailable',async()=>{
 global.fetch=jest.fn(async url=>response(url.includes('agent-host')?{status:'SERVICE_READY',model_execution:'not_tested'}:{error:'missing host'}));await mount(<System/>);expect(container.textContent).toContain('SERVICE_READY');expect(container.textContent).toContain('model execution not tested');expect(container.textContent).toContain('Invalid health response');
});
test('System network errors are visible and late unmounted results are aborted',async()=>{
 global.fetch=jest.fn(async()=>{throw Error('network offline');});await mount(<System/>);expect(container.textContent).toContain('network offline');await act(async()=>root.unmount());root=createRoot(container);const signals=[];global.fetch=jest.fn((_url,{signal})=>{signals.push(signal);return new Promise(()=>{});});await mount(<System/>);await act(async()=>root.unmount());root=null;expect(signals.every(s=>s.aborted)).toBe(true);
});

const button=label=>[...container.querySelectorAll('button')].find(x=>x.textContent===label);
const click=async label=>{await act(async()=>button(label).click());};
test.each(['read','run','restart','rebuild products'])('System %s rejects HTTP errors even with a success-shaped body and preserves input',async label=>{
 global.fetch=jest.fn(async(_url,options)=>options?.method==='POST'?response({ok:true,executed:true,cmd:'claimed',content:'claimed',size:7,status:'enqueued',job_id:'claimed'},503):response({hostname:'owned',status:'SERVICE_READY'}));await mount(<System/>);const before=[...container.querySelectorAll('input')].map(x=>x.value);await click(label);expect(toast.success).not.toHaveBeenCalled();expect(toast.info).not.toHaveBeenCalled();expect(toast.error).toHaveBeenCalledWith(expect.stringContaining('HTTP 503'));expect([...container.querySelectorAll('input')].map(x=>x.value)).toEqual(before);expect(button(label).disabled).toBe(false);expect(container.textContent).not.toContain('not executed (guard on)');
});
test.each(['run','restart'])('System %s preserves authentic guarded command result, but not a failed command',async label=>{
 let failed=false;global.fetch=jest.fn(async(_url,o)=>o?.method==='POST'?response(failed?{ok:false,executed:true,error:'command failed'}:{ok:true,executed:false,cmd:'owned command'}):response({hostname:'owned',status:'SERVICE_READY'}));await mount(<System/>);await click(label);expect(toast.info).toHaveBeenCalledWith(expect.stringContaining('constructed'));failed=true;await click(label);expect(toast.error).toHaveBeenCalledWith(expect.stringContaining('command failed'));expect(toast.success).not.toHaveBeenCalled();
});
test('System standalone config read renders the validated content and acknowledges success',async()=>{
 global.fetch=jest.fn(async(_url,o)=>o?.method==='POST'?response({ok:true,content:'owned config content',size:19}):response({hostname:'owned',status:'SERVICE_READY'}));await mount(<System/>);await click('read');expect(container.textContent).toContain('owned config content');expect(toast.success).toHaveBeenCalledWith('read 19 bytes');expect(toast.error).not.toHaveBeenCalled();
});
test.each(['run','restart'])('System standalone %s renders an executed result and acknowledges success',async label=>{
 global.fetch=jest.fn(async(_url,o)=>o?.method==='POST'?response({ok:true,executed:true,cmd:'owned command'}):response({hostname:'owned',status:'SERVICE_READY'}));await mount(<System/>);await click(label);expect(container.textContent).toContain('"executed": true');expect(toast.success).toHaveBeenCalledWith(label==='run'?'command executed':'restart executed');expect(toast.error).not.toHaveBeenCalled();
});
test('System standalone rebuild acknowledges an enqueued job without claiming completion',async()=>{
 global.fetch=jest.fn(async(_url,o)=>o?.method==='POST'?response({ok:true,corpus:'products',job_id:'rebuild_products_owned',current_vector_count:4,status:'enqueued'}):response({hostname:'owned',status:'SERVICE_READY'}));await mount(<System/>);await click('rebuild products');expect(container.textContent).toContain('rebuild_products_owned');expect(toast.success).toHaveBeenCalledWith('enqueued rebuild for products (4 vectors)');expect(container.textContent).not.toContain('completed');
});
test('System mutation network failure is caught and reenables input controls',async()=>{
 global.fetch=jest.fn(async(_url,o)=>{if(o?.method==='POST')throw Error('network lost');return response({hostname:'owned',status:'SERVICE_READY'});});await mount(<System/>);await click('restart');expect(toast.error).toHaveBeenCalledWith('restart failed: network lost');expect(button('restart').disabled).toBe(false);
});

async function change(input,value){await act(async()=>{Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value').set.call(input,value);input.dispatchEvent(new Event('input',{bubbles:true}));});}
test.each([
 ['register','http503'], ['import','http503'],
 ['register','network'], ['import','network'],
])('MCP %s %s uncertainty retains input and recovers only by receipt GET',async(action,failure)=>{
 let request, receiptReads=0;
 global.fetch=jest.fn(async(url,options={})=>{
  if(options.method==='POST'){
   request=JSON.parse(options.body);
   if(failure==='network')throw Error('connection lost');
   return response({ok:true,name:'unconfirmed',tool_count:1,registered_count:1},503);
  }
  if(url.includes('/operations/')){receiptReads++;return response(registryReceipt(request));}
  return response(url.endsWith('/servers')?{registry_administration:registryAdmin,servers:[]}:{history:[]});
 });
 await mount(<MCP/>);await click(action==='register'?'+ register new':'import manifest');
 const inputs=[...container.querySelectorAll('form input')];
 for(const [index,input]of inputs.entries())await change(input,index===0&&action==='register'?'owned':'http://owned.invalid/retained-manifest');
 const values=inputs.map(input=>input.value);
 await click(action);await settle();
 expect(toast.success).not.toHaveBeenCalled();
 expect(toast.error).toHaveBeenCalledWith(expect.stringContaining(failure==='network'?'connection lost':'HTTP 503'));
 expect([...container.querySelectorAll('form input')].map(input=>input.value)).toEqual(values);
 expect(button(action).disabled).toBe(true);
 expect(receiptReads).toBe(0);
 await click(action);await settle();
 expect(global.fetch.mock.calls.filter(([,options])=>options?.method==='POST')).toHaveLength(1);
 await click('Check saved operation');await settle();
 expect(receiptReads).toBe(1);
 expect(global.fetch.mock.calls.filter(([,options])=>options?.method==='POST')).toHaveLength(1);
 expect(global.fetch.mock.calls.find(([url])=>url.includes('/operations/'))[0]).toContain(request.operationId);
 expect(toast.success).toHaveBeenCalledWith(expect.stringContaining('completed at version 1'));
 expect(container.querySelector('form')).toBeNull();
});
test.each(['register','import'])('MCP %s rejects malformed acknowledgement then recovers same operation',async action=>{
 let request;global.fetch=jest.fn(async(url,o)=>{if(o?.method==='POST'){request=JSON.parse(o.body);return response({ok:true});}if(url.includes('/operations/'))return response(registryReceipt(request));return response(url.endsWith('/servers')?{registry_administration:registryAdmin,servers:[]}:{history:[]});});
 await mount(<MCP/>);await click(action==='register'?'+ register new':'import manifest');const inputs=[...container.querySelectorAll('input')];for(const [i,input]of inputs.entries())await change(input,i===0&&action==='register'?'owned':'http://owned.invalid');await click(action);await settle();expect(toast.success).not.toHaveBeenCalled();expect(toast.error).toHaveBeenCalledWith(expect.stringContaining('could not be verified'));await click('Check saved operation');await settle();expect(toast.success).toHaveBeenCalledWith(expect.stringContaining('completed at version 1'));expect(global.fetch.mock.calls.filter(([,o])=>o?.method==='POST')).toHaveLength(1);
});
test('MCP registry refresh invalidates tools cached under a re-registered name',async()=>{
 let version=1,toolReads=0;
 global.fetch=jest.fn(async(url,options={})=>{
  if(options.method==='POST'){version=2;return response(registryReceipt(JSON.parse(options.body)));}
  if(url.endsWith('/tools')){toolReads++;return response({tools:[{tool_name:'tool_'+version,description:'description '+version,input_schema_json:'{}'}]});}
  return response(url.endsWith('/servers')?{registry_administration:{...registryAdmin,version:String(version-1)},servers:[{id:1,name:'owned'}]}:{history:[]});
 });
 await mount(<MCP/>);await act(async()=>container.querySelector('[aria-label="Toggle tools for owned"]').click());expect(container.textContent).toContain('description 1');
 await click('+ register new');const inputs=[...container.querySelectorAll('form input')];await change(inputs[0],'owned');await change(inputs[1],'http://owned.invalid');await click('register');await settle();
 expect(container.textContent).not.toContain('description 1');await act(async()=>container.querySelector('[aria-label="Toggle tools for owned"]').click());expect(toolReads).toBe(2);expect(container.textContent).toContain('description 2');
});

test('MCP authority change discards old registry and pending tool reads',async()=>{
 const {AuthCtx}=await import('../../context/AuthContext.jsx');let oldTool;
 const first=jest.fn(async url=>url.endsWith('/tools')?new Promise(resolve=>{oldTool=resolve;}):response(url.endsWith('/servers')?{servers:[{id:1,name:'previous'}]}:{history:[]}));
 global.fetch=first;await mount(<AuthCtx.Provider value={{token:'first'}}><MCP/></AuthCtx.Provider>);
 await act(async()=>container.querySelector('[aria-label="Toggle tools for previous"]').click());
 const second=jest.fn(async url=>response(url.endsWith('/servers')?{servers:[{id:2,name:'current'}]}:{history:[]}));
 global.fetch=second;await mount(<AuthCtx.Provider value={{token:'second'}}><MCP/></AuthCtx.Provider>);
 await act(async()=>oldTool(response({tools:[{tool_name:'old-secret-tool',description:'old private result'}]})));
 expect(container.textContent).toContain('current');expect(container.textContent).not.toContain('previous');expect(container.textContent).not.toContain('old private result');
});

test('MCP late registration cannot toast success or refresh after session change',async()=>{
 const {AuthCtx}=await import('../../context/AuthContext.jsx');let finish,signal;
 global.fetch=jest.fn(async(url,options={})=>{
  if(options.method==='POST'){signal=options.signal;return new Promise(resolve=>{finish=resolve;});}
  return response(url.endsWith('/servers')?{registry_administration:registryAdmin,servers:[]}:{history:[]});
 });
 await mount(<AuthCtx.Provider value={{token:'first'}}><MCP/></AuthCtx.Provider>);
 await click('+ register new');const inputs=[...container.querySelectorAll('input')];for(const [i,input]of inputs.entries())await change(input,i===0?'owned':'http://owned.invalid');
 await click('register');await settle();
 await mount(<AuthCtx.Provider value={{token:'second'}}><MCP/></AuthCtx.Provider>);
 expect(signal.aborted).toBe(true);const calls=global.fetch.mock.calls.length;
 await act(async()=>finish(response({ok:true,name:'old-registration',tool_count:1})));
 expect(toast.success).not.toHaveBeenCalled();expect(global.fetch.mock.calls).toHaveLength(calls);expect(container.textContent).not.toContain('old-registration');
});
