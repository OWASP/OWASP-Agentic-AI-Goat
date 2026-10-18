import React,{act} from 'react';
import {createRoot} from 'react-dom/client';
import MCP from './MCP.jsx';
import {SHOP_MCP_REGISTRY_KEY} from '../../utils/shopStorage.mjs';
const {webcrypto}=require('node:crypto'),{TextEncoder}=require('node:util');
const {normalizeRegistryRequest,registryRequestDigest}=require('../../../../../../server/services/secureshopMcpRegistryContract');
const toast={success:jest.fn(),error:jest.fn(),info:jest.fn(),warn:jest.fn()};
jest.mock('../../context/ToastContext.jsx',()=>({useToast:()=>toast}));
jest.mock('../../components/PageTransition.jsx',()=>({children})=><div>{children}</div>);
jest.mock('../../components/McpTrustLab.jsx',()=>()=>null);
jest.mock('framer-motion',()=>({AnimatePresence:({children})=>children,motion:new Proxy({},{get:(_,tag)=>({children,initial,animate,exit,transition,whileHover,...props})=>React.createElement(tag,props,children)})}));
const response=(body,status=200)=>({ok:status>=200&&status<300,status,json:async()=>body});
let root,node,head,writes,readiness,writeBehavior,statusBehavior,servers;
const receipt=request=>({ok:true,version:'secureshop-owned-mcp-registry.v1',operationId:request.operationId,action:request.action,requestSha256:registryRequestDigest(request),state:'completed',registryVersion:String(BigInt(request.expectedVersion)+1n),changes:[{name:request.name||'imported',action:request.action}]});
const flush=()=>act(async()=>{await new Promise(r=>setTimeout(r,10));});
const button=text=>[...node.querySelectorAll('button')].find(v=>v.textContent===text);
async function click(text){await act(async()=>button(text).click());await flush();}
async function type(label,value){const el=[...node.querySelectorAll('label')].find(v=>v.textContent.trim().startsWith(label)).querySelector('input');await act(async()=>{Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value').set.call(el,value);el.dispatchEvent(new Event('input',{bubbles:true}));});}
beforeEach(()=>{localStorage.clear();jest.clearAllMocks();global.IS_REACT_ACT_ENVIRONMENT=true;global.TextEncoder=TextEncoder;Object.defineProperty(global.crypto,'subtle',{configurable:true,value:webcrypto.subtle});head='0';writes=[];readiness=true;servers=[];writeBehavior=null;statusBehavior=null;node=document.createElement('div');document.body.appendChild(node);root=createRoot(node);
 global.fetch=jest.fn(async(url,options)=>{
  if(options?.method==='POST'||options?.method==='DELETE'){const request=normalizeRegistryRequest(JSON.parse(options.body));writes.push(request);if(writeBehavior)return writeBehavior(request);head=String(BigInt(head)+1n);servers=request.action==='retire'?[]:[{id:1,name:request.name||'imported',transport:'sse'}];return response(receipt(request));}
  if(url.includes('/operations/'))return statusBehavior?statusBehavior(url):response({},404);
  if(url.endsWith('/servers'))return response({servers,registry_administration:readiness?{ready:true,version:head,scopeKey:'a'.repeat(64)}:{ready:false}});
  return response({history:[]});
 });
});
afterEach(async()=>{await act(async()=>root.unmount());node.remove();});
async function mount(){await act(async()=>root.render(<MCP/>));await flush();}
async function register(){await click('+ register new');await type('name','owned-test');await type('url','http://127.0.0.1:9000/mcp?raw=%2e%2e');await click('register');}
test('actual register/import/delete forms send exact owned contract then display persisted reads',async()=>{
 await mount();await register();expect(writes).toHaveLength(1);expect(writes[0]).toMatchObject({version:1,action:'register',expectedVersion:'0',name:'owned-test',url:'http://127.0.0.1:9000/mcp?raw=%2e%2e'});expect(toast.success).toHaveBeenCalled();expect(localStorage.getItem(SHOP_MCP_REGISTRY_KEY)).toBeNull();expect(node.textContent).toContain('owned-test');
 await act(async()=>node.querySelector('[aria-label="Remove owned-test"]').click());await click('remove');expect(writes[1]).toMatchObject({action:'retire',expectedVersion:'1',name:'owned-test'});
 await click('import manifest');await type('xml_url','http://127.0.0.1:9000/manifest.xml');await click('import');expect(writes[2]).toMatchObject({action:'import',expectedVersion:'2',xml_url:'http://127.0.0.1:9000/manifest.xml'});expect(node.textContent).toContain('imported');
});
test('unknown write persists across remount; explicit missing-status retry reuses exact operation',async()=>{
 writeBehavior=()=>{throw Error('Lost acknowledgement');};await mount();await register();expect(writes).toHaveLength(1);const first=JSON.stringify(writes[0]);expect(localStorage.getItem(SHOP_MCP_REGISTRY_KEY)).not.toBeNull();expect(toast.success).not.toHaveBeenCalled();
 await act(async()=>root.unmount());root=createRoot(node);await mount();expect(button('+ register new').disabled).toBe(true);await click('Check saved operation');expect(writes).toHaveLength(1);writeBehavior=null;await click('Retry same saved request');expect(JSON.stringify(writes[1])).toBe(first);expect(localStorage.getItem(SHOP_MCP_REGISTRY_KEY)).toBeNull();
});
test('version conflict needs explicit discard and new intent with refreshed head',async()=>{
 writeBehavior=()=>{head='4';return response({ok:false,code:'MCP_REGISTRY_OPERATION_CONFLICT'},409);};await mount();await register();expect(writes).toHaveLength(1);expect(button('+ register new').disabled).toBe(true);expect(toast.success).not.toHaveBeenCalled();await click('Discard rejected intent');writeBehavior=null;await register();expect(writes[1].expectedVersion).toBe('4');expect(writes[1].operationId).not.toBe(writes[0].operationId);
});
test('unqualified readiness never permits a mutation',async()=>{readiness=false;await mount();expect(button('+ register new').disabled).toBe(true);expect(button('import manifest').disabled).toBe(true);expect(node.textContent).toContain('Registry writes are unavailable');expect(writes).toHaveLength(0);});
test('completed readback must match saved identity and digest',async()=>{writeBehavior=()=>{throw Error('Lost acknowledgement');};await mount();await register();statusBehavior=()=>response({...receipt(writes[0]),requestSha256:'0'.repeat(64)});await click('Check saved operation');expect(toast.success).not.toHaveBeenCalled();expect(localStorage.getItem(SHOP_MCP_REGISTRY_KEY)).not.toBeNull();expect(node.textContent).toContain('could not be verified');});

test('completed import projects exact entity-read text outside the closed modal',async()=>{
 const value='<img src=x onerror=alert(1)>', bytes=new TextEncoder().encode(value);
 const read={path:'/owned-mcp-files/admin-token.txt',value,bytes:bytes.length,
  sha256:require('node:crypto').createHash('sha256').update(bytes).digest('hex')};
 writeBehavior=request=>response({...receipt(request),changes:[{name:'imported',action:'import',effect:{
  isolation:'owned-mcp-registry-v1',mode:'vuln',entityReads:[read]}}]});
 await mount();await click('import manifest');await type('xml_url','http://owned.invalid/manifest.xml');await click('import');
 for(let attempt=0;attempt<40&&!node.querySelector('[aria-label="Imported MCP entity reads"]');attempt++)
  await act(async()=>new Promise(resolve=>setTimeout(resolve,25)));
 const details=node.querySelector('[aria-label="Imported MCP entity reads"]');
 expect(details).not.toBeNull();expect(details.textContent).toContain(value);
 expect(details.querySelector('img')).toBeNull();expect(writes).toHaveLength(1);
});

test.each(['register','import'])('%s HTTP503 preserves submitted inputs and unknown operation without success',async action=>{
 writeBehavior=()=>response({ok:true,name:'unverified',registered_count:1},503);
 await mount();await click(action==='register'?'+ register new':'import manifest');
 if(action==='register'){await type('name','owned-test');await type('url','http://owned.invalid/mcp');}
 else await type('xml_url','http://owned.invalid/manifest.xml');
 const values=[...node.querySelectorAll('form input')].map(input=>input.value);
 await click(action);
 expect(writes).toHaveLength(1);expect(writes[0].action).toBe(action);
 expect([...node.querySelectorAll('form input')].map(input=>input.value)).toEqual(values);
 expect(toast.success).not.toHaveBeenCalled();expect(node.textContent).toContain('HTTP 503');
 expect(localStorage.getItem(SHOP_MCP_REGISTRY_KEY)).not.toBeNull();
 expect(button(action).disabled).toBe(true);expect(button('Check saved operation').disabled).toBe(false);
});
test('import network failure preserves submitted URL and pending intent without automatic resend',async()=>{
 writeBehavior=()=>{throw Error('connection lost');};await mount();await click('import manifest');
 const url='http://owned.invalid/manifest.xml';await type('xml_url',url);await click('import');
 expect(node.querySelector('form input').value).toBe(url);expect(writes).toHaveLength(1);
 expect(writes[0].xml_url).toBe(url);expect(toast.success).not.toHaveBeenCalled();
 expect(node.textContent).toContain('connection lost');expect(localStorage.getItem(SHOP_MCP_REGISTRY_KEY)).not.toBeNull();
 expect(button('import').disabled).toBe(true);expect(button('Check saved operation').disabled).toBe(false);
});
