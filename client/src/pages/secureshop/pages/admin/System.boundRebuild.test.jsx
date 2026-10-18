import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import System from './System.jsx';
import { AuthCtx } from '../../context/AuthContext.jsx';
import { SHOP_SYSTEM_REBUILD_KEY } from '../../utils/shopStorage.mjs';
const { webcrypto } = require('node:crypto');

let bound = true;
jest.mock('../../bridge/fetchAdapter.mjs', () => ({ getBridgeFetchMetadata: () => bound ? {} : null }));
const toast = { success: jest.fn(), error: jest.fn(), warn: jest.fn(), info: jest.fn() };
jest.mock('../../context/ToastContext.jsx', () => ({ useToast: () => toast }));
jest.mock('../../components/PageTransition.jsx', () => ({ children, className }) => <div className={className}>{children}</div>);
jest.mock('framer-motion', () => ({ AnimatePresence: ({ children }) => children, motion: new Proxy({}, { get: (_, tag) => ({ children, ...props }) => React.createElement(tag, props, children) }) }));
const scopeKey = 'b'.repeat(64);
const response = (body, status = 200) => ({ ok: status >= 200 && status < 300, status, json: async () => body });
const health = url => response(url.includes('agent-host') ? { status: 'SERVICE_READY', model_execution: 'not_tested' } : { hostname: 'owned', platform: 'darwin', node: 'v26', uptime_s: 1, loadavg: [0], freemem_mb: 1 });
const sha = async text => Array.from(new Uint8Array(await globalThis.crypto.subtle.digest('SHA-256', new TextEncoder().encode(text))), b => b.toString(16).padStart(2, '0')).join('');
const admin = () => response({ ok: true, administration: { scopeKey, rebuildCapability: 'secureshop-owned-system-rebuild.v1', corpora:['products','reviews','manuals'] } });
let root, container;
beforeEach(() => { Object.defineProperty(global.crypto, 'subtle', { configurable: true, value: webcrypto.subtle }); Object.defineProperty(global.crypto, 'randomUUID', { configurable: true, value: webcrypto.randomUUID.bind(webcrypto) }); bound = true; jest.clearAllMocks(); localStorage.clear(); global.IS_REACT_ACT_ENVIRONMENT = true; container = document.createElement('div'); document.body.appendChild(container); root = createRoot(container); });
afterEach(async () => { if (root) await act(async () => root.unmount()); container.remove(); });
const mount = (token = 'admin') => act(async () => root.render(<AuthCtx.Provider value={{ token }}><System /></AuthCtx.Provider>));
const settle = () => act(async () => { await new Promise(resolve => setTimeout(resolve, 200)); });
const clickRebuild=()=>act(async()=>{[...container.querySelectorAll('button')].find(b=>b.textContent==='rebuild products').click();await new Promise(r=>setTimeout(r,100));});
const completed=async body=>({ok:true,state:'completed',operationId:body.operationId,operationMode:'initialize',revisionId:body.operationId,corpus:body.corpus,targetId:body.operationId,generation:1,documentCount:4,replayed:false,requestSha256:await sha(JSON.stringify(body)),bindingSha256:'a'.repeat(64),sourceSetDigest:'c'.repeat(64),runtimeSha256:'d'.repeat(64),vectorDigest:'e'.repeat(64)});
test('rebuild persists before POST and clears only a validated committed receipt',async()=>{
 let persisted=false;
 global.fetch=jest.fn(async(url,options={})=>{
  if(url.endsWith('/rebuild-index')&&!options.method)return admin();
  if(options.method==='POST'){persisted=localStorage.getItem(SHOP_SYSTEM_REBUILD_KEY)!==null;return response(await completed(JSON.parse(options.body)));}
  return health(url);
 });
 await mount();await settle();await clickRebuild();
 expect(persisted).toBe(true);expect(localStorage.getItem(SHOP_SYSTEM_REBUILD_KEY)).toBeNull();
 expect(container.textContent).toContain('"state": "completed"');
 expect([...container.querySelectorAll('button')].find(b=>b.textContent==='rebuild policies').disabled).toBe(true);
});
test('lost response survives reload and recovers using GET only',async()=>{
 let body;
 global.fetch=jest.fn(async(url,options={})=>{
  if(url.endsWith('/rebuild-index')&&!options.method)return admin();
  if(options.method==='POST'){body=JSON.parse(options.body);throw Error('Response lost');}
  if(url.includes('/rebuild-index/operations/'))return response(await completed(body));
  return health(url);
 });
 await mount();await settle();await clickRebuild();expect(localStorage.getItem(SHOP_SYSTEM_REBUILD_KEY)).not.toBeNull();
 expect(JSON.parse(localStorage.getItem(SHOP_SYSTEM_REBUILD_KEY)).references[0].state).toBe('unknown');
 expect(container.textContent).toContain('outcome unverified');
 expect(toast.error).not.toHaveBeenCalled();
 await act(async()=>root.unmount());root=createRoot(container);await mount();await settle();
 expect(global.fetch.mock.calls.filter(([,o])=>o?.method==='POST')).toHaveLength(1);
 expect(container.textContent).toContain('"state": "completed"');expect(localStorage.getItem(SHOP_SYSTEM_REBUILD_KEY)).toBeNull();
});
test('storage failure stops rebuild dispatch',async()=>{
 global.fetch=jest.fn(async(url)=>url.endsWith('/rebuild-index')?admin():health(url));
 await mount();await settle();const spy=jest.spyOn(Storage.prototype,'setItem').mockImplementation(()=>{throw Error('Storage unavailable');});
 try{await clickRebuild();expect(global.fetch.mock.calls.some(([,o])=>o?.method==='POST')).toBe(false);}finally{spy.mockRestore();}
});
test('pending rebuild remains recoverable and never presents committed success',async()=>{
 global.fetch=jest.fn(async(url,options={})=>{
  if(url.endsWith('/rebuild-index')&&!options.method)return admin();
  if(options.method==='POST')return response({ok:false,state:'pending',operationId:JSON.parse(options.body).operationId,automaticRetry:false},202);
  return health(url);
 });
 await mount();await settle();await clickRebuild();
 expect(container.textContent).toContain('outcome remains pending');expect(container.textContent).not.toContain('"state": "completed"');
 expect(localStorage.getItem(SHOP_SYSTEM_REBUILD_KEY)).not.toBeNull();
 expect([...container.querySelectorAll('button')].find(b=>b.textContent==='rebuild products').disabled).toBe(true);
});
test('changed original session does not read another scope operation',async()=>{
 const operationId=webcrypto.randomUUID();localStorage.setItem(SHOP_SYSTEM_REBUILD_KEY,JSON.stringify({version:1,references:[{scopeKey:'f'.repeat(64),operationId,state:'pending'}]}));
 global.fetch=jest.fn(async url=>url.endsWith('/rebuild-index')?admin():health(url));
 await mount();await settle();
 await act(async()=>[...container.querySelectorAll('button')].find(b=>b.textContent==='verify outcome').click());
 expect(global.fetch.mock.calls.some(([url])=>url.includes('/rebuild-index/operations/'))).toBe(false);
 expect(container.textContent).toContain('another launch or session');
});
test('unmount fences a late completed response and keeps its recovery reference',async()=>{
 let finish,body;
 global.fetch=jest.fn(async(url,options={})=>{
  if(url.endsWith('/rebuild-index')&&!options.method)return admin();
  if(options.method==='POST'){body=JSON.parse(options.body);return new Promise(resolve=>{finish=resolve;});}
  return health(url);
 });
 await mount();await settle();await clickRebuild();
 await act(async()=>root.unmount());root=null;
 await act(async()=>finish(response(await completed(body))));
 expect(localStorage.getItem(SHOP_SYSTEM_REBUILD_KEY)).not.toBeNull();
});
test('mismatched committed receipt keeps recovery reference and never renders success',async()=>{
 global.fetch=jest.fn(async(url,options={})=>{
  if(url.endsWith('/rebuild-index')&&!options.method)return admin();
  if(options.method==='POST'){const value=await completed(JSON.parse(options.body));value.requestSha256='f'.repeat(64);return response(value);}
  return health(url);
 });
 await mount();await settle();await clickRebuild();
 expect(container.textContent).toContain('Invalid rebuild receipt');
 expect(container.textContent).not.toContain('"state": "completed"');
 expect(localStorage.getItem(SHOP_SYSTEM_REBUILD_KEY)).not.toBeNull();
});

test.each([false,true])('terminal failure is trusted only with its exact request digest (forged=%s)',async forged=>{
 global.fetch=jest.fn(async(url,options={})=>{
  if(url.endsWith('/rebuild-index')&&!options.method)return admin();
  if(options.method==='POST'){
   const body=JSON.parse(options.body);
   return response({ok:false,state:'failed',operationId:body.operationId,operationMode:'initialize',corpus:body.corpus,
    targetId:body.operationId,generation:1,replayed:false,failureCode:'SOURCE_CHANGED',
    requestSha256:forged?'0'.repeat(64):await sha(JSON.stringify(body)),bindingSha256:'a'.repeat(64)});
  }
  return health(url);
 });
 await mount();await settle();await clickRebuild();
 const button=[...container.querySelectorAll('button')].find(b=>b.textContent==='rebuild products');
 if(forged){
  expect(localStorage.getItem(SHOP_SYSTEM_REBUILD_KEY)).not.toBeNull();
  expect(container.textContent).toContain('outcome unverified');expect(button.disabled).toBe(true);
 }else{
  expect(localStorage.getItem(SHOP_SYSTEM_REBUILD_KEY)).toBeNull();
  expect(container.textContent).toContain('failed without publishing a revision');
  expect(container.textContent).toContain('SOURCE_CHANGED');expect(button.disabled).toBe(false);
 }
 expect(global.fetch.mock.calls.filter(([,options])=>options?.method==='POST')).toHaveLength(1);
 expect(toast.success).not.toHaveBeenCalled();
});

test('policy-enabled capability preserves all rebuild controls and validates policy receipt',async()=>{
 let posted;
 global.fetch=jest.fn(async(url,options={})=>{
  if(url.endsWith('/rebuild-index')&&!options.method)return response({ok:true,administration:{scopeKey,rebuildCapability:'secureshop-owned-system-rebuild.v1',corpora:['products','reviews','manuals','policies']}});
  if(options.method==='POST'){posted=JSON.parse(options.body);return response(await completed(posted));}
  return health(url);
 });
 await mount();await settle();
 for(const corpus of ['products','reviews','manuals','policies'])expect([...container.querySelectorAll('button')].find(b=>b.textContent===`rebuild ${corpus}`).disabled).toBe(false);
 await act(async()=>{[...container.querySelectorAll('button')].find(b=>b.textContent==='rebuild policies').click();await new Promise(r=>setTimeout(r,100));});
 expect(posted.corpus).toBe('policies');expect(container.textContent).toContain('"corpus": "policies"');
 expect(localStorage.getItem(SHOP_SYSTEM_REBUILD_KEY)).toBeNull();
});

test.each([
 {corpora:['products','reviews','policies']},
 {corpora:['products','reviews','manuals','manuals']},
 {corpora:['products','reviews','manuals','unknown']},
])('invalid advertised corpora stay unavailable: $corpora',async({corpora})=>{
 global.fetch=jest.fn(async url=>url.endsWith('/rebuild-index')?response({ok:true,administration:{scopeKey,rebuildCapability:'secureshop-owned-system-rebuild.v1',corpora}}):health(url));
 await mount();await settle();
 expect([...container.querySelectorAll('button')].find(b=>b.textContent==='rebuild products').disabled).toBe(true);
 expect(container.textContent).toContain('Invalid rebuild capability');
});
