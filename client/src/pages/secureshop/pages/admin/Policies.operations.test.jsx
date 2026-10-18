import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import Policies from './Policies.jsx';
import { AuthCtx } from '../../context/AuthContext.jsx';
import { flushShopStorage, SHOP_PROMPT_POLICY_KEY } from '../../utils/shopStorage.mjs';
const { createHash, webcrypto, randomUUID } = require('node:crypto');
const { TextEncoder } = require('node:util');
jest.mock('../../utils/shopStorage.mjs', () => ({ ...jest.requireActual('../../utils/shopStorage.mjs'), flushShopStorage: jest.fn(() => Promise.resolve()) }));
let mockBoundMetadata = true;
jest.mock('../../bridge/fetchAdapter.mjs', () => ({ getBridgeFetchMetadata: () => mockBoundMetadata ? { boundReviews: true } : null }));
const toast = { success: jest.fn(), error: jest.fn(), info: jest.fn(), warn: jest.fn() };
jest.mock('../../context/ToastContext.jsx', () => ({ useToast: () => toast }));
jest.mock('../../components/PageTransition.jsx', () => ({ children }) => <div>{children}</div>);
jest.mock('framer-motion', () => ({ AnimatePresence: ({ children }) => children,
  motion: new Proxy({}, { get: (_, tag) => ({ children, initial, animate, exit, transition, ...props }) => React.createElement(tag, props, children) }) }));
const hash = text => createHash('sha256').update(text).digest('hex');
const response = (body, status = 200) => ({ ok: status < 400, status, json: async () => body });
const row = { name: 'returns', policy_version: '1', markdown_source: 'Original source', markdown_rendered: 'Original source', injected_into_json: '["customer"]' };
const list = (version = '1', scopeKey = 'a'.repeat(64), policies = [row], supportedTaskTargets) => ({ ok: true, version, administration: { versionedPolicy: true, scopeKey }, supported_targets: ['customer','merchant','admin'], ...(supportedTaskTargets ? { supported_task_targets:supportedTaskTargets } : {}), policies });
function receipt(body, { action = 'save', name = 'returns', rendered = 'Rendered output', renderKind = null } = {}) {
  const mappedTargets=action==='delete'?[]:[...new Set(body.injected_into.map(target=>({summarizer:'customer','review-moderator':'merchant'}[target]||target)))].sort();
  const requestSha256 = action === 'delete' ? hash('trusted delete') : hash(JSON.stringify({ version:1,operationId:body.operationId,name,markdown:body.markdown,targets:mappedTargets }));
  const hasTask=action!=='delete'&&body.injected_into.some(target=>['summarizer','review-moderator'].includes(target));
  const policyRequestSha256=hasTask?hash(JSON.stringify({version:2,request:{contractVersion:2,operationId:body.operationId,name,markdown:body.markdown,targets:[...body.injected_into].sort()}})):null;
  return { operationId:body.operationId,version:action === 'preview' ? body.expectedVersion : String(BigInt(body.expectedVersion)+1n),requestSha256,
    ...(hasTask?{policyRequestSha256}:{}),
    ...(action === 'delete' ? { deleted:true } : { renderResult: renderKind
      ? { version:2,kind:renderKind,operationId:body.operationId,requestSha256,executionSha256:'c'.repeat(64),
        rendered,renderedSha256:hash(rendered),...(renderKind==='isolated_template' ? {
          isolation:'bwrap-policy-template-v1',exitCode:0,timedOut:false,truncated:false,drained:true,
          effectWitness:{version:1,workerAttested:true,commandEffectObserved:false,effectSha256:null,
            compilerSha256:'d'.repeat(64),workerSha256:'e'.repeat(64)} } : {}) }
      : {version:1,operationId:body.operationId,requestSha256,isolation:'bwrap-policy-template-v1',rendered,renderedSha256:hash(rendered),exitCode:0,timedOut:false,truncated:false,drained:true} }) };
}
let root,container,readinessReply;
beforeEach(() => {
  jest.clearAllMocks();mockBoundMetadata=true;flushShopStorage.mockResolvedValue();localStorage.clear();global.IS_REACT_ACT_ENVIRONMENT=true;global.TextEncoder=TextEncoder;
  readinessReply=()=>response({ready:true});
  Object.defineProperty(global.crypto,'subtle',{configurable:true,value:webcrypto.subtle});Object.defineProperty(global.crypto,'randomUUID',{configurable:true,value:randomUUID});
  container=document.createElement('div');document.body.appendChild(container);root=createRoot(container);
});
afterEach(async()=>{await act(async()=>root.unmount());container.remove();});
const mount=(token='admin-one')=>{
 if(!global.fetch.__policiesReadyWrapped){const original=global.fetch;const wrapped=jest.fn((url,options)=>url==='/api/secureshop/admin/policies/readiness'?readinessReply():original(url,options));wrapped.__policiesReadyWrapped=true;global.fetch=wrapped;}
 return act(async()=>root.render(<AuthCtx.Provider value={{token}}><Policies/></AuthCtx.Provider>));
};
const button=text=>[...container.querySelectorAll('button')].find(b=>b.textContent===text);
const editorTargetInput = target => [...container.querySelectorAll('label')]
  .find(label => label.textContent.trim() === target)?.querySelector('input[type="checkbox"]');
const click=text=>act(async()=>{expect(button(text)).toBeTruthy();button(text).click();await new Promise(resolve=>setTimeout(resolve,10));});
async function edit(element,value){await act(async()=>{Object.getOwnPropertyDescriptor(element.tagName==='TEXTAREA'?HTMLTextAreaElement.prototype:HTMLInputElement.prototype,'value').set.call(element,value);element.dispatchEvent(new Event('input',{bubbles:true}));});}
const writes=()=>global.fetch.mock.calls.filter(([,options])=>['POST','DELETE'].includes(options?.method));

test('bound policy list and editor show the current row version instead of a missing timestamp', async () => {
  let version = '7';
  global.fetch = jest.fn(async () => response(list('9', 'a'.repeat(64), [{ ...row, policy_version: version }])));
  await mount();
  expect(container.textContent).toContain('· version 7');
  expect(container.textContent).toContain('current policy version 7');
  expect(container.textContent).not.toContain('last updated —');
  version = '8';
  await click('Reload policies');
  expect(container.textContent).toContain('current policy version 8');
});

test('retained historical targets remain readable and removable but cannot be newly assigned', async () => {
  const historical = { ...row, injected_into_json: '["analytics","customer"]' };
  global.fetch = jest.fn(async () => response(list('9', 'a'.repeat(64), [historical])));
  await mount();
  expect(container.textContent).toContain('analytics (unavailable)');
  const analytics = [...container.querySelectorAll('label')].find(label => label.textContent.includes('analytics (unavailable)'));
  expect(analytics.querySelector('input').checked).toBe(true);
  expect(analytics.querySelector('input').disabled).toBe(false);
  await act(async () => analytics.querySelector('input').click());
  expect(analytics.querySelector('input').checked).toBe(false);
  expect(analytics.querySelector('input').disabled).toBe(true);
  expect(button('delete').disabled).toBe(false);
});

test('legacy policy rows retain their timestamp display', async () => {
  mockBoundMetadata = false;
  global.fetch = jest.fn(async () => response({ policies: [{ ...row, updated_at: '2026-10-10T12:34:56Z' }] }));
  await mount();
  expect(container.textContent).toContain('last updated 2026-10-10 12:34:56');
  expect(container.textContent).not.toContain('current policy version');
});

test('explicit renderer setup absence explains and disables policy writes without claiming an empty catalog',async()=>{
 readinessReply=()=>response({ready:false});global.fetch=jest.fn(async()=>response(list()));
 await mount();expect(container.textContent).toContain('Policy renderer configuration is required');
 expect(button('+ new policy').disabled).toBe(true);
 expect(container.textContent).not.toContain('no policies yet');
 expect(global.fetch.mock.calls.some(([url])=>url==='/api/secureshop/admin/policies')).toBe(false);
 expect(writes()).toHaveLength(0);
});

test.each([response({error:'unavailable'},503),response({ready:'false'}),response({ready:false,extra:true})])('failed or malformed readiness stays a failure, never setup-required',async result=>{
 readinessReply=()=>result;global.fetch=jest.fn(async()=>response(list()));
 await mount();expect(container.textContent).toContain('Policy readiness check failed');
 expect(container.textContent).not.toContain('configuration is required');
 expect(button('+ new policy').disabled).toBe(true);expect(writes()).toHaveLength(0);
});

test('versioned save, preview and delete use exact captured bodies and verified receipts',async()=>{
 let version='1',rows=[row];
 global.fetch=jest.fn(async(url,options)=>{
  if(!options?.method)return response(list(version,'a'.repeat(64),rows));
  const body=JSON.parse(options.body),action=options.method==='DELETE'?'delete':url.endsWith('/render')?'preview':'save';
  const result=receipt(body,{action});version=result.version;if(action==='delete')rows=[];
  return response({ok:true,receipt:result});
 });
 await mount();expect(container.textContent).toContain('summarizer (unavailable)');
 for (const target of ['summarizer', 'review-moderator', 'listing']) {
  const label = [...container.querySelectorAll('label')].find(value => value.textContent.includes(`${target} (unavailable)`));
  expect(label).toBeTruthy();
  expect(label.querySelector('input[type="checkbox"]').disabled).toBe(true);
 }
 await edit(container.querySelector('textarea'),'Raw {{ teaching }}');await click('save (renders → persists)');
 expect(JSON.parse(writes()[0][1].body)).toEqual({name:'returns',markdown:'Raw {{ teaching }}',injected_into:['customer'],operationId:expect.any(String),expectedVersion:'1'});
 expect(container.querySelector('textarea').value).toBe('Raw {{ teaching }}');expect(localStorage.getItem(SHOP_PROMPT_POLICY_KEY)).toBeNull();
 await click('test render (no persist)');expect(JSON.parse(writes()[1][1].body)).toEqual({markdown:'Raw {{ teaching }}',injected_into:['customer'],operationId:expect.any(String),expectedVersion:'2'});
 await click('delete');await act(async()=>[...container.querySelectorAll('button')].filter(b=>b.textContent==='delete').at(-1).click());expect(JSON.parse(writes()[2][1].body)).toEqual({operationId:expect.any(String),expectedVersion:'2'});
 expect(container.textContent).toContain('no policies yet');
});
test('saved v2 literal policy output is escaped and never presented as an executed template', async () => {
 global.fetch=jest.fn(async(_url,options)=>options?.method
   ? response({ok:true,receipt:receipt(JSON.parse(options.body),{renderKind:'literal',rendered:'Literal <img src=x>'})})
   : response(list()));
 await mount();await click('save (renders → persists)');
 expect(container.textContent).toContain('literal policy text; no template execution');
 expect(container.textContent).toContain('Literal <img src=x>');
 expect(container.querySelector('img')).toBeNull();
});
test('advertised task targets stay in the public body and durable metadata binds both v2 and renderer digests',async()=>{
 let body,stored;
 global.fetch=jest.fn(async(_url,options)=>{
  if(!options?.method)return response(list('1','a'.repeat(64),[row],['review-moderator','summarizer']));
  body=JSON.parse(options.body);stored=JSON.parse(localStorage.getItem(SHOP_PROMPT_POLICY_KEY));return response({ok:true,receipt:receipt(body)});
 });
 await mount();
 const labels=[...container.querySelectorAll('label')];
 const summarizer=labels.find(label=>label.textContent==='summarizer')?.querySelector('input');
 const review=labels.find(label=>label.textContent==='review-moderator')?.querySelector('input');
 expect(summarizer?.disabled).toBe(false);expect(review?.disabled).toBe(false);
 await act(async()=>summarizer.click());await act(async()=>review.click());await click('save (renders → persists)');
 expect(body.injected_into).toEqual(['customer','summarizer','review-moderator']);
 const operation=stored.scopes[0].pending;
 expect(operation.requestSha256).toBe(hash(JSON.stringify({version:1,operationId:body.operationId,name:'returns',markdown:'Original source',targets:['customer','merchant']})));
 expect(operation.policyRequestSha256).toBe(hash(JSON.stringify({version:2,request:{contractVersion:2,operationId:body.operationId,name:'returns',markdown:'Original source',targets:['customer','review-moderator','summarizer']}})));
 expect(localStorage.getItem(SHOP_PROMPT_POLICY_KEY)).toBeNull();
});
test('create sends one exact upsert and keeps only nonsecret pending metadata',async()=>{
 let held,body;global.fetch=jest.fn(async(url,options)=>{if(!options?.method)return response(list('1','a'.repeat(64),[]));body=JSON.parse(options.body);return new Promise(resolve=>{held=resolve;});});
 await mount();await click('+ new policy');await edit(container.querySelector('form input'),'new-policy');await edit(container.querySelector('form textarea'),'Private draft {{ source }}');
 await act(async()=>container.querySelector('form').dispatchEvent(new Event('submit',{bubbles:true,cancelable:true})));
 // WebCrypto settles outside React's microtask-only act callback.
 await act(async()=>{await new Promise(resolve=>setTimeout(resolve,10));});
 expect(body).toMatchObject({name:'new-policy',markdown:'Private draft {{ source }}',injected_into:['customer'],expectedVersion:'1'});
 const saved=localStorage.getItem(SHOP_PROMPT_POLICY_KEY);expect(saved).not.toContain('Private draft');expect(saved).not.toContain('admin-one');
 await act(async()=>{held(response({ok:true,receipt:receipt(body,{name:'new-policy'})}));await new Promise(resolve=>setTimeout(resolve,10));});expect(toast.success).toHaveBeenCalled();
});
test('uncertain write survives remount; pending and404 recovery never posts again',async()=>{
 let body,status=202;
 global.fetch=jest.fn(async(url,options)=>{
  if(url.includes('/operations/'))return status===200?response({ok:true,receipt:receipt(body)}):response({ok:false,state:'pending'},status);
  if(options?.method){body=JSON.parse(options.body);throw Error('lost response');}return response(list());
 });
 await mount();await click('save (renders → persists)');await act(async()=>{await new Promise(resolve=>setTimeout(resolve,10));});
 expect(writes()).toHaveLength(1);expect(button('save (renders → persists)').disabled).toBe(true);
 await act(async()=>root.unmount());root=createRoot(container);await mount();expect(button('save (renders → persists)').disabled).toBe(true);
 await click('Refresh operation status');expect(container.textContent).toContain('remains pending');status=404;await click('Refresh operation status');expect(container.textContent).toContain('not observed');
 expect(writes()).toHaveLength(1);status=200;await click('Refresh operation status');expect(localStorage.getItem(SHOP_PROMPT_POLICY_KEY)).toBeNull();expect(writes()).toHaveLength(1);
});
test('persistence failure prevents mutation; load error is unavailable rather than empty',async()=>{
 global.fetch=jest.fn(async()=>response(list()));flushShopStorage.mockRejectedValue(new Error('durability unavailable'));await mount();await click('save (renders → persists)');await act(async()=>{await new Promise(resolve=>setTimeout(resolve,10));});expect(writes()).toHaveLength(0);expect(container.textContent).toContain('not sent');
});
test('manual policy save refuses a same-UUID reference replacement after parent storage ACK',async()=>{
 let acknowledge;
 flushShopStorage.mockImplementationOnce(()=>new Promise(resolve=>{acknowledge=resolve;}));
 global.fetch=jest.fn(async()=>response(list()));
 await mount();
 await click('save (renders → persists)');
 expect(acknowledge).toEqual(expect.any(Function));
 const saved=JSON.parse(localStorage.getItem(SHOP_PROMPT_POLICY_KEY));
 const replacement={...saved,scopes:saved.scopes.map(scope=>({...scope,
  pending:{...scope.pending,expectedVersion:'2'}}))};
 localStorage.setItem(SHOP_PROMPT_POLICY_KEY,JSON.stringify(replacement));
 await act(async()=>{acknowledge();await new Promise(resolve=>setTimeout(resolve,10));});
 expect(writes()).toHaveLength(0);
 expect(JSON.parse(localStorage.getItem(SHOP_PROMPT_POLICY_KEY))).toEqual(replacement);
 expect(container.textContent).toContain('Saved policy operation changed');
});
test.each([response({},503),response({policies:[]}),response({...list(),supported_targets:['summarizer']})])('bad bound list never enables mutations or claims empty',async result=>{
 global.fetch=jest.fn(async()=>result);await mount();expect(button('+ new policy').disabled).toBe(true);expect(container.textContent).toContain('unavailable');expect(container.textContent).not.toContain('no policies yet');
});
test('reload preserves dirty source and original selected version',async()=>{
 let version='1',body;global.fetch=jest.fn(async(url,options)=>{if(options?.method){body=JSON.parse(options.body);return response({code:'REVISION_CONFLICT'},409);}return response(list(version));});
 await mount();await edit(container.querySelector('textarea'),'Unsaved edit');version='9';await click('Reload policies');expect(container.querySelector('textarea').value).toBe('Unsaved edit');await click('save (renders → persists)');await act(async()=>{await new Promise(resolve=>setTimeout(resolve,10));});expect(body.expectedVersion).toBe('1');expect(container.textContent).toContain('Policy change was not published');
});
test('auth change ignores held old completion and never displays old rendered output',async()=>{
 let finish,body,currentScope='a'.repeat(64);global.fetch=jest.fn(async(url,options)=>{if(options?.method){body=JSON.parse(options.body);return new Promise(resolve=>{finish=resolve;});}return response(list('1',currentScope));});
 await mount();await click('save (renders → persists)');await act(async()=>{await new Promise(resolve=>setTimeout(resolve,10));});currentScope='b'.repeat(64);await mount('admin-two');
 await act(async()=>finish(response({ok:true,receipt:receipt(body,{rendered:'OLD PRIVATE RENDER'})})));expect(container.textContent).not.toContain('OLD PRIVATE RENDER');expect(toast.success).not.toHaveBeenCalled();
});
test('known capacity rejection clears pending but never automatically retries',async()=>{
 global.fetch=jest.fn(async(_url,options)=>options?.method?response({code:'POLICY_RENDER_BUSY'},503):response(list()));
 await mount();await click('save (renders → persists)');await act(async()=>{await new Promise(resolve=>setTimeout(resolve,10));});
 expect(writes()).toHaveLength(1);expect(localStorage.getItem(SHOP_PROMPT_POLICY_KEY)).toBeNull();expect(button('save (renders → persists)').disabled).toBe(false);expect(container.textContent).toContain('not admitted');
});
test('malformed completed receipt remains uncertain and cannot enable another render',async()=>{
 global.fetch=jest.fn(async(_url,options)=>options?.method?response({ok:true,receipt:{operationId:JSON.parse(options.body).operationId,version:'2',requestSha256:'0'.repeat(64)}}):response(list()));
 await mount();await click('test render (no persist)');await act(async()=>{await new Promise(resolve=>setTimeout(resolve,10));});
 expect(writes()).toHaveLength(1);expect(button('save (renders → persists)').disabled).toBe(true);expect(container.querySelector('textarea').value).toBe('Original source');expect(toast.success).not.toHaveBeenCalled();expect(toast.info).not.toHaveBeenCalled();
});
test('duplicate clicks serialize one admitted operation; unmount ignores its completion',async()=>{
 let finish,body;global.fetch=jest.fn(async(_url,options)=>{if(options?.method){body=JSON.parse(options.body);return new Promise(resolve=>{finish=resolve;});}return response(list());});
 await mount();await act(async()=>{button('save (renders → persists)').click();button('save (renders → persists)').click();await new Promise(resolve=>setTimeout(resolve,10));});expect(writes()).toHaveLength(1);
 await act(async()=>root.unmount());root=createRoot(container);await act(async()=>finish(response({ok:true,receipt:receipt(body)})));expect(toast.success).not.toHaveBeenCalled();expect(localStorage.getItem(SHOP_PROMPT_POLICY_KEY)).not.toBeNull();
});
test('oversized source fails before durable admission or network mutation',async()=>{
 global.fetch=jest.fn(async()=>response(list()));await mount();await edit(container.querySelector('textarea'),'x'.repeat(16385));await click('save (renders → persists)');expect(writes()).toHaveLength(0);expect(localStorage.getItem(SHOP_PROMPT_POLICY_KEY)).toBeNull();expect(container.textContent).toContain('16 KiB');
});
test('explicit dismissal refreshes same-scope head without POST; new action is separate and prior readback survives',async()=>{
 let head='1',firstBody,newBody,writeCount=0;
 global.fetch=jest.fn(async(url,options)=>{
  if(url.includes('/operations/'))return response({ok:true,receipt:receipt(firstBody,{rendered:'Prior saved render'})});
  if(options?.method){writeCount++;if(writeCount===1){firstBody=JSON.parse(options.body);throw Error('lost acknowledgment');}newBody=JSON.parse(options.body);return response({ok:false,state:'pending'},202);}
  return response(list(head));
 });
 await mount();await click('save (renders → persists)');await act(async()=>{await new Promise(resolve=>setTimeout(resolve,10));});head='8';
 await click('Dismiss pending operation…');expect(container.textContent).toContain('does not cancel');await click('Acknowledge unknown outcome');
 expect(writes()).toHaveLength(1);expect(container.textContent).toContain(firstBody.operationId);expect(container.textContent).toContain('outcome unknown (acknowledged)');expect(button('save (renders → persists)').disabled).toBe(false);
 await click('save (renders → persists)');await act(async()=>{await new Promise(resolve=>setTimeout(resolve,10));});expect(newBody.expectedVersion).toBe('8');expect(newBody.operationId).not.toBe(firstBody.operationId);expect(writes()).toHaveLength(2);
 await act(async()=>root.unmount());root=createRoot(container);await mount();expect(container.textContent).toContain(firstBody.operationId);expect(button('save (renders → persists)').disabled).toBe(true);
 await click('Check prior operation status');await act(async()=>{await new Promise(resolve=>setTimeout(resolve,10));});expect(writes()).toHaveLength(2);expect(container.textContent).not.toContain('Prior saved render');expect(button('save (renders → persists)').disabled).toBe(true);
 const stored=JSON.parse(localStorage.getItem(SHOP_PROMPT_POLICY_KEY));expect(stored.version).toBe(2);const metadata=stored.scopes[0];expect(metadata.pending.operationId).toBe(newBody.operationId);expect(metadata.history).toHaveLength(0);
});
test.each(['unavailable','different-scope'])('dismissal %s head read stays locked and retains unknown operation',async mode=>{
 let headReads=0;global.fetch=jest.fn(async(_url,options)=>{
  if(options?.method)throw Error('lost response');headReads++;if(headReads===1)return response(list());return mode==='unavailable'?response({},503):response(list('2','b'.repeat(64)));
 });
 await mount();await click('save (renders → persists)');await act(async()=>{await new Promise(resolve=>setTimeout(resolve,10));});const before=localStorage.getItem(SHOP_PROMPT_POLICY_KEY);
 await click('Dismiss pending operation…');await click('Acknowledge unknown outcome');expect(writes()).toHaveLength(1);expect(button('save (renders → persists)').disabled).toBe(true);expect(localStorage.getItem(SHOP_PROMPT_POLICY_KEY)).toBe(before);expect(container.textContent).toContain('remains locked');
});


test('definitive conflict remains known across remount, refresh is explicit and separate save uses fresh version',async()=>{
 let head='1',post=0;const bodies=[];
 global.fetch=jest.fn(async(url,options)=>{if(options?.method){const body=JSON.parse(options.body);bodies.push(body);post++;return post===1?response({code:'REVISION_CONFLICT'},409):response({ok:true,receipt:receipt(body)});}return response(list(head));});
 await mount();await edit(container.querySelector('textarea'),'Keep dirty source');await act(async()=>editorTargetInput('merchant').click());
 const gets=global.fetch.mock.calls.length;await click('save (renders → persists)');expect(global.fetch.mock.calls.length).toBe(gets+1);expect(writes()).toHaveLength(1);expect(button('Review current policy version')).toBeTruthy();expect(button('Dismiss pending operation…')).toBeUndefined();
 expect(JSON.parse(localStorage.getItem(SHOP_PROMPT_POLICY_KEY)).scopes[0].pending.outcome).toBe('revision_conflict');
 head='4';await click('Review current policy version');expect(writes()).toHaveLength(1);expect(container.querySelector('textarea').value).toBe('Keep dirty source');expect(editorTargetInput('merchant').checked).toBe(true);expect(localStorage.getItem(SHOP_PROMPT_POLICY_KEY)).toBeNull();
 await click('save (renders → persists)');expect(bodies[1].expectedVersion).toBe('4');expect(bodies[1].operationId).not.toBe(bodies[0].operationId);expect(bodies[1].markdown).toBe('Keep dirty source');expect(bodies[1].injected_into).toEqual(['customer','merchant']);
});
test('known conflict metadata survives real component remount without becoming unknown history',async()=>{
 global.fetch=jest.fn(async(_url,options)=>options?.method?response({code:'REVISION_CONFLICT'},409):response(list()));await mount();await click('save (renders → persists)');
 await act(async()=>root.unmount());root=createRoot(container);await mount();expect(container.textContent).toContain('Policy change was not published');expect(button('Review current policy version')).toBeTruthy();expect(writes()).toHaveLength(1);expect(JSON.parse(localStorage.getItem(SHOP_PROMPT_POLICY_KEY)).scopes[0].history).toEqual([]);
});
test.each(['unavailable','foreign'])('known conflict refresh %s stays locked without clearing original record',async mode=>{
 let refresh=false;global.fetch=jest.fn(async(_url,options)=>options?.method?response({code:'REVISION_CONFLICT'},409):refresh?(mode==='foreign'?response(list('2','b'.repeat(64))):response({},503)):response(list()));await mount();await click('save (renders → persists)');const prior=localStorage.getItem(SHOP_PROMPT_POLICY_KEY);refresh=true;await click('Review current policy version');expect(localStorage.getItem(SHOP_PROMPT_POLICY_KEY)).toBe(prior);expect(button('save (renders → persists)').disabled).toBe(true);expect(writes()).toHaveLength(1);
});
test.each([['OPERATION_CONFLICT',409],['REVISION_CONFLICT',503]])('only exact409 revision code is known; %s/%s remains unknown',async(code,status)=>{
 global.fetch=jest.fn(async(_url,options)=>options?.method?response({code},status):response(list()));await mount();await click('save (renders → persists)');expect(button('Review current policy version')).toBeUndefined();expect(button('Refresh operation status')).toBeTruthy();expect(JSON.parse(localStorage.getItem(SHOP_PROMPT_POLICY_KEY)).scopes[0].pending.outcome).toBeUndefined();
});
test('explicit foreign reference forgetting requires confirmation, makes no request and survives remount',async()=>{
 const operation={scopeKey:'c'.repeat(64),operationId:randomUUID(),expectedVersion:'1',action:'save',name:'old-policy',requestSha256:'b'.repeat(64)};
 localStorage.setItem(SHOP_PROMPT_POLICY_KEY,JSON.stringify({version:2,scopes:[{scopeKey:operation.scopeKey,pending:operation,history:[]}]}));
 global.fetch=jest.fn(async()=>response(list()));await mount();await edit(container.querySelector('textarea'),'Preserved dirty draft');const count=global.fetch.mock.calls.length;
 expect(container.textContent).toContain(operation.operationId);expect(container.textContent).toContain(operation.scopeKey);
 await click('Forget local reference…');expect(container.textContent).toContain('does not cancel, publish, or verify');await click('cancel');expect(localStorage.getItem(SHOP_PROMPT_POLICY_KEY)).toContain(operation.operationId);
 await click('Forget local reference…');await click('Forget this local reference');expect(global.fetch).toHaveBeenCalledTimes(count);expect(localStorage.getItem(SHOP_PROMPT_POLICY_KEY)).toBeNull();expect(container.querySelector('textarea').value).toBe('Preserved dirty draft');
 await act(async()=>root.unmount());root=createRoot(container);await mount();expect(container.textContent).not.toContain(operation.operationId);expect(writes()).toHaveLength(0);
});
test('current pending is protected and changed retained reference is not removed by stale confirmation',async()=>{
 const current={scopeKey:'a'.repeat(64),operationId:randomUUID(),expectedVersion:'1',action:'save',name:'returns',requestSha256:'b'.repeat(64)},old={...current,scopeKey:'c'.repeat(64),operationId:randomUUID()};
 const scopes=[{scopeKey:current.scopeKey,pending:current,history:[]},{scopeKey:old.scopeKey,pending:old,history:[]}];localStorage.setItem(SHOP_PROMPT_POLICY_KEY,JSON.stringify({version:2,scopes}));global.fetch=jest.fn(async()=>response(list()));await mount();
 expect([...container.querySelectorAll('button')].filter(b=>b.textContent==='Forget local reference…')).toHaveLength(1);await click('Forget local reference…');scopes[1].pending={...old,expectedVersion:'2'};localStorage.setItem(SHOP_PROMPT_POLICY_KEY,JSON.stringify({version:2,scopes}));const count=global.fetch.mock.calls.length;
 await click('Forget this local reference');expect(container.textContent).toContain('Saved policy reference changed');expect(JSON.parse(localStorage.getItem(SHOP_PROMPT_POLICY_KEY)).scopes).toEqual(scopes);expect(global.fetch).toHaveBeenCalledTimes(count);expect(writes()).toHaveLength(0);
});
test('acknowledged current-scope history can be forgotten; auth change closes a held confirmation',async()=>{
 const operation={scopeKey:'a'.repeat(64),operationId:randomUUID(),expectedVersion:'1',action:'save',name:'returns',requestSha256:'b'.repeat(64)};
 localStorage.setItem(SHOP_PROMPT_POLICY_KEY,JSON.stringify({version:2,scopes:[{scopeKey:operation.scopeKey,pending:null,history:[operation]}]}));
 global.fetch=jest.fn(async()=>response(list()));await mount();await click('Forget local reference…');await mount('admin-two');expect(button('Forget this local reference')).toBeUndefined();expect(localStorage.getItem(SHOP_PROMPT_POLICY_KEY)).toContain(operation.operationId);
 await click('Forget local reference…');const count=global.fetch.mock.calls.length;await click('Forget this local reference');expect(global.fetch).toHaveBeenCalledTimes(count);expect(localStorage.getItem(SHOP_PROMPT_POLICY_KEY)).toBeNull();expect(button('Check prior operation status')).toBeUndefined();expect(writes()).toHaveLength(0);
});
