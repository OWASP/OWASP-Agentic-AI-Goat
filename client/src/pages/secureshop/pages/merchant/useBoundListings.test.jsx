import React,{act} from 'react';
import {createRoot} from 'react-dom/client';
import {useBoundListings} from './useBoundListings';
import {createHostTransport,createFrameTransport} from '../../bridge/transport.mjs';
import {compileBridgeOperation} from '../../bridge/compiler.mjs';
let mockStandalone = false;
jest.mock('../../bridge/assessmentPanelIntent.mjs', () => ({ isStandaloneShopFrame: () => mockStandalone }));
const {webcrypto,randomUUID}=require('node:crypto');const {TextEncoder}=require('node:util');
jest.mock('../../bridge/fetchAdapter.mjs',()=>({getBridgeFetchMetadata:()=>({})}));
let root,container,bound,transport,templateResponse;const response=(v,status=200)=>({ok:status<400,status,json:async()=>v});
const bridgeTransport=(url,options)=>url.endsWith('/template-readiness')?templateResponse(url,options):transport(url,options);
function Probe({token}){bound=useBoundListings(token,bridgeTransport);return null;}
const render=(token='a')=>act(async()=>root.render(<Probe token={token}/>));
beforeEach(()=>{global.IS_REACT_ACT_ENVIRONMENT=true;mockStandalone=false;templateResponse=async()=>response({ready:false});global.TextEncoder=TextEncoder;Object.defineProperty(global.crypto,'subtle',{configurable:true,value:webcrypto.subtle});Object.defineProperty(global.crypto,'randomUUID',{configurable:true,value:randomUUID});localStorage.clear();container=document.createElement('div');root=createRoot(container);});
afterEach(async()=>{await act(async()=>root.unmount());jest.restoreAllMocks();});
test('false readiness fails closed without operation dispatch',async()=>{transport=jest.fn(async()=>response({ready:false}));await render();expect(bound.ready).toBe(false);await expect(bound.run('import',{json_url:'http://supplier',xml_url:null})).rejects.toThrow('unavailable');expect(transport).toHaveBeenCalledTimes(1);});
test('optional template readiness gates only template execution and retries by GET',async()=>{
 let available=false;templateResponse=jest.fn(async()=>response({ready:available}));
 transport=jest.fn(async()=>response({ready:true,versionedListings:true,scopeKey:'a'.repeat(64)}));
 await render();expect(bound.ready).toBe(true);expect(bound.templateReady).toBe(false);
 await act(async()=>{await expect(bound.templateOperation(7)).rejects.toThrow('unavailable');});
 expect(transport).toHaveBeenCalledTimes(1);
 available=true;await act(async()=>bound.retryTemplateReadiness());
 expect(bound.templateReady).toBe(true);expect(templateResponse).toHaveBeenCalledTimes(2);
 expect(templateResponse.mock.calls.every(([,options])=>options.method===undefined)).toBe(true);
});
test('template sidecar alone cannot admit a render without mounted Listings scope',async()=>{
 templateResponse=async()=>response({ready:true});
 transport=jest.fn(async()=>response({ready:false}));
 await render();expect(bound.templateReady).toBe(true);expect(bound.ready).toBe(false);
 await act(async()=>{await expect(bound.templateOperation(7)).rejects.toThrow('unavailable');});
 expect(transport).toHaveBeenCalledTimes(1);
});
test('template response loss keeps opaque reference and all later checks are GET only',async()=>{
 templateResponse=async()=>response({ready:true});let posts=0,gets=0;
 transport=jest.fn(async(url,options={})=>{
  if(url.endsWith('/readiness'))return response({ready:true,versionedListings:true,scopeKey:'a'.repeat(64)});
  if(options.method==='POST'){posts++;throw Error('response lost');}
  gets++;return response({ok:false,operationId:url.split('/').pop(),productId:7,state:'unknown'},202);
 });
 await render();expect(bound.templateReady).toBe(true);
 await act(async()=>{await expect(bound.templateOperation(7)).rejects.toThrow('response lost');});
 const saved=localStorage.getItem('secureshop.listings.operations.v1');
 expect(saved).toContain('"productId":7');expect(saved).not.toContain('templateSource');expect(posts).toBe(1);
 await act(async()=>{expect((await bound.templateOperation(7)).state).toBe('unknown');});
 await act(async()=>root.unmount());root=createRoot(container);await render();
 await act(async()=>{expect((await bound.templateOperation()).state).toBe('unknown');});
 expect(posts).toBe(1);expect(gets).toBe(2);
 await act(async()=>{await expect(bound.templateOperation(8)).rejects.toThrow('saved template render');});
 expect(posts).toBe(1);
});
test('template mode conflict keeps the exact saved reference and never infers non-admission',async()=>{
 templateResponse=async()=>response({ready:true});let posts=0;
 transport=jest.fn(async(url,options={})=>{
  if(url.endsWith('/readiness'))return response({ready:true,versionedListings:true,scopeKey:'a'.repeat(64)});
  if(options.method==='POST'){posts++;return response({ok:false,code:'LISTING_MODE_TARGET_CONFLICT'},409);}
  return response({ok:false,code:'LISTING_MODE_TARGET_CONFLICT'},409);
 });
 await render();
 await act(async()=>{await expect(bound.templateOperation(7)).rejects.toThrow('another mode');});
 const saved=bound.references.template;expect(saved.productId).toBe(7);expect(posts).toBe(1);
 await act(async()=>{await expect(bound.templateOperation()).rejects.toThrow('another mode');});
 expect(bound.references.template).toEqual(saved);expect(posts).toBe(1);
});
test('template readback validates exact product and operation before displaying completion',async()=>{
 templateResponse=async()=>response({ready:true});let wrong=true;
 transport=jest.fn(async(url,options={})=>{
  if(url.endsWith('/readiness'))return response({ready:true,versionedListings:true,scopeKey:'a'.repeat(64)});
  const body=JSON.parse(options.body);return response({ok:true,operationId:body.operationId,
   productId:wrong?8:7,state:'completed',commandEffectObserved:true});
 });
 await render();
 await act(async()=>{await expect(bound.templateOperation(7)).rejects.toThrow('outcome unresolved');});
 expect(bound.references.template.productId).toBe(7);
 wrong=false;
 transport.mockImplementation(async(url)=>url.endsWith('/readiness')
  ?response({ready:true,versionedListings:true,scopeKey:'a'.repeat(64)})
  :response({ok:true,operationId:url.split('/').pop(),productId:7,state:'completed',commandEffectObserved:true}));
 await act(async()=>{expect((await bound.templateOperation()).commandEffectObserved).toBe(true);});
 expect(transport.mock.calls.filter(([,options])=>options?.method==='POST')).toHaveLength(1);
});
test('malformed template readiness fails closed without blocking ordinary Listings readiness',async()=>{
 templateResponse=async()=>response({ready:'yes'});
 transport=jest.fn(async()=>response({ready:true,versionedListings:true,scopeKey:'a'.repeat(64)}));
 await render();expect(bound.ready).toBe(true);expect(bound.templateReady).toBe(false);
 expect(bound.templateError).toContain('could not be verified');
 await act(async()=>{await expect(bound.templateOperation(7)).rejects.toThrow('unavailable');});
 expect(transport).toHaveBeenCalledTimes(1);
});
test('template persistence failure prevents POST and a stale auth response cannot publish completion',async()=>{
 templateResponse=async()=>response({ready:true});let finish,signal,posts=0;
 transport=jest.fn(async(url,options={})=>{
  if(url.endsWith('/readiness'))return response({ready:true,versionedListings:true,scopeKey:'a'.repeat(64)});
  posts++;signal=options.signal;return new Promise(resolve=>{finish=resolve;});
 });
 await render();
 const failed=jest.spyOn(Storage.prototype,'setItem').mockImplementationOnce(()=>{throw Error('storage unavailable');});
 await act(async()=>{await expect(bound.templateOperation(7)).rejects.toThrow('storage unavailable');});
 expect(posts).toBe(0);failed.mockRestore();
 let pending;
 await act(async()=>{pending=bound.templateOperation(7).catch(error=>error);await new Promise(resolve=>setTimeout(resolve,5));});
 expect(posts).toBe(1);
 await render('rotated-token');expect(signal.aborted).toBe(true);
 await act(async()=>{finish(response({ok:true,operationId:bound.references.template?.operationId,
  productId:7,state:'completed',commandEffectObserved:true}));expect((await pending).message).toBe('Listings session changed');});
});
test('readiness 503 shows a retryable error and only retries GET before enabling actions',async()=>{
 let available=false;
 transport=jest.fn(async(url,options={})=>{
  expect(url).toBe('/api/secureshop/merchant/listings/readiness');expect(options.method).toBeUndefined();
  return available?response({ready:true,versionedListings:true,scopeKey:'a'.repeat(64)}):response({error:'Unavailable'},503);
 });
 await render();expect(bound.ready).toBe(false);expect(bound.readinessChecking).toBe(false);
 expect(bound.readinessError).toContain('HTTP 503');
 await act(async()=>bound.retryReadiness());
 expect(bound.readinessError).toContain('HTTP 503');expect(transport).toHaveBeenCalledTimes(2);
 available=true;await act(async()=>bound.retryReadiness());
 expect(bound.ready).toBe(true);expect(bound.readinessError).toBeNull();expect(transport).toHaveBeenCalledTimes(3);
 expect(transport.mock.calls.every(([,options])=>options.method===undefined)).toBe(true);
});
test('failed readiness cancels each bridge response before retrying and releases request capacity',async()=>{
 let active=0,attempts=0,cancelled=0;
 transport=jest.fn(async(url)=>{
  expect(url).toBe('/api/secureshop/merchant/listings/readiness');
  expect(active).toBe(0);
  attempts++;if(attempts===3)return response({ready:true,versionedListings:true,scopeKey:'a'.repeat(64)});
  active++;
  return {ok:false,status:503,body:{cancel:async()=>{active--;cancelled++;}}};
 });
 await render();expect(bound.readinessError).toContain('HTTP 503');expect(active).toBe(0);
 await act(async()=>bound.retryReadiness());
 expect(bound.readinessError).toContain('HTTP 503');expect(active).toBe(0);
 await act(async()=>bound.retryReadiness());
 expect(bound.ready).toBe(true);expect(active).toBe(0);
 expect(cancelled).toBe(2);expect(attempts).toBe(3);
});
test('failed readiness releases the real bridge slot before a successful retry',async()=>{
 const streams=require('node:stream/web');
 const previous={MessagePort:global.MessagePort,ReadableStream:global.ReadableStream,
  Response:global.Response,Headers:global.Headers};
 Object.assign(global,{MessagePort:require('node:worker_threads').MessagePort,
  ReadableStream:streams.ReadableStream});
 const web=require('undici');Object.assign(global,{Response:web.Response,Headers:web.Headers});
 const listeners=[new Set(),new Set()];
 const ports=[0,1].map(index=>({
  addEventListener(_type,listener){listeners[index].add(listener);},
  removeEventListener(_type,listener){listeners[index].delete(listener);},
  start(){},close(){listeners[index].clear();},
  postMessage(message){
   const data={...message,...(message.input?{input:{...message.input}}:{}),
    ...(message.chunk?{chunk:new Uint8Array(message.chunk).slice().buffer}:{})};
   queueMicrotask(()=>listeners[1-index].forEach(listener=>listener({data})));
  },
 }));
 const [port1,port2]=ports;let host,frame;
 try{
  let attempts=0;
  host=createHostTransport({port:port1,origin:'http://shop.invalid',
   compileOperation:compileBridgeOperation,getLaunchBearer:()=> 'a'.repeat(43),maxPending:1,
   fetchImpl:async()=>{
    attempts++;
    const unavailable=attempts<3;
    return new web.Response(JSON.stringify(unavailable?{error:'Unavailable'}
      :{ready:true,versionedListings:true,scopeKey:'a'.repeat(64)}),
    {status:unavailable?503:200,headers:{'content-type':'application/json'}});
   }});
  frame=createFrameTransport({port:port2,timeoutMs:500});
  transport=(_url,{signal})=>frame.request('merchant.listings.readiness',{},
   {shopBearer:'persona-token',signal});
  await render();expect(bound.readinessError).toContain('HTTP 503');
  await act(async()=>bound.retryReadiness());expect(bound.readinessError).toContain('HTTP 503');
  await act(async()=>bound.retryReadiness());expect(bound.ready).toBe(true);
  expect(attempts).toBe(3);
 }finally{
  frame?.close();host?.close();port1.close();port2.close();Object.assign(global,previous);
 }
});
test('failed template readiness cancels its bridge response and preserves Listings readiness',async()=>{
 let active=0,cancelled=0;
 templateResponse=jest.fn(async()=>{
  expect(active).toBe(0);active++;
  return {ok:false,status:503,body:{cancel:async()=>{active--;cancelled++;}}};
 });
 transport=jest.fn(async()=>response({ready:true,versionedListings:true,scopeKey:'a'.repeat(64)}));
 await render();expect(bound.ready).toBe(true);expect(bound.templateError).toContain('HTTP 503');
 expect(active).toBe(0);
 await act(async()=>bound.retryTemplateReadiness());
 expect(bound.templateError).toContain('HTTP 503');expect(active).toBe(0);
 expect(cancelled).toBe(2);expect(templateResponse).toHaveBeenCalledTimes(2);
});
test('late cancellation from an old readiness epoch cannot replace current availability',async()=>{
 let releaseCancel;
 transport=jest.fn(async(_url,options)=>options.signal&&transport.mock.calls.length===1
  ?{ok:false,status:503,body:{cancel:()=>new Promise(resolve=>{releaseCancel=resolve;})}}
  :response({ready:true,versionedListings:true,scopeKey:'b'.repeat(64)}));
 await render();expect(bound.readinessChecking).toBe(true);
 await render('rotated-token');expect(bound.ready).toBe(true);
 await act(async()=>releaseCancel());
 expect(bound.ready).toBe(true);expect(bound.readinessError).toBeNull();
});
test('malformed successful readiness stays disabled and can retry without losing saved references',async()=>{
 let valid=true;
 transport=jest.fn(async()=>valid?response({ready:true,versionedListings:true,scopeKey:'a'.repeat(64)}):response({ready:true,versionedListings:true,scopeKey:'wrong'}));
 await render();
 await act(async()=>{await expect(bound.run('import',{json_url:'http://supplier',xml_url:null})).rejects.toThrow('outcome unresolved');});
 const saved=bound.references.import;expect(saved?.operationId).toBeTruthy();
 valid=false;await act(async()=>bound.retryReadiness());
 expect(bound.ready).toBe(false);expect(bound.readinessError).toContain('could not be verified');
 expect(bound.references.import).toEqual(saved);
 valid=true;await act(async()=>bound.retryReadiness());
 expect(bound.ready).toBe(true);expect(bound.references.import).toEqual(saved);
});
test('late readiness failure from an old auth epoch cannot replace the new ready state',async()=>{
 let resolveOld;
 transport=jest.fn((url,options)=>options.signal&&transport.mock.calls.length===1
  ?new Promise(resolve=>{resolveOld=resolve;}):Promise.resolve(response({ready:true,versionedListings:true,scopeKey:'b'.repeat(64)})));
 await render();expect(bound.readinessChecking).toBe(true);
 await render('new-token');expect(bound.ready).toBe(true);
 await act(async()=>resolveOld(response({error:'old failure'},503)));
 expect(bound.ready).toBe(true);expect(bound.readinessError).toBeNull();
});
test('unmount aborts readiness and ignores its late completion',async()=>{
 let resolveOld,signal;
 transport=jest.fn((url,options)=>{signal=options.signal;return new Promise(resolve=>{resolveOld=resolve;});});
 await render();expect(bound.readinessChecking).toBe(true);
 await act(async()=>root.unmount());expect(signal.aborted).toBe(true);
 await act(async()=>resolveOld(response({error:'late unavailable'},503)));
 root=createRoot(container);
});
test('synchronous readiness transport failure is visible and retry remains read-only',async()=>{
 transport=jest.fn(()=>{throw Error('Bridge disconnected');});
 await render();expect(bound.ready).toBe(false);expect(bound.readinessError).toBe('Could not check listing actions.');
 await act(async()=>bound.retryReadiness());expect(transport).toHaveBeenCalledTimes(2);
 expect(bound.readinessError).toBe('Could not check listing actions.');
});
test('lost response retains only digest/id and remount recovery GET does not resend',async()=>{
 let posts=0;transport=jest.fn(async(url,options={})=>{if(url.endsWith('/readiness'))return response({ready:true,versionedListings:true,scopeKey:'a'.repeat(64)});if(options.method==='POST'){posts++;throw Error('lost');}return response({operationId:url.split('/').pop(),state:'unknown',ok:false});});await render();
 await act(async()=>{await expect(bound.run('import',{json_url:'http://secret-supplier',xml_url:null})).rejects.toThrow('lost');});
 const saved=localStorage.getItem('secureshop.listings.operations.v1');expect(saved).not.toContain('secret-supplier');expect(posts).toBe(1);
 await act(async()=>root.unmount());root=createRoot(container);await render();await act(async()=>{expect((await bound.recover('import')).state).toBe('unknown');});expect(posts).toBe(1);
});
test('storage failure prevents execution',async()=>{transport=jest.fn(async()=>response({ready:true,versionedListings:true,scopeKey:'a'.repeat(64)}));await render();jest.spyOn(Storage.prototype,'setItem').mockImplementation(()=>{throw Error('storage unavailable');});await act(async()=>{await expect(bound.run('rewrite',{title:'A',description:'B'})).rejects.toThrow('storage unavailable');});expect(transport).toHaveBeenCalledTimes(1);});
test('save response-loss retry uses exact GET without repeating the publication',async()=>{
 const bodies=[],reads=[];transport=jest.fn(async(url,options={})=>{if(url.endsWith('/readiness'))return response({ready:true,versionedListings:true,scopeKey:'a'.repeat(64)});if(options.method==='POST'){bodies.push(JSON.parse(options.body));throw Error('lost');}reads.push(url);return response({ok:true,saveOperationId:url.split('/').pop().split('?')[0],rewriteOperationId:bodies[0].rewriteOperationId,state:'completed',productId:4});});await render();
 const payload={rewriteOperationId:randomUUID(),productId:null,item:{name:'N',description:'D',price:1,category:null,images:[],templateSource:null}};
 await act(async()=>{await expect(bound.run('save',payload)).rejects.toThrow('lost');});
 await act(async()=>{await expect(bound.run('save',{...payload,productId:5})).rejects.toThrow('changing');});expect(bodies).toHaveLength(1);
 await act(async()=>{expect((await bound.run('save',payload)).state).toBe('completed');});
 expect(bodies).toHaveLength(1);expect(reads).toEqual([`/api/secureshop/merchant/listings/rewrite-saves/${bodies[0].saveOperationId}?rewriteOperationId=${payload.rewriteOperationId}`]);
});
test('auth transition aborts pending operation and rejects late response',async()=>{
 let finish,signal;transport=jest.fn(async(url,options={})=>{if(url.endsWith('/readiness'))return response({ready:true,versionedListings:true,scopeKey:'a'.repeat(64)});signal=options.signal;return new Promise(resolve=>{finish=resolve;});});await render();
 let result;await act(async()=>{result=bound.run('rewrite',{title:'A',description:'B'}).catch(e=>e);await new Promise(resolve=>setTimeout(resolve,5));});
 await render('b');expect(signal.aborted).toBe(true);
 await act(async()=>{finish(response({operationId:'wrong',state:'completed',html:'old'}));expect((await result).message).toBe('Listings session changed');});
});

test('failed storage write leaves no phantom operation and retry dispatches a new POST',async()=>{
 transport=jest.fn(async(url,options={})=>{
  if(url.endsWith('/readiness'))return response({ready:true,versionedListings:true,scopeKey:'a'.repeat(64)});
  const body=JSON.parse(options.body);return response({operationId:body.operationId,state:'completed',html:'<p>Ready</p>'});
 });
 await render();
 jest.spyOn(Storage.prototype,'setItem').mockImplementationOnce(()=>{throw Error('storage unavailable');});
 await act(async()=>{await expect(bound.run('rewrite',{title:'A',description:'B'})).rejects.toThrow('storage unavailable');});
 expect(bound.references).toEqual({});expect(transport).toHaveBeenCalledTimes(1);
 await act(async()=>{expect((await bound.run('rewrite',{title:'A',description:'B'})).state).toBe('completed');});
 expect(transport.mock.calls[1][1].method).toBe('POST');
 expect(transport.mock.calls[1][0]).toMatch(/assist-write$/);
});
test('saved assessment loss persists only opaque references and remount replays exact request UUID',async()=>{
 const bodies=[];transport=jest.fn(async(url,options={})=>{if(url.endsWith('/readiness'))return response({ready:true,versionedListings:true,scopeKey:'a'.repeat(64)});const body=JSON.parse(options.body);bodies.push(body);if(bodies.length===1)throw Error('lost');return response({completed:true,judgment:{verdict:'completed'},productId:7,...body});});await render();
 const ids={rewriteOperationId:randomUUID(),saveOperationId:randomUUID()};
 await act(async()=>{await expect(bound.assessSaved(ids)).rejects.toThrow('lost');});
 const stored=JSON.parse(localStorage.getItem('secureshop.listings.operations.v1'));
 expect(Object.keys(stored.assessment[0]).sort()).toEqual(['digest','requestId','rewriteOperationId','saveOperationId','scopeKey']);
 await act(async()=>root.unmount());root=createRoot(container);await render();
 await act(async()=>{expect((await bound.assessSaved()).completed).toBe(true);});
 expect(bodies[1]).toEqual(bodies[0]);expect(bound.references.assessment).toEqual([]);
});
test('disabled assessment retains stable retry while unavailable response cannot claim completion',async()=>{
 let status=200;const bodies=[];transport=jest.fn(async(url,options={})=>{if(url.endsWith('/readiness'))return response({ready:true,versionedListings:true,scopeKey:'a'.repeat(64)});bodies.push(JSON.parse(options.body));return status===200?response({completed:false,status:'disabled',modelEvaluated:false}):response({error:'unavailable'},status);});await render();
 await act(async()=>{expect((await bound.assessSaved({rewriteOperationId:randomUUID(),saveOperationId:randomUUID()})).status).toBe('disabled');});
 status=503;await act(async()=>{await expect(bound.assessSaved()).rejects.toThrow('assessment unavailable');});expect(bodies[1]).toEqual(bodies[0]);expect(bound.references.assessment).toHaveLength(1);
});
test('assessment storage failure prevents POST; stale session aborts and rejects late result',async()=>{
 let finish,signal;transport=jest.fn(async(url,options={})=>{if(url.endsWith('/readiness'))return response({ready:true,versionedListings:true,scopeKey:'a'.repeat(64)});signal=options.signal;return new Promise(resolve=>finish=resolve);});await render();
 jest.spyOn(Storage.prototype,'setItem').mockImplementationOnce(()=>{throw Error('storage unavailable');});
 await act(async()=>{await expect(bound.assessSaved({rewriteOperationId:randomUUID(),saveOperationId:randomUUID()})).rejects.toThrow('storage unavailable');});expect(transport).toHaveBeenCalledTimes(1);
 let result;await act(async()=>{result=bound.assessSaved({rewriteOperationId:randomUUID(),saveOperationId:randomUUID()}).catch(e=>e);await new Promise(resolve=>setTimeout(resolve,5));});
 await render('b');expect(signal.aborted).toBe(true);await act(async()=>{finish(response({completed:false,status:'disabled'}));expect((await result).message).toBe('Listings session changed');});
});
test('assessment reference replaces successful save references atomically and storage failure remains recoverable',async()=>{
 const requests=[];transport=jest.fn(async(url,options={})=>{if(url.endsWith('/readiness'))return response({ready:true,versionedListings:true,scopeKey:'a'.repeat(64)});const body=JSON.parse(options.body);requests.push({url,body});if(url.endsWith('/assist-write'))return response({state:'completed',operationId:body.operationId,html:'<p>Generated</p>'});if(url.endsWith('/rewrite-save'))return response({ok:true,state:'completed',saveOperationId:body.saveOperationId,rewriteOperationId:body.rewriteOperationId,productId:7});return response({completed:false,status:'disabled'});});await render();
 let rewrite,saved;await act(async()=>{rewrite=await bound.run('rewrite',{title:'Title',description:'Private source'});});
 await act(async()=>{saved=await bound.run('save',{rewriteOperationId:rewrite.operationId,productId:null,item:{name:'Title',description:'Private source',price:1,category:null,images:[],templateSource:null}});});
 jest.spyOn(Storage.prototype,'setItem').mockImplementationOnce(()=>{throw Error('storage unavailable');});
 await act(async()=>{await expect(bound.assessSaved({rewriteOperationId:rewrite.operationId,saveOperationId:saved.saveOperationId})).rejects.toThrow('storage unavailable');});
 expect(bound.references.save.operationId).toBe(saved.saveOperationId);expect(bound.references.rewrite.operationId).toBe(rewrite.operationId);expect(requests).toHaveLength(2);
 await act(async()=>{expect((await bound.assessSaved()).status).toBe('disabled');});
 expect(requests[2].body).toMatchObject({rewriteOperationId:rewrite.operationId,saveOperationId:saved.saveOperationId});
 expect(bound.references.save).toBeUndefined();expect(bound.references.rewrite).toBeUndefined();expect(bound.references.assessment).toHaveLength(1);
 expect(localStorage.getItem('secureshop.listings.operations.v1')).not.toContain('Private source');
});

test('retryable unavailable Judge result retains assessment identity instead of dropping recovery',async()=>{
 transport=jest.fn(async(url,options={})=>{if(url.endsWith('/readiness'))return response({ready:true,versionedListings:true,scopeKey:'a'.repeat(64)});
  const body=JSON.parse(options.body);return response({completed:false,productId:7,rewriteOperationId:body.rewriteOperationId,saveOperationId:body.saveOperationId,judgment:{verdict:'unavailable',canRetry:true,evaluationId:randomUUID()}});});
 await render();await act(async()=>{const result=await bound.assessSaved({rewriteOperationId:randomUUID(),saveOperationId:randomUUID()});expect(result.completed).toBe(false);});
 expect(bound.references.assessment).toHaveLength(1);
 expect(JSON.parse(localStorage.getItem('secureshop.listings.operations.v1')).assessment).toHaveLength(1);
});
test('standalone saved listing never dispatches legacy bound Judge retry',async()=>{
 mockStandalone=true;const evaluationId=randomUUID(),ids={rewriteOperationId:randomUUID(),saveOperationId:randomUUID()};
 transport=jest.fn(async(url,options={})=>{if(url.endsWith('/readiness'))return response({ready:true,versionedListings:true,scopeKey:'a'.repeat(64)});
  const body=JSON.parse(options.body);return response({completed:false,productId:7,rewriteOperationId:body.rewriteOperationId,
   saveOperationId:body.saveOperationId,judgment:{verdict:'unavailable',canRetry:true,evaluationId}});});
 await render();await act(async()=>bound.assessSaved(ids));
 await act(async()=>{await expect(bound.assessSaved(ids)).rejects.toThrow('Open saved assessments');});
 expect(transport.mock.calls.filter(([url])=>url.endsWith('/browser-attempt'))).toHaveLength(1);
 expect(transport.mock.calls.some(([url])=>url.endsWith('/browser-retry'))).toBe(false);
});
test('Judge retry uses a separate durable request and replays it after response loss without a new browser attempt',async()=>{
 const sent=[],evaluationId=randomUUID();
 transport=jest.fn(async(url,options={})=>{
  if(url.endsWith('/readiness'))return response({ready:true,versionedListings:true,scopeKey:'a'.repeat(64)});
  const body=JSON.parse(options.body);sent.push({url,body});
  if(sent.length===1)return response({completed:false,productId:7,rewriteOperationId:body.rewriteOperationId,saveOperationId:body.saveOperationId,judgment:{verdict:'unavailable',canRetry:true,evaluationId}});
  if(sent.length===2)throw Error('lost retry');
  return response({completed:true,productId:7,rewriteOperationId:body.rewriteOperationId,saveOperationId:body.saveOperationId,judgment:{verdict:'pass',canRetry:false}});
 });
 await render();await act(async()=>bound.assessSaved({rewriteOperationId:randomUUID(),saveOperationId:randomUUID()}));
 await act(async()=>{await expect(bound.assessSaved()).rejects.toThrow('lost retry');});
 expect(sent[1].url).toMatch(/browser-retry$/);expect(sent[1].body.evaluationId).toBe(evaluationId);
 expect(sent[1].body.requestId).not.toBe(sent[0].body.requestId);
 await act(async()=>root.unmount());root=createRoot(container);await render();
 await act(async()=>{expect((await bound.assessSaved()).completed).toBe(true);});
 expect(sent[2]).toEqual(sent[1]);expect(bound.references.assessment).toEqual([]);
 expect(sent.filter(x=>x.url.endsWith('/browser-attempt'))).toHaveLength(1);
});
test.each(['EVIDENCE_EXPIRED','RETRY_EXHAUSTED','OBJECTIVE_DISABLED'])('Judge retry handles explicit %s without resaving',async code=>{
 let calls=0;transport=jest.fn(async(url,options={})=>{
  if(url.endsWith('/readiness'))return response({ready:true,versionedListings:true,scopeKey:'a'.repeat(64)});
  const body=JSON.parse(options.body);if(++calls===1)return response({completed:false,productId:7,rewriteOperationId:body.rewriteOperationId,saveOperationId:body.saveOperationId,judgment:{verdict:'unavailable',canRetry:true,evaluationId:randomUUID()}});
  return response({ok:false,error:'Listings unavailable',code},409);
 });await render();await act(async()=>bound.assessSaved({rewriteOperationId:randomUUID(),saveOperationId:randomUUID()}));
 await act(async()=>{await expect(bound.assessSaved()).rejects.toThrow(code==='OBJECTIVE_DISABLED'?'assessment unavailable':'no longer be retried');});
 expect(bound.references.assessment).toHaveLength(code==='OBJECTIVE_DISABLED'?1:0);
});
test('mode change retains both opaque import references and can read the earlier mode without another POST',async()=>{
 const scopeA='a'.repeat(64),scopeB='b'.repeat(64),payload={json_url:'http://supplier',xml_url:null};let scope=scopeA,posts=0;
 transport=jest.fn(async(url,options={})=>{
  if(url.endsWith('/readiness'))return response({ready:true,versionedListings:true,scopeKey:scope});
  if(options.method==='POST'){posts++;throw Error('outcome lost');}
  return response({operationId:url.split('/').pop(),state:'unknown',ok:false});
 });
 await render();await act(async()=>{await expect(bound.run('import',payload)).rejects.toThrow('outcome lost');});
 const first=bound.references.import;
 scope=scopeB;await act(async()=>bound.retryReadiness());expect(bound.references.import).toBeUndefined();
 await act(async()=>{await expect(bound.run('import',payload)).rejects.toThrow('outcome lost');});
 const second=bound.references.import;expect(second.operationId).not.toBe(first.operationId);
 const stored=JSON.parse(localStorage.getItem('secureshop.listings.operations.v1'));
 expect(stored.import).toEqual(second);expect(stored.retained).toContainEqual({scopeKey:scopeA,import:first});
 scope=scopeA;await act(async()=>bound.retryReadiness());expect(bound.references.import).toEqual(first);
 await act(async()=>{expect((await bound.recover('import')).operationId).toBe(first.operationId);});expect(posts).toBe(2);
});
test('generic conflict retains exact current reference and another mode reference',async()=>{
 const scopeA='a'.repeat(64),scopeB='b'.repeat(64),payload={json_url:'http://supplier',xml_url:null};let scope=scopeA;
 transport=jest.fn(async(url,options={})=>{
  if(url.endsWith('/readiness'))return response({ready:true,versionedListings:true,scopeKey:scope});
  if(options.method==='POST')return response({ok:false,error:'Listings unavailable'},409);
  return response({operationId:url.split('/').pop(),state:'unknown'});
 });
 await render();await act(async()=>{await expect(bound.run('import',payload)).rejects.toThrow('outcome unresolved');});
 const first=bound.references.import;
 scope=scopeB;await act(async()=>bound.retryReadiness());
 await act(async()=>{await expect(bound.run('import',payload)).rejects.toThrow('outcome unresolved');});
 expect(bound.references.import.scopeKey).toBe(scopeB);
 expect(JSON.parse(localStorage.getItem('secureshop.listings.operations.v1')).retained).toContainEqual({scopeKey:scopeA,import:first});
});
test('mode-target conflict gives recovery guidance but does not discard an unproven operation',async()=>{
 const payload={json_url:'http://supplier',xml_url:null},sent=[];
 transport=jest.fn(async(url,options={})=>{
  if(url.endsWith('/readiness'))return response({ready:true,versionedListings:true,scopeKey:'a'.repeat(64)});
  if(options.method==='POST'){sent.push(JSON.parse(options.body));return response({ok:false,code:'LISTING_MODE_TARGET_CONFLICT'},409);}
  return response({ok:false,error:'Listings unavailable'},404);
 });
 await render();await act(async()=>{await expect(bound.run('import',payload)).rejects.toThrow('belongs to another mode');});
 const saved=bound.references.import;expect(saved.operationId).toBe(sent[0].operationId);
 await act(async()=>{await expect(bound.run('import',payload)).rejects.toThrow('outcome unresolved');});
 expect(bound.references.import).toEqual(saved);
 expect(sent).toHaveLength(1);
});
test('changed stored reference prevents clear from deleting another scope or a concurrent reference',async()=>{
 const scopeA='a'.repeat(64),scopeB='b'.repeat(64),payload={json_url:'http://supplier',xml_url:null};
 transport=jest.fn(async(url,options={})=>url.endsWith('/readiness')?response({ready:true,versionedListings:true,scopeKey:scopeA}):response({ok:false},503));
 await render();await act(async()=>{await expect(bound.run('import',payload)).rejects.toThrow('outcome unresolved');});
 const original=bound.references.import,replacement={...original,operationId:randomUUID()};
 localStorage.setItem('secureshop.listings.operations.v1',JSON.stringify({import:replacement,retained:[{scopeKey:scopeB,import:{scopeKey:scopeB,operationId:randomUUID(),digest:'b'.repeat(64)}}]}));
 await act(async()=>{await expect(bound.clear('import')).rejects.toThrow('reference changed');});
 const stored=JSON.parse(localStorage.getItem('secureshop.listings.operations.v1'));
 expect(stored.import).toEqual(replacement);expect(stored.retained[0].scopeKey).toBe(scopeB);
});
test('invalid stored reference disables listings actions instead of overwriting a pending operation',async()=>{
 localStorage.setItem('secureshop.listings.operations.v1','{"import":{"operationId":"unknown"}}');
 transport=jest.fn(async()=>response({ready:true,versionedListings:true,scopeKey:'a'.repeat(64)}));
 await render();expect(bound.ready).toBe(false);expect(bound.readinessError).toContain('references could not be verified');
 await act(async()=>{await expect(bound.run('import',{json_url:'http://supplier',xml_url:null})).rejects.toThrow('unavailable');});
 expect(transport).toHaveBeenCalledTimes(1);
});
test('bounded reference storage refuses a ninth scope before POST and evicts nothing',async()=>{
 const retained='bcdef012'.split('').map(letter=>({scopeKey:letter.repeat(64),import:{scopeKey:letter.repeat(64),operationId:randomUUID(),digest:'d'.repeat(64)}}));
 const raw=JSON.stringify({retained});localStorage.setItem('secureshop.listings.operations.v1',raw);
 transport=jest.fn(async()=>response({ready:true,versionedListings:true,scopeKey:'a'.repeat(64)}));
 await render();expect(bound.ready).toBe(true);
 await act(async()=>{await expect(bound.run('import',{json_url:'http://supplier',xml_url:null})).rejects.toThrow('capacity');});
 expect(localStorage.getItem('secureshop.listings.operations.v1')).toBe(raw);
 expect(transport).toHaveBeenCalledTimes(1);
});
test('chat setup uses deterministic operation and retains only source tuple for GET recovery',async()=>{
 const proposalId=randomUUID(),chatSource={sessionId:randomUUID(),requestId:randomUUID(),proposalId};const posts=[];
 transport=jest.fn(async(url,options={})=>{if(url.endsWith('/readiness'))return response({ready:true,versionedListings:true,scopeKey:'a'.repeat(64)});
 if(options.method==='POST'){posts.push(JSON.parse(options.body));throw Error('lost');}return response({operationId:proposalId,state:'unknown'});});await render();
 await act(async()=>{await expect(bound.run('import',{json_url:'http://supplier.test/private',xml_url:null,chatSource})).rejects.toThrow('lost');});
 expect(posts[0].operationId).toBe(proposalId);expect(posts[0].chatSource).toEqual(chatSource);
 expect(localStorage.getItem('secureshop.listings.operations.v1')).not.toContain('supplier');
 await act(async()=>root.unmount());root=createRoot(container);await render();
 await act(async()=>{expect((await bound.recover('import')).state).toBe('unknown');});expect(posts).toHaveLength(1);
});

test('chat save reload recovers with exact original role source and no repeated POST',async()=>{
 const proposalId=randomUUID(),chatSource={sessionId:randomUUID(),requestId:randomUUID(),proposalId};let posted;
 transport=jest.fn(async(url,options={})=>{if(url.endsWith('/readiness'))return response({ready:true,versionedListings:true,scopeKey:'a'.repeat(64)});
  if(options.method==='POST'){posted=JSON.parse(options.body);throw Error('lost');}
  return response({ok:true,state:'completed',saveOperationId:posted.saveOperationId,rewriteOperationId:proposalId,productId:7});});
 await render();await act(async()=>{await expect(bound.run('save',{rewriteOperationId:proposalId,chatSource})).rejects.toThrow('lost');});
 await act(async()=>root.unmount());root=createRoot(container);await render();
 await act(async()=>{expect((await bound.recover('save')).state).toBe('completed');});
 const reads=transport.mock.calls.filter(([url])=>url.includes('/rewrite-saves/'));
 expect(reads).toHaveLength(1);expect(reads[0][0]).toBe(`/api/secureshop/merchant/listings/rewrite-saves/${posted.saveOperationId}?${new URLSearchParams(chatSource)}`);
 expect(transport.mock.calls.filter(([,options])=>options?.method==='POST')).toHaveLength(1);
});

test('host ACK cannot approve a reference replaced while the write was pending',async()=>{
 const {attachShopStorage}=await import('../../utils/shopStorage.mjs');const values=new Map();let acknowledge;
 const release=attachShopStorage({getItem:key=>values.get(key)??null,setItem:(key,value)=>values.set(key,value),removeItem:key=>values.delete(key),flush:()=>new Promise(resolve=>{acknowledge=resolve;})});
 transport=jest.fn(async()=>response({ready:true,versionedListings:true,scopeKey:'a'.repeat(64)}));
 try{
  await render();let result;
  await act(async()=>{result=bound.run('import',{json_url:'http://supplier',xml_url:null}).catch(error=>error);await new Promise(resolve=>setTimeout(resolve,5));});
  const raw=JSON.parse(values.get('secureshop.listings.operations.v1'));raw.import.operationId=randomUUID();values.set('secureshop.listings.operations.v1',JSON.stringify(raw));
  await act(async()=>{acknowledge();expect((await result).message).toContain('reference changed');});
  expect(transport).toHaveBeenCalledTimes(1);
 }finally{release();}
});
test('opaque frame waits for host persistence and fences an auth change before dispatch',async()=>{
 const {attachShopStorage}=await import('../../utils/shopStorage.mjs');let acknowledge;const values=new Map();
 const release=attachShopStorage({getItem:k=>values.get(k)??null,setItem:(k,v)=>values.set(k,v),removeItem:k=>values.delete(k),flush:()=>new Promise(resolve=>{acknowledge=resolve;})});
 const opaque=jest.spyOn(window,'sessionStorage','get').mockImplementation(()=>{throw new DOMException('opaque','SecurityError');});
 transport=jest.fn(async()=>response({ready:true,versionedListings:true,scopeKey:'a'.repeat(64)}));
 try{await render();let result;await act(async()=>{result=bound.run('import',{json_url:'http://supplier',xml_url:null}).catch(e=>e);await new Promise(r=>setTimeout(r,5));});expect(transport).toHaveBeenCalledTimes(1);await render('b');await act(async()=>{acknowledge();expect((await result).message).toBe('Listings session changed');});expect(transport).toHaveBeenCalledTimes(2);}finally{opaque.mockRestore();release();}
});
test('host persistence refusal leaves no optimistic recovery reference or dispatch',async()=>{
 const {attachShopStorage}=await import('../../utils/shopStorage.mjs');const release=attachShopStorage({getItem:()=>null,setItem:()=>{},removeItem:()=>{},flush:async()=>{throw Error('Host refused persistence');}});
 transport=jest.fn(async()=>response({ready:true,versionedListings:true,scopeKey:'a'.repeat(64)}));
 try{await render();await act(async()=>{await expect(bound.run('import',{json_url:'http://supplier',xml_url:null})).rejects.toThrow('Host refused');});expect(bound.references.import).toBeUndefined();expect(transport).toHaveBeenCalledTimes(1);}finally{release();}
});
