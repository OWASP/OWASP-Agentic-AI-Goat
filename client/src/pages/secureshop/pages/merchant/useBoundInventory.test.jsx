import React,{act} from 'react';
import {createRoot} from 'react-dom/client';
import {useBoundInventory} from './useBoundInventory';
import {decodeInventoryReference,decodeInventoryProposal,readInventoryReference,
 saveInventoryReference,clearInventoryReference} from './inventoryReference.mjs';
import {compileOperation} from '../../bridge/operations.mjs';
let mockStandalone = false;
jest.mock('../../bridge/assessmentPanelIntent.mjs', () => ({ isStandaloneShopFrame: () => mockStandalone }));
import {attachShopStorage,SHOP_INVENTORY_KEY} from '../../utils/shopStorage.mjs';
const {webcrypto,randomUUID}=require('node:crypto');const {TextEncoder}=require('node:util');
jest.mock('../../bridge/fetchAdapter.mjs',()=>({getBridgeFetchMetadata:()=>({})}));
let root,api,fetcher,release,values,flush;
const response=(value,status=200)=>({ok:status===200,status,json:async()=>value});
function Probe({token,transport}){api=useBoundInventory(token,transport||fetcher);return null;}
const render=(token='merchant',transport)=>act(async()=>root.render(<Probe token={token} transport={transport}/>));
beforeEach(()=>{global.IS_REACT_ACT_ENVIRONMENT=true;mockStandalone=false;global.TextEncoder=TextEncoder;Object.defineProperty(global.crypto,'subtle',{configurable:true,value:webcrypto.subtle});Object.defineProperty(global.crypto,'randomUUID',{configurable:true,value:randomUUID});values=new Map();flush=async()=>{};release=attachShopStorage({getItem:k=>values.get(k)??null,setItem:(k,v)=>values.set(k,v),removeItem:k=>values.delete(k),flush:()=>flush()});root=createRoot(document.createElement('div'));});
afterEach(async()=>{await act(async()=>root.unmount());release();});
const ready=()=>response({ready:true,scopeKey:'a'.repeat(64)});
test('v3 reference is closed and bridge requires exact stockChange field',()=>{
 const reference={version:3,scopeKey:'a'.repeat(64),requestId:randomUUID(),digest:'b'.repeat(64),access:'write',stockChange:{productId:6,quantity:0}};
 expect(decodeInventoryReference(JSON.stringify(reference))).toEqual(reference);
 expect(()=>decodeInventoryReference(JSON.stringify({...reference,stockChange:{productId:6,quantity:-1}}))).toThrow();
 expect(()=>decodeInventoryReference(JSON.stringify({...reference,stockChange:{productId:6,quantity:0,extra:true}}))).toThrow();
 expect(()=>decodeInventoryReference(JSON.stringify({...reference,access:'read'}))).toThrow();
 const body={requestId:reference.requestId,message:'change stock',access:'write',stockChange:reference.stockChange};
 expect(compileOperation('merchant.inventory.run',{body}).body).toEqual(body);
 expect(()=>compileOperation('merchant.inventory.run',{body:{...body,stockChange:undefined}})).toThrow();
 expect(()=>compileOperation('merchant.inventory.run',{body:{requestId:body.requestId,message:body.message,access:body.access}})).toThrow();
});
test('shared inventory confirmation reference requires exact parent ACK and restores failed clear',async()=>{
 const reference={version:3,scopeKey:'a'.repeat(64),requestId:randomUUID(),digest:'b'.repeat(64),
  access:'write',stockChange:{productId:6,quantity:0}};
 let flushes=0;flush=async()=>{if(++flushes===2)throw Error('clear ack lost');};
 await saveInventoryReference(reference);
 expect(readInventoryReference()).toEqual(reference);
 await expect(clearInventoryReference(reference)).rejects.toThrow('clear ack lost');
 expect(readInventoryReference()).toEqual(reference);
 await expect(saveInventoryReference({...reference,requestId:randomUUID()})).rejects.toThrow('Check the saved');
});
test('failed clear ACK after adapter renewal never restores an old ref into the new adapter',async()=>{
 const reference={version:3,scopeKey:'a'.repeat(64),requestId:randomUUID(),digest:'b'.repeat(64),
  access:'write',stockChange:{productId:6,quantity:0}};
 await saveInventoryReference(reference);
 let rejectAck,current=true;
 flush=()=>new Promise((_,reject)=>{rejectAck=reject;});
 const clearing=clearInventoryReference(reference,()=>current);
 expect(rejectAck).toBeDefined();
 release();
 const renewed=new Map();
 release=attachShopStorage({getItem:key=>renewed.get(key)??null,
  setItem:(key,value)=>renewed.set(key,value),removeItem:key=>renewed.delete(key),flush:async()=>{}});
 current=false;
 rejectAck(Error('old removal ACK lost'));
 await expect(clearing).rejects.toThrow('old removal ACK lost');
 expect(renewed.has(SHOP_INVENTORY_KEY)).toBe(false);
});
test('saved inventory proposal requires a closed named product, exact stock tuple and inventory mode',()=>{
 const proposal={version:1,proposalId:randomUUID(),product:{choiceId:randomUUID(),name:'Practice laptop'},
  stockChange:{productId:6,quantity:0},message:'Set its stock to zero',scopeKey:'a'.repeat(64),
  modeCapability:{version:1,featureId:'inventory',policyVersion:'inventory-v1',effectiveMode:'fixed',
   scope:{kind:'launch_feature',id:'inventory'}}};
 expect(decodeInventoryProposal(proposal)).toEqual(proposal);
 expect(()=>decodeInventoryProposal({...proposal,stockChange:{productId:6,quantity:-1}})).toThrow();
 expect(()=>decodeInventoryProposal({...proposal,product:{...proposal.product,email:'secret'}})).toThrow();
 expect(()=>decodeInventoryProposal({...proposal,modeCapability:{...proposal.modeCapability,featureId:'merchant_chat'}})).toThrow();
 expect(()=>decodeInventoryProposal({...proposal,extra:true})).toThrow();
});
test('unready inventory never dispatches',async()=>{fetcher=jest.fn(async()=>response({ready:false}));await render();await expect(api.run('stock')).rejects.toThrow('unavailable');expect(fetcher).toHaveBeenCalledTimes(1);});
test('lost response recovers after remount without storing raw text or repeating POST',async()=>{
 let posts=0;fetcher=jest.fn(async(url,options={})=>{if(url.endsWith('/readiness'))return ready();if(options.method==='POST'){posts++;throw Error('lost');}return response({requestId:url.split('/').pop(),status:'uncertain'});});await render();await act(async()=>{await expect(api.run('private inventory message')).rejects.toThrow('lost');});expect([...values.values()].join('')).not.toContain('private inventory');await act(async()=>root.unmount());root=createRoot(document.createElement('div'));await render();await act(async()=>{expect((await api.recover()).status).toBe('uncertain');await expect(api.run('private inventory message')).rejects.toThrow('Check');});expect(posts).toBe(1);
});
test('not_found explicit retry uses identical UUID and rejects a changed message',async()=>{
 const ids=[];fetcher=jest.fn(async(url,options={})=>{if(url.endsWith('/readiness'))return ready();if(options.method==='GET')return response({requestId:url.split('/').pop(),status:'not_found'});const body=JSON.parse(options.body);ids.push(body.requestId);if(ids.length===1)throw Error('lost');return response({ok:true,status:'completed',requestId:body.requestId,answer:'Done',operations:[]});});await render();await act(async()=>{await expect(api.run('stock')).rejects.toThrow('lost');});await act(async()=>{await api.recover();});await act(async()=>{await expect(api.run('changed')).rejects.toThrow('Check');});await act(async()=>{expect((await api.run('stock')).status).toBe('completed');});expect(ids).toHaveLength(2);expect(ids[0]).toBe(ids[1]);expect(api.reference).toBeNull();expect(values.size).toBe(0);
});
test('task access defaults to read and remains bound to a saved exact retry',async()=>{
 const posts=[];fetcher=jest.fn(async(url,options={})=>{if(url.endsWith('/readiness'))return ready();if(url.endsWith('/history'))return response({ok:true,operations:[]});if(options.method==='GET')return response({requestId:url.split('/').pop(),status:'not_found'});posts.push(JSON.parse(options.body));throw Error('lost');});
 await render();await act(async()=>{await expect(api.run('stock')).rejects.toThrow('lost');});
 expect(posts[0].access).toBe('read');expect(posts[0].stockChange).toBeNull();expect(api.reference.access).toBe('read');expect(api.reference.version).toBe(3);
 await act(async()=>api.recover());
 await act(async()=>{await expect(api.run('stock','write',{productId:6,quantity:0})).rejects.toThrow('Check');});expect(posts).toHaveLength(1);
 await act(async()=>{await expect(api.run('stock','read')).rejects.toThrow('lost');});expect(posts[1]).toEqual(posts[0]);
});
test('legacy references remain recoverable but cannot be resent even after not_found',async()=>{
 const prior={scopeKey:'a'.repeat(64),requestId:randomUUID(),digest:'c'.repeat(64)};values.set('secureshop.inventory.operation.v1',JSON.stringify(prior));
 fetcher=jest.fn(async(url,options={})=>{if(url.endsWith('/readiness'))return ready();if(url.endsWith('/history'))return response({ok:true,operations:[]});if(options.method==='POST')throw Error('Unexpected mutation');return response({requestId:prior.requestId,status:'not_found'});});
 await render();await act(async()=>api.recover());
 await act(async()=>{await expect(api.run('stock','write')).rejects.toThrow('older saved request');});
 expect(JSON.parse(values.get('secureshop.inventory.operation.v1'))).toEqual(prior);
 expect(fetcher.mock.calls.every(([,options])=>options?.method!=='POST')).toBe(true);
});
test('v2 permission reference remains GET-only despite a newly supplied stock tuple',async()=>{
 const prior={scopeKey:'a'.repeat(64),requestId:randomUUID(),digest:'c'.repeat(64),access:'write'};
 values.set('secureshop.inventory.operation.v1',JSON.stringify(prior));
 fetcher=jest.fn(async(url,options={})=>{
  if(url.endsWith('/readiness'))return ready();if(url.endsWith('/history'))return response({ok:true,operations:[]});
  if(options.method==='POST')throw Error('Unexpected mutation');
  return response({requestId:prior.requestId,status:'not_found'});
 });
 await render();await act(async()=>api.recover());
 await act(async()=>{await expect(api.run('stock','write',{productId:6,quantity:0})).rejects.toThrow('older saved request');});
 expect(JSON.parse(values.get('secureshop.inventory.operation.v1'))).toEqual(prior);
 expect(fetcher.mock.calls.every(([,options])=>options?.method!=='POST')).toBe(true);
});
test('explicit write tuple including zero and a foreign product ID is saved before dispatch',async()=>{
 const posts=[];fetcher=jest.fn(async(url,options={})=>{if(url.endsWith('/readiness'))return ready();if(url.endsWith('/history'))return response({ok:true,operations:[]});const body=JSON.parse(options.body);posts.push(body);expect(JSON.parse(values.get('secureshop.inventory.operation.v1')).access).toBe('write');return response({ok:true,status:'completed',requestId:body.requestId,answer:'Saved',operations:[]});});
 await render();await act(async()=>{await expect(api.run('stock','admin')).rejects.toThrow('choose its access');});expect(values.size).toBe(0);
 await act(async()=>{await expect(api.run('stock','write',{productId:0,quantity:0})).rejects.toThrow('Select a catalog product');});expect(values.size).toBe(0);
 await act(async()=>api.run('stock','write',{productId:6,quantity:0}));expect(posts[0].access).toBe('write');expect(posts[0].stockChange).toEqual({productId:6,quantity:0});expect(api.reference).toBeNull();
});
test('v3 saved write retry is same UUID and exact tuple only after protected not_found',async()=>{
 const posts=[];fetcher=jest.fn(async(url,options={})=>{if(url.endsWith('/readiness'))return ready();if(url.endsWith('/history'))return response({ok:true,operations:[]});if(options.method==='GET')return response({requestId:url.split('/').pop(),status:'not_found'});const body=JSON.parse(options.body);posts.push(body);throw Error('lost');});
 await render();await act(async()=>{await expect(api.run('change','write',{productId:6,quantity:0})).rejects.toThrow('lost');});
 const ref=api.reference;expect(ref.version).toBe(3);expect(ref.stockChange).toEqual({productId:6,quantity:0});
 await act(async()=>api.recover());
 await act(async()=>{await expect(api.run('change','write',{productId:6,quantity:1})).rejects.toThrow('Check');});
 await act(async()=>{await expect(api.run('different','write',{productId:6,quantity:0})).rejects.toThrow('Check');});
 expect(posts).toHaveLength(1);
 await act(async()=>{await expect(api.run('change','write',{productId:6,quantity:0})).rejects.toThrow('lost');});
 expect(posts).toHaveLength(2);expect(posts[1]).toEqual(posts[0]);
});
test('persistence failure prevents dispatch and optimistic reference',async()=>{fetcher=jest.fn(async()=>ready());await render();flush=async()=>{throw Error('refused');};await act(async()=>{await expect(api.run('stock')).rejects.toThrow('refused');});expect(fetcher).toHaveBeenCalledTimes(2);expect(api.reference).toBeNull();});
test('a changed parent reference after save acknowledgement prevents inventory POST',async()=>{
 fetcher=jest.fn(async()=>ready());await render();
 flush=async()=>{const saved=JSON.parse(values.get('secureshop.inventory.operation.v1'));
  values.set('secureshop.inventory.operation.v1',JSON.stringify({...saved,requestId:randomUUID()}));};
 await act(async()=>{await expect(api.run('stock')).rejects.toThrow('reference changed');});
 expect(fetcher.mock.calls.filter(([,options])=>options?.method==='POST')).toHaveLength(0);
 expect(api.reference).toBeNull();
});
test('lost removal acknowledgement restores the exact completed inventory reference',async()=>{
 let flushes=0,posts=0;fetcher=jest.fn(async(url,options={})=>{
  if(url.endsWith('/readiness'))return ready();if(url.endsWith('/history'))return response({ok:true,operations:[]});
  if(options.method==='POST'){posts++;const body=JSON.parse(options.body);
   return response({ok:true,status:'completed',requestId:body.requestId,answer:'Saved',operations:[]});}
  throw Error('Unexpected request');
 });
 await render();flush=async()=>{if(++flushes===2)throw Error('clear ack lost');};
 await act(async()=>{await expect(api.run('stock')).rejects.toThrow('clear ack lost');});
 expect(posts).toBe(1);expect(api.reference?.requestId).toBeTruthy();
 expect(decodeInventoryReference(values.get('secureshop.inventory.operation.v1'))).toEqual(api.reference);
 await act(async()=>{await expect(api.run('new stock')).rejects.toThrow('Check the saved request');});
 expect(posts).toBe(1);
});
test('held acknowledgement is fenced by auth change',async()=>{fetcher=jest.fn(async()=>ready());await render();let ack;flush=()=>new Promise(r=>{ack=r;});let result;await act(async()=>{result=api.run('stock').catch(e=>e);await new Promise(r=>setTimeout(r,5));});await render('other');await act(async()=>{ack();expect((await result).message).toContain('session changed');});expect(fetcher).toHaveBeenCalledTimes(4);});
test('held inventory save acknowledgement cannot dispatch through a replaced transport',async()=>{
 fetcher=jest.fn(async()=>ready());await render();let ack;
 flush=()=>new Promise(resolve=>{ack=resolve;});let result;
 await act(async()=>{result=api.run('stock').catch(error=>error);await new Promise(resolve=>setTimeout(resolve,5));});
 const replacement=jest.fn(async()=>ready());await render('merchant',replacement);
 await act(async()=>{ack();expect((await result).message).toContain('session changed');});
 expect(fetcher.mock.calls.filter(([,options])=>options?.method==='POST')).toHaveLength(0);
 expect(replacement.mock.calls.filter(([,options])=>options?.method==='POST')).toHaveLength(0);
});
test('UTF8 byte bound rejects oversized unicode before persistence',async()=>{fetcher=jest.fn(async()=>ready());await render();await act(async()=>{await expect(api.run('界'.repeat(3000))).rejects.toThrow('8192');});expect(values.size).toBe(0);expect(fetcher).toHaveBeenCalledTimes(2);});
test('unavailable grading persists separate retry identity and lost retry response replays after remount without stock POST',async()=>{
 const evaluationId=randomUUID(),calls=[];let lose=true;fetcher=jest.fn(async(url,options={})=>{if(url.endsWith('/readiness'))return ready();const body=JSON.parse(options.body);calls.push({url,...body});if(url.endsWith('/judge-retry')){if(lose){lose=false;throw Error('lost retry');}return response({ok:true,status:'completed',requestId:body.requestId,originalRequestId:body.originalRequestId,grading:{completed:true,status:'evaluated',judgment:{evaluationId:randomUUID(),verdict:'pass',canRetry:false}}});}return response({ok:true,status:'completed',requestId:body.requestId,answer:'Saved',operations:[],grading:{completed:false,status:'evaluated',judgment:{evaluationId,verdict:'unavailable',canRetry:true}}});});
 await render();await act(async()=>{await api.run('stock');});expect(api.reference.evaluationId).toBe(evaluationId);await act(async()=>{await expect(api.retryGrading()).rejects.toThrow('lost retry');});await act(async()=>root.unmount());root=createRoot(document.createElement('div'));await render();await act(async()=>{await api.retryGrading();});expect(calls).toHaveLength(3);expect(calls[1]).toEqual(calls[2]);expect(calls[1].requestId).not.toBe(calls[0].requestId);expect(calls[1].originalRequestId).toBe(calls[0].requestId);expect(api.reference).toBeNull();expect(api.result.grading.completed).toBe(true);
});
test('standalone inventory refuses legacy bound Judge retry after saving stock evidence',async()=>{
 mockStandalone=true;const evaluationId=randomUUID();fetcher=jest.fn(async(url,options={})=>{
  if(url.endsWith('/readiness'))return ready();const body=JSON.parse(options.body);
  return response({ok:true,status:'completed',requestId:body.requestId,answer:'Saved',operations:[],
   grading:{completed:false,status:'evaluated',judgment:{evaluationId,verdict:'unavailable',canRetry:true}}});
 });
 await render();await act(async()=>api.run('stock'));
 await act(async()=>{await expect(api.retryGrading()).rejects.toThrow('Open saved assessments');});
 expect(fetcher.mock.calls.filter(([,options])=>options?.method==='POST')).toHaveLength(1);
});
test('disabled grading retains pending retry reference while terminal expiry clears it',async()=>{
 let code;fetcher=jest.fn(async(url,options={})=>{if(url.endsWith('/readiness'))return ready();const b=JSON.parse(options.body);if(url.endsWith('/judge-retry'))return code?response({code},409):response({ok:true,status:'completed',requestId:b.requestId,originalRequestId:b.originalRequestId,grading:{status:'disabled',completed:false}});return response({ok:true,status:'completed',requestId:b.requestId,answer:'Saved',operations:[],grading:{judgment:{evaluationId:randomUUID(),verdict:'unavailable',canRetry:true}}});});await render();await act(async()=>{await api.run('stock');});const ref=api.reference;await act(async()=>{await api.retryGrading();});expect(api.reference).toEqual(ref);code='EVIDENCE_EXPIRED';await act(async()=>{await expect(api.retryGrading()).rejects.toThrow('no longer available');});expect(api.reference).toBeNull();
});
test('remount recovery accepts canonical child projection instead of recreating stale unavailable retry',async()=>{
 const evaluationId=randomUUID(),childId=randomUUID();let stockId;fetcher=jest.fn(async(url,options={})=>{if(url.endsWith('/readiness'))return ready();if(options.method==='GET')return response({ok:true,status:'completed',requestId:stockId,answer:'Saved',operations:[],grading:{completed:true,status:'evaluated',judgment:{evaluationId:childId,verdict:'pass',canRetry:false}}});const b=JSON.parse(options.body);stockId=b.requestId;return response({ok:true,status:'completed',requestId:stockId,answer:'Saved',operations:[],grading:{judgment:{evaluationId,verdict:'unavailable',canRetry:true}}});});await render();await act(async()=>{await api.run('stock');});await act(async()=>root.unmount());root=createRoot(document.createElement('div'));await render();await act(async()=>{await api.recover();});expect(api.result.grading.judgment.evaluationId).toBe(childId);expect(api.reference).toBeNull();expect(fetcher.mock.calls.filter(([,opts])=>opts?.method==='POST')).toHaveLength(1);
});
test('completed history is read without resending a stock request or changing current result',async()=>{
 const requestId=randomUUID(),recordedAt='2026-10-09T12:00:00.000Z';fetcher=jest.fn(async url=>{
  if(url.endsWith('/readiness'))return ready();
  if(url.endsWith('/history'))return response({ok:true,operations:[{requestId,recordedAt,mode:'vuln',status:'completed'}]});
  if(url.endsWith('/history/'+requestId))return response({ok:true,status:'completed',historical:true,requestId,mode:'vuln',answer:'Saved stock',operations:[]});
  throw Error('Unexpected inventory request');
 });await render();expect(api.history).toEqual([{requestId,recordedAt,mode:'vuln',status:'completed'}]);
 await act(async()=>{expect((await api.readHistory(requestId)).answer).toBe('Saved stock');});
 expect(api.historicalResult.answer).toBe('Saved stock');expect(api.result).toBeNull();expect(fetcher.mock.calls.every(([,options])=>!options?.method||options.method==='GET')).toBe(true);
});
test('a foreign saved request blocks new work until exact historical terminal readback',async()=>{
 const prior={scopeKey:'b'.repeat(64),requestId:randomUUID(),digest:'c'.repeat(64)};values.set('secureshop.inventory.operation.v1',JSON.stringify(prior));let posts=0;
 fetcher=jest.fn(async(url,options={})=>{
  if(url.endsWith('/readiness'))return ready();if(url.endsWith('/history'))return response({ok:true,operations:[]});
  if(url.endsWith('/history/'+prior.requestId))return response({ok:true,status:'completed',historical:true,requestId:prior.requestId,mode:'fixed',answer:'Old result',operations:[]});
  if(options.method==='POST'){posts++;const body=JSON.parse(options.body);return response({ok:true,status:'completed',requestId:body.requestId,answer:'New result',operations:[]});}
  throw Error('Unexpected inventory request');
 });await render();expect(api.foreignReference).toEqual(prior);
 await act(async()=>{await expect(api.run('new stock')).rejects.toThrow('prior-session');});expect(posts).toBe(0);expect(values.size).toBe(1);
 await act(async()=>{await api.readHistory(prior.requestId);});expect(api.foreignReference).toBeNull();expect(values.size).toBe(0);
 await act(async()=>{await api.run('new stock');});expect(posts).toBe(1);
});
test('unavailable historical read retains foreign request and never resends it',async()=>{
 const prior={scopeKey:'b'.repeat(64),requestId:randomUUID(),digest:'c'.repeat(64)};values.set('secureshop.inventory.operation.v1',JSON.stringify(prior));
 fetcher=jest.fn(async url=>url.endsWith('/readiness')?ready():url.endsWith('/history')?response({ok:true,operations:[]}):response({message:'unavailable'},404));await render();
 await act(async()=>{await expect(api.readHistory(prior.requestId)).rejects.toThrow('unavailable');await expect(api.run('new stock')).rejects.toThrow('prior-session');});
 expect(api.foreignReference).toEqual(prior);expect(values.size).toBe(1);expect(fetcher.mock.calls.every(([,options])=>!options?.method||options.method==='GET')).toBe(true);
});
test('historical read never clears a saved reference changed during readback',async()=>{
 const prior={scopeKey:'b'.repeat(64),requestId:randomUUID(),digest:'c'.repeat(64)};values.set('secureshop.inventory.operation.v1',JSON.stringify(prior));let resolveRead;
 fetcher=jest.fn(async url=>url.endsWith('/readiness')?ready():url.endsWith('/history')?response({ok:true,operations:[]}):new Promise(resolve=>{resolveRead=resolve;}));await render();
 let reading;await act(async()=>{reading=api.readHistory(prior.requestId).catch(error=>error);});
 const changed={...prior,evaluationId:randomUUID(),retryRequestId:randomUUID()};values.set('secureshop.inventory.operation.v1',JSON.stringify(changed));
 await act(async()=>{resolveRead(response({ok:true,status:'completed',historical:true,requestId:prior.requestId,mode:'fixed',answer:'Old result',operations:[]}));expect((await reading).message).toContain('changed');});
 expect(JSON.parse(values.get('secureshop.inventory.operation.v1'))).toEqual(changed);expect(api.foreignReference).toEqual(prior);
});
