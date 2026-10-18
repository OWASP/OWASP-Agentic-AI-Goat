import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import { webcrypto } from 'node:crypto';
import useBoundAnalytics from './useBoundAnalytics';
const scopeKey='a'.repeat(64),id='11111111-1111-4111-8111-111111111111';
const response=body=>({ok:true,json:async()=>body});
let node,root,api;
function Harness({transport,token='persona'}){api=useBoundAnalytics({bound:true,token,transport});return null;}
beforeEach(()=>{localStorage.clear();Object.defineProperty(global.crypto,'randomUUID',{configurable:true,value:webcrypto.randomUUID.bind(webcrypto)});global.IS_REACT_ACT_ENVIRONMENT=true;node=document.createElement('div');document.body.append(node);root=createRoot(node);});
afterEach(async()=>{await act(async()=>root.unmount());node.remove();jest.restoreAllMocks();});
const defaults=url=>response(url.endsWith('/analytics')?{ok:true,analytics:{capability:'secureshop-owned-analytics.v1',scopeKey}}:{entries:[],nextCursor:null});
test('lost POST saves only metadata, blocks redispatch, and reload uses GET only',async()=>{
 const transport=jest.fn(async(url,options)=>{
  if(options.method==='POST'){const stored=JSON.parse(localStorage.getItem('ss_analytics_recovery'));expect(stored.references[0].operationId).toBe(JSON.parse(options.body).requestId);throw Error('lost response');}
  if(url.includes('/requests/'))return response({status:'uncertain',question:'count products',requestId:url.split('/').at(-1),sessionId:id});
  return defaults(url);
 });
 await act(async()=>root.render(<Harness transport={transport}/>));
 await act(async()=>{await expect(api.submit('count products')).rejects.toThrow('lost response');});
 expect(localStorage.getItem('ss_analytics_recovery')).not.toContain('count products');
 await act(async()=>{await expect(api.submit('count products')).rejects.toThrow('saved query');});
 await act(async()=>root.unmount());root=createRoot(node);
 await act(async()=>root.render(<Harness transport={transport}/>));
 expect(transport.mock.calls.filter(([,options])=>options.method==='POST')).toHaveLength(1);
 expect(transport.mock.calls.some(([url])=>url.includes('/requests/'))).toBe(true);
 expect(api.notice).toContain('unverified');
});
test('storage failure prevents POST admission',async()=>{
 const transport=jest.fn(async url=>defaults(url));
 await act(async()=>root.render(<Harness transport={transport}/>));
 jest.spyOn(Storage.prototype,'setItem').mockImplementation(()=>{throw Error('quota');});
 await act(async()=>{await expect(api.submit('count products')).rejects.toThrow('quota');});
 expect(transport.mock.calls.some(([,options])=>options.method==='POST')).toBe(false);
});
test('new persona scope does not recover a prior session reference',async()=>{
 localStorage.setItem('ss_analytics_recovery',JSON.stringify({version:1,references:[{scopeKey:'b'.repeat(64),operationId:id,state:'unknown'}]}));
 const transport=jest.fn(async url=>defaults(url));await act(async()=>root.render(<Harness transport={transport}/>));
 expect(transport.mock.calls.some(([url])=>url.includes('/requests/'))).toBe(false);
 expect(api.references).toHaveLength(1);
});
function completed(requestId,question='count products') {
 const sessionId=id,runId='33333333-3333-4333-8333-333333333333';
 const query={sql:'SELECT COUNT(*) FROM products',columns:['count'],rows:[{count:'256'}],row_count:1,error:null};
 return {status:'completed',ok:true,question,requestId,sessionId,runId,answer:'256',provider:'ollama',model:'llama3.1:8b',...query,
  receipt:{requestId,sessionId,runId,result:query},effectReceipt:{status:'completed',runId}};
}
test('confirmed saved result clears only its reference and returns the original model answer',async()=>{
 localStorage.setItem('ss_analytics_recovery',JSON.stringify({version:1,references:[{scopeKey,operationId:id,state:'unknown'}]}));
 const transport=jest.fn(async url=>url.includes('/requests/')?response(completed(id)):defaults(url));
 await act(async()=>root.render(<Harness transport={transport}/>));
 expect(api.recovered.answer).toBe('256');expect(api.references).toHaveLength(0);
 expect(localStorage.getItem('ss_analytics_recovery')).toBeNull();
 expect(transport.mock.calls.some(([,options])=>options.method==='POST')).toBe(false);
});
test('selects an older listed result by protected GET without redispatch or a typed ID', async () => {
 const olderId='44444444-4444-4444-8444-444444444444';
 const newest={...completed(id,'newer question'),createdAt:'2026-10-11T12:00:00.000000Z'};
 const older={...completed(olderId,'older question'),createdAt:'2026-10-10T12:00:00.000000Z'};
 const transport=jest.fn(async url=>url.endsWith('/analytics')?response({ok:true,analytics:{capability:'secureshop-owned-analytics.v1',scopeKey}})
   :url.includes('/history?limit=20&cursor=')?response({entries:[older],nextCursor:null})
   :url.includes('/history?')?response({entries:[newest],nextCursor:'older-page'})
   :url.endsWith('/requests/'+olderId)?response(completed(olderId,'older question'))
   :response({error:'unexpected'}));
 await act(async()=>root.render(<Harness transport={transport}/>));
 expect(api.entries).toHaveLength(1);
 await act(async()=>api.loadMore());
 expect(api.entries).toHaveLength(2);
 await act(async()=>{expect(await api.selectHistory(olderId)).toBe(true);});
 expect(api.selected.question).toBe('older question');
 expect(transport.mock.calls.filter(([url])=>url.endsWith('/requests/'+olderId))).toHaveLength(1);
 expect(transport.mock.calls.some(([,options])=>options?.method==='POST')).toBe(false);
 await act(async()=>{expect(await api.selectHistory('55555555-5555-4555-8555-555555555555')).toBe(false);});
 expect(transport.mock.calls.filter(([url])=>url.includes('/requests/'))).toHaveLength(1);
});
test('a mismatched or late saved read cannot replace history after persona change', async () => {
 const listed={...completed(id),createdAt:'2026-10-11T12:00:00.000000Z'};
 let release;
 const transport=jest.fn(async url=>url.endsWith('/analytics')?response({ok:true,analytics:{capability:'secureshop-owned-analytics.v1',scopeKey}})
   :url.includes('/history')?response({entries:[listed],nextCursor:null})
   :url.includes('/requests/')?new Promise(resolve=>{release=resolve;})
   :response({error:'unexpected'}));
 await act(async()=>root.render(<Harness transport={transport}/>));
 let selected;
 await act(async()=>{selected=api.selectHistory(id);});
 await act(async()=>root.render(<Harness transport={transport} token="another-persona"/>));
 await act(async()=>{release(response(completed(id)));expect(await selected).toBe(false);});
 expect(api.selected).toBeNull();
 expect(transport.mock.calls.some(([,options])=>options?.method==='POST')).toBe(false);
});
test('an exact GET with changed saved row content is not presented as the listed history', async () => {
 const listed={...completed(id),createdAt:'2026-10-11T12:00:00.000000Z'};
 const changed=completed(id);
 changed.rows=[{count:'999'}];
 changed.receipt.result={...changed.receipt.result,rows:[{count:'999'}]};
 const transport=jest.fn(async url=>url.endsWith('/analytics')?response({ok:true,analytics:{capability:'secureshop-owned-analytics.v1',scopeKey}})
   :url.includes('/history')?response({entries:[listed],nextCursor:null})
   :url.includes('/requests/')?response(changed):response({error:'unexpected'}));
 await act(async()=>root.render(<Harness transport={transport}/>));
 await act(async()=>{expect(await api.selectHistory(id)).toBe(false);});
 expect(api.selected).toBeNull();
 expect(api.notice).toBe('Saved Analytics history changed');
 expect(transport.mock.calls.some(([,options])=>options?.method==='POST')).toBe(false);
});
test('mismatched query receipt stays unknown and cannot erase the saved reference',async()=>{
 localStorage.setItem('ss_analytics_recovery',JSON.stringify({version:1,references:[{scopeKey,operationId:id,state:'unknown'}]}));
 const forged=completed(id);forged.rows=[{count:'999'}];
 const transport=jest.fn(async url=>url.includes('/requests/')?response(forged):defaults(url));
 await act(async()=>root.render(<Harness transport={transport}/>));
 expect(api.recovered).toBeNull();expect(api.notice).toBe('Invalid Analytics response');
 expect(JSON.parse(localStorage.getItem('ss_analytics_recovery')).references).toHaveLength(1);
});
function denied(requestId,question='count products') {
 const value=completed(requestId,question);
 const query={sql:'SELECT api_key FROM shop_users',columns:[],rows:[],row_count:0,error:'Database permission denied (42501).'};
 return {...value,...query,status:'denied',ok:false,responseSource:'server',answer:null,provider:null,model:null,
  receipt:{...value.receipt,version:4,mode:{mode:'fixed'},result:query,denial:{code:'42501',source:'postgresql',backendAbsent:true},protectedEvidence:{version:1,observations:[],truncated:false}}};
}
test('confirmed permission denial is terminal and allows a subsequent query',async()=>{
 const transport=jest.fn(async(url,options)=>options.method==='POST'?response(denied(JSON.parse(options.body).requestId,JSON.parse(options.body).question)):defaults(url));
 await act(async()=>root.render(<Harness transport={transport}/>));
 await act(async()=>{expect((await api.submit('read private keys')).status).toBe('denied');});
 expect(api.references).toHaveLength(0);expect(localStorage.getItem('ss_analytics_recovery')).toBeNull();
 await act(async()=>{expect((await api.submit('count products')).status).toBe('denied');});
 expect(transport.mock.calls.filter(([,options])=>options.method==='POST')).toHaveLength(2);
});
test('lost denial response recovers via GET and clears reference without redispatch',async()=>{
 localStorage.setItem('ss_analytics_recovery',JSON.stringify({version:1,references:[{scopeKey,operationId:id,state:'unknown'}]}));
 const transport=jest.fn(async url=>url.includes('/requests/')?response(denied(id)):defaults(url));
 await act(async()=>root.render(<Harness transport={transport}/>));
 expect(api.recovered.status).toBe('denied');expect(api.recovered.answer).toBeNull();expect(api.references).toHaveLength(0);
 expect(transport.mock.calls.some(([,options])=>options.method==='POST')).toBe(false);
});
test.each(['backend','rows','model','mode','receiptError'])('invalid denial %s preserves recovery reference',async(kind)=>{
 localStorage.setItem('ss_analytics_recovery',JSON.stringify({version:1,references:[{scopeKey,operationId:id,state:'unknown'}]}));
 const value=denied(id);
 if(kind==='backend')value.receipt.denial.backendAbsent=false;
 if(kind==='rows')value.rows=[{api_key:'not-a-denial'}];
 if(kind==='model')value.answer='fabricated model answer';
 if(kind==='mode')value.receipt.mode.mode='vuln';
 if(kind==='receiptError')value.receipt.result={...value.receipt.result,error:null};
 const transport=jest.fn(async url=>url.includes('/requests/')?response(value):defaults(url));
 await act(async()=>root.render(<Harness transport={transport}/>));
 expect(api.recovered).toBeNull();expect(api.notice).toBe('Invalid Analytics response');expect(api.references).toHaveLength(1);
});
