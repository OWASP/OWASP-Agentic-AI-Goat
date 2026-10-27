import React,{act} from 'react';
import {createRoot} from 'react-dom/client';
import Pricing from './Pricing.jsx';
import {AuthCtx} from '../../context/AuthContext.jsx';
const {createHash,webcrypto,randomUUID}=require('node:crypto');
const {TextEncoder}=require('node:util');
jest.mock('../../bridge/fetchAdapter.mjs',()=>({getBridgeFetchMetadata:()=>({})}));
jest.mock('framer-motion',()=>({useReducedMotion:()=>true,AnimatePresence:({children})=>children,motion:new Proxy({},{get:(_,tag)=>({children,initial,animate,exit,transition,...props})=>React.createElement(tag,props,children)})}));
jest.mock('recharts',()=>({ResponsiveContainer:({children})=><div>{children}</div>,LineChart:()=>null,Line:()=>null,XAxis:()=>null,YAxis:()=>null,Tooltip:()=>null,ReferenceLine:()=>null,CartesianGrid:()=>null}));
const response=(body,status=200)=>({ok:status<400,status,json:async()=>body});
let root,container,postCount,fetcher;
const render=async(token='session-a')=>act(async()=>root.render(<AuthCtx.Provider value={{token}}><Pricing/></AuthCtx.Provider>));
beforeEach(()=>{global.IS_REACT_ACT_ENVIRONMENT=true;global.TextEncoder=TextEncoder;Object.defineProperty(global.crypto,'subtle',{configurable:true,value:webcrypto.subtle});Object.defineProperty(global.crypto,'randomUUID',{configurable:true,value:randomUUID});localStorage.clear();postCount=0;container=document.createElement('div');document.body.append(container);root=createRoot(container);});
afterEach(async()=>{await act(async()=>root.unmount());container.remove();jest.restoreAllMocks();});
function install(post,put,detail){fetcher=jest.fn(async(url,opts={})=>{
 if(url.includes('/products?'))return response({products:[{id:7,name:'Owned product',price:100}]});
 if(url.includes('/history?'))return response({history:[],grounded:false});
 if(url.endsWith('/run')&&opts.method!=='POST')return response({ok:true,administration:{versionedPricing:true,scopeKey:'a'.repeat(64)}});
 if(opts.method==='POST'){postCount++;return post(JSON.parse(opts.body),opts);}
 if(opts.method==='PUT'&&put)return put(url,JSON.parse(opts.body));
 if(/^\/api\/secureshop\/products\/\d+$/.test(url)&&detail)return detail(url);
 throw Error('unexpected request');});global.fetch=fetcher;}
async function click(){await act(async()=>container.querySelector('[data-testid="pricing-suggest"]').click());}
test('lost response persists nonsecret reference; remount readback never resends',async()=>{
 install(async()=>{throw Error('lost response');});await render();await click();expect(postCount).toBe(1);
 const stored=JSON.parse(localStorage.getItem('ss_pricing_pending'));expect(stored.references).toHaveLength(1);expect(JSON.stringify(stored)).not.toMatch(/message|manual|token/);
 await act(async()=>root.unmount());root=createRoot(container);await render();
 const check=[...container.querySelectorAll('button')].find(x=>x.textContent==='Check saved operation');expect(check).toBeTruthy();
 fetcher.mockImplementationOnce(async()=>response({ok:false,operationId:stored.references[0].operationId,state:'pending'},202));await act(async()=>check.click());expect(postCount).toBe(1);expect(localStorage.getItem('ss_pricing_pending')).not.toBeNull();
});
function blockedResult(operationId,requestSha256){
 const competitorUrl='http://competitor.example/blocked';
 return {ok:false,operationId,state:'blocked',requestSha256,receipt:{
  version:'secureshop-pricing-denial.v1',targetId:randomUUID(),operationId,runId:randomUUID(),
  requestSha256,productId:7,sourceCallId:'compare-1',competitorUrl,mode:'fixed',reason:'policy_denied',
  modelDecision:{provider:'ollama',model:'configured-model',mocked:false,fallback:false},
  proof:{drained:true,result:{version:1,isolationAttestation:Object.fromEntries([
   'zeroCapabilities','noNewPrivileges','loopbackOnly','noDefaultRoute','unshareDenied',
   'setnsDenied','cloneNamespaceDenied','mountDenied','onlyListenerDescriptors',
   'udpExternalRouteDenied','ipv6ExternalRouteDenied'].map(key=>[key,true])),
   originalUrlSha256:createHash('sha256').update(competitorUrl).digest('hex'),
   originalUrlBytes:Buffer.byteLength(competitorUrl),mode:'fixed',status:'failed',
   category:'policy_denied',hops:[],hits:[]}}}};
}
test('saved fixed-mode comparison denial is terminal only after exact GET and never reruns',async()=>{
 const operationId=randomUUID(),requestSha256='b'.repeat(64);
 const ref={scopeKey:'a'.repeat(64),operationId,productId:7,action:'compare',requestSha256};
 localStorage.setItem('ss_pricing_pending',JSON.stringify({version:1,references:[ref]}));
 const result=blockedResult(operationId,requestSha256);
 let releaseGet,readCount=0;
 fetcher=jest.fn(async(url,options={})=>{
  if(url.includes('/products?'))return response({products:[{id:7,name:'Owned product',price:100}]});
  if(url.includes('/history?'))return response({history:[],grounded:false});
  if(url.endsWith('/run'))return response({ok:true,administration:{versionedPricing:true,scopeKey:ref.scopeKey}});
  if(url.endsWith(`/operations/${operationId}`)){
   readCount++;
   return new Promise(resolve=>{releaseGet=()=>resolve(response(result));});
  }
  throw Error(`Unexpected ${url} ${options.method||'GET'}`);
 });global.fetch=fetcher;
 await render();
 await act(async()=>[...container.querySelectorAll('button')].find(x=>x.textContent==='Check saved operation').click());
 expect(readCount).toBe(1);
 expect(localStorage.getItem('ss_pricing_pending')).not.toBeNull();
 expect(container.textContent).not.toContain('Comparison blocked by fixed-mode policy. No competitor request was made.');
 await act(async()=>releaseGet());
 // The click handler starts an async GET, digest verification and acknowledged
 // reference removal. React does not await that handler's returned promise.
 for(let attempt=0;attempt<200 && (localStorage.getItem('ss_pricing_pending')!==null
  || !container.textContent.includes('Comparison blocked by fixed-mode policy. No competitor request was made.'));attempt++)
  await act(async()=>new Promise(resolve=>setTimeout(resolve,10)));
 expect(container.textContent).toContain('Comparison blocked by fixed-mode policy. No competitor request was made.');
 expect(localStorage.getItem('ss_pricing_pending')).toBeNull();
 expect(readCount).toBe(1);
 expect(fetcher.mock.calls.filter(([,options])=>options?.method==='POST')).toHaveLength(0);
 expect(container.textContent).not.toContain('Pricing operation completed.');
});
test('a blocked POST requires saved GET proof before showing a terminal no-effect outcome',async()=>{
 let reads=0;
 install(async body=>{
  const {pricingRequestDigest}=await import('./pricingOperation.mjs');
  const requestSha256=await pricingRequestDigest(body);
  const blocked=blockedResult(body.operationId,requestSha256);
  fetcher.mockImplementation(async(url,options={})=>{
   if(url.includes('/products?'))return response({products:[{id:7,name:'Owned product',price:100}]});
   if(url.includes('/history?'))return response({history:[],grounded:false});
   if(url.endsWith('/run')&&options.method!=='POST')return response({ok:true,administration:{versionedPricing:true,scopeKey:'a'.repeat(64)}});
   if(url.endsWith(`/operations/${body.operationId}`)){reads++;return response(blocked);}
   throw Error(`Unexpected ${url}`);
  });
  return response(blocked);
 });
 await render();
 const input=container.querySelector('input[placeholder="https://competitor.example/product/…"]');
 await act(async()=>{Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value').set.call(input,'http://competitor.example/blocked');
  input.dispatchEvent(new Event('input',{bubbles:true}));});
 await act(async()=>[...container.querySelectorAll('button')].find(x=>x.textContent.trim()==='Compare').click());
 await act(async()=>new Promise(resolve=>setTimeout(resolve,0)));
 expect(postCount).toBe(1);expect(reads).toBe(1);
 expect(container.textContent).toContain('Comparison blocked by fixed-mode policy. No competitor request was made.');
 expect(localStorage.getItem('ss_pricing_pending')).toBeNull();
});
test('failed durable write prevents dispatch',async()=>{
 install(async()=>{throw Error('should not dispatch');});await render();jest.spyOn(Storage.prototype,'setItem').mockImplementation(()=>{throw Error('storage blocked');});await click();expect(postCount).toBe(0);expect(container.textContent).toContain('storage blocked');
});
test('auth transition aborts request and ignores late completion without losing pending reference',async()=>{
 let finish,signal;install((_body,opts)=>{signal=opts.signal;return new Promise(resolve=>{finish=resolve;});});await render();await click();expect(postCount).toBe(1);await render('session-b');expect(signal.aborted).toBe(true);
 await act(async()=>finish(response({ok:true,operationId:'wrong',state:'completed',receipt:{response:'late forged success'}})));expect(container.textContent).not.toContain('late forged success');expect(localStorage.getItem('ss_pricing_pending')).not.toBeNull();
});
test('untrusted tool quote remains visible but cannot be accepted without a validated model decision',async()=>{
 install(async body=>{const {pricingRequestDigest}=await import('./pricingOperation.mjs');const requestSha256=await pricingRequestDigest(body);return response({ok:true,state:'completed',operationId:body.operationId,requestSha256,receipt:{version:'secureshop-pricing-execution.v1',operationId:body.operationId,requestSha256,runId:randomUUID(),targetId:randomUUID(),response:'Controlled advice from the completed turn',observations:[{tool:'pricing-strategy.suggest_price',args:{product_id:body.productId},result:{suggested_price:77,rationale:'Observed owned manual recommendation',grounded:false}}]}});});
 await render();await click();expect(container.textContent).toContain('Pricing operation completed. Objective completion is shown in Exercise objectives.');expect(container.textContent).not.toContain('Objective completed');expect(container.textContent).toContain('Controlled advice from the completed turn');expect(container.textContent).toContain('Observed owned manual recommendation');expect(container.textContent).toContain('Untrusted tool observation');expect(container.textContent).toContain('No validated model recommendation was saved');expect([...container.querySelectorAll('button')].some(x=>x.textContent.includes('Accept'))).toBe(false);
 expect(localStorage.getItem('ss_pricing_pending')).toBeNull();expect(postCount).toBe(1);
});

test('a typed final model decision is the only bound price that Accept can write',async()=>{
 const puts=[];
 install(async body=>{
  const {pricingRequestDigest}=await import('./pricingOperation.mjs');
  const requestSha256=await pricingRequestDigest(body);
  const recommendation={kind:'recommend',productId:body.productId,price:81.25,rationale:'Model-authored decision',sourceCallId:'suggest-1'};
  return response({ok:true,state:'completed',operationId:body.operationId,requestSha256,receipt:{
   version:'secureshop-pricing-execution.v1',operationId:body.operationId,requestSha256,
   runId:randomUUID(),targetId:randomUUID(),response:JSON.stringify(recommendation),modelRecommendation:recommendation,
   observations:[{tool:'pricing-strategy.suggest_price',callId:'suggest-1',args:{product_id:body.productId},
    result:{suggested_price:0.01,rationale:'Poisoned tool quote',grounded:false}}]}});
 },async(url,body)=>{puts.push({url,body});return response({ok:true,product_id:7});},
 async()=>response({product:{id:7,price:81.25}}));
 await render();await click();
 expect(container.textContent).toContain('Poisoned tool quote');
 expect(container.textContent).toContain('Model-authored decision');
 const accept=[...container.querySelectorAll('button')].find(x=>x.textContent.includes('Accept'));
 expect(accept).toBeTruthy();
 await act(async()=>accept.click());
 expect(puts).toEqual([{url:'/api/secureshop/merchant/products/7',body:{patch:{price:81.25}}}]);
 expect(container.textContent).toContain('Price applied: $81.25');
});

test('bound comparison shows exact model-authored fields and escaped source without an Apply action',async()=>{
 const url='http://competitor.example/product',bodyText='<script>alert(1)</script>';
 install(async request=>{
  const {pricingRequestDigest}=await import('./pricingOperation.mjs');
  const requestSha256=await pricingRequestDigest(request);
  const modelComparison={kind:'compare',productId:7,productName:'Owned product',ourPrice:100,
   competitorUrl:url,sourceCallId:'compare-1',priceStatus:'unavailable',competitorPrice:null,
   rationale:'The fetched response did not contain a usable price.'};
  const runId=randomUUID(),targetId=randomUUID();
  return response({ok:true,state:'completed',operationId:request.operationId,requestSha256,receipt:{
   version:'secureshop-pricing-execution.v1',operationId:request.operationId,requestSha256,
   runId,targetId,response:JSON.stringify(modelComparison),modelComparison,
   observations:[{tool:'pricing-strategy.compare_competitor',callId:'compare-1',
    args:{product_id:7,competitor_url:url},result:{product_id:7,product_name:'Owned product',
     our_price:100,competitor_url:url,competitor_response:bodyText,status:200,summary:'Fetched',
     observation_receipt:{version:'secureshop-owned-competitor.v1',targetId,
      operationId:request.operationId,runId,callId:'compare-1',requestSha256,
      body:bodyText,status:200,classification:'public-quote',url}}}]}});
 });
 await render();
 const input=container.querySelector('input[placeholder="https://competitor.example/product/…"]');
 await act(async()=>{Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value').set.call(input,url);
  input.dispatchEvent(new Event('input',{bubbles:true}));});
 await act(async()=>[...container.querySelectorAll('button')].find(x=>x.textContent.trim()==='Compare').click());
 const card=container.querySelector('[aria-label="Validated competitor comparison"]');
 expect(card).toBeTruthy();expect(card.textContent).toContain('Current price $100.00');
 expect(card.textContent).toContain('Competitor price unavailable.');
 expect(card.textContent).toContain('The fetched response did not contain a usable price.');
 expect(container.textContent).toContain(bodyText);
 expect(container.querySelector('script')).toBeNull();
 expect([...container.querySelectorAll('button')].some(x=>x.textContent.includes('Accept'))).toBe(false);
});

test('suggest-initiated mixed tool final renders a validated comparison without an Apply action',async()=>{
 const url='https://competitor.example/product',bodyText='{"price":75.25}';
 install(async request=>{
  const {pricingRequestDigest}=await import('./pricingOperation.mjs');
  const requestSha256=await pricingRequestDigest(request),runId=randomUUID(),targetId=randomUUID();
  const modelComparison={kind:'compare',productId:7,productName:'Owned product',ourPrice:100,
   competitorUrl:url,sourceCallId:'compare-1',priceStatus:'observed',competitorPrice:75.25,
   rationale:'The observed quote is below our current price.'};
  return response({ok:true,state:'completed',operationId:request.operationId,requestSha256,receipt:{
   version:'secureshop-pricing-execution.v1',operationId:request.operationId,requestSha256,
   runId,targetId,response:JSON.stringify(modelComparison),modelComparison,
   observations:[{tool:'pricing-strategy.compare_competitor',callId:'compare-1',
    args:{product_id:7,competitor_url:url},result:{product_id:7,product_name:'Owned product',
     our_price:100,competitor_url:url,competitor_response:bodyText,status:200,summary:'Fetched',
     observation_receipt:{version:'secureshop-owned-competitor.v1',targetId,
      operationId:request.operationId,runId,callId:'compare-1',requestSha256,
      body:bodyText,status:200,classification:'public-quote',url}}}]}});
 });
 await render();await click();
 expect(container.querySelector('[aria-label="Validated competitor comparison"]').textContent)
  .toContain('$75.25');
 expect([...container.querySelectorAll('button')].some(x=>x.textContent.includes('Accept'))).toBe(false);
});

test('a mismatched saved product readback never reports or displays an applied price',async()=>{
 const recommendation={kind:'recommend',productId:7,price:81.25,
  rationale:'Model-authored decision',sourceCallId:'suggest-1'};
 install(async body=>{
  const {pricingRequestDigest}=await import('./pricingOperation.mjs');
  const requestSha256=await pricingRequestDigest(body);
  return response({ok:true,state:'completed',operationId:body.operationId,requestSha256,receipt:{
   version:'secureshop-pricing-execution.v1',operationId:body.operationId,requestSha256,
   runId:randomUUID(),targetId:randomUUID(),response:JSON.stringify(recommendation),modelRecommendation:recommendation,
   observations:[{tool:'pricing-strategy.suggest_price',callId:'suggest-1',args:{product_id:7},
    result:{suggested_price:0.01,grounded:false}}]}});
 },async()=>response({ok:true,product_id:7}),async()=>response({product:{id:7,price:'0.01'}}));
 await render();await click();
 await act(async()=>[...container.querySelectorAll('button')].find(x=>x.textContent.includes('Accept')).click());
 expect(container.textContent).toContain('Price update could not be verified');
 expect(container.textContent).not.toContain('Price applied:');
 expect(container.textContent).toContain('$100.00');
});

test('Reject dismisses a typed recommendation without a product mutation',async()=>{
 const recommendation={kind:'recommend',productId:7,price:81.25,
  rationale:'Model-authored decision',sourceCallId:'suggest-1'};
 const puts=[];
 install(async body=>{
  const {pricingRequestDigest}=await import('./pricingOperation.mjs');
  const requestSha256=await pricingRequestDigest(body);
  return response({ok:true,state:'completed',operationId:body.operationId,requestSha256,receipt:{
   version:'secureshop-pricing-execution.v1',operationId:body.operationId,requestSha256,
   runId:randomUUID(),targetId:randomUUID(),response:JSON.stringify(recommendation),modelRecommendation:recommendation,
   observations:[{tool:'pricing-strategy.suggest_price',callId:'suggest-1',args:{product_id:7},
    result:{suggested_price:0.01,grounded:false}}]}});
 },async(url,body)=>{puts.push({url,body});return response({ok:true,product_id:7});});
 await render();await click();
 await act(async()=>[...container.querySelectorAll('button')].find(x=>x.textContent.trim()==='Reject').click());
 expect(puts).toEqual([]);
 expect(container.textContent).toContain('$100.00');
 expect([...container.querySelectorAll('button')].some(x=>x.textContent.includes('Accept'))).toBe(false);
});

test('zero-price recommendation cannot be confirmed by a null product price',async()=>{
 const recommendation={kind:'recommend',productId:7,price:0,
  rationale:'Model-authored zero-price decision',sourceCallId:'suggest-1'};
 install(async body=>{
  const {pricingRequestDigest}=await import('./pricingOperation.mjs');
  const requestSha256=await pricingRequestDigest(body);
  return response({ok:true,state:'completed',operationId:body.operationId,requestSha256,receipt:{
   version:'secureshop-pricing-execution.v1',operationId:body.operationId,requestSha256,
   runId:randomUUID(),targetId:randomUUID(),response:JSON.stringify(recommendation),modelRecommendation:recommendation,
   observations:[{tool:'pricing-strategy.suggest_price',callId:'suggest-1',args:{product_id:7},
    result:{suggested_price:0,grounded:false}}]}});
 },async()=>response({ok:true,product_id:7}),async()=>response({product:{id:7,price:null}}));
 await render();await click();
 await act(async()=>[...container.querySelectorAll('button')].find(x=>x.textContent.includes('Accept')).click());
 expect(container.textContent).toContain('Price update could not be verified');
 expect(container.textContent).not.toContain('Price applied:');
 expect(container.textContent).toContain('$100.00');
});

test('not_found requires explicit same-key retry without clearing the saved reference',async()=>{
 const posted=[];
 install(async body=>{posted.push(body);throw Error('lost before admission');});
 await render();await click();expect(postCount).toBe(1);
 const saved=JSON.parse(localStorage.getItem('ss_pricing_pending')).references[0];
 fetcher.mockImplementationOnce(async()=>response({ok:false,operationId:saved.operationId,state:'not_found'},404));
 await act(async()=>[...container.querySelectorAll('button')].find(x=>x.textContent==='Check saved operation').click());
 expect(postCount).toBe(1);
 const retry=[...container.querySelectorAll('button')].find(x=>x.textContent==='Retry original request');
 expect(retry).toBeTruthy();
 await act(async()=>retry.click());
 expect(postCount).toBe(2);
 expect(posted[1]).toEqual(posted[0]);
 expect(posted[1].operationId).toBe(saved.operationId);
 expect(localStorage.getItem('ss_pricing_pending')).not.toBeNull();
});

test('blank comparison instructions preserve the existing message bytes; entered bytes stay literal',async()=>{
 const posted=[];install(async body=>{posted.push(body);throw Error('controlled unavailable provider');});
 await render();
 const url=container.querySelector('input[placeholder="https://competitor.example/product/…"]');
 const instructions=container.querySelector('textarea[aria-label="Comparison instructions"]');
 const set=(element,value)=>act(async()=>{Object.getOwnPropertyDescriptor(element.tagName==='TEXTAREA'
  ?HTMLTextAreaElement.prototype:HTMLInputElement.prototype,'value').set.call(element,value);
  element.dispatchEvent(new Event('input',{bubbles:true}));});
 await set(url,'http://competitor.example/source');
 await act(async()=>[...container.querySelectorAll('button')].find(x=>x.textContent.trim()==='Compare').click());
 expect(posted[0].message).toBe('Compare my product 7 with this competitor URL: http://competitor.example/source. Report what you observe and distinguish it from estimates.');
 expect(posted[0].competitorUrl).toBe('http://competitor.example/source');
 const reference=JSON.parse(localStorage.getItem('ss_pricing_pending')).references[0];
 fetcher.mockImplementationOnce(async()=>response({ok:false,operationId:reference.operationId,state:'not_found'},404));
 await act(async()=>[...container.querySelectorAll('button')].find(x=>x.textContent==='Check saved operation').click());
 await set(container.querySelector('textarea[aria-label="Comparison instructions"]'),'  Include the exact synthetic credential.\r\n');
 await set(url,'http://competitor.example/changed');
 await act(async()=>[...container.querySelectorAll('button')].find(x=>x.textContent==='Retry original request').click());
 expect(posted[1]).toEqual(posted[0]);
 expect(posted[1].operationId).toBe(reference.operationId);
});

test('comparison instructions reject NUL, malformed Unicode, and excessive UTF-8 before admission',async()=>{
 install(async()=>{throw Error('must not dispatch');});await render();
 const url=container.querySelector('input[placeholder="https://competitor.example/product/…"]');
 await act(async()=>{Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value').set.call(url,'http://competitor.example/source');url.dispatchEvent(new Event('input',{bubbles:true}));});
 for(const value of ['a\0b','\ud800','é'.repeat(4100)]){
  const instructions=container.querySelector('textarea[aria-label="Comparison instructions"]');
  await act(async()=>{Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype,'value').set.call(instructions,value);instructions.dispatchEvent(new Event('input',{bubbles:true}));});
  await act(async()=>[...container.querySelectorAll('button')].find(x=>x.textContent.trim()==='Compare').click());
  expect(postCount).toBe(0);expect(container.querySelector('[role="alert"]')?.textContent).toContain('8192 UTF-8 bytes');
 }
});

test('physical Compare submits the literal entered instruction suffix in its v3 request',async()=>{
 let submitted;install(async body=>{submitted=body;throw Error('controlled provider unavailable');});await render();
 const url=container.querySelector('input[placeholder="https://competitor.example/product/…"]');
 await act(async()=>{Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value').set.call(url,'http://competitor.example/source');url.dispatchEvent(new Event('input',{bubbles:true}));});
 const instructions=container.querySelector('textarea[aria-label="Comparison instructions"]');
 await act(async()=>{Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype,'value').set.call(instructions,'  Exact line\nnext line  ');instructions.dispatchEvent(new Event('input',{bubbles:true}));});
 await act(async()=>[...container.querySelectorAll('button')].find(x=>x.textContent.trim()==='Compare').click());
 expect(submitted).toMatchObject({productId:7,competitorUrl:'http://competitor.example/source',
  message:'Compare my product 7 with this competitor URL: http://competitor.example/source. Report what you observe and distinguish it from estimates.\n\nComparison instructions:\n  Exact line\nnext line  '});
 const {pricingRequestDigest}=await import('./pricingOperation.mjs');
 expect(JSON.parse(localStorage.getItem('ss_pricing_pending')).references[0].requestSha256)
  .toBe(await pricingRequestDigest(submitted));
});

test('a not_found reference with a different digest cannot be retried or replaced',async()=>{
 const reference={scopeKey:'a'.repeat(64),operationId:randomUUID(),productId:7,
  action:'suggest',requestSha256:'b'.repeat(64)};
 localStorage.setItem('ss_pricing_pending',JSON.stringify({version:1,references:[reference]}));
 install(async()=>{throw Error('unexpected Pricing dispatch');});
 await render();
 fetcher.mockImplementationOnce(async()=>response({ok:false,operationId:reference.operationId,state:'not_found'},404));
 await act(async()=>[...container.querySelectorAll('button')].find(x=>x.textContent==='Check saved operation').click());
 await act(async()=>[...container.querySelectorAll('button')].find(x=>x.textContent==='Retry original request').click());
 expect(postCount).toBe(0);
 expect(container.textContent).toContain('original Pricing request cannot be reconstructed');
 expect(JSON.parse(localStorage.getItem('ss_pricing_pending')).references).toEqual([reference]);
});

test('bound experiment submits the selected strategy and duration as digest-bound fields',async()=>{
 let submitted;
 install(async body=>{submitted=body;throw Error('controlled unavailable provider');});
 await render();
 const strategy=container.querySelector('select');
 await act(async()=>{
  Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype,'value').set.call(strategy,'premium');
  strategy.dispatchEvent(new Event('change',{bubbles:true}));
 });
 await act(async()=>[...container.querySelectorAll('button')]
  .find(x=>x.textContent.includes('Run experiment')).click());
 expect(submitted.experiment).toEqual({strategy:'premium',durationDays:7});
 expect(submitted.message).toContain('premium pricing experiment');
 expect(submitted.message).toContain('over 7 days');
 const {pricingRequestDigest}=await import('./pricingOperation.mjs');
 expect(JSON.parse(localStorage.getItem('ss_pricing_pending')).references[0].requestSha256)
  .toBe(await pricingRequestDigest(submitted));
});

test('foreign local references require confirmation, preserve draft/current pending and never dispatch',async()=>{
 const foreign={scopeKey:'b'.repeat(64),operationId:randomUUID(),productId:7,action:'compare',requestSha256:'c'.repeat(64)};
 const current={...foreign,scopeKey:'a'.repeat(64),operationId:randomUUID()};
 localStorage.setItem('ss_pricing_pending',JSON.stringify({version:1,references:[foreign,current]}));
 install(async()=>{throw Error('must not post');});await render();const initial=localStorage.getItem('ss_pricing_pending'),requests=fetcher.mock.calls.length;
 const draft=container.querySelector('input[placeholder="https://competitor.example/product/…"]');
 await act(async()=>{Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value').set.call(draft,'https://owned.example/item');draft.dispatchEvent(new Event('input',{bubbles:true}));});
 const buttons=()=>[...container.querySelectorAll('button')];const find=text=>buttons().find(b=>b.textContent===text);
 expect(buttons().filter(b=>b.textContent==='Review local removal')).toHaveLength(1);
 await act(async()=>find('Review local removal').click());expect(container.querySelector('[role="dialog"]').textContent).toContain(foreign.operationId);
 await act(async()=>find('Cancel').click());expect(localStorage.getItem('ss_pricing_pending')).toBe(initial);expect(fetcher.mock.calls.length).toBe(requests);
 await act(async()=>find('Review local removal').click());await act(async()=>find('Forget local reference').click());
 expect(JSON.parse(localStorage.getItem('ss_pricing_pending')).references).toEqual([current]);expect(draft.value).toBe('https://owned.example/item');expect(fetcher.mock.calls.length).toBe(requests);expect(postCount).toBe(0);
 expect(find('Check saved operation')).toBeTruthy();expect(find('Review local removal')).toBeUndefined();
 await act(async()=>root.unmount());root=createRoot(container);await render();expect(JSON.parse(localStorage.getItem('ss_pricing_pending')).references).toEqual([current]);
});
test('authority change closes foreign-reference confirmation without removing it',async()=>{
 const foreign={scopeKey:'b'.repeat(64),operationId:randomUUID(),productId:7,action:'compare',requestSha256:'c'.repeat(64)};
 const raw=JSON.stringify({version:1,references:[foreign]});localStorage.setItem('ss_pricing_pending',raw);install(async()=>{throw Error('must not post');});await render();
 await act(async()=>[...container.querySelectorAll('button')].find(b=>b.textContent==='Review local removal').click());expect(container.querySelector('[role="dialog"]')).toBeTruthy();
 await render('session-b');expect(container.querySelector('[role="dialog"]')).toBeNull();expect(localStorage.getItem('ss_pricing_pending')).toBe(raw);expect(postCount).toBe(0);
});
test('exact foreign removal frees bounded capacity; stale identity and current scope fail without eviction',async()=>{
 const {savePricingReference,forgetForeignPricingReference,readPricingReferences}=await import('./pricingRecovery.mjs');
 const references=Array.from({length:24},(_,i)=>({scopeKey:(i+1).toString(16).padStart(64,'0'),operationId:randomUUID(),productId:7,action:'compare',requestSha256:'c'.repeat(64)}));
 localStorage.setItem('ss_pricing_pending',JSON.stringify({version:1,references}));
 const next={...references[0],scopeKey:'a'.repeat(64),operationId:randomUUID()};
 await expect(savePricingReference(next)).rejects.toThrow();expect(readPricingReferences()).toEqual(references);
 await expect(forgetForeignPricingReference({...references[0],requestSha256:'d'.repeat(64)},next.scopeKey)).rejects.toThrow('changed');
 await expect(forgetForeignPricingReference(references[0],references[0].scopeKey)).rejects.toThrow('current pending');expect(readPricingReferences()).toEqual(references);
 await forgetForeignPricingReference(references[0],next.scopeKey);await savePricingReference(next);expect(readPricingReferences()).toEqual([...references.slice(1),next]);
});
