'use strict';
// Controlled React/jsdom state tests of current modules. No browser/provider or qualification.
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),Module=require('node:module');
const ROOT=path.resolve(__dirname,'..'),clientRequire=Module.createRequire(path.join(ROOT,'client/package.json'));
const swc=clientRequire('@swc/core'),{JSDOM}=clientRequire('jsdom');
const dom=new JSDOM('<html><body></body></html>',{url:'https://owned.invalid'});
global.window=dom.window;global.document=dom.window.document;global.HTMLElement=dom.window.HTMLElement;global.IS_REACT_ACT_ENVIRONMENT=true;
const React=clientRequire('react'),{createRoot}=clientRequire('react-dom/client');
const KEY='secureshop.product-summary.operations.v1',rawStorage=new Map();
const fakeStorage={getItem:key=>rawStorage.get(key)||null,setItem:(key,value)=>rawStorage.set(key,value)};
function compile(name,overrides={}){
 const mod={exports:{}};const text=fs.readFileSync(path.join(ROOT,name),'utf8');
 const code=swc.transformSync(text,{jsc:{parser:{syntax:'ecmascript',jsx:true},target:'es2022'},module:{type:'commonjs'}}).code;
 const requireValue=spec=>Object.hasOwn(overrides,spec)?overrides[spec]:spec==='react'?React:Module.createRequire(path.join(ROOT,name))(spec);
 Function('require','module','exports',code)(requireValue,mod,mod.exports);return mod.exports;
}
const references=compile('client/src/pages/secureshop/utils/productSummaryReference.mjs',{'./shopStorage.mjs':{SHOP_PRODUCT_SUMMARY_KEY:KEY,shopStorage:fakeStorage,flushShopStorage:async()=>{}}});
const hook=compile('client/src/pages/secureshop/hooks/useProductSummary.js',{
 '../utils/productSummaryReference.mjs':references,
 '../utils/turnModeCapability.mjs':compile('client/src/pages/secureshop/utils/turnModeCapability.mjs')});
const sessionId='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',requestId='bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const recoveryKey='a'.repeat(64);
const ref=(productId=7)=>({version:2,recoveryKey,shopUserId:12,productId,sessionId,requestId,startedAt:123});
const response=(body,status=200)=>({status,ok:status<400,headers:{get:()=> 'application/json'},json:async()=>body});
const complete=(r,text='Original summary')=>({status:'completed',result:{product_id:r.productId,name:'Owned',price:10,stock_quantity:1,category:'Home',description:'Raw product',description_html:null,summary:text,provider:'ollama',model:'controlled',sessionId:r.sessionId,requestId:r.requestId}});
const flush=()=>React.act(async()=>{await new Promise(resolve=>setImmediate(resolve));});
async function mount(options,strict=false){
 let state;const history=[];const element=document.createElement('div');document.body.append(element);const root=createRoot(element);
 function Harness(props){state=hook.useProductSummary(props);history.push({props:{...props},summary:state.summary});return React.createElement('div',null,state.summary?.summary||state.error||'');}
 const render=async props=>{await React.act(async()=>root.render(strict?React.createElement(React.StrictMode,null,React.createElement(Harness,props)):React.createElement(Harness,props)));await flush();};
 await render(options);return{get state(){return state;},history,element,render,unmount:async()=>{await React.act(async()=>root.unmount());element.remove();}};
}
test('summary references keep products separate and reject semantic data, duplicates, overwrite and nondurable storage',async()=>{
 rawStorage.clear();const store=references.productSummaryReferenceStore;
 await store.save(ref());await store.save({...ref(8),requestId:'cccccccc-cccc-4ccc-8ccc-cccccccccccc'});
 assert.equal(store.read(12,7,recoveryKey).productId,7);assert.equal(store.read(12,8,recoveryKey).productId,8);assert.equal(store.read(13,7,recoveryKey),null);
 await assert.rejects(store.save(ref()));
 assert.throws(()=>references.decodeProductSummaryReferences(JSON.stringify({version:1,entries:[{...ref(),summary:'forged'}]})));
 const failed=references.createProductSummaryReferenceStore({storage:{getItem:()=>null,setItem(){}},flush:async()=>{}});await assert.rejects(failed.save(ref()));
});
test('StrictMode admits one summary POST; lost ACK and remount use saved GET without rerun',async()=>{
 rawStorage.clear();const calls=[];let saved;
 const transport=async(url,options)=>{calls.push([url,options.method]);
  if(url.endsWith('/session'))return response({sessionId,recoveryKey});
  if(options.method==='POST'){saved={...ref(),...JSON.parse(options.body)};throw Error('lost ACK');}
  return response(complete(saved));};
 const props={productId:'7',shopUserId:12,authorityKey:'owned',transport};
 let mounted=await mount(props,true);assert.equal(mounted.state.summary.summary,'Original summary');
 assert.equal(calls.filter(([url,method])=>method==='POST'&&url.endsWith('/summary')).length,1);await mounted.unmount();
 mounted=await mount(props,true);assert.equal(mounted.state.summary.summary,'Original summary');
 assert.equal(calls.filter(([url,method])=>method==='POST'&&url.endsWith('/summary')).length,1);await mounted.unmount();
});
test('guest makes no requests; failed reference custody prevents model POST',async()=>{
 rawStorage.clear();let calls=0;let mounted=await mount({productId:'7',shopUserId:null,transport:async()=>{calls++;throw Error('guest');}});assert.equal(calls,0);await mounted.unmount();
 const transport=async()=>{calls++;return response({sessionId,recoveryKey});};
 mounted=await mount({productId:'7',shopUserId:12,transport,referenceStore:{read:()=>null,save:async()=>{throw Error('offline');}}});
 assert.equal(calls,1);assert.equal(mounted.state.summary,null);await mounted.unmount();
});
test('pending saved request and explicit check are GET-only; malformed response cannot publish',async()=>{
 rawStorage.clear();await references.productSummaryReferenceStore.save(ref());let calls=0,bad=false;
 const transport=async(_url,options)=>{if(_url.endsWith('/session'))return response({sessionId,recoveryKey});assert.equal(options.method,'GET');calls++;return response(bad?complete({...ref(),productId:9}):{status:'pending',sessionId,requestId},202);};
 const mounted=await mount({productId:'7',shopUserId:12,transport});assert.equal(mounted.state.status,'pending');
 bad=true;await React.act(async()=>mounted.state.check());assert.equal(calls,2);assert.equal(mounted.state.summary,null);await mounted.unmount();
});
test('changed product aborts old source and suppresses late summary without sharing operation identity',async()=>{
 rawStorage.clear();let finish,oldSignal;const saved=new Map();
 const transport=async(url,options)=>{const productId=Number(url.split('/products/')[1].split('/')[0]);
  if(url.endsWith('/session'))return response({sessionId,recoveryKey});
  if(options.method==='POST'){saved.set(productId,{...ref(productId),...JSON.parse(options.body)});if(productId===7){oldSignal=options.signal;await new Promise(resolve=>{finish=resolve;});}return response({});}
  return response(complete(saved.get(productId),`Summary ${productId}`));};
 const props={productId:'7',shopUserId:12,transport};const mounted=await mount(props);await mounted.render({...props,productId:'8'});
 assert.equal(oldSignal.aborted,true);assert.equal(mounted.state.summary.summary,'Summary 8');
 await React.act(async()=>finish());await flush();assert.equal(mounted.state.summary.summary,'Summary 8');assert.equal(references.productSummaryReferenceStore.read(12,7,recoveryKey).productId,7);await mounted.unmount();
});

test('confirmed not-found recovery rechecks absence and resubmits only the saved IDs',async()=>{
 rawStorage.clear();await references.productSummaryReferenceStore.save(ref());const calls=[];let posted=false;
 const transport=async(url,options)=>{if(url.endsWith('/session'))return response({sessionId,recoveryKey});calls.push([url,options]);
  if(url.includes('/product-summary/assessment'))return response({completed:false,status:'ineligible',modelEvaluated:false});
  if(options.method==='POST'){assert.deepEqual(JSON.parse(options.body),{sessionId,requestId});posted=true;return response({});}
  return response(posted?complete(ref()):{status:'not_found',sessionId,requestId},posted?200:404);};
 const mounted=await mount({productId:'7',shopUserId:12,transport});assert.equal(mounted.state.status,'not_found');assert.equal(posted,false);
 await React.act(async()=>mounted.state.retryNotFound());
 assert.equal(mounted.state.summary.summary,'Original summary');assert.equal(calls.filter(([,o])=>o.method==='POST').length,1);
 assert.deepEqual(calls.slice(0,3).map(([,o])=>o.method),['GET','GET','POST']);await mounted.unmount();
});
test('negative and unavailable assessment retain the original ordinary summary and never imply credit',async()=>{
 for(const outcome of [{completed:false,judgment:{evaluationId:requestId,verdict:'fail',canRetry:false},replayed:true},null]){
  rawStorage.clear();await references.productSummaryReferenceStore.save(ref());
  const transport=async(url,options)=>{if(url.endsWith('/session'))return response({sessionId,recoveryKey});assert.equal(options.method,'GET');
   if(url.includes('/product-summary/assessment')){if(!outcome)throw Error('unavailable');return response(outcome);}
   return response(complete(ref()));};
  const mounted=await mount({productId:'7',shopUserId:12,transport});assert.equal(mounted.state.summary.summary,'Original summary');
  assert.equal(mounted.state.assessment.completed,false);assert.equal(mounted.state.assessment.judgment?.verdict||mounted.state.assessment.status,outcome?'fail':'unavailable');await mounted.unmount();
 }
});
test('summary reference capacity refuses overflow without erasing any unresolved operation',async()=>{
 rawStorage.clear();const store=references.productSummaryReferenceStore;
 for(let i=1;i<=32;i++)await store.save({...ref(i),requestId:`bbbbbbbb-bbbb-4bbb-8bbb-${String(i).padStart(12,'0')}`});
 const before=rawStorage.get(KEY);await assert.rejects(store.save({...ref(33),requestId:'cccccccc-cccc-4ccc-8ccc-cccccccccccc'}));assert.equal(rawStorage.get(KEY),before);
});

test('a changed authority masks old summary during the render before the reset effect',async()=>{
 rawStorage.clear();await references.productSummaryReferenceStore.save(ref());let deny=false;
 const transport=async(url)=>{if(deny)return response({error:'revoked'},401);if(url.endsWith('/session'))return response({sessionId,recoveryKey});
  return response(url.includes('/product-summary/assessment')?{completed:false,status:'ineligible',modelEvaluated:false}:complete(ref()));};
 const props={productId:'7',shopUserId:12,authorityKey:'old',transport};const mounted=await mount(props);assert.equal(mounted.state.summary.summary,'Original summary');
 deny=true;await mounted.render({...props,authorityKey:'new'});
 assert.ok(mounted.history.filter(row=>row.props.authorityKey==='new').every(row=>row.summary===null));await mounted.unmount();
});

test('full recovery storage is reported honestly and does not dispatch a summary run',async()=>{
 rawStorage.clear();const store=references.productSummaryReferenceStore;
 for(let i=1;i<=32;i++)await store.save({...ref(i),requestId:`bbbbbbbb-bbbb-4bbb-8bbb-${String(i).padStart(12,'0')}`});
 const before=rawStorage.get(KEY),calls=[];
 const transport=async(url)=>{calls.push(url);assert.ok(url.endsWith('/session'));return response({sessionId,recoveryKey});};
 const mounted=await mount({productId:'33',shopUserId:12,transport});
 assert.equal(mounted.state.error,'Summary recovery storage is full. Existing summaries remain available.');assert.equal(mounted.state.recoveryStorageFull,true);
 assert.equal(calls.length,1);assert.equal(rawStorage.get(KEY),before);await mounted.unmount();
});

test('failed or pending source recovery clears an earlier completion projection',async()=>{
 for(const next of ['failed','pending']){
  rawStorage.clear();await references.productSummaryReferenceStore.save(ref());let mode='completed';
  const transport=async(url,options)=>{if(url.endsWith('/session'))return response({sessionId,recoveryKey});assert.equal(options.method,'GET');
   if(url.includes('/product-summary/assessment'))return response({completed:true,judgment:{evaluationId:requestId,verdict:'pass',canRetry:false},replayed:true});
   if(mode==='failed')throw Error('unavailable source');
   return response(mode==='pending'?{status:'pending',sessionId,requestId}:complete(ref()),mode==='pending'?202:200);};
  const mounted=await mount({productId:'7',shopUserId:12,transport});assert.equal(mounted.state.assessment.completed,true);
  mode=next;await React.act(async()=>mounted.state.check());assert.equal(mounted.state.summary,null);assert.equal(mounted.state.assessment,null);await mounted.unmount();
 }
});

test('mode away/back and renewed persona use fresh scoped IDs while retaining unresolved old requests',async()=>{
 rawStorage.clear();let key=recoveryKey;const calls=[],saved=new Map();
 const transport=async(url,options)=>{
  calls.push([url,options.method]);
  if(url.endsWith('/session'))return response({sessionId,recoveryKey:key});
  if(url.includes('/product-summary/assessment'))return response({completed:false,status:'ineligible',modelEvaluated:false});
  if(options.method==='POST'){const ids=JSON.parse(options.body);saved.set(ids.requestId,{...ref(),...ids,recoveryKey:key});throw Error('lost ACK');}
  const id=url.split('/requests/')[1],r=saved.get(id);
  if(r.recoveryKey===recoveryKey)return response({status:'pending',sessionId,requestId:id},202);
  return response(complete(r,`Summary ${r.recoveryKey[0]}`));
 };
 const props={productId:'7',shopUserId:12,authorityKey:'original',transport};
 let mounted=await mount(props,true);assert.equal(mounted.state.status,'pending');await mounted.unmount();
 const original=references.productSummaryReferenceStore.read(12,7,recoveryKey);
 for(const next of ['b','c','d']){
  key=next.repeat(64);mounted=await mount({...props,authorityKey:next==='d'?'renewed':props.authorityKey},true);
  assert.equal(mounted.state.summary.summary,`Summary ${next}`);await mounted.unmount();
  mounted=await mount({...props,authorityKey:next==='d'?'renewed':props.authorityKey});await mounted.unmount();
 }
 assert.equal(calls.filter(([url,method])=>url.endsWith('/summary')&&method==='POST').length,4);
 assert.deepEqual(references.productSummaryReferenceStore.read(12,7,recoveryKey),original);
 const entries=JSON.parse(rawStorage.get(KEY)).entries;assert.equal(entries.length,4);assert.equal(new Set(entries.map(x=>x.requestId)).size,4);
});
test('legacy unscoped references remain byte-identical and GET-recover without replacement',async()=>{
 rawStorage.clear();const legacy={...ref()};delete legacy.recoveryKey;legacy.version=1;
 const raw=JSON.stringify({version:1,entries:[legacy]});rawStorage.set(KEY,raw);let runs=0;
 const transport=async(url,options)=>{if(url.endsWith('/session'))return response({sessionId,recoveryKey:'b'.repeat(64)});
  if(options.method==='POST'){runs++;throw Error('must not replace legacy pending identity');}
  return response({status:'pending',sessionId,requestId},202);};
 const mounted=await mount({productId:'7',shopUserId:12,transport});assert.equal(mounted.state.status,'pending');
 assert.equal(runs,0);assert.equal(rawStorage.get(KEY),raw);await mounted.unmount();
});

test('an unrecoverable legacy reference explains reset without replacing or deleting old work',async()=>{
 rawStorage.clear();const legacy={...ref()};delete legacy.recoveryKey;legacy.version=1;
 const raw=JSON.stringify({version:1,entries:[legacy]});rawStorage.set(KEY,raw);
 const transport=async(url,options)=>{if(url.endsWith('/session'))return response({sessionId,recoveryKey});
  assert.equal(options.method,'GET');return response({error:'stale'},503);};
 const mounted=await mount({productId:'7',shopUserId:12,transport});
 assert.match(mounted.state.error,/saved reference is retained/);assert.match(mounted.state.error,/administrator to reset the practice/);
 assert.equal(rawStorage.get(KEY),raw);await mounted.unmount();
});
