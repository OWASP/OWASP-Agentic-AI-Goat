'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const origin='http://localhost:3000';
function setup(){const frameWindow=new EventTarget();const originalFetch=()=>{throw Error('native API fetch forbidden');};Object.assign(frameWindow,{fetch:originalFetch,document:{baseURI:origin+'/frame'}});let resolve;const ready=new Promise(r=>{resolve=r;});let closed=false;return {frameWindow,originalFetch,resolve,session:{ready,close(){closed=true;}},isClosed:()=>closed};}
test('frame startup hydrates and installs bridge fetch before rendering and reverses ownership on close',async()=>{
 const {startShopFrame}=await import('../client/src/pages/secureshop/bridge/runtime.mjs');const f=setup();let rendered=false,released=false,unmounted=false,attached;const requests=[];
 const pending=startShopFrame({origin,frameWindow:f.frameWindow,connect:()=>f.session,attachStorage:state=>{attached=state;return()=>{released=true;};},storage:{getItem:()=> 'shop-jwt'},render:()=>{rendered=true;return()=>{unmounted=true;};}});
 assert.equal(rendered,false);assert.equal(f.frameWindow.fetch,f.originalFetch);
 const state={};f.resolve({state,request:async(...args)=>{requests.push(args);return new Response('{}');}});
 const runtime=await pending;assert.equal(attached,state);assert.equal(rendered,true);
 await f.frameWindow.fetch('/api/secureshop/products');assert.equal(requests[0][0],'catalog.list');assert.equal(requests[0][2].shopBearer,'shop-jwt');
 runtime.close();assert.equal(f.isClosed(),true);assert.equal(released,true);assert.equal(unmounted,true);assert.equal(f.frameWindow.fetch,f.originalFetch);
});
test('pagehide during startup prevents rendering; renderer failure closes every acquired resource',async()=>{
 const {startShopFrame}=await import('../client/src/pages/secureshop/bridge/runtime.mjs');
 const first=setup();let rendered=false;
 const pending=startShopFrame({origin,frameWindow:first.frameWindow,connect:()=>first.session,render:()=>{rendered=true;return()=>{};}});
 first.frameWindow.dispatchEvent(new Event('pagehide'));first.resolve({state:{}});await assert.rejects(pending,{name:'AbortError'});assert.equal(rendered,false);assert.equal(first.isClosed(),true);
 const second=setup();let released=false;second.resolve({state:{},request(){}});
 await assert.rejects(startShopFrame({origin,frameWindow:second.frameWindow,connect:()=>second.session,attachStorage:()=>()=>{released=true;},render:()=>{throw Error('render failed');}}),/render failed/);
 assert.equal(released,true);assert.equal(second.isClosed(),true);assert.equal(second.frameWindow.fetch,second.originalFetch);
});
test('frame activity uses trusted visible input only and removes listeners on close',async()=>{
 const {startShopFrame}=await import('../client/src/pages/secureshop/bridge/runtime.mjs');const f=setup(),listeners=new Map();let signals=0;
 f.frameWindow.document.visibilityState='visible';f.frameWindow.addEventListener=(type,fn)=>listeners.set(type,fn);f.frameWindow.removeEventListener=(type)=>listeners.delete(type);
 f.resolve({state:{},request:async()=>new Response('{}'),markActivity:()=>signals++});
 const runtime=await startShopFrame({origin,frameWindow:f.frameWindow,connect:()=>f.session,attachStorage:()=>()=>{},render:()=>()=>{}});
 const input=listeners.get('keydown');input({isTrusted:false});assert.equal(signals,0);f.frameWindow.document.visibilityState='hidden';input({isTrusted:true});assert.equal(signals,0);f.frameWindow.document.visibilityState='visible';input({isTrusted:true});input({isTrusted:true});assert.equal(signals,1);
 runtime.close();assert.equal(listeners.has('keydown'),false);input({isTrusted:true});assert.equal(signals,1);
});
