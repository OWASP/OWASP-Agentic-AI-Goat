'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),{EventEmitter}=require('node:events');
const {permissionRecovery,ROUTE,RECOVERY,CELL}=require('./fixtures/secureshopAclPermissionRecoveryBrowser');
function setup({wrong=false,aborted=false,duplicate=false,disableFault=false,detachFault=false,clickFault=false,pendingGet=false}={}){
 const origin='http://owned.invalid',events=[],page=new EventEmitter(),cdp=new EventEmitter(),controller=new AbortController();
 if(aborted)controller.abort(Error('owner cancelled'));
 const policy={version:'4',registrySha256:'a'.repeat(64),tools:[{tool_name:'audit.search_by_user',admin:true}]};
 const receipt={operationId:'exact-operation',version:'5',registrySha256:policy.registrySha256};
 const body={receipt,tool_name:'audit.search_by_user',role:'admin',allowed:false};
 cdp.send=async(method)=>{events.push(method);if(method==='Fetch.disable'&&disableFault)throw Error('disable fault');if(method==='Fetch.getResponseBody')return{body:JSON.stringify(body)};};
 cdp.detach=async()=>{events.push('detach');if(detachFault)throw Error('detach fault');};page.createCDPSession=async()=>cdp;
 let resolve,rejectResponse;page.waitForResponse=predicate=>new Promise((r,j)=>{rejectResponse=j;resolve=x=>{assert(predicate(x));r(x);};});
 const request=(url,method,data)=>({url:()=>url,method:()=>method,postData:()=>JSON.stringify(data)});
 const frame={waitForSelector:async s=>assert.equal(s,CELL),waitForFunction:async()=>{},
  click:async()=>{events.push('physical-permission');const r=request(origin+ROUTE,'POST',{operationId:receipt.operationId,expectedVersion:'4',tool_name:body.tool_name,role:'admin',allowed:false});
   page.emit('request',r);if(duplicate)page.emit('request',r);queueMicrotask(()=>cdp.emit('Fetch.requestPaused',{requestId:'one',request:{url:origin+ROUTE,method:'POST'},responseStatusCode:200}));},
  $$:async()=>[{evaluate:async()=>true,click:async()=>{events.push('physical-recovery');page.emit('request',request(origin+RECOVERY+receipt.operationId,'GET'));
   if(clickFault)throw Error('click fault');resolve({url:()=>origin+RECOVERY+receipt.operationId,request:()=>({method:()=> 'GET'}),status:()=>200,json:async()=>({ok:true,receipt})});}}]};
 return{events,controller,options:{origin,page,frame,policy,signal:controller.signal,deadline:Date.now()+1000,
  abortOwner:()=>controller.abort(),closeBrowser:async()=>{events.push('browser-close');rejectResponse?.(Error('page closed'));},check(){controller.signal.throwIfAborted();},
  readOperation:async id=>{events.push('canonical-read');assert.equal(id,receipt.operationId);if(pendingGet){queueMicrotask(()=>controller.abort(Error('owner cancelled GET')));await new Promise((_,reject)=>controller.signal.addEventListener('abort',()=>{events.push('GET-joined');reject(controller.signal.reason);},{once:true}));}return{ok:true,receipt:wrong?{...receipt,operationId:'foreign'}:receipt};}}};
}
test('one physical permission click commits, loses ACK, then physical exact GET recovery without repost',async()=>{
 const x=setup(),r=await permissionRecovery(x.options);assert.equal(r.posts,1);assert.equal(r.qualificationComplete,false);
 assert(x.events.indexOf('canonical-read')<x.events.indexOf('Fetch.failRequest'));
 assert(x.events.indexOf('Fetch.failRequest')<x.events.indexOf('physical-recovery'));
 assert.equal(x.events.filter(e=>e==='physical-permission').length,1);assert.equal(x.events.at(-1),'detach');
});
test('foreign canonical receipt and duplicate mutation fail closed before recovery',async()=>{
 for(const options of [{wrong:true},{duplicate:true}]){const x=setup(options);await assert.rejects(permissionRecovery(x.options));assert(!x.events.includes('physical-recovery'));}
});
test('cancelled owner cannot dispatch first mutation',async()=>{const x=setup({aborted:true});await assert.rejects(permissionRecovery(x.options));assert.deepEqual(x.events,[]);});
test('disable and detach faults both attempted with primary preserved and debt',async()=>{
 const x=setup({disableFault:true,detachFault:true});await assert.rejects(permissionRecovery(x.options),e=>e.message==='disable fault'&&e.cleanupDebt===true);assert(x.events.includes('detach'));assert(x.events.includes('browser-close'));
});
test('asynchronous pending canonical GET is aborted and joined before return',async()=>{
 const x=setup({pendingGet:true});await assert.rejects(permissionRecovery(x.options));assert(x.events.includes('GET-joined'));assert(x.events.includes('browser-close'));assert(!x.events.includes('physical-recovery'));
});
test('click failure joins rejected response waiter without unhandled rejection',async()=>{
 const x=setup({clickFault:true}),unhandled=[];const listener=e=>unhandled.push(e);process.on('unhandledRejection',listener);
 try{await assert.rejects(permissionRecovery(x.options),/click fault/);await new Promise(setImmediate);assert.deepEqual(unhandled,[]);assert(x.events.includes('browser-close'));}finally{process.off('unhandledRejection',listener);}
});
test('unjoined owner close retains debt at the same absolute deadline',async()=>{
 const x=setup({clickFault:true});x.options.deadline=Date.now()+25;x.options.closeBrowser=()=>new Promise(()=>{});
 const before=Date.now();await assert.rejects(permissionRecovery(x.options),e=>e.message==='click fault'&&e.cleanupDebt===true);assert(Date.now()-before<250);assert(x.events.includes('detach'));
});
