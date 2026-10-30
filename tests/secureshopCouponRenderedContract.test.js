'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os'),path=require('node:path');
test('controlled coupon refund adapter emits ordered owned tools and honest mock provenance',async()=>{
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'coupon-provider-control-')),moduleRef=require('../server/services/secureshopBoundRefundRuntime'),original=moduleRef.createSecureShopBoundRefundRuntime;
 const prior={PG_TEST_DISPOSABLE:process.env.PG_TEST_DISPOSABLE,LISTINGS_EVIDENCE_ROOT:process.env.LISTINGS_EVIDENCE_ROOT};let captured;
 try{process.env.PG_TEST_DISPOSABLE='yes';process.env.LISTINGS_EVIDENCE_ROOT=root;moduleRef.createSecureShopBoundRefundRuntime=options=>(captured=options);
 require('../tests/fixtures/secureshopCouponFullAppProvider.cjs');moduleRef.createSecureShopBoundRefundRuntime({});
 const input={messages:[{role:'user',content:'refund order 12'}]};const first=await captured.provider.chat(input),second=await captured.provider.chat(input),last=await captured.provider.finalResponse(input);
 assert.equal(first.mocked,true);assert.equal(first.provider,'mock');assert.deepEqual(first.tool_uses[0].args,{order_id:12});assert.equal(first.tool_uses[0].name,'support.order_status');assert.equal(second.tool_uses[0].name,'support.refund_request');assert.equal(second.tool_uses[0].args.order_id,12);assert.equal(last.responseMode,'structured_final');assert.match(last.text,/no money was refunded/);
 assert.equal(JSON.parse(fs.readFileSync(path.join(root,'controlled-coupon-refund.json'))).actualModelCalls,0);
 }finally{moduleRef.createSecureShopBoundRefundRuntime=original;for(const[k,v]of Object.entries(prior))if(v===undefined)delete process.env[k];else process.env[k]=v;fs.rmSync(root,{recursive:true});}
});

test('browser predicates reject unrelated totals and hidden or disabled actions',()=>{
 const {JSDOM}=require('../client/node_modules/jsdom');const {findAction,summaryMatches}=require('./fixtures/secureshopCouponFullAppBrowser');
 const dom=new JSDOM('<p>$5.00</p><div class="ss-card"><div class="ss-card__meta">Order summary</div><div><span><strong>Total</strong></span><span>$10.00</span></div></div><button disabled>Apply</button><button style="visibility:hidden">Apply</button><button id="active">Apply</button><div role="dialog"><button>Request refund</button></div>');
 const priorDocument=global.document,priorStyle=global.getComputedStyle;global.document=dom.window.document;global.getComputedStyle=dom.window.getComputedStyle;
 try{for(const button of document.querySelectorAll('button'))button.getClientRects=()=>[{}];assert.equal(summaryMatches('Order summary',5),false);assert.equal(summaryMatches('Order summary',10),true);assert.equal(summaryMatches('Order',10),false);assert.equal(findAction('Apply','body').id,'active');assert.equal(findAction('Request refund','[role="dialog"]').textContent,'Request refund');document.querySelector('[role="dialog"]').remove();assert.equal(findAction('Request refund','[role="dialog"]'),undefined);}
 finally{global.document=priorDocument;global.getComputedStyle=priorStyle;dom.window.close();}
});
test('pointer readiness rejects covered and fading controls after geometry resolution',()=>{
 const {JSDOM}=require('../client/node_modules/jsdom'),{isPointerReady}=require('./fixtures/secureshopCouponFullAppBrowser');const dom=new JSDOM('<button id="target">Apply</button><div id="cover"></div>');const keys=['document','getComputedStyle','innerWidth','innerHeight'],prior=Object.fromEntries(keys.map(k=>[k,global[k]]));
 try{global.document=dom.window.document;global.innerWidth=1000;global.innerHeight=800;global.getComputedStyle=e=>({display:'block',visibility:'visible',opacity:e.dataset.fade?'0':'1'});const target=document.querySelector('#target');target.getBoundingClientRect=()=>({x:100,y:100,width:80,height:30});document.elementFromPoint=()=>document.querySelector('#cover');assert.equal(isPointerReady(target),false);document.elementFromPoint=()=>target;assert.equal(isPointerReady(target),true);target.dataset.fade='yes';assert.equal(isPointerReady(target),false);delete target.dataset.fade;target.disabled=true;assert.equal(isPointerReady(target),false);}
 finally{for(const k of keys)global[k]=prior[k];dom.window.close();}
});
test('coupon helper reaches real installer authority with isolated endpoint and executable path',async()=>{
 const setup=require('../scripts/install/analytics-setup'),target=require('../scripts/install/analytics-target'),original=setup.setupOwnedAnalytics;
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'coupon-install-contract-')),home=path.join(root,'home');fs.mkdirSync(home,{mode:0o700});
 const source=fs.realpathSync(path.resolve(__dirname,'..')),host='unix:///Users/averma5/.colima/owasp-ai-goat-pg-verify/docker.sock',dockerDir='/Applications/Rancher Desktop.app/Contents/Resources/resources/darwin/bin';
 const keys=['PG_TEST_DISPOSABLE','OWASP_AI_GOAT_ISOLATED_TEST_WORKSPACE','DOCKER_HOST'],prior=Object.fromEntries(keys.map(k=>[k,process.env[k]]));let called=0,validated=false;
 const env={PATH:dockerDir+path.delimiter+process.env.PATH,HOME:home,SS_ENABLE:'true',SS_BOUND_REVIEWS_ENABLED:'true',PLATFORM_DATABASE_ENGINE:'postgres',WORKSHOP_DATABASE_ENGINE:'postgres',SECURESHOP_AGENTS_DATABASE_URL:'postgres://fixture:fixture@127.0.0.1:1/unused'};
 fs.mkdirSync(target.plan({root:source,homeDirectory:home}).directory,{recursive:true,mode:0o700});
 const stop=Object.assign(Error('controlled authority boundary; no Docker execution'),{code:'CONTROLLED_STOP'});
 try{
  process.env.PG_TEST_DISPOSABLE='yes';process.env.OWASP_AI_GOAT_ISOLATED_TEST_WORKSPACE=source;process.env.DOCKER_HOST=host;
  setup.setupOwnedAnalytics=options=>original({...options,provisionService:p=>target.provision({...p,execute:async(file,args,options)=>{called++;assert.equal(file,'docker');assert.deepEqual(args.slice(0,3),['--host',host,'info']);assert.equal(options.env.DOCKER_HOST,undefined);assert.equal(options.env.HOME,home);const executable=options.env.PATH.split(path.delimiter).map(dir=>path.join(dir,file)).find(p=>fs.existsSync(p));assert.equal(executable,path.join(dockerDir,'docker'));validated=true;throw stop;}})});
  await assert.rejects(require('./fixtures/secureshopCouponFullAppSupport').prepareCouponFullApp({source,root,home,env}),error=>{assert.equal(called,1, String(error.code)+': '+error.message);return true;});assert.equal(called,1);assert.equal(validated,true);
  delete process.env.DOCKER_HOST;await assert.rejects(require('./fixtures/secureshopCouponFullAppSupport').prepareCouponFullApp({source,root,home,env}),error=>{assert.equal(called,1, String(error.code)+': '+error.message);return true;});assert.equal(called,1);assert.equal(validated,true);
  process.env.DOCKER_HOST=host;await assert.rejects(require('./fixtures/secureshopCouponFullAppSupport').prepareCouponFullApp({source,root,home,env:{...env,SS_ENABLE:'false'}}),{code:'ANALYTICS_SETUP_PREREQUISITES'});assert.equal(called,1);
 }finally{setup.setupOwnedAnalytics=original;for(const k of keys)if(prior[k]===undefined)delete process.env[k];else process.env[k]=prior[k];fs.rmSync(root,{recursive:true});}
});
test('auth readiness rejects blank opaque boot and waits for visible real form or sign-in state',()=>{
 const {JSDOM}=require('../client/node_modules/jsdom'),{couponAuthState}=require('./fixtures/secureshopCouponFullAppBrowser');const dom=new JSDOM('<main></main>');const prior={document:global.document,getComputedStyle:global.getComputedStyle};
 try{global.document=dom.window.document;global.getComputedStyle=dom.window.getComputedStyle;const render=html=>{document.body.innerHTML=html;for(const e of document.querySelectorAll('*'))e.getClientRects=()=>[{}];};
 assert.equal(couponAuthState(),false);render('<a href="/secureshop/login" style="opacity:0">Sign in</a>');assert.equal(couponAuthState(),false);
 render('<a href="/secureshop/login">Sign in</a>');assert.equal(couponAuthState(),'sign-in');assert.equal(couponAuthState(['authenticated']),false);
 render('<form><input id="ss-login-user"><input id="ss-login-pw"><button type="submit" disabled>Signing in…</button></form>');assert.equal(couponAuthState(),false);document.querySelector('button').disabled=false;assert.equal(couponAuthState(['form']),'form');
 render('<button aria-label="Account menu">Customer</button>');assert.equal(couponAuthState(['authenticated']),'authenticated');assert.equal(couponAuthState(['form','sign-in']),false);
 render('<a href="/secureshop/login">Sign in</a>');assert.equal(couponAuthState(['form','sign-in']),'sign-in');
 }finally{Object.assign(global,prior);dom.window.close();}
});

test('real cart action assertion binds exact selected product, quantity and single emitted request',()=>{
 const {assertSelectedCart}=require('./fixtures/secureshopCouponFullAppBrowser'),posts=[{product_id:7,quantity:2}],cart={items:[{product_id:7,quantity:2}]};assert.doesNotThrow(()=>assertSelectedCart(posts,cart,7));
 assert.throws(()=>assertSelectedCart([{product_id:8,quantity:2}],cart,7));assert.throws(()=>assertSelectedCart([...posts,...posts],cart,7));assert.throws(()=>assertSelectedCart(posts,{items:[]},7));assert.throws(()=>assertSelectedCart(posts,{items:[{product_id:7,quantity:1}]},7));assert.throws(()=>assertSelectedCart([{...posts[0],user_id:99}],cart,7));
});
test('coupon response capture reports upstream denial and always resumes untouched failures',async()=>{
 const {captureCouponResponse}=require('./fixtures/secureshopCouponFullAppBrowser'),expected={code:'WELCOME10',operationId:'owned-fixture-id'},event={requestId:'paused1',responseStatusCode:401,request:{url:'http://127.0.0.1/api/secureshop/cart/apply-coupon',method:'POST',postData:JSON.stringify(expected)}};
 const calls=[],diagnostics=[],cdp={async send(method){calls.push(method);return{body:JSON.stringify({error:'Shop authentication required',code:'SHOP_AUTH_INVALID'}),base64Encoded:false};}};
 await assert.rejects(captureCouponResponse(cdp,event,expected,diagnostics),/upstream status 401/);assert.deepEqual(calls,['Fetch.getResponseBody','Fetch.continueRequest']);assert.equal(diagnostics[0].status,401);
 calls.length=0;await assert.rejects(captureCouponResponse(cdp,event,{...expected,operationId:'different'},[]));assert.deepEqual(calls,['Fetch.continueRequest']);
 calls.length=0;const ok={async send(method){calls.push(method);return{body:'{"ok":true,"applied_amount":8}',base64Encoded:false};}};const result=await captureCouponResponse(ok,{...event,responseStatusCode:200},expected,[]);assert.equal(result.ok,true);assert.deepEqual(calls,['Fetch.getResponseBody','Fetch.fulfillRequest']);
 calls.length=0;await assert.rejects(captureCouponResponse({async send(method){calls.push(method);return{body:'invalid'};}},{...event,responseStatusCode:200},expected,[]));assert.deepEqual(calls,['Fetch.getResponseBody','Fetch.continueRequest']);
});
test('response observer rejection is handled before a pending pointer action and aborts on click failure',async()=>{
 const {observeActionResponse}=require('./fixtures/secureshopCouponFullAppBrowser');let signal,cleanup=false;
 const page={waitForResponse(_predicate,options){signal=options.signal;return Promise.reject(Error('controlled response timeout'));}};
 try{await assert.rejects(observeActionResponse(page,()=>true,()=>new Promise(resolve=>setTimeout(resolve,10))),/controlled response timeout/);}finally{cleanup=true;}
 assert(cleanup);assert(signal.aborted);
 const waiting={waitForResponse(_predicate,options){signal=options.signal;return new Promise((resolve,reject)=>signal.addEventListener('abort',()=>reject(Error('cancelled')),{once:true}));}};
 await assert.rejects(observeActionResponse(waiting,()=>true,async()=>{throw Error('pointer unavailable');}),/pointer unavailable/);assert(signal.aborted);
 const response={status:()=>200};assert.equal(await observeActionResponse({waitForResponse:async()=>response},()=>true,async()=>{}),response);
});

test('checkout replacement explicitly selects then verifies empty before real typing',async()=>{
 const {replaceInput}=require('./fixtures/secureshopCouponFullAppBrowser');let value='Student Customer',selected=false,emptyRead=false;
 const element={focus:async()=>{},press:async k=>{assert.equal(k,'Backspace');assert(selected);value='';},type:async text=>{assert(emptyRead);value+=text;},evaluate:async fn=>{const result=fn({value,select(){selected=true;}});if(result==='')emptyRead=true;return result;}};
 await replaceInput(element,'Owned Test Customer');assert.equal(value,'Owned Test Customer');assert(selected);assert(emptyRead);
});
test('order Fetch capture correlates request, continues unchanged and cleans up on malformed response or timeout',async()=>{
 const {captureOrderAction}=require('./fixtures/secureshopCouponFullAppBrowser');const {EventEmitter}=require('node:events');
 const sent={operationId:'12345678-1234-4234-8234-123456789abc',shipping_address:'owned',payment_method:'Visa ending 4242'};
 for(const kind of ['success','wrong-id','malformed','timeout','action-failure']){
  const session=new EventEmitter(),calls=[];session.send=async(name)=>{calls.push(name);if(name==='Fetch.getResponseBody')return{body:kind==='malformed'?'{':JSON.stringify({order_id:1,total:18}),base64Encoded:false};};session.detach=async()=>calls.push('detach');
  const action=async()=>{if(kind==='action-failure')throw Error('pointer failed');if(kind!=='timeout')session.emit('Fetch.requestPaused',{requestId:'cdp1',responseStatusCode:200,request:{url:'http://owned/api/secureshop/orders',method:'POST',postData:JSON.stringify({...sent,...(kind==='wrong-id'?{operationId:'wrong'}:{})})}});};
  const pending=captureOrderAction({createCDPSession:async()=>session},'http://owned',[sent],action,[],10);
  if(kind==='success')assert.deepEqual(await pending,{status:200,body:{order_id:1,total:18}});else await assert.rejects(pending);
  if(!['timeout','action-failure'].includes(kind))assert(calls.includes('Fetch.continueRequest'));
  assert(calls.includes('Fetch.disable'));assert(calls.includes('detach'));assert(!calls.includes('Fetch.fulfillRequest'));
 }
});
