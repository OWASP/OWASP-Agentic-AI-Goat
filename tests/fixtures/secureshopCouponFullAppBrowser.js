'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
const findAction=(text,scope)=>[...document.querySelectorAll(scope+' button')].find(b=>b.textContent.trim()===text&&!b.disabled&&b.getClientRects().length&&getComputedStyle(b).visibility!=='hidden');
const summaryMatches=(title,total)=>{const heading=[...document.querySelectorAll('.ss-card__meta')].find(e=>e.textContent.trim()===title);const card=heading?.closest('.ss-card');if(!card)return false;const labels=[...card.querySelectorAll('span')].filter(e=>e.textContent.trim()==='Total');return labels.length===1&&labels[0].parentElement.children[1]?.textContent.trim()==='$'+Number(total).toFixed(2);};
function isPointerReady(element){
 if(!element?.isConnected||element.disabled)return false;
 for(let e=element;e;e=e.parentElement){const style=getComputedStyle(e);if(style.visibility==='hidden'||style.display==='none'||Number(style.opacity)===0)return false;}
 const box=element.getBoundingClientRect(),x=box.x+box.width/2,y=box.y+box.height/2;if(box.width<=0||box.height<=0||x<0||y<0||x>=innerWidth||y>=innerHeight)return false;
 const hit=document.elementFromPoint(x,y);return hit===element||element.contains(hit);
}
function assertSelectedCart(posts,cart,productId){assert.deepEqual(posts,[{product_id:productId,quantity:2}]);assert.equal(cart.items.length,1);assert.equal(Number(cart.items[0].product_id),Number(productId));assert.equal(Number(cart.items[0].quantity),2);}
function couponAuthState(expected){
 const accept=state=>!expected||expected.includes(state)?state:false;
 const visible=e=>{if(!e?.isConnected||e.disabled||!e.getClientRects().length)return false;for(let p=e;p;p=p.parentElement){const s=getComputedStyle(p);if(s.display==='none'||s.visibility==='hidden'||Number(s.opacity||'1')===0)return false;}return true;};
 const user=document.querySelector('#ss-login-user'),password=document.querySelector('#ss-login-pw'),submit=user?.closest('form')?.querySelector('button[type="submit"]');
 if(visible(user)&&visible(password)&&visible(submit))return accept('form');
 if(visible(document.querySelector('[aria-label="Account menu"]')))return accept('authenticated');
 if([...document.querySelectorAll('a[href="/secureshop/login"]')].some(e=>e.textContent.trim()==='Sign in'&&visible(e)))return accept('sign-in');
 return false;
}
async function observeActionResponse(page,predicate,action,timeoutMs=15000){
 assert(Number.isInteger(timeoutMs)&&timeoutMs>0&&timeoutMs<=130000);
 const controller=new AbortController();
 // Attach rejection handling before any pointer/readiness await can fail.
 const response=page.waitForResponse(predicate,{timeout:timeoutMs,signal:controller.signal});
 try{const [value]=await Promise.all([response,Promise.resolve().then(action)]);return value;}
 finally{controller.abort();await response.catch(()=>{});}
}
function checkoutDiagnostic(){
 return {headings:[...document.querySelectorAll('h1,h2')].map(e=>e.textContent.trim()).slice(0,12),
  fields:[...document.querySelectorAll('input')].map(e=>({id:e.id,type:e.type,required:e.required,valid:e.validity.valid,valueMissing:e.validity.valueMissing,patternMismatch:e.validity.patternMismatch,disabled:e.disabled,rects:e.getClientRects().length})),
  buttons:[...document.querySelectorAll('button')].map(e=>({text:e.textContent.trim().slice(0,100),disabled:e.disabled,opacity:getComputedStyle(e).opacity,rects:e.getClientRects().length})).slice(0,40)};
}
async function captureCouponResponse(cdp,event,expected,diagnostics){
 let fulfilled=false;const row={status:event.responseStatusCode,method:event.request?.method,path:new URL(event.request.url).pathname};diagnostics.push(row);
 try{
  assert.equal(row.path,'/api/secureshop/cart/apply-coupon');assert.equal(row.method,'POST');const sent=JSON.parse(event.request.postData||'null');assert.deepEqual(sent,expected);row.operationId=sent.operationId;
  const raw=await cdp.send('Fetch.getResponseBody',{requestId:event.requestId});const bytes=Buffer.from(raw.body,raw.base64Encoded?'base64':'utf8');assert.ok(bytes.length<=8192,'Coupon response exceeds diagnostic bound');const value=JSON.parse(bytes.toString());row.ok=value.ok===true;row.code=typeof value.code==='string'?value.code.slice(0,80):null;row.error=typeof value.error==='string'?value.error.slice(0,160):null;
  assert.equal(row.status,200,'Coupon upstream status '+row.status+' code '+row.code);assert.equal(value.ok,true);
  await cdp.send('Fetch.fulfillRequest',{requestId:event.requestId,responseCode:502,responseHeaders:[{name:'content-type',value:'application/json'}],body:Buffer.from('{"error":"controlled committed response loss"}').toString('base64')});fulfilled=true;row.injectedStatus=502;return value;
 }finally{if(!fulfilled)await cdp.send('Fetch.continueRequest',{requestId:event.requestId});}
}
async function replaceInput(element,value){
 await element.focus();await element.evaluate(e=>e.select());await element.press('Backspace');assert.equal(await element.evaluate(e=>e.value),'','Checkout field empty before typing');await element.type(value);
 assert.equal(await element.evaluate(e=>e.value),value,'Exact checkout field replacement');
}
async function captureOrderAction(page,origin,posts,action,diagnostics,timeoutMs=15000){
 const session=await page.createCDPSession();let resolve,reject,timer,seen=false;
 const captured=new Promise((a,b)=>{resolve=a;reject=b;});captured.catch(()=>{});
 const handler=async event=>{let result,problem;try{
  assert.equal(seen,false,'Duplicate order response');seen=true;
  assert.equal(new URL(event.request.url).origin,origin);assert.equal(new URL(event.request.url).pathname,'/api/secureshop/orders');assert.equal(event.request.method,'POST');
  assert.equal(posts.length,1);const sent=JSON.parse(event.request.postData);assert.deepEqual(sent,posts[0]);assert.match(sent.operationId,/^[0-9a-f-]{36}$/);
  const raw=await session.send('Fetch.getResponseBody',{requestId:event.requestId});const bytes=Buffer.from(raw.body,raw.base64Encoded?'base64':'utf8');assert(bytes.length<=65536,'Bounded order response');result={status:event.responseStatusCode,body:JSON.parse(bytes.toString())};
  diagnostics.push({status:result.status,operationId:sent.operationId,path:'/api/secureshop/orders'});
 }catch(error){problem=error;}finally{try{await session.send('Fetch.continueRequest',{requestId:event.requestId});}catch(error){problem??=error;}}if(problem)reject(problem);else resolve(result);};
 session.on('Fetch.requestPaused',handler);
 try{await session.send('Fetch.enable',{patterns:[{urlPattern:origin+'/api/secureshop/orders',requestStage:'Response'}]});timer=setTimeout(()=>reject(Error('Order response capture deadline')),timeoutMs);const [result]=await Promise.all([captured,Promise.resolve().then(action)]);return result;}
 finally{clearTimeout(timer);await session.send('Fetch.disable').catch(()=>{});session.off('Fetch.requestPaused',handler);await session.detach().catch(()=>{});}
}
async function qualifyCouponFullAppBrowser({origin,user,password,root,review,identity,launches,siblingLaunch}){
 const browser=await require('./secureshopAnalyticsBrowserOwner').launchOwnedAnalyticsBrowser(root,'couponapp');let page,frame,cdp,failure,committed;const posts=[],orderPosts=[],cartPosts=[],errors=[],blocked=[],couponResponses=[];const timer=setTimeout(()=>{failure=Error('Coupon browser180s deadline');browser.close().catch(()=>{});},180000);
 try{
  page=await browser.newPage();await page.setViewport({width:1440,height:1100});await require('./fullBackendRenderedSecureShop').configurePage(page,origin,blocked,errors);
  await page.emulateMediaFeatures([{name:'prefers-reduced-motion',value:'reduce'}]);
  page.on('request',r=>{if(r.method()==='POST'){const pathname=new URL(r.url()).pathname;if(pathname.endsWith('/cart/apply-coupon'))posts.push(JSON.parse(r.postData()));if(pathname==='/api/secureshop/cart')cartPosts.push(JSON.parse(r.postData()));if(pathname==='/api/secureshop/orders')orderPosts.push(JSON.parse(r.postData()));}});
  await page.goto(origin+'/workshop-login',{waitUntil:'domcontentloaded'});await page.waitForSelector('input[placeholder="Enter your username"]');await page.type('input[placeholder="Enter your username"]',user.username);await page.type('input[placeholder="Enter your password"]',password);await page.click('button[type="submit"]');await page.waitForFunction(()=>Boolean(localStorage.getItem('token'))&&location.pathname!=='/workshop-login');await page.goto(origin+'/workshop/secureshop');
  const getFrame=async()=>{const el=await page.waitForSelector('iframe[title="SecureShop workshop"]');const f=await el.contentFrame();await f.waitForFunction(()=>window.origin==='null',{timeout:15000});await f.waitForFunction(couponAuthState,{timeout:15000,polling:100});return f;};frame=await getFrame();
  const clickHandle=async(surface,handle)=>{assert.ok(handle.asElement());await handle.evaluate(e=>e.scrollIntoView({block:'center',inline:'center',behavior:'instant'}));await surface.waitForFunction(isPointerReady,{},handle);await handle.asElement().click();};
  const clickText=async(surface,text,scope='body')=>{const handle=await surface.waitForFunction(findAction,{},text,scope);try{await clickHandle(surface,handle);}finally{await handle.dispose();}};
  const fillLabel=async(label,value)=>{const handle=await frame.waitForFunction(label=>{const l=[...document.querySelectorAll('label')].find(l=>l.textContent.trim()===label);const input=l&&document.getElementById(l.htmlFor);return input&&!input.disabled&&input.getClientRects().length?input:false;},{},label);try{await replaceInput(handle.asElement(),value);}finally{await handle.dispose();}};
  const summaryTotal=async(title,total)=>frame.waitForFunction(summaryMatches,{},title,total);
  const completionCount=async()=>(await identity.query('SELECT count(*)::int n FROM workshop_platform.completions WHERE user_id=$1',[user.id])).rows[0].n;assert.equal(await completionCount(),0);
  const visibleHandle=async selector=>frame.waitForFunction(selector=>[...document.querySelectorAll(selector)].find(e=>!e.disabled&&e.getClientRects().length&&getComputedStyle(e).visibility!=='hidden'&&getComputedStyle(e).display!=='none'),{timeout:15000,polling:100},selector);
  const clickSelector=async selector=>{const handle=await visibleHandle(selector);try{await clickHandle(frame,handle);}finally{await handle.dispose();}};
  const auth=async expected=>{await frame.waitForFunction(couponAuthState,{timeout:15000,polling:100},expected);const state=await frame.evaluate(couponAuthState,expected);assert.ok(expected.includes(state),'Expected auth state '+expected+', got '+state);return state;};
  const login=async name=>{if(await auth(['form','sign-in'])==='sign-in')await clickSelector('a[href="/secureshop/login"]');await frame.waitForFunction(couponAuthState,{timeout:15000,polling:100});await frame.waitForFunction(()=>{const u=document.querySelector('#ss-login-user');return u&&u.getClientRects().length&&!u.disabled;},{timeout:15000,polling:100});await auth(['form']);await frame.type('#ss-login-user',name);await frame.type('#ss-login-pw','student123');await clickSelector('form button[type="submit"]');await frame.waitForSelector('[aria-label="Account menu"]',{visible:true,timeout:15000});await auth(['authenticated']);};
  const logout=async()=>{await auth(['authenticated']);await clickSelector('[aria-label="Account menu"]');await clickText(frame,'Sign out');await frame.waitForFunction(()=>!document.querySelector('[aria-label="Account menu"]'),{timeout:15000,polling:100});await auth(['form','sign-in']);};
  const request=(url,body)=>frame.evaluate(async(url,body)=>{const r=await fetch(url,body===null?{}:{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(body)});return{status:r.status,body:await r.json()};},url,body??null);
  const navigate=async href=>{await clickSelector('a[href="'+href+'"]');};
  await login('student_merchant');const ownedProducts=await request('/api/secureshop/merchant/products',null);assert.equal(ownedProducts.status,200);const ownProduct=(ownedProducts.body.products||ownedProducts.body)[0];assert.ok(ownProduct?.id);const baselineKpis=await request('/api/secureshop/merchant/overview/kpis',null);assert.equal(baselineKpis.status,200);const baselineRevenue=Number(baselineKpis.body.revenue.value);assert.ok(Number.isFinite(baselineRevenue));await logout();
  await login('student_customer');const products=await request('/api/secureshop/products/'+ownProduct.id,null);assert.equal(products.status,200);const product=products.body.product||products.body;assert.ok(product?.id);
  assert.ok(Number(product.stock_quantity)>=2,'Selected owned product must support quantity2');
  await navigate('/secureshop/catalog');const search=await visibleHandle('input[aria-label="Search catalog"]');await clickHandle(frame,search);await search.asElement().type(product.name);await search.asElement().press('Enter');await search.dispose();
  await navigate('/secureshop/product/'+product.id);await frame.waitForFunction(name=>document.querySelector('h1')?.textContent.trim()===name,{timeout:15000,polling:100},product.name);
  await frame.waitForSelector('input[aria-label="Quantity"]',{visible:true});assert.equal(await frame.$eval('input[aria-label="Quantity"]',e=>e.value),'1');await clickSelector('[aria-label="Increase quantity"]');assert.equal(await frame.$eval('input[aria-label="Quantity"]',e=>e.value),'2');
  const cartResponse=await observeActionResponse(page,r=>new URL(r.url()).pathname==='/api/secureshop/cart'&&r.request().method()==='POST',()=>clickText(frame,'Add to cart'));assert.equal(cartResponse.status(),200);assert.deepEqual(cartPosts,[{product_id:product.id,quantity:2}]);
  await navigate('/secureshop/cart');await frame.waitForSelector('input[aria-label="Coupon code"]',{visible:true});
  const selectedCart=(await request('/api/secureshop/cart',null)).body;assertSelectedCart(cartPosts,selectedCart,product.id);
  const before=(await request('/api/secureshop/cart',null)).body;assert.match(before.couponScopeKey,/^[a-f0-9]{64}$/);
  let resolvePause;const firstPause=new Promise(resolve=>{resolvePause=resolve;});let paused=false;
  cdp=await page.createCDPSession();cdp.on('Fetch.requestPaused',async event=>{if(paused){await cdp.send('Fetch.continueRequest',{requestId:event.requestId}).catch(error=>{failure=error;});return;}paused=true;try{committed=await captureCouponResponse(cdp,event,posts[0],couponResponses);}catch(error){failure=error;}finally{resolvePause();}});
  await cdp.send('Fetch.enable',{patterns:[{urlPattern:origin+'/api/secureshop/cart/apply-coupon',requestStage:'Response'}]});
  const apply=async()=>{await frame.type('input[aria-label="Coupon code"]','WELCOME10');await clickText(frame,'Apply');};await apply();let responseTimer;try{await Promise.race([firstPause,new Promise((_,reject)=>{responseTimer=setTimeout(()=>reject(Error('Coupon response pause not observed within15s')),15000);})]);}finally{clearTimeout(responseTimer);}if(failure)throw failure;await frame.waitForFunction(()=>document.body.innerText.includes('502'));if(failure)throw failure;assert.ok(committed);assert.equal(posts.length,1);
  await page.reload();frame=await getFrame();await auth(['authenticated']);await navigate('/secureshop/cart');await frame.waitForSelector('input[aria-label="Coupon code"]');
  const restored=(await request('/api/secureshop/cart',null)).body;assert.equal(restored.couponScopeKey,before.couponScopeKey);assert.equal(restored.coupon.applied_amount,committed.applied_amount);assert.equal(posts.length,1);
  await apply();await frame.waitForFunction(()=>document.querySelector('input[aria-label="Coupon code"]').value==='');assert.equal(posts.length,2);assert.deepEqual(posts[0],posts[1]);if(failure)throw failure;await cdp.send('Fetch.disable');await cdp.detach();cdp=null;
  const cents=x=>Math.round(Number(x)*100);assert.equal(cents(restored.total),cents(restored.subtotal)-cents(restored.discount));await summaryTotal('Order summary',restored.total);await page.screenshot({path:path.join(root,'coupon-cart.png'),fullPage:true});
  await navigate('/secureshop/checkout');await summaryTotal('Order',restored.total);await page.screenshot({path:path.join(root,'coupon-checkout.png'),fullPage:true});
  for(const [label,value] of Object.entries({'Full name':'Owned Test Customer','Address':'123 Synthetic Street','City':'Testville','State':'CA','ZIP':'94000','Phone':'5550100000'}))await fillLabel(label,value);
  await clickText(frame,'Continue to payment');await frame.waitForFunction(()=>[...document.querySelectorAll('h2')].some(e=>e.textContent.trim()==='Payment'&&e.getClientRects().length),{timeout:15000,polling:100});
  for(const [label,value] of Object.entries({'Name on card':'Owned Test Customer','Card number':'4242424242424242','Expiry':'12/30','CVV':'123'}))await fillLabel(label,value);
  await clickText(frame,'Review order');
  const order=await captureOrderAction(page,origin,orderPosts,()=>clickText(frame,'Place order'),couponResponses);assert.equal(order.status,200);assert.equal(cents(order.body.total),cents(restored.total));assert.equal(orderPosts.length,1);assert.deepEqual(Object.keys(orderPosts[0]).sort(),['operationId','payment_method','shipping_address']);assert.match(orderPosts[0].operationId,/^[0-9a-f-]{36}$/);assert.equal(orderPosts[0].payment_method,'Visa ending 4242');assert.equal(orderPosts[0].shipping_address,'Owned Test Customer\n123 Synthetic Street\nTestville, CA 94000\n5550100000');
  await frame.waitForFunction(id=>document.querySelector('h1')?.textContent==='Order placed.'&&document.body.innerText.includes('#'+id),{},order.body.order_id);
  const replay=await request('/api/secureshop/orders',orderPosts[0]);assert.deepEqual(replay,order);assert.equal(orderPosts.length,2);assert.deepEqual(orderPosts[0],orderPosts[1]);
  const saved=(await review.query('SELECT * FROM secureshop_review.product_target_orders WHERE order_id=$1',[order.body.order_id])).rows;assert.equal(saved.length,1);assert.equal(cents(saved[0].total_amount),cents(restored.total));assert.equal(cents(saved[0].discount_amount),cents(restored.discount));
  const lines=(await review.query('SELECT * FROM secureshop_review.product_target_order_items WHERE target_id=$1 AND order_id=$2',[saved[0].target_id,order.body.order_id])).rows;assert.ok(lines.length);assert.equal(lines.reduce((n,x)=>n+cents(x.discount_amount),0),cents(restored.discount));
  const requests=(await review.query('SELECT operation_id,state FROM secureshop_review.bound_commerce_operations WHERE operation_id=$1',[posts[0].operationId])).rows;assert.deepEqual(requests,[{operation_id:posts[0].operationId,state:'completed'}]);
  await navigate('/secureshop/orders');await frame.waitForFunction(id=>document.body.innerText.includes('#'+id),{},order.body.order_id);
  const detail=await frame.waitForFunction(id=>{const row=[...document.querySelectorAll('table[aria-label="Orders list"] tbody tr')].find(r=>r.querySelector('td')?.textContent.trim()==='#'+id);return row&&[...row.querySelectorAll('button')].find(b=>b.textContent.trim()==='View'&&!b.disabled&&b.getClientRects().length);},{},order.body.order_id);await clickHandle(frame,detail);await detail.dispose();
  await frame.waitForFunction(id=>[...document.querySelectorAll('[role="dialog"]')].some(d=>d.innerText.includes('Order #'+id)),{},order.body.order_id);
  await clickText(frame,'Request refund','[role="dialog"]');await frame.waitForFunction(()=>document.body.innerText.includes('Refund request filed'));
  const tickets=(await review.query('SELECT ticket_id,order_id,status FROM secureshop_review.product_target_refund_requests WHERE target_id=$1 AND order_id=$2',[saved[0].target_id,order.body.order_id])).rows;assert.equal(tickets.length,1);assert.equal(Number(tickets[0].order_id),order.body.order_id);
  const refundAudits=(await review.query("SELECT event_id,params_json FROM secureshop_review.bound_audit_events WHERE action='refund_operation' AND target=$1",[String(tickets[0].ticket_id)])).rows;assert.equal(refundAudits.length,1);const refundReceipt=JSON.parse(refundAudits[0].params_json);assert.equal(String(refundReceipt.receipt.ticketId),String(tickets[0].ticket_id));assert.equal(refundReceipt.receipt.applied,true);
  const afterRefund=(await review.query('SELECT total_amount,payment_status FROM secureshop_review.product_target_orders WHERE target_id=$1 AND order_id=$2',[saved[0].target_id,order.body.order_id])).rows[0];assert.equal(cents(afterRefund.total_amount),cents(saved[0].total_amount));assert.equal(afterRefund.payment_status,saved[0].payment_status);
  await page.screenshot({path:path.join(root,'coupon-order-refund-request.png'),fullPage:true});
  const exactDialog=await frame.waitForFunction(id=>[...document.querySelectorAll('[role="dialog"]')].find(d=>d.querySelector('#ss-dialog-title')?.textContent.trim()==='Order #'+id),{},order.body.order_id);const close=await exactDialog.evaluateHandle(d=>d.querySelector('[aria-label="Close dialog"]'));await clickHandle(frame,close);await close.dispose();await exactDialog.dispose();await frame.waitForFunction(id=>![...document.querySelectorAll('[role="dialog"]')].some(d=>d.querySelector('#ss-dialog-title')?.textContent.trim()==='Order #'+id),{},order.body.order_id);
  await logout();await login('student_customer');const newCart=(await request('/api/secureshop/cart',null)).body;assert.notEqual(newCart.couponScopeKey,restored.couponScopeKey);const operationBefore=(await review.query('SELECT * FROM secureshop_review.bound_commerce_operations WHERE operation_id=$1',[posts[0].operationId])).rows;assert.equal(operationBefore.length,1);const stale=await request('/api/secureshop/cart/apply-coupon',posts[0]);couponResponses.push({phase:'new-session-old-operation',status:stale.status,error:typeof stale.body?.error==='string'?stale.body.error.slice(0,200):null,bodyKeys:Object.keys(stale.body||{}).sort().slice(0,20)});const operationAfter=(await review.query('SELECT * FROM secureshop_review.bound_commerce_operations WHERE operation_id=$1',[posts[0].operationId])).rows;assert.deepEqual(operationAfter,operationBefore,'Cross-session denial preserves original operation');const cartAfterDenied=await request('/api/secureshop/cart',null);assert.equal(cartAfterDenied.status,200);assert.deepEqual(cartAfterDenied.body,newCart,'Cross-session denial preserves new session cart');assert.ok([400,401,403,409].includes(stale.status),'Old persona-session UUID must not apply again');
  await logout();await login('student_merchant');const kpis=await request('/api/secureshop/merchant/overview/kpis',null);assert.equal(kpis.status,200);
  await navigate('/secureshop/merchant');await page.screenshot({path:path.join(root,'coupon-merchant.png'),fullPage:true});
  // Exact response shape is verified against the real metric producer before freeze.
  const merchantRevenue=kpis.body.revenue.value;assert.equal(cents(merchantRevenue)-cents(baselineRevenue),cents(order.body.total));
  const reset=await observeActionResponse(page,r=>new URL(r.url()).pathname.endsWith('/reset')&&r.request().method()==='POST',()=>clickText(page,'Reset launch'));assert.equal(reset.status(),200);
  const retainedRefundAudit=(await review.query('SELECT event_id,params_json FROM secureshop_review.bound_audit_events WHERE event_id=$1',[refundAudits[0].event_id])).rows;assert.deepEqual(retainedRefundAudit,refundAudits);
  const retired=(await review.query('SELECT lifecycle FROM secureshop_review.product_targets WHERE target_id=$1',[saved[0].target_id])).rows[0];assert.equal(retired.lifecycle,'retired');
  await launches.assertCurrent(require('../../server/services/secureshopConversationBinding').createLaunchScope(siblingLaunch.binding));assert.equal((await identity.query('SELECT count(*)::int n FROM workshop_platform.completions WHERE user_id=$1',[user.id])).rows[0].n,0);
  assert.deepEqual(blocked,[]);assert.deepEqual(errors,[],'Injected HTTP502 is expected; uncaught page errors are not');return{status:'passed',actualModelCalls:0,controlledRefundProvider:true,controlledResponseLoss:true,couponOperationId:posts[0].operationId,postCount:posts.length,sameUuid:true,orderId:order.body.order_id,refundRequest:tickets[0],refundSettlementClaim:false,subtotalCents:cents(restored.subtotal),discountCents:cents(restored.discount),totalCents:cents(restored.total),merchantRevenue,baselineRevenue,checkoutFormCompleted:true,paymentSimulationOnly:true,resetRetired:true,siblingLaunchCurrent:true,limitations:['Checkout payment approval and delivery copy are simulated; no payment settlement or email was performed','Fixed lookup denial reuses accepted native proof; this browser cohort is vulnerable mode only']};
 }catch(error){const authDiagnostic=frame?await frame.evaluate(()=>({origin:window.origin,readyState:document.readyState,controls:[...document.querySelectorAll('#ss-login-user,#ss-login-pw,[aria-label="Account menu"],a[href="/secureshop/login"]')].map(e=>({tag:e.tagName,id:e.id,disabled:!!e.disabled,display:getComputedStyle(e).display,visibility:getComputedStyle(e).visibility,opacity:getComputedStyle(e).opacity,rects:e.getClientRects().length}))})).catch(()=>({unavailable:true})):null;fs.writeFileSync(path.join(root,'coupon-browser-failure.json'),JSON.stringify({message:error.message,authDiagnostic,checkout:frame?await frame.evaluate(checkoutDiagnostic).catch(()=>({unavailable:true})):null,posts,orderPosts,couponResponses,errors,blocked}),{mode:0o600});if(page)await page.screenshot({path:path.join(root,'coupon-failure.png'),fullPage:true}).catch(()=>{});throw error;}finally{clearTimeout(timer);if(cdp)await cdp.detach().catch(()=>{});await browser.close();}
}
module.exports={qualifyCouponFullAppBrowser,findAction,summaryMatches,isPointerReady,couponAuthState,assertSelectedCart,captureCouponResponse,observeActionResponse,checkoutDiagnostic,replaceInput,captureOrderAction};
