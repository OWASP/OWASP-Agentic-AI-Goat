'use strict';
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');

// Caller owns the native platform/launch/gateway and real renderer. Fault controls
// interrupt only the response or schedule a real competing mutation; they never
// fabricate a policy result. This helper exercises the existing opaque App frame.
async function qualifyPromptPoliciesBrowser({origin,user,password,root,advanceHead,dropNextCompletedResponse,readOperation,rendererCount}){
  for(const fn of [advanceHead,dropNextCompletedResponse,readOperation,rendererCount])assert.equal(typeof fn,'function');
  const browser=await require('puppeteer').launch({headless:true,userDataDir:path.join(root,'prompt-policies-browser'),args:['--disable-background-networking']});
  const errors=[],blocked=[],result={scope:'Actual Policies page through opaque frame and bridge; native bound gateway/repository and real renderer supplied by owned caller.',checks:[]};
  let page;const httpFailures=[];
  try{
    fs.writeFileSync(path.join(root,'prompt-policies-browser-owner.json'),JSON.stringify({pid:browser.process().pid}),{mode:0o600});
    page=await browser.newPage();await page.setViewport({width:1440,height:1100});
    await require('./fullBackendRenderedSecureShop').configurePage(page,origin,blocked,errors);
    page.on('response',r=>{const u=new URL(r.url());if(u.origin===origin&&r.status()>=400)httpFailures.push({path:u.pathname,status:r.status(),method:r.request().method(),operationId:(()=>{try{return JSON.parse(r.request().postData()||'{}').operationId||null;}catch{return null;}})()});});
    const response=(pathname,method='GET')=>page.waitForResponse(r=>new URL(r.url()).origin===origin&&new URL(r.url()).pathname===pathname&&r.request().method()===method,{timeout:30000});
    await page.goto(origin+'/workshop-login',{waitUntil:'domcontentloaded'});
    await page.waitForSelector('input[placeholder="Enter your username"]');await page.type('input[placeholder="Enter your username"]',user.username);await page.type('input[placeholder="Enter your password"]',password);
    const signedIn=response('/api/auth/login','POST');await page.click('button[type="submit"]');assert.equal((await signedIn).status(),200);await page.waitForFunction(()=>Boolean(localStorage.getItem('token')));
    await page.goto(origin+'/workshop/secureshop',{waitUntil:'domcontentloaded'});
    let frame;
    const getFrame=async()=>{const element=await page.waitForSelector('iframe[title="SecureShop workshop"]');frame=await element.contentFrame();assert.ok(frame);await frame.waitForFunction(()=>window.origin==='null');};
    await getFrame();await frame.waitForSelector('a[href="/secureshop/login"]');await frame.click('a[href="/secureshop/login"]');await frame.waitForSelector('#ss-login-user');await frame.type('#ss-login-user','student_admin');await frame.type('#ss-login-pw','student123');await frame.click('button[type="submit"]');
    await frame.waitForSelector('a[href="/secureshop/admin"]');await frame.click('a[href="/secureshop/admin"]');await frame.waitForSelector('a[href="/secureshop/admin/policies"]');await frame.click('a[href="/secureshop/admin/policies"]');
    const click=async text=>{await frame.waitForFunction(t=>Array.from(document.querySelectorAll('button')).some(e=>e.textContent.trim()===t&&!e.disabled),{},text);await frame.evaluate(t=>Array.from(document.querySelectorAll('button')).find(e=>e.textContent.trim()===t).click(),text);};
    const fill=async(selector,value)=>{await frame.waitForSelector(selector);await frame.$eval(selector,(element,text)=>{const setter=Object.getOwnPropertyDescriptor(element.tagName==='TEXTAREA'?HTMLTextAreaElement.prototype:HTMLInputElement.prototype,'value').set;setter.call(element,text);element.dispatchEvent(new Event('input',{bubbles:true}));},value);};
    const settled=async()=>{await frame.waitForFunction(()=>document.getAnimations({subtree:true}).every(a=>a.playState==='finished'||a.playState==='idle'));};
    await click('+ new policy');await frame.waitForSelector('.ss-role-modal');
    await fill('.ss-role-modal input[placeholder="e.g. return_policy"]','browser_policy');await fill('.ss-role-modal textarea','Browser policy arithmetic: {{ 6 * 7 }}.');
    const unsupported=await frame.$$eval('.ss-role-modal label',labels=>labels.filter(l=>/summarizer|review-moderator|price-advisor|analytics/.test(l.textContent)).map(l=>({text:l.textContent,disabled:l.querySelector('input')?.disabled})));assert.equal(unsupported.length,4);assert.ok(unsupported.every(r=>r.disabled));result.checks.push('four unsupported targets disabled');
    let pending=response('/api/secureshop/admin/policies','POST');await click('create');let received=await pending;assert.equal(received.status(),200);let payload=await received.json();assert.equal(payload.receipt.renderResult.rendered,'Browser policy arithmetic: 42.');result.created=payload.receipt;result.checks.push('actual rendered create');
    await frame.waitForFunction(()=>!document.querySelector('.ss-role-modal'));await frame.waitForSelector('section textarea');await fill('section textarea','Edited arithmetic: {{ 7 * 7 }}.');
    pending=response('/api/secureshop/admin/policies/browser_policy/render','POST');await click('test render (no persist)');received=await pending;assert.equal(received.status(),200);payload=await received.json();assert.equal(payload.receipt.renderResult.rendered,'Edited arithmetic: 49.');assert.equal(payload.receipt.version,result.created.version);result.checks.push('preview renders without version advance');
    pending=response('/api/secureshop/admin/policies','POST');await click('save (renders → persists)');received=await pending;assert.equal(received.status(),200);payload=await received.json();assert.equal(payload.receipt.renderResult.rendered,'Edited arithmetic: 49.');result.saved=payload.receipt;result.checks.push('edit persists rendered output');
    await fill('section textarea','Stale local draft');await advanceHead();pending=response('/api/secureshop/admin/policies','POST');await click('save (renders → persists)');const conflictResponse=await pending;assert.equal(conflictResponse.status(),409);result.conflictOperationId=JSON.parse(conflictResponse.request().postData()).operationId;assert.equal(await frame.$eval('section textarea',e=>e.value),'Stale local draft');result.checks.push('real CAS conflict preserves draft');
    // A definitive CAS rejection is distinct from uncertain transport. Only
    // this explicit action adopts the current head; no render is repeated.
    await click('Review current policy version');assert.equal(await frame.$eval('section textarea',e=>e.value),'Stale local draft');await click('Reload policies');
    await frame.waitForFunction(()=>Array.from(document.querySelectorAll('aside button')).some(e=>e.textContent.includes('browser_policy')));await frame.evaluate(()=>Array.from(document.querySelectorAll('aside button')).find(e=>e.textContent.includes('browser_policy')).click());
    await fill('section textarea','Lost response arithmetic: {{ 8 * 8 }}.');await dropNextCompletedResponse();await click('save (renders → persists)');await frame.waitForFunction(()=>document.body.textContent.includes('Refresh operation status'));
    const operation=await readOperation();
    await frame.click('a[href="/secureshop/admin"]');await frame.waitForSelector('a[href="/secureshop/admin/policies"]');await frame.click('a[href="/secureshop/admin/policies"]');await frame.waitForFunction(()=>document.body.textContent.includes('Refresh operation status'));result.checks.push('pending metadata survives Policies remount');
    assert.equal(operation.state,'completed');result.lostResponseOperationId=operation.operationId;const committedRendererCount=operation.rendererCount;assert.equal(await rendererCount(),committedRendererCount);
    await click('Refresh operation status');await frame.waitForFunction(()=>!Array.from(document.querySelectorAll('button')).some(e=>e.textContent==='Refresh operation status'));assert.equal(await rendererCount(),committedRendererCount);result.checks.push('lost response recovered by readback without rerender');
    await settled();await page.screenshot({path:path.join(root,'prompt-policies-editor-settled.png'),fullPage:true});
    pending=response('/api/secureshop/admin/policies/browser_policy','DELETE');await click('delete');await frame.waitForSelector('.ss-role-modal');await frame.$eval('.ss-role-modal button.ss-btn:not(.ss-btn--ghost)',e=>e.click());received=await pending;assert.equal(received.status(),200);result.deleted=await received.json();result.checks.push('delete');
    await settled();await page.screenshot({path:path.join(root,'prompt-policies-settled.png'),fullPage:true});assert.deepEqual(errors,[],'Uncaught page errors are not outside-scope API failures');const outsideScope=path=>/^\/api\/secureshop\/(products|categories|cart|orders|recommended|admin\/(kpis|agent-host|mcp|db-sizes|trace|audit))(?:\/|$)/.test(path)||/^\/api\/(changes|solutions|hints|ctf\/config|auth\/permissions)(?:\/|$)/.test(path);result.httpFailures=httpFailures.map(row=>({...row,attribution:row.path==='/api/secureshop/admin/policies'&&row.method==='POST'&&row.status===502&&row.operationId===result.lostResponseOperationId?'expected owned postcommit response drop':((row.path==='/api/secureshop/admin/policies'&&row.method==='POST'&&row.status===409&&row.operationId===result.conflictOperationId)||(row.path===`/api/secureshop/admin/policies/operations/${result.conflictOperationId}`&&row.method==='GET'&&row.status===404))?'expected conflict/readback':outsideScope(row.path)?'explicitly unavailable unrelated fixture surface':'unexpected'}));assert.ok(result.httpFailures.every(row=>row.attribution!=='unexpected'),JSON.stringify(result.httpFailures));result.errors=errors;result.blocked=blocked;fs.writeFileSync(path.join(root,'prompt-policies-browser-result.json'),JSON.stringify(result,null,2));return result;
  }catch(error){const frames=[];for(const frame of page?.frames()||[]){try{frames.push({url:frame.url(),text:await frame.$eval('body',e=>e.innerText)});}catch{}}fs.writeFileSync(path.join(root,'prompt-policies-browser-failure.json'),JSON.stringify({error:{name:error.name,message:error.message},errors,blocked,httpFailures,frames},null,2));await page?.screenshot({path:path.join(root,'prompt-policies-failure.png'),fullPage:true}).catch(()=>{});throw error;}finally{await browser.close();}
}
module.exports={qualifyPromptPoliciesBrowser};
