'use strict';
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const {createHash}=require('node:crypto');
const ROUTE='/api/secureshop/admin/system/diagnostic';
const CAPABILITY='secureshop-owned-system-diagnostic.v1';
const {validateOwnedSystemMetrics}=require('../../sidecars/sandbox-runner/owned-system/health-contract');

// Real full-App opaque frame and real enabled backend. Only the lost-response
// fault is injected: replace one already-completed POST response, never its input.
async function qualifyEnabledSystemDiagnosticBrowser({origin,user,password,root,readExecutorCalls,readPersistedOperation,signal}){
 assert.equal(typeof readExecutorCalls,'function');assert.equal(typeof readPersistedOperation,'function');
 const url=new URL(origin);assert.equal(url.origin,origin);assert.equal(url.hostname,'127.0.0.1');
 const browser=await require('puppeteer').launch({headless:true,userDataDir:path.join(root,'system-diagnostic-browser'),args:['--disable-background-networking']});
 const errors=[],blocked=[],httpFailures=[],posts=[],captureContinuity=[];let page,cdp,drop=true,faultError,committed,healthProof,responsiveProof,lastContinuity,captureStage='not-started',resolveCommitted;
 const committedResponse=new Promise(resolve=>{resolveCommitted=resolve;});
 const close=()=>browser.close().catch(()=>{});signal?.addEventListener('abort',close,{once:true});
 const deadline=setTimeout(close,120000);
 try{
  page=await browser.newPage();await page.setViewport({width:1440,height:1100});
  await require('./fullBackendRenderedSecureShop').configurePage(page,origin,blocked,errors);
  page.on('response',response=>{const u=new URL(response.url());if(u.origin===origin&&response.status()>=400)httpFailures.push({method:response.request().method(),path:u.pathname,status:response.status()});});
  page.on('request',request=>{const u=new URL(request.url());if(u.origin===origin&&u.pathname===ROUTE&&request.method()==='POST'){const value=JSON.parse(request.postData());posts.push({operationId:value.operationId,cmd_template:value.cmd_template,args:value.args});}});
  const response=(pathname,method='GET')=>page.waitForResponse(r=>new URL(r.url()).origin===origin&&new URL(r.url()).pathname===pathname&&r.request().method()===method,{timeout:15000});
  const button=async(frame,text)=>{await frame.waitForFunction(text=>[...document.querySelectorAll('button')].some(b=>b.textContent.trim()===text&&!b.disabled),{},text);await frame.evaluate(text=>[...document.querySelectorAll('button')].find(b=>b.textContent.trim()===text&&!b.disabled).click(),text);};
  const fill=async(frame,selector,value)=>{await frame.waitForSelector(selector);await frame.$eval(selector,(element,text)=>{const setter=Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value').set;setter.call(element,text);element.dispatchEvent(new Event('input',{bubbles:true}));},value);assert.equal(await frame.$eval(selector,element=>element.value),value);};
  const getFrame=async()=>{const element=await page.waitForSelector('iframe[title="SecureShop workshop"]');const frame=await element.contentFrame();assert.ok(frame);await frame.waitForFunction(()=>window.origin==='null');return frame;};
  const platformLaunch=async()=>page.evaluate(async()=>{const token=localStorage.getItem('token');const response=await fetch('/api/auth/secureshop-launch',{headers:{Authorization:`Bearer ${token}`}});return{status:response.status,body:await response.json()};});
  const personaLogin=async frame=>{
   await frame.waitForFunction(()=>document.querySelector('#ss-login-user')||document.querySelector('a[href="/secureshop/login"]'));
   if(!await frame.$('#ss-login-user')){await frame.waitForSelector('a[href="/secureshop/login"]');await frame.click('a[href="/secureshop/login"]');await frame.waitForSelector('#ss-login-user');}
   await frame.type('#ss-login-user','student_admin');await frame.type('#ss-login-pw','student123');const pending=response('/api/secureshop/v2/auth/login','POST');await frame.click('button[type="submit"]');const result=await pending;assert.equal(result.status(),200);assert.equal((await result.json()).user.role,'admin');
  };
  const system=async frame=>{
   if(!await frame.$('a[href="/secureshop/admin/system"]')){await frame.waitForSelector('a[href="/secureshop/admin"]');await frame.click('a[href="/secureshop/admin"]');}
   await frame.waitForSelector('a[href="/secureshop/admin/system"]');const pending=response(ROUTE),healthPending=response('/api/secureshop/admin/system/health');await frame.click('a[href="/secureshop/admin/system"]');const result=await pending,healthResult=await healthPending;assert.equal(result.status(),200);const value=await result.json();assert.equal(value.administration.diagnosticCapability,CAPABILITY);assert.match(value.administration.scopeKey,/^[a-f0-9]{64}$/);
   assert.equal(healthResult.status(),200);const health=validateOwnedSystemMetrics(await healthResult.json());assert.equal(health.version,'secureshop-owned-system-metrics.v1');assert.equal(health.ok,true);assert.equal(health.metricsSource,'owned-system-listener');assert.equal(health.uptimeSource,'listener-process');assert.equal(health.loadSource,'unavailable');assert.equal(health.loadavg,null);assert.ok(Number.isFinite(health.uptime_s)&&health.uptime_s>=0);assert.ok(['cgroup-v2','unavailable'].includes(health.memorySource));
   if(health.memorySource==='cgroup-v2'){assert.equal(health.totalmem_mb,512);assert.ok(Number.isFinite(health.freemem_mb)&&health.freemem_mb>=0&&health.freemem_mb<=health.totalmem_mb);}else{assert.equal(health.totalmem_mb,null);assert.equal(health.freemem_mb,null);}
   healthProof={version:health.version,metricsSource:health.metricsSource,uptimeSource:health.uptimeSource,loadSource:health.loadSource,memorySource:health.memorySource,totalmem_mb:health.totalmem_mb};
   await frame.waitForFunction(()=>{const input=document.querySelector('[aria-label="Command template"]');return input&&!input.closest('form').querySelector('button').disabled;});return value.administration.scopeKey;
  };
  await page.goto(origin+'/workshop-login',{waitUntil:'domcontentloaded'});await page.waitForSelector('input[placeholder="Enter your username"]');
  await page.type('input[placeholder="Enter your username"]',user.username);await page.type('input[placeholder="Enter your password"]',password);
  const login=response('/api/auth/login','POST');await page.click('button[type="submit"]');assert.equal((await login).status(),200);await page.waitForFunction(()=>Boolean(localStorage.getItem('token')));await page.waitForFunction(()=>location.pathname==='/workshop-dashboard');
  await page.goto(origin+'/workshop/secureshop',{waitUntil:'domcontentloaded'});let frame=await getFrame();await personaLogin(frame);const originalScopeKey=await system(frame);
  cdp=await page.createCDPSession();
  cdp.on('Fetch.requestPaused',async event=>{
   try{
    const u=new URL(event.request.url);
    if(drop&&u.origin===origin&&u.pathname===ROUTE&&event.request.method==='POST'&&event.responseStatusCode===200){
     drop=false;const body=await cdp.send('Fetch.getResponseBody',{requestId:event.requestId});const value=JSON.parse(Buffer.from(body.body,body.base64Encoded?'base64':'utf8').toString('utf8'));
     assert.equal(value.state,'completed');assert.equal(value.ok,true);assert.equal(value.stdout,value.hostname+'\n');assert.equal(value.hostname,'system-diag-'+value.targetId.replaceAll('-',''));
     const persisted=await readPersistedOperation(value.operationId);assert.equal(persisted.state,'completed');assert.equal(persisted.receipt_json.result.operationId,value.operationId);assert.deepEqual(persisted.receipt_json,value.receipt);
     committed={operationId:value.operationId,hostname:value.hostname,targetId:value.targetId,stdout:value.stdout,executorCalls:await readExecutorCalls()};
     await cdp.send('Fetch.fulfillRequest',{requestId:event.requestId,responseCode:502,responseHeaders:[{name:'content-type',value:'application/json'},{name:'cache-control',value:'no-store'}],body:Buffer.from(JSON.stringify({error:'Owned response loss fixture'})).toString('base64')});resolveCommitted(committed);return;
    }
    await cdp.send('Fetch.continueRequest',{requestId:event.requestId});
   }catch(error){faultError=error;try{await cdp.send('Fetch.failRequest',{requestId:event.requestId,errorReason:'Failed'});}catch{}resolveCommitted(null);}
  });
  await cdp.send('Fetch.enable',{patterns:[{urlPattern:origin+ROUTE,requestStage:'Response'}]});
  const callsBefore=await readExecutorCalls();await frame.select('[aria-label="Command template"]','');await fill(frame,'[aria-label="Custom cmd_template"]','/usr/bin/uname');await fill(frame,'[aria-label="Custom command args"]','-n');await button(frame,'run');
  let interceptionTimer;try{await Promise.race([committedResponse,new Promise((_,reject)=>{interceptionTimer=setTimeout(()=>reject(Error('Committed response interception timed out')),15000);})]);}finally{clearTimeout(interceptionTimer);}if(faultError)throw faultError;assert.ok(committed);assert.equal(committed.executorCalls,callsBefore+1);
  await frame.waitForFunction(id=>document.body.textContent.includes(id)&&document.body.textContent.includes('diagnostic failed'),{},committed.operationId);
  await cdp.send('Fetch.disable');await cdp.detach();cdp=null;
  assert.equal(posts.length,1);await page.reload({waitUntil:'domcontentloaded'});frame=await getFrame();
  if(!await frame.$('[aria-label="Command template"]'))await system(frame);
  await frame.waitForFunction(id=>document.body.textContent.includes(id)&&[...document.querySelectorAll('button')].some(b=>b.textContent.trim()==='Refresh operation status'&&!b.disabled),{},committed.operationId);
  assert.equal(posts.length,1);assert.equal(await readExecutorCalls(),committed.executorCalls);
  const recovered=response('/api/secureshop/admin/system/diagnostic-operations/'+committed.operationId);await button(frame,'Refresh operation status');const recovery=await recovered;assert.equal(recovery.status(),200);const value=await recovery.json();assert.equal(value.state,'completed');assert.equal(value.operationId,committed.operationId);assert.equal(value.targetId,committed.targetId);assert.equal(value.stdout,committed.stdout);assert.equal(value.hostname,committed.hostname);
  await frame.waitForFunction(stdout=>[...document.querySelectorAll('pre')].some(node=>{try{return JSON.parse(node.textContent).stdout===stdout;}catch{return false;}}),{},value.stdout);assert.equal(posts.length,1);assert.equal(await readExecutorCalls(),committed.executorCalls);
  await frame.waitForFunction(({id,stdout})=>{
   const selector=document.querySelector('[aria-label="Command template"]');const section=selector?.closest('section');
   return section&&[...section.querySelectorAll('pre')].some(node=>{try{return JSON.parse(node.textContent).stdout===stdout;}catch{return false;}})&&section.textContent.includes('EXECUTED')&&!section.textContent.includes('REQUEST FAILED')&&!section.textContent.includes('Diagnostic '+id+' · outcome')&&!section.querySelector('[role="alert"]');
  },{},{id:committed.operationId,stdout:committed.stdout});
  const originalFrame=frame,launchBaseline=await platformLaunch();assert.equal(launchBaseline.status,200);const continuity=[];
  const verifyContinuity=async stage=>{
   assert.equal(await getFrame(),originalFrame);const launch=await platformLaunch();assert.equal(launch.status,200);assert.equal(launch.body.launch.launchId,launchBaseline.body.launch.launchId);assert.equal(launch.body.launch.generation,launchBaseline.body.launch.generation);
   const state=await frame.evaluate(async id=>{const available=await fetch('/api/secureshop/admin/system/diagnostic'),availability=await available.json();const operation=await fetch('/api/secureshop/admin/system/diagnostic-operations/'+id),value=await operation.json();const section=document.querySelector('[aria-label="Command template"]')?.closest('section');return{status:operation.status,scope:availability.administration?.scopeKey,targetId:value.targetId,stdout:value.stdout,rendered:[...(section?.querySelectorAll('pre')||[])].some(node=>{try{return JSON.parse(node.textContent).stdout===value.stdout;}catch{return false;}})&&section?.textContent.includes('EXECUTED')&&!section?.textContent.includes('REQUEST FAILED'),retainedReference:section?.textContent.includes('Diagnostic '+id+' · outcome')};},committed.operationId);
   assert.equal(state.status,200);assert.equal(state.scope,originalScopeKey);assert.equal(state.targetId,committed.targetId);assert.equal(state.stdout,committed.stdout);assert.equal(state.rendered,true);assert.equal(state.retainedReference,false);assert.equal(posts.length,1);assert.equal(await readExecutorCalls(),committed.executorCalls);continuity.push({stage,...state});
  };
  const screenshots=[];
  for(const [label,width,height] of [['desktop',1440,1100],['narrow',390,844]]){
   await page.setViewport({width,height});await verifyContinuity(label+':before');await frame.$eval('[aria-label="Command template"]',node=>node.closest('section').scrollIntoView({block:'start'}));
   await frame.waitForFunction(()=>document.getAnimations({subtree:true}).every(a=>['finished','idle'].includes(a.playState)));
   assert.equal(await frame.evaluate(()=>document.documentElement.scrollWidth<=document.documentElement.clientWidth+1),true);
   assert.equal(await readExecutorCalls(),committed.executorCalls);assert.equal(posts.length,1);
   const element=await page.$('iframe[title="SecureShop workshop"]');const name=`enabled-system-diagnostic-${label}.png`;await element.screenshot({path:path.join(root,name)});screenshots.push(name);await verifyContinuity(label+':after');
  }
  await page.setViewport({width:1440,height:1100});
  await frame.click('[aria-label="Account menu"]');const loggedOut=response('/api/secureshop/v2/auth/logout','POST');await button(frame,'Sign out');assert.equal((await loggedOut).status(),200);
  await personaLogin(frame);const laterScopeKey=await system(frame);assert.notEqual(laterScopeKey,originalScopeKey);
  const denied=await frame.evaluate(async id=>{const response=await fetch('/api/secureshop/admin/system/diagnostic-operations/'+id);return{status:response.status,body:await response.json()};},committed.operationId);assert.equal(denied.status,409);assert.equal(denied.body.code,'OPERATION_CONFLICT');assert.equal(await readExecutorCalls(),committed.executorCalls);assert.equal(posts.length,1);
  assert.deepEqual(errors,[]);assert.deepEqual(blocked,[]);
  const failures=httpFailures.map(row=>({...row,scope:row.path===ROUTE&&row.method==='POST'&&row.status===502?'injected-response-loss':row.path==='/api/secureshop/admin/system/diagnostic-operations/'+committed.operationId&&row.method==='GET'&&row.status===409?'expected-new-session-denial':row.path===ROUTE||row.path==='/api/secureshop/admin/system/health'||row.path.startsWith('/api/secureshop/admin/system/diagnostic-operations/')?'system-failure':'outside-system-acceptance'}));assert.equal(failures.filter(row=>row.scope==='system-failure').length,0);
  const result={scope:'Actual full App opaque frame/platform and persona login/enabled backend/native PG/private HTTP diagnostic executor. No model/Judge evidence.',opaqueFrame:true,health:healthProof,operationId:committed.operationId,targetId:committed.targetId,hostname:committed.hostname,executorCallsForBrowser:1,persistedBeforeResponseLoss:true,reloadRecoveryWithoutResend:true,laterSessionDenied:true,terminalRendered:true,completedReferenceRemoved:true,continuity,screenshots,httpFailures:failures};fs.writeFileSync(path.join(root,'enabled-system-diagnostic-browser-result.json'),JSON.stringify(result,null,2));return result;
 }catch(error){if(page&&!page.isClosed())await page.screenshot({path:path.join(root,'enabled-system-diagnostic-browser-failure.png'),fullPage:true}).catch(()=>{});fs.writeFileSync(path.join(root,'enabled-system-diagnostic-browser-failure.json'),JSON.stringify({message:error.message,posts,httpFailures,errors,blocked},null,2));throw error;}
 finally{clearTimeout(deadline);signal?.removeEventListener('abort',close);if(cdp)await cdp.detach().catch(()=>{});await browser.close();}
}
module.exports={qualifyEnabledSystemDiagnosticBrowser};
