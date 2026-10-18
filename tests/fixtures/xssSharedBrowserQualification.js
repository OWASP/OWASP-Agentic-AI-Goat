
'use strict';
// Frozen retained shared-renderer cases. No launch, provider or database imports.
const assert = require('node:assert/strict');
const {createXssBrowserQualification, MAX_HTML_BYTES} = require('../../server/services/xssBrowserQualification');
const WORK_MS=120000, CLEANUP_MS=5000;
async function bounded(work,ms,label){let timer;try{return await Promise.race([work,new Promise((_,reject)=>{timer=setTimeout(()=>reject(Object.assign(new Error(label),{code:'SHARED_BROWSER_DEADLINE'})),ms);})]);}finally{clearTimeout(timer);}}
async function qualifySharedBrowserModes({browser}) {
 if(typeof browser?.createBrowserContext!=='function'||typeof browser?.browserContexts!=='function'||typeof browser?.wsEndpoint!=='function'||typeof browser?.target!=='function')throw TypeError('Owned connected browser required');
 const originalContexts=new Set(browser.browserContexts()),cases=[],groups=[];const controller=new AbortController();
 const deadline=setTimeout(()=>controller.abort(Object.assign(new Error('Shared browser qualification deadline'),{code:'SHARED_BROWSER_DEADLINE'})),WORK_MS);
 let connected, connectionContexts;
 const connect=async()=>{connected=await require('puppeteer').connect({browserWSEndpoint:browser.wsEndpoint(),protocolTimeout:15000});connectionContexts=new Set(connected.browserContexts());return connected;};
 let active,primary,baselineSession,baselinePending,observerRetiring=false,observerCleanup,globalContextIds;
 const checkBaseline=async()=>{
  if(!baselinePending){
   baselinePending=Promise.resolve().then(()=>browser.target().createCDPSession()).then(session=>{
    baselineSession=session;
    if(observerRetiring)observerCleanup=bounded(session.detach(),CLEANUP_MS,'Late context observer detach deadline');
    observerCleanup?.catch(()=>{});
    return session;
   });
  }
  if(!baselineSession)await bounded(baselinePending,CLEANUP_MS,'Context observer admission');
  const observed=await bounded(baselineSession.send('Target.getBrowserContexts'),CLEANUP_MS,'Context observer deadline');
  assert(Array.isArray(observed.browserContextIds));const ids=[...observed.browserContextIds].sort();
  if(!globalContextIds)globalContextIds=ids;else assert.deepEqual(ids,globalContextIds,'Protocol-global qualification contexts must retire');
  assert.deepEqual(new Set(browser.browserContexts()),originalContexts,'Owner context baseline unchanged');
  if(connected&&connectionContexts)assert.deepEqual(new Set(connected.browserContexts()),connectionContexts,'Every qualification context must retire');
 };
 async function group(name,work){
  controller.signal.throwIfAborted();await checkBaseline();
  active=createXssBrowserQualification({connectBrowser:connect,timeoutMs:8000,retirementTimeoutMs:CLEANUP_MS});
  const runner={};
  for(const method of ['qualify','qualifyDocument'])runner[method]=async(html,options={})=>{
   controller.signal.throwIfAborted();
   const result=await active[method](html,{...options,signal:controller.signal});
   await checkBaseline();cases.push({group:name,index:cases.length+1,method,html,options,result,contextBaseline:originalContexts.size,contextsAfter:browser.browserContexts().length,protocolContextIds:[...globalContextIds]});
   return result;
  };
  let failure;
  try {await work(runner);groups.push(name);} catch(error){failure=error;throw error;}
  finally {try{await bounded(active.close(),CLEANUP_MS+100,'Shared runner close deadline');active=null;connected=null;connectionContexts=null;}catch(error){if(failure)failure.cleanupErrorCode=error.code||'SHARED_BROWSER_CLEANUP';else throw error;}}

 }
 try {
  await group('fresh sandboxed browser context reproduces innerHTML event handlers and blocks external requests', async runner => {

  for (const html of [
    '<img src="https://attacker.invalid/pixel" onerror=alert(document.domain)>',
    '<input onfocus=alert(1)>',
    '<input oninput=alert(5)>',
    '<details ontoggle=alert(2)>test</details>',
    '<svg onmouseover=alert(3)>hover</svg>',
    '<button onclick=alert(6)>click</button>',
    '<a href="javascript:alert(7)">link</a>',
  ]) {
    const result = await runner.qualify(html);
    assert.equal(result.executed, true, `${html}: ${JSON.stringify(result)}`);
    assert.equal(result.syntheticCookieOnly, true);
  }
  const network = await runner.qualify('<img src="https://attacker.invalid/collect" onerror=alert(4)>');
  assert(network.blockedRequests.some(item => item.url === 'https://attacker.invalid/collect'));
  assert.equal(network.elementCount, 1);
  });
  await group('script tags inserted with innerHTML do not execute and plain markup remains non-executable', async runner => {

  assert.equal((await runner.qualify('<script>alert(1)</script>')).executed, false);
  assert.equal((await runner.qualify('<b>rendered markup</b>')).executed, false);
  });
  await group('learner element comparison allows presentation attributes but preserves source DOM semantics', async runner => {


  const styled = await runner.qualify('<div class="assistant"><b style="font-family: Arial">hello</b></div>', {
    learnerHtml: '<b>hello</b>',
  });
  assert.equal(styled.learnerElementPreserved, true, JSON.stringify(styled));
  assert.equal(styled.learnerElementTag, 'b');

  const cases = [
    {
      learnerHtml: '<a href="/original">open</a>',
      output: '<a href="/changed">open</a>',
      label: 'changed learner attribute',
    },
    { learnerHtml: '<b>hello</b>', output: '<b style="color:red">goodbye</b>', label: 'changed learner content' },
    { learnerHtml: '<b>hello</b>', output: '&lt;b&gt;hello&lt;/b&gt;', label: 'escaped learner markup' },
    { learnerHtml: '<b>hello</b>', output: '<div><b>unrelated</b><span>hello</span></div>', label: 'unrelated wrapper markup' },
  ];
  for (const fixture of cases) {
    const result = await runner.qualify(fixture.output, { learnerHtml: fixture.learnerHtml });
    assert.equal(result.learnerElementPreserved, false, `${fixture.label}: ${JSON.stringify(result)}`);
  }

  const noInput = await runner.qualify('<b style="font-family:Arial">hello</b>');
  assert.equal(noInput.learnerElementPreserved, false);
  assert.equal(noInput.learnerElementTag, null);
  });
  await group('document renderer proves inline script parsing without attributing sibling handlers', async runner => {

  const script = await runner.qualifyDocument('<script>alert(1)</script>');
  assert.equal(script.executed, true);
  assert.equal(script.scriptExecuted, true);
  assert.equal(script.renderingMode, 'document');

  const sibling = await runner.qualifyDocument(`<script type="application/json">{}</script>
    <img src=x onerror="window.__dvaiaXssMarkers=[];window.__dvaiaXssMarkers.push({kind:'script',value:'parser_execution'})">`);
  assert.equal(sibling.executed, false);
  assert.equal(sibling.scriptExecuted, false);
  assert.deepEqual(sibling.markers, [], 'page-owned marker writes are not browser evidence');

  const source = '<script>alert(3)</script>';
  for (const persisted of [
    `<!--${source}--><script>alert(9)</script>`,
    `<template>${source}</template><script>alert(9)</script>`,
    `<textarea>${source}</textarea><script>alert(9)</script>`,
  ]) {
    const contextual = await runner.qualifyDocument(persisted, { scriptSource: source });
    assert.equal(contextual.executed, true, persisted);
    assert.equal(contextual.scriptExecuted, false, persisted);
  }
  });
  await group('innerHTML target attribution rejects inert fields despite an executing sibling handler', async runner => {

  const source = '<img src=x onerror=alert(2)>';
  for (const persisted of [
    `<!--${source}--><img src=x onerror=alert(9)>`,
    `<template>${source}</template><img src=x onerror=alert(9)>`,
    `<textarea>${source}</textarea><img src=x onerror=alert(9)>`,
  ]) {
    const result = await runner.qualify(persisted, { eventSource: source });
    assert.equal(result.executed, false, persisted);
    assert.equal(result.targetEventExecuted, false, persisted);
  }
  const active = await runner.qualify(`<section>${source}</section><img src=x onerror=alert(9)>`, { eventSource: source });
  assert.equal(active.targetEventExecuted, true);

  const copied = `<textarea id="stolen">${source}</textarea>
    <img src=x onerror="const proof=document.querySelector('#stolen').value.match(/globalThis\\.([A-Za-z0-9_]+)\\(String\\(0x([a-f0-9]+)n\\)\\)/);if(proof){this.setAttribute('onerror','globalThis.'+proof[1]+'(String(0x'+proof[2]+'n));alert(99)');this.dispatchEvent(new Event('error'))}">`;
  const spoof = await runner.qualify(copied, { eventSource: source });
  assert.equal(spoof.targetEventExecuted, false, JSON.stringify(spoof));
  assert.equal(spoof.executed, false, 'non-target executable attributes are disabled before live DOM attachment');

  const quoted = await runner.qualify(`<div title='${source}'>safe</div><img src=x onerror=alert(9)>`, { eventSource: source });
  assert.equal(quoted.targetEventExecuted, false, JSON.stringify(quoted));
  assert.equal(quoted.executed, false, 'instrumentation must not change an inert quoted-attribute parse');
  });
  await group('innerHTML target attribution supports javascript URLs in their persisted context', async runner => {

  const source = '<a href="javascript:alert(7)">open</a>';
  const active = await runner.qualify(`<section>${source}</section><img src=x onerror=alert(9)>`, { eventSource: source });
  assert.equal(active.executed, true, JSON.stringify(active));
  assert.equal(active.targetEventExecuted, true, JSON.stringify(active));

  const inert = await runner.qualify(`<textarea>${source}</textarea><img src=x onerror=alert(9)>`, { eventSource: source });
  assert.equal(inert.targetEventExecuted, false, JSON.stringify(inert));
  assert.equal(inert.executed, false, JSON.stringify(inert));

  const bareUrl = 'javascript:alert(8)';
  const substitutedUrl = await runner.qualify(`<a href="${bareUrl}">open</a>`, { eventSource: bareUrl });
  assert.equal(substitutedUrl.targetEventExecuted, true, JSON.stringify(substitutedUrl));

  const breakout = '" onmouseover=alert(3) data-x="';
  const substitutedAttribute = await runner.qualify(`<div title="${breakout}">hover</div>`, { eventSource: breakout });
  assert.equal(substitutedAttribute.targetEventExecuted, true, JSON.stringify(substitutedAttribute));

  const mixedOrigin = '<img src=x onclick="void 0" onerror="alert(4)">';
  const modelOnly = await runner.qualify(mixedOrigin, { eventSources: ['onclick="void 0"'] });
  assert.equal(modelOnly.targetEventExecuted, true, JSON.stringify(modelOnly));
  assert.equal(modelOnly.targetEffectObserved, false, 'profile-owned onerror must be removed from the target projection');

  const fakeEffect = '<img src=x onerror="window.__dvaiaXssMarkers=[];window.__dvaiaXssMarkers.push({kind:\'alert\',value:\'1\'})">';
  const forged = await runner.qualify(fakeEffect, { eventSource: fakeEffect });
  assert.equal(forged.targetEventExecuted, true, JSON.stringify(forged));
  assert.equal(forged.targetEffectObserved, false, 'page-owned marker writes cannot impersonate a browser dialog');
  });
  await group('oversized learner comparison source is rejected without changing candidate qualification', async runner => {

  const result = await runner.qualify('<b>hello</b>', { learnerHtml: `<b>${'x'.repeat(MAX_HTML_BYTES)}</b>` });
  assert.equal(result.reason, 'no_instrumented_execution');
  assert.equal(result.elementCount, 1);
  assert.equal(result.learnerElementPreserved, false);
  assert.equal(result.learnerElementTag, null);
  });
  await group('popup effect and context retirement',async runner=>{
   const result=await runner.qualify('<button onclick="window.open(\'about:blank\')">open</button>');
   assert(result.markers.some(effect=>effect.kind==='window_open'));
  });
  // A trusted test mount stalls only until cancellation. The renderer and its
  // real BrowserContext still use production initialization and cleanup.
  controller.signal.throwIfAborted();let entered;const mounted=new Promise(resolve=>entered=resolve),stop=new AbortController();
  active=createXssBrowserQualification({connectBrowser:connect,timeoutMs:8000,retirementTimeoutMs:CLEANUP_MS,
   clientMount:async(_page,{signal})=>{entered();await new Promise((resolve,reject)=>{if(signal.aborted)return reject(signal.reason);signal.addEventListener('abort',()=>reject(signal.reason),{once:true});});}});
  const cancelled=active.qualifyClient('<b>cancelled controlled mount</b>',{signal:AbortSignal.any([stop.signal,controller.signal])});
  const rejection=assert.rejects(cancelled,{name:'AbortError'});rejection.catch(()=>{});
  await bounded(mounted,8000,'Cancellation mount admission deadline');stop.abort();await rejection;await checkBaseline();
  cases.push({group:'physical cancellation',index:cases.length+1,method:'qualifyClient',cancelled:true,contextBaseline:originalContexts.size,contextsAfter:browser.browserContexts().length,protocolContextIds:[...globalContextIds]});
  const next=await active.qualify('<b>next qualification</b>',{signal:controller.signal});assert.equal(next.executed,false);await checkBaseline();
  cases.push({group:'physical cancellation recovery',index:cases.length+1,method:'qualify',html:'<b>next qualification</b>',result:next,contextBaseline:originalContexts.size,contextsAfter:browser.browserContexts().length,protocolContextIds:[...globalContextIds]});
  await bounded(active.close(),CLEANUP_MS+100,'Shared runner close deadline');active=null;connected=null;connectionContexts=null;
  controller.signal.throwIfAborted();await checkBaseline();
  return {version:1,status:'passed',scope:'Shared renderer semantics only; no model, database or objective credit',workBudgetMs:WORK_MS,cleanupBudgetMs:CLEANUP_MS,groups,cases,contextBaseline:originalContexts.size,contextsAfter:browser.browserContexts().length,protocolContextIds:[...globalContextIds]};
 } catch(error){primary=error;error.sharedBrowserQualification={version:1,status:'failed',groups,cases,completedCases:cases.length};throw error;} finally {
  clearTimeout(deadline);controller.abort();
  let cleanupError;
  if(active){try{await bounded(active.close(),CLEANUP_MS+100,'Shared runner final close deadline');}catch(error){cleanupError=error;}}
  observerRetiring=true;
  if(baselinePending){
   try{
    await bounded(baselinePending,CLEANUP_MS,'Context observer ownership unresolved');
    if(!observerCleanup)observerCleanup=bounded(baselineSession.detach(),CLEANUP_MS,'Context observer detach deadline');
    await observerCleanup;
   }catch(error){cleanupError ||= error;}
  }
  if(cleanupError){if(primary)primary.cleanupErrorCode=cleanupError.code||'SHARED_BROWSER_CLEANUP';else throw cleanupError;}
 }
}
module.exports={qualifySharedBrowserModes};
