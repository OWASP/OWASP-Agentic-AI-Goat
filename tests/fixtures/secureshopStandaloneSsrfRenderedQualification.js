'use strict';

// Browser flow only. The owning isolated caller supplies the real app, pinned
// browser/14-call forwarding transport, canonical SQL readers and Judge capture.
// This module never creates authority, a terminal, an HTTP effect or a verdict.
const assert=require('node:assert/strict');
const path=require('node:path');
const {createHash}=require('node:crypto');
const TOTAL_MODEL_CALLS=14;
const RUN_PATH='/api/secureshop/v2/controlled-ssrf/run';
const HTML_BASE='/api/secureshop/v2/controlled-ssrf/html';
const HTML_RUN_PATH=HTML_BASE+'/run';
const BOOTSTRAP_PATH='/api/secureshop/auth/bootstrap';
const MODE_PATH='/api/secureshop/auth/mode';
const UUID=/^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i;
const COUNTER_KEYS=Object.freeze(['actor','judge','http','turns','invocations','traces','judgments','contributions']);

function assertCounters(value,{complete=false}={}){
 assert(value&&Object.getPrototypeOf(value)===Object.prototype);
 assert.deepEqual(Object.keys(value).sort(),[...COUNTER_KEYS].sort());
 for(const count of Object.values(value))assert(Number.isSafeInteger(count)&&count>=0);
 assert(value.actor+value.judge<=TOTAL_MODEL_CALLS,'The existing 14-call transport budget was exhausted');
 assert(value.judge<=4,'The four-Judge-call ceiling was exceeded');
 if(complete){assert(value.actor>=6,'Three genuine decision/final turns are required');assert(value.judge>=1,'A genuine protected-case Judge call is required');}
 return value;
}

function exactRunRequest(value){
 assert(value&&Object.getPrototypeOf(value)===Object.prototype);
 assert.deepEqual(Object.keys(value).sort(),['request_id','resource']);
 assert(['public-policy','private-policy'].includes(value.resource));assert.match(value.request_id,UUID);
 return value;
}
function exactPolicyRunRequest(value){
 assert(value&&Object.getPrototypeOf(value)===Object.prototype);
 assert.deepEqual(Object.keys(value).sort(),['policy_html','request_id']);assert.match(value.request_id,UUID);
 assert.equal(typeof value.policy_html,'string');assert(value.policy_html.trim()&&value.policy_html.isWellFormed());
 assert(!value.policy_html.includes('\0')&&Buffer.byteLength(value.policy_html)<=8192);return value;
}
function exactPolicyRunResponse(value,{requestId,sessionId=null,replayed=false,mode}={}){
 assert(value&&Object.getPrototypeOf(value)===Object.prototype);
 assert.deepEqual(Object.keys(value).sort(),['sessionId','requestId','response','stopReason','replayed','modeCapability'].sort());
 assert.match(value.sessionId,UUID);assert.equal(value.requestId,requestId);if(sessionId!==null)assert.equal(value.sessionId,sessionId);
 assert.equal(value.stopReason,'end_turn');assert.equal(value.replayed,replayed);assert.equal(typeof value.response,'string');
 assert(value.response.trim()&&value.response.isWellFormed()&&!value.response.includes('\0')&&Buffer.byteLength(value.response)<=20000);
 assert(['vuln','fixed'].includes(mode));assert.deepEqual(value.modeCapability,{version:1,featureId:'controlled_ssrf',
  policyVersion:'owned-public-destination-v1',effectiveMode:mode,scope:{kind:'launch_feature',id:'controlled_ssrf'}});return value;
}

// Shared transport fault: only original bytes are transmitted, after headers.
function writeTruncatedJsonAcknowledgement(response,originalBytes,onWritten){
 assert(Buffer.isBuffer(originalBytes)&&originalBytes.length>1&&originalBytes.length<=262144);
 assert.equal(typeof onWritten,'function');
 response.writeHead(response.statusCode,{'content-type':'application/json','content-length':originalBytes.length});
 response.flushHeaders();response.write(originalBytes.subarray(0,1),onWritten);
}

// Install after express.json(), before the real bound dispatch. Only a real,
// completed private response is withheld; no response body is synthesized.
function createCommittedSsrfAckLoss({onCommitted,timeoutMs=15000,responseTimeoutMs=180000,policyOutput=false}={}){
 assert.equal(typeof policyOutput,'boolean');
 assert.equal(typeof onCommitted,'function');assert(Number.isSafeInteger(timeoutMs)&&timeoutMs>0&&timeoutMs<=15000);
 assert(Number.isSafeInteger(responseTimeoutMs)&&responseTimeoutMs>0&&responseTimeoutMs<=180000);
 let armed=false,used=false,closed=false,settled=false,pending=null,record=null,controller=null,timer=null,resolve,reject,heldResponse,closedResponse,observedResponse;
 function finish(error){if(settled)return;settled=true;clearTimeout(timer);timer=null;if(error)reject?.(error);else resolve?.(record);}
 const middleware=(request,response,next)=>{
  if(!armed||closed||used||request.method!=='POST'||new URL(request.originalUrl,'http://127.0.0.1').pathname!==(policyOutput?HTML_RUN_PATH:RUN_PATH)||(!policyOutput&&request.body?.resource!=='private-policy'))return next();
  observedResponse=response;
  const original=response.json;
  response.json=function(value){
   if(used||closed)return original.call(this,value);
   (policyOutput?exactPolicyRunRequest:exactRunRequest)(request.body);used=true;armed=false;
   clearTimeout(timer);
   record={request:structuredClone(request.body),status:response.statusCode,packet:structuredClone(value),authority:{scope:structuredClone(request.ssLaunch),persona:structuredClone(request.boundPersona),personaSession:structuredClone(request.ssPersonaSession)},source:null,responseClosed:false};
   let validPolicy=true;if(policyOutput)try{exactPolicyRunResponse(value,{requestId:request.body.request_id,mode:'vuln'});}catch{validPolicy=false;}
   if(response.statusCode!==200||!validPolicy||!policyOutput&&value?.resourceKind!=='private-policy'||value.replayed!==false||value.stopReason!=='end_turn'||typeof value.response!=='string'||!value.response.trim()){
    response.once('close',()=>{record.responseClosed=true;});
    const error=Object.assign(Error(`Private SSRF response did not complete (HTTP ${response.statusCode})`),{code:'SSRF_PRIVATE_RESPONSE_INCOMPLETE'});
    finish(error);return original.call(this,value);
   }
   heldResponse=response;closedResponse=new Promise(done=>response.once('close',()=>{record.responseClosed=true;done();}));controller=new AbortController();
   timer=setTimeout(()=>{const error=Error('Committed private response witness timed out');controller.abort(error);response.destroy();finish(error);},timeoutMs);
   Promise.resolve().then(()=>onCommitted({...record,signal:controller.signal})).then(source=>{
    if(controller.signal.aborted)return;
    assert(source&&Object.getPrototypeOf(source)===Object.prototype);assert.deepEqual(Object.keys(source).sort(),['requestId','sessionId','status','result'].sort());
    assert.equal(source.requestId,record.request.request_id);assert.match(source.sessionId,UUID);assert.equal(source.status,'completed');assert.equal(source.result?.stopReason,'end_turn');assert.equal(source.result?.text,record.packet.response);
    if(policyOutput)assert.equal(source.sessionId,record.packet.sessionId);
    record.source=structuredClone(source);
    // A close before headers lets the browser transparently retry the POST.
    // Transmit an incomplete prefix of the original packet after headers so
    // the local observer loses the body while retaining its original UUID.
    record.responseBody=JSON.stringify(record.packet);
    const originalBytes=Buffer.from(record.responseBody);
    record.responseBodySha256=createHash('sha256').update(originalBytes).digest('hex');
    assert(originalBytes.length>1);
    writeTruncatedJsonAcknowledgement(response,originalBytes,error=>{
     if(controller.signal.aborted)return;
     response.destroy();
     if(error){controller.abort(error);finish(error);}else finish();
    });
   }).catch(error=>{if(controller.signal.aborted)return;controller.abort(error);response.destroy();finish(error);});
   return this;
  };
  next();
 };
 return Object.freeze({middleware,
  arm(){assert(!armed&&!used&&!closed,'One committed ACK-loss attempt only');armed=true;pending=new Promise((yes,no)=>{resolve=yes;reject=no;});void pending.catch(()=>{});
   timer=setTimeout(()=>{armed=false;used=true;observedResponse?.destroy();finish(Object.assign(Error('Private SSRF response timed out before a completed acknowledgement'),{code:'SSRF_PRIVATE_RESPONSE_TIMEOUT'}));},responseTimeoutMs);},
  wait(){assert(pending,'ACK loss was not armed');return pending;},
  snapshot(){return {armed,used,closed,record:record?structuredClone(record):null};},
  async close(){closed=true;armed=false;clearTimeout(timer);controller?.abort(Error('ACK witness closed'));if(!record?.responseClosed)heldResponse?.destroy();if(pending&&!settled)finish(Error(record?.source?'ACK witness closed before response completion':'ACK witness closed before durable source verification'));if(pending)await pending.catch(()=>{});if(closedResponse)await closedResponse;},
 });
}

function endpoint(url){return new URL(url).pathname;}
function observeResponse(page,predicate,timeoutMs=180000){
 const controller=new AbortController();const result=page.waitForResponse(predicate,{timeout:timeoutMs,signal:controller.signal}).then(response=>({response}),error=>({error}));
 return {async read(){const value=await result;if(value.error)throw value.error;return value.response;},async close(){controller.abort();await result;}};
}
async function frameFor(page){
 const handle=await page.waitForSelector('iframe[title="SecureShop"]',{visible:true,timeout:30000});
 const frame=await handle.contentFrame();assert(frame&&!frame.detached,'Authenticated standalone frame is unavailable');return frame;
}
async function physicalButton(surface,label){
 const handle=await surface.waitForFunction(text=>[...document.querySelectorAll('button')].find(e=>e.textContent?.trim()===text&&!e.disabled&&e.getClientRects().length),{timeout:30000},label);
 const button=handle.asElement();assert(button);await button.evaluate(e=>e.scrollIntoView({block:'center',behavior:'instant'}));
 await surface.waitForFunction(text=>{const e=[...document.querySelectorAll('button')].find(e=>e.textContent?.trim()===text&&!e.disabled&&e.getClientRects().length);if(!e)return false;const r=e.getBoundingClientRect(),hit=document.elementFromPoint(r.left+r.width/2,r.top+r.height/2);return hit===e||e.contains(hit);},{timeout:20000},label);
 const hit=await button.evaluate(e=>{const r=e.getBoundingClientRect();return {x:r.left+r.width/2,y:r.top+r.height/2,tagName:e.tagName,text:e.textContent.trim()};});
 await button.click();return hit;
}
function packet(response,body){return {status:response.status(),body};}
async function selectFixedThroughSettings(page,{observe,onCapture=async()=>{}}){
 const value={openHit:await physicalButton(page,'Shop settings'),hit:null,response:null,closeHit:null,settingsClosed:false};
 await page.waitForSelector('aside#secureshop-settings',{visible:true});await onCapture(structuredClone(value));
 const watch=observe(r=>r.request().method()==='POST'&&endpoint(r.url())===MODE_PATH);
 value.hit=await physicalButton(page,'Fixed');const response=await watch.read();value.response=packet(response,await response.json().catch(()=>null));await onCapture(structuredClone(value));
 assert.equal(response.status(),200);assert.equal(value.response.body?.mode,'fixed');
 value.closeHit=await physicalButton(page,'Shop settings');await page.waitForSelector('aside#secureshop-settings',{hidden:true});value.settingsClosed=true;await onCapture(structuredClone(value));return value;
}

async function qualifyStandaloneSsrfRendered({browser,origin,credentials,evidenceDirectory,ackLoss,
 bindBootstrap,readCase,readCounters,readPrivateSnapshot,onCapture=async()=>{}}={}){
 const url=new URL(origin);assert.equal(url.origin,origin);assert.equal(url.protocol,'http:');assert.equal(url.hostname,'127.0.0.1');assert(url.port);
 assert(credentials&&typeof credentials.username==='string'&&credentials.username&&typeof credentials.password==='string'&&credentials.password);
 assert(path.isAbsolute(evidenceDirectory));assert.equal(typeof browser?.createBrowserContext,'function');
 for(const fn of [bindBootstrap,readCase,readCounters,readPrivateSnapshot,onCapture])assert.equal(typeof fn,'function');
 for(const method of ['arm','wait','snapshot','close'])assert.equal(typeof ackLoss?.[method],'function');
 let context,page,frame,authority,failure;const waits=[],requests=[],cases=[];
 const evidence={version:1,profile:'standalone-ssrf-rendered-flow',phase:'initializing',cases,retry:null,mode:null,ackLoss:null,browserErrors:[],browserOwner:'caller',contextOwned:false,contextsClosed:false,ackControllerClosed:false,modelCounters:null};
 const publish=async()=>onCapture(structuredClone(evidence));
 const measured=async()=>{const value=await readCounters();evidence.modelCounters=structuredClone(value);await publish();return assertCounters(value);};
 const observe=predicate=>{const wait=observeResponse(page,predicate);waits.push(wait);return wait;};
 try{
  context=await browser.createBrowserContext();evidence.contextOwned=true;page=await context.newPage();
  await page.setViewport({width:1440,height:1000});page.setDefaultTimeout(30000);
  page.on('pageerror',error=>{if(evidence.browserErrors.length<16)evidence.browserErrors.push({name:error.name,message:String(error.message).slice(0,2048)});});
  await page.setRequestInterception(true);page.on('request',request=>{let allowed=false;try{const u=new URL(request.url());allowed=u.origin===origin||['data:','blob:','about:'].includes(u.protocol);}catch{}
   if(allowed&&request.method()==='POST'&&endpoint(request.url())===RUN_PATH){try{requests.push(exactRunRequest(JSON.parse(request.postData())));}catch(error){evidence.browserErrors.push({name:error.name,message:'Malformed actual SSRF POST'});}}
   void(allowed?request.continue():request.abort()).catch(()=>{});});
  const bootstrap=observe(r=>r.request().method()==='POST'&&endpoint(r.url())===BOOTSTRAP_PATH&&r.status()===200);
  await page.goto(origin+'/secureshop/login',{waitUntil:'domcontentloaded'});await page.waitForSelector('#ss-login-user');await page.type('#ss-login-user',credentials.username);await page.type('#ss-login-pw',credentials.password);
  await physicalButton(page,'Sign in');const boot=await(await bootstrap.read()).json();authority=await bindBootstrap(boot);
  assert(authority?.scope&&authority?.persona&&authority?.personaSession,'Caller must bind the actual bootstrap through canonical authority');
  frame=await frameFor(page);await frame.waitForSelector('#controlled-ssrf-title',{visible:true});
  evidence.phase='authenticated-policy-lab';await publish();const initial=await measured();assert.equal(initial.actor,0);assert.equal(initial.judge,0);
  async function action(id,resource,label){
   const before=requests.length,watch=observe(r=>r.request().method()==='POST'&&endpoint(r.url())===RUN_PATH);
   const hit=await physicalButton(frame,label);const response=await watch.read();const body=await response.json().catch(()=>null);
   const row={id,resource,physical:{label,hit,postBody:requests[before],response:packet(response,body),renderedText:null},captured:null};cases.push(row);evidence.phase=id+'-response';await publish();
   row.captured=await readCase({id,request:row.physical.postBody,response:row.physical.response,authority});await publish();
   assert.equal(response.status(),200);assert.equal(body?.stopReason,'end_turn');assert.equal(body?.resourceKind,resource);assert.equal(body?.replayed,false);assert.equal(typeof body?.response,'string');assert(body.response.trim());
   await frame.waitForFunction(text=>document.querySelector('[aria-label="Policy agent observation"] pre')?.textContent===text,{timeout:30000},body.response);
   row.physical.renderedText=await frame.$eval('[aria-label="Policy agent observation"] pre',e=>e.textContent);assert.equal(requests.length,before+1);await measured();await page.screenshot({path:path.join(evidenceDirectory,`standalone-ssrf-${id}.png`),fullPage:true});await publish();return row;
  }
  await action('public','public-policy','Fetch public policy');
  const publicCounts=await measured();assert.equal(publicCounts.http,1);assert.equal(publicCounts.judge,0);assert.equal(publicCounts.contributions,0);
  ackLoss.arm();const beforePrivate=requests.length;const privateHit=await physicalButton(frame,'Try internal policy');
  const lost=await ackLoss.wait();assert.equal(requests.length,beforePrivate+1);assert.deepEqual(requests[beforePrivate],lost.request);
  const privateRow={id:'private',resource:'private-policy',physical:{label:'Try internal policy',hit:privateHit,postBody:lost.request,response:{status:200,body:lost.packet},renderedText:null},captured:null};cases.push(privateRow);evidence.phase='private-durable-ack-lost';await publish();
  privateRow.captured=await readCase({id:'private',request:lost.request,response:privateRow.physical.response,authority});await publish();
  await frame.waitForSelector('[role="alert"]',{visible:true});
  const countsBefore=await measured(),rowsBefore=await readPrivateSnapshot({request:lost.request,authority});
  const retry=observe(r=>r.request().method()==='POST'&&endpoint(r.url())===RUN_PATH);const retryHit=await physicalButton(frame,'Try internal policy');
  const response=await retry.read(),body=await response.json().catch(()=>null);
  evidence.retry={request:requests.at(-1),hit:retryHit,response:packet(response,body),before:rowsBefore,after:null,countsBefore,countsAfter:null};await publish();
  assert.equal(requests.length,beforePrivate+2);assert.deepEqual(requests.at(-1),lost.request);assert.equal(response.status(),200);assert.deepEqual(body,{...lost.packet,replayed:true});
  await frame.waitForFunction(text=>document.querySelector('[aria-label="Policy agent observation"] pre')?.textContent===text,{timeout:30000},body.response);
  privateRow.physical.renderedText=await frame.$eval('[aria-label="Policy agent observation"] pre',e=>e.textContent);
  await page.screenshot({path:path.join(evidenceDirectory,'standalone-ssrf-private-recovered.png'),fullPage:true});
  evidence.retry.after=await readPrivateSnapshot({request:lost.request,authority});evidence.retry.countsAfter=await measured();assert.deepEqual(evidence.retry.after,rowsBefore);assert.deepEqual(evidence.retry.countsAfter,countsBefore);await publish();
  evidence.mode=await selectFixedThroughSettings(page,{observe,onCapture:async value=>{evidence.mode=value;await publish();}});
  frame=await frameFor(page);await frame.waitForSelector('#controlled-ssrf-title',{visible:true});const fixedBefore=await measured();
  await action('fixed-private','private-policy','Try internal policy');const fixedAfter=await measured();
  for(const key of ['http','invocations','judgments','contributions'])assert.equal(fixedAfter[key],fixedBefore[key],`Fixed private request changed ${key}`);
  assert.equal(fixedAfter.http,2);assertCounters(fixedAfter,{complete:true});assert.equal(requests.length,4);assert.deepEqual(evidence.browserErrors,[]);
  evidence.phase='rendered-actions-complete';await page.screenshot({path:path.join(evidenceDirectory,'standalone-ssrf-fixed-private.png'),fullPage:true});await publish();
 }catch(error){failure=error;evidence.phase='failed';evidence.failure={name:error.name,code:error.code||null,message:String(error.message).slice(0,4096)};try{evidence.ackLoss=ackLoss.snapshot();}catch{}try{evidence.modelCounters=await readCounters();}catch{}try{await publish();}catch{}
  const failed=evidence.ackLoss?.record;if(failed&&!cases.some(row=>row.id==='private')){try{evidence.privateFailureCapture=await readCase({id:'private',request:failed.request,response:{status:failed.status,body:failed.packet},authority});}catch(readError){evidence.privateFailureReadError={name:readError.name,code:readError.code||null,message:String(readError.message).slice(0,2048)};}try{await publish();}catch{}}
  try{await page?.screenshot({path:path.join(evidenceDirectory,'standalone-ssrf-failure.png'),fullPage:true});}catch{}
 }finally{
  const cleanup=await Promise.allSettled([Promise.resolve().then(()=>ackLoss.close()),...waits.map(wait=>wait.close()),Promise.resolve().then(()=>context?.close())]);
  evidence.ackControllerClosed=cleanup[0].status==='fulfilled';evidence.contextsClosed=cleanup.at(-1).status==='fulfilled';evidence.cleanupFailures=cleanup.filter(row=>row.status==='rejected').map(row=>String(row.reason?.message||row.reason));
  try{evidence.ackLoss=ackLoss.snapshot();}catch{}
  try{await publish();}catch(error){failure??=error;}
  const errors=cleanup.filter(row=>row.status==='rejected').map(row=>row.reason);if(errors.length)failure=new AggregateError([...(failure?[failure]:[]),...errors],'Standalone SSRF flow and cleanup failed',{cause:failure});
 }
 if(failure)throw failure;
 return Object.freeze({renderedControlsVerified:true,actualModelProof:false,qualification:'pending-owned-caller',actionCount:3,freshPosts:3,retryPosts:1,actorCalls:evidence.modelCounters.actor,judgeCalls:evidence.modelCounters.judge,evidence});
}

// Browser inputs use the real input handle; evaluate is read-only here.
async function physicallyTypePolicy(frame,text){
 assert.equal(typeof text,'string');assert(text.trim()&&text.isWellFormed()&&!text.includes('\0')&&Buffer.byteLength(text)<=8192);
 const input=await frame.waitForSelector('textarea[aria-label="Policy HTML"]',{visible:true});
 await frame.waitForFunction(()=>{const e=document.querySelector('textarea[aria-label="Policy HTML"]');return e&&!e.disabled;},{timeout:30000});
 await input.evaluate(e=>e.scrollIntoView({block:'center',behavior:'instant'}));
 await frame.waitForFunction(e=>{if(!e.isConnected||e.disabled||!e.getClientRects().length)return false;
  const r=e.getBoundingClientRect(),hit=document.elementFromPoint(r.left+r.width/2,r.top+r.height/2);return hit===e||e.contains(hit);},{timeout:30000},input);
 const current=await input.evaluate(e=>e.value);assert.equal(typeof current,'string');assert(current.isWellFormed()&&Buffer.byteLength(current)<=8192);
 await input.click();await frame.waitForFunction(e=>document.activeElement===e,{timeout:30000},input);
 // Native select-all shortcuts are not reliable through this headless CDP
 // connection. Reuse the bounded physical clearing sequence of upload lessons.
 const keyboard=frame.page().keyboard;
 for(let i=0;i<=current.length;i++)await keyboard.press('ArrowRight');
 for(let i=0;i<=current.length;i++)await keyboard.press('Backspace');
 assert.equal(await input.evaluate(e=>e.value),'');await input.type(text);
 assert.equal(await input.evaluate(e=>e.value),text);return{selector:'textarea[aria-label="Policy HTML"]',value:text};
}
// This function is serialized into the real frame. All live DOM operations
// are reads; normalization removes only the generated marker from a detached clone.
function policyDomObservation(text,mode,markerRequired,contract){
 const original=new DOMParser().parseFromString(text,'text/html').body;
 const staticMarker=root=>root.querySelector('[data-v27-owned-canary]')||[...root.querySelectorAll('template')].some(e=>staticMarker(e.content));
 if(staticMarker(original))throw Error('Original model answer contains a static marker');
 const matches=root=>[...root.querySelectorAll('img')].filter(e=>e.getAttribute('onerror')===contract.handler);
 const sourceImages=matches(original);
 if(markerRequired&&sourceImages.length!==1)throw Error('Original answer must contain exactly one owned image handler');
 const reply=document.querySelector('#policy-final-html-title')?.closest('section')?.querySelector('[data-testid="agent-turn-reply"]');
 if(!reply)return null;
 const markers=[...reply.querySelectorAll('[data-v27-owned-canary]')],activeElements=reply.querySelectorAll('img,script,iframe,svg,object,embed,[onerror],[onload]').length;
 let reconstructedHtml=reply.innerHTML,marker=null;
 if(mode==='fixed'){
  if(reply.textContent!==text||activeElements!==0||markers.length!==0)return null;
 }else if(markerRequired){
  const images=matches(reply),node=markers[0];
  if(images.length!==1||markers.length!==1||!node.matches(contract.selector)||node.attributes.length!==1||node.textContent!==contract.text||node.children.length!==0
   ||images[0].nextElementSibling!==node||images[0].outerHTML!==sourceImages[0].outerHTML
   ||!node.getClientRects().length||getComputedStyle(node).display==='none'||getComputedStyle(node).visibility==='hidden')return null;
  const clone=reply.cloneNode(true);clone.querySelector(contract.selector).remove();reconstructedHtml=clone.innerHTML;
  if(reconstructedHtml!==original.innerHTML)return null;
  marker={tagName:node.tagName,text:node.textContent,html:node.outerHTML,adjacentToOriginalImage:true,visible:true};
 }else if(markers.length!==0||reply.innerHTML!==original.innerHTML)return null;
 return{text:reply.textContent,html:reply.innerHTML,activeElements,marker,originalHtml:original.innerHTML,reconstructedHtml};
}
async function policyReply(frame,body,mode,markerRequired=false){
 const H=require('./secureshopStandaloneSsrfQualification'),contract={handler:H.POLICY_OUTPUT_HANDLER,selector:H.POLICY_OUTPUT_MARKER_SELECTOR,text:H.POLICY_OUTPUT_MARKER_TEXT};
 assert.equal(typeof contract.handler,'string');assert.equal(typeof contract.selector,'string');assert.equal(typeof contract.text,'string');
 await frame.waitForFunction(policyDomObservation,{timeout:30000},body.response,mode,markerRequired,contract);
 return frame.evaluate(policyDomObservation,body.response,mode,markerRequired,contract);
}
async function absentPolicyMarker(frame){
 const result=await frame.$eval('#policy-final-html-title',title=>({markers:title.closest('section').querySelectorAll('[data-v27-owned-canary]').length}));
 assert.deepEqual(result,{markers:0});return result;
}
function assertPolicyAssessment(value,kind,expectedVerdict='pass'){
 assert(['baseline','fixed','attack','recovered-attack'].includes(kind));
 assert(['pass','fail'].includes(expectedVerdict));
 if(kind==='baseline'||kind==='fixed'){
  assert.deepEqual(value,{completed:false,status:'ineligible',modelEvaluated:false,...(kind==='baseline'?{replayed:false}:{})});return value;
 }
 assert.equal(value?.completed,expectedVerdict==='pass');assert.equal(value.replayed,kind==='recovered-attack');assert.equal(value.judgment?.verdict,expectedVerdict);assert.match(value.judgment.evaluationId,UUID);return value;
}
async function qualifyPolicyOutputRendered({browser,origin,credentials,evidenceDirectory,ackLoss,
 bindBootstrap,readOriginal,readAssessment,readCounters,readPublicProgress,verifyLifecycle,onCapture=async()=>{}}={}){
 const {POLICY_OUTPUT_BASELINE,POLICY_OUTPUT_ATTACK}=require('./secureshopStandaloneSsrfQualification');
 const url=new URL(origin);assert.equal(url.origin,origin);assert.equal(url.protocol,'http:');assert.equal(url.hostname,'127.0.0.1');assert(url.port);
 assert(credentials&&typeof credentials.username==='string'&&credentials.username&&typeof credentials.password==='string'&&credentials.password);
 assert(path.isAbsolute(evidenceDirectory));assert.equal(typeof browser?.createBrowserContext,'function');
 for(const fn of [bindBootstrap,readOriginal,readAssessment,readCounters,readPublicProgress,verifyLifecycle,onCapture])assert.equal(typeof fn,'function');
 for(const method of ['arm','wait','snapshot','close'])assert.equal(typeof ackLoss?.[method],'function');
 let context,page,frame,authority,failure,reloadHold,reloadTimer;const waits=[],requests=[],assessPosts=[],cases=[];
 const evidence={version:1,profile:'standalone-policy-output-rendered-flow',phase:'initializing',cases,requests,assessPosts,
  recovery:null,reload:null,mode:null,progress:[],lifecycle:null,dialogs:[],browserErrors:[],contextOwned:false,contextsClosed:false,ackControllerClosed:false,modelCounters:null};
 const publish=async()=>onCapture(structuredClone(evidence));
 const measured=async()=>{const value=await readCounters();evidence.modelCounters=structuredClone(value);await publish();return assertCounters(value);};
 const progress=async completed=>{const value=await readPublicProgress({page,completed});assert(value&&typeof value==='object');evidence.progress.push({completed,value});await publish();return value;};
 const observe=predicate=>{const wait=observeResponse(page,predicate);waits.push(wait);return wait;};
 const watchPath=(method,path)=>observe(r=>r.request().method()===method&&endpoint(r.url())===path);
 try{
  context=await browser.createBrowserContext();evidence.contextOwned=true;page=await context.newPage();
  await page.setViewport({width:1440,height:1000});page.setDefaultTimeout(30000);
  page.on('pageerror',error=>evidence.browserErrors.push({name:error.name,message:String(error.message).slice(0,2048)}));
  page.on('dialog',dialog=>{const row={type:dialog.type(),message:dialog.message()};evidence.dialogs.push(row);
   void dialog.accept().catch(error=>evidence.browserErrors.push({name:error.name,message:String(error.message)}));});
  await page.setRequestInterception(true);page.on('request',request=>{let allowed=false;try{const u=new URL(request.url());allowed=u.origin===origin||['data:','blob:','about:'].includes(u.protocol);}catch{}
   if(allowed&&request.method()==='POST')try{
    const pathname=endpoint(request.url());if(pathname===HTML_RUN_PATH)requests.push(exactPolicyRunRequest(JSON.parse(request.postData())));
    if(pathname===HTML_BASE+'/assess'){const body=JSON.parse(request.postData());assert.deepEqual(Object.keys(body).sort(),['request_id','session_id']);assert.match(body.request_id,UUID);assert.match(body.session_id,UUID);assessPosts.push(body);}
   }catch(error){evidence.browserErrors.push({name:error.name,message:'Malformed actual policy output POST: '+error.message});}
   if(allowed&&reloadHold&&request.method()==='GET'&&endpoint(request.url())===reloadHold.path){reloadHold.request=request;reloadHold.resolve();return;}
   void(allowed?request.continue():request.abort()).catch(()=>{});});
  const bootstrap=observe(r=>r.request().method()==='POST'&&endpoint(r.url())===BOOTSTRAP_PATH&&r.status()===200);
  await page.goto(origin+'/secureshop/login',{waitUntil:'domcontentloaded'});await page.waitForSelector('#ss-login-user');await page.type('#ss-login-user',credentials.username);await page.type('#ss-login-pw',credentials.password);
  await physicalButton(page,'Sign in');authority=await bindBootstrap(await(await bootstrap.read()).json());
  assert(authority?.scope&&authority?.persona&&authority?.personaSession,'Actual canonical bootstrap authority is required');
  frame=await frameFor(page);await frame.waitForSelector('#policy-final-html-title',{visible:true});
  evidence.phase='authenticated-policy-output';await publish();const initial=await measured();for(const count of Object.values(initial))assert.equal(count,0);await progress(false);
  async function action(id,source,mode,lostAck=false){
   if(id==='baseline'){
    evidence.physicalInputPreflight={initial:await physicallyTypePolicy(frame,source),replacement:null};await publish();
   }
   const input=await physicallyTypePolicy(frame,source),before=requests.length,markerBefore=await absentPolicyMarker(frame);
   if(id==='baseline'){
    evidence.physicalInputPreflight.replacement=input;assert.equal(before,0);
    for(const count of Object.values(await measured()))assert.equal(count,0);await publish();
   }
   let watch;if(lostAck)ackLoss.arm();else watch=watchPath('POST',HTML_RUN_PATH);
   const hit=await physicalButton(frame,'Fetch and explain policy');
   let response,lost;if(lostAck){lost=await ackLoss.wait();response={status:lost.status,body:lost.packet};}else{const actual=await watch.read();response=packet(actual,await actual.json().catch(()=>null));}
   const row={id,physical:{input,markerBefore,hit,postBody:requests[before],response,rendered:null},original:null,assessment:null};cases.push(row);evidence.phase=id+'-original';await publish();
   assert.equal(requests.length,before+1);assert.deepEqual(row.physical.postBody,{request_id:row.physical.postBody.request_id,policy_html:source});
   assert.equal(response.status,200);exactPolicyRunResponse(response.body,{requestId:row.physical.postBody.request_id,mode});
   row.original=await readOriginal({id,request:row.physical.postBody,response,authority});assert(row.original&&typeof row.original==='object');await publish();
   if(lostAck){
    assert.deepEqual(lost.request,row.physical.postBody);
    const countsBefore=await measured(),postCount=requests.length,watch=watchPath('GET',HTML_RUN_PATH+'/'+response.body.requestId);
    const recoveryHit=await physicalButton(frame,'Check saved policy answer'),actual=await watch.read(),body=await actual.json().catch(()=>null);
    evidence.recovery={hit:recoveryHit,response:packet(actual,body),countsBefore,countsAfter:null};await publish();
    assert.equal(actual.status(),200);exactPolicyRunResponse(body,{requestId:response.body.requestId,sessionId:response.body.sessionId,replayed:true,mode});assert.deepEqual(body,{...response.body,replayed:true});
    evidence.recovery.countsAfter=await measured();assert.deepEqual(evidence.recovery.countsAfter,countsBefore);assert.equal(requests.length,postCount);
   }
   row.physical.rendered=await policyReply(frame,response.body,mode,id==='attack');if(mode==='fixed'){assert.equal(row.physical.rendered.text,response.body.response);assert.equal(row.physical.rendered.activeElements,0);}
   await page.screenshot({path:path.join(evidenceDirectory,'policy-output-'+id+'.png'),fullPage:true});await publish();return row;
  }
  async function assess(row){
   const before=assessPosts.length,watch=watchPath('POST',HTML_BASE+'/assess'),hit=await physicalButton(frame,'Check policy output');
   const actual=await watch.read(),body=await actual.json().catch(()=>null),reference={sessionId:row.physical.response.body.sessionId,requestId:row.physical.response.body.requestId};
   row.assessment={hit,request:assessPosts[before],response:packet(actual,body),stored:null};await publish();
   assert.equal(actual.status(),200);assert.equal(assessPosts.length,before+1);assert.deepEqual(assessPosts[before],{session_id:reference.sessionId,request_id:reference.requestId});assertPolicyAssessment(body,row.id,row.id==='attack'?body?.judgment?.verdict:'pass');
   row.assessment.stored=await readAssessment({id:row.id,reference,response:row.assessment.response,authority});assert(row.assessment.stored&&typeof row.assessment.stored==='object');await publish();
   await frame.waitForFunction(expected=>[...document.querySelector('#policy-final-html-title').closest('section').querySelectorAll('[role="status"]')].some(e=>e.textContent.startsWith('Policy output assessment:')&&e.textContent.includes(expected)),{timeout:30000},row.id==='attack'?(body.completed?'Objective completed':'fail'):'ineligible');return body;
  }
  const baseline=await action('baseline',POLICY_OUTPUT_BASELINE,'vuln');await assess(baseline);
  const baselineCounts=await measured();assert.equal(baselineCounts.actor,2);assert.equal(baselineCounts.http,1);assert.equal(baselineCounts.judge,0);assert.equal(baselineCounts.contributions,0);assert.deepEqual(evidence.dialogs,[]);await progress(false);
  await physicalButton(frame,'New policy request');
  const attack=await action('attack',POLICY_OUTPUT_ATTACK,'vuln',true);
  const attackAssessment=await assess(attack),semanticPassed=attackAssessment.completed;
  evidence.semanticOutcome={originalVerdict:attackAssessment.judgment.verdict,semanticPassed,genuineCredit:Number(semanticPassed),coverageCompleted:false};await publish();await progress(semanticPassed);
  const countsBefore=await measured(),postsBefore={run:requests.length,assess:assessPosts.length};
  const originalGet=watchPath('GET',HTML_RUN_PATH+'/'+attack.physical.response.body.requestId),assessmentGet=watchPath('GET',HTML_BASE+'/assessment/'+attack.physical.response.body.sessionId+'/'+attack.physical.response.body.requestId);
  const held=new Promise((resolve,reject)=>{reloadHold={path:HTML_RUN_PATH+'/'+attack.physical.response.body.requestId,resolve,request:null};
   reloadTimer=setTimeout(()=>reject(Error('Saved original GET was not intercepted before reload')),30000);});
  void held.catch(()=>{});
  await page.reload({waitUntil:'domcontentloaded'});await held;clearTimeout(reloadTimer);
  frame=await frameFor(page);await frame.waitForSelector('#policy-final-html-title',{visible:true});const markerBefore=await absentPolicyMarker(frame);
  const heldRequest=reloadHold.request;reloadHold=null;await heldRequest.continue();
  const original=await originalGet.read(),outcome=await assessmentGet.read();
  evidence.reload={markerBefore,original:packet(original,await original.json().catch(()=>null)),assessment:packet(outcome,await outcome.json().catch(()=>null)),countsBefore,countsAfter:null};await publish();
  assert.equal(original.status(),200);assert.equal(outcome.status(),200);assert.deepEqual(evidence.reload.original.body,{...attack.physical.response.body,replayed:true});
  assertPolicyAssessment(evidence.reload.assessment.body,'recovered-attack',attackAssessment.judgment.verdict);assert.deepEqual(evidence.reload.assessment.body,{...attack.assessment.response.body,replayed:true});
  frame=await frameFor(page);await frame.waitForSelector('#policy-final-html-title',{visible:true});evidence.reload.rendered=await policyReply(frame,attack.physical.response.body,'vuln',true);
  evidence.reload.countsAfter=await measured();assert.deepEqual(evidence.reload.countsAfter,countsBefore);assert.deepEqual({run:requests.length,assess:assessPosts.length},postsBefore);await progress(semanticPassed);
  await physicalButton(frame,'New policy request');evidence.mode=await selectFixedThroughSettings(page,{observe,onCapture:async value=>{evidence.mode=value;await publish();}});
  frame=await frameFor(page);await frame.waitForSelector('#policy-final-html-title',{visible:true});
  const fixedBefore=await measured(),dialogsBefore=evidence.dialogs.length;
  const fixed=await action('fixed',POLICY_OUTPUT_ATTACK,'fixed');await assess(fixed);const fixedAfter=await measured();
  assert.equal(fixedAfter.actor,fixedBefore.actor+2);assert.equal(fixedAfter.http,fixedBefore.http+1);for(const key of ['judge','judgments','contributions'])assert.equal(fixedAfter[key],fixedBefore[key]);assert.equal(evidence.dialogs.length,dialogsBefore);await progress(semanticPassed);
  assert.equal(requests.length,3);assert.equal(assessPosts.length,3);assertCounters(fixedAfter,{complete:true});assert.deepEqual(evidence.browserErrors,[]);
  evidence.phase='lifecycle';const lifecycleBefore=await measured();evidence.lifecycle=await verifyLifecycle({page,authority,cases});assert(evidence.lifecycle&&typeof evidence.lifecycle==='object');
  evidence.lifecycleCounters={before:lifecycleBefore,after:await measured()};assert.deepEqual(evidence.lifecycleCounters.after,lifecycleBefore);await publish();
  evidence.semanticOutcome.coverageCompleted=true;evidence.phase='rendered-actions-complete';await publish();
 }catch(error){failure=error;evidence.phase='failed';evidence.failure={name:error.name,code:error.code||null,message:String(error.message).slice(0,4096)};
  try{evidence.ackLoss=ackLoss.snapshot();}catch{}try{evidence.modelCounters=await readCounters();}catch{}try{await publish();}catch{}try{await page?.screenshot({path:path.join(evidenceDirectory,'policy-output-failure.png'),fullPage:true});}catch{}
 }finally{
  clearTimeout(reloadTimer);if(reloadHold?.request)await reloadHold.request.abort().catch(()=>{});reloadHold=null;
  const cleanup=await Promise.allSettled([Promise.resolve().then(()=>ackLoss.close()),...waits.map(wait=>wait.close()),Promise.resolve().then(()=>context?.close())]);
  evidence.ackControllerClosed=cleanup[0].status==='fulfilled';evidence.contextsClosed=cleanup.at(-1).status==='fulfilled';evidence.cleanupFailures=cleanup.filter(row=>row.status==='rejected').map(row=>String(row.reason?.message||row.reason));
  try{evidence.ackLoss=ackLoss.snapshot();await publish();}catch(error){failure??=error;}
  const errors=cleanup.filter(row=>row.status==='rejected').map(row=>row.reason);if(errors.length)failure=new AggregateError([...(failure?[failure]:[]),...errors],'Policy output flow and cleanup failed',{cause:failure});
 }
 if(failure)throw failure;
 return Object.freeze({renderedControlsVerified:true,actualModelProof:false,qualification:'pending-owned-caller',actionCount:3,freshPosts:3,retryPosts:0,assessmentPosts:3,actorCalls:evidence.modelCounters.actor,judgeCalls:evidence.modelCounters.judge,evidence});
}

module.exports={writeTruncatedJsonAcknowledgement,qualifyStandaloneSsrfRendered,qualifyPolicyOutputRendered,createCommittedSsrfAckLoss,assertCounters,exactRunRequest,exactPolicyRunRequest,exactPolicyRunResponse,assertPolicyAssessment,TOTAL_MODEL_CALLS,RUN_PATH,HTML_RUN_PATH,_internals:{observeResponse,physicalButton,selectFixedThroughSettings,physicallyTypePolicy,policyDomObservation}};
