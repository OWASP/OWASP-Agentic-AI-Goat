'use strict';
const assert=require('node:assert/strict'),path=require('node:path');
async function selectInboxUser({page,frame,id}){
 const text=typeof id==='number'&&Number.isSafeInteger(id)?String(id):id;
 assert(typeof text==='string'&&/^[1-9][0-9]*$/.test(text),'Canonical inbox user ID required');
 // Inbox navigation can briefly replace the iframe document. Wait for the
 // exact visible control, then keep that handle through the physical edit so
 // the existing connected/same-node checks still reject a mid-edit rerender.
 const input=await frame.waitForSelector('[data-testid="inbox-userid"]',
  {visible:true,timeout:15000});
 assert(input,'Rendered Inbox user selector required');
 await frame.waitForFunction(el=>el.isConnected
  &&el===document.querySelector('[data-testid="inbox-userid"]')
  &&!el.disabled&&el.getClientRects().length>0,
  {timeout:15000},input);
 const inboxReads=[];
 const observe=request=>{if(request.method()==='GET'&&/^\/api\/secureshop\/email\/inbox\//.test(new URL(request.url()).pathname))inboxReads.push(request.url());};
 page.on('request',observe);
 try {
  await input.click();
  await input.press('End');
  await page.keyboard.down('Shift');
  try { await input.press('Home'); } finally { await page.keyboard.up('Shift'); }
  await input.press('Backspace');
  await frame.evaluate(()=>new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(resolve))));
  const blank=await frame.evaluate(el=>({connected:el.isConnected,sameNode:el===document.querySelector('[data-testid="inbox-userid"]'),focused:document.activeElement===el,value:el.value}),input);
  assert.deepEqual(blank,{connected:true,sameNode:true,focused:true,value:''},'Blank edit must retain focused selector');
  assert.equal(inboxReads.length,0,'Blank edit must not request a fallback inbox');
  // Exercise ordinary typing; every character must preserve the focused node.
  for(const char of text){
   await input.type(char);
   const typing=await frame.evaluate(el=>({connected:el.isConnected,sameNode:el===document.querySelector('[data-testid="inbox-userid"]'),focused:document.activeElement===el}),input);
   assert.deepEqual(typing,{connected:true,sameNode:true,focused:true},'Typing must retain focused selector');
  }
  await frame.waitForFunction(expected=>document.querySelector('[data-testid="inbox-userid"]')?.value===expected,{},text);
 } finally { page.off('request',observe); }
}
function trackRequestCancellation(cdp){
 const failures=new Map(),waiters=new Set();
 const onFailed=event=>{failures.set(event.requestId,event);for(const wake of waiters)wake();};
 cdp.on('Network.loadingFailed',onFailed);
 return{async release(event,{timeoutMs=1000}={}){
  assert(event&&typeof event.requestId==='string','Exact held interception required');
  try{await cdp.send('Fetch.continueRequest',{requestId:event.requestId});return{released:true,cancelled:false};}
  catch(error){
   if(!/Invalid InterceptionId\.?$/.test(error.message||''))throw error;
   assert(typeof event.networkId==='string'&&event.networkId,'Cancelled interception requires Network request identity');
   let timer,wake;try{await new Promise((resolve,reject)=>{
    wake=()=>{const failure=failures.get(event.networkId);if(!failure)return;if(failure.canceled===true)resolve();else reject(Error('Held request failed without confirmed cancellation'));};
    waiters.add(wake);timer=setTimeout(()=>reject(Error('Held interception cancellation evidence unavailable')),timeoutMs);wake();
   });}finally{clearTimeout(timer);waiters.delete(wake);}
   return{released:false,cancelled:true,networkId:event.networkId};
  }
 },close(){cdp.off('Network.loadingFailed',onFailed);}};
}
async function qualifyDisclosureInFrame({page,frame,origin,root,click,restorePersona,observations,fixed=false}){
 const actors=await observations.personas(),merchant=actors.student_merchant,posts=[];let foreign=actors.student_customer,captureError,readLost=false,gradeLost=false,held,holdNext=false;const cdp=await page.createCDPSession();const cancellations=trackRequestCancellation(cdp);let mailboxCancellation,personaCancellation;
 const select=id=>selectInboxUser({page,frame,id});
 const status=part=>frame.waitForFunction(text=>document.body.innerText.includes(text),{timeout:15000},part);
 const response=route=>page.waitForResponse(r=>new URL(r.url()).pathname===route&&r.request().method()==='POST',{timeout:15000});
 page.on('request',r=>{if(r.method()==='POST'&&new URL(r.url()).pathname.startsWith('/api/secureshop/email/'))posts.push({path:new URL(r.url()).pathname,body:JSON.parse(r.postData()),headers:r.headers()});});
 cdp.on('Fetch.requestPaused',async event=>{try{
  if(holdNext&&event.request.url.endsWith('/disclosure')){holdNext=false;held=event;return;}
  const isRead=event.request.url.endsWith('/disclosure'),lose=!fixed&&event.responseStatusCode===200&&(isRead?!readLost:!gradeLost);
  if(lose){if(isRead)readLost=true;else gradeLost=true;await cdp.send('Fetch.fulfillRequest',{requestId:event.requestId,responseCode:502,responseHeaders:[{name:'content-type',value:'application/json'}],body:Buffer.from('{"ok":false,"error":"Owned response loss"}').toString('base64')});}else await cdp.send('Fetch.continueRequest',{requestId:event.requestId});
 }catch(e){captureError=e;await cdp.send('Fetch.failRequest',{requestId:event.requestId,errorReason:'Failed'}).catch(()=>{});}});
 try{
  await cdp.send('Network.enable');
  // Real Compose supplies owned foreign mail; no injected receipt or message row.
  await click('Compose');await frame.waitForSelector('[role="dialog"] input[placeholder="someone@example.com"]',{visible:true});const fields=await frame.$$('[role="dialog"] input');await fields[0].type(foreign.email);await fields[2].type('Owned disclosure rendered');await frame.type('[role="dialog"] textarea','Synthetic foreign mailbox receipt.');const sent=response('/api/secureshop/email/send');await click('Send');assert.equal((await sent).status(),200);await frame.waitForFunction(require('./secureshopMailHeaderFullAppBrowser').composeClosed,{timeout:15000});
  await select(foreign.id);const before=await observations.counts();const browse=page.waitForResponse(r=>new URL(r.url()).pathname==='/api/secureshop/email/inbox/'+foreign.id,{timeout:15000});await click('Reload');await browse;assert.deepEqual(await observations.counts(),before);assert(!posts.some(p=>p.path.endsWith('/disclosure-assessment')));
  await cdp.send('Fetch.enable',{patterns:[{urlPattern:origin+'/api/secureshop/email/disclosure',requestStage:'Response'},{urlPattern:origin+'/api/secureshop/email/disclosure-assessment',requestStage:'Response'}]});
  await click('Read for assessment');await status('Disclosure read not confirmed');
  const first=posts.find(p=>p.path.endsWith('/disclosure'));assert(first,'Read for assessment must issue the canonical disclosure POST before denial or response-loss recovery; inspect bridge admission if no request was captured');
  if(fixed){assert.deepEqual(await observations.counts(),before);if(captureError)throw captureError;return{status:'passed',fixedDenied:true,actualModelCalls:0};}
  await observations.verifyRead(first.body.requestId,foreign.id);await click('Read for assessment');await status('Disclosure read saved');const reads=posts.filter(p=>p.path.endsWith('/disclosure'));assert.equal(reads.length,2);assert.deepEqual(reads[0].body,reads[1].body);assert.equal((await observations.counts()).reads,before.reads+1);
  await click('Check saved disclosure');await status('retry to recover the same assessment');const after=await observations.counts();assert.equal(after.completions,1);assert(after.calls>0);await click('Check saved disclosure');await status('Objective completed.');assert.deepEqual(await observations.counts(),after);const assessments=posts.filter(p=>p.path.endsWith('/disclosure-assessment'));assert.deepEqual(assessments[0].body,assessments[1].body);assert.equal(assessments[0].body.readOperationId,first.body.requestId);assert.notEqual(assessments[0].body.requestId,first.body.requestId);
  await page.screenshot({path:path.join(root,'mail-disclosure-recovered.png'),fullPage:true});await observations.setEnabled(false);await click('Check saved disclosure');await status('Grading is disabled');assert.deepEqual(await observations.counts(),after);await observations.setEnabled(true);
  // Hold a committed read response, change mailbox, then release: old view cannot return.
  holdNext=true;await click('Read for assessment');await waitHeld();await select(merchant.id);mailboxCancellation=await cancellations.release(held);held=null;await frame.waitForFunction(()=>!document.body.innerText.includes('Check saved disclosure'),{timeout:15000});assert.equal((await observations.counts()).calls,after.calls);
  const resetResponse=page.waitForResponse(r=>new URL(r.url()).pathname.endsWith('/secureshop-launch/reset')&&r.request().method()==='POST',{timeout:15000});const reset=await require('./secureshopMailHeaderFullAppBrowser').waitForMailButton(page,'Reset launch');await reset.click();assert.equal((await resetResponse).status(),200);
  const stale=await fetch(origin+'/api/secureshop/email/disclosure-assessment',{method:'POST',headers:Object.fromEntries(Object.entries(assessments[0].headers).filter(([key])=>key==='authorization'||key==='content-type'||key.startsWith('x-'))),body:JSON.stringify(assessments[0].body),signal:AbortSignal.timeout(10000)});assert.notEqual(stale.status,200);assert.equal((await observations.counts()).calls,after.calls);assert.equal((await observations.counts()).completions,0);if(captureError)throw captureError;
  // Old headers prove retired authority denial. Separately prove stale receipt denial with current authority.
  frame=await restorePersona();foreign=(await observations.personas()).student_customer;
  await select(foreign.id);const currentReadResponse=response('/api/secureshop/email/disclosure');await click('Read for assessment');assert.equal((await currentReadResponse).status(),200);await status('Disclosure read saved');
  const currentRead=posts.filter(p=>p.path.endsWith('/disclosure')).at(-1);assert(currentRead);assert.notEqual(currentRead.body.requestId,first.body.requestId);await observations.verifyRead(currentRead.body.requestId,foreign.id);
  const currentCounts=await observations.counts();assert.equal(currentCounts.calls,after.calls);assert.equal(currentCounts.completions,0);
  const staleReceipt=await fetch(origin+'/api/secureshop/email/disclosure-assessment',{method:'POST',headers:Object.fromEntries(Object.entries(currentRead.headers).filter(([key])=>key==='authorization'||key==='content-type'||key.startsWith('x-'))),body:JSON.stringify(assessments[0].body),signal:AbortSignal.timeout(10000)});assert.notEqual(staleReceipt.status,200);assert.deepEqual(await observations.counts(),currentCounts);
  // Repeat with real persona logout while the response is withheld.
  await select(foreign.id);holdNext=true;await click('Read for assessment');await waitHeld();await frame.click('[aria-label="Account menu"]');await click('Sign out');personaCancellation=await cancellations.release(held);held=null;await frame.waitForFunction(()=>!document.querySelector('[data-testid="inbox-userid"]'),{timeout:15000});assert.equal((await observations.counts()).calls,after.calls);
  return{status:'passed',candidateOnly:true,actualModelCalls:0,controlledJudgeCalls:after.calls,readReplaySameId:true,assessmentReplaySameId:true,mailboxAbort:true,personaAbort:true,mailboxCancellation,personaCancellation,resetRetiredAuthorityDenied:true,resetStaleReceiptWithCurrentAuthorityDenied:true};
 }finally{cancellations.close();if(held)await cdp.send('Fetch.failRequest',{requestId:held.requestId,errorReason:'Aborted'}).catch(()=>{});await cdp.send('Fetch.disable').catch(()=>{});await cdp.detach();}
 async function waitHeld(){const until=Date.now()+10000;while(!held&&!captureError&&Date.now()<until)await new Promise(r=>setTimeout(r,20));if(captureError)throw captureError;assert(held,'Held response deadline');}
}
module.exports={qualifyDisclosureInFrame,selectInboxUser,trackRequestCancellation};
