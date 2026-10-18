'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
const key='direct_prompt_injection',route='/vulnerabilities/direct-prompt-injection';
function canonicalObjectiveLabel(rows,id){
 const matched=rows.filter(row=>row.objective_id===id);
 assert.equal(matched.length,1,'Exactly one current canonical objective required: '+id);
 assert.ok(typeof matched[0].label==='string'&&matched[0].label.trim(),'Current canonical objective label required: '+id);
 return matched[0].label;
}
async function qualifyDpiFullAppRendered({origin,student,sibling,admin,password,root,rows,projection,teachingCopy,retainedPending8b=false,actualSystemPrompt=false,actualBaselineLanguage=false,actualMultilingual70b=false,actualWholeTask70b=false,actualSideSelected70b=false,actualSideSelectedV16_70b=false,actualTechniquesSelected70b=false,actualTechniquesSelected8b=false,creditMultilingual70b=false,creditTechniquesSelected8b=false,baselineLanguageTailOnly=false,actualPrompt=null,actualTurns=null,multilingual70bTurns=null,wholeTask70bTurns=null,sideSelected70bTurns=null,techniquesSelected70bTurns=null,techniquesSelected8bTurns=null,onActualTurn=null,onMultilingual70bTurn=null,onWholeTask70bTurn=null,onSideSelected70bTurn=null,onSideSelectedV16_70bTurn=null,onTechniquesSelected70bTurn=null,onTechniquesSelected8bTurn=null,healthOnly=false}){
 assert.ok(!retainedPending8b||!healthOnly&&!baselineLanguageTailOnly&&![actualSystemPrompt,actualBaselineLanguage,actualMultilingual70b,actualWholeTask70b,actualSideSelected70b,actualSideSelectedV16_70b,actualTechniquesSelected70b,actualTechniquesSelected8b].some(Boolean),'Retained pending browser is an exclusive zero-model profile');
 assert.ok(!healthOnly||actualSystemPrompt,'Actual provider health requires the real-model profile');
 assert.ok(!(actualSystemPrompt&&actualBaselineLanguage),'One actual DPI cohort per owned browser');
 assert.ok(!actualMultilingual70b||!actualSystemPrompt&&!actualBaselineLanguage&&!actualWholeTask70b&&!baselineLanguageTailOnly&&!healthOnly,'70B multilingual profile is exclusive');
 assert.ok(!actualWholeTask70b||!actualSystemPrompt&&!actualBaselineLanguage&&!actualMultilingual70b&&!baselineLanguageTailOnly&&!healthOnly,'70B whole-task profile is exclusive');
 assert.ok(!actualSideSelected70b||!actualSystemPrompt&&!actualBaselineLanguage&&!actualMultilingual70b&&!actualWholeTask70b&&!baselineLanguageTailOnly&&!healthOnly,'70B selected-task side-stepping profile is exclusive');
 assert.ok(!actualSideSelectedV16_70b||!actualSystemPrompt&&!actualBaselineLanguage&&!actualMultilingual70b&&!actualWholeTask70b&&!actualSideSelected70b&&!baselineLanguageTailOnly&&!healthOnly,'70B v16 selected-task side-stepping profile is exclusive');
 assert.ok(!actualTechniquesSelected70b||!actualSystemPrompt&&!actualBaselineLanguage&&!actualMultilingual70b&&!actualWholeTask70b&&!actualSideSelected70b&&!actualSideSelectedV16_70b&&!baselineLanguageTailOnly&&!healthOnly,'70B selected-task techniques profile is exclusive');
 assert.ok(!actualTechniquesSelected8b||!actualSystemPrompt&&!actualBaselineLanguage&&!actualMultilingual70b&&!actualWholeTask70b&&!actualSideSelected70b&&!actualSideSelectedV16_70b&&!actualTechniquesSelected70b&&!baselineLanguageTailOnly&&!healthOnly,'8B selected-task techniques profile is exclusive');
 assert.ok(!creditTechniquesSelected8b||actualTechniquesSelected8b,'8B selected-task credit requires its actual profile');
 assert.ok(!creditMultilingual70b||actualMultilingual70b,'Credit profile requires actual multilingual cohort');
 assert.ok(!baselineLanguageTailOnly||actualBaselineLanguage,'Controlled tail requires baseline/language rendering');
 const actualDpi=retainedPending8b||actualSystemPrompt||actualBaselineLanguage||actualMultilingual70b||actualWholeTask70b||actualSideSelected70b||actualSideSelectedV16_70b||actualTechniquesSelected70b||actualTechniquesSelected8b;
 const browser=await require('./secureshopAnalyticsBrowserOwner').launchOwnedAnalyticsBrowser(root,'dpiparity');
 const browserDeadline=setTimeout(()=>{browser.close().catch(()=>{});},retainedPending8b||actualBaselineLanguage||actualMultilingual70b||actualWholeTask70b||actualSideSelected70b||actualSideSelectedV16_70b||actualTechniquesSelected70b?900000:actualTechniquesSelected8b?900000:actualSystemPrompt?480000:180000);
 const errors=[],blocked=[],posts=[],helpRequests=[],screenshots=[];let page,adminPage,siblingPage,stage='login',activeHelp=null;
 const click=async(page,selector)=>{const el=await page.waitForSelector(selector,{visible:true});await el.evaluate(e=>e.scrollIntoView({block:'center',behavior:'instant'}));await page.waitForFunction(s=>{const e=document.querySelector(s);if(!e)return false;const r=e.getBoundingClientRect(),hit=document.elementFromPoint(r.x+r.width/2,r.y+r.height/2);return hit===e||e.contains(hit);},{},selector);await el.click();};
 const activateHelp=async(page,selector)=>{const el=await page.waitForSelector(selector,{visible:true});await el.evaluate(e=>e.scrollIntoView({block:'center',behavior:'instant'}));await el.focus();await el.press('Enter');await page.waitForFunction(s=>document.querySelector(s)?.getAttribute('aria-expanded')==='true',{},selector);};
 const api=(page,url,method='GET',body)=>page.evaluate(async({url,method,body})=>{const response=await fetch(url,{method,headers:{authorization:'Bearer '+localStorage.getItem('token'),'content-type':'application/json'},...(body===undefined?{}:{body:JSON.stringify(body)})});return{status:response.status,body:await response.json()};},{url,method,body});
 const screenshot=async(page,name)=>{await page.waitForFunction(()=>document.readyState==='complete'&&getComputedStyle(document.body).visibility!=='hidden'&&Number(getComputedStyle(document.body).opacity)>=0.99);await page.screenshot({path:path.join(root,name+'.png'),fullPage:true});screenshots.push(name+'.png');};
 async function login(user){const context=await browser.createBrowserContext(),p=await context.newPage();await p.setViewport({width:1440,height:1100});p.setDefaultTimeout(15000);await require('./fullBackendRenderedSecureShop').configurePage(p,origin,blocked,errors);await p.emulateMediaFeatures([{name:'prefers-reduced-motion',value:'reduce'}]);p.on('request',r=>{const pathname=new URL(r.url()).pathname;if(r.method()==='POST')posts.push(pathname);if(r.method()==='GET'&&(/^\/api\/hints\/direct_prompt_injection\//.test(pathname)||/^\/api\/solutions\/prompt-injection\//.test(pathname)))helpRequests.push(pathname);});await p.goto(origin+'/workshop-login',{waitUntil:'domcontentloaded'});await p.waitForSelector('input[placeholder="Enter your username"]');await p.type('input[placeholder="Enter your username"]',user.username);await p.type('input[placeholder="Enter your password"]',password);const response=p.waitForResponse(r=>new URL(r.url()).pathname==='/api/auth/login'&&r.request().method()==='POST');await click(p,'button[type="submit"]');const login=await response;assert.equal(login.status(),200);assert.equal(Number((await login.json()).user.id),user.id);await p.waitForFunction(()=>localStorage.getItem('token')&&location.pathname!=='/workshop-login');return p;}
 const counts=async(page,completed,total)=>{await page.waitForFunction(({completed,total})=>new RegExp(completed+'\\s*[/]\\s*'+total+'|'+completed+' of '+total).test(document.body.innerText),{},{completed,total});};
 try{
  page=await login(student);
  if(healthOnly){
   const status=page.waitForResponse(r=>new URL(r.url()).pathname==='/api/workshop/prompt-injection/llm-status'&&r.request().method()==='GET');status.catch(()=>{});
   await page.goto(origin+route,{waitUntil:'domcontentloaded'});
   const received=await status,body=await received.json();assert.equal(received.status(),200);assert.equal(body.provider,'ollama');assert.equal(body.model,'llama3.1:8b');assert.equal(body.available,true);assert.equal(body.healthy,true);
   await page.waitForFunction(()=>document.body.innerText.includes('Ollama actor available')&&document.body.innerText.includes('Actor availability does not confirm Judge readiness.'));
   await page.waitForFunction(()=>{const badge=[...document.querySelectorAll('span')].find(node=>node.textContent.includes('Ollama actor available'));if(!badge)return false;const rect=badge.getBoundingClientRect();if(rect.width===0||rect.height===0)return false;for(let node=badge;node;node=node.parentElement){const style=getComputedStyle(node);if(style.display==='none'||style.visibility==='hidden'||Number(style.opacity)<0.99)return false;}return true;});
   assert.equal(posts.filter(p=>p==='/api/workshop/prompt-injection/chat').length,0);assert.deepEqual(errors,[]);assert.deepEqual(blocked,[]);
   await screenshot(page,'dpi-provider-health');
   return {status:'passed',healthOnly:true,fullIndex:true,realJwtLogin:true,providerReady:true,model:body.model,chatPosts:0,screenshots};
  }
  adminPage=await login(admin);
  if(retainedPending8b){assert(sibling);siblingPage=await login(sibling);await siblingPage.goto(origin+'/workshop-dashboard',{waitUntil:'domcontentloaded'});await counts(siblingPage,1,8);}
  let actualSystemPromptJudgment=null,actualBaselineLanguageJudgments=null,actualMultilingual70bJudgments=null,actualWholeTask70bJudgments=null,actualSideSelected70bJudgments=null,actualSideSelectedV16_70bJudgments=null,actualTechniquesSelected70bJudgments=null,actualTechniquesSelected8bJudgments=null;const completed=retainedPending8b?0:actualTechniquesSelected70b||actualTechniquesSelected8b&&creditTechniquesSelected8b?2:actualSideSelectedV16_70b?1:actualWholeTask70b||actualSideSelected70b||actualTechniquesSelected8b?0:actualMultilingual70b?(creditMultilingual70b?1:0):actualSystemPrompt?1:2;
  if(actualSystemPrompt){
   assert.equal(actualPrompt,require('../../server/data/promptInjectionSolutions').solutions.system_prompt.examples[0].prompt);
   await page.goto(origin+route,{waitUntil:'domcontentloaded'});
   await click(page,'[data-testid="objective-card-system_prompt"]');
   const objectiveLabel=canonicalObjectiveLabel(rows,'system_prompt');
   await page.waitForFunction(label=>document.querySelector('[data-testid="dpi-active-objective"]')?.textContent.trim()===`Exercise: ${label}`,{},objectiveLabel);
   assert.ok((await page.$eval('[data-testid="objective-card-system_prompt"]',element=>element.innerText)).includes('ACTIVE'));
   await page.waitForSelector('textarea:not([disabled])');await page.type('textarea',actualPrompt);
   const response=page.waitForResponse(r=>new URL(r.url()).pathname==='/api/workshop/prompt-injection/chat'&&r.request().method()==='POST',{timeout:180000});response.catch(()=>{});
   await click(page,'button[aria-label="Send message"]');const reply=await response,body=await reply.json();
   if(reply.status()!==200){const projected={status:reply.status(),authorizationPresent:Boolean(reply.request().headers().authorization)};for(const key of ['success','code','field','error','message'])if(['boolean','string'].includes(typeof body?.[key])&&String(body[key]).length<=256)projected[key]=body[key];fs.writeFileSync(path.join(root,'dpi-chat-non200.json'),JSON.stringify(projected),{flag:'wx',mode:0o600});}
   assert.equal(reply.status(),200);assert.equal(body.judgment?.verdict,'pass');assert.equal(body.completedObjectiveId,'system_prompt');
   await page.waitForFunction(()=>document.querySelector('[data-testid="objective-card-system_prompt"]')?.innerText.includes('COMPLETED'));
   await page.waitForFunction(()=>document.querySelector('[data-testid="active-transcript"]')?.innerText.includes('Success!'));
   actualSystemPromptJudgment=body.judgment;
  }
  if(actualBaselineLanguage&&!baselineLanguageTailOnly){
   assert.equal(actualTurns?.length,5);
   const expected=[['interact','fail','not_pass'],['interact','pass','threshold_pending'],['interact','pass','awarded'],['multi_language','fail','not_pass'],['multi_language','pass','awarded']];
   actualBaselineLanguageJudgments=[];
   await page.goto(origin+route,{waitUntil:'domcontentloaded'});
   for(let i=0;i<actualTurns.length;i++){
    stage='actual-turn-'+(i+1);
    const turn=actualTurns[i], [objectiveId,verdict,disposition]=expected[i];
    assert.equal(turn.objectiveId,objectiveId);assert.equal(turn.expectedVerdict,verdict);assert.equal(turn.expectedDisposition,disposition);
    await click(page,'[data-testid="objective-card-'+objectiveId+'"]');
    const label=canonicalObjectiveLabel(rows,objectiveId);
    await page.waitForFunction(text=>document.querySelector('[data-testid="dpi-active-objective"]')?.textContent.trim()===`Exercise: ${text}`,{},label);
    await page.waitForSelector('textarea:not([disabled])');await page.type('textarea',turn.prompt);
    const response=page.waitForResponse(r=>new URL(r.url()).pathname==='/api/workshop/prompt-injection/chat'&&r.request().method()==='POST',{timeout:180000});response.catch(()=>{});
    await click(page,'button[aria-label="Send message"]');const reply=await response,body=await reply.json();
    assert.equal(reply.status(),200);assert.equal(body.judgment?.verdict,verdict);
    assert.ok(body.judgment?.evaluationId);
    if(disposition==='awarded'){
     if(objectiveId==='interact')assert.equal(body.completedObjectiveId,null,'Practice completion is read from canonical progress');
     else assert.equal(body.completedObjectiveId,objectiveId);
     await page.waitForFunction(id=>document.querySelector('[data-testid="objective-card-'+id+'"]')?.innerText.includes('COMPLETED')||document.querySelector('[data-testid="objective-card-'+id+'"]')?.innerText.includes('DONE'),{},objectiveId);
    }else assert.notEqual(body.completedObjectiveId,objectiveId);
    const observed={id:turn.id,objectiveId,evaluationId:body.judgment.evaluationId,verdict,expectedDisposition:disposition};
    if(onActualTurn)await onActualTurn(observed,i);
    actualBaselineLanguageJudgments.push(observed);
   }
   assert.ok((await page.$eval('[data-testid="objective-card-interact"]',e=>e.innerText)).includes('DONE'));
   assert.ok((await page.$eval('[data-testid="objective-card-multi_language"]',e=>e.innerText)).includes('COMPLETED'));
   await screenshot(page,'dpi-baseline-language-completed');
  }
  if(actualMultilingual70b){
   assert.equal(multilingual70bTurns?.length,2);actualMultilingual70bJudgments=[];
   await page.goto(origin+route,{waitUntil:'domcontentloaded'});
   for(let i=0;i<2;i++){
    stage='actual-multilingual70b-turn-'+(i+1);
    const turn=multilingual70bTurns[i];assert.equal(turn.objectiveId,'multi_language');
    await click(page,'[data-testid="objective-card-multi_language"]');
    const label=canonicalObjectiveLabel(rows,'multi_language');
    await page.waitForFunction(text=>document.querySelector('[data-testid="dpi-active-objective"]')?.textContent.trim()===`Exercise: ${text}`,{},label);
    await page.waitForSelector('textarea:not([disabled])');await page.type('textarea',turn.prompt);
    const response=page.waitForResponse(r=>new URL(r.url()).pathname==='/api/workshop/prompt-injection/chat'&&r.request().method()==='POST',{timeout:180000});response.catch(()=>{});
    await click(page,'button[aria-label="Send message"]');const reply=await response,body=await reply.json();
    const observed={id:turn.id,objectiveId:'multi_language',evaluationId:body.judgment?.evaluationId??null,rawVerdict:body.judgment?.verdict??null,gradingDisposition:body.judgment?.gradingDisposition??null,httpStatus:reply.status(),completedObjectiveId:body.completedObjectiveId??null};
    fs.writeFileSync(path.join(root,'dpi-multilingual70b-browser-turn-'+String(i+1).padStart(2,'0')+'.json'),JSON.stringify({observed,responseBody:body}),{flag:'wx',mode:0o600});
    if(onMultilingual70bTurn&&observed.evaluationId)await onMultilingual70bTurn(observed,i);
    assert.equal(reply.status(),200);assert.ok(observed.evaluationId);
    if(creditMultilingual70b){assert.equal(observed.rawVerdict,i?'pass':'fail');assert.equal(observed.gradingDisposition,null);assert.equal(body.completedObjectiveId,i?'multi_language':null);}
    else{assert.equal(observed.gradingDisposition,'grading_unqualified');assert.notEqual(body.completedObjectiveId,'multi_language');await page.waitForFunction(()=>document.querySelector('[data-testid="active-transcript"]')?.innerText.includes('Objective grading is not qualified for reliable credit.'));}
    if(i&&creditMultilingual70b)await page.waitForFunction(()=>document.querySelector('[data-testid="objective-card-multi_language"]')?.innerText.includes('COMPLETED'));
    else assert.ok(!(await page.$eval('[data-testid="objective-card-multi_language"]',element=>element.innerText)).includes('COMPLETED'));
    actualMultilingual70bJudgments.push(observed);
   }
   await screenshot(page,creditMultilingual70b?'dpi-multilingual70b-credit':'dpi-multilingual70b-pending');
  }
  if(actualWholeTask70b){
   assert.equal(wholeTask70bTurns?.length,4);actualWholeTask70bJudgments=[];
   await page.goto(origin+route,{waitUntil:'domcontentloaded'});
   for(let i=0;i<wholeTask70bTurns.length;i++){
    stage='actual-whole-task70b-turn-'+(i+1);
    const turn=wholeTask70bTurns[i];assert.ok(['virtualization','obfuscation'].includes(turn.objectiveId));
    await click(page,'[data-testid="objective-card-'+turn.objectiveId+'"]');
    const label=canonicalObjectiveLabel(rows,turn.objectiveId);
    await page.waitForFunction(text=>document.querySelector('[data-testid="dpi-active-objective"]')?.textContent.trim()===`Exercise: ${text}`,{},label);
    await page.waitForSelector('textarea:not([disabled])');await page.type('textarea',turn.prompt);
    const response=page.waitForResponse(r=>new URL(r.url()).pathname==='/api/workshop/prompt-injection/chat'&&r.request().method()==='POST',{timeout:360000});response.catch(()=>{});
    await click(page,'button[aria-label="Send message"]');const reply=await response,body=await reply.json();
    const observed={id:turn.id,objectiveId:turn.objectiveId,evaluationId:body.judgment?.evaluationId??null,rawVerdict:body.judgment?.verdict??null,gradingDisposition:body.judgment?.gradingDisposition??null,httpStatus:reply.status(),completedObjectiveId:body.completedObjectiveId??null};
    fs.writeFileSync(path.join(root,'dpi-whole-task70b-browser-turn-'+String(i+1).padStart(2,'0')+'.json'),JSON.stringify({observed,responseBody:body}),{flag:'wx',mode:0o600});
    assert.equal(reply.status(),200);assert.ok(observed.evaluationId);assert.equal(observed.rawVerdict,turn.expectedVerdict);assert.equal(observed.gradingDisposition,'grading_unqualified');assert.notEqual(body.completedObjectiveId,turn.objectiveId);
    await page.waitForFunction(()=>document.querySelector('[data-testid="active-transcript"]')?.innerText.includes('Objective grading is not qualified for reliable credit.'));
    assert.ok(!(await page.$eval('[data-testid="objective-card-'+turn.objectiveId+'"]',element=>element.innerText)).includes('COMPLETED'));
    if(onWholeTask70bTurn)await onWholeTask70bTurn(observed,i);
    actualWholeTask70bJudgments.push(observed);
   }
   await screenshot(page,'dpi-whole-task70b-pending');
  }
  if(actualSideSelected70b){
   assert.equal(sideSelected70bTurns?.length,2);actualSideSelected70bJudgments=[];
   await page.goto(origin+route,{waitUntil:'domcontentloaded'});
   for(let i=0;i<sideSelected70bTurns.length;i++){
    stage='actual-side-selected70b-turn-'+(i+1);
    const turn=sideSelected70bTurns[i];assert.equal(turn.objectiveId,'side_stepping');
    await click(page,'[data-testid="objective-card-side_stepping"]');
    const label=canonicalObjectiveLabel(rows,'side_stepping');
    await page.waitForFunction(text=>document.querySelector('[data-testid="dpi-active-objective"]')?.textContent.trim()===`Exercise: ${text}`,{},label);
    await page.waitForSelector('textarea:not([disabled])');await page.type('textarea',turn.prompt);
    const response=page.waitForResponse(r=>new URL(r.url()).pathname==='/api/workshop/prompt-injection/chat'&&r.request().method()==='POST',{timeout:360000});response.catch(()=>{});
    await click(page,'button[aria-label="Send message"]');const reply=await response,body=await reply.json();
    const observed={id:turn.id,objectiveId:'side_stepping',evaluationId:body.judgment?.evaluationId??null,rawVerdict:body.judgment?.verdict??null,gradingDisposition:body.judgment?.gradingDisposition??null,httpStatus:reply.status(),completedObjectiveId:body.completedObjectiveId??null};
    fs.writeFileSync(path.join(root,'dpi-side-selected70b-browser-turn-'+String(i+1).padStart(2,'0')+'.json'),JSON.stringify({observed,responseBody:body}),{flag:'wx',mode:0o600});
    assert.equal(reply.status(),200);assert.ok(observed.evaluationId);assert.equal(observed.rawVerdict,turn.expectedVerdict);assert.equal(observed.gradingDisposition,'grading_unqualified');assert.notEqual(body.completedObjectiveId,'side_stepping');
    await page.waitForFunction(()=>document.querySelector('[data-testid="active-transcript"]')?.innerText.includes('Objective grading is not qualified for reliable credit.'));
    assert.ok(!(await page.$eval('[data-testid="objective-card-side_stepping"]',element=>element.innerText)).includes('COMPLETED'));
    if(onSideSelected70bTurn)await onSideSelected70bTurn(observed,i);
    actualSideSelected70bJudgments.push(observed);
   }
   await screenshot(page,'dpi-side-selected70b-pending');
  }
  if(actualSideSelectedV16_70b){
   assert.equal(sideSelected70bTurns?.length,2);actualSideSelectedV16_70bJudgments=[];
   await page.goto(origin+route,{waitUntil:'domcontentloaded'});
   for(let i=0;i<sideSelected70bTurns.length;i++){
    stage='actual-side-selected-v16-70b-turn-'+(i+1);
    const turn=sideSelected70bTurns[i];assert.equal(turn.objectiveId,'side_stepping');
    await click(page,'[data-testid="objective-card-side_stepping"]');
    const label=canonicalObjectiveLabel(rows,'side_stepping');
    await page.waitForFunction(text=>document.querySelector('[data-testid="dpi-active-objective"]')?.textContent.trim()===`Exercise: ${text}`,{},label);
    await page.waitForSelector('textarea:not([disabled])');await page.type('textarea',turn.prompt);
    const response=page.waitForResponse(r=>new URL(r.url()).pathname==='/api/workshop/prompt-injection/chat'&&r.request().method()==='POST',{timeout:360000});response.catch(()=>{});
    await click(page,'button[aria-label="Send message"]');const reply=await response,body=await reply.json();
    const observed={id:turn.id,objectiveId:'side_stepping',evaluationId:body.judgment?.evaluationId??null,rawVerdict:body.judgment?.verdict??null,gradingDisposition:body.judgment?.gradingDisposition??null,httpStatus:reply.status(),completedObjectiveId:body.completedObjectiveId??null};
    fs.writeFileSync(path.join(root,'dpi-side-selected-v16-70b-browser-turn-'+String(i+1).padStart(2,'0')+'.json'),JSON.stringify({observed,responseBody:body}),{flag:'wx',mode:0o600});
    assert.equal(reply.status(),200);assert.ok(observed.evaluationId);assert.equal(observed.rawVerdict,turn.expectedVerdict);assert.equal(observed.gradingDisposition,null);
    if(i===0){assert.equal(body.completedObjectiveId,null);assert.ok(!(await page.$eval('[data-testid="objective-card-side_stepping"]',element=>element.innerText)).includes('COMPLETED'));}
    else{assert.equal(body.completedObjectiveId,'side_stepping');await page.waitForFunction(()=>document.querySelector('[data-testid="objective-card-side_stepping"]')?.innerText.includes('COMPLETED'));}
    if(onSideSelectedV16_70bTurn)await onSideSelectedV16_70bTurn(observed,i);
    actualSideSelectedV16_70bJudgments.push(observed);
   }
   await screenshot(page,'dpi-side-selected-v16-70b-awarded');
  }
  if(actualTechniquesSelected70b){
   assert.equal(techniquesSelected70bTurns?.length,4);actualTechniquesSelected70bJudgments=[];
   const expected=[['jailbreak-negative','jailbreak','fail'],['jailbreak-positive','jailbreak','pass'],['role-negative','role_playing','fail'],['role-positive','role_playing','pass']];
   await page.goto(origin+route,{waitUntil:'domcontentloaded'});
   for(let i=0;i<techniquesSelected70bTurns.length;i++){
    stage='actual-techniques-selected70b-turn-'+(i+1);
    const turn=techniquesSelected70bTurns[i],[id,objectiveId,verdict]=expected[i];assert.equal(turn.id,id);assert.equal(turn.objectiveId,objectiveId);assert.equal(turn.expectedVerdict,verdict);
    await click(page,'[data-testid="objective-card-'+objectiveId+'"]');
    const label=canonicalObjectiveLabel(rows,objectiveId);
    await page.waitForFunction(text=>document.querySelector('[data-testid="dpi-active-objective"]')?.textContent.trim()===`Exercise: ${text}`,{},label);
    await page.waitForSelector('textarea:not([disabled])');await page.type('textarea',turn.prompt);
    const response=page.waitForResponse(r=>new URL(r.url()).pathname==='/api/workshop/prompt-injection/chat'&&r.request().method()==='POST',{timeout:360000});response.catch(()=>{});
    await click(page,'button[aria-label="Send message"]');const reply=await response,body=await reply.json();
    const observed={id:turn.id,objectiveId,evaluationId:body.judgment?.evaluationId??null,rawVerdict:body.judgment?.verdict??null,gradingDisposition:body.judgment?.gradingDisposition??null,httpStatus:reply.status(),completedObjectiveId:body.completedObjectiveId??null};
    fs.writeFileSync(path.join(root,'dpi-techniques-selected70b-browser-turn-'+String(i+1).padStart(2,'0')+'.json'),JSON.stringify({observed,responseBody:body}),{flag:'wx',mode:0o600});
    assert.equal(reply.status(),200);assert.ok(observed.evaluationId);assert.equal(observed.rawVerdict,verdict);assert.equal(observed.gradingDisposition,null);
    if(verdict==='pass'){assert.equal(body.completedObjectiveId,objectiveId);await page.waitForFunction(id=>document.querySelector('[data-testid="objective-card-'+id+'"]')?.innerText.includes('COMPLETED'),{},objectiveId);}
    else{assert.equal(body.completedObjectiveId,null);assert.ok(!(await page.$eval('[data-testid="objective-card-'+objectiveId+'"]',element=>element.innerText)).includes('COMPLETED'));}
    if(i===2)assert.ok((await page.$eval('[data-testid="objective-card-jailbreak"]',element=>element.innerText)).includes('COMPLETED'));
    if(onTechniquesSelected70bTurn)await onTechniquesSelected70bTurn(observed,i);
    actualTechniquesSelected70bJudgments.push(observed);
   }
   assert.ok((await page.$eval('[data-testid="objective-card-jailbreak"]',element=>element.innerText)).includes('COMPLETED'));
   assert.ok((await page.$eval('[data-testid="objective-card-role_playing"]',element=>element.innerText)).includes('COMPLETED'));
   await screenshot(page,'dpi-techniques-selected70b-awarded');
  }
  if(actualTechniquesSelected8b){
   assert.equal(techniquesSelected8bTurns?.length,4);actualTechniquesSelected8bJudgments=[];
   const expected=[['jailbreak-negative','jailbreak','fail'],['jailbreak-positive','jailbreak','pass'],['role-negative','role_playing','fail'],['role-positive','role_playing','pass']];
   await page.goto(origin+route,{waitUntil:'domcontentloaded'});
   for(let i=0;i<techniquesSelected8bTurns.length;i++){
    stage='actual-techniques-selected8b-turn-'+(i+1);
    const turn=techniquesSelected8bTurns[i],[id,objectiveId,verdict]=expected[i];assert.equal(turn.id,id);assert.equal(turn.objectiveId,objectiveId);assert.equal(turn.expectedVerdict,verdict);
    await click(page,'[data-testid="objective-card-'+objectiveId+'"]');
    const label=canonicalObjectiveLabel(rows,objectiveId);
    await page.waitForFunction(text=>document.querySelector('[data-testid="dpi-active-objective"]')?.textContent.trim()===`Exercise: ${text}`,{},label);
    await page.waitForSelector('textarea:not([disabled])');await page.type('textarea',turn.prompt);
    const response=page.waitForResponse(r=>new URL(r.url()).pathname==='/api/workshop/prompt-injection/chat'&&r.request().method()==='POST',{timeout:360000});response.catch(()=>{});
    await click(page,'button[aria-label="Send message"]');const reply=await response,body=await reply.json();
    const observed={id:turn.id,objectiveId,evaluationId:body.judgment?.evaluationId??null,rawVerdict:body.judgment?.verdict??null,gradingDisposition:body.judgment?.gradingDisposition??null,httpStatus:reply.status(),completedObjectiveId:body.completedObjectiveId??null};
    fs.writeFileSync(path.join(root,'dpi-techniques-selected8b-browser-turn-'+String(i+1).padStart(2,'0')+'.json'),JSON.stringify({observed,responseBody:body}),{flag:'wx',mode:0o600});
    assert.equal(reply.status(),200);assert.ok(observed.evaluationId);assert.equal(observed.rawVerdict,verdict);assert.equal(observed.gradingDisposition,creditTechniquesSelected8b?null:'grading_unqualified');
    if(creditTechniquesSelected8b&&verdict==='pass'){assert.equal(body.completedObjectiveId,objectiveId);await page.waitForFunction(id=>document.querySelector('[data-testid="objective-card-'+id+'"]')?.innerText.includes('COMPLETED'),{},objectiveId);}
    else{assert.equal(body.completedObjectiveId,null);if(!creditTechniquesSelected8b)await page.waitForFunction(()=>document.querySelector('[data-testid="active-transcript"]')?.innerText.includes('Objective grading is not qualified for reliable credit.'));assert.ok(!(await page.$eval('[data-testid="objective-card-'+objectiveId+'"]',element=>element.innerText)).includes('COMPLETED'));}
    if(onTechniquesSelected8bTurn)await onTechniquesSelected8bTurn(observed,i);
    actualTechniquesSelected8bJudgments.push(observed);
   }
   assert.equal((await page.$eval('[data-testid="objective-card-jailbreak"]',element=>element.innerText)).includes('COMPLETED'),creditTechniquesSelected8b);
   assert.equal((await page.$eval('[data-testid="objective-card-role_playing"]',element=>element.innerText)).includes('COMPLETED'),creditTechniquesSelected8b);
   await screenshot(page,creditTechniquesSelected8b?'dpi-techniques-selected8b-awarded':'dpi-techniques-selected8b-pending');
  }
  for(const p of ['/workshop-dashboard','/workshop/challenges','/workshop/progress']){
   stage='dashboard:'+p;
   const loaded=actualDpi?page.waitForResponse(r=>new URL(r.url()).pathname==='/api/workshop/challenges'&&r.request().method()==='GET',{timeout:15000}):null;loaded?.catch(()=>{});
   await page.goto(origin+p,{waitUntil:'domcontentloaded'});await counts(page,completed,8);
   const card=await page.$eval('[data-testid="workshop-card-direct_prompt_injection"]',e=>e.innerText);
   if(actualDpi){
    const payload=await(await loaded).json(),challenge=payload.challenges.find(x=>x.workshopKey===key);
    assert.equal(challenge.completedObjectiveCount,completed);assert.equal(challenge.objectiveCount,8);
    const seconds=Math.max(0,Math.floor(Number(challenge.timeSpentSeconds)||0));assert.ok(seconds>0);
    const hours=Math.floor(seconds/3600),minutes=Math.floor((seconds%3600)/60);
    const expected=p==='/workshop/challenges'?(seconds<60?'< 1m':hours>0?`${hours}h ${minutes}m`:`${minutes}m`):(seconds<60?`${seconds}s`:hours>0?`${hours}h ${minutes}m`:`${minutes}m`);
    assert.ok(card.includes(expected),`Current DPI card time must equal its fetched canonical ${seconds}s projection`);
   }else assert.ok(card.includes(p==='/workshop/challenges'?'< 1m':projection.timeSpentSeconds+'s'));
   if(p==='/workshop/progress')assert.equal(new URL(page.url()).pathname,'/workshop-dashboard');
  }
  const progress=await api(page,'/api/workshop/progress'),challenges=await api(page,'/api/workshop/challenges'),stats=await api(page,'/api/workshop/student/stats');for(const r of [progress,challenges,stats])assert.equal(r.status,200);
  const pp=progress.body.challenges.find(x=>x.workshopKey===key),cp=challenges.body.challenges.find(x=>x.workshopKey===key);assert.deepEqual(pp,cp);assert.equal(pp.completedObjectiveCount,completed);assert.equal(pp.objectiveCount,8);assert.ok(pp.timeSpentSeconds>=projection.timeSpentSeconds);assert.equal(stats.body.completedObjectives,completed);assert.equal(stats.body.totalObjectives,8);await screenshot(page,'dpi-dashboard');
  stage='teaching:navigate';await page.goto(origin+route,{waitUntil:'domcontentloaded'});
  if(retainedPending8b){
   for(const id of ['virtualization','side_stepping','obfuscation']){
    const selector='[data-testid="objective-card-'+id+'"]';await page.waitForSelector(selector);assert.ok(!(await page.$eval(selector,e=>e.innerText)).includes('COMPLETED'));
    await click(page,selector);const label=canonicalObjectiveLabel(rows,id);await page.waitForFunction(text=>document.querySelector('[data-testid="dpi-active-objective"]')?.textContent.trim()===`Exercise: ${text}`,{},label);
    assert.equal((await api(page,'/api/workshop/progress')).body.challenges.find(x=>x.workshopKey===key).completedObjectiveCount,0);
   }
   assert.equal((await api(page,'/api/admin/exercises/'+key+'/objectives/obfuscation','PATCH',{enabled:false})).status,403);
  }
  for(const row of rows){const card='[data-testid="objective-card-'+row.objective_id+'"]';stage='teaching:'+row.objective_id+':card '+card;await page.waitForSelector(card);assert.ok((await page.$eval(card,e=>e.innerText)).includes(row.label));for(const kind of ['hint','solution']){const selector='[data-testid="'+kind+'-button-'+row.objective_id+'"]';stage='teaching:'+row.objective_id+':'+kind+':selector '+selector;if(!(kind==='hint'?row.has_hint:row.has_solution)){assert.equal(await page.$(selector),null);continue;}const visibility=await api(page,'/api/workshop/config/snapshot'),gate=visibility.body.exercises?.[key]?.objectives?.[row.objective_id];assert.equal(visibility.status,200);assert.equal(visibility.body.exercises?.[key]?.isVisible,true);assert.equal(gate?.isVisible,true);assert.equal(kind==='hint'?gate?.hintVisible:gate?.solutionVisible,true);const endpoint=kind==='hint'?'/api/hints/'+key+'/'+row.objective_id:'/api/solutions/prompt-injection/'+row.objective_id;activeHelp={objectiveId:row.objective_id,kind,selector,endpoint};const response=page.waitForResponse(r=>new URL(r.url()).pathname===endpoint);response.catch(()=>{});stage='teaching:'+row.objective_id+':'+kind+':activate '+selector;await activateHelp(page,selector);stage='teaching:'+row.objective_id+':'+kind+':loading-dialog';await page.waitForSelector('[role="dialog"]',{visible:true});stage='teaching:'+row.objective_id+':'+kind+':response '+endpoint;const received=await response;assert.equal(received.status(),200);assert.ok(helpRequests.includes(endpoint),'Native help activation must issue its visible-content request');const content=(await received.json())[kind];assert.ok(content?.title);stage='teaching:'+row.objective_id+':'+kind+':dialog-title';await page.waitForFunction(title=>document.querySelector('[role="dialog"]')?.innerText.includes(title),{},content.title);if(teachingCopy?.[row.objective_id]){
    assert.deepEqual(content,teachingCopy[row.objective_id][kind],'canonical current teaching content');
    if(kind==='hint')for(let i=1;i<content.hints.length;i++){
      const next=await page.evaluateHandle(()=>[...document.querySelectorAll('[role="dialog"] button')].find(b=>b.textContent.includes('Next hint')));assert.ok(next.asElement());await next.asElement().click();await page.waitForFunction(text=>document.querySelector('[role="dialog"]')?.innerText.includes(text),{},content.hints[i]);
    }
    const visible=await page.$eval('[role="dialog"]',e=>e.innerText),normalize=text=>text.replace(/\s+/g,' ').trim();
    const authored=kind==='hint'?content.hints:[content.approach,...content.examples.flatMap(x=>[x.prompt,x.explanation]),...(content.tips||[])];
    for(const text of authored.filter(Boolean))assert.ok(normalize(visible).includes(normalize(text)),'rendered authored teaching text: '+row.objective_id+'/'+kind);
    if(row.objective_id==='obfuscation')await screenshot(page,'dpi-decoder-'+kind);
  }stage='teaching:'+row.objective_id+':'+kind+':close';await click(page,'button[aria-label="Close '+kind+'"]');await page.waitForSelector('[role="dialog"]',{hidden:true});activeHelp=null;}}
  if(teachingCopy)assert.ok((await page.$eval('body',e=>e.innerText)).includes('vulnerable mode deliberately promotes the decoded output above the AWS-only restriction.'));
  if(!retainedPending8b&&!actualSystemPrompt&&!actualMultilingual70b&&!actualWholeTask70b&&!actualSideSelected70b&&!actualSideSelectedV16_70b&&!actualTechniquesSelected70b&&!actualTechniquesSelected8b)assert.ok((await page.$eval('[data-testid="objective-card-interact"]',e=>e.innerText)).includes('DONE'));
  if(actualMultilingual70b){assert.equal((await page.$eval('[data-testid="objective-card-multi_language"]',e=>e.innerText)).includes('COMPLETED'),creditMultilingual70b);await page.waitForFunction(count=>document.body.innerText.includes(count+' of 7 challenges completed'),{},creditMultilingual70b?1:0);}
  else if(actualSideSelectedV16_70b){assert.ok((await page.$eval('[data-testid="objective-card-side_stepping"]',e=>e.innerText)).includes('COMPLETED'));await page.waitForFunction(()=>document.body.innerText.includes('1 of 7 challenges completed'));}
  else if(actualTechniquesSelected70b){await page.waitForFunction(()=>document.body.innerText.includes('2 of 7 challenges completed'));}
  else if(actualTechniquesSelected8b){await page.waitForFunction(count=>document.body.innerText.includes(count+' of 7 challenges completed'),{},creditTechniquesSelected8b?2:0);}
  else if(!retainedPending8b&&!actualWholeTask70b&&!actualSideSelected70b){assert.ok((await page.$eval('[data-testid="objective-card-'+(actualBaselineLanguage?'multi_language':'system_prompt')+'"]',e=>e.innerText)).includes('COMPLETED'));await page.waitForFunction(()=>document.body.innerText.includes('1 of 7 challenges completed'));}
  if(retainedPending8b)await page.waitForFunction(()=>document.body.innerText.includes('0 of 7 challenges completed'));
  await screenshot(page,'dpi-eight-objectives');
  await adminPage.goto(origin+'/admin/exercises',{waitUntil:'domcontentloaded'});const card='[data-exercise-key="'+key+'"]';await adminPage.waitForSelector(card);
  if(teachingCopy){
    const manage=await adminPage.evaluateHandle(selector=>[...document.querySelector(selector).querySelectorAll('button')].find(b=>b.textContent.includes('Manage Objectives')),card);assert.ok(manage.asElement());await manage.asElement().click();
    await adminPage.waitForSelector('[data-objective-id="obfuscation"]');
    await click(adminPage,'[data-objective-id="obfuscation"] button[title="Edit Solution"]');
    await adminPage.waitForFunction(()=>[...document.querySelectorAll('h2')].some(e=>e.textContent.startsWith('Edit Solution:')));
    const editor=await adminPage.evaluate(()=>({textareas:[...document.querySelectorAll('textarea')].map(e=>e.value),inputs:[...document.querySelectorAll('input')].map(e=>e.value)}));
    assert.ok(editor.textareas.includes(teachingCopy.obfuscation.solution.approach));
    for(const example of teachingCopy.obfuscation.solution.examples){assert.ok(editor.textareas.includes(example.prompt));assert.ok(editor.textareas.includes(example.explanation));}
    for(const tip of teachingCopy.obfuscation.solution.tips)assert.ok(editor.inputs.includes(tip));
    await screenshot(adminPage,'dpi-decoder-admin-editor');
    // Navigation closes the read-only editor without saving or changing defaults.
    await adminPage.goto(origin+'/admin/exercises',{waitUntil:'domcontentloaded'});await adminPage.waitForSelector(card);
  }
  const master=async(field,value)=>{const dimension=field==='showSolutions'?'solutions':'hints',selector=card+' [data-control="'+dimension+'"]';stage='admin:canonical-'+field+'='+value;await adminPage.waitForFunction(async({field,value,key})=>{const response=await fetch('/api/workshop/config/snapshot',{cache:'no-store'}),body=await response.json(),observed=body.exercises?.[key]?.[field];window.__dpiMasterLast={field,expected:value,status:response.status,observed};return response.ok&&observed===value;},{polling:250},{field,value,key});stage='admin:control-settled-'+field+'='+value;await adminPage.waitForFunction(({selector,value})=>{const button=document.querySelector(selector);if(!button||button.getAttribute('aria-disabled')!=='false')return false;const expected=value?'rgb(72, 187, 120)':'rgb(203, 213, 224)';return getComputedStyle(button).backgroundColor===expected;},{polling:250},{selector,value});};
  stage='admin:toggle-solutions-off';await click(adminPage,card+' [data-control="solutions"]');await master('showSolutions',false);
  stage='learner:solutions-off';await page.reload();await page.waitForSelector('[data-testid="hint-button-interact"]');assert.equal(await page.$('[data-testid="solution-button-system_prompt"]'),null);
  stage='admin:toggle-solutions-on';await click(adminPage,card+' [data-control="solutions"]');await master('showSolutions',true);
  stage='admin:toggle-hints-off';await click(adminPage,card+' [data-control="hints"]');await master('showHints',false);
  stage='learner:hints-off';await page.reload();await page.waitForSelector('[data-testid="solution-button-system_prompt"]');assert.equal(await page.$('[data-testid="hint-button-interact"]'),null);
  stage='admin:toggle-hints-on';await click(adminPage,card+' [data-control="hints"]');await master('showHints',true);
  for(const row of rows)for(const [h,s]of [[false,false],[true,false],[false,true],[true,true]]){const base='/api/admin/exercises/'+key+'/objectives/'+row.objective_id;assert.equal((await api(adminPage,base+'/hint','PATCH',{enabled:h})).status,h&&!row.has_hint?404:200);assert.equal((await api(adminPage,base+'/solution','PATCH',{enabled:s})).status,s&&!row.has_solution?404:200);assert.equal((await api(page,'/api/hints/'+key+'/'+row.objective_id)).status,h&&row.has_hint?200:403);assert.equal((await api(page,'/api/solutions/prompt-injection/'+row.objective_id)).status,s&&row.has_solution?200:403);}
  assert.equal((await api(page,'/api/admin/exercises/'+key+'/objectives/interact','PATCH',{enabled:false})).status,403);
  const attackObjectives=retainedPending8b?['virtualization','side_stepping','obfuscation']:actualWholeTask70b?['virtualization','obfuscation']:actualSideSelected70b||actualSideSelectedV16_70b?['side_stepping']:actualTechniquesSelected70b||actualTechniquesSelected8b?['jailbreak','role_playing']:[actualBaselineLanguage||actualMultilingual70b?'multi_language':'system_prompt'];for(const attackObjective of attackObjectives)assert.equal((await api(adminPage,'/api/admin/exercises/'+key+'/objectives/'+attackObjective,'PATCH',{enabled:false})).status,200);await page.goto(origin+'/workshop-dashboard');await counts(page,retainedPending8b||actualSystemPrompt||actualMultilingual70b||actualWholeTask70b||actualSideSelected70b||actualSideSelectedV16_70b||actualTechniquesSelected70b||actualTechniquesSelected8b?0:1,8-attackObjectives.length);for(const attackObjective of attackObjectives)assert.equal((await api(adminPage,'/api/admin/exercises/'+key+'/objectives/'+attackObjective,'PATCH',{enabled:true})).status,200);await page.reload();await counts(page,completed,8);
  assert.equal((await api(adminPage,'/api/admin/exercises/'+key,'PATCH',{enabled:false})).status,200);assert.equal((await api(page,'/api/hints/'+key+'/interact')).status,403);await page.goto(origin+'/workshop/challenges');await page.waitForFunction(()=>document.readyState==='complete');const hidden=await api(page,'/api/workshop/challenges');assert.equal(hidden.body.challenges.some(x=>x.workshopKey===key),false);assert.equal((await api(adminPage,'/api/admin/exercises/'+key,'PATCH',{enabled:true})).status,200);
  await adminPage.goto(origin+'/admin/student-workshop-view?studentId='+student.id);await counts(adminPage,completed,8);assert.ok((await adminPage.$eval('body',e=>e.innerText)).match(/\b[1-9][0-9]*s\b|\b[1-9][0-9]*m\b/));await screenshot(adminPage,'dpi-admin-student');
  await page.goto(origin+route);await page.waitForSelector('[data-testid="objective-card-interact"]');page.on('dialog',dialog=>dialog.accept());const reset=page.waitForResponse(r=>new URL(r.url()).pathname==='/api/workshop/prompt-injection/progress/reset'&&r.request().method()==='POST');const resetButton=await page.evaluateHandle(()=>[...document.querySelectorAll('button')].find(b=>b.textContent.trim()==='Reset Progress'));assert.ok(resetButton.asElement());await resetButton.asElement().evaluate(e=>e.scrollIntoView({block:'center',behavior:'instant'}));await resetButton.asElement().click();await page.waitForSelector('[role="alertdialog"]');await click(page,'[role="alertdialog"] button:last-child');assert.equal((await reset).status(),200);await page.waitForFunction(()=>document.body.innerText.includes('0 of 7 challenges completed'));await page.goto(origin+'/workshop-dashboard');await counts(page,0,8);
  if(retainedPending8b){await siblingPage.reload();await counts(siblingPage,1,8);assert.equal((await api(page,'/api/workshop/progress')).body.challenges.find(x=>x.workshopKey===key).completedObjectiveCount,0);assert.equal((await api(page,'/api/auth/logout','POST',{})).status,200);assert.equal((await api(page,'/api/workshop/progress')).status,401);await siblingPage.reload();await counts(siblingPage,1,8);}
  assert.equal(posts.filter(p=>p==='/api/workshop/prompt-injection/chat').length,baselineLanguageTailOnly?0:actualWholeTask70b?4:actualSideSelected70b||actualSideSelectedV16_70b?2:actualTechniquesSelected70b?4:actualMultilingual70b?2:actualTechniquesSelected8b?4:actualBaselineLanguage?5:actualSystemPrompt?1:0);assert.deepEqual(errors,[]);assert.deepEqual(blocked,[]);
  return{status:'passed',fullIndex:true,realJwtLogin:true,controlledPersistedDisplay:retainedPending8b||baselineLanguageTailOnly||!actualDpi,retainedPending8b,baselineLanguageTailOnly,actualSystemPromptJudgment,actualBaselineLanguageJudgments,actualMultilingual70bJudgments,actualWholeTask70bJudgments,actualSideSelected70bJudgments,actualSideSelectedV16_70bJudgments,actualTechniquesSelected70bJudgments,actualTechniquesSelected8bJudgments,actualActorCalls:retainedPending8b||baselineLanguageTailOnly?0:actualWholeTask70b?6:actualSideSelected70b||actualSideSelectedV16_70b?2:actualTechniquesSelected70b?4:actualTechniquesSelected8b?4:actualMultilingual70b?2:actualBaselineLanguage?5:actualSystemPrompt?1:0,actualJudgeCalls:retainedPending8b||baselineLanguageTailOnly?0:actualDpi?null:0,objectiveIds:rows.map(r=>r.objective_id),canonicalCount:{completed,total:8},exerciseCount:{attackCompleted:retainedPending8b||actualWholeTask70b||actualSideSelected70b?0:actualSideSelectedV16_70b?1:actualTechniquesSelected70b?2:actualTechniquesSelected8b?(creditTechniquesSelected8b?2:0):actualMultilingual70b?(creditMultilingual70b?1:0):1,attackTotal:7,practiceCompleted:!retainedPending8b&&!actualSystemPrompt&&!actualMultilingual70b&&!actualWholeTask70b&&!actualSideSelected70b&&!actualSideSelectedV16_70b&&!actualTechniquesSelected70b&&!actualTechniquesSelected8b},independentHelpGateCombinations:32,teachingCopyRendered:!!teachingCopy,decoderAdminEditorParity:!!teachingCopy,practiceSolutionAbsent:!rows.find(r=>r.objective_id==='interact').has_solution,reset:true,siblingRenderedPreserved:retainedPending8b,revokedSessionDenied:retainedPending8b,screenshots};
 }catch(error){const helpState=page&&activeHelp?await page.evaluate(selector=>{const e=document.querySelector(selector),r=e?.getBoundingClientRect(),hit=r?document.elementFromPoint(r.x+r.width/2,r.y+r.height/2):null;return{exists:!!e,ariaExpanded:e?.getAttribute('aria-expanded')??null,disabled:e?.disabled??null,rect:r?{x:r.x,y:r.y,width:r.width,height:r.height}:null,hitTag:hit?.tagName??null,hitTestId:hit?.getAttribute('data-testid')??null,dialogOpen:!!document.querySelector('[role="dialog"]')};},activeHelp.selector).catch(()=>null):null,masterState=adminPage?await adminPage.evaluate(()=>window.__dpiMasterLast??null).catch(()=>null):null;if(page)await screenshot(page,'dpi-learner-failure').catch(()=>{});if(adminPage)await screenshot(adminPage,'dpi-admin-failure').catch(()=>{});fs.writeFileSync(path.join(root,'dpi-browser-error.json'),JSON.stringify({message:error.message,stage,activeHelp,helpState,masterState,errors,blocked,posts,helpRequests}),{mode:0o600});throw error;}finally{clearTimeout(browserDeadline);await browser.close();}
}
module.exports={qualifyDpiFullAppRendered,canonicalObjectiveLabel};
