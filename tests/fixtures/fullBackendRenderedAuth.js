'use strict';
const assert = require('node:assert/strict');
const { createValidatedBrowserJsonCache } = require('./validatedBrowserJsonCache');

// Caller owns the sandboxed, pinned browser and proxy. Accounts/run IDs are
// generated projection fixtures; this function never claims model execution.
function assertDeletedIdentity(row,{id,jobId}){assert.equal(Number(row?.id),id);assert.equal(Number(row.is_active),0);assert.equal(row.role,'student');assert.equal(Number(row.admin_level),0);assert.equal(row.username,'deleted-'+jobId);assert.equal(row.email,'deleted-'+jobId+'@invalid.local');}
function assertPopulatedRunDetail(body,{runId,ownerId,admin,privateMarker}){
 assert.equal(body?.run?.runId,runId);assert.equal(body.run.provider,'controlled-fixture');
 if(admin)assert.equal(body.run.ownerId,String(ownerId));else assert.equal(body.run.ownerId,undefined);
 assert.equal(body.run.ownerKey,undefined);assert.equal(body.run.owner_key,undefined);
 assert.ok(body.events.some(row=>row.type==='tool'&&row.data.tool==='searchProducts'));
 assert.ok(body.judgments.some(row=>row.verdict==='inconclusive'&&row.disposition==='not_pass'));
 assert.equal(JSON.stringify(body).includes(privateMarker),false,'private source packet must not be exposed');
}
// Runs in the browser against the real inspector, never the surrounding page/recovery list.
function populatedInspectorVisible({admin,runId,privateMarker}){
 const label=admin?'Administrator agent run inspector':'Your agent run inspector';
 const roots=document.querySelectorAll('[aria-label="'+label+'"]');if(roots.length!==1)return false;
 const root=roots[0],selected=[...root.querySelectorAll('[data-run-id][aria-pressed="true"]')];
 if(selected.length!==1||selected[0].getAttribute('data-run-id')!==runId)return false;
 const receipts=root.querySelectorAll('[aria-label="Authoritative Judge receipts"]');if(receipts.length!==1)return false;
 const exact=(scope,text)=>[...scope.querySelectorAll('span,strong')].some(e=>e.textContent.trim()===text);
 const receipt=receipts[0];
 if(!exact(receipt,'ARIA · sqli_1 · not_pass')||!exact(receipt,'Verdict: inconclusive · Disposition: not_pass')
  ||!exact(receipt,'Evaluation explanation: Controlled persisted receipt; no model evaluation was performed.'))return false;
 const event=[...root.querySelectorAll('ol > li')].some(row=>exact(row,'execute_tool')&&exact(row,'tool')&&exact(row,'tool: searchProducts')&&exact(row,'decision: controlled-fixture'));
 return event&&root.textContent.includes(runId)&&!root.textContent.includes(privateMarker);
}
async function replaceInput(element,value){
 await element.evaluate(e=>{e.focus();e.select();});await element.press('Backspace');
 assert.equal(await element.evaluate(e=>e.value),'','Owned input must be empty before typing');
 await element.type(value);assert.equal(await element.evaluate(e=>e.value),value,'Owned input must match typed value');
}
async function exactButton(page,label,username){
 await page.waitForFunction(({label,username})=>{const scope=username?[...document.querySelectorAll('tr')].find(row=>row.querySelector('td')?.textContent===username):document;const rows=[...(scope?.querySelectorAll('button')||[])].filter(b=>b.textContent.trim()===label&&!b.disabled&&b.getAttribute('aria-disabled')!=='true'&&b.getClientRects().length);if(rows.length!==1)return false;const b=rows[0];b.scrollIntoView({block:'center',inline:'center',behavior:'instant'});const r=b.getBoundingClientRect(),hit=document.elementFromPoint(r.x+r.width/2,r.y+r.height/2);return hit===b||b.contains(hit);},{},{label,username});
 const selector=await page.evaluate(({label,username})=>{
  const scope=username?[...document.querySelectorAll('tr')].find(row=>row.querySelector('td')?.textContent===username):document;
  const found=[...(scope?.querySelectorAll('button')||[])].filter(b=>b.textContent.trim()===label&&!b.disabled&&b.getAttribute('aria-disabled')!=='true'&&b.getClientRects().length);
  if(found.length!==1)throw Error('Expected unique enabled platform control: '+label);
  found[0].setAttribute('data-platform-control','selected');return '[data-platform-control="selected"]';
 },{label,username});
 try{await page.click(selector);}finally{await page.evaluate(()=>document.querySelector('[data-platform-control="selected"]')?.removeAttribute('data-platform-control'));}
}
function createResponseWaitOwner(){
 const pending=new Map();
 function wait(page,predicate){
  const controller=new AbortController();
  const promise=page.waitForResponse(predicate,{timeout:15000,signal:controller.signal});
  // Attach rejection ownership synchronously, including failures before the triggering click.
  promise.catch(()=>{});pending.set(promise,controller);
  promise.then(()=>pending.delete(promise),()=>pending.delete(promise));
  return promise;
 }
 async function settle(){
  const waits=[...pending.keys()];for(const controller of pending.values())controller.abort();
  let timer;try{await Promise.race([Promise.allSettled(waits),new Promise((_,reject)=>{timer=setTimeout(()=>reject(Error('Response wait cleanup deadline')),1000);})]);}finally{clearTimeout(timer);}
 }
 return {wait,settle};
}
async function qualifyFullBackendRenderedAuth({ browser, origin, admin, students, password, runId, foreignRunId, verifySession, platform }) {
  assert.equal(students.length, 2);
  const blocked = [], errors = [], contexts = [];
  const responseOwner=createResponseWaitOwner();let primaryFailure;
  const matches = (response, pathname) => new URL(response.url()).pathname === pathname;
  async function pageFor(user,{denied=false}={}) {
    const context = await browser.createBrowserContext();contexts.push(context);
    const page = await context.newPage();page.setDefaultTimeout(15000);
    page.on('pageerror', error => errors.push(error.message));await page.setRequestInterception(true);
    page.on('request', request => {
      const url = new URL(request.url());
      if (url.protocol === 'data:' || url.origin === origin) void request.continue();
      else { blocked.push(url.origin);void request.abort('blockedbyclient'); }
    });
    await page.setCacheEnabled(false);
    await page.goto(origin + '/workshop-login', { waitUntil: 'domcontentloaded' });
    await page.waitForSelector('input[placeholder="Enter your username"]', { visible: true });
    await page.waitForSelector('input[placeholder="Enter your password"]', { visible: true });
    await page.type('input[placeholder="Enter your username"]', user.username);
    await page.type('input[placeholder="Enter your password"]', password);
    const pending = responseOwner.wait(page,response => matches(response, '/api/auth/login') && response.request().method() === 'POST');
    await page.click('button[type="submit"]');const response = await pending;
    if(denied){assert.ok([401,403].includes(response.status()));const body=await response.json();assert.equal(body.token,undefined);return {page,denied:true};}
    assert.equal(response.status(), 200);const body = await response.json();
    assert.equal(Number(body.user.id), user.id);await verifySession(body.token, user.id);
    return { page, token: body.token };
  }
  async function api(page, pathname, token, method = 'GET') {
    return page.evaluate(async ({ pathname, token, method }) => {
      const response = await fetch(pathname, { method, headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' }, ...(method === 'POST' ? { body: '{}' } : {}) });
      return { status: response.status, body: await response.json() };
    }, { pathname, token, method });
  }
  try {
    const { page, token } = await pageFor(admin);
    const checks={R03:null,R06:null};
    if(platform)platform.record({stage:'R03_create'});
    if(platform){
      const subject={username:'crud-'+require('node:crypto').randomUUID(),email:require('node:crypto').randomUUID()+'@example.invalid',full_name:'Owned platform learner'};
      await page.goto(origin+'/admin/students',{waitUntil:'domcontentloaded'});
      await page.waitForFunction(()=>[...document.querySelectorAll('button')].some(b=>b.textContent.trim()==='Create New Student'));
      await exactButton(page,'Create New Student');
      for(const [placeholder,value]of [['Enter username',subject.username],['Enter email',subject.email],['Enter password',password],['Confirm password',password],['Enter full name',subject.full_name]])await page.type('input[placeholder="'+placeholder+'"]',value);
      const createdResponse=responseOwner.wait(page,r=>matches(r,'/api/admin/students')&&r.request().method()==='POST');
      await exactButton(page,'Create Student');const created=await createdResponse;assert.equal(created.status(),201);const createdBody=await created.json();assert.equal(createdBody.success,true);subject.id=Number(createdBody.user.id);assert.ok(Number.isSafeInteger(subject.id));
      const subjectView=await pageFor(subject);await platform.populate(subject.id);
      const levelOne=await pageFor(platform.levelOne);assert.equal((await api(levelOne.page,'/api/admin/students/'+subject.id,levelOne.token,'DELETE')).status,403);
      assert.equal((await api(subjectView.page,'/api/admin/users',subjectView.token)).status,403);
      platform.record({stage:'R03_edit',createdId:subject.id});
      await page.goto(origin+'/admin/students',{waitUntil:'domcontentloaded'});
      await page.waitForFunction(name=>[...document.querySelectorAll('tr')].some(row=>row.querySelector('td')?.textContent===name),{},subject.username);await exactButton(page,'Edit',subject.username);
      await page.waitForSelector('#is_active');
      const fullName=await page.evaluateHandle(()=>[...document.querySelectorAll('label')].find(l=>l.textContent.trim()==='Full Name')?.parentElement.querySelector('input'));
      assert(fullName.asElement());await replaceInput(fullName.asElement(),'Edited owned learner');await fullName.dispose();await page.click('#is_active');
      const updatedResponse=responseOwner.wait(page,r=>matches(r,'/api/admin/students/'+subject.id)&&r.request().method()==='PUT');await exactButton(page,'Update Student');assert.equal((await updatedResponse).status(),200);
      const edited=await api(page,'/api/admin/users/'+subject.id,token);assert.equal(edited.status,200);assert.equal(edited.body.user.full_name,'Edited owned learner');assert.equal(Number(edited.body.user.is_active),0);
      assert.ok([401,403].includes((await api(subjectView.page,'/api/agent-runs',subjectView.token)).status));await pageFor(subject,{denied:true});
      await page.goto(origin+'/admin/students',{waitUntil:'domcontentloaded'});await page.waitForFunction(name=>[...document.querySelectorAll('tr')].some(row=>row.querySelector('td')?.textContent===name),{},subject.username);await exactButton(page,'Edit',subject.username);await page.waitForSelector('#is_active');assert.equal(await page.$eval('#is_active',e=>e.checked),false);await page.click('#is_active');
      const enabledResponse=responseOwner.wait(page,r=>matches(r,'/api/admin/students/'+subject.id)&&r.request().method()==='PUT');await exactButton(page,'Update Student');assert.equal((await enabledResponse).status(),200);const activeSubject=await pageFor(subject);
      await platform.verifyPopulated(subject.id);
      platform.record({stage:'R03_delete',createdId:subject.id});
      await page.goto(origin+'/admin/students',{waitUntil:'domcontentloaded'});await page.waitForFunction(name=>[...document.querySelectorAll('tr')].some(row=>row.querySelector('td')?.textContent===name),{},subject.username);await exactButton(page,'Delete',subject.username);
      await page.type('#delete-confirmation','DELETE');const removedResponse=responseOwner.wait(page,r=>matches(r,'/api/admin/students/'+subject.id)&&r.request().method()==='DELETE');await exactButton(page,'Delete Student');const removed=await removedResponse;assert.equal(removed.status(),200);const deleted=await removed.json();assert.equal(deleted.success,true);assert.match(deleted.jobId,/^[a-f0-9-]{36}$/);
      assert.equal((await api(activeSubject.page,'/api/agent-runs',activeSubject.token)).status,401);const tombstone=await api(page,'/api/admin/users/'+subject.id,token);assert.equal(tombstone.status,200);assertDeletedIdentity(tombstone.body.user,{id:subject.id,jobId:deleted.jobId});
      await platform.verifyDeleted(subject.id,deleted.jobId);checks.R03={created:true,edited:true,inactiveDenied:true,reactivatedLogin:true,populatedDeletion:true,deletedSessionDenied:true,levelOneDenied:true,siblingPreserved:true};platform.record({stage:'R06_detail',checks});
    }
    const adminContext=page.browserContext();
    const readStudentView=createValidatedBrowserJsonCache(adminContext);
    const rosterPending = responseOwner.wait(page,response => matches(response, '/api/admin/users'));
    await page.goto(origin + '/admin/activity', { waitUntil: 'domcontentloaded' });
    const roster = await rosterPending;assert.equal(roster.status(), 200);
    const rosterBody = await roster.json();assert.equal(rosterBody.success, true);
    assert.ok(Number.isSafeInteger(rosterBody.pagination.pages) && rosterBody.pagination.pages >= 0);
    for (const student of students) {
      assert.ok(rosterBody.users.some(row => Number(row.id) === student.id));
      await page.waitForFunction(name => document.body.innerText.includes(name), {}, student.username);
    }
    for (const [index, student] of [students[0],students[1],students[0]].entries()) {
      const pending = responseOwner.wait(page,response => matches(response, `/api/admin/student-workshop-view/${student.id}`));
      if (index === 0) await page.goto(origin + `/admin/student-workshop-view?studentId=${student.id}`, { waitUntil:'domcontentloaded' });
      else await page.evaluate(id => {
        const heading=[...document.querySelectorAll('h2')].find(node=>node.textContent.includes('Student Workshop View'));
        const select=heading?.parentElement?.parentElement?.querySelector('select');
        if(!select)throw Error('Student selector unavailable');select.value=String(id);select.dispatchEvent(new Event('change',{bubbles:true}));
      },student.id);
      const response=await pending;
      const view=await readStudentView(response,{context:adminContext,expectedUrl:origin+`/api/admin/student-workshop-view/${student.id}`});
      assert.equal(Number(view.student.id),student.id);
      const expected=student.id===students[0].id?1:0;
      assert.equal(view.overview.completedChallenges,expected);
      await page.waitForFunction(({id,expected})=>{
        const heading=[...document.querySelectorAll('h2')].find(node=>node.textContent.includes('Student Workshop View'));
        const select=heading?.parentElement?.parentElement?.querySelector('select');
        const label=[...document.querySelectorAll('.label')].find(node=>node.textContent.trim()==='Completed');
        return select?.value===String(id)&&label?.parentElement?.querySelector('.value')?.textContent.trim()===String(expected);
      },{}, {id:student.id,expected});
    }
    const detail = responseOwner.wait(page,response => matches(response, `/api/admin/agent-runs/${runId}`));
    const list = responseOwner.wait(page,response => matches(response, '/api/admin/agent-runs'));
    await page.goto(origin + '/admin/agent-runs', { waitUntil: 'domcontentloaded' });assert.equal((await list).status(), 200);
    await page.waitForSelector('[aria-label="Administrator agent run inspector"]');
    await page.type('[aria-label="Owner ID"]', String(students[0].id));
    const row = await (await detail).json();assert.equal(row.run.runId, runId);
    if(platform)assertPopulatedRunDetail(row,{runId,ownerId:students[0].id,admin:true,privateMarker:platform.privateMarker});
    assert.ok(JSON.stringify(row.judgments).includes('Controlled persisted receipt'), 'controlled receipt must be projected');assert.equal(row.run.ownerId, String(students[0].id));
    await page.waitForFunction(id => document.body.innerText.includes(id), {}, runId);
    if(platform)await page.waitForFunction(populatedInspectorVisible,{}, {admin:true,runId,privateMarker:platform.privateMarker});
    const studentView = await pageFor(students[0]);
    const studentList = responseOwner.wait(studentView.page,response => matches(response, '/api/agent-runs'));
    await studentView.page.goto(origin + '/workshop/agent-runs', { waitUntil: 'domcontentloaded' });
    const owned = await (await studentList).json();assert.deepEqual(owned.runs.map(row => row.runId), [runId]);
    await studentView.page.waitForFunction(id => document.body.innerText.includes(id), {}, runId);
    if(platform){const detail=await api(studentView.page,'/api/agent-runs/'+runId,studentView.token);assert.equal(detail.status,200);assertPopulatedRunDetail(detail.body,{runId,ownerId:students[0].id,admin:false,privateMarker:platform.privateMarker});await studentView.page.waitForFunction(populatedInspectorVisible,{}, {admin:false,runId,privateMarker:platform.privateMarker});checks.R06={populatedAdminDetail:true,populatedLearnerDetail:true,privatePacketExcluded:true,foreignDenied:true};}
    assert.equal((await api(studentView.page, `/api/agent-runs/${foreignRunId}`, studentView.token)).status, 404);
    assert.equal((await api(studentView.page, '/api/admin/agent-runs', studentView.token)).status, 403);
    let ux;
    const siblingView=platform?await pageFor(students[1]):null;
    if(platform){
      platform.record({stage:'rendered_workshop_ux',checks});
      ux=await require('./fullBackendRenderedUx').qualifyRenderedWorkshopUx({
        origin,admin:{page,token},learner:studentView,sibling:siblingView,wait:responseOwner.wait,
      });
    }
    if(platform?.boundSessionOptions){
      const binding=async(view,user)=>({...view,id:user.id,cookie:(await view.page.cookies()).map(c=>c.name+'='+c.value).join('; ')});
      const receipt=await require('./fullBackendBoundSessionQualification').qualifyBoundSessions({origin,...platform.boundSessionOptions,owner:await binding(studentView,students[0]),sibling:await binding(siblingView,students[1])});
      checks.R02=receipt.checks;
    }else assert.equal((await api(studentView.page, '/api/auth/logout', studentView.token, 'POST')).status, 200);
    assert.equal((await api(studentView.page, '/api/agent-runs', studentView.token)).status, 401);
    assert.deepEqual(blocked, []);assert.deepEqual(errors, []);
    const receipt={scope:'rendered_full_backend_auth_projection',passed:true,...(platform?{checks,ux,actualModelProof:false}: {})};if(platform)platform.record({stage:'complete',...receipt});return receipt;
  } catch(error){primaryFailure=error;throw error;} finally {
    let timer;
    const closing=Promise.race([Promise.all(contexts.map(context=>Promise.resolve().then(()=>context.close()))),
      new Promise((_,reject)=>{timer=setTimeout(()=>reject(Error('Browser context cleanup deadline')),10000);})]);
    const settled=await Promise.allSettled([responseOwner.settle(),closing]).finally(()=>clearTimeout(timer));
    const failures=settled.filter(row=>row.status==='rejected').map(row=>row.reason);if(failures.length)throw new AggregateError([...(primaryFailure?[primaryFailure]:[]),...failures],'Platform browser cleanup incomplete');
  }
}
module.exports = { qualifyFullBackendRenderedAuth, assertPopulatedRunDetail, assertDeletedIdentity, populatedInspectorVisible, createResponseWaitOwner, exactButton, replaceInput };
