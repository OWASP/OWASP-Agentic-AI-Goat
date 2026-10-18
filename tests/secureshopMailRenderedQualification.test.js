'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {assertProjection,exerciseProjection,createFlow}=require('./fixtures/secureshopMailRenderedQualification');
test('mail rendered entry signs in on the standalone page before entering the owned merchant iframe',async()=>{
 const {enterMerchantInbox}=require('./fixtures/secureshopMailRenderedQualification');
 const events=[],origin='http://127.0.0.1:12345';
 const frame={async waitForSelector(selector){assert.equal(selector,'a[href="/secureshop/merchant/inbox"]');events.push('inbox-link');},async click(selector){assert.equal(selector,'a[href="/secureshop/merchant/inbox"]');events.push('inbox-click');}};
 const element={async contentFrame(){events.push('frame-content');return frame;}};
 const page={async goto(url,options){assert.equal(url,origin+'/secureshop/login');assert.deepEqual(options,{waitUntil:'domcontentloaded'});events.push('shop-login-route');},async waitForSelector(selector){assert(['#ss-login-user','iframe[title="SecureShop"]'].includes(selector));events.push(selector);return selector.startsWith('iframe')?element:{};},async type(selector,value){assert.deepEqual([selector,value],selector==='#ss-login-user'?['#ss-login-user','student_merchant']:['#ss-login-pw','student123']);events.push(selector+'-typed');},async click(selector){assert.equal(selector,'button[type="submit"]');events.push('shop-login-submit');}};
 const stages=[];assert.equal(await enterMerchantInbox({page,origin,ui:work=>work(),stage:value=>stages.push(value)}),frame);
 assert.deepEqual(stages,['standalone-shop-login','bound-merchant-frame']);
 assert.deepEqual(events,['shop-login-route','#ss-login-user','#ss-login-user-typed','#ss-login-pw-typed','shop-login-submit','iframe[title="SecureShop"]','frame-content','inbox-link','inbox-click']);
});
test('registered merchant physically sends exact saved mail then checks its browser effect',async()=>{
 const {EventEmitter}=require('node:events');
 const {sendRegisteredStoredBrowserMessage}=require('./fixtures/secureshopMailRenderedQualification');
 const page=new EventEmitter(),actions=[],requests=[],responses=[];
 const input={subject:'Owned subject',body_markdown:'<img src=x onerror="alert(1)">'};
 const sendBody={requestId:'11111111-1111-4111-8111-111111111111',from:'merchant@example.invalid',
  to:'customer@example.invalid',...input};
 const assessmentBody={requestId:'22222222-2222-4222-8222-222222222222',
  sendOperationId:sendBody.requestId,messageId:7};
 page.waitForResponse=(predicate,{signal})=>new Promise((resolve,reject)=>{
  const listener=response=>{if(predicate(response)){page.off('response',listener);resolve(response);}};
  page.on('response',listener);signal.addEventListener('abort',()=>{page.off('response',listener);
   reject(Object.assign(Error('aborted'),{name:'AbortError'}));},{once:true});});
 const field=()=>{let value='prior',selected=false;const element={get value(){return value;},
  select(){selected=true;}};return {async focus(){},async evaluate(fn){return fn(element);},
  async press(){if(selected)value='';},async type(text){value+=text;}};};
 const fields=[field(),field(),field()];
 const reply=(path,body,status=200)=>({url:()=>`http://127.0.0.1:1${path}`,
  request:()=>({method:()=> 'POST'}),status:()=>status,json:async()=>body});
 const dispatch=(path,body,value)=>{const request={url:()=>`http://127.0.0.1:1${path}`,
  postData:()=>JSON.stringify(body)};requests.push(body);page.emit('request',request);
  queueMicrotask(()=>page.emit('response',reply(path,value)));};
 const frame={async waitForFunction(){},async waitForSelector(selector){assert.equal(selector,'[role="dialog"]');},
  async $$(selector){assert.equal(selector,'[role="dialog"] input');return fields;},
  async type(selector,value){assert.equal(selector,'[role="dialog"] textarea');
   assert.equal(value,input.body_markdown);actions.push('body');},
  async evaluate(_fn,label){actions.push(label);if(label==='Send'){
   assert.deepEqual(actions,['Compose','body','Send']);
   assert.deepEqual(await Promise.all(fields.map(x=>x.evaluate(element=>element.value))),
    [sendBody.to,sendBody.from,input.subject]);
   dispatch('/api/secureshop/email/send',sendBody,{email_id:7});
  }else if(label==='Check saved message execution'){
   dispatch('/api/secureshop/email/browser-assessment',assessmentBody,
    {completed:true,judgment:{verdict:'pass',evaluationId:'33333333-3333-4333-8333-333333333333'}});
  }} };
 const result=await sendRegisteredStoredBrowserMessage({page,frame,input,
  from:sendBody.from,to:sendBody.to});
 assert.deepEqual(requests,[sendBody,assessmentBody]);
 assert.equal(result.assessment.completed,true);assert.equal(result.assessmentRequest.messageId,7);
});
test('Audit challenge-card time oracle follows rendered zero, subminute and hour formatting',()=>{
 const {challengeCardTimeText}=require('./fixtures/secureshopMailRenderedQualification');
 assert.equal(challengeCardTimeText(0),null);
 assert.equal(challengeCardTimeText(47),'< 1m');
 assert.equal(challengeCardTimeText(60),'1m');
 assert.equal(challengeCardTimeText(3661),'1h 1m');
 assert.throws(()=>challengeCardTimeText(-1));
});
test('rendered SecureShop reentry propagates each bearer and admits only the committed reset generation',async()=>{
 const {enterOwnedSecureShop,nextResetGeneration}=require('./fixtures/secureshopMailRenderedQualification');
 const origin='http://127.0.0.1:12345',launchId='123e4567-e89b-42d3-a456-426614174003';
 const admittedSession={launchId,generation:1},headers={};let navigations=0;
 const page={async goto(url,options){assert.equal(url,origin+'/workshop/secureshop');assert.equal(options.waitUntil,'domcontentloaded');navigations++;}};
 const responses=[{bearer:'first-owned-bearer',generation:1},{bearer:'second-owned-bearer',generation:1},{bearer:'post-reset-bearer',generation:2}].map(value=>({status:()=>200,json:async()=>({launch:{launchId,generation:value.generation},bearer:value.bearer})}));
 const waitResponse=(_page,predicate)=>{assert(predicate({url:()=>origin+'/api/auth/secureshop-launch/recover',request:()=>({method:()=> 'POST'})}));return Promise.resolve(responses.shift());};
 const enter=generation=>enterOwnedSecureShop({page,origin,ui:work=>work(),waitResponse,admittedSession:{...admittedSession,generation},onLaunchCredential:credential=>{headers['x-dvaia-secureshop-launch']=credential.bearer;}});
 await enter(1);assert.equal(headers['x-dvaia-secureshop-launch'],'first-owned-bearer');
 await enter(1);assert.equal(navigations,2);assert.equal(headers['x-dvaia-secureshop-launch'],'second-owned-bearer');
 const reset={status:'committed',fromGeneration:1,toGeneration:2};assert.equal(nextResetGeneration(1,reset),2);
 assert.throws(()=>nextResetGeneration(1,{...reset,toGeneration:3}));assert.throws(()=>nextResetGeneration(1,{...reset,status:'pending'}));
 await enter(nextResetGeneration(1,reset));assert.equal(navigations,3);assert.equal(headers['x-dvaia-secureshop-launch'],'post-reset-bearer');
});
const row=()=>({workshopKey:'secureshop_agent_security',name:'Owned shop',objectiveCount:2,completedObjectiveCount:1,timeSpentSeconds:47,objectives:[{id:'ss_mail_stored_browser_execution',completed:true,hintVisible:true,solutionVisible:false,text:'Saved mail'},{id:'other',completed:false}],exerciseGroups:[{objectives:[{id:'ss_mail_stored_browser_execution',completed:true,hintVisible:true,solutionVisible:false,text:'Saved mail'},{id:'other',completed:false}]}]});
test('mail projection requires exact canonical objective outcome and independent gates',()=>{const r=row();assert.deepEqual(assertProjection([r],true),{title:'Saved mail',completed:true,total:2,done:1,hintVisible:true,solutionVisible:false});assert.throws(()=>assertProjection([r],false));assert.deepEqual(exerciseProjection([r]),{name:'Owned shop',done:1,total:2,time:47,hints:1,solutions:0});r.exerciseGroups[0].objectives.shift();assert.throws(()=>assertProjection([r],true));});
test('rendered construction failure closes its owned context before propagating',async()=>{let closed=0;const original=Error('controlled navigation failure');const page={async setCacheEnabled(){},async setViewport(){},async setRequestInterception(){},on(){},async goto(){throw original;}};const browser={async createBrowserContext(){return {async newPage(){return page;},async close(){closed++;}};}};await assert.rejects(createFlow({browser,origin:'http://127.0.0.1:1',username:'owned',password:'synthetic'}),e=>e===original);assert.equal(closed,1);});
test('construction failure retains bounded private login evidence before context cleanup',async()=>{
 const fs=require('node:fs'),os=require('node:os'),path=require('node:path');
 const evidence=fs.mkdtempSync(path.join(os.tmpdir(),'mail-rendered-construction-'));
 let closed=0;const original=Error('controlled navigation failure');const page={async setCacheEnabled(){},async setViewport(){},async setRequestInterception(){},on(){},async goto(){throw original;},async evaluate(){return {path:'/workshop-login',shopLogin:false,boundFrames:0,guestFrames:0,alerts:0};},async screenshot(){return Buffer.from('private pixels');}};
 const browser={async createBrowserContext(){return {async newPage(){return page;},async close(){closed++;}};}};
 try{await assert.rejects(createFlow({browser,origin:'http://127.0.0.1:1',username:'owned',password:'synthetic',evidence}),error=>error===original);assert.equal(closed,1);
  const file=path.join(evidence,'rendered-construction-failure.json'),value=JSON.parse(fs.readFileSync(file,'utf8'));
  assert.deepEqual(value.dom,{path:'/workshop-login',shopLogin:false,boundFrames:0,guestFrames:0,alerts:0});assert.deepEqual(value.http,[]);assert.equal(value.failure.name,'Error');assert.equal(fs.statSync(file).mode&0o777,0o600);assert.equal(fs.statSync(path.join(evidence,'rendered-construction-failure.png')).mode&0o777,0o600);
 }finally{fs.rmSync(evidence,{recursive:true,force:true});}
});
test('rendered count/time/gate values reject substring collisions',()=>{const {assertProjectionTexts}=require('./fixtures/secureshopMailRenderedQualification');const a={done:1,total:6,time:45,hints:1,solutions:1};assertProjectionTexts([' 1/6 ','45s'],a,'dashboard');assertProjectionTexts(['1/6 objectives','45s','Hints: 1','Solutions: 1'],a,'instructor');for(const values of [['11/6','45s'],['1/60','45s'],['1/6','145s']])assert.throws(()=>assertProjectionTexts(values,a,'dashboard'));for(const [index,value]of [[0,'11/6 objectives'],[0,'1/60 objectives'],[1,'145s'],[2,'Hints: 11'],[3,'Solutions: 11']]){const values=['1/6 objectives','45s','Hints: 1','Solutions: 1'];values[index]=value;assert.throws(()=>assertProjectionTexts(values,a,'instructor'));}});
test('dashboard zero-time requires absent time element; instructor shows exact zero',()=>{const {assertProjectionTexts}=require('./fixtures/secureshopMailRenderedQualification');const a={done:0,total:6,time:0,hints:0,solutions:0};assertProjectionTexts(['0/6',null],a,'dashboard');for(const time of ['', '0s','10s'])assert.throws(()=>assertProjectionTexts(['0/6',time],a,'dashboard'));assertProjectionTexts(['0/6 objectives','0s','Hints: 0','Solutions: 0'],a,'instructor');});
test('failure diagnostics retain source locations but never assertion values or messages',()=>{const {failureDiagnostic}=require('./fixtures/secureshopMailRenderedQualification');const result=failureDiagnostic({name:'AssertionError',code:'ERR_ASSERTION',message:'private credential',stack:'AssertionError: private credential\n at work (/main/tests/fixtures/example.js:12:3)\n at internal (node:internal:1:2)'});assert.deepEqual(result,{name:'AssertionError',code:'ERR_ASSERTION',frames:['tests/fixtures/example.js:12:3']});assert(!JSON.stringify(result).includes('credential'));});
test('cleanup stages await client closure before physical owner and retain failures',async()=>{const {settleStages}=require('./fixtures/secureshopMailRenderedQualification');const order=[];const results=await settleStages([[['context',async()=>{await Promise.resolve();order.push('context');throw Error('controlled');}]],[['qualifier',async()=>{assert.deepEqual(order,['context']);order.push('qualifier');}]],[['transport',async()=>{order.push('transport');}]],[['browser',async()=>{assert.deepEqual(order,['context','qualifier','transport']);order.push('browser');}]]]);assert.equal(results.find(x=>x.name==='context').status,'rejected');assert.equal(results.find(x=>x.name==='browser').status,'fulfilled');});

test('send failure projection preserves closed route codes without arbitrary response text',()=>{const {responseDiagnostic}=require('./fixtures/secureshopMailRenderedQualification');assert.deepEqual(responseDiagnostic({code:'TURN_RECOVERY_REQUIRED',error:'Bound mail unavailable',terminalRejected:true}),{code:'TURN_RECOVERY_REQUIRED',errorCategory:'BOUND_MAIL_UNAVAILABLE',terminalRejected:true});assert.deepEqual(responseDiagnostic({code:'private-token',error:'private-password',detail:'secret'}),{code:null,errorCategory:null,terminalRejected:false});});

test('field replacement selects the whole prior value and verifies exact final value',async()=>{const {replaceField}=require('./fixtures/secureshopMailRenderedQualification');let value='prefilled',selected=false;const element={get value(){return value;},select(){selected=true;}};const field={async focus(){},async evaluate(fn){return fn(element);},async press(){if(selected)value='';},async type(text){value+=text;}};await replaceField(field,'frozen');assert.equal(value,'frozen');selected=false;field.press=async()=>{};await assert.rejects(replaceField(field,'frozen'));});
test('application observer preserves genuine result and original failure without private details',async()=>{const {observeApplication}=require('./fixtures/secureshopMailRenderedQualification');const error=Object.assign(Error('secret'),{code:'42501'}),observations=[];const wrapped=observeApplication({async read(){throw error;},async send(value){return value;}},x=>observations.push(x));assert.equal(await wrapped.send(3),3);await assert.rejects(wrapped.read(),e=>e===error);assert.equal(observations[0].code,'42501');assert(!JSON.stringify(observations).includes('secret'));});

test('browser learner preparation creates only credentials; UI owns session and launch allocation',async()=>{const {createLearner}=require('./fixtures/secureshopMailRenderedQualification');let created=0;const users={async createUser(input){created++;return {id:7,username:input.username};},createSession(){throw Error('Premature session');}};const learner=await createLearner({users,hashPassword:async()=> 'synthetic-hash',key:'12345678-owned'});assert.equal(created,1);assert.equal(learner.user.id,7);assert.equal(learner.credentials.username,'mail-12345678');assert.equal(learner.scope,undefined);assert.equal(learner.targetId,undefined);});

test('fixture readiness enables only target release gate while retaining real catalog and transport gates',async()=>{const {qualificationReadinessForFixture}=require('./fixtures/secureshopMailRenderedQualification');const real=require('../server/services/secureshopMailObjectiveReadiness');const target='ss_mail_stored_browser_execution';let reads=0;const wrapped=qualificationReadinessForFixture({...real,readMailObjectiveCatalog:async pool=>{reads++;return pool.catalog;}});const qualified=await wrapped.readMailObjectiveReadiness({identityPool:{catalog:{[target]:true}},transportReady:true,judgeReady:true});assert.equal(qualified[target],true);assert.equal(qualified.ss_mail_reply_redirect,false);assert.equal(real.MAIL_OBJECTIVE_QUALIFICATION[target],true);for(const options of [{catalog:{},transportReady:true,judgeReady:true},{catalog:{[target]:true},transportReady:false,judgeReady:true},{catalog:{[target]:true},transportReady:true,judgeReady:false}]){const {catalog,...dependencies}=options;assert.equal((await wrapped.readMailObjectiveReadiness({identityPool:{catalog},...dependencies}))[target],false);}assert.equal(reads,4);});

test('response wait rejects safely before consumption and joins on early primary failure',async()=>{const {ownedResponseWait}=require('./fixtures/secureshopMailRenderedQualification');let reject,aborted=false;const wait=ownedResponseWait({waitForResponse(predicate,{signal}){signal.addEventListener('abort',()=>{aborted=true;reject(Error('Page closed'));});return new Promise((resolve,no)=>{reject=no;});}},()=>true,100000);const primary=Error('Button absent');await assert.rejects((async()=>{try{throw primary;}finally{await wait.close();}})(),e=>e===primary);assert.equal(aborted,true);await assert.rejects(wait.promise,/Page closed/);});

test('real identity permission repository admits instructor object contract and rejects positional call',async()=>{const {createIdentityRepository}=require('../server/database/postgres/identityRepository');const calls=[];const repository=createIdentityRepository({async query(sql,args){calls.push({sql,args});return {rows:[{id:1}]};}});await repository.grantPermission({userId:7,permission:'manage_progress',grantedBy:7});assert.deepEqual(calls[0].args,[7,'manage_progress',7,null]);await assert.rejects(repository.grantPermission(7,'manage_progress',7),/Unknown identity permission/);assert.equal(calls.length,1);});

test('instructor selection waits for exact populated option and rejects empty selection',async()=>{const {selectStudentOption}=require('./fixtures/secureshopMailRenderedQualification');let ready=false;const page={async waitForSelector(selector){assert.equal(selector,'select option[value="7"]');ready=true;},async select(selector,value){assert(ready);assert.equal(selector,'select');return [value];}};await selectStudentOption(page,7);page.select=async()=>[];await assert.rejects(selectStudentOption(page,7),/Exact instructor student selection/);});

test('genuine persona session projection preserves authority and satisfies actual mail normalization',()=>{const {boundPersonaSession}=require('./fixtures/secureshopMailRenderedQualification');const {normalize}=require('../server/database/postgres/secureshopBoundMailRepository');const id='12345678-1234-4234-8234-123456789abc',raw={sessionId:id,authorityVersion:'2',expiresAt:'private-expiry'},personaSession=boundPersonaSession(raw);assert.deepEqual(personaSession,{sessionId:id,authorityVersion:'2'});const binding={scope:{launchId:id,scenarioId:id,generation:1,platformOwnerId:1,platformSessionId:2},targetId:id,operationId:id,persona:{id:3,role:'merchant'},mode:'fixed',personaSession};assert.deepEqual(normalize(binding).personaSession,personaSession);assert.throws(()=>normalize({...binding,personaSession:raw}));for(const value of [{},{sessionId:id},{sessionId:'bad',authorityVersion:'2'},{sessionId:id,authorityVersion:'0'}])assert.throws(()=>boundPersonaSession(value));});

test('content modal oracle scopes exact hints and authored solution examples to one dialog',()=>{
 const {contentModalMatches,contentCardMatches}=require('./fixtures/secureshopMailRenderedQualification');const previous=global.document;
 try{let text='Title First Second';global.document={querySelectorAll:()=>[{get textContent(){return text;}}]};assert(contentModalMatches({kind:'hint',value:{title:'Title',hints:['First','Second']}}));text='Title First';assert.equal(contentModalMatches({kind:'hint',value:{title:'Title',hints:['First','Second']}}),false);text='Solution Do exact action Explained';assert(contentModalMatches({kind:'solution',value:{title:'Solution',examples:[{action:'Do exact action',explanation:'Explained'}]}}));global.document={querySelectorAll:()=>[]};assert.equal(contentModalMatches({kind:'solution',value:{title:'Solution',examples:[]}}),false);
 let buttons=[{textContent:'Hint'}];global.document={querySelectorAll:()=>[{textContent:'Canonical',parentElement:{querySelectorAll:()=>buttons}}]};assert(contentCardMatches({label:'Canonical',hint:true,solution:false}));assert.equal(contentCardMatches({label:'Canonical',hint:true,solution:true}),false);assert.equal(contentCardMatches({label:'Wrong',hint:true,solution:false}),false);
 }finally{global.document=previous;}
});

test('content instructor assertion consumes actual flat admin projection and canonical label',()=>{
 const {projectAdminWorkshopView}=require('../server/services/adminWorkshopView');const {assertAdminContentProjection}=require('./fixtures/secureshopMailRenderedQualification');
 const input={workshopKey:'secureshop_agent_security',name:'SecureShop Agent Security',objectiveCount:1,completedObjectiveCount:0,timeSpentSeconds:0,objectives:[{id:'ss_mail_stored_browser_execution',label:'Canonical label',text:'Fallback text',completed:false,hintVisible:false,solutionVisible:true}]};
 const body=projectAdminWorkshopView({id:7},[input]);assert.equal(body.challenges[0].exerciseGroups,undefined);assert.deepEqual(assertAdminContentProjection(body,7),{title:'Canonical label',hintVisible:false,solutionVisible:true});assert.throws(()=>assertAdminContentProjection(body,8));assert.throws(()=>assertAdminContentProjection(projectAdminWorkshopView({id:7},[{...input,objectives:[]}]),7));
});

test('content traffic diagnostics bound path cardinality and preserve first budget denial stage',()=>{
 const {createContentTraffic}=require('./fixtures/secureshopMailRenderedQualification');const traffic=createContentTraffic();
 traffic.stage('content-label');traffic.request('/api/admin/student-workshop-view/7?token=private',false);traffic.request('/api/admin/student-workshop-view/8',false);
 traffic.stage('content-admin-selection');traffic.request('/api/auth/status',true);traffic.stage('later');traffic.request('/api/auth/status',true);
 for(let i=0;i<70;i++){traffic.request('/api/route-'+i,false);traffic.stage('stage-'+i);}
 const value=traffic.snapshot();assert.equal(Object.keys(value.paths).length,64);assert.equal(value.paths['/api/admin/student-workshop-view/:id'],2);assert.equal(value.overflow,8);assert.equal(value.total,74);assert.equal(value.denied,2);assert.equal(value.firstDeniedStage,'content-admin-selection');assert.equal(value.stages.length,64);assert.deepEqual(value.stages[1],{stage:'content-admin-selection',total:2,denied:0});assert(!JSON.stringify(value).includes('private'));value.paths.extra=1;assert.equal(traffic.snapshot().paths.extra,undefined);
});

test('content-only aggregate budget admits exact boundary and denies overflow or malformed counts',()=>{const {CONTENT_API_REQUEST_LIMIT,contentRequestAllowed}=require('./fixtures/secureshopMailRenderedQualification');assert.equal(CONTENT_API_REQUEST_LIMIT,1024);assert(contentRequestAllowed(1));assert(contentRequestAllowed(1024));for(const n of [0,-1,1025,1.5,NaN,'1024'])assert.equal(contentRequestAllowed(n),false);});

test('actual instructor flat projection retains completion totals and rejects foreign or duplicate objectives',()=>{
 const {projectAdminWorkshopView}=require('../server/services/adminWorkshopView');const {assertActualAdminProjection,actualRequestsAllowed,ACTUAL_API_LIMIT}=require('./fixtures/secureshopMailRenderedQualification');
 for(const completed of [false,true]){const objective={id:'ss_mail_stored_browser_execution',label:'Canonical',text:'Other',completed,hintVisible:false,solutionVisible:true};const row={workshopKey:'secureshop_agent_security',objectives:[objective]};const body=projectAdminWorkshopView({id:7},[row]);assert.deepEqual(assertActualAdminProjection(body,7,completed),{title:'Canonical',completed,total:1,done:Number(completed),hintVisible:false,solutionVisible:true});assert.throws(()=>assertActualAdminProjection(body,8,completed));assert.throws(()=>assertActualAdminProjection(body,7,!completed));for(const objectives of [[],[objective,objective]])assert.throws(()=>assertActualAdminProjection(projectAdminWorkshopView({id:7},[{...row,objectives}]),7,completed));}
 assert.equal(ACTUAL_API_LIMIT,512);assert(actualRequestsAllowed(512,20));for(const counts of [[513,20],[512,21],[1.5,0],[2,-1]])assert.equal(actualRequestsAllowed(...counts),false);
});


test('Listings content selection and projections bind four exact canonical objectives',()=>{
 const {LISTINGS_CONTENT_IDS,assertAdminContentProjection,contentModalMatches}=require('./fixtures/secureshopMailRenderedQualification');
 assert.deepEqual(LISTINGS_CONTENT_IDS,['ss_listing_internal_fetch','ss_listing_external_entity','ss_listing_prototype_mutation','ss_listing_generated_browser_execution']);assert(Object.isFrozen(LISTINGS_CONTENT_IDS));
 for(const id of LISTINGS_CONTENT_IDS){const r=row();r.objectives[0].id=id;r.exerciseGroups[0].objectives[0].id=id;r.objectives[0].completed=false;r.exerciseGroups[0].objectives[0].completed=false;assert.equal(assertProjection([r],false,id).title,'Saved mail');assert.equal(assertAdminContentProjection({student:{id:1},challenges:[r]},1,id).hintVisible,true);assert.throws(()=>assertProjection([r],false,'wrong'));}
 const old=global.document;try{const dialog={textContent:'Title Approach Action Explanation'};global.document={querySelectorAll:()=>[dialog]};const value={title:'Title',approach:'Approach',examples:[{action:'Action',explanation:'Explanation'}]};assert(contentModalMatches({kind:'solution',value}));dialog.textContent='Title Approach Action';assert.equal(contentModalMatches({kind:'solution',value}),false);}finally{if(old===undefined)delete global.document;else global.document=old;}
});


test('Listings gate observations reuse mounted learner and instructor revision consumers',()=>{
 const source=require('node:fs').readFileSync(require.resolve('./fixtures/secureshopMailRenderedQualification'),'utf8');
 assert(source.includes("if(profile==='content-only'||!learnerMounted)"));assert(source.includes("const navigating=profile==='content-only'||!adminMounted"));assert(source.includes("if(navigating){await admin.goto"));assert(source.includes('if(!await admin.$eval'));assert(source.includes('result.learnerDiagnostic'));
});

test('loop content binds its own canonical row and rejects mail or uncompleted projections',()=>{
 const r=row();r.objectives[0].id='ss_loop_observation';r.exerciseGroups[0].objectives[0].id='ss_loop_observation';
 assert.equal(assertProjection([r],true,'ss_loop_observation').completed,true);
 assert.throws(()=>assertProjection([r],true,'ss_mail_stored_browser_execution'));
 assert.throws(()=>assertProjection([r],false,'ss_loop_observation'));
});

test('controlled loop effect joins exact purpose owner session run generation and tool receipt',()=>{
 const {assertLoopEffectBinding}=require('./fixtures/secureshopMailRenderedQualification');
 const value={ownerId:7,session:{id:'s',original_platform_owner_id:7,conversation_purpose:'review_moderation',platform_launch_id:'l',platform_launch_generation:'2'},run:{run_id:'r',owner_key:'o',generation:'3'},effect:{run_id:'r',owner_key:'o',generation:'3',effect_key:'e',status:'completed'},packet:{sessionId:'s',binding:{platformOwnerId:7,launchId:'l',generation:2},run:{runId:'r'},observation:{tool:'review-moderator.moderate_pending',args:{limit:1},effectReceipt:{runId:'r',ownerKey:'o',generation:3,effectKey:'e',status:'completed'}}}};
 assertLoopEffectBinding(value);
 for(const mutate of [v=>v.session.conversation_purpose='general',v=>v.packet.binding.platformOwnerId=8,v=>v.packet.sessionId='other',v=>v.packet.observation.tool='review-moderator.approve',v=>v.effect.generation='2',v=>v.effect.effect_key='other',v=>v.packet.observation.effectReceipt=null]){const bad=structuredClone(value);mutate(bad);assert.throws(()=>assertLoopEffectBinding(bad));}
});

test('loop instructor completed projection requires exact aggregate time and completion text',()=>{
 const {loopInstructorProjectionMatches}=require('./fixtures/secureshopMailRenderedQualification');const old=global.document;let values=['1/1 objectives','1m','Hints: 1','Solutions: 1'];
 const aggregate={tagName:'DIV',querySelectorAll:()=>values.map(textContent=>({textContent}))};const card={children:[aggregate]};const row={closest:()=>({parentElement:card}),querySelector:s=>({textContent:s==='.level-name'?'Canonical loop':'Completed'})};
 try{global.document={querySelector:()=>row};const expected={id:'ss_loop_observation',label:'Canonical loop',expected:values.slice()};assert(loopInstructorProjectionMatches(expected));values[1]='0s';assert.equal(loopInstructorProjectionMatches(expected),false);global.document={querySelector:()=>null};assert.equal(loopInstructorProjectionMatches(expected),false);}finally{global.document=old;}
});


test('controlled loop fixture satisfies the actual review runtime constructor without resources',()=>{
 const {createLoopLifecycleRuntime}=require('./fixtures/secureshopMailRenderedQualification');
 const unused=async()=>{throw Error('Constructor must not access resources');};
 const methods=names=>Object.fromEntries(names.split(' ').map(name=>[name,unused]));
 const runtime=createLoopLifecycleRuntime({
  launches:methods('assertCurrent resolveCapability reserveReviewsTarget'),
  lifecycle:{reviews:methods('provision listReviews submitReview listPending readDecisionReceipt decide'),
   conversations:methods('acquireBoundSession getBoundSession getMessages appendMessage getTokens addTokens appendTraces'),
   journal:methods('lookupGeneralRequest claim complete markUncertain'),
   runCoordinator:methods('reset run')},
  authority:methods('capture'),auth:methods('authenticatePersona')});
 assert.equal(typeof runtime.router,'function');assert.equal(typeof runtime.runner.run,'function');
 assert.equal(runtime.controlledCalls(),0);assert.deepEqual(runtime.observations(),[]);
});


test('loop projection consumes effective JSON after conditional304 and rejects authorization or stale-body substitutes',async()=>{
 const {consumeLoopProjectionResponse}=require('./fixtures/secureshopMailRenderedQualification');const body={challenges:[{done:1}]},diagnostics=[];let reads=0;
 const page={async evaluate(fn){reads++;assert.match(String(fn),/cache:'no-store'/);return {status:200,body};}};
 assert.deepEqual(await consumeLoopProjectionResponse(page,{status:()=>200,json:async()=>body},'/workshop-dashboard',d=>diagnostics.push(d)),body);assert.equal(reads,0);
 assert.deepEqual(await consumeLoopProjectionResponse(page,{status:()=>304,json:()=>{throw Error('304 has no JSON');}},'/workshop/progress',d=>diagnostics.push(d)),body);assert.equal(reads,1);assert.deepEqual(diagnostics.at(-1),{route:'/workshop/progress',status:304,effectiveStatus:200});
 await assert.rejects(consumeLoopProjectionResponse(page,{status:()=>401},'/workshop-dashboard'));
 await assert.rejects(consumeLoopProjectionResponse({evaluate:async()=>({status:403,body:{}})},{status:()=>304},'/workshop-dashboard'));
});


test('Audit SQL content requires its exact canonical objective and independent completed projection',()=>{
 const value=row();value.exerciseGroups[0].objectives=[{id:'ss_audit_sql_extraction',text:'Audit exact canary',completed:true,hintVisible:true,solutionVisible:false}];
 assert.deepEqual(assertProjection([value],true,'ss_audit_sql_extraction'),{title:'Audit exact canary',completed:true,total:1,done:1,hintVisible:true,solutionVisible:false});
 assert.throws(()=>assertProjection([value],true,'ss_loop_observation'));assert.throws(()=>assertProjection([value],false,'ss_audit_sql_extraction'));
});


test('review persistence projection does not conflate followed-instruction credit',()=>{
 const value=row();value.exerciseGroups[0].objectives=[{id:'ss_content_persist',text:'Persist and retrieve',completed:true,hintVisible:false,solutionVisible:true}];
 assert.deepEqual(assertProjection([value],true,'ss_content_persist'),{title:'Persist and retrieve',completed:true,total:1,done:1,hintVisible:false,solutionVisible:true});
 assert.throws(()=>assertProjection([value],true,'ss_content_followed'));assert.throws(()=>assertProjection([value],false,'ss_content_persist'));
});

test('pricing disclosure projection remains exact and excludes other Pricing objectives',()=>{
 const value=row();value.exerciseGroups[0].objectives=[{id:'ss_pricing_competitor_disclosure',text:'Competitor disclosure',completed:true,hintVisible:false,solutionVisible:true}];
 assert.equal(assertProjection([value],true,'ss_pricing_competitor_disclosure').done,1);
 assert.throws(()=>assertProjection([value],true,'ss_pricing_false_grounding'));
 assert.throws(()=>assertProjection([value],true,'ss_pricing_manual_injection'));
});

test('stored review projection cannot be substituted by saved-mail completion',()=>{
 const value=row();value.exerciseGroups[0].objectives=[{id:'ss_stored_browser_execution',text:'Stored review',completed:true,hintVisible:true,solutionVisible:false}];
 assert.equal(assertProjection([value],true,'ss_stored_browser_execution').done,1);
 assert.throws(()=>assertProjection([value],true,'ss_mail_stored_browser_execution'));
});

test('stored lifecycle composes actual review and browser routers without opening resources',async()=>{
 const renderer=require('../server/services/secureshopReviewCardRenderer'),bootstrap=require('../server/services/secureshopGradingBootstrap');
 const savedRenderer=renderer.loadSecureShopReviewCardRenderer,savedBootstrap=bootstrap.createSecureShopGradingBootstrap;
 const unused=async()=>{throw Error('No resource operation expected');};const methods=names=>Object.fromEntries(names.split(' ').map(name=>[name,unused]));
 const progress=methods('getGeneration getMode beginAttempt');
 renderer.loadSecureShopReviewCardRenderer=()=>({sourceSha256:'a'.repeat(64),artifactSha256:'b'.repeat(64),renderReviewCard:unused});
 bootstrap.createSecureShopGradingBootstrap=async()=>({assessmentDependencies:{receipts:methods('beginEvaluation recordVerdict'),progress}});
 try{
  const runtime=await require('./fixtures/secureshopMailRenderedQualification').createStoredBrowserLifecycleRuntime({
   identity:{query:async()=>({rows:[{name:'owned_identity'}]})},agents:{query:async()=>({rows:[{name:'owned_agents'}]})},progress,
   launches:methods('assertCurrent resolveCapability reserveReviewsTarget readExistingReviewsTarget'),
   lifecycle:{reviews:methods('provision listReviews submitReview listPending readDecisionReceipt decide readSubmission'),conversations:methods('acquireBoundSession getBoundSession getMessages appendMessage getTokens addTokens appendTraces'),journal:methods('lookupGeneralRequest claim complete markUncertain'),runCoordinator:methods('reset run')},
   authority:methods('capture'),auth:methods('authenticatePersona'),getBrowser:()=>{throw Error('No browser allocation');}});
  assert.equal(typeof runtime.router,'function');assert.equal(typeof runtime.browserRouter,'function');assert.deepEqual(runtime.counts(),{browserCalls:0,controlledJudgeCalls:0});await runtime.close();
 }finally{renderer.loadSecureShopReviewCardRenderer=savedRenderer;bootstrap.createSecureShopGradingBootstrap=savedBootstrap;}
});


test('Inbox display projection admits exactly the three distinct lessons and preserves singleton profiles',()=>{
 const {INBOX_CONTENT_IDS,controlledProjectionIds,assertProjectionTexts}=require('./fixtures/secureshopMailRenderedQualification');
 assert(Object.isFrozen(INBOX_CONTENT_IDS));assert.deepEqual(INBOX_CONTENT_IDS,['ss_cross_persona_effect','ss_acl_advisory_effect','ss_acl_enforced_block']);
 const rows=INBOX_CONTENT_IDS.map(id=>({id,row:{label:id}}));assert.deepEqual(controlledProjectionIds(rows,INBOX_CONTENT_IDS[0]),INBOX_CONTENT_IDS);
 for(const id of ['ss_loop_observation','ss_audit_sql_extraction','ss_content_persist','ss_pricing_competitor_disclosure','ss_stored_browser_execution'])assert.deepEqual(controlledProjectionIds([{id}],id),[id]);
 for(const invalid of [rows.slice(0,2),[...rows].reverse(),[rows[0],rows[0],rows[2]],[{id:'ss_acl_enforced_block'}]])assert.throws(()=>controlledProjectionIds(invalid,invalid[0].id));
 assert.throws(()=>controlledProjectionIds(rows,'ss_acl_enforced_block'));
 const aggregate={done:3,total:3,time:75,hints:3,solutions:3};assertProjectionTexts(['3/3','1m'],aggregate,'dashboard');assertProjectionTexts(['3/3 objectives','1m','Hints: 3','Solutions: 3'],aggregate,'instructor');
 for(const text of ['1/1','2/3','3/30'])assert.throws(()=>assertProjectionTexts([text,'1m'],aggregate,'dashboard'));
});

test('actual Inbox binder joins current packet text, actor selection, durable effect and raw Judge before credit',()=>{
 const {bindInboxActual,INBOX_CONTENT_IDS}=require('./fixtures/secureshopMailRenderedQualification'),{createHash}=require('node:crypto');const hash=x=>createHash('sha256').update(x).digest('hex');
 const retained={scope:{ownerId:1,persona:{id:7},messageId:3},cases:[],actorInvocations:[],providerCalls:[],transcripts:[]},wire={model:'llama3.1:8b',failed:false,calls:[]};
 const add=(role,messages,text,caseId)=>{const request=JSON.stringify({messages,format:{type:'object'},options:{temperature:0,num_predict:2048}}),response=JSON.stringify({message:{content:text},done:true})+'\n';wire.calls.push({role,caseId,status:'returned',request,response,requestSha256:hash(request),responseSha256:hash(response)});};
 for(const [phase,ids]of [['advisory',INBOX_CONTENT_IDS.slice(0,2)],['enforced',INBOX_CONTENT_IDS.slice(2)]]){const snapshot={accesses:[{event_id:phase,target_id:'target',body_sha256:phase==='advisory'?hash('owned body'):null,message_id:3,caller_shop_user_id:7,acl_mode:phase,acl_decision:'deny',disclosed:phase==='advisory',acl_version:phase==='advisory'?1:2}],traces:[{kind:'terminal'},{kind:'model_decision',provider:'ollama',step:1,params_json:JSON.stringify({toolCalls:[{id:phase,name:'persona-inbox.read_message',args:{message_id:3}}]})}],judgments:[],packets:[],effects:[],contributions:[]};const start=wire.calls.length;const actorMessages=[{role:'user',content:phase}],actorRaw=JSON.stringify({tool_calls:[{agent:'persona-inbox',tool:'read_message',args:{message_id:3}}]});add('actor',actorMessages,actorRaw,phase);retained.providerCalls.push({phase,wireIndex:start,messages:actorMessages,options:{format:{type:'object'},temperature:0,num_predict:2048},result:{response:actorRaw}});retained.actorInvocations.push({phase,wireStart:start,wireEnd:wire.calls.length,result:{provider:'ollama',model:wire.model,mocked:false,tool_uses:[{id:phase,name:'persona-inbox.read_message',args:{message_id:3}}]}});
 for(const id of ids){const receipt={runId:id,ownerKey:'owner',generation:5,effectKey:phase+':'+JSON.stringify([1,phase,'persona-inbox.read_message']),status:'completed'},chain={requestId:phase,eventId:phase,targetId:'target',messageId:3,effectReceipt:receipt,modelCall:{step:1,callId:phase,tool:'persona-inbox.read_message',args:{message_id:3}}},packet=JSON.stringify({rubric:{objectiveId:id},evidence:[{id:'persona_inbox_chain',content:chain}]}),result={verdict:'pass',provider:'ollama',model:wire.model},input=[{role:'system',content:id},{role:'user',content:packet}],raw=JSON.stringify(result);add('judge',input,raw);snapshot.judgments.push({user_id:1,evaluation_id:id,objective_id:id,verdict:'pass',run_id:id,result_json:result,evidence_digest:hash(packet)});snapshot.packets.push({user_id:1,evaluation_id:id,packet,owner_key:'owner',owner_generation:'5'});snapshot.effects.push({run_id:id,effect_key:receipt.effectKey,owner_key:'owner',generation:5,status:'completed'});snapshot.contributions.push({evaluation_id:id,objective_id:id});retained.transcripts.push({complete:true,header:{runId:id,rubric:{objectiveId:id},packet,evidenceDigest:hash(packet)},outcome:{value:result},calls:[{transport:'returned',request:{input},response:raw}]});}
 retained.cases.push({name:phase,requestId:phase,response:{status:200,body:{accesses:[{event_id:phase,...(phase==='enforced'?{body:null,body_sha256:null}:{body:'owned body',body_sha256:hash('owned body')})}]}},snapshot});}
 assert.equal(bindInboxActual(retained,wire).genuineCredit,3);
 for(const mutate of [r=>r.cases[0].snapshot.effects[0].generation=6,r=>r.cases[0].snapshot.accesses[0].body_sha256='wrong',r=>r.cases[0].snapshot.accesses[0].target_id='other',r=>r.cases[0].snapshot.packets[0].owner_key='other',r=>r.cases[1].response.body.accesses[0].body='leaked',r=>r.actorInvocations[0].result.mocked=true,r=>r.transcripts[0].outcome.value.verdict='fail']){const bad=structuredClone(retained);mutate(bad);assert.throws(()=>bindInboxActual(bad,wire));}
 const changed=structuredClone(wire);changed.calls[0].response=changed.calls[0].response.replace('read_message','list_messages');changed.calls[0].responseSha256=hash(changed.calls[0].response);assert.throws(()=>bindInboxActual(retained,changed));
});

 test('MCP trust content admits only exact ordered two-objective projection',()=>{
 const {MCP_TRUST_CONTENT_IDS:ids,controlledProjectionIds}=require('./fixtures/secureshopMailRenderedQualification');
 assert(Object.isFrozen(ids));assert.deepEqual(ids,['ss_rogue_tool_selected','ss_rug_pull_invoked']);
 assert.deepEqual(controlledProjectionIds(ids.map(id=>({id})),ids[0]),ids);
 for(const invalid of [[ids[0]],[ids[1],ids[0]],[ids[0],ids[0]],['ss_cross_persona_effect',ids[1]]])assert.throws(()=>controlledProjectionIds(invalid.map(id=>({id})),invalid[0]));
 });

test('MCP actual binder binds canonical SDK invocation, raw decisions, policy/effect and both Judge awards',()=>{
 const {bindMcpTrustActual,MCP_TRUST_CONTENT_IDS:ids}=require('./fixtures/secureshopMailRenderedQualification'),{digestMcpValue}=require('../server/services/secureshopMcpTrustTools'),{createHash}=require('node:crypto');const hash=x=>createHash('sha256').update(x).digest('hex');
 const r={scope:{ownerId:1,launchId:'launch',persona:{id:7}},policyScope:{toolPolicy:'canonical',promptPolicyFeatureEnabled:false,rendererActivated:false},cases:[],providerCalls:[],actorInvocations:[],transcripts:[]},w={model:'llama3.1:8b',failed:false,calls:[]};
 function wire(role,phase,messages,answer,options={format:{type:'object'},temperature:0,num_predict:2048}){const request=JSON.stringify({messages,format:options.format,options:{temperature:0,num_predict:options.num_predict}}),response=JSON.stringify({message:{content:answer}});w.calls.push({role,caseId:phase,status:'returned',request,response,requestSha256:hash(request),responseSha256:hash(response)});}
 let baseline;
 for(const [n,name] of ['rogue','baseline','changed'].entries()){
  const scenario=name==='rogue'?'rogue_registration':'rug_pull',target=name==='rogue'?'rogue-target':'rug-target',server=name==='rogue'?'rogue':'rug',tools=[{name:'forecast_lookup',description:name,inputSchema:{type:'object'}}],schema=digestMcpValue(tools),args={city:'Seattle'},call={id:name,name:server+'.forecast_lookup',args},messages=[{role:'user',content:name}],raw=JSON.stringify({tool_calls:[{agent:server,tool:'forecast_lookup',args}]}),index=w.calls.length;
  wire('actor',name,messages,raw);r.providerCalls.push({phase:name,wireIndex:index,messages,options:{format:{type:'object'},temperature:0,num_predict:2048},result:{response:raw}});r.actorInvocations.push({phase:name,wireStart:index,wireEnd:index+1,result:{provider:'ollama',model:w.model,mocked:false,tool_uses:[call]}});
  const inv={invocation_id:name,operation_id:name,target_id:target,request_id:name,run_id:name,call_id:name,tool_name:'forecast_lookup',arguments_sha256:digestMcpValue(args),schema_version:name==='changed'?2:1,schema_sha256:schema,trust_scenario:scenario,behavior_class:name==='baseline'?'public_forecast_lookup':'protected_record_export',approved:name==='baseline',remote_receipt_sha256:'a'.repeat(64),result_sha256:digestMcpValue({answer:name}),trust_policy_sha256:'c'.repeat(64)};
  const effect={run_id:name,effect_key:`${name}:${JSON.stringify([1,name,call.name])}`,owner_key:'owner',generation:'4',status:'completed'},snapshot={payloads:[{target_id:target,version:inv.schema_version,tools_json:tools}],invocations:[inv],traces:[{kind:'model_decision',session_id:name,provider:'ollama',step:1,params_json:JSON.stringify({toolCalls:[call]})}],effects:[effect],policyReceipts:[{run_id:name,platform_launch_id:'launch',original_platform_owner_id:1,action:'dispatch',invocation_id:'1:'+name,persona_id:7,args_sha256:inv.arguments_sha256}],judgments:[],packets:[],contributions:[]};
  r.actorInvocations.at(-1).input={tools:require('../server/services/secureshopMcpTrustExecutionConfig').createSecureShopMcpTrustExecutionConfig({serverIdentity:server,trustScenario:scenario,schema:{serverIdentity:server,version:inv.schema_version,schemaSha256:schema,tools}}).manifest.getForRole('admin')};snapshot.traces.push({kind:'mcp_result',session_id:name,step:1,agent_ns:server,tool_name:'forecast_lookup',result_json:JSON.stringify({content:[{text:JSON.stringify({answer:name})}]})});
  r.cases.push({name,scenario,requestId:name,discovery:{schemaSha256:schema,serverIdentity:server},response:{status:200,body:{stopReason:'end_turn'}},snapshot});
  if(name==='baseline'){baseline=inv;continue;}
  const objective=ids[name==='rogue'?0:1],chain={requestId:name,runId:name,targetId:target,callId:name,currentInvocation:{invocationId:name},schemaSha256:schema,remoteReceiptSha256:inv.remote_receipt_sha256,resultSha256:inv.result_sha256,trustPolicySha256:inv.trust_policy_sha256,effectReceipt:{runId:name,effectKey:effect.effect_key,ownerKey:'owner',generation:'4',status:'completed'},...(name==='changed'?{priorInvocation:{invocationId:baseline.invocation_id},priorSchemaSha256:baseline.schema_sha256}:{})};
  const packet=JSON.stringify({rubric:{objectiveId:objective},evidence:[{id:'bound_mcp_invocation_chain',content:chain}]}),out={verdict:'pass',provider:'ollama',model:w.model},jm=[{role:'user',content:packet}],answer=JSON.stringify(out);wire('judge',name,jm,answer);
  snapshot.judgments.push({evaluation_id:name,objective_id:objective,verdict:'pass',run_id:name,user_id:1,evidence_digest:'digest',result_json:out});snapshot.packets.push({evaluation_id:name,user_id:1,packet,owner_key:'owner',owner_generation:'4'});snapshot.contributions.push({evaluation_id:name,objective_id:objective});r.transcripts.push({header:{runId:name,rubric:{objectiveId:objective},packet,evidenceDigest:'digest'},complete:true,outcome:{value:out},calls:[{transport:'returned',request:{input:jm},response:answer}]});
 }
 // Cumulative snapshots retain earlier same-server/tool/step result in another session.
 const priorResult=structuredClone(r.cases[1].snapshot.traces.find(x=>x.kind==='mcp_result'));priorResult.session_id='changed';r.cases[2].snapshot.traces.unshift(priorResult);
 // Real final-response model_decision rows carry SQL NULL params_json.
 for(const c of r.cases)c.snapshot.traces.push({kind:'model_decision',session_id:c.name,provider:'ollama',step:2,params_json:null,result_json:JSON.stringify({text:'Observed result'})});
 assert.equal(bindMcpTrustActual(r,w).genuineCredit,2);
 for(const mutate of [x=>x.cases[2].snapshot.invocations[0].target_id='foreign',x=>x.cases[0].snapshot.policyReceipts=[],x=>x.cases[2].snapshot.effects[0].generation='5',x=>x.actorInvocations[0].result.tool_uses[0].args.city='changed',x=>x.cases[1].snapshot.judgments.push({run_id:'baseline'})]){const copy=structuredClone(r);mutate(copy);assert.throws(()=>bindMcpTrustActual(copy,w));}
 const bad=structuredClone(w);bad.calls[0].response=JSON.stringify({message:{content:'{}'}});bad.calls[0].responseSha256=hash(bad.calls[0].response);assert.throws(()=>bindMcpTrustActual(r,bad));
});

 test('Controlled SSRF display projection is exact and never accepts another objective',()=>{
 const {controlledProjectionIds,assertProjection}=require('./fixtures/secureshopMailRenderedQualification');
 assert.deepEqual(controlledProjectionIds([{id:'ss_controlled_ssrf'}],'ss_controlled_ssrf'),['ss_controlled_ssrf']);
 assert.throws(()=>controlledProjectionIds([{id:'ss_controlled_ssrf'},{id:'ss_rug_pull_invoked'}],'ss_controlled_ssrf'));
 const value=row();value.exerciseGroups[0].objectives=[{id:'ss_controlled_ssrf',text:'Current SSRF label',completed:true,hintVisible:false,solutionVisible:true}];
 assert.deepEqual(assertProjection([value],true,'ss_controlled_ssrf'),{title:'Current SSRF label',completed:true,total:1,done:1,hintVisible:false,solutionVisible:true});
 assert.throws(()=>assertProjection([value],false,'ss_controlled_ssrf'));
 });

test('SSRF binder joins real-shaped HTTP receipt, nullable final trace and same-session turn interval',()=>{
 const {bindSsrfActual}=require('./fixtures/secureshopMailRenderedQualification'),{digestMcpValue:digest}=require('../server/services/secureshopMcpTrustTools'),{createHash}=require('node:crypto');const hash=x=>createHash('sha256').update(x).digest('hex');
 const r={scope:{ownerId:1,platformSessionId:2,launchId:'launch',persona:{id:7}},policyScope:{toolPolicy:'canonical',promptPolicyFeatureEnabled:false,rendererActivated:false},cases:[],providerCalls:[],actorInvocations:[],transcripts:[]},w={model:'llama3.1:8b',failed:false,calls:[]};let prior=[];
 function wire(role,phase,messages,answer){const options={format:{type:'object'},temperature:0,num_predict:2048},request=JSON.stringify({messages,format:options.format,options:{temperature:0,num_predict:2048}}),response=JSON.stringify({message:{content:answer}});const index=w.calls.length;w.calls.push({role,caseId:phase,status:'returned',request,response,requestSha256:hash(request),responseSha256:hash(response)});if(role==='actor')r.providerCalls.push({phase,wireIndex:index,messages,options,result:{response:answer}});return index;}
 for(const name of ['baseline','private']){
  const resource=name==='baseline'?'public-policy':'private-policy',url='http://127.0.0.1:12345/'+name,args={policy_url:url},call={id:name,name:'summarizer.explain_return_policy',args},body=JSON.stringify({recordId:'internal-policy:target',classification:'protected-training-record'}),returned={url,status:200,body},inv={operation_id:name,target_id:'target',request_id:name,run_id:name,call_id:name,session_id:'shared',launch_id:'launch',original_platform_owner_id:1,original_platform_session_id:2,resource_kind:resource,request_method:'GET',request_path:'/'+name,response_status:200,policy_decision:name==='baseline'?'allowed':'denied',egress_policy_sha256:require('../server/services/secureshopSsrfExternalAdapter').SSRF_EGRESS_POLICY_SHA256,arguments_sha256:digest(args),result_sha256:digest(returned),response_sha256:hash(body),egress_receipt_sha256:'a'.repeat(64)};
  let index=wire('actor',name,[{role:'user',content:name}],JSON.stringify({tool_calls:[{agent:'summarizer',tool:'explain_return_policy',args}]}));r.actorInvocations.push({phase:name,method:'chat',wireStart:index,wireEnd:index+1,input:{tools:require('../server/services/secureshopSsrfExecutionConfig').createSecureShopSsrfExecutionConfig().manifest.getForRole('admin')},result:{provider:'ollama',model:w.model,mocked:false,tool_uses:[call]}});
  index=wire('actor',name,[{role:'user',content:'observation'}],JSON.stringify({answer:name}));r.actorInvocations.push({phase:name,method:'finalResponse',wireStart:index,wireEnd:index+1,result:{provider:'ollama',model:w.model,mocked:false,stop_reason:'end_turn',text:name}});
  const effect={run_id:name,effect_key:`${name}:${JSON.stringify([1,name,call.name])}`,owner_key:'owner',generation:'3',status:'completed'},traces=[...prior,{kind:'model_decision',provider:'ollama',step:1,session_id:'shared',params_json:JSON.stringify({toolCalls:[call]})},{kind:'mcp_result',session_id:'shared',step:1,agent_ns:'summarizer',tool_name:'explain_return_policy',result_json:JSON.stringify({content:[{text:JSON.stringify(returned)}],_meta:{operationId:name,requestId:name,runId:name,ownerKey:'owner',generation:'3',egressReceiptSha256:inv.egress_receipt_sha256}})},{kind:'model_decision',provider:'ollama',session_id:'shared',params_json:null}];prior=traces;
  const snapshot={invocations:[inv],requests:[{operation_id:name,issued_url:url}],traces,effects:[effect],policyReceipts:[{run_id:name,platform_launch_id:'launch',original_platform_owner_id:1,action:'dispatch',invocation_id:'1:'+name,persona_id:7,args_sha256:'b'.repeat(64)}],judgments:[],packets:[],contributions:[]};
  if(name==='private'){
   const id='ss_controlled_ssrf',receipt={runId:name,ownerKey:'owner',generation:'3',effectKey:effect.effect_key,status:'completed'},chain={requestId:name,runId:name,operationId:name,targetId:'target',callId:name,egressPolicySha256:inv.egress_policy_sha256,egressReceiptSha256:inv.egress_receipt_sha256,responseSha256:inv.response_sha256,resultSha256:inv.result_sha256,protectedObservation:{recordId:'internal-policy:target',classification:'protected-training-record'},effectReceipt:receipt},packet=JSON.stringify({rubric:{objectiveId:id},evidence:[{id:'bound_ssrf_invocation_chain',content:chain}]}),result={verdict:'pass',provider:'ollama',model:w.model},input=[{role:'user',content:packet}],raw=JSON.stringify(result);wire('judge',name,input,raw);
   snapshot.judgments.push({user_id:1,evaluation_id:id,objective_id:id,verdict:'pass',run_id:name,result_json:result,evidence_digest:hash(packet)});snapshot.packets.push({user_id:1,evaluation_id:id,packet,owner_key:'owner',owner_generation:'3'});snapshot.contributions.push({evaluation_id:id,objective_id:id});r.transcripts.push({complete:true,header:{runId:name,rubric:{objectiveId:id},packet,evidenceDigest:hash(packet)},outcome:{value:result},calls:[{transport:'returned',request:{input},response:raw}]});
  }
  r.cases.push({name,resource,requestId:name,response:{status:200,body:{stopReason:'end_turn',resourceKind:resource,response:name}},snapshot});
 }
 assert.equal(bindSsrfActual(r,w).genuineCredit,1);
 for(const change of [x=>x.cases[1].snapshot.invocations[0].response_sha256='bad',x=>x.cases[1].snapshot.effects[0].owner_key='foreign',x=>x.cases[1].snapshot.requests[0].issued_url='http://other/',x=>x.actorInvocations[3].result.text='fabricated',x=>x.cases[1].response.body.response='fabricated',x=>x.cases[1].snapshot.invocations[0].original_platform_session_id=99,x=>x.cases[1].snapshot.traces.at(-2).result_json=x.cases[0].snapshot.traces[1].result_json]){const bad=structuredClone(r);change(bad);assert.throws(()=>bindSsrfActual(bad,w));}
 const raw=structuredClone(w);raw.calls[0].response=JSON.stringify({message:{content:'{}'}});raw.calls[0].responseSha256=hash(raw.calls[0].response);assert.throws(()=>bindSsrfActual(r,raw));
});


test('Audit instruction content projection cannot substitute Audit SQL or another lesson',()=>{
 const {controlledProjectionIds}=require('./fixtures/secureshopMailRenderedQualification');
 assert.deepEqual(controlledProjectionIds([{id:'ss_audit_instruction_followed'}],'ss_audit_instruction_followed'),['ss_audit_instruction_followed']);
 assert.throws(()=>controlledProjectionIds([{id:'ss_audit_sql_extraction'}],'ss_audit_instruction_followed'));
 assert.throws(()=>controlledProjectionIds([{id:'ss_audit_instruction_followed'}],'ss_audit_sql_extraction'));
 assert.throws(()=>controlledProjectionIds([{id:'unknown'}],'unknown'));
 const value=row();value.exerciseGroups[0].objectives=[{id:'ss_audit_instruction_followed',text:'Follow an owned audit instruction',completed:true,hintVisible:false,solutionVisible:true}];
 assert.deepEqual(assertProjection([value],true,'ss_audit_instruction_followed'),{title:'Follow an owned audit instruction',completed:true,total:1,done:1,hintVisible:false,solutionVisible:true});
 assert.throws(()=>assertProjection([value],true,'ss_audit_sql_extraction'));
 assert.throws(()=>assertProjection([value],false,'ss_audit_instruction_followed'));
 const curriculum=require('../server/config/secureshopCurriculum');assert.equal(curriculum.isQualifiedObjective('ss_audit_instruction_followed'),true);
});

test('Audit offline replay binds actual provider requests, repair attempts and final answer',async()=>{
 const {replayAuditActor}=require('./fixtures/secureshopMailRenderedQualification');const {OllamaProvider}=require('../server/services/secureshop/providers/ollamaProvider');const config=require('../server/services/secureshopAuditExecutionConfig').createSecureShopAuditExecutionConfig(),model='llama3.1:8b',wire={model,calls:[]},messages=[{role:'user',content:'Summarize anomalies in the latest 5000 audit events.'}];let attempt=0;
 const provider=new OllamaProvider({model,baseUrl:'http://127.0.0.1:1'});provider.transport.chat=async(input,tools,options)=>{const response=++attempt===1?'invalid':attempt===2?JSON.stringify({tool_calls:[{agent:'audit',tool:'summarize_anomalies',args:{limit:5000}}]}):JSON.stringify({answer:'Routine summary.'});const frame={model,message:{content:response},done:true,done_reason:'stop'};wire.calls.push({caseId:'benign',role:'actor',request:JSON.stringify({model,messages:input,stream:true,format:options.format,options:{num_predict:options.num_predict,temperature:options.temperature}}),response:JSON.stringify(frame)+'\n'});return {provider:'ollama',model,response,metadata:frame};};
 const selected=await provider.chat({system:config.buildBasePrompt('admin'),messages,tools:config.manifest.getForRole('admin'),max_tokens:2048});messages.push({role:'assistant',content:'',tool_calls:selected.tool_uses},{role:'tool',content:'Owned observation'});await provider.finalResponse({system:config.buildBasePrompt('admin')+'\n\n'+require('../server/agent-runtime/secureshopSupervisorGraph').FINAL_RESPONSE_INSTRUCTION,messages,max_tokens:2048});messages.push({role:'assistant',content:'Routine summary.'});
 const c={name:'benign',verified:{summary:'Routine summary.'},artifactText:{messages:JSON.stringify(messages),traces:JSON.stringify([{kind:'model_decision',params_json:JSON.stringify({toolCalls:selected.tool_uses})},{kind:'model_decision',params_json:null}])}};assert.equal(await replayAuditActor(c,wire),true);const bad=structuredClone(wire);bad.calls[1].request=bad.calls[1].request.replace('5000','4999');await assert.rejects(replayAuditActor(c,bad));const changed=structuredClone(c);changed.verified.summary='Fabricated';await assert.rejects(replayAuditActor(changed,wire));
});

test('Audit actual URLs match real gateway routes, with only persona authentication versioned',()=>{
 const {AUDIT_ACTUAL_PATHS:p}=require('./fixtures/secureshopMailRenderedQualification');
 const fail=()=>{throw Error('Route inspection must not execute a service');};
 const methods=names=>Object.fromEntries(names.split(' ').map(name=>[name,fail]));
 const router=require('../server/routes/secureshop/boundGateway').createSecureShopBoundGateway({
  launches:{resolveCapability:fail},authenticatePersona:fail,
  personaAuth:methods('login renew logout listSessions revokeOwnedSession changePassword listApiKey rotateApiKey authenticateApiKey'),
  reviewsRouter:fail,browserRouter:fail,auditSummary:methods('createSession run'),
  catalog:methods('listProducts getProduct listMerchantProducts createMerchantProduct updateMerchantProduct archiveMerchantProduct categories'),
  commerce:methods('cart add update remove summary checkout orders order'),account:methods('profile updateProfile addresses createAddress updateAddress deleteAddress')});
 const routes=router.stack.filter(layer=>layer.route);
 for(const [path,method] of [[p.login,'post'],[p.logout,'post'],[p.products,'post'],[p.products+'/17','put'],[p.session,'post'],[p.summary,'post']]){
  assert.equal(routes.filter(layer=>layer.route.methods[method]&&layer.match(path)).length,1,method+' '+path);
  assert.equal(new URL(p.base+path,'http://127.0.0.1').pathname,p.base+path);
 }
 assert.equal(p.base,'/api/secureshop');
 for(const path of ['/v2/merchant/products','/v2/admin/audit/bound-session','/v2/admin/audit/bound-summary','/auth/login','/auth/logout'])assert.equal(routes.some(layer=>layer.route.methods.post&&layer.match(path)),false,path);
});

test('Audit fixed payload is admitted against the exported canonical solution example before resources',()=>{
 const {getAuditActualPayload}=require('./fixtures/secureshopMailRenderedQualification');const solutions=require('../server/config/secureshopCurriculum').SOLUTIONS;
 const payload=getAuditActualPayload();assert(solutions.ss_audit_instruction_followed.examples[0].action.includes(payload));
 for(const value of [{},{ss_audit_instruction_followed:{action:payload}},{ss_audit_instruction_followed:{examples:[{action:'Changed teaching request'}]}}])assert.throws(()=>getAuditActualPayload(value));
});

test('Audit post-completion readback does not impersonate an active graph lease',async()=>{
 const {readAuditCompletedRunEffect}=require('./fixtures/secureshopMailRenderedQualification');
 const context={ownerKey:'owner',runId:'run',durableGeneration:'3'},key='request:audit-summary-job';
 const good={ownerKey:'owner',runId:'run',generation:'3',effectKey:key,status:'completed',runStatus:'completed',currentGeneration:'3'};let row=good;
 const pool={query:async(sql,args)=>{assert(sql.includes('JOIN graph_runtime.owners'));assert(sql.includes("r.status='completed'"));assert.deepEqual(args,['owner','3',key,'run']);return {rows:row?[row]:[]};}};
 const ledger=require('../server/agent-runtime/postgresRunLedger').createPostgresRunLedger(pool);
 await assert.rejects(ledger.readCompletedEffect(context,key),/no active lease/);
 assert.deepEqual(await readAuditCompletedRunEffect(pool,context,key),{ownerKey:'owner',runId:'run',generation:'3',effectKey:key,status:'completed'});
 for(const delta of [{runStatus:'running'},{status:'uncertain'},{currentGeneration:'4'},{ownerKey:'foreign'},{runId:'foreign'},{effectKey:'other'}]){row={...good,...delta};assert.equal(await readAuditCompletedRunEffect(pool,context,key),null);}row=null;assert.equal(await readAuditCompletedRunEffect(pool,context,key),null);
});

test('review actual pair preserves original matched bytes and production comparison budgets',()=>{
 const cases=require('./fixtures/secureshopReviewModerationComparisonCalibration').cases(),ids=['authentic_advertising_approve_exploit','advertising_violation_without_instruction'];
 const pair=ids.map(id=>cases.find(c=>c.definition.id===id));assert(pair.every(Boolean));assert.equal(pair[0].definition.body,pair[1].definition.body+'\n'+require('./fixtures/secureshopReviewModerationComparisonCalibration').APPROVE_REQUEST);assert.deepEqual(pair.map(x=>x.comparison.policy.maxOutput),[1040,900]);assert.deepEqual(pair.map(x=>x.comparison.policy.maximumCalls),[4,4]);
 const source=require('node:fs').readFileSync(require.resolve('./fixtures/secureshopMailRenderedQualification'),'utf8').split('async function qualifyReviewFollowedActual')[1];assert(source.includes("row.error={name:error.name,code:error.code||null}"));assert(source.indexOf('proof.cases.push')<source.indexOf('bindReviewFollowedActual(retained'));assert(source.includes("const owners=[await owner(),await owner()]"));assert(source.includes("for(let index=0;index<cases.length;index++)"));assert(source.includes("actorCalls<=32"));
});

test('review canonical offline replay rejects changed criteria, audit, rubric and stage options',async()=>{
 const {replayReviewJudge}=require('./fixtures/secureshopMailRenderedQualification'),cal=require('./fixtures/secureshopReviewModerationComparisonCalibration'),{createObjectiveJudge}=require('../server/agent-runtime/objectiveJudge');
 for(const caseId of ['authentic_advertising_approve_exploit','advertising_violation_without_instruction']){
  const fixed=cal.cases().find(x=>x.definition.id===caseId),providerCalls=[];let transcript,count=0;
  const judge=createObjectiveJudge({observeExecutionTranscript:x=>{transcript=x;},model:{chat:async(messages,tools,options)=>{const response=++count===1?'invalid':messages[0].content.startsWith(require('../server/agent-runtime/reviewModerationComparison').INSTRUCTION_POLICY)?cal.instructionFixture(fixed):cal.contentFixture(fixed),result={provider:'ollama',model:'llama3.1:8b',response,mocked:false};providerCalls.push({role:'judge',phase:caseId,wireIndex:providerCalls.length,messages:structuredClone(messages),tools:[],options:JSON.parse(JSON.stringify({...options,signal:undefined})),result});return result;}}});
  const result=await judge({rubric:fixed.rubric,evidence:fixed.evidence,facts:fixed.facts,execution:{runId:'owned-run'}});assert.equal(result.attempts,3);
  const fixture={transcript,judgment:{run_id:'owned-run',evidence_digest:result.evidenceDigest,result_json:result},packetRecord:{packet:transcript.header.packet},providerCalls,phase:caseId};assert.equal((await replayReviewJudge(fixture)).verdict,result.verdict);
  const canonical=structuredClone(fixture);canonical.judgment.result_json.errorCode=null;delete canonical.transcript.outcome.value.errorCode;assert.equal((await replayReviewJudge(canonical)).verdict,result.verdict);
  const realError=structuredClone(canonical);realError.judgment.result_json.errorCode='INVALID_JUDGE_OUTPUT';await assert.rejects(replayReviewJudge(realError));
  for(const change of [x=>{x.judgment.result_json.criteria[0].satisfied=!x.judgment.result_json.criteria[0].satisfied;x.transcript.outcome.value.criteria=structuredClone(x.judgment.result_json.criteria);},x=>{x.judgment.result_json.reviewModeration.observation.sourceSha256='0'.repeat(64);x.transcript.outcome.value.reviewModeration=structuredClone(x.judgment.result_json.reviewModeration);},x=>x.transcript.calls[0].request.schema={type:'string'},x=>x.providerCalls[1].options.num_predict++,x=>x.judgment.result_json.judgeVersion='old',x=>x.providerCalls.push(structuredClone(x.providerCalls[0]))]){const bad=structuredClone(fixture);change(bad);await assert.rejects(replayReviewJudge(bad));}
 }
});

test('review selected action binds exact actor arguments and unique completed owned effect',()=>{
 const {bindReviewSelectedEffect}=require('./fixtures/secureshopMailRenderedQualification'),selected={step:2,callId:'call',tool:'review-moderator.approve',args:{review_id:7},result:{ok:true},effectReceipt:{version:1,status:'completed',runId:'run',ownerKey:JSON.stringify(['SecureShopBoundConversation','session']),generation:'3',effectKey:'request:'+JSON.stringify([2,'call','review-moderator.approve'])}},chain={protectedRunId:'run'},invocations=[{phase:'case',error:null,result:{tool_uses:[{id:'call',name:selected.tool,args:selected.args}]}}],c={id:'case',moderationRequest:{request_id:'request'},snapshot:{runs:[{run_id:'run',owner_key:JSON.stringify(['SecureShopBoundConversation','session']),generation:3,status:'completed'}],effects:[{run_id:'run',owner_key:JSON.stringify(['SecureShopBoundConversation','session']),generation:3,effect_key:selected.effectReceipt.effectKey,status:'completed'}],traces:[{id:1,session_id:'session',kind:'model_decision',actor:'supervisor',step:2,params_json:JSON.stringify({toolCalls:invocations[0].result.tool_uses})},{id:2,session_id:'session',kind:'local_tool_result',actor:'task→supervisor',step:2,agent_ns:'review-moderator',tool_name:'approve',result_json:JSON.stringify({content:[{type:'text',text:JSON.stringify(selected.result)}]})}]}};
 assert.equal(bindReviewSelectedEffect(c,chain,selected,invocations).run_id,'run');
 for(const change of [x=>x.selected.args.review_id=8,x=>x.c.snapshot.effects[0].owner_key='foreign',x=>x.c.snapshot.effects[0].status='pending',x=>x.c.snapshot.runs[0].generation=4,x=>x.c.snapshot.traces[1].result_json='{}',x=>x.c.snapshot.effects.push(structuredClone(x.c.snapshot.effects[0]))]){const bad=structuredClone({c,chain,selected,invocations});change(bad);assert.throws(()=>bindReviewSelectedEffect(bad.c,bad.chain,bad.selected,bad.invocations));}
});

test('review credit joins the exact award and denies any negative contribution or completion',()=>{
 const {bindReviewCredit}=require('./fixtures/secureshopMailRenderedQualification'),row={user_id:7,workshop_key:'secureshop_agent_security',objective_id:'ss_content_followed',evaluation_id:'evaluation'},c={ownerId:7,snapshot:{contributions:[row],completions:[row]}},j={evaluation_id:'evaluation',verdict:'pass',disposition:'awarded'};assert.equal(bindReviewCredit(c,j,true),true);
 for(const change of [x=>x.snapshot.contributions[0].evaluation_id='other',x=>x.snapshot.completions[0].user_id=8,x=>x.snapshot.contributions=[],x=>x.snapshot.completions[0].workshop_key='other']){const bad=structuredClone(c);change(bad);assert.throws(()=>bindReviewCredit(bad,j,true));}
 const negative={ownerId:7,snapshot:{contributions:[],completions:[]}},fail={evaluation_id:'negative',verdict:'fail',disposition:'not_pass'};assert.equal(bindReviewCredit(negative,fail,false),true);for(const key of ['contributions','completions']){const bad=structuredClone(negative);bad.snapshot[key].push(row);assert.throws(()=>bindReviewCredit(bad,fail,false));}
});

test('review committed outcome cannot swap review, body, status or read/action order',()=>{
 const {bindReviewCommittedSource}=require('./fixtures/secureshopMailRenderedQualification'),review={id:7,body:'original',status:'approved',moderator_kind:'auto'},c={submissionRequest:{submission_id:'submission'},snapshot:{reviews:[{...review,submission_id:'submission'}]}},chain={source:{reviewId:7,body:'original',bodySha256:'digest'},retrieval:{step:1},action:{step:2,tool:'review-moderator.approve',args:{review_id:7},result:{ok:true,applied:true,review}}},outcome={reviewId:7,decision:'approve',status:'approved',applied:true,moderatorKind:'auto',bodySha256:'digest'};assert.equal(bindReviewCommittedSource(c,chain,outcome),true);
 for(const change of [x=>x.outcome.reviewId=8,x=>x.outcome.status='rejected',x=>x.chain.action.result.review.body='changed',x=>x.c.snapshot.reviews[0].body='changed',x=>x.chain.action.step=1,x=>x.chain.action.args.review_id=8,x=>x.chain.action.result.applied=false,x=>x.c.snapshot.reviews[0].submission_id='foreign']){const bad=structuredClone({c,chain,outcome});change(bad);assert.throws(()=>bindReviewCommittedSource(bad.c,bad.chain,bad.outcome));}
});

test('native admission helper stays controlled and binds retired owner plus nonempty sibling',async()=>{
 const {qualifyReviewAdmissionTimeNative}=require('./postgres/secureshopReviewSubmissions.integration.test'),{randomUUID,createHash}=require('node:crypto'),owner={userId:91,launchId:randomUUID()},sibling={userId:92,launchId:randomUUID()},rows=[owner,sibling].map((x,i)=>({target_id:randomUUID(),launch_id:x.launchId,scenario_id:randomUUID(),generation:1,original_platform_owner_id:x.userId,original_platform_session_id:901+i})),sources=new Map();let retired=false,id=0;
 const current=scope=>{const row=rows.find(x=>x.launch_id===scope.launchId);assert(row);assert.equal(scope.platformOwnerId,row.original_platform_owner_id);assert.equal(scope.platformSessionId,row.original_platform_session_id);assert.equal(scope.generation,1);assert(!(retired&&scope.launchId===owner.launchId));};
 const repository={async submitReview(scope,persona,input){current(scope);const source={version:1,...scope,reviewId:++id,...input,bodySha256:createHash('sha256').update(input.body).digest('hex'),submittedByShopUserId:persona.id,submittedByShopRole:persona.role,createdAt:new Date('2026-09-30T22:15:43.970Z'),createdAtMicros:'1790806543970779'};sources.set(source.reviewId,source);return source;},async readSubmission(scope,reviewId){current(scope);return structuredClone(sources.get(reviewId));},async captureReviewAdmissionTime(scope){current(scope);return '1790806543970780';}};
 const reviewRuntime={async query(sql,args){if(sql.includes('review_targets'))return {rows:rows.filter(x=>x.launch_id===args[0])};assert(sql.includes('extract(epoch FROM created_at)'));return {rows:[{micros:sources.get(args[1]).createdAtMicros}]};}};
 const result=await qualifyReviewAdmissionTimeNative({repository,reviewRuntime,owner,sibling});assert.equal(result.proof.modelCalls,0);assert.equal(result.proof.genuineCredit,0);assert.deepEqual(result.proof.boundaries.map(x=>x.laterProtectedTurn),[true,false,false]);assert.equal(result.proof.resetDenied,false);retired=true;await result.afterReset();assert.equal(result.proof.resetDenied,true);assert.equal(result.proof.siblingPreserved,true);
});


test('followed content projection is exactly one followed objective and cannot substitute persistence',()=>{
 const {controlledProjectionIds}=require('./fixtures/secureshopMailRenderedQualification');
 assert.deepEqual(controlledProjectionIds([{id:'ss_content_followed'}],'ss_content_followed'),['ss_content_followed']);
 assert.throws(()=>controlledProjectionIds([{id:'ss_content_persist'}],'ss_content_followed'));
 assert.throws(()=>controlledProjectionIds([{id:'ss_content_followed'},{id:'ss_content_persist'}],'ss_content_followed'));
});

test('Analytics reset proof requires seeded owner retirement, nonempty sibling, exact replay and immutable evidence',()=>{
 const {assertAnalyticsProjectionReset}=require('./fixtures/secureshopMailRenderedQualification');const key='secureshop_agent_security',id='ss_analytics_sensitive_disclosure';
 const before={ownerCompletions:[{user_id:1,workshop_key:key,objective_id:id}],ownerTime:[{id:10,user_id:1,workshop_key:key,duration_seconds:75,platform_launch_id:'owned',platform_launch_generation:1,workshop_generation:0}],siblingCompletions:[{user_id:2,workshop_key:key,objective_id:id}],siblingTime:[{id:11,user_id:2,workshop_key:key,duration_seconds:23,platform_launch_id:'sibling',platform_scenario_id:'scenario',platform_launch_generation:1,workshop_generation:0}]};
 const reset={status:200,body:{resetId:'12345678-1234-4123-8123-123456789012',cleanupComplete:true,launch:{generation:2}}};
 const valid={ownerId:1,siblingId:2,siblingLaunch:{ownerId:2,launchId:'sibling',scenarioId:'scenario',generation:1,workshopGeneration:0},launchId:'owned',cleanupHistory:{reset_id:reset.body.resetId,launch_id:'owned',original_platform_owner_id:1,from_launch_generation:1,workshop_generation:0,workshop_key:key,retired_time_entry_count:1,retired_time_seconds:75,projected_time_seconds:0},canonicalAfter:{workshopKey:key,completedObjectiveCount:0,timeSpentSeconds:0},seededTimeId:10,beforeGeneration:1,afterGeneration:2,before,after:{...structuredClone(before),ownerCompletions:[]},reset,replay:structuredClone(reset),staleStatus:409,immutableBefore:{packets:[{id:'retained'}]},immutableAfter:{packets:[{id:'retained'}]}};
 assert.equal(assertAnalyticsProjectionReset(valid),true);
 const audit=structuredClone(valid);audit.objectiveId='ss_audit_instruction_followed';audit.before.ownerCompletions[0].objective_id=audit.objectiveId;audit.before.siblingCompletions[0].objective_id=audit.objectiveId;audit.after.siblingCompletions[0].objective_id=audit.objectiveId;
 assert.equal(assertAnalyticsProjectionReset(audit),true);audit.after.siblingCompletions[0].objective_id=id;assert.throws(()=>assertAnalyticsProjectionReset(audit));
 for(const mutate of [p=>p.siblingLaunch.generation=2,p=>delete p.before.siblingTime[0].platform_launch_id,p=>p.after.ownerCompletions=p.before.ownerCompletions,p=>p.after.ownerTime=[],p=>p.canonicalAfter.timeSpentSeconds=75,p=>p.cleanupHistory.retired_time_seconds=0,p=>p.cleanupHistory.reset_id='foreign',p=>p.before.siblingTime=[],p=>p.after.siblingCompletions=[],p=>p.replay.body.resetId='different',p=>p.staleStatus=200,p=>p.afterGeneration=3,p=>p.immutableAfter.packets=[]]){const bad=structuredClone(valid);mutate(bad);assert.throws(()=>assertAnalyticsProjectionReset(bad));}
});

test('Analytics projection reset pauses pages, resets live projection and restores sibling fixtures without model calls',async()=>{
 const {qualifyAnalyticsProjectionReset}=require('./fixtures/secureshopMailRenderedQualification');const key='secureshop_agent_security',objectiveId='ss_analytics_sensitive_disclosure',events=[];
 const state={completions:[{user_id:1,workshop_key:key,objective_id:objectiveId}],time_tracking:[{id:10,user_id:1,workshop_key:key,duration_seconds:75,platform_launch_id:'owned',platform_launch_generation:1,workshop_generation:0}]};
 const identity={async query(sql,args){if(sql.includes('identity.secureshop_launches')){assert.equal(args[0],2);assert(sql.includes("status='active' AND expires_at>clock_timestamp()"));return {rows:[{launch_id:'sibling',scenario_id:'scenario',generation:1}]};}if(sql.includes('SELECT generation FROM workshop_platform.user_state'))return {rows:[{generation:0}]};if(sql.includes('secureshop_progress_cleanup_history'))return {rows:[{row:{reset_id:'12345678-1234-4123-8123-123456789012',launch_id:'owned',original_platform_owner_id:1,from_launch_generation:1,workshop_generation:0,workshop_key:key,retired_time_entry_count:1,retired_time_seconds:75,projected_time_seconds:0}}]};if(sql.includes('WHERE user_id')){const table=sql.includes('time_tracking')?'time_tracking':'completions';return {rows:state[table].filter(r=>r.user_id===Number(args[0])).map(row=>({row:structuredClone(row)}))};}return {rows:[]};}};
 const migration={async query(sql,args){if(sql.includes('INSERT INTO workshop_platform.user_state'))return {rows:[]};if(sql.startsWith('INSERT')&&sql.includes('completions'))state.completions.push({user_id:Number(args[0]),workshop_key:args[1],objective_id:args[2]});else if(sql.startsWith('INSERT')){assert(sql.includes('platform_launch_id,platform_scenario_id,platform_launch_generation,workshop_generation'));assert.deepEqual(args,[2,key,'sibling','scenario',1,0]);state.time_tracking.push({id:11,user_id:Number(args[0]),workshop_key:args[1],duration_seconds:23,platform_launch_id:args[2],platform_scenario_id:args[3],platform_launch_generation:args[4],workshop_generation:args[5]});return {rows:[{id:11}]};}else if(sql.includes('completions'))state.completions=state.completions.filter(r=>r.user_id!==Number(args[0]));else state.time_tracking=state.time_tracking.filter(r=>r.id!==args[0]);return {rows:[]};}};
 const page=name=>({async goto(url){assert(url.endsWith('/api/auth/secureshop-launch'));events.push(name);}});
 const reply={status:200,body:{resetId:'12345678-1234-4123-8123-123456789012',cleanupComplete:true,launch:{generation:2}}};let resets=0;
 const api=async(p,url,body)=>{assert.deepEqual(events,['learner','admin']);if(url.endsWith('/challenges'))return {status:200,body:{challenges:[{workshopKey:key,completedObjectiveCount:0,timeSpentSeconds:0}]}};if(url.endsWith('/recover'))return {status:409,body:{error:'stale'}};assert.equal(body.expectedGeneration,1);if(resets++===0){assert.equal(state.completions.filter(r=>r.user_id===1).length,1);assert.equal(state.time_tracking.find(r=>r.id===10).duration_seconds,75);state.completions=state.completions.filter(r=>r.user_id!==1);}return structuredClone(reply);};
 const result=await qualifyAnalyticsProjectionReset({learnerPage:page('learner'),admin:page('admin'),origin:'http://127.0.0.1:1',identity,migration,uid:1,siblingId:2,objectiveId,launch:{launch_id:'owned',generation:1,credential_version:1},timeId:10,api});
 assert.equal(result.controlledProjectionReset,true);assert.equal(resets,2);assert.equal(state.completions.length,0);assert.equal(state.time_tracking.length,1);assert.equal(state.time_tracking[0].id,10);assert.equal(result.rawTimePreserved,true);
});

test('Analytics singleton passes the real controlled projection admission',()=>{const {controlledProjectionIds}=require('./fixtures/secureshopMailRenderedQualification');const id='ss_analytics_sensitive_disclosure';assert.deepEqual(controlledProjectionIds([{id}],id),[id]);assert.throws(()=>controlledProjectionIds([{id:'ss_pricing_false_grounding'}],id));});


test('Audit rendered gate requires real persisted owner/run judgment, contribution and completion',()=>{
 const {assertAuditEarnedCompletion}=require('./fixtures/secureshopMailRenderedQualification');const objective='ss_audit_instruction_followed',scope={ownerId:7};
 const value={name:'injected',response:{body:{objectiveCredit:true,runId:'run'}},verified:{runId:'run'},snapshot:{judgments:[{user_id:7,objective_id:objective,run_id:'run',verdict:'pass',evaluation_id:'evaluation'}],contributions:[{user_id:7,objective_id:objective,evaluation_id:'evaluation'}],completions:[{user_id:7,workshop_key:'secureshop_agent_security',objective_id:objective}]}};
 assert.deepEqual(assertAuditEarnedCompletion(value,scope),{objectiveId:objective,ownerId:7,runId:'run',evaluationId:'evaluation'});
 for(const mutate of [x=>x.name='benign',x=>x.response.body.objectiveCredit=false,x=>x.verified.runId='other',x=>x.snapshot.judgments[0].verdict='fail',x=>x.snapshot.judgments[0].user_id=8,x=>x.snapshot.contributions=[],x=>x.snapshot.completions=[],x=>x.snapshot.completions[0].user_id=8,x=>x.snapshot.completions.push({...x.snapshot.completions[0]})]){const bad=structuredClone(value);mutate(bad);assert.throws(()=>assertAuditEarnedCompletion(bad,scope));}
});
test('Audit projection is closed to its exact objective and default mail remains unchanged',()=>{
 const {assertActualAdminProjection}=require('./fixtures/secureshopMailRenderedQualification');const mail='ss_mail_stored_browser_execution',audit='ss_audit_instruction_followed';const row=id=>({id,label:id,completed:true,hintVisible:true,solutionVisible:false});const body={student:{id:7},challenges:[{workshopKey:'secureshop_agent_security',objectives:[row(mail),row(audit)]}]};
 assert.equal(assertActualAdminProjection(body,7,true).title,mail);assert.equal(assertActualAdminProjection(body,7,true,audit).title,audit);assert.throws(()=>assertActualAdminProjection(body,7,true,'ss_audit_sql_extraction'));assert.throws(()=>assertActualAdminProjection(body,8,true,audit));
});
