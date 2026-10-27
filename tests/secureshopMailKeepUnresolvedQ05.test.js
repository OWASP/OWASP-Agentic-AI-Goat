'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs');
const {createRequire}=require('node:module');
const path=require('node:path');
const {createMailPersistenceFault}=require('./fixtures/secureshopMailKeepUnresolvedQ05');
const {createBoundMailRepository}=require('../server/database/postgres/secureshopBoundMailRepository');
const {operationId}=require('../server/services/secureshopBoundMailGraph');
const {createKeepUnresolvedFacet}=require('./fixtures/secureshopMailKeepUnresolvedQ05');
test('committed mail capture delegates original query and admits witnesses only after successful COMMIT',async()=>{
 const {observeCommittedMailPool}=require('./fixtures/secureshopMailKeepUnresolvedQ05'),records=[],events=[];
 const f=graphFixture(),v=[f.input.targetId,...['launchId','scenarioId','generation','platformOwnerId','platformSessionId'].map(k=>f.input.scope[k]),f.input.persona.id,
  f.input.personaSession.sessionId,'merchant','1','vuln',f.input.operationId,'read','{}'];
 let failCommit=false;const client={async query(sql){events.push(sql);if(sql==='COMMIT'&&failCommit)throw Error('commit failed');return {rows:[{result:{ok:true,operationId:f.input.operationId,receipt:{userId:2,messages:[]}}}]};},release(){events.push('release');}};
 const pool=observeCommittedMailPool({connect:async()=>client},records),c=await pool.connect();
 const sql='SELECT secureshop_agents.bound_lab_mail($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14::jsonb) AS result';
 await c.query(sql,v);assert.equal(records.length,0);await c.query('ROLLBACK');await c.query('COMMIT');assert.equal(records.length,0);
 await c.query(sql,v);failCommit=true;await assert.rejects(c.query('COMMIT'));failCommit=false;await c.query('COMMIT');assert.equal(records.length,0);
 await c.query(sql,v);await c.query('COMMIT');assert.equal(records.length,1);assert.equal(records[0].operationId,f.input.operationId);assert.equal(records[0].result.userId,2);
 await c.query(sql,[...v.slice(0,12),'browse','{}']);await c.query('COMMIT');assert.equal(records.length,1,'UI browse creates no receipt witness');
 c.release();assert.equal(events.at(-1),'release');
});
test('strict target delta preserves all baseline rows and rejects unobserved or foreign changes',()=>{
 const {assertReceiptDelta}=require('./fixtures/secureshopMailKeepUnresolvedQ05');const f=graphFixture(),context={scope:f.input.scope,persona:f.input.persona,personaSession:f.input.personaSession};
 const baseline={operation_id:'baseline',target_id:f.input.targetId,caller_id:99,persona_session_id:'sibling',result:{email_id:7},request_sha256:Buffer.alloc(32)};
 const witness={operationId:f.input.operationId,targetId:f.input.targetId,scope:context.scope,personaId:context.persona.id,sessionId:context.personaSession.sessionId,
  role:context.persona.role,authorityVersion:'1',mode:'vuln',action:'read',payload:{userId:context.persona.id},result:{userId:context.persona.id,messages:[{id:9,sha256:'a'.repeat(64)}]}};
 const row={operation_id:witness.operationId,target_id:witness.targetId,caller_id:witness.personaId,persona_session_id:witness.sessionId,role:witness.role,
  authority_version:'1',mode:'vuln',action:'read',result:witness.result,request_sha256:Buffer.alloc(32)};
 const packet={before:[baseline],after:[baseline,row],witnesses:[witness],expected:[{operationId:witness.operationId,targetId:witness.targetId,context,action:'read',payload:witness.payload,requestSha256:'0'.repeat(64)}],forbidden:['faulted-send'],siblingId:99,siblingSession:'sibling'};
 assertReceiptDelta(packet);
 for(const mutate of [p=>p.after.shift(),p=>p.after[0].result.email_id++,p=>p.after.push({...row,operation_id:'unexplained'}),
  p=>p.witnesses=[],p=>p.witnesses[0].scope.platformOwnerId++,p=>p.after[1].caller_id=99,p=>p.after[1].persona_session_id='sibling',
  p=>p.after[1].result.userId++,p=>p.after[1].authority_version='2',p=>p.after[1].action='send',p=>p.after[1].operation_id='faulted-send',
  p=>p.witnesses.push({...witness,operationId:'unobserved-extra'}),p=>p.expected[0].operationId='wrong-known-id',
  p=>p.after[1].request_sha256[0]=1,p=>p.witnesses[0].payload.userId++,p=>p.expected=[],p=>p.expected.push(p.expected[0])]){
  const p=Object.fromEntries(Object.entries(packet).map(([k,v])=>[k,structuredClone(v)]));mutate(p);assert.throws(()=>assertReceiptDelta(p));
 }
});
test('populated sibling full-thread comparison rejects changed removed and newly appended messages',()=>{
 const {assertSiblingMail}=require('./fixtures/secureshopMailKeepUnresolvedQ05');
 const before=[{message_id:1,thread_id:7,sender_id:99,recipient_id:99,body_markdown:'controlled sibling'},
  {message_id:2,thread_id:7,sender_id:3,recipient_id:4,body_markdown:'controlled same thread'}];
 assertSiblingMail(before,structuredClone(before),99);
 for(const mutate of [rows=>rows.pop(),rows=>rows[0].body_markdown='changed',rows=>rows.push({...rows[0],message_id:3}),rows=>rows[1].sender_id=5]){
  const rows=structuredClone(before);mutate(rows);assert.throws(()=>assertSiblingMail(before,rows,99));
 }
 assert.throws(()=>assertSiblingMail([],[],99));
});
test('original authority and mail repository produce committed exact read witness through facet pool',async()=>{
 const f=graphFixture(),p=persistence(f.input),facet=createKeepUnresolvedFacet(),originalQuery=p.client.query;
 p.client.query=async function(sql,values){
  if(typeof sql==='string'&&sql.includes('bound_lab_mail(')&&values[12]==='read'){
   p.events.push('actual-read');return {rows:[{result:{ok:true,replayed:false,operationId:values[11],receipt:{userId:f.input.persona.id,messages:[]},emails:[]}}]};
  }return originalQuery.call(this,sql,values);
 };
 const authority=facet.createAuthority({pool:p.pool,checkCurrent:async()=>{}});
 const repository=createBoundMailRepository({pool:p.pool,personaAuthority:authority,checkCleanup:async()=>{}});
 const binding={...f.input};delete binding.threadId;
 await repository.read(binding,f.input.persona.id);
 const records=facet.committed();assert.equal(records.length,1);assert.equal(records[0].operationId,binding.operationId);
 assert.deepEqual(records[0].scope,binding.scope);assert.equal(records[0].sessionId,binding.personaSession.sessionId);
 assert.equal(records[0].action,'read');assert.deepEqual(records[0].result,{userId:f.input.persona.id,messages:[]});
 assert(p.events.indexOf('actual-read')<p.events.indexOf('COMMIT'));assert.equal(p.events.at(-1),'release');facet.close();
});
test('actual selected-panel predicate waits through delayed DOM mount and rejects wrong panel/state without clicking',async()=>{
 const {JSDOM}=require('../client/node_modules/jsdom');
 const {selectedReplyButton,waitSelectedReplyButton}=require('./fixtures/secureshopMailKeepUnresolvedQ05');
 for(const role of ['customer','merchant']){
  const dom=new JSDOM('<body></body>',{runScripts:'outside-only'}),win=dom.window;
  // jsdom has no layout; only geometry is controlled. DOM selection, ancestry,
  // exact text, disabled state and the serialized browser predicate are real.
  win.HTMLElement.prototype.getClientRects=function(){return this.hidden?[]:[{}];};
  const evaluate=win.eval('('+selectedReplyButton.toString()+')');
  const label=role==='customer'?'Auto-reply (LLM01 test — invokes summarize_thread + send)':'Auto-reply';
  const options={role,threadId:51,subject:'Exact selected subject',label,disabled:false};
  const mount=(id,subject,disabled,button=true)=>{const header=`<div><div class="ss-card__meta">${role==='merchant'?'THREAD':'Thread'} #${id} · from lab</div><h2>${subject}</h2></div>`;
   win.document.body.innerHTML=`<section>${role==='customer'?`<header>${header}</header>`:header}${button?`<div><button ${disabled?'disabled':''}>${label}</button></div>`:''}</section>`;};
  let clicks=0,polls=0;
  const frame={async waitForFunction(fn,{timeout,polling},input){
   assert.equal(fn,selectedReplyButton);assert.equal(polling,'raf');assert(timeout>0&&timeout<=1000);
   for(const transition of [()=>{},()=>mount(50,options.subject,false),()=>mount(51,'Old subject',false),()=>mount(51,options.subject,false,false),()=>mount(51,options.subject,true),()=>mount(51,options.subject,false)]){
    transition();polls++;const element=evaluate(input);
    if(element){element.addEventListener('click',()=>clicks++);return {asElement:()=>({click:async()=>element.click()}),dispose:async()=>{}};}
    assert.equal(clicks,0);await Promise.resolve();
   }throw Error('controlled timeout');
  }};
  const handle=await waitSelectedReplyButton(frame,options,performance.now()+1000);
  assert.equal(polls,6);assert.equal(clicks,0);await handle.asElement().click();assert.equal(clicks,1);await handle.dispose();
  mount(51,options.subject,true);assert(evaluate({...options,disabled:true}));assert.equal(evaluate(options),false);
  mount(50,options.subject,true);assert.equal(evaluate({...options,disabled:true}),false);
  await assert.rejects(waitSelectedReplyButton(frame,options,performance.now()-1),/Q05_SELECTED_PANEL_DEADLINE/);
  await assert.rejects(waitSelectedReplyButton({waitForFunction:async(fn,args,input)=>{mount(51,options.subject,true);assert.equal(evaluate(input),false);throw Error('controlled timeout');}},options,performance.now()+1000),/controlled timeout/);
  assert.equal(clicks,1);win.close();
 }
});
// Execute the existing admission implementation without minting a native FIFO
// grant. Only Puppeteer's event surface is controlled; the guard is not stubbed.
function actualBrowserGuards(){
 const source=fs.readFileSync(path.join(__dirname,'fixtures/secureshopMerchantMailActionsBrowserAdmission.js'),'utf8');
 const start=source.indexOf('  function watchBrowserTargets('),end=source.indexOf('  async function acknowledgeBrowser(',start);
 assert(start>0&&end>start);
 return new Function('assert',source.slice(start,end)+';return {watchBrowserTargets,guardPageRequests};')(assert);
}
function browserEvents(){
 const {EventEmitter}=require('node:events'),browser=new EventEmitter();browser.contexts=[];
 browser.createBrowserContext=async()=>{const context={closed:false,pages:[],async close(){this.closed=true;for(const p of this.pages)await p.close();},async newPage(){
  const page=new EventEmitter();Object.assign(page,{closed:false,async close(){this.closed=true;},async setViewport(){},async setRequestInterception(value){this.intercepted=value;}});
  this.pages.push(page);browser.emit('targetcreated',{type:()=> 'page',page:async()=>page});return page;
 }};browser.contexts.push(context);return context;};return browser;
}
test('actual target watcher rejects raw Q05 page birth but reserves isolated guarded role pages',async()=>{
 const guards=actualBrowserGuards(),bad=browserEvents(),badBoundary=guards.watchBrowserTargets(bad);
 const rawContext=await bad.createBrowserContext(),raw=await rawContext.newPage();await Promise.resolve();
 assert.equal(raw.closed,true);assert.throws(()=>badBoundary.assertNoUnexpectedTargets());await rawContext.close();
 const browser=browserEvents(),boundary=guards.watchBrowserTargets(browser),contexts=[],pageErrors=[];
 const {createAdmittedRolePage}=require('./fixtures/secureshopMailKeepUnresolvedQ05');
 try{for(const role of ['merchant','customer']){
  const page=await createAdmittedRolePage({browser,boundary,admission:guards,origin:'http://127.0.0.1:8123',contexts,pageErrors});
  assert.equal(page.closed,false);assert.equal(page.intercepted,true);
  const seen=[];for(const url of ['http://127.0.0.1:8123/secureshop/inbox','http://127.0.0.1:8124/','https://example.invalid/','not a url'])
   page.emit('request',{url:()=>url,continue:()=>seen.push('continue'),abort:()=>seen.push('abort')});
  assert.deepEqual(seen,['continue','abort','abort','abort']);
  page.emit('pageerror',Object.assign(Error(role),{name:'ControlledPageError'}));boundary.assertNoUnexpectedTargets();
 }assert.equal(contexts.length,2);assert.notEqual(contexts[0],contexts[1]);assert.deepEqual(pageErrors,['ControlledPageError','ControlledPageError']);
 }finally{for(const c of contexts)await c.close();}
 assert(contexts.every(c=>c.closed&&c.pages.every(p=>p.closed)));
 for(const type of ['page','service_worker','worker']){
  const b=browserEvents(),guard=guards.watchBrowserTargets(b);let closed=false;
  b.emit('targetcreated',{type:()=>type,page:async()=>({close:async()=>{closed=true;}})});await Promise.resolve();
  assert.throws(()=>guard.assertNoUnexpectedTargets());if(type==='page')assert.equal(closed,true);
 }
});
test('Q05 guarded role page retains context ownership when admission setup fails',async()=>{
 const guards=actualBrowserGuards(),browser=browserEvents(),contexts=[];
 await assert.rejects(require('./fixtures/secureshopMailKeepUnresolvedQ05').createAdmittedRolePage({browser,
  boundary:guards.watchBrowserTargets(browser),admission:guards,origin:'https://wrong.invalid',contexts,pageErrors:[]}));
 assert.equal(contexts.length,1);for(const c of contexts)await c.close();assert(contexts[0].closed);
});
test('actual Q05 role-page callsite installs guards before login and preserves shared diagnostics',async()=>{
 const source=fs.readFileSync(path.join(__dirname,'postgres/secureshopStandaloneRoleChoicesRendered.integration.test.js'),'utf8');
 const start=source.indexOf("    page=await require('../fixtures/secureshopMailKeepUnresolvedQ05').createAdmittedRolePage("),end=source.indexOf('    await frame.waitForFunction',start);
 assert(start>0&&end>start);
 const run=new Function('require','browser','mailActionsBoundary','mailActionsAdmission','origin','contexts','pageErrors','loginAndFrame','role','password','evidencePath','setupDiagnostics','facet',
  'return (async()=>{let page;'+source.slice(start,end)+';return page;})();');
 const browser=browserEvents(),guards=actualBrowserGuards(),boundary=guards.watchBrowserTargets(browser),contexts=[],diagnostics=[];
 try{for(const role of ['merchant','customer'])await run(name=>{assert.equal(name,'../fixtures/secureshopMailKeepUnresolvedQ05');return require('./fixtures/secureshopMailKeepUnresolvedQ05');},
  browser,boundary,guards,'http://127.0.0.1:8123',contexts,[],async(page,options)=>{
   assert.equal(page.closed,false);assert.equal(page.intercepted,true);assert.equal(page.listenerCount('request'),1);assert.equal(page.listenerCount('pageerror'),1);
   assert.equal(options.diagnostics,diagnostics);assert.equal(options.stage,`q05-${role}`);options.diagnostics.push({stage:options.stage,status:200});return {};
  },{role,username:role},'controlled','controlled',diagnostics,{observePageReadiness(){return {wait:async()=>({}),close(){}};}});
  boundary.assertNoUnexpectedTargets();assert.equal(diagnostics.length,2);
 }finally{for(const c of contexts)await c.close();}
 assert(contexts.every(c=>c.closed));
});
test('actual readiness middleware joins new page bootstrap and delayed authenticated request, never competing old page',async()=>{
 const {EventEmitter}=require('node:events'),page=new EventEmitter(),facet=createKeepUnresolvedFacet();
 const origin='http://127.0.0.1:8123',old={persona:{role:'merchant'},personaSession:{sessionId:'old'}},fresh={persona:{role:'merchant'},personaSession:{sessionId:'new'}};
 let release;const hold=new Promise(resolve=>{release=resolve;});
 const app=facet.wrapApplication({readiness:async c=>{if(c===fresh)await hold;return {available:true};}},{});
 await app.readiness(old);assert.equal(facet.context('merchant'),old);
 const observed=facet.observePageReadiness(page,{origin,role:'merchant',username:'merchant'});
 const bootstrap={url:()=>origin+'/api/secureshop/auth/bootstrap',request:()=>({method:()=> 'POST'}),status:()=>200,json:async()=>({persona:{user:{role:'merchant',username:'merchant'},token:'new-token'}})};
 const response=(id,token)=>({url:()=>origin+'/api/secureshop/email/readiness',status:()=>200,headers:()=>({'x-q05-readiness-witness':id}),request:()=>({method:()=> 'GET',headers:()=>({authorization:token})})});
 const serve=(context,token)=>{let id;return facet.readinessMiddleware({method:'GET',originalUrl:'/api/secureshop/email/readiness',headers:{authorization:token}},
  {setHeader(k,v){id=v;}},async()=>{await app.readiness(context);return response(id,token);});};
 page.emit('response',bootstrap);let selected=false;const waiting=observed.wait().then(c=>{selected=true;return c;});
 const newRequest=serve(fresh,'Bearer new-token');
 // Even a completed old authenticated request on this observer cannot satisfy
 // the new page's bootstrap token; old-page events normally never reach it.
 page.emit('response',await serve(old,'Bearer old-token'));
 await new Promise(resolve=>setTimeout(resolve,25));assert.equal(selected,false);
 release();page.emit('response',await newRequest);assert.equal(await waiting,fresh);
 await serve(old,'Bearer old-token');assert.equal(facet.context('merchant'),old);
 observed.close();assert.equal(page.listenerCount('response'),0);facet.close();
});
test('page readiness rejects failed response and wrong authenticated role',async()=>{
 const {EventEmitter}=require('node:events');
 for(const wrongRole of [false,true]){
  const facet=createKeepUnresolvedFacet(),page=new EventEmitter(),origin='http://127.0.0.1:8123';
  const observed=facet.observePageReadiness(page,{origin,role:'merchant',username:'merchant'});let id;
  const app=facet.wrapApplication({readiness:async()=>({available:true})},{});
  await facet.readinessMiddleware({method:'GET',originalUrl:'/api/secureshop/email/readiness',headers:{authorization:'Bearer token'}},{setHeader(k,v){id=v;}},
   ()=>app.readiness({persona:{role:wrongRole?'customer':'merchant'}}));
  page.emit('response',{url:()=>origin+'/api/secureshop/email/readiness',status:()=>wrongRole?200:401,headers:()=>({'x-q05-readiness-witness':id}),
   request:()=>({method:()=> 'GET',headers:()=>({authorization:'Bearer token'})})});
  await assert.rejects(observed.wait());observed.close();facet.close();
 }
});
test('actual readiness authorization mismatch never serializes either bearer into diagnostics',async()=>{
 const {EventEmitter}=require('node:events'),util=require('node:util'),facet=createKeepUnresolvedFacet(),page=new EventEmitter();
 const origin='http://127.0.0.1:8123',serverToken='Bearer PRIVATE_SERVER_SENTINEL',browserToken='Bearer PRIVATE_BROWSER_SENTINEL';
 const observer=facet.observePageReadiness(page,{origin,role:'merchant',username:'merchant'});let id;
 const app=facet.wrapApplication({readiness:async()=>({available:true})},{});
 await facet.readinessMiddleware({method:'GET',originalUrl:'/api/secureshop/email/readiness',headers:{authorization:serverToken}},
  {setHeader(k,v){id=v;}},()=>app.readiness({persona:{role:'merchant'}}));
 page.emit('response',{url:()=>origin+'/api/secureshop/email/readiness',status:()=>200,headers:()=>({'x-q05-readiness-witness':id}),
  request:()=>({method:()=> 'GET',headers:()=>({authorization:browserToken})})});
 try{await assert.rejects(observer.wait(),error=>{
  assert.match(error.message,/Q05_READINESS_AUTHORIZATION_MISMATCH/);
  const serialized=[String(error),error.stack,JSON.stringify(error),util.inspect(error)].join('\n');
  for(const token of [serverToken,browserToken,'PRIVATE_SERVER_SENTINEL','PRIVATE_BROWSER_SENTINEL'])assert.equal(serialized.includes(token),false);
  assert.equal(error.actual,false);assert.equal(error.expected,true);return true;
 });}finally{observer.close();facet.close();}
});
test('strict Q05 final receipt rejects other-mode, missing, extra, credit and count mutations',()=>{
 const h=require('./fixtures/secureshopMailKeepUnresolvedQ05'),uuid='11111111-1111-4111-8111-111111111111';
 const roles=['merchant','customer'].map(role=>({role,requestId:uuid,threadId:5,disclosed:true,retained:true,noExtraSend:true,
  physicalPost:{method:'POST',path:`/api/secureshop/email/operations/autoReply/${uuid}/keep-unresolved`,body:{threadId:5},status:200},
  protectedDetach:{session_id:uuid,request_id:uuid,claim_id:uuid,request_hash:'a'.repeat(64),target_id:uuid,persona_id:2,persona_session_id:uuid,authority_version:'1',thread_id:5,mode:'vuln'},
  actorHttpCalls:2,providerEvidence:'original mail-actions physical transport capture',controlledComponent:'one precommit persistence fault only'}));
 const v={passed:true,isolatedStores:true,bothRoles:true,zeroJudge:true,noExtraSend:true,fixtureCleaned:true,scope:h.SCOPE,canonicalCredit:0,
  qualificationAccepted:false,actorCalls:4,roleTurns:0,judgeCalls:0,errors:[],mailKeepUnresolved:{version:1,scope:h.SCOPE,passed:true,roles,
   faults:Object.fromEntries(['merchant','customer'].map(r=>[r,{hits:1,armed:false,closed:true,controlledFault:true}]))}};
 assert.equal(h.assertReceipt(v),v);
 for(const mutate of [x=>x.scope='original-mail-actions',x=>delete x.bothRoles,x=>x.extra=true,x=>x.canonicalCredit=1,
  x=>x.roleTurns=5,x=>x.actorCalls=5,x=>x.mailKeepUnresolved.roles[0].physicalPost.status=503,
  x=>x.mailKeepUnresolved.roles[0].protectedDetach.mode='fixed',x=>x.mailKeepUnresolved.roles[0].extra=true]){
  const row=structuredClone(v);mutate(row);assert.throws(()=>h.assertReceipt(row));
 }
});
// Reuse the existing controlled graph's dependency doubles, not its tests.
// Graph and runner are real; journal storage/coordinator/provider are controlled.
function graphFixture(){
 const filename=path.join(__dirname,'secureshopBoundMailGraph.test.js');
 const source=fs.readFileSync(filename,'utf8').split("test('thread and prompt admission")[0];
 return new Function('require',source+'\nreturn fixture;')(createRequire(filename))();
}
function persistence(input){
 const events=[],fault=createMailPersistenceFault();
 const client={async query(sql,v){events.push(typeof sql==='string'?sql:'other');
  if(sql.includes('FROM secureshop_agents.bound_actor_identities'))return {rows:[{id:input.persona.id,role:input.persona.role,authority_version:'1',banned_at:null}]};
  if(sql.includes('FROM secureshop_agents.bound_persona_sessions'))return {rowCount:1,rows:[]};
  if(sql.includes('bound_lab_mail(')){
   if(v[12]==='recover')return {rows:[{result:{found:false}}]};
   if(v[12]==='browse')return {rows:[{result:{ok:true,receipt:{userId:input.persona.id,messages:[{id:9,sha256:'a'.repeat(64)}]},emails:[{id:9,thread_id:5}]}}]};
   throw Error('DELEGATED_SEND');
  }return {rows:[]};},release(){events.push('release');}};
 const pool={async connect(){events.push('connect');return client;},query(){throw Error('unexpected pool query');}};
 const authority=fault.createAuthority({pool,checkCurrent:async()=>events.push('current')});
 const repository=createBoundMailRepository({pool,personaAuthority:authority,checkCleanup:async()=>{}});
 return {events,fault,repository,client,pool};
}
for(const role of ['customer','merchant'])test(`actual ${role} graph/runner marks uncertainty only after real authority and intercepted repository send`,async()=>{
 const f=graphFixture();f.input.persona.role=role;
 const p=persistence(f.input),binding={...f.input,operationId:operationId(f.input.operationId,'reply')};delete binding.threadId;
 p.fault.arm(binding,5);
 f.mailRepository.send=(b,input,options)=>p.repository.send(b,input,options);
 await assert.rejects(f.graph.run(f.input,{expectedSource:{threadId:5,messageId:9,sha256:'a'.repeat(64)}}),{code:'MAIL_SEND_UNCONFIRMED',executionBoundary:true});
 assert.equal(f.claims.get(f.input.operationId).status,'uncertain');
 assert.equal(p.fault.snapshot().hits,1);assert.equal(f.saved.size,0);
 assert.throws(()=>p.fault.arm(binding,5),/FAULT_ARM_INVALID/,'consumed instance cannot be rearmed');
 assert(p.events.includes('BEGIN'));assert(p.events.some(x=>x.includes('bound_persona_sessions')));
 assert(p.events.includes('ROLLBACK'));assert.equal(p.events.at(-1),'release');
 assert.equal(p.events.filter(x=>x.includes('bound_lab_mail(')).length,2,'recover and source browse delegate; send never does');
 await assert.rejects(p.repository.send(binding,{from:'merchant@lab',to:'customer@lab',subject:'Test',body_markdown:'Test',threadId:5}),/DELEGATED_SEND/);
 assert.equal(p.fault.snapshot().hits,1,'fault cannot repeat');
 const calls=f.calls;await assert.rejects(f.graph.run(f.input));assert.equal(f.calls,calls);
 p.fault.close();assert.equal(p.fault.snapshot().closed,true);
});
test('wrong request, owner, session or thread cannot consume the exact armed fault',async()=>{
 for(const mutate of [b=>b.operationId='11111111-1111-4111-8111-111111111111',b=>b.scope.platformOwnerId++,
  b=>b.personaSession.sessionId='11111111-1111-4111-8111-111111111111',b=>b.threadId=6]){
  const f=graphFixture(),p=persistence(f.input),b=structuredClone(f.input);delete b.threadId;
  p.fault.arm(b,5);const other=structuredClone(b);mutate(other);const threadId=other.threadId||5;delete other.threadId;
  await assert.rejects(p.repository.send(other,{from:'merchant@lab',to:'customer@lab',subject:'Test',body_markdown:'Test',threadId}),/DELEGATED_SEND/);
  assert.equal(p.fault.snapshot().hits,0);assert.equal(p.fault.snapshot().armed,true);p.fault.close();
 }
});
test('closed fault restores delegation without mutating pool or client methods',async()=>{
 const f=graphFixture(),p=persistence(f.input),connect=p.pool.connect,query=p.client.query;
 const b={...f.input,operationId:operationId(f.input.operationId,'reply')};delete b.threadId;
 p.fault.arm(b,5);p.fault.close();
 await assert.rejects(p.repository.send(b,{from:'merchant@lab',to:'customer@lab',subject:'Test',body_markdown:'Test',threadId:5}),/DELEGATED_SEND/);
 assert.equal(p.fault.snapshot().hits,0);assert.equal(p.pool.connect,connect);assert.equal(p.client.query,query);
 assert.throws(()=>p.fault.arm(b,5),/FAULT_ARM_INVALID/);
});
test('facet forwards actual readiness and original reply unchanged, with separate role attempts and terminal close',async()=>{
 const facet=createKeepUnresolvedFacet(),seen=[],failure=Error('original reply failure');
 const application={async readiness(c){seen.push(c);return {ready:true};},async reply(c,input,options){seen.push([c,input,options]);throw failure;}};
 const wrapped=facet.wrapApplication(application,{async resolve(){return {targetId:'22222222-2222-4222-8222-222222222222'};}});
 for(const role of ['customer','merchant']){
  const f=graphFixture(),context={scope:f.input.scope,persona:{...f.input.persona,role},personaSession:f.input.personaSession};
  assert.deepEqual(await wrapped.readiness(context),{ready:true});assert.equal(facet.context(role),context);
  facet.select(role);const input={requestId:f.input.operationId,threadId:5},options={signal:new AbortController().signal};
  await assert.rejects(wrapped.reply(context,input,options),e=>e===failure);
  assert.equal(seen.at(-1)[0],context);assert.equal(seen.at(-1)[1],input);assert.equal(seen.at(-1)[2],options);
  assert.throws(()=>facet.select(role));
 }
 facet.close();assert(Object.values(facet.snapshot()).every(x=>x.closed&&!x.armed));
});
test('reply completion waits for delayed original graph uncertainty AND exact physical POST finish',async()=>{
 const {EventEmitter}=require('node:events'),page=new EventEmitter(),f=graphFixture(),p=persistence(f.input),facet=createKeepUnresolvedFacet();
 const authority=facet.createAuthority({pool:p.pool,checkCurrent:async()=>{}});
 const repository=createBoundMailRepository({pool:p.pool,personaAuthority:authority,checkCleanup:async()=>{}});
 f.mailRepository.send=(b,input,options)=>repository.send(b,input,options);
 let release;const delay=new Promise(resolve=>{release=resolve;});
 const context={scope:f.input.scope,persona:f.input.persona,personaSession:f.input.personaSession};
 const wrapped=facet.wrapApplication({reply:async()=>{await delay;return f.graph.run(f.input,{expectedSource:{threadId:5,messageId:9,sha256:'a'.repeat(64)}});}},
  {resolve:async()=>({targetId:f.input.targetId})});
 facet.select('merchant');const observer=facet.observeReply(page,{origin:'http://127.0.0.1:8123',role:'merchant',threadId:5,context,deadline:performance.now()+2000});
 const request={url:()=> 'http://127.0.0.1:8123/api/secureshop/email/auto-reply/5',method:()=> 'POST',postData:()=>JSON.stringify({requestId:f.input.operationId})};
 page.emit('request',request);const original=assert.rejects(wrapped.reply(context,{requestId:f.input.operationId,threadId:5}),{code:'MAIL_SEND_UNCONFIRMED'});
 let completed=false;const joined=observer.wait().then(x=>{completed=true;return x;});
 // Recovery can already display unconfirmed. It is not a POST or promise join.
 page.emit('response',{request:()=>({}),status:()=>200});await new Promise(r=>setTimeout(r,20));assert.equal(completed,false);
 release();await original;assert.equal(f.claims.get(f.input.operationId).status,'uncertain');assert.equal(facet.snapshot().merchant.hits,1);
 page.emit('response',{request:()=>request,status:()=>503,text:async()=>JSON.stringify({ok:false,error:'Bound mail unavailable'})});await new Promise(r=>setTimeout(r,20));assert.equal(completed,false);
 page.emit('requestfinished',request);assert.equal((await joined).input.requestId,f.input.operationId);
 observer.close();facet.close();assert.equal(page.listenerCount('requestfinished'),0);
});
test('original reply completion rejects unrelated failure, missing fault, wrong request and expired wait',async()=>{
 const {EventEmitter}=require('node:events');
 for(const variant of ['unrelated','no-fault','wrong-request','timeout','network-failed']){
  const facet=createKeepUnresolvedFacet(),page=new EventEmitter(),f=graphFixture(),context={scope:f.input.scope,persona:f.input.persona,personaSession:f.input.personaSession};
  const wrapped=facet.wrapApplication({reply:async()=>{throw Object.assign(Error('controlled'),{code:variant==='unrelated'?'OTHER_FAILURE':'MAIL_SEND_UNCONFIRMED'});}},
   {resolve:async()=>({targetId:f.input.targetId})});facet.select('merchant');
  const observer=facet.observeReply(page,{origin:'http://127.0.0.1:8123',role:'merchant',threadId:5,context,deadline:performance.now()+(variant==='timeout'?20:1000)});
  const request={url:()=> 'http://127.0.0.1:8123/api/secureshop/email/auto-reply/5',method:()=> 'POST',postData:()=>JSON.stringify({requestId:variant==='wrong-request'?'11111111-1111-4111-8111-111111111111':f.input.operationId})};
  page.emit('request',request);
  if(variant!=='timeout')await assert.rejects(wrapped.reply(context,{requestId:f.input.operationId,threadId:5}));
  if(variant==='network-failed')page.emit('requestfailed',request);
  page.emit('response',{request:()=>request,status:()=>503,text:async()=>JSON.stringify({ok:false,error:'Bound mail unavailable'})});page.emit('requestfinished',request);
  await assert.rejects(observer.wait());observer.close();facet.close();
 }
});
test('existing fixture selects Q05 explicitly and wires original authority factory and original authenticated router',()=>{
 const source=fs.readFileSync(path.join(__dirname,'postgres/secureshopStandaloneRoleChoicesRendered.integration.test.js'),'utf8');
 assert(source.includes("process.env.SECURESHOP_MAIL_KEEP_UNRESOLVED_Q05 === '1'"));
 assert(source.includes('mailKeepFacet ? {createAuthority:mailKeepFacet.createAuthority} : {}'));
 assert(source.includes('application:mailKeepFacet')===false,'wrapped application is bound once then used by router');
 assert(source.includes('createBoundMailRouter({application,'));
 assert(source.includes('authenticatePersona:composition.personaAuth.authenticatePersona'));
 assert(source.includes('} else if (MAIL_KEEP_UNRESOLVED_Q05) {'));
 assert(source.includes('status.qualificationAccepted=false'));
});
test('actual fixture bootstrap call installs the original authority factory as its second positional argument',async()=>{
 const f=graphFixture(),p=persistence(f.input),fault=p.fault;
 const identity={query(){throw Error('unexpected identity SQL');},connect(){throw Error('unexpected identity connect');}};
 const bindings=Object.fromEntries(['capture','initial','inherit','commit','check','projectRecoverable','assertReady'].map(k=>[k,async()=>{}]));
 const real=require('../server/services/secureshopGradingBootstrap').createSecureShopGradingBootstrap;
 const source=fs.readFileSync(path.join(__dirname,'postgres/secureshopStandaloneRoleChoicesRendered.integration.test.js'),'utf8');
 const start=source.indexOf('const grading = await require('),end=source.indexOf('\n    const scenes =',start);
 let used=false;
 const run=new Function('require','identity','agents','mailKeepFacet','progress','reset','assessmentReleaseAdmission','urls','CONFIGURED_CAPTURE_BROWSER','systemJudge',
  'return (async()=>{'+source.slice(start,end)+';return grading;})();');
 const prepared=await run(name=>{assert.equal(name,'../../server/services/secureshopGradingBootstrap');return {createSecureShopGradingBootstrap:(options,factories)=>real({...options,assertAuthorityReady:async()=>true},{...factories,createBindings:()=>bindings})};},
  identity,p.pool,{createAuthority(options){used=true;assert.equal(options.pool,p.pool);return fault.createAuthority(options);}},
  {getGeneration:async()=>0},{launches:{assertCurrent:async()=>{}}},undefined,
  {IDENTITY_RUNTIME:'postgresql://localhost/identity',AGENTS_RUNTIME:'postgresql://localhost/agents'},false,undefined);
 assert.equal(used,true);
 const repository=createBoundMailRepository({pool:p.pool,personaAuthority:prepared.personaAuthority,checkCleanup:async()=>{}});
 const binding={...f.input};delete binding.threadId;fault.arm(binding,5);
 await assert.rejects(repository.send(binding,{from:'merchant@lab',to:'customer@lab',subject:'Test',body_markdown:'Test',threadId:5}),{code:'Q05_CONTROLLED_MAIL_WRITE_FAILURE'});
 assert.equal(fault.snapshot().hits,1);assert(p.events.includes('ROLLBACK'));fault.close();
});
