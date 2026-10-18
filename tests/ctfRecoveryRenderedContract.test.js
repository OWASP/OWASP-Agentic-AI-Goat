'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs');
const read=p=>fs.readFileSync(p,'utf8');
const helper=read('tests/postgres/support/ctfRecoveryRenderedCases.js');
test('rendered branch retains ordinary application and direct SQL recovery fixture branches',()=>{
 const fixture=read('tests/postgres/ctfAuthorityApplication.integration.test.js');
 assert(fixture.includes("CTF_RECOVERY_RENDERED_ISOLATED==='1'"));
 assert(fixture.includes("require('./support/ctfRecoveryRenderedCases')"));
 assert(fixture.includes("require('./support/ctfPredefenseRecoveryCases')"));
 assert(fixture.includes('all thirty-two HTTP surfaces'));
});
test('rendered entry imports actual page and obtains actual authenticated stage projection',()=>{
 const entry=read('tests/postgres/support/ctfRecoveryRenderedEntry.jsx');
 assert(entry.includes("import CTFChallenge from './src/pages/CTFChallenge'"));
 assert(entry.includes("fetch('/api/ctf/stages'"));assert(entry.includes('state: { stage }'));
 assert(!/mock|interceptResponse|setRequestHandler/.test(entry));
 assert(helper.includes('initial recovery is read-only'));assert(helper.includes("body.blocked,true"));assert(helper.includes('body.success,false'));
 assert(helper.includes("UPDATE identity.user_sessions SET is_active=0"));assert(helper.includes("mutate(admin,'owner_reset'"));
 assert(helper.includes("assert.equal(ledger.length,calls"));assert(helper.includes('beforeSibling'));
});
test('browser remains in owned process group with bounded endpoint, network, and cancellation cleanup',()=>{
 assert(!helper.includes('detached:true'));assert(helper.includes('--remote-debugging-address=127.0.0.1'));
 assert(helper.includes('--disable-extensions'));assert(helper.includes('Owned browser endpoint deadline'));
 assert(helper.includes("child.once('error',errorHandler)"));assert(helper.includes("child.once('exit',exitHandler)"));
 assert(helper.includes('r.abort()'));assert(helper.includes('cancelled=true;reject'));
 assert(helper.includes("active();const owner"));assert(helper.includes('casesTask.then(()=>true,()=>true)'));
 assert(helper.includes("throw new AggregateError([primary,error]"));
 assert(helper.includes("lateHintRace:'component control only'"));
});

test('closed full-App content receipt distinguishes projections from genuine credit and enforces ceilings',()=>{
 const {assertContentReceipt,CONTENT_LIMITS}=require('./postgres/support/ctfRecoveryRenderedCases');
 const receipt={version:1,profile:'ctf-ten-content',modelCalls:0,judgeCalls:0,genuineCredit:0,controlledProjectionCount:55,controlledProjectionCountPerStore:55,controlledProjectionCountTotal:110,projectionStoreCount:2,prerequisiteProjectionCount:45,displayProjectionCount:10,cases:Array.from({length:10},(_,n)=>({stage:n+1,label:true,hints:true,adminSolution:true})),browserActions:CONTENT_LIMITS.browserActions,apiRequests:CONTENT_LIMITS.apiRequests,unexpectedApiPaths:[]};
 for(const k of ['hintGate','adminMutation','progressParity','restored','siblingPreserved','populatedReadback','sessionDenied','ownerReset','immutablePreserved','browserRetired'])receipt[k]=true;
 assert.doesNotThrow(()=>assertContentReceipt(receipt));
 for(const change of [{genuineCredit:1},{modelCalls:1},{controlledProjectionCount:10},{apiRequests:1201},{browserActions:1601},{cases:receipt.cases.slice(1)},{restored:false},{unexpectedApiPaths:[{path:'/api/unknown'}]}])assert.throws(()=>assertContentReceipt({...receipt,...change}));
});
test('content API closure admits canonical bootstrap and paid-hint routes, denies inference and unrelated mutation',()=>{
 const {contentApiAllowed}=require('./postgres/support/ctfRecoveryRenderedCases');
 for(const path of ['/api/auth/status','/api/workshop/config/snapshot','/api/changes/revisions','/api/ctf/admin/solutions','/api/admin/xss-workshop/objective-solutions'])assert(contentApiAllowed('GET',path),path);
 assert(contentApiAllowed('POST','/api/ctf/stage/10/hint'));
 for(const [method,path]of [['POST','/api/ctf/stage/10/attempt'],['GET','/api/ctf/admin/secrets'],['POST','/api/admin/users/1/delete'],['GET','/api/unknown'],['GET','/api/ctf/admin/solutions/extra']])assert.equal(contentApiAllowed(method,path),false,path);
});
test('expanded solution oracle requires the exact level card and rejects background payload matches',()=>{
 const {contentSolutionMatches}=require('./postgres/support/ctfRecoveryRenderedCases');
 const old=global.document;
 try{
  const card={children:[{},{}],innerText:'L1 Guardian Defenses: none exact payload'},button={textContent:'L1 Guardian Defenses: none',querySelector:()=>({textContent:'L1'}),parentElement:card};
  global.document={querySelectorAll:()=>[button]};assert(contentSolutionMatches({level:1,values:['exact payload']}));
  assert.equal(contentSolutionMatches({level:2,values:['exact payload']}),false);
  card.children=[{}];assert.equal(contentSolutionMatches({level:1,values:['exact payload']}),false);
  card.children=[{},{}];card.innerText='L1 Guardian Defenses: none';assert.equal(contentSolutionMatches({level:1,values:['exact payload']}),false);
 }finally{if(old===undefined)delete global.document;else global.document=old;}
});

test('challenge back navigation selects the unique top-bar button despite the footer duplicate',()=>{
 const {contentBackButton}=require('./postgres/support/ctfRecoveryRenderedCases');const old=global.document;
 try{
  const top={tagName:'BUTTON',textContent:'Back to Dashboard',getClientRects:()=>[{}]},footer={...top};
  const bar={children:[top,{},{}]},title={textContent:'Guardian',parentElement:{parentElement:bar}};
  global.document={querySelectorAll:selector=>selector==='h1'?[title]:[top,footer]};
  assert.equal(contentBackButton('Guardian'),top);assert.equal(contentBackButton('Other'),null);
  bar.children.push({...top});assert.equal(contentBackButton('Guardian'),null);
  bar.children.pop();top.getClientRects=()=>[];assert.equal(contentBackButton('Guardian'),null);
 }finally{if(old===undefined)delete global.document;else global.document=old;}
});

test('loaded main source closure rejects unpinned and changed modules',()=>{
 const {assertContentLoadedSources}=require('./postgres/support/ctfRecoveryRenderedCases');
 const path=require('node:path'),root=path.resolve(__dirname,'..'),file=__filename,relative=path.relative(root,file),digest=require('node:crypto').createHash('sha256').update(fs.readFileSync(file)).digest('hex');
 assert.equal(assertContentLoadedSources(root,{[relative]:{kind:'file',sha256:digest}},[file]),1);
 assert.throws(()=>assertContentLoadedSources(root,{},[file]));
 assert.throws(()=>assertContentLoadedSources(root,{[relative]:{kind:'file',sha256:'0'.repeat(64)}},[file]));
});

test('content diagnostics retain bounded path/status without URL credentials, query or raw failures',()=>{
 const {contentDiagnosticEvent}=require('./postgres/support/ctfRecoveryRenderedCases');
 const e=contentDiagnosticEvent('failed','http://secret:password@127.0.0.1:1234/assets/app.js?token=private#fragment',{failure:'net::ERR_ABORTED',resourceType:'script',status:404});
 assert.deepEqual(e,{kind:'failed',pathname:'/assets/app.js',status:404,resourceType:'script',failure:'net::ERR_ABORTED'});
 assert.equal(contentDiagnosticEvent('failed','invalid',{failure:'token private'}).failure,'[redacted]');
 assert(contentDiagnosticEvent('response','http://localhost/'+ 'a'.repeat(500)).pathname.length<=180);
});

test('content browser reuses the owned launcher and journals its real identity with close on invalid receipt',async()=>{
 const {launchContentBrowser}=require('./postgres/support/ctfRecoveryRenderedCases');const path=require('node:path'),os=require('node:os');
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'ctf-browser-contract-')),prior=[process.env.ANALYTICS_BROWSER_EXECUTABLE,process.env.PUPPETEER_EXECUTABLE_PATH];let closes=0;
 try{process.env.ANALYTICS_BROWSER_EXECUTABLE=process.env.PUPPETEER_EXECUTABLE_PATH='/owned/chrome';
  const browser={close:async()=>{closes++;}},records=[];
  const launch=async(directory,label)=>{assert.equal(directory,root);assert.equal(label,'content');fs.writeFileSync(path.join(root,'content-process.json'),JSON.stringify({pid:1234}));return browser;};
  assert.equal(await launchContentBrowser(root,x=>records.push(x),launch),browser);assert.deepEqual(records,[{kind:'browser',pid:1234}]);
  await assert.rejects(launchContentBrowser(root,()=>{},async()=>{fs.writeFileSync(path.join(root,'content-process.json'),'{}');return browser;}));assert.equal(closes,1);
 }finally{for(const [n,v]of [['ANALYTICS_BROWSER_EXECUTABLE',prior[0]],['PUPPETEER_EXECUTABLE_PATH',prior[1]]])if(v===undefined)delete process.env[n];else process.env[n]=v;fs.rmSync(root,{recursive:true,force:true});}
});

test('canonical hint denial and exact instructor bootstrap reads retain closed admission',()=>{
 const {assertContentHintDenied,contentApiAllowed}=require('./postgres/support/ctfRecoveryRenderedCases');
 assert.doesNotThrow(()=>assertContentHintDenied({status:409,body:{error:'Hint availability changed; refresh stage status'}}));
 for(const value of [{status:403,body:{error:'Hint availability changed; refresh stage status'}},{status:409,body:{error:'other'}},{status:200,body:{}}])assert.throws(()=>assertContentHintDenied(value));
 for(const path of ['/api/admin/solutions','/api/admin/activity-stats','/api/admin/activity-logs']){assert(contentApiAllowed('GET',path));assert.equal(contentApiAllowed('POST',path),false);assert.equal(contentApiAllowed('GET',path+'/extra'),false);}
});

test('content cleanup preserves primary failure and restores before closing mounted services',async()=>{
 const {finishContent,contentFailure,contentRuntimeStatus,contentApiAllowed}=require('./postgres/support/ctfRecoveryRenderedCases');
 const primary=Object.assign(new Error('PRIVATE token'),{name:'TimeoutError',code:'PRIVATE'}),events=[],records=[];
 await assert.rejects(finishContent({primary,retire:async()=>events.push('retire'),restore:async()=>{events.push('restore');throw Object.assign(Error('PRIVATE restoration'),{code:'ERR_ASSERTION'});},close:async()=>events.push('close'),finish:async()=>events.push('finish'),record:x=>records.push(x)}),e=>e===primary);
 assert.deepEqual(events,['retire','restore','close','finish']);assert.deepEqual(records.map(({location,...v})=>v),[{phase:'restore',name:'Error',code:'ERR_ASSERTION'}]);assert.equal(records[0].location.file,'ctfRecoveryRenderedCases.js');assert(!JSON.stringify(records).includes('PRIVATE'));assert.deepEqual(contentFailure(primary),{name:'TimeoutError'});
 const secondary=[];await assert.rejects(finishContent({retire:async()=>{throw Error('retire');},restore:async()=>secondary.push('restore'),close:async()=>secondary.push('close'),finish:async()=>secondary.push('finish'),record:()=>{}}),AggregateError);assert.deepEqual(secondary,['restore','close','finish']);
 assert.deepEqual(contentRuntimeStatus({state:'running',requests:2,secret:'PRIVATE',worker:{state:'paused',active:false,lastOutcome:'failed',secret:'PRIVATE'}}),{state:'running',requests:2,worker:{state:'paused',active:false,lastOutcome:'failed'}});
 assert(contentApiAllowed('GET','/api/workshop/time/summary'));assert.equal(contentApiAllowed('POST','/api/workshop/time/summary'),false);assert.equal(contentApiAllowed('GET','/api/workshop/time/summary/extra'),false);
});


test('content pointer uses instant scroll and waits for exact hit before one physical click',async()=>{
 const {contentPointerClick}=require('./postgres/support/ctfRecoveryRenderedCases');
 const events=[];let predicate;
 const element={isConnected:true,disabled:false,scrollIntoView:o=>{assert.deepEqual(o,{behavior:'instant',block:'center',inline:'center'});events.push('scroll');},getBoundingClientRect:()=>({x:10,y:10,width:20,height:20}),contains:()=>false};
 const handle={evaluate:async fn=>fn(element),asElement:()=>({click:async()=>events.push('click')})};
 const page={waitForFunction:async(fn,options,target)=>{assert.equal(options.timeout,15000);assert.equal(target,handle);predicate=fn;events.push('wait');return{dispose:async()=>events.push('dispose')};}};
 await contentPointerClick(page,handle,fn=>fn());assert.deepEqual(events,['scroll','wait','dispose','click']);
 const old=[global.document,global.innerWidth,global.innerHeight];
 try{global.innerWidth=100;global.innerHeight=100;global.document={elementFromPoint:()=>element};assert.equal(predicate(element),true);global.document.elementFromPoint=()=>({});assert.equal(predicate(element),false);element.disabled=true;assert.equal(predicate(element),false);}
 finally{for(const [k,v]of [['document',old[0]],['innerWidth',old[1]],['innerHeight',old[2]]])if(v===undefined)delete global[k];else global[k]=v;}
 events.length=0;await assert.rejects(contentPointerClick({...page,waitForFunction:async()=>{throw Error('blocked pointer');}},handle,fn=>fn()),/blocked pointer/);assert.deepEqual(events,['scroll']);
});


test('hint purchase selector binds exact own indexed label and canonical price span',()=>{
 const {contentHintButton}=require('./postgres/support/ctfRecoveryRenderedCases');const old=global.document;
 const make=(label='Unlock Hint 1',price='(-15 pts)')=>({childNodes:[{nodeType:1,textContent:'icon'},{nodeType:3,textContent:' '+label+' '}],children:[{tagName:'svg'},{tagName:'SPAN',textContent:price}],getClientRects:()=>[{}]});
 try{let buttons=[make()];global.document={querySelectorAll:selector=>{assert.equal(selector,'button');return buttons;}};
  assert.equal(contentHintButton({index:1,cost:15}),buttons[0]);assert.equal(contentHintButton({index:2,cost:15}),null);assert.equal(contentHintButton({index:1,cost:25}),null);
  for(const bad of [make('Unlock Hint 10'),make('Other Unlock Hint 1'),make('Unlock Hint 1','(-15 pts) extra'),{...make(),getClientRects:()=>[]}, {...make(),children:[{tagName:'SPAN',textContent:'(-15 pts)'},{tagName:'SPAN',textContent:'extra'}]}]){buttons=[bad];assert.equal(contentHintButton({index:1,cost:15}),null);}
  buttons=[make(),make()];assert.equal(contentHintButton({index:1,cost:15}),null);
 }finally{if(old===undefined)delete global.document;else global.document=old;}
});


test('content actors use separate contexts and retire every context despite failures',async()=>{
 const {contentActorPages}=require('./postgres/support/ctfRecoveryRenderedCases');let next=0;const contexts=[],closed=[];
 const browser={createBrowserContext:async()=>{const id=++next,storage=new Map(),context={newPage:async()=>({id,storage}),close:async()=>{closed.push(id);if(id===3)throw Error('close failed');}};contexts.push(context);return context;}};
 const actors=contentActorPages(browser),admin=await actors.newPage(),learner=await actors.newPage();admin.storage.set('token','admin');learner.storage.set('token','learner');assert.equal(admin.storage.get('token'),'admin');assert.notEqual(admin.id,learner.id);
 await actors.closePage(learner);assert.deepEqual(closed,[2]);await actors.newPage();await actors.newPage();await assert.rejects(actors.close(),AggregateError);assert.deepEqual(closed,[2,1,3,4]);
 const failed=[];const broken=contentActorPages({createBrowserContext:async()=>({newPage:async()=>{throw Error('page failed');},close:async()=>failed.push('closed')})});await assert.rejects(broken.newPage(),/page failed/);await broken.close();assert.deepEqual(failed,['closed']);
});
