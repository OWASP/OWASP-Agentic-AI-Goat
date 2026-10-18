'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {allowedRequest,assertContent,learnerMatches,LIMITS}=require('./fixtures/mcpAuditContentBrowser');
test('content network policy denies model/tool/reset and nonowned hosts at exact request cap',()=>{
 const origin='http://127.0.0.1:12345';assert(allowedRequest(origin+'/api/hints/mcp_workshop/status',origin,LIMITS.browser));assert(!allowedRequest(origin,origin,LIMITS.browser+1));
 for(const suffix of ['chat','jsonrpc','progress/reset','progress/complete','shadow-source/write'])assert(!allowedRequest(origin+'/api/workshop/mcp/'+suffix,origin,1));
 assert(!allowedRequest('http://127.0.0.1:11434/api/chat',origin,1));assert(!allowedRequest('https://example.invalid/',origin,1));
});
test('all three exact content fields reject substitution, dropped content and SQL-null loss',()=>{
 const value={label:'Owned label',hint_content:{hints:['exact hint']},solution_content:{approach:'exact solution'}};assertContent(structuredClone(value),value);
 for(const field of Object.keys(value)){assert.throws(()=>assertContent({...value,[field]:null},value));assert.throws(()=>assertContent({...value,[field]:'other'},value));}
 assertContent({...value,hint_content:null},{...value,hint_content:null});assert.throws(()=>assertContent({...value,hint_content:{}},{...value,hint_content:null}));
});
test('actual DOM oracle requires unique exact label and independent effective disclosure buttons',()=>{
 const {JSDOM}=require('../client/node_modules/jsdom');const dom=new JSDOM('<div class="obj-content"><div class="obj-name">Audit label</div><button>View Hint</button></div>');const previous=global.document;global.document=dom.window.document;
 try{assert(learnerMatches({label:'Audit label',hint:true,solution:false}));assert(!learnerMatches({label:'Audit label',hint:false,solution:true}));assert(!learnerMatches({label:'Wrong label',hint:true,solution:false}));document.body.insertAdjacentHTML('beforeend',document.body.innerHTML);assert(!learnerMatches({label:'Audit label',hint:true,solution:false}));}finally{global.document=previous;dom.window.close();}
});

test('admin challenge card identity is the canonical challenge key, distinct from content workshop key',()=>{
 const {KEY,ADMIN_KEY}=require('./fixtures/mcpAuditContentBrowser');assert.equal(require('../server/config/workshopCatalog').toChallengeKey(KEY),ADMIN_KEY);assert.notEqual(KEY,ADMIN_KEY);
});

test('admin navigation reuses loaded page and closes real preview/objective controls without reload',async()=>{
 const {prepareAdminPage,closeAdminDialogs,adminDialogsClosed}=require('./fixtures/mcpAuditContentBrowser');let current='about:blank',navigations=0,closes=0;
 const page={url:()=>current,goto:async url=>{current=url;navigations++;},waitForSelector:async selector=>assert.match(selector,/mcp_server_rce/),evaluate:async fn=>{assert.equal(fn,closeAdminDialogs);closes++;},waitForFunction:async fn=>assert.equal(fn,adminDialogsClosed)};
 for(let i=0;i<10;i++)await prepareAdminPage(page,'http://127.0.0.1:12345');assert.equal(navigations,1);assert.equal(closes,10);
});
test('actual admin close selectors reject ambiguous dialogs and never click reset/cancel actions',()=>{
 const {JSDOM}=require('../client/node_modules/jsdom'),{closeAdminDialogs,adminDialogsClosed}=require('./fixtures/mcpAuditContentBrowser');const previous=global.document,dom=new JSDOM('<section id="preview"><button>Close Preview</button></section><section id="objectives"><header><h3>Objectives — MCP</h3><button>×</button></header><button>Reset Progress</button></section>');global.document=dom.window.document;let forbidden=0;
 try{document.querySelector('#preview button').onclick=()=>document.querySelector('#preview').remove();document.querySelector('header button').onclick=()=>document.querySelector('#objectives').remove();document.querySelector('#objectives > button').onclick=()=>forbidden++;assert.equal(adminDialogsClosed(),false);closeAdminDialogs();assert.equal(adminDialogsClosed(),true);assert.equal(forbidden,0);document.body.innerHTML='<button>Close Preview</button><button>Close Preview</button>';assert.throws(closeAdminDialogs,/Ambiguous/);}finally{global.document=previous;dom.window.close();}
});

test('master mutation waits for unique enabled control and denies persistent pending state',async()=>{
 const {JSDOM}=require('../client/node_modules/jsdom'),{masterReady,waitMasterReady}=require('./fixtures/mcpAuditContentBrowser');const prior=global.document,dom=new JSDOM('<div data-control="solutions" aria-disabled="true"></div>');global.document=dom.window.document;const selector='[data-control="solutions"]';let clicked=false;
 try{const page={waitForFunction:async(fn,options,arg)=>{assert.equal(options.timeout,15000);assert.equal(fn(arg),false);assert.equal(clicked,false);document.querySelector(arg).setAttribute('aria-disabled','false');assert.equal(fn(arg),true);}};await waitMasterReady(page,selector);clicked=true;assert(masterReady(selector));document.body.insertAdjacentHTML('beforeend',document.body.innerHTML);assert.equal(masterReady(selector),false);await assert.rejects(waitMasterReady({waitForFunction:async()=>{throw Error('timeout');}},selector),{code:'MCP_MASTER_MUTATION_STALE'});}finally{global.document=prior;dom.window.close();}
});

test('learner gate synchronization keeps mounted page; direct SQL seed phases explicitly reload',async()=>{
 const {viewLearner,learnerMatches}=require('./fixtures/mcpAuditContentBrowser');let current='about:blank',navigations=0;const observed=[];
 const page={url:()=>current,goto:async url=>{current=url;navigations++;},waitForFunction:async(fn,options,expected)=>{assert.equal(fn,learnerMatches);observed.push(expected);}};
 const origin='http://127.0.0.1:12345',on={label:'audit',hint:true,solution:true};await viewLearner(page,origin,on);
 for(const kind of ['hint','solution']){await viewLearner(page,origin,{...on,[kind]:false});await viewLearner(page,origin,on);}assert.equal(navigations,1);assert.equal(observed.length,5);
 await viewLearner(page,origin,{...on,label:'custom'},{reload:true});await viewLearner(page,origin,{label:'custom',hint:false,solution:false},{reload:true});assert.equal(navigations,3);assert.deepEqual(observed.at(-1),{label:'custom',hint:false,solution:false});
});

test('typed content fixture uses exact editor PUT and waits for persisted save before closing',async()=>{
 const {editContentTitle}=require('./fixtures/mcpAuditContentBrowser');
 for(const kind of ['hint','solution']){const events=[];let predicate,value='Original title',focused=false,selected=false;const request={method:()=> 'PUT',postData:()=>JSON.stringify({title:'Typed title'})};const response={url:()=> 'http://127.0.0.1/api/admin/exercises/mcp_workshop/objectives/mcp_audit_gap/'+kind,request:()=>request,status:()=>200};
 const page={keyboard:{press:async key=>{events.push(['key',key]);if(key==='Backspace')value=focused&&selected?'':value.slice(0,-1);selected=false;}},click:async selector=>events.push(['click',selector]),type:async(selector,text)=>{value+=text;events.push(['type',text]);},waitForSelector:async(selector,options)=>events.push(['wait',options?.hidden===true]),waitForResponse:fn=>{predicate=fn;return Promise.resolve(response);},$eval:async(selector,fn)=>{if(selector.endsWith('input')||selector.endsWith('title'))return fn({get value(){return value;},focus(){focused=true;events.push(['focus']);},select(){assert(focused);selected=true;events.push(['select']);}});events.push(['save']);}};
 await editContentTitle(page,kind,'Typed title');assert(predicate(response));assert(!predicate({...response,request:()=>({...request,method:()=> 'POST'})}));assert.deepEqual(events.at(-1),['wait',true]);assert(events.findIndex(e=>e[0]==='key'&&e[1]==='Backspace')<events.findIndex(e=>e[0]==='type'));assert(events.findIndex(e=>e[0]==='focus')<events.findIndex(e=>e[0]==='select'));assert(events.findIndex(e=>e[0]==='select')<events.findIndex(e=>e[0]==='key'&&e[1]==='Backspace'));assert(events.some(e=>e[0]==='type'&&e[1]==='Typed title'));
 await assert.rejects(editContentTitle({...page,$eval:async()=> 'wrong title'},kind,'Typed title'),{code:'MCP_EDITOR_CLEAR_MISMATCH'});
 await assert.rejects(editContentTitle({...page,waitForResponse:()=>Promise.resolve({...response,status:()=>400})},kind,'Typed title'));
 }
});

test('bounded failure metadata retains frames after multiline assertion without exposing values',()=>{
 const {safeFailure}=require('./fixtures/mcpAuditContentBrowser');const error={name:'AssertionError',code:'ERR_ASSERTION',operator:'deepStrictEqual',actual:'private-actual',expected:'private-expected',stack:'AssertionError\n'+Array(20).fill('private-value').join('\n')+'\n at assertContent (/main/tests/fixtures/mcpAuditContentBrowser.js:6:90)\n at run (/main/tests/fixtures/mcpAuditContentBrowser.js:80:5)'};
 const value=safeFailure(error);assert.deepEqual(value.frames,['tests/fixtures/mcpAuditContentBrowser.js:6:90','tests/fixtures/mcpAuditContentBrowser.js:80:5']);assert.equal(value.operator,'deepStrictEqual');assert(!JSON.stringify(value).includes('private'));assert.equal(safeFailure({...error,code:'private value',operator:'private value'}).code,null);
});


test('unused page retirement awaits bounded physical close and rejects unresolved closure',async()=>{
 const {retireUnusedPage}=require('./fixtures/mcpAuditContentBrowser');
 let closed=false,resolveClose;const events=[];const pending=new Promise(resolve=>{resolveClose=()=>{closed=true;events.push('closed');resolve();};});
 const page={close:()=>{events.push('close');return pending;},isClosed:()=>closed};
 let finished=false;const work=retireUnusedPage(page,async(promise,ms,label)=>{assert.equal(ms,10000);assert.equal(label,'MCP unused page retirement');return promise;}).then(()=>{finished=true;});
 await Promise.resolve();assert.equal(finished,false);assert.deepEqual(events,['close']);resolveClose();await work;assert.equal(finished,true);
 await assert.rejects(retireUnusedPage({close:async()=>{},isClosed:()=>false},p=>p),/must be closed/);
 await assert.rejects(retireUnusedPage({close:async()=>{throw Error('close failed');},isClosed:()=>false},p=>p),/close failed/);
});

test('focused content modals require complete seeded text inside the current modal, including all example explanations',()=>{
 const {JSDOM}=require('../client/node_modules/jsdom'),{focusedModalMatches}=require('./fixtures/mcpAuditContentBrowser'),dom=new JSDOM(''),previous=global.document;global.document=dom.window.document;
 const value={title:'Exact content',difficulty:'Hard',approach:'Exact approach',hints:['first hint','second hint'],examples:[{prompt:'read ticket',explanation:'Exact explanation'}],tips:['Exact tip']};
 const escape=x=>x.replace(/&/g,'&amp;').replace(/</g,'&lt;');const parts=[value.difficulty,value.approach,...value.hints,value.examples[0].prompt,value.examples[0].explanation,...value.tips];
 try{for(const kind of ['Solution','Preview']){const header=kind==='Preview'?'<h2>'+value.title+'</h2>':'<h3>Solution: '+value.title+'</h3>';document.body.innerHTML='<section><header>'+header+'</header><article>'+parts.map(x=>'<p>'+escape(x)+'</p>').join('')+'</article><footer><button>'+(kind==='Preview'?'Close Preview':'Close')+'</button></footer></section>';assert(focusedModalMatches({kind,value}));document.querySelector('article p:nth-child(6)').remove();document.body.insertAdjacentHTML('beforeend','<aside>Exact explanation</aside>');assert(!focusedModalMatches({kind,value}));}
 document.body.innerHTML='<section><header><h3>Hint: Exact content</h3></header><div>first hint second hint</div></section>';assert(focusedModalMatches({kind:'Hint',value}));document.body.insertAdjacentHTML('beforeend',document.body.innerHTML);assert(!focusedModalMatches({kind:'Hint',value}));
 }finally{global.document=previous;dom.window.close();}
});
test('supply DONE oracle excludes another completed card, TODO and duplicate labels',()=>{
 const {JSDOM}=require('../client/node_modules/jsdom'),{supplyDoneMatches}=require('./fixtures/mcpAuditContentBrowser'),dom=new JSDOM('<section><span class="status-badge">DONE</span><div class="obj-content"><div class="obj-name">Other</div></div></section><section id="target"><span class="status-badge">TODO</span><div class="obj-content"><div class="obj-name">Supply</div></div></section>'),previous=global.document;global.document=dom.window.document;
 try{assert.equal(supplyDoneMatches('Supply'),false);document.querySelector('#target .status-badge').textContent='DONE';assert.equal(supplyDoneMatches('Supply'),true);document.body.insertAdjacentHTML('beforeend',document.querySelector('#target').outerHTML);assert.equal(supplyDoneMatches('Supply'),false);}finally{global.document=previous;dom.window.close();}
});

test('remaining nine is closed, disjoint, all-completed and bounded without widening older profiles',()=>{
 const h=require('./fixtures/mcpAuditContentBrowser'),c=h.configuration(h.REMAINING_PROFILE);
 assert.equal(c.ids.length,9);assert.equal(new Set(c.ids).size,9);assert.deepEqual(c.completed,c.ids);assert(c.ids.every(id=>!h.FOCUSED_IDS.includes(id)));
 assert.equal(c.browser,1000);assert.equal(h.configuration().browser,400);assert.equal(h.configuration(h.FOCUSED_PROFILE).browser,400);
 assert.throws(()=>h.configuration('other'));assert(h.allowedRequest('http://localhost/a','http://localhost',1000,h.REMAINING_PROFILE));assert(!h.allowedRequest('http://localhost/a','http://localhost',1001,h.REMAINING_PROFILE));assert(!h.allowedRequest('http://localhost/a','http://localhost',401));
 for(const endpoint of ['chat','jsonrpc','progress/complete','progress/reset'])assert(!h.allowedRequest('http://localhost/'+endpoint,'http://localhost',1,h.REMAINING_PROFILE));
});

test('remaining-nine time proof requires exact nonzero projections and restores nonempty sibling time',()=>{
 const f=require('./fixtures/mcpAuditContentBrowser');assert.equal(f.CONTROLLED_TIME_SECONDS,165);assert.equal(f.assertTimeProjection({timeSpentSeconds:165}).timeSpentSeconds,165);for(const seconds of [0,23,164,166,'165',undefined])assert.throws(()=>f.assertTimeProjection({timeSpentSeconds:seconds}));
 const before=[{id:1,user_id:42,duration_seconds:23}];assert.equal(f.assertTimeRestoration(before,structuredClone(before),42),true);for(const after of [[],[{...before[0],duration_seconds:24}],[...before,{id:2,user_id:41,duration_seconds:165}]])assert.throws(()=>f.assertTimeRestoration(before,after,42));assert.throws(()=>f.assertTimeRestoration([],[],42));
});

test('remaining-nine instructor page pauses alive until projection then retires; other focused profile closes early',async()=>{
 const {prepareFocusedAdmin,retireUnusedPage}=require('./fixtures/mcpAuditContentBrowser');const events=[];let closed=false;const page={isClosed:()=>closed,goto:async url=>{assert.equal(closed,false);events.push(url);},close:async()=>{closed=true;events.push('close');}};const bound=p=>p;
 await prepareFocusedAdmin(page,true,bound);assert.equal(closed,false);await page.goto('/admin/student-workshop-view');await retireUnusedPage(page,bound);assert.deepEqual(events,['about:blank','/admin/student-workshop-view','close']);await assert.rejects(prepareFocusedAdmin(page,true,bound),/must remain open/);
 closed=false;events.length=0;await prepareFocusedAdmin(page,false,bound);assert.equal(closed,true);assert.deepEqual(events,['close']);
});
