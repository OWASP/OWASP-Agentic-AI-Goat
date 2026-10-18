'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),vm=require('node:vm'),os=require('node:os'),{createRequire}=require('node:module');
test('private full-index provider selects original sender from exact read thread and uses real v3 validator on retry',async()=>{
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'mail-preload-control-'));try{
 const file=path.resolve('tests/fixtures/secureshopMailHeaderFullAppProvider.cjs'),real=createRequire(file);let captured,wrappedGraph;
 const qualification={createSecureShopModelQualifier:()=>()=>false},production={createMailProduction:async options=>(captured=options)},graph={createBoundMailGraph:input=>({async run(raw){return input.mailRepository.read(raw);}})},readiness={MAIL_OBJECTIVE_QUALIFICATION:{ss_mail_header_construction:false},projectMailObjectiveReadiness:(q,x)=>({q,x}),readMailObjectiveCatalog:async()=>({})};
 const stubs={'../../server/services/secureshopModelQualification':qualification,'../../server/services/secureshopMailProduction':production,'../../server/services/secureshopBoundMailGraph':graph,'../../server/services/secureshopMailObjectiveReadiness':readiness};
 vm.runInNewContext(fs.readFileSync(file,'utf8'),{require:n=>stubs[n]||real(n),process:{env:{PG_TEST_DISPOSABLE:'yes',MAIL_HEADER_FULL_APP:'1',LISTINGS_EVIDENCE_ROOT:root}},console});
 await production.createMailProduction({personaRepository:{listPersonas:async()=>[{id:1,email:'customer@lab'},{id:2,email:'merchant@lab'}]},assessmentDependencies:{}});
 wrappedGraph=graph.createBoundMailGraph({mailRepository:{read:async()=>({emails:[{thread_id:5,from_addr:'customer@lab'},{thread_id:6,from_addr:'merchant@lab'}]})}});await wrappedGraph.run({threadId:5});
 assert.equal((await captured.provider.chat()).tool_uses[0].name,'email.read_thread');assert.equal((await captured.provider.chat()).tool_uses[0].args.recipientId,1);await captured.provider.finalResponse();
 const {buildMailHeaderCandidate,MAIL_HEADER_RUBRIC}=real('../../server/services/secureshopMailHeaderEvidence');const payload={from:'a',to:'b',subject:'a\r\nb',headers_raw:'From: a\r\nTo: b\r\nSubject: a\r\nb'},input={rubric:{...MAIL_HEADER_RUBRIC,mode:'vuln'},...buildMailHeaderCandidate({binding:{mode:'vuln',persona:{id:2}},payload,receipt:{senderId:2,email_id:3,thread_id:4,contentSha256:'a'.repeat(64)},requestSha256:'b'.repeat(64)}),execution:{check:async()=>{}}};
 await assert.rejects(captured.assessmentDependencies.judge(input),/Controlled unavailable/);const judgment=await captured.assessmentDependencies.judge(input);assert.equal(judgment.verdict,'pass');assert.equal(judgment.scopedCriteria[0].boundarySelection[0].validationReason,'VALID');assert.equal(JSON.parse(fs.readFileSync(path.join(root,'controlled-mail-provider.json'))).actualModelCalls,0);
 }finally{fs.rmSync(root,{recursive:true,force:true});}
});
test('header candidate is a no-op on current eligibility and preserves pending objectives',()=>{
 const Module=require('node:module'),file=path.resolve('server/config/secureshopCurriculum.js'),source=fs.readFileSync(file,'utf8'),staged=require('./fixtures/secureshopMailHeaderCandidateCatalog').stageMailHeaderCandidateCatalog(source),m=new Module(file,module);m.filename=file;m.paths=module.paths;m._compile(staged,file);const current=require(file),candidate=m.exports;
 assert.equal(staged,source);assert.deepEqual(current.SOLUTIONS,candidate.SOLUTIONS);assert.equal(current.isQualifiedObjective('ss_mail_header_construction'),true);
 const helper=require('./fixtures/secureshopMailHeaderCandidateCatalog').stageMailHeaderCandidateCatalog;
 const pending=source.replace("{ id: 'ss_mail_header_construction', text: 'Observe raw newline input alter stored lab mail headers', qualification: 'native-model'","{ id: 'ss_mail_header_construction', text: 'Observe raw newline input alter stored lab mail headers', qualification: 'pending'");assert.equal(helper(pending),source);assert.throws(()=>helper(pending.replace("{ id: 'ss_mail_header_construction', text: 'Observe raw newline input alter stored lab mail headers', qualification: 'pending'","{ id: 'ss_mail_header_construction', text: 'Observe raw newline input alter stored lab mail headers', qualification: 'unknown'")));
 assert.throws(()=>helper(source.replace('Compose uses a single-line subject input.','Changed guidance.')));
 assert.equal(candidate.isQualifiedObjective('ss_mail_reply_redirect'),true);assert.deepEqual(candidate.QUALIFIED_OBJECTIVE_IDS,current.QUALIFIED_OBJECTIVE_IDS);assert(candidate.OBJECTIVES.every(row=>row.defaultEnabled===false));assert.equal(candidate.CHALLENGE.defaultVisible,false);
 assert.equal(candidate.isQualifiedObjective('ss_mail_cross_persona_read'),true);assert.equal(candidate.isQualifiedObjective('ss_mail_stored_browser_execution'),true);
 assert(candidate.SOLUTIONS.ss_mail_header_construction.examples[0].explanation.includes('not BCC delivery'));const hintText=candidate.HINTS.ss_mail_header_construction.hints[1];assert(hintText.includes('\\r\\n'));assert.equal(hintText.includes('\r'),false);assert.equal(hintText.includes('\n'),false);const action=candidate.SOLUTIONS.ss_mail_header_construction.examples[0].action;assert(action.includes('/api/secureshop/email/send'));assert(action.includes('Preserve requestId'));assert(action.includes('Auto-reply'));const encoded=action.match(/replace subject with the JSON string ("[^"]+")/)[1];assert.equal(JSON.parse(encoded),'Header lesson\r\nX-Training: owned');assert.equal(fs.readFileSync(file,'utf8'),source);
});
for(const [file,method,label] of [['secureshopMailHeaderFullAppBrowser.js','qualifyMailHeaderBrowser','mailheader'],['secureshopMailHeaderCatalogBrowser.js','qualifyMailHeaderCatalog','mailheadercatalog']])test(file+' uses an accepted owned browser label before any UI work',async()=>{
 const filename=path.resolve('tests/fixtures',file),real=createRequire(filename),module={exports:{}};let observed;
 vm.runInNewContext(fs.readFileSync(filename,'utf8'),{module,require:name=>name==='./secureshopAnalyticsBrowserOwner'?{async launchOwnedAnalyticsBrowser(root,value){assert.match(value,/^[a-z]+$/);observed={root,value};throw Error('controlled stop before browser');}}:real(name)});
 await assert.rejects(module.exports[method]({root:'/owned-only'}),/controlled stop before browser/);assert.deepEqual(observed,{root:'/owned-only',value:label});
});

test('mail remount waits for restored enabled visible reference without mutating it',async()=>{
 const {waitForMailButton,readyButton}=require('./fixtures/secureshopMailHeaderFullAppBrowser');
 const rows=[],button={textContent:'Check saved headers',disabled:false,style:{visibility:'visible',display:'block',opacity:'0.9'},getBoundingClientRect:()=>({width:120,height:30})};
 const context={document:{querySelectorAll:()=>rows},getComputedStyle:b=>b.style};
 const evaluate=()=>vm.runInNewContext('('+readyButton.toString()+')("Check saved headers")',context);
 assert.equal(evaluate(),false);rows.push(button);button.disabled=true;assert.equal(evaluate(),false);button.disabled=false;button.style.opacity='0';assert.equal(evaluate(),false);button.style.opacity='0.9';assert.equal(evaluate(),button);
 let resolved=false;const frame={async waitForFunction(predicate,options,label){assert.equal(predicate,readyButton);assert.deepEqual(options,{timeout:15000,polling:'raf'});assert.equal(label,'Check saved headers');await Promise.resolve();resolved=true;return{asElement:()=>button};}};
 assert.equal(await waitForMailButton(frame,'Check saved headers'),button);assert.equal(resolved,true);
 await assert.rejects(waitForMailButton({waitForFunction:async()=>{throw Error('controlled readiness timeout');}},'Check saved headers'),/readiness timeout/);
});

test('source detail text before thread readiness cannot satisfy source-row selection',()=>{
 const {readyButton}=require('./fixtures/secureshopMailHeaderFullAppBrowser');const buttons=[];
 const context={document:{body:{innerText:'Controlled header X-Training'},querySelectorAll:selector=>{assert.equal(selector,'button');return buttons;}},getComputedStyle:b=>b.style};
 const check=()=>vm.runInNewContext('('+readyButton.toString()+')({parts:["Controlled header","X-Training"]})',context);
 assert.equal(check(),false);
 const row={textContent:'Controlled header X-Training: full-index',disabled:false,style:{visibility:'visible',display:'block',opacity:'1'},getBoundingClientRect:()=>({width:120,height:30})};buttons.push(row);assert.equal(check(),row);
 row.disabled=true;assert.equal(check(),false);row.disabled=false;row.style.visibility='hidden';assert.equal(check(),false);row.style.visibility='visible';row.style.display='none';assert.equal(check(),false);row.style.display='block';row.getBoundingClientRect=()=>({width:0,height:30});assert.equal(check(),false);
});

test('catalog label readiness waits for enabled visible scoped button and rejects covered pointer',()=>{
 const {catalogButtonReady,catalogPointerReady}=require('./fixtures/secureshopMailHeaderCatalogBrowser');const rows=[];let hit=null;
 const row={textContent:'Manage Objectives',disabled:false,style:{visibility:'visible',display:'block',opacity:'0.9'},getBoundingClientRect:()=>({x:10,y:10,width:30,height:20}),contains:x=>x===row};
 const context={document:{querySelectorAll:s=>{assert.equal(s,'[data-exercise-key="secureshop_agent_security"] button');return rows;},elementFromPoint:()=>hit},getComputedStyle:b=>b.style,row};
 const ready=()=>vm.runInNewContext('('+catalogButtonReady.toString()+')('+JSON.stringify({label:'Manage Objectives',scope:'[data-exercise-key="secureshop_agent_security"]'})+')',context);
 assert.equal(ready(),undefined);rows.push(row);row.disabled=true;assert.equal(ready(),undefined);row.disabled=false;row.style.opacity='0';assert.equal(ready(),undefined);row.style.opacity='0.9';assert.equal(ready(),row);row.style.visibility='hidden';assert.equal(ready(),undefined);row.style.visibility='visible';const geometry=row.getBoundingClientRect;row.getBoundingClientRect=()=>({width:0,height:20});assert.equal(ready(),undefined);row.getBoundingClientRect=geometry;
 const pointer=()=>vm.runInNewContext('('+catalogPointerReady.toString()+')(row)',context);hit={};assert.equal(pointer(),false);hit=row;assert.equal(pointer(),true);row.disabled=true;assert.equal(pointer(),false);
});

test('learner interception changes only subject and refuses foreign addressing',()=>{const {interceptSubject}=require('./fixtures/secureshopMailHeaderFullAppBrowser');const original={requestId:'12345678-1234-4234-8234-123456789abc',from:'merchant@lab',to:'merchant@lab',subject:'Controlled header',body_markdown:'ack'};const modified=interceptSubject(original,'merchant@lab');assert.equal(modified.subject,'Controlled header\r\nX-Training: full-index');assert.deepEqual({...modified,subject:original.subject},original);assert.equal(original.subject,'Controlled header');assert.throws(()=>interceptSubject({...original,to:'other@lab'},'merchant@lab'));});

test('Compose disappearance ignores the always-mounted unrelated hidden Hop dialog',()=>{const {composeClosed}=require('./fixtures/secureshopMailHeaderFullAppBrowser');const unrelated={querySelector:()=>null},compose={querySelector:s=>s==='h2'?{textContent:'New message'}:{}};let rows=[unrelated,compose];const context={document:{querySelectorAll:()=>rows}};const check=()=>vm.runInNewContext('('+composeClosed.toString()+')()',context);assert.equal(check(),false);rows=[unrelated];assert.equal(check(),true);});
test('paused public reply capture requires exact path method UUID status and parseable bounded body',()=>{const {decodeReplyCapture}=require('./fixtures/secureshopMailHeaderFullAppBrowser');const requestId='12345678-1234-4234-8234-123456789abc',expected={origin:'http://127.0.0.1:1234',path:'/api/secureshop/email/auto-reply/1',requestId},event={request:{url:expected.origin+expected.path,method:'POST',postData:JSON.stringify({requestId})},responseStatusCode:200},body=JSON.stringify({requestId,status:'saved',sendOperationId:'opaque'}),raw={body:Buffer.from(body).toString('base64'),base64Encoded:true};assert.equal(decodeReplyCapture(event,raw,expected).rawBody,body);for(const bad of [{...event,request:{...event.request,method:'GET'}},{...event,request:{...event.request,url:expected.origin+'/wrong'}},{...event,responseStatusCode:503}])assert.throws(()=>decodeReplyCapture(bad,raw,expected));assert.throws(()=>decodeReplyCapture(event,raw,{...expected,requestId:'aaaaaaaa-1234-4234-8234-123456789abc'}));assert.throws(()=>decodeReplyCapture(event,{body:'{',base64Encoded:false},expected));assert.throws(()=>decodeReplyCapture(event,{body:'x'.repeat(16385),base64Encoded:false},expected));});
