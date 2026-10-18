'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {assertPopulatedRunDetail}=require('./fixtures/fullBackendRenderedAuth');
function value(){return {run:{runId:'owned-run',ownerId:'7',provider:'controlled-fixture'},events:[{type:'tool',data:{tool:'searchProducts'}}],judgments:[{verdict:'inconclusive',disposition:'not_pass'}]};}
const scope={runId:'owned-run',ownerId:7,admin:true,privateMarker:'synthetic-private-packet'};
test('populated projection requires exact owner, tool and no-credit receipt, excluding private content',()=>{
 assertPopulatedRunDetail(value(),scope);
 for(const change of [v=>v.run.ownerId='8',v=>v.events=[],v=>v.judgments=[],v=>v.judgments[0].verdict='pass',v=>v.run.ownerKey='internal',v=>v.private='synthetic-private-packet']){const v=value();change(v);assert.throws(()=>assertPopulatedRunDetail(v,scope));}
 const learner=value();delete learner.run.ownerId;assertPopulatedRunDetail(learner,{...scope,admin:false});assert.throws(()=>assertPopulatedRunDetail(value(),{...scope,admin:false}));
});
test('fixture event type and query use the real trace schema, not invented completion events',()=>{
 const fs=require('node:fs');const schema=fs.readFileSync(require.resolve('../db/postgres/identity-migrations/0006_graph_trace.sql'),'utf8');assert.match(schema,/event_type IN \('node_start','node_end','decision','tool','error'\)/);
});

test('successful deletion preserves only exact job-bound inactive identity tombstone',()=>{
 const {assertDeletedIdentity}=require('./fixtures/fullBackendRenderedAuth');const jobId='00000000-0000-4000-8000-000000000001';const row={id:9,is_active:0,role:'student',admin_level:0,username:'deleted-'+jobId,email:'deleted-'+jobId+'@invalid.local'};
 assertDeletedIdentity(row,{id:9,jobId});for(const delta of [{is_active:1},{username:'old-learner'},{admin_level:1},{email:'old@example.invalid'}])assert.throws(()=>assertDeletedIdentity({...row,...delta},{id:9,jobId}));assert.throws(()=>assertDeletedIdentity(undefined,{id:9,jobId}));
});

test('inspector DOM requires the selected run, exact receipt and tool event in both scopes',()=>{
 const {JSDOM}=require('../client/node_modules/jsdom');const {populatedInspectorVisible}=require('./fixtures/fullBackendRenderedAuth');
 const original=global.document;const html=label=>`<section aria-label="${label}"><button data-run-id="owned-run" aria-pressed="true">owned-run</button><section aria-label="Authoritative Judge receipts"><strong>ARIA · sqli_1 · not_pass</strong><span>Verdict: inconclusive · Disposition: not_pass</span><span>Evaluation explanation: Controlled persisted receipt; no model evaluation was performed.</span></section><ol><li><strong>execute_tool</strong><span>tool</span><span>tool: searchProducts</span><span>decision: controlled-fixture</span></li></ol></section>`;
 try{for(const admin of [false,true]){const label=admin?'Administrator agent run inspector':'Your agent run inspector',scope={admin,runId:'owned-run',privateMarker:'private-content'};
  for(const mutate of [x=>x,x=>x.replace('Verdict: inconclusive','Verdict: pass'),x=>x.replace('Disposition: not_pass','Disposition: passed'),x=>x.replace('Controlled persisted receipt; no model evaluation was performed.','different receipt'),x=>x.replace('tool: searchProducts','tool: other'),x=>x.replace('aria-pressed="true"','aria-pressed="false"'),x=>x.replace('data-run-id="owned-run"','data-run-id="foreign-run"'),x=>x.replace('execute_tool','other_node')]){const content=mutate(html(label));const dom=new JSDOM(content);global.document=dom.window.document;assert.equal(populatedInspectorVisible(scope),content===html(label));dom.window.close();}
  const dom=new JSDOM(html(label).replace('<section aria-label="Authoritative Judge receipts">','<section aria-label="unrelated receipts">')+'<aside>'+html(label==='Your agent run inspector'?'Administrator agent run inspector':'Your agent run inspector')+'</aside>');global.document=dom.window.document;assert.equal(populatedInspectorVisible(scope),false);dom.window.close();
 }}finally{global.document=original;}
});

test('owned response wait handles rejection before await and aborts after a triggering action failure',async()=>{
 const {createResponseWaitOwner}=require('./fixtures/fullBackendRenderedAuth');const owner=createResponseWaitOwner();let signal;
 const pending=owner.wait({waitForResponse:(_predicate,options)=>{signal=options.signal;return new Promise((_,reject)=>signal.addEventListener('abort',()=>reject(Error('page closed')),{once:true}));}},()=>true);
 const primary=Error('click failed');let observed;
 try{throw primary;}catch(error){observed=error;}finally{await owner.settle();}
 assert.equal(observed,primary);assert.equal(signal.aborted,true);await assert.rejects(pending,/page closed/);
});
test('owned response wait supports early rejection and sequential successful waits without abort poisoning',async()=>{
 const {createResponseWaitOwner}=require('./fixtures/fullBackendRenderedAuth');const owner=createResponseWaitOwner();const rejected=owner.wait({waitForResponse:()=>Promise.reject(Error('early rejection'))},()=>true);await new Promise(resolve=>setImmediate(resolve));await assert.rejects(rejected,/early rejection/);
 for(let n=0;n<2;n++)assert.equal(await owner.wait({waitForResponse:()=>Promise.resolve(n)},()=>true),n);await owner.settle();
});

test('actual login failure retains its primary cause while owning context-close waiter rejection',async()=>{
 const {qualifyFullBackendRenderedAuth}=require('./fixtures/fullBackendRenderedAuth');
 for(const cleanupFailure of [false,true]){
  const primary=Error('controlled click failure');let closed=false,signal;
  const page={setDefaultTimeout(){},on(){},async setRequestInterception(){},async setCacheEnabled(){},async goto(){},async waitForSelector(){},async type(){},async click(){throw primary;},waitForResponse(_p,options){signal=options.signal;return new Promise((_,reject)=>signal.addEventListener('abort',()=>reject(Error('late page closure')),{once:true}));}};
  const context={async newPage(){return page;},close(){closed=true;if(cleanupFailure)throw Error('controlled close failure');}};
  await assert.rejects(qualifyFullBackendRenderedAuth({browser:{async createBrowserContext(){return context;}},origin:'http://127.0.0.1:1234',admin:{id:1,username:'admin'},students:[{},{}],password:'synthetic',verifySession:async()=>{}}),error=>cleanupFailure?error instanceof AggregateError&&error.errors[0]===primary:error===primary);
  assert.equal(closed,true);assert.equal(signal.aborted,true);
 }
});


test('rendered platform browser bytes require the admitted owner digest; generic pin remains closed',()=>{
 const {admitRendered}=require('./fixtures/fullBackendRenderedBranch');const {createHash}=require('node:crypto');
 const bytes=Buffer.from('controlled current browser bytes'),digest=createHash('sha256').update(bytes).digest('hex'),executable='/owned/browser';
 const env={PG_FULL_BACKEND_RENDERED:'1',PG_MAIN_RENDERED_PLATFORM:'1',PG_MAIN_BACKEND_AUTH:'1',PG_FULL_BACKEND_BROWSER:executable,PG_FULL_BACKEND_BROWSER_SHA256:digest};
 const owner={profile:'rendered-platform',browser:executable,browserSha256:digest};const io={realpathSync:p=>p,readFileSync:()=>bytes};
 assert.deepEqual(admitRendered(env,owner,io),{executable,sha256:digest});
 for(const bad of [undefined,{...owner,browser:'/foreign/browser'},{...owner,browserSha256:'0'.repeat(64)},{...owner,profile:'other'}])assert.throws(()=>admitRendered(env,bad,io));
 assert.throws(()=>admitRendered(env,owner,{...io,readFileSync:()=>Buffer.from('changed browser')}));
 assert.throws(()=>admitRendered({...env,PG_MAIN_RENDERED_PLATFORM:undefined,PG_MAIN_BACKEND_AUTH:undefined},undefined,io));
 assert.throws(()=>admitRendered({...env,PG_FULL_BACKEND_BROWSER_SHA256:'0'.repeat(64)},owner,io));
});

test('standalone rendered browser uses only its separate exact owner digest',()=>{
 const {admitRendered}=require('./fixtures/fullBackendRenderedBranch');const {createHash}=require('node:crypto');
 const bytes=Buffer.from('standalone rendered browser bytes'),digest=createHash('sha256').update(bytes).digest('hex');
 const executable='/owned/browser',io={realpathSync:p=>p,readFileSync:()=>bytes};
 const env={PG_FULL_BACKEND_RENDERED:'1',PG_MAIN_RENDERED_STANDALONE:'1',PG_MAIN_BACKEND_AUTH:'1',
  PG_FULL_BACKEND_BROWSER:executable,PG_FULL_BACKEND_BROWSER_SHA256:digest};
 const owner={profile:'standalone-core-rendered',browser:executable,browserSha256:digest};
 assert.deepEqual(admitRendered(env,owner,io),{executable,sha256:digest});
 for(const change of [{PG_MAIN_RENDERED_STANDALONE:undefined},{PG_MAIN_RENDERED_PLATFORM:'1'},
  {PG_FULL_BACKEND_BROWSER_SHA256:'0'.repeat(64)}])assert.throws(()=>admitRendered({...env,...change},owner,io));
 assert.throws(()=>admitRendered(env,{...owner,profile:'rendered-platform'},io));
});

test('exact button scrolls offscreen form controls before hit testing without accepting overlays or duplicates',async()=>{
 const {JSDOM}=require('../client/node_modules/jsdom');const {exactButton}=require('./fixtures/fullBackendRenderedAuth');const original=global.document;
 for(const scenario of ['offscreen','overlay','disabled','duplicate']){
  const dom=new JSDOM('<form style="height:2000px"><button>Create Student</button></form>');global.document=dom.window.document;
  const b=document.querySelector('button');let scrolled=false,clicked=false;
  b.getClientRects=()=>[{}];b.getBoundingClientRect=()=>({x:10,y:scrolled?20:2000,width:100,height:30});b.scrollIntoView=()=>{scrolled=true;};
  document.elementFromPoint=(_x,y)=>y<600&&scenario!=='overlay'?b:null;
  if(scenario==='disabled')b.disabled=true;
  if(scenario==='duplicate'){const other=b.cloneNode(true);other.getClientRects=()=>[{}];document.querySelector('form').append(other);}
  const page={waitForFunction:async(fn,_opts,args)=>{if(!fn(args))throw Error('controlled target not ready');},evaluate:async(fn,args)=>fn(args),click:async selector=>{assert.equal(document.querySelector(selector),b);assert.ok(scrolled);clicked=true;}};
  try{if(scenario==='offscreen'){await exactButton(page,'Create Student');assert.equal(clicked,true);assert.equal(b.hasAttribute('data-platform-control'),false);}else{await assert.rejects(exactButton(page,'Create Student'),/not ready/);assert.equal(clicked,false);}}finally{global.document=original;dom.window.close();}
 }
});

test('input replacement selects all, proves empty, types via keyboard and verifies exact readback',async()=>{
 const {replaceInput}=require('./fixtures/fullBackendRenderedAuth');
 for(const scenario of ['normal','partial-clear','changed-type']){
  let value='Prior multi word learner name',selected=false,focused=false,typed=false;
  const input={focus(){focused=true;},select(){assert.ok(focused);selected=true;},get value(){return value;}};
  const element={evaluate:async fn=>fn(input),press:async key=>{assert.equal(key,'Backspace');assert.ok(selected);value=scenario==='partial-clear'?'Prior':'';},type:async text=>{typed=true;value+=scenario==='changed-type'?text+'x':text;}};
  if(scenario==='normal'){await replaceInput(element,'Edited owned learner');assert.equal(value,'Edited owned learner');}
  else{await assert.rejects(replaceInput(element,'Edited owned learner'));if(scenario==='partial-clear')assert.equal(typed,false);}
 }
});
