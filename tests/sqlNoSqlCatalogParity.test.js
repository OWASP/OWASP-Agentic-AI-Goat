'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {FAMILIES,assertCatalog,assertReset,assertSeedPreserved}=require('./fixtures/sqlNoSqlCatalogProjection');
const {assertGate,timeText,assertParity,LIMITS,createBudget,closeContexts,qualifySqlNoSqlCatalog}=require('./fixtures/sqlNoSqlCatalogParity');
const catalog=()=>({exercises:Object.fromEntries(FAMILIES.map(f=>[f.key,{objectives:Object.fromEntries(Array.from({length:10},(_,i)=>[f.prefix+(i+1),{label:'Canonical '+i}]))}]))});
test('closed canonical twenty IDs reject omissions and duplicates substituted for another ID',()=>{assertCatalog(catalog());const c=catalog();delete c.exercises[FAMILIES[0].key].objectives.sqli_10;assert.throws(()=>assertCatalog(c));c.exercises[FAMILIES[0].key].objectives.sqli_11={label:'wrong'};assert.throws(()=>assertCatalog(c));});
test('all four independent gates require actual status and rendered control parity',()=>{for(const h of [false,true])for(const s of [false,true]){const row={hint:h,solution:s,hintStatus:h?200:403,solutionStatus:s?200:403};assertGate(h,s,row);assert.throws(()=>assertGate(h,s,{...row,hint:!h}));assert.throws(()=>assertGate(h,s,{...row,hintStatus:h?403:200}));}});
test('time projections preserve the two existing rounding contracts',()=>{assert.equal(timeText(2),'2s');assert.equal(timeText(2,true),'< 1m');assert.equal(timeText(61),'1m');assert.equal(timeText(3601),'1h 0m');assert.throws(()=>timeText(-1));});
test('count and time parity rejects stale projection or total',()=>{const rows=[{workshopKey:'a',objectiveCount:10,completedObjectiveCount:10,timeSpentSeconds:2}];assertParity(rows,rows,{totalObjectives:10,completedObjectives:10,totalTime:2});assert.throws(()=>assertParity(rows,[{...rows[0],timeSpentSeconds:3}],{totalObjectives:10,completedObjectives:10,totalTime:2}));assert.throws(()=>assertParity(rows,rows,{totalObjectives:9,completedObjectives:10,totalTime:2}));});
function state(){return {ownerId:1,...Object.fromEntries(FAMILIES.map(f=>[f.key,{completions:Array.from({length:10},(_,i)=>({objective_id:f.prefix+i})),seconds:2,history:[{id:1}],generation:0,graphGeneration:0,judgments:[],effects:[]}]))}}
test('nonzero reset requires family progress/time/history cleared with both generations and sibling retained',()=>{const before=state(),after=structuredClone(before),key=FAMILIES[0].key;Object.assign(after[key],{completions:[],seconds:0,history:[],generation:1,graphGeneration:1});assertReset(before,after,key);for(const field of ['seconds','generation','graphGeneration']){const bad=structuredClone(after);bad[key][field]=before[key][field];assert.throws(()=>assertReset(before,bad,key));}const bad=structuredClone(after);bad[FAMILIES[1].key].seconds++;assert.throws(()=>assertReset(before,bad,key));const zero=structuredClone(before);zero[key].completions=[];assert.throws(()=>assertReset(zero,after,key));});
test('reset cannot erase immutable evidence and no-op remains generation fenced',()=>{const before=state(),key=FAMILIES[0].key;before[key].judgments=[{id:'retained'}];const after=structuredClone(before);Object.assign(after[key],{completions:[],seconds:0,history:[],generation:1,graphGeneration:1});assertReset(before,after,key);after[key].judgments=[];assert.throws(()=>assertReset(before,after,key));});
test('declared gate workload fits bounded HTTP allowance without semantic cohort',()=>{const minimum=20*4*(2+2+2)+20*2+2*6;assert.ok(minimum<LIMITS.http);assert.equal(LIMITS.renderMs,900000);});

test('remaining render deadline and HTTP ceiling cannot be renewed',()=>{let now=0;const b=createBudget({now:()=>now,http:2});b.request();b.request();assert.throws(()=>b.request());const deadline=createBudget({now:()=>now});now=900000;assert.throws(()=>deadline.remaining());});
test('context cleanup surfaces rejection and hanging context rather than claiming absence',async()=>{await closeContexts([{close:async()=>{}}]);await assert.rejects(closeContexts([{close:async()=>{throw Error('owned close failed');}}]));await assert.rejects(closeContexts([{close:()=>new Promise(()=>{})}],{timeoutMs:5}),/deadline/);});

test('initial catalog failure clears owned deadline before any browser admission',async t=>{const fs=require('node:fs'),os=require('node:os'),path=require('node:path');const root=fs.mkdtempSync(path.join(os.tmpdir(),'sql-nova-catalog-control-'));const pending=new Set(),set=global.setTimeout,clear=global.clearTimeout;t.mock.method(global,'setTimeout',(fn,ms,...args)=>{const handle=set(fn,ms,...args);pending.add(handle);return handle;});t.mock.method(global,'clearTimeout',handle=>{pending.delete(handle);return clear(handle);});try{await assert.rejects(qualifySqlNoSqlCatalog({browser:{createBrowserContext(){throw Error('Unexpected browser');}},origin:'http://127.0.0.1:1',students:[{},{},{},{}],root,projection:{catalog:async()=>{throw Error('Catalog unavailable');}}}),/Catalog unavailable/);assert.equal(pending.size,0);assert.equal(JSON.parse(fs.readFileSync(path.join(root,'sql-nova-catalog-failure.json'))).status,'failed');}finally{for(const handle of pending)clear(handle);fs.rmSync(root,{recursive:true,force:true});}});

test('reseed cannot overwrite instructor content or sibling flags',()=>{const rows=[{id:'a',hint:{hints:['instructor']},enabled:true},{id:'b',enabled:false}];assertSeedPreserved(rows,structuredClone(rows));const changed=structuredClone(rows);changed[0].hint.hints=['default'];assert.throws(()=>assertSeedPreserved(rows,changed));changed[0]=rows[0];changed[1].enabled=true;assert.throws(()=>assertSeedPreserved(rows,changed));});
test('reset rejects a different owner even with identical zeroed progress',()=>{const before=state(),after=structuredClone(before),key=FAMILIES[0].key;Object.assign(after[key],{completions:[],seconds:0,history:[],generation:1,graphGeneration:1});after.ownerId=2;assert.throws(()=>assertReset(before,after,key),/owner/);});

test('native display-account username reaches canonical createUser while historical overlength fails before query',async()=>{
 const fs=require('node:fs'),path=require('node:path'),vm=require('node:vm'),{randomUUID}=require('node:crypto');
 const source=fs.readFileSync(path.join(__dirname,'postgres/fullApplicationBackendAuth.integration.test.js'),'utf8');
 const declaration=source.match(/displayStudents\.push\(await identity\.createUser\(\{username:([^,]+),email:/);
 assert(declaration,'Actual native display-account declaration is required');
 const username=vm.runInNewContext(declaration[1],{randomUUID},{timeout:100});
 const calls=[],repository=require('../server/database/postgres/identityRepository').createIdentityRepository({query:async(sql,params)=>{calls.push({sql,params});return {rows:[{id:1,username:params[0]}]};}});
 const fields={email:'owned@example.invalid',passwordHash:'$2b$04$'+'.'.repeat(53)};
 await assert.rejects(repository.createUser({...fields,username:'catalog-display-'+randomUUID()}),/Invalid username/);
 assert.equal(calls.length,0,'Overlength username must fail before SQL');
 const created=await repository.createUser({...fields,username});
 assert.equal(created.username,username);assert.equal(calls.length,1);assert.equal(calls[0].params[0],username);
});

test('owned page waits for cache disable before navigation and fails closed if configuration fails',async()=>{
 const fs=require('node:fs'),os=require('node:os'),path=require('node:path');
 for(const rejectCache of [false,true]){
  const root=fs.mkdtempSync(path.join(os.tmpdir(),'sql-nova-cache-control-'));let settle,entered,closed=0;const events=[];
  const started=new Promise(r=>entered=r),cache=new Promise((resolve,reject)=>{settle=()=>rejectCache?reject(Error('cache configuration failed')):resolve();});
  const page={setCacheEnabled(value){assert.equal(value,false);events.push('cache');entered();return cache;},async setViewport(){events.push('viewport');throw Error('controlled stop after cache');},goto(){assert.fail('Navigation must not precede cache configuration');}};
  const context={newPage:async()=>page,close:async()=>{closed++;}};
  try{
   const run=qualifySqlNoSqlCatalog({browser:{createBrowserContext:async()=>context},origin:'http://127.0.0.1:1',students:[{},{},{},{}],root,projection:{catalog:async()=>catalog()}});
   const checked=assert.rejects(run,rejectCache?/cache configuration failed/:/controlled stop after cache/);
   await started;assert.deepEqual(events,['cache']);settle();await checked;
   assert.deepEqual(events,rejectCache?['cache']:['cache','viewport']);assert.equal(closed,1);
  }finally{settle?.();fs.rmSync(root,{recursive:true,force:true});}
 }
});

test('content assertion requires exact DOM payload and whitespace-normalized visible text together',()=>{
 const {catalogContentVisible}=require('./fixtures/sqlNoSqlCatalogParity'),vm=require('node:vm');
 const text='Example:\n  SELECT * FROM products';
 const check=(textContent,innerText,visible=true,rects=1)=>vm.runInNewContext('('+catalogContentVisible.toString()+')({kind:"hint",title:"Hint",text})',{text,getComputedStyle:()=>({display:visible?'block':'none',visibility:visible?'visible':'hidden'}),document:{querySelector:()=>({textContent,innerText,getClientRects:()=>Array(rects).fill({})})}});
 assert.equal(check(text,'Example:\nSELECT * FROM products'),true,'pre-line whitespace collapse is legitimate');
 assert.equal(check(text,text,false),false,'hidden modal text fallback is not visibility');
 assert.equal(check(text,text,true,0),false,'empty rendered geometry is not visibility');
 assert.equal(check(text,'Hint only'),false,'hidden exact DOM alone cannot prove visible content');
 assert.equal(check('Example:\nSELECT * FROM products','Example: SELECT * FROM products'),false,'visible normalization cannot excuse changed payload bytes');
 assert.equal(check(text.replace('products','orders'),'Example: SELECT * FROM orders'),false);
});

test('mounted exercise navigation does not reload and aliases retain redirect assertion',async()=>{
 const {navigateCatalog}=require('./fixtures/sqlNoSqlCatalogParity');const events=[];
 const mounted={evaluate:async()=>'/workshop/sql',goto:()=>assert.fail('full reload'),waitForFunction:()=>assert.fail('already mounted')};
 assert.equal(await navigateCatalog(mounted,'/workshop/sql',100),'mounted');
 const alias={evaluate:async(fn,arg)=>{events.push(arg);return arg?'history':'/admin/exercises';},waitForFunction:async(fn,options,target)=>{assert.equal(target,'/admin/exercises');assert.equal(options.timeout,100);}};
 assert.equal(await navigateCatalog(alias,'/admin/solutions',100),'history');assert.deepEqual(events,[undefined,'/admin/solutions']);
});
test('navigation prefers a real rendered same-origin link and otherwise dispatches BrowserRouter history',async()=>{
 const {navigateCatalog}=require('./fixtures/sqlNoSqlCatalogParity'),vm=require('node:vm');
 for(const linked of [true,false]){const events=[];const page={evaluate:async(fn,arg)=>arg===undefined?'/old':vm.runInNewContext('('+fn.toString()+')(route)',{route:arg,location:{origin:'http://owned'},document:{querySelectorAll:()=>linked?[{origin:'http://owned',pathname:arg,getClientRects:()=>[{}],click:()=>events.push('click')}]:[]},getComputedStyle:()=>({visibility:'visible'}),history:{pushState:(a,b,r)=>events.push(r)},PopStateEvent:function(type){this.type=type;},dispatchEvent:e=>events.push(e.type)}),waitForFunction:async()=>{}};
 assert.equal(await navigateCatalog(page,'/workshop/nosql',100),linked?'link':'history');assert.deepEqual(events,linked?['click']:['/workshop/nosql','popstate']);}
});
test('HTTP budget diagnostics retain rejected attempted count independently of wall deadline',()=>{
 const b=createBudget({http:1,now:()=>0});b.request();assert.throws(()=>b.request(),{code:'CATALOG_HTTP_BUDGET'});assert.equal(b.count(),2);
});

test('objectives modal closes through its real pointer-ready button before card interaction',async()=>{
 const {closeCatalogObjectives}=require('./fixtures/sqlNoSqlCatalogParity');
 for(const present of [false,true]){const events=[];const button={evaluate:async()=>events.push('scroll'),click:async()=>events.push('click')};const handle={asElement:()=>present?button:null,dispose:async()=>events.push('dispose')};const page={evaluateHandle:async()=>handle,waitForFunction:async(fn,opts,element)=>{assert.equal(opts.timeout,123);events.push(element?'pointer':'closed');}};
 assert.equal(await closeCatalogObjectives(page,123),present);assert.deepEqual(events,present?['scroll','pointer','click','closed','dispose']:['dispose']);}
});
test('objectives modal handle disposes when pointer readiness fails without synthetic click',async()=>{
 const {closeCatalogObjectives}=require('./fixtures/sqlNoSqlCatalogParity');let disposed=false;const page={evaluateHandle:async()=>({asElement:()=>({evaluate:async()=>{},click:()=>assert.fail('must not force click')}),dispose:async()=>{disposed=true;}}),waitForFunction:async()=>{throw Error('blocked pointer');}};
 await assert.rejects(closeCatalogObjectives(page,100),/blocked pointer/);assert(disposed);
});

test('gate sequence preserves all four combinations with one real mutation per transition',()=>{
 const {gateTransitions}=require('./fixtures/sqlNoSqlCatalogParity');const rows=gateTransitions({hint:true,solution:true});assert.equal(rows.length,4);assert.equal(new Set(rows.map(x=>String(x.hint)+String(x.solution))).size,4);let current={hint:true,solution:true};for(const row of rows){assert.deepEqual(['hint','solution'].filter(k=>current[k]!==row[k]),[row.dimension]);assert.equal(row.enabled,row[row.dimension]);current={hint:row.hint,solution:row.solution};}assert.deepEqual(current,{hint:true,solution:true});for(const hint of [true,false])for(const solution of [true,false])if(!hint||!solution)assert.throws(()=>gateTransitions({hint,solution}));
});

test('batched alias assertion verifies every exact modal ID and label, not unrelated page text',()=>{
 const {catalogAliasRowsVisible}=require('./fixtures/sqlNoSqlCatalogParity'),vm=require('node:vm');
 const expected=Array.from({length:10},(_,i)=>({id:'sqli_'+(i+1),label:'Canonical '+i,h:true,s:true}));
 function check(change=()=>{}){
  const rows=expected.map(x=>({id:x.id,getAttribute(){return this.id;},children:[{firstElementChild:{textContent:x.label,getAttribute(){return this.textContent;}}},{},{firstElementChild:{backgroundColor:'rgb(72, 187, 120)'}},{firstElementChild:{backgroundColor:'rgb(72, 187, 120)'}}]}));change(rows);
  const modal={getClientRects:()=>[{}],visibility:'visible',querySelectorAll:()=>rows};
  return vm.runInNewContext('('+catalogAliasRowsVisible.toString()+')(expected)',{expected,document:{querySelectorAll:()=>[{textContent:'Objectives — ARIA',parentElement:{parentElement:modal}}]},getComputedStyle:x=>x});
 }
 assert.equal(check(),true);
 for(let i=0;i<10;i++){
  assert.equal(check(rows=>{rows[i].id='foreign';}),false);
  assert.equal(check(rows=>{rows[i].children[0].firstElementChild.textContent='stale';}),false);
  for(const column of [2,3])assert.equal(check(rows=>{rows[i].children[column].firstElementChild.backgroundColor='off';}),false);
 }
 assert.equal(check(rows=>rows.pop()),false);assert.equal(check(rows=>{rows[9].id=rows[0].id;}),false);
});

test('actual fixture checks all ten aliases for every round and final state',()=>{
 const fs=require('node:fs'),source=fs.readFileSync(require.resolve('./fixtures/sqlNoSqlCatalogParity'),'utf8');
 assert.match(source,/aliases:expected=>checkAliases\(f,expected\)/);
 assert.match(source,/aliasExpected=Object.entries\(aliasCatalog.objectives\).map/);
 assert.match(source,/await checkAliases\(f,aliasExpected\)/);
 assert.doesNotMatch(source,/if\(id!==Object.keys\(catalog.objectives\)\[0\]\)await checkAliases/);
 assert.match(source,/assert.equal\(result.gateCases,80\)/);assert.equal(LIMITS.http,4000);assert.equal(LIMITS.renderMs,900000);
});

test('objective toggle waits for loaded modal rows then real pointer readiness',async()=>{
 const {clickCatalogObjectiveToggle}=require('./fixtures/sqlNoSqlCatalogParity'),vm=require('node:vm');const events=[];let rows=[];
 const toggle={evaluate:async()=>events.push('scroll'),click:async()=>events.push('click')};
 const modal={getClientRects:()=>[{}],querySelectorAll:()=>rows};
 const document={querySelectorAll:()=>[{textContent:'Objectives — ARIA',parentElement:{parentElement:modal}}]};
 const page={waitForFunction:async(fn,options,arg)=>{
  assert.equal(options.timeout,123);
  if(arg===toggle){events.push('pointer');return;}
  const run=()=>vm.runInNewContext('('+fn.toString()+')(arg)',{arg,document,getComputedStyle:()=>({display:'block',visibility:'visible'})});
  assert.equal(run(),false,'modal exists before asynchronous objectives load');
  rows=[{getAttribute:()=> 'nosqli_1',children:[{},{},{firstElementChild:toggle}]}];assert.equal(run(),false,'other family cannot satisfy readiness');
  rows=[{getAttribute:()=> 'sqli_1',children:[{},{},{firstElementChild:toggle}]}];assert.equal(run(),toggle);events.push('loaded');
  return{asElement:()=>toggle,dispose:async()=>events.push('dispose')};
 }};
 await clickCatalogObjectiveToggle(page,'sqli_1',3,123);assert.deepEqual(events,['loaded','scroll','pointer','click','dispose']);
});
test('objective toggle does not force blocked clicks and disposes its handle',async()=>{
 const {clickCatalogObjectiveToggle}=require('./fixtures/sqlNoSqlCatalogParity');let calls=0,disposed=false;
 const page={waitForFunction:async()=>{if(calls++)throw Error('pointer blocked');return{asElement:()=>({evaluate:async()=>{},click:()=>assert.fail('forced click')}),dispose:async()=>{disposed=true;}};}};
 await assert.rejects(clickCatalogObjectiveToggle(page,'sqli_1',4,100),/pointer blocked/);assert.equal(disposed,true);
});
test('individual admin controls await the complete current family after reopening the modal',()=>{
 const source=require('node:fs').readFileSync(require.resolve('./fixtures/sqlNoSqlCatalogParity'),'utf8');
 assert.match(source,/async function adminRows\(f,expected\).*waitForFunction\(catalogAliasRowsVisible,\{timeout:remaining\(\)\},expected\)/);
 assert.match(source,/await adminRows\(f,aliasExpected\);for\(const expected of \[false,true\]\)\{await clickCatalogObjectiveToggle/);
});
test('round barriers cover ten individual mutations and verifications before advancing all four states',async()=>{
 const {runGateRounds}=require('./fixtures/sqlNoSqlCatalogParity');const objectives=Object.fromEntries(Array.from({length:10},(_,i)=>['o'+i,{label:'Label '+i,hintVisible:true,solutionVisible:true}]));const events=[],records=[];
 await runGateRounds(objectives,{mutate:async(id,dimension,enabled)=>{events.push('mutate');objectives[id][dimension==='hint'?'hintVisible':'solutionVisible']=enabled;},canonical:async()=>structuredClone(objectives),barrier:async rows=>{assert.equal(rows.length,10);assert(rows.every(r=>objectives[r.id].hintVisible===r.h&&objectives[r.id].solutionVisible===r.s));events.push('barrier');},verify:async r=>{events.push('verify');assert.equal(objectives[r.id].hintVisible,r.h);},aliases:async rows=>{assert.equal(rows.length,10);events.push('aliases');},record:r=>records.push(r)});
 assert.equal(records.length,40);for(const id of Object.keys(objectives))assert.deepEqual(records.filter(r=>r.id===id).map(r=>[r.h,r.s]),[[true,false],[false,false],[false,true],[true,true]]);
 assert.deepEqual(events,['barrier',...Array.from({length:4},()=>[...Array(10).fill('mutate'),'barrier',...Array(10).fill('verify'),'aliases']).flat()]);
});
test('round canonical mismatch prevents rendered assertions or next round',async()=>{const {runGateRounds}=require('./fixtures/sqlNoSqlCatalogParity');const objectives=Object.fromEntries(Array.from({length:10},(_,i)=>['o'+i,{label:'Label '+i,hintVisible:true,solutionVisible:true}]));let mutations=0,barriers=0;await assert.rejects(runGateRounds(objectives,{mutate:async()=>mutations++,canonical:async()=>objectives,barrier:async()=>barriers++,verify:()=>assert.fail('stale gates verified'),aliases:()=>{},record:()=>{}}));assert.equal(mutations,10);assert.equal(barriers,1);});
test('cleanup deadline cannot replace original rendered failure',()=>{const {preservePrimaryFailure}=require('./fixtures/sqlNoSqlCatalogParity'),primary=new Error('original wait'),cleanup=new Error('restore expired');assert.throws(()=>preservePrimaryFailure(primary,cleanup),e=>e===primary);assert.throws(()=>preservePrimaryFailure(null,cleanup),e=>e===cleanup);assert.doesNotThrow(()=>preservePrimaryFailure(null,null));});
test('rendered round barrier rejects any stale, missing, duplicate or extra objective',()=>{const {catalogGateRowsVisible}=require('./fixtures/sqlNoSqlCatalogParity'),vm=require('node:vm');const expected=Array.from({length:10},(_,i)=>({id:'o'+i,label:'Label '+i,h:true,s:false}));const check=mutate=>{const rows=expected.map(x=>({label:x.label,h:x.h,s:x.s}));mutate?.(rows);const nodes=rows.map(x=>({textContent:x.label,parentElement:{parentElement:{querySelectorAll:()=>[...(x.h?[{textContent:'Hint'}]:[]),...(x.s?[{textContent:'View Solution'}]:[])]}}}));return vm.runInNewContext('('+catalogGateRowsVisible.toString()+')(expected)',{expected,document:{querySelectorAll:()=>nodes}});};assert.equal(check(),true);for(let i=0;i<10;i++){assert.equal(check(rows=>rows[i].h=false),false);assert.equal(check(rows=>rows[i].s=true),false);}assert.equal(check(rows=>rows.pop()),false);assert.equal(check(rows=>rows.push(rows[0])),false);assert.equal(check(rows=>rows[9].label=rows[0].label),false);});
test('restoration execution distinguishes skipped, thrown, and verified work',async()=>{const {restoreCatalogState,preservePrimaryFailure}=require('./fixtures/sqlNoSqlCatalogParity');let calls=0;const skipped=await restoreCatalogState({eligible:false,restore:async()=>calls++});assert.deepEqual(skipped,{performed:false,verified:false,status:'skipped'});assert.equal(calls,0);const failure=new Error('projection mismatch');const failed=await restoreCatalogState({eligible:true,restore:async()=>{calls++;throw failure;}});assert.equal(failed.performed,true);assert.equal(failed.verified,false);assert.equal(failed.status,'failed');assert.equal(failed.error,failure);const primary=new Error('original wait');assert.throws(()=>preservePrimaryFailure(primary,failed.error),e=>e===primary);const verified=await restoreCatalogState({eligible:true,restore:async()=>{calls++;}});assert.deepEqual(verified,{performed:true,verified:true,status:'verified'});assert.equal(calls,2);});

 test('aggregate dashboard predicate accepts icon whitespace but rejects wrong count, total, time or missing labels',()=>{
 const {catalogAggregateVisible}=require('./fixtures/sqlNoSqlCatalogParity'),vm=require('node:vm');
 const expected={done:20,total:136,time:'4s',challenges:false};
 const check=({done=20,total=136,time='4s',omit=null}={})=>{
  const labels=[{textContent:' Objectives',nextElementSibling:{textContent:`${done} / ${total}`} },{textContent:' Time',nextElementSibling:{textContent:time}}].filter(x=>x.textContent.trim()!==omit);
  return !!vm.runInNewContext('('+catalogAggregateVisible.toString()+')(expected)',{expected,document:{querySelectorAll:()=>labels}});
 };
 assert.equal(check(),true);assert.equal(check({done:19}),false);assert.equal(check({done:120}),false);assert.equal(check({total:135}),false);assert.equal(check({time:'3s'}),false);assert.equal(check({time:'14s'}),false);assert.equal(check({omit:'Objectives'}),false);assert.equal(check({omit:'Time'}),false);
 const source=require('node:fs').readFileSync(require.resolve('./fixtures/sqlNoSqlCatalogParity'),'utf8');assert(source.includes('waitForFunction(catalogAggregateVisible,{timeout:remaining()}'));
});

test('challenge aggregate and every family view reject substring count and time collisions',()=>{
 const {catalogAggregateVisible,catalogFamilyProjectionVisible}=require('./fixtures/sqlNoSqlCatalogParity'),vm=require('node:vm');
 const aggregate=(done,total)=>vm.runInNewContext('('+catalogAggregateVisible.toString()+')(expected)',{expected:{done:20,total:136,time:'4s',challenges:true},document:{querySelectorAll:()=>[{textContent:`15% complete — ${done}/${total} objectives done`}]}});
 assert.equal(aggregate(20,136),true);assert.equal(aggregate(120,136),false);assert.equal(aggregate(20,1360),false);
 for(const view of ['dashboard','challenges','admin']){
  const check=({done=2,total=10,time='2s',name='ARIA',duplicate=false}={})=>{
   const suffix=view==='dashboard'?'':view==='admin'?' objectives':' completed';const count={textContent:`${done}/${total}${suffix}`},clock={textContent:' '+time};
   const card={querySelectorAll:selector=>selector==='span'?[count]:[count,clock]},title={textContent:name,parentElement:{parentElement:{parentElement:card}}};
   return vm.runInNewContext('('+catalogFamilyProjectionVisible.toString()+')(expected)',{expected:{name:'ARIA',done:2,total:10,time:'2s',view},document:{body:{},querySelectorAll:()=>duplicate?[title,title]:[title]}});
  };
  assert.equal(check(),true,view);for(const wrong of [{done:12},{total:100},{time:'12s'},{name:'NOVA'},{duplicate:true}])assert.equal(check(wrong),false,view+JSON.stringify(wrong));
 }
});
