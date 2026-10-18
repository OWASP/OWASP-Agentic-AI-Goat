'use strict';
// Closed controlled-provider browser qualification; importing allocates nothing.
const assert=require('node:assert/strict'),path=require('node:path'),crypto=require('node:crypto');
const sha=value=>crypto.createHash('sha256').update(value).digest('hex');
const FAMILIES=Object.freeze([
 {id:'sql',resetLabel:'Reset',resetTitle:'Clear conversation, cart, and progress',name:'aria',key:'sql_injection_workshop',request:'search products HistoryProbe',store:'sqlWorkshopDb',factory:'createSqlWorkshopDb',initialize:'initializeSqlWorkshopDb',prefix:'SQL_WORKSHOP'},
 {id:'nosql',resetLabel:'Reset conversation',resetTitle:'Clear conversation, reading list, and progress',name:'nova',key:'nosql_injection_workshop',request:'search papers HistoryProbe',store:'nosqlWorkshopDb',factory:'createNosqlWorkshopDb',initialize:'initializeNosqlWorkshopDb',prefix:'NOSQL_WORKSHOP'},
]);
const LIMITS=Object.freeze({chats:6,resets:2,controlledCalls:6,controlledCallsPerFamily:3,api:1500,uiMs:420000,operationMs:15000});
const LONG='HistoryProbe '+ 'complete-value-'.repeat(9)+'| `ticks` <img data-history-probe="owned" src="invalid">';
const NARRATIVE='Controlled history explanation.\n\n| Fixture | State |\n|---|---|\n| history | retained |\n\n&lt;img data-history-narrative="owned" src="invalid"&gt;';
function createControlledNarrative(){
 let calls=0,next=null;const active=new Set();
 return {provider:'fixture',get calls(){return calls;},
  arm(){assert.equal(next,null);let entered,release;const began=new Promise(r=>{entered=r;}),finished=new Promise(r=>{release=r;});const gate={began,release,finished};next={gate,entered};active.add(gate);return gate;},
  async generateResponse(){assert(++calls<=LIMITS.controlledCallsPerFamily,'Controlled call bound');const hold=next;next=null;if(hold){hold.entered();await hold.gate.finished;active.delete(hold.gate);return {response:'LATE_HISTORY_RESPONSE',provider:'fixture',mocked:true};}return {response:NARRATIVE,provider:'fixture',mocked:true};},
  releaseAll(){if(next){next.entered();next=null;}for(const gate of active)gate.release();active.clear();},
 };
}
function assertPersisted({body,history,request}){
 assert.equal(body.success,true);assert.equal(body.presentation?.narrative.source,'fixture');assert.equal(body.run?.responseSource,'fixture');assert.equal(body.presentation.responseSha256,sha(body.response));assert.deepEqual(body.completedObjectives,[]);assert.deepEqual(body.judgments,[]);
 assert.deepEqual(history.map(({message_type,message})=>({message_type,message})),[{message_type:'user',message:request},{message_type:'assistant',message:body.response}]);
 assert.equal(body.toolObservations.length,1);assert.equal(body.toolObservations[0].toolResult.length,4);
 return {responseSha256:sha(body.response),rowCount:4,source:'fixture'};
}
function assertZeroCredit(rows){assert.equal(rows.length,0,'Controlled browser fixture cannot earn canonical credit');}
function responseWait(page,predicate,timeout){const controller=new AbortController();const outcome=page.waitForResponse(predicate,{timeout,signal:controller.signal}).then(value=>({value}),error=>({error}));return {outcome,async read(){const result=await outcome;if(result.error)throw result.error;return result.value;},async close(){controller.abort();await outcome;}};}
function clickResetControl({resetLabel,resetTitle}){
 const matches=[...document.querySelectorAll('button')].filter(button=>button.textContent.trim()===resetLabel&&button.getAttribute('title')===resetTitle);
 if(matches.length!==1||matches[0].disabled||matches[0].getAttribute('aria-disabled')==='true')throw Error('Exact enabled reset control required');
 matches[0].click();
}
function browserProjection({family,expectedRows}){
 const bubbles=[...document.querySelectorAll('[data-message-id] .bubble')];const bubble=bubbles.find(e=>e.textContent.includes('Controlled history explanation.'));
 if(!bubble)return false;
 const normalized=value=>String(value).replace(/\s+/g,' ').trim();
 const text=normalized(bubble.textContent);
 const fixtureTable=[...bubble.querySelectorAll('table')].some(t=>[...t.querySelectorAll('td')].map(c=>c.textContent.trim()).join('|')==='history|retained');
 let exactRows=false;
 if(family==='sql'){
  const rows=[];for(const block of bubble.querySelectorAll('pre code')){try{rows.push(JSON.parse(block.textContent));}catch{}}
  exactRows=JSON.stringify(rows)===JSON.stringify(expectedRows);
 }else{
  const headerKeys=t=>{try{return [...t.querySelectorAll('th')].map(e=>{const key=JSON.parse(e.textContent);if(typeof key!=='string')throw Error('Invalid result header');return key;});}catch{return null;}};
  const table=[...bubble.querySelectorAll('table')].find(t=>headerKeys(t)?.includes('paper_id'));
  if(table){const keys=headerKeys(table);const actual=[...table.querySelectorAll('tbody tr')].map(row=>[...row.querySelectorAll('td')].map(cell=>cell.textContent));const expected=expectedRows.map(row=>keys.map(key=>Object.hasOwn(row,key)?JSON.stringify(row[key]):'— (absent)'));exactRows=JSON.stringify([...keys].sort())===JSON.stringify([...new Set(expectedRows.flatMap(Object.keys))].sort())&&JSON.stringify(actual)===JSON.stringify(expected);}
 }
 return fixtureTable&&exactRows&&text.includes('<img data-history-narrative="owned" src="invalid">')&&!bubble.querySelector('img,script,iframe,[data-history-probe],[data-history-narrative]');
}
async function qualify({browser,origin,token,siblingToken,learnerId,siblingId,stores,providers,joinInvocations,evidence,onCheckpoint=()=>{}}){
 const {bounded,settleOwnership}=require('./secureshopAnalyticsBrowserOwner');
 const contexts=[],waits=new Set(),cases=[],started=Date.now();let api=0,chats=0,resets=0,historyRequests=0,stage='start';const http=[];
 const checkpoint=()=>onCheckpoint({stage,api,chats,resets,historyRequests,http:[...http],cases:[...cases]});
 const ui=fn=>{const remaining=LIMITS.uiMs-(Date.now()-started);assert(remaining>0,'History browser deadline');return bounded(Promise.resolve().then(fn),Math.min(LIMITS.operationMs,remaining),'History browser operation deadline');};
 const wait=(page,pathname,method)=>{const w=responseWait(page,r=>new URL(r.url()).pathname===pathname&&(!method||r.request().method()===method),LIMITS.operationMs);waits.add(w);return w;};
 const read=async w=>{try{const response=await ui(()=>w.read());assert.equal(response.status(),200);return await ui(()=>response.json());}finally{await w.close();waits.delete(w);}};
 async function page(bearer){
  let abandoned=false;const pending=browser.createBrowserContext();pending.then(c=>{if(abandoned)c.close().catch(()=>{});},()=>{});let context;
  try{context=await ui(()=>pending);}catch(error){abandoned=true;throw error;}contexts.push(context);const p=await ui(()=>context.newPage());await ui(()=>p.setCacheEnabled(false));await ui(()=>p.setViewport({width:1440,height:1000}));p.setDefaultTimeout(LIMITS.operationMs);p.setDefaultNavigationTimeout(LIMITS.operationMs);
  await ui(()=>p.evaluateOnNewDocument(t=>localStorage.setItem('token',t),bearer));await fence(p);return p;
 }
 async function fence(p){await ui(()=>p.setRequestInterception(true));p.on('request',r=>{let allowed=false;try{const u=new URL(r.url());allowed=u.origin===origin||['data:','about:','blob:'].includes(u.protocol);if(u.origin===origin&&u.pathname.startsWith('/api/')){api++;if(/\/history\//.test(u.pathname))historyRequests++;allowed&&=api<=LIMITS.api;if(r.method()==='POST'&&/\/chat$/.test(u.pathname)){chats++;allowed&&=chats<=LIMITS.chats;}if(r.method()==='POST'&&/\/reset$/.test(u.pathname)){resets++;allowed&&=resets<=LIMITS.resets;}}}catch{}(allowed?r.continue():r.abort()).catch(()=>{});});
  p.on('response',r=>{const u=new URL(r.url());if(u.origin===origin&&u.pathname.startsWith('/api/')&&http.length<LIMITS.api)http.push({path:u.pathname,status:r.status(),method:r.request().method()});});
 }
 const send=async(p,message)=>{await ui(()=>p.waitForSelector('textarea:not([disabled])'));await ui(()=>p.type('textarea',message));await ui(()=>p.keyboard.press('Enter'));};
 try{
  for(const family of FAMILIES){
   stage=family.id+':open';checkpoint();const learner=await page(token),sibling=await page(siblingToken),endpoint='/api/workshop/'+family.id;
   const open=async(p,id)=>{const w=wait(p,endpoint+'/history/'+id,'GET');await ui(()=>p.goto(origin+'/workshop/'+family.id,{waitUntil:'domcontentloaded'}));await read(w);await ui(()=>p.waitForSelector('textarea:not([disabled])'));};
   const siblingMarker='SIBLING_HISTORY_'+family.id;await stores[family.id].saveMessage(String(siblingId),'assistant',siblingMarker);const siblingBefore=await stores[family.id].getHistory(String(siblingId),50);
   await open(learner,learnerId);await open(sibling,siblingId);await ui(()=>sibling.waitForFunction(marker=>document.body.textContent.includes(marker),{},siblingMarker));assert.equal(await ui(()=>learner.evaluate(marker=>document.body.textContent.includes(marker),siblingMarker)),false);
   stage=family.id+':persist';checkpoint();const response=wait(learner,endpoint+'/chat','POST');await send(learner,family.request);const body=await read(response);const reference=family.id==='sql'?await stores.sql.searchProducts('HistoryProbe',null,'fixed'):await stores.nosql.searchPapers('HistoryProbe',null,null,'fixed');assert.deepEqual(body.toolResult,JSON.parse(JSON.stringify(reference)));const persisted=assertPersisted({body,history:await stores[family.id].getHistory(String(learnerId),50),request:family.request});
   require('./boundedJsonArtifact').saveBounded(path.join(evidence,family.id+'-composed-history.json'),{body,history:await stores[family.id].getHistory(String(learnerId),50)});
   const values=family.id==='sql'?body.toolResult.map(r=>r.name):body.toolResult.map(r=>r.title);assert.equal(values.length,4);assert(values.some(x=>x===LONG));
   await ui(()=>learner.waitForFunction(browserProjection,{},{family:family.id,expectedRows:body.toolResult}));await ui(()=>learner.screenshot({path:path.join(evidence,family.id+'-before-reload.png'),fullPage:true}));
   stage=family.id+':reload';checkpoint();const history=wait(learner,endpoint+'/history/'+learnerId,'GET');await ui(()=>learner.reload({waitUntil:'domcontentloaded'}));const loaded=await read(history);assert.deepEqual(loaded.history.map(({message_type,message})=>({message_type,message})),[{message_type:'user',message:family.request},{message_type:'assistant',message:body.response}]);await ui(()=>learner.waitForFunction(browserProjection,{},{family:family.id,expectedRows:body.toolResult}));
   assert.equal(await ui(()=>sibling.evaluate(()=>document.body.textContent.includes('Controlled history explanation.'))),false);assert.deepEqual(await stores[family.id].getHistory(String(siblingId),50),siblingBefore);
   stage=family.id+':reset-pending';checkpoint();const resetGate=providers[family.id].arm();await send(learner,family.request);await ui(()=>resetGate.began);const reset=wait(learner,endpoint+'/reset','POST');await ui(()=>learner.evaluate(clickResetControl,{resetLabel:family.resetLabel,resetTitle:family.resetTitle}));await read(reset);resetGate.release();await ui(()=>resetGate.finished);await ui(joinInvocations);await ui(()=>learner.waitForFunction(()=>!document.body.textContent.includes('Controlled history explanation.')&&!document.body.textContent.includes('LATE_HISTORY_RESPONSE')));assert.deepEqual(await stores[family.id].getHistory(String(learnerId),50),[]);
   stage=family.id+':owner-pending';checkpoint();const ownerGate=providers[family.id].arm();await send(learner,family.request);await ui(()=>ownerGate.began);
   // A real same-origin second tab changes the token; the browser emits the
   // storage event to the mounted workshop, exercising AuthContext itself.
   const switcher=await ui(()=>learner.browserContext().newPage());switcher.setDefaultNavigationTimeout(LIMITS.operationMs);await fence(switcher);await ui(()=>switcher.goto(origin+'/api/history-owner-switch',{waitUntil:'domcontentloaded'}));const changed=wait(learner,endpoint+'/history/'+siblingId,'GET');await ui(()=>switcher.evaluate(t=>localStorage.setItem('token',t),siblingToken));await read(changed);await ui(()=>learner.waitForFunction(marker=>document.body.textContent.includes(marker),{},siblingMarker));ownerGate.release();await ui(()=>ownerGate.finished);await ui(joinInvocations);await ui(()=>learner.waitForFunction(()=>!document.body.textContent.includes('LATE_HISTORY_RESPONSE')&&!document.body.textContent.includes('Controlled history explanation.')));assert.deepEqual(await stores[family.id].getHistory(String(siblingId),50),siblingBefore);assert.deepEqual(await stores[family.id].getHistory(String(learnerId),50),[]);
   await ui(()=>learner.screenshot({path:path.join(evidence,family.id+'-after-fences.png'),fullPage:true}));cases.push({id:family.id,...persisted,persistenceReload:true,siblingIsolation:true,resetLateResponse:true,ownerSwitchLateResponse:true,actualRenderedResults:true,resultLayout:family.id==='sql'?'json-blocks':'table',escapedHtml:true,siblingHistoryPreserved:true});checkpoint();
   await ui(()=>learner.browserContext().close());await ui(()=>sibling.browserContext().close());contexts.splice(contexts.length-2,2);
  }
  assert.equal(chats,LIMITS.chats);assert.equal(resets,LIMITS.resets);assert.equal(Object.values(providers).reduce((n,p)=>n+p.calls,0),LIMITS.controlledCalls);return {cases,requests:{api,chats,resets,historyRequests},controlledProviderCalls:LIMITS.controlledCalls};
 }finally{for(const w of waits)await w.close();const rows=await settleOwnership(contexts.map((c,i)=>['context-'+i,()=>c.close()]),10000);for(const provider of Object.values(providers))provider.releaseAll();assert(rows.every(r=>r.status==='fulfilled'),'History contexts did not retire');}
}
async function retireInvocations({agents,owners,providers,join}){
 const failures=[];for(const agent of agents)for(const owner of owners)try{agent.cancel(owner);}catch(error){failures.push(error);}for(const provider of Object.values(providers))try{provider.releaseAll();}catch(error){failures.push(error);}try{await join();}catch(error){failures.push(error);}if(failures.length)throw new AggregateError(failures,'Controlled graph retirement failed');
}
async function run({owned,runtime,ports,source}){
 const {saveBounded}=require('./boundedJsonArtifact'),{settleOwnership}=require('./secureshopAnalyticsBrowserOwner');const result={status:'preparing',profile:'workshop-history',actualModelProof:false,modelCalls:0,genuineCredit:0,installedWrites:false,cleanupFailures:[],cases:[]};const save=()=>saveBounded(path.join(owned.evidence,'result.json'),result);
 const pools=[],restores=[],providers={},stores={},inflight=new Set(),agents=[];let ownerIds=[];const joinInvocations=async()=>{const results=await Promise.allSettled([...inflight]);for(const row of results)if(row.status==='rejected')assert.equal(row.reason?.name,'AbortError');};let pg,server,browser,mounted,primary;
 try{
  result.stage='migration-probe';save();
  pg=require('../../server/database/postgres');for(const prefix of ['IDENTITY','SQL_WORKSHOP','NOSQL_WORKSHOP'])for(const suffix of ['_DATABASE_URL','_MIGRATION_DATABASE_URL'])pools.push(pg.createPool(process.env,prefix+suffix));const [identity,migration]=pools;
  const identityApi=require('../../server/database/postgres/identityRepository');result.migrationProbe=await require('./workshopPresentationMigration').qualify({runtime:identity,migration,viewRoot:runtime,sourcePins:owned.manifest.sourcePins});result.stage='identity-initialization';save();await identityApi.initializeIdentityRepository(identity,migration);await require('../../server/database/postgres/workshopPlatformSeed').seedWorkshopPlatform(migration);
  for(const [i,f]of FAMILIES.entries()){const module=require('../../server/database/postgres/'+f.store);stores[f.id]=module[f.factory](pools[2+i*2]);await stores[f.id][f.initialize](pools[3+i*2]);}
  for(let i=0;i<4;i++){await pools[3].query('INSERT INTO aria.products(product_id,name,category,price,description,stock) VALUES($1,$2,$3,$4,$5,$6)',['PROD-'+(99000+i),i===0?LONG:'HistoryProbe row '+i,'owned fixture',10+i,i===0?null:'full description '+i,9]);await pools[5].query('INSERT INTO nova.papers(paper_id,title,abstract,authors,topics,year,journal,citations,cited_by,url,access_level) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)',['PAPER-2099-00'+i,i===0?LONG:'HistoryProbe row '+i,'owned fixture','["Alpha","Beta","Gamma"]','[]',2099,null,123+i,'[]','https://example.invalid/fixture','public']);}
  const users=identityApi.createIdentityRepository(identity),hash=await require('bcryptjs').hash(crypto.randomUUID(),4),make=()=>users.createUser({username:crypto.randomUUID(),email:crypto.randomUUID()+'@example.invalid',passwordHash:hash});const learner=await make(),sibling=await make();ownerIds=[String(learner.id),String(sibling.id)];
  const platform=await require('../../server/services/postgresPlatformStores').getPostgresPlatformStores(),adapter=require('../../server/services/postgresIdentityAdapter').getPostgresIdentityAdapter(),session=async u=>adapter.createSession(await users.findCredentialById(u.id),{get:()=>null,ip:'127.0.0.1'});const token=(await session(learner)).token,siblingToken=(await session(sibling)).token;
  await migration.query('UPDATE workshop_platform.exercises SET is_visible=(workshop_key=ANY($1::text[]))',[FAMILIES.map(f=>f.key)]);await migration.query('UPDATE workshop_platform.objectives SET is_enabled=true WHERE workshop_key=ANY($1::text[])',[FAMILIES.map(f=>f.key)]);
  const express=require('express'),app=express();app.use(express.json({limit:'128kb'}));mounted=await require('./legacyFileSsiFullAppParity').mountLegacyParityRoutes({app,adapter,pool:identity,migration,progress:platform.progress,config:platform.config,identity:users});
  for(const f of FAMILIES){for(const userId of [learner.id,sibling.id])await require('../../server/services/workshopModeService').setMode({userId,workshopKey:f.key,mode:'fixed'});const service=require('../../server/services/'+f.name+'AgentService'),previous={invoke:service.invoke,reset:service.reset,cancel:service.cancel};providers[f.id]=createControlledNarrative();const agent=service.createAgent({store:stores[f.id],model:providers[f.id],decisionMode:'scripted',runLedger:require('../../server/agent-runtime/postgresRunLedger').configuredRunLedger()});agents.push(agent);Object.assign(service,{invoke(...args){const pending=agent.invoke(...args);inflight.add(pending);pending.then(()=>inflight.delete(pending),()=>inflight.delete(pending));return pending;},reset:agent.reset,cancel:agent.cancel});restores.push(()=>Object.assign(service,previous));app.use('/api/workshop/'+f.id,require('../../server/routes/'+f.id+'Workshop'));}
  app.use('/api/solutions',require('../../server/routes/solutions'));app.use('/api/hints',require('../../server/routes/hints'));app.use('/api',(_q,s)=>s.sendStatus(404));app.use(express.static(path.join(source,'client/build')));app.get('/{*path}',(_q,s)=>s.sendFile(path.join(source,'client/build/index.html')));
  server=await new Promise((resolve,reject)=>{const s=app.listen(0,'127.0.0.1',()=>resolve(s));s.once('error',reject);});ports.add(server.address().port);browser=await require('./secureshopAnalyticsBrowserOwner').launchOwnedAnalyticsBrowser(runtime,'browser');result.stage='browser';save();Object.assign(result,await qualify({browser,origin:'http://127.0.0.1:'+server.address().port,token,siblingToken,learnerId:learner.id,siblingId:sibling.id,stores,providers,joinInvocations,evidence:owned.evidence,onCheckpoint:value=>{result.diagnostic=value;save();}}));
  assertZeroCredit((await identity.query('SELECT objective_id FROM workshop_platform.completions WHERE user_id=ANY($1::bigint[])',[[learner.id,sibling.id]])).rows);result.status='passed';result.stage='done';
 }catch(error){primary=error;result.status='failed';result.failure={name:error.name,code:typeof error.code==='string'&&/^[A-Z0-9_]{1,80}$/.test(error.code)?error.code:null,frames:String(error.stack).split('\n').slice(1,8).map(x=>x.match(/((?:tests|server)\/[^ ()]+:\d+:\d+)/)?.[1]).filter(Boolean)};save();
 }finally{const rows=[];rows.push(...await settleOwnership([['browser',()=>browser?.close()]],10000));rows.push(...await settleOwnership([['routes',()=>mounted?.close?.()],['server',()=>new Promise((resolve,reject)=>{if(!server)return resolve();server.close(e=>e?reject(e):resolve());server.closeAllConnections?.();})]],10000));rows.push(...await settleOwnership([['runs',async()=>{await retireInvocations({agents,owners:ownerIds,providers,join:joinInvocations});assert.equal(inflight.size,0);}]],10000));rows.push(...await settleOwnership([['pools',async()=>{const closed=await Promise.allSettled(pools.map(p=>p.end()));await pg?.closePostgresPools();assert(closed.every(x=>x.status==='fulfilled'));}]],10000));for(const restore of restores)restore();result.cleanup=rows;result.cleanupFailures=rows.filter(x=>x.status==='rejected');if(result.cleanupFailures.length)result.status='failed';save();}
 if(primary||result.status!=='passed')throw Error('Controlled workshop history qualification failed');return result;
}
module.exports={FAMILIES,LIMITS,LONG,NARRATIVE,createControlledNarrative,assertPersisted,assertZeroCredit,responseWait,browserProjection,clickResetControl,retireInvocations,qualify,run};
