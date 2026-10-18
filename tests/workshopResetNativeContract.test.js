'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs');
test('reset-only native launcher preserves family selection and bounded no-model qualification',()=>{
 const launcher=fs.readFileSync('tests/postgres/run-workshop-reset-session-isolated.py','utf8');
 assert.match(launcher,/signal\.alarm\(900\)/);assert.match(launcher,/child_deadline=time\.monotonic\(\)\+720/);assert.match(launcher,/family=='xss' else 'tests\/postgres\/workshopResetCaller.native.js'/);assert.match(launcher,/'maxActualHttpCalls':0/);
 const xss=fs.readFileSync('tests/postgres/workshopResetXss.native.js','utf8');
 assert.match(xss,/pg_blocking_pids/);assert.match(xss,/classid=\$1::oid AND objid=\$2::oid/);assert.match(xss,/serialized\.profile\.profile\.bio,value/);assert.match(xss,/serialized\.progress,\[\]/);assert.match(xss,/response\.headers\.get\('retry-after'\),'2'/);assert.match(xss,/revoked-waiter/);
 const caller=fs.readFileSync('tests/postgres/workshopResetCaller.native.js','utf8');assert.match(caller,/\['\/reset','\/progress\/reset','\/conversation\/reset'\]/);assert.match(caller,/after\.effects,before\.effects/);assert.match(caller,/snapshot\('sibling'\),sibling/);
});
test('fixture request drain waits for in-flight handlers and bounds failure cleanup',async()=>{
 const {trackedRequests}=require('./postgres/workshopSessionNativeSupport');const requests=trackedRequests();let release;
 requests.track(new Promise(resolve=>release=resolve));assert.equal(await requests.drain(5),false);release();assert.equal(await requests.drain(50),true);
 requests.track(Promise.reject(new Error('retained original failure')));assert.equal(await requests.drain(50),true);
});
for(const [family,tool,params,method]of [['aria','add_to_cart',{productName:'Laptop'},'addToCart'],['nova','add_to_reading_list',{paperId:'P-1'},'addToReadingList']])test(`${family} native controlled wire enters actual decision graph rather than mock regex dispatch`,async()=>{
 const {selectControlledDecisionWire}=require('./postgres/workshopSessionNativeSupport');let decisions=0,selected=0;
 const model={provider:'mock',generateResponse:async prompt=>({provider:'ollama',model:'CONTROLLED-NOT-ACTUAL',response:prompt.includes('Select exactly one tool')?JSON.stringify(++decisions===1?{tool,params}:{tool:'general_chat',params:{}}):'CONTROLLED'})};
 const wire=selectControlledDecisionWire(model);
 try{
  const store={getHistory:async()=>[],saveMessage:async()=>{},[method]:async()=>{selected++;return{success:true};}};
  const agent=require(`../server/services/${family}AgentService`).createAgent({store,model,runLedger:null});
  await agent.invoke('7','Add the selected item to my own collection.','vuln');
  assert.ok(decisions>0);assert.equal(selected,1);assert.match(wire.qualification,/synthetic/);
 }finally{wire.restore();assert.equal(model.provider,'mock');}
});
