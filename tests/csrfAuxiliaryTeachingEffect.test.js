'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
function boundary(){let held=false;const events=[];return{events,inside:name=>{assert.equal(held,true);events.push(name);},outside:name=>{assert.equal(held,false);events.push(name);},execution:{check:async()=>assert.equal(held,false),trace:async()=>{},withTeachingEffect:async work=>{held=true;events.push('acquire');try{return await work();}finally{held=false;events.push('release');}}}};}
test('RAG forge and successful-query counter flush together before activity and Judge',async()=>{
 const f=boundary(),t={ragPoisoned:true,ragSessionId:'poison'};
 const sandbox={getTabState:()=>({}),forge:()=>{f.inside('forge');return{blocked:false,executed:true};},flush:async()=>{f.inside('flush');assert.equal(t.ragFiredQuestions.length,1);}};
 const deps={execution:f.execution,ensureCleanKb:async()=>{f.outside('clean');return'clean';},ragVectorStore:{similaritySearch:async()=>[{text:'policy <img onerror=fixture()>',score:1}]},summarizeWithHtml:async()=>{f.outside('model');return{answer:'<img onerror=fixture()>',llmOk:true,modelGenerated:true,htmlPreserved:true};},XSS_GADGET_RE:/onerror/,extractGadget:()=>'<img onerror=fixture()>',directiveToAction:()=> 'change_email',directiveParams:()=>({}),recordActivity:async()=>f.outside('activity'),getCompleted:async()=>new Set(),creditObjective:async()=>{f.outside('judge');return true;},extractGadgetMessage:()=> 'fixture'};
 await require('../server/agent-runtime/csrfRagGraph').runCsrfRagGraph({userKey:'7',userId:7,t,message:'policy',sandbox},deps);
 assert.deepEqual(f.events.slice(-5),['forge','flush','release','activity','judge']);
});
test('fixed poisoned RAG still answers with real retrieval but never publishes a gadget or victim effect',async()=>{
 const f=boundary(),t={ragPoisoned:true,ragSessionId:'poison'},sandbox={getTabState:()=>({balance:100}),forge:()=>assert.fail('fixed RAG must not forge')};
 let summaryKind,credits=0,checks=0;
 const output=await require('../server/agent-runtime/csrfRagGraph').runCsrfRagGraph({userKey:'7',userId:7,t,message:'policy',sandbox},{mode:'fixed',assertMode:async()=>{checks++;},execution:f.execution,ensureCleanKb:async()=> 'clean',ragVectorStore:{similaritySearch:async()=>[{text:'policy <img onerror=fixture()>',score:1}]},summarizeWithHtml:async(_context,_question,kind)=>{summaryKind=kind;return{answer:'Policy details <img onerror=fixture()>',llmOk:true,modelGenerated:true,htmlPreserved:true};},XSS_GADGET_RE:/onerror/,extractGadget:()=>assert.fail('fixed RAG must not parse executable gadget'),recordActivity:async()=>assert.fail('fixed RAG must not log attack'),getCompleted:async()=>new Set(),creditObjective:async()=>{credits++;return true;}});
 assert.equal(summaryKind,'rag_fixed');assert.equal(output.responseFormat,'plain_text');assert.equal(output.ragHtml,undefined);assert.deepEqual(output.newlyCompleted,[]);assert.equal(output.victimState.balance,100);assert.equal(credits,0);assert.ok(checks>0);assert.deepEqual(f.events,[]);
});
test('classified browser proof precedes short email-read flush; Judge outside',async()=>{
 const f=boundary(),t={xssInbox:'owner@example.invalid'},sandbox={getTabState:()=>({}),flush:async()=>{f.inside('flush');assert.equal(t.xssEmailRead,true);}};
 await require('../server/agent-runtime/csrfInboxGraph').runCsrfInboxGraph({userKey:'7',userId:7,t,sandbox,wantsList:false,mailScope:{}},{execution:f.execution,mailDispatch:{retrieve:async()=>{f.outside('mail');return{email:{payload:'<img onerror=fixture()>',body:'<img onerror=fixture()>',subject:'s',from:'sender'}};}},TABS:{xss:{victim:{name:'v'}}},summarizeWithHtml:async()=>{f.outside('model');return{answer:'<img onerror=fixture()>',llmOk:true,modelGenerated:true,htmlPreserved:true};},executeClassifiedEmail:async()=>{f.outside('browser');return{qualified:true,proof:{},browser:{receipt:{},activity:{}}};},noteClassifiedEmailProof:async()=>f.outside('proof'),getCompleted:async()=>new Set(),creditObjective:async()=>{f.outside('judge');return true;},extractGadgetMessage:()=>'',recordActivity:async()=>f.outside('activity'),noteGradeReceipt:()=>{}});
 assert.deepEqual(f.events.slice(f.events.indexOf('proof'),f.events.indexOf('judge')+1),['proof','acquire','flush','release','judge']);
});
test('durable RAG projections use trusted mutation callback only after authoritative read',async()=>{
 const {createCsrfDurableRagResources}=require('../server/services/csrfDurableRagResources');const events=[],tab={};
 const service=await createCsrfDurableRagResources({tab,execution:{},composition:{resolveRequest:async()=>({read:async({slot})=>{events.push(`read:${slot}`);return{document:{},documentId:slot};}})},mutateTab:async work=>{events.push('mutate');work();events.push('flush');}});
 await service.ensureClean();await service.assertPoisonAvailable();assert.deepEqual(events,['read:clean','mutate','flush','read:poison','mutate','flush']);assert.equal(tab.ragSessionId,'poison');
});
