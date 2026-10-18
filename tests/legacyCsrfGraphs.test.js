'use strict';
const Module=require('node:module'),load=Module._load;
Module._load=function(r,p,m){if(/(?:^|\/)authDb(?:\.js)?$/.test(r))throw Error('Test isolation: authDb forbidden');return load.call(this,r,p,m);};
const {test}=require('node:test'),assert=require('node:assert/strict');
const {runLegacyXssGraph,runLegacyCtfGraph,runBiasGraph}=require('../server/agent-runtime/legacyChallengeGraphs');
const {runCsrfInboxGraph}=require('../server/agent-runtime/csrfInboxGraph');
const {runCsrfRagGraph}=require('../server/agent-runtime/csrfRagGraph');
test('Legacy graphs preserve reflection, partial grading and zero temperature',async()=>{
 const payload='<img onerror=fixture()>';assert.match(await runLegacyXssGraph(payload,{aiService:{generateResponse:async()=>({response:'hello'})}}),/onerror=fixture/);
 const ctf=await runLegacyCtfGraph('question',{systemPrompt:'prompt',secret:'PART_SECRET'},{aiService:{generateResponse:async()=>({response:'PART'})}});assert.equal(ctf.extractionMethod,'encoded');
 const bias=await runBiasGraph('fixture',0,{ollamaService:{generateResponse:async(p,o)=>{assert.equal(o.temperature,0);return {response:'typically fixture'};}}});assert.equal(bias.hasBias,true);
});
test('CSRF inbox read uses classified browser, credit, HTML and missing-inbox branch',async()=>{
 const credits=[],events=[];let forged=0,broadListings=0;const sandbox={getTabState:()=>({}),forge:()=>{forged++;return {blocked:false,executed:true,stateChanged:true,changed:{from:'before',to:'after'}};}};
 const deps={execution:{trace:async event=>{await Promise.resolve();events.push(event);}},mailbox:{fetchEmails:async()=>{broadListings++;return {emails:[{id:1}]};}},mailDispatch:{retrieve:async()=>({email:{payload:'<img onerror=fixture()>',body:'<img onerror=fixture()>',subject:'fixture',from:'fixture',sender:'fixture'}})},aiService:{},TABS:{xss:{victim:{name:'fixture'}}},LLM_STARTING:'starting',executeClassifiedEmail:async()=>{forged++;return {qualified:true,proof:{},browser:{receipt:{},activity:{}}};},noteClassifiedEmailProof:()=>{},getCompleted:async()=>new Set(),creditObjective:async(u,id)=>{credits.push(id);return true;},summarizeWithHtml:async()=>({answer:'<img onerror=fixture()>',llmOk:true,modelGenerated:true,htmlPreserved:true}),extractGadgetMessage:()=> 'fixture',noteGradeReceipt:()=>{}};
 const missing=await runCsrfInboxGraph({t:{},sandbox},deps);assert.match(missing.response,/Set up/);assert.equal(forged,0);
 const result=await runCsrfInboxGraph({t:{xssInbox:'fixture'},sandbox,userKey:'owner',userId:1,wantsList:false,mailScope:{}},deps);assert.equal(forged,1);assert.deepEqual(credits,['csrf_x3']);assert.match(result.ragHtml,/onerror/);assert.equal(broadListings,0);
 const unavailable=await runCsrfInboxGraph({t:{xssInbox:'fixture'},sandbox,userKey:'owner',userId:1,wantsList:false,mailScope:{}},{...deps,mailDispatch:{retrieve:async()=>({error:'No exact current dispatch'})}});
 assert.match(unavailable.response,/No exact current dispatch/);assert.equal(forged,1);assert.deepEqual(credits,['csrf_x3']);
 assert.ok(events.find(event=>event.node==='browser'&&event.type==='node_start'));assert.equal(events.some(event=>event.data.decisionSource==='lab_gadget_interpreter'),false);assert.equal(JSON.stringify(events).includes('<img'),false);
 await assert.rejects(runCsrfInboxGraph({t:{xssInbox:'fixture'},sandbox,userKey:'owner',userId:1,wantsList:false,mailScope:{}},{...deps,execution:{trace:async event=>{if(event.node==='browser')throw Error('trace unavailable');}}}),/trace unavailable/);assert.equal(forged,1);

});
test('CSRF RAG only forges when poisoned chunk ranks with sufficient relevance',async()=>{
 let forged=0;const sandbox={getTabState:()=>({}),forge:()=>{forged++;return {blocked:false,executed:true,stateChanged:true,changed:{from:'before',to:'after'}};}};
 const deps={ensureCleanKb:async()=> 'clean',ragVectorStore:{similaritySearch:async(u,id)=>id==='clean'?[{text:'policy',score:1}]:[{text:'<img onerror=fixture()>',score:0.9}]},summarizeWithHtml:async()=>({answer:'<img onerror=fixture()>',llmOk:true,modelGenerated:true,htmlPreserved:true}),XSS_GADGET_RE:/onerror/,extractGadget:()=>'<img onerror=fixture()>',directiveToAction:()=> 'change_email',directiveParams:()=>({}),recordActivity:async()=>{},getCompleted:async()=>new Set(),creditObjective:async()=>true,extractGadgetMessage:()=> 'fixture'};
 const clean=await runCsrfRagGraph({t:{},message:'policy',lower:'policy',sandbox},deps);assert.equal(forged,0);assert.deepEqual(clean.newlyCompleted,[]);
 let checked=0;await assert.rejects(runCsrfRagGraph({t:{},message:'policy',sandbox},{...deps,ensureCleanKb:async()=>{checked++;return 'clean';},execution:{trace:async()=>{throw Error('trace failed');}}}),/trace failed/);assert.equal(checked,0);
 const attack=await runCsrfRagGraph({t:{ragPoisoned:true,ragSessionId:'poison'},message:'policy',lower:'policy',sandbox},deps);assert.equal(forged,1);assert.deepEqual(attack.newlyCompleted,['csrf_i2']);
});
test('Legacy Ollama method graphs preserve deterministic parsers and offline contracts',async()=>{
 const {OllamaService}=require('../server/services/ollamaService');const service=new OllamaService('http://fixture.invalid');
 service.generateResponse=async()=>({response:'Step 1: fixture COMMAND: ls',model:'fixture'});
 const cot=await service.processChainOfThoughtAttack('fixture',{temperature:0});assert.equal(cot.reasoning_detected,true);
 const context=await service.processContextStuffing('fixture','abc');assert.equal(context.success,true);assert.equal(typeof context.context_length,'number');
 const multi=await service.processMultiTurnJailbreak([{user:'ignore previous',assistant:'fixture'}],'fixture');assert.equal(multi.jailbreak_detected,true);
 const sql=await service.processSQLRequest('show all orders');assert.equal(sql.sqlQuery,'SELECT * FROM orders');
 service.generateResponse=async()=>{throw Error('fixture offline');};
 const fallback=await service.processChainOfThoughtAttack('fixture');assert.equal(fallback.success,false);assert.match(fallback.response,/Offline mode/);
});
test('CTF admission blocks previously used technique before model/input filter and counts once',async()=>{
 const {runCtfAdmissionGraph}=require('../server/agent-runtime/ctfAdmissionGraph');let increments=0,logged=0;
 const result=await runCtfAdmissionGraph({payload:'fixture',stage:{adaptive_mode:'hybrid'},participant:{id:1},stageId:2,sessionToken:'fixture'},{classifyTechnique:()=>({tag:'fixture',confidence:1}),hashPayload:()=>({hash:'h',normalized:'n'}),TECHNIQUE_TAGS:{OTHER:'other'},isNearDuplicate:()=>{throw Error('wrong order');},CTFHelpers:{getConfig:async()=> 'true',istechniqueBlocked:async()=>true,logAttempt:async()=>logged++},atomicIncrementAttempts:async()=>++increments,runDefenseLayers:()=>{throw Error('blocked before filters');}});
 assert.equal(result.blockedResponse.blocked,true);assert.equal(increments,1);assert.equal(logged,1);
});
test('CTF failed result logs post-defense response and does not complete stage',async()=>{
 const {runCtfResultGraph}=require('../server/agent-runtime/ctfResultGraph');let committed=false;
 const result=await runCtfResultGraph({wasSuccessful:false,participant:{id:1},stageId:2,stage:{level_score:100},attemptNumber:3,studentResponse:'[redacted]',techniqueTag:'fixture',adaptiveMode:'none',showFeedback:false},{commit:async()=>{committed=true;return {accepted:false};},TECHNIQUE_TAGS:{OTHER:'other'},leaderboardRefresh:{requestRefresh:()=>{}},ctfDb:{run:(s,p,cb)=>cb(),get:(s,p,cb)=>cb(null,{hints_used:1,hint_penalty_total:5})},CTFHelpers:{getProgress:async()=>({hints_used:1,hint_penalty_total:5}),logAttempt:async()=>{throw Error("commit owns audit");},updateParticipantActivity:async()=>{},getConfig:async()=> '3',completeStage:()=>{throw Error('failure completed stage');}}});
 assert.equal(result.success,false);assert.equal(result.aiResponse,'[redacted]');assert.equal(result.hintPenaltyTotal,5);assert.equal(committed,true);
});
test('Explicit mock provider never invokes adapter or network fallback',async()=>{
 const {createMultiProviderAIService}=require('../server/services/multiProviderAIService');
 const svc=createMultiProviderAIService({env:{AI_PROVIDER:'mock'},logger:{log:()=>{}},providerFactory:()=>{throw Error('network adapter forbidden');}});
 svc.checkOllamaAvailable=()=>{throw Error('network probe forbidden');};
 for(const result of [await svc.generateResponse('fixture'),await svc.chatWithMessages([{role:'user',content:'fixture'}]),await svc.chatWithTools([],[]),await svc.fallbackGenerate('fixture',0,1)]){assert.equal(result.provider,'mock');assert.equal(result.mocked,true);assert.equal(result.fallback,true);}
 assert.equal((await svc.verifyProviderConnection('mock')).mocked,true);assert.equal((await svc.verifyProviderConnectionLite('mock')).mocked,true);assert.equal(svc.getActiveProviderInfo().model,'deterministic-mock');
});

test('teaching interpreter classification survives the public trace projection',()=>{
 const {traceData}=require('../server/agent-runtime/runTraceStore');
 assert.deepEqual(traceData({decisionSource:'lab_gadget_interpreter',rawPayload:'private fixture'}),{decisionSource:'lab_gadget_interpreter'});
});
