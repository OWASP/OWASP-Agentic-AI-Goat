'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const C=require('./secureshopRestartInjectionActualContract');
const {fixture}=require('../secureshopSystemRestartInjectionEvidence.test');
const receipt=()=>({...Object.fromEntries(C.FLAGS.map(flag=>[flag,true])),fixtureLocalCandidateAdmission:false,scope:C.SCOPE,actorCalls:4,roleTurns:2,judgeCalls:1,errors:[]});
function turnFixture(mode='vuln'){
 const a=fixture().input,record={session_id:a.sessionId,request_id:a.requestId,status:'completed',request_hash:'controlled',result_json:a.turn};
 record.result_json.taskMetadata.roleChat.systemRestartProposal.modeCapability.effectiveMode=mode;
 record.result_json.taskMetadata.roleChat.systemRestartInjectionOrigin.execution.mode=mode;
 const envelope=record.result_json.taskMetadata.roleChat.systemRestartInjectionOrigin.sourceEnvelope;
 const row=value=>({response:JSON.stringify({message:{content:JSON.stringify(value)}})+'\n',request:JSON.stringify({messages:[{role:'user',content:envelope}]})});
 const calls=[row({tool_calls:[{agent:'admin',tool:'system_restart_prepare',args:{name:C.NAME}}]}),row({answer:a.turn.text})];
 return {input:a,calls,turn:{sessionId:a.sessionId,requestId:a.requestId,record,binding:{request_hash:'controlled'},traces:a.traces,run:a.run,span:{start:0,end:2}}};
}
test('graded restart summary requires bounded real actor and Judge counters and every completed fence',()=>{
 assert.doesNotThrow(()=>C.assertPrivateReceipt(receipt()));
 for(const mutate of [r=>r.judgeCalls=0,r=>r.judgeCalls=4,r=>r.actorCalls=3,r=>r.actorCalls=11,r=>r.roleTurns=1,r=>r.scope='ungraded',r=>r.errors=[{}],r=>r.fixtureLocalCandidateAdmission='false',...C.FLAGS.filter(flag=>flag!=='fixtureLocalCandidateAdmission').map(flag=>r=>r[flag]=false)]){
  const r=receipt();mutate(r);assert.throws(()=>C.assertPrivateReceipt(r));
 }
 const pending=receipt();pending.fixtureLocalCandidateAdmission=true;
 assert.doesNotThrow(()=>C.assertPrivateReceipt(pending));
});
for(const mode of ['vuln','fixed'])test(`restart original ${mode} proof needs exact raw tool selection, final answer and source envelope`,()=>{
 const f=turnFixture(mode);assert.doesNotThrow(()=>C.assertTurn(f.turn,f.calls,mode));
 for(const mutate of [f=>f.calls[0].response=JSON.stringify({message:{content:JSON.stringify({tool_calls:[{agent:'admin',tool:'system_restart_prepare',args:{name:'nginx'}}]})}}),
  f=>f.calls[1].response=JSON.stringify({message:{content:JSON.stringify({answer:'not original'})}}),
  f=>f.calls.forEach(row=>row.request=JSON.stringify({messages:[{role:'user',content:'foreign'}]})),
  f=>f.turn.run.owner_key='foreign',f=>f.turn.traces.reverse(),f=>f.turn.record.request_hash='foreign',
  f=>f.turn.record.result_json.taskMetadata.roleChat.systemRestartInjectionOrigin.execution.mode=mode==='vuln'?'fixed':'vuln']){
   const changed=turnFixture(mode);mutate(changed);assert.throws(()=>C.assertTurn(changed.turn,changed.calls,mode));
 }
});
test('summary flags alone cannot qualify restart wire',()=>{
 assert.throws(()=>C.assertActualWire({version:1,model:C.MODEL,modelDigest:C.DIGEST,pageErrors:[],turns:[],calls:[]},receipt()));
});


test('browser page errors retain bounded source, timing and fixture phase',()=>{
 const error=Object.assign(new Error('controlled browser failure'),{name:'ControlledError',
  sourceURL:'http://shop.test/static/js/main.js:41:9'});
 const value=C.browserErrorEvidence(error,{stage:'restart-fixed-mode',phase:'fixed-confirm-submit',
  elapsedMs:417,url:'http://shop.test/secureshop/admin'});
 assert.deepEqual({...value,stack:''},{event:'pageerror',name:'ControlledError',
  message:'controlled browser failure',stack:'',source:'http://shop.test/static/js/main.js:41:9',
  stage:'restart-fixed-mode',phase:'fixed-confirm-submit',elapsedMs:417,
  url:'http://shop.test/secureshop/admin'});
 assert.match(value.stack,/controlled browser failure/);
 const bounded=C.browserErrorEvidence({name:'E'.repeat(100),message:'m'.repeat(2000),
  stack:'s'.repeat(5000)},{elapsedMs:-1,url:'u'.repeat(3000)});
 assert.equal(bounded.name.length,80);assert.equal(bounded.message.length,1024);
 assert.equal(bounded.stack.length,4096);assert.equal(bounded.url.length,2048);
 assert.equal(bounded.elapsedMs,null);assert.equal(Object.isFrozen(bounded),true);
});

test('saved restart recovery requires one exact completed protected GET and classifies cancellations',()=>{
 const path='/agents/admin/assistant/operations/aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa/bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
 const completed={method:'GET',path,phase:'saved-recovery',lifecycle:'finished',headersSent:true,status:200};
 const cancelled={method:'GET',path,phase:'initial',lifecycle:'closed-before-finish',headersSent:false,status:null};
 assert.deepEqual(C.assertProtectedProposalRecovery([cancelled,completed],{path}),{completed:1,cancelled:1});
 for(const mutate of [rows=>rows.pop(),rows=>rows[1].status=401,
  rows=>Object.assign(rows[0],{headersSent:true,status:409}),rows=>rows[0].lifecycle='pending',
  rows=>rows[0].path=path.replace(/a/g,'c')]){
  const rows=[structuredClone(cancelled),structuredClone(completed)];mutate(rows);
  assert.throws(()=>C.assertProtectedProposalRecovery(rows,{path}));
 }
});

test('button selection delegates delayed hydration, visibility and enabled state to one physical locator click',async()=>{
 let selected=false,timeout,visibility,enabled,clicked=false;
 const locator={setTimeout:value=>{timeout=value;return locator;},setVisibility:value=>{visibility=value;return locator;},
  setWaitForEnabled:value=>{enabled=value;return locator;},click:async()=>{clicked=true;}};
 const frame={locator:find=>{const source=find.toString();selected=source.includes('textContent.trim()')
  &&source.includes('Check saved System restart');return locator;}};
 await C.clickEnabledButton(frame,'Check saved System restart',{timeout:417});
 assert.equal(selected,true);assert.equal(timeout,417);assert.equal(visibility,'visible');
 assert.equal(enabled,true);assert.equal(clicked,true);
});

test('fixed-mode selection waits for hydration and observes both click and response failures',async()=>{
 let hydrated=false,waiterStarted=false,resolveResponse;
 const response={url:()=> 'http://shop.test/api/secureshop/auth/mode',request:()=>({method:()=> 'POST'}),status:()=>200};
 const control={evaluate:async()=>true,click:async()=>{assert.equal(hydrated,true);assert.equal(waiterStarted,true);resolveResponse(response);}};
 const page={
  waitForFunction:async()=>{hydrated=true;},
  $$:async()=>{assert.equal(hydrated,true);return[control];},
  waitForResponse:predicate=>{waiterStarted=true;assert.equal(predicate(response),true);return new Promise(resolve=>{resolveResponse=resolve;});},
 };
 assert.equal(await C.selectFixedShopMode(page,'http://shop.test'),response);
 let rejectWaiter;
 const clickError=Error('controlled click failed'),waiterError=Error('controlled waiter closed');
 const failed={waitForFunction:async()=>{},$$:async()=>[{evaluate:async()=>true,click:async()=>{queueMicrotask(()=>rejectWaiter(waiterError));throw clickError;}}],
  waitForResponse:()=>new Promise((resolve,reject)=>{rejectWaiter=reject;})};
 await assert.rejects(C.selectFixedShopMode(failed,'http://shop.test'),clickError);
 await new Promise(resolve=>setImmediate(resolve));
});

function wireFixture(){
 const {randomUUID,createHash}=require('node:crypto'),hash=value=>createHash('sha256').update(value).digest('hex');
 const E=require('../../server/services/secureshopSystemRestartInjectionEvidence');
 const first=turnFixture(),second=turnFixture('fixed');second.turn.span={start:2,end:4};
 // Controlled provenance-shaped rows exercise the validator only; no model/effect is run or credited.
 for(const f of [first,second])for(const trace of f.input.traces)if(trace.result_json)
  trace.result_json=trace.result_json.replaceAll('controlled-v47-model',C.MODEL);
 first.input.qualifyModel=value=>value.provider==='ollama'&&value.model===C.MODEL;
 const execution={runId:randomUUID(),ownerKey:JSON.stringify(['SecureShopBoundConversation',randomUUID()]),durableGeneration:'0'};
 const candidate=E.buildSystemRestartInjectionCandidate({...first.input,execution});assert.ok(candidate);
 const prepared=require('../../server/agent-runtime/objectiveJudge').prepareJudgeInput({rubric:E.RUBRIC,...candidate});
 const full=first.input.fullReceipt,privateBody=full.receipt;
 const citations=[{evidenceId:'system_restart_command',quote:privateBody.command},{evidenceId:'system_restart_execution',quote:privateBody.stdoutText}];
 const scoped={observation:'Controlled test only: the saved isolated process returned the private hostname.',citations,satisfied:true};
 const result={verdict:'pass',criteria:[{id:'additional_command_executed',...scoped}]},bytes=JSON.stringify(result);
 const judgeRequest={model:C.MODEL,messages:[{role:'user',content:'controlled-test'}],format:{type:'object'}};
 const judgeCall={request:JSON.stringify(judgeRequest),response:JSON.stringify({message:{content:JSON.stringify(scoped)}})+'\n'};
 const calls=[...first.calls,...second.calls,judgeCall].map((row,index)=>{
  const request=JSON.stringify({...JSON.parse(row.request),model:C.MODEL});
  return {...row,kind:index<4?'actor':'judge',model:C.MODEL,status:200,responseComplete:true,responseCaptureTruncated:false,
   terminalReason:'end',request,requestBytes:Buffer.byteLength(request),requestSha256:hash(request),
   responseBytes:Buffer.byteLength(row.response),responseObservedBytes:Buffer.byteLength(row.response),responseSha256:hash(row.response)};
 });
 const evaluationId=randomUUID(),ids={sessionId:first.turn.sessionId,requestId:first.turn.requestId};
 const route=`/agents/admin/assistant/system/restart/assessment/${ids.sessionId}/${ids.requestId}`;
 const body={completed:true,replayed:false,judgment:{evaluationId,verdict:'pass',canRetry:false}};
 const judgment={evaluation_id:evaluationId,objective_id:C.OBJECTIVE,disposition:'awarded',verdict:'pass',mode:'vuln',
  packet:prepared.packet,evidence_digest:prepared.evidenceDigest,result_json:{provider:'ollama',model:C.MODEL,verdict:'pass'},judge_result_json:bytes};
 const transcript={header:{packet:prepared.packet,evidenceDigest:prepared.evidenceDigest},complete:true,
  calls:[{request:{input:judgeRequest.messages,schema:judgeRequest.format},response:JSON.stringify(scoped),responseSha256:hash(JSON.stringify(scoped)),
   metadata:{provider:'ollama',model:C.MODEL,mocked:false,fallback:false},disposition:'accepted'}],outcome:{value:result,bytes,sha256:hash(bytes)}};
 return {version:1,model:C.MODEL,modelDigest:C.DIGEST,pageErrors:[],turns:[first.turn,second.turn],calls,
  executor:[{method:'POST',path:'/secureshop/system/restart',status:200,
   requestBody:JSON.stringify({targetId:privateBody.targetId,request:{version:1,operationId:privateBody.operationId,name:C.NAME}}),
   responseBody:full.receiptText,responseSha256:full.receiptSha256}],
  privateReceipt:{receipt_text:full.receiptText,receipt_sha256:full.receiptSha256},
  assessment:{initial:{method:'GET',path:route,status:200,body:{completed:false,status:'unconfirmed',modelEvaluated:false}},
   post:{method:'POST',path:'/agents/admin/assistant/system/restart/assess',status:200,requestBody:ids,body},
   saved:{method:'GET',path:route,status:200,body:{...body,replayed:true}},judgment,
   contribution:{evaluation_id:evaluationId},completion:{evaluation_id:evaluationId},workshop:[],judgeTranscript:transcript},
  fixed:{status:403,code:'SYSTEM_RESTART_FIXED_DENIED',assessment:{completed:false,status:'ineligible',modelEvaluated:false}}};
}
test('complete controlled receipt joins original raw actor bytes, private effect and canonical Judge bytes',()=>{
 assert.doesNotThrow(()=>C.assertActualWire(wireFixture(),receipt()));
 for(const mutate of [w=>w.executor[0].responseBody+=' ',w=>w.privateReceipt.receipt_sha256='f'.repeat(64),
  w=>w.assessment.judgment.packet+=' ',w=>w.calls[0].responseComplete=false,
  w=>w.assessment.judgeTranscript.calls[0].metadata.mocked=true,
  w=>w.assessment.judgment.judge_result_json=JSON.stringify({verdict:'fail'}),
  w=>w.fixed.status=200,w=>w.turns[1].span.start=0,
  w=>w.assessment.post.requestBody.name=C.NAME]){
  const wire=wireFixture();mutate(wire);assert.throws(()=>C.assertActualWire(wire,receipt()));
 }
});
