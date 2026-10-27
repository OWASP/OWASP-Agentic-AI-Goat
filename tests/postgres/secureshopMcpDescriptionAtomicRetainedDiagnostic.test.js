'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {createHash}=require('node:crypto');
const http=require('node:http');
const {EventEmitter}=require('node:events');
const R=require('./secureshopMcpDescriptionAtomicRetainedDiagnostic');
const D=require('../fixtures/secureshopMcpDescriptionAtomicDiagnostic');
const ranges=require('../../server/agent-runtime/mcpDescriptionRangeRelationsV6');
const {OllamaProvider}=require('../../server/services/secureshop/providers/ollamaProvider');
const {createSecureShopModelQualifier}=require('../../server/services/secureshopModelQualification');
const {validateSource}=require('../../server/services/secureshopMcpDescriptionEvidence');
const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
const note='This is a controlled diagnostic observation of the exact selected atomic source.';
function answer(stage,slot,{positivePrefix=false,contradictTitles=false}={}){
 if(stage.endsWith('.source_witness')){
  const rows=ranges.indexText(slot.quote,'d_','description');
  return {directiveForm:contradictTitles&&slot.id==='titles'?'other_behavioral_directive':'post_result_behavioral_directive',
   directiveRange:{first:rows[0].id,last:rows.at(-1).id},
   requiredOutputLiteralId:slot.id==='prefix'?'literal_0':null,observation:note};
 }
 if(stage.endsWith('.task_relation'))return {relation:'does_not_independently_require_same_behavior',supportingRange:null,observation:note};
 if(stage.endsWith('.result_relation'))return {relation:'does_not_independently_supply_same_behavior',supportingRange:null,observation:note};
 if((positivePrefix&&slot.id==='prefix')||(contradictTitles&&slot.id==='titles'))return {finalRelation:'enacted_same_directive',
  finalBehaviorRange:{first:'f_0',last:'f_0'},satisfied:true,observation:note};
 return {finalRelation:'not_enacted',finalBehaviorRange:null,satisfied:false,observation:note};
}
function fixtureSend({badTerminal=false,positivePrefix=false,contradictTitles=false}={}){
 const calls=[];let current=null;
 const record=report=>{current=report.calls.at(-1)?.stage||null;};
 const send=async ({origin,method,pathname,body,timeoutMs,byteLimit,signal,onPhysicalAttempt})=>{
  assert.equal(origin,'http://127.0.0.1:11434');assert.equal(method,'POST');assert.equal(pathname,'/api/chat');
  assert.equal(timeoutMs,90000);assert.equal(byteLimit,R.MAX_RESPONSE_BYTES);assert.equal(signal.aborted,false);
  const payload=JSON.parse(body);assert.equal(payload.model,'llama3.1:8b');assert.equal(payload.stream,true);
  assert.deepEqual(payload.options,{temperature:0,num_ctx:32768,num_predict:900});assert.equal(payload.messages.length,2);
  assert.equal(payload.messages[0].role,'system');assert.equal(payload.messages[1].role,'user');
  const user=JSON.parse(payload.messages[1].content),slot=user.exactAtomicSourceSpan;
  assert.equal(current?.startsWith(slot.id+'.'),true);
  onPhysicalAttempt();
  calls.push({stage:current,requestSha256:sha(body)});
  const content=JSON.stringify(answer(current,slot,{positivePrefix,contradictTitles}));
  const bytes=Buffer.from(JSON.stringify({model:'llama3.1:8b',message:{content},done:true,
   done_reason:badTerminal?'length':'stop'})+'\n');
  return {status:200,termination:'complete',body:bytes,responseBytes:bytes.length,localSocketRetired:true,socketAssigned:true};
 };
 return {calls,record,send};
}
test('pinned original admission validates real publication, actor trace and retained physical wire',()=>{
 const admitted=R.admitOriginal();
 assert.equal(admitted.plan.provenance,'validated-original-source');assert.equal(admitted.plan.maxJudgeCalls,12);
 assert.deepEqual(admitted.plan.evidence.slots.map(x=>x.id),['prefix','titles','preference']);
 assert.equal(admitted.inputs['mcp-description-wire.json'],'d10b81c2a3c848e25c7c4d72a1cf0efe320af153718705ac18f244a3bbef0d8c');
 const q=require('../../tasks/qualification/dvaia-mcp-assembly-iw6u2bic/mcp-description-qualification.json');
 const bad=structuredClone(q.original);bad.traces[0].event_id='00000000-0000-4000-8000-000000000000';
 const provider=new OllamaProvider({baseUrl:'http://127.0.0.1:11434',model:'llama3.1:8b'});
 assert.throws(()=>validateSource(bad,createSecureShopModelQualifier(provider)),/evidence unavailable/);
 const forged=structuredClone(admitted.plan);assert.throws(()=>D.verifyPlan(forged),/original provenance seal/);
});
test('default CLI plan is inert and exact original Judge request construction is bounded',async()=>{
 const out=[];const old=process.stdout.write;process.stdout.write=value=>{out.push(value);return true;};
 try{await R.main([]);}finally{process.stdout.write=old;}
 const plan=JSON.parse(out.join(''));assert.equal(plan.nativeStarted,false);assert.equal(plan.maxPhysicalJudgePosts,12);
 assert.equal(plan.perCallTimeoutMs,90000);assert.equal(plan.canonicalCredit,false);
 const admitted=R.admitOriginal(),slot=admitted.plan.evidence.slots[0];
 const schema=ranges._schemas.sourceSchema(ranges.indexText(slot.quote,'d_','description'),ranges.literalCandidates(slot.quote));
 assert.throws(()=>R.stageRequest('prefix.source_witness',schema,'x'.repeat(40000),{}),/context guard/);
 assert.throws(()=>R.stageRequest('unknown.source_witness',schema,'x',{}));
 await assert.rejects(R.main(['--run','--output','/invalid/v39-atomic-retained-diagnostic.json']),
  /Root-admitted diagnostic run required/);
});
test('controlled positive and negative use twelve original atomic stages without credit',async()=>{
 const admitted=R.admitOriginal();
 for(const positivePrefix of [true,false]){
 const f=fixtureSend({positivePrefix});let recorded=[];
 const {report}=await R.runDiagnostic({admitted,probe:async()=>({identityMatched:true,localSocketRetired:true}),
  send:f.send,record:row=>{f.record(row);recorded.push(structuredClone(row));}});
 assert.equal(report.status,'diagnostic-complete');assert.equal(report.physicalJudgePosts,12);
 assert.equal(f.calls.length,12);assert.equal(new Set(f.calls.map(x=>x.stage)).size,12);
 assert.deepEqual(f.calls.map(x=>x.stage),['prefix.source_witness','prefix.task_relation','prefix.result_relation','prefix.final_judgment',
  'titles.source_witness','titles.task_relation','titles.result_relation','titles.final_judgment',
  'preference.source_witness','preference.task_relation','preference.result_relation','preference.final_judgment']);
 assert.equal(report.result.physicalAttemptsVerified,false);assert.equal(report.canonicalCredit,false);
 assert.equal(report.qualificationAccepted,false);assert.equal(report.remoteModelCancellationProven,false);
 assert.deepEqual(report.result.candidateCompleteAtomicChains,positivePrefix?['prefix']:[]);
 assert.equal(report.result.diagnosticExistential,positivePrefix);
 assert(report.calls.every(x=>x.status===200&&x.termination==='complete'&&x.localSocketRetired===true
  &&x.responseSha256===sha(Buffer.from(x.responseBase64,'base64'))));
 assert(recorded.some(x=>x.physicalJudgePosts===12));
 }
});
test('thirteenth, duplicate, malformed terminal and aborted signals fail before any retry',async()=>{
 const admitted=R.admitOriginal(),items=[];let dispatched=0;
 const oneResponse=async({onPhysicalAttempt})=>{onPhysicalAttempt();dispatched++;const body=Buffer.from(JSON.stringify({model:'llama3.1:8b',message:{content:'{}'},
  done:true,done_reason:'stop'})+'\n');return {status:200,termination:'complete',body,responseBytes:body.length,localSocketRetired:true};};
 const invoker=R.createInvoker({send:oneResponse,record:row=>{items.push(structuredClone(row));},signal:new AbortController().signal});
 const slot=admitted.plan.evidence.slots[0];
 const schema=ranges._schemas.sourceSchema(ranges.indexText(slot.quote,'d_','description'),ranges.literalCandidates(slot.quote));
 for(let i=0;i<12;i++){
  // Direct transport-cap test: stage grammar permits the twelve exact slots.
  const names=['prefix','titles','preference'],stages=['source_witness','task_relation','result_relation','final_judgment'];
  const stage=names[Math.floor(i/4)]+'.'+stages[i%4];
  // The transport answer need only be a JSON object here; semantic parsing is
  // independently exercised by the full evaluate test.
  await invoker.invoke(stage,schema,'Judge past evidence only.',{exactAtomicSourceSpan:{...slot,id:names[Math.floor(i/4)]}});
 }
 const before=dispatched;
 await assert.rejects(invoker.invoke('prefix.source_witness',schema,'x',{}),/Twelve physical Judge POST cap/);
 assert.equal(dispatched,before);
 const malformed=fixtureSend({badTerminal:true});
 const failed=await R.runDiagnostic({admitted,probe:async()=>({identityMatched:true,localSocketRetired:true}),
  send:malformed.send,record:malformed.record});
 assert.equal(failed.report.status,'diagnostic-failed');assert.equal(failed.report.physicalJudgePosts,1);
 assert.equal(malformed.calls.length,1);assert.equal(failed.report.calls[0].localSocketRetired,true);
 const controller=new AbortController();controller.abort(Error('controlled stop'));
 const never=R.createInvoker({send:async()=>assert.fail('no network after abort'),record:()=>{},signal:controller.signal});
 await assert.rejects(never.invoke('prefix.source_witness',schema,'x',{exactAtomicSourceSpan:slot}),/controlled stop/);
 assert.equal(never.state.reservations,0);
});
test('physical wire parser rejects early/multiple terminal, provider error and invalid UTF-8',()=>{
 const frame=(done,extra={})=>JSON.stringify({model:'llama3.1:8b',message:{content:'{}'},done,...extra})+'\n';
 const parse=body=>R.decodeChat({status:200,termination:'complete',localSocketRetired:true,
  body:Buffer.isBuffer(body)?body:Buffer.from(body)});
 assert.deepEqual(parse(frame(true,{done_reason:'stop'})),{});
 for(const body of [frame(true,{done_reason:'stop'})+frame(true,{done_reason:'stop'}),
  frame(false)+frame(true,{done_reason:'length'}),
  frame(true,{done_reason:'stop',error:'provider failed'}),
  Buffer.from([0xc3,0x28])])assert.throws(()=>parse(body));
 assert.throws(()=>R.decodeChat({status:503,termination:'complete',localSocketRetired:true,
  body:Buffer.from(frame(true,{done_reason:'stop'}))}));
});
test('duplicate stage and pre-dispatch failure never fabricate a physical provider attempt',async()=>{
 const admitted=R.admitOriginal(),slot=admitted.plan.evidence.slots[0];
 const schema=ranges._schemas.sourceSchema(ranges.indexText(slot.quote,'d_','description'),ranges.literalCandidates(slot.quote));
 let starts=0;const invoker=R.createInvoker({signal:new AbortController().signal,record:()=>{},
  send:async({onPhysicalAttempt})=>{onPhysicalAttempt();starts++;const body=Buffer.from(JSON.stringify({model:'llama3.1:8b',
   message:{content:'{}'},done:true,done_reason:'stop'})+'\n');
   return {status:200,termination:'complete',body,responseBytes:body.length,localSocketRetired:true};}});
 await invoker.invoke('prefix.source_witness',schema,'Judge past evidence only.',{});
 await assert.rejects(invoker.invoke('prefix.source_witness',schema,'Judge past evidence only.',{}),/duplicate stage/);
 assert.equal(starts,1);assert.equal(invoker.state.physicalAttempts,1);
 const failed=R.createInvoker({signal:new AbortController().signal,record:()=>{},
  send:async()=>{throw Error('controlled pre-dispatch failure');}});
 await assert.rejects(failed.invoke('prefix.source_witness',schema,'Judge past evidence only.',{}),/pre-dispatch failure/);
 assert.equal(failed.state.reservations,1);assert.equal(failed.state.physicalAttempts,0);
});
test('real singlePost call path retires a callback failure and does not dispatch an already-aborted request',async()=>{
 const old=http.request;let constructed=0,ended=0,destroyed=0;
 http.request=()=>{constructed++;const request=new EventEmitter();
  request.destroy=()=>{destroyed++;queueMicrotask(()=>request.emit('close'));};
  request.end=()=>{ended++;queueMicrotask(()=>request.emit('close'));};return request;};
 try{
  const stopped=new AbortController();stopped.abort(Error('stopped'));
  let attempts=0;
  const common={origin:'http://127.0.0.1:11434',method:'POST',pathname:'/api/chat',body:Buffer.from('{}'),
   timeoutMs:90000,byteLimit:R.MAX_RESPONSE_BYTES,onPhysicalAttempt:()=>{attempts++;}};
  const aborted=await R.singlePost({...common,signal:stopped.signal});
  assert.equal(aborted.termination,'aborted');assert.equal(aborted.localSocketRetired,true);
  assert.equal(constructed,0);assert.equal(attempts,0);
  await assert.rejects(R.singlePost({...common,onPhysicalAttempt:()=>{throw Error('journal failed');}}),error=>{
   assert.equal(error.message,'journal failed');assert.equal(error.localSocketRetired,true);
   assert.equal(error.termination,'record_error');return true;
  });
  assert.equal(constructed,1);assert.equal(destroyed,1);assert.equal(ended,0);
 }finally{http.request=old;}
});
test('invalid UTF-8 response failure retains exact bounded physical bytes and hash',async()=>{
 const admitted=R.admitOriginal(),slot=admitted.plan.evidence.slots[0];
 const schema=ranges._schemas.sourceSchema(ranges.indexText(slot.quote,'d_','description'),ranges.literalCandidates(slot.quote));
 const bad=Buffer.from([0xc3,0x28]);let finalRow;
 const invoker=R.createInvoker({signal:new AbortController().signal,record:row=>{finalRow=structuredClone(row);},
  send:async({onPhysicalAttempt})=>{onPhysicalAttempt();return {status:200,termination:'complete',body:bad,
   responseBytes:bad.length,localSocketRetired:true};}});
 await assert.rejects(invoker.invoke('prefix.source_witness',schema,'Judge past evidence only.',{}));
 assert.equal(finalRow.responseBase64,bad.toString('base64'));
 assert.equal(finalRow.responseSha256,sha(Buffer.from(finalRow.responseBase64,'base64')));
 assert.equal(finalRow.physicalAttempt,true);
});
test('semantic contradiction preserves only the known validationCode without converting earlier calls into credit',async()=>{
 const admitted=R.admitOriginal(),f=fixtureSend({positivePrefix:true,contradictTitles:true});
 const {report,primary}=await R.runDiagnostic({admitted,
  probe:async()=>({identityMatched:true,localSocketRetired:true}),send:f.send,record:f.record});
 assert.equal(primary.validationCode,'MCP_DESCRIPTION_CAUSAL_FINDING_CONTRADICTION');
 assert.deepEqual(report.failure,{phase:'judge',name:'Error',code:null,
  validationCode:'MCP_DESCRIPTION_CAUSAL_FINDING_CONTRADICTION'});
 assert.equal(report.status,'diagnostic-failed');assert.equal(report.physicalJudgePosts,8);
 assert.deepEqual(f.calls.map(x=>x.stage).slice(0,4),['prefix.source_witness','prefix.task_relation',
  'prefix.result_relation','prefix.final_judgment']);
 assert.equal(report.result,null);assert.equal(report.qualificationAccepted,false);
 assert.equal(report.canonicalCredit,false);assert.equal(report.calls[7].failure,undefined);
 const slot=admitted.plan.evidence.slots[0],schema=ranges._schemas.sourceSchema(
  ranges.indexText(slot.quote,'d_','description'),ranges.literalCandidates(slot.quote));
 let row;const checked=R.createInvoker({signal:new AbortController().signal,record:value=>{row=structuredClone(value);},
  send:async()=>{throw Object.assign(Error('untrusted code'),{validationCode:'MCP_DESCRIPTION_FORGED_SUCCESS'});}});
 await assert.rejects(checked.invoke('prefix.source_witness',schema,'Judge past evidence only.',{}));
 assert.equal(row.failure.validationCode,null);
 assert.equal(checked.state.physicalAttempts,0);
});
