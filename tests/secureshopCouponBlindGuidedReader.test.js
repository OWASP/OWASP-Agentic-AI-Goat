'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {randomUUID,createHash}=require('node:crypto');
const {fixture,start}=require('./secureshopCouponProbeApplication.test');
const {createCouponProbeApplication}=require('../server/services/secureshopCouponProbeApplication');
const {createCouponBlindEvidenceRepository}=require('../server/database/postgres/secureshopCouponBlindEvidenceRepository');
const {buildCouponBlindCandidate,isCouponBlindJudgeInputValid,RUBRIC}=require('../server/services/secureshopCouponBlindEvidence');
const {createSecureShopModelQualifier}=require('../server/services/secureshopModelQualification');
const {prepareJudgeInput}=require('../server/agent-runtime/objectiveJudge');
const Guided=require('../server/services/secureshopCouponProbeGuidedProtocol');
const Request=require('../server/services/secureshopCouponProbeRequest');
const hash=value=>createHash('sha256').update(value).digest('hex');
async function guidedSource(){
 const codes=[Guided.BASELINE,...Guided.BIT_CODES,Guided.equalityCode('a'),Guided.equalityCode('4')];
 const f=fixture({codes,policy:true,couponResult:input=>[codes[0],codes[5]].includes(input.lookup.code)?input.lookup.coupons[0]:null});
 // The fixture supplies controlled SQL results only; all graph decisions,
 // request hashes, traces, effects and metadata use the production code.
 f.args.readCoupons=async()=>[{id:1,code:Guided.BASELINE,discount_percent:10,active:1}];
 f.app=createCouponProbeApplication(f.args);
 const input={...await start(f),protocol:Request.GUIDED};await f.app.run(input);
 const m=f.rows.get(input.requestId).result_json.taskMetadata.couponProbe;
 const run={run_id:m.execution.runId,owner_key:m.execution.ownerKey,generation:m.execution.generation,status:'completed'};
 const effects=m.probes.map(p=>({run_id:run.run_id,owner_key:run.owner_key,generation:run.generation,effect_key:p.observation.effectReceipt.effectKey,status:'completed'}));
 let mutate=()=>{},receiptReads=0;
 const dependencies={identityPool:{async query(sql){assert.match(sql,/JOIN graph_runtime.owners/);assert.doesNotMatch(sql,/INSERT|UPDATE|DELETE/);return {rows:sql.includes('FROM graph_runtime.runs')?[run]:effects};}},
  conversationRepository:{getTraceEvents:async(_s,_b,ids,purpose)=>{assert.equal(purpose,'secureshop_coupon_probe');return ids.map(id=>f.traces.find(row=>row.event_id===id));}},
  readSavedSource:async(...args)=>{const saved=await f.app.readSavedSource(...args);mutate(saved);return saved;},
  readCouponProbeReceipt:async request=>{receiptReads++;return structuredClone(m.probes.find(p=>p.operationId===request.operationId).receipt);},
  readCouponProbeReference:async request=>({version:1,targetId:request.targetId,operationId:request.operationId,requestSha256:request.requestSha256,position:request.position,rowId:1,character:'a',characterSha256:hash('a')})};
 return {f,input,m,codes,repo:createCouponBlindEvidenceRepository(dependencies),mutate(fn){mutate=fn;},get receiptReads(){return receiptReads;}};
}
test('guided production graph feeds the protected reader and unchanged full raw-code candidate',async()=>{
 const s=await guidedSource(),before=[s.f.calls,s.f.finalCalls,s.f.requests.length,s.f.provisions];
 const read=await s.repo.readSource(s.f.context,s.input);
 assert.equal(s.m.version,2);assert.equal(s.receiptReads,7);
 assert.deepEqual(read.source.probes.map(p=>p.code),s.codes);
 assert.deepEqual(read.source.turn.traces.map(t=>t.event_id),s.m.traceEventIds);
 assert.equal(read.source.turn.message,Request.encode(s.input.message,Request.GUIDED));
 const qualifyModelTrace=createSecureShopModelQualifier(s.f.args.provider);
 const assessmentExecution={runId:randomUUID(),ownerKey:JSON.stringify(['SecureShopBoundConversation',randomUUID()]),durableGeneration:'0'};
 const candidate=buildCouponBlindCandidate({...read,assessmentExecution,qualifyModelTrace});assert.ok(candidate);
 const prepared=prepareJudgeInput({rubric:RUBRIC,...candidate});assert.equal(prepared.evidenceError,undefined);
 assert.ok(Buffer.byteLength(prepared.packet)<=24000);
 assert.equal(isCouponBlindJudgeInputValid({rubric:RUBRIC,...candidate},qualifyModelTrace),true);
 const raw=require('node:zlib').inflateRawSync(Buffer.from(candidate.evidence[0].content.source.original.data,'base64'));
 assert.equal(raw.toString('utf8'),JSON.stringify(read.source));
 assert.deepEqual([s.f.calls,s.f.finalCalls,s.f.requests.length,s.f.provisions],before);
 // Successful structural admission never repairs a wrong private reference.
 assert.equal(buildCouponBlindCandidate({...read,privateReference:{...read.privateReference,character:'b',characterSha256:hash('b')},assessmentExecution,qualifyModelTrace}),null);
});
test('protected reader rejects guided version, protocol and journal identity substitutions before receipt reads',async()=>{
 const mutations=[
  s=>{s.turn.taskMetadata.couponProbe.version=1;},
  s=>{delete s.turn.taskMetadata.couponProbe.protocol;},
  s=>{s.turn.taskMetadata.couponProbe.protocol='guided-boolean-v2';},
  s=>{s.turn.taskMetadata.couponProbe.originalMessage+=' ';},
  s=>{s.savedRequest.message+=' ';},
  s=>{const m=s.turn.taskMetadata.couponProbe;delete m.protocol;delete m.originalMessage;},
 ];
 for(const mutate of mutations){const s=await guidedSource();s.mutate(mutate);
  const before=[s.f.calls,s.f.finalCalls,s.f.requests.length,s.f.provisions];
  await assert.rejects(s.repo.readSource(s.f.context,s.input),{code:'COUPON_BLIND_SOURCE_UNAVAILABLE'});
  assert.equal(s.receiptReads,0);assert.deepEqual([s.f.calls,s.f.finalCalls,s.f.requests.length,s.f.provisions],before);
 }
});

test('guided v2 reader joins actual model-selected arithmetic trace and durable effect without changing Judge rubric',async()=>{
 const {createCouponProbeApplication}=require('../server/services/secureshopCouponProbeApplication');
 const Arithmetic=require('../server/services/secureshopCouponProbeArithmetic');
 const codes=[Guided.BASELINE,...Guided.BIT_CODES,Guided.equalityCode('8'),Guided.equalityCode('1')];
 const terms=[false,false,false,true].map((valid,i)=>({probeNumber:i+2,valid,weight:2**i}));
 const decisions=[...codes.slice(0,5),{agent:'arithmetic',tool:'sum',args:{terms}},...codes.slice(5)];
 const f=fixture({decisions,couponResult:input=>[codes[0],codes[4],codes[5]].includes(input.lookup.code)?input.lookup.coupons[0]:null});
 f.args.readCoupons=async()=>[{id:1,code:Guided.BASELINE,discount_percent:10,active:1}];
 f.app=createCouponProbeApplication(f.args);
 const input={...await start(f),protocol:Request.GUIDED_V2};await f.app.run(input);
 const m=f.rows.get(input.requestId).result_json.taskMetadata.couponProbe;
 const run={run_id:m.execution.runId,owner_key:m.execution.ownerKey,generation:m.execution.generation,status:'completed'};
 const effects=[...m.probes.map(p=>p.observation.effectReceipt),m.arithmetic.observation.effectReceipt]
  .map(e=>({run_id:run.run_id,owner_key:run.owner_key,generation:run.generation,effect_key:e.effectKey,status:'completed'}));
 const deps={identityPool:{async query(sql){return{rows:sql.includes('FROM graph_runtime.runs')?[run]:effects};}},
  conversationRepository:{getTraceEvents:async(_s,_b,ids)=>ids.map(id=>f.traces.find(r=>r.event_id===id))},
  readSavedSource:(...args)=>f.app.readSavedSource(...args),
  readCouponProbeReceipt:async request=>structuredClone(m.probes.find(p=>p.operationId===request.operationId).receipt),
  readCouponProbeReference:async request=>({version:1,targetId:request.targetId,operationId:request.operationId,
   requestSha256:request.requestSha256,position:request.position,rowId:1,character:'8',characterSha256:hash('8')})};
 const repo=createCouponBlindEvidenceRepository(deps),read=await repo.readSource(f.context,input);
 assert.deepEqual(read.source.arithmetic.result,{version:2,sum:8,hex:'8'});
 assert.equal(read.source.turn.hops[5].tool,Arithmetic.TOOL);
 assert.deepEqual(read.source.effects.map(e=>e.effect_key),effects.map(e=>e.effect_key));
 const qualify=createSecureShopModelQualifier(f.args.provider),assessmentExecution={runId:randomUUID(),
  ownerKey:JSON.stringify(['SecureShopBoundConversation',randomUUID()]),durableGeneration:'0'};
 const candidate=buildCouponBlindCandidate({...read,assessmentExecution,qualifyModelTrace:qualify});
 assert.ok(candidate);assert.equal(isCouponBlindJudgeInputValid({rubric:RUBRIC,...candidate},qualify),true);
 for(const mutate of [
  source=>{source.arithmetic.result.sum=9;},
  source=>{source.arithmetic.result.hex='08';},
  source=>{source.arithmetic.result.version=1;},
  source=>{source.turn.traces.find(r=>r.kind==='local_tool_result'&&r.agent_ns==='arithmetic')
   .result_json=JSON.stringify({content:[{type:'text',text:JSON.stringify({version:2,sum:8,hex:'9'})}]});},
  source=>{source.turn.traces.find(r=>r.kind==='model_decision'&&r.step===6).actor='cart';},
  source=>{source.arithmetic.execution.callId=source.probes[0].execution.callId;},
  source=>{source.arithmetic.args.terms[3].valid=false;},
  source=>{source.effects.at(-1).effect_key+='forged';},
  source=>{source.turn.hops[5].result.content[0].text='\"forged\"';},
 ]){const forged=structuredClone(read);mutate(forged.source);
  assert.equal(buildCouponBlindCandidate({...forged,assessmentExecution,qualifyModelTrace:qualify}),null);}
 // Historical exact {sum} observations remain readable with no invented hex in the source.
 const legacy=structuredClone(read),old={sum:8},observation={content:[{type:'text',text:JSON.stringify(old)}]};
 legacy.source.arithmetic.result=old;
 legacy.source.arithmetic.observation.result=observation;
 legacy.source.turn.hops[5].result=observation;
 legacy.source.turn.traces.find(r=>r.kind==='local_tool_result'&&r.agent_ns==='arithmetic')
  .result_json=JSON.stringify(observation);
 assert.ok(buildCouponBlindCandidate({...legacy,assessmentExecution,qualifyModelTrace:qualify}));
 // A fabricated arithmetic sum cannot be recovered or credited.
 m.arithmetic.result.sum=9;
 await assert.rejects(repo.readSource(f.context,input));
});

test('guided v2 repaired end is retained but only the model-selected contrast reaches Judge evidence',async()=>{
 const codes=[Guided.BASELINE,...Guided.BIT_CODES,Guided.equalityCode('1'),Guided.equalityCode('2')];
 const terms=[true,false,false,false].map((valid,i)=>({probeNumber:i+2,valid,weight:2**i}));
 const decisions=[...codes.slice(0,5),{agent:'arithmetic',tool:'sum',args:{terms}},codes[5],
  {reply:'An untested contrasting equality is false.'},codes[6]];
 const f=fixture({decisions,couponResult:input=>[codes[0],codes[1],codes[5]].includes(input.lookup.code)
  ?input.lookup.coupons[0]:null});
 f.args.readCoupons=async()=>[{id:1,code:Guided.BASELINE,discount_percent:10,active:1}];
 f.app=createCouponProbeApplication(f.args);
 const input={...await start(f),protocol:Request.GUIDED_V2};await f.app.run(input);
 const m=f.rows.get(input.requestId).result_json.taskMetadata.couponProbe;
 const run={run_id:m.execution.runId,owner_key:m.execution.ownerKey,generation:m.execution.generation,status:'completed'};
 const effects=[...m.probes.map(p=>p.observation.effectReceipt),m.arithmetic.observation.effectReceipt]
  .map(e=>({run_id:run.run_id,owner_key:run.owner_key,generation:run.generation,effect_key:e.effectKey,status:'completed'}));
 const deps={identityPool:{async query(sql){return{rows:sql.includes('FROM graph_runtime.runs')?[run]:effects};}},
  conversationRepository:{getTraceEvents:async(_s,_b,ids)=>ids.map(id=>f.traces.find(r=>r.event_id===id))},
  readSavedSource:(...args)=>f.app.readSavedSource(...args),
  readCouponProbeReceipt:async request=>structuredClone(m.probes.find(p=>p.operationId===request.operationId).receipt),
  readCouponProbeReference:async request=>({version:1,targetId:request.targetId,operationId:request.operationId,
   requestSha256:request.requestSha256,position:request.position,rowId:1,character:'1',characterSha256:hash('1')})};
 const read=await createCouponBlindEvidenceRepository(deps).readSource(f.context,input);
 assert.deepEqual(read.source.continuation,{version:1,reason:'missing_contrast',afterSql:6});
 assert.equal(read.source.turn.taskMetadata,undefined);
 assert.deepEqual(read.source.probes.map(p=>p.execution.step),[1,2,3,4,5,7,9]);
 const qualify=createSecureShopModelQualifier(f.args.provider),assessmentExecution={runId:randomUUID(),
  ownerKey:JSON.stringify(['SecureShopBoundConversation',randomUUID()]),durableGeneration:'0'};
 const candidate=buildCouponBlindCandidate({...read,assessmentExecution,qualifyModelTrace:qualify});
 assert.ok(candidate);assert.equal(isCouponBlindJudgeInputValid({rubric:RUBRIC,...candidate},qualify),true);
 const mutations=[
  source=>{delete source.continuation;},
  source=>{source.continuation.afterSql=5;},
  source=>{source.turn.traces.find(r=>r.kind==='final_admission').step=7;},
  source=>{source.turn.traces.find(r=>r.kind==='final_admission').result_json=JSON.stringify({version:1,
   action:'continue',reason:'missing_contrast',completedCount:7,remainingCount:0});},
  source=>{source.turn.traces.find(r=>r.kind==='model_decision'&&r.step===8).actor='cart';},
  source=>{source.turn.traces=source.turn.traces.filter(r=>r.kind!=='final_admission');},
  source=>{const marker=source.turn.traces.find(r=>r.kind==='final_admission');
   source.turn.traces.splice(source.turn.traces.indexOf(marker),0,{...marker,event_id:randomUUID()});},
  source=>{source.probes[6].execution.step=8;},
 ];
 for(const mutate of mutations){const forged=structuredClone(read);mutate(forged.source);
  assert.equal(buildCouponBlindCandidate({...forged,assessmentExecution,qualifyModelTrace:qualify}),null);}
});
