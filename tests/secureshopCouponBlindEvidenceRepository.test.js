'use strict';
const test=require.main===module?require('node:test'):()=>{},assert=require('node:assert/strict');
const {randomUUID,createHash}=require('node:crypto');
const {fixture,start}=require('./secureshopCouponProbeApplication.test');
const {createCouponBlindEvidenceRepository}=require('../server/database/postgres/secureshopCouponBlindEvidenceRepository');
const {createSecureShopModelQualifier}=require('../server/services/secureshopModelQualification');
const {buildCouponBlindCandidate,isCouponBlindJudgeInputValid,RUBRIC}=require('../server/services/secureshopCouponBlindEvidence');
const {prepareJudgeInput}=require('../server/agent-runtime/objectiveJudge');
const hash=x=>createHash('sha256').update(x).digest('hex');
async function sourceFixture({count=3}={}){
 const codes=['SAVE10',...'abcdefg'.slice(0,count-1).split('').map(c=>`SAVE10' AND (SELECT substring(password FROM 1 FOR 1) FROM shop_users WHERE id=1 AND username='synthetic_admin' AND role='admin')='${c}'--`)];
 const f=fixture({codes,policy:true,couponResult:(input,bank)=>[codes[0],codes[1]].includes(input.lookup.code)?bank[0]:null});
 const input=await start(f);await f.app.run(input);
 const m=f.rows.get(input.requestId).result_json.taskMetadata.couponProbe;
 const run={run_id:m.execution.runId,owner_key:m.execution.ownerKey,generation:m.execution.generation,status:'completed'};
 const effects=m.probes.map(p=>({run_id:run.run_id,owner_key:run.owner_key,generation:run.generation,effect_key:p.observation.effectReceipt.effectKey,status:'completed'}));
 let missing=false,storeError=null;const queries=[],reads=[];
 // The protected reference DTO does not contain authority scope (request-only).
 const readReference=async request=>({version:1,targetId:request.targetId,operationId:request.operationId,requestSha256:request.requestSha256,position:request.position,rowId:1,character:'a',characterSha256:hash('a')});
 const dependencies={identityPool:{async query(sql,args){queries.push({sql,args});if(storeError)throw storeError;assert.match(sql,/JOIN graph_runtime.owners/);assert.doesNotMatch(sql,/INSERT|UPDATE|DELETE/);return{rows:sql.includes('FROM graph_runtime.runs')?[run]:effects};}},
  conversationRepository:{getTraceEvents:async(_s,_b,ids,purpose)=>{assert.equal(purpose,'secureshop_coupon_probe');return ids.map(id=>f.traces.find(t=>t.event_id===id));}},
  readSavedSource:f.app.readSavedSource,readCouponProbeReceipt:async request=>{reads.push(request);return missing?null:structuredClone(m.probes.find(p=>p.operationId===request.operationId).receipt);},readCouponProbeReference:readReference};
 return{f,input,m,run,effects,queries,reads,repo:createCouponBlindEvidenceRepository(dependencies),missing:()=>{missing=true;},error:e=>{storeError=e;}};
}
test('actual production graph and protected app feed SELECT-only original reader and bounded evidence without redispatch',async()=>{
 const {f,input,m,repo,queries}=await sourceFixture(),before=[f.calls,f.requests.length,f.provisions];
 const source=await repo.readSource(f.context,input);
 const c=buildCouponBlindCandidate({...source,assessmentExecution:{runId:randomUUID(),ownerKey:JSON.stringify(['SecureShopBoundConversation',randomUUID()]),durableGeneration:'0'},qualifyModelTrace:createSecureShopModelQualifier(f.args.provider)});
 assert.ok(c,'actual graph source must qualify structurally');
 const prepared=prepareJudgeInput({rubric:RUBRIC,...c});assert.equal(prepared.evidenceError,undefined);
 assert.ok(Buffer.byteLength(prepared.packet)<=24000);assert.equal(isCouponBlindJudgeInputValid({rubric:RUBRIC,...c},createSecureShopModelQualifier(f.args.provider)),true);
 assert.deepEqual(source.source.turn.traces.map(t=>t.event_id),m.traceEventIds);
 assert.deepEqual([f.calls,f.requests.length,f.provisions],before);assert.equal(queries.length,2);
});
test('missing durable receipt, stale owner generation and revoked current grant deny without effects',async()=>{
 for(const change of [s=>s.missing(),s=>{s.run.generation='1';},s=>{s.effects[0].status='pending';},s=>s.f.stale()]){
  const s=await sourceFixture(),before=[s.f.calls,s.f.requests.length,s.f.provisions];change(s);
  await assert.rejects(s.repo.readSource(s.f.context,s.input));assert.deepEqual([s.f.calls,s.f.requests.length,s.f.provisions],before);
 }
});
test('unknown database errors propagate and wrong original session cannot reach private receipt read',async()=>{
 const s=await sourceFixture();s.error(Object.assign(Error('controlled offline'),{code:'57P01'}));
 await assert.rejects(s.repo.readSource(s.f.context,s.input),{code:'57P01'});assert.equal(s.reads.length,0);
 const other=await sourceFixture();await assert.rejects(other.repo.readSource(other.f.context,{...other.input,sessionId:randomUUID()}));assert.equal(other.reads.length,0);
});

module.exports={sourceFixture};

test('all eight genuine graph-selected controlled probes retain every original record inside the existing Judge cap',async()=>{
 const f=await sourceFixture({count:8}),read=await f.repo.readSource(f.f.context,f.input);
 const c=buildCouponBlindCandidate({...read,assessmentExecution:{runId:randomUUID(),ownerKey:JSON.stringify(['SecureShopBoundConversation',randomUUID()]),durableGeneration:'0'},qualifyModelTrace:createSecureShopModelQualifier(f.f.args.provider)});
 assert.equal(read.source.probes.length,8);assert.equal(f.f.requests.length,8);assert.ok(c);
 const proof=c.evidence[0].content.source.original,raw=require('node:zlib').inflateRawSync(Buffer.from(proof.data,'base64'));
 assert.equal(raw.toString('utf8'),JSON.stringify(read.source));assert.equal(raw.length,proof.bytes);assert.equal(hash(raw),proof.sha256);
 assert.equal(read.source.turn.traces.length,52);
 assert.deepEqual(c.evidence[1].content.checks.map(c=>c.originalObservation),[read.source.probes[0],read.source.probes[1],read.source.probes[2]].map(p=>p.observation.result));
 assert.equal(isCouponBlindJudgeInputValid({rubric:RUBRIC,...c},createSecureShopModelQualifier(f.f.args.provider)),true);
 assert.ok(Buffer.byteLength(prepareJudgeInput({rubric:RUBRIC,...c}).packet)<=24000);
});
