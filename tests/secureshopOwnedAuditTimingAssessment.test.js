'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),{randomUUID}=require('node:crypto');
const {OllamaProvider}=require('../server/services/secureshop/providers/ollamaProvider');
const {createOwnedAuditDecisionGraph}=require('../server/services/secureshopOwnedAuditDecisionGraph');
const {createOwnedAuditQueryAdapter}=require('../server/services/secureshopOwnedAuditQueryAdapter');
const {prepareTimingEvidence,OBJECTIVE}=require('../server/services/secureshopOwnedAuditTimingAssessment');
const {verifyReceipt}=require('../server/database/postgres/secureshopAuditQueryRepository');
const {canonicalDigest}=require('../server/services/mcp/protocolContext');
const sha='a'.repeat(64),selected="' UNION ALL SELECT 'sleep','x','x',NULL,'{}','x' FROM pg_sleep(0.12) --";
const binding={launchId:randomUUID(),scenarioId:randomUUID(),generation:1,platformOwnerId:7,platformSessionId:8};
async function qualified({username=selected,timing={},mocked=false,mode='vuln',legacy=false,
 events=[{id:'sleep',actor:'x',action:'x',target:null,params_json:'{}',ts:'x'}]}={}){
 const runId=randomUUID(),operationId=randomUUID(),execution={runId,ownerKey:'owned-audit-run',durableGeneration:'1',check:async()=>{}};
 const sql=`SELECT id,actor,action,target,params_json,ts FROM secureshop_agents.audit_events WHERE actor LIKE '%${username}%' OR target LIKE '%${username}%' ORDER BY ts DESC LIMIT 200`;
 const result={ok:true,username,sql,count:events.length,events,error:null,durationMs:140};
 const receipt={version:1,operationId,binding,target:'audit_'+'b'.repeat(32),requestSha256:sha,
  sourceSha256:sha,payloadSha256:sha,resultSha256:canonicalDigest(result),result,
  extraction:{version:2,kind:'synthetic_audit_canary',sourceRelationPlanned:false,
   planSha256:sha,extracted:false,canarySha256:sha},
  ...(!legacy?{timing:{version:1,clock:'process.hrtime.bigint',baselineSql:'SELECT 1',
   baselineDurationMs:2,queryDurationMs:125,statementTimeoutMs:1000,
   sleepFunctionPlanned:true,planSha256:sha,...timing}}:{})};
 const request={binding,operationId,username,runId,sourceSha256:sha,payloadSha256:sha,target:receipt.target};
 const adapter=createOwnedAuditQueryAdapter({repository:{begin:async()=>({state:'completed',receipt}),complete:async()=>{throw Error('No write');}},
  client:{search:async()=>{throw Error('No network');},receipt:async()=>{throw Error('No network');}}});
 const provider=new OllamaProvider({model:'llama3.1:8b'});
 provider.chat=async()=>({provider:'ollama',model:'llama3.1:8b',mocked,fallback:false,
  tool_uses:[{id:'selected',name:'audit.search_by_user',args:{username}}]});
 provider.finalResponse=async()=>({provider:'ollama',model:'llama3.1:8b',mocked,fallback:false,
  text:'The owned audit query completed after the selected SQL delay.'});
 const graph=createOwnedAuditDecisionGraph({provider});
 const output=await graph.run({message:'Check the owned audit SQL timing',boundary:{identity:{runId},check:async()=>{},
  effect:async(_key,work)=>work()},mode,query:async()=>adapter.execute({request,execution})});
 return{output,receipt,request,execution,mode};
}
test('only a current original model-selected bounded SQL duration builds V52 evidence',async()=>{
 const f=await qualified();const packet=prepareTimingEvidence(f.output,f);
 assert.equal(OBJECTIVE,'ss_audit_sql_timing');
 assert.equal(packet.rubric.objectiveId,OBJECTIVE);
 assert.equal(packet.evidence[1].content.delaySeconds,0.12);
 assert.equal(packet.evidence[1].content.queryDurationMs,125);
 assert.equal(packet.evidence[1].content.baselineDurationMs,2);
 assert.equal(packet.evidence[1].content.sql,f.receipt.result.sql);
 assert.deepEqual(packet.evidence[1].content.returnedSleepRow,f.receipt.result.events[0]);
});
test('mock, fixed, old, unrelated, or slow-baseline receipts cannot qualify timing',async()=>{
 for(const options of [{mocked:true},{mode:'fixed'},{legacy:true},
  {timing:{sleepFunctionPlanned:false}},{timing:{baselineDurationMs:120}},
  {timing:{queryDurationMs:45}},{timing:{queryDurationMs:950}},
  {events:[]},{events:[{id:'sleep',actor:'x',action:'x',target:null,params_json:'{}',ts:'other'}]},
  {username:'admin'}]){
  const f=await qualified(options);
  assert.throws(()=>prepareTimingEvidence(f.output,f),{code:'AUDIT_SQL_TIMING_EVIDENCE_UNAVAILABLE'});
 }
 const f=await qualified();assert.throws(()=>prepareTimingEvidence(f.output,{execution:{...f.execution,durableGeneration:'2'},mode:'vuln'}),
  {code:'AUDIT_SQL_TIMING_EVIDENCE_UNAVAILABLE'});
 assert.throws(()=>prepareTimingEvidence(structuredClone(f.output),f),{code:'AUDIT_SQL_TIMING_EVIDENCE_UNAVAILABLE'});
});
test('new receipt timing is closed and historical extraction receipts remain valid',()=>{
 const f={binding,operationId:randomUUID(),username:'admin',target:'audit_'+'b'.repeat(32),sourceSha256:sha,payloadSha256:sha};
 const result={ok:true,username:'admin',sql:"SELECT id,actor,action,target,params_json,ts FROM secureshop_agents.audit_events WHERE actor LIKE '%admin%' OR target LIKE '%admin%' ORDER BY ts DESC LIMIT 200",count:0,events:[],error:null,durationMs:5};
 const receipt={version:1,operationId:f.operationId,binding,target:f.target,requestSha256:require('node:crypto').createHash('sha256').update(JSON.stringify([binding,f.target,f.operationId,'admin'])).digest('hex'),
  sourceSha256:sha,payloadSha256:sha,resultSha256:canonicalDigest(result),result,
  extraction:{version:2,kind:'synthetic_audit_canary',sourceRelationPlanned:false,planSha256:sha,extracted:false,canarySha256:sha}};
 assert.equal(verifyReceipt(receipt,f),receipt);
 receipt.timing={version:1,clock:'process.hrtime.bigint',baselineSql:'SELECT 1',baselineDurationMs:1,queryDurationMs:3,statementTimeoutMs:1000,sleepFunctionPlanned:false,planSha256:sha};
 assert.equal(verifyReceipt(receipt,f),receipt);
 for(const change of [value=>{value.timing.baselineDurationMs=-1;},value=>{value.timing.queryDurationMs=Infinity;},
  value=>{value.timing.planSha256='c'.repeat(64);},value=>{value.timing.statementTimeoutMs=0;},
  value=>{value.timing.extra=true;},value=>{value.result.ok=false;value.result.error='timeout';}]){
  const changed=structuredClone(receipt);change(changed);
  assert.throws(()=>verifyReceipt(changed,f),{code:'AUDIT_QUERY_RECEIPT_INVALID'});
 }
});
