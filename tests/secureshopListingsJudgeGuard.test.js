'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {projectListingsCandidate,createListingsJudgeGuard,validatePacket}=require('../server/services/secureshopListingsJudgeGuard');
const {LISTINGS_IMPORT_RUBRICS,GENERATED_BROWSER_RUBRIC}=require('../server/services/secureshopListingsAssessment');
const {hash}=require('../server/services/secureshopListingJournalContract');
const records=require('./fixtures/secureshopListingsV1Packets.json').records;
function packet(record){return {...projectListingsCandidate({objectiveId:record.objectiveId,facts:record.packet.facts,evidence:record.packet.evidence}),rubric:{...(LISTINGS_IMPORT_RUBRICS[record.objectiveId]||GENERATED_BROWSER_RUBRIC),mode:'vuln'}};}
function mutateEffect(raw,id){
 if(id.endsWith('internal_fetch'))raw.internalResource.sourceSha256='0'.repeat(64);
 else if(id.endsWith('external_entity'))for(const source of raw.sources)source.entityReads=[];
 else if(id.endsWith('prototype_mutation'))for(const source of raw.sources)source.prototypeEffect={observed:false,inheritedProperties:[]};
 else{raw.browser.executed=false;raw.browser.targetEventExecuted=false;raw.browser.targetEffectObserved=false;raw.browser.markers=[];}
}
function reconcileImportCopies(raw){
 if(!raw.loop)return;
 const observation=raw.loop[0].content.observation,response=JSON.parse(observation.result_json),receipt=JSON.parse(response.content[0].text);
 receipt.sources=structuredClone(raw.sources);response.content[0].text=JSON.stringify(receipt);observation.result_json=JSON.stringify(response);raw.importReceiptSha256=hash(JSON.stringify(receipt));
}
test('all four retained authentic packets faithfully project into guarded v2 without changing original evidence',async()=>{
 const before=JSON.stringify(records);let calls=0;const judge=createListingsJudgeGuard(async()=>{calls++;return{verdict:'pass'};});
 for(const record of records){const p=packet(record);assert.equal(validatePacket(p),true);assert.equal((await judge(p)).verdict,'pass');assert.equal(p.evidence[1].content.kind.length>0,true);}
 assert.equal(calls,4);assert.equal(JSON.stringify(records),before);
});
test('the four observed contradictory calibration failures are rejected before model even with true facts',async()=>{
 let calls=0;const judge=createListingsJudgeGuard(async()=>{calls++;return{verdict:'pass'};});
 for(const record of records){const p=packet(record),audit=p.evidence[0].content;mutateEffect(audit.raw,record.objectiveId);audit.rawSha256=hash(JSON.stringify(audit.raw));const r=await judge(p);assert.equal(r.verdict,'fail');assert.equal(r.errorCode,'LISTINGS_EVIDENCE_INCONSISTENT');}
 assert.equal(calls,0);
});
test('coherent removal across every receipt copy cannot recreate an eligible effect by updating hashes',()=>{
 for(const record of records){const candidate={objectiveId:record.objectiveId,facts:record.packet.facts,evidence:structuredClone(record.packet.evidence)};const raw=candidate.evidence[0].content;mutateEffect(raw,record.objectiveId);reconcileImportCopies(raw);assert.throws(()=>projectListingsCandidate(candidate),{code:'LISTINGS_EVIDENCE_INCONSISTENT'});}
});
test('projection edits, duplicate scoped records and wrong receipt identity are denied; v1 stays explicitly unsupported',async()=>{
 let calls=0;const judge=createListingsJudgeGuard(async()=>{calls++;return{verdict:'pass'};});
 for(const record of records){
  const p=packet(record);p.evidence[1].content.observedOutcome='Forged success';assert.equal((await judge(p)).verdict,'fail');
  const old=await judge(record.packet);assert.equal(old.verdict,'unavailable');assert.equal(old.errorCode,'LISTINGS_EVIDENCE_VERSION_UNSUPPORTED');
 }
 const p=packet(records[0]);p.evidence[0].content.raw.loop[0].content.receipt.ownerKey='foreign';p.evidence[0].content.rawSha256=hash(JSON.stringify(p.evidence[0].content.raw));assert.equal((await judge(p)).verdict,'fail');assert.equal(calls,0);
});
test('canonical retained retry applies the versioned guard before model without rewriting historical packets',async()=>{
 const {createObjectiveCompletionService}=require('../server/services/objectiveCompletionService');
 const {prepareJudgeInput}=require('../server/agent-runtime/objectiveJudge');
 let calls=0;const judge=createListingsJudgeGuard(async()=>{calls++;return{verdict:'pass'};});
 for(const record of records)for(const historical of [true,false]){
  const p=historical?structuredClone(record.packet):packet(record);
  if(!historical){const audit=p.evidence[0].content;mutateEffect(audit.raw,record.objectiveId);audit.rawSha256=hash(JSON.stringify(audit.raw));}
  const prepared=prepareJudgeInput(p),before=prepared.packet;
  const receipt={evaluationId:'child',family:p.rubric.family,scenario:p.rubric.scenario,objectiveId:p.rubric.objectiveId,rubricVersion:p.rubric.version,evidenceDigest:prepared.evidenceDigest,runId:'original-run',mode:'vuln',verdict:null};
  const service=createObjectiveCompletionService({judge,progress:{async getGeneration(){return 1;}},receipts:{async beginEvaluation(){},async beginRetry(){return{receipt,packet:before};},async recordVerdict({result}){return{...receipt,result,verdict:result.verdict,disposition:'not_pass'};}}});
  const result=await service.retry({userId:1,evaluationId:'parent',execution:{runId:'retry-run',ownerKey:'owner',durableGeneration:'1',async check(){}}});
  assert.equal(result.judgment.verdict,historical?'unavailable':'fail');assert.equal(result.judgment.canRetry,false);assert.equal(prepared.packet,before);
 }
 assert.equal(calls,0);
});
