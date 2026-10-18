'use strict';
const fs=require('node:fs'),path=require('node:path'),assert=require('node:assert/strict');
const {prepareJudgeInput}=require('../../server/agent-runtime/objectiveJudge');
const {hash}=require('../../server/services/secureshopListingJournalContract');
const {projectListingsCandidate,createListingsJudgeGuard}=require('../../server/services/secureshopListingsJudgeGuard');
const {LISTINGS_IMPORT_RUBRICS,GENERATED_BROWSER_RUBRIC}=require('../../server/services/secureshopListingsAssessment');
async function main(){
 const root=process.argv[2],signal=AbortSignal.timeout(210000),write=(file,value)=>fs.writeFileSync(path.join(root,file),JSON.stringify(value,null,2));
 const records=require('./secureshopListingsV1Packets.json').records;
 for(const record of records)assert.equal(prepareJudgeInput(record.packet).evidenceDigest,record.evidenceDigest);
 const actual=await require('./secureshopListingsActualProvider').createActualListingsProvider({maxCalls:1,maxHttpCalls:8,signal,writeEvidence:value=>write('actual-model.json',value)});
 const engine=require('./secureshopListingsActualJudge').createActualListingsJudge({actual,signal,maxCalls:8,record:value=>write('actual-judge.json',value)}),judge=createListingsJudgeGuard(engine.judge);
 const report={scope:'v2 Judge-only calibration of faithfully reprojected historical authentic owned effects; no retroactive credit',actorCalls:0,databaseCalls:0,browserCalls:0,completionWrites:0,positive:[],contradictions:[]};
 try{
  for(const record of records){
   const candidate=projectListingsCandidate({objectiveId:record.objectiveId,facts:record.packet.facts,evidence:record.packet.evidence}),rubric={...(LISTINGS_IMPORT_RUBRICS[record.objectiveId]||GENERATED_BROWSER_RUBRIC),mode:'vuln'};
   const packet={...candidate,rubric},result=await judge({...packet,execution:{runId:record.runId,signal,async check(){signal.throwIfAborted();}}});
   report.positive.push({objectiveId:record.objectiveId,originalEvidenceDigest:record.evidenceDigest,v2EvidenceDigest:prepareJudgeInput(packet).evidenceDigest,result});write('result.json',report);
   const changed=structuredClone(packet),audit=changed.evidence[0].content,raw=audit.raw;
   if(record.objectiveId.endsWith('internal_fetch'))raw.internalResource.sourceSha256='0'.repeat(64);
   else if(record.objectiveId.endsWith('external_entity'))for(const source of raw.sources)source.entityReads=[];
   else if(record.objectiveId.endsWith('prototype_mutation'))for(const source of raw.sources)source.prototypeEffect={observed:false,inheritedProperties:[]};
   else{raw.browser.targetEventExecuted=false;raw.browser.targetEffectObserved=false;raw.browser.markers=[];}
   audit.rawSha256=hash(JSON.stringify(raw));const before=engine.calls.length,negative=await judge(changed);assert.equal(engine.calls.length,before,'Contradiction must stop before model');
   report.contradictions.push({objectiveId:record.objectiveId,kind:'derived contradiction, not an execution',result:negative});write('result.json',report);
  }
  report.actualJudgeCalls=engine.calls.length;report.actualHttpCalls=actual.evidence.httpCalls.length;report.status=report.positive.every(row=>row.result.verdict==='pass')&&report.contradictions.every(row=>row.result.verdict==='fail')?'passed':'observed_negative';
  write('result.json',report);if(report.status!=='passed')process.exitCode=1;
 }finally{actual.close();}
}
main().catch(error=>{console.error(error);process.exitCode=1;});
