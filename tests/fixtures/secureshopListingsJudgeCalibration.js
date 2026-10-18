'use strict';
// Capture actual canonical packets in an owned integrated fixture. This helper
// never creates a positive packet or awards a completion from calibration.
const assert=require('node:assert/strict');
const {createHash}=require('node:crypto');
const {prepareJudgeInput}=require('../../server/agent-runtime/objectiveJudge');
const {LISTINGS_IMPORT_RUBRICS,GENERATED_BROWSER_RUBRIC}=require('../../server/services/secureshopListingsAssessment');
const RUBRICS={...LISTINGS_IMPORT_RUBRICS,[GENERATED_BROWSER_RUBRIC.objectiveId]:GENERATED_BROWSER_RUBRIC};
const sha=value=>createHash('sha256').update(value).digest('hex');
function captureCanonicalListingsPackets({receipts,record}={}){
 assert.equal(typeof receipts?.beginEvaluation,'function');assert.equal(typeof record,'function');
 const captured=new Map();
 const wrapped={...receipts};
 wrapped.beginEvaluation=async function(scope,personaToken){
  const packetText=scope?.recovery?.packet;
  if(scope?.workshopKey!=='secureshop_agent_security'||!RUBRICS[scope.objectiveId])return receipts.beginEvaluation(scope,personaToken);
  assert.equal(typeof packetText,'string');assert.equal(sha(packetText),scope.evidenceDigest);
  const packet=JSON.parse(packetText),prepared=prepareJudgeInput(packet);
  assert.equal(prepared.evidenceError,undefined);assert.equal(prepared.evidenceDigest,scope.evidenceDigest);
  assert.deepEqual(packet.rubric,prepareJudgeInput({rubric:{...RUBRICS[scope.objectiveId],mode:scope.mode},facts:packet.facts,evidence:packet.evidence}).rubric);
  assert.ok(packet.rubric.requiredFacts.every(key=>packet.facts[key]===true));
  // Forward the private token unchanged and never include it in artifacts.
  const receipt=await receipts.beginEvaluation(scope,personaToken);
  const value={objectiveId:scope.objectiveId,evaluationId:scope.evaluationId,runId:scope.runId,
   evidenceDigest:scope.evidenceDigest,packet:JSON.parse(packetText),source:'forwarded canonical beginEvaluation recovery.packet'};
  const existing=captured.get(scope.evaluationId);if(existing)assert.deepEqual(existing,value);
  else{captured.set(scope.evaluationId,structuredClone(value));await record(structuredClone(value));}
  return receipt;
 };
 return{receipts:wrapped,snapshot:()=>structuredClone([...captured.values()])};
}
function calibrationCases(records){
 const selected=Object.keys(RUBRICS).map(objectiveId=>{
  const matches=records.filter(record=>record.objectiveId===objectiveId);assert.equal(matches.length,1,'Exactly one fresh authentic packet per objective required');
  const value=structuredClone(matches[0]);assert.equal(prepareJudgeInput(value.packet).evidenceDigest,value.evidenceDigest);return value;
 });
 return selected.flatMap(value=>{
  const positive={id:value.objectiveId+':authentic',kind:'authentic-recorded-positive',expected:'pass',originalEvaluationId:value.evaluationId,originalDigest:value.evidenceDigest,packet:value.packet};
  const missingEffect=structuredClone(value.packet),effect=missingEffect.evidence.find(row=>row.id==='listing_owned_effect')||{content:missingEffect.evidence.find(row=>row.id==='listing_audit')?.content?.raw};assert.ok(effect.content);
  // This is a deliberately derived calibration input, never a claimed run.
  if(value.objectiveId===GENERATED_BROWSER_RUBRIC.objectiveId){effect.content.browser.targetEventExecuted=false;effect.content.browser.targetEffectObserved=false;effect.content.browser.markers=[];}
  else if(value.objectiveId==='ss_listing_internal_fetch')effect.content.internalResource.sourceSha256='0'.repeat(64);
  else if(value.objectiveId==='ss_listing_external_entity')for(const source of effect.content.sources)source.entityReads=[];
  else for(const source of effect.content.sources)source.prototypeEffect={observed:false,inheritedProperties:[]};
  const audit=missingEffect.evidence.find(row=>row.id==='listing_audit')?.content;if(audit)audit.rawSha256=sha(JSON.stringify(audit.raw));
  // Leave facts as-is to test semantic rejection of conflicting claimed facts.
  return[positive,{id:value.objectiveId+':derived-no-effect',kind:'derived-negative-not-an-execution',expected:'not-pass',originalEvaluationId:value.evaluationId,originalDigest:value.evidenceDigest,packet:missingEffect}];
 });
}
module.exports={captureCanonicalListingsPackets,calibrationCases};
