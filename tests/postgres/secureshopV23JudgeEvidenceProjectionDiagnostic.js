'use strict';
// Offline prospective presentation only. No transport, verdict, or credit API.
const assert=require('node:assert/strict');
const {createHash}=require('node:crypto');
const retained=require('./secureshopV23JudgePresentationDiagnostic');
const {canonicalDigest}=require('../../server/services/mcp/protocolContext');
const VERSION='datum-reference-projection-v1';
const REFS=Object.freeze(['selected-call','durable-effect','registration-receipt','actor-final']);
const sha=value=>createHash('sha256').update(value).digest('hex');
function own(object,key){assert(object&&Object.hasOwn(object,key),`Missing datum: ${key}`);return object[key];}
function project(packet){
 const e=own(packet,'evidence');assert.equal(canonicalDigest(e),packet.evidenceSha256);
 assert.deepEqual(e.refs,REFS);assert.equal(e.registrationLinks.length,1);
 const observation=e.observation,record=e.registrationLinks[0].record;
 const receipt=record.receipt,change=receipt.proof.changes[0];
 assert.equal(receipt.state,'completed');assert.equal(receipt.drained,true);
 assert.equal(receipt.proof.changes.length,1);
 const measured=own(change.effect,'stdioEffect');
 assert.deepEqual(own(e,'effect'),measured);
 assert.deepEqual(own(observation.result.receipt.changes[0].effect,'stdioEffect'),measured);
 assert.equal(observation.result.receipt.changes.length,1);
 for(const key of ['state','operationId','requestSha256'])assert.equal(observation.result.receipt[key],receipt.proof[key]);
 assert.deepEqual(observation.result.receipt.changes[0].effect,change.effect);
 assert.equal(e.suppliedCommand,change.endpoint);
 assert.equal(e.selectedArgs.stdio_cmd,e.suppliedCommand);
 assert.deepEqual(e.selectedArgs,observation.args);
 assert.equal(record.envelope.args.stdio_cmd,e.suppliedCommand);
 assert.equal(record.envelope.argsSha256,canonicalDigest(record.envelope.args));
 assert.equal(record.envelope.requestSha256,receipt.proof.requestSha256);
 assert.equal(record.envelope.runId,e.runId);
 assert.equal(record.envelope.callId,observation.callId);
 if(measured!==null){
  assert.deepEqual(Object.keys(measured).sort(),['bytes','sha256','text']);
  assert.equal(typeof measured.text,'string');assert.equal(measured.bytes,Buffer.byteLength(measured.text));
  assert.equal(measured.sha256,sha(measured.text));
 }
 // Reference values contain observations, never case labels or inferred truth values.
 return {version:VERSION,refs:[...REFS],dataByReference:{
  'selected-call':{suppliedCommand:e.suppliedCommand,tool:observation.tool,args:structuredClone(e.selectedArgs),callId:observation.callId,step:observation.step},
  'durable-effect':{path:'/owned-mcp-files/stdio-effect',observation:structuredClone(measured)},
  'registration-receipt':{state:receipt.state,drained:receipt.drained,runId:e.runId,operationId:receipt.proof.operationId,requestSha256:receipt.proof.requestSha256,instanceId:receipt.proof.instanceId},
  'actor-final':{text:e.finalText}
 }};
}
function prepare(packets,wire){
 // Reuse the original terminal reconstruction and exact original physical-wire joins.
 // Discard its experimental wording; clone the ORIGINAL request below instead.
 retained.prepare(packets,wire,retained.COMBINED_VERSION);
 return packets.map((capture,i)=>{
  const judgeView=project(capture.packet),call=wire.judges[i],request=JSON.parse(call.request);
  request.messages[1].content=JSON.stringify(judgeView);
  return {version:VERSION,request,judgeView,provenance:{rawPacket:structuredClone(capture.packet),
   rawPacketSha256:canonicalDigest(capture.packet),terminalSha256:canonicalDigest(capture.terminal),
   originalRequestSha256:call.requestSha256,originalResponseSha256:call.responseSha256,
   sourcePaths:{'selected-call':'evidence.observation','durable-effect':'evidence.registrationLinks[0].record.receipt.proof.changes[0].effect.stdioEffect','registration-receipt':'evidence.registrationLinks[0].record.receipt','actor-final':'evidence.finalText'}},
   limits:{actorCalls:0,judgeCalls:2,callSeconds:60,totalSeconds:135,registrationEffects:0},canonicalCredit:false,qualificationComplete:false};
 });
}
module.exports={VERSION,REFS,project,prepare};
