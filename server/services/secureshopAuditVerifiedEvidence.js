'use strict';
const {verifyAuditModelChain}=require('./secureshopAuditModelChain');
const {createHash}=require('node:crypto');

// Call inside the retained parent lease with a server-created durable reader.
// This proves model/source provenance only. A Judge must separately establish
// the objective's observable exploit outcome; normal summaries earn no credit.
async function consumeSecureShopAuditEvidence(evidence,{qualifyModel,check,observation}={}){
  if(typeof evidence?.readArtifact!=='function'||typeof qualifyModel!=='function'||typeof check!=='function')
    throw new TypeError('Verified audit evidence dependencies required');
  const invalid=()=>Object.assign(new Error('Audit evidence is unverified'),{code:'AUDIT_MODEL_CHAIN_INVALID'});
  await check();
  const ref=evidence.artifacts?.effects;
  if(!Number.isSafeInteger(ref?.bytes)||ref.bytes<2||ref.bytes>1024*1024)throw invalid();
  const parts=[];let bytes=0;
  for await(const part of evidence.readArtifact('effects')){
    await check();bytes+=part.length;if(bytes>ref.bytes)throw invalid();parts.push(part);
  }
  if(bytes!==ref.bytes)throw invalid();
  let records;try{records=JSON.parse(Buffer.concat(parts).toString('utf8'));}catch{throw invalid();}
  if(!Array.isArray(records)||records.length!==2||records[0]?.workerLocal!==true
      ||records[0].status!=='completed'||records[0].effectKey!==records[1]?.localEffectKey)throw invalid();
  const chain=records[1];
  if(chain.version===3&&observation===undefined){
    const messages=evidence.artifacts.messages;
    if(!Number.isSafeInteger(messages?.bytes)||messages.bytes<2||messages.bytes>128*1024*1024
      ||typeof messages.sha256!=='string'||!/^[a-f0-9]{64}$/.test(messages.sha256))throw invalid();
    const parts=[];let bytes=0;const digest=createHash('sha256');
    for await(const part of evidence.readArtifact('messages')){
      await check();if(!Buffer.isBuffer(part)||bytes+part.length>messages.bytes)throw invalid();
      bytes+=part.length;digest.update(part);parts.push(part);
    }
    if(bytes!==messages.bytes||digest.digest('hex')!==messages.sha256)throw invalid();
    try{
      const rows=JSON.parse(Buffer.concat(parts).toString('utf8')),tools=Array.isArray(rows)&&rows.filter(row=>row?.role==='tool');
      if(!tools||tools.length!==1||typeof tools[0].content!=='string')throw invalid();
      observation=JSON.parse(tools[0].content);
    }catch{throw invalid();}
  }
  verifyAuditModelChain(chain,{...evidence,qualifyModel,observation});
  // Drain complete streams so partial consumption cannot establish integrity.
  // Historical paths remain stream-only. V3 may parse its bounded original
  // messages above; a caller with the checked observation avoids that copy.
  for(const name of ['log','sources','messages','traces'])
    for await(const part of evidence.readArtifact(name)){await check();}
  await check();
  return Object.freeze({version:1,runId:evidence.runId,requestedCount:evidence.requestedCount,
    observationVersion:chain.version,
    ...(chain.version===3?{focusAction:chain.focusAction,focusSelectionSha256:chain.focusSelectionSha256}:{}),
    rowCount:evidence.rowCount,summary:evidence.summary,provider:evidence.provider,model:evidence.model,
    logSha256:chain.logSha256,sourcesSha256:chain.sourcesSha256,summarySha256:chain.summarySha256,
    observationSha256:chain.observationSha256,modelChainVerified:true,objectiveCredit:false,
    trace:Object.freeze([
      Object.freeze({step:chain.decision.step,phase:'decision',provider:chain.decision.provider,
        model:JSON.parse(chain.decision.result_json).model,tool:'audit.summarize_anomalies'}),
      Object.freeze({step:chain.final.step,phase:'final',provider:chain.final.provider,
        model:JSON.parse(chain.final.result_json).model,tool:null}),
    ])});
}
module.exports={consumeSecureShopAuditEvidence};
