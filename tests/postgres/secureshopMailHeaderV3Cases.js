"use strict";
const assert=require('node:assert/strict'),crypto=require('node:crypto');
const legacy=require('./secureshopMailHeaderJudgeCases');
const {buildMailHeaderCandidate,MAIL_HEADER_RUBRIC}=require('../../server/services/secureshopMailHeaderEvidence');
const {prepareJudgeInput}=require('../../server/agent-runtime/objectiveJudge');
const {selection}=require('../../server/agent-runtime/mailHeaderBoundarySelection');
function buildCases(bytes,hash){
 const prior=legacy.buildCases(bytes,hash);
 const cases=prior.cases.filter(c=>c.kind!=='synthetic_semantic').map(c=>{
  if(c.kind==='synthetic_guard'){assert.equal(buildMailHeaderCandidate(c.observed),null);return c;}
  const packet=buildMailHeaderCandidate(c.observed);assert(packet);
  const prepared=prepareJudgeInput({...packet,rubric:{...MAIL_HEADER_RUBRIC,mode:'vuln'}});assert.equal(prepared.evidenceError,undefined);
  return {...c,packet,packetDigest:prepared.evidenceDigest};
 });
 assert.equal(cases.filter(c=>c.packet).length,2);assert.equal(cases.filter(c=>!c.packet).length,7);
 return {retainedSha256:hash,maximumModelCases:2,maximumHttpCalls:4,maximumCallsPerCase:2,cases};
}
async function evaluateCases(plan,judge,onResult=()=>{}){
 const results=[];
 for(const c of plan.cases){
  let row;
  if(!c.packet){assert.equal(buildMailHeaderCandidate(c.observed),null);row={name:c.name,status:'not_admitted',modelCalls:0,expectationPassed:true};}
  else {const judgment=await judge({...c.packet,rubric:{...MAIL_HEADER_RUBRIC,mode:'vuln'},execution:{async check(){}}});const audit=judgment.scopedCriteria?.find(x=>x.boundarySelection)?.boundarySelection?.at(-1);const valid=audit?.validationReason==='VALID'&&audit.rawSatisfied===true&&audit.selectedIds.length>0&&new Set(audit.selectedIds).size===audit.selectedIds.length&&audit.citations.length===audit.selectedIds.length;row={name:c.name,kind:c.kind,packetDigest:c.packetDigest,judgment,rawSatisfied:audit?.rawSatisfied??null,selectedIds:audit?.selectedIds||[],citations:audit?.citations||[],validationReason:audit?.validationReason||null,expectationPassed:judgment.verdict==='pass'&&valid,scope:'Retained native effect with current real Judge; no fresh actor or credit'};}
  results.push(row);onResult(row);
 }return results;
}
function replayPrior(bytes,hash){
 assert.equal(crypto.createHash('sha256').update(bytes).digest('hex'),hash);
 const prior=JSON.parse(bytes);assert.equal(prior.status,'observed_negative');
 assert.equal(prior.http.length,6);
 return prior.cases.filter(c=>c.judgment).map((c,i)=>{
  const response=prior.http[i].response;const chunks=response.trim().split('\n').map(line=>JSON.parse(line));const raw=JSON.parse(chunks.map(envelope=>envelope.message?.content||envelope.response||'').join(''));
  const packet=prior.plan.cases.find(p=>p.name===c.name)?.packet;
  const boundaries=packet?.evidence.find(e=>e.id==='header_boundary')?.content.boundaries||[];
  return {name:c.name,scope:'Offline historical response support replay only; no model call, no production admission, no semantic reclassification',originalVerdict:c.judgment?.verdict,raw,selection:selection(raw,boundaries.map(w=>({...w,id:`${w.field}:${w.sourceOffset}`})))};
 }).filter(r=>r.raw);
}
module.exports={buildCases,evaluateCases,replayPrior};
