'use strict';
// Fixture-only v2 runner. No production dispatch, persistence, provider or credit.
const assert=require('node:assert/strict'),{createHash}=require('node:crypto');
const {createDiagnostic,STAGES}=require('./factoredJudgePrimitives');
const contracts=require('./factoredJudgeExpressionContracts');
const sha=x=>createHash('sha256').update(x).digest('hex');
async function diagnose(evidence,{objective,transport,timeoutMs=360000,signal,effectRequired=false}={}){
 assert.equal(typeof transport,'function');assert(['pricing_attack','rag_attack','rag_defense'].includes(objective));assert.equal(typeof effectRequired,'boolean');
 assert(Number.isSafeInteger(timeoutMs)&&timeoutMs>0&&timeoutMs<=360000);
 const deadline=performance.now()+timeoutMs,controller=new AbortController(),combined=AbortSignal.any([controller.signal,...(signal?[signal]:[])]);
 const check=()=>{if(performance.now()>=deadline)controller.abort();combined.throwIfAborted();};
 assert(evidence&&Object.getPrototypeOf(evidence)===Object.prototype);assert.deepEqual(Object.keys(evidence).sort(),['effects','response','responseComplete','source','task']);assert.equal(evidence.effects,null);
 const immutable=JSON.parse(JSON.stringify(evidence)),context={},requests=[],failures=[];
 const run=createDiagnostic({source:immutable.source,timeoutMs:Math.max(1,Math.floor(deadline-performance.now())),signal:combined});
 for(const stage of STAGES){
  if(stage==='extraction'&&context.classification?.decision==='no_directive'){run.skipNegativeExtraction();continue;}
  if(context.classification?.decision==='uncertain')break;
  const input=STAGES.indexOf(stage)<3?{source:immutable.source}:stage==='task_relation'?{source:immutable.source,task:immutable.task}:immutable;
  try{
   check();const request=contracts.requestFor(stage,input,context);check();requests.push({stage,request,sha256:sha(JSON.stringify(request))});
   const outcome=await run.run(stage,input,async(_,{signal,timeoutMs})=>{check();const remaining=Math.floor(deadline-performance.now());assert(remaining>0);return transport(request,{signal,timeoutMs:Math.min(timeoutMs,remaining),attempt:run.snapshot().attempts});});
   check();const row=outcome.records.at(-1);if(row.status!=='observed-unvalidated'){failures.push({stage,reason:row.status});break;}
   context[stage]=contracts.parseStage(stage,row.raw,{source:immutable.source,response:immutable.response,groups:context.extraction?.groups||[]});check();
   if(stage==='extraction'&&context.extraction.coverage==='uncertain')break;
   if(stage==='coverage'&&(context.classification.decision==='no_directive'||!contracts.sourceReady(context)))break;
  }catch(error){if(combined.aborted||performance.now()>=deadline){controller.abort();failures.push({stage,reason:'cancelled-or-deadline'});}else failures.push({stage,reason:error instanceof SyntaxError?'invalid-json':'invalid-contract'});break;}
 }
 let disposition;
 try{check();disposition=failures.length?{verdict:'unavailable',reason:failures[0].reason}:contracts.decide(context,{objective,effectRequired});check();}
 catch{controller.abort();disposition={verdict:'unavailable',reason:'cancelled-or-deadline'};}
 return Object.freeze({protocol:contracts.PROTOCOL,...disposition,creditAuthorized:false,semanticAccepted:null,stages:context,requests,failures,transport:run.snapshot(),wireAttemptsVerified:false});
}
module.exports={diagnose};
