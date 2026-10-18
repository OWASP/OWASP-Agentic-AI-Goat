'use strict';
const assert=require('node:assert/strict'),{createHash}=require('node:crypto');
const {createDiagnostic,STAGES}=require('./factoredJudgePrimitives'),contracts=require('./factoredJudgeSemanticContracts');
const sha=x=>createHash('sha256').update(x).digest('hex');
async function diagnose(evidence,{objective,transport,timeoutMs=360000,signal,effectRequired=false}={}){
 assert.equal(typeof transport,'function');assert(['pricing_attack','rag_attack','rag_defense'].includes(objective));
 // Diagnostic inputs never establish authenticated external-effect authority.
 assert(Number.isSafeInteger(timeoutMs)&&timeoutMs>0&&timeoutMs<=360000);
 const deadline=performance.now()+timeoutMs;
 const check=()=>{if(signal?.aborted||performance.now()>=deadline){const error=new Error('Diagnostic deadline or cancellation');error.code='DIAGNOSTIC_DEADLINE';throw error;}};
 const immutable=JSON.parse(JSON.stringify(evidence)),context={},requests=[],failures=[];
 const run=createDiagnostic({source:immutable.source,timeoutMs:Math.max(1,Math.floor(deadline-performance.now())),signal});
 for(const stage of STAGES){
  if(stage==='extraction'&&context.classification?.decision==='no_directive'){run.skipNegativeExtraction();continue;}
  if(context.classification?.decision==='uncertain')break;
  const input=STAGES.indexOf(stage)<3?{source:immutable.source}:stage==='task_relation'?{source:immutable.source,task:immutable.task}:{source:immutable.source,task:immutable.task,response:immutable.response,responseComplete:immutable.responseComplete,effects:immutable.effects};
  try{
   check();const request=contracts.requestFor(stage,input,context);requests.push({stage,sha256:sha(JSON.stringify(request)),request});check();
   const result=await run.run(stage,input,async(_,{signal,timeoutMs})=>{
    // Exactly one callback dispatch. A future HTTP harness must bind this attempt
    // to one recorded request; SDK retries are neither allowed nor proven here.
    check();const remaining=Math.floor(deadline-performance.now());if(remaining<1){const error=new Error('Diagnostic deadline');error.code='DIAGNOSTIC_DEADLINE';throw error;}
    return transport(request,{signal,timeoutMs:Math.min(timeoutMs,remaining),attempt:run.snapshot().attempts});
   });
   const row=result.records.at(-1);if(row.status!=='observed-unvalidated'){failures.push({stage,reason:row.status});break;}
   context[stage]=contracts.parseStage(stage,row.raw,{source:immutable.source,response:immutable.response,groups:context.extraction?.groups||[]});check();
   if(stage==='extraction'&&context.extraction.coverage!=='complete')break;
   if(stage==='coverage'&&(context.classification.decision==='no_directive'||context.coverage.coverage!=='complete'||context.coverage.structure!=='supported'||context.coverage.sourceHasDirective!=='yes'||context.coverage.omissions.length||context.coverage.groups.some(g=>g.entailed!=='yes'||g.groupingFaithful!=='yes'||g.items.some(i=>i.entailed!=='yes'||i.kindFaithful!=='yes'))))break;
  }catch(error){failures.push({stage,reason:error.code==='DIAGNOSTIC_DEADLINE'?'cancelled-or-deadline':error instanceof SyntaxError?'invalid-json':'invalid-contract'});break;}
 }
 try{check();}catch{failures.push({stage:'final-disposition',reason:'cancelled-or-deadline'});}
 let disposition;
 if(failures.length)disposition={verdict:'unavailable',reason:failures[0].reason};
 else if(context.extraction?.coverage==='uncertain')disposition={verdict:'inconclusive',reason:'unsupported-source-coverage'};
 else disposition=contracts.decide(context,{objective,effectRequired,effectAuthenticated:false});
 try{check();}catch{disposition={verdict:'unavailable',reason:'cancelled-or-deadline'};}
 return Object.freeze({protocol:contracts.PROTOCOL,...disposition,creditAuthorized:false,semanticAccepted:null,stages:context,requests,failures,transport:run.snapshot(),wireAttemptsVerified:false});
}
module.exports={diagnose};
