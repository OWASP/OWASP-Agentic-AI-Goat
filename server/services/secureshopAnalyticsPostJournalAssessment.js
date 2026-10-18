'use strict';
function createAnalyticsPostJournalAssessment({loopFactory,disclosureFactory,additionalFactories=[],privateEvidence,readCommittedProjection}){
 if([loopFactory,disclosureFactory,readCommittedProjection].some(f=>typeof f!=='function')||!Array.isArray(additionalFactories)||additionalFactories.some(f=>typeof f!=='function'))throw TypeError('Post-journal assessment dependencies required');
 if(additionalFactories.length===0)return createLegacy({loopFactory,disclosureFactory,privateEvidence,readCommittedProjection});
 let pending,committedProjection,work,terminalError;
 const failures=[];
 const authorityCodes=new Set(['ATTEMPT_SCOPE_MISMATCH','EXECUTION_REQUIRED','STALE_GENERATION','STALE_LAUNCH','CANCELLED','PERSONA_EVALUATION_UNAVAILABLE','ANALYTICS_MODE_STALE','SHOP_AUTH_INVALID','SHOP_ASSESSMENT_STALE','PERSONA_EFFECT_OUTCOME_UNCERTAIN','JUDGMENT_SCOPE_MISMATCH','MODE_CHANGED','ASSESSMENT_SCOPE_UNAVAILABLE']);
 const boundaryError=error=>error?.name==='AbortError'||error?.executionBoundary===true||authorityCodes.has(error?.code);
 const unavailable=phase=>Object.freeze({assessmentStatus:'unavailable',modelEvaluated:false,phase});
 const factory=async(context,fence)=>{
  const loop=await loopFactory(context,fence),entries=[];
  const evidence={...privateEvidence,projectResult:async()=>{if(!committedProjection)throw Error('Completed response unavailable');return committedProjection;}};
  async function check(execution){execution?.signal?.throwIfAborted();if(execution)await execution.check();if(fence?.assertRemoteAdmission)await fence.assertRemoteAdmission();}
  async function call(entry,phase,execution,fn){
   await check(execution);
   let value;try{value=await fn();}
   catch(error){
    // Never turn a lifecycle rejection into an optional objective failure.
    await check(execution);if(boundaryError(error))throw error;
    failures.push(Object.freeze({index:entry.index,phase,error}));entry.error=error;entry.phase=phase;
    return {ok:false,value:unavailable(phase)};
   }
   await check(execution);return {ok:true,value};
  }
  for(const [index,build] of [disclosureFactory,...additionalFactories].entries()){
   const entry={index};entries.push(entry);
   const built=await call(entry,'factory',null,()=>build(context,fence,evidence));
   if(built.ok&&built.value){
    if([built.value.begin,built.value.observe,built.value.finalize].some(fn=>typeof fn!=='function')){
     const error=TypeError('Invalid optional assessment lifecycle');failures.push(Object.freeze({index,phase:'factory',error}));entry.error=error;entry.phase='factory';
    }else entry.assessment=built.value;
   }
  }
  let attempts;
  return {async begin(execution){
   if(attempts)throw Error('Assessment already begun');
   attempts={loop:loop?await loop.begin(execution):null};
   for(const entry of entries)if(entry.assessment){const begun=await call(entry,'begin',execution,()=>entry.assessment.begin(execution));if(begun.ok){entry.attempt=begun.value;entry.admitted=true;}}
   return attempts;
  },async observe(execution,packet){
   if(packet.attempt!==attempts)throw Error('Assessment attempt mismatch');
   if(loop)await loop.observe(execution,{...packet,attempt:attempts.loop});
   for(const entry of entries)if(entry.admitted&&!entry.error)await call(entry,'observe',execution,()=>entry.assessment.observe(execution,{...packet,attempt:entry.attempt}));
  },async finalize(execution,packet){
   if(packet.attempt!==attempts||pending)throw Error('Assessment attempt mismatch');
   if(loop)await loop.finalize(execution,{...packet,attempt:attempts.loop});
   pending={execution,packet,entries,check,call};
  }};
 };
 return Object.freeze({factory,readFailures:()=>failures.slice(),async afterCommit({execution,result}){
  if(!pending)return;
  if(pending.execution!==execution)throw Error('Assessment execution mismatch');
  if(terminalError)throw terminalError;
  if(work)return work;
  // Install the promise before the first asynchronous callback. Concurrent or
  // repeated callbacks cannot repeat a finalizer even when one rejects.
  work=Promise.resolve().then(async()=>{
   await pending.check(execution);
   let postJournalError;
   try{committedProjection=await readCommittedProjection(result);}
   catch(error){await pending.check(execution);if(boundaryError(error))throw error;postJournalError=error;}
   await pending.check(execution);const outcomes=[];
   for(const entry of pending.entries){
    await pending.check(execution);
    if(!entry.admitted){outcomes.push(entry.error?unavailable(entry.phase):undefined);continue;}
    const failure=entry.error||postJournalError;
    const settled=await pending.call(entry,'finalize',execution,()=>entry.assessment.finalize(execution,{...pending.packet,attempt:entry.attempt,...(failure?{postJournalError:failure}:{})}));
    outcomes.push(settled.value);
   }
   return additionalFactories.length?outcomes:outcomes[0];
  }).catch(error=>{terminalError=error;throw error;});
  return work;
 }});
}
module.exports={createAnalyticsPostJournalAssessment};

'use strict';
// Per-query coordinator. A disclosure attempt observes the genuine graph but
// cannot evaluate until the caller has read its completed immutable journal DTO.
function createLegacy({loopFactory,disclosureFactory,privateEvidence,readCommittedProjection}){
 if([loopFactory,disclosureFactory,readCommittedProjection].some(f=>typeof f!=='function'))throw TypeError('Post-journal assessment dependencies required');
 let pending,committedProjection,finished=false;
 const factory=async(context,fence)=>{const loop=await loopFactory(context,fence),disclosure=await disclosureFactory(context,fence,{...privateEvidence,projectResult:async()=>{if(!committedProjection)throw Error('Completed response unavailable');return committedProjection;}});let attempts;
  return {async begin(execution){attempts={loop:loop?await loop.begin(execution):null,disclosure:disclosure?await disclosure.begin(execution):null};return attempts;},async observe(execution,packet){if(packet.attempt!==attempts)throw Error('Assessment attempt mismatch');if(loop)await loop.observe(execution,{...packet,attempt:attempts.loop});if(disclosure)await disclosure.observe(execution,{...packet,attempt:attempts.disclosure});},async finalize(execution,packet){if(packet.attempt!==attempts||pending)throw Error('Assessment attempt mismatch');if(loop)await loop.finalize(execution,{...packet,attempt:attempts.loop});if(disclosure)pending={execution,packet:{...packet,attempt:attempts.disclosure},disclosure};}};
 };
 return Object.freeze({factory,async afterCommit({execution,result}){if(finished||!pending)return;finished=true;if(pending.execution!==execution)throw Error('Assessment execution mismatch');await execution.check();try{committedProjection=await readCommittedProjection(result);}catch(error){await execution.check();return pending.disclosure.finalize(execution,{...pending.packet,postJournalError:error});}await execution.check();return pending.disclosure.finalize(execution,pending.packet);}});
}
