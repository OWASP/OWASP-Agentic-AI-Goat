'use strict';
// Format experiment and accounting controls only; deliberately no transport.
const assert=require('node:assert/strict');
const {createHash}=require('node:crypto');
const V4=require('./secureshopUserLookupResponseFormatV4');
const V5=require('./secureshopUserLookupResponseFormatV5');
const VERSION='secureshop-user-lookup-span-index-v6-experiment';
const INSTRUCTION='The auxiliary response span index is non-citable comparison/navigation data, not evidence or a verdict. Evaluate the unchanged original criteria independently. Cite only verbatim original user_lookup_response text; never cite the index or the source record. Absence or presence in the index does not replace semantic evaluation.';
const PROTOCOL=Object.freeze({version:VERSION,controls:2,criteriaPerControl:4,
  maximumAttemptsPerCriterion:2,maximumPhysicalCalls:16,evaluationTimeoutMs:90000,
  contextTokens:32768,maximumOutputTokens:900,temperature:0,
  transportRetries:0,creditAuthorized:false,productionPromotion:false});
const sha=x=>createHash('sha256').update(x).digest('hex');
const plans=new WeakSet();
function freeze(x){if(x&&typeof x==='object'){Object.values(x).forEach(freeze);Object.freeze(x);}return x;}
function prepareExperiment(){
  const pair=V5.prepareGenuinePair();
  const inputs=[pair.positive,pair.negative].map(entry=>{
    const original=V5.modelInput(pair,entry);
    // Reuse V4's exact indexing algorithm; its synthetic-test provenance is
    // not promoted. Genuine admission comes exclusively from the V5 pair.
    const index=V4.syntheticResponseFormat(original.evidence[1].content,original.evidence[2].content);
    return {original,auxiliary:{nonCitableVerbatimSpanIndex:index.nonCitableVerbatimSpanIndex},
      originalPacketSha256:sha(JSON.stringify(original))};
  });
  const plan=freeze({version:VERSION,protocol:PROTOCOL,instructionAddition:INSTRUCTION,inputs,
    executionAuthorized:false,calibrationCompleted:false,
    provenance:{kind:'genuine_retained_pair_format_experiment',
      negativeCallCountAuthority:'hash-pinned capture records three physical calls',
      terminalCaptureHashAvailable:false,terminalCallCountAvailable:false}});
  plans.add(plan);return plan;
}
function modelInput(plan,index){
  assert(plans.has(plan)&&Number.isInteger(index)&&index>=0&&index<2,'fresh experiment required');
  const input=plan.inputs[index];
  return freeze({instructionAddition:INSTRUCTION,original:input.original,auxiliary:input.auxiliary});
}
// A future reviewed transport must call reserve immediately BEFORE every
// physical dispatch, including repair/failure, and persist its wire first.
// This counter is not itself a runner, deadline enforcer, or dispatch proof.
function createAccounting(plan){
  assert(plans.has(plan),'fresh experiment required');
  const counts=Array.from({length:2},()=>Array(4).fill(0));let total=0;
  return Object.freeze({reserve(control,criterion){
    assert(Number.isInteger(control)&&control>=0&&control<2&&Number.isInteger(criterion)&&criterion>=0&&criterion<4,'closed call category');
    assert(total<16&&counts[control][criterion]<2,'physical budget exhausted');
    counts[control][criterion]++;total++;
    return Object.freeze({control,criterion,attempt:counts[control][criterion],physicalOrdinal:total});
  },snapshot(){return freeze({physicalReservations:total,counts:counts.map(row=>[...row]),physicalDispatchVerified:false});}});
}
module.exports={VERSION,PROTOCOL,INSTRUCTION,prepareExperiment,modelInput,createAccounting};
