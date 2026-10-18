'use strict';
function analyticsAssessmentGroup({loopFactory,disclosureFactory,privateEvidence}){
 if(typeof loopFactory!=='function'||typeof disclosureFactory!=='function')throw TypeError('Analytics assessment factories required');
 return async(context,fence)=>{
  const assessments=[await loopFactory(context,fence),await disclosureFactory(context,fence,privateEvidence)].filter(Boolean);let attempts;
  return {async begin(execution){attempts=[];for(const assessment of assessments)attempts.push(await assessment.begin(execution));return attempts;},async observe(execution,packet){if(packet.attempt!==attempts)throw Error('Analytics assessment attempt mismatch');for(let i=0;i<assessments.length;i++)await assessments[i].observe(execution,{...packet,attempt:attempts[i]});},async finalize(execution,packet){if(packet.attempt!==attempts)throw Error('Analytics assessment attempt mismatch');const outcomes=[];for(let i=0;i<assessments.length;i++)outcomes.push(await assessments[i].finalize(execution,{...packet,attempt:attempts[i]}));return outcomes;}};
 };
}
module.exports={analyticsAssessmentGroup};
