'use strict';
// Pure presentation only. Caller must perform current publication authorization
// AFTER building this response; retained applied receipts are not current credit.
const {validateDecisionEvent,validateDecisionReceipt}=require('./ctfDecisionProjectionContract');
const {validateResponseDiagnostics}=require('./ctfResponseDiagnostics');
function formatCtfCurrentAttemptResponse({event,receipt,diagnostics,config,usedTechniques=[]}){
 const e=validateDecisionEvent(event),applied=validateDecisionReceipt(e,receipt?.canonicalResult,receipt?.resultHash).value.data;
 if(!diagnostics)throw Error('CTF_RESPONSE_DIAGNOSTICS_UNAVAILABLE');
 const observation=validateResponseDiagnostics(diagnostics.canonicalDiagnostics,diagnostics.diagnosticsHash,e.evidence);
 if(!config||typeof config.showFeedback!=='boolean'||!Number.isSafeInteger(config.hintGatingAttempts)||config.hintGatingAttempts<0||config.hintGatingAttempts>2147483647||!Array.isArray(usedTechniques)||usedTechniques.length>256||usedTechniques.some(x=>typeof x!=='string'||!x.isWellFormed()||x.includes('\0')||Buffer.byteLength(x)>128))throw TypeError('CTF response configuration invalid');
 const f=e.facts,b=e.evidence.binding;
 const lessonState=b.stageNumber>=6&&b.stageNumber<=10?{
  input_guard_observed:false,reviewer_observed:observation.reviewerObserved,
  category_consumed:['technique','hybrid'].includes(f.adaptiveMode)&&applied.techniqueAdded,
  category_reuse_blocked:false,shared_similarity_blocked:false,
 }:undefined;
 // These are successful decision-path observations, not the separate pre-defense
 // blocked response. Bare blocked verdict never manufactures observed guards.
 if(observation.guardianUnavailable)return{status:503,body:{error:'AI system temporarily unavailable. Please try again.',retryable:true,attemptNumber:f.attemptNumber,judgment:{verdict:'unavailable'},...(lessonState?{lessonState}:{})}};
 const judgment=e.evidence.judgment,success=e.decision.accepted,penalty=applied.hintPenaltyTotal;
 const techniques=config.showFeedback&&['technique','hybrid'].includes(f.adaptiveMode)?[...usedTechniques]:[];
 return{status:200,body:{success,judgment:{verdict:e.decision.verdict,rubricVersion:judgment.rubricVersion,judgeVersion:judgment.judgeVersion},aiResponse:e.evidence.visibleResponse,attemptNumber:f.attemptNumber,responseTime:observation.responseTimeMs,
 techniqueTag:config.showFeedback?e.evidence.techniqueTag:undefined,blocked:false,hintsAvailable:f.attemptNumber>=config.hintGatingAttempts,hintsUsed:applied.hintsUsed,hintPenaltyTotal:penalty,usedTechniques:techniques.length?techniques:undefined,...(lessonState?{lessonState}:{}),
 message:success?`Congratulations! You've completed ${f.stageName}! Score: +${Math.max(0,(f.stageScore??100)-penalty)}${penalty>0?` (${penalty} pts deducted for hints)`:''}`:e.decision.verdict==='unavailable'?'Grading is temporarily unavailable. Your response was saved, but no completion credit was awarded. Please try again.':e.decision.verdict==='inconclusive'?'The Judge could not verify completion from this response. No completion credit was awarded. Please try again.':"The AI didn't reveal the secret. Try a different approach."}};
}
module.exports={formatCtfCurrentAttemptResponse};
