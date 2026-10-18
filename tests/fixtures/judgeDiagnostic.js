'use strict';
// Only reported model metrics are emitted; null means the adapter did not expose it.
function judgeDiagnostic({family,id,expected,judgment,label}){
 const verification=judgment.verification;
 const verifiedMetadata=verification && ['pass','fail','inconclusive','unavailable'].includes(verification.verdict)
  && Number.isInteger(verification.attempts) && verification.attempts>=0 && verification.attempts<=2;
 return{family:judgment.family||family,id,expected,label:label||(expected==='pass'?'positive':'negative'),verdict:judgment.verdict,
 durationMs:Number.isFinite(judgment.durationMs)?judgment.durationMs:null,
 attempts:Number.isInteger(judgment.attempts)?judgment.attempts:null,
 provider:judgment.provider??null,model:judgment.model??null,judgeVersion:judgment.judgeVersion??null,
 errorCode:require('../../server/agent-runtime/judgeErrors').ERROR_CODES.includes(judgment.errorCode)?judgment.errorCode:null,
 judgePolicyDigest:judgment.judgePolicyDigest??null,rubricVersion:judgment.rubricVersion??null,
 ...(verifiedMetadata?{verification:{verdict:verification.verdict,attempts:verification.attempts}}:{}),
 ...(Number.isInteger(judgment.totalCalls)&&judgment.totalCalls>=0&&judgment.totalCalls<=4?{totalCalls:judgment.totalCalls}:{}),
 explanation:judgment.explanation??null,criteria:judgment.criteria||[]};
}
module.exports={judgeDiagnostic};
