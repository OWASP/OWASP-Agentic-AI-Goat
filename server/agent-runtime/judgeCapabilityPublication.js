'use strict';
// Pure transaction-local precondition. Trusted readers must validate their own
// brands. Caller must supply canonical facts read while holding publication locks.
const fields=['owner','session','generation','run','objective','rubric','evidenceContract','adapter','provider','contextTokens','evidenceDigest','evaluationId','requestDigest','contextDigest','schemaDigest'];
const hex=v=>typeof v==='string'&&/^[a-f0-9]{64}$/.test(v);
function deny(){throw Object.assign(Error('Judge publication binding unavailable'),{code:'JUDGE_PUBLICATION_UNAVAILABLE'});}
function scope(v){if(!v||Object.keys(v).sort().join()!==[...fields].sort().join())deny();for(const k of fields){const x=v[k];if(['generation','contextTokens'].includes(k)){if(!Number.isSafeInteger(x)||x<(k==='generation'?0:1))deny();}else if(k.endsWith('Digest')){if(!hex(x))deny();}else if(typeof x!=='string'||!x.length||x.length>160)deny();}return Object.freeze(Object.fromEntries(fields.map(k=>[k,v[k]])));}
function createJudgeCapabilityPublication({readEvaluation,readQualification,readExecution}){
 if([readEvaluation,readQualification,readExecution].some(f=>typeof f!=='function'))deny();
 return Object.freeze({validate({evaluation,qualification,execution,canonical,signal}){
  if(signal?.aborted)deny();
  const current=scope(canonical),admitted=scope(readEvaluation(evaluation));
  if(fields.some(k=>current[k]!==admitted[k]))deny();
  const q=readQualification(qualification);
  if(!q||!['objective','rubric','evidenceContract','adapter','provider'].every(k=>q[k]===admitted[k])||!hex(q.modelDigest)||!hex(q.evaluationDigest)||!Number.isSafeInteger(q.contextLimit)||q.contextLimit<admitted.contextTokens)deny();
  const expected=Object.freeze(Object.fromEntries(['evaluationId','requestDigest','contextDigest','schemaDigest','adapter','provider'].map(k=>[k,admitted[k]]).concat([['modelDigest',q.modelDigest]])));
  const e=readExecution(execution,expected,{signal});
  if(!e||!Object.keys(expected).every(k=>e[k]===expected[k])||!hex(e.outputDigest)||!hex(e.proofDigest)||signal?.aborted)deny();
  return Object.freeze({...admitted,modelDigest:q.modelDigest,qualificationDigest:q.evaluationDigest,outputDigest:e.outputDigest,executionProofDigest:e.proofDigest});
 }});
}
module.exports={createJudgeCapabilityPublication};
