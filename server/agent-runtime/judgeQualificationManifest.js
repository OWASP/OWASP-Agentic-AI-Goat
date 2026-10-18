'use strict';
const {verify,createHash}=require('node:crypto');
const {parseStrictJson}=require('./referenceComparisonVerifier');
const hash=b=>createHash('sha256').update(b).digest('hex');
const hex=v=>typeof v==='string'&&/^[a-f0-9]{64}$/.test(v);
const text=v=>typeof v==='string'&&v.length>0&&v.length<=160;
function deny(){throw Object.assign(Error('Judge qualification unavailable'),{code:'JUDGE_CAPABILITY_UNAVAILABLE'});}
function keys(v,list){if(!v||typeof v!=='object'||Object.keys(v).sort().join()!==[...list].sort().join())deny();}
// Trusted public keys and content-addressed artifact reader are bootstrap-only.
// A signed approval is necessary but not evidence of universal semantic accuracy.
function createJudgeQualificationVerifier({approvalKeys,readArtifact}){
 if(!Array.isArray(approvalKeys)||!approvalKeys.length||approvalKeys.some(k=>k?.type!=='public'||k.asymmetricKeyType!=='ed25519')||typeof readArtifact!=='function')deny();
 const trusted=[...approvalKeys],owned=new WeakMap();
 async function approve(raw,signature){
  if(typeof raw!=='string'||Buffer.byteLength(raw)>8192||!Buffer.isBuffer(signature)||signature.length!==64)deny();
  const bytes=Buffer.from(raw);if(!trusted.some(k=>verify(null,bytes,k,signature)))deny();
  const v=parseStrictJson(raw);
  keys(v,['version','objective','rubric','evidenceContract','adapter','provider','modelDigest','contextLimit','cohortDigest','rawDigest','resultDigest','requiredPositive','requiredNegative']);
  if(v.version!==1||!['objective','rubric','evidenceContract','adapter','provider'].every(k=>text(v[k]))||!['modelDigest','cohortDigest','rawDigest','resultDigest'].every(k=>hex(v[k]))||!['contextLimit','requiredPositive','requiredNegative'].every(k=>Number.isSafeInteger(v[k])&&v[k]>0))deny();
  for(const d of [v.cohortDigest,v.rawDigest,v.resultDigest]){const b=await readArtifact(d);if(!Buffer.isBuffer(b)||b.length>16777216||hash(b)!==d)deny();if(d===v.resultDigest){const r=parseStrictJson(b.toString('utf8'));keys(r,['passed','positiveMatched','negativeMatched','caseCount','unavailable','falseCredit','tupleDigest','cohortDigest','rawDigest']);const tuple=Object.fromEntries(['objective','rubric','evidenceContract','adapter','provider','modelDigest','contextLimit'].map(k=>[k,v[k]]));if(r.passed!==true||r.positiveMatched!==v.requiredPositive||r.negativeMatched!==v.requiredNegative||r.caseCount!==v.requiredPositive+v.requiredNegative||r.unavailable!==0||r.falseCredit!==0||r.tupleDigest!==hash(JSON.stringify(tuple))||r.cohortDigest!==v.cohortDigest||r.rawDigest!==v.rawDigest)deny();}}
  const entry=Object.freeze(Object.fromEntries(['objective','rubric','evidenceContract','adapter','provider','modelDigest','contextLimit'].map(k=>[k,v[k]]).concat([['evaluationDigest',hash(bytes)]])));
  const token=Object.freeze(Object.create(null));owned.set(token,entry);return token;
 }
 function read(token){const entry=owned.get(token);if(!entry)deny();return entry;}
 return Object.freeze({approve,read});
}
module.exports={createJudgeQualificationVerifier};
