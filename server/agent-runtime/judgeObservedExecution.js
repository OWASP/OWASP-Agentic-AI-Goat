'use strict';
const {createHash}=require('node:crypto');
const hash=v=>createHash('sha256').update(v).digest('hex');
const fields=['evaluationId','requestDigest','contextDigest','schemaDigest','adapter','provider','modelDigest'];
const hex=v=>typeof v==='string'&&/^[a-f0-9]{64}$/.test(v);
function deny(){throw Object.assign(Error('Observed Judge execution unavailable'),{code:'JUDGE_EXECUTION_UNAVAILABLE'});}
function cancel(s){if(s?.aborted)throw Object.assign(Error('Judge execution cancelled'),{code:'ABORT_ERR'});}
function binding(v){if(!v||Object.keys(v).sort().join()!==[...fields].sort().join()||!fields.every(k=>k.endsWith('Digest')?hex(v[k]):typeof v[k]==='string'&&v[k].length>0&&v[k].length<=160))deny();return Object.freeze(Object.fromEntries(fields.map(k=>[k,v[k]])));}
// resolveExecution is a trusted adapter-owned attestation verifier, NOT a tags
// lookup or client metadata reader. No default implementation is provided.
function createJudgeObservedExecution({resolveExecution}){
 if(typeof resolveExecution!=='function')deny();const receipts=new WeakMap();
 async function capture(handle,expected,{signal}={}){
  const wanted=binding(expected);cancel(signal);const value=await resolveExecution(handle,{signal});cancel(signal);
  if(!value||Object.keys(value).sort().join()!=='binding,output,proofDigest')deny();
  const actual=binding(value.binding);if(JSON.stringify(actual)!==JSON.stringify(wanted)||!hex(value.proofDigest)||typeof value.output!=='string'||Buffer.byteLength(value.output)>65536)deny();
  const snapshot=Object.freeze({...actual,outputDigest:hash(value.output),proofDigest:value.proofDigest});
  const token=Object.freeze(Object.create(null));receipts.set(token,{snapshot,signal});return token;
 }
 function read(token,expected,{signal}={}){const r=receipts.get(token);if(!r)deny();cancel(signal);cancel(r.signal);const wanted=binding(expected);if(fields.some(k=>r.snapshot[k]!==wanted[k]))deny();return r.snapshot;}
 return Object.freeze({capture,read});
}
module.exports={createJudgeObservedExecution};
