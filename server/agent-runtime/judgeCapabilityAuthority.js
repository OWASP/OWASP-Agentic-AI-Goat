'use strict';
// Unmounted server composition primitive. Both callbacks and registry are trusted
// bootstrap dependencies, never request fields. No default qualification exists.
const { createHash } = require('node:crypto');
const digest = value => createHash('sha256').update(JSON.stringify(value)).digest('hex');
const hex = value => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
const text = value => typeof value === 'string' && value.length > 0 && value.length <= 160;
function unavailable() { const error = new Error('Judge capability unavailable'); error.code = 'JUDGE_CAPABILITY_UNAVAILABLE'; throw error; }
function cancelled(signal) { if (signal?.aborted) { const error = new Error('Judge admission cancelled'); error.code = 'ABORT_ERR'; throw error; } }
const fields = ['objective','rubric','evidenceContract','adapter','provider','modelDigest','contextLimit','evaluationDigest'];
function qualification(value) {
 if (!value || Object.keys(value).sort().join() !== [...fields].sort().join()) unavailable();
 if (!['objective','rubric','evidenceContract','adapter','provider'].every(k => text(value[k])) || !hex(value.modelDigest) || !hex(value.evaluationDigest) || !Number.isSafeInteger(value.contextLimit) || value.contextLimit < 1) unavailable();
 return Object.freeze(Object.fromEntries(fields.map(k => [k,value[k]])));
}
function facts(value) {
 const keys=['owner','session','generation','run','objective','rubric','evidenceContract','adapter','provider','contextTokens','evidenceDigest'];
 if (!value || Object.keys(value).sort().join() !== keys.sort().join() || !keys.filter(k=>!['generation','contextTokens','evidenceDigest'].includes(k)).every(k=>text(value[k])) || !Number.isSafeInteger(value.generation) || value.generation<0 || !Number.isSafeInteger(value.contextTokens) || value.contextTokens<1 || !hex(value.evidenceDigest)) unavailable();
 return Object.freeze(Object.fromEntries(keys.map(k=>[k,value[k]])));
}
function createJudgeCapabilityAuthority({ registry, resolveAdmission, observeModelIdentity }) {
 if (!Array.isArray(registry) || typeof resolveAdmission !== 'function' || typeof observeModelIdentity !== 'function') unavailable();
 const entries=registry.map(qualification), records=new WeakMap();
 async function current(handle,signal) {
  cancelled(signal);
  const admission=facts(await resolveAdmission(handle,{signal}));
  cancelled(signal);
  // Resolver must attest currently authorized actor/effect provenance, not merely
  // decode a client object. Identity observer must query actual provider identity.
  const identity=await observeModelIdentity(admission,{signal});
  cancelled(signal);
  if (!identity || Object.keys(identity).sort().join()!=='adapter,modelDigest,provider' || !hex(identity.modelDigest) || identity.provider!==admission.provider || identity.adapter!==admission.adapter) unavailable();
  const match=entries.find(q=>['objective','rubric','evidenceContract','adapter','provider'].every(k=>q[k]===admission[k]) && q.modelDigest===identity.modelDigest && admission.contextTokens<=q.contextLimit);
  if (!match) unavailable();
  return { admission, qualification:match, fingerprint:digest({admission,qualification:match}) };
 }
 async function admit(handle,{signal}={}) {
  const value=await current(handle,signal);
  // Recheck after asynchronous model observation so reset during observation fails.
  const latest=facts(await resolveAdmission(handle,{signal}));cancelled(signal);
  if(digest(latest)!==digest(value.admission))unavailable();
  const token=Object.freeze(Object.create(null));records.set(token,{...value,handle,signal});return token;
 }
 async function assertCurrent(token,{signal}={}) {
  const saved=records.get(token);if(!saved)unavailable();cancelled(saved.signal);
  const value=await current(saved.handle,signal);cancelled(saved.signal);
  const latest=facts(await resolveAdmission(saved.handle,{signal}));cancelled(signal);cancelled(saved.signal);
  if(value.fingerprint!==saved.fingerprint || digest(latest)!==digest(value.admission))unavailable();
  return Object.freeze({objective:value.admission.objective,run:value.admission.run,evaluationDigest:value.qualification.evaluationDigest,modelDigest:value.qualification.modelDigest});
 }
 return Object.freeze({admit,assertCurrent});
}
module.exports={createJudgeCapabilityAuthority};
