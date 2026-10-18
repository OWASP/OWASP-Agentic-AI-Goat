'use strict';
const {createHash}=require('node:crypto');
const {canonicalCtfJson}=require('./ctfLifecycleCommands');
const {parseStrictJson}=require('../agent-runtime/referenceComparisonVerifier');
const {matches}=require('./ctfPredefenseContract');
const schema={type:'object',properties:{version:{type:'number',enum:[1]},responseTimeMs:{type:'number',integer:true,minimum:0,maximum:300000,nullable:true},timingScope:{type:'string',enum:['guardian_generation','guardian_failure_elapsed']},guardianUnavailable:{type:'boolean'},reviewerObserved:{type:'boolean'},visibleResponseSha256:{type:'string',bytes:64,pattern:'^[a-f0-9]{64}$'}}};
const sha=value=>createHash('sha256').update(value,'utf8').digest('hex');
function encodeResponseDiagnostics(value,evidence){
 if(!matches(value,schema)||value.guardianUnavailable!==(value.timingScope==='guardian_failure_elapsed'))throw TypeError('Invalid CTF response diagnostics');
 if(!evidence||typeof evidence.visibleResponse!=='string'||!evidence.visibleResponse.isWellFormed()||value.visibleResponseSha256!==sha(evidence.visibleResponse))throw TypeError('CTF diagnostic output mismatch');
 if(!value.guardianUnavailable&&evidence.guardian==null)throw TypeError('CTF diagnostic guardian missing');
 if(value.guardianUnavailable&&(evidence.judgment?.verdict!=='unavailable'||evidence.observedSecret!==false||evidence.guardian!==null))throw TypeError('CTF diagnostic unavailable mismatch');
 const canonicalDiagnostics=canonicalCtfJson(value);
 return Object.freeze({canonicalDiagnostics,diagnosticsHash:sha(canonicalDiagnostics)});
}
function validateResponseDiagnostics(raw,digest,evidence){
 if(typeof raw!=='string'||Buffer.byteLength(raw)>2048||!raw.isWellFormed()||sha(raw)!==digest)throw TypeError('CTF diagnostic bytes invalid');
 const encoded=encodeResponseDiagnostics(parseStrictJson(raw),evidence);
 if(encoded.canonicalDiagnostics!==raw)throw TypeError('CTF diagnostic canonical bytes invalid');
 return Object.freeze(JSON.parse(raw));
}
module.exports={encodeResponseDiagnostics,validateResponseDiagnostics};
