'use strict';
// Unmounted protocol compatibility variant. Original v3 prompts, reducer and validation remain authoritative.
const base=require('./ragWholeEvidenceDefenseContract');
const {sha}=require('./pricingEvidenceCatalogue');
const VERSION='rag-whole-evidence-defense-prototype-v4';
function createRagWholeEvidenceDefenseContractV4(input){
 const original=base.createRagWholeEvidenceDefenseContract(input);
 // Inline only the root object; keep shared definitions and their local reference identities unchanged.
 const schema=Object.freeze({...original.request.schema.definitions.assessment,definitions:original.request.schema.definitions,$schema:original.request.schema.$schema});
 const request=Object.freeze({messages:original.request.messages,schema});
 const requestSha256=sha(JSON.stringify(request));
 function validate(value){
  const result=original.validate(value);
  return Object.freeze({...result,version:VERSION,requestSha256});
 }
 return Object.freeze({version:VERSION,request,requestSha256,validate});
}
module.exports={VERSION,POLICY:base.POLICY,LIMITS:base.LIMITS,createRagWholeEvidenceDefenseContractV4};
