'use strict';
// Unmounted sparse-output candidate; never a production grader or credit authority.
const base=require('./ragWholeEvidenceDefenseContractV4');
const {sha}=require('./pricingEvidenceCatalogue');
const VERSION='rag-whole-evidence-defense-prototype-v5';
const SPARSE_POLICY=`Cardinality clarification: ID ranges are ceilings, never lists to fill. Discover the actual distinct actions first, then assign a0 through a(n-1); do likewise for quotes and conditions. Include every distinct multiple, nested, conditional or alternative action needed for complete coverage, including possible actions with uncertain classification. Never invent or repeat actions, conditions, relations or quotes to fill capacity. actions, conditions and relations may be empty when no corresponding item exists. Quotes must include the trusted task citation and every required evidence citation, but no padding. Reuse the SAME quote ID whenever the same field and exact span supports multiple assertions or relations. Use the shortest sufficient uniquely locating exact quote; do not shorten away necessary meaning or scope. Equal words at different locations remain ambiguous under the exact-quote rule. A condition is not a hiding place for a possible affirmative action. If complete representation exceeds a ceiling, report overflow/unsupported rather than dropping actions. Sparse output does not certify coverage: assess ALL full evidence. The output guide below describes types and permitted values, not example rows or required array lengths. Required nullable fields must be present with null when unused.`;
// Generated from the transmitted schema; no independent hand-maintained field list.
function schemaGuide(schema){
 function describe(s){
  if(s.$ref)return {$ref:s.$ref};
  const out={};
  for(const key of ['type','enum','const','pattern','minLength','maxLength','minimum','maximum','minItems','maxItems','additionalProperties','required'])if(Object.hasOwn(s,key))out[key]=s[key];
  for(const key of ['anyOf','oneOf','allOf'])if(s[key])out[key]=s[key].map(describe);
  if(s.properties)out.properties=Object.fromEntries(Object.entries(s.properties).map(([k,v])=>[k,describe(v)]));
  if(s.items)out.items=describe(s.items);
  return out;
 }
 return {root:describe(schema),definitions:Object.fromEntries(Object.entries(schema.definitions).filter(([k])=>k!=='assessment').map(([k,v])=>[k,describe(v)]))};
}
function createRagWholeEvidenceDefenseContractV5(input){
 const original=base.createRagWholeEvidenceDefenseContractV4(input);
 const messages=Object.freeze(original.request.messages.map((m,i)=>Object.freeze(i===0?{...m,content:m.content+'\n'+SPARSE_POLICY+'\nOutput guide: '+JSON.stringify(schemaGuide(original.request.schema))}:m)));
 const request=Object.freeze({messages,schema:original.request.schema}),requestSha256=sha(JSON.stringify(request));
 function validate(value){
  const result=original.validate(value),seen=new Set();
  for(const c of result.citations){const key=JSON.stringify([c.field,c.start,c.end]);if(seen.has(key))throw Error('Duplicate exact quote span; reuse its quote ID');seen.add(key);}
  return Object.freeze({...result,version:VERSION,requestSha256});
 }
 return Object.freeze({version:VERSION,request,requestSha256,validate});
}
module.exports={VERSION,POLICY:base.POLICY,SPARSE_POLICY,LIMITS:base.LIMITS,schemaGuide,createRagWholeEvidenceDefenseContractV5};
