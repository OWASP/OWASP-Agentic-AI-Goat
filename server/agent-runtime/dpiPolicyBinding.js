'use strict';
// Serializable admission joins; authenticated execution ownership is established
// by the graph's private proof capture, never by this envelope alone.
const { z } = require('zod');
const { isDeepStrictEqual } = require('node:util');
const VERSION = 'dpi-policy-binding-v2';
const LEGACY_VERSION='dpi-policy-binding-v1';
const { createHash } = require('node:crypto');
const digest=value=>createHash('sha256').update(JSON.stringify(value)).digest('hex');
const hex=z.string().regex(/^[a-f0-9]{64}$/);
const schema = z.object({version:z.literal(VERSION),objective:z.string().min(1).max(100),mode:z.enum(['vuln','fixed']),policy:z.record(z.string(),z.string()),extension:z.union([z.object({messagesSha256:hex}).strict(),z.object({decisionMessagesSha256:hex}).strict()]),legacyEvidenceSha256:hex}).strict();
function createPolicyBinding(proof) {
 const decoder=proof?.version==='dpi-owned-decoder-v3';
 const module=require(decoder?'./dpiDecoderEvidence':'./dpiActorProof');
 const legacy=module[decoder?'projectLegacyDecoderEvidence':'projectLegacyActorEvidence'](proof);
 return schema.parse({version:VERSION,objective:proof.policy.objectiveId,mode:proof.mode,policy:proof.policy,extension:decoder?{decisionMessagesSha256:proof.decisionMessagesSha256}:{messagesSha256:proof.messagesSha256},legacyEvidenceSha256:digest(legacy)});
}
function stripPolicyBinding(packet){const {dpiPolicyBinding,...rubric}=packet.rubric;return {...packet,rubric,evidence:packet.evidence.filter(row=>row.id!=='owned_policy')};}
function validatePolicyBindingBudget(packet,maxBytes=24000){
 if(packet.rubric.dpiPolicyBinding!==VERSION)throw Error('Compact policy binding required');
 admitPolicyBinding(packet);
 const full=JSON.stringify(packet),legacy=JSON.stringify(stripPolicyBinding(packet));
 const bytes=Buffer.byteLength(full),legacyBytes=Buffer.byteLength(legacy);
 if(legacyBytes>maxBytes||bytes-legacyBytes>1024||bytes>maxBytes+1024)throw Error('DPI policy binding evidence size exceeded');
 return full;
}
function admitPolicyBinding({rubric,evidence,facts={}}) {
  const records=evidence.filter(row=>row.id==='owned_policy');
  const legacy=evidence.filter(row=>row.id==='owned_actor'||row.id==='owned_decoder');
  if(legacy.some(row=>['dpi-owned-actor-v3','dpi-owned-decoder-v3'].includes(row.content?.version)))throw Error('DPI policy proof requires separate binding');
  if(rubric.dpiPolicyBinding===undefined){if(records.length)throw Error('Orphan DPI policy binding');return null;}
  if(![VERSION,LEGACY_VERSION].includes(rubric.dpiPolicyBinding)||rubric.family!=='DPI'||rubric.scenario!=='aws_assistant'||records.length!==1||records[0].source!=='server_observation')throw Error('Invalid DPI policy binding authority');
  const historical=rubric.dpiPolicyBinding===LEGACY_VERSION;
  const envelope=historical?z.object({version:z.literal(LEGACY_VERSION),objective:z.string().min(1).max(100),mode:z.enum(['vuln','fixed']),proof:z.unknown()}).strict().parse(records[0].content):schema.parse(records[0].content);
  const decoder=rubric.objectiveId==='obfuscation',id=decoder?'owned_decoder':'owned_actor';
  if(legacy.length!==1||legacy[0].id!==id||legacy[0].source!=='server_observation')throw Error('DPI policy binding legacy evidence mismatch');
  if(!historical&&(digest(legacy[0].content)!==envelope.legacyEvidenceSha256||Object.keys(envelope.extension).join(',')!==(decoder?'decisionMessagesSha256':'messagesSha256')))throw Error('DPI policy extension or legacy digest mismatch');
  const proof=historical?envelope.proof:{...legacy[0].content,version:decoder?'dpi-owned-decoder-v3':'dpi-owned-actor-v3',...(!decoder?{objective:envelope.objective}:{}),policy:envelope.policy,...envelope.extension};
  if(envelope.objective!==rubric.objectiveId||envelope.mode!==rubric.mode||proof?.mode!==rubric.mode)throw Error('DPI policy binding identity mismatch');
  require('./dpiPolicyContract').validatePolicy(proof?.policy,rubric.objectiveId,rubric.mode);
  if(proof?.version!==(decoder?'dpi-owned-decoder-v3':'dpi-owned-actor-v3'))throw Error('DPI policy binding proof version mismatch');
  if(!decoder&&proof.objective!==rubric.objectiveId)throw Error('DPI policy binding objective mismatch');
  const unique=(id,source)=>{const rows=evidence.filter(row=>row.id===id);if(rows.length!==1||rows[0].source!==source)throw Error('DPI policy binding evidence mismatch');return rows[0].content;};
  const request=unique('request','student_input'),response=unique('response','assistant_response');
  if(typeof request!=='string'||typeof response!=='string')throw Error('DPI policy binding text required');
  if(legacy.length!==1||legacy[0].id!==id||legacy[0].source!=='server_observation')throw Error('DPI policy binding legacy evidence mismatch');
  const module=require(decoder?'./dpiDecoderEvidence':'./dpiActorProof');
  const observed=module[decoder?'validateDecoderEvidence':'validateActorEvidence'](proof,request,response,rubric.mode);
  const projected=module[decoder?'projectLegacyDecoderEvidence':'projectLegacyActorEvidence'](proof);
  if(!isDeepStrictEqual(projected,legacy[0].content))throw Error('DPI policy binding projection mismatch');
  const fact=decoder?'owned_decoder_observed':'owned_actor_observed';
  if(Object.hasOwn(facts,fact)&&facts[fact]!==observed)throw Error('DPI policy binding fact mismatch');
  return {...envelope,proof};
}
module.exports={VERSION,LEGACY_VERSION,createPolicyBinding,admitPolicyBinding,stripPolicyBinding,validatePolicyBindingBudget};
