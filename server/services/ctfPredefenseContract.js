'use strict';
// Trusted-server input transport. Never accepts a learner nominated disposition.
const {createHash}=require('node:crypto');
const {canonicalCtfJson}=require('./ctfLifecycleCommands');
const {hashPayload}=require('./promptInjectionCTF');
const id={type:'string',bytes:10,pattern:'^[1-9][0-9]*$',minimum:1,maximum:2147483647};
const gen={type:'string',bytes:19,pattern:'^(0|[1-9][0-9]*)$',minimum:0,maximum:'9223372036854775807'};
const digest={type:'string',bytes:64,pattern:'^[a-f0-9]{64}$'};
const inputSchema={type:'object',properties:{version:{type:'number',enum:[1]},binding:{type:'object',properties:{ownerId:id,sessionId:id,runId:{type:'string',bytes:36,pattern:'^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$'},ownerGeneration:gen,globalRevision:gen,stageRevision:gen,ownerRevision:gen,participantId:id,progressId:id,stageId:id,stageDigest:digest}},payload:{type:'string',bytes:16384},normalizedPayload:{type:'string',bytes:16384,pattern:'^[a-z0-9_ ]*$'},payloadHash:digest,techniqueTag:{type:'string',bytes:128},techniqueConfidence:{type:'number',minimum:0,maximum:1}}};
const outcomeSchema={type:'object',properties:{version:{type:'number',enum:[1]},inputHash:digest,inputDecision:{type:'string',enum:['allow','block','skipped']},reason:{type:'string',bytes:4096},languageStatus:{type:'string',bytes:128,nullable:true},providerReceipt:{type:'string',bytes:16384,nullable:true}}};
const sha=s=>createHash('sha256').update(s,'utf8').digest('hex');
function matches(v,s){
 if(v===null)return s.nullable===true;
 if(s.type==='object')return v&&[Object.prototype,null].includes(Object.getPrototypeOf(v))&&Reflect.ownKeys(v).length===Object.keys(s.properties).length&&Object.entries(s.properties).every(([k,child])=>{const d=Object.getOwnPropertyDescriptor(v,k);return d&&d.enumerable&&Object.hasOwn(d,'value')&&matches(d.value,child);});
 if(typeof v!==s.type||s.enum&&!s.enum.includes(v))return false;
 if(s.type==='string'&&(!v.isWellFormed()||v.includes('\0')||Buffer.byteLength(v)>(s.bytes||Infinity)||s.pattern&&!new RegExp(s.pattern).test(v)))return false;
 if(s.type==='number'&&(!Number.isFinite(v)||s.integer&&!Number.isSafeInteger(v)))return false;
 if(s.minimum!==undefined){if(s.type==='string')return BigInt(v)>=BigInt(s.minimum)&&BigInt(v)<=BigInt(s.maximum);return v>=s.minimum&&v<=s.maximum;}
 return true;
}
function encode(value,schema,max){if(!matches(value,schema))throw TypeError('Invalid CTF pre-defense document');const raw=canonicalCtfJson(value);if(Buffer.byteLength(raw)>max)throw TypeError('CTF pre-defense document too large');return{document:JSON.parse(raw),canonicalDocument:raw,documentHash:sha(raw)};}
function inputDocument(value,stageSnapshot){
 const out=encode(value,inputSchema,32768),actual=hashPayload(value.payload);
 if(actual.hash!==value.payloadHash||actual.normalized!==value.normalizedPayload||typeof stageSnapshot!=='string'||Buffer.byteLength(stageSnapshot)>65536||sha(stageSnapshot)!==value.binding.stageDigest)throw TypeError('CTF pre-defense input binding mismatch');
 const pairs=JSON.parse(stageSnapshot);if(!Array.isArray(pairs)||pairs.some((p,n)=>!Array.isArray(p)||p.length!==2||typeof p[0]!=='string'||n>0&&pairs[n-1][0]>=p[0]))throw TypeError('CTF stage snapshot invalid');
 return{...out,stageSnapshot};
}
function outcomeDocument(value){return encode(value,outcomeSchema,24576);}
module.exports={inputSchema,outcomeSchema,inputDocument,outcomeDocument,matches};
