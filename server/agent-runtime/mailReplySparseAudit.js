'use strict';
const {isDeepStrictEqual}=require('node:util');
const {normalizeSourceOnlyMailAudit}=require('./mailReplySourceAudit');
const {createSparseWire,VERSION}=require('./mailReplySparseComparison');
const {VERSION:PREVIOUS}=require('./mailReplySourceComparison');
function keyedStage(stage){
 const local=s=>({quote:s.quote,occurrence:s.occurrence});
 return {passages:Object.fromEntries(stage.passages.map(p=>[p.sourceQuoteId,{coverage:p.coverage,operations:p.operations.map(({addressee,...op})=>({...op,action:local(op.action),object:local(op.object),recipient:op.recipient?{personaId:op.recipient.personaId,mention:local(op.recipient.mention),anchor:{sourceQuoteId:op.recipient.anchor.sourceQuoteId,...local(op.recipient.anchor)}}:null}))}]))};
}
function normalizeSparseMailAudit(input,result){
 if(input?.version!==VERSION||(input.observation&&input.observation.version!==VERSION)||Buffer.byteLength(JSON.stringify(input))>200000)throw Error('Invalid sparse mail audit version or bound');
 let legacyObservation;
 if(input.observation){const {sparseWire,...rest}=input.observation;if(!sparseWire||Object.keys(sparseWire).sort().join(',')!=='extraction,verification')throw Error('Exact raw sparse stage coverage required');legacyObservation={...rest,version:PREVIOUS};}
 const normalized=normalizeSourceOnlyMailAudit({...input,version:PREVIOUS,...(legacyObservation?{observation:legacyObservation}:{})},result);
 if(!normalized.observation)return {...normalized,version:VERSION};
 const o=normalized.observation,packet={originalThreadPassages:o.sourceScope,ownedRecipients:o.personas},raw={};
 for(const [name,id] of [['extraction','extract'],['verification','verify']]){
  const decoded=createSparseWire(packet,id).decode(input.observation.sparseWire[name]);
  if(!isDeepStrictEqual(decoded.keyed,keyedStage(o[name])))throw Error('Sparse raw coverage disagrees with canonical grounding');raw[name]=decoded.raw;
 }
 return {...normalized,version:VERSION,observation:{...o,version:VERSION,sparseWire:raw}};
}
module.exports={normalizeSparseMailAudit};
