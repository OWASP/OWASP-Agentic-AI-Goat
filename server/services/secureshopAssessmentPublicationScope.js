'use strict';
const {isDeepStrictEqual}=require('node:util');
const WORKSHOP='secureshop_agent_security';
const unavailable=()=>Object.assign(Error('Current assessment scope unavailable'),{code:'ASSESSMENT_SCOPE_UNAVAILABLE'});
async function captureAssessmentPublicationScope(progress,userId,signal,launchScope){
 if(typeof progress?.getEvaluationScope!=='function'||!Number.isSafeInteger(userId)||userId<1)throw unavailable();
 async function read(atEffect=false){
  const reader=atEffect?progress.getEvaluationScopeAtEffect:progress.getEvaluationScope;
  if(typeof reader!=='function')throw unavailable();
  signal?.throwIfAborted();const row=await reader.call(progress,userId,WORKSHOP,launchScope);signal?.throwIfAborted();
  if(!row||Object.keys(row).sort().join(',')!=='generation,mode,modeStamp'||!Number.isSafeInteger(row.generation)||row.generation<0||!['vuln','fixed'].includes(row.mode)||typeof row.modeStamp!=='string'||!row.modeStamp.length||Buffer.byteLength(row.modeStamp)>256||!row.modeStamp.isWellFormed()||row.modeStamp.includes('\0'))throw unavailable();
  return Object.freeze({generation:row.generation,mode:row.mode,modeStamp:row.modeStamp});
 }
 const binding=await read();
 return Object.freeze({binding,
  async assertCurrent(){if(!isDeepStrictEqual(binding,await read()))throw unavailable();},
  async assertCurrentAtEffect(){if(!isDeepStrictEqual(binding,await read(true)))throw unavailable();}});
}
module.exports={captureAssessmentPublicationScope};
