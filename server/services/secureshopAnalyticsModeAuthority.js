'use strict';
const {createLaunchScope}=require('./secureshopConversationBinding');
const WORKSHOP='secureshop_agent_security';
const invalid=()=>Object.assign(Error('Analytics canonical mode changed or is unavailable'),{code:'ANALYTICS_MODE_STALE'});
function checkedMode(value){
 if(!value||(Object.hasOwn(value,'version')&&value.version!==1)||!['vuln','fixed'].includes(value.mode)||!Number.isSafeInteger(value.generation)||value.generation<0||value.generation>2147483647||typeof value.modeStamp!=='string'||!value.modeStamp||Buffer.byteLength(value.modeStamp)>128)throw invalid();
 return Object.freeze({version:1,mode:value.mode,generation:value.generation,modeStamp:value.modeStamp});
}
// The injected repository is canonical PostgreSQL progress, never an HTTP DTO.
// Capture/check occur outside a held persona effect transaction to avoid nested
// same-owner transaction acquisition. Effects use the captured capability only.
function createAnalyticsModeAuthority({progress,launches}){
 if(typeof progress?.getEvaluationScope!=='function'||typeof launches?.assertCurrent!=='function')throw TypeError('Canonical mode authority required');
 const owned=new WeakSet();
 async function read(scope,atEffect=false){await launches.assertCurrent(scope);const reader=atEffect&&typeof progress.getEvaluationScopeAtEffect==='function'?progress.getEvaluationScopeAtEffect:progress.getEvaluationScope;const mode=checkedMode(await reader.call(progress,scope.platformOwnerId,WORKSHOP,scope));await launches.assertCurrent(scope);return mode;}
 return Object.freeze({async capture(input){const scope=createLaunchScope(input),mode=await read(scope);
  const check=async atEffect=>{const current=await read(scope,atEffect);if(JSON.stringify(current)!==JSON.stringify(mode))throw invalid();return true;};
  const token=Object.freeze({mode,assertCurrent:()=>check(false),assertCurrentAtEffect:()=>check(true)});owned.add(token);return token;
 },assertToken(token){if(!owned.has(token))throw invalid();return token;}});
}
module.exports={createAnalyticsModeAuthority,checkedMode};
