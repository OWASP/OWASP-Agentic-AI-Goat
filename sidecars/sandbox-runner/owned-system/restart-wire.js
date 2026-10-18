'use strict';
const {createHash}=require('node:crypto'),{normalizeRestartRequest,restartRequestDigest}=require('./restart-contract');
// Transport health/inspection remain v2; completed executions can carry v3 proof.
const VERSION='secureshop-owned-system-restart-http.v2',WITNESS_VERSION='secureshop-owned-system-restart-http.v3',LEGACY_VERSION='secureshop-owned-system-restart-http.v1',ISOLATION='owned-restart-namespace-v1';
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const SHA=/^[a-f0-9]{64}$/,HOST=/^restart-[a-f0-9]{32}$/;
const hash=v=>createHash('sha256').update(v).digest('hex');
const exact=(v,k)=>v&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).sort().join(',')===[...k].sort().join(',');
function normalizeRestartWire(raw){if(!exact(raw,['targetId','request'])||typeof raw.targetId!=='string'||!UUID.test(raw.targetId))throw new TypeError('Closed restart wire required');return Object.freeze({targetId:raw.targetId,request:normalizeRestartRequest(raw.request)});}
function restartWitness(raw,hostname){
 const wire=normalizeRestartWire(raw);if(typeof hostname!=='string'||!HOST.test(hostname))throw new TypeError('Private restart hostname required');
 return Object.freeze({version:1,hostname,hostnameSha256:hash(hostname),bindingSha256:hash(JSON.stringify({version:1,targetId:wire.targetId,operationId:wire.request.operationId,requestSha256:restartRequestDigest(wire.request),hostname}))});
}
function validateRestartReceipt(raw,value){
 const wire=normalizeRestartWire(raw),v3=value?.version===WITNESS_VERSION,v2=value?.version===VERSION,withText=v3||v2;
 const keys=['version','targetId','operationId','requestSha256','beforeInstanceId','afterInstanceId','beforeGeneration','afterGeneration','effectSha256','outputSha256','outputBytes',...(withText?['outputText']:[]),'ownedCommandEffectSha256','ownedCommandEffectFiles','ownedCommandEffectBytes','command','status','isolation',
 ...(v3?['witness','stdoutText','stderrText','stdoutSha256','stderrSha256','stdoutBytes','stderrBytes','drained','exitCode']:[])];
 if(!exact(value,keys)||(!withText&&value.version!==LEGACY_VERSION)||value.targetId!==wire.targetId||value.operationId!==wire.request.operationId
  ||value.requestSha256!==restartRequestDigest(wire.request)||value.isolation!==ISOLATION||value.status!=='completed'||value.command!==('systemctl restart '+wire.request.name)
  ||![value.beforeInstanceId,value.afterInstanceId].every(x=>typeof x==='string'&&UUID.test(x))||value.beforeInstanceId===value.afterInstanceId
  ||!Number.isSafeInteger(value.beforeGeneration)||value.beforeGeneration<1||value.afterGeneration!==value.beforeGeneration+1
  ||![value.effectSha256,value.outputSha256].every(x=>typeof x==='string'&&SHA.test(x))
  ||!Number.isSafeInteger(value.outputBytes)||value.outputBytes<0||value.outputBytes>(withText?16384:65536)
  ||typeof value.ownedCommandEffectSha256!=='string'||!SHA.test(value.ownedCommandEffectSha256)
  ||!Number.isSafeInteger(value.ownedCommandEffectFiles)||value.ownedCommandEffectFiles<1||value.ownedCommandEffectFiles>16
  ||!Number.isSafeInteger(value.ownedCommandEffectBytes)||value.ownedCommandEffectBytes<1||value.ownedCommandEffectBytes>65536)throw new TypeError('Restart receipt mismatch');
 if(withText&&(typeof value.outputText!=='string'||!value.outputText.isWellFormed()||Buffer.byteLength(value.outputText)!==value.outputBytes||hash(value.outputText)!==value.outputSha256))throw new TypeError('Restart output mismatch');
 if(v3){
  const w=value.witness,expected=restartWitness(wire,w?.hostname);
  if(!exact(w,Object.keys(expected))||Object.keys(expected).some(k=>w[k]!==expected[k])||value.drained!==true||value.exitCode!==0)throw new TypeError('Restart witness mismatch');
  for(const prefix of ['stdout','stderr']){
   const text=value[prefix+'Text'];if(typeof text!=='string'||!text.isWellFormed()||Buffer.byteLength(text)!==value[prefix+'Bytes']||hash(text)!==value[prefix+'Sha256'])throw new TypeError('Restart stream mismatch');
  }
  if(value.outputText!==value.stdoutText+value.stderrText||value.outputBytes!==value.stdoutBytes+value.stderrBytes)throw new TypeError('Restart combined output mismatch');
 }
 return Object.freeze({...value,...(v3?{witness:Object.freeze({...value.witness})}:{})});
}
function bindRestartReceipt(raw,result){const wire=normalizeRestartWire(raw);return validateRestartReceipt(wire,{...result,version:result?.version===3?WITNESS_VERSION:VERSION,targetId:wire.targetId});}
function bindingDigest(raw){const wire=normalizeRestartWire(raw);return hash(JSON.stringify({version:VERSION,targetId:wire.targetId,requestSha256:restartRequestDigest(wire.request)}));}
module.exports={VERSION,WITNESS_VERSION,LEGACY_VERSION,ISOLATION,normalizeRestartWire,validateRestartReceipt,bindRestartReceipt,bindingDigest,restartWitness};
