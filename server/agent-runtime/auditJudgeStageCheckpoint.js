'use strict';
const {createHash}=require('node:crypto');
const VERSION='audit-stage-checkpoint-v1';
const COMPARISON='source-only-obligation-verified-v6';
const sha=value=>createHash('sha256').update(value).digest('hex');
const hex=value=>typeof value==='string'&&/^[a-f0-9]{64}$/.test(value);
const invalid=()=>Object.assign(new Error('Audit Judge checkpoint is invalid'),{code:'AUDIT_CHECKPOINT_INVALID'});

function checkpoint(input){
  if(!input||typeof input!=='object'||Array.isArray(input))throw invalid();
  const {stage,runId,evidenceDigest,packetSha256,judgeVersion,comparisonVersion,
    policyDigest,canonicalInputSha256,actualRequestSha256,sourceCheckpointSha256,
    provider,model,rawResponse}=input;
  if(!['source','effect'].includes(stage)||!/^[-0-9a-f]{36}$/i.test(runId||'')
    ||![evidenceDigest,packetSha256,policyDigest,canonicalInputSha256,actualRequestSha256].every(hex)
    ||typeof judgeVersion!=='string'||!judgeVersion||judgeVersion.length>100
    ||comparisonVersion!==COMPARISON||typeof provider!=='string'||!provider||provider.length>100
    ||typeof model!=='string'||!model||model.length>200
    ||typeof rawResponse!=='string'||!rawResponse||Buffer.byteLength(rawResponse)>16384
    ||(stage==='source'?sourceCheckpointSha256!==null:!hex(sourceCheckpointSha256)))throw invalid();
  const value={version:VERSION,stage,runId:runId.toLowerCase(),evidenceDigest,packetSha256,
    judgeVersion,comparisonVersion,policyDigest,canonicalInputSha256,actualRequestSha256,
    sourceCheckpointSha256,provider,model,rawResponse,responseSha256:sha(rawResponse)};
  return Object.freeze({...value,checkpointSha256:sha(JSON.stringify(value))});
}
function verifyCheckpoint(value,expected){
  const made=checkpoint(value);
  if(value.version!==VERSION||value.responseSha256!==made.responseSha256
    ||value.checkpointSha256!==made.checkpointSha256
    ||Object.entries(expected||{}).some(([key,expectedValue])=>made[key]!==expectedValue))throw invalid();
  return made;
}
module.exports={VERSION,COMPARISON,sha,checkpoint,verifyCheckpoint};
