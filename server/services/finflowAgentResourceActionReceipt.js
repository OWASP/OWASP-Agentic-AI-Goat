'use strict';

const { createHash } = require('node:crypto');
const issued = new WeakMap();
const sha256 = value => createHash('sha256').update(String(value)).digest('hex');
const canonicalParams = params => JSON.stringify(Object.keys(params || {}).sort()
  .reduce((out,key)=>{out[key]=params[key];return out;},{}));

function issueFinflowAgentResourceActionReceipt({ execution, toolName, params, result,
  resourceAuthorityReceipt }) {
  if (!execution || !resourceAuthorityReceipt
      || !['admin_delete_database','admin_create_backup','admin_download_backup'].includes(toolName)
      || typeof result !== 'string') return null;
  const receipt=Object.freeze({type:'finflow_agent_resource_action',version:1,toolName,
    ownerId:String(execution.ownerId),generation:String(execution.durableGeneration),runId:execution.runId,
    paramsSha256:sha256(canonicalParams(params)),returnedSha256:sha256(result),returnedByteLength:Buffer.byteLength(result)});
  issued.set(receipt,{execution,resourceAuthorityReceipt});return receipt;
}

function verifyFinflowAgentResourceActionReceipt({receipt,execution,toolCall,resourceAuthorityReceipt}) {
  const binding=receipt&&issued.get(receipt);
  if(!binding||binding.execution!==execution||binding.resourceAuthorityReceipt!==resourceAuthorityReceipt
      ||receipt.type!=='finflow_agent_resource_action'||receipt.version!==1||!toolCall
      ||receipt.toolName!==toolCall.name||toolCall.success!==true||typeof toolCall.result!=='string'
      ||receipt.ownerId!==String(execution?.ownerId)||receipt.generation!==String(execution?.durableGeneration)
      ||receipt.runId!==execution?.runId||receipt.paramsSha256!==sha256(canonicalParams(toolCall.params))
      ||receipt.returnedByteLength!==Buffer.byteLength(toolCall.result)
      ||receipt.returnedSha256!==sha256(toolCall.result))return null;
  return receipt;
}

module.exports={issueFinflowAgentResourceActionReceipt,verifyFinflowAgentResourceActionReceipt};
