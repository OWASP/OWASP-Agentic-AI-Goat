'use strict';

const {createHash}=require('node:crypto');
const issued=new WeakMap();
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const SHA256=/^[a-f0-9]{64}$/;
const sha=value=>createHash('sha256').update(String(value)).digest('hex');

function issueFinflowLogMutationReceipt({execution,metadata,result}){
  if(!execution||typeof execution!=='object'||!metadata||typeof result!=='string'
      ||!UUID.test(execution.runId||'')||metadata.runId!==execution.runId.toLowerCase()
      ||Number(metadata.ownerId)!==Number(execution.ownerId)
      ||Number(metadata.generation)!==Number(execution.durableGeneration)
      ||!UUID.test(metadata.operationId||'')||!['access','error','audit','llm_requests'].includes(metadata.logType)
      ||!['delete','modify'].includes(metadata.action)||!SHA256.test(metadata.contentSha256||'')
      ||!Number.isSafeInteger(metadata.byteLength)||metadata.byteLength<0
      ||!Number.isSafeInteger(metadata.revision)||metadata.revision<1)return null;
  const receipt=Object.freeze({type:'finflow_log_mutation',version:1,ownerId:String(metadata.ownerId),
    generation:String(metadata.generation),runId:metadata.runId,operationId:metadata.operationId,
    logType:metadata.logType,action:metadata.action,contentSha256:metadata.contentSha256,
    byteLength:metadata.byteLength,revision:metadata.revision,returnedSha256:sha(result),
    returnedByteLength:Buffer.byteLength(result)});
  issued.set(receipt,{execution,metadata,result});return receipt;
}

function verifyFinflowLogMutationReceipt({receipt,execution,toolCall}){
  const scope=receipt&&issued.get(receipt),metadata=toolCall?.resourceMetadata;
  if(!scope||scope.execution!==execution||scope.metadata!==metadata||scope.result!==toolCall?.result
      ||toolCall?.name!=='admin_modify_logs'||toolCall.success!==true
      ||receipt.type!=='finflow_log_mutation'||receipt.version!==1
      ||receipt.ownerId!==String(execution?.ownerId)||receipt.generation!==String(execution?.durableGeneration)
      ||receipt.runId!==execution?.runId||receipt.operationId!==metadata?.operationId
      ||receipt.logType!==metadata?.logType||receipt.action!==metadata?.action
      ||receipt.contentSha256!==metadata?.contentSha256||receipt.byteLength!==metadata?.byteLength
      ||receipt.revision!==metadata?.revision||receipt.returnedSha256!==sha(toolCall.result)
      ||receipt.returnedByteLength!==Buffer.byteLength(toolCall.result))return null;
  const params=toolCall.params||{},logType=String(params.log_type||'audit').toLowerCase();
  const action=String(params.action||'delete').toLowerCase();
  if(logType!==receipt.logType||action!==receipt.action)return null;
  return receipt;
}

module.exports={issueFinflowLogMutationReceipt,verifyFinflowLogMutationReceipt};
