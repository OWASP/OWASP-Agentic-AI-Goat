'use strict';

const {issueFinflowOwnerDeletionReceipt}=require('./finflowOwnerDeletionReceipt');
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const MAX=1000000;
const fail=(code,message)=>{const error=new Error(message);error.code=code;throw error;};
function scope(value){
  if(!value||!Number.isSafeInteger(value.subjectId)||value.subjectId<1||value.subjectId>2147483647
    ||!UUID.test(value.jobId||'')||!UUID.test(value.leaseToken||'')||typeof value.check!=='function'){
    throw new TypeError('Exact FinFlow deletion job scope required');
  }
  return Object.freeze({ownerId:value.subjectId,jobId:value.jobId.toLowerCase(),check:value.check,signal:value.signal});
}
function pending(row,bound){
  if(!row||row.ownerId!==bound.ownerId||row.jobId!==bound.jobId||!['pending','completed'].includes(row.status)
    ||!Array.isArray(row.fileTokens)||new Set(row.fileTokens).size!==row.fileTokens.length
    ||row.fileTokens.length>MAX||row.fileTokens.some(value=>!UUID.test(value||''))
    ||row.artifactCount!==row.fileTokens.length||!Number.isSafeInteger(row.datasetCount)
    ||row.datasetCount<0||row.datasetCount>MAX) {
    fail('FINFLOW_OWNER_CLEANUP_INVALID','FinFlow owner cleanup reservation is invalid');
  }
  return Object.freeze({...row,fileTokens:Object.freeze(row.fileTokens.map(value=>value.toLowerCase()).sort())});
}
function complete(row,bound,fileTokens){
  const completedAt=row?.completedAt instanceof Date?row.completedAt.toISOString():row?.completedAt;
  if(!row||row.ownerId!==bound.ownerId||row.jobId!==bound.jobId||row.status!=='completed'
    ||row.artifactCount!==fileTokens.length||!Array.isArray(row.fileTokens)
    ||JSON.stringify(row.fileTokens.map(value=>value.toLowerCase()).sort())!==JSON.stringify(fileTokens)
    ||!Number.isSafeInteger(row.datasetCount)||row.datasetCount<0||row.datasetCount>MAX
    ||typeof completedAt!=='string'||!Number.isFinite(Date.parse(completedAt)))fail('FINFLOW_OWNER_CLEANUP_INVALID','FinFlow owner cleanup receipt is invalid');
  return issueFinflowOwnerDeletionReceipt({completed:true,ownerId:bound.ownerId,jobId:bound.jobId,
    artifactCount:fileTokens.length,datasetCount:row.datasetCount,completedAt});
}
function createFinflowOwnerResourceDeletion({repository,files}={}){
  if(!repository||typeof repository.beginOwnerDeletion!=='function'||typeof repository.completeOwnerDeletion!=='function'
    ||!files||typeof files.remove!=='function'||typeof files.absent!=='function'){
    throw new TypeError('Complete FinFlow owner cleanup dependencies required');
  }
  return async function cleanupFinflowBackups(value){
    const bound=scope(value);bound.signal?.throwIfAborted();await bound.check();
    const reservation=pending(await repository.beginOwnerDeletion(bound),bound);
    bound.signal?.throwIfAborted();await bound.check();
    await files.remove(reservation.fileTokens);
    for(const token of reservation.fileTokens){
      bound.signal?.throwIfAborted();await bound.check();
      if(!await files.absent(token))fail('FINFLOW_OWNER_CLEANUP_INCOMPLETE','FinFlow backup bytes remain');
    }
    bound.signal?.throwIfAborted();await bound.check();
    return complete(await repository.completeOwnerDeletion({...bound,fileTokens:reservation.fileTokens}),bound,reservation.fileTokens);
  };
}
module.exports={createFinflowOwnerResourceDeletion,_internals:{scope,pending,complete}};
