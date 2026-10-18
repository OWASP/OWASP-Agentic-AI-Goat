'use strict';
const issued=new WeakSet();
function issueFinflowOwnerDeletionReceipt(value){
  const receipt=Object.freeze({...value});issued.add(receipt);return receipt;
}
function verifyFinflowOwnerDeletionReceipt(value,expected){
  return issued.has(value)&&value?.completed===true&&value.ownerId===expected.ownerId
    &&value.jobId===expected.jobId&&Number.isSafeInteger(value.artifactCount)
    &&value.artifactCount>=0&&value.artifactCount<=1000000;
}
module.exports={issueFinflowOwnerDeletionReceipt,verifyFinflowOwnerDeletionReceipt};
