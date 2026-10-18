'use strict';

const crypto = require('node:crypto');
const issued = new WeakMap();
const sha256 = value => crypto.createHash('sha256').update(value).digest('hex');
const canonicalResult = value => Buffer.from(JSON.stringify(value));

// Public metadata checksums diagnose persistence and transport. Authority comes
// only from this module-private object identity bound to the live execution.
function issueFinflowBackupResourceReceipt({ execution, action, ownerId, operationId,
  backupId = null, requestedPath = null, result }) {
  if (!execution || typeof execution !== 'object' || !execution.runId || ownerId == null
      || !['dataset_deleted', 'backup_created', 'backup_downloaded'].includes(action)) return null;
  const returned = canonicalResult(result);
  const receipt = Object.freeze({ type:'controlled_finflow_backup_resource', version:1, action,
    ownerId:String(ownerId), generation:String(execution.durableGeneration), runId:execution.runId,
    operationId, backupId, requestedPath, returnedSha256:sha256(returned), returnedByteLength:returned.length });
  issued.set(receipt, { execution });
  return receipt;
}

function verifyFinflowBackupResourceReceipt({ receipt, execution, action, ownerId,
  operationId, backupId = null, requestedPath = null, result }) {
  const privateBinding = receipt && issued.get(receipt);
  if (!privateBinding || privateBinding.execution !== execution || receipt.type !== 'controlled_finflow_backup_resource'
      || receipt.version !== 1 || receipt.action !== action || receipt.ownerId !== String(ownerId)
      || receipt.generation !== String(execution?.durableGeneration) || receipt.runId !== execution?.runId
      || receipt.operationId !== operationId || receipt.backupId !== backupId || receipt.requestedPath !== requestedPath) return null;
  const returned = canonicalResult(result);
  if (receipt.returnedByteLength !== returned.length || receipt.returnedSha256 !== sha256(returned)) return null;
  return receipt;
}

module.exports = { issueFinflowBackupResourceReceipt, verifyFinflowBackupResourceReceipt };
