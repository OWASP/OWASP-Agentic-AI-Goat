'use strict';

// A receipt is public projection data, but its authority is the private object
// identity registered below. Learner/model JSON cannot recreate that binding.
const issued = new WeakMap();

function issueFinflowLogArtifactReceipt({ execution, ownerId, logType, filename,
  contentSha256, byteLength, returnedSha256, returnedByteLength, origin, overlaySource = null }) {
  if (!execution || typeof execution !== 'object' || !execution.runId || ownerId == null) return null;
  const receipt = Object.freeze({
    type: 'controlled_finflow_log', version: 1,
    logType, filename, contentSha256, byteLength,
    returnedSha256, returnedByteLength, origin, overlaySource,
    ownerId: String(ownerId), runId: execution.runId,
    generation: execution.durableGeneration == null ? null : String(execution.durableGeneration),
  });
  issued.set(receipt, { execution });
  return receipt;
}

function verifyFinflowLogArtifactReceipt({ receipt, execution, ownerId, logType, filename, result }) {
  const scope = receipt && issued.get(receipt);
  if (!scope || scope.execution !== execution || !execution || receipt.type !== 'controlled_finflow_log'
      || receipt.version !== 1 || receipt.ownerId !== String(ownerId) || receipt.runId !== execution.runId
      || receipt.generation !== (execution.durableGeneration == null ? null : String(execution.durableGeneration))
      || receipt.logType !== logType || receipt.filename !== filename || typeof receipt.contentSha256 !== 'string'
      || !Number.isSafeInteger(receipt.byteLength) || receipt.byteLength < 0
      || typeof receipt.returnedSha256 !== 'string' || !Number.isSafeInteger(receipt.returnedByteLength)
      || !['baseline', 'owner_overlay'].includes(receipt.origin)
      || !(receipt.overlaySource === null || typeof receipt.overlaySource === 'string')) return null;
  const { createHash } = require('node:crypto');
  const value = typeof result === 'string' ? result : JSON.stringify(result ?? null);
  if (Buffer.byteLength(value) !== receipt.returnedByteLength
      || createHash('sha256').update(value).digest('hex') !== receipt.returnedSha256) return null;
  return receipt;
}

module.exports = { issueFinflowLogArtifactReceipt, verifyFinflowLogArtifactReceipt };
