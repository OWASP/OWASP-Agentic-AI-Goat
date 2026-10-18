'use strict';

// Public receipt fields are safe to persist, but only this module's private
// identity registry can attest that an application-controlled read issued it.
const issued = new WeakMap();

function issueFinflowTraversalArtifactReceipt({ execution, ownerId, toolName, logicalPath,
  targetId, contentSha256, byteLength, returnedSha256, returnedByteLength }) {
  if (!execution || typeof execution !== 'object' || !execution.runId || ownerId == null) return null;
  const receipt = Object.freeze({
    type: 'controlled_finflow_traversal', version: 1, toolName, logicalPath, targetId,
    contentSha256, byteLength, returnedSha256, returnedByteLength,
    ownerId: String(ownerId), runId: execution.runId,
    generation: execution.durableGeneration == null ? null : String(execution.durableGeneration),
  });
  issued.set(receipt, { execution });
  return receipt;
}

function verifyFinflowTraversalArtifactReceipt({ receipt, execution, ownerId, toolName,
  logicalPath, targetId, result }) {
  const scope = receipt && issued.get(receipt);
  if (!scope || scope.execution !== execution || !execution || receipt.type !== 'controlled_finflow_traversal'
      || receipt.version !== 1 || receipt.ownerId !== String(ownerId) || receipt.runId !== execution.runId
      || receipt.generation !== (execution.durableGeneration == null ? null : String(execution.durableGeneration))
      || receipt.toolName !== toolName || receipt.logicalPath !== logicalPath || receipt.targetId !== targetId
      || typeof receipt.contentSha256 !== 'string' || !Number.isSafeInteger(receipt.byteLength) || receipt.byteLength < 0
      || typeof receipt.returnedSha256 !== 'string' || !Number.isSafeInteger(receipt.returnedByteLength)
      || receipt.returnedByteLength < 0) return null;
  const { createHash } = require('node:crypto');
  const value = typeof result === 'string' ? result : JSON.stringify(result ?? null);
  if (Buffer.byteLength(value) !== receipt.returnedByteLength
      || createHash('sha256').update(value).digest('hex') !== receipt.returnedSha256) return null;
  return receipt;
}

module.exports = { issueFinflowTraversalArtifactReceipt, verifyFinflowTraversalArtifactReceipt };
