'use strict';

const { createHash } = require('node:crypto');
const issued = new WeakMap();
const digest = value => createHash('sha256').update(value).digest('hex');

function issueAdminArtifactReceipt({ execution, kind, virtualPath, value }) {
  if (!execution?.runId || execution.ownerId == null || execution.durableGeneration == null
      || !['config', 'directory'].includes(kind) || typeof virtualPath !== 'string'
      || typeof value !== 'string') throw new TypeError('Bound admin artifact execution required');
  const receipt = Object.freeze({ type: 'finflow_admin_artifact', version: 1,
    ownerId: String(execution.ownerId), generation: String(execution.durableGeneration),
    runId: execution.runId, kind, virtualPath,
    sha256: digest(value), byteLength: Buffer.byteLength(value) });
  issued.set(receipt, execution);
  return receipt;
}

function verifyAdminArtifactReceipt({ receipt, execution, kind, virtualPath, value }) {
  if (!receipt || !execution || issued.get(receipt) !== execution
      || receipt.ownerId !== String(execution.ownerId)
      || receipt.generation !== String(execution.durableGeneration)
      || receipt.runId !== execution.runId || receipt.kind !== kind
      || receipt.virtualPath !== virtualPath || typeof value !== 'string'
      || receipt.byteLength !== Buffer.byteLength(value) || receipt.sha256 !== digest(value)) return null;
  return receipt;
}

module.exports = { issueAdminArtifactReceipt, verifyAdminArtifactReceipt };
