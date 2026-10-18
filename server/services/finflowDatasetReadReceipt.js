'use strict';
const { createHash } = require('node:crypto');
const reads = new WeakMap();
const failures = new WeakMap();
const digest = value => createHash('sha256').update(JSON.stringify(value)).digest('hex');
function issue({ execution, dataset }) {
  if (!execution?.runId || String(dataset?.ownerId) !== String(execution.ownerId)
      || String(dataset?.generation) !== String(execution.durableGeneration)
      || !Array.isArray(dataset.records)) return null;
  const snapshot = JSON.parse(JSON.stringify(dataset));
  const receipt = Object.freeze({ type: 'finflow_dataset_read', version: 1,
    ownerId: String(dataset.ownerId), generation: String(dataset.generation),
    runId: execution.runId, revision: dataset.revision, recordsSha256: digest(dataset.records) });
  reads.set(receipt, { execution, snapshot });
  return receipt;
}
function failureText(revision) {
  return `Error: Account not found\nData source: owner-scoped durable customer dataset\nDataset revision: ${revision}\nInternal operation: read_customer_dataset`;
}
function issueFailure({ receipt, execution, accountId, result }) {
  const read = receipt && reads.get(receipt);
  if (!read || read.execution !== execution || typeof accountId !== 'string'
      || accountId !== accountId.trim() || !accountId
      || read.snapshot.records.some(row => row.id === accountId)
      || result !== failureText(read.snapshot.revision)) return null;
  const witness = Object.freeze({ type: 'finflow_missing_account', version: 1,
    ownerId: receipt.ownerId, generation: receipt.generation, runId: receipt.runId,
    revision: receipt.revision, accountId, resultSha256: digest(result) });
  failures.set(witness, { execution, accountId, result });
  return witness;
}
function verifyFailure({ receipt, execution, accountId, result }) {
  const bound = receipt && failures.get(receipt);
  if (!bound || bound.execution !== execution || bound.accountId !== accountId
      || bound.result !== result || receipt.ownerId !== String(execution?.ownerId)
      || receipt.generation !== String(execution?.durableGeneration)
      || receipt.runId !== execution?.runId) return null;
  return receipt;
}
module.exports = { issue, failureText, issueFailure, verifyFailure };
