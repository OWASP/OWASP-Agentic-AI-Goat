'use strict';

const receipts = new WeakMap();
const witnesses = new WeakSet();
const VERSION = 'mcp-owned-protected-observation.v1';
const OPERATIONS = Object.freeze({
  mcp_secret_exposure: 'read_configuration',
  mcp_broken_authz: 'rotate_keys',
  mcp_audit_gap: 'set_audit_logging',
});

function bindTool(result, receipt) {
  if (!result || typeof result !== 'object' || Array.isArray(result) || !Object.isFrozen(receipt)
      || receipt.version !== 'mcp-owned-protected-state.v1') {
    throw Object.assign(new Error('Protected-state tool observation is invalid'), { code: 'MCP_PROTECTED_OBSERVATION_INVALID' });
  }
  receipts.set(result, receipt); return result;
}

function adoptTool(source, target) {
  const receipt = source && typeof source === 'object' ? receipts.get(source) : null;
  if (receipt && target && typeof target === 'object' && !Array.isArray(target)) receipts.set(target, receipt);
  return target;
}

function witnessFor({ objectiveId, result, scope, execution } = {}) {
  const receipt = receipts.get(result); const operation = OPERATIONS[objectiveId];
  if (!operation || !receipt || receipt.operation !== operation || receipt.runId !== execution?.runId
      || receipt.targetId !== scope?.targetId || receipt.platformOwnerId !== scope?.platformOwnerId
      || receipt.platformSessionId !== scope?.platformSessionId || receipt.generation !== scope?.generation) return null;
  const common = { version: VERSION, objectiveId, operation, targetId: receipt.targetId,
    platformOwnerId: receipt.platformOwnerId, platformSessionId: receipt.platformSessionId,
    generation: receipt.generation, runId: receipt.runId, receiptSha256: receipt.receiptSha256 };
  const fact = operation === 'read_configuration'
    ? { configSha256: receipt.configSha256, byteCount: receipt.byteCount }
    : operation === 'rotate_keys'
      ? { labRole: receipt.labRole, policy: receipt.policy, changed: receipt.changed,
        keyVersionBefore: receipt.keyVersionBefore, keyVersionAfter: receipt.keyVersionAfter, audited: receipt.audited }
      : { action: receipt.action, auditEnabledBefore: receipt.auditEnabledBefore,
        auditEnabled: receipt.auditEnabled, entriesBefore: receipt.entriesBefore,
        entriesAfter: receipt.entriesAfter, audited: receipt.audited };
  const witness = Object.freeze({ ...common, fact: Object.freeze(fact) }); witnesses.add(witness); return witness;
}

function isTrustedWitness(value) { return witnesses.has(value); }

module.exports = { VERSION, bindTool, adoptTool, witnessFor, isTrustedWitness };
