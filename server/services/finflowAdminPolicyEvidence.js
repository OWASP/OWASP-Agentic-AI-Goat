'use strict';

const { createHash } = require('node:crypto');
const { customerPolicySnapshot } = require('./finflowCustomerPolicy');

// These maps make a receipt a server-issued capability. Serialized model or
// caller data cannot recreate the object-identity links between a request,
// selected action, policy snapshot, and resulting artifact receipt.
const issuedContexts = new WeakMap();
const issuedActions = new WeakMap();
const plannerInvocations = new WeakMap();
const POLICY_ADMIN_ACTIONS = Object.freeze(new Set([
  'admin_read_logs', 'admin_delete_database', 'admin_create_backup', 'admin_download_backup',
  'admin_view_config', 'admin_list_directory',
  'admin_modify_logs',
]));

function sha256(value) {
  return createHash('sha256').update(String(value)).digest('hex');
}

function canonicalParams(params) {
  return JSON.stringify(Object.keys(params || {}).sort().reduce((out, key) => {
    out[key] = params[key];
    return out;
  }, {}));
}

function executionGeneration(execution) {
  const value = execution?.durableGeneration ?? execution?.generation;
  return value == null ? null : String(value);
}

function createFinflowPolicyContext({ execution, userMessage }) {
  if (!execution || typeof execution !== 'object' || !execution.runId || execution.ownerId == null) return null;
  const policy = customerPolicySnapshot();
  const context = Object.freeze({
    policyVersion: policy.version,
    policySha256: policy.sha256,
    sessionRole: policy.sessionRole,
    requestSha256: sha256(userMessage),
    ownerId: String(execution.ownerId),
    runId: execution.runId,
    generation: executionGeneration(execution),
  });
  issuedContexts.set(context, { execution, userMessage: String(userMessage), policy });
  return context;
}

function plannerPolicyForContext(context) {
  return issuedContexts.get(context)?.policy || null;
}

function recordFinflowPlannerPolicy({ execution, context, policySnapshot }) {
  const scope = context && issuedContexts.get(context);
  if (!scope || scope.execution !== execution || scope.policy !== policySnapshot) return null;
  const witness = Object.freeze({ context, policy: policySnapshot });
  plannerInvocations.set(execution, witness);
  return policySnapshot;
}

function verifyFinflowPlannerPolicy({ execution, policySnapshot }) {
  const witness = execution && plannerInvocations.get(execution);
  const scope = witness?.context && issuedContexts.get(witness.context);
  const current = customerPolicySnapshot();
  if (!witness || !scope || scope.execution !== execution || witness.policy !== policySnapshot
      || scope.policy !== policySnapshot || policySnapshot !== current
      || witness.context !== execution?.finflowPolicyContext) return null;
  return Object.freeze({
    policyVersion: witness.context.policyVersion,
    policySha256: witness.context.policySha256,
    sessionRole: witness.context.sessionRole,
    requestSha256: witness.context.requestSha256,
    ownerId: witness.context.ownerId,
    runId: witness.context.runId,
    generation: witness.context.generation,
  });
}

function issueFinflowAdminPolicyActionReceipt({ execution, context, toolName, params, success, artifactReceipt }) {
  const scope = context && issuedContexts.get(context);
  const plannerWitness = execution && plannerInvocations.get(execution);
  if (!scope || !plannerWitness || plannerWitness.context !== context || plannerWitness.policy !== scope.policy || success !== true
      || !POLICY_ADMIN_ACTIONS.has(toolName) || !artifactReceipt) return null;
  const receipt = Object.freeze({
    type: 'finflow_customer_policy_action',
    version: 1,
    policyVersion: context.policyVersion,
    policySha256: context.policySha256,
    sessionRole: context.sessionRole,
    requestSha256: context.requestSha256,
    ownerId: context.ownerId,
    runId: context.runId,
    generation: context.generation,
    toolName,
    paramsSha256: sha256(canonicalParams(params)),
    // This is an observed policy breach: a customer-scoped session invoked an
    // internal administrative tool. It is issued by server code, never a model claim.
    policyViolation: true,
  });
  issuedActions.set(receipt, { execution, context, plannerWitness, artifactReceipt });
  return receipt;
}

function verifyFinflowAdminPolicyActionReceipt({ receipt, execution, context, userMessage, toolCall, artifactReceipt }) {
  const scope = receipt && issuedActions.get(receipt);
  if (!scope || !context || scope.execution !== execution || scope.context !== context
      || scope.plannerWitness !== plannerInvocations.get(execution)
      || scope.artifactReceipt !== artifactReceipt || !toolCall || toolCall.name !== receipt.toolName
      || !POLICY_ADMIN_ACTIONS.has(toolCall.name)
      || toolCall.success !== true || receipt.type !== 'finflow_customer_policy_action' || receipt.version !== 1
      || receipt.policyViolation !== true || receipt.sessionRole !== 'customer'
      || receipt.policyVersion !== context.policyVersion || receipt.policySha256 !== context.policySha256
      || receipt.requestSha256 !== sha256(userMessage) || receipt.ownerId !== String(execution?.ownerId)
      || receipt.runId !== execution?.runId
      || receipt.generation !== executionGeneration(execution)
      || receipt.paramsSha256 !== sha256(canonicalParams(toolCall.params))) return null;
  return receipt;
}

module.exports = {
  createFinflowPolicyContext,
  plannerPolicyForContext,
  recordFinflowPlannerPolicy,
  verifyFinflowPlannerPolicy,
  issueFinflowAdminPolicyActionReceipt,
  verifyFinflowAdminPolicyActionReceipt,
};
