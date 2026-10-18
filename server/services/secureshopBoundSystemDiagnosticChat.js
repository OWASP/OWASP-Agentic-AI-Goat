'use strict';

const C = require('./secureshopRoleSystemDiagnosticProposal');
const { normalizeDiagnosticRequest, diagnosticRequestDigest } = require('../../sidecars/sandbox-runner/owned-system/diagnostic-contract');
const { validateBoundDiagnosticResult } = require('../../sidecars/sandbox-runner/owned-system/diagnostic-wire');
const { canonicalDigest } = require('./mcp/protocolContext');

const fail = code => Object.assign(new Error('System diagnostic conversation unavailable'), { code });
function createBoundSystemDiagnosticChat({ getDiagnostic } = {}) {
  if (typeof getDiagnostic !== 'function') throw new TypeError('Lazy bound System diagnostic required');
  async function service() {
    const composition = await getDiagnostic();
    if (composition?.ready !== true || typeof composition.service?.administration !== 'function'
        || typeof composition.service?.execute !== 'function'
        || typeof composition.service?.operation !== 'function') throw fail('SYSTEM_DIAGNOSTIC_UNAVAILABLE');
    return composition.service;
  }
  async function administration(context, signal) {
    const application = await service();
    signal?.throwIfAborted();
    const value = await application.administration(structuredClone(context), { includeExecution: true, signal });
    signal?.throwIfAborted();
    return { application, value };
  }
  async function snapshot({ context, signal }) {
    const { value } = await administration(context, signal);
    return C.systemDiagnosticSourceSnapshot({ context, administration: value });
  }
  async function prepare({ context, source, origin, cmd_template, args, modeCapability, signal }) {
    const { value } = await administration(context, signal);
    const state = C.systemDiagnosticSourceSnapshot({ context, administration: value });
    if (modeCapability !== undefined && canonicalDigest(modeCapability) !== canonicalDigest(state.modeCapability))
      throw fail('ROLE_SYSTEM_DIAGNOSTIC_PROPOSAL_INVALID');
    return C.createRoleSystemDiagnosticProposal({ context, administration: value, source, origin,
      cmd_template, args });
  }
  function currentProposal(saved, current) {
    if (current.scopeKey !== saved.scopeKey
        || current.sourceSnapshotSha256 !== saved.sourceSnapshotSha256
        || canonicalDigest(current.execution) !== canonicalDigest(saved.execution)
        || canonicalDigest(current.modeCapability) !== canonicalDigest(saved.modeCapability))
      throw fail('SYSTEM_DIAGNOSTIC_CHAT_SCOPE_MISMATCH');
  }
  function project(value, saved) {
    if (!value || value.operationId !== saved.proposalId) throw fail('SYSTEM_DIAGNOSTIC_CHAT_STATE_INVALID');
    const operationId = saved.proposalId;
    if (value.state === 'not_found') return { ok: false, state: 'not_found', operationId };
    if (value.requestSha256 !== saved.requestSha256) throw fail('SYSTEM_DIAGNOSTIC_CHAT_STATE_INVALID');
    if (['admitted', 'pending', 'unknown', 'not_executed'].includes(value.state)) {
      return { ok: false, state: value.state, operationId, automaticRetry: false };
    }
    if (value.state !== 'completed') throw fail('SYSTEM_DIAGNOSTIC_CHAT_STATE_INVALID');
    const request = normalizeDiagnosticRequest({ operationId, cmd_template: saved.cmd_template, args: saved.args });
    if (diagnosticRequestDigest(request) !== saved.requestSha256) throw fail('SYSTEM_DIAGNOSTIC_CHAT_STATE_INVALID');
    let receipt;
    try { receipt = validateBoundDiagnosticResult({ targetId: value.targetId, request }, value.receipt); }
    catch { throw fail('SYSTEM_DIAGNOSTIC_CHAT_STATE_INVALID'); }
    return { ok: true, state: 'completed', operationId, requestSha256: saved.requestSha256,
      targetId: value.targetId, receipt };
  }
  async function confirm(raw) {
    const { context, source, proposal } = structuredClone({ context: raw.context,
      source: raw.source, proposal: raw.proposal });
    const { signal, beforeEffect } = raw;
    if (typeof beforeEffect !== 'function') throw fail('ROLE_SYSTEM_DIAGNOSTIC_PROPOSAL_INVALID');
    const saved = C.validateRoleSystemDiagnosticProposal(proposal, source);
    const { application, value } = await administration(context, signal);
    const current = C.systemDiagnosticSourceSnapshot({ context, administration: value });
    currentProposal(saved, current);
    if (current.modeCapability.effectiveMode !== 'vuln') throw fail('SYSTEM_DIAGNOSTIC_FIXED_DENIED');
    await beforeEffect();
    signal?.throwIfAborted();
    const outcome = await application.execute({ ...context, operationId: saved.proposalId,
      cmd_template: saved.cmd_template, args: saved.args }, { signal, beforeEffect });
    return project(outcome, saved);
  }
  async function operation({ context, source, proposal, signal }) {
    const saved = C.validateRoleSystemDiagnosticProposal(proposal, source);
    const { application, value } = await administration(context, signal);
    // A saved receipt remains readable after a mode change. Rebuild the
    // original source digest from its immutable epoch while administration
    // independently rechecks the current owner/session/launch.
    const historical = C.systemDiagnosticSourceSnapshot({ context,
      administration: { ...value, modeCapability: saved.modeCapability, execution: saved.execution } });
    if (historical.scopeKey !== saved.scopeKey
        || historical.sourceSnapshotSha256 !== saved.sourceSnapshotSha256)
      throw fail('SYSTEM_DIAGNOSTIC_CHAT_SCOPE_MISMATCH');
    const outcome = await application.operation({ ...structuredClone(context), operationId: saved.proposalId });
    return project(outcome, saved);
  }
  return Object.freeze({ snapshot, prepare, confirm, operation });
}
module.exports = { createBoundSystemDiagnosticChat };
