'use strict';

const { canonicalDigest } = require('./mcp/protocolContext');
const { createLaunchScope, createConversationBinding } = require('./secureshopConversationBinding');
const { normalizeDiagnosticRequest, diagnosticRequestDigest } = require('../../sidecars/sandbox-runner/owned-system/diagnostic-contract');
const { CAPABILITY } = require('./secureshopSystemDiagnosticClient');

const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const SHA = /^[a-f0-9]{64}$/;
const POLICY = 'owned-system-diagnostic-shell-v1';
const LITERAL_REQUEST_PREFIX = 'System diagnostic JSON:';
const fail = () => Object.assign(new Error('System diagnostic proposal unavailable'), { code: 'ROLE_SYSTEM_DIAGNOSTIC_PROPOSAL_INVALID' });
const exact = (value, keys) => value && Object.getPrototypeOf(value) === Object.prototype
  && Object.keys(value).sort().join(',') === [...keys].sort().join(',');

// Optional whole-message literal input. Never select a JSON fragment from prose,
// history or a tool result. A marked malformed request cannot fall back to a
// generated diagnostic. Scan keys before decoding the object so duplicates
// (including escaped duplicate names) cannot be hidden by JSON.parse.
function currentExplicitSystemDiagnosticRequest(message) {
  if (typeof message !== 'string') throw fail();
  const text = message.trim();
  if (!text.startsWith(LITERAL_REQUEST_PREFIX)) return undefined;
  if (!message.isWellFormed() || message.includes('\0') || Buffer.byteLength(message, 'utf8') > 8192) throw fail();
  const document = text.slice(LITERAL_REQUEST_PREFIX.length);
  let index = 0;
  const space = () => { while (/[\x20\t\r\n]/.test(document[index] || '') && index < document.length) index++; };
  const token = char => { space(); if (document[index++] !== char) throw fail(); };
  const string = () => {
    space(); const start = index;
    if (document[index++] !== '"') throw fail();
    while (index < document.length) {
      const char = document[index++];
      if (char === '\\') { index++; continue; }
      if (char === '"') {
        try { return JSON.parse(document.slice(start, index)); } catch { throw fail(); }
      }
    }
    throw fail();
  };
  token('{');
  const values = Object.create(null);
  for (let pair = 0; pair < 2; pair++) {
    if (pair) token(',');
    const key = string();
    if (!['cmd_template', 'args'].includes(key) || Object.hasOwn(values, key)) throw fail();
    token(':'); values[key] = string();
  }
  token('}'); space(); if (index !== document.length) throw fail();
  let normalized;
  try { normalized = normalizeDiagnosticRequest({
    // Validation only: this ID is never a proposal, operation or executor target.
    operationId: '00000000-0000-4000-8000-000000000000',
    cmd_template: values.cmd_template, args: values.args,
  }); } catch { throw fail(); }
  return Object.freeze({ cmd_template: normalized.cmd_template, args: normalized.args });
}

function mode(value) {
  if (!exact(value, ['version', 'featureId', 'policyVersion', 'effectiveMode', 'scope'])
      || value.version !== 1 || value.featureId !== 'system_diagnostic'
      || value.policyVersion !== POLICY || !['vuln', 'fixed'].includes(value.effectiveMode)
      || !exact(value.scope, ['kind', 'id']) || value.scope.kind !== 'launch_feature'
      || value.scope.id !== 'system_diagnostic') throw fail();
  return { version: 1, featureId: 'system_diagnostic', policyVersion: POLICY,
    effectiveMode: value.effectiveMode, scope: { kind: 'launch_feature', id: 'system_diagnostic' } };
}
function contextBinding(context) {
  try {
    if (!exact(context, ['scope', 'persona', 'personaSession'])
        || !exact(context.persona, ['id', 'role'])
        || !exact(context.personaSession, ['sessionId', 'authorityVersion'])) throw fail();
    const scope = createLaunchScope(context.scope);
    const persona = createConversationBinding(scope, context.persona);
    if (persona.role !== 'admin' || !UUID.test(context.personaSession.sessionId || '')
        || typeof context.personaSession.authorityVersion !== 'string'
        || !/^[1-9]\d{0,15}$/.test(context.personaSession.authorityVersion)
        || BigInt(context.personaSession.authorityVersion) > BigInt(Number.MAX_SAFE_INTEGER)) throw fail();
    return { scope, persona: { id: persona.shopUserId, role: 'admin' },
      personaSession: { sessionId: context.personaSession.sessionId.toLowerCase(),
        authorityVersion: context.personaSession.authorityVersion } };
  } catch { throw fail(); }
}
function snapshot({ context, administration }) {
  if (!exact(administration, ['diagnosticCapability', 'scopeKey', 'modeCapability', 'execution'])
      || administration.diagnosticCapability !== CAPABILITY || !SHA.test(administration.scopeKey || '')) throw fail();
  const capability = mode(administration.modeCapability);
  const execution = administration.execution;
  if (!exact(execution, ['version', 'featureId', 'policyVersion', 'mode', 'generation', 'modeStamp', 'scope'])
      || execution.version !== 1 || execution.featureId !== 'system_diagnostic'
      || execution.policyVersion !== POLICY || execution.mode !== capability.effectiveMode
      || (!Number.isSafeInteger(execution.generation) && execution.generation !== null)
      || (execution.generation !== null && execution.generation < 0)
      || (typeof execution.modeStamp !== 'string' && execution.modeStamp !== null)
      || canonicalDigest(execution.scope) !== canonicalDigest(createLaunchScope(context.scope))) throw fail();
  const binding = contextBinding(context);
  const expectedScopeKey = canonicalDigest({ version: 'secureshop-system-diagnostic-administration.v1',
    scope: binding.scope, persona: binding.persona, personaSession: binding.personaSession });
  if (administration.scopeKey !== expectedScopeKey) throw fail();
  const executionCopy = structuredClone(execution);
  return Object.freeze({ version: 1, scopeKey: administration.scopeKey,
    diagnosticCapability: CAPABILITY, modeCapability: capability, execution: executionCopy,
    sourceSnapshotSha256: canonicalDigest({ version: 'secureshop-role-system-diagnostic-source.v1',
      binding, scopeKey: administration.scopeKey, diagnosticCapability: CAPABILITY, execution: executionCopy }) });
}
function proposalId(state, source, origin) {
  if (!exact(source, ['sessionId', 'requestId']) || !UUID.test(source.sessionId || '')
      || !UUID.test(source.requestId || '') || !exact(origin, ['step', 'callId'])
      || !Number.isInteger(origin.step) || origin.step < 1 || origin.step > 5
      || typeof origin.callId !== 'string' || !origin.callId
      || !origin.callId.isWellFormed() || Buffer.byteLength(origin.callId) > 128) throw fail();
  const digest = canonicalDigest(['admin-system-diagnostic-proposal-v1', state.scopeKey,
    state.sourceSnapshotSha256, source.sessionId.toLowerCase(), source.requestId.toLowerCase(),
    origin.step, origin.callId]);
  return `${digest.slice(0, 8)}-${digest.slice(8, 12)}-5${digest.slice(13, 16)}-8${digest.slice(17, 20)}-${digest.slice(20, 32)}`;
}
function publicBody(value) {
  if (value.version !== 1 || value.action !== 'system_diagnostic'
      || !UUID.test(value.proposalId || '') || !SHA.test(value.scopeKey || '')
      || !SHA.test(value.sourceSnapshotSha256 || '')
      || value.diagnosticCapability !== CAPABILITY) throw fail();
  let request;
  try { request = normalizeDiagnosticRequest({ operationId: value.proposalId,
    cmd_template: value.cmd_template, args: value.args }); } catch { throw fail(); }
  if (value.requestSha256 !== diagnosticRequestDigest(request)) throw fail();
  return { version: 1, proposalId: request.operationId, action: 'system_diagnostic',
    cmd_template: request.cmd_template, args: request.args, scopeKey: value.scopeKey,
    diagnosticCapability: CAPABILITY, sourceSnapshotSha256: value.sourceSnapshotSha256,
    modeCapability: mode(value.modeCapability), requestSha256: value.requestSha256 };
}
function validate(value, source) {
  if (!exact(value, ['version', 'proposalId', 'action', 'cmd_template', 'args', 'scopeKey',
    'diagnosticCapability', 'sourceSnapshotSha256', 'modeCapability', 'requestSha256',
    'proposalSha256', 'origin', 'execution']) || !SHA.test(value.proposalSha256 || '')) throw fail();
  let body;
  try { body = publicBody(value); } catch { throw fail(); }
  const state = { scopeKey: value.scopeKey, sourceSnapshotSha256: value.sourceSnapshotSha256 };
  if (proposalId(state, source, value.origin) !== value.proposalId
      || canonicalDigest(body) !== value.proposalSha256
      || value.execution?.featureId !== 'system_diagnostic'
      || value.execution?.mode !== body.modeCapability.effectiveMode) throw fail();
  return Object.freeze({ ...body, proposalSha256: value.proposalSha256,
    origin: { step: value.origin.step, callId: value.origin.callId },
    execution: structuredClone(value.execution) });
}
function create({ context, administration, source, origin, cmd_template, args }) {
  const state = snapshot({ context, administration });
  const id = proposalId(state, source, origin);
  let request;
  try { request = normalizeDiagnosticRequest({ operationId: id, cmd_template, args }); } catch { throw fail(); }
  const candidate = { version: 1, proposalId: id, action: 'system_diagnostic',
    cmd_template: request.cmd_template, args: request.args, scopeKey: state.scopeKey,
    diagnosticCapability: CAPABILITY, sourceSnapshotSha256: state.sourceSnapshotSha256,
    modeCapability: state.modeCapability, requestSha256: diagnosticRequestDigest(request),
    origin, execution: state.execution };
  const body = publicBody(candidate);
  return validate({ ...candidate, proposalSha256: canonicalDigest(body) }, source);
}
function project(value, source) {
  const { origin, execution, ...publicValue } = validate(value, source);
  return publicValue;
}
module.exports = { createRoleSystemDiagnosticProposal: create,
  validateRoleSystemDiagnosticProposal: validate, projectRoleSystemDiagnosticProposal: project,
  systemDiagnosticSourceSnapshot: snapshot, currentExplicitSystemDiagnosticRequest, LITERAL_REQUEST_PREFIX };
