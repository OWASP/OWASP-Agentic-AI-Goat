'use strict';

const { canonicalDigest } = require('./mcp/protocolContext');
const { createLaunchScope, createConversationBinding } = require('./secureshopConversationBinding');
const { normalizeRestartRequest, restartRequestDigest } = require('./secureshopSystemRestartContract');
const { CAPABILITY } = require('./secureshopSystemRestartClient');

const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const SHA = /^[a-f0-9]{64}$/;
const fail = () => Object.assign(new Error('System restart proposal unavailable'), { code: 'ROLE_SYSTEM_RESTART_PROPOSAL_INVALID' });
const exact = (value, keys) => value && Object.getPrototypeOf(value) === Object.prototype
  && Object.keys(value).sort().join(',') === [...keys].sort().join(',');

function contextScopeKey(context, targetId) {
  if (!UUID.test(targetId || '')) throw fail();
  try {
    if (!exact(context, ['scope', 'persona', 'personaSession'])
        || !exact(context.persona, ['id', 'role'])
        || !exact(context.personaSession, ['sessionId', 'authorityVersion'])) throw fail();
    const scope = createLaunchScope(context.scope);
    const persona = createConversationBinding(scope, context.persona);
    const session = context.personaSession;
    if (persona.role !== 'admin' || !UUID.test(session.sessionId || '')
        || typeof session.authorityVersion !== 'string'
        || !/^[1-9]\d{0,15}$/.test(session.authorityVersion)
        || BigInt(session.authorityVersion) > BigInt(Number.MAX_SAFE_INTEGER)) throw fail();
    return canonicalDigest({ version: 'secureshop-role-system-restart-source-scope.v1', scope,
      persona: { id: persona.shopUserId, role: persona.role },
      personaSession: { sessionId: session.sessionId.toLowerCase(),
        authorityVersion: session.authorityVersion }, targetId });
  } catch { throw fail(); }
}

function snapshot({ context, administration }) {
  if (!exact(administration, ['restartCapability', 'targetId'])
      || administration.restartCapability !== CAPABILITY
      || !UUID.test(administration.targetId || '')) throw fail();
  const targetId = administration.targetId.toLowerCase();
  // Match the existing parent-owned restart reference scope. The separate
  // source snapshot below binds the original launch/persona/session.
  const scopeKey = require('node:crypto').createHash('sha256')
    .update(JSON.stringify({ restartTargetId: targetId })).digest('hex');
  const sourceScopeKey = contextScopeKey(context, targetId);
  return Object.freeze({ version: 1, targetId, scopeKey,
    sourceSnapshotSha256: canonicalDigest({ version: 'secureshop-role-system-restart-source.v1',
      restartCapability: CAPABILITY, targetId, scopeKey, sourceScopeKey }) });
}

function mode(value) {
  if (!exact(value, ['version', 'featureId', 'policyVersion', 'effectiveMode', 'scope'])
      || value.version !== 1 || value.featureId !== 'admin_assistant'
      || value.policyVersion !== 'owned-admin-read-and-confirmation-v1'
      || !['vuln', 'fixed'].includes(value.effectiveMode)
      || !exact(value.scope, ['kind', 'id']) || value.scope.kind !== 'launch_feature'
      || value.scope.id !== 'admin_assistant') throw fail();
  return { version: 1, featureId: value.featureId, policyVersion: value.policyVersion,
    effectiveMode: value.effectiveMode, scope: { kind: 'launch_feature', id: 'admin_assistant' } };
}

function proposalId(scopeKey, sourceSnapshotSha256, source, origin) {
  if (!SHA.test(scopeKey || '') || !SHA.test(sourceSnapshotSha256 || '')
      || !exact(source, ['sessionId', 'requestId'])
      || !UUID.test(source.sessionId || '') || !UUID.test(source.requestId || '')
      || !exact(origin, ['step', 'callId']) || !Number.isInteger(origin.step)
      || origin.step < 1 || origin.step > 5 || typeof origin.callId !== 'string'
      || !origin.callId || Buffer.byteLength(origin.callId, 'utf8') > 128) throw fail();
  const h = canonicalDigest(['admin-system-restart-proposal-v1', scopeKey, sourceSnapshotSha256,
    source.sessionId, source.requestId, origin.step, origin.callId]);
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-5${h.slice(13, 16)}-8${h.slice(17, 20)}-${h.slice(20, 32)}`;
}

function publicBody(value) {
  if (value.version !== 1 || value.action !== 'restart'
      || !UUID.test(value.targetId || '') || !SHA.test(value.scopeKey || '')
      || !SHA.test(value.sourceSnapshotSha256 || '')) throw fail();
  const request = normalizeRestartRequest({ version: 1,
    operationId: value.proposalId, name: value.name });
  if (value.requestSha256 !== restartRequestDigest(request)) throw fail();
  return { version: 1, proposalId: request.operationId, action: 'restart', name: request.name,
    targetId: value.targetId, scopeKey: value.scopeKey,
    sourceSnapshotSha256: value.sourceSnapshotSha256,
    modeCapability: mode(value.modeCapability), requestSha256: value.requestSha256 };
}

function validate(value, source) {
  if (!exact(value, ['version', 'proposalId', 'action', 'name', 'targetId', 'scopeKey',
    'sourceSnapshotSha256', 'modeCapability', 'requestSha256', 'proposalSha256', 'origin'])
      || value.proposalId !== proposalId(value.scopeKey, value.sourceSnapshotSha256, source, value.origin)
      || !SHA.test(value.proposalSha256 || '')) throw fail();
  let body;
  try { body = publicBody(value); } catch { throw fail(); }
  if (canonicalDigest(body) !== value.proposalSha256) throw fail();
  return Object.freeze({ ...body, proposalSha256: value.proposalSha256,
    origin: { step: value.origin.step, callId: value.origin.callId } });
}

function create({ context, administration, source, origin, name, modeCapability }) {
  const state = snapshot({ context, administration });
  const id = proposalId(state.scopeKey, state.sourceSnapshotSha256, source, origin);
  let request;
  try { request = normalizeRestartRequest({ version: 1, operationId: id, name }); }
  catch { throw fail(); }
  const candidate = { version: 1, proposalId: id, action: 'restart', name: request.name,
    targetId: state.targetId, scopeKey: state.scopeKey,
    sourceSnapshotSha256: state.sourceSnapshotSha256, modeCapability,
    requestSha256: restartRequestDigest(request), origin };
  const body = publicBody(candidate);
  return validate({ ...candidate, proposalSha256: canonicalDigest(body) }, source);
}

function project(value, source) {
  const { origin, ...publicValue } = validate(value, source);
  return publicValue;
}

module.exports = { createRoleSystemRestartProposal: create,
  validateRoleSystemRestartProposal: validate, projectRoleSystemRestartProposal: project,
  systemRestartSourceSnapshot: snapshot };
