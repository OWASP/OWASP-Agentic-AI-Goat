'use strict';

const { createHash } = require('node:crypto');
const { createLaunchScope } = require('./secureshopConversationBinding');
const { auditQuery } = require('../database/postgres/secureshopBoundAuditRepository');
const { canonicalDigest } = require('./mcp/protocolContext');
const MAX_OBSERVATION_BYTES = 16 * 1024;
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const SHA = /^[a-f0-9]{64}$/;
const exact = (value, keys) => value && Object.getPrototypeOf(value) === Object.prototype
  && Object.keys(value).sort().join(',') === [...keys].sort().join(',');
const fail = () => Object.assign(new Error('Audit chat read unavailable'), { code: 'AUDIT_CHAT_INVALID' });
function auditSearchOperationId(context, source, origin) {
  const captured = contextFor(context);
  if (!exact(source, ['sessionId', 'requestId']) || !UUID.test(source.sessionId) || !UUID.test(source.requestId)
      || !exact(origin, ['step', 'callId']) || !Number.isSafeInteger(origin.step) || origin.step < 1 || origin.step > 5
      || typeof origin.callId !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(origin.callId)) throw fail();
  const h = createHash('sha256').update(JSON.stringify(['admin-audit-search-v1', captured.scope,
    captured.persona.id, captured.personaSession.sessionId, captured.personaSession.authorityVersion, source.sessionId,
    source.requestId, origin.step, origin.callId])).digest('hex');
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-5${h.slice(13, 16)}-8${h.slice(17, 20)}-${h.slice(20, 32)}`;
}
function contextFor(input) {
  if (!input || input.persona?.role !== 'admin' || !Number.isSafeInteger(input.persona.id) || input.persona.id < 1
      || !UUID.test(input.personaSession?.sessionId || '')
      || !/^[1-9][0-9]*$/.test(input.personaSession?.authorityVersion || '')) throw fail();
  return Object.freeze({ scope: createLaunchScope(input.scope),
    persona: Object.freeze({ id: input.persona.id, role: 'admin' }),
    personaSession: Object.freeze({ sessionId: input.personaSession.sessionId,
      authorityVersion: input.personaSession.authorityVersion }) });
}
function envelope(value, operationId) {
  const blocked = value?.status === 'blocked';
  if (!exact(value, ['version','operationId','status','result','source','modeCapability', ...(blocked ? ['reason'] : [])])
      || value.version !== 1 || value.operationId !== operationId
      || !['not_found','unconfirmed','completed','blocked'].includes(value.status)) throw fail();
  const mode = value.modeCapability;
  if (!exact(mode, ['version','featureId','policyVersion','effectiveMode','scope']) || mode.version !== 1
      || mode.featureId !== 'audit' || mode.policyVersion !== require('./secureshopFeatureModeAuthority').POLICIES.audit
      || !['vuln','fixed'].includes(mode.effectiveMode) || !exact(mode.scope, ['kind','id'])
      || mode.scope.kind !== 'launch_feature' || mode.scope.id !== 'audit'
      || (blocked ? mode.effectiveMode !== 'fixed' || typeof value.reason !== 'string'
        : mode.effectiveMode !== 'vuln')) throw fail();
  if (value.status === 'completed') {
    const r = value.result;
    if (!exact(value.source, ['sourceSha256','payloadSha256']) || !SHA.test(value.source.sourceSha256)
        || !SHA.test(value.source.payloadSha256) || !exact(r, ['ok','username','sql','count','events','error','durationMs']) || typeof r.ok !== 'boolean'
        || typeof r.username !== 'string' || typeof r.sql !== 'string' || !Array.isArray(r.events)
        || r.count !== r.events.length || !Number.isFinite(r.durationMs) || r.durationMs < 0
        || (r.ok ? r.error !== null : typeof r.error !== 'string')) throw fail();
  } else if (value.result !== null || value.source !== null) throw fail();
  if (Buffer.byteLength(JSON.stringify(value)) > 17 * 1024 * 1024) throw fail();
  return structuredClone(value);
}
function boundedAuditObservation(value) {
  if (typeof value?.operationId !== 'string' || !UUID.test(value.operationId)) throw fail();
  const saved = envelope(value, value.operationId), completed = saved.status === 'completed';
  const result = saved.result;
  const observation = {
    version: 1, kind: 'audit.sql_search', operationId: saved.operationId, status: saved.status,
    resultSha256: completed ? canonicalDigest(result) : null,
    resultBytes: completed ? Buffer.byteLength(JSON.stringify(result), 'utf8') : 0,
    count: completed ? result.count : null, ok: completed ? result.ok : null,
    source: saved.source, modeCapability: saved.modeCapability, oversized: false, result,
    ...(saved.status === 'blocked' ? { reason: saved.reason } : {}),
  };
  if (completed && Buffer.byteLength(JSON.stringify(observation), 'utf8') > MAX_OBSERVATION_BYTES) {
    observation.result = null;
    observation.oversized = true;
  }
  if (Buffer.byteLength(JSON.stringify(observation), 'utf8') > MAX_OBSERVATION_BYTES) throw fail();
  return observation;
}
function createBoundAuditChat({ admin, getAuditSearch } = {}) {
  if (typeof admin?.audit !== 'function' || typeof getAuditSearch !== 'function') throw TypeError('Audit chat dependencies required');
  function service() {
    const value = getAuditSearch();
    if (typeof value?.search !== 'function' || typeof value?.readSearch !== 'function') throw fail();
    return value;
  }
  async function read({ context, token, operationId, signal }) {
    const captured = contextFor(context);
    if (!UUID.test(operationId || '') || typeof token !== 'string' || !token) throw fail();
    signal?.throwIfAborted();
    const value = await service().readSearch({ scope: captured.scope, persona: captured.persona,
      expectedPersonaSession: captured.personaSession, token, operationId, signal });
    signal?.throwIfAborted();
    return envelope(value, operationId);
  }
  return Object.freeze({
    async list({ context, query = {}, signal }) {
      const captured = contextFor(context), copied = structuredClone(query);
      auditQuery(copied); signal?.throwIfAborted();
      const page = await admin.audit({ ...captured, query: copied });
      signal?.throwIfAborted();
      if (!exact(page, ['count','events','hasMore','nextCursor']) || !Array.isArray(page.events)
          || page.count !== page.events.length || typeof page.hasMore !== 'boolean'
          || (page.hasMore ? typeof page.nextCursor !== 'string' : page.nextCursor !== null)
          || Buffer.byteLength(JSON.stringify(page)) > 16 * 1024 * 1024) throw fail();
      return structuredClone(page);
    },
    async search({ context, token, source, origin, username, signal, beforeEffect }) {
      const captured = contextFor(context), operationId = auditSearchOperationId(captured, source, origin);
      if (typeof token !== 'string' || !token || typeof username !== 'string'
          || Buffer.byteLength(username) > 8192 || (beforeEffect !== undefined && typeof beforeEffect !== 'function')) throw fail();
      signal?.throwIfAborted();
      const result = await service().search({ scope: captured.scope, persona: captured.persona,
        expectedPersonaSession: captured.personaSession, token, operationId, username, signal, beforeEffect });
      signal?.throwIfAborted();
      if (result?.blocked === true) return envelope({ version: 1, operationId, status: 'blocked', result: null,
        source: null, modeCapability: result.modeCapability, reason: result.reason }, operationId);
      const saved = await read({ context: captured, token, operationId, signal });
      if (saved.status === 'blocked') throw fail();
      if (saved.status === 'completed' && saved.result.username !== username) throw fail();
      return saved;
    },
    read,
  });
}
module.exports = { createBoundAuditChat, auditSearchOperationId, boundedAuditObservation, MAX_OBSERVATION_BYTES };
