'use strict';

const { createHash } = require('node:crypto');
const { createLaunchScope, createConversationBinding } = require('./secureshopConversationBinding');
const { normalizeRequest, requestDigest } = require('../../sidecars/sandbox-runner/owned-system/contract');
const { validateSystemConfigReceipt } = require('../../sidecars/sandbox-runner/owned-system/receipt');
const { validateSystemConfigExecution } = require('./secureshopSystemConfigExecution');
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const SHA = /^[a-f0-9]{64}$/;
// Match RoleChat's observation(value) bound on the first JSON serialization.
const OBSERVATION_BYTES = 16384;
const fail = code => Object.assign(new Error('Admin System read unavailable'), { code });
const digest = value => createHash('sha256').update(JSON.stringify(value)).digest('hex');
const exact = (value, keys) => value && Object.getPrototypeOf(value) === Object.prototype
  && Object.keys(value).sort().join(',') === [...keys].sort().join(',');

function trustedContext(raw) {
  const value = structuredClone(raw);
  if (!exact(value, ['scope', 'persona', 'personaSession'])) throw fail('SYSTEM_READ_CONTEXT_INVALID');
  const scope = createLaunchScope(value.scope);
  const binding = createConversationBinding(scope, value.persona);
  if (binding.role !== 'admin' || !UUID.test(value.personaSession?.sessionId || '')
      || typeof value.personaSession?.authorityVersion !== 'string'
      || !/^[1-9]\d{0,15}$/.test(value.personaSession.authorityVersion)
      || BigInt(value.personaSession.authorityVersion) > 9007199254740991n) throw fail('SYSTEM_READ_CONTEXT_INVALID');
  return { scope, persona: { id: binding.shopUserId, role: binding.role },
    personaSession: { sessionId: value.personaSession.sessionId,
      authorityVersion: value.personaSession.authorityVersion } };
}

function configReadOperationId(context, source, origin) {
  if (!exact(source, ['sessionId', 'requestId']) || !UUID.test(source.sessionId || '')
      || !UUID.test(source.requestId || '') || !exact(origin, ['step', 'callId'])
      || !Number.isInteger(origin.step) || origin.step < 1 || origin.step > 5
      || typeof origin.callId !== 'string' || !origin.callId
      || Buffer.byteLength(origin.callId) > 128) throw fail('SYSTEM_READ_ORIGIN_INVALID');
  const x = trustedContext(context);
  const h = digest(['system.config_read.v1', x.scope.launchId, x.scope.scenarioId,
    x.scope.generation, x.scope.platformOwnerId, x.scope.platformSessionId,
    x.persona.id, x.personaSession.sessionId, x.personaSession.authorityVersion,
    source.sessionId, source.requestId, origin.step, origin.callId]);
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-5${h.slice(13, 16)}-8${h.slice(17, 20)}-${h.slice(20, 32)}`;
}

function boundedConfigObservation(value, request, scopeKey) {
  if (!SHA.test(scopeKey || '') || value?.operationId !== request.operationId
      || !['pending', 'unknown', 'not_executed', 'completed'].includes(value.state)
      || value.requestSha256 !== requestDigest(request)) throw fail('SYSTEM_READ_RESULT_INVALID');
  const base = { version: 1, kind: 'system.config_read', scopeKey,
    operationId: request.operationId, requestSha256: value.requestSha256, state: value.state };
  if (value.state !== 'completed') return { ...base, result: null };
  const receipt = validateSystemConfigReceipt(request, value.receipt);
  if (receipt.status === 'unavailable') return { ...base, result: { status: 'unavailable' } };
  const read = receipt.readResult;
  if (read.ok === false) return { ...base, result: { status: 'completed', ok: false, error: read.error } };
  const full = { ...base, result: { status: 'completed', ok: true, input: read.input,
    sanitized: read.sanitized, targetPath: read.targetPath, size: read.size,
    contentSha256: read.contentSha256, content: read.content, oversized: false } };
  if (Buffer.byteLength(JSON.stringify(full)) <= OBSERVATION_BYTES) return full;
  return { ...base, result: { status: 'completed', ok: true, size: read.size,
    contentSha256: read.contentSha256, content: null, oversized: true } };
}

function createRoleSystemReads({ getSystemConfig } = {}) {
  if (typeof getSystemConfig !== 'function') throw new TypeError('Lazy System composition required');
  const executions = new WeakMap();
  async function current(context, signal) {
    signal?.throwIfAborted();
    const value = await getSystemConfig();
    signal?.throwIfAborted();
    if (value?.ready !== true || typeof value.service?.administration !== 'function'
        || typeof value.service?.read !== 'function' || typeof value.service?.operation !== 'function'
        || typeof value.healthService?.health !== 'function') throw fail('SYSTEM_READ_UNAVAILABLE');
    return value;
  }
  async function check(callback, signal) {
    signal?.throwIfAborted();
    await callback();
    signal?.throwIfAborted();
  }
  return Object.freeze({
    executionFor: value => executions.has(value) ? structuredClone(executions.get(value)) : null,
    async health({ context, assertCurrent, signal } = {}) {
      if (typeof assertCurrent !== 'function') throw new TypeError('Current scene check required');
      const x = trustedContext(context);
      await check(assertCurrent, signal);
      const system = await current(x, signal);
      await check(assertCurrent, signal);
      const admission = await system.service.administration(x);
      if (!SHA.test(admission?.scopeKey || '')) throw fail('SYSTEM_READ_AUTH_INVALID');
      await check(assertCurrent, signal);
      const metrics = await system.healthService.health(x, { signal });
      await check(assertCurrent, signal);
      return { version: 1, kind: 'system.health', scopeKey: admission.scopeKey, metrics };
    },
    async configRead({ context, source, origin, path, assertCurrent, signal } = {}) {
      if (typeof assertCurrent !== 'function') throw new TypeError('Current scene check required');
      const x = trustedContext(context);
      const operationId = configReadOperationId(x, source, origin);
      const request = normalizeRequest({ operationId, path });
      await check(assertCurrent, signal);
      const system = await current(x, signal);
      await check(assertCurrent, signal);
      const admission = await system.service.administration(x);
      if (!SHA.test(admission?.scopeKey || '')) throw fail('SYSTEM_READ_AUTH_INVALID');
      await check(assertCurrent, signal);
      const value = await system.service.read({ ...x, ...request }, {
        signal, beforeEffect: () => check(assertCurrent, signal),
      });
      await check(assertCurrent, signal);
      const observation = boundedConfigObservation(value, request, admission.scopeKey);
      if(value.execution!==undefined)executions.set(observation,validateSystemConfigExecution(value.execution,x.scope));
      return observation;
    },
    async operation({ context, operationId, signal } = {}) {
      // Exact journal readback is scoped to the original launch/persona/session.
      // It intentionally does not require the original chat scene to be active.
      const x = trustedContext(context);
      if (!UUID.test(operationId || '')) throw fail('SYSTEM_READ_OPERATION_INVALID');
      const system = await current(x, signal);
      const value = await system.service.operation({ ...x, operationId });
      signal?.throwIfAborted();
      if (!value || value.operationId !== operationId
          || !['not_found', 'pending', 'unknown', 'not_executed', 'completed'].includes(value.state))
        throw fail('SYSTEM_READ_RESULT_INVALID');
      // Preserve the full, immutable receipt for protected exact GET recovery.
      return Object.freeze(structuredClone(value));
    },
  });
}

module.exports = { createRoleSystemReads, configReadOperationId, boundedConfigObservation };
