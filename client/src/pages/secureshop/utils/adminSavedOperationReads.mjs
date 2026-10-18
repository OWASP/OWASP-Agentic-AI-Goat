import { trustedTurnMode } from './turnModeCapability.mjs';

const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const SHA = /^[a-f0-9]{64}$/;
const encoder = new TextEncoder();
const exact = (value, keys) => value && Object.getPrototypeOf(value) === Object.prototype
  && Object.keys(value).sort().join(',') === keys.slice().sort().join(',');
const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);
const fail = label => { throw new Error(`Saved ${label} invalid`); };

const adminMode = value => exact(value, ['version', 'featureId', 'policyVersion', 'effectiveMode', 'scope'])
  && exact(value.scope, ['kind', 'id']) && !!trustedTurnMode(value)
  && value.version === 1 && value.featureId === 'admin_assistant'
  && value.policyVersion === 'owned-admin-read-and-confirmation-v1'
  && value.scope.kind === 'launch_feature' && value.scope.id === 'admin_assistant';
const auditMode = value => exact(value, ['version', 'featureId', 'policyVersion', 'effectiveMode', 'scope'])
  && exact(value.scope, ['kind', 'id']) && value.version === 1 && value.featureId === 'audit'
  && value.policyVersion === 'raw-audit-query-disabled-v1'
  && ['vuln', 'fixed'].includes(value.effectiveMode)
  && value.scope.kind === 'launch_feature' && value.scope.id === 'audit';
const canonical = value => Array.isArray(value) ? value.map(canonical)
  : value && Object.getPrototypeOf(value) === Object.prototype
    ? Object.fromEntries(Object.keys(value).sort().map(key => [key, canonical(value[key])])) : value;
async function sha(value) {
  if (!globalThis.crypto?.subtle) fail('audit SQL result');
  const bytes = await globalThis.crypto.subtle.digest('SHA-256', encoder.encode(value));
  return [...new Uint8Array(bytes)].map(byte => byte.toString(16).padStart(2, '0')).join('');
}
const source = value => exact(value, ['sourceSha256', 'payloadSha256'])
  && SHA.test(value.sourceSha256) && SHA.test(value.payloadSha256);
const healthText = value => typeof value === 'string' && value.length > 0 && value.length <= 255
  && !/[\u0000-\u001f\u007f]/.test(value);
export function decodeUserLookup(value, turnMode, stopReason) {
  if (value == null) return null;
  if (!adminMode(turnMode) || stopReason !== 'end_turn'
    || !exact(value, ['version', 'username', 'status', 'assessmentReady'])
    || value.version !== 1 || !healthText(value.username)
    || !['complete', 'redacted', 'not_found'].includes(value.status)
    || typeof value.assessmentReady !== 'boolean') fail('user lookup');
  return Object.freeze({ ...value });
}
const auditResult = value => exact(value, ['ok', 'username', 'sql', 'count', 'events', 'error', 'durationMs'])
  && typeof value.ok === 'boolean' && typeof value.username === 'string'
  && typeof value.sql === 'string' && Number.isSafeInteger(value.count)
  && Array.isArray(value.events) && value.count === value.events.length
  && Number.isFinite(value.durationMs) && value.durationMs >= 0
  && (value.ok ? value.error === null : typeof value.error === 'string');

export function decodeAuditSearchDescriptor(value, turnMode, stopReason) {
  if (value == null) return null;
  const blocked = value.status === 'blocked';
  if (!adminMode(turnMode) || stopReason !== 'end_turn'
    || !exact(value, ['version', 'kind', 'operationId', 'status', 'resultSha256',
      'resultBytes', 'count', 'ok', 'source', 'modeCapability', 'oversized', 'result',
      ...(blocked ? ['reason'] : [])])
    || value.version !== 1 || value.kind !== 'audit.sql_search' || !UUID.test(value.operationId)
    || !['completed', 'not_found', 'unconfirmed', 'blocked'].includes(value.status)
    || !auditMode(value.modeCapability) || typeof value.oversized !== 'boolean') fail('audit SQL search');
  if (value.status === 'completed') {
    if (!SHA.test(value.resultSha256) || !Number.isSafeInteger(value.resultBytes)
      || value.resultBytes < 0 || value.resultBytes > 17 * 1024 * 1024
      || !Number.isSafeInteger(value.count) || value.count < 0
      || typeof value.ok !== 'boolean' || !source(value.source)
      || value.modeCapability.effectiveMode !== 'vuln'
      || (value.oversized ? value.result !== null : !auditResult(value.result))) fail('audit SQL search');
  } else if (value.resultSha256 !== null || value.resultBytes !== 0 || value.count !== null
    || value.ok !== null || value.source !== null || value.result !== null || value.oversized
    || (blocked ? value.modeCapability.effectiveMode !== 'fixed' || typeof value.reason !== 'string'
      : value.modeCapability.effectiveMode !== 'vuln')) fail('audit SQL search');
  return value;
}

export async function decodeAuditSearchOperation(descriptor, value) {
  if (!descriptor || descriptor.status !== 'completed'
    || !exact(value, ['version', 'operationId', 'status', 'result', 'source', 'modeCapability'])
    || value.version !== 1 || value.operationId !== descriptor.operationId
    || value.status !== 'completed' || !auditMode(value.modeCapability)
    || !same(canonical(value.modeCapability), canonical(descriptor.modeCapability))
    || !source(value.source) || !same(canonical(value.source), canonical(descriptor.source))
    || !auditResult(value.result)) fail('audit SQL result');
  const raw = JSON.stringify(value.result);
  if (encoder.encode(raw).byteLength !== descriptor.resultBytes
    || value.result.count !== descriptor.count || value.result.ok !== descriptor.ok
    || await sha(JSON.stringify(canonical(value.result))) !== descriptor.resultSha256
    || (!descriptor.oversized && !same(canonical(value.result), canonical(descriptor.result)))) {
    fail('audit SQL result');
  }
  return Object.freeze({ ...value.result, oversized: descriptor.oversized });
}

export function decodeSystemHealth(value, turnMode, stopReason) {
  if (value == null) return null;
  const metrics = value.metrics;
  if (!adminMode(turnMode) || stopReason !== 'end_turn'
    || !exact(value, ['version', 'kind', 'scopeKey', 'metrics']) || value.version !== 1
    || value.kind !== 'system.health' || !SHA.test(value.scopeKey)
    || !exact(metrics, ['version', 'ok', 'hostname', 'platform', 'node', 'uptime_s',
      'loadavg', 'freemem_mb', 'totalmem_mb', 'ts', 'metricsSource', 'memorySource',
      'uptimeSource', 'loadSource'])
    || metrics.version !== 'secureshop-owned-system-metrics.v1' || metrics.ok !== true
    || !['hostname', 'platform', 'node', 'ts', 'metricsSource', 'memorySource',
      'uptimeSource', 'loadSource'].every(key => healthText(metrics[key]))
    || !Number.isSafeInteger(metrics.uptime_s) || metrics.uptime_s < 0
    || !(metrics.freemem_mb === null || Number.isSafeInteger(metrics.freemem_mb) && metrics.freemem_mb >= 0)
    || !(metrics.totalmem_mb === null || Number.isSafeInteger(metrics.totalmem_mb) && metrics.totalmem_mb >= 0)
    || (metrics.freemem_mb === null) !== (metrics.totalmem_mb === null)
    || (metrics.freemem_mb !== null && metrics.freemem_mb > metrics.totalmem_mb)
    || metrics.loadavg !== null || metrics.metricsSource !== 'owned-system-listener'
    || !['cgroup-v2', 'unavailable'].includes(metrics.memorySource)
    || metrics.uptimeSource !== 'listener-process' || metrics.loadSource !== 'unavailable'
    || (metrics.memorySource === 'cgroup-v2') !== (metrics.totalmem_mb !== null)
    || !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(metrics.ts)
    || Number.isNaN(Date.parse(metrics.ts))) fail('System health read');
  return Object.freeze({ ...metrics });
}

export function decodeSystemConfigDescriptor(value, turnMode, stopReason) {
  if (value == null) return null;
  if (!adminMode(turnMode) || stopReason !== 'end_turn'
    || !exact(value, ['version', 'kind', 'scopeKey', 'operationId', 'requestSha256', 'state', 'result'])
    || value.version !== 1 || value.kind !== 'system.config_read' || !SHA.test(value.scopeKey)
    || !UUID.test(value.operationId) || !SHA.test(value.requestSha256)
    || !['pending', 'unknown', 'not_executed', 'completed'].includes(value.state)
    || (value.state !== 'completed' && value.result !== null)) fail('System config read');
  const result = value.result;
  const validSize = size => Number.isSafeInteger(size) && size >= 0 && size <= 512 * 1024;
  const validPath = path => typeof path === 'string' && path.isWellFormed()
    && !path.includes('\0') && encoder.encode(path).byteLength <= 8192;
  if (value.state === 'completed' && !(exact(result, ['status']) && result.status === 'unavailable'
    || exact(result, ['status', 'ok', 'error']) && result.status === 'completed'
      && result.ok === false && typeof result.error === 'string'
    || exact(result, ['status', 'ok', 'input', 'sanitized', 'targetPath', 'size',
      'contentSha256', 'content', 'oversized']) && result.status === 'completed'
      && result.ok === true && result.oversized === false
      && validPath(result.input) && validPath(result.sanitized) && validPath(result.targetPath)
      && validSize(result.size) && typeof result.content === 'string'
      && result.content.isWellFormed() && encoder.encode(result.content).byteLength === result.size
      && SHA.test(result.contentSha256)
    || exact(result, ['status', 'ok', 'size', 'contentSha256', 'content', 'oversized'])
      && result.status === 'completed' && result.ok === true && result.oversized === true
      && result.content === null && validSize(result.size)
      && SHA.test(result.contentSha256))) fail('System config read');
  return value;
}

export async function decodeSystemConfigOperation(descriptor, value) {
  // The existing owned journal carries internal metadata in addition to this
  // projection. Read only the fields bound by the saved role-turn descriptor.
  if (!descriptor || !value || Object.getPrototypeOf(value) !== Object.prototype
    || !Object.hasOwn(value, 'operationId') || !Object.hasOwn(value, 'requestSha256')
    || !Object.hasOwn(value, 'state')
    || value.operationId !== descriptor.operationId
    || value.requestSha256 !== descriptor.requestSha256
    || !['pending', 'unknown', 'not_executed', 'completed', 'not_found'].includes(value.state)) {
    fail('System config result');
  }
  if (value.state !== 'completed') return Object.freeze({ state: value.state });
  if (descriptor.state !== 'completed') return Object.freeze({ state: 'unconfirmed' });
  if (!Object.hasOwn(value, 'receipt')) fail('System config result');
  const receipt = value.receipt, read = receipt?.readResult;
  if (!receipt || receipt.operationId !== descriptor.operationId
    || receipt.requestSha256 !== descriptor.requestSha256
    || !['completed', 'unavailable'].includes(receipt.status)) fail('System config result');
  if (descriptor.result.status === 'unavailable') {
    if (receipt.status !== 'unavailable') fail('System config result');
    return Object.freeze({ state: 'completed', kind: 'unavailable' });
  }
  if (receipt.status !== 'completed') fail('System config result');
  if (descriptor.result.ok === false) {
    if (read?.ok !== false || read.error !== descriptor.result.error) fail('System config result');
    return Object.freeze({ state: 'completed', kind: 'error', error: read.error });
  }
  if (read?.ok !== true || read.contentSha256 !== descriptor.result.contentSha256
    || read.size !== descriptor.result.size || typeof read.content !== 'string'
    || encoder.encode(read.content).byteLength !== read.size
    || await sha(read.content) !== read.contentSha256
    || (!descriptor.result.oversized && (read.content !== descriptor.result.content
      || read.input !== descriptor.result.input || read.sanitized !== descriptor.result.sanitized
      || read.targetPath !== descriptor.result.targetPath))) fail('System config result');
  return Object.freeze({ state: 'completed', kind: 'content', content: read.content,
    size: read.size, contentSha256: read.contentSha256, oversized: descriptor.result.oversized });
}
