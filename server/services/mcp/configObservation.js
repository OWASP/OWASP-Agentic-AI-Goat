'use strict';

const crypto = require('node:crypto');

const SNAPSHOT_VERSION = 'config-snapshot.v1';
const SHA256_RE = /^[a-f0-9]{64}$/;
const UUID_RE = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i;
const SESSION_RE = /^mcp_([1-9][0-9]*)$/;
const SOURCE_IDS = new Set(['environment', 'credentials']);
// Independently mirror the runner's public receipt ceilings. The observer does
// not trust transport JSON merely because the producer also enforces limits.
const MAX_SOURCE_BYTES = 65_536;
const MAX_OUTPUT_BYTES = 131_136;
const MAX_RECEIPT_BYTES = 64 * 1024;
const MAX_CREDENTIALS = 64;
const MAX_CREDENTIAL_NAME_BYTES = 256;

function fail(code, message) {
  const error = new Error(message);
  error.code = code;
  throw error;
}

function invalid(message) {
  fail('CONFIG_OBSERVATION_INVALID', message);
}

function digest(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function isAbort(error, signal) {
  return signal?.aborted || error?.name === 'AbortError' || error?.code === 'ABORT_ERR';
}

function validGeneration(value) {
  return (Number.isSafeInteger(value) && value >= 0)
    || (typeof value === 'string' && /^(0|[1-9][0-9]*)$/.test(value));
}

function immutableCopy(value) {
  if (Array.isArray(value)) return Object.freeze(value.map(immutableCopy));
  if (value && typeof value === 'object') {
    return Object.freeze(Object.fromEntries(
      Object.entries(value).map(([key, item]) => [key, immutableCopy(item)]),
    ));
  }
  return value;
}

function validateScope(sessionId, execution) {
  const session = SESSION_RE.exec(String(sessionId || ''));
  if (!session) fail('INVALID_CONFIG_SESSION', 'a canonical MCP session identity is required');
  if (execution === undefined) return null;
  if (!execution || typeof execution !== 'object' || Array.isArray(execution)) {
    fail('INVALID_CONFIG_EXECUTION', 'execution must be a provenance object when supplied');
  }

  let owner;
  try { owner = JSON.parse(execution.ownerKey); } catch {
    fail('INVALID_CONFIG_EXECUTION', 'execution ownerKey must be canonical JSON');
  }
  const canonicalOwner = JSON.stringify(['MCP', session[1]]);
  if (!Array.isArray(owner) || owner.length !== 2 || owner[0] !== 'MCP'
      || String(owner[1]) !== session[1] || execution.ownerKey !== canonicalOwner) {
    fail('INVALID_CONFIG_EXECUTION', 'execution owner does not match the MCP session');
  }
  if (!UUID_RE.test(String(execution.runId || ''))
      || !validGeneration(execution.generation)
      || !validGeneration(execution.durableGeneration)
      || typeof execution.check !== 'function') {
    fail('INVALID_CONFIG_EXECUTION', 'execution provenance is incomplete');
  }
  return Object.freeze({
    sessionId: String(sessionId),
    ownerKey: canonicalOwner,
    runId: String(execution.runId),
    generation: execution.generation,
    durableGeneration: execution.durableGeneration,
  });
}

function validateRange(range, totalBytes, label) {
  if (!range || typeof range !== 'object'
      || !Number.isSafeInteger(range.startByte) || !Number.isSafeInteger(range.endByte)
      || range.startByte < 0 || range.endByte <= range.startByte || range.endByte > totalBytes) {
    invalid(`${label} has an invalid UTF-8 byte range`);
  }
  return { startByte: range.startByte, endByte: range.endByte };
}

function sliceUtf8(buffer, range, label) {
  const value = buffer.subarray(range.startByte, range.endByte);
  if (!Buffer.from(value.toString('utf8'), 'utf8').equals(value)) {
    invalid(`${label} range splits invalid UTF-8 bytes`);
  }
  return value;
}

function validateSnapshot(snapshot, expectedInvocationId) {
  if (!snapshot || snapshot.ok !== true || typeof snapshot.output !== 'string'
      || snapshot.invocationId !== expectedInvocationId) {
    invalid('runner returned an invalid config snapshot envelope');
  }
  const observation = snapshot.observation;
  const output = Buffer.from(snapshot.output, 'utf8');
  let receiptBytes;
  try { receiptBytes = Buffer.byteLength(JSON.stringify(observation), 'utf8'); } catch {
    invalid('runner config observation is not serializable');
  }
  if (!observation || observation.version !== SNAPSHOT_VERSION
      || !SHA256_RE.test(String(observation.outputSha256 || ''))
      || observation.outputSha256 !== digest(output)
      || !Number.isSafeInteger(observation.outputBytes)
      || observation.outputBytes !== output.length || output.length === 0 || output.length > MAX_OUTPUT_BYTES
      || !Number.isSafeInteger(receiptBytes) || receiptBytes > MAX_RECEIPT_BYTES
      || !Array.isArray(observation.sources) || observation.sources.length !== SOURCE_IDS.size
      || !Array.isArray(observation.credentials) || observation.credentials.length === 0
      || observation.credentials.length > MAX_CREDENTIALS) {
    invalid('runner config observation does not match its output');
  }

  const sources = new Map();
  for (const source of observation.sources) {
    if (!source || !SOURCE_IDS.has(source.id) || sources.has(source.id)
        || !SHA256_RE.test(String(source.sha256 || '')) || !Number.isSafeInteger(source.bytes)
        || source.bytes < 1 || source.bytes > MAX_SOURCE_BYTES) {
      invalid('runner returned an invalid or duplicate config source');
    }
    const range = validateRange(source.range, output.length, `source ${source.id}`);
    const bytes = sliceUtf8(output, range, `source ${source.id}`);
    if (source.bytes !== bytes.length || source.sha256 !== digest(bytes)) {
      invalid(`source ${source.id} digest does not match output`);
    }
    sources.set(source.id, range);
  }
  if (sources.size !== SOURCE_IDS.size || [...SOURCE_IDS].some(id => !sources.has(id))) {
    invalid('runner config observation must attest both config sources exactly once');
  }

  const credentialNames = new Set();
  for (const credential of observation.credentials) {
    if (!credential || typeof credential.name !== 'string' || credential.name.length === 0
        || Buffer.byteLength(credential.name, 'utf8') > MAX_CREDENTIAL_NAME_BYTES
        || credentialNames.has(credential.name) || !SOURCE_IDS.has(credential.source)
        || !SHA256_RE.test(String(credential.valueSha256 || ''))
        || !Number.isSafeInteger(credential.valueBytes)) {
      invalid('runner returned invalid credential provenance');
    }
    const sourceRange = sources.get(credential.source);
    if (!sourceRange) invalid('credential names an absent source');
    const range = validateRange(credential.range, output.length, `credential ${credential.name}`);
    if (range.startByte < sourceRange.startByte || range.endByte > sourceRange.endByte) {
      invalid('credential range is outside its declared source');
    }
    const bytes = sliceUtf8(output, range, `credential ${credential.name}`);
    if (credential.valueBytes !== bytes.length || credential.valueSha256 !== digest(bytes)) {
      invalid(`credential ${credential.name} digest does not match output`);
    }
    credentialNames.add(credential.name);
  }
  return immutableCopy(observation);
}

/**
 * Authenticate runner-produced config bytes for Judge use. This binds only
 * invocation provenance. The runner's current shared filesystem remains a
 * separate isolation boundary and is not made owner-private by this helper.
 */
function createConfigObserver({ readSnapshot } = {}) {
  if (typeof readSnapshot !== 'function') throw new TypeError('readSnapshot is required');
  const registrations = new WeakMap();

  return Object.freeze({
    async observe({ sessionId, execution } = {}) {
      const scope = validateScope(sessionId, execution);
      const invocationId = crypto.randomUUID();
      if (scope) await execution.check();
      let snapshot;
      try {
        snapshot = await readSnapshot(String(sessionId), invocationId, { signal: execution?.signal });
      } catch (error) {
        if (isAbort(error, execution?.signal)) throw error;
        fail('CONFIG_SNAPSHOT_UNAVAILABLE', 'runner config snapshot is unavailable');
      }
      if (scope) await execution.check();
      if (!snapshot || snapshot.ok !== true) {
        fail('CONFIG_SNAPSHOT_UNAVAILABLE', 'runner config snapshot is unavailable');
      }
      const observation = validateSnapshot(snapshot, invocationId);
      if (!scope) return Object.freeze({ output: snapshot.output, observation, token: null });

      const token = Object.freeze(Object.create(null));
      registrations.set(token, Object.freeze({
        ...scope, invocationId, outputSha256: observation.outputSha256,
      }));
      return Object.freeze({ output: snapshot.output, observation, token });
    },

    verify({ token, output, sessionId, execution } = {}) {
      if ((!token || typeof token !== 'object') || typeof output !== 'string') return false;
      const registered = registrations.get(token);
      if (!registered) return false;
      let scope;
      try { scope = validateScope(sessionId, execution); } catch { return false; }
      return Boolean(scope)
        && ['sessionId', 'ownerKey', 'runId', 'generation', 'durableGeneration']
          .every(key => registered[key] === scope[key])
        && digest(Buffer.from(output, 'utf8')) === registered.outputSha256;
    },
  });
}

let singleton;
function getConfigObserver() {
  if (!singleton) {
    const client = require('./sandboxRunnerClient');
    singleton = createConfigObserver({ readSnapshot: client.configSnapshot });
  }
  return singleton;
}

module.exports = { createConfigObserver, getConfigObserver, SNAPSHOT_VERSION };
