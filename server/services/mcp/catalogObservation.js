'use strict';

const protocol = require('./protocolContext');

const VERSION = 'mcp-catalog-observation.v1';
const CAPABILITY = 'mcp-owned-catalog-observation.v1';
const catalogs = new WeakMap();
const results = new WeakMap();
const witnesses = new WeakSet();
const witnessBindings = new WeakMap();
const issued = new WeakSet();

function deepFreeze(value) {
  if (!value || typeof value !== 'object' || Object.isFrozen(value)) return value;
  for (const child of Object.values(value)) deepFreeze(child);
  return Object.freeze(value);
}

function snapshotCatalog(value) {
  if (!Array.isArray(value)) throw new TypeError('MCP SDK tools/list must return an array');
  let encoded;
  try { encoded = JSON.stringify(value); } catch { throw new TypeError('MCP SDK catalog must be JSON serializable'); }
  if (typeof encoded !== 'string' || Buffer.byteLength(encoded) > 256 * 1024) {
    throw new TypeError('MCP SDK catalog is invalid or too large');
  }
  const snapshot = JSON.parse(encoded);
  if (!Array.isArray(snapshot)) throw new TypeError('MCP SDK catalog is invalid');
  return deepFreeze(snapshot);
}

function validCatalog(value) {
  if (!Array.isArray(value) || value.length < 2) return false;
  const names = new Set();
  for (const tool of value) {
    if (!tool || typeof tool !== 'object' || Array.isArray(tool)
        || typeof tool.name !== 'string' || !tool.name.trim()
        || typeof tool.description !== 'string' || !tool.description.trim()
        || names.has(tool.name)) return false;
    names.add(tool.name);
  }
  return true;
}

function captureSdkCatalog(value, sessionId, ownedScope = null) {
  const state = protocol.requireProtocolContext(sessionId);
  if (!state || state.retired || state.surface !== 'chat') {
    throw Object.assign(new Error('Current MCP chat catalog invocation is required'),
      { code: 'MCP_PROTOCOL_CONTEXT_REQUIRED' });
  }
  const catalog = snapshotCatalog(value);
  const ownerId = Number(String(state.ownerId));
  const generation = protocol._internals.normalizeGeneration(state.execution);
  const scope = ownedScope && ownedScope.platformOwnerId === ownerId
    && Number.isSafeInteger(ownedScope.platformSessionId) && ownedScope.platformSessionId > 0
    && String(ownedScope.generation) === generation
    && /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(ownedScope.targetId || '')
    ? Object.freeze({ targetId: ownedScope.targetId, platformOwnerId: ownerId,
      platformSessionId: ownedScope.platformSessionId, generation }) : null;
  catalogs.set(catalog, Object.freeze({
    version: VERSION,
    sessionId: state.sessionId,
    ownerKey: state.execution.ownerKey,
    runId: state.execution.runId,
    generation,
    scope,
    surface: state.surface,
    invocationId: state.invocationId,
    catalogSha256: protocol.canonicalDigest(catalog),
    toolCount: catalog.length,
  }));
  return catalog;
}

function adoptCatalog(catalog, result) {
  const record = catalog && typeof catalog === 'object' ? catalogs.get(catalog) : null;
  if (!record || !result || typeof result !== 'object' || Array.isArray(result)
      || protocol.canonicalDigest(catalog) !== record.catalogSha256
      || result.catalog !== catalog || result.tool !== 'list_tools'
      || !result.args || Object.keys(result.args).length !== 0
      || typeof result.output !== 'string' || !result.output.trim()) return result;
  results.set(result, Object.freeze({ invocation: record,
    outputSha256: protocol.canonicalDigest(result.output) }));
  return result;
}

function witnessFor({ result, scope, execution } = {}) {
  const bound = result && typeof result === 'object' ? results.get(result) : null;
  const record = bound?.invocation;
  if (!record || !record.scope || issued.has(record) || !validCatalog(result.catalog)
      || typeof result.output !== 'string' || !result.output.trim()
      || protocol.canonicalDigest(result.catalog) !== record.catalogSha256
      || protocol.canonicalDigest(result.output) !== bound.outputSha256
      || record.sessionId !== `mcp_${scope?.platformOwnerId}`
      || record.ownerKey !== execution?.ownerKey || record.runId !== execution?.runId
      || record.generation !== String(execution?.durableGeneration ?? execution?.generation)
      || record.scope.targetId !== scope?.targetId
      || record.scope.platformOwnerId !== scope?.platformOwnerId
      || record.scope.platformSessionId !== scope?.platformSessionId
      || String(scope?.generation) !== record.generation
      || !Number.isSafeInteger(scope?.platformOwnerId) || scope.platformOwnerId < 1
      || !Number.isSafeInteger(scope?.platformSessionId) || scope.platformSessionId < 1
      || !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(scope?.targetId || '')) return null;
  const witness = deepFreeze({
    version: VERSION,
    targetId: record.scope.targetId,
    platformOwnerId: record.scope.platformOwnerId,
    platformSessionId: record.scope.platformSessionId,
    sessionId: record.sessionId,
    ownerKey: record.ownerKey,
    runId: record.runId,
    generation: record.generation,
    surface: record.surface,
    invocationId: record.invocationId,
    catalogSha256: record.catalogSha256,
    outputSha256: bound.outputSha256,
    toolCount: record.toolCount,
    toolNames: result.catalog.map(tool => tool.name),
  });
  issued.add(record);
  witnesses.add(witness);
  witnessBindings.set(witness, Object.freeze({ result, record }));
  return witness;
}

function isTrustedWitness(value) { return witnesses.has(value); }
function matchesWitness(result, witness) {
  const binding = witnessBindings.get(witness);
  const bound = result && typeof result === 'object' ? results.get(result) : null;
  return Boolean(binding && binding.result === result && bound?.invocation === binding.record);
}

module.exports = { VERSION, CAPABILITY, captureSdkCatalog, adoptCatalog, witnessFor,
  isTrustedWitness, matchesWitness, _internals: { validCatalog, snapshotCatalog } };
