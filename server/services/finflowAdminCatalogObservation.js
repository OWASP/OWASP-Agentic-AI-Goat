'use strict';

const { createHash } = require('node:crypto');

const VERSION = 'finflow-admin-catalog-observation.v2';
const ACTION = 'admin_catalog_observation';

function stableJson(value) {
  if (Array.isArray(value)) return `[${value.map(stableJson).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${stableJson(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

function digest(value) {
  return createHash('sha256').update(typeof value === 'string' ? value : stableJson(value)).digest('hex');
}

function deepFreeze(value) {
  if (!value || typeof value !== 'object' || Object.isFrozen(value)) return value;
  for (const child of Object.values(value)) deepFreeze(child);
  return Object.freeze(value);
}

function snapshotCatalog(value) {
  if (!Array.isArray(value) || value.length !== 8) {
    throw new TypeError('FinFlow administrative catalog must contain exactly eight tools');
  }
  let encoded;
  try { encoded = JSON.stringify(value); } catch { throw new TypeError('FinFlow administrative catalog must be JSON serializable'); }
  if (typeof encoded !== 'string' || Buffer.byteLength(encoded) > 128 * 1024) {
    throw new TypeError('FinFlow administrative catalog is invalid or too large');
  }
  const snapshot = JSON.parse(encoded);
  const names = new Set();
  for (const definition of snapshot) {
    const tool = definition?.function;
    if (definition?.type !== 'function' || !tool || typeof tool !== 'object'
        || typeof tool.name !== 'string' || !/^admin_[a-z0-9_]+$/.test(tool.name)
        || typeof tool.description !== 'string' || !tool.description.trim()
        || !tool.parameters || typeof tool.parameters !== 'object' || Array.isArray(tool.parameters)
        || names.has(tool.name)) {
      throw new TypeError('FinFlow administrative catalog contains an invalid tool definition');
    }
    names.add(tool.name);
  }
  return deepFreeze(snapshot);
}

function executionIdentity(execution) {
  if (!execution || typeof execution.check !== 'function') return null;
  const generation = String(execution?.durableGeneration ?? execution?.generation ?? '');
  let owner;
  try { owner = JSON.parse(execution.ownerKey); } catch { return null; }
  if (!Array.isArray(owner) || owner.length !== 2 || owner[0] !== 'FinFlow'
      || typeof owner[1] !== 'string' || !owner[1]
      || typeof execution.runId !== 'string'
      || !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(execution.runId)
      || !/^(0|[1-9][0-9]*)$/.test(generation)
      || !Number.isSafeInteger(Number(generation))) return null;
  return Object.freeze({ ownerKey: execution.ownerKey, runId: execution.runId, generation });
}

function createFinflowAdminCatalogAuthority(canonicalSchemas, { canonicalDecisionCatalog, policySnapshot } = {}) {
  const catalog = snapshotCatalog(canonicalSchemas);
  const adminCatalogSha256 = digest(catalog);
  const expectedDecisionCatalog = canonicalDecisionCatalog
    && require('../agent-runtime/finflowDecisions').finflowCatalogContract(canonicalDecisionCatalog);
  const currentPolicy = require('./finflowCustomerPolicy').customerPolicySnapshot();
  if (!expectedDecisionCatalog || policySnapshot !== currentPolicy) {
    throw new TypeError('Canonical FinFlow decision catalog and customer policy are required');
  }
  const toolNames = Object.freeze(catalog.map(definition => definition.function.name));
  const observations = new WeakMap();
  const consumedDecisionEvents = new WeakSet();
  const issued = new WeakSet();
  const witnesses = new WeakSet();
  const witnessBindings = new WeakMap();

  async function observe({ execution, decision, decisionMetadata } = {}) {
    await execution?.check?.();
    const identity = executionIdentity(execution);
    const decisionBinding = require('../agent-runtime/finflowDecisions')
      .trustedFinflowDecisionBinding(decision, decisionMetadata, execution);
    const verifiedPolicy = decisionBinding && require('./finflowAdminPolicyEvidence')
      .verifyFinflowPlannerPolicy({ execution, policySnapshot: decisionBinding.policySnapshot });
    if (!identity || decision?.action !== ACTION || decision?.params === null
        || typeof decision?.params !== 'object' || Array.isArray(decision.params)
        || Object.keys(decision.params).length !== 0
        || consumedDecisionEvents.has(decisionMetadata)
        || !decisionBinding || !verifiedPolicy
        || decisionBinding.policySnapshot !== policySnapshot
        || decisionBinding.catalogSha256 !== expectedDecisionCatalog.sha256
        || stableJson(decisionBinding.catalogProjection) !== stableJson(expectedDecisionCatalog.projection)
        || verifiedPolicy.ownerId !== String(execution.ownerId)
        || verifiedPolicy.runId !== identity.runId
        || verifiedPolicy.generation !== identity.generation
        || verifiedPolicy.requestSha256 !== decisionBinding.requestSha256
        || verifiedPolicy.sessionRole !== 'customer') {
      throw Object.assign(new Error('Current model-selected FinFlow administrative catalog action is required'),
        { code: 'FINFLOW_ADMIN_CATALOG_DECISION_REQUIRED' });
    }
    consumedDecisionEvents.add(decisionMetadata);
    const output = catalog.map(definition => ({ name: definition.function.name,
      description: definition.function.description }));
    const observation = deepFreeze({ version: VERSION, action: ACTION, catalog, output });
    observations.set(observation, Object.freeze({ ...identity, execution, action: ACTION,
      decisionBinding, verifiedPolicy, decisionCatalogSha256: decisionBinding.catalogSha256,
      adminCatalogSha256, outputSha256: digest(output), toolCount: toolNames.length,
      provider: decisionMetadata.provider, model: decisionMetadata.model }));
    await execution?.check?.();
    return observation;
  }

  async function witnessFor({ observation, execution } = {}) {
    await execution?.check?.();
    const record = observation && typeof observation === 'object' ? observations.get(observation) : null;
    const identity = executionIdentity(execution);
    if (!record || !identity || issued.has(observation)
        || observation.action !== ACTION || observation.catalog !== catalog
        || digest(observation.catalog) !== record.adminCatalogSha256
        || digest(observation.output) !== record.outputSha256
        || record.execution !== execution
        || record.ownerKey !== identity.ownerKey || record.runId !== identity.runId
        || record.generation !== identity.generation) return null;
    const witness = deepFreeze({ version: VERSION, action: ACTION,
      ownerKey: record.ownerKey, runId: record.runId, generation: record.generation,
      policyVersion: record.verifiedPolicy.policyVersion,
      policySha256: record.verifiedPolicy.policySha256,
      requestSha256: record.verifiedPolicy.requestSha256,
      decisionCatalogSha256: record.decisionCatalogSha256,
      adminCatalogSha256: record.adminCatalogSha256,
      outputSha256: record.outputSha256, provider: record.provider, model: record.model,
      toolCount: record.toolCount, toolNames: [...toolNames] });
    issued.add(observation);
    witnesses.add(witness);
    witnessBindings.set(witness, Object.freeze({ observation, record }));
    await execution?.check?.();
    return witness;
  }

  function isTrustedWitness(value) { return witnesses.has(value); }
  function matchesWitness(observation, witness, execution) {
    const binding = witnessBindings.get(witness);
    const identity = executionIdentity(execution);
    return Boolean(binding && identity && binding.observation === observation
      && binding.record === observations.get(observation)
      && binding.record.execution === execution
      && binding.record.ownerKey === identity.ownerKey
      && binding.record.runId === identity.runId
      && binding.record.generation === identity.generation);
  }

  return Object.freeze({ catalog, observe, witnessFor, isTrustedWitness, matchesWitness });
}

module.exports = { VERSION, ACTION, createFinflowAdminCatalogAuthority,
  _internals: { snapshotCatalog, stableJson, digest, executionIdentity } };
