'use strict';

const { createHash } = require('node:crypto');
const { normalizeRegistryRequest, registryRequestDigest } = require('./secureshopMcpRegistryContract');
const data = require('./secureshopOwnedMcpInvocationContract');
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const SHA = /^[a-f0-9]{64}$/;
const MAX_VERSION = 9007199254740991n;
const PLACEHOLDER = '00000000-0000-4000-8000-000000000001';
const exact = (v, keys) => v && Object.getPrototypeOf(v) === Object.prototype
  && Object.keys(v).sort().join(',') === [...keys].sort().join(',');
const fail = () => Object.assign(new Error('MCP registry proposal unavailable'), { code: 'ROLE_MCP_REGISTRY_PROPOSAL_INVALID' });
const text = (v, max) => typeof v === 'string' && v.isWellFormed() && !!v.trim()
  && !v.includes('\0') && Buffer.byteLength(v) <= max;
const version = v => typeof v === 'string' && /^(0|[1-9]\d{0,15})$/.test(v) && BigInt(v) <= MAX_VERSION;
const hash = v => createHash('sha256').update(JSON.stringify(v)).digest('hex');

function mode(v) {
  if (!exact(v, ['version', 'featureId', 'policyVersion', 'effectiveMode', 'scope'])
      || v.version !== 1 || v.featureId !== 'admin_assistant'
      || v.policyVersion !== 'owned-admin-read-and-confirmation-v1'
      || !['vuln', 'fixed'].includes(v.effectiveMode)
      || !exact(v.scope, ['kind', 'id']) || v.scope.kind !== 'launch_feature'
      || v.scope.id !== 'admin_assistant') throw fail();
  return { version: 1, featureId: v.featureId, policyVersion: v.policyVersion,
    effectiveMode: v.effectiveMode, scope: { kind: v.scope.kind, id: v.scope.id } };
}
function server(value, withDigest = true) {
  const keys = ['provenance', 'id', 'name', 'transport', 'url', 'stdio_cmd', 'schemaSha256', 'scenario'];
  if (!exact(value, [...keys, ...(withDigest ? ['snapshotSha256'] : [])])
      || !['owned_registry', 'scenario'].includes(value.provenance) || !UUID.test(value.id || '')
      || !text(value.name, 256) || (withDigest && !SHA.test(value.snapshotSha256 || ''))) throw fail();
  if (value.provenance === 'owned_registry') {
    if (value.scenario !== null || !SHA.test(value.schemaSha256 || '')) throw fail();
    normalizeRegistryCandidate('register', { name: value.name, transport: value.transport,
      url: value.url ?? '', stdio_cmd: value.stdio_cmd ?? '' });
    if (value.transport === 'stdio' ? value.url !== null || !text(value.stdio_cmd, 4096)
      : value.stdio_cmd !== null || !text(value.url, 4096)) throw fail();
  } else if (value.transport !== null || value.url !== null || value.stdio_cmd !== null
      || !['rogue_registration', 'rug_pull'].includes(value.scenario)
      || !(value.schemaSha256 === null || SHA.test(value.schemaSha256 || ''))) throw fail();
  return { provenance: value.provenance, id: value.id, name: value.name,
    transport: value.transport, url: value.url, stdio_cmd: value.stdio_cmd,
    schemaSha256: value.schemaSha256, scenario: value.scenario,
    ...(withDigest ? { snapshotSha256: value.snapshotSha256 } : {}) };
}
function normalizeRegistryCandidate(action, value) {
  const keys = action === 'register' ? ['name', 'transport', 'url', 'stdio_cmd']
    : action === 'import' ? ['xml_url'] : action === 'retire' ? ['name'] : null;
  if (!keys || !exact(value, keys)) throw fail();
  const request = normalizeRegistryRequest({ version: 1, action, operationId: PLACEHOLDER,
    expectedVersion: '0', ...value });
  return Object.fromEntries(keys.map(key => [key, request[key]]));
}
function id(source, origin) {
  if (!exact(source, ['sessionId', 'requestId']) || !UUID.test(source.sessionId || '')
      || !UUID.test(source.requestId || '') || !exact(origin, ['step', 'callId'])
      || !Number.isInteger(origin.step) || origin.step < 1 || origin.step > 4
      || !text(origin.callId, 128)) throw fail();
  const h = hash(['admin-mcp-registry-proposal-v1', source.sessionId, source.requestId, origin.step, origin.callId]);
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-5${h.slice(13, 16)}-8${h.slice(17, 20)}-${h.slice(20, 32)}`;
}
function registryServerSnapshotDigest({ scopeKey, registryVersion, server: value }) {
  if (!SHA.test(scopeKey || '') || !(registryVersion === null || version(registryVersion))) throw fail();
  return hash({ version: 1, scopeKey, registryVersion, server: server(value, false) });
}
function publicValue(value) {
  const request = normalizeRegistryRequest(value.request);
  return { version: 1, proposalId: value.proposalId, choiceId: value.choiceId, action: value.action,
    before: value.before === null ? null : server(value.before), request,
    scopeKey: value.scopeKey, modeCapability: mode(value.modeCapability), registryMode: value.registryMode,
    sourceSnapshotSha256: value.sourceSnapshotSha256, requestSha256: value.requestSha256 };
}
function registryProposalDigest(value) { return hash(publicValue(value)); }
function validate(value, source) {
  if (!exact(value, ['version', 'proposalId', 'choiceId', 'action', 'before', 'request', 'scopeKey',
    'modeCapability', 'registryMode', 'sourceSnapshotSha256', 'requestSha256', 'proposalSha256', 'origin'])
      || value.version !== 1 || value.proposalId !== id(source, value.origin)
      || !['register', 'import', 'retire'].includes(value.action)
      || !SHA.test(value.scopeKey || '') || !['vuln', 'fixed'].includes(value.registryMode)
      || !SHA.test(value.proposalSha256 || '')) throw fail();
  const p = publicValue(value);
  if (p.request.operationId !== p.proposalId || p.request.action !== p.action
      || !version(p.request.expectedVersion) || BigInt(p.request.expectedVersion) >= MAX_VERSION
      || p.requestSha256 !== registryRequestDigest(p.request)) throw fail();
  if (p.action === 'retire' || (p.action === 'register' && p.before !== null)) {
    if ((p.action === 'retire' ? !UUID.test(p.choiceId || '') : p.choiceId !== null)
        || !p.before || p.before.provenance !== 'owned_registry'
        || p.before.name !== p.request.name || p.sourceSnapshotSha256 !== p.before.snapshotSha256) throw fail();
    const { snapshotSha256, ...header } = p.before;
    if (snapshotSha256 !== registryServerSnapshotDigest({ scopeKey: p.scopeKey,
      registryVersion: p.request.expectedVersion, server: header })) throw fail();
  } else if (p.choiceId !== null || p.before !== null || p.sourceSnapshotSha256 !== null) throw fail();
  if (hash(p) !== value.proposalSha256) throw fail();
  return { ...p, proposalSha256: value.proposalSha256,
    origin: { step: value.origin.step, callId: value.origin.callId } };
}
function create({ source, origin, action, selected, before, candidate, expectedVersion,
  scopeKey, modeCapability, registryMode }) {
  if (action === 'retire' ? candidate !== null || !selected
    : selected !== null || (action !== 'register' && before !== null)) throw fail();
  const proposalId = id(source, origin);
  const request = normalizeRegistryRequest({ version: 1, action, operationId: proposalId,
    expectedVersion, ...normalizeRegistryCandidate(action, action === 'retire' ? { name: before?.name } : candidate) });
  const p = { version: 1, proposalId, choiceId: selected?.choiceId ?? null, action, before, request,
    scopeKey, modeCapability, registryMode, sourceSnapshotSha256: selected?.snapshotSha256 ?? before?.snapshotSha256 ?? null,
    requestSha256: registryRequestDigest(request), origin };
  p.proposalSha256 = registryProposalDigest(p);
  return validate(p, source);
}
function project(value, source) { const { origin, ...p } = validate(value, source); return p; }
module.exports = { createRoleMcpRegistryProposal: create, validateRoleMcpRegistryProposal: validate,
  projectRoleMcpRegistryProposal: project, registryProposalDigest, normalizeRegistryCandidate,
  registryServerSnapshotDigest, normalizeRegistryServer: server, boundedRegistryData: data.bounded };
