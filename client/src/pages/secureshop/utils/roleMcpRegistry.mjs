import { normalizeSavedRegistryRequest, registryRequestHash } from '../pages/admin/mcpRegistryOperation.mjs';
import { sameRolePolicyMode } from './rolePolicyProposal.mjs';

const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const SHA = /^[a-f0-9]{64}$/;
const MAX_VERSION = 9007199254740991n;
const exact = (value, keys) => value && Object.getPrototypeOf(value) === Object.prototype
  && Object.keys(value).sort().join(',') === [...keys].sort().join(',');
const text = (value, limit) => typeof value === 'string' && value.isWellFormed()
  && !!value.trim() && !value.includes('\0') && new TextEncoder().encode(value).byteLength <= limit;
const invalid = () => { throw new Error('Saved MCP registry review invalid'); };
async function hash(value) {
  const bytes = await globalThis.crypto.subtle.digest('SHA-256',
    new TextEncoder().encode(JSON.stringify(value)));
  return [...new Uint8Array(bytes)].map(byte => byte.toString(16).padStart(2, '0')).join('');
}
function mode(value) {
  const expected = { version: 1, featureId: 'admin_assistant',
    policyVersion: 'owned-admin-read-and-confirmation-v1', effectiveMode: value?.effectiveMode,
    scope: { kind: 'launch_feature', id: 'admin_assistant' } };
  if (!['vuln', 'fixed'].includes(value?.effectiveMode)
    || !sameRolePolicyMode(value, expected)) invalid();
  return expected;
}

export function decodeMcpServerHeader(value) {
  if (!exact(value, ['provenance', 'id', 'name', 'transport', 'url', 'stdio_cmd',
    'schemaSha256', 'scenario', 'snapshotSha256'])
    || !['owned_registry', 'scenario'].includes(value.provenance)
    || typeof value.id !== 'string' || !UUID.test(value.id) || !text(value.name, 256)
    || typeof value.snapshotSha256 !== 'string' || !SHA.test(value.snapshotSha256)) invalid();
  if (value.provenance === 'owned_registry') {
    if (value.scenario !== null || !SHA.test(value.schemaSha256)
      || !['sse', 'streamable-http', 'stdio'].includes(value.transport)) invalid();
    try {
      normalizeSavedRegistryRequest({ version: 1, action: 'register',
        operationId: '00000000-0000-4000-8000-000000000001', expectedVersion: '0',
        name: value.name, transport: value.transport, url: value.url ?? '',
        stdio_cmd: value.stdio_cmd ?? '' });
    } catch { invalid(); }
    if (value.transport === 'stdio'
      ? value.url !== null || !text(value.stdio_cmd, 4096)
      : value.stdio_cmd !== null || !text(value.url, 4096)) invalid();
  } else if (value.transport !== null || value.url !== null || value.stdio_cmd !== null
    || !['rogue_registration', 'rug_pull'].includes(value.scenario)
    || !(value.schemaSha256 === null || SHA.test(value.schemaSha256))) invalid();
  return Object.freeze({ provenance: value.provenance, id: value.id, name: value.name,
    transport: value.transport, url: value.url, stdio_cmd: value.stdio_cmd,
    schemaSha256: value.schemaSha256, scenario: value.scenario,
    snapshotSha256: value.snapshotSha256 });
}

export async function decodeRoleMcpRegistryProposal(value) {
  if (value == null) return null;
  if (!exact(value, ['version', 'proposalId', 'choiceId', 'action', 'before', 'request',
    'scopeKey', 'modeCapability', 'registryMode', 'sourceSnapshotSha256',
    'requestSha256', 'proposalSha256'])
    || value.version !== 1 || typeof value.proposalId !== 'string' || !UUID.test(value.proposalId)
    || !['register', 'import', 'retire'].includes(value.action)
    || typeof value.scopeKey !== 'string' || !SHA.test(value.scopeKey)
    || !['vuln', 'fixed'].includes(value.registryMode)
    || typeof value.requestSha256 !== 'string' || !SHA.test(value.requestSha256)
    || typeof value.proposalSha256 !== 'string' || !SHA.test(value.proposalSha256)) invalid();
  let request;
  try { request = normalizeSavedRegistryRequest(value.request); } catch { invalid(); }
  if (request.operationId !== value.proposalId || request.action !== value.action
    || BigInt(request.expectedVersion) >= MAX_VERSION
    || await registryRequestHash(request) !== value.requestSha256) invalid();
  const before = value.before === null ? null : decodeMcpServerHeader(value.before);
  const selected = value.action === 'retire';
  if (selected && (typeof value.choiceId !== 'string' || !UUID.test(value.choiceId) || !before
    || before.provenance !== 'owned_registry' || before.name !== request.name)) invalid();
  if (!selected && value.choiceId !== null) invalid();
  if (value.action === 'import' && before) invalid();
  if (before) {
    if (before.provenance !== 'owned_registry' || before.name !== request.name
      || value.sourceSnapshotSha256 !== before.snapshotSha256) invalid();
    const { snapshotSha256, ...header } = before;
    if (await hash({ version: 1, scopeKey: value.scopeKey,
      registryVersion: request.expectedVersion, server: header }) !== snapshotSha256) invalid();
  } else if (value.sourceSnapshotSha256 !== null) invalid();
  const canonical = { version: 1, proposalId: value.proposalId, choiceId: value.choiceId,
    action: value.action, before, request, scopeKey: value.scopeKey,
    modeCapability: mode(value.modeCapability), registryMode: value.registryMode,
    sourceSnapshotSha256: value.sourceSnapshotSha256, requestSha256: value.requestSha256 };
  if (await hash(canonical) !== value.proposalSha256) invalid();
  return Object.freeze({ ...canonical, proposalSha256: value.proposalSha256 });
}

const version = value => typeof value === 'string' && /^(0|[1-9]\d{0,15})$/.test(value)
  && BigInt(value) <= MAX_VERSION;

export async function decodeRoleMcpDetail(value) {
  if (value == null) return null;
  if (!exact(value, ['version', 'scopeKey', 'registryVersion', 'server', 'schemaVersion',
    'tools', 'history', 'choiceId', 'oversized']) || value.version !== 1
    || typeof value.scopeKey !== 'string' || !SHA.test(value.scopeKey)
    || !(value.registryVersion === null || version(value.registryVersion))
    || !version(value.schemaVersion) || typeof value.choiceId !== 'string' || !UUID.test(value.choiceId)
    || typeof value.oversized !== 'boolean' || !Array.isArray(value.tools)
    || value.tools.length > 64 || !Array.isArray(value.history)
    || value.history.length > 288 || new TextEncoder().encode(JSON.stringify(value)).byteLength > 131072) invalid();
  const server = decodeMcpServerHeader(value.server);
  const { snapshotSha256, ...header } = server;
  if (await hash({ version: 1, scopeKey: value.scopeKey,
    registryVersion: value.registryVersion, server: header }) !== snapshotSha256) invalid();
  const names = new Set();
  const tools = value.tools.map(tool => {
    if (!exact(tool, ['name', 'description', 'inputSchema'])
      || !text(tool.name, 256) || names.has(tool.name)
      || typeof tool.description !== 'string' || !tool.description.isWellFormed()
      || tool.description.includes('\0') || !tool.inputSchema
      || Object.getPrototypeOf(tool.inputSchema) !== Object.prototype) invalid();
    names.add(tool.name);
    return Object.freeze({ name: tool.name, description: tool.description,
      inputSchema: JSON.parse(JSON.stringify(tool.inputSchema)) });
  });
  const history = value.history.map(item => {
    if (!exact(item, ['version', 'schemaSha256', 'observedAt'])
      || !version(item.version) || !SHA.test(item.schemaSha256)
      || !text(item.observedAt, 128) || !Number.isFinite(Date.parse(item.observedAt))) invalid();
    return Object.freeze({ ...item });
  });
  return Object.freeze({ version: 1, scopeKey: value.scopeKey,
    registryVersion: value.registryVersion, server, schemaVersion: value.schemaVersion,
    tools: Object.freeze(tools), history: Object.freeze(history),
    choiceId: value.choiceId, oversized: value.oversized });
}

export function decodeRegisteredMcpSetup(value, sessionId, requestId) {
  if (value == null) return null;
  if (!exact(value, ['version', 'kind', 'sessionId', 'requestId', 'scopeKey',
    'message', 'registeredModeCapability']) || value.version !== 1
    || value.kind !== 'registered_mcp_setup' || value.sessionId !== sessionId
    || value.requestId !== requestId || !UUID.test(sessionId || '')
    || !UUID.test(requestId || '') || typeof value.scopeKey !== 'string' || !SHA.test(value.scopeKey)
    || !text(value.message, 8192)) invalid();
  const projected = { version: 1, featureId: 'registered_mcp',
    policyVersion: 'registered-schema-approval-v1',
    effectiveMode: value.registeredModeCapability?.effectiveMode,
    scope: { kind: 'launch_feature', id: 'registered_mcp' } };
  if (!['vuln', 'fixed'].includes(projected.effectiveMode)
    || !sameRolePolicyMode(value.registeredModeCapability, projected)) invalid();
  return Object.freeze({ version: 1, kind: 'registered_mcp_setup', sessionId,
    requestId, scopeKey: value.scopeKey, message: value.message,
    registeredModeCapability: projected });
}
