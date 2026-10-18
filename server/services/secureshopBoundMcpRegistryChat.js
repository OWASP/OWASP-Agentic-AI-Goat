'use strict';

const { createHash } = require('node:crypto');
const C = require('./secureshopRoleMcpRegistryProposal');
const { createLaunchScope } = require('./secureshopConversationBinding');
const fail = code => Object.assign(new Error('MCP registry conversation unavailable'), { code });
const exact = (v, keys) => v && Object.getPrototypeOf(v) === Object.prototype
  && Object.keys(v).sort().join(',') === [...keys].sort().join(',');
const version = v => typeof v === 'string' && /^(0|[1-9]\d{0,15})$/.test(v)
  && BigInt(v) <= 9007199254740991n;
const SHA = /^[a-f0-9]{64}$/;
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const scopeDigest = context => createHash('sha256').update(JSON.stringify(createLaunchScope(context.scope))).digest('hex');
const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);

// This adapter only reads persisted discovery while preparing a proposal.
// Registry fetch/process effects and their uncertainty remain in the existing service.
function createBoundMcpRegistryChat({ admin, getRegistry } = {}) {
  if (['mcpServers', 'mcpTools', 'mcpHistory'].some(k => typeof admin?.[k] !== 'function')
      || typeof getRegistry !== 'function') throw new TypeError('MCP registry chat dependencies required');
  async function registry() {
    const value = await getRegistry();
    if (value == null) return null;
    if (!['vuln', 'fixed'].includes(value.mode)
        || ['mutate', 'read'].some(k => typeof value.service?.[k] !== 'function')) throw fail('MCP_CHAT_UNAVAILABLE');
    return { service: value.service, mode: value.mode };
  }
  async function read(context, configured) {
    const value = await admin.mcpServers(context), scopeKey = scopeDigest(context);
    const ready = value?.registry_administration?.ready === true;
    const head = ready ? value.registry_administration.version : null;
    if (!Array.isArray(value?.servers) || value.servers.length > 34
        || (ready && (!version(head) || value.registry_administration.scopeKey !== scopeKey))) throw fail('MCP_CHAT_STATE_INVALID');
    const servers = value.servers.map(row => {
      const owned = row.provenance === 'owned_registry';
      if (!owned && row.provenance !== undefined) throw fail('MCP_CHAT_STATE_INVALID');
      const header = C.normalizeRegistryServer({ provenance: owned ? 'owned_registry' : 'scenario',
        id: row.id, name: row.name, transport: owned ? row.transport : null,
        url: owned ? row.url : null, stdio_cmd: owned ? row.stdio_cmd : null,
        schemaSha256: row.last_schema_hash, scenario: owned ? null : row.trust_scenario }, false);
      if (owned && (!ready || row.status !== 'registered')) throw fail('MCP_CHAT_STATE_INVALID');
      if (!owned && row.status !== 'discovered') throw fail('MCP_CHAT_STATE_INVALID');
      return { ...header, snapshotSha256: C.registryServerSnapshotDigest({ scopeKey,
        registryVersion: head, server: header }) };
    }).sort((a, b) => a.provenance.localeCompare(b.provenance) || a.name.localeCompare(b.name) || a.id.localeCompare(b.id));
    if (new Set(servers.map(s => `${s.provenance}:${s.id}`)).size !== servers.length
        || new Set(servers.map(s => `${s.provenance}:${s.name}`)).size !== servers.length) throw fail('MCP_CHAT_STATE_INVALID');
    return { version: 1, scopeKey, registryVersion: head, registryReady: ready && !!configured,
      registryMode: configured?.mode ?? null, servers };
  }
  async function snapshot({ context: raw }) {
    const context = structuredClone(raw), configured = await registry();
    const before = await read(context, configured), after = await read(context, configured);
    // Heads only advance. A second completed read rejects mixed head/entry
    // observations from the existing overlay's independent SELECTs.
    if (!same(before, after)) throw fail('MCP_CHOICE_STALE');
    return after;
  }
  function selectedServer(state, selected) {
    if (!exact(selected, ['choiceId', 'id', 'provenance', 'snapshotSha256'])
        || !UUID.test(selected.choiceId || '')) throw fail('MCP_CHOICE_STALE');
    const found = state.servers.find(s => s.id === selected.id && s.provenance === selected.provenance);
    if (!found || found.snapshotSha256 !== selected.snapshotSha256) throw fail('MCP_CHOICE_STALE');
    return found;
  }
  async function detail({ context: raw, selected: selection }) {
    const context = structuredClone(raw), selected = structuredClone(selection);
    const state = await snapshot({ context }), server = selectedServer(state, selected);
    const value = await admin.mcpTools({ ...context, name: server.name, provenance: server.provenance });
    const historyValue = await admin.mcpHistory(context);
    if (!Array.isArray(value?.tools) || value.tools.length > 64 || value.name !== server.name
        || value.schema_hash !== server.schemaSha256 || !SHA.test(value.schema_hash || '')
        || !version(String(value.version)) || !Array.isArray(historyValue?.history)
        || historyValue.history.length > 288) throw fail('MCP_CHAT_STATE_INVALID');
    const tools = value.tools.map(t => {
      if (!exact(t, ['tool_name', 'description', 'input_schema_json']) || typeof t.tool_name !== 'string'
          || !t.tool_name.trim() || Buffer.byteLength(t.tool_name) > 256
          || typeof t.description !== 'string' || typeof t.input_schema_json !== 'string') throw fail('MCP_CHAT_STATE_INVALID');
      let inputSchema;
      try { inputSchema = JSON.parse(t.input_schema_json); } catch { throw fail('MCP_CHAT_STATE_INVALID'); }
      if (!inputSchema || Array.isArray(inputSchema) || typeof inputSchema !== 'object') throw fail('MCP_CHAT_STATE_INVALID');
      return { name: t.tool_name, description: t.description, inputSchema };
    });
    C.boundedRegistryData(tools, 65536);
    // This existing admin projection contains common tool fields only. Its
    // authoritative schema_hash identifies the full saved SDK schema, including
    // annotations/outputSchema omitted here; do not rehash the lossy projection.
    if (new Set(tools.map(t => t.name)).size !== tools.length) throw fail('MCP_CHAT_STATE_INVALID');
    const history = historyValue.history.filter(h => h.name === server.name
      && (h.provenance === 'owned_registry' ? 'owned_registry' : 'scenario') === server.provenance).map(h => {
      const observedAt = h.ts instanceof Date ? h.ts.toISOString() : h.ts;
      if (!version(String(h.version)) || !SHA.test(h.schema_hash || '')
          || typeof observedAt !== 'string' || !Number.isFinite(Date.parse(observedAt))) throw fail('MCP_CHAT_STATE_INVALID');
      return { version: String(h.version), schemaSha256: h.schema_hash, observedAt };
    });
    const after = await snapshot({ context });
    if (!same(state, after)) throw fail('MCP_CHOICE_STALE');
    const result = { version: 1, scopeKey: state.scopeKey, registryVersion: state.registryVersion,
      server, schemaVersion: String(value.version), tools, history };
    C.boundedRegistryData(result, 131072);
    return result;
  }
  async function prepare(raw) {
    const { context, source, origin, action, selected, candidate, modeCapability } = structuredClone(raw);
    const state = await snapshot({ context });
    if (!state.registryReady) throw fail('MCP_CHAT_UNAVAILABLE');
    let before = null;
    if (action === 'retire') {
      before = selectedServer(state, selected);
      if (before.provenance !== 'owned_registry' || candidate !== null) throw fail('MCP_CHOICE_DENIED');
    } else {
      if (selected !== null) throw fail('MCP_CHOICE_DENIED');
      const fields = C.normalizeRegistryCandidate(action, candidate);
      // MCP09 deliberately permits replacement in vulnerable mode. Capture the
      // current entry for truthful review; the existing executor owns its policy.
      if (action === 'register') before = state.servers.find(s => s.provenance === 'owned_registry'
        && s.name === fields.name) ?? null;
    }
    return C.createRoleMcpRegistryProposal({ source, origin, action, selected, before, candidate,
      expectedVersion: state.registryVersion, scopeKey: state.scopeKey, modeCapability,
      registryMode: state.registryMode });
  }
  function envelope(raw, expected) {
    const value = C.boundedRegistryData(raw, 131072);
    const completed = value.state === 'completed';
    if (!exact(value, ['version', 'operationId', 'state', 'action', 'requestSha256', 'replayed',
      ...(completed ? ['registryVersion', 'changes'] : [])])
        || value.version !== 'secureshop-owned-mcp-registry.v1' || !UUID.test(value.operationId || '')
        || !['register', 'import', 'retire'].includes(value.action) || !SHA.test(value.requestSha256 || '')
        || typeof value.replayed !== 'boolean' || !['admitted', 'completed', 'failed', 'unknown'].includes(value.state)
        || (expected && (value.operationId !== expected.proposalId || value.action !== expected.action
          || value.requestSha256 !== expected.requestSha256))) throw fail('MCP_CHAT_STATE_INVALID');
    if (completed && (!version(value.registryVersion) || !Array.isArray(value.changes)
        || value.changes.length < 1 || value.changes.length > 32
        || new Set(value.changes.map(c => c.name)).size !== value.changes.length
        || value.changes.some(c => !exact(c, ['name', 'entryId', 'action', 'schemaSha256', 'effect'])
          || typeof c.name !== 'string' || !c.name.trim() || Buffer.byteLength(c.name) > 256
          || !UUID.test(c.entryId || '') || c.action !== value.action
          || (c.action === 'retire' ? c.schemaSha256 !== null : !SHA.test(c.schemaSha256 || ''))
          || !c.effect || typeof c.effect !== 'object' || Array.isArray(c.effect))
        || (expected && (value.registryVersion !== String(BigInt(expected.request.expectedVersion) + 1n)
          || (expected.action !== 'import' && (value.changes.length !== 1 || value.changes[0].name !== expected.request.name)))))) {
      throw fail('MCP_CHAT_STATE_INVALID');
    }
    return { ...value, ok: completed, ...(!completed ? { automaticRetry: false } : {}) };
  }
  async function confirm(raw) {
    const { context, proposal, source } = structuredClone({ context: raw.context, proposal: raw.proposal, source: raw.source });
    const { beforeEffect, signal } = raw;
    if (beforeEffect !== undefined && typeof beforeEffect !== 'function') throw fail('MCP_CHAT_STATE_INVALID');
    signal?.throwIfAborted();
    const p = C.validateRoleMcpRegistryProposal(proposal, source), current = await registry();
    if (!current) throw fail('MCP_CHAT_UNAVAILABLE');
    // Scope and executor mode are authority. Current rows/head are deliberately
    // not a replay gate: the existing journal checks UUID before head CAS.
    if (scopeDigest(context) !== p.scopeKey || current.mode !== p.registryMode) throw fail('MCP_CHAT_SCOPE_MISMATCH');
    if (beforeEffect) await beforeEffect();
    signal?.throwIfAborted();
    return envelope(await current.service.mutate({ ...context, request: p.request }, { signal }), p);
  }
  async function operation({ context: raw, operationId }) {
    const context = structuredClone(raw), current = await registry();
    if (!current || !UUID.test(operationId || '')) throw fail('MCP_CHAT_UNAVAILABLE');
    const result = envelope(await current.service.read({ ...context, operationId }));
    if (result.operationId !== operationId) throw fail('MCP_CHAT_STATE_INVALID');
    return result;
  }
  return Object.freeze({ snapshot, detail, prepare, confirm, operation });
}
module.exports = { createBoundMcpRegistryChat };
