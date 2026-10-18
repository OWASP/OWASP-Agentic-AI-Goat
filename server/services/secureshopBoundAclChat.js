'use strict';

const C = require('./secureshopRoleAclProposal');

const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const SHA = /^[a-f0-9]{64}$/;
const MAX_VERSION = 9223372036854775807n;
const ROLES = ['customer', 'merchant', 'admin'];
const exact = (value, keys) => value && Object.getPrototypeOf(value) === Object.prototype
  && Object.keys(value).sort().join(',') === [...keys].sort().join(',');
const fail = code => Object.assign(new Error('ACL conversation unavailable'), { code });
const version = value => typeof value === 'string' && /^[1-9]\d{0,18}$/.test(value)
  && BigInt(value) <= MAX_VERSION;

// Preparation only reads the original bound ACL service. That service remains
// the sole writer of the versioned policy, immutable operation and audit row.
function createBoundAclChat({ accessControl } = {}) {
  if (['read', 'mutate', 'operation'].some(method => typeof accessControl?.[method] !== 'function')) {
    throw new TypeError('Bound access-control service required');
  }

  async function snapshot({ context: raw }) {
    const context = structuredClone(raw);
    const value = await accessControl.read(context);
    if (!value || value.administration?.versionedPolicy !== true
        || typeof value.administration.scopeKey !== 'string'
        || !value.administration.scopeKey || Buffer.byteLength(value.administration.scopeKey) > 1024
        || !version(value.version) || !SHA.test(value.registrySha256 || '')
        || typeof value.enforcement_enabled !== 'boolean'
        || !Array.isArray(value.tools) || value.tools.length > 512) {
      throw fail('ACL_CHAT_STATE_INVALID');
    }
    const scopeKey = value.administration.scopeKey;
    const expectedVersion = value.version;
    const registrySha256 = value.registrySha256;
    const enforcement = value.enforcement_enabled;
    const choices = [];
    const seen = new Set();
    for (const row of value.tools) {
      if (typeof row?.tool_name !== 'string' || !row.tool_name
          || Buffer.byteLength(row.tool_name) > 256
          || typeof row.supported !== 'boolean' || typeof row.readOnly !== 'boolean'
          || !exact(row.applicable_roles, ROLES)
          || ROLES.some(role => typeof row[role] !== 'boolean'
            || typeof row.applicable_roles[role] !== 'boolean')) throw fail('ACL_CHAT_STATE_INVALID');
      if (seen.has(row.tool_name)) throw fail('ACL_CHAT_STATE_INVALID');
      seen.add(row.tool_name);
      if (!row.supported || row.readOnly) continue;
      for (const role of ROLES) {
        if (!row.applicable_roles[role]) continue;
        const allowed = row[role];
        const base = { scopeKey, expectedVersion, registrySha256,
          toolKey: row.tool_name, role, allowed, enforcement };
        choices.push({ toolKey: row.tool_name, role, allowed, enforcement,
          snapshotSha256: C.aclChoiceSnapshot(base) });
      }
    }
    choices.sort((a, b) => a.toolKey.localeCompare(b.toolKey) || ROLES.indexOf(a.role) - ROLES.indexOf(b.role));
    return { version: 1, scopeKey, expectedVersion, registrySha256, enforcement,
      enforcementSnapshotSha256: C.aclEnforcementSnapshot({ scopeKey, expectedVersion,
        registrySha256, enforcement }), choices };
  }

  async function prepare(raw) {
    const { context, source, origin, action, selected, candidate, modeCapability } = structuredClone(raw);
    const state = await snapshot({ context });
    let before, after, current = null;
    if (action === 'permission') {
      if (!exact(selected, ['choiceId', 'toolKey', 'role', 'snapshotSha256'])
          || !/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(selected.choiceId || '')
          || !exact(candidate, ['allowed']) || typeof candidate.allowed !== 'boolean') {
        throw fail('ACL_CHOICE_STALE');
      }
      current = state.choices.find(row => row.toolKey === selected.toolKey && row.role === selected.role);
      if (!current || current.snapshotSha256 !== selected.snapshotSha256) throw fail('ACL_CHOICE_STALE');
      if (current.allowed === candidate.allowed) throw fail('ACL_NO_CHANGE');
      before = { allowed: current.allowed, enforcement: state.enforcement };
      after = { allowed: candidate.allowed, enforcement: state.enforcement };
    } else if (action === 'enforcement') {
      if (selected !== null || !exact(candidate, ['enabled']) || typeof candidate.enabled !== 'boolean') {
        throw fail('ROLE_ACL_PROPOSAL_INVALID');
      }
      if (state.enforcement === candidate.enabled) throw fail('ACL_NO_CHANGE');
      before = { enforcement: state.enforcement };
      after = { enforcement: candidate.enabled };
    } else throw fail('ROLE_ACL_PROPOSAL_INVALID');
    return C.createRoleAclProposal({ source, origin, action, selected, before, after,
      expectedVersion: state.expectedVersion, registrySha256: state.registrySha256,
      scopeKey: state.scopeKey, modeCapability });
  }

  function receipt(value, expected = null) {
    if (!exact(value, ['operationId', 'expectedVersion', 'version', 'registrySha256', 'enforcement', 'change'])
        || !UUID.test(value.operationId || '') || !version(value.expectedVersion)
        || !version(value.version)
        || BigInt(value.version) !== BigInt(value.expectedVersion) + 1n
        || !SHA.test(value.registrySha256 || '') || typeof value.enforcement !== 'boolean') {
      throw fail('ACL_CHAT_STATE_INVALID');
    }
    if (value.change?.kind === 'permission') {
      if (!exact(value.change, ['kind', 'toolKey', 'role', 'allowed'])
          || typeof value.change.toolKey !== 'string' || !value.change.toolKey
          || !ROLES.includes(value.change.role) || typeof value.change.allowed !== 'boolean') {
        throw fail('ACL_CHAT_STATE_INVALID');
      }
    } else if (value.change?.kind === 'enforcement') {
      if (!exact(value.change, ['kind', 'enabled']) || typeof value.change.enabled !== 'boolean'
          || value.enforcement !== value.change.enabled) throw fail('ACL_CHAT_STATE_INVALID');
    } else throw fail('ACL_CHAT_STATE_INVALID');
    if (expected) {
      const change = expected.action === 'permission'
        ? { kind: 'permission', toolKey: expected.tool.toolKey, role: expected.tool.role,
          allowed: expected.after.allowed }
        : { kind: 'enforcement', enabled: expected.after.enforcement };
      if (value.operationId !== expected.proposalId || value.expectedVersion !== expected.expectedVersion
          || value.registrySha256 !== expected.registrySha256
          || value.enforcement !== expected.after.enforcement
          || Object.keys(change).some(key => value.change[key] !== change[key])) throw fail('ACL_CHAT_STATE_INVALID');
    }
    return structuredClone(value);
  }

  async function confirm(raw) {
    const { context, proposal, source } = structuredClone({ context: raw.context,
      proposal: raw.proposal, source: raw.source });
    const { signal, beforeEffect } = raw;
    if (beforeEffect !== undefined && typeof beforeEffect !== 'function') throw fail('ROLE_ACL_PROPOSAL_INVALID');
    signal?.throwIfAborted();
    const p = C.validateRoleAclProposal(proposal, source);
    const state = await snapshot({ context });
    if (state.scopeKey !== p.scopeKey) throw fail('ACL_CHAT_SCOPE_MISMATCH');
    // The graph checks original scene/mode/turn authority after this awaited
    // read. The repository checks exact UUID replay before its head CAS.
    if (beforeEffect) await beforeEffect();
    signal?.throwIfAborted();
    const change = p.action === 'permission'
      ? { kind: 'permission', toolKey: p.tool.toolKey, role: p.tool.role, allowed: p.after.allowed }
      : { kind: 'enforcement', enabled: p.after.enforcement };
    const value = await accessControl.mutate({ ...context, operationId: p.proposalId,
      expectedVersion: p.expectedVersion, change });
    return { ok: true, receipt: receipt(value?.receipt, p) };
  }

  async function operation({ context: raw, operationId }) {
    if (!UUID.test(operationId || '')) throw fail('ROLE_ACL_PROPOSAL_INVALID');
    const value = await accessControl.operation({ ...structuredClone(raw), operationId });
    return value === null ? null : { ok: true, receipt: receipt(value) };
  }

  return Object.freeze({ snapshot, prepare, confirm, operation });
}

module.exports = { createBoundAclChat };
