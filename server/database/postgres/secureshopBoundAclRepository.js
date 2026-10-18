'use strict';

const { createHash, randomUUID } = require('node:crypto');
const { createLaunchScope, createConversationBinding } = require('../../services/secureshopConversationBinding');
const { REGISTRY, REGISTRY_SHA256, REGISTRY_UPGRADES,
  ROLES, createBoundAclResolver } = require('../../services/secureshopBoundAclRegistry');

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const COLUMNS = 'platform_launch_id,platform_scenario_id,platform_launch_generation,original_platform_owner_id,original_platform_session_id';
const WHERE = 'platform_launch_id=$1 AND platform_scenario_id=$2 AND platform_launch_generation=$3 AND original_platform_owner_id=$4 AND original_platform_session_id=$5';
const TABLE = 'secureshop_agents.';
function error(code) { return Object.assign(new Error(code), { code }); }
function uuid(value) {
  if (typeof value !== 'string' || !UUID.test(value)) throw error('INVALID_ARGUMENT');
  return value.toLowerCase();
}
function version(value) {
  if (typeof value !== 'string' || !/^[1-9]\d{0,18}$/.test(value) || BigInt(value) > 9223372036854775807n) throw error('INVALID_ARGUMENT');
  return value;
}
function canonical(value, state = { seen: new Set(), nodes: 0 }, depth = 0) {
  if (depth > 24 || ++state.nodes > 4096) throw error('INVALID_ARGUMENT');
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return JSON.stringify(value);
  if (typeof value === 'number' && Number.isFinite(value)) return JSON.stringify(value);
  if (!value || typeof value !== 'object' || state.seen.has(value)) throw error('INVALID_ARGUMENT');
  state.seen.add(value);
  let result;
  if (Array.isArray(value)) result = '[' + value.map(item => canonical(item, state, depth + 1)).join(',') + ']';
  else if (Object.getPrototypeOf(value) === Object.prototype) {
    result = '{' + Object.keys(value).sort().map(key => JSON.stringify(key) + ':' + canonical(value[key], state, depth + 1)).join(',') + '}';
  } else throw error('INVALID_ARGUMENT');
  state.seen.delete(value);
  return result;
}
function digest(value) {
  const text = canonical(value);
  if (Buffer.byteLength(text) > 65536) throw error('INVALID_ARGUMENT');
  return createHash('sha256').update(text).digest('hex');
}
function values(input) {
  const s = input.scope;
  return [s.launchId, s.scenarioId, s.generation, s.platformOwnerId, s.platformSessionId];
}
function snapshot(raw, admin = false) {
  const input = structuredClone(raw);
  input.scope = createLaunchScope(input.scope);
  createConversationBinding(input.scope, input.persona);
  if (admin && input.persona.role !== 'admin') throw error('ADMIN_REQUIRED');
  input.personaSession = {
    sessionId: uuid(input.personaSession?.sessionId),
    authorityVersion: version(input.personaSession?.authorityVersion),
  };
  return input;
}
function actorValues(input) {
  return [input.persona.id, input.personaSession.sessionId, input.persona.role, input.personaSession.authorityVersion];
}
function sameActor(row, input) {
  return Number(row.persona_id) === input.persona.id && row.persona_session_id === input.personaSession.sessionId
    && row.persona_role === input.persona.role && String(row.authority_version) === input.personaSession.authorityVersion;
}

// Unmounted candidate. Constructor dependencies are trusted server objects; request
// adapters must never accept a personaAuthority, scope or acting credential from a body.
function createSecureShopBoundAclRepository({ personaAuthority, audit } = {}) {
  if (typeof personaAuthority?.capture !== 'function' || typeof audit?.append !== 'function') {
    throw new TypeError('Persona authority and same-store audit writer required');
  }
  async function transaction(input, work, receiptEffect = false) {
    const expected = { ...input.scope, personaId: input.persona.id, role: input.persona.role,
      sessionId: input.personaSession.sessionId, authorityVersion: input.personaSession.authorityVersion };
    const fence = await personaAuthority.capture({ scope: input.scope, ...Object.fromEntries(
      ['personaId', 'role', 'sessionId', 'authorityVersion'].map(key => [key, expected[key]])) });
    if (typeof fence?.withPersonaEffect !== 'function' || typeof fence?.assertRemoteAdmission !== 'function'
      || !fence.binding || Object.keys(expected).some(key => fence.binding[key] !== expected[key])) throw error('SHOP_AUTH_INVALID');
    const result = await fence.withPersonaEffect(async client => {
      if (typeof client?.query !== 'function') throw error('SHOP_AUTH_INVALID');
      await client.query("SET LOCAL statement_timeout = '3000ms'");
      await client.query("SET LOCAL lock_timeout = '3000ms'");
      return work(client);
    });
    try {
      await fence.assertRemoteAdmission();
    } catch (cause) {
      if (!receiptEffect) throw cause;
      const uncertain = error('ACL_RECEIPT_OUTCOME_UNCERTAIN');
      Object.defineProperty(uncertain, 'cause', { value: cause });
      throw uncertain;
    }
    return result;
  }
  async function head(client, input) {
    const scope = values(input);
    await client.query(`INSERT INTO ${TABLE}bound_tool_policy_heads (${COLUMNS},enforcement_enabled,registry_sha256)
      VALUES ($1,$2,$3,$4,$5,false,decode($6,'hex')) ON CONFLICT DO NOTHING`, [...scope, REGISTRY_SHA256]);
    let row = (await client.query(`SELECT policy_version::text,enforcement_enabled,encode(registry_sha256,'hex') AS registry_sha256
      FROM ${TABLE}bound_tool_policy_heads WHERE ${WHERE} FOR UPDATE`, scope)).rows[0];
    if (!row) throw error('ACL_REGISTRY_MISMATCH');
    const addedKeys = Object.hasOwn(REGISTRY_UPGRADES, row.registry_sha256)
      ? REGISTRY_UPGRADES[row.registry_sha256] : null;
    if (addedKeys) {
      const oldOverrides = (await client.query(`SELECT tool_key,role,allowed FROM ${TABLE}bound_tool_policy_overrides
        WHERE ${WHERE} ORDER BY tool_key,role`, scope)).rows;
      if (oldOverrides.some(override => addedKeys.includes(override.tool_key))) throw error('ACL_REGISTRY_MISMATCH');
      const addedDenials = REGISTRY.filter(tool => addedKeys.includes(tool.toolKey))
        .flatMap(tool => ROLES.filter(role => tool.roleApplicability[role]).map(role => ({ toolKey: tool.toolKey, role })));
      if (addedDenials.length !== addedKeys.length) throw error('ACL_REGISTRY_MISMATCH');
      const nextVersion = (BigInt(row.policy_version) + 1n).toString();
      await client.query(`INSERT INTO ${TABLE}bound_tool_registry_upgrades (${COLUMNS},predecessor_version,successor_version,
        predecessor_sha256,successor_sha256,enforcement_enabled,overrides_before,overrides_sha256,added_denials)
        VALUES ($1,$2,$3,$4,$5,$6,$7,decode($8,'hex'),decode($9,'hex'),$10,$11::jsonb,
        sha256(convert_to($11::jsonb::text,'UTF8')),$12::jsonb)`,
      [...scope,row.policy_version,nextVersion,row.registry_sha256,REGISTRY_SHA256,row.enforcement_enabled,
        JSON.stringify(oldOverrides.map(override => ({ toolKey: override.tool_key, role: override.role, allowed: override.allowed }))),
        JSON.stringify(addedDenials)]);
      for (const denied of addedDenials) {
        await client.query(`INSERT INTO ${TABLE}bound_tool_policy_overrides (${COLUMNS},tool_key,role,allowed)
          VALUES ($1,$2,$3,$4,$5,$6,$7,false)`, [...scope,denied.toolKey,denied.role]);
      }
      await client.query(`UPDATE ${TABLE}bound_tool_policy_heads SET policy_version=policy_version+1,
        registry_sha256=decode($6,'hex') WHERE ${WHERE}`,[...scope,REGISTRY_SHA256]);
      row = { policy_version: nextVersion, enforcement_enabled: row.enforcement_enabled, registry_sha256: REGISTRY_SHA256 };
    }
    if (row.registry_sha256 !== REGISTRY_SHA256) throw error('ACL_REGISTRY_MISMATCH');
    return row;
  }
  async function append(client, input, sourceId, action, params, outcome = 'completed') {
    await audit.append(client, { eventId: randomUUID(), scope: input.scope, persona: input.persona,
      actor: input.persona.role, action, target: 'bound-tool-policy', paramsJson: JSON.stringify(params),
      outcome, sourceKind: 'bound_tool_policy', sourceId });
  }
  async function operation(client, input) {
    return (await client.query(`SELECT *,encode(request_sha256,'hex') AS request_digest FROM ${TABLE}bound_tool_policy_operations
      WHERE ${WHERE} AND operation_id=$6`, [...values(input), input.operationId])).rows[0];
  }
  return Object.freeze({
    async readPolicy(raw) {
      const input = snapshot(raw);
      return transaction(input, async client => {
        const current = await head(client, input);
        const overrides = (await client.query(`SELECT tool_key,role,allowed FROM ${TABLE}bound_tool_policy_overrides WHERE ${WHERE}`, values(input))).rows;
        const byKey = new Map(overrides.map(row => [JSON.stringify([row.tool_key, row.role]), row.allowed]));
        return { version: current.policy_version, enforcement: current.enforcement_enabled, registrySha256: REGISTRY_SHA256,
          rows: REGISTRY.map(row => ({ ...row, readOnly: !row.supported,
            allowed: Object.fromEntries(ROLES.map(role => [role, row.supported && byKey.has(JSON.stringify([row.toolKey, role]))
              ? byKey.get(JSON.stringify([row.toolKey, role])) : row.defaultAllowed[role]])) })) };
      });
    },
    async readOperation(raw) {
      const input = snapshot(raw, true);
      input.operationId = uuid(input.operationId);
      return transaction(input, async client => {
        const row = await operation(client, input);
        if (!row) return null;
        if (Number(row.persona_id) !== input.persona.id) throw error('ACL_OPERATION_UNAVAILABLE');
        return structuredClone(row.receipt_json);
      });
    },
    async mutate(raw) {
      const input = snapshot(raw, true);
      input.operationId = uuid(input.operationId);
      input.expectedVersion = version(input.expectedVersion);
      const change = input.change;
      if (!change || typeof change !== 'object' || Array.isArray(change)) throw error('INVALID_ARGUMENT');
      if (change.kind === 'enforcement') {
        if (Object.keys(change).sort().join(',') !== 'enabled,kind' || typeof change.enabled !== 'boolean') throw error('INVALID_ARGUMENT');
      } else if (change.kind === 'permission') {
        if (Object.keys(change).sort().join(',') !== 'allowed,kind,role,toolKey' || typeof change.allowed !== 'boolean'
          || !ROLES.includes(change.role) || !REGISTRY.some(row => row.supported && row.toolKey === change.toolKey && row.roleApplicability[change.role])) throw error('INVALID_ARGUMENT');
      } else throw error('INVALID_ARGUMENT');
      const requestDigest = digest({ expectedVersion: input.expectedVersion, change });
      return transaction(input, async client => {
        const current = await head(client, input);
        const previous = await operation(client, input);
        if (previous) {
          if (Number(previous.persona_id) !== input.persona.id || previous.request_digest !== requestDigest) throw error('ACL_OPERATION_CONFLICT');
          return structuredClone(previous.receipt_json);
        }
        if (current.policy_version !== input.expectedVersion) throw error('ACL_VERSION_CONFLICT');
        const next = (BigInt(current.policy_version) + 1n).toString();
        const enforcement = change.kind === 'enforcement' ? change.enabled : current.enforcement_enabled;
        await client.query(`UPDATE ${TABLE}bound_tool_policy_heads SET policy_version=policy_version+1,enforcement_enabled=$6 WHERE ${WHERE}`, [...values(input), enforcement]);
        if (change.kind === 'permission') await client.query(`INSERT INTO ${TABLE}bound_tool_policy_overrides (${COLUMNS},tool_key,role,allowed)
          VALUES ($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT (${COLUMNS},tool_key,role) DO UPDATE SET allowed=EXCLUDED.allowed`,
        [...values(input), change.toolKey, change.role, change.allowed]);
        const receipt = { operationId: input.operationId, expectedVersion: input.expectedVersion, version: next,
          registrySha256: REGISTRY_SHA256, enforcement, change };
        await client.query(`INSERT INTO ${TABLE}bound_tool_policy_operations (${COLUMNS},operation_id,persona_id,persona_session_id,persona_role,authority_version,
          expected_version,policy_version,request_sha256,receipt_json) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,decode($13,'hex'),$14::jsonb)`,
        [...values(input), input.operationId, ...actorValues(input), input.expectedVersion, next, requestDigest, JSON.stringify(receipt)]);
        await append(client, input, input.operationId, 'tool_policy_changed', receipt);
        return receipt;
      }, true);
    },
    async admitTool(raw) {
      const input = snapshot(raw);
      input.runId = uuid(input.runId);
      if (typeof input.invocationId !== 'string' || !input.invocationId.length || input.invocationId.length > 256) throw error('INVALID_ARGUMENT');
      const resolver = createBoundAclResolver({ workflow: input.workflow, declaredTools: input.declaredTools, admittedMcp: input.admittedMcp });
      const tool = resolver.resolve(input.agent, input.tool);
      if (!tool || !resolver.isRoleApplicable(input.persona.role)) throw error('ACL_TOOL_UNAVAILABLE');
      // Include the concrete dynamic declaration, not merely its stable policy alias.
      const argsDigest = digest({ args: input.args, workflow: input.workflow, agent: input.agent, tool: input.tool,
        declaredTools: input.declaredTools, admittedMcp: input.admittedMcp ?? null });
      return transaction(input, async client => {
        const current = await head(client, input);
        const previous = (await client.query(`SELECT *,encode(args_sha256,'hex') AS args_digest FROM ${TABLE}bound_tool_admissions
          WHERE ${WHERE} AND run_id=$6 AND invocation_id=$7`, [...values(input), input.runId, input.invocationId])).rows[0];
        function receipt(row) {
          return { admissionId: row.admission_id, runId: input.runId, invocationId: input.invocationId, toolKey: row.tool_key,
            policyVersion: String(row.policy_version), registrySha256: REGISTRY_SHA256, enforcement: row.enforcement_enabled,
            allowed: row.allowed, action: row.action, policyViolation: row.policy_violation };
        }
        if (previous) {
          if (!sameActor(previous, input) || previous.args_digest !== argsDigest || previous.tool_key !== tool.toolKey) throw error('ACL_ADMISSION_CONFLICT');
          if (String(previous.policy_version) !== current.policy_version) throw error('ACL_ADMISSION_STALE');
          return receipt(previous);
        }
        const override = (await client.query(`SELECT allowed FROM ${TABLE}bound_tool_policy_overrides WHERE ${WHERE} AND tool_key=$6 AND role=$7`,
          [...values(input), tool.toolKey, input.persona.role])).rows[0];
        const allowed = override ? override.allowed : tool.defaultAllowed[input.persona.role];
        const action = allowed || !current.enforcement_enabled ? 'dispatch' : 'block';
        const violation = allowed ? null : 'denied-by-acl';
        const admissionId = randomUUID();
        await client.query(`INSERT INTO ${TABLE}bound_tool_admissions (${COLUMNS},admission_id,run_id,invocation_id,persona_id,persona_session_id,persona_role,authority_version,
          tool_key,args_sha256,registry_sha256,policy_version,enforcement_enabled,allowed,action,policy_violation)
          VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,decode($14,'hex'),decode($15,'hex'),$16,$17,$18,$19,$20)`,
        [...values(input), admissionId, input.runId, input.invocationId, ...actorValues(input), tool.toolKey, argsDigest,
          REGISTRY_SHA256, current.policy_version, current.enforcement_enabled, allowed, action, violation]);
        const result = receipt({ admission_id: admissionId, tool_key: tool.toolKey, policy_version: current.policy_version,
          enforcement_enabled: current.enforcement_enabled, allowed, action, policy_violation: violation });
        await append(client, input, admissionId, 'tool_policy_admission', result, allowed ? 'completed' : 'denied');
        return result;
      }, true);
    },
  });
}
module.exports = { createSecureShopBoundAclRepository };
