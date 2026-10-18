'use strict';

// Unwired foundation. Reads existing canonical rows; never dispatches a tool.
const C = require('../../services/secureshopOwnedMcpInvocationContract');
const { createLaunchScope, createConversationBinding } = require('../../services/secureshopConversationBinding');
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const denied = () => Object.assign(new Error('Owned MCP invocation snapshot unavailable'), { code: 'MCP_INVOCATION_DENIED' });

const CURRENT_SQL = `SELECT e.entry_id::text AS entry_id,e.current_version::text AS registry_version,
 encode(e.schema_sha256,'hex') AS schema_sha256,r.tools_json
 FROM secureshop_agents.bound_mcp_registry_entries e
 JOIN secureshop_agents.bound_mcp_registry_revisions r
 ON r.platform_launch_id=e.platform_launch_id AND r.platform_scenario_id=e.platform_scenario_id
 AND r.platform_launch_generation=e.platform_launch_generation
 AND r.original_platform_owner_id=e.original_platform_owner_id
 AND r.original_platform_session_id=e.original_platform_session_id
 AND r.name=e.name AND r.entry_id=e.entry_id AND r.registry_version=e.current_version
 AND r.schema_sha256=e.schema_sha256 AND r.transport=e.transport AND r.endpoint_text=e.endpoint_text
 WHERE e.platform_launch_id=$1 AND e.platform_scenario_id=$2 AND e.platform_launch_generation=$3
 AND e.original_platform_owner_id=$4 AND e.original_platform_session_id=$5 AND e.entry_id=$6
 AND e.lifecycle='active' AND r.redacted_at IS NULL AND r.action IN ('register','import')
 LIMIT 2`;

function createOwnedMcpInvocationRepository({ personaAuthority } = {}) {
  if (typeof personaAuthority?.capture !== 'function') throw new TypeError('Canonical persona authority required');
  function capture(raw) {
    // Snapshot before any await and reject getters/non-JSON inputs. The private
    // persona session stays in this closure, never in the model tool manifest.
    const input = C.bounded(raw, 8192);
    const scope = createLaunchScope(input.scope);
    const binding = createConversationBinding(scope, input.persona);
    const session = input.personaSession;
    if (binding.role !== 'admin' || typeof input.entryId !== 'string' || !UUID.test(input.entryId)
      || typeof session?.sessionId !== 'string' || !UUID.test(session.sessionId)
      || typeof session.authorityVersion !== 'string' || !/^[1-9][0-9]{0,18}$/.test(session.authorityVersion)
      || BigInt(session.authorityVersion) > 9223372036854775807n) throw denied();
    const entryId = input.entryId;
    const expectedFence = C.freeze({ ...scope, personaId: binding.shopUserId, role: binding.role,
      sessionId: session.sessionId, authorityVersion: session.authorityVersion });
    const fence = personaAuthority.capture({ scope, personaId: binding.shopUserId, role: binding.role,
      sessionId: session.sessionId, authorityVersion: session.authorityVersion });
    if (C.digest(fence?.binding) !== C.digest(expectedFence)
      || typeof fence.withPersonaEffect !== 'function' || typeof fence.assertRemoteAdmission !== 'function') throw denied();
    // Bind methods too: changing an injected authority object later cannot
    // substitute a different fence for this captured run.
    const withPersonaEffect = fence.withPersonaEffect.bind(fence);
    const admit = fence.assertRemoteAdmission.bind(fence);
    const params = Object.freeze([scope.launchId, scope.scenarioId, scope.generation,
      scope.platformOwnerId, scope.platformSessionId, entryId]);
    function matches(candidate, selected = entryId) {
      if (selected !== entryId || C.digest(candidate) !== C.digest(binding)) throw denied();
    }
    async function assertAuthority(candidate) { matches(candidate); await admit(); }
    async function readSnapshot() {
      const value = await withPersonaEffect(async client => {
        await client.query("SET LOCAL statement_timeout='3000ms'");
        await client.query("SET LOCAL lock_timeout='3000ms'");
        const result = await client.query(CURRENT_SQL, params);
        if (result.rows.length !== 1 || result.rows[0].entry_id !== entryId) throw denied();
        const row = result.rows[0];
        // JSONB normalizes key order/whitespace; the established schema digest
        // preserves array order and every original descriptor string/value.
        return C.snapshot({ binding, entryId, registryVersion: row.registry_version,
          schemaSha256: row.schema_sha256, tools: row.tools_json });
      });
      await admit(); // Original authority may have changed after the read lock.
      return value;
    }
    function readCurrent(candidate, selected) { matches(candidate, selected); return readSnapshot(); }
    return Object.freeze({ binding, entryId, readSnapshot, readCurrent, assertAuthority });
  }
  return Object.freeze({ capture });
}

module.exports = { createOwnedMcpInvocationRepository };
