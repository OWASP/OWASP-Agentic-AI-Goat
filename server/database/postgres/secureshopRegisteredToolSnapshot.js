'use strict';

// Per-turn reads only. Registry mutation remains owned by the registry service.
const C = require('../../services/secureshopOwnedMcpInvocationContract');
const { createConversationBinding } = require('../../services/secureshopConversationBinding');
const unavailable = () => Object.assign(new Error('Registered tools unavailable'),
  { code: 'MCP_REGISTRY_SNAPSHOT_UNAVAILABLE', executionBoundary: true });
const SQL = `SELECT e.entry_id::text AS entry_id,e.name,e.transport,e.endpoint_text,
 e.current_version::text AS registry_version,encode(e.schema_sha256,'hex') AS schema_sha256,r.tools_json
 FROM secureshop_agents.bound_mcp_registry_entries e
 JOIN secureshop_agents.bound_mcp_registry_revisions r
 ON r.platform_launch_id=e.platform_launch_id AND r.platform_scenario_id=e.platform_scenario_id
 AND r.platform_launch_generation=e.platform_launch_generation
 AND r.original_platform_owner_id=e.original_platform_owner_id
 AND r.original_platform_session_id=e.original_platform_session_id
 AND r.name=e.name AND r.entry_id=e.entry_id AND r.registry_version=e.current_version
 AND r.schema_sha256=e.schema_sha256 AND r.transport=e.transport AND r.endpoint_text=e.endpoint_text
 WHERE e.platform_launch_id=$1 AND e.platform_scenario_id=$2 AND e.platform_launch_generation=$3
 AND e.original_platform_owner_id=$4 AND e.original_platform_session_id=$5
 AND e.lifecycle='active' AND r.redacted_at IS NULL AND r.action IN ('register','import')
 ORDER BY e.name LIMIT 33`;

function createRegisteredToolSnapshotRepository({ pool } = {}) {
  if (typeof pool?.query !== 'function') throw new TypeError('Registered tool store required');
  function capture(rawBinding, fence) {
    const input = C.bounded(rawBinding, 8192);
    const binding = createConversationBinding(input, { id: input.shopUserId, role: input.role });
    const keys = ['launchId', 'scenarioId', 'generation', 'platformOwnerId', 'platformSessionId'];
    if (binding.role !== 'admin' || C.digest(input) !== C.digest(binding)
        || keys.some(key => fence?.binding?.[key] !== binding[key])
        || fence?.binding?.personaId !== binding.shopUserId || fence?.binding?.role !== binding.role
        || typeof fence.withPersonaEffect !== 'function' || typeof fence.withCrossStoreEffect !== 'function') throw unavailable();
    const values = Object.freeze(keys.map(key => binding[key]));
    async function read(client) {
      const result = await client.query({ text: SQL, values, query_timeout: 3000 });
      if (!Array.isArray(result.rows) || result.rows.length > 32) throw unavailable();
      const ids = new Set(), names = new Set();
      let count = 0;
      const entries = result.rows.map(row => {
        const snapshot = C.snapshot({ binding, entryId: row.entry_id,
          registryVersion: row.registry_version, schemaSha256: row.schema_sha256, tools: row.tools_json });
        if (ids.has(snapshot.entryId) || names.has(row.name) || typeof row.name !== 'string' || !row.name
            || !['sse', 'streamable-http', 'stdio'].includes(row.transport)
            || typeof row.endpoint_text !== 'string' || !row.endpoint_text || Buffer.byteLength(row.endpoint_text) > 8192
            || (count += snapshot.tools.length) > 64) throw unavailable();
        ids.add(snapshot.entryId); names.add(row.name);
        return { name: row.name, entryId: snapshot.entryId, registryVersion: snapshot.registryVersion,
          transport: row.transport, endpoint: row.endpoint_text, schemaSha256: snapshot.schemaSha256,
          tools: snapshot.tools };
      });
      return C.freeze(C.bounded(entries, 131072));
    }
    return Object.freeze({
      read: () => fence.withPersonaEffect(read),
      // The persona transaction holds the same owner/admission locks used by
      // registry publication and retirement. Do not reacquire that fence from
      // inside this callback. Remote work must settle/drain before returning.
      async withCurrentEntry(rawEntry, work) {
        const entry = C.freeze(C.bounded(rawEntry, 98304));
        if (typeof work !== 'function') throw unavailable();
        return fence.withCrossStoreEffect(async () => {
          const current = (await read(pool)).find(value => value.entryId === entry.entryId);
          if (!current || C.digest(current) !== C.digest(entry)) throw unavailable();
          return work(current);
        });
      },
    });
  }
  return Object.freeze({ capture });
}
module.exports = { createRegisteredToolSnapshotRepository };
