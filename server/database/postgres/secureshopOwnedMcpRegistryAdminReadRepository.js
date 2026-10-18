'use strict';
const {createLaunchScope}=require('../../services/secureshopConversationBinding');
const predicate=(prefix='')=>`${prefix}platform_launch_id=$1 AND ${prefix}platform_scenario_id=$2 AND ${prefix}platform_launch_generation=$3
 AND ${prefix}original_platform_owner_id=$4 AND ${prefix}original_platform_session_id=$5`;
const args=raw=>{const s=createLaunchScope(raw);return[s.launchId,s.scenarioId,s.generation,s.platformOwnerId,s.platformSessionId];};
function createOwnedMcpRegistryAdminReadRepository({pool}={}){
 if(typeof pool?.query!=='function')throw new TypeError('Owned MCP registry read pool required');
 return Object.freeze({
  async head(scope){const rows=(await pool.query(`SELECT registry_version::text AS version FROM secureshop_agents.bound_mcp_registry_heads WHERE ${predicate()}`,args(scope))).rows;if(rows.length>1)throw Error('Owned registry head unavailable');const version=rows[0]?.version??'0';if(typeof version!=='string'||!/^(0|[1-9][0-9]{0,15})$/.test(version)||BigInt(version)>9007199254740991n)throw Error('Owned registry head unavailable');return version;},
  async servers(scope){return Object.freeze((await pool.query(`SELECT entry_id::text AS id,name,transport,
    CASE WHEN transport='stdio' THEN NULL ELSE endpoint_text END AS url,
    CASE WHEN transport='stdio' THEN endpoint_text ELSE NULL END AS stdio_cmd,
    encode(schema_sha256,'hex') AS last_schema_hash,'registered'::text AS status,registered_by AS added_by,
    registered_at AS added_at,'owned_registry'::text AS provenance
   FROM secureshop_agents.bound_mcp_registry_entries WHERE ${predicate()} AND lifecycle='active' ORDER BY name LIMIT 33`,args(scope))).rows);},
  async history(scope){return Object.freeze((await pool.query(`SELECT name,registry_version::text AS version,
    encode(schema_sha256,'hex') AS schema_hash,discovered_at AS ts,'owned_registry'::text AS provenance
   FROM secureshop_agents.bound_mcp_registry_revisions WHERE ${predicate()} AND redacted_at IS NULL AND action IN ('register','import')
   ORDER BY discovered_at,name,registry_version LIMIT 257`,args(scope))).rows);},
  async tools(scope,name){if(typeof name!=='string'||!name||Buffer.byteLength(name)>256)return null;return(await pool.query(`SELECT r.registry_version::text AS version,encode(r.schema_sha256,'hex') AS schema_hash,r.tools_json
   FROM secureshop_agents.bound_mcp_registry_entries e JOIN secureshop_agents.bound_mcp_registry_revisions r
    ON r.platform_launch_id=e.platform_launch_id AND r.platform_scenario_id=e.platform_scenario_id AND r.platform_launch_generation=e.platform_launch_generation
    AND r.original_platform_owner_id=e.original_platform_owner_id AND r.original_platform_session_id=e.original_platform_session_id
    AND r.name=e.name AND r.registry_version=e.current_version
   WHERE ${predicate('e.')} AND e.lifecycle='active' AND e.name=$6 AND r.redacted_at IS NULL LIMIT 1`,[...args(scope),name])).rows[0]||null;}
 });
}
module.exports={createOwnedMcpRegistryAdminReadRepository};
