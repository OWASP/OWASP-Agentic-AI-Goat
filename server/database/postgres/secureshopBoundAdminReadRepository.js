'use strict';
const { createLaunchScope } = require('../../services/secureshopConversationBinding');
const predicate = `t.launch_id=$1 AND t.scenario_id=$2 AND t.generation=$3
 AND t.original_platform_owner_id=$4 AND t.original_platform_session_id=$5 AND t.lifecycle='active'`;
function args(raw) { const s=createLaunchScope(raw); return [s.launchId,s.scenarioId,s.generation,s.platformOwnerId,s.platformSessionId]; }
function createSecureShopBoundAdminReadRepository({ agentsPool, reviewPool }) {
 if (!agentsPool?.query || !reviewPool?.query) throw new TypeError('Bound read pools required');
 return Object.freeze({
  async probe(scope) {
   const results=await Promise.allSettled([
    agentsPool.query(`SELECT 1 FROM secureshop_agents.bound_mcp_targets t WHERE ${predicate} LIMIT 1`,args(scope)),
    reviewPool.query(`SELECT 1 FROM secureshop_review.product_targets t WHERE ${predicate} LIMIT 1`,args(scope)),
   ]);
   const failure=results.find(r=>r.status==='rejected');if(failure)throw failure.reason;
   // An empty current launch is legitimate; successful scoped queries establish
   // store availability without inventing a provisioned target.
   return true;
  },
  async mcpServers(scope) {
   return (await agentsPool.query(`SELECT t.target_id AS id,t.server_identity AS name,t.trust_scenario,
    t.current_schema_version AS schema_version,t.created_at AS registered_at,t.created_at AS added_at,
    encode(v.schema_sha256,'hex') AS last_schema_hash,'discovered'::text AS status
    FROM secureshop_agents.bound_mcp_targets t
    LEFT JOIN secureshop_agents.bound_mcp_schema_versions v ON v.target_id=t.target_id AND v.version=t.current_schema_version
    WHERE ${predicate} ORDER BY t.server_identity LIMIT 3`,args(scope))).rows;
  },
  async mcpHistory(scope) {
   return (await agentsPool.query(`SELECT t.server_identity AS name,v.version,encode(v.schema_sha256,'hex') AS schema_hash,
    v.discovered_at AS ts FROM secureshop_agents.bound_mcp_targets t
    JOIN secureshop_agents.bound_mcp_schema_versions v USING(target_id) WHERE ${predicate}
    ORDER BY v.discovered_at,t.server_identity,v.version LIMIT 33`,args(scope))).rows;
  },
  async mcpTools(scope, name) {
   const rows=(await agentsPool.query(`SELECT v.version,encode(v.schema_sha256,'hex') AS schema_hash,p.tools_json
    FROM secureshop_agents.bound_mcp_targets t
    JOIN secureshop_agents.bound_mcp_schema_versions v ON v.target_id=t.target_id AND v.version=t.current_schema_version
    JOIN secureshop_agents.bound_mcp_tool_payloads p ON p.target_id=v.target_id AND p.version=v.version
    WHERE ${predicate} AND t.server_identity=$6 LIMIT 1`,[...args(scope),name])).rows;
   return rows[0] || null;
  },
  async sizes(scope) {
   // Logical serialized rows only: no physical database size, paths, credentials,
   // payload text or sibling counts leave the store. Explicit selected scope.
   const results=await Promise.allSettled([
    agentsPool.query(`SELECT coalesce(sum(octet_length(to_jsonb(v)::text)),0)::text AS bytes
     FROM secureshop_agents.bound_mcp_targets t JOIN secureshop_agents.bound_mcp_schema_versions v USING(target_id)
     WHERE ${predicate}`,args(scope)),
    reviewPool.query(`SELECT coalesce(sum(octet_length(to_jsonb(p)::text)),0)::text AS bytes
     FROM secureshop_review.product_targets t JOIN secureshop_review.product_target_products p USING(target_id)
     WHERE ${predicate}`,args(scope)),
   ]);
   const failure=results.find(r=>r.status==='rejected'); if(failure)throw failure.reason;
   return results.map((r,i)=>{const bytes=Number(r.value.rows[0]?.bytes);if(!Number.isSafeInteger(bytes)||bytes<0)throw new Error('Invalid logical byte measurement');
    return {path:['MCP schema rows','Product source rows'][i],size_bytes:bytes,size_mb:Math.round(bytes/1048576*1000000)/1000000};});
  },
 });
}
module.exports={createSecureShopBoundAdminReadRepository};
