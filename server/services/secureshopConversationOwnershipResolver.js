'use strict';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

function positiveInteger(value) {
  const number = Number(value);
  return Number.isSafeInteger(number) && number > 0 ? number : null;
}

function createSecureShopConversationOwnershipResolver({ agentsPool, identityPool } = {}) {
  if (!agentsPool?.query || !identityPool?.query) {
    throw new TypeError('SecureShop agents and identity pools are required');
  }

  async function resolveRows(rows) {
    if (!rows.length) return new Map();
    const candidates = rows.filter(row => UUID.test(String(row.id || ''))
      && row.authority_mode === 'launch_bound' && ['active', 'abandoned'].includes(row.binding_state)
      && UUID.test(String(row.platform_launch_id || '')) && UUID.test(String(row.platform_scenario_id || ''))
      && positiveInteger(row.platform_launch_generation) && positiveInteger(row.original_platform_owner_id)
      && positiveInteger(row.original_platform_session_id));
    if (!candidates.length) return new Map();
    const launchIds = [...new Set(candidates.map(row => String(row.platform_launch_id).toLowerCase()))];
    const launches = (await identityPool.query(`SELECT launch_id,scenario_id,generation,status,
      original_platform_owner_id,original_platform_session_id
      FROM identity.secureshop_launches WHERE launch_id=ANY($1::uuid[])`, [launchIds])).rows;
    const byLaunch = new Map(launches.map(row => [String(row.launch_id).toLowerCase(), row]));
    const resolved = new Map();
    for (const row of candidates) {
      const conversationId = String(row.id || '').toLowerCase();
      const launchId = String(row.platform_launch_id || '').toLowerCase();
      const launch = byLaunch.get(launchId);
      const ownerId = positiveInteger(row.original_platform_owner_id);
      const sessionId = positiveInteger(row.original_platform_session_id);
      const generation = positiveInteger(row.platform_launch_generation);
      const launchGeneration = positiveInteger(launch?.generation);
      if (!launch || !ownerId || !sessionId || !generation || !launchGeneration
        || String(row.platform_scenario_id).toLowerCase() !== String(launch.scenario_id).toLowerCase()
        || ownerId !== positiveInteger(launch.original_platform_owner_id)
        || sessionId !== positiveInteger(launch.original_platform_session_id)
        || generation > launchGeneration
        || (row.binding_state === 'active' && generation !== launchGeneration)) continue;
      resolved.set(conversationId, Object.freeze({ conversationId, ownerId: String(ownerId), launchId,
        scenarioId: String(row.platform_scenario_id).toLowerCase(), generation, state: row.binding_state }));
    }
    return resolved;
  }

  async function resolveMany(conversationIds) {
    if (!Array.isArray(conversationIds)) throw new TypeError('Conversation IDs are required');
    const ids = [...new Set(conversationIds.map(value => String(value).toLowerCase()))];
    if (ids.some(id => !UUID.test(id))) throw new TypeError('Invalid SecureShop conversation ID');
    if (!ids.length) return new Map();
    const rows = (await agentsPool.query(`SELECT id,authority_mode,binding_state,platform_launch_id,
      platform_scenario_id,platform_launch_generation,original_platform_owner_id,original_platform_session_id
      FROM secureshop_agents.agent_sessions WHERE id=ANY($1::text[])`, [ids])).rows;
    return resolveRows(rows);
  }

  async function listOwnedConversationIds(platformOwnerId) {
    const ownerId = positiveInteger(platformOwnerId);
    if (!ownerId) throw new TypeError('Valid platform owner ID required');
    const rows = (await agentsPool.query(`SELECT id,authority_mode,binding_state,platform_launch_id,
      platform_scenario_id,platform_launch_generation,original_platform_owner_id,original_platform_session_id
      FROM secureshop_agents.agent_sessions
      WHERE authority_mode='launch_bound' AND binding_state IN ('active','abandoned')
        AND original_platform_owner_id=$1 ORDER BY created_at,id`, [ownerId])).rows;
    return [...(await resolveRows(rows)).keys()];
  }

  return Object.freeze({
    async resolve(conversationId) { return (await resolveMany([conversationId])).get(String(conversationId).toLowerCase()) || null; },
    resolveMany,
    listOwnedConversationIds,
  });
}

module.exports = { createSecureShopConversationOwnershipResolver };
