'use strict';

const { createConversationBinding } = require('./secureshopConversationBinding');
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
function denied() { return Object.assign(new Error('Prompt policy run authority unavailable'), { code: 'POLICY_RUN_AUTHORITY_UNAVAILABLE' }); }

// Identity and agent stores are separate databases. These reads are not a
// distributed transaction: callers must retain the coordinator lease and check
// execution authority before and after snapshot admission. The repository's
// persona effect fence protects the agent-side lifecycle during this callback.
function createPromptPolicyRunBinding({ identityPool } = {}) {
  if (typeof identityPool?.query !== 'function') throw new TypeError('Identity run store required');
  return async function checkRunBinding(client, raw) {
    const input = structuredClone(raw);
    const binding = createConversationBinding(input.scope, input.persona);
    if (typeof client?.query !== 'function' || typeof input.runId !== 'string' || !UUID.test(input.runId)) throw denied();
    const read = async () => (await identityPool.query(`SELECT r.owner_key,r.generation::text AS generation
      FROM graph_runtime.runs r JOIN graph_runtime.owners o ON o.owner_key=r.owner_key
      WHERE r.run_id=$1 AND r.status='running' AND r.finished_at IS NULL AND r.generation=o.generation`, [input.runId])).rows;
    const runs = await read();
    if (runs.length !== 1) throw denied();
    const run = runs[0];
    let owner;
    try { owner = JSON.parse(run.owner_key); } catch { throw denied(); }
    if (!Array.isArray(owner) || owner.length !== 2 || owner[0] !== 'SecureShopBoundConversation'
      || typeof owner[1] !== 'string' || !UUID.test(owner[1]) || JSON.stringify(owner) !== run.owner_key) throw denied();
    const rows = (await client.query(`SELECT id FROM secureshop_agents.agent_sessions
      WHERE id=$1 AND authority_mode='launch_bound' AND binding_state='active'
      AND platform_launch_id=$2 AND platform_scenario_id=$3 AND platform_launch_generation=$4
      AND original_platform_owner_id=$5 AND original_platform_session_id=$6 AND user_id=$7 AND role=$8`,
    [owner[1], binding.launchId, binding.scenarioId, binding.generation, binding.platformOwnerId,
      binding.platformSessionId, binding.shopUserId, binding.role])).rows;
    if (rows.length !== 1 || rows[0].id !== owner[1]) throw denied();
    const after = await read();
    if (after.length !== 1 || after[0].owner_key !== run.owner_key || after[0].generation !== run.generation) throw denied();
    return true;
  };
}

module.exports = { createPromptPolicyRunBinding };
