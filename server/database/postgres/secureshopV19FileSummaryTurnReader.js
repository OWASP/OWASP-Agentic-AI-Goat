'use strict';

const {
  createConversationBinding
} = require('../../services/secureshopConversationBinding');
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const SHA = /^[0-9a-f]{64}$/;
const PURPOSE = 'secureshop_file_summary';
const fail = code => Object.assign(new Error('File summary turn unavailable'), {
  code
});
function createV19FileSummaryTurnReader({
  pool
} = {}) {
  if (typeof pool?.connect !== 'function') throw new TypeError('Bound file summary turn pool required');
  return Object.freeze({
    async readFileSummaryRequest({
      sessionId,
      requestId,
      binding,
      purpose
    } = {}) {
      if (!UUID.test(sessionId || '') || !UUID.test(requestId || '') || purpose !== PURPOSE) throw fail('INVALID_ARGUMENT');
      const b = createConversationBinding(binding, {
        id: binding?.shopUserId,
        role: binding?.role
      });
      if (b.role !== 'customer') throw fail('INVALID_ARGUMENT');
      const client = await pool.connect();
      try {
        const rows = (await client.query(`SELECT tr.session_id,tr.request_id,tr.status,
          tr.request_hash,tr.request_version,tr.result_json
          FROM secureshop_agents.turn_requests tr
          JOIN secureshop_agents.agent_sessions s ON s.id=tr.session_id
          WHERE tr.session_id=$1 AND tr.request_id=$2 AND s.conversation_purpose=$3
            AND s.authority_mode='launch_bound' AND s.binding_state='active'
            AND s.platform_launch_id=$4 AND s.platform_scenario_id=$5
            AND s.platform_launch_generation=$6 AND s.original_platform_owner_id=$7
            AND s.original_platform_session_id=$8 AND s.user_id=$9 AND s.role=$10 LIMIT 2`, [sessionId.toLowerCase(), requestId.toLowerCase(), PURPOSE, b.launchId, b.scenarioId, b.generation, b.platformOwnerId, b.platformSessionId, b.shopUserId, b.role])).rows;
        if (rows.length > 1) throw fail('TURN_REQUEST_CONFLICT');
        const row = rows[0];
        if (!row) return null;
        if (row.session_id !== sessionId.toLowerCase() || row.request_id !== requestId.toLowerCase() || !['started', 'uncertain', 'completed'].includes(row.status) || row.request_version !== 1 || !SHA.test(row.request_hash || '') || row.status === 'completed' && (!row.result_json || typeof row.result_json !== 'object' || Array.isArray(row.result_json))) throw fail('TURN_REQUEST_CONFLICT');
        return Object.freeze(row);
      } finally {
        client.release();
      }
    }
  });
}
module.exports = {
  createV19FileSummaryTurnReader
};
