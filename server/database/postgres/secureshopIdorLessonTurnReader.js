'use strict';

const { createConversationBinding } = require('../../services/secureshopConversationBinding');

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const SHA = /^[0-9a-f]{64}$/;
const PURPOSE = 'secureshop_idor_lesson';
const fail = code => Object.assign(new Error('Isolated lesson turn unavailable'), { code });

// This reader is deliberately separate from the generic bound-request reader.
// Its only authority is a current, active customer session for this lesson.
function createSecureShopIdorLessonTurnReader({ pool } = {}) {
  if (typeof pool?.connect !== 'function') throw new TypeError('Agent turn pool required');
  async function selected({ requestId, binding, purpose, sessionId = null }) {
    if (!UUID.test(requestId || '') || (sessionId !== null && !UUID.test(sessionId || '')))
      throw fail('INVALID_ARGUMENT');
    const b = createConversationBinding(binding, { id: binding?.shopUserId,
      role: binding?.role });
    if (b.role !== 'customer' || purpose !== PURPOSE && purpose !== 'persona_inbox')
      throw fail('INVALID_ARGUMENT');
    const client = await pool.connect();
    try {
      const rows = (await client.query(`SELECT tr.session_id,tr.request_id,tr.status,
        tr.request_hash,tr.request_version,tr.result_json
        FROM secureshop_agents.turn_requests tr
        JOIN secureshop_agents.agent_sessions s ON s.id=tr.session_id
        WHERE tr.request_id=$1 AND s.conversation_purpose=$2
          AND s.authority_mode='launch_bound' AND s.binding_state='active'
          AND s.platform_launch_id=$3 AND s.platform_scenario_id=$4
          AND s.platform_launch_generation=$5
          AND s.original_platform_owner_id=$6
          AND s.original_platform_session_id=$7
          AND s.user_id=$8 AND s.role=$9 LIMIT 2`,
      [requestId.toLowerCase(), purpose, b.launchId, b.scenarioId,
        b.generation, b.platformOwnerId, b.platformSessionId,
        b.shopUserId, b.role])).rows;
      if (rows.length > 1 || rows[0] && sessionId !== null
          && rows[0].session_id !== sessionId.toLowerCase())
        throw fail('TURN_REQUEST_CONFLICT');
      const row = rows[0];
      if (!row) return null;
      if (!UUID.test(row.session_id || '') || row.request_id !== requestId.toLowerCase()
          || !['started','uncertain','completed'].includes(row.status)
          || row.request_version !== 1 || !SHA.test(row.request_hash || '')
          || row.status === 'completed' && (!row.result_json
            || typeof row.result_json !== 'object' || Array.isArray(row.result_json)))
        throw fail('TURN_REQUEST_CONFLICT');
      return Object.freeze({ session_id: row.session_id,
        request_id: row.request_id, status: row.status,
        request_hash: row.request_hash, request_version: row.request_version,
        result_json: row.result_json });
    } finally { client.release(); }
  }
  return Object.freeze({
    readIdorLessonRequest({ sessionId, requestId, binding, purpose } = {}) {
      if (purpose !== PURPOSE) throw fail('INVALID_ARGUMENT');
      return selected({ sessionId, requestId, binding, purpose });
    },
    readIdorLessonAssessment({ requestId, binding } = {}) {
      return selected({ requestId, binding, purpose: 'persona_inbox' });
    },
  });
}

module.exports = { createSecureShopIdorLessonTurnReader };
