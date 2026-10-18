'use strict';

const { createConversationBinding } = require('../../services/secureshopConversationBinding');

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const SHA = /^[a-f0-9]{64}$/;
const fail = () => Object.assign(new Error('Ticket browser assessment turn unavailable'),
  { code: 'TICKET_BROWSER_ASSESSMENT_UNAVAILABLE' });

// The browser assessment request ID is selected by the server-side admin
// workflow. This reader only retrieves its exact original persona_inbox turn.
function createTicketBrowserAssessmentReader({ pool } = {}) {
  if (typeof pool?.connect !== 'function') throw new TypeError('Agent turn pool required');
  return Object.freeze({
    async readTicketBrowserAssessment({ requestId, binding } = {}) {
      if (!UUID.test(requestId || '')) throw fail();
      const b = createConversationBinding(binding,
        { id: binding?.shopUserId, role: binding?.role });
      if (b.role !== 'admin') throw fail();
      const client = await pool.connect();
      try {
        const rows = (await client.query(`SELECT tr.session_id,tr.request_id,tr.status,
          tr.request_hash,tr.request_version,tr.result_json
          FROM secureshop_agents.turn_requests tr
          JOIN secureshop_agents.agent_sessions s ON s.id=tr.session_id
          WHERE tr.request_id=$1 AND s.conversation_purpose='persona_inbox'
            AND s.authority_mode='launch_bound' AND s.binding_state='active'
            AND s.platform_launch_id=$2 AND s.platform_scenario_id=$3
            AND s.platform_launch_generation=$4
            AND s.original_platform_owner_id=$5
            AND s.original_platform_session_id=$6
            AND s.user_id=$7 AND s.role='admin' LIMIT 2`,
        [requestId.toLowerCase(), b.launchId, b.scenarioId, b.generation,
          b.platformOwnerId, b.platformSessionId, b.shopUserId])).rows;
        if (rows.length > 1) throw fail();
        const row = rows[0];
        if (!row) return null;
        if (!UUID.test(row.session_id || '')
            || row.request_id !== requestId.toLowerCase()
            || !['started','uncertain','completed'].includes(row.status)
            || row.request_version !== 1 || !SHA.test(row.request_hash || '')
            || row.status === 'completed' && (!row.result_json
              || typeof row.result_json !== 'object'
              || Array.isArray(row.result_json))) throw fail();
        return Object.freeze({ session_id: row.session_id,
          request_id: row.request_id, status: row.status,
          request_hash: row.request_hash, request_version: row.request_version,
          result_json: row.result_json });
      } finally { client.release(); }
    },
  });
}

module.exports = { createTicketBrowserAssessmentReader };
