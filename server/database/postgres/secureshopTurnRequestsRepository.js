'use strict';
const { randomUUID } = require('node:crypto');
const { createConversationBinding } = require('../../services/secureshopConversationBinding');
const { createTurnRequest } = require('../../services/secureshopTurnRequest');
const columns = ['platform_launch_id','platform_scenario_id','platform_launch_generation',
  'original_platform_owner_id','original_platform_session_id','user_id','role'];
const fail = code => Object.assign(new Error('Turn request unavailable'), { code });

function createTurnRequestsRepository({ pool }) {
  if (typeof pool?.connect !== 'function') throw new TypeError('Turn request pool required');
  async function transaction(sessionId, binding, operation, fence) {
    const b = createConversationBinding(binding, { id: binding.shopUserId, role: binding.role });
    const args = [sessionId,b.launchId,b.scenarioId,b.generation,b.platformOwnerId,b.platformSessionId,b.shopUserId,b.role];
    const ownedOperation=async client=>{
      const owned = await client.query(`SELECT id FROM secureshop_agents.agent_sessions
        WHERE id=$1 AND authority_mode='launch_bound' AND binding_state='active'
        AND ${columns.map((column, i) => `${column}=$${i + 2}`).join(' AND ')} FOR UPDATE`, args);
      if (!owned.rowCount) throw fail('CONVERSATION_UNAVAILABLE');
      return operation(client);
    };
    if(fence!==undefined){
      if(typeof fence?.withPersonaEffect!=='function'||!fence.binding
        ||['launchId','scenarioId','generation','platformOwnerId','platformSessionId'].some(key=>fence.binding[key]!==b[key])
        ||fence.binding.personaId!==b.shopUserId||fence.binding.role!==b.role)throw fail('SHOP_AUTH_INVALID');
      // Authority holds owner/admission locks first; use that same agents client.
      return fence.withPersonaEffect(ownedOperation);
    }
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      const result = await ownedOperation(client);
      await client.query('COMMIT');
      return result;
    } catch (error) {
      try { await client.query('ROLLBACK'); } catch {}
      throw error;
    } finally { client.release(); }
  }
  return Object.freeze({
    // A completed MCP turn must be located before refreshing a mutable remote
    // schema. This read never claims a request or provisions a conversation.
    async lookupMcpRequest({ requestId, binding, purpose }) {
      const b = createConversationBinding(binding, { id: binding.shopUserId, role: binding.role });
      const uuid = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
      if (b.role !== 'admin' || !uuid.test(requestId || '')
          || !['mcp_rogue_registration','mcp_rug_pull'].includes(purpose)) throw fail('INVALID_ARGUMENT');
      const client = await pool.connect();
      try {
        const rows = (await client.query(`SELECT tr.session_id,tr.request_id,tr.status,tr.request_hash,tr.request_version,tr.result_json
          FROM secureshop_agents.turn_requests tr JOIN secureshop_agents.agent_sessions s ON s.id=tr.session_id
          WHERE tr.request_id=$1 AND s.conversation_purpose=$2
            AND s.authority_mode='launch_bound' AND s.binding_state='active'
            AND ${columns.map((column,i)=>`s.${column}=$${i+3}`).join(' AND ')} LIMIT 2`,
        [requestId.toLowerCase(),purpose,b.launchId,b.scenarioId,b.generation,
          b.platformOwnerId,b.platformSessionId,b.shopUserId,b.role])).rows;
        if (rows.length > 1) throw fail('TURN_REQUEST_CONFLICT');
        return rows[0] || null;
      } finally { client.release(); }
    },
    async readAuditRequest({ sessionId, requestId, binding, purpose }) {
      const b = createConversationBinding(binding, { id: binding.shopUserId, role: binding.role });
      const uuid = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
      if (b.role !== 'admin' || !uuid.test(sessionId || '') || !uuid.test(requestId || '')
          || !['secureshop_audit_sql','secureshop_audit_summary'].includes(purpose)) throw fail('INVALID_ARGUMENT');
      const client = await pool.connect();
      try {
        const rows = (await client.query(`SELECT tr.session_id,tr.request_id,tr.status,tr.request_hash,tr.request_version,tr.result_json
          FROM secureshop_agents.turn_requests tr JOIN secureshop_agents.agent_sessions s ON s.id=tr.session_id
          WHERE tr.session_id=$1 AND tr.request_id=$2 AND s.conversation_purpose=$3
            AND s.authority_mode='launch_bound' AND s.binding_state='active'
            AND ${columns.map((column,i)=>`s.${column}=$${i+4}`).join(' AND ')} LIMIT 2`,
        [sessionId,requestId,purpose,b.launchId,b.scenarioId,b.generation,b.platformOwnerId,b.platformSessionId,b.shopUserId,b.role])).rows;
        if (rows.length > 1) throw fail('TURN_REQUEST_CONFLICT');
        return rows[0] || null;
      } finally { client.release(); }
    },
    async readRegisteredAdminRequest({ sessionId, requestId, binding }) {
      const b = createConversationBinding(binding, { id: binding.shopUserId, role: binding.role });
      const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
      if (b.role !== 'admin' || typeof sessionId !== 'string' || !uuid.test(sessionId)
          || typeof requestId !== 'string' || !uuid.test(requestId)) throw fail('INVALID_ARGUMENT');
      const client = await pool.connect();
      try {
        const rows = (await client.query(`SELECT tr.session_id,tr.request_id,tr.status,tr.request_hash,tr.request_version,tr.result_json
          FROM secureshop_agents.turn_requests tr
          JOIN secureshop_agents.agent_sessions s ON s.id=tr.session_id
          WHERE tr.session_id=$1 AND tr.request_id=$2 AND s.conversation_purpose='general'
            AND s.authority_mode='launch_bound' AND s.binding_state='active'
            AND ${columns.map((column, i) => `s.${column}=$${i + 3}`).join(' AND ')} LIMIT 2`,
        [sessionId,requestId,b.launchId,b.scenarioId,b.generation,b.platformOwnerId,
          b.platformSessionId,b.shopUserId,b.role])).rows;
        if (rows.length > 1) throw fail('TURN_REQUEST_CONFLICT');
        return rows[0] || null;
      } finally { client.release(); }
    },
    async readBoundRequest({ sessionId, requestId, binding, purpose }) {
      const b = createConversationBinding(binding, { id: binding.shopUserId, role: binding.role });
      if (typeof sessionId !== 'string' || typeof requestId !== 'string'
          || !['secureshop_refund_request','secureshop_customer_chat','secureshop_merchant_assistant',
            'secureshop_admin_assistant','secureshop_product_assist',
            'secureshop_product_manual_ingest'].includes(purpose)) throw fail('INVALID_ARGUMENT');
      const client = await pool.connect();
      try {
        const rows = (await client.query(`SELECT tr.session_id,tr.status,tr.request_hash,tr.request_version,tr.result_json
          FROM secureshop_agents.turn_requests tr
          JOIN secureshop_agents.agent_sessions s ON s.id=tr.session_id
          WHERE tr.request_id=$1
            AND s.conversation_purpose=$2 AND s.authority_mode='launch_bound'
            AND ${columns.map((column, i) => `s.${column}=$${i + 3}`).join(' AND ')} LIMIT 2`,
        [requestId.toLowerCase(),purpose,b.launchId,b.scenarioId,b.generation,
          b.platformOwnerId,b.platformSessionId,b.shopUserId,b.role])).rows;
        // The refund effect receipt carries a turn request ID, not a
        // conversation ID. Reused IDs across retained conversations cannot
        // be attributed to either turn, even when the requested one is live.
        if (rows.length > 1 || (rows[0] && rows[0].session_id !== sessionId)) throw fail('TURN_REQUEST_CONFLICT');
        return rows[0] || null;
      } finally { client.release(); }
    },
    async lookupGeneralRequest({ requestId, binding, message }) {
      const b = createConversationBinding(binding, { id: binding.shopUserId, role: binding.role });
      const client = await pool.connect();
      try {
        const result = await client.query(`SELECT tr.session_id,tr.request_id,tr.request_hash,tr.request_version,
            tr.status,tr.result_json
          FROM secureshop_agents.turn_requests tr
          JOIN secureshop_agents.agent_sessions s ON s.id=tr.session_id
          WHERE tr.request_id=$1 AND s.conversation_purpose='general'
            AND s.authority_mode='launch_bound' AND s.binding_state='active'
            AND ${columns.map((column, i) => `s.${column}=$${i + 2}`).join(' AND ')}`,
        [requestId.toLowerCase(),b.launchId,b.scenarioId,b.generation,b.platformOwnerId,
          b.platformSessionId,b.shopUserId,b.role]);
        if (result.rows.length !== 1) {
          return result.rows.length ? Object.freeze({ status: 'conflict' }) : null;
        }
        const row = result.rows[0];
        let expected;
        try {
          expected = createTurnRequest({ sessionId: row.session_id, requestId: row.request_id,
            binding: b, message, version: row.request_version });
        } catch (error) {
          if (error?.code === 'TURN_VERSION_UNAVAILABLE') return Object.freeze({ status: 'conflict' });
          throw error;
        }
        if (expected.hash !== row.request_hash) return Object.freeze({ status: 'conflict' });
        if (!['started', 'uncertain', 'completed'].includes(row.status)) return Object.freeze({ status: 'conflict' });
        return Object.freeze({ status: row.status, result: row.result_json });
      } finally { client.release(); }
    },
    async claim({ sessionId, requestId, binding, message }) {
      const request = createTurnRequest({ sessionId, requestId, binding, message });
      return transaction(request.sessionId, binding, async client => {
        const existing = (await client.query(`SELECT request_version,request_hash,status,result_json,claim_id
          FROM secureshop_agents.turn_requests WHERE session_id=$1 AND request_id=$2`,
        [request.sessionId,request.requestId])).rows[0];
        if (existing) {
          const retry = createTurnRequest({ sessionId, requestId, binding, message, version: existing.request_version });
          if (retry.hash !== existing.request_hash) throw fail('TURN_REQUEST_CONFLICT');
          return Object.freeze({ status: existing.status, requestId: request.requestId,
            claimId: existing.claim_id, ...(existing.status === 'completed' ? { result: existing.result_json } : {}) });
        }
        const count = (await client.query('SELECT COUNT(*)::integer AS count FROM secureshop_agents.turn_requests WHERE session_id=$1', [request.sessionId])).rows[0].count;
        if (count >= 256) throw fail('TURN_CAPACITY');
        const claimId = randomUUID();
        await client.query(`INSERT INTO secureshop_agents.turn_requests(session_id,request_id,request_hash,request_version,claim_id)
          VALUES($1,$2,$3,$4,$5)`, [request.sessionId,request.requestId,request.hash,request.version,claimId]);
        return Object.freeze({ status: 'claimed', requestId: request.requestId, claimId });
      });
    },
    async complete({ sessionId, requestId, binding, claimId, result }, fence) {
      if (!result || typeof result !== 'object' || Array.isArray(result)) throw fail('INVALID_TURN_RESULT');
      const encoded = JSON.stringify(result);
      if (Buffer.byteLength(encoded, 'utf8') > 262144) throw fail('TURN_RESULT_TOO_LARGE');
      return transaction(sessionId, binding, async client => {
        // PostgreSQL's JSONB representation may be larger than compact JSON;
        // check that representation too rather than relying on a CHECK error.
        const size = (await client.query('SELECT octet_length($1::jsonb::text) AS bytes', [encoded])).rows[0].bytes;
        if (size > 262144) throw fail('TURN_RESULT_TOO_LARGE');
        const changed = await client.query(`UPDATE secureshop_agents.turn_requests SET status='completed',result_json=$4::jsonb,finished_at=clock_timestamp()
          WHERE session_id=$1 AND request_id=$2 AND claim_id=$3 AND status='started'`, [sessionId,requestId,claimId,encoded]);
        if (changed.rowCount !== 1) throw fail('TURN_CLAIM_UNAVAILABLE');
      }, fence);
    },
    async markUncertain({ sessionId, requestId, binding, claimId }) {
      return transaction(sessionId, binding, async client => {
        const changed = await client.query(`UPDATE secureshop_agents.turn_requests SET status='uncertain',finished_at=clock_timestamp()
          WHERE session_id=$1 AND request_id=$2 AND claim_id=$3 AND status='started'`, [sessionId,requestId,claimId]);
        return changed.rowCount === 1;
      });
    },
  });
}
module.exports = { createTurnRequestsRepository };
