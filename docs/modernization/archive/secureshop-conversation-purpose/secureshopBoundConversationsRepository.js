'use strict';
const { createConversationBinding } = require('../../services/secureshopConversationBinding');
const { normalizeConversationPurpose } = require('../../services/secureshopConversationPurpose');
const { BOUND_TRACE_COLUMNS } = require('../../services/secureshopBoundTraceRecord');

const COLUMNS = 'platform_launch_id,platform_scenario_id,platform_launch_generation,original_platform_owner_id,original_platform_session_id,user_id,role';
const PURPOSE_COLUMN = 'conversation_purpose';
function values(binding) {
  const normalized = createConversationBinding(binding, { id: binding.shopUserId, role: binding.role });
  return [normalized.launchId, normalized.scenarioId, normalized.generation,
    normalized.platformOwnerId, normalized.platformSessionId, normalized.shopUserId, normalized.role];
}
const qualified = COLUMNS.split(',').map((column, index) => `s.${column}=$${index + 2}`).join(' AND ');
const qualifiedWithPurpose = `${qualified} AND s.${PURPOSE_COLUMN}=$9`;
function boundedLimit(limit) {
  if (!Number.isInteger(limit) || limit < 1 || limit > 500) throw new TypeError('Invalid trace limit');
  return limit;
}
function unavailable() { return Object.assign(new Error('Conversation unavailable'), { code: 'CONVERSATION_UNAVAILABLE' }); }
const exact = COLUMNS.split(',').map((column, index) => `${column}=$${index + 2}`).join(' AND ');
const exactWithPurpose = `${exact} AND ${PURPOSE_COLUMN}=$9`;

// Separate repository: legacy shop-only access must never implicitly select
// these rows. queue must provide qualified per-conversation serialization.
function createBoundConversationsRepository({ pool, queue }) {
  if (!pool || typeof pool.query !== 'function' || typeof queue !== 'function') throw new TypeError('Bound conversation pool and queue required');
  let purposeCapability;
  async function supportsPurpose(executor) {
    if (purposeCapability !== undefined) return purposeCapability;
    const result = await executor.query(`SELECT EXISTS(SELECT 1 FROM information_schema.columns
      WHERE table_schema='secureshop_agents' AND table_name='agent_sessions'
        AND column_name='conversation_purpose') AS ready`);
    purposeCapability = result.rows[0]?.ready === true;
    return purposeCapability;
  }
  async function purposeContext(executor, value) {
    const purpose = normalizeConversationPurpose(value);
    const supported = await supportsPurpose(executor);
    if (!supported && purpose !== 'general') throw unavailable();
    return Object.freeze({ purpose, supported });
  }
  return Object.freeze({
    async acquireBoundSession({ id, binding, purpose }) {
      const coordinates = values(binding);
      const client = await pool.connect();
      try {
        await client.query('BEGIN');
        const purposeState = await purposeContext(client, purpose);
        purpose = purposeState.purpose;
        // Short transaction only: never hold this connection across model or
        // tool execution. All processes serialize admission for one launch.
        await client.query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))", [`secureshop-conversation-admission:${coordinates[0]}`]);
        // The lifecycle table is a forward draft until its qualification and
        // promotion. Once present, a pending or completed generation journal
        // permanently fences late admission for that retired generation.
        const lifecycleAvailable = (await client.query(
          "SELECT to_regclass('secureshop_agents.conversation_generation_retirements') AS relation"
        )).rows[0]?.relation;
        if (lifecycleAvailable) {
          const retired = await client.query(`SELECT 1 FROM secureshop_agents.conversation_generation_retirements
            WHERE platform_launch_id=$1 AND from_generation=$2 LIMIT 1`, [coordinates[0], coordinates[2]]);
          if (retired.rowCount) throw unavailable();
        }
        const existing = (await client.query(`SELECT id,binding_state FROM secureshop_agents.agent_sessions
          WHERE authority_mode='launch_bound' AND ${COLUMNS.split(',').map((column, index) => `${column}=$${index + 1}`).join(' AND ')}
            ${purposeState.supported ? `AND ${PURPOSE_COLUMN}=$8` : ''}
          ORDER BY created_at,id LIMIT 2`, purposeState.supported ? [...coordinates,purpose] : coordinates)).rows;
        if (existing.length > 1 || existing[0]?.binding_state === 'abandoned') throw unavailable();
        if (existing.length) {
          await client.query('COMMIT');
          return Object.freeze({ id: existing[0].id, state: existing[0].binding_state, created: false });
        }
        // Count every retained state and generation; persona switching or reset
        // must not bypass the storage budget. Cleanup policy can later replace
        // this lifetime ceiling without silently deleting learner history.
        const count = (await client.query(`SELECT COUNT(*)::integer AS count FROM secureshop_agents.agent_sessions
          WHERE authority_mode='launch_bound' AND platform_launch_id=$1`, [coordinates[0]])).rows[0].count;
        if (count >= 256) throw Object.assign(new Error('Conversation capacity reached'), { code: 'CONVERSATION_CAPACITY' });
        await client.query(purposeState.supported
          ? `INSERT INTO secureshop_agents.agent_sessions
            (id,authority_mode,binding_state,${COLUMNS},${PURPOSE_COLUMN}) VALUES ($1,'launch_bound','pending',$2,$3,$4,$5,$6,$7,$8,$9)`
          : `INSERT INTO secureshop_agents.agent_sessions
            (id,authority_mode,binding_state,${COLUMNS}) VALUES ($1,'launch_bound','pending',$2,$3,$4,$5,$6,$7,$8)`,
        purposeState.supported ? [id, ...coordinates,purpose] : [id,...coordinates]);
        await client.query('COMMIT');
        return Object.freeze({ id, state: 'pending', created: true });
      } catch (error) {
        try { await client.query('ROLLBACK'); } catch {}
        throw error;
      } finally { client.release(); }
    },
    async createPendingBoundSession({ id, binding, purpose }) {
      const state = await purposeContext(pool,purpose); purpose=state.purpose;
      await pool.query(state.supported
        ? `INSERT INTO secureshop_agents.agent_sessions
          (id,authority_mode,binding_state,${COLUMNS},${PURPOSE_COLUMN}) VALUES ($1,'launch_bound','pending',$2,$3,$4,$5,$6,$7,$8,$9)`
        : `INSERT INTO secureshop_agents.agent_sessions
          (id,authority_mode,binding_state,${COLUMNS}) VALUES ($1,'launch_bound','pending',$2,$3,$4,$5,$6,$7,$8)`,
      state.supported ? [id,...values(binding),purpose] : [id,...values(binding)]);
      return Object.freeze({ id });
    },
    async activateBoundSession(id, binding, purpose) {
      const state=await purposeContext(pool,purpose);purpose=state.purpose;
      const result = await pool.query(`UPDATE secureshop_agents.agent_sessions SET binding_state='active'
        WHERE id=$1 AND authority_mode='launch_bound' AND binding_state='pending' AND ${state.supported?exactWithPurpose:exact}`,
      state.supported?[id,...values(binding),purpose]:[id,...values(binding)]);
      return result.rowCount === 1;
    },
    async abandonBoundSession(id, binding, purpose) {
      const state=await purposeContext(pool,purpose);purpose=state.purpose;
      const result = await pool.query(`UPDATE secureshop_agents.agent_sessions SET binding_state='abandoned'
        WHERE id=$1 AND authority_mode='launch_bound' AND binding_state IN ('pending','active') AND ${state.supported?exactWithPurpose:exact}`,
      state.supported?[id,...values(binding),purpose]:[id,...values(binding)]);
      return result.rowCount === 1;
    },
    async getBoundSession(id) {
      const supported=await supportsPurpose(pool);
      const row = (await pool.query(`SELECT id,binding_state,${COLUMNS}${supported?`,${PURPOSE_COLUMN}`:''} FROM secureshop_agents.agent_sessions
        WHERE id=$1 AND authority_mode='launch_bound'`, [id])).rows[0];
      if (!row) return null;
      const binding = createConversationBinding({ launchId: row.platform_launch_id, scenarioId: row.platform_scenario_id,
        generation: Number(row.platform_launch_generation), platformOwnerId: row.original_platform_owner_id,
        platformSessionId: row.original_platform_session_id }, { id: row.user_id, role: row.role });
      return Object.freeze({ id: row.id, state: row.binding_state, binding,
        ...(supported?{purpose:normalizeConversationPurpose(row.conversation_purpose)}:{}) });
    },
    async appendMessage(id, binding, message, purpose) {
      const state=await purposeContext(pool,purpose);purpose=state.purpose;
      const result = await pool.query(`UPDATE secureshop_agents.agent_sessions
        SET messages_json=(messages_json::jsonb || $${state.supported?10:9}::jsonb)::text,updated_at=clock_timestamp()
        WHERE id=$1 AND authority_mode='launch_bound' AND binding_state='active' AND ${state.supported?exactWithPurpose:exact}`,
      state.supported?[id,...values(binding),purpose,JSON.stringify([message])]:[id,...values(binding),JSON.stringify([message])]);
      if (result.rowCount !== 1) throw unavailable();
    },
    async getMessages(id, binding, purpose) {
      const state=await purposeContext(pool,purpose);purpose=state.purpose;
      const row = (await pool.query(`SELECT messages_json FROM secureshop_agents.agent_sessions
        WHERE id=$1 AND authority_mode='launch_bound' AND binding_state='active' AND ${state.supported?exactWithPurpose:exact}`,
      state.supported?[id,...values(binding),purpose]:[id,...values(binding)])).rows[0];
      if (!row) throw unavailable();
      return JSON.parse(row.messages_json);
    },
    async getTokens(id, binding, purpose) {
      const state=await purposeContext(pool,purpose);purpose=state.purpose;
      const row = (await pool.query(`SELECT token_budget_used FROM secureshop_agents.agent_sessions
        WHERE id=$1 AND authority_mode='launch_bound' AND binding_state='active' AND ${state.supported?exactWithPurpose:exact}`,
      state.supported?[id,...values(binding),purpose]:[id,...values(binding)])).rows[0];
      if (!row) throw unavailable();
      return row.token_budget_used;
    },
    async addTokens(id, binding, count, purpose) {
      if (!Number.isInteger(count) || count < 0 || count > 2147483647) throw new TypeError('Invalid token count');
      const state=await purposeContext(pool,purpose);purpose=state.purpose;
      const result = await pool.query(`UPDATE secureshop_agents.agent_sessions
        SET token_budget_used=token_budget_used+$${state.supported?10:9},updated_at=clock_timestamp()
        WHERE id=$1 AND authority_mode='launch_bound' AND binding_state='active' AND ${state.supported?exactWithPurpose:exact}`,
      state.supported?[id,...values(binding),purpose,count]:[id,...values(binding),count]);
      if (result.rowCount !== 1) throw unavailable();
    },
    async appendTraces(id, binding, rows, purpose) {
      if (!Array.isArray(rows) || rows.length > 1000) throw new TypeError('Invalid trace batch');
      const state=await purposeContext(pool,purpose);purpose=state.purpose;
      const columns = BOUND_TRACE_COLUMNS;
      const payloads = rows.map(row => {
        if (!row || row.session_id !== id || typeof row.event_id !== 'string' || !row.event_id) throw new TypeError('Invalid trace identity');
        return columns.map(column => row[column] ?? null);
      });
      const args = state.supported?[id,...values(binding),purpose]:[id,...values(binding)];
      const client = await pool.connect();
      try {
        await client.query('BEGIN');
        const active = await client.query(`SELECT id FROM secureshop_agents.agent_sessions
          WHERE id=$1 AND authority_mode='launch_bound' AND binding_state='active' AND ${state.supported?exactWithPurpose:exact} FOR SHARE`, args);
        if (!active.rowCount) throw unavailable();
        for (const payload of payloads) {
          const same = columns.map(column => `t.${column}`).join(',');
          const incoming = columns.map(column => `EXCLUDED.${column}`).join(',');
          const result = await client.query(`INSERT INTO secureshop_agents.agent_trace AS t (${columns.join(',')})
            VALUES (${columns.map((_, index) => '$' + (index + 1)).join(',')})
            ON CONFLICT(event_id) DO UPDATE SET event_id=EXCLUDED.event_id
            WHERE (${same}) IS NOT DISTINCT FROM (${incoming}) RETURNING event_id`, payload);
          if (result.rowCount !== 1) throw Object.assign(new Error('Trace identity conflict'), { code: 'TRACE_CONFLICT' });
        }
        await client.query('COMMIT');
      } catch (error) {
        try { await client.query('ROLLBACK'); } catch {}
        throw error;
      } finally { client.release(); }
    },
    async getTrace(id, binding, limit = 100, purpose) {
      const state=await purposeContext(pool,purpose);purpose=state.purpose;
      return (await pool.query(`SELECT t.id,t.session_id,t.step,t.actor,t.kind,t.agent_ns,t.tool_name,t.params_json,t.result_json,t.latency_ms,t.tokens_in,t.tokens_out,t.provider,t.policy_violation,t.ts FROM secureshop_agents.agent_trace t
        JOIN secureshop_agents.agent_sessions s ON s.id=t.session_id
        WHERE s.id=$1 AND s.authority_mode='launch_bound' AND s.binding_state='active' AND ${state.supported?qualifiedWithPurpose:qualified}
        ORDER BY t.ts ASC,t.id ASC LIMIT $${state.supported?10:9}`,
      state.supported?[id,...values(binding),purpose,boundedLimit(limit)]:[id,...values(binding),boundedLimit(limit)])).rows;
    },
    async latestTrace(binding, limit = 20, purpose) {
      const state=await purposeContext(pool,purpose);purpose=state.purpose;
      const coordinates = COLUMNS.split(',').map((column, index) => `s.${column}=$${index + 1}`).join(' AND ');
      return (await pool.query(`SELECT t.id,t.session_id,s.role AS session_role,t.step,t.actor,t.kind,t.agent_ns,t.tool_name,t.latency_ms,t.tokens_in,t.tokens_out,t.provider,t.ts FROM secureshop_agents.agent_trace t
        JOIN secureshop_agents.agent_sessions s ON s.id=t.session_id
        WHERE s.authority_mode='launch_bound' AND s.binding_state='active' AND ${coordinates} ${state.supported?`AND s.${PURPOSE_COLUMN}=$8`:''}
        ORDER BY t.ts DESC,t.id DESC LIMIT $${state.supported?9:8}`,
      state.supported?[...values(binding),purpose,boundedLimit(limit)]:[...values(binding),boundedLimit(limit)])).rows;
    },
    runExclusive(id, operation) { return queue(id, operation); },
  });
}
module.exports = { createBoundConversationsRepository };
