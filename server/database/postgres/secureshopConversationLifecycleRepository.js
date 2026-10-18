'use strict';

const { createHash } = require('node:crypto');
const { createLaunchScope } = require('../../services/secureshopConversationBinding');

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const SHA256 = /^[a-f0-9]{64}$/;
const TABLE = 'secureshop_agents.conversation_generation_retirements';
function failure(code, message = 'Conversation generation retirement unavailable') {
  return Object.assign(new Error(message), { code });
}
function uuid(value, label) {
  if (typeof value !== 'string' || !UUID.test(value)) throw failure('INVALID_ARGUMENT', `${label} is invalid`);
  return value.toLowerCase();
}
function operation(input) {
  if (!input || Object.getPrototypeOf(input) !== Object.prototype) throw failure('INVALID_ARGUMENT');
  return Object.freeze({ resetId: uuid(input.resetId, 'resetId'), ...createLaunchScope(input.binding) });
}
function same(row, scope) {
  return row.reset_id === scope.resetId && row.platform_launch_id === scope.launchId
    && row.platform_scenario_id === scope.scenarioId
    && Number(row.from_generation) === scope.generation
    && Number(row.original_platform_owner_id) === scope.platformOwnerId
    && Number(row.original_platform_session_id) === scope.platformSessionId;
}
function iso(value) {
  if (!(value instanceof Date) && typeof value !== 'string') {
    throw failure('INVALID_RETIREMENT_RECEIPT');
  }
  const date = value instanceof Date ? value : new Date(value);
  if (!Number.isFinite(date.getTime())) throw failure('INVALID_RETIREMENT_RECEIPT');
  const canonical = date.toISOString();
  if (typeof value === 'string' && value !== canonical) throw failure('INVALID_RETIREMENT_RECEIPT');
  return canonical;
}
function digestSessionIds(ids) {
  if (!Array.isArray(ids) || ids.some(id => typeof id !== 'string' || !UUID.test(id))) {
    throw failure('INVALID_RETIREMENT_RECEIPT');
  }
  const sorted = ids.map(id => id.toLowerCase()).sort();
  if (new Set(sorted).size !== sorted.length) throw failure('INVALID_RETIREMENT_RECEIPT');
  return createHash('sha256').update(JSON.stringify(sorted), 'utf8').digest('hex');
}
function buildReceipt(scope, { completedAt, sessionCount, uncertainTurnCount, sessionSetSha256 }) {
  if (!Number.isInteger(sessionCount) || sessionCount < 0
      || !Number.isInteger(uncertainTurnCount) || uncertainTurnCount < 0
      || typeof sessionSetSha256 !== 'string' || !SHA256.test(sessionSetSha256)) {
    throw failure('INVALID_RETIREMENT_RECEIPT');
  }
  completedAt = iso(completedAt);
  const fields = Object.freeze({ version: 1, resetId: scope.resetId, launchId: scope.launchId,
    scenarioId: scope.scenarioId, fromGeneration: scope.generation,
    platformOwnerId: scope.platformOwnerId, platformSessionId: scope.platformSessionId,
    status: 'completed', sessionCount, uncertainTurnCount, sessionSetSha256, completedAt });
  const receiptSha256 = createHash('sha256').update(JSON.stringify([
    'dvaia-secureshop-conversation-generation-retirement', fields.version, fields.resetId,
    fields.launchId, fields.scenarioId, fields.fromGeneration, fields.platformOwnerId,
    fields.platformSessionId, fields.status, fields.sessionCount, fields.uncertainTurnCount,
    fields.sessionSetSha256, fields.completedAt,
  ]), 'utf8').digest('hex');
  return Object.freeze({ ...fields, receiptSha256 });
}
function rowReceipt(row, scope) {
  if (!row || !same(row, scope) || row.status !== 'completed'
      || !Buffer.isBuffer(row.session_set_sha256) || row.session_set_sha256.length !== 32
      || !Buffer.isBuffer(row.receipt_sha256) || row.receipt_sha256.length !== 32) {
    throw failure('INVALID_RETIREMENT_RECEIPT');
  }
  const receipt = buildReceipt(scope, { completedAt: row.completed_at,
    sessionCount: row.session_count, uncertainTurnCount: row.uncertain_turn_count,
    sessionSetSha256: row.session_set_sha256.toString('hex') });
  if (receipt.receiptSha256 !== row.receipt_sha256.toString('hex')) {
    throw failure('INVALID_RETIREMENT_RECEIPT');
  }
  return receipt;
}

function createSecureShopConversationLifecycleRepository({ pool } = {}) {
  if (typeof pool?.connect !== 'function' || typeof pool?.query !== 'function') {
    throw failure('INVALID_CONFIGURATION');
  }
  async function transaction(work) {
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      const result = await work(client);
      await client.query('COMMIT');
      return result;
    } catch (error) {
      try { await client.query('ROLLBACK'); } catch {}
      throw error;
    } finally { client.release(); }
  }
  async function lockedOperation(client, scope, statuses = ['pending', 'completed']) {
    const row = (await client.query(`SELECT * FROM ${TABLE} WHERE reset_id=$1 FOR UPDATE`, [scope.resetId])).rows[0];
    if (!row || !same(row, scope) || !statuses.includes(row.status)) throw failure('RETIREMENT_SCOPE_MISMATCH');
    return row;
  }
  async function assertPersonasRetired(client, scope) {
    const available = (await client.query(
      "SELECT to_regclass('secureshop_agents.bound_persona_sessions') AS relation"
    )).rows[0]?.relation;
    if (!available) return;
    const active = await client.query(`SELECT 1 FROM secureshop_agents.bound_persona_sessions
      WHERE platform_launch_id=$1 AND platform_scenario_id=$2
        AND platform_launch_generation=$3 AND original_platform_owner_id=$4
        AND original_platform_session_id=$5 AND revoked_at IS NULL LIMIT 1`,
    [scope.launchId, scope.scenarioId, scope.generation,
      scope.platformOwnerId, scope.platformSessionId]);
    if (active.rowCount) throw failure('RETIREMENT_INCOMPLETE');
  }
  async function validateCompleted(client, row, scope) {
    const receipt = rowReceipt(row, scope);
    const sessions = (await client.query(`SELECT id,binding_state FROM secureshop_agents.agent_sessions
      WHERE authority_mode='launch_bound' AND platform_launch_id=$1 AND platform_scenario_id=$2
        AND platform_launch_generation=$3 AND original_platform_owner_id=$4
        AND original_platform_session_id=$5 ORDER BY id`, [scope.launchId, scope.scenarioId,
      scope.generation, scope.platformOwnerId, scope.platformSessionId])).rows;
    if (sessions.some(session => session.binding_state !== 'abandoned')
        || sessions.length !== receipt.sessionCount
        || digestSessionIds(sessions.map(session => session.id)) !== receipt.sessionSetSha256) {
      throw failure('INVALID_RETIREMENT_RECEIPT');
    }
    const turnCounts = (await client.query(`SELECT
        COUNT(*) FILTER (WHERE t.status='started')::integer AS started_count,
        COUNT(*) FILTER (WHERE t.status='uncertain')::integer AS uncertain_count
      FROM secureshop_agents.turn_requests t JOIN secureshop_agents.agent_sessions s ON s.id=t.session_id
      WHERE s.authority_mode='launch_bound' AND s.platform_launch_id=$1
        AND s.platform_scenario_id=$2 AND s.platform_launch_generation=$3
        AND s.original_platform_owner_id=$4 AND s.original_platform_session_id=$5`,
    [scope.launchId, scope.scenarioId, scope.generation,
      scope.platformOwnerId, scope.platformSessionId])).rows[0];
    if (turnCounts.started_count !== 0 || turnCounts.uncertain_count !== receipt.uncertainTurnCount) {
      throw failure('INVALID_RETIREMENT_RECEIPT');
    }
    await assertPersonasRetired(client, scope);
    return receipt;
  }
  return Object.freeze({
    async beginRetirement(input) {
      const scope = operation(input);
      return transaction(async client => {
        await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1,0))',
          [`secureshop-conversation-admission:${scope.launchId}`]);
        const rows = (await client.query(`SELECT * FROM ${TABLE}
          WHERE reset_id=$1 OR (platform_launch_id=$2 AND from_generation=$3) FOR UPDATE`,
        [scope.resetId, scope.launchId, scope.generation])).rows;
        if (rows.length) {
          if (rows.length !== 1 || !same(rows[0], scope)) throw failure('RETIREMENT_SCOPE_MISMATCH');
          return Object.freeze({ resetId: scope.resetId, status: rows[0].status,
            ...(rows[0].status === 'completed'
              ? { receipt: await validateCompleted(client, rows[0], scope) } : {}) });
        }
        await client.query(`INSERT INTO ${TABLE}
          (reset_id,platform_launch_id,platform_scenario_id,from_generation,
           original_platform_owner_id,original_platform_session_id)
          VALUES($1,$2,$3,$4,$5,$6)`, [scope.resetId, scope.launchId, scope.scenarioId,
          scope.generation, scope.platformOwnerId, scope.platformSessionId]);
        return Object.freeze({ resetId: scope.resetId, status: 'pending' });
      });
    },
    async listRetirableSessions(input) {
      const scope = operation(input);
      const row = (await pool.query(`SELECT * FROM ${TABLE} WHERE reset_id=$1`, [scope.resetId])).rows[0];
      if (!row || !same(row, scope)) throw failure('RETIREMENT_SCOPE_MISMATCH');
      const rows = (await pool.query(`SELECT id,binding_state FROM secureshop_agents.agent_sessions
        WHERE authority_mode='launch_bound' AND platform_launch_id=$1 AND platform_scenario_id=$2
          AND platform_launch_generation=$3 AND original_platform_owner_id=$4
          AND original_platform_session_id=$5 ORDER BY id`, [scope.launchId, scope.scenarioId,
        scope.generation, scope.platformOwnerId, scope.platformSessionId])).rows;
      return Object.freeze(rows.map(value => Object.freeze({ sessionId: value.id, state: value.binding_state })));
    },
    async retireSession(input) {
      const scope = operation(input);
      const sessionId = uuid(input.sessionId, 'sessionId');
      return transaction(async client => {
        const journal = await lockedOperation(client, scope, ['pending']);
        const session = (await client.query(`SELECT id,binding_state FROM secureshop_agents.agent_sessions
          WHERE id=$1 AND authority_mode='launch_bound' AND platform_launch_id=$2
            AND platform_scenario_id=$3 AND platform_launch_generation=$4
            AND original_platform_owner_id=$5 AND original_platform_session_id=$6 FOR UPDATE`,
        [sessionId, scope.launchId, scope.scenarioId, scope.generation,
          scope.platformOwnerId, scope.platformSessionId])).rows[0];
        if (!session) throw failure('CONVERSATION_UNAVAILABLE');
        if (session.binding_state === 'abandoned') {
          const started = await client.query("SELECT 1 FROM secureshop_agents.turn_requests WHERE session_id=$1 AND status='started' LIMIT 1", [sessionId]);
          if (started.rowCount) throw failure('RETIREMENT_INCOMPLETE');
          return Object.freeze({ sessionId, replayed: true, uncertainTurns: 0 });
        }
        if (!['pending', 'active'].includes(session.binding_state) || journal.status !== 'pending') {
          throw failure('CONVERSATION_UNAVAILABLE');
        }
        // Terminalize admitted work while the parent is still active. The turn
        // trigger takes a parent share lock, so no new started row can race this.
        const uncertain = await client.query(`UPDATE secureshop_agents.turn_requests
          SET status='uncertain',finished_at=clock_timestamp()
          WHERE session_id=$1 AND status='started'`, [sessionId]);
        const abandoned = await client.query(`UPDATE secureshop_agents.agent_sessions
          SET binding_state='abandoned' WHERE id=$1 AND binding_state IN ('pending','active')`, [sessionId]);
        if (abandoned.rowCount !== 1) throw failure('RETIREMENT_INCOMPLETE');
        return Object.freeze({ sessionId, replayed: false, uncertainTurns: uncertain.rowCount });
      });
    },
    async completeRetirement(input) {
      const scope = operation(input);
      return transaction(async client => {
        await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1,0))',
          [`secureshop-conversation-admission:${scope.launchId}`]);
        const row = await lockedOperation(client, scope);
        if (row.status === 'completed') {
          return Object.freeze({ receipt: await validateCompleted(client, row, scope), replayed: true });
        }
        // Do not row-lock sessions after taking the launch advisory lock. A
        // direct UPDATE owns its row before its BEFORE trigger can take that
        // advisory lock, so advisory -> row would invert the order. The durable
        // journal already makes every pending/active insert or update fail once
        // it reaches the trigger. Abandoned rows and terminal turns are one-way,
        // so these committed facts cannot become usable after this read.
        const sessions = (await client.query(`SELECT id,binding_state FROM secureshop_agents.agent_sessions
          WHERE authority_mode='launch_bound' AND platform_launch_id=$1 AND platform_scenario_id=$2
            AND platform_launch_generation=$3 AND original_platform_owner_id=$4
            AND original_platform_session_id=$5 ORDER BY id`, [scope.launchId,
          scope.scenarioId, scope.generation, scope.platformOwnerId, scope.platformSessionId])).rows;
        if (sessions.some(session => session.binding_state !== 'abandoned')) throw failure('RETIREMENT_INCOMPLETE');
        const started = await client.query(`SELECT 1 FROM secureshop_agents.turn_requests t
          JOIN secureshop_agents.agent_sessions s ON s.id=t.session_id
          WHERE s.authority_mode='launch_bound' AND s.platform_launch_id=$1
            AND s.platform_scenario_id=$2 AND s.platform_launch_generation=$3
            AND s.original_platform_owner_id=$4 AND s.original_platform_session_id=$5
            AND t.status='started' LIMIT 1`, [scope.launchId, scope.scenarioId,
          scope.generation, scope.platformOwnerId, scope.platformSessionId]);
        if (started.rowCount) throw failure('RETIREMENT_INCOMPLETE');
        await assertPersonasRetired(client, scope);
        const uncertain = (await client.query(`SELECT COUNT(*)::integer AS count
          FROM secureshop_agents.turn_requests t JOIN secureshop_agents.agent_sessions s ON s.id=t.session_id
          WHERE s.authority_mode='launch_bound' AND s.platform_launch_id=$1
            AND s.platform_scenario_id=$2 AND s.platform_launch_generation=$3
            AND s.original_platform_owner_id=$4 AND s.original_platform_session_id=$5
            AND t.status='uncertain'`, [scope.launchId, scope.scenarioId,
          scope.generation, scope.platformOwnerId, scope.platformSessionId])).rows[0].count;
        const sessionSetSha256 = digestSessionIds(sessions.map(session => session.id));
        const completedAt = (await client.query('SELECT clock_timestamp() AS now')).rows[0].now;
        const receipt = buildReceipt(scope, { completedAt, sessionCount: sessions.length,
          uncertainTurnCount: uncertain, sessionSetSha256 });
        const changed = await client.query(`UPDATE ${TABLE} SET status='completed',session_count=$2,
          uncertain_turn_count=$3,session_set_sha256=$4,receipt_sha256=$5,completed_at=$6
          WHERE reset_id=$1 AND status='pending' RETURNING *`, [scope.resetId, receipt.sessionCount,
          receipt.uncertainTurnCount, Buffer.from(receipt.sessionSetSha256, 'hex'),
          Buffer.from(receipt.receiptSha256, 'hex'), receipt.completedAt]);
        if (changed.rowCount !== 1) throw failure('RETIREMENT_INCOMPLETE');
        return Object.freeze({ receipt: rowReceipt(changed.rows[0], scope), replayed: false });
      });
    },
    async readRetirementReceipt(input) {
      const scope = operation(input);
      return transaction(async client => {
        const row = (await client.query(`SELECT * FROM ${TABLE} WHERE reset_id=$1 FOR SHARE`,
          [scope.resetId])).rows[0];
        return validateCompleted(client, row, scope);
      });
    },
  });
}

module.exports = { createSecureShopConversationLifecycleRepository, buildReceipt, digestSessionIds };
