'use strict';

const {
  createPool,
  withTransaction
} = require('./index');
const {
  initialize,
  singleton
} = require('./workshopSupport');
function owner(value) {
  if (typeof value !== 'string' || !value.length || value.length > 200) throw new TypeError('Workshop owner required');
  return value;
}
function deletionOwner(value) { const id=owner(value);if(!/^[1-9][0-9]{0,9}$/.test(id)||Number(id)>2147483647)throw new TypeError('Valid platform owner required');return id; }
function createCsrfWorkshopDb(pool) {
  return {
    engine: 'postgres',
    initialize: migration => initialize(pool, migration, 'csrf', async () => {}),
    async getProgress(userKey) {
      return (await pool.query('SELECT objective_id,completed,completed_at FROM csrf.progress WHERE user_key=$1 ORDER BY objective_id', [owner(userKey)])).rows;
    },
    async markProgress(userKey, objectiveId) {
      if (typeof objectiveId !== 'string' || !/^csrf_[gpxi][123]$/.test(objectiveId)) throw new TypeError('Invalid CSRF objective');
      await pool.query('INSERT INTO csrf.progress(user_key,objective_id) VALUES($1,$2) ON CONFLICT(user_key,objective_id) DO UPDATE SET completed=1,completed_at=now()', [owner(userKey), objectiveId]);
    },
    async logToolCall({
      userKey,
      tabId,
      toolName,
      args,
      resultSummary,
      flag,
      success = true
    }) {
      return (await pool.query('INSERT INTO csrf.tool_log(user_key,exercise_id,tool_name,args,result_summary,flag,success) VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING id', [owner(userKey), tabId, toolName, args, resultSummary, flag, success ? 1 : 0])).rows[0];
    },
    async listActivity(userKey, tabId = null) {
      return (await pool.query('SELECT id,exercise_id,tool_name,args,result_summary,flag,success,created_at FROM csrf.tool_log WHERE user_key=$1 AND ($2::text IS NULL OR exercise_id=$2) ORDER BY id DESC LIMIT 50', [owner(userKey), tabId])).rows;
    },
    async clearActivity(userKey) {
      await pool.query('DELETE FROM csrf.tool_log WHERE user_key=$1', [owner(userKey)]);
    },
    resetUser(userKey) {
      return withTransaction(pool, async client => {
        const id = owner(userKey);
        await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1,0))', [id]);
        await client.query('DELETE FROM csrf.progress WHERE user_key=$1', [id]);
        await client.query('DELETE FROM csrf.tool_log WHERE user_key=$1', [id]);
        await client.query('DELETE FROM csrf.victim_state WHERE session_key=$1', ['csrf_' + id]);
        await client.query('DELETE FROM csrf.wallets WHERE user_key=$1', [id]);
      });
    },
    destroyOwner(userKey) {
      const id = deletionOwner(userKey);
      return withTransaction(pool, async client => {
        await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1,0))', [id]);
        const progress = await client.query('DELETE FROM csrf.progress WHERE user_key=$1', [id]);
        const activity = await client.query('DELETE FROM csrf.tool_log WHERE user_key=$1', [id]);
        const victim = await client.query('DELETE FROM csrf.victim_state WHERE session_key=$1', ['csrf_' + id]);
        const wallets = await client.query('DELETE FROM csrf.wallets WHERE user_key=$1', [id]);
        return { removed: progress.rowCount + activity.rowCount + victim.rowCount + wallets.rowCount };
      });
    },
    resetTab(userKey, tabId, objectiveIds) {
      return withTransaction(pool, async client => {
        const id = owner(userKey);
        await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1,0))', [id]);
        await client.query('DELETE FROM csrf.progress WHERE user_key=$1 AND objective_id=ANY($2::text[])', [id, objectiveIds]);
        await client.query('DELETE FROM csrf.tool_log WHERE user_key=$1 AND exercise_id=$2', [id, tabId]);
      });
    },
    async getVictimState(sessionKey) {
      return (await pool.query('SELECT state_json FROM csrf.victim_state WHERE session_key=$1', [owner(sessionKey)])).rows[0]?.state_json || null;
    },
    async saveVictimState(sessionKey, state) {
      await pool.query('INSERT INTO csrf.victim_state(session_key,state_json) VALUES($1,$2::jsonb) ON CONFLICT(session_key) DO UPDATE SET state_json=EXCLUDED.state_json,updated_at=now()', [owner(sessionKey), JSON.stringify(state)]);
    },
    async deleteVictimState(sessionKey) {
      await pool.query('DELETE FROM csrf.victim_state WHERE session_key=$1', [owner(sessionKey)]);
    }
  };
}
const lazy = singleton(createCsrfWorkshopDb, 'CSRF_WORKSHOP_DATABASE_URL');
async function initializeCsrfWorkshopDb() {
  const migration = createPool(process.env, 'CSRF_WORKSHOP_MIGRATION_DATABASE_URL');
  try {
    await lazy('initialize')(migration);
  } finally {
    await migration.end();
  }
}
module.exports = {
  engine: 'postgres',
  createCsrfWorkshopDb,
  initializeCsrfWorkshopDb,
  ...Object.fromEntries(['getProgress', 'markProgress', 'logToolCall', 'listActivity', 'clearActivity', 'resetUser', 'destroyOwner', 'resetTab', 'getVictimState', 'saveVictimState', 'deleteVictimState'].map(name => [name, lazy(name)]))
};
