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
  if (typeof value !== 'string' || !value.length || value.length > 200) throw new TypeError('Workshop owner is required');
  return value;
}
function deletionOwner(value) { const id=owner(value);if(!/^[1-9][0-9]{0,9}$/.test(id)||Number(id)>2147483647)throw new TypeError('Valid platform owner required');return id; }
function createMcpWorkshopDb(pool) {
  return {
    engine: 'postgres',
    async runtimePool() { return pool; },
    initialize: migrationPool => initialize(pool, migrationPool, 'mcp', async () => {}),
    async getProgress(userKey) {
      return (await pool.query('SELECT objective_id,completed,completed_at FROM mcp.progress WHERE user_key=$1 ORDER BY objective_id', [owner(userKey)])).rows;
    },
    async markProgress(userKey, objectiveId) {
      if (typeof objectiveId !== 'string' || !/^mcp_[a-z_]+$/.test(objectiveId)) throw new TypeError('Invalid MCP objective');
      await pool.query('INSERT INTO mcp.progress(user_key,objective_id) VALUES($1,$2) ON CONFLICT(user_key,objective_id) DO UPDATE SET completed=1,completed_at=now()', [owner(userKey), objectiveId]);
    },
    async logToolCall({
      userKey,
      toolName,
      args,
      resultSummary,
      outcome = null,
      success = true
    }) {
      const row = (await pool.query('INSERT INTO mcp.tool_log(user_key,tool_name,args,result_summary,outcome,success) VALUES($1,$2,$3,$4,$5,$6) RETURNING id', [owner(userKey), toolName, args, resultSummary, outcome, success ? 1 : 0])).rows[0];
      return row;
    },
    async listActivity(userKey) {
      return (await pool.query('SELECT id,tool_name,args,result_summary,outcome,success,created_at FROM mcp.tool_log WHERE user_key=$1 ORDER BY id DESC LIMIT 50', [owner(userKey)])).rows;
    },
    async clearActivity(userKey) {
      await pool.query('DELETE FROM mcp.tool_log WHERE user_key=$1', [owner(userKey)]);
    },
    resetUser(userKey) {
      return withTransaction(pool, async client => {
        const id = owner(userKey);
        await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1,0))', [id]);
        await client.query('DELETE FROM mcp.progress WHERE user_key=$1', [id]);
        await client.query('DELETE FROM mcp.tool_log WHERE user_key=$1', [id]);
      });
    },
    destroyOwner(userKey) {
      const id = deletionOwner(userKey);
      return withTransaction(pool, async client => {
        await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1,0))', [id]);
        const progress = await client.query('DELETE FROM mcp.progress WHERE user_key=$1', [id]);
        const activity = await client.query('DELETE FROM mcp.tool_log WHERE user_key=$1', [id]);
        return { removed: progress.rowCount + activity.rowCount };
      });
    }
  };
}
const method = singleton(createMcpWorkshopDb, 'MCP_WORKSHOP_DATABASE_URL');
async function initializeMcpWorkshopDb() {
  const migration = createPool(process.env, 'MCP_WORKSHOP_MIGRATION_DATABASE_URL');
  try {
    await method('initialize')(migration);
  } finally {
    await migration.end();
  }
}
module.exports = {
  createMcpWorkshopDb,
  engine: 'postgres',
  initializeMcpWorkshopDb,
  ...Object.fromEntries(['runtimePool', 'getProgress', 'markProgress', 'logToolCall', 'listActivity', 'clearActivity', 'resetUser', 'destroyOwner'].map(name => [name, method(name)]))
};
