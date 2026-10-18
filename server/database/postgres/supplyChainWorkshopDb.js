'use strict';

const {
  createPool,
  withTransaction
} = require('./index');
const {
  initialize,
  singleton
} = require('./workshopSupport');
const {
  SC_OBJECTIVE_IDS
} = require('../../data/supplyChainSolutions');
function owner(value) {
  if (typeof value !== 'string' || !value.length || value.length > 200) throw new TypeError('Workshop owner required');
  return value;
}
async function seed(client) {
  for (const [ordinal, id] of SC_OBJECTIVE_IDS.entries()) await client.query('INSERT INTO supply_chain.objectives(objective_id,ordinal) VALUES($1,$2) ON CONFLICT(objective_id) DO UPDATE SET ordinal=EXCLUDED.ordinal', [id, ordinal]);
}
function createSupplyChainWorkshopDb(pool) {
  return {
    engine: 'postgres',
    initialize: migration => initialize(pool, migration, 'supply_chain', seed),
    async ensureObjectives(userId) {
      await pool.query('INSERT INTO supply_chain.progress(user_id,objective_id) SELECT $1,objective_id FROM supply_chain.objectives ON CONFLICT DO NOTHING', [owner(userId)]);
    },
    async getProgress(userId) {
      return (await pool.query('SELECT p.objective_id,p.status,p.completed_at FROM supply_chain.progress p JOIN supply_chain.objectives o USING(objective_id) WHERE p.user_id=$1 ORDER BY o.ordinal', [owner(userId)])).rows;
    },
    completeObjective(userId, objectiveId) {
      if (!SC_OBJECTIVE_IDS.includes(objectiveId)) throw new TypeError('Unknown Supply Chain objective');
      return withTransaction(pool, async client => {
        const id = owner(userId);
        await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1,0))', [id]);
        const result = await client.query("INSERT INTO supply_chain.progress(user_id,objective_id,status,completed_at) VALUES($1,$2,'completed',now()) ON CONFLICT(user_id,objective_id) DO UPDATE SET status='completed',completed_at=COALESCE(supply_chain.progress.completed_at,EXCLUDED.completed_at) WHERE supply_chain.progress.status<>'completed' RETURNING completed_at", [id, objectiveId]);
        return {
          changed: result.rowCount > 0,
          completed: true
        };
      });
    },
    async resetUser(userId) {
      await pool.query('DELETE FROM supply_chain.progress WHERE user_id=$1', [owner(userId)]);
    },
    async destroyOwner(userId) {
      const id=owner(userId);
      if (!/^[1-9][0-9]{0,9}$/.test(id) || Number(id) > 2147483647) throw new TypeError('Valid platform owner required');
      const result = await pool.query('DELETE FROM supply_chain.progress WHERE user_id=$1', [id]);
      return { removed: result.rowCount };
    }
  };
}
const lazy = singleton(createSupplyChainWorkshopDb, 'SUPPLY_CHAIN_WORKSHOP_DATABASE_URL');
async function initializeSupplyChainWorkshopDb() {
  const migration = createPool(process.env, 'SUPPLY_CHAIN_WORKSHOP_MIGRATION_DATABASE_URL');
  try {
    await lazy('initialize')(migration);
  } finally {
    await migration.end();
  }
}
module.exports = {
  engine: 'postgres',
  createSupplyChainWorkshopDb,
  initializeSupplyChainWorkshopDb,
  ...Object.fromEntries(['ensureObjectives', 'getProgress', 'completeObjective', 'resetUser', 'destroyOwner'].map(name => [name, lazy(name)]))
};
