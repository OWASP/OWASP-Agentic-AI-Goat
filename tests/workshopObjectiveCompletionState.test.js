'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { createWorkshopProgressRepository } = require('../server/database/postgres/workshopProgressRepository');

function fixture({ generation = 4, completions = new Set() } = {}) {
  const queries = [];
  const client = {
    async query(sql, params = []) {
      queries.push({ sql, params });
      if (/^(BEGIN|COMMIT|ROLLBACK)$/.test(sql)) return { rows: [], rowCount: 0 };
      if (sql.includes('FROM workshop_platform.exercises')) return { rows: [{ workshop_key: 'xss_workshop' }], rowCount: 1 };
      if (sql.includes('INSERT INTO workshop_platform.user_state')) return { rows: [], rowCount: 0 };
      if (sql.includes('FROM workshop_platform.user_state')) return { rows: [{ generation }], rowCount: 1 };
      if (sql.includes('FROM workshop_platform.completions')) {
        if (params.length === 2) {
          const prefix = `${params[0]}:${params[1]}:`;
          const rows = [...completions].filter(key => key.startsWith(prefix))
            .map(key => ({ objective_id: key.slice(prefix.length) })).sort((a, b) => a.objective_id.localeCompare(b.objective_id));
          return { rows, rowCount: rows.length };
        }
        const key = `${params[0]}:${params[1]}:${params[2]}`;
        return { rows: completions.has(key) ? [{ '?column?': 1 }] : [], rowCount: completions.has(key) ? 1 : 0 };
      }
      throw new Error(`Unexpected query: ${sql}`);
    },
    release() {},
  };
  return {
    pool: { connect: async () => client },
    queries,
    // Deliberate decoy representing a workshop-local projection. The canonical
    // repository must never consult this source.
    localXssProjection: new Set(['8:xss_g2']),
  };
}

test('canonical completion lookup ignores local projections and binds owner plus generation', async () => {
  const state = fixture({ completions: new Set(['7:xss_workshop:xss_g2']) });
  const repository = createWorkshopProgressRepository(state.pool);
  assert.deepEqual(await repository.getObjectiveCompletionState(7, 'xss_workshop', 'xss_g2', { expectedGeneration: 4 }),
    { completed: true, generation: 4 });
  assert.deepEqual(await repository.getObjectiveCompletionState(8, 'xss_workshop', 'xss_g2', { expectedGeneration: 4 }),
    { completed: false, generation: 4 });
  assert.equal(state.localXssProjection.has('8:xss_g2'), true, 'decoy local projection is positive');
  assert.deepEqual(await repository.getCanonicalWorkshopCompletions(7, 'xss_workshop', { expectedGeneration: 4 }),
    { objectiveIds: ['xss_g2'], generation: 4 });
  assert.deepEqual(await repository.getCanonicalWorkshopCompletions(8, 'xss_workshop', { expectedGeneration: 4 }),
    { objectiveIds: [], generation: 4 });
  assert.ok(state.queries.some(entry => entry.sql.includes('workshop_platform.completions')));
  assert.ok(state.queries.every(entry => !entry.sql.includes('xss.progress')));
  await assert.rejects(repository.getObjectiveCompletionState(7, 'xss_workshop', 'xss_g2', { expectedGeneration: 3 }), { code: 'STALE_GENERATION' });
  await assert.rejects(repository.getObjectiveCompletionState(7, 'xss_workshop', 'unknown', { expectedGeneration: 4 }), { code: 'NOT_FOUND' });
  await assert.rejects(repository.getObjectiveCompletionState(7, 'xss_workshop', 'xss_g2', {}), { code: 'BAD_REQUEST' });
  await assert.rejects(repository.getObjectiveCompletionState(7, 'xss_workshop', 'xss_g2', { expectedGeneration: -1 }), { code: 'BAD_REQUEST' });
  await assert.rejects(repository.getCanonicalWorkshopCompletions(7, 'xss_workshop', { expectedGeneration: 3 }), { code: 'STALE_GENERATION' });
  await assert.rejects(repository.getCanonicalWorkshopCompletions(7, 'xss_workshop'), { code: 'BAD_REQUEST' });
});
