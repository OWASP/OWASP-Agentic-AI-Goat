'use strict';

const { withTransaction } = require('./index');
const { bump } = require('./workshopPlatformSupport');
const { readConfig } = require('./workshopConfigRepository');

const CHALLENGE_IDS = Object.freeze(['reflected', 'stored_user', 'stored_llm', 'email']);

function createXssLegacyAdminRepository(pool) {
  if (!pool?.query || !pool?.connect) throw new TypeError('PostgreSQL pool is required');

  async function mutation(work) {
    return withTransaction(pool, async client => {
      await client.query('SELECT revision FROM workshop_platform.config_revision WHERE id=1 FOR UPDATE');
      const result = await work(client);
      await client.query('UPDATE workshop_platform.config_revision SET revision=revision+1,updated_at=now() WHERE id=1');
      await bump(client, { scopeType: 'workshop', scopeKey: 'xss_workshop', category: 'workshop_config' });
      return result;
    });
  }

  return {
    async listSolutions() {
      return (await pool.query(`SELECT v.challenge_id,v.solutions_enabled,v.enabled_by,
        to_char(v.enabled_at AT TIME ZONE 'UTC','YYYY-MM-DD HH24:MI:SS') AS enabled_at,
        to_char(v.updated_at AT TIME ZONE 'UTC','YYYY-MM-DD HH24:MI:SS') AS updated_at,
        s.title,s.difficulty
        FROM workshop_platform.xss_legacy_solution_visibility v
        LEFT JOIN workshop_platform.xss_legacy_solutions s USING(challenge_id)
        ORDER BY v.challenge_id`)).rows;
    },

    async setVisibility(challengeId, enabled, actorId) {
      return mutation(async client => (await client.query(`UPDATE workshop_platform.xss_legacy_solution_visibility
        SET solutions_enabled=$1,enabled_by=$2,
            enabled_at=CASE WHEN $1 THEN now() ELSE enabled_at END,updated_at=now()
        WHERE challenge_id=$3`, [Boolean(enabled), actorId ?? null, challengeId])).rowCount);
    },

    async setAllVisibility(enabled, actorId) {
      return mutation(async client => (await client.query(`UPDATE workshop_platform.xss_legacy_solution_visibility
        SET solutions_enabled=$1,enabled_by=$2,
            enabled_at=CASE WHEN $1 THEN now() ELSE enabled_at END,updated_at=now()`,
      [Boolean(enabled), actorId ?? null])).rowCount);
    },

    async getSolution(challengeId) {
      return (await pool.query(`SELECT title,difficulty,hints,examples,approach,tips
        FROM workshop_platform.xss_legacy_solutions WHERE challenge_id=$1`, [challengeId])).rows[0] || null;
    },

    async updateSolution(challengeId, content) {
      return mutation(async client => (await client.query(`UPDATE workshop_platform.xss_legacy_solutions
        SET title=$1,difficulty=$2,hints=$3,examples=$4,approach=$5,tips=$6,updated_at=now()
        WHERE challenge_id=$7`, [content.title, content.difficulty, content.hints, content.examples,
        content.approach, content.tips, challengeId])).rowCount);
    },

    async setCanonicalAndLegacyMasterVisibility(enabled, actorId) {
      return mutation(async client => {
        let changed = (await client.query(`UPDATE workshop_platform.exercises
          SET show_solutions=$1,updated_by=$2,updated_at=now()
          WHERE workshop_key='xss_workshop' AND show_solutions IS DISTINCT FROM $1`,
        [enabled, actorId ?? null])).rowCount;
        changed += (await client.query(`UPDATE workshop_platform.objectives
          SET solution_enabled=$1,updated_by=$2,updated_at=now()
          WHERE workshop_key='xss_workshop' AND catalog_active=true
            AND solution_enabled IS DISTINCT FROM $1 AND (solution_content IS NOT NULL OR $1=false)`,
        [enabled, actorId ?? null])).rowCount;
        changed += (await client.query(`UPDATE workshop_platform.xss_legacy_solution_visibility
          SET solutions_enabled=$1,enabled_by=$2,
              enabled_at=CASE WHEN $1 THEN now() ELSE enabled_at END,updated_at=now()`,
        [enabled, actorId ?? null])).rowCount;
        const snapshot = await readConfig(client, { includeRaw: true });
        return { changed: changed > 0, revision: snapshot.revision + 1,
          exercise: snapshot.exercises.xss_workshop };
      });
    },
  };
}

module.exports = { CHALLENGE_IDS, createXssLegacyAdminRepository };
