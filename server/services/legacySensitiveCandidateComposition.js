'use strict';

const { OBJECTIVES, WORKSHOP_KEY } = require('./legacySensitiveObjectiveGrader');
const { createLegacySensitiveCandidateApplication } = require('./legacySensitiveCandidateApplication');

const FLAG = 'LEGACY_SENSITIVE_CANONICAL_AGENT_ENABLED';
let retained;
const enabled=env=>env[FLAG]===undefined||env[FLAG]==='true';

async function assertLegacySensitiveCandidateReadiness({ pool, requiredObjectives = OBJECTIVES } = {}) {
  if (typeof pool?.query !== 'function') throw Object.assign(new Error('Canonical progress storage is unavailable'), { code: 'GRADE_STORE_NOT_READY' });
  const rows = (await pool.query(`SELECT o.objective_id,o.is_enabled,o.catalog_active,e.is_visible,e.catalog_active AS exercise_active
    FROM workshop_platform.objectives o JOIN workshop_platform.exercises e USING(workshop_key)
    WHERE o.workshop_key=$2 AND o.objective_id=ANY($1::text[])
    ORDER BY o.objective_id`, [[...requiredObjectives], WORKSHOP_KEY])).rows;
  // An instructor disabling one objective must not disable every sibling.
  // The completion repository checks the selected objective before accepting credit.
  if (rows.length !== requiredObjectives.length || rows.some(row => row.catalog_active !== true || row.is_visible !== true || row.exercise_active !== true)) {
    throw Object.assign(new Error('Canonical Legacy Sensitive objective catalog is not ready'), { code: 'GRADE_STORE_NOT_READY' });
  }
  return true;
}

async function createLegacySensitiveCandidateComposition({ legacyRuns, env = process.env,
  platformStores, completionService, agentProduction, tools, aggregateReset, legacyStore } = {}) {
  if (!enabled(env)) return null;
  const stores = platformStores || require('./postgresPlatformStores').getPostgresPlatformStores();
  await assertLegacySensitiveCandidateReadiness({ pool: stores.pool });
  const legacy = legacyStore || require('../database/sensitiveInfoDb');
  let reset=aggregateReset,ownedCleanupPool;
  if(!reset){
    const cleanupPool=ownedCleanupPool=require('../database/postgres').createPool(env,'FINFLOW_WORKSHOP_DATABASE_URL',{purpose:'workshop'});
    try{reset=(await require('./legacyFileSsiResetComposition').createLegacyFileSsiResetComposition({identityPool:stores.pool,finflowPool:cleanupPool,runs:legacyRuns})).reset;}
    catch(error){await cleanupPool.end();throw error;}
  }
  if (!reset || typeof reset.reset !== 'function') throw Object.assign(
    new Error('Sensitive Information aggregate reset is unavailable'), { code: 'RESET_STORAGE_NOT_READY' });
  try {
  const production = agentProduction || require('./legacySensitiveAgentProduction').createLegacySensitiveAgentProduction({
    env, tools: tools || require('./legacySensitiveTools').createLegacySensitiveTools({
      sensitiveFilesDir: legacy.sensitiveFilesDir, publicDir: legacy.publicDir,
    }),
  });
  return Object.freeze({ application: createLegacySensitiveCandidateApplication({
    agent: production.agent, runs: legacyRuns,
    modeAuthority: require('./workshopModeRunAuthority').createWorkshopModeRunAuthority({
      workshopKey: WORKSHOP_KEY,
      readScope: (userId, key) => stores.progress.getEvaluationScope(userId, key),
    }),
    admit: async () => {
      const row = (await stores.pool.query(`SELECT is_visible,catalog_active
        FROM workshop_platform.exercises WHERE workshop_key=$1`, [WORKSHOP_KEY])).rows[0];
      if (!row || row.is_visible !== true || row.catalog_active !== true) {
        throw Object.assign(new Error('Exercise is not enabled'), { code: 'OBJECTIVE_DISABLED' });
      }
    },
    snapshot: async userId => {
      const rows=await stores.progress.getVisibleUserProgress(userId);
      const row=rows.find(value=>value.workshopKey===WORKSHOP_KEY);
      if(!row)throw Object.assign(new Error('Exercise is not enabled'),{code:'OBJECTIVE_DISABLED'});
      const content={};
      for(const objective of row.objectives){
        const entry=content[objective.id]={};
        if(objective.hintVisible){const hint=await stores.config.getStudentContent(WORKSHOP_KEY,objective.id,'hint');entry.hints=hint.hints;}
        if(objective.solutionVisible){const solution=await stores.config.getStudentContent(WORKSHOP_KEY,objective.id,'solution');entry.solution=solution.approach||solution.description||'';}
      }
      return {challenges:[row],content};
    },
    completionService: completionService || require('./objectiveCompletionService').getObjectiveCompletionService(), reset,
  }), model: production.snapshot, reset });
  } catch(error) {if(ownedCleanupPool)await ownedCleanupPool.end();throw error;}
}

async function getLegacySensitiveCandidateComposition(options = {}) {
  if (!enabled(options.env || process.env)) return null;
  if (!retained) retained = createLegacySensitiveCandidateComposition(options).catch(error => { retained = null; throw error; });
  return retained;
}

module.exports = { FLAG, assertLegacySensitiveCandidateReadiness,
  createLegacySensitiveCandidateComposition, getLegacySensitiveCandidateComposition };
