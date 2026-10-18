'use strict';

const WORKSHOP_KEY = 'indirect_prompt_injection';

function emptyProgress(objectiveIds) {
  return Object.fromEntries(objectiveIds.map((objectiveId) => [objectiveId, { completed: false }]));
}

function createPostgresRagProgressStore({ progress }, objectiveIds) {
  if (!progress?.getWorkshopProgress) throw new TypeError('PostgreSQL progress store is required');
  return {
    async complete({ objectiveId, platformUserId, durable = false }) {
      if (!platformUserId || durable) return;
      await progress.syncObjectiveComplete(platformUserId, WORKSHOP_KEY, objectiveId, objectiveId);
      await progress.checkAndMarkWorkshopComplete(platformUserId, WORKSHOP_KEY);
    },
    async get({ platformUserId }) {
      const objectives = emptyProgress(objectiveIds);
      if (!platformUserId) return objectives;
      const current = await progress.getWorkshopProgress(platformUserId, WORKSHOP_KEY);
      for (const objective of current?.objectives || []) {
        if (objectives[objective.id]) {
          objectives[objective.id] = {
            completed: objective.completed === true,
            ...(objective.completedAt ? { completedAt: objective.completedAt } : {}),
          };
        }
      }
      return objectives;
    },
    async reset({ platformUserId }) {
      if (!platformUserId) return;
      await progress.resetWorkshopProgress(platformUserId, WORKSHOP_KEY, { objectiveIds });
    },
  };
}

function createDefaultRagProgressStore(objectiveIds) {
  return createPostgresRagProgressStore(
    require('./postgresPlatformStores').getPostgresPlatformStores(), objectiveIds
  );
}

module.exports = { createPostgresRagProgressStore, createDefaultRagProgressStore };
