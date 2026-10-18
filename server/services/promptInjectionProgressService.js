'use strict';

const { WORKSHOP_OBJECTIVES } = require('../config/workshopCatalog');

const WORKSHOP_KEY = 'direct_prompt_injection';
const PRACTICE_OBJECTIVE_ID = 'interact';
const CATALOG = new Map(
  WORKSHOP_OBJECTIVES[WORKSHOP_KEY].map(({ id, text }) => [id, text])
);

class PromptInjectionProgressError extends Error {
  constructor(message, { statusCode = 400, field = null, code = 'INVALID_PROGRESS' } = {}) {
    super(message);
    this.name = 'PromptInjectionProgressError';
    this.statusCode = statusCode;
    this.field = field;
    this.code = code;
  }
}

function validateIdentity(userId, userKey) {
  if (!Number.isInteger(userId) || userId <= 0) {
    throw new PromptInjectionProgressError('An authenticated user is required', {
      statusCode: 401,
      field: 'userId',
      code: 'AUTH_REQUIRED',
    });
  }
  if (userKey !== String(userId)) {
    throw new PromptInjectionProgressError('userKey must identify the authenticated user', {
      statusCode: 403,
      field: 'userKey',
      code: 'USER_MISMATCH',
    });
  }
}

function validateCatalogObjective(objectiveId) {
  if (typeof objectiveId !== 'string' || !CATALOG.has(objectiveId)) {
    throw new PromptInjectionProgressError('objectiveId is not a known Direct Prompt Injection objective', {
      statusCode: 400,
      field: 'objectiveId',
      code: 'UNKNOWN_OBJECTIVE',
    });
  }
}

function createPostgresPromptInjectionProgressService({ pool, progress, config }) {
  if (!pool?.query || !progress?.getWorkshopProgress || !config?.getSnapshot) {
    throw new TypeError('PostgreSQL platform stores are required');
  }

  async function visibleObjective(objectiveId) {
    validateCatalogObjective(objectiveId);
    const exercise = (await config.getSnapshot()).exercises[WORKSHOP_KEY];
    if (!exercise?.isVisible) {
      throw new PromptInjectionProgressError('Direct Prompt Injection workshop is not enabled', {
        statusCode: 403, field: 'workshop', code: 'WORKSHOP_DISABLED',
      });
    }
    if (!exercise.objectives[objectiveId]?.isVisible) {
      throw new PromptInjectionProgressError('Objective is not enabled', {
        statusCode: 403, field: 'objectiveId', code: 'OBJECTIVE_DISABLED',
      });
    }
    return exercise;
  }

  async function interactionCount(userId) {
    const row = (await pool.query(
      `SELECT activity_count FROM workshop_platform.activity_counters
       WHERE user_id=$1 AND workshop_key=$2 AND activity_key=$3`,
      [userId, WORKSHOP_KEY, PRACTICE_OBJECTIVE_ID]
    )).rows[0];
    return Number(row?.activity_count || 0);
  }

  async function read({ userId, userKey }) {
    validateIdentity(userId, userKey);
    const snapshot = await config.getSnapshot();
    const exercise = snapshot.exercises[WORKSHOP_KEY];
    if (!exercise?.isVisible) {
      return { objectives: {}, objectiveCount: 0, completedObjectiveCount: 0,
        completed: false, workshopStatus: 'not_started' };
    }
    const canonical = await progress.getWorkshopProgress(userId, WORKSHOP_KEY);
    const count = await interactionCount(userId);
    const enabledIds = Object.entries(exercise.objectives)
      .filter(([, objective]) => objective.isVisible)
      .map(([objectiveId]) => objectiveId)
      .filter((objectiveId) => CATALOG.has(objectiveId));
    const byId = new Map((canonical?.objectives || []).map((objective) => [objective.id, objective]));
    const objectives = Object.fromEntries(enabledIds.map((objectiveId) => {
      const objective = byId.get(objectiveId);
      return [objectiveId, {
        completed: objective?.completed === true,
        interactionCount: objectiveId === PRACTICE_OBJECTIVE_ID ? count : 0,
        completedAt: objective?.completedAt || null,
      }];
    }));
    const completedObjectiveCount = Object.values(objectives).filter((objective) => objective.completed).length;
    const completed = enabledIds.length > 0 && completedObjectiveCount === enabledIds.length;
    return {
      objectives,
      objectiveCount: enabledIds.length,
      completedObjectiveCount,
      completed,
      workshopStatus: completed ? 'completed' : (completedObjectiveCount > 0 || count > 0 ? 'in_progress' : 'not_started'),
    };
  }

  return {
    async assertObjectiveEnabled(objectiveId) {
      await visibleObjective(objectiveId);
      return true;
    },
    getProgress: read,
    async completeObjective({ userId, userKey, objectiveId }) {
      validateIdentity(userId, userKey);
      await visibleObjective(objectiveId);
      throw new PromptInjectionProgressError('Objective completion requires an accepted Judge receipt', {
        statusCode: 409, field: 'objectiveId', code: 'JUDGED_ATTEMPT_REQUIRED',
      });
    },
    async recordValidInteraction({ userId, userKey }) {
      validateIdentity(userId, userKey);
      await visibleObjective(PRACTICE_OBJECTIVE_ID);
      throw new PromptInjectionProgressError('Practice credit requires an accepted Judge receipt', {
        statusCode: 409, field: 'objectiveId', code: 'JUDGED_ATTEMPT_REQUIRED',
      });
    },
    async resetProgress({ userId, userKey }) {
      validateIdentity(userId, userKey);
      await progress.resetWorkshopProgress(userId, WORKSHOP_KEY);
      return read({ userId, userKey });
    },
  };
}

function createDefaultPromptInjectionProgressService() {
  return createPostgresPromptInjectionProgressService(
    require('./postgresPlatformStores').getPostgresPlatformStores()
  );
}

module.exports = {
  createPostgresPromptInjectionProgressService,
  createDefaultPromptInjectionProgressService,
  PromptInjectionProgressError,
  WORKSHOP_KEY,
};
