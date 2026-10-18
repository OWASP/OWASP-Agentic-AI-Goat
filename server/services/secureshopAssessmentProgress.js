'use strict';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const USERNAME = /^[a-z][a-z0-9_]{2,31}$/;
const OBJECTIVE = /^ss_[a-z0-9_]{1,100}$/;
const exact = (value, keys) => value && Object.getPrototypeOf(value) === Object.prototype
  && Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key));
const fail = () => Object.assign(new Error('Shop assessment progress unavailable'), { code: 'SHOP_PROGRESS_UNAVAILABLE' });

function projectObjective(value) {
  if (!exact(value, ['objectiveId', 'label', 'completed']) || typeof value.objectiveId !== 'string'
      || !OBJECTIVE.test(value.objectiveId) || typeof value.label !== 'string' || !value.label.length
      || Buffer.byteLength(value.label, 'utf8') > 4096 || typeof value.completed !== 'boolean') {
    throw fail();
  }
  return Object.freeze({ objectiveId: value.objectiveId, label: value.label, completed: value.completed });
}

function projectProgress(value) {
  if (!exact(value, ['principalId', 'shopUserId', 'username', 'role', 'generation', 'objectives',
    'totalObjectives', 'completedObjectives']) || typeof value.principalId !== 'string'
      || !UUID.test(value.principalId) || !Number.isSafeInteger(value.shopUserId) || value.shopUserId < 1
      || typeof value.username !== 'string' || !USERNAME.test(value.username)
      || !['customer', 'merchant', 'admin'].includes(value.role)
      || !Number.isSafeInteger(value.generation) || value.generation < 0
      || !Array.isArray(value.objectives) || value.objectives.length > 256
      || !Number.isSafeInteger(value.totalObjectives) || !Number.isSafeInteger(value.completedObjectives)) {
    throw fail();
  }
  const objectives = value.objectives.map(projectObjective);
  if (new Set(objectives.map(row => row.objectiveId)).size !== objectives.length
      || value.totalObjectives !== objectives.length
      || value.completedObjectives !== objectives.filter(row => row.completed).length) {
    throw fail();
  }
  return Object.freeze({ principalId: value.principalId.toLowerCase(), shopUserId: value.shopUserId,
    username: value.username, role: value.role, generation: value.generation,
    objectives: Object.freeze(objectives), totalObjectives: value.totalObjectives,
    completedObjectives: value.completedObjectives });
}

function targetInput(value) {
  if (!exact(value, ['targetPrincipalId']) || typeof value.targetPrincipalId !== 'string'
      || !UUID.test(value.targetPrincipalId)) throw fail();
  return { targetPrincipalId: value.targetPrincipalId.toLowerCase() };
}

function listInput(value) {
  if (value === undefined) return { limit: 25, cursor: null };
  if (!exact(value, ['limit', 'cursor']) || !Number.isSafeInteger(value.limit)
      || value.limit < 1 || value.limit > 50
      || !(value.cursor === null || (Number.isSafeInteger(value.cursor) && value.cursor >= 0))) throw fail();
  return { limit: value.limit, cursor: value.cursor };
}

function createSecureShopAssessmentProgress({ repository } = {}) {
  if (typeof repository?.readSelf !== 'function' || typeof repository.readLearner !== 'function'
      || typeof repository.listLearners !== 'function') {
    throw new TypeError('Shop assessment progress repository required');
  }
  return Object.freeze({
    async readSelf(base) {
      return projectProgress(await repository.readSelf({ base }));
    },
    async readLearner(base, input) {
      return projectProgress(await repository.readLearner({ base, ...targetInput(input) }));
    },
    async listLearners(base, input) {
      const page = listInput(input);
      const value = await repository.listLearners({ base, ...page });
      if (!exact(value, ['learners', 'nextCursor']) || !Array.isArray(value.learners)
          || value.learners.length > page.limit
          || !(value.nextCursor === null || (Number.isSafeInteger(value.nextCursor) && value.nextCursor > 0))) {
        throw fail();
      }
      const learners = value.learners.map(projectProgress);
      if (new Set(learners.map(row => row.principalId)).size !== learners.length) throw fail();
      return Object.freeze({ learners: Object.freeze(learners), nextCursor: value.nextCursor });
    },
  });
}

module.exports = { createSecureShopAssessmentProgress };
