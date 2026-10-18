'use strict';

const AGENT_RESOURCE_METHODS = Object.freeze([
  'readDataset', 'deleteDataset', 'createBackup', 'downloadBackup', 'listBackups',
  'readLogOverlay', 'writeLogOverlay',
]);

function unavailable(message = 'FinFlow agent resource storage is not ready') {
  return Object.assign(new Error(message), {
    code: 'FINFLOW_AGENT_RESOURCE_STORAGE_NOT_READY', statusCode: 503,
  });
}

function createFinflowAgentResourceFacade({ getLifecycle } = {}) {
  if (typeof getLifecycle !== 'function') throw new TypeError('FinFlow resource lifecycle provider required');
  const resolve = async () => {
    const lifecycle = await getLifecycle();
    if (!lifecycle?.resources
        || AGENT_RESOURCE_METHODS.some(name => typeof lifecycle.resources[name] !== 'function')
        || typeof lifecycle.repository?.assertReady !== 'function'
        || typeof lifecycle.logRepository?.assertReady !== 'function'
        || typeof lifecycle.files?.assertReady !== 'function') {
      throw unavailable();
    }
    return lifecycle;
  };
  const facade = {
    async assertReady() {
      const lifecycle = await resolve();
      await lifecycle.repository.assertReady();
      await lifecycle.logRepository.assertReady();
      await lifecycle.files.assertReady();
      return true;
    },
  };
  for (const method of AGENT_RESOURCE_METHODS) {
    facade[method] = async input => (await resolve()).resources[method](input);
  }
  return Object.freeze(facade);
}

function configuredFinflowAgentResources() {
  return createFinflowAgentResourceFacade({
    getLifecycle: async () => (await require('./sensitiveInfoResetComposition')
      .getSensitiveInfoResetComposition())?.resourceLifecycle,
  });
}

module.exports = { AGENT_RESOURCE_METHODS, createFinflowAgentResourceFacade,
  configuredFinflowAgentResources };
