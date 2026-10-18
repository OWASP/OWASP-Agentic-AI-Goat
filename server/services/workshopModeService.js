'use strict';

const freezeConfig = (defaultMode, allowedModes) => Object.freeze({
  defaultMode,
  allowedModes: Object.freeze([...allowedModes]),
});

const WORKSHOP_MODE_CATALOG = Object.freeze({
  csrf_workshop: Object.freeze({...freezeConfig(null, ['vuln','fixed']), fixedObjectiveIds:Object.freeze(['csrf_g1','csrf_g2','csrf_g3','csrf_p1','csrf_p2','csrf_p3','csrf_x1','csrf_x2','csrf_x3','csrf_i1','csrf_i2','csrf_i3'])}),
  direct_prompt_injection: Object.freeze({...freezeConfig('vuln', ['vuln','fixed']),
    fixedObjectiveIds:Object.freeze(['interact','system_prompt','jailbreak','multi_language','virtualization','role_playing','side_stepping','obfuscation'])}),
  secureshop_agent_security: freezeConfig('vuln', ['fixed', 'vuln']),
  sql_injection_workshop: freezeConfig('fixed', ['fixed', 'vuln']),
  nosql_injection_workshop: freezeConfig('fixed', ['fixed', 'vuln']),
  sensitive_info_disclosure: freezeConfig('vulnerable', ['fixed', 'vulnerable']),
  supply_chain_rce: freezeConfig('vulnerable', ['fixed', 'vulnerable']),
  excessive_agency: freezeConfig('fixed', ['fixed', 'vuln']),
  // These families historically had a null mode scope. Keep that default for
  // existing attempts while explicit learner selections use their fixed paths.
  xss_workshop: freezeConfig(null, ['vuln', 'fixed']),
  xss_email_builder: freezeConfig(null, ['vuln', 'fixed']),
  indirect_prompt_injection: Object.freeze({...freezeConfig(null, ['vuln', 'fixed']),
    fixedObjectiveIds: Object.freeze(['rag_injected_doc', 'email_understand_defense'])}),
  mcp_workshop: freezeConfig(null, ['vuln', 'fixed']),
  legacy_sensitive_file_ssi: freezeConfig(null, ['vuln', 'fixed']),
});

function resolveWorkshopModeConfig(workshopKey) {
  const config = WORKSHOP_MODE_CATALOG[workshopKey];
  if (!config) throw new TypeError(`Unsupported workshop: ${workshopKey}`);
  return config;
}

function createWorkshopModeService(store) {
  if (!store || typeof store.initialize !== 'function' || typeof store.getMode !== 'function' || typeof store.setMode !== 'function') {
    throw new TypeError('Workshop mode store is required');
  }
  let ready;
  function ensureReady() {
    if (!ready) {
      ready = Promise.resolve()
        .then(() => store.initialize())
        .catch((error) => {
          ready = undefined;
          throw error;
        });
    }
    return ready;
  }
  return {
    async getMode({ userId, workshopKey }) {
      const { defaultMode } = resolveWorkshopModeConfig(workshopKey);
      await ensureReady();
      return store.getMode({ userId, workshopKey, defaultMode });
    },
    async setMode({ userId, workshopKey, mode }) {
      const { defaultMode, allowedModes } = resolveWorkshopModeConfig(workshopKey);
      if (!allowedModes.includes(mode)) throw new TypeError(`Invalid mode for ${workshopKey}`);
      await ensureReady();
      const current = await store.getMode({ userId, workshopKey, defaultMode });
      if (current === mode) return mode;
      await store.setMode({ userId, workshopKey, mode });
      return mode;
    },
  };
}

let defaultService;
function getDefaultService() {
  if (!defaultService) {
    defaultService = createWorkshopModeService(require('./postgresPlatformStores').getPostgresPlatformStores().modes);
  }
  return defaultService;
}

const workshopModeService = {
  getMode(input) { return getDefaultService().getMode(input); },
  setMode(input) { return getDefaultService().setMode(input); },
};

module.exports = workshopModeService;
module.exports.createWorkshopModeService = createWorkshopModeService;
module.exports.WORKSHOP_MODE_CATALOG = WORKSHOP_MODE_CATALOG;
module.exports.resolveWorkshopModeConfig = resolveWorkshopModeConfig;
