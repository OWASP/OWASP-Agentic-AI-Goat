'use strict';

const { WORKSHOP_OBJECTIVES } = require('../config/workshopCatalog');
const { resolveWorkshopModeConfig } = require('./workshopModeService');

const allObjectiveIds = key => Object.freeze((WORKSHOP_OBJECTIVES[key] || []).map(objective => objective.id));
const fixed = (scope, supportedObjectiveIds) => Object.freeze({
  scope: Object.freeze(scope),
  fixedSupported: true,
  supportedObjectiveIds: Object.freeze([...supportedObjectiveIds]),
  reason: null,
});
const unavailable = (scope, reason) => Object.freeze({
  scope: Object.freeze(scope),
  fixedSupported: false,
  supportedObjectiveIds: Object.freeze([]),
  reason,
});

// This describes implemented fixed behavior, not objective credit. Credit still
// depends on each family's canonical Judge, observed effect and mode policy.
const FIXED_CAPABILITIES = Object.freeze({
  sql_injection_workshop: fixed({ kind: 'tool', id: 'search_products' }, allObjectiveIds('sql_injection_workshop')),
  nosql_injection_workshop: fixed({ kind: 'tool', id: 'search_papers' }, allObjectiveIds('nosql_injection_workshop')),
  sensitive_info_disclosure: fixed({ kind: 'agent', id: 'finflow' }, allObjectiveIds('sensitive_info_disclosure')),
  supply_chain_rce: fixed({ kind: 'agent', id: 'codebot' }, allObjectiveIds('supply_chain_rce')),
  excessive_agency: fixed({ kind: 'tool_router', id: 'excessive_agency' },
    ['objective_1', 'objective_2', 'objective_3', 'objective_4']),
  direct_prompt_injection: fixed({ kind: 'workshop', id: 'direct_prompt_injection' },
    ['interact','system_prompt','jailbreak','multi_language','virtualization','role_playing','side_stepping','obfuscation']),
  csrf_workshop: fixed({ kind: 'workshop', id: 'csrf_workshop' }, allObjectiveIds('csrf_workshop')),
  secureshop_agent_security: unavailable({ kind: 'registered_feature', id: 'secureshop_v2' },
    'Fixed behavior must be reported by the selected SecureShop feature and launch.'),
  xss_workshop: fixed({ kind: 'workshop', id: 'xss_workshop' }, allObjectiveIds('xss_workshop')),
  xss_email_builder: fixed({ kind: 'workshop', id: 'xss_email_builder' }, allObjectiveIds('xss_email_builder')),
  indirect_prompt_injection: fixed({ kind: 'workshop', id: 'indirect_prompt_injection' },
    ['rag_injected_doc', 'email_understand_defense']),
  mcp_workshop: fixed({ kind: 'chat', id: 'mcp_assistant' }, allObjectiveIds('mcp_workshop')),
  legacy_sensitive_file_ssi: fixed({ kind: 'file_ssi_workflow', id: 'legacy_sensitive_file_ssi' },
    allObjectiveIds('legacy_sensitive_file_ssi')),
});

function effectiveMode(mode) {
  return mode === 'vulnerable' || mode === null ? 'vuln' : mode;
}

function rawModeForUi(workshopKey, uiMode) {
  const config = resolveWorkshopModeConfig(workshopKey);
  if (!['vuln', 'fixed'].includes(uiMode)) throw new TypeError('Unsupported display mode');
  const raw = uiMode === 'vuln' && config.allowedModes.includes('vulnerable') ? 'vulnerable' : uiMode;
  if (!config.allowedModes.includes(raw)) throw new TypeError(`Mode unavailable for ${workshopKey}`);
  return raw;
}

function projectWorkshopModeCapability(workshopKey, mode) {
  const config = resolveWorkshopModeConfig(workshopKey);
  const capability = FIXED_CAPABILITIES[workshopKey];
  if (!capability || !(mode === null && config.defaultMode === null) && !config.allowedModes.includes(mode)) {
    throw new TypeError(`Mode unavailable for ${workshopKey}`);
  }
  const selectableModes = [...new Set(config.allowedModes.map(effectiveMode))]
    .filter(value => value !== 'fixed' || capability.fixedSupported);
  return {
    success: true,
    version: 1,
    mode,
    effectiveMode: effectiveMode(mode),
    defaultMode: config.defaultMode,
    allowedModes: [...config.allowedModes],
    selectableModes,
    fixedSupported: capability.fixedSupported,
    scope: { ...capability.scope },
    supportedObjectiveIds: [...capability.supportedObjectiveIds],
    reason: capability.reason,
  };
}

module.exports = { FIXED_CAPABILITIES, effectiveMode, rawModeForUi, projectWorkshopModeCapability };
