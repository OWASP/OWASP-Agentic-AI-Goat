'use strict';

const {HTTP_CAPABILITY}=require('./ownedHttpCapability');
const httpQualifications=new WeakMap(), shadowQualifications=new WeakMap();
const SHADOW_CAPABILITY='mcp-owned-shadow-sdk.v1';
function baseQualification(value){const base=shadowQualifications.get(value)||httpQualifications.get(value);return base?baseQualification(base):value;}
function hasShadowQualification(value){return shadowQualifications.has(value);}
function hasHttpQualification(value){return httpQualifications.has(value)||Boolean(shadowQualifications.has(value)&&hasHttpQualification(shadowQualifications.get(value)));}
function withShadowQualification(base,{capability,enabled=false}={}){
  if(!enabled)return base;
  if(capability!==SHADOW_CAPABILITY||!isProductionQualification(base))throw TypeError('Qualified owned shadow readiness required');
  const value=Object.freeze({version:base.version+'.shadow-v1',mode:base.mode,
    qualifiedObjectives:Object.freeze([...base.qualifiedObjectives,'mcp_shadow_server']),
    canGrade:objective=>objective==='mcp_shadow_server'||base.canGrade(objective)});
  shadowQualifications.set(value,base);return value;
}
const QUALIFICATION_VERSION = 'mcp-owned-connected.v20';
const QUALIFIED_OBJECTIVES = Object.freeze(['mcp_cmd_injection', 'mcp_confused_deputy']);
const PROTECTED_STATE_CAPABILITY = 'mcp-owned-protected-state-transition.v2';
const PROTECTED_QUALIFICATION_VERSION = 'mcp-owned-connected.protected-v2';
const PROTECTED_QUALIFIED_OBJECTIVES = Object.freeze([...QUALIFIED_OBJECTIVES,
  'mcp_broken_authz', 'mcp_secret_exposure', 'mcp_audit_gap']);
const OBSERVED_ACTION_CAPABILITY = 'mcp-owned-observed-action.v1';
const OBSERVED_ACTION_QUALIFICATION_VERSION = 'mcp-owned-connected.observed-action-v1';
const OBSERVED_ACTION_QUALIFIED_OBJECTIVES = Object.freeze([...PROTECTED_QUALIFIED_OBJECTIVES,
  'mcp_tool_poisoning']);
const TICKET_READ_CAPABILITY = 'mcp-owned-ticket-read.v2';
const INDIRECT_INJECTION_QUALIFICATION_VERSION = 'mcp-owned-connected.indirect-injection-v1';
const INDIRECT_INJECTION_QUALIFIED_OBJECTIVES = Object.freeze([...OBSERVED_ACTION_QUALIFIED_OBJECTIVES,
  'mcp_indirect_injection']);
const PACKAGE_INSTALL_CAPABILITY = 'mcp-owned-package-install.v1';
const SUPPLY_CHAIN_QUALIFICATION_VERSION = 'mcp-owned-connected.supply-chain-v1';
const SUPPLY_CHAIN_QUALIFIED_OBJECTIVES = Object.freeze([...OBSERVED_ACTION_QUALIFIED_OBJECTIVES,
  'mcp_supply_chain']);
const CATALOG_OBSERVATION_CAPABILITY = 'mcp-owned-catalog-observation.v1';
const CATALOG_QUALIFICATION_VERSION = 'mcp-owned-connected.catalog-v1';
const PROTECTED_CATALOG_QUALIFICATION_VERSION = 'mcp-owned-connected.protected-catalog-v1';
const OBSERVED_ACTION_CATALOG_QUALIFICATION_VERSION = 'mcp-owned-connected.observed-action-catalog-v1';
const SUPPLY_CHAIN_CATALOG_QUALIFICATION_VERSION = 'mcp-owned-connected.supply-chain-catalog-v1';
const INDIRECT_INJECTION_CATALOG_QUALIFICATION_VERSION = 'mcp-owned-connected.indirect-injection-catalog-v1';
const INDIRECT_SUPPLY_CHAIN_CATALOG_QUALIFICATION_VERSION =
  'mcp-owned-connected.indirect-supply-chain-catalog-v1';
const CATALOG_QUALIFIED_OBJECTIVES = Object.freeze([...QUALIFIED_OBJECTIVES, 'mcp_recon']);
const PROTECTED_CATALOG_QUALIFIED_OBJECTIVES = Object.freeze([...PROTECTED_QUALIFIED_OBJECTIVES, 'mcp_recon']);
const OBSERVED_ACTION_CATALOG_QUALIFIED_OBJECTIVES = Object.freeze([...OBSERVED_ACTION_QUALIFIED_OBJECTIVES, 'mcp_recon']);
const SUPPLY_CHAIN_CATALOG_QUALIFIED_OBJECTIVES = Object.freeze([...SUPPLY_CHAIN_QUALIFIED_OBJECTIVES, 'mcp_recon']);
const INDIRECT_INJECTION_CATALOG_QUALIFIED_OBJECTIVES = Object.freeze([
  ...INDIRECT_INJECTION_QUALIFIED_OBJECTIVES, 'mcp_recon',
]);
const INDIRECT_SUPPLY_CHAIN_CATALOG_QUALIFIED_OBJECTIVES = Object.freeze([
  ...INDIRECT_INJECTION_QUALIFIED_OBJECTIVES, 'mcp_supply_chain', 'mcp_recon',
]);
const BASELINE_TOOLS = Object.freeze(['run_command', 'send_report']);
const PROTECTED_TOOLS = Object.freeze([...BASELINE_TOOLS, 'admin_rotate_keys', 'get_config', 'set_audit_logging']);
const OBSERVED_ACTION_TOOLS = Object.freeze([...PROTECTED_TOOLS, 'check_system_status', 'read_file']);
const INDIRECT_INJECTION_TOOLS = Object.freeze([...OBSERVED_ACTION_TOOLS, 'read_ticket']);
const SUPPLY_CHAIN_TOOLS = Object.freeze([...OBSERVED_ACTION_TOOLS, 'install_plugin']);
const INDIRECT_SUPPLY_CHAIN_TOOLS = Object.freeze([...INDIRECT_INJECTION_TOOLS, 'install_plugin']);

function profile(protectedStateReady, observedActionReady, supplyChainReady) {
  if (protectedStateReady && observedActionReady && supplyChainReady) {
    return { version: SUPPLY_CHAIN_QUALIFICATION_VERSION,
      objectives: SUPPLY_CHAIN_QUALIFIED_OBJECTIVES, tools: SUPPLY_CHAIN_TOOLS };
  }
  if (protectedStateReady && observedActionReady) return { version: OBSERVED_ACTION_QUALIFICATION_VERSION,
    objectives: OBSERVED_ACTION_QUALIFIED_OBJECTIVES, tools: OBSERVED_ACTION_TOOLS };
  if (protectedStateReady) return { version: PROTECTED_QUALIFICATION_VERSION,
    objectives: PROTECTED_QUALIFIED_OBJECTIVES, tools: PROTECTED_TOOLS };
  return { version: QUALIFICATION_VERSION, objectives: QUALIFIED_OBJECTIVES, tools: BASELINE_TOOLS };
}
const catalogProfiles = new Map([
  [QUALIFICATION_VERSION, Object.freeze({ version: CATALOG_QUALIFICATION_VERSION,
    objectives: CATALOG_QUALIFIED_OBJECTIVES })],
  [PROTECTED_QUALIFICATION_VERSION, Object.freeze({ version: PROTECTED_CATALOG_QUALIFICATION_VERSION,
    objectives: PROTECTED_CATALOG_QUALIFIED_OBJECTIVES })],
  [OBSERVED_ACTION_QUALIFICATION_VERSION, Object.freeze({ version: OBSERVED_ACTION_CATALOG_QUALIFICATION_VERSION,
    objectives: OBSERVED_ACTION_CATALOG_QUALIFIED_OBJECTIVES })],
  [SUPPLY_CHAIN_QUALIFICATION_VERSION, Object.freeze({ version: SUPPLY_CHAIN_CATALOG_QUALIFICATION_VERSION,
    objectives: SUPPLY_CHAIN_CATALOG_QUALIFIED_OBJECTIVES })],
  [INDIRECT_INJECTION_QUALIFICATION_VERSION, Object.freeze({
    version: INDIRECT_INJECTION_CATALOG_QUALIFICATION_VERSION,
    objectives: INDIRECT_INJECTION_CATALOG_QUALIFIED_OBJECTIVES,
  })],
]);
function createOwnedQualification(enabled, { protectedStateCapability = null, observedActionCapability = null,
  ticketReadCapability = null, packageInstallCapability = null, catalogObservationCapability = null,
  enableObservedAction = false, enableIndirectInjection = false,
  enableSupplyChain = false, enableCatalogRecon = false, httpCapability = null } = {}) {
  const protectedStateReady = protectedStateCapability === PROTECTED_STATE_CAPABILITY;
  const observedActionCapable = observedActionCapability === OBSERVED_ACTION_CAPABILITY;
  const observedActionReady = enableObservedAction === true
    && observedActionCapable;
  const supplyChainReady = observedActionReady && enableSupplyChain === true
    && packageInstallCapability === PACKAGE_INSTALL_CAPABILITY;
  const indirectInjectionReady = enableIndirectInjection === true && protectedStateReady
    && observedActionCapable && ticketReadCapability === TICKET_READ_CAPABILITY;
  const selected = indirectInjectionReady
    ? { version: INDIRECT_INJECTION_QUALIFICATION_VERSION,
      objectives: INDIRECT_INJECTION_QUALIFIED_OBJECTIVES, tools: INDIRECT_INJECTION_TOOLS }
    : profile(protectedStateReady, observedActionReady, supplyChainReady);
  const catalogReady = enableCatalogRecon === true
    && catalogObservationCapability === CATALOG_OBSERVATION_CAPABILITY;
  const catalog = catalogReady && indirectInjectionReady && supplyChainReady
    ? { version: INDIRECT_SUPPLY_CHAIN_CATALOG_QUALIFICATION_VERSION,
      objectives: INDIRECT_SUPPLY_CHAIN_CATALOG_QUALIFIED_OBJECTIVES }
    : catalogReady ? catalogProfiles.get(selected.version) : null;
  const effective = catalog ? { ...selected, ...catalog } : selected;
  const qualified = new Set(effective.objectives);
  const base = Object.freeze({
    version: enabled ? effective.version : null,
    mode: enabled ? 'qualified_subset' : 'legacy',
    qualifiedObjectives: enabled ? effective.objectives : Object.freeze([]),
    canGrade(objectiveId) { return enabled ? qualified.has(objectiveId) : true; },
  });
  if (!enabled || httpCapability !== HTTP_CAPABILITY) return base;
  const expanded = Object.freeze({version: base.version + '.http-v1', mode: base.mode,
    qualifiedObjectives: Object.freeze([...base.qualifiedObjectives, 'mcp_ssrf']),
    canGrade: objectiveId => objectiveId === 'mcp_ssrf' || base.canGrade(objectiveId)});
  httpQualifications.set(expanded,base);return expanded;
}
function createOwnedToolAuthorizer(qualification) {
  if(shadowQualifications.has(qualification)){
    const authorize=createOwnedToolAuthorizer(shadowQualifications.get(qualification));
    // Imported names still require exact durable catalog membership in the registry.
    return (toolName,context)=>toolName==='register_server'||authorize(toolName,context);
  }
  if (httpQualifications.has(qualification)) {
    const authorize = createOwnedToolAuthorizer(httpQualifications.get(qualification));
    return (toolName,context) => toolName === 'fetch_url' || authorize(toolName,context);
  }
  const supplyCatalog = catalogProfiles.get(SUPPLY_CHAIN_QUALIFICATION_VERSION);
  const observedCatalog = catalogProfiles.get(OBSERVED_ACTION_QUALIFICATION_VERSION);
  const protectedCatalog = catalogProfiles.get(PROTECTED_QUALIFICATION_VERSION);
  const supplyChain = (qualification?.version === SUPPLY_CHAIN_QUALIFICATION_VERSION
    && qualification.qualifiedObjectives === SUPPLY_CHAIN_QUALIFIED_OBJECTIVES)
    || (qualification?.version === supplyCatalog.version && qualification.qualifiedObjectives === supplyCatalog.objectives);
  const observed = (qualification?.version === OBSERVED_ACTION_QUALIFICATION_VERSION
    && qualification.qualifiedObjectives === OBSERVED_ACTION_QUALIFIED_OBJECTIVES)
    || (qualification?.version === observedCatalog.version && qualification.qualifiedObjectives === observedCatalog.objectives);
  const indirectCatalog = catalogProfiles.get(INDIRECT_INJECTION_QUALIFICATION_VERSION);
  const indirectSupplyCatalog = qualification?.version === INDIRECT_SUPPLY_CHAIN_CATALOG_QUALIFICATION_VERSION
    && qualification.qualifiedObjectives === INDIRECT_SUPPLY_CHAIN_CATALOG_QUALIFIED_OBJECTIVES;
  const indirectInjection = (qualification?.version === INDIRECT_INJECTION_QUALIFICATION_VERSION
    && qualification.qualifiedObjectives === INDIRECT_INJECTION_QUALIFIED_OBJECTIVES)
    || (qualification?.version === indirectCatalog.version
      && qualification.qualifiedObjectives === indirectCatalog.objectives)
    || indirectSupplyCatalog;
  const selected = indirectSupplyCatalog ? INDIRECT_SUPPLY_CHAIN_TOOLS
    : indirectInjection ? INDIRECT_INJECTION_TOOLS
    : supplyChain ? SUPPLY_CHAIN_TOOLS : observed ? OBSERVED_ACTION_TOOLS : qualification?.version === PROTECTED_QUALIFICATION_VERSION
    && qualification.qualifiedObjectives === PROTECTED_QUALIFIED_OBJECTIVES
    || qualification?.version === protectedCatalog.version && qualification.qualifiedObjectives === protectedCatalog.objectives
    ? PROTECTED_TOOLS : BASELINE_TOOLS;
  const allowed = new Set(selected);
  return (toolName, context = {}) => allowed.has(toolName)
    && (toolName !== 'read_ticket' || (indirectInjection && context.purpose === 'observation'))
    && (toolName !== 'send_report' || context.purpose !== 'indirect_injection' || indirectInjection)
    && (toolName !== 'check_system_status' || context.purpose === 'observation')
    && (toolName !== 'read_file' || context.purpose === 'tool_poisoning');
}
function canExecuteOwnedTool(toolName, context = {}) {
  return createOwnedToolAuthorizer(createOwnedQualification(true))(toolName, context);
}
function isProductionQualification(value) {
  if(shadowQualifications.has(value))return isProductionQualification(shadowQualifications.get(value));
  if (httpQualifications.has(value)) return isProductionQualification(httpQualifications.get(value));
  return Boolean(value && typeof value.canGrade === 'function'
    && ((value.version === QUALIFICATION_VERSION && value.qualifiedObjectives === QUALIFIED_OBJECTIVES)
      || (value.version === PROTECTED_QUALIFICATION_VERSION
        && value.qualifiedObjectives === PROTECTED_QUALIFIED_OBJECTIVES)
      || (value.version === OBSERVED_ACTION_QUALIFICATION_VERSION
        && value.qualifiedObjectives === OBSERVED_ACTION_QUALIFIED_OBJECTIVES)
      || (value.version === SUPPLY_CHAIN_QUALIFICATION_VERSION
        && value.qualifiedObjectives === SUPPLY_CHAIN_QUALIFIED_OBJECTIVES)
      || (value.version === INDIRECT_INJECTION_QUALIFICATION_VERSION
        && value.qualifiedObjectives === INDIRECT_INJECTION_QUALIFIED_OBJECTIVES)
      || (value.version === INDIRECT_SUPPLY_CHAIN_CATALOG_QUALIFICATION_VERSION
        && value.qualifiedObjectives === INDIRECT_SUPPLY_CHAIN_CATALOG_QUALIFIED_OBJECTIVES)
      || [...catalogProfiles.values()].some(profile => value.version === profile.version
        && value.qualifiedObjectives === profile.objectives)));
}

module.exports = { hasShadowQualification, SHADOW_CAPABILITY, withShadowQualification, HTTP_CAPABILITY, baseQualification, hasHttpQualification, QUALIFICATION_VERSION, QUALIFIED_OBJECTIVES, PROTECTED_STATE_CAPABILITY,
  PROTECTED_QUALIFICATION_VERSION, PROTECTED_QUALIFIED_OBJECTIVES,
  OBSERVED_ACTION_CAPABILITY, OBSERVED_ACTION_QUALIFICATION_VERSION, OBSERVED_ACTION_QUALIFIED_OBJECTIVES,
  TICKET_READ_CAPABILITY, INDIRECT_INJECTION_QUALIFICATION_VERSION,
  INDIRECT_INJECTION_QUALIFIED_OBJECTIVES,
  PACKAGE_INSTALL_CAPABILITY, SUPPLY_CHAIN_QUALIFICATION_VERSION, SUPPLY_CHAIN_QUALIFIED_OBJECTIVES,
  CATALOG_OBSERVATION_CAPABILITY, CATALOG_QUALIFICATION_VERSION,
  PROTECTED_CATALOG_QUALIFICATION_VERSION, OBSERVED_ACTION_CATALOG_QUALIFICATION_VERSION,
  SUPPLY_CHAIN_CATALOG_QUALIFICATION_VERSION, INDIRECT_INJECTION_CATALOG_QUALIFICATION_VERSION,
  INDIRECT_SUPPLY_CHAIN_CATALOG_QUALIFICATION_VERSION,
  CATALOG_QUALIFIED_OBJECTIVES, PROTECTED_CATALOG_QUALIFIED_OBJECTIVES,
  OBSERVED_ACTION_CATALOG_QUALIFIED_OBJECTIVES, SUPPLY_CHAIN_CATALOG_QUALIFIED_OBJECTIVES,
  INDIRECT_INJECTION_CATALOG_QUALIFIED_OBJECTIVES,
  INDIRECT_SUPPLY_CHAIN_CATALOG_QUALIFIED_OBJECTIVES,
  createOwnedQualification, createOwnedToolAuthorizer, canExecuteOwnedTool, isProductionQualification };
